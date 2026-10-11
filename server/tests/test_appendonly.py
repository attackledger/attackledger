"""Append-only tables, enforced by the database (TM-5, app/appendonly.py, migration 0026).

Each test runs on a database made from the models (create_all, as the tests make theirs) and on
one migrated to head (as every installation's), on SQLite and, under tools/test_postgres.sh, on
Postgres: raw SQL that changes a protected column or deletes a row is refused, and every change
the product makes (deleting an engagement's content, by an owner or the retention policy, and
timestamping a receipt later) still goes through."""
from datetime import date, datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

import testdb
from app import appendonly, auditlog, db, keylog, ledger, migrate, vault
from app.models import (Asset, AuditEntry, ChecklistItem, Engagement, Evidence, GatewayRequest, KeyLogEntry, Lane,
                        Receipt)

TABLES = sorted(appendonly.RULES)


@pytest.fixture(params=["models", "migrated"])
def Session(request, tmp_path, monkeypatch):
    if request.param == "models":
        eng = testdb.memory_engine()
        db.Base.metadata.create_all(eng)
    else:
        eng = testdb.file_engine(tmp_path / "al.db")
        monkeypatch.setattr(db, "engine", eng)
        monkeypatch.setattr(migrate, "engine", eng)
        migrate.upgrade_head()
    yield sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
    eng.dispose()


def seed(Session) -> dict:
    """One row in each protected table, made the way the product makes them."""
    with Session() as s:
        e = Engagement(name="e", scope_include=["*.example.com"], authorized_by="op",
                       authorized_at=datetime.now(timezone.utc))
        a = Asset(engagement=e, host="shop.example.com")
        lane = Lane(asset=a, role="recon")
        lane.items = [ChecklistItem(idx=1, item_key="R-1", text="check", controls=[])]
        s.add_all([e, a, lane])
        s.commit()
        ev = ledger.append_evidence(s, lane, kind="note", sha256_hex="0" * 64, summary="a note", source="manual")
        rc = Receipt(lane_id=lane.id, manifest_sha256="1" * 64, closed_by="Rita")
        g = GatewayRequest(at=datetime.now(timezone.utc), engagement_id=e.id, tool="httpx", kind="target",
                           method="GET", url="https://shop.example.com/a?b=c", host="shop.example.com", port=443,
                           status=200, verdict="allowed", reason="a reason")
        s.add_all([rc, g])
        au = auditlog.append(s, actor=auditlog.CLI, action="engagement.created", engagement_id=e.id,
                             change={"after": {"name": "e"}})
        kl = keylog.append_instance(s, organization_id=e.organization_id, fingerprint="2" * 64, algorithm="ECDSA-P256")
        s.commit()
        return {"engagement": e.id, "evidence": ev.id, "receipts": rc.id, "gateway_requests": g.id,
                "audit_log": au.id, "key_log": kl.id}


def refused(Session, sql: str, **params) -> bool:
    with Session() as s:
        try:
            s.execute(text(sql), params)
            s.commit()
        except DBAPIError as e:
            s.rollback()
            assert "append-only" in str(e.orig), e
            return True
    return False


# A column of each table the product never changes, and a value for it.
PROTECTED = {"evidence": ("chain_hash", "'f'"), "receipts": ("manifest_sha256", "'f'"),
             "gateway_requests": ("verdict", "'refused'"), "audit_log": ("actor_name", "'someone'"),
             "key_log": ("user_name", "'someone'")}


def test_the_rules_cover_the_tables_the_code_calls_append_only():
    assert set(appendonly.RULES) == {"evidence", "receipts", "gateway_requests", "audit_log", "key_log"}
    assert set(PROTECTED) == set(appendonly.RULES)


@pytest.mark.parametrize("table", TABLES)
def test_raw_sql_cannot_change_or_delete_a_row(Session, table):
    ids = seed(Session)
    column, value = PROTECTED[table]
    assert refused(Session, f"UPDATE {table} SET {column} = {value} WHERE id = :id", id=ids[table])
    assert refused(Session, f"UPDATE {table} SET id = id + 1000 WHERE id = :id", id=ids[table])
    assert refused(Session, f"DELETE FROM {table} WHERE id = :id", id=ids[table])
    assert refused(Session, f"DELETE FROM {table}")
    with Session() as s:
        assert s.scalar(text(f"SELECT count(*) FROM {table}")) == 1
        postgres = s.get_bind().dialect.name == "postgresql"
    if postgres:
        assert refused(Session, f"TRUNCATE {table} CASCADE")


def test_only_the_changes_the_product_makes_go_through(Session):
    ids = seed(Session)
    # evidence: the encrypted summary may go, nothing else, and it may not be replaced
    assert refused(Session, "UPDATE evidence SET summary_enc = 'x' WHERE id = :id", id=ids["evidence"])
    assert refused(Session, "UPDATE evidence SET summary_enc = NULL, summary = 'x' WHERE id = :id", id=ids["evidence"])
    assert refused(Session, "UPDATE evidence SET summary_sha256 = NULL WHERE id = :id", id=ids["evidence"])
    assert not refused(Session, "UPDATE evidence SET summary_enc = NULL WHERE id = :id", id=ids["evidence"])
    # the request log: the URL and the reason may be emptied, nothing else
    assert refused(Session, "UPDATE gateway_requests SET url = 'https://elsewhere/' WHERE id = :id",
                   id=ids["gateway_requests"])
    assert refused(Session, "UPDATE gateway_requests SET url = '', status = 500 WHERE id = :id",
                   id=ids["gateway_requests"])
    assert not refused(Session, "UPDATE gateway_requests SET url = '', reason = '' WHERE id = :id",
                       id=ids["gateway_requests"])
    # receipts: the timestamp, once, while there is none
    assert refused(Session, "UPDATE receipts SET closed_by = 'Mallory' WHERE id = :id", id=ids["receipts"])
    assert not refused(Session, "UPDATE receipts SET timestamp_error = 'unreachable' WHERE id = :id", id=ids["receipts"])
    assert not refused(Session, "UPDATE receipts SET timestamp_token = 'tok', timestamp_tsa = 'http://tsa.invalid', "
                                "timestamp_error = NULL WHERE id = :id", id=ids["receipts"])
    assert refused(Session, "UPDATE receipts SET timestamp_token = 'another' WHERE id = :id", id=ids["receipts"])
    assert refused(Session, "UPDATE receipts SET timestamp_error = 'x' WHERE id = :id", id=ids["receipts"])
    # an UPDATE that changes nothing is not a change
    assert not refused(Session, "UPDATE audit_log SET actor_name = actor_name WHERE id = :id", id=ids["audit_log"])


def test_deleting_content_and_retention_still_work(Session):
    """vault.delete_content (an owner's, from the Team tab) and the retention pass, through the
    application, on a database with the triggers: they make exactly the changes allowed."""
    ids = seed(Session)
    with Session() as s:
        eng = s.get(Engagement, ids["engagement"])
        eng.retain_until = date.today() - timedelta(days=1)
        s.commit()
        assert vault.apply_retention(s) == [eng.id]
    with Session() as s:
        ev = s.get(Evidence, ids["evidence"])
        assert ev.summary_enc is None and ev.summary_sha256 == ledger.sha256("a note")
        g = s.get(GatewayRequest, ids["gateway_requests"])
        assert (g.url, g.reason, g.verdict, g.status) == ("", "", "allowed", 200)
        assert s.get(Engagement, ids["engagement"]).content_deleted_reason == "retention"
        assert s.scalars(select(AuditEntry).where(AuditEntry.action == "engagement.content_deleted")).one()
        assert auditlog.verify(s) == [] and keylog.verify(s) == []
        assert vault.delete_content(s, s.get(Engagement, ids["engagement"]), actor=auditlog.CLI,
                                    reason="operator")["already_deleted"]


def test_timestamping_a_receipt_later_still_works(Session, monkeypatch):
    """main.timestamp_receipt: the ORM sets the four columns of a receipt without a token."""
    from app import main, timestamps
    ids = seed(Session)
    monkeypatch.setattr(timestamps, "tsa_url", lambda: "http://tsa.invalid")
    monkeypatch.setattr(timestamps, "fetch", lambda url, stmt: ("dG9rZW4=", datetime.now(timezone.utc)))
    with Session() as s:
        rc = s.get(Receipt, ids["receipts"])
        main._timestamp(rc)
        s.commit()
    with Session() as s:
        rc = s.get(Receipt, ids["receipts"])
        assert rc.timestamp_token == "dG9rZW4=" and rc.timestamp_tsa == "http://tsa.invalid"
        main._timestamp(rc)              # a second one is refused by the database as by the route
        with pytest.raises(DBAPIError, match="append-only"):
            s.commit()


def _triggers(eng) -> list[str]:
    with eng.connect() as c:
        if eng.dialect.name == "sqlite":
            return sorted(r[0] for r in c.execute(text("SELECT sql FROM sqlite_master WHERE type = 'trigger'")))
        defs = [r[0] for r in c.execute(text(
            "SELECT pg_get_triggerdef(t.oid) FROM pg_trigger t WHERE NOT t.tgisinternal"))]
        funcs = [r[0] for r in c.execute(text(
            "SELECT pg_get_functiondef(p.oid) FROM pg_proc p WHERE p.proname LIKE 'attackledger_append_only%'"))]
        return sorted(defs + funcs)


def test_a_migrated_database_has_the_triggers_of_one_made_from_the_models(tmp_path, monkeypatch):
    """Migration 0026 freezes the column lists of its time; the models make theirs from today's.
    A column added to a protected table, or a table rebuilt on SQLite, without making the
    triggers again shows here."""
    made = testdb.memory_engine()
    db.Base.metadata.create_all(made)
    migrated = testdb.file_engine(tmp_path / "al.db")
    monkeypatch.setattr(db, "engine", migrated)
    monkeypatch.setattr(migrate, "engine", migrated)
    migrate.upgrade_head()
    want = _triggers(made)
    assert want and _triggers(migrated) == want
    assert len([t for t in want if "CREATE TRIGGER" in t.upper()]) == len(TABLES) * 2


def test_downgrading_0026_removes_the_triggers_and_upgrading_makes_them_again(tmp_path, monkeypatch):
    from alembic import command
    eng = testdb.file_engine(tmp_path / "al.db")
    monkeypatch.setattr(db, "engine", eng)
    monkeypatch.setattr(migrate, "engine", eng)
    migrate.upgrade_head()
    command.downgrade(migrate._config(), "0025")
    assert _triggers(eng) == []
    S = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
    ids = seed(S)
    with S() as s:
        name = s.get(AuditEntry, ids["audit_log"]).actor_name
    assert not refused(S, "UPDATE audit_log SET actor_name = 'x' WHERE id = :id", id=ids["audit_log"])
    assert not refused(S, "UPDATE audit_log SET actor_name = :n WHERE id = :id", n=name, id=ids["audit_log"])
    migrate.upgrade_head()
    assert refused(S, "UPDATE audit_log SET actor_name = 'x' WHERE id = :id", id=ids["audit_log"])
    with S() as s:
        assert auditlog.verify(s) == []


def test_tests_that_tamper_say_so():
    """testdb.append_only_off is what a superuser can do; the triggers come back afterwards."""
    eng = testdb.memory_engine()
    db.Base.metadata.create_all(eng)
    S = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
    ids = seed(S)
    with S() as s:
        with testdb.append_only_off(s):
            s.execute(text("DELETE FROM key_log"))
            s.commit()
        assert s.scalar(text("SELECT count(*) FROM key_log")) == 0
    assert refused(S, "DELETE FROM audit_log WHERE id = :id", id=ids["audit_log"])
    with S() as s:
        assert keylog.verify(s) == [] and s.scalars(select(KeyLogEntry)).all() == []
