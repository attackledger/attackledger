"""Migration 0022 on a database with data (D-042, docs/ORGANIZATIONS.md).

The fixture is a database at migration 0021, filled through the 0.7.1 API (orgfill.py, run by
data/org-migration/make_fixture.py at the commit before this change), with the engagement's
key and the report that API issued. Every table has rows. The test upgrades it, checks that
every row went to the default organization, that the chains and the old report still verify
and continue, that the API scopes the upgraded data, then downgrades and upgrades again.

On Postgres: set ATTACKLEDGER_TEST_PG_URL to a database at 0021 filled by make_fixture.py and
ATTACKLEDGER_TEST_PG_FIXTURE to the folder it wrote (docs/ORGANIZATIONS.md, "Upgrading").
"""
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from harness import ROOT
from orgfill import sign_in

from app import auditlog, auth, db, keylog, migrate
from app.main import app

FIXTURE = Path(__file__).parent / "data" / "org-migration"
DIRECT = ("users", "engagements", "memberships", "assets", "lanes", "evidence", "jobs", "observations", "endpoints",
          "leads", "key_log", "audit_log", "import_batches", "inbox_entries", "test_accounts", "write_proposals",
          "gateway_requests")
THROUGH = ("checklist_items", "receipts", "agent_exchanges", "signing_keys", "user_sessions")


def counts(eng) -> dict:
    with eng.connect() as c:
        return {t: c.execute(text(f"SELECT count(*) FROM {t}")).scalar() for t in DIRECT + THROUGH}


def chain_rows(eng) -> dict:
    with eng.connect() as c:
        return {t: [tuple(r) for r in c.execute(text(f"SELECT seq, prev_hash, record_sha256, entry_hash FROM {t} "
                                                    "ORDER BY seq"))] for t in ("audit_log", "key_log")} | {
            "evidence": [tuple(r) for r in c.execute(text("SELECT engagement_id, seq, prev_hash, chain_hash "
                                                          "FROM evidence ORDER BY engagement_id, seq"))]}


def verify_file(path: Path) -> str:
    r = subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "verify_report.py"), str(path)],
                       capture_output=True, text=True)
    assert r.returncode == 0 and "Verified." in r.stdout, r.stdout + r.stderr
    return r.stdout


def upgrade_and_check(eng, monkeypatch, tmp_path, fixture: Path):
    """The whole check, on a database at 0021 made by make_fixture.py."""
    monkeypatch.setattr(db, "engine", eng)
    monkeypatch.setattr(migrate, "engine", eng)
    monkeypatch.delenv("ATTACKLEDGER_API_TOKEN", raising=False)
    shutil.copytree(fixture / "blobs", tmp_path / "blobs", dirs_exist_ok=True)
    monkeypatch.setenv("ATTACKLEDGER_BLOBS", str(tmp_path / "blobs"))
    ids = json.loads((fixture / "ids.json").read_text())
    old_report = json.loads((fixture / "report.json").read_text())
    assert migrate.current() == "0021"
    before, chains = counts(eng), chain_rows(eng)
    assert all(before[t] > 0 for t in before), before          # every table has rows to move

    migrate.upgrade_head()
    assert migrate.current() == "0022"
    with eng.connect() as c:
        orgs = c.execute(text("SELECT id, name FROM organizations")).all()
        assert len(orgs) == 1 and orgs[0][1] == "Default organization"
        for t in DIRECT:
            assert c.execute(text(f"SELECT DISTINCT organization_id FROM {t}")).scalars().all() == [orgs[0][0]], t
    assert counts(eng) == before and chain_rows(eng) == chains  # nothing lost, the chains as they were
    Session = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
    with Session() as s:
        assert auditlog.verify(s) == [] and keylog.verify(s) == []

    # The report issued at 0021 still verifies, and its heads are in the upgraded chains.
    old = tmp_path / "old-report.json"
    old.write_text(json.dumps(old_report))
    verify_file(old)
    for log, table in (("audit_log", "audit_log"), ("key_log", "key_log")):
        head = old_report[log]["head"]
        assert (head["seq"], head["entry_hash"]) in {(r[0], r[3]) for r in chains[table]}

    # Through the API: the same owner signs in and sees the same engagement; a new report
    # verifies, has the same evidence chain, and the chains continue from where they were.
    def _session():
        s = Session()
        try:
            yield s
        finally:
            s.close()
    app.dependency_overrides[db.get_session] = _session
    try:
        auth._failures.clear()
        c = TestClient(app)
        sign_in(c, ids["owner_email"])
        assert [e["id"] for e in c.get("/engagements").json()] == [ids["eng"]]
        assert c.patch(f"/engagements/{ids['eng']}", json={"separation_of_duties": True}).status_code == 200
        new_report = c.get(f"/engagements/{ids['eng']}/report").json()
        assert "organization" not in c.get("/auth/me").json()           # one organization: nothing new shown
    finally:
        app.dependency_overrides.clear()
    new = tmp_path / "new-report.json"
    new.write_text(json.dumps(new_report))
    verify_file(new)
    assert [e["chain_hash"] for e in new_report["evidence"]] == [e["chain_hash"] for e in old_report["evidence"]]
    head = new_report["audit_log"]["head"]
    old_head = old_report["audit_log"]["head"]
    links = {l["seq"]: l for l in new_report["audit_log"]["links"]}
    assert head["seq"] > old_head["seq"] and links[old_head["seq"]]["entry_hash"] == old_head["entry_hash"]
    assert links[old_head["seq"] + 1]["prev_hash"] == links[old_head["seq"]]["entry_hash"]

    # Down to 0021 and up again: refused while there are two organizations, then clean.
    with eng.begin() as c:
        c.execute(text("INSERT INTO organizations (name, created_at) VALUES ('Second', CURRENT_TIMESTAMP)"))
    with pytest.raises(RuntimeError, match="2 organizations"):
        command.downgrade(migrate._config(), "0021")
    with eng.begin() as c:
        c.execute(text("DELETE FROM organizations WHERE name = 'Second'"))
    after = counts(eng)
    command.downgrade(migrate._config(), "0021")
    assert migrate.current() == "0021"
    insp = inspect(eng)
    assert "organizations" not in insp.get_table_names()
    for t in DIRECT:
        assert "organization_id" not in {col["name"] for col in insp.get_columns(t)}, t
    assert counts(eng) == after
    with eng.connect() as c:                                    # unique for the deployment again
        uniques = {t: [u["column_names"] for u in inspect(c).get_unique_constraints(t)]
                   for t in ("engagements", "users", "key_log", "audit_log")}
    assert uniques == {"engagements": [["name"]], "users": [["email"]], "key_log": [["seq"]], "audit_log": [["seq"]]}
    migrate.upgrade_head()
    assert migrate.current() == "0022" and counts(eng) == after
    with Session() as s:
        assert auditlog.verify(s) == [] and keylog.verify(s) == []


def test_upgrade_with_data_on_sqlite(tmp_path, monkeypatch):
    path = tmp_path / "al.db"
    con = sqlite3.connect(path)
    con.executescript((FIXTURE / "fixture.sql").read_text())
    con.close()
    upgrade_and_check(create_engine(f"sqlite:///{path}"), monkeypatch, tmp_path, FIXTURE)


@pytest.mark.skipif(not os.environ.get("ATTACKLEDGER_TEST_PG_URL"), reason="needs a Postgres database at 0021")
def test_upgrade_with_data_on_postgres(tmp_path, monkeypatch):
    upgrade_and_check(create_engine(os.environ["ATTACKLEDGER_TEST_PG_URL"]), monkeypatch, tmp_path,
                      Path(os.environ["ATTACKLEDGER_TEST_PG_FIXTURE"]))
