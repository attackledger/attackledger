"""Key trust (D-036): no one sets another person's password through the API, every key
registration and revocation is in a hash-chained log, the person sees new keys, and
reports carry the history of the keys that signed them."""
import copy
import hashlib
import json
import os
import sys
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite://")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import auth, db, keylog, migrate, people
from app.main import app
from app.models import KeyLogEntry, User
from test_signing import BrowserKey, verifier

PW = "correct horse battery"     # test passwords for this suite only
NEW = "a different battery staple"


@pytest.fixture()
def env(monkeypatch):
    monkeypatch.delenv("ATTACKLEDGER_API_TOKEN", raising=False)
    auth._failures.clear()
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    db.Base.metadata.create_all(eng)
    Session = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)

    def _session():
        s = Session()
        try:
            yield s
        finally:
            s.close()
    app.dependency_overrides[db.get_session] = _session
    monkeypatch.setattr(people, "SessionLocal", Session)
    with TestClient(app) as c:
        yield c, Session
    app.dependency_overrides.clear()


def sign_in(c, email, password=PW):
    c.cookies.clear()
    r = c.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def setup(c):
    c.post("/people", json={"email": "owner@lab.test", "name": "Olive Owner", "password": PW, "is_owner": True})
    sign_in(c, "owner@lab.test")
    rita = c.post("/people", json={"email": "rita@lab.test", "name": "Rita Reviewer", "password": PW}).json()["id"]
    e = c.post("/engagements", json={"name": "Keys"}).json()["id"]
    c.put(f"/engagements/{e}/members", json={"members": [{"user_id": rita, "roles": ["tester", "reviewer"]}]})
    a = c.post(f"/engagements/{e}/assets", json={"host": "shop.lab.test"}).json()["id"]
    lane = c.post("/lanes", json={"asset_id": a, "role": "recon"}).json()
    for it in lane["items"]:
        c.patch(f"/lanes/{lane['id']}/items/{it['idx']}", json={"state": "na", "na_reason": "lab"})
    return e, lane["id"], rita


def register(c, alg="Ed25519"):
    k = BrowserKey(alg)
    r = c.post("/auth/keys", json={"algorithm": alg, "public_key": k.spki})
    assert r.status_code == 201, r.text
    k.fingerprint, k.id = r.json()["fingerprint"], r.json()["id"]
    return k


def signed_close(c, lane_id, k):
    payload = c.get(f"/lanes/{lane_id}/receipt-payload", params={"key": k.fingerprint}).json()["payload"]
    r = c.post(f"/lanes/{lane_id}/close", json={"reviewed": True, "payload": payload,
                                                "signature": k.sign(payload), "key_fingerprint": k.fingerprint})
    assert r.status_code == 200, r.text
    return json.loads(payload)


# ---- passwords -------------------------------------------------------------------

def test_owners_cannot_set_someone_elses_password(env):
    c, _ = env
    _, _, rita = setup(c)
    r = c.patch(f"/people/{rita}", json={"password": NEW})
    assert r.status_code == 422 and "set-password" in r.json()["detail"]
    assert c.patch(f"/people/{rita}", json={"name": "Rita", "unknown": 1}).status_code == 422
    assert c.patch(f"/people/{rita}", json={"name": "Rita R."}).status_code == 200   # the rest still works
    c.cookies.clear()
    assert c.post("/auth/login", json={"email": "rita@lab.test", "password": NEW}).status_code == 401
    sign_in(c, "rita@lab.test")


def test_own_password_change_needs_the_current_one_and_ends_other_sessions(env):
    c, _ = env
    setup(c)
    other = TestClient(app)                       # Rita's second browser
    sign_in(other, "rita@lab.test")
    sign_in(c, "rita@lab.test")
    assert c.get("/auth/me").json()["password_chosen"] is False
    r = c.post("/auth/password", json={"current_password": "not my password", "new_password": NEW})
    assert r.status_code == 403
    assert c.post("/auth/password", json={"current_password": PW, "new_password": "short"}).status_code == 422
    assert c.post("/auth/password", json={"current_password": PW, "new_password": NEW}).status_code == 200
    assert c.get("/auth/me").json()["password_chosen"] is True        # this session stays
    assert other.get("/auth/me").status_code == 401                    # every other one ends
    c.cookies.clear()
    assert c.post("/auth/login", json={"email": "rita@lab.test", "password": PW}).status_code == 401
    sign_in(c, "rita@lab.test", NEW)


def test_password_change_is_for_people_and_counts_failures(env, monkeypatch):
    c, _ = env
    setup(c)
    sign_in(c, "rita@lab.test")
    for _ in range(auth.LOCKOUT_FAILURES):
        c.post("/auth/password", json={"current_password": "guess guess guess", "new_password": NEW})
    assert c.post("/auth/password", json={"current_password": PW, "new_password": NEW}).status_code == 429
    monkeypatch.setenv("ATTACKLEDGER_API_TOKEN", "tok-1")
    r = c.post("/auth/password", headers={"authorization": "Bearer tok-1"},
               json={"current_password": PW, "new_password": NEW})
    assert r.status_code == 422


def test_disabling_a_person_ends_their_sessions(env):
    c, _ = env
    _, _, rita = setup(c)
    other = TestClient(app)
    sign_in(other, "rita@lab.test")
    assert c.patch(f"/people/{rita}", json={"disabled": True}).status_code == 200
    assert c.patch(f"/people/{rita}", json={"disabled": False}).status_code == 200
    assert other.get("/auth/me").status_code == 401          # gone, not just paused


def test_operator_reset_and_revoke_on_the_server(env, monkeypatch, capsys):
    c, Session = env
    setup(c)
    sign_in(c, "rita@lab.test")
    c.post("/auth/password", json={"current_password": PW, "new_password": NEW})
    k = register(c)
    monkeypatch.setenv("ATTACKLEDGER_NEW_PASSWORD", PW)
    assert people.main(["set-password", "--email", "rita@lab.test"]) == 0
    assert PW not in capsys.readouterr().out
    assert c.get("/auth/me").status_code == 401                      # signed out everywhere
    me = sign_in(c, "rita@lab.test", PW)
    assert c.get("/auth/me").json()["password_chosen"] is False      # the operator knows this one
    assert people.main(["revoke-key", "--email", "rita@lab.test", "--fingerprint", k.fingerprint[:4]]) == 1
    assert people.main(["revoke-key", "--email", "rita@lab.test", "--fingerprint", k.fingerprint[:12]]) == 0
    with Session() as s:
        last = s.scalars(select(KeyLogEntry).order_by(KeyLogEntry.seq.desc())).first()
        assert (last.event, last.via, last.key_fingerprint) == ("revoked", "operator_cli", k.fingerprint)
    assert people.main(["key-log"]) == 0 and "intact" in capsys.readouterr().out
    assert me["key_notice"]["events"][0]["key_fingerprint"] == k.fingerprint


# ---- the key log ------------------------------------------------------------------

def test_key_log_chains_every_registration_and_revocation(env):
    c, Session = env
    setup(c)
    sign_in(c, "rita@lab.test")
    k1 = register(c)
    c.post("/auth/password", json={"current_password": PW, "new_password": NEW})
    k2 = register(c, "ECDSA-P256")
    assert c.post(f"/auth/keys/{k1.id}/revoke").status_code == 200
    assert c.post(f"/auth/keys/{k1.id}/revoke").status_code == 200   # once in the log, not twice
    with Session() as s:
        rows = list(s.scalars(select(KeyLogEntry).order_by(KeyLogEntry.seq)))
        assert [(e.seq, e.event, e.key_fingerprint, e.via) for e in rows] == [
            (1, "registered", k1.fingerprint, "assigned_password"),
            (2, "registered", k2.fingerprint, "own_session"),
            (3, "revoked", k1.fingerprint, "own_session")]
        assert rows[0].prev_hash == keylog.GENESIS and rows[1].prev_hash == rows[0].entry_hash
        assert rows[0].user_name == "Rita Reviewer" and keylog.verify(s) == []

        # Someone with database access edits an entry, or removes one.
        s.execute(text("UPDATE key_log SET user_name = 'Ray' WHERE seq = 1"))
        s.commit()
        s.expire_all()
        assert any("record hash" in p for p in keylog.verify(s))
        s.execute(text("UPDATE key_log SET user_name = 'Rita Reviewer' WHERE seq = 1"))
        s.execute(text("DELETE FROM key_log WHERE seq = 2"))
        s.commit()
        s.expire_all()
        problems = keylog.verify(s)
        assert any("out of order" in p for p in problems) and any("link" in p for p in problems)


def test_notice_lists_key_changes_since_the_previous_sign_in(env):
    c, _ = env
    _, _, rita = setup(c)
    first = sign_in(c, "rita@lab.test")
    assert first["key_notice"] == {"since": None, "events": []}
    k = register(c)
    me = c.get("/auth/me").json()["key_notice"]           # this session's own key shows too
    assert [e["key_fingerprint"] for e in me["events"]] == [k.fingerprint]

    again = sign_in(c, "rita@lab.test")["key_notice"]      # registered after the previous sign-in
    assert again["since"] is not None
    assert [(e["event"], e["key_fingerprint"], e["key_id"], e["key_revoked"]) for e in again["events"]] == [
        ("registered", k.fingerprint, k.id, False)]
    assert again["events"][0]["at"].endswith("+00:00")
    assert sign_in(c, "rita@lab.test")["key_notice"]["events"] == []     # nothing new since

    c.post(f"/auth/keys/{k.id}/revoke")
    notice = sign_in(c, "rita@lab.test")["key_notice"]
    assert [(e["event"], e["key_revoked"]) for e in notice["events"]] == [("revoked", True)]
    sign_in(c, "owner@lab.test")
    assert c.get("/auth/me").json()["key_notice"]["events"] == []          # only your own keys


# ---- reports -----------------------------------------------------------------

def rechain(report):
    """Recompute every key log hash in a report, as someone rewriting it would."""
    log = report["key_log"]
    recs = {e["seq"]: e for e in log["entries"]}
    prev = log["links"][0]["prev_hash"]
    for ln in log["links"]:
        if ln["seq"] in recs:
            ln["record_sha256"] = verifier.sha(verifier.canonical({k: recs[ln["seq"]][k] for k in verifier.KEY_LOG_FIELDS}))
        ln["prev_hash"] = prev
        ln["entry_hash"] = prev = verifier.sha(prev + ln["record_sha256"])
    log["head"] = {"seq": log["links"][-1]["seq"], "entry_hash": prev}
    return report


def signed_report(c):
    e, lane, rita = setup(c)
    sign_in(c, "rita@lab.test")
    c.post("/auth/password", json={"current_password": PW, "new_password": NEW})
    k = register(c)
    register(c, "ECDSA-P256")             # another key: only its hashes go in the report
    payload = signed_close(c, lane, k)
    c.post(f"/auth/keys/{k.id}/revoke")
    return c.get(f"/engagements/{e}/report").json(), k, payload, rita


def test_report_carries_the_signing_keys_history(env, tmp_path):
    c, _ = env
    report, k, payload, rita = signed_report(c)
    log = report["key_log"]
    assert [(x["event"], x["key_fingerprint"]) for x in log["entries"]] == [
        ("registered", k.fingerprint), ("revoked", k.fingerprint)]
    assert [x["seq"] for x in log["links"]] == [1, 2, 3] and log["head"]["seq"] == 3
    assert verifier.check_body(report) == []
    problems, notes = verifier.check_key_log(report)
    assert problems == []
    assert any(n.startswith(f"Rita Reviewer (rita@lab.test) signed with key {k.fingerprint[:16]}, registered ")
               and "from their own session" in n and "revoked" in n for n in notes), notes
    path = tmp_path / "r.json"
    path.write_text(json.dumps(report))
    assert verifier.main(["verify_report.py", str(path)]) == 0
    page = c.get(f"/engagements/{report['engagement']['id']}/report.html").text
    assert "registered" in page[page.index('id="receipts"'):page.index('id="verify"')]


def test_verifier_flags_bad_key_history(env):
    c, _ = env
    report, k, payload, rita = signed_report(c)
    issued = payload["issued_at"]

    def problems(change, chain=True):
        bad = copy.deepcopy(report)
        change(bad["key_log"])
        return verifier.check_key_log(rechain(bad) if chain else bad)[0]

    def entry(log, event):
        return next(x for x in log["entries"] if x["event"] == event)

    # Registered after the payload was issued, even with every hash redone.
    assert any("registered after" in p for p in problems(lambda log: entry(log, "registered").update(at="2099-01-01T00:00:00+00:00")))
    # Revoked before it was issued.
    assert any("revoked before the receipt" in p for p in problems(lambda log: entry(log, "revoked").update(at="2000-01-01T00:00:00+00:00")))
    # Registered to someone else.
    assert any("registered to" in p for p in problems(lambda log: entry(log, "registered").update(user_id=rita + 99)))
    # No registration at all.
    assert any("no registration" in p for p in problems(lambda log: log.update(entries=[entry(log, "revoked")])))
    # Changed without redoing the hashes; a broken link; a head that is not the last link.
    assert any("record hash" in p for p in problems(lambda log: entry(log, "registered").update(user_name="Ray"), chain=False))
    assert any("does not link" in p for p in problems(lambda log: log["links"][-1].update(prev_hash="f" * 64), chain=False))
    assert any("chain hash" in p for p in problems(lambda log: log["links"][0].update(entry_hash="e" * 64), chain=False))
    assert any("head" in p for p in problems(lambda log: log["head"].update(seq=99), chain=False))
    assert any("out of sequence" in p for p in problems(lambda log: log["links"].pop(1) and None))
    assert any("genesis" in p for p in problems(lambda log: log["links"][0].update(prev_hash="1" * 64)))
    # An entry the links do not cover.
    assert any("not in the chain" in p for p in problems(lambda log: log.update(links=log["links"][1:]), chain=False))
    # A revocation dated before the registration it follows in the chain.
    assert any("dated before" in p for p in problems(lambda log: entry(log, "revoked").update(at="2001-01-01T00:00:00+00:00")))
    # Within the payload's issue second is fine: issue times are whole seconds.
    for at in (issued, issued.replace("+00:00", ".900000+00:00")):
        assert not any("registered after" in p for p in problems(lambda log: entry(log, "registered").update(at=at)))

    # A report from before the key log still verifies, with a note.
    old = copy.deepcopy(report)
    del old["key_log"]
    found, notes = verifier.check_key_log(old)
    assert found == [] and any("no key history" in n for n in notes)


def test_unsigned_reports_have_no_key_log(env):
    c, _ = env
    e, lane, _ = setup(c)
    assert c.post(f"/lanes/{lane}/close", json={"reviewed": True}).status_code == 200
    report = c.get(f"/engagements/{e}/report").json()
    assert "key_log" not in report and verifier.check_key_log(report) == ([], [])


# ---- the migration backfills keys that already exist ------------------------------

def test_migration_backfills_existing_keys(tmp_path, monkeypatch):
    eng = create_engine(f"sqlite:///{tmp_path / 'al.db'}")
    monkeypatch.setattr(db, "engine", eng)
    monkeypatch.setattr(migrate, "engine", eng)
    command.upgrade(migrate._config(), "0012")
    fp1, fp2 = hashlib.sha256(b"one").hexdigest(), hashlib.sha256(b"two").hexdigest()
    with eng.begin() as conn:
        conn.execute(text("INSERT INTO users (id, email, name, password_hash, is_owner, disabled, created_at) "
                          "VALUES (1, 'r@lab.test', 'Rita', 'x', 0, 0, '2026-10-01 09:00:00')"))
        conn.execute(text("INSERT INTO signing_keys (user_id, algorithm, public_key, fingerprint, created_at, revoked_at) "
                          "VALUES (1, 'Ed25519', 'AA==', :a, '2026-10-01 10:00:00.250000', '2026-10-03 08:00:00'),"
                          "       (1, 'Ed25519', 'AQ==', :b, '2026-10-02 10:00:00', NULL)"), {"a": fp1, "b": fp2})
    migrate.upgrade_head()
    with sessionmaker(bind=eng)() as s:
        rows = list(s.scalars(select(KeyLogEntry).order_by(KeyLogEntry.seq)))
        assert [(e.event, e.key_fingerprint, e.at, e.via) for e in rows] == [
            ("registered", fp1, "2026-10-01T10:00:00.250000+00:00", "backfill"),
            ("registered", fp2, "2026-10-02T10:00:00.000000+00:00", "backfill"),
            ("revoked", fp1, "2026-10-03T08:00:00.000000+00:00", "backfill")]
        assert keylog.verify(s) == []
        assert s.get(User, 1).password_chosen is False
