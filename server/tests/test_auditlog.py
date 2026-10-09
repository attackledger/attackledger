"""The audit log (D-037): every administrative change is one hash-chained entry, written
with the change; receipts name the signer's email (payload v3); reports carry the history
and the verifier checks each signer's role and name at the time of the receipt."""
import copy
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite://")
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "server"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from alembic import command
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

from app import auditlog, db, migrate, people, signing
from app.models import AuditEntry
from test_keytrust import NEW, PW, env, register, sign_in, signed_close  # noqa: F401  (env is a fixture)
from test_signing import verifier

CSV = "identifier,asset_type,eligible_for_submission\nshop.lab.test,URL,true\nold.lab.test,URL,false\n"


def entries(Session, action=None):
    with Session() as s:
        q = select(AuditEntry).order_by(AuditEntry.seq)
        return [auditlog.record(e) for e in s.scalars(q) if action is None or e.action == action]


def setup(c):
    """Olive (owner) adds Rita (tester and reviewer) and Vic (viewer) to an engagement with one lane."""
    c.post("/people", json={"email": "owner@lab.test", "name": "Olive Owner", "password": PW, "is_owner": True})
    sign_in(c, "owner@lab.test")
    ids = {n: c.post("/people", json={"email": f"{n}@lab.test", "name": f"{n.title()} {s}", "password": PW}).json()["id"]
           for n, s in (("rita", "Reviewer"), ("vic", "Viewer"))}
    e = c.post("/engagements", json={"name": "Audit"}).json()["id"]
    c.put(f"/engagements/{e}/members", json={"members": [{"user_id": ids["rita"], "roles": ["tester", "reviewer"]},
                                                         {"user_id": ids["vic"], "roles": ["viewer"]}]})
    a = c.post(f"/engagements/{e}/assets", json={"host": "shop.lab.test"}).json()["id"]
    lane = c.post("/lanes", json={"asset_id": a, "role": "recon"}).json()
    for it in lane["items"]:
        c.patch(f"/lanes/{lane['id']}/items/{it['idx']}", json={"state": "na", "na_reason": "lab"})
    return e, lane["id"], ids


OLIVE = {"kind": "person", "user_id": 1, "name": "Olive Owner", "email": "owner@lab.test"}


# ---- each action writes one entry ---------------------------------------------------

def test_people_and_engagement_actions_write_one_entry_each(env):
    c, Session = env
    e, _, ids = setup(c)
    rita = ids["rita"]
    log = entries(Session)
    assert [x["action"] for x in log] == ["person.created"] * 3 + ["engagement.created", "members.updated"]
    created = log[1]
    assert created["actor"] == OLIVE and created["subject_id"] == rita
    assert created["change"] == {"person": {"id": rita, "name": "Rita Reviewer", "email": "rita@lab.test"},
                                 "after": {"email": "rita@lab.test", "name": "Rita Reviewer", "is_owner": False,
                                           "disabled": False}, "password": "assigned"}
    assert PW not in json.dumps(log)
    assert log[3]["engagement_id"] == e and log[3]["change"]["after"]["name"] == "Audit"
    assert log[4]["change"]["before"] == [] and [(m["user_id"], m["roles"]) for m in log[4]["change"]["after"]] == [
        (rita, ["reviewer", "tester"]), (ids["vic"], ["viewer"])]

    # Each change is one entry; saving the same values again is none.
    n = len(log)
    c.patch(f"/people/{rita}", json={"name": "Rita R. Reviewer", "is_owner": True})
    c.patch(f"/people/{rita}", json={"is_owner": False, "disabled": True})
    c.patch(f"/people/{rita}", json={"disabled": False, "name": "Rita R. Reviewer"})
    c.patch(f"/engagements/{e}", json={"separation_of_duties": True})
    c.patch(f"/engagements/{e}", json={"separation_of_duties": True, "require_signatures": False})
    c.put(f"/engagements/{e}/members", json={"members": [{"user_id": rita, "roles": ["reviewer"]},
                                                         {"user_id": ids["vic"], "roles": ["viewer"]}]})
    c.put(f"/engagements/{e}/members", json={"members": [{"user_id": rita, "roles": ["reviewer"]},
                                                         {"user_id": ids["vic"], "roles": ["viewer"]}]})
    new = entries(Session)[n:]
    assert [(x["action"], x["change"].get("before"), x["change"].get("after")) for x in new[:6]] == [
        ("person.renamed", {"name": "Rita Reviewer"}, {"name": "Rita R. Reviewer"}),
        ("person.owner", {"is_owner": False}, {"is_owner": True}),
        ("person.owner", {"is_owner": True}, {"is_owner": False}),
        ("person.disabled", {"disabled": False}, {"disabled": True}),
        ("person.enabled", {"disabled": True}, {"disabled": False}),
        ("engagement.settings", {"separation_of_duties": False, "require_signatures": False, "redact_evidence": True},
         {"separation_of_duties": True, "require_signatures": False, "redact_evidence": True})]
    assert [x["action"] for x in new] == [x["action"] for x in new[:6]] + ["members.updated"]
    assert new[-1]["change"]["after"][0] == {"user_id": rita, "name": "Rita R. Reviewer", "email": "rita@lab.test",
                                             "roles": ["reviewer"]}
    assert all(x["actor"] == OLIVE and x["subject_id"] in (rita, None) for x in new)
    assert "Renamed Rita Reviewer to Rita R. Reviewer" in auditlog.describe(new[0])
    assert "Turned separation of duties on" == auditlog.describe(new[5])

    # Refused changes write nothing.
    n = len(entries(Session))
    assert c.post("/people", json={"email": "rita@lab.test", "name": "Again", "password": PW}).status_code == 409
    assert c.post("/engagements", json={"name": "Audit"}).status_code == 409
    assert c.patch(f"/people/{rita}", json={"password": NEW}).status_code == 422
    assert c.patch("/people/1", json={"is_owner": False}).status_code == 422          # the last owner
    assert len(entries(Session)) == n


def test_scope_authorization_and_import_entries(env):
    c, Session = env
    e, _, _ = setup(c)
    n = len(entries(Session))
    rules = {"include": ["*.lab.test", "api.lab.test"], "exclude": ["old.lab.test"], "rate_limit_rps": 3,
             "research_header": "X-Research: olive", "research_user_agent": "olive-test", "crawl_depth": 2,
             "enabled_modules": ["ports"]}
    assert c.put(f"/engagements/{e}/scope", json=rules).status_code == 200
    assert c.put(f"/engagements/{e}/scope", json=rules).status_code == 200                   # unchanged: no entry
    assert c.post(f"/engagements/{e}/attest", json={"operator": "Olive", "policy_url": "https://example.com/sow",
                                                    "confirm": True}).status_code == 200
    assert c.post(f"/engagements/{e}/scope/import", json={"csv": CSV}).status_code == 200    # preview: no entry
    assert c.post(f"/engagements/{e}/scope/import", json={"csv": CSV, "apply": True, "mode": "replace"}).status_code == 200
    scope, auth_, imported = entries(Session)[n:]
    assert scope["action"] == "scope.updated" and scope["engagement_id"] == e
    assert scope["change"]["before"] == {"include": [], "exclude": [], "rate_limit_rps": 5, "research_header": None,
                                         "research_user_agent": None, "enabled_modules": [], "crawl_depth": 3}
    assert scope["change"]["after"] == {"include": ["*.lab.test", "api.lab.test"], "exclude": ["old.lab.test"],
                                        "rate_limit_rps": 3, "research_header": "X-Research: olive",
                                        "research_user_agent": "olive-test", "enabled_modules": ["ports"],
                                        "crawl_depth": 2}
    assert scope["change"]["hosts_added"] == ["api.lab.test"]
    assert auth_["action"] == "engagement.authorized" and auth_["change"]["before"]["authorized_by"] is None
    assert auth_["change"]["after"]["authorized_by"] == "Olive" and auth_["change"]["after"]["authorized_at"]
    assert imported["change"]["import"] == "replace"
    assert imported["change"]["after"]["include"] == ["shop.lab.test"]
    assert imported["change"]["after"]["exclude"] == ["old.lab.test"]
    text_ = auditlog.describe(scope)
    assert "rate limit 3 requests per second (was 5 requests per second)" in text_ and "added hosts api.lab.test" in text_


def test_password_events_and_the_operator_cli(env, monkeypatch, capsys):
    c, Session = env
    _, _, ids = setup(c)
    sign_in(c, "rita@lab.test")
    assert c.post("/auth/password", json={"current_password": PW, "new_password": NEW}).status_code == 200
    monkeypatch.setenv("ATTACKLEDGER_NEW_PASSWORD", PW)
    assert people.main(["set-password", "--email", "rita@lab.test"]) == 0
    assert people.main(["create", "--email", "cli@lab.test", "--name", "Cli Person"]) == 0
    changed, reset, created = entries(Session)[-3:]
    assert changed["action"] == "person.password_changed" and changed["actor"]["email"] == "rita@lab.test"
    assert (reset["action"], reset["actor"], reset["subject_id"]) == ("person.password_reset", auditlog.CLI, ids["rita"])
    assert created["action"] == "person.created" and created["actor"]["kind"] == "cli"
    log = json.dumps(entries(Session))
    assert PW not in log and NEW not in log
    capsys.readouterr()
    assert people.main(["audit-log"]) == 0
    out = capsys.readouterr().out
    assert "audit log chain: intact" in out and "person.password_reset" in out and PW not in out


def test_token_and_open_mode_actors(env, monkeypatch):
    c, Session = env
    assert c.post("/engagements", json={"name": "Open"}).status_code == 201
    monkeypatch.setenv("ATTACKLEDGER_API_TOKEN", "tok-1")
    h = {"authorization": "Bearer tok-1"}
    assert c.post("/engagements", headers=h, json={"name": "Token"}).status_code == 201
    assert [x["actor"]["kind"] for x in entries(Session)] == ["open", "token"]
    assert auditlog.actor_label(entries(Session)[1]["actor"]) == "the operator token"


# ---- the chain -------------------------------------------------------------------

def test_chain_detects_edits_deletions_and_reordering(env, capsys):
    c, Session = env
    setup(c)
    with Session() as s:
        assert auditlog.verify(s) == []
        rows = list(s.scalars(select(AuditEntry).order_by(AuditEntry.seq)))
        assert rows[0].prev_hash == auditlog.GENESIS and rows[1].prev_hash == rows[0].entry_hash

        def problems(*sql):
            for q in sql:
                s.execute(text(q))
            s.commit()
            s.expire_all()
            return auditlog.verify(s)
        # An edited change, an edited actor, then put back.
        assert any("record hash" in p for p in problems(
            "UPDATE audit_log SET change = replace(change, '\"tester\"', '\"owner\"') WHERE action = 'members.updated'"))
        assert any("record hash" in p for p in problems(
            "UPDATE audit_log SET change = replace(change, '\"owner\"', '\"tester\"') WHERE action = 'members.updated'",
            "UPDATE audit_log SET actor_name = 'Someone Else' WHERE seq = 2"))
        assert problems("UPDATE audit_log SET actor_name = 'Olive Owner' WHERE seq = 2") == []
        # Two entries swapped.
        swapped = problems("UPDATE audit_log SET seq = 99 WHERE seq = 2", "UPDATE audit_log SET seq = 2 WHERE seq = 3",
                           "UPDATE audit_log SET seq = 3 WHERE seq = 99")
        assert any("link" in p for p in swapped) and any("record hash" in p for p in swapped)
        problems("UPDATE audit_log SET seq = 99 WHERE seq = 2", "UPDATE audit_log SET seq = 2 WHERE seq = 3",
                 "UPDATE audit_log SET seq = 3 WHERE seq = 99")
        # One removed.
        gone = problems("DELETE FROM audit_log WHERE seq = 3")
        assert any("out of order" in p for p in gone) and any("link" in p for p in gone)
    capsys.readouterr()
    assert people.main(["audit-log"]) == 1 and "audit log chain: broken" in capsys.readouterr().out


# ---- reading it ------------------------------------------------------------------

def test_engagement_history_is_readable_by_every_role_and_the_whole_log_by_owners(env):
    c, Session = env
    e, _, ids = setup(c)
    other = c.post("/engagements", json={"name": "Other"}).json()["id"]
    c.post("/people", json={"email": "out@lab.test", "name": "Outside", "password": PW})
    c.patch(f"/people/{ids['vic']}", json={"name": "Vic V. Viewer"})
    sign_in(c, "vic@lab.test")
    r = c.get(f"/engagements/{e}/audit")
    assert r.status_code == 200 and r.json()["chain"]["intact"] is True
    rows = r.json()["entries"]
    assert {x["engagement_id"] for x in rows} == {e, None}
    assert {x["subject_id"] for x in rows if x["subject_id"]} == {ids["rita"], ids["vic"]}     # members only
    assert any(x["text"] == "Renamed Vic Viewer to Vic V. Viewer (vic@lab.test)" for x in rows)
    assert all(x["actor_label"] == "Olive Owner (owner@lab.test)" for x in rows)
    assert c.get(f"/engagements/{other}/audit").status_code == 404
    assert c.get("/audit").status_code == 403
    sign_in(c, "owner@lab.test")
    everything = c.get("/audit").json()
    assert [x["seq"] for x in everything["entries"]] == list(range(1, len(entries(Session)) + 1))


# ---- payload v3 ------------------------------------------------------------------

def test_payload_v3_names_the_email_and_old_formats_are_refused(env):
    c, _ = env
    e, lane, ids = setup(c)
    sign_in(c, "rita@lab.test")
    k = register(c)
    payload = c.get(f"/lanes/{lane}/receipt-payload", params={"key": k.fingerprint}).json()["payload"]
    p = json.loads(payload)
    assert p["format"] == "attackledger-receipt-v3"
    assert p["signer"] == {"id": ids["rita"], "name": "Rita Reviewer", "email": "rita@lab.test"}

    def close(text_):
        return c.post(f"/lanes/{lane}/close", json={"reviewed": True, "payload": text_, "signature": k.sign(text_),
                                                    "key_fingerprint": k.fingerprint})
    v2 = {**p, "format": "attackledger-receipt-v2", "signer": {"id": p["signer"]["id"], "name": p["signer"]["name"]}}
    r = close(json.dumps(v2, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    assert r.status_code == 422 and "another format" in r.json()["detail"]
    other = {**p, "signer": {**p["signer"], "email": "olive@lab.test"}}
    r = close(signing.payload_for(**{**_fields(other)}))
    assert r.status_code == 422 and "another signer" in r.json()["detail"]
    # Renamed after the payload was issued: ask for a new one.
    sign_in(c, "owner@lab.test")
    c.patch(f"/people/{ids['rita']}", json={"name": "Rita Renamed"})
    sign_in(c, "rita@lab.test")
    assert "another signer" in close(payload).json()["detail"]
    assert signed_close(c, lane, k)["signer"]["name"] == "Rita Renamed"
    view = c.get(f"/lanes/{lane}").json()["receipt"]
    assert view["closed_by"] == "Rita Renamed" and view["closed_by_email"] == "rita@lab.test"


def _fields(p):
    return {"engagement_id": p["engagement"]["id"], "engagement_name": p["engagement"]["name"],
            "lane_id": p["lane"]["id"], "host": p["lane"]["host"], "role": p["lane"]["role"],
            "manifest_sha256": p["manifest_sha256"], "chain_seq": p["chain"]["seq"], "chain_head": p["chain"]["head"],
            "signer_id": p["signer"]["id"], "signer_name": p["signer"]["name"], "signer_email": p["signer"]["email"],
            "key_fingerprint": p["key_fingerprint"], "issued_at": p["issued_at"]}


# ---- reports and the verifier -------------------------------------------------------

def rechain(report):
    """Recompute every audit log hash in a report, as someone rewriting it would."""
    log = report["audit_log"]
    recs = {e["seq"]: e for e in log["entries"]}
    prev = log["links"][0]["prev_hash"]
    for ln in log["links"]:
        if ln["seq"] in recs:
            ln["record_sha256"] = verifier.sha(verifier.canonical({k: recs[ln["seq"]][k] for k in verifier.AUDIT_FIELDS}))
        ln["prev_hash"] = prev
        ln["entry_hash"] = prev = verifier.sha(prev + ln["record_sha256"])
    log["head"] = {"seq": log["links"][-1]["seq"], "entry_hash": prev}
    return report


def signed_report(c):
    e, lane, ids = setup(c)
    c.put(f"/engagements/{e}/scope", json={"include": ["*.lab.test"], "rate_limit_rps": 2})
    c.post("/people", json={"email": "out@lab.test", "name": "Outside", "password": PW})   # not in this report
    sign_in(c, "rita@lab.test")
    k = register(c)
    payload = signed_close(c, lane, k)
    # Afterwards: renamed and no longer a reviewer. Neither changes what the receipt proves.
    sign_in(c, "owner@lab.test")
    c.patch(f"/people/{ids['rita']}", json={"name": "Rita Later"})
    c.put(f"/engagements/{e}/members", json={"members": [{"user_id": ids["vic"], "roles": ["viewer"]}]})
    return c.get(f"/engagements/{e}/report").json(), payload, ids


def test_report_carries_the_history_and_a_rename_changes_nothing_it_proves(env, tmp_path):
    c, Session = env
    report, payload, ids = signed_report(c)
    log = report["audit_log"]
    assert {x["subject_id"] for x in log["entries"] if x["subject_id"]} == {ids["rita"], ids["vic"]}
    assert "Outside" not in json.dumps(log["entries"])
    assert len(log["links"]) == len(entries(Session)) - log["links"][0]["seq"] + 1
    assert verifier.check_body(report) == []
    problems, notes = verifier.check_audit_log(report)
    assert problems == [], problems
    note = next(n for n in notes if n.startswith("shop.lab.test / "))
    assert "Rita Reviewer (rita@lab.test) held the reviewer role, given " in note and "by Olive Owner" in note
    assert "in scope *.lab.test; out of scope none; 2 requests per second" in note
    assert payload["signer"] == {"id": ids["rita"], "name": "Rita Reviewer", "email": "rita@lab.test"}
    sig_problems, sig_notes = verifier.check_signatures(report)
    assert sig_problems == [] and any("signed by Rita Reviewer (rita@lab.test)" in n for n in sig_notes)
    path = tmp_path / "r.json"
    path.write_text(json.dumps(report))
    assert verifier.main(["verify_report.py", str(path)]) == 0

    page = c.get(f"/engagements/{report['engagement']['id']}/report.html").text
    assert page.index('id="receipts"') < page.index('id="history"') < page.index('id="verify"')
    history = page[page.index('id="history"'):page.index('id="verify"')]
    assert "Renamed Rita Reviewer to Rita Later" in history and "Changed the roles" in history
    assert "Olive Owner (owner@lab.test)" in history
    receipts = page[page.index('id="receipts"'):page.index('id="history"')]
    assert "rita@lab.test" in receipts
    assert "<td>Change history</td>" in page[page.index('id="verify"'):]


def test_verifier_flags_a_signer_without_the_role_or_with_another_name(env):
    c, _ = env
    report, _, ids = signed_report(c)
    rita = ids["rita"]

    def problems(change, chain=True):
        bad = copy.deepcopy(report)
        change(bad["audit_log"])
        return verifier.check_audit_log(rechain(bad) if chain else bad)[0]

    def first(log, action, **match):
        return next(x for x in log["entries"] if x["action"] == action
                    and all(x.get(k) == v for k, v in match.items()))

    def demote(log):            # the role change that gave Rita "reviewer" gave only "tester"
        for m in first(log, "members.updated")["change"]["after"]:
            if m["user_id"] == rita:
                m["roles"] = ["tester"]
    assert any("did not hold the reviewer role" in p for p in problems(demote))
    # The same, but she was an owner then: owners may sign any receipt.
    owner = copy.deepcopy(report)
    demote(owner["audit_log"])
    first(owner["audit_log"], "person.created", subject_id=rita)["change"]["after"]["is_owner"] = True
    found, notes = verifier.check_audit_log(rechain(owner))
    assert found == [] and any("was an owner" in n for n in notes)
    # Another name, or another email, in the log at that time.
    assert any("names them Ray at that time" in p for p in problems(
        lambda log: first(log, "person.created", subject_id=rita)["change"]["after"].update(name="Ray")))
    assert any("email" in p for p in problems(
        lambda log: first(log, "person.created", subject_id=rita)["change"]["after"].update(email="ray@lab.test")))
    # The rename moved before the receipt, and the account disabled then.
    renamed = lambda log: first(log, "person.renamed", subject_id=rita)  # noqa: E731
    assert any("names them Rita Later" in p for p in problems(
        lambda log: renamed(log).update(at=first(log, "members.updated")["at"])))
    assert any("disabled" in p for p in problems(
        lambda log: first(log, "person.created", subject_id=rita)["change"]["after"].update(disabled=True)))
    # No record of the signer at all.
    assert any("no record of the signer" in p for p in problems(
        lambda log: log.update(entries=[x for x in log["entries"] if x["subject_id"] != rita])))
    # Tampering without redoing the hashes, and a broken link.
    assert any("record hash" in p for p in problems(demote, chain=False))
    assert any("does not link" in p for p in problems(lambda log: log["links"][-1].update(prev_hash="f" * 64),
                                                         chain=False))
    assert any("dated before" in p for p in problems(lambda log: renamed(log).update(at="2001-01-01T00:00:00+00:00")))


def test_unsigned_receipts_are_checked_too(env):
    c, _ = env
    e, lane, ids = setup(c)
    sign_in(c, "rita@lab.test")
    assert c.post(f"/lanes/{lane}/close", json={"reviewed": True}).status_code == 200
    report = c.get(f"/engagements/{e}/report").json()
    rc = report["lanes"][0]["receipt"]
    assert (rc["closed_by"], rc["closed_by_user"], rc["closed_by_email"]) == ("Rita Reviewer", ids["rita"], "rita@lab.test")
    assert verifier.check_audit_log(report)[0] == []
    bad = copy.deepcopy(report)
    bad["lanes"][0]["receipt"]["closed_by"] = "Rita Other"
    assert any("names the signer Rita Other" in p for p in verifier.check_audit_log(bad)[0])


def test_old_reports_and_v2_receipts_still_verify(env, tmp_path):
    c, _ = env
    e, lane, ids = setup(c)
    sign_in(c, "rita@lab.test")
    k = register(c)
    signed_close(c, lane, k)
    report = c.get(f"/engagements/{e}/report").json()

    # A receipt signed before v3: the payload had no email.
    old = copy.deepcopy(report)
    sig = old["lanes"][0]["receipt"]["signature"]
    p = json.loads(sig["payload"])
    p["format"], p["signer"] = "attackledger-receipt-v2", {"id": p["signer"]["id"], "name": p["signer"]["name"]}
    sig["payload"] = json.dumps(p, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    sig["value"] = k.sign(sig["payload"])
    assert verifier.check_signatures(old) == ([], [f"shop.lab.test / {report['lanes'][0]['name']}: signed by "
                                                   f"Rita Reviewer with key {k.fingerprint[:16]} (Ed25519)"])
    assert verifier.check_audit_log(old)[0] == []
    # A v3 payload without the email is refused.
    p3 = json.loads(report["lanes"][0]["receipt"]["signature"]["payload"])
    del p3["signer"]["email"]
    bad = copy.deepcopy(report)
    bad["lanes"][0]["receipt"]["signature"]["payload"] = json.dumps(p3)
    assert any("email" in x for x in verifier.check_signatures(bad)[0])

    # A report from before the audit log: a note, no failure.
    del old["audit_log"]
    del old["integrity"]
    old["integrity"] = {"algorithm": "sha256", "body_sha256": verifier.sha(verifier.canonical(old)),
                        "chain_genesis": verifier.GENESIS}
    found, notes = verifier.check_audit_log(old)
    assert found == [] and any("no change history" in n for n in notes)
    path = tmp_path / "old.json"
    path.write_text(json.dumps(old))
    assert verifier.main(["verify_report.py", str(path)]) == 0
    # The published sample report, made before either change.
    assert verifier.main(["verify_report.py", str(ROOT / "site" / "sample-report.json")]) == 0

    # A receipt issued before the log covered its engagement: a note, not a problem.
    early = copy.deepcopy(report)
    first = min(x["at"] for x in early["audit_log"]["entries"] if x["engagement_id"] == e)
    early["lanes"][0]["receipt"]["issued_at"] = (datetime.fromisoformat(first) - timedelta(days=1)).isoformat()
    found, notes = verifier.check_audit_log(early)
    assert found == [] and any("before the audit log covered" in n for n in notes)


# ---- the migration records what exists ------------------------------------------------

def test_migration_backfills_people_engagements_and_roles(tmp_path, monkeypatch):
    eng = create_engine(f"sqlite:///{tmp_path / 'al.db'}")
    monkeypatch.setattr(db, "engine", eng)
    monkeypatch.setattr(migrate, "engine", eng)
    command.upgrade(migrate._config(), "0014")
    with eng.begin() as conn:
        conn.execute(text("INSERT INTO users (id, email, name, password_hash, is_owner, disabled, password_chosen, created_at) "
                          "VALUES (1, 'o@lab.test', 'Olive', 'x', 1, 0, 0, '2026-10-01 09:00:00'),"
                          "       (2, 'r@lab.test', 'Rita', 'x', 0, 1, 0, '2026-10-01 09:00:00')"))
        conn.execute(text("INSERT INTO engagements (id, name, pack_id, engagement_type, created_at, scope_include, "
                          "scope_exclude, rate_limit_rps, enabled_modules, crawl_depth, separation_of_duties, "
                          "require_signatures, authorized_by, authorized_at, policy_url) VALUES (7, 'Old', 'bug-bounty', "
                          "'bug_bounty', '2026-10-01 09:00:00', '[\"*.lab.test\"]', '[]', 4, '[]', 3, 1, 0, 'Olive', "
                          "'2026-10-02 10:00:00', 'https://example.com/p')"))
        conn.execute(text("INSERT INTO memberships (engagement_id, user_id, roles) VALUES (7, 2, '[\"reviewer\"]')"))
    migrate.upgrade_head()
    with sessionmaker(bind=eng)() as s:
        rows = [auditlog.record(e) for e in s.scalars(select(AuditEntry).order_by(AuditEntry.seq))]
        assert auditlog.verify(s) == []
    assert [(x["action"], x["engagement_id"], x["subject_id"]) for x in rows] == [
        ("person.created", None, 1), ("person.created", None, 2), ("scope.updated", 7, None),
        ("engagement.settings", 7, None), ("engagement.authorized", 7, None), ("members.updated", 7, None)]
    assert all(x["actor"]["kind"] == "backfill" for x in rows)
    assert rows[1]["change"]["after"] == {"email": "r@lab.test", "name": "Rita", "is_owner": False, "disabled": True}
    assert rows[2]["change"]["after"]["include"] == ["*.lab.test"] and rows[2]["change"]["after"]["rate_limit_rps"] == 4
    assert rows[4]["change"]["after"]["authorized_at"] == "2026-10-02T10:00:00+00:00"
    assert rows[5]["change"]["after"] == [{"user_id": 2, "name": "Rita", "email": "r@lab.test", "roles": ["reviewer"]}]
    assert auditlog.describe(rows[5]) == "Roles when the audit log was added: Rita (r@lab.test): reviewer"
    assert datetime.fromisoformat(rows[0]["at"]) <= datetime.now(timezone.utc)
    # An entry appended afterwards continues the same chain.
    with sessionmaker(bind=eng)() as s:
        auditlog.append(s, actor=auditlog.CLI, action="person.password_reset", subject_id=2,
                        change={"person": {"id": 2, "name": "Rita", "email": "r@lab.test"}, "password": "assigned"})
        s.commit()
        assert auditlog.verify(s) == []


def test_turning_redaction_off_is_recorded(env):
    """An owner switching evidence redaction off for a lab leaves an entry auditors can see."""
    c, Session = env
    e = c.post("/engagements", json={"name": "lab"}).json()["id"]
    assert c.patch(f"/engagements/{e}", json={"redact_evidence": False}).status_code == 200
    last = entries(Session, "engagement.settings")[-1]
    assert last["change"]["before"]["redact_evidence"] is True and last["change"]["after"]["redact_evidence"] is False
    assert "evidence redaction" in auditlog.describe(last)
