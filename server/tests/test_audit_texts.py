"""Audit record v2 (D-058): the free text of the change history can be deleted with an engagement's
content, and the chain, the receipts, the seal and the reports still verify.

The audit log is hash-chained (D-037), so a text the record holds can never go. Entries written
since migration 0028 take the free text an action carries (auditlog.TEXT_FIELDS: notes on approved
and rejected writes, the path typed to confirm a DELETE, test accounts' roles, hosts and header
names, dismissal reasons, the tool that made an imported file) out of the record, which commits
instead to sha256(canonical({field, salt, value})) with a random 128-bit salt per field. The salt
and the value are kept outside the hashed bytes and blanked when the content is deleted. Entries
written before keep their text and verify as before.
"""
import copy
import json
import re

import pytest
from sqlalchemy import func, select, text

import testdb
from app import auditlog, db, ledger, migrate
from app.models import AuditEntry, Engagement, Job, JobStatus, Lane, WriteProposal
from test_appendonly import Session, refused  # noqa: F401  (Session is a fixture: models and migrated)
from test_auditlog import setup
from test_keytrust import env, register, sign_in, signed_close  # noqa: F401  (env is a fixture)
from test_security_verifier import rehash, reseal, run
from test_signing import verifier


def har_with(host: str, word: str) -> bytes:
    """A HAR file of one exchange with host, made by a tool whose name holds word."""
    entry = {"startedDateTime": "2026-10-14T10:00:00.000Z",
             "request": {"method": "GET", "url": f"https://{host}/page", "httpVersion": "HTTP/1.1",
                         "headers": [{"name": "Host", "value": host}], "queryString": [], "cookies": []},
             "response": {"status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1",
                          "headers": [{"name": "Content-Type", "value": "text/plain"}], "cookies": [],
                          "content": {"size": 2, "mimeType": "text/plain", "text": "ok"}}}
    return json.dumps({"log": {"version": "1.2", "creator": {"name": f"tool {word}", "version": "1"},
                               "entries": [entry]}}).encode()


def every_text(c, Session, e: int, lane: int, host: str, word: str, labels=("A", "B")) -> None:
    """One entry of each action that carries free text (auditlog.TEXT_FIELDS), each text holding
    word: an import and a dismissal, a test account added, replaced and deleted, and writes
    approved, confirmed as a DELETE and rejected. c may change the engagement (an owner)."""
    def ok(r, codes=(200, 201)):
        assert r.status_code in codes, r.text
        return r.json()
    ok(c.patch(f"/engagements/{e}", json={"allow_writes": True}))
    ok(c.post(f"/engagements/{e}/imports", params={"filename": "lab.har"}, content=har_with(host, word),
              headers={"content-type": "application/octet-stream"}))
    ids = [x["id"] for x in ok(c.get(f"/engagements/{e}/inbox", params={"state": "new"}))["entries"]]
    ok(c.post(f"/engagements/{e}/inbox/dismiss", json={"entry_ids": ids[:1], "reason": f"reason {word}"}))
    a = ok(c.post(f"/engagements/{e}/test-accounts", json={"label": labels[0], "role": f"role {word}", "hosts": [host],
                                                            "kind": "headers", "value": f"X-{word}: v"}))
    ok(c.put(f"/engagements/{e}/test-accounts/{a['id']}", json={"role": f"other {word}"}))
    b = ok(c.post(f"/engagements/{e}/test-accounts", json={"label": labels[1], "role": f"role {word}", "hosts": [host],
                                                            "kind": "bearer", "value": "tok"}))
    ok(c.post(f"/engagements/{e}/test-accounts/{b['id']}/delete"))
    from app import approvals
    with Session() as s:
        eng, ln = s.get(Engagement, e), s.get(Lane, lane)
        job = Job(engagement_id=e, kind="agent", targets=[host], status=JobStatus.running, lane_id=lane)
        s.add(job)
        s.flush()
        made = [approvals.propose(s, eng=eng, lane=ln, job_id=job.id, method=m, url=f"https://{host}/api/{word}/{n}",
                                  headers=[], body=b"", account=None, item_idx=1, reason="lab")
                for n, m in enumerate(("POST", "DELETE", "PUT"))]
        s.commit()
        posted, deleted, put = ((p.id, p.request_sha256) for p in made)
    ok(c.post(f"/engagements/{e}/approvals/{posted[0]}/approve", json={"request_sha256": posted[1],
                                                                       "note": f"note {word}"}))
    ok(c.post(f"/engagements/{e}/approvals/{deleted[0]}/approve", json={"request_sha256": deleted[1],
                                                                        "note": f"delete {word}"}))
    ok(c.post(f"/engagements/{e}/approvals/{deleted[0]}/confirm-delete",
              json={"request_sha256": deleted[1], "confirm_path": f"/api/{word}/1"}))
    ok(c.post(f"/engagements/{e}/approvals/{put[0]}/reject", json={"note": f"no {word}"}))


WORD = "zebracanary"          # letters only: redaction leaves it, every encoding spells it the same
PATHS = {"import.batch": ["after.creator"], "import.dismissed": ["after.reason"],
         "account.added": ["after.header_names", "after.hosts", "after.role"],
         "account.replaced": ["after.header_names", "after.hosts", "after.role",
                              "before.header_names", "before.hosts", "before.role"],
         "account.deleted": ["before.header_names", "before.hosts", "before.role"],
         "write.approved": ["after.note"], "write.delete_confirmed": ["after.path"], "write.rejected": ["after.note"]}


def history(c, Session, word=WORD, signed=True):
    """An engagement with every kind of free text, and a receipt signed after it (v4, so it
    commits to the history). Returns (engagement, lane)."""
    e, lane, _ = setup(c)
    with Session() as s:
        s.get(Engagement, e).scope_include = ["shop.lab.test"]
        s.commit()
    every_text(c, Session, e, lane, "shop.lab.test", word)
    sign_in(c, "rita@lab.test")
    for it in c.get(f"/lanes/{lane}").json()["items"]:
        assert c.patch(f"/lanes/{lane}/items/{it['idx']}", json={"state": "na", "na_reason": "lab"}).status_code == 200
    if signed:
        signed_close(c, lane, register(c))
    sign_in(c, "owner@lab.test")
    return e, lane


def rows(Session, e) -> list[AuditEntry]:
    with Session() as s:
        return list(s.scalars(select(AuditEntry).where(AuditEntry.engagement_id == e).order_by(AuditEntry.seq)))


# ---- what is written -------------------------------------------------------------------

def test_new_entries_commit_to_a_salted_hash_of_each_text_and_keep_it_outside(env):
    c, Session = env
    e, _ = history(c, Session)
    mine = [r for r in rows(Session, e) if r.action in auditlog.TEXT_FIELDS]
    assert sorted({r.action for r in mine}) == sorted(PATHS)
    salts = set()
    for r in mine:
        assert r.record_version == 2
        rec, texts = auditlog.record(r), json.loads(r.texts)
        assert rec["v"] == 2 and sorted(rec["text_sha256"]) == PATHS[r.action] == sorted(texts), r.action
        # The record, which the chain hashes, holds no text; the texts hold it, each with its salt.
        assert WORD not in json.dumps(rec) and WORD in r.texts
        for path, t in texts.items():
            assert re.fullmatch(r"[0-9a-f]{32}", t["salt"]) and t["salt"] not in salts
            salts.add(t["salt"])
            assert rec["text_sha256"][path] == ledger.sha256(ledger.canonical(
                {"field": path, "salt": t["salt"], "value": t["value"]}))
        assert r.record_sha256 == ledger.sha256(ledger.canonical(rec))
    # The same role in two entries has two hashes: nothing links or reveals them.
    added = [json.loads(r.text_sha256)["after.role"] for r in mine if r.action == "account.added"]
    assert len(added) == 2 and added[0] != added[1]
    with Session() as s:
        assert auditlog.verify(s) == []
    # People read the history with the text put back.
    view = {x["action"]: x for x in c.get(f"/engagements/{e}/audit").json()["entries"]}     # the last of each
    assert view["write.approved"]["change"]["after"]["note"] == f"delete {WORD}"
    assert view["write.approved"]["text"].endswith(f": delete {WORD}; it waits for the DELETE confirmation")
    assert view["write.rejected"]["text"].endswith(f": no {WORD}")
    assert view["write.delete_confirmed"]["text"].endswith(f"by typing its path /api/{WORD}/1")
    assert view["account.replaced"]["text"].startswith("Replaced role of test account A (other ")
    assert view["import.batch"]["text"].startswith(f"Imported a file (har, tool {WORD} 1, SHA-256 ")
    assert all(x["texts_deleted"] == [] and "salt" not in json.dumps(x) for x in view.values() if x.get("v") == 2)


def test_entries_without_text_stay_v1(env):
    """An entry with no free text has nothing to take out: its v1 record is the same change, and
    reports made only of such entries still verify with verifiers from before D-058."""
    c, Session = env
    e, _, _ = setup(c)
    approval = {"proposal": 1, "note": None}
    with Session() as s:
        auditlog.append(s, actor=auditlog.CLI, action="write.rejected", engagement_id=e, change={"after": approval})
        s.commit()
    for r in rows(Session, e):
        assert r.record_version == 1 and r.text_sha256 is None and r.texts is None
        assert auditlog.entry(r) == auditlog.record(r) and "v" not in auditlog.record(r)


def test_old_entries_keep_their_text_and_mixed_logs_verify(env, tmp_path, monkeypatch):
    """Entries written before 0028 (record v1) keep their text in the record, hash exactly as
    before, and sit in one chain with v2 entries; reports with both verify in strict mode."""
    c, Session = env
    monkeypatch.setattr(auditlog, "RECORD_VERSION", 1)
    e, lane, _ = setup(c)
    with Session() as s:
        s.get(Engagement, e).scope_include = ["shop.lab.test"]
        s.commit()
    assert c.post(f"/engagements/{e}/test-accounts", json={"label": "O", "role": "old role", "hosts": ["shop.lab.test"],
                                                           "kind": "bearer", "value": "t"}).status_code == 201
    old = rows(Session, e)
    assert all(r.record_version == 1 and r.text_sha256 is None and r.texts is None for r in old)
    acc = next(r for r in old if r.action == "account.added")
    assert "v" not in auditlog.record(acc) and json.loads(acc.change)["after"]["role"] == "old role"
    assert acc.record_sha256 == ledger.sha256(ledger.canonical({k: auditlog.record(acc)[k] for k in auditlog.RECORD_FIELDS}))
    monkeypatch.setattr(auditlog, "RECORD_VERSION", 2)
    every_text(c, Session, e, lane, "shop.lab.test", WORD)
    sign_in(c, "rita@lab.test")
    for it in c.get(f"/lanes/{lane}").json()["items"]:
        c.patch(f"/lanes/{lane}/items/{it['idx']}", json={"state": "na", "na_reason": "lab"})
    signed_close(c, lane, register(c))
    sign_in(c, "owner@lab.test")
    with Session() as s:
        assert auditlog.verify(s) == []
    r = c.get(f"/engagements/{e}/report").json()
    versions = {x.get("v", 1) for x in r["audit_log"]["entries"]}
    assert versions == {1, 2}
    for flags in ((), ("--require-history",)):
        code, out = run(tmp_path, r, *flags)
        assert code == 0 and "PASS  Change history" in out, out
        assert "of the change history" not in out          # nothing deleted, so no note


# ---- deleting the content ----------------------------------------------------------------

def test_deleting_the_content_blanks_the_texts_and_every_report_still_verifies(env, tmp_path, monkeypatch):
    c, Session = env
    monkeypatch.setattr(auditlog, "RECORD_VERSION", 1)
    e, lane, _ = setup(c)
    with Session() as s:
        s.get(Engagement, e).scope_include = ["shop.lab.test"]
        s.commit()
    # An entry from before 0028: its text stays, and the deletion screen and record say so.
    assert c.post(f"/engagements/{e}/test-accounts", json={"label": "O", "role": "legacy", "hosts": ["shop.lab.test"],
                                                           "kind": "bearer", "value": "t"}).status_code == 201
    monkeypatch.setattr(auditlog, "RECORD_VERSION", 2)
    every_text(c, Session, e, lane, "shop.lab.test", WORD)
    sign_in(c, "rita@lab.test")
    for it in c.get(f"/lanes/{lane}").json()["items"]:
        c.patch(f"/lanes/{lane}/items/{it['idx']}", json={"state": "na", "na_reason": "lab"})
    signed_close(c, lane, register(c))
    sign_in(c, "owner@lab.test")
    before = c.get(f"/engagements/{e}/report").json()
    assert WORD in json.dumps(before)
    status = c.get(f"/engagements/{e}/content").json()
    assert any("salted hash" in x for x in status["removes"])
    assert any("1 change history entry recorded before audit record v2" in x for x in status["keeps"])

    r = c.post(f"/engagements/{e}/content/delete", json={"confirm_name": "Audit"})
    assert r.status_code == 200 and r.json()["removed"]["audit_texts"] == 10, r.text
    after = c.get(f"/engagements/{e}/report").json()
    assert WORD not in json.dumps(after)
    with Session() as s:
        assert auditlog.verify(s) == []
        assert WORD not in json.dumps([(x.change, x.texts, x.text_sha256) for x in s.scalars(select(AuditEntry))])
        assert s.scalar(select(func.count()).select_from(AuditEntry).where(AuditEntry.texts.is_not(None))) == 0
    gone = [x for x in after["audit_log"]["entries"] if x.get("v") == 2 and x["text_sha256"]]
    assert len(gone) == 10 and all(x["texts"] is None for x in gone)
    # The records, the links and the head are the same: only the texts went.
    strip = [{k: v for k, v in x.items() if k != "texts"} for x in before["audit_log"]["entries"]]
    assert strip == [{k: v for k, v in x.items() if k != "texts"} for x in after["audit_log"]["entries"]
                     if x["seq"] <= before["audit_log"]["head"]["seq"]]
    assert after["audit_log"]["links"][:len(before["audit_log"]["links"])] == before["audit_log"]["links"]
    for report in (before, after):
        for flags in ((), ("--require-history",)):
            code, out = run(tmp_path, report, *flags)
            assert code == 0 and "PASS  Change history" in out and "PASS  Report seal" in out, out
    assert ("NOTE  21 texts of the change history (notes, paths, test account roles and hosts): content unavailable "
            "(deleted on ") in out and "; the change history was still checked" in out
    # The history shows what was there, and that its text was deleted.
    view = {x["action"]: x for x in c.get(f"/engagements/{e}/audit").json()["entries"]}
    assert view["write.rejected"]["text"].endswith(": [deleted]")
    assert view["write.rejected"]["texts_deleted"] == ["after.note"]
    assert view["account.replaced"]["text"].startswith("Replaced role of test account A ([deleted], ")
    deleted = view["engagement.content_deleted"]
    assert "the text of 10 history entries" in deleted["text"]
    assert "1 history entry recorded before audit record v2 keeps its text" in deleted["text"]
    assert "legacy" in json.dumps(after)            # the v1 entry's text: its record holds it
    html = c.get(f"/engagements/{e}/report.html").text
    assert WORD not in html and "[deleted]" in html and "21 texts (notes, typed paths, test account roles" in html


def test_an_entry_written_after_the_deletion_keeps_no_text(env):
    c, Session = env
    e, lane, _ = setup(c)
    assert c.post(f"/engagements/{e}/content/delete", json={"confirm_name": "Audit"}).status_code == 200
    with Session() as s:
        auditlog.append(s, actor=auditlog.CLI, action="import.dismissed", engagement_id=e,
                        change={"after": {"entries": [1], "reason": f"late {WORD}"}})
        s.commit()
        last = s.scalars(select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1)).one()
        assert last.texts is None and "after.reason" in json.loads(last.text_sha256) and WORD not in last.change
        assert auditlog.texts_of(last) is None and auditlog.verify(s) == []


# ---- what the verifiers and the database catch -------------------------------------------------

def test_the_verifier_catches_a_text_that_is_not_the_one_committed_to(env, tmp_path):
    c, Session = env
    e, _ = history(c, Session)
    base = c.get(f"/engagements/{e}/report").json()

    def problems(change):
        r = copy.deepcopy(base)
        change(r)
        return verifier.check_audit_log(r)[0]

    def entry(r, action):
        return next(x for x in r["audit_log"]["entries"] if x["action"] == action)

    def edit(r):
        entry(r, "write.approved")["texts"]["after.note"]["value"] = "note approved by the client"
    assert problems(edit) == [f"audit log entry #{entry(base, 'write.approved')['seq']}: the text of after.note does "
                              "not match the hash the record commits to"]

    def salt(r):
        entry(r, "write.approved")["texts"]["after.note"]["salt"] = "0" * 32
    assert len(problems(salt)) == 1

    def moved(r):                   # one text put under another field
        t = entry(r, "account.added")["texts"]
        t["after.role"], t["after.hosts"] = t["after.hosts"], t["after.role"]
    assert len(problems(moved)) == 2

    def unknown_path(r):
        entry(r, "write.approved")["texts"]["after.extra"] = entry(r, "write.approved")["texts"]["after.note"]
    assert len(problems(unknown_path)) == 1

    def on_v1(r):                   # passed off as v1, with its texts
        x = entry(r, "write.rejected")
        x.pop("v")
        x.pop("text_sha256")
    found = problems(on_v1)
    assert any("content does not match its record hash" in p for p in found)
    assert any("gives texts, but its record version commits to none" in p for p in found)

    def unknown_version(r):
        entry(r, "write.approved")["v"] = 3
    assert any("unknown record version 3" in p for p in problems(unknown_version))

    def not_a_dict(r):
        entry(r, "write.approved")["texts"] = ["note"]
    assert any("its texts cannot be read" in p for p in problems(not_a_dict))

    # Removed from a report whose engagement was not deleted: still verifies, and says so.
    r = copy.deepcopy(base)
    entry(r, "write.approved")["texts"] = None
    code, out = run(tmp_path, reseal(r))
    assert code == 0 and ("NOTE  1 text of the change history (notes, paths, test account roles and hosts): content "
                          "unavailable (the report does not say it was deleted)") in out, out
    # An edited text after a rehash fails the change history, and the seal unless sealed again.
    r = copy.deepcopy(base)
    edit(r)
    code, out = run(tmp_path, rehash(r))
    assert code == 1 and "FAIL  Change history" in out and "FAIL  Report seal" in out


def test_the_server_finds_a_text_changed_in_the_database(env):
    c, Session = env
    e, _ = history(c, Session, signed=False)
    with Session() as s:
        row = s.scalars(select(AuditEntry).where(AuditEntry.action == "write.rejected")).one()
        texts = json.loads(row.texts)
        texts["after.note"]["value"] = "no, never"
        with testdb.append_only_off(s):
            s.execute(text("UPDATE audit_log SET texts = :t WHERE id = :id"), {"t": ledger.canonical(texts), "id": row.id})
            s.commit()
        s.expire_all()
        assert auditlog.verify(s) == [f"audit log entry {row.seq}: the text of after.note does not match the hash its "
                                      "record commits to"]


def test_the_database_lets_the_texts_go_and_nothing_else(Session):
    S = Session
    with S() as s:
        e = Engagement(name="e", scope_include=["*.example.com"])
        s.add(e)
        s.commit()
        row = auditlog.append(s, actor=auditlog.CLI, action="write.rejected", engagement_id=e.id,
                              change={"after": {"proposal": 1, "note": "a note"}})
        s.commit()
        rid = row.id
    assert row.texts and row.record_version == 2
    assert refused(S, "UPDATE audit_log SET texts = '{}' WHERE id = :id", id=rid)
    assert refused(S, "UPDATE audit_log SET text_sha256 = NULL WHERE id = :id", id=rid)
    assert refused(S, "UPDATE audit_log SET record_version = 1 WHERE id = :id", id=rid)
    assert refused(S, "UPDATE audit_log SET texts = NULL, change = '{}' WHERE id = :id", id=rid)
    assert not refused(S, "UPDATE audit_log SET texts = NULL WHERE id = :id", id=rid)
    assert refused(S, "UPDATE audit_log SET texts = '{}' WHERE id = :id", id=rid)       # it never comes back
    with S() as s:
        assert auditlog.verify(s) == []


# ---- the migration -------------------------------------------------------------------------------

def test_0028_keeps_every_existing_entry_as_it_was(tmp_path, monkeypatch):
    """Entries written before 0028 become record v1 and verify with the hashes they had; new ones
    are v2 in the same chain; 0028 cannot be downgraded once a v2 entry exists."""
    from alembic import command
    eng = testdb.file_engine(tmp_path / "al.db")
    monkeypatch.setattr(db, "engine", eng)
    monkeypatch.setattr(migrate, "engine", eng)
    command.upgrade(migrate._config(), "0027")
    with eng.begin() as conn:
        org = conn.execute(text("SELECT id FROM organizations ORDER BY id LIMIT 1")).scalar()
        rec = {"seq": 1, "at": "2026-10-13T10:00:00.000000+00:00",
               "actor": {"kind": "cli", "user_id": None, "name": "operator CLI", "email": None},
               "action": "write.rejected", "engagement_id": None, "subject_id": None,
               "change": {"after": {"proposal": 1, "note": "an old note"}}}
        rsha = ledger.sha256(ledger.canonical(rec))
        conn.execute(text(
            "INSERT INTO audit_log (organization_id, seq, at, actor_kind, actor_user_id, actor_name, actor_email, action, "
            "engagement_id, subject_id, change, record_sha256, prev_hash, entry_hash) VALUES (:org, 1, :at, 'cli', NULL, "
            "'operator CLI', NULL, 'write.rejected', NULL, NULL, :change, :rsha, :genesis, :eh)"),
            {"org": org, "at": rec["at"], "change": ledger.canonical(rec["change"]), "rsha": rsha,
             "genesis": auditlog.GENESIS, "eh": auditlog.entry_hash(auditlog.GENESIS, rsha)})
    migrate.upgrade_head()
    from sqlalchemy.orm import sessionmaker
    with sessionmaker(bind=eng)() as s:
        old = s.scalars(select(AuditEntry)).one()
        assert old.record_version == 1 and auditlog.record(old) == rec and auditlog.entry(old) == rec
        auditlog.append(s, actor=auditlog.CLI, action="write.rejected", change={"after": {"proposal": 2, "note": "new"}})
        s.commit()
        assert [e.record_version for e in s.scalars(select(AuditEntry).order_by(AuditEntry.seq))] == [1, 2]
        assert auditlog.verify(s) == []
    with pytest.raises(RuntimeError, match="record version 2 exist"):
        command.downgrade(migrate._config(), "0027")
    eng.dispose()
