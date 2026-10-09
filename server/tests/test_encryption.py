"""Per-engagement encryption at rest, deleting content, retention, and chain record v2 (D-043)."""
import base64
import copy
import hashlib
import importlib.util
import json
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "server"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import auditlog, blobs, ledger, vault, workerapi
from app.main import app
from app.models import AuditEntry, Endpoint, Engagement, Evidence, Job, JobStatus, Lane, Lead, Observation
from test_agent import HOST, FakeTransport, api, get, load_worker, make_lane, session, toolbox  # noqa: F401
from harness import stack  # noqa: F401
from test_people import PW, client, setup_team, sign_in  # noqa: F401

spec = importlib.util.spec_from_file_location("verify_report", ROOT / "tools" / "verify_report.py")
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)

SIGN = {"closed_by": "test reviewer", "reviewed": True}
OTHER_KEY = base64.b64encode(hashlib.sha256(b"another test master key").digest()).decode()


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def engagement(api, name="lab"):
    e = api.post("/engagements", json={"name": name}).json()["id"]
    a = api.post(f"/engagements/{e}/assets", json={"host": HOST}).json()["id"]
    lane = api.post("/lanes", json={"asset_id": a, "role": "recon"}).json()
    return e, lane


def attach_note(api, lane_id, idx, text):
    r = api.post(f"/lanes/{lane_id}/attach", json={"item_idx": idx, "kind": "note", "text": text})
    assert r.status_code == 201, r.text
    return r.json()["evidence"][-1]


def close(api, lane):
    """Resolve every item (a note on the first, N/A on the rest) and issue a receipt."""
    lane_id = lane["id"]
    for it in lane["items"]:
        if it["idx"] == 1:
            assert api.patch(f"/lanes/{lane_id}/items/1", json={"state": "done"}).status_code == 200
        else:
            api.patch(f"/lanes/{lane_id}/items/{it['idx']}", json={"state": "na", "na_reason": "lab"})
    r = api.post(f"/lanes/{lane_id}/close", json=SIGN)
    assert r.status_code == 200, r.text


def run_verifier(tmp_path, report: dict, capsys, name="r.json") -> tuple[int, str]:
    path = tmp_path / name
    path.write_text(json.dumps(report))
    capsys.readouterr()
    code = verify.main(["verify_report.py", str(path)])
    return code, capsys.readouterr().out


def delete(api, e, name="lab"):
    r = api.post(f"/engagements/{e}/content/delete", json={"confirm_name": name})
    assert r.status_code == 200, r.text
    return r.json()


# ---- the master key -------------------------------------------------------------------

def test_missing_master_key_fails_closed(monkeypatch, tmp_path):
    monkeypatch.delenv("ATTACKLEDGER_DEV_KEY")
    with pytest.raises(vault.MasterKeyError, match="no master key"):
        vault.master_key()
    with pytest.raises(vault.MasterKeyError):
        blobs.put(b"x", engagement_id=1)
    with pytest.raises(vault.MasterKeyError):                 # the API does not start
        with TestClient(app):
            pass
    # The worker holds no key at all (D-042): it never reads or writes the blob store.
    worker_src = (ROOT / "worker" / "worker.py").read_text()
    assert "vault" not in worker_src and "blobs" not in worker_src and "app.db" not in worker_src
    assert blobs.get(blobs.put(b"plain")) == b"plain"         # the plaintext store does not need a key


def test_a_key_file_that_does_not_open_never_falls_back(monkeypatch, tmp_path):
    monkeypatch.setenv("ATTACKLEDGER_MASTER_KEY", OTHER_KEY)
    monkeypatch.setenv("ATTACKLEDGER_MASTER_KEY_FILE", str(tmp_path / "missing.key"))
    with pytest.raises(vault.MasterKeyError, match="cannot be read"):
        vault.master_key()
    (tmp_path / "short.key").write_text("c2hvcnQ=\n")
    monkeypatch.setenv("ATTACKLEDGER_MASTER_KEY_FILE", str(tmp_path / "short.key"))
    with pytest.raises(vault.MasterKeyError, match="not a 256-bit key"):
        vault.master_key()
    (tmp_path / "good.key").write_text(OTHER_KEY + "\n")
    monkeypatch.setenv("ATTACKLEDGER_MASTER_KEY_FILE", str(tmp_path / "good.key"))
    mk = vault.master_key()
    assert mk.source == "file" and mk.key != vault.DEV_KEY and vault.describe_master() == {"master_key": "configured"}


def test_wrong_master_key_is_refused_at_startup_and_rotation_fixes_it(monkeypatch):
    d = blobs.put(b"evidence", engagement_id=7)               # made under the development key
    monkeypatch.setenv("ATTACKLEDGER_MASTER_KEY", OTHER_KEY)
    with pytest.raises(vault.StoreError, match="did not wrap the keys of engagement 7"):
        vault.check_store()
    with pytest.raises(vault.StoreError, match="another master key"):
        vault.data_key(7)
    assert blobs.get(d, engagement_id=7) is None              # unreadable, never "deleted"
    res = vault.rotate_master(vault.DEV_KEY)
    assert res["rewrapped"] == 1 and res["failed"] == []
    vault.check_store()
    assert blobs.get(d, engagement_id=7) == b"evidence"
    assert vault.rotate_master(vault.DEV_KEY)["skipped"] == 1          # safe to run again
    doc = json.loads((vault.eng_dir(7) / "key.json").read_text())
    assert doc["master_key_id"] == vault.key_id(base64.b64decode(OTHER_KEY)) and OTHER_KEY not in json.dumps(doc)


# ---- blobs ---------------------------------------------------------------------------------

def test_blob_round_trip_is_encrypted_per_engagement():
    data = b"GET /api/users/42 HTTP/1.1\r\nHost: shop.lab.test\r\n\r\n{\"email\":\"x\"}"
    d = blobs.put(data, engagement_id=1)
    assert d == sha(data)                                     # the digest is the plaintext's
    stored = blobs.encrypted_path(d, 1)
    raw = stored.read_bytes()
    assert raw.startswith(vault.BLOB_MAGIC) and b"/api/users" not in raw and data not in raw
    assert not blobs.plain_path(d).exists()
    assert blobs.get(d, engagement_id=1) == data
    assert blobs.get(d) is None                               # without the engagement, it is not found
    assert blobs.put(data, engagement_id=1) == d and stored.read_bytes() == raw   # written once


def test_wrong_engagement_key_is_refused():
    d = blobs.put(b"engagement one only", engagement_id=1)
    blobs.put(b"something else", engagement_id=2)             # engagement 2 has its own key
    assert vault.data_key(1) != vault.data_key(2)
    target = blobs.encrypted_path(d, 2)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(blobs.encrypted_path(d, 1).read_bytes())
    assert blobs.get(d, engagement_id=2) is None              # copied file, other engagement: does not open
    assert vault.open_blob(1, d, target.read_bytes(), key=vault.data_key(2)) is None
    # A key file copied to another engagement does not open either: the id is bound in.
    (vault.eng_dir(2) / "key.json").write_text((vault.eng_dir(1) / "key.json").read_text())
    with pytest.raises(vault.StoreError, match="does not open"):
        vault.data_key(2)


def test_tampered_ciphertext_is_refused():
    d = blobs.put(b"original exchange", engagement_id=3)
    path = blobs.encrypted_path(d, 3)
    raw = bytearray(path.read_bytes())
    raw[-1] ^= 1
    path.write_bytes(bytes(raw))
    assert blobs.get(d, engagement_id=3) is None
    # Swapping in a valid ciphertext of other bytes under this name does not pass either.
    other = blobs.put(b"other bytes", engagement_id=3)
    path.write_bytes(blobs.encrypted_path(other, 3).read_bytes())
    assert blobs.get(d, engagement_id=3) is None
    sealed = vault.seal_summary(3, "a summary", ledger.sha256("a summary"))
    assert vault.open_summary(3, sealed, ledger.sha256("a summary")) == "a summary"
    flipped = sealed[:-2] + ("A" if sealed[-2] != "A" else "B") + sealed[-1]
    assert vault.open_summary(3, flipped, ledger.sha256("a summary")) is None
    assert vault.open_summary(3, sealed, ledger.sha256("another")) is None    # bound to its hash


def test_tampered_summary_in_the_database_shows_unreadable_not_an_error(api):
    e, lane = engagement(api)
    attach_note(api, lane["id"], 1, "robots.txt lists /backup/")
    with api.Session() as s:
        ev = s.scalars(select(Evidence)).one()
        ev.summary_enc = ev.summary_enc[:-4] + "AAAA"
        s.commit()
    r = api.get(f"/lanes/{lane['id']}")
    assert r.status_code == 200
    assert r.json()["evidence"][0]["summary"] is None and r.json()["evidence"][0]["content"] == "unreadable"
    assert api.get(f"/engagements/{e}/report").status_code == 200


# ---- chain record v2 -------------------------------------------------------------------------

def test_new_evidence_is_v2_with_its_source_and_an_encrypted_summary(api):
    e, lane = engagement(api)
    note = attach_note(api, lane["id"], 1, "robots.txt lists /backup/")
    api.post(f"/lanes/{lane['id']}/evidence", json={"item_idx": 2, "kind": "response", "sha256": sha(b"r"),
                                                    "summary": "login answers 200"})
    view = api.get(f"/lanes/{lane['id']}").json()["evidence"]
    assert [(x["v"], x["source"], x["content"]) for x in view] == [(2, "manual", "available")] * 2
    assert note["summary"] == "robots.txt lists /backup/"
    with api.Session() as s:
        rows = s.scalars(select(Evidence).order_by(Evidence.seq)).all()
        assert all(r.summary is None and r.summary_enc.startswith("ale1:") for r in rows)
        assert "backup" not in rows[0].summary_enc
        assert rows[0].summary_sha256 == ledger.sha256("robots.txt lists /backup/")
    rep = api.get(f"/engagements/{e}/report").json()
    entry = rep["evidence"][0]
    assert set(entry) == {"id", "v", "seq", "lane_id", "host", "role", "item_id", "kind", "sha256", "uri",
                          "summary_sha256", "source", "summary", "created_at", "prev_hash", "chain_hash"}
    assert entry["v"] == 2 and entry["source"] == "manual" and entry["summary"] == "robots.txt lists /backup/"
    assert rep["engagement"]["content_deleted"] is None and rep["engagement"]["retain_until"] is None
    assert verify.check_chain(rep) == [] and verify.check_body(rep) == []


def test_agent_evidence_is_v2_and_its_exchanges_are_encrypted(session):
    lane, job = make_lane(session)
    tb = toolbox(session, lane, job, transport=FakeTransport(body=b"Disallow: /secret-admin/"))
    get(tb, f"https://{HOST}/robots.txt")
    tb.call("add_evidence", {"item_idx": 1, "exchange_ids": ["x1"], "summary": "robots lists an admin path"})
    session.commit()
    ev = session.scalars(select(Evidence)).one()
    assert ev.record_version == 2 and ev.source == "agent"
    raw = blobs.encrypted_path(ev.sha256, lane.asset.engagement_id).read_bytes()
    assert b"secret-admin" not in raw
    assert blobs.get(ev.sha256, engagement_id=lane.asset.engagement_id).endswith(b"Disallow: /secret-admin/")


def test_recon_run_evidence_has_the_recon_source(stack, monkeypatch):
    worker = load_worker()
    e = stack.engagement(name="recon-source", include=("*.lab.test",))
    stack.lane(e, HOST)
    stack.queue(e, "archive", ["lab.test"])
    job = stack.claim()

    def fake_archive(r, chunk):
        r.digest.update(b"one url")
        return worker.store_endpoints(r, {f"https://{HOST}/a?q=1": {"gau"}})
    monkeypatch.setitem(worker.RUNNERS, "archive", fake_archive)
    assert worker.execute(job)["status"] == "done"
    with stack.Session() as s:
        ev = s.scalars(select(Evidence)).one()       # written by the API when the run finished
        assert ev.source == "recon" and ev.record_version == 2 and vault.summary_of(ev).endswith(f"job {job.id}")
        assert ev.sha256 == stack.job(job.id).output_sha256 and ev.uri == f"job:{job.id}"
        assert ledger.verify_chain([{**ledger.evidence_record(x, HOST, "recon"), "prev_hash": x.prev_hash,
                                     "chain_hash": x.chain_hash} for x in s.scalars(select(Evidence))]) == []


def v1_row(s, lane: Lane, summary: str, digest: str) -> Evidence:
    """A row as it was written before 0018: chain v1, plaintext summary, no source."""
    eng_id = lane.asset.engagement_id
    last = s.scalars(select(Evidence).where(Evidence.engagement_id == eng_id).order_by(Evidence.seq.desc())).first()
    ev = Evidence(engagement_id=eng_id, lane_id=lane.id, item_id=lane.items[0].id, kind="note", sha256=digest,
                  uri=None, summary=summary, seq=(last.seq + 1) if last else 1,
                  prev_hash=last.chain_hash if last else ledger.GENESIS)
    ev.chain_hash = ledger.chain_hash(ev.prev_hash, {
        "seq": ev.seq, "lane_id": lane.id, "host": lane.asset.host, "role": lane.role, "item_id": ev.item_id,
        "kind": "note", "sha256": digest, "uri": None, "summary": summary})
    s.add(ev)
    s.commit()
    return ev


def test_v1_and_v2_rows_in_one_chain_verify(api, tmp_path, capsys):
    e, lane = engagement(api)
    old = b"note written before 0018"
    blobs.put(old)                                            # plaintext, the old store
    with api.Session() as s:
        v1_row(s, s.get(Lane, lane["id"]), "old note", sha(old))
    attach_note(api, lane["id"], 1, "new note")
    with api.Session() as s:
        v1_row(s, s.get(Lane, lane["id"]), "old again", sha(b"x"))   # order does not matter to the chain
    attach_note(api, lane["id"], 2, "newer note")
    rep = api.get(f"/engagements/{e}/report").json()
    assert [x.get("v", 1) for x in rep["evidence"]] == [1, 2, 1, 2]
    assert "v" not in rep["evidence"][0] and "source" not in rep["evidence"][0]
    assert rep["evidence"][0]["summary"] == "old note"
    code, out = run_verifier(tmp_path, rep, capsys)
    assert code == 0 and "PASS  Evidence chain" in out
    view = api.get(f"/lanes/{lane['id']}").json()["evidence"]
    assert view[0]["v"] == 1 and view[0]["source"] is None and view[0]["summary"] == "old note"
    assert api.get(f"/blobs/{sha(old)}").content == old       # an old plaintext blob still opens
    with api.Session() as s:
        rows = s.scalars(select(Evidence).order_by(Evidence.seq)).all()
        recs = [{**ledger.evidence_record(r, HOST, "recon"), "summary": vault.summary_of(r),
                 "prev_hash": r.prev_hash, "chain_hash": r.chain_hash} for r in rows]
    assert ledger.verify_chain(recs) == []


def test_changing_a_summary_breaks_summary_sha256(api, tmp_path, capsys):
    e, lane = engagement(api)
    attach_note(api, lane["id"], 1, "admin panel answers 401")
    rep = api.get(f"/engagements/{e}/report").json()
    t = copy.deepcopy(rep)
    t["evidence"][0]["summary"] = "admin panel answers 200"
    body = {k: v for k, v in t.items() if k != "integrity"}
    t["integrity"]["body_sha256"] = verify.sha(verify.canonical(body))      # the forger redoes the body hash
    assert any("does not match the hash the chain commits to" in p for p in verify.check_chain(t))
    code, out = run_verifier(tmp_path, t, capsys)
    assert code == 1 and "FAIL  Evidence chain" in out
    # Moving the forged text into the hash breaks the chain hash instead.
    t["evidence"][0]["summary_sha256"] = ledger.sha256("admin panel answers 200")
    assert any("chain hash" in p for p in verify.check_chain(t))
    # And a v2 entry passed off as v1 does not verify.
    t = copy.deepcopy(rep)
    del t["evidence"][0]["v"]
    assert verify.check_chain(t)
    t["evidence"][0]["v"] = 3
    assert any("unknown chain record version" in p for p in verify.check_chain(t))


# Reports published before chain record v2: copies of the site's sample and demo reports as
# they were then. The site's current reports (chain v2) are checked by the test below.
@pytest.mark.parametrize("path", sorted(str(p.relative_to(ROOT)) for p in
                                        (ROOT / "server" / "tests" / "data" / "legacy-reports").glob("*.json")))
def test_old_fixture_reports_still_verify(path, tmp_path, capsys):
    report = json.loads((ROOT / path).read_text())
    assert all("v" not in e for e in report["evidence"])       # made before chain v2
    code, out = run_verifier(tmp_path, report, capsys)
    assert code == 0 and "Verified." in out and "content unavailable" not in out


@pytest.mark.parametrize("path", sorted(str(p.relative_to(ROOT)) for p in
                                        [ROOT / "site" / "sample-report.json", *(ROOT / "site" / "demo" / "reports").glob("*.json")]))
def test_published_site_reports_verify(path, tmp_path, capsys):
    code, out = run_verifier(tmp_path, json.loads((ROOT / path).read_text()), capsys)
    assert code == 0 and "Verified." in out


# ---- deleting content ----------------------------------------------------------------------------

def test_deleting_content_makes_blobs_and_summaries_unreadable_and_the_report_still_verifies(api, tmp_path, capsys):
    e, lane = engagement(api)
    other_e, other_lane = engagement(api, "other")
    note = attach_note(api, lane["id"], 1, "IDOR on /api/orders/1002")
    png = b"\x89PNG\r\n\x1a\nscreenshot"
    api.post(f"/lanes/{lane['id']}/attach", json={"item_idx": 1, "kind": "file", "filename": "shot.png",
                                                   "content_b64": base64.b64encode(png).decode(),
                                                   "summary": "Order of another user."})
    old = b"plaintext from before 0018, cited only here"
    shared = b"plaintext cited by both engagements"
    blobs.put(old)
    blobs.put(shared)
    with api.Session() as s:
        v1_row(s, s.get(Lane, lane["id"]), "old v1 note", sha(old))
        v1_row(s, s.get(Lane, lane["id"]), "shared v1 note", sha(shared))
        v1_row(s, s.get(Lane, other_lane["id"]), "other's v1 note", sha(shared))
        s.add_all([Observation(job_id=_job(s, e), engagement_id=e, host=HOST, data={"title": "Admin"}),
                   Endpoint(engagement_id=e, job_id=_job(s, e), host=HOST, url=f"https://{HOST}/a",
                            url_sha256=sha(b"a"), source="katana"),
                   Lead(engagement_id=e, job_id=_job(s, e), host=HOST, source_url=f"https://{HOST}/", kind="agent",
                        title="t", detail={"text": "captured"}, fingerprint="f" * 64)])
        s.commit()
    attach_note(api, other_lane["id"], 1, "the other engagement's note")
    close(api, api.get(f"/lanes/{lane['id']}").json())
    before = api.get(f"/engagements/{e}/report").json()
    assert vault.has_key(e) and blobs.encrypted_path(note["sha256"], e).exists()

    # The confirmation: the exact name, by an owner (see the people test for the role).
    r = api.post(f"/engagements/{e}/content/delete", json={"confirm_name": "LAB"})
    assert r.status_code == 422 and vault.has_key(e)
    preview = api.get(f"/engagements/{e}/content").json()
    assert preview["encrypted_summaries"] == 2 and preview["v1_summaries"] == 2 and preview["content_deleted"] is None
    res = delete(api, e)
    assert res["removed"]["summaries_removed"] == 2 and res["removed"]["observations"] == 1
    assert res["removed"]["plaintext_blobs_removed"] == 1
    assert api.post(f"/engagements/{e}/content/delete", json={"confirm_name": "lab"}).status_code == 409

    # Unreadable everywhere: blob store, database, API.
    assert not vault.has_key(e) and not blobs.encrypted_path(note["sha256"], e).exists()
    assert blobs.get(note["sha256"], engagement_id=e) is None
    assert not blobs.plain_path(sha(old)).exists() and blobs.plain_path(sha(shared)).exists()
    with pytest.raises(vault.ContentDeleted):
        blobs.put(b"new", engagement_id=e)
    with api.Session() as s:
        rows = s.scalars(select(Evidence).where(Evidence.engagement_id == e).order_by(Evidence.seq)).all()
        assert all(r.summary_enc is None for r in rows) and all(r.summary_sha256 for r in rows if r.record_version == 2)
        assert [r.summary for r in rows if r.record_version == 1] == ["old v1 note", "shared v1 note"]
        assert s.scalars(select(Observation).where(Observation.engagement_id == e)).all() == []
        assert s.scalars(select(Lead).where(Lead.engagement_id == e)).all() == []
        assert all(j.log.startswith("Log deleted") for j in s.scalars(select(Job).where(Job.engagement_id == e)))
    gone = api.get(f"/blobs/{note['sha256']}")
    assert gone.status_code == 410 and "deleted on" in gone.json()["detail"]
    view = api.get(f"/lanes/{lane['id']}").json()
    assert view["status"] == "closed"                          # the receipt still holds
    assert view["content_deleted"]["by"] == "open mode (no sign-in)" and view["content_deleted"]["reason"] == "owner"
    v2 = [x for x in view["evidence"] if x["v"] == 2]
    assert v2 and all(x["summary"] is None and x["content"] == "deleted" for x in v2)
    assert api.get(f"/blobs/{sha(shared)}").content == shared  # still the other engagement's evidence
    assert api.get(f"/lanes/{other_lane['id']}").json()["evidence"][-1]["summary"] == "the other engagement's note"

    # No new content.
    assert api.post(f"/lanes/{lane['id']}/attach", json={"item_idx": 1, "kind": "note", "text": "x"}).status_code == 409
    r = api.post(f"/lanes/{lane['id']}/evidence", json={"kind": "note", "sha256": sha(b"y"), "summary": "y"})
    assert r.status_code == 409 and "deleted on" in r.json()["detail"]
    asset = api.get(f"/engagements/{e}/coverage").json()["assets"][0]["asset_id"]
    mapper = api.post("/lanes", json={"asset_id": asset, "role": "mapper"})     # no lane can be receipted again
    assert mapper.status_code == 409 and "deleted on" in mapper.json()["detail"]

    # A report built afterwards verifies, with the summaries null; so does the one from before.
    after = api.get(f"/engagements/{e}/report").json()
    assert after["engagement"]["content_deleted"]["at"] and after["summary"]["chain_head"] == before["summary"]["chain_head"]
    assert [x["summary"] for x in after["evidence"] if x.get("v") == 2] == [None, None]
    code, out = run_verifier(tmp_path, after, capsys)
    assert code == 0 and "2 evidence entries: content unavailable (key deleted on" in out, out
    assert "PASS  Evidence chain" in out and "PASS  Lane receipts" in out
    code, out = run_verifier(tmp_path, before, capsys, "before.json")
    assert code == 0
    html = api.get(f"/engagements/{e}/report.html").text
    assert "Content deleted on" in html and "IDOR" not in html and "Order of another user" not in html
    (tmp_path / "after.html").write_text(html)
    capsys.readouterr()
    assert verify.main(["verify_report.py", str(tmp_path / "after.html")]) == 0


def _job(s, eng_id) -> int:
    job = s.scalars(select(Job).where(Job.engagement_id == eng_id)).first()
    if job is None:
        job = Job(engagement_id=eng_id, kind="archive", targets=[], status=JobStatus.done, log="saw shop.lab.test/admin")
        s.add(job)
        s.flush()
    return job.id


def test_deleted_engagement_takes_no_runs(api):
    e, lane = engagement(api)
    api.put(f"/engagements/{e}/scope", json={"include": ["*.lab.test"], "research_header": "X-Bug-Bounty: r"})
    api.post(f"/engagements/{e}/attest", json={"operator": "op", "policy_url": "https://example.com/p", "confirm": True})
    delete(api, e)
    r = api.post(f"/engagements/{e}/jobs", json={"kind": "subdomains"})
    assert r.status_code == 422 and "deleted" in r.json()["detail"]
    assert api.patch(f"/engagements/{e}", json={"retain_until": "2099-01-01"}).status_code == 409


def test_deleted_engagement_takes_no_lane_or_item_changes(api):
    e, lane = engagement(api)
    attach_note(api, lane["id"], 1, "GET / answered 200")
    asset = api.get(f"/engagements/{e}/coverage").json()["assets"][0]["asset_id"]
    delete(api, e)
    r = api.post(f"/lanes/{lane['id']}/close", json=SIGN)     # an open lane gets no new receipt
    assert r.status_code == 409 and "can no longer be reviewed" in r.json()["detail"]
    r = api.patch(f"/lanes/{lane['id']}/items/1", json={"state": "done"})
    assert r.status_code == 409 and "deleted" in r.json()["detail"]
    r = api.patch(f"/lanes/{lane['id']}/items/2", json={"state": "na", "na_reason": "no login"})
    assert r.status_code == 409
    r = api.post("/lanes", json={"asset_id": asset, "role": "mapper"})
    assert r.status_code == 409 and "deleted" in r.json()["detail"]


def test_only_an_owner_deletes_content(client):
    owner, ids, e, a, lane = setup_team(client)
    for who in ("rita", "tess", "vic"):
        assert sign_in(client, f"{who}@lab.test").status_code == 200
        assert client.post(f"/engagements/{e}/content/delete", json={"confirm_name": "Team"}).status_code == 403
        assert client.patch(f"/engagements/{e}", json={"retain_until": "2099-01-01"}).status_code == 403
    assert client.get(f"/engagements/{e}/content").json()["content_deleted"] is None   # every role can see the state
    assert sign_in(client, "owner@lab.test").status_code == 200
    r = client.post(f"/engagements/{e}/content/delete", json={"confirm_name": "Team"})
    assert r.status_code == 200 and r.json()["content_deleted"]["by"] == "Olive Owner (owner@lab.test)"


# ---- retention and the audit log ----------------------------------------------------------------

def test_retention_date_is_executed_by_the_api_and_audited(api):
    e, lane = engagement(api)
    note = attach_note(api, lane["id"], 1, "kept until the date")
    yesterday = (datetime.now(timezone.utc).date() - timedelta(days=1)).isoformat()
    tomorrow = (datetime.now(timezone.utc).date() + timedelta(days=1)).isoformat()
    r = api.patch(f"/engagements/{e}", json={"retain_until": yesterday})
    assert r.status_code == 422 and "in the past" in r.json()["detail"]
    r = api.patch(f"/engagements/{e}", json={"retain_until": tomorrow})
    assert r.status_code == 200 and r.json()["retain_until"] == tomorrow
    assert api.get(f"/engagements/{e}/scope").json()["retain_until"] == tomorrow
    assert api.patch(f"/engagements/{e}", json={"separation_of_duties": True}).json()["retain_until"] == tomorrow

    with api.Session() as s:
        assert workerapi.retention_pass(s) == []               # the date has not passed
    assert vault.has_key(e)
    with api.Session() as s:                                   # a day later
        s.get(Engagement, e).retain_until = date.fromisoformat(yesterday)
        s.commit()
        assert workerapi.retention_pass(s) == [e]
        assert workerapi.retention_pass(s) == []               # once
    assert not vault.has_key(e) and blobs.get(note["sha256"], engagement_id=e) is None
    info = api.get(f"/lanes/{lane['id']}").json()["content_deleted"]
    assert info["reason"] == "retention" and info["by"] == "the retention policy"

    log = api.get(f"/engagements/{e}/audit").json()
    assert log["chain"]["intact"]
    mine = [x for x in log["entries"] if x["action"].startswith("engagement.retention")
            or x["action"] == "engagement.content_deleted"]
    assert [x["action"] for x in mine] == ["engagement.retention", "engagement.content_deleted"]
    assert mine[0]["actor"]["kind"] == "open" and "kept until " + tomorrow in mine[0]["text"]
    assert mine[1]["actor"]["kind"] == "retention" and mine[1]["actor_label"] == "the retention policy"
    assert "because its retention date had passed" in mine[1]["text"]
    assert mine[1]["change"]["removed"]["summaries"] == 1
    rep = api.get(f"/engagements/{e}/report").json()
    assert any(x["action"] == "engagement.content_deleted" for x in rep["audit_log"]["entries"])
    assert verify.check_audit_log(rep)[0] == []


def test_owner_deletion_is_audited(api):
    e, lane = engagement(api)
    attach_note(api, lane["id"], 1, "note")
    delete(api, e)
    with api.Session() as s:
        entry = s.scalars(select(AuditEntry).where(AuditEntry.action == "engagement.content_deleted")).one()
        assert entry.engagement_id == e and entry.actor_kind == "open"
        assert auditlog.verify(s) == []
        ch = json.loads(entry.change)
        assert ch["after"]["reason"] == "owner" and ch["removed"]["summaries"] == 1


def test_interrupted_deletion_is_finished_by_the_api(api, monkeypatch):
    e, lane = engagement(api)
    note = attach_note(api, lane["id"], 1, "note")
    with monkeypatch.context() as m, api.Session() as s:
        m.setattr(vault, "finish_deletion", lambda s, eng: {})     # the process stops after the commit
        vault.delete_content(s, s.get(Engagement, e), actor=auditlog.CLI, reason="operator")
    assert vault.has_key(e) and blobs.get(note["sha256"], engagement_id=e) == b"note"
    assert api.get(f"/lanes/{lane['id']}").json()["evidence"][0]["content"] == "deleted"   # the database says so already
    with api.Session() as s:
        workerapi.retention_pass(s)
    assert not vault.has_key(e) and not blobs.encrypted_path(note["sha256"], e).exists()


# ---- existing data -------------------------------------------------------------------------------

def test_encrypt_existing_moves_old_blobs_into_each_engagement(api):
    e1, lane1 = engagement(api, "one")
    e2, lane2 = engagement(api, "two")
    only, shared = b"old blob of one", b"old blob of both"
    blobs.put(only)
    blobs.put(shared)
    with api.Session() as s:
        v1_row(s, s.get(Lane, lane1["id"]), "only one", sha(only))
        v1_row(s, s.get(Lane, lane1["id"]), "shared", sha(shared))
        v1_row(s, s.get(Lane, lane2["id"]), "shared too", sha(shared))
        res = vault.encrypt_existing(s, [e1])
    assert res == {"encrypted": 2, "already_encrypted": 0, "plaintext_removed": 1}   # engagement two still needs one
    assert not blobs.plain_path(sha(only)).exists() and blobs.get(sha(only), engagement_id=e1) == only
    assert b"old blob" not in blobs.encrypted_path(sha(only), e1).read_bytes()
    assert blobs.plain_path(sha(shared)).exists()
    with api.Session() as s:
        assert vault.encrypt_existing(s, [e1]) == {"encrypted": 0, "already_encrypted": 2, "plaintext_removed": 0}
        res = vault.encrypt_existing(s)
    assert res["encrypted"] == 1 and res["plaintext_removed"] == 1 and not blobs.plain_path(sha(shared)).exists()
    assert blobs.get(sha(shared), engagement_id=e2) == shared
    assert api.get(f"/blobs/{sha(only)}").content == only
    with api.Session() as s:                                   # v1 summaries stay plaintext: the chain covers them
        assert s.scalars(select(Evidence).where(Evidence.summary == "only one")).one()


def test_a_blob_store_this_process_cannot_write_stops_startup():
    blobs.put(b"x", engagement_id=5)
    folder = vault.eng_dir(5)
    folder.chmod(0o555)
    try:
        with pytest.raises(vault.StoreError, match="cannot write"):
            vault.check_store()
    finally:
        folder.chmod(0o755)
    vault.check_store()


def test_retention_runs_in_the_api_background(api, monkeypatch):
    """The worker used to run retention; with no database it cannot, so the API's maintenance
    thread does, once a minute (and at once when it starts)."""
    import time
    e, lane = engagement(api, "background")
    note = attach_note(api, lane["id"], 1, "kept until the date")
    with api.Session() as s:
        s.get(Engagement, e).retain_until = date.today() - timedelta(days=1)
        s.commit()
    monkeypatch.setattr(workerapi, "SessionLocal", api.Session)
    stop = workerapi.start_maintenance(seconds=0.05)
    try:
        end = time.time() + 10
        while vault.has_key(e) and time.time() < end:
            time.sleep(0.05)
    finally:
        stop()
    assert not vault.has_key(e) and blobs.get(note["sha256"], engagement_id=e) is None
    assert api.get(f"/lanes/{lane['id']}").json()["content_deleted"]["reason"] == "retention"
    assert workerapi.start_maintenance(seconds=0) is not None    # off: nothing starts


def test_the_deletion_screen_says_that_urls_and_query_strings_stay(api, tmp_path, capsys):
    """The chain (record v2) commits to each evidence URI, query string included, so deleting
    the content cannot remove it. The content view says so before and after, and it is true."""
    e, lane = engagement(api)
    api.post(f"/lanes/{lane['id']}/evidence", json={"item_idx": 1, "kind": "request", "sha256": sha(b"q"),
                                                    "uri": f"https://{HOST}/search?q=lab-term", "summary": "query"})
    api.post(f"/lanes/{lane['id']}/evidence", json={"item_idx": 1, "kind": "request", "sha256": sha(b"p"),
                                                    "uri": f"https://{HOST}/about", "summary": "plain"})
    attach_note(api, lane["id"], 1, "a note has no URI")
    st = api.get(f"/engagements/{e}/content").json()
    assert st["evidence_uris"] == 2 and st["uris_with_query"] == 1
    assert st["keeps"][0].startswith("The URI of each evidence entry, with its host, path and query string")
    assert "(2 entries have one, 1 with a query string)" in st["keeps"][0]
    assert any("raw evidence" in x for x in st["removes"])
    after = delete(api, e)
    assert after["keeps"] == st["keeps"]                # the same statement once it is done
    report = api.get(f"/engagements/{e}/report").json()
    assert f"https://{HOST}/search?q=lab-term" in [x["uri"] for x in report["evidence"]]   # and it is true
    assert all(x["summary"] is None for x in report["evidence"])
    assert run_verifier(tmp_path, report, capsys)[0] == 0
