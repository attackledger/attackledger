"""Deleting an engagement's content reaches every place AttackLedger keeps it
(docs/security-review/RETENTION.md, D-043).

One test seeds a unique string (the canary) into every store that holds an engagement's content:
evidence, the blob store (encrypted and from before encryption), recon results, the import inbox,
test accounts, proposed writes, jobs (log, outcome, targets, a run that is still running), an agent
run's exchanges, the gateway's request log, the gateway's quarantine file, and the free text of
the change history (audit record v2, D-058: approval notes, the typed DELETE path, test accounts'
roles, hosts and header names, dismissal reasons, import tool names). It deletes the
content, lets the running job and the gateway carry on as they would, and then searches every
table row, every file of the blob store, the quarantine file and, on SQLite, the database file's
raw bytes. A second engagement's canary must still be found in each of them: a search that finds
nothing proves something only if it can find something.
"""
import asyncio
import base64
import hashlib
import json
import random
import string
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy.orm import sessionmaker

import testdb
from harness import WORKER_TOKEN, Stack
from test_audit_texts import every_text
from test_gateway_log import GATEWAY_TOKEN, Bridge

from app import approvals, blobs, db, gateway, ledger, vault
from app.models import (AgentExchange, Endpoint, Engagement, Evidence, GatewayRequest, Job, JobStatus, Lane, Lead,
                        Observation, WriteProposal)

HOST = "shop.example.com"


def canary(tag: str) -> str:
    # Letters only: nothing the redaction takes for a secret, and the same in every encoding.
    return f"canary{tag}" + "".join(random.choices(string.ascii_lowercase, k=16))


class ContentBridge(Bridge):
    """The gateway's API client, on the test API (test_gateway_log.Bridge), with the call the
    quarantine purge makes."""

    async def content_deleted(self, engagements, jobs):
        return await asyncio.to_thread(self._call, "POST", "/gateway/content-deleted",
                                       {"engagements": engagements, "jobs": jobs})


@pytest.fixture()
def file_stack(tmp_path, monkeypatch):
    """The API on a database file (a Postgres database of its own under tools/test_postgres.sh),
    made by db.make_engine as the application makes its own."""
    from fastapi.testclient import TestClient
    from app.main import app
    monkeypatch.setenv("ATTACKLEDGER_WORKER_TOKEN", WORKER_TOKEN)
    monkeypatch.setenv("ATTACKLEDGER_GATEWAY_TOKEN", GATEWAY_TOKEN)
    path = tmp_path / "attackledger.db"
    eng = testdb.file_engine(path) if testdb.on_postgres() else db.make_engine(f"sqlite:///{path}")
    db.Base.metadata.create_all(eng)
    Session = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)

    def _session():
        s = Session()
        try:
            yield s
        finally:
            s.close()
    app.dependency_overrides[db.get_session] = _session
    with TestClient(app) as c:
        st = Stack(c, Session)
        st.db_path = None if testdb.on_postgres() else path
        yield st
    app.dependency_overrides.clear()
    eng.dispose()


def table_dump(Session) -> str:
    """Every row of every table, as text: what a database dump holds."""
    out = []
    with Session() as s:
        for t in db.Base.metadata.sorted_tables:
            for row in s.execute(t.select()):
                out.append(f"{t.name}: {tuple(row)!r}")
    return "\n".join(out)


def audit_rows(Session) -> str:
    """The audit log's rows, as text."""
    from app.models import AuditEntry
    with Session() as s:
        return "\n".join(repr(tuple(row)) for row in s.execute(AuditEntry.__table__.select()))


def files_holding(root: Path, needle: str) -> list[str]:
    b = needle.encode()
    return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file() and b in p.read_bytes())


def raw_database(stack) -> bytes:
    """The SQLite file and its journals, byte for byte: deleted rows stay in free pages unless
    they are overwritten."""
    if stack.db_path is None:
        return b""
    p = Path(stack.db_path)
    return b"".join(q.read_bytes() for q in (p, p.with_name(p.name + "-journal"), p.with_name(p.name + "-wal"))
                    if q.exists())


def v1_row(s, lane: Lane, digest: str) -> None:
    """Evidence as written before encryption (chain v1), citing a plaintext blob."""
    ev = Evidence(engagement_id=lane.asset.engagement_id, lane_id=lane.id, item_id=lane.items[0].id, kind="note",
                  sha256=digest, uri=None, summary="an old note", seq=1, prev_hash=ledger.GENESIS)
    ev.chain_hash = ledger.chain_hash(ev.prev_hash, {
        "seq": 1, "lane_id": lane.id, "host": lane.asset.host, "role": lane.role, "item_id": ev.item_id,
        "kind": "note", "sha256": digest, "uri": None, "summary": "an old note"})
    s.add(ev)


def har(c: str) -> bytes:
    entry = {"startedDateTime": "2026-10-09T10:00:00.000Z", "comment": f"label {c}",
             "request": {"method": "GET", "url": f"https://{HOST}/{c}/page?q={c}", "httpVersion": "HTTP/1.1",
                         "headers": [{"name": "Host", "value": HOST}], "queryString": [], "cookies": []},
             "response": {"status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1",
                          "headers": [{"name": "Content-Type", "value": "text/plain"}], "cookies": [],
                          "content": {"size": 30, "mimeType": "text/plain", "text": f"body {c}"}}}
    return json.dumps({"log": {"version": "1.2", "creator": {"name": "lab", "version": "1"},
                               "entries": [entry]}}).encode()


def log_row(e, job, c, **kw) -> dict:
    return {"at": datetime.now(timezone.utc).isoformat(), "engagement_id": e, "job_id": job, "tool": "httpx",
            "kind": "target", "method": "GET", "url": f"https://{HOST}/{c}?q={c}", "host": HOST, "port": 443,
            "status": 403, "verdict": "refused", "reason": f"write not sent: GET https://{HOST}/{c} differs", **kw}


def seed(stack, gw, name: str, c: str) -> dict:
    """Content holding the canary c in every store, for a new engagement."""
    api = stack.api
    e = stack.engagement(name=name, include=("*.example.com",))
    lane = stack.lane(e, HOST, items=3)
    assert api.patch(f"/engagements/{e}", json={"allow_writes": True}).status_code == 200
    # A blob from before encryption, cited by this engagement's v1 evidence only (the chain's first row).
    with stack.Session() as s:
        old = f"plaintext {c}".encode()
        blobs.put(old)
        v1_row(s, s.get(Lane, lane), hashlib.sha256(old).hexdigest())
        s.commit()
    # Evidence: a note, a file with a summary (blob store, encrypted; summary_enc).
    r = api.post(f"/lanes/{lane}/attach", json={"item_idx": 1, "kind": "note", "text": f"note {c}"})
    assert r.status_code == 201, r.text
    r = api.post(f"/lanes/{lane}/attach", json={"item_idx": 1, "kind": "file", "filename": "shot.png",
                                                "content_b64": base64.b64encode(f"file {c}".encode()).decode(),
                                                "summary": f"summary {c}"})
    assert r.status_code == 201, r.text
    # The import inbox (entries, the batch, the raw request and response in the blob store).
    r = api.post(f"/engagements/{e}/imports", params={"filename": f"{c}.har"}, content=har(c),
                 headers={"content-type": "application/octet-stream"})
    assert r.status_code in (200, 201), r.text
    # A test account (its material sealed with the engagement's key).
    r = api.post(f"/engagements/{e}/test-accounts", json={"label": "A", "role": "customer", "hosts": [HOST],
                                                          "kind": "bearer", "value": f"tok{c}"})
    assert r.status_code == 201, r.text
    # A running job, which goes on after the deletion (below).
    stack.queue(e, "probe", [HOST])
    running = stack.claim()
    with stack.Session() as s:
        ln = s.get(Lane, lane)
        done = Job(engagement_id=e, kind="params", targets=[f"https://{HOST}/{c}?id=1"],
                   remaining_targets=[f"https://{HOST}/{c}?id=2"], status=JobStatus.partial, log=f"saw {c}\n",
                   result={"limits": {}, "status": "finished", "summary": f"summary {c}", "detail": f"detail {c}"})
        s.add(done)
        s.flush()
        s.add_all([Observation(job_id=done.id, engagement_id=e, host=HOST, data={"title": f"title {c}"}),
                   Endpoint(engagement_id=e, job_id=done.id, host=HOST, url=f"https://{HOST}/{c}",
                            url_sha256=hashlib.sha256(c.encode()).hexdigest(), source="katana"),
                   Lead(engagement_id=e, job_id=done.id, host=HOST, source_url=f"https://{HOST}/{c}", kind="secret",
                        title=f"title {c}", detail={"text": c}, fingerprint=hashlib.sha256(c.encode()).hexdigest()),
                   AgentExchange(job_id=running.id, xid="x1", sha256="0" * 64, method="GET",
                                 url=f"https://{HOST}/{c}", status=200)])
        # Proposed writes: one waiting, one that the gateway could not send.
        eng = s.get(Engagement, e)
        for status in ("pending", "failed"):
            p = approvals.propose(s, eng=eng, lane=ln, job_id=None, method="POST", url=f"https://{HOST}/{c}/orders",
                                  headers=[["X-Note", c]], body=c.encode(), account=None, item_idx=1,
                                  reason=f"because {c}")
            p.status = status
            if status == "failed":
                p.decision_note = f"could not connect: {c}"
        s.commit()
    # The gateway's request log, and a row the gateway set aside in its quarantine file.
    r = api.post("/gateway/log", json={"rows": [log_row(e, running.id, c)]},
                 headers={"authorization": f"Bearer {GATEWAY_TOKEN}"})
    assert r.status_code == 200 and r.json()["unlogged"] == [], r.text
    # A row that names the job but not its engagement (a placeholder's engagement id was not valid).
    with stack.Session() as s:
        s.add(GatewayRequest(at=datetime.now(timezone.utc), engagement_id=None, job_id=running.id, tool="httpx",
                             kind="target", method="GET", url="", host=HOST, verdict="unlogged",
                             reason=f"not stored (url: {c})"))
        s.commit()
    gw.set_aside(log_row(e, running.id, c), "the API stored a placeholder instead: url: refused")
    gw.set_aside(log_row(None, running.id, c), "the API stored a placeholder instead: engagement_id: refused")
    return {"e": e, "lane": lane, "running": running}


def test_deleting_content_leaves_nothing_readable_in_any_store(file_stack, tmp_path):
    stack = file_stack
    C, OTHER = canary("gone"), canary("kept")
    quarantine = tmp_path / "gateway" / "log-quarantine.jsonl"
    quarantine.parent.mkdir()
    gw = gateway.Gateway(ContentBridge(stack.api), None, deny_hosts=(), networks=[], quarantine=str(quarantine))
    a = seed(stack, gw, "lab", C)
    b = seed(stack, gw, "other", OTHER)
    for x, c in ((a, C), (b, OTHER)):           # the change history's free text (D-058)
        every_text(stack.api, stack.Session, x["e"], x["lane"], HOST, c, labels=("T", "U"))
    blob_root = vault.blob_root()

    # Every store holds both canaries (in the blob store only the plaintext blob shows it: the
    # rest is encrypted). This is what the searches below can find.
    for c in (C, OTHER):
        assert c in table_dump(stack.Session)
        assert c in audit_rows(stack.Session)
        assert files_holding(blob_root, c) and c in quarantine.read_text()
        if stack.db_path:
            assert c.encode() in raw_database(stack)

    r = stack.api.post(f"/engagements/{a['e']}/content/delete", json={"confirm_name": "lab"})
    assert r.status_code == 200, r.text

    # The run that was going on is stopped, and what it sends afterwards is not kept.
    job = a["running"]
    assert job.heartbeat() == "cancelled"
    job.log(f"after the deletion: {C}")
    job.finish(error=f"stopped at {C}")
    r = stack.api.post("/gateway/log", json={"rows": [log_row(a["e"], job.id, C)]},
                       headers={"authorization": f"Bearer {GATEWAY_TOKEN}"})
    assert r.status_code == 200, r.text
    # The gateway asks which engagements of its quarantine file were deleted, and drops their rows.
    assert asyncio.run(gw.purge_quarantine()) == 2

    dump, raw = table_dump(stack.Session), raw_database(stack)
    assert C not in dump, [line for line in dump.splitlines() if C in line]
    assert C.encode() not in raw
    assert files_holding(blob_root, C) == []
    assert C not in quarantine.read_text()
    assert oct(quarantine.stat().st_mode & 0o777) == "0o600"
    assert not vault.has_key(a["e"])
    # Through the API too.
    for path in (f"/engagements/{a['e']}/jobs", f"/engagements/{a['e']}/gateway-log", f"/engagements/{a['e']}/approvals",
                 f"/engagements/{a['e']}/inbox", f"/engagements/{a['e']}/imports",
                 f"/engagements/{a['e']}/test-accounts", f"/engagements/{a['e']}/report",
                 f"/lanes/{a['lane']}"):
        r = stack.api.get(path)
        assert r.status_code == 200 and C not in r.text, path

    # The other engagement keeps all of its own.
    assert OTHER in dump and OTHER in quarantine.read_text() and files_holding(blob_root, OTHER)
    assert OTHER in audit_rows(stack.Session) and C not in audit_rows(stack.Session)
    r = stack.api.get(f"/engagements/{a['e']}/audit")
    assert r.status_code == 200 and C not in r.text and "[deleted]" in r.text
    if stack.db_path:
        assert OTHER.encode() in raw
    assert OTHER in stack.api.get(f"/engagements/{b['e']}/jobs").text


def test_what_deletion_keeps_of_the_jobs_and_the_request_log(file_stack):
    """Jobs keep their kind, status, counts and the hosts they ran on; the request log keeps
    method, host, port, status, verdict and byte counts, not the URL or the reason."""
    stack = file_stack
    gw = gateway.Gateway(ContentBridge(stack.api), None, deny_hosts=(), networks=[], quarantine=None)
    C = canary("gone")
    a = seed(stack, gw, "lab", C)
    assert stack.api.post(f"/engagements/{a['e']}/content/delete", json={"confirm_name": "lab"}).status_code == 200
    with stack.Session() as s:
        jobs = {j.kind: j for j in s.query(Job).filter_by(engagement_id=a["e"])}
        assert jobs["params"].targets == [HOST] and jobs["params"].remaining_targets == [HOST]
        assert jobs["params"].status == JobStatus.partial and jobs["params"].result == {"limits": {}, "status": "finished"}
        assert jobs["probe"].status == JobStatus.cancelled and jobs["probe"].targets == [HOST]
        assert s.query(AgentExchange).filter_by(job_id=a["running"].id).count() == 0
        g = s.query(GatewayRequest).filter_by(engagement_id=a["e"]).one()
        assert (g.url, g.reason, g.method, g.host, g.status, g.verdict) == ("", "", "GET", HOST, 403, "refused")
        assert {p.status for p in s.query(WriteProposal).filter_by(engagement_id=a["e"])} == {"failed"}


def test_the_gateway_keeps_its_quarantine_file_when_the_api_does_not_answer(tmp_path):
    """The purge is the API's answer: without one (the API down, a wrong token), nothing is
    removed, and the next pass asks again."""
    class Down:
        base = "down"

        async def content_deleted(self, engagements, jobs):
            return 0, {"detail": "API unreachable"}
    q = tmp_path / "q.jsonl"
    gw = gateway.Gateway(Down(), None, deny_hosts=(), networks=[], quarantine=str(q))
    gw.set_aside(log_row(7, 8, "x"), "why")
    before = q.read_text()
    assert asyncio.run(gw.purge_quarantine()) == 0 and q.read_text() == before


def test_a_row_set_aside_while_the_gateway_asks_is_kept(tmp_path):
    """The gateway asks the API, then rewrites the file without the deleted engagements' rows. A
    row set aside meanwhile (the same event loop, while it waits for the answer) is kept."""
    q = tmp_path / "q.jsonl"

    class Api:
        base = "fake"

        async def content_deleted(self, engagements, jobs):
            gw.set_aside(log_row(3, 30, "meanwhile"), "why")
            return 200, {"engagements": [1], "jobs": [20]}
    gw = gateway.Gateway(Api(), None, deny_hosts=(), networks=[], quarantine=str(q))
    gw.set_aside(log_row(1, 10, "deleted-eng"), "why")
    gw.set_aside(log_row(None, 20, "deleted-job"), "why")
    gw.set_aside(log_row(2, 21, "live"), "why")
    with open(q, "a") as f:
        f.write('{"set_aside_at": "cut short')          # a write that never ended
    assert asyncio.run(gw.purge_quarantine()) == 3
    kept = q.read_text()
    assert "deleted-eng" not in kept and "deleted-job" not in kept and "cut short" not in kept
    assert "live" in kept and "meanwhile" in kept


def test_the_api_names_only_deleted_engagements_and_their_jobs(file_stack):
    stack = file_stack
    e1 = stack.engagement(name="one")
    e2 = stack.engagement(name="two")
    j1, j2 = stack.queue(e1, "probe", [HOST]), stack.queue(e2, "probe", [HOST])
    assert stack.api.post(f"/engagements/{e1}/content/delete", json={"confirm_name": "one"}).status_code == 200
    auth = {"authorization": f"Bearer {GATEWAY_TOKEN}"}
    r = stack.api.post("/gateway/content-deleted", json={"engagements": [e1, e2, 999, 2**40], "jobs": [j1, j2, 999]},
                       headers=auth)
    assert r.status_code == 200 and r.json() == {"engagements": [e1], "jobs": [j1]}
    assert stack.api.post("/gateway/content-deleted", json={"engagements": [e1], "jobs": []}).status_code == 401
    # Only the gateway's token opens it, and the worker's does not.
    r = stack.api.post("/gateway/content-deleted", json={"engagements": [e1], "jobs": []},
                       headers={"authorization": f"Bearer {WORKER_TOKEN}"})
    assert r.status_code == 401


def test_the_sqlite_database_overwrites_what_it_deletes(tmp_path):
    """SQLite leaves a deleted row's bytes in the file's free pages, and an updated value's old
    bytes in the page, until something overwrites them: a copy of the file (a backup, a disk
    image) still showed deleted content. The application's engine turns secure_delete on.

    The SQLite in the Docker image (Debian's) is built with secure_delete on by default; the one
    in macOS's Python 3.13 (3.49.1) is not, and SQLite is what a source install runs on. The
    connections here start with it off, as on such a build."""
    if testdb.on_postgres():
        pytest.skip("SQLite only; Postgres is described in RETENTION.md")
    import sqlite3

    from sqlalchemy import text
    path = tmp_path / "x.db"

    def library_default_off():
        conn = sqlite3.connect(path, check_same_thread=False)
        conn.execute("PRAGMA secure_delete = 0")
        return conn
    eng = db.make_engine(f"sqlite:///{path}", creator=library_default_off)
    c = canary("row")
    with eng.begin() as conn:
        assert conn.execute(text("PRAGMA secure_delete")).scalar() == 1
        conn.execute(text("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)"))
        conn.execute(text("INSERT INTO t (v) VALUES (:v), (:w)"), {"v": f"{c} " * 50, "w": f"update {c}"})
    with eng.begin() as conn:
        conn.execute(text("DELETE FROM t WHERE id = 1"))
        conn.execute(text("UPDATE t SET v = '' WHERE id = 2"))
    eng.dispose()
    assert c.encode() not in path.read_bytes()


def test_the_gateway_redacts_a_reason_that_quotes_the_request(tmp_path):
    """A write that is not the approved one is refused with a reason naming its URL, as the agent
    sent it (approvals.consume). The gateway redacted the log row's URL but not its reason, so a
    token in the query string reached the log, and the quarantine file, in the clear."""
    gw = gateway.Gateway(ContentBridge(None), None, deny_hosts=(), networks=[], quarantine=None)
    url = f"https://{HOST}/orders?access_token=Zq8Tkv3PloMnB7aa"
    gw.record(rules=None, tool="agent", kind="target", method="POST", url=url, verdict="refused", status=403,
              reason=f"write not sent: the request is not the approved one: POST {url} differs", job_id=3)
    row = gw.log_rows[-1]
    assert "Zq8Tkv3PloMnB7aa" not in row["url"] and "Zq8Tkv3PloMnB7aa" not in row["reason"]
    assert row["reason"].startswith("write not sent: the request is not the approved one: POST https://")


def test_encrypt_existing_removes_plaintext_blobs_no_evidence_cites():
    """Before encryption (0017) an agent run stored every exchange it sent in the plaintext store;
    only those it added as evidence are cited. Deleting the engagement's content removed the cited
    ones and never these: nothing names their engagement. encrypt-existing, run over every
    engagement, now removes them too; a run limited to some engagements leaves them."""
    from test_agent import make_lane
    eng = testdb.memory_engine()
    db.Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)()
    lane, _ = make_lane(s)
    cited, uncited = b"an exchange added as evidence", f"an exchange it only sent {canary('x')}".encode()
    blobs.put(cited)
    blobs.put(uncited)
    v1_row(s, lane, hashlib.sha256(cited).hexdigest())
    s.commit()
    assert vault.uncited_plaintext(s) == [hashlib.sha256(uncited).hexdigest()]
    assert vault.encrypt_existing(s, [lane.asset.engagement_id])["uncited_removed"] == 0
    assert blobs.plain_path(hashlib.sha256(uncited).hexdigest()).exists()
    res = vault.encrypt_existing(s)
    assert res["uncited_removed"] == 1 and not blobs.plain_path(hashlib.sha256(uncited).hexdigest()).exists()
    assert blobs.get(hashlib.sha256(cited).hexdigest(), engagement_id=lane.asset.engagement_id) == cited
    assert vault.blob_root().joinpath("e").is_dir() and vault.uncited_plaintext(s) == []
    s.close()


def test_the_deletion_screen_and_the_backup_tools_say_that_backups_are_not_reached(file_stack):
    """Deletion cannot reach a backup made before it, and the database half of a backup is not
    encrypted, so rotating the master key does not finish the deletion there. The docs said it
    did; the owner's deletion screen did not say anything."""
    stack = file_stack
    e = stack.engagement(name="lab")
    keeps = stack.api.get(f"/engagements/{e}/content").json()["keeps"]
    assert any(k.startswith("Backups made before the deletion") and "not encrypted" in k for k in keeps)
    root = Path(__file__).resolve().parents[2]
    backup = (root / "tools" / "backup.sh").read_text()
    assert "does not reach a backup made before it" in backup and "rotation does nothing to it" in backup
    assert "brings the content back" in backup
    assert "delete it again afterwards" in (root / "tools" / "restore.sh").read_text()
    install = " ".join((root / "docs" / "INSTALL.md").read_text().split())
    assert "the database dump is not encrypted." in install and "Rotating the key does nothing to it." in install
    assert "Restoring a backup made before a deletion brings the deleted content back" in install
