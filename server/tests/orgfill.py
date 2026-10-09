"""Fill one organization with a bit of everything, through the API only.

Used twice: by test_organizations.py, which fills two organizations and walks every route of
one as a member of the other, and to make the migration fixture in data/org-migration/ (a
database at migration 0021, filled by the 0.7.1 API, see make_fixture.py there). So it uses
nothing that 0021 lacks: no organization appears in a request.

Every row kind the API can make is made: people, roles, an engagement with scope and
authorization, assets, lanes, items, evidence of every source (manual note, recon run, import,
agent), a signed receipt, the key log and the audit log, jobs with recon results, an agent run
with an exchange and a proposed write, a test account, an import batch with a mapped and a
dismissed entry, and gateway log rows. Names, hosts and summaries carry `tag`, so a test can
look for it in what another organization is shown.
"""
import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from test_signing import BrowserKey

PW = "correct horse battery"     # test passwords for this suite only
HAR = Path(__file__).parent / "data" / "import" / "sample.har"


def _ok(r, *codes):
    assert r.status_code in (codes or (200, 201)), f"{r.request.method} {r.request.url}: {r.status_code} {r.text}"
    return r.json() if r.content else {}


def sign_in(c, email, password=PW):
    c.cookies.clear()
    _ok(c.post("/auth/login", json={"email": email, "password": password}))


def bearer(token):
    return {"authorization": f"Bearer {token}"}


def fill(c, *, tag: str, owner_email: str, worker_token: str, gateway_token: str) -> dict:
    """c is signed in as an owner (owner_email). Returns the ids of what it made."""
    host = f"shop.{tag}.example.com"
    out = {"tag": tag, "host": host, "owner_email": owner_email}
    rev_email = f"reviewer-{tag}@example.com"
    view_email = f"viewer-{tag}@example.com"
    out["reviewer"] = _ok(c.post("/people", json={"email": rev_email, "name": f"Rita {tag}", "password": PW}))["id"]
    out["viewer"] = _ok(c.post("/people", json={"email": view_email, "name": f"Vic {tag}", "password": PW}))["id"]
    out["reviewer_email"], out["viewer_email"] = rev_email, view_email
    e = out["eng"] = _ok(c.post("/engagements", json={"name": f"Engagement {tag}", "pack_id": "bug-bounty"}))["id"]
    _ok(c.put(f"/engagements/{e}/scope", json={"include": [f"*.{tag}.example.com"], "exclude": [],
                                              "rate_limit_rps": 5, "research_header": f"X-Bug-Bounty: {tag}"}))
    _ok(c.post(f"/engagements/{e}/attest", json={"operator": f"Olive {tag}", "policy_url": "https://example.com/policy",
                                                 "confirm": True}))
    _ok(c.put(f"/engagements/{e}/members", json={"members": [
        {"user_id": out["reviewer"], "roles": ["tester", "reviewer"]},
        {"user_id": out["viewer"], "roles": ["viewer"]}]}))
    _ok(c.patch(f"/engagements/{e}", json={"allow_writes": True, "retain_until": "2099-01-01"}))
    out["asset"] = _ok(c.post(f"/engagements/{e}/assets", json={"host": host}))["id"]
    lane = _ok(c.post("/lanes", json={"asset_id": out["asset"], "role": "recon"}))
    out["lane"] = lane["id"]

    # A recon run through the worker channel: observations, then its output as evidence.
    job = _ok(c.post(f"/engagements/{e}/jobs", json={"kind": "resolve", "targets": [host]}))
    claim = _ok(c.post("/worker/claim", json={}, headers=bearer(worker_token)))["job"]
    assert claim and claim["id"] == job["id"], claim
    out["recon_job"], jt = claim["id"], bearer(claim["token"])
    _ok(c.post(f"/worker/jobs/{claim['id']}/results", headers=jt,
               json={"observations": [{"host": host, "data": {"a": ["192.0.2.10"]}}]}))
    _ok(c.post(f"/worker/jobs/{claim['id']}/progress", headers=jt, json={"done": [host]}))
    output = hashlib.sha256(f"resolve output {tag}".encode()).hexdigest()
    _ok(c.post(f"/worker/jobs/{claim['id']}/finish", headers=jt, json={"output_sha256": output, "result_count": 1}))
    # And a well-known reader run: an endpoint and a lead.
    url = f"https://{host}/"
    job = _ok(c.post(f"/engagements/{e}/jobs", json={"kind": "wellknown", "targets": [url]}))
    claim = _ok(c.post("/worker/claim", json={}, headers=bearer(worker_token)))["job"]
    assert claim and claim["id"] == job["id"], claim
    out["wellknown_job"], jt = claim["id"], bearer(claim["token"])
    _ok(c.post(f"/worker/jobs/{claim['id']}/results", headers=jt, json={
        "endpoints": [{"url": f"https://{host}/private-{tag}/", "sources": ["robots"]}],
        "leads": [{"host": host, "source_url": f"https://{host}/robots.txt", "kind": "robots",
                   "title": f"robots names /private-{tag}/", "key": tag}]}))
    _ok(c.post(f"/worker/jobs/{claim['id']}/progress", headers=jt, json={"done": [url]}))
    _ok(c.post(f"/worker/jobs/{claim['id']}/finish", headers=jt, json={"result_count": 2}))

    # A note on item 1, the rest not applicable; then the reviewer signs with their key.
    note = _ok(c.post(f"/lanes/{out['lane']}/attach", json={"item_idx": 1, "kind": "note",
                                                          "text": f"canary note {tag}", "summary": f"note {tag}"}))
    out["note_evidence"] = note["id"]
    out["note_digest"] = next(ev["sha256"] for ev in note["evidence"] if ev["id"] == note["id"])
    for it in note["items"]:
        state = {"state": "done"} if it["idx"] == 1 else {"state": "na", "na_reason": f"lab {tag}"}
        _ok(c.patch(f"/lanes/{out['lane']}/items/{it['idx']}", json=state))
    sign_in(c, rev_email)
    key = BrowserKey("Ed25519")
    k = _ok(c.post("/auth/keys", json={"algorithm": "Ed25519", "public_key": key.spki}))
    out["key"], out["key_fingerprint"] = k["id"], k["fingerprint"]
    payload = _ok(c.get(f"/lanes/{out['lane']}/receipt-payload", params={"key": k["fingerprint"]}))["payload"]
    _ok(c.post(f"/lanes/{out['lane']}/close", json={"reviewed": True, "payload": payload,
                                                   "signature": key.sign(payload), "key_fingerprint": k["fingerprint"]}))
    sign_in(c, owner_email)

    # The recon lane is receipted, so the next lane may open (the pack's needs_gate).
    lane2 = _ok(c.post("/lanes", json={"asset_id": out["asset"], "role": "mapper"}))
    out["lane2"] = lane2["id"]

    # An import: one entry mapped to the second lane, one dismissed.
    har = HAR.read_text().replace("shop.example.com", host)
    batch = _ok(c.post(f"/engagements/{e}/imports", params={"filename": f"{tag}.har"}, content=har.encode(),
                       headers={"content-type": "application/octet-stream"}))
    out["batch"] = batch["id"]
    entries = _ok(c.get(f"/engagements/{e}/inbox"))["entries"]
    out["entry"], out["entry2"] = entries[0]["id"], entries[1]["id"]
    _ok(c.post(f"/engagements/{e}/inbox/map", json={"entry_ids": [out["entry"]],
                                                   "targets": [{"lane_id": out["lane2"], "item_idx": 1}]}))
    _ok(c.post(f"/engagements/{e}/inbox/dismiss", json={"entry_ids": [out["entry2"]], "reason": f"noise {tag}"}))

    # A test account, and an agent run (outside driver) that records an exchange, cites it as
    # evidence and proposes a write. The run stays running, so its exchange row stays.
    out["account"] = _ok(c.post(f"/engagements/{e}/test-accounts", json={
        "label": "A", "role": f"customer {tag}", "hosts": [host], "kind": "cookie", "value": f"sid={tag}"}))["id"]
    run = _ok(c.post(f"/lanes/{out['lane2']}/agent-runs", json={"driver": f"driver {tag}"}))
    claim = _ok(c.post("/worker/claim", json={"job_id": run["id"]}, headers=bearer(worker_token)))["job"]
    assert claim and claim["id"] == run["id"], claim
    out["agent_job"], jt = claim["id"], bearer(claim["token"])
    out["agent_job_token"], out["agent_gateway_secret"] = claim["token"], claim["gateway_secret"]
    x = _ok(c.post(f"/worker/jobs/{claim['id']}/agent/exchange", headers=jt, json={
        "method": "GET", "url": f"https://{host}/", "headers": {}, "status": 200,
        "response_headers": [["Content-Type", "text/plain"]],
        "body_b64": base64.b64encode(f"hello {tag}".encode()).decode(),
        "at": datetime.now(timezone.utc).isoformat()}))
    call = _ok(c.post(f"/worker/jobs/{claim['id']}/agent/call", headers=jt, json={
        "name": "add_evidence", "args": {"item_idx": 2, "summary": f"agent saw {tag}", "exchange_ids": [x["exchange_id"]]}}))
    assert not call["is_error"], call
    call = _ok(c.post(f"/worker/jobs/{claim['id']}/agent/call", headers=jt, json={
        "name": "propose_write", "args": {"method": "POST", "url": f"https://{host}/api/basket", "headers": [],
                                          "body": "{}", "as_account": "", "item_idx": 1, "reason": f"try {tag}"}}))
    assert not call["is_error"], call
    out["proposal"] = json.loads(call["text"])["proposal_id"]

    # Two gateway log rows: one for the agent job, one refused with no engagement.
    now = datetime.now(timezone.utc).isoformat()
    _ok(c.post("/gateway/log", headers=bearer(gateway_token), json={"rows": [
        {"at": now, "engagement_id": e, "job_id": out["agent_job"], "tool": "agent", "kind": "target",
         "method": "GET", "url": f"https://{host}/", "host": host, "status": 200, "verdict": "allowed"},
        {"at": now, "tool": "dns", "kind": "dns", "method": "DNS", "url": f"refused.{tag}.example.org",
         "host": f"refused.{tag}.example.org", "verdict": "refused", "reason": f"not in scope {tag}"}]}))
    return out
