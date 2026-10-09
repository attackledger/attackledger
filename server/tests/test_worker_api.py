"""The worker's channel to the API (D-042, docs/WORKER_API.md): who may call it, what one job's
token opens, what each job kind may write, and that the API keeps every gate it had."""
import json
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from harness import WORKER_TOKEN, stack  # noqa: F401

from app import blobs, ledger, modules, vault, workerapi
from app.main import app
from app.models import AgentExchange, Asset, Endpoint, Evidence, ItemState, JobStatus, Lane, Lead, Observation

HOST = "shop.example.com"
JOB_ROUTES = ["heartbeat", "log", "progress", "results", "finish", "agent/exchange", "agent/call"]


def recon(stack, kind="resolve", targets=("a.example.com",), **eng):
    e = stack.engagement(name=f"{kind}-{len(stack.api.get('/engagements').json())}", **eng)
    stack.queue(e, kind, list(targets))
    return stack.claim(), e


def agent(stack, max_requests=3, **eng):
    e = stack.engagement(name=f"agent-{len(stack.api.get('/engagements').json())}", **eng)
    lane = stack.lane(e, HOST, executor="agent")
    stack.queue(e, "agent", [HOST], lane_id=lane, result={"limits": {"max_requests": max_requests}})
    return stack.claim(), lane, e


def exchange(job, url=f"https://{HOST}/", method="GET", headers=None, body=b"hello"):
    return job.agent_exchange(method=method, url=url, headers=headers or {"X-Bug-Bounty": "r1"}, status=200,
                              response_headers=[("Content-Type", "text/plain")], body=body,
                              at=datetime.now(timezone.utc).isoformat())


# ---- who may call ---------------------------------------------------------------------------

def test_worker_routes_need_the_worker_token(stack, monkeypatch):
    assert stack.call("GET", "/worker/ping", WORKER_TOKEN) == (200, {"ok": True})
    for token in (None, "wrong", "x" * 40):
        assert stack.call("POST", "/worker/claim", token, {})[0] == 401
    monkeypatch.setenv("ATTACKLEDGER_API_TOKEN", "operator-token-0000000000000000")
    assert stack.call("POST", "/worker/claim", "operator-token-0000000000000000", {})[0] == 401
    monkeypatch.delenv("ATTACKLEDGER_WORKER_TOKEN")
    assert stack.call("POST", "/worker/claim", WORKER_TOKEN, {})[0] == 503     # no token configured: closed


def test_the_worker_token_is_made_by_the_worker_and_read_by_the_api(tmp_path, monkeypatch):
    from app import workerclient
    monkeypatch.delenv("ATTACKLEDGER_WORKER_TOKEN", raising=False)
    monkeypatch.setenv("ATTACKLEDGER_WORKER_TOKEN_FILE", str(tmp_path / "wc" / "token"))
    assert workerclient.worker_token() is None                # the API never creates it
    tok = workerclient.worker_token(create=True)
    assert len(tok) >= 40 and workerclient.worker_token() == tok
    assert oct((tmp_path / "wc" / "token").stat().st_mode & 0o777) == "0o600"


def test_claim_issues_a_job_token_and_a_separate_gateway_secret(stack):
    e = stack.engagement()
    a = stack.queue(e, "resolve", ["a.example.com"])
    b = stack.queue(e, "resolve", ["b.example.com"])
    first, second = stack.claim(), stack.claim()
    assert (first.id, second.id) == (a, b) and stack.claim() is None     # each job once, oldest first
    assert first.token != first.gateway_secret
    j = stack.job(a)
    assert j.status == JobStatus.running and j.heartbeat_at is not None
    import hashlib
    assert j.worker_token_sha256 == hashlib.sha256(first.token.encode()).hexdigest()
    assert j.gateway_secret_sha256 == hashlib.sha256(first.gateway_secret.encode()).hexdigest()
    assert first.spec["engagement"]["scope_include"] == ["*.example.com"] and first.spec["targets"] == ["a.example.com"]


def test_a_job_token_opens_only_its_own_job(stack, monkeypatch):
    a, e1 = recon(stack)
    b, e2 = recon(stack, targets=("b.example.com",))
    # With sign-in required (every production install, D-045). In open mode, a local trial,
    # anyone who reaches the API is an owner; there the gateway's relay is what keeps the
    # worker to /worker/* (test_gateway.test_the_control_port_relays_nothing_else).
    monkeypatch.setenv("ATTACKLEDGER_API_TOKEN", "operator-token-0000000000000000")
    for route in JOB_ROUTES:
        assert stack.call("POST", f"/worker/jobs/{b.id}/{route}", a.token, {})[0] == 401, route
        assert stack.call("POST", f"/worker/jobs/{a.id}/{route}", WORKER_TOKEN, {})[0] == 401, route
        assert stack.call("POST", f"/worker/jobs/{a.id}/{route}", None, {})[0] == 401, route
    # Nothing of another engagement, or of its own, through a person's routes either.
    for path in (f"/engagements/{e2}/report", f"/engagements/{e1}/scope", f"/jobs/{b.id}", "/engagements",
                 f"/engagements/{e2}/endpoints", "/audit", f"/blobs/{'0' * 64}"):
        assert stack.call("GET", path, a.token)[0] == 401, path
    assert stack.call("POST", f"/worker/jobs/{a.id}/heartbeat", a.token) == (200, {"status": "running"})


def test_a_finished_jobs_token_and_gateway_secret_stop_working(stack, monkeypatch):
    job, _ = recon(stack)
    monkeypatch.setenv("ATTACKLEDGER_GATEWAY_TOKEN", "gateway-token-for-tests-000000000")
    gw = lambda: stack.call("POST", "/gateway/session", "gateway-token-for-tests-000000000",  # noqa: E731
                            {"job_id": job.id, "secret": job.gateway_secret})[0]
    assert gw() == 200
    job.progress(["a.example.com"])
    assert job.finish(output_sha256="a" * 64, result_count=0) == {"status": "done"}
    for route in JOB_ROUTES:
        assert stack.call("POST", f"/worker/jobs/{job.id}/{route}", job.token, {})[0] == 401, route
    assert gw() == 404                               # its tools are refused by the gateway too
    assert stack.job(job.id).status == JobStatus.done


def test_a_cancelled_job_can_only_report_how_it_stopped(stack):
    job, lane, _ = agent(stack)
    assert stack.api.post(f"/jobs/{job.id}/cancel").status_code == 200       # a person cancels it
    assert job.heartbeat() == "cancelled"
    assert stack.call("POST", f"/worker/jobs/{job.id}/agent/call", job.token,
                      {"name": "record_lead", "args": {}})[0] == 403          # no new writes to the ledger
    with pytest.raises(Exception, match="403"):
        exchange(job)
    assert job.finish(agent={"status": "cancelled"}) == {"status": "cancelled"}
    assert stack.call("POST", f"/worker/jobs/{job.id}/heartbeat", job.token)[0] == 401


def test_the_worker_cannot_write_receipts_or_change_scope_or_rules(stack, monkeypatch):
    job, lane, e = agent(stack)
    monkeypatch.setenv("ATTACKLEDGER_API_TOKEN", "operator-token-0000000000000000")   # as above
    for token in (job.token, WORKER_TOKEN):
        for method, path, body in (
                ("POST", f"/lanes/{lane}/close", {"closed_by": "worker", "reviewed": True}),
                ("PUT", f"/engagements/{e}/scope", {"include": ["*"], "exclude": []}),
                ("POST", f"/engagements/{e}/attest", {"authorized_by": "worker"}),
                ("PATCH", f"/engagements/{e}", {"redact_evidence": False}),
                ("PATCH", f"/lanes/{lane}/items/1", {"state": "done"}),
                ("POST", f"/lanes/{lane}/evidence", {"kind": "note", "sha256": "0" * 64, "summary": "x"}),
                ("POST", "/people", {"email": "w@example.com", "name": "w", "password": "x" * 16})):
            assert stack.call(method, path, token, body)[0] == 401, (method, path)
    # And the worker's own routes offer none of it.
    worker_routes = sorted((m, r.path) for r in app.routes if getattr(r, "path", "").startswith("/worker/")
                           for m in r.methods)
    assert worker_routes == sorted([("GET", "/worker/ping"), ("POST", "/worker/claim")]
                                   + [("POST", f"/worker/jobs/{{job_id}}/{x}") for x in JOB_ROUTES])
    assert stack.call("POST", f"/worker/jobs/{job.id}/agent/call", job.token,
                      {"name": "close_lane", "args": {}})[0] == 422
    with stack.Session() as s:
        assert s.get(Lane, lane).asset.engagement.scope_include == ["*.example.com"]


# ---- what each kind may write -----------------------------------------------------------------

def test_every_job_kind_has_a_capability():
    assert set(workerapi.WRITES) == set(modules.BY_KIND) | {"agent"}


def test_writes_are_limited_by_the_job_kind(stack):
    archive, _ = recon(stack, "archive", targets=("example.com",))
    with pytest.raises(Exception, match="403.*does not write observations"):
        archive.results(observations=[{"host": "a.example.com", "data": {"a": []}}])
    probe, _ = recon(stack, "probe")
    with pytest.raises(Exception, match="422.*open_ports"):
        probe.results(observations=[{"host": "a.example.com", "data": {"open_ports": [22]}}])
    with pytest.raises(Exception, match="403.*does not write leads"):
        probe.results(leads=[{"host": "a.example.com", "source_url": "https://a.example.com/", "kind": "nuclei",
                              "title": "x"}])
    nuclei, _ = recon(stack, "nuclei", targets=("https://a.example.com/",), modules=("nuclei",))
    with pytest.raises(Exception, match="422.*secret leads"):
        nuclei.results(leads=[{"host": "a.example.com", "source_url": "https://a.example.com/", "kind": "secret",
                               "title": "x"}])
    with stack.Session() as s:
        assert s.scalars(select(Observation)).first() is None and s.scalars(select(Lead)).first() is None


def test_rows_out_of_scope_are_refused_and_never_stored(stack):
    job, e = recon(stack, exclude=("admin.example.com",))
    out = job.results(observations=[{"host": h, "data": {"a": ["192.0.2.1"]}}
                                    for h in ("a.example.com", "admin.example.com", "evil.test", "not a host")])
    assert out["observations"] == 1 and out["refused"] == 3
    archive, _ = recon(stack, "archive", targets=("example.com",))
    out = archive.results(endpoints=[{"url": u, "sources": ["gau"]} for u in
                                     ("https://a.example.com/x", "https://evil.test/x", "https://admin.example.com.evil.test/")])
    assert out["endpoints_added"] == 1
    with stack.Session() as s:
        assert [o.host for o in s.scalars(select(Observation))] == ["a.example.com"]
        assert [x.url for x in s.scalars(select(Endpoint))] == ["https://a.example.com/x"]
        assert {a.host for a in s.scalars(select(Asset).where(Asset.engagement_id == e))} == {"a.example.com"}


def test_dork_leads_name_the_root_and_are_deduplicated(stack):
    job, e = recon(stack, "dorks", targets=("example.com",))
    lead = {"host": "example.com", "source_url": "https://www.google.com/search?q=site%3Aexample.com",
            "kind": "dork", "title": "Login pages", "key": "site:example.com inurl:login"}
    assert job.results(leads=[lead, {**lead, "host": "other.test"}])["leads_added"] == 1
    assert job.results(leads=[lead])["leads_added"] == 0             # the API knows earlier rows


def test_progress_only_removes_the_jobs_own_remaining_targets(stack):
    job, _ = recon(stack, targets=("a.example.com", "b.example.com"))
    with pytest.raises(Exception, match="422"):
        job.progress(["c.example.com"])
    assert job.progress(["a.example.com"]) == {"targets_done": 1, "remaining": 1}
    with pytest.raises(Exception, match="422"):
        job.progress(["a.example.com"])                              # not twice
    # Never done with targets left, whatever the worker says.
    assert job.finish(output_sha256="b" * 64) == {"status": "partial"}
    assert stack.job(job.id).remaining_targets == ["b.example.com"]


# ---- agent runs: evidence through the channel ---------------------------------------------------

def test_agent_evidence_through_the_channel_is_chained_encrypted_and_marked_agent(stack):
    job, lane, e = agent(stack, redact=True)
    rec = exchange(job, url=f"https://{HOST}/robots.txt", headers={"X-Bug-Bounty": "forged", "Accept": "*/*"},
                   body=b"Disallow: /admin/\nsession=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlLXZhbHVl")
    assert rec["exchange_id"] == "x1" and "Disallow" in rec["text"] and "eyJzdWIi" not in rec["text"]
    out = job.agent_call("add_evidence", {"item_idx": 1, "exchange_ids": ["x1"], "summary": "robots lists /admin/"})
    assert not out["is_error"] and out["evidence_added"] == 1
    assert job.agent_call("add_evidence", {"item_idx": 1, "exchange_ids": ["x9"], "summary": "made up"})["is_error"]
    assert not job.agent_call("mark_item", {"item_idx": 1, "state": "done", "reason": ""})["is_error"]
    assert job.agent_call("record_lead", {"title": "admin path", "detail": "in robots", "severity": "",
                                          "url": ""})["leads_added"] == 1
    with stack.Session() as s:
        ev = s.scalars(select(Evidence)).one()
        assert ev.source == "agent" and ev.record_version == 2 and vault.summary_of(ev).startswith("[agent] GET")
        raw = blobs.encrypted_path(ev.sha256, e).read_bytes()
        assert b"Disallow" not in raw                                   # encrypted by the API
        stored = blobs.get(ev.sha256, engagement_id=e)
        meta = json.loads(stored.split(b"\n\n", 1)[0])
        # The identification is the engagement's, not what the worker claimed it sent.
        assert meta["request"]["headers"]["X-Bug-Bounty"] == "r1" and meta["request"]["headers"]["Accept"] == "*/*"
        rows = [{**ledger.evidence_record(x, HOST, "recon"), "prev_hash": x.prev_hash, "chain_hash": x.chain_hash}
                for x in s.scalars(select(Evidence).order_by(Evidence.seq))]
        assert ledger.verify_chain(rows) == []
        assert s.get(Lane, lane).items[0].state == ItemState.done
        assert s.scalars(select(AgentExchange)).one().xid == "x1"
    job.finish(agent={"status": "finished", "evidence_added": 1})
    with stack.Session() as s:
        assert s.scalars(select(AgentExchange)).first() is None         # forgotten when the run ends


@pytest.mark.parametrize("kw,why", [
    ({"url": "https://other.example.com/"}, "covers shop.example.com only"),
    ({"url": "https://evil.test/"}, "only"),
    ({"method": "POST"}, "not allowed"),
    ({"headers": {"X-Bug-Bounty": "r1", "Host": "evil.test"}}, "set by AttackLedger"),
    ({"headers": {"X-Bug-Bounty": "r1", "Proxy-Authorization": "x"}}, "set by AttackLedger"),
])
def test_agent_exchanges_are_checked_again_by_the_api(stack, kw, why):
    job, _, _ = agent(stack)
    with pytest.raises(Exception, match=f"422.*{why}"):
        exchange(job, **kw)
    with stack.Session() as s:
        assert s.scalars(select(AgentExchange)).first() is None


def test_agent_exchanges_stop_at_the_request_budget(stack):
    job, _, _ = agent(stack, max_requests=2)
    exchange(job)
    exchange(job)
    with pytest.raises(Exception, match="422.*budget"):
        exchange(job)


def test_recon_jobs_have_no_agent_tools_and_agents_no_recon_results(stack):
    job, _ = recon(stack)
    with pytest.raises(Exception, match="403"):
        exchange(job)
    with pytest.raises(Exception, match="403"):
        job.agent_call("record_lead", {})
    ag, _, _ = agent(stack)
    with pytest.raises(Exception, match="403"):
        ag.results(leads=[{"host": HOST, "source_url": f"https://{HOST}/", "kind": "agent", "title": "x"}])
    for name in ("finish", "http_request"):
        with pytest.raises(Exception, match="422"):
            ag.agent_call(name, {"summary": "x"})


def test_an_outside_driver_claims_its_own_run_and_the_loop_never_does(stack, monkeypatch):
    monkeypatch.delenv("ATTACKLEDGER_AGENTS_ENABLED", raising=False)       # no Claude API key anywhere
    e = stack.engagement(name="bridge")
    lane = stack.lane(e, HOST)                                               # manual executor
    r = stack.api.post(f"/lanes/{lane}/agent-runs", json={"driver": "Claude in Claude Code", "max_requests": 4})
    assert r.status_code == 201, r.text
    j = r.json()["id"]
    assert stack.api.post(f"/lanes/{lane}/agent-runs", json={}).status_code in (409, 422)
    assert stack.claim() is None                                             # the worker's loop skips it
    job = stack.claim(j)
    assert job.id == j and job.spec["driver"] == "Claude in Claude Code" and job.spec["limits"]["max_requests"] == 4
    assert job.spec["context"]["host"] == HOST
    assert stack.claim(j) is None                                            # once
    assert job.finish(agent={"status": "finished", "model": "Claude in Claude Code"}) == {"status": "done"}


def test_unknown_agent_outcomes_are_refused(stack):
    job, _, _ = agent(stack)
    with pytest.raises(Exception, match="422"):
        job.finish(agent={"status": "closed the lane"})
    assert stack.job(job.id).status == JobStatus.running


def test_the_bridge_and_the_worker_use_no_database():
    from harness import ROOT
    for path in ("worker/worker.py", "tools/agent_bridge.py", "server/app/workerclient.py"):
        src = (ROOT / path).read_text()
        assert "app.db" not in src and "SessionLocal" not in src and "sqlalchemy" not in src, path
