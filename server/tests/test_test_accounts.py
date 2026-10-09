"""Test accounts (D-040) and writes with a person's approval (D-041): refusals first.

Most tests here run the real thing end to end in one process: the worker's tools
(agenttools.RemoteToolbox) send through the real gateway (gateway.Gateway, on localhost in a
background event loop), which asks the real API (a TestClient, through a bridge holding the
gateway token) for the rules, the test account and the approval, and forwards to a fake upstream
that records every request it receives and echoes the credentials it was given. So "nothing was
sent" is checked where it matters: at the upstream.
"""
import asyncio
import base64
import json
import os
import threading
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import select, text

from harness import stack  # noqa: F401

from app import agenttools, approvals, blobs, egress, gateway, testaccounts, vault
from app.models import AuditEntry, Engagement, Evidence, GatewayRequest, Job, Lane, TestAccount, WriteProposal

HOST = "shop.example.com"
GW_TOKEN = "gateway-token-for-tests-0000000000000"
A_SESSION = "A-session-7f3c9e1b2d4a6f8091ab"
A_COOKIE = f"sid={A_SESSION}; theme=dark"
B_TOKEN = "B-bearer-token-5e6d7c8b9a0f1e2d3c4b"
SECRETS = (A_SESSION, B_TOKEN)


# ---- the stack: real gateway, real API, fake upstream ------------------------------------

class Bridge:
    """gateway.Api, but calling the API in this process with the gateway token."""
    base = "testserver"

    def __init__(self, client):
        self.c, self.lock = client, threading.Lock()

    def _call(self, method, path, body=None):
        with self.lock:
            r = self.c.request(method, path, json=body, headers={"authorization": f"Bearer {GW_TOKEN}"})
        return r.status_code, (r.json() if r.content else {})

    async def session(self, job_id, secret):
        return await asyncio.to_thread(self._call, "POST", "/gateway/session", {"job_id": job_id, "secret": secret})

    async def account(self, job_id, secret, label, host):
        return await asyncio.to_thread(self._call, "POST", "/gateway/account",
                                       {"job_id": job_id, "secret": secret, "label": label, "host": host})

    async def approval(self, job_id, secret, approval_id, method, url, body_sha256, account):
        return await asyncio.to_thread(self._call, "POST", "/gateway/approval", {
            "job_id": job_id, "secret": secret, "approval_id": approval_id, "method": method, "url": url,
            "body_sha256": body_sha256, "account": account})

    async def dns_scopes(self):
        return await asyncio.to_thread(self._call, "GET", "/gateway/dns-scopes")

    async def post_log(self, rows):
        return await asyncio.to_thread(self._call, "POST", "/gateway/log", {"rows": rows})


class Echo:
    """Records each request; answers with the credentials it received in the body and a new
    session cookie, as a target that echoes and rotates sessions would."""

    def __init__(self):
        self.requests = []

    async def handle(self, reader, writer):
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, ConnectionError):
            writer.close()
            return
        lines = head.decode("latin-1").split("\r\n")
        method, target, _ = lines[0].split(" ", 2)
        headers = [tuple(x.strip() for x in l.split(":", 1)) for l in lines[1:] if ":" in l]
        h = {k.lower(): v for k, v in headers}
        body = await reader.readexactly(int(h.get("content-length", "0") or 0)) if h.get("content-length") else b""
        self.requests.append({"method": method, "target": target, "headers": headers, "body": body})
        # Under names redaction knows, and once in plain words it does not: only the gateway's
        # exact-value scrub catches that one.
        out = json.dumps({"you_sent_cookie": h.get("cookie", ""), "you_sent_auth": h.get("authorization", ""),
                          "greeting": f"hello {h.get('cookie', '')} {h.get('authorization', '')}"}).encode()
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: sid=rotated-session-value-99; "
                     b"Path=/\r\nContent-Length: " + str(len(out)).encode() + b"\r\nConnection: close\r\n\r\n" + out)
        await writer.drain()
        writer.close()

    def header(self, i, name):
        return [v for k, v in self.requests[i]["headers"] if k.lower() == name.lower()]


class Gw:
    def __init__(self, api_client, tmp_path):
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.loop.run_forever, daemon=True).start()
        self.up = Echo()
        self.ca = gateway.CA(str(tmp_path / "gw-private"), str(tmp_path / "gw-public"))
        self.gw = gateway.Gateway(Bridge(api_client), self.ca, deny_hosts=())

        async def resolve(host):
            return "192.0.2.10"

        async def connector(ip, port, ssl=None, server_hostname=None):
            return await asyncio.open_connection("127.0.0.1", self.up_port)
        self.gw.resolve, self.gw.open_connection = resolve, connector

        async def start():
            return [await asyncio.start_server(self.up.handle, "127.0.0.1", 0),
                    await asyncio.start_server(self.gw.handle_client, "127.0.0.1", 0)]
        self.servers = asyncio.run_coroutine_threadsafe(start(), self.loop).result(10)
        self.up_port = self.servers[0].sockets[0].getsockname()[1]
        self.port = self.servers[1].sockets[0].getsockname()[1]

    def flush(self):
        while self.gw.log_rows:
            assert asyncio.run_coroutine_threadsafe(self.gw.flush_log(), self.loop).result(10)

    def egress(self, job):
        return egress.Egress(job.id, job.gateway_secret, address=f"127.0.0.1:{self.port}", dns="",
                             ca_file=str(Path(self.ca._dir).parent / "unused.pem"))

    def raw(self, job, method, url, headers=None, body=b""):
        """One request through the gateway as a tool would send it: (status, body)."""
        auth = base64.b64encode(f"job-{job.id}.agent:{job.gateway_secret}".encode()).decode()
        h = {"Proxy-Authorization": f"Basic {auth}", "X-AttackLedger-Errors": "respond", **(headers or {})}
        req = urllib.request.Request(url, method=method, data=body or None, headers=h)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{self.port}"}))
        try:
            with opener.open(req, timeout=20) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def close(self):
        for s in self.servers:
            self.loop.call_soon_threadsafe(s.close)
        self.loop.call_soon_threadsafe(self.loop.stop)


@pytest.fixture()
def gw(stack, tmp_path, monkeypatch):
    monkeypatch.setenv("ATTACKLEDGER_GATEWAY_TOKEN", GW_TOKEN)
    g = Gw(stack.api, tmp_path)
    yield g
    g.close()


def setup(stack, *, writes=True, accounts=True, redact=True, max_requests=20, name="lab"):
    e = stack.engagement(name=name, redact=redact)
    lane = stack.lane(e, HOST, items=3, executor="agent")
    stack.lane(e, "other.example.com", items=1)
    if accounts:
        add(stack, e, "A", "customer", "cookie", A_COOKIE)
        add(stack, e, "B", "customer", "bearer", B_TOKEN)
    if writes:
        assert stack.api.patch(f"/engagements/{e}", json={"allow_writes": True}).status_code == 200
    stack.queue(e, "agent", [HOST], lane_id=lane, result={"limits": {"max_requests": max_requests}})
    job = stack.claim()
    assert job is not None
    return e, lane, job


def add(stack, e, label, role, kind, value, hosts=(HOST,), status=201):
    r = stack.api.post(f"/engagements/{e}/test-accounts", json={"label": label, "role": role, "hosts": list(hosts),
                                                              "kind": kind, "value": value})
    assert r.status_code == status, r.text
    return r.json()


def tools(gw, job):
    tb = agenttools.RemoteToolbox(job, job.spec["context"], transport=agenttools.urllib_transport(gw.egress(job)),
                                  sleep=lambda s: None, max_requests=job.spec["limits"].get("max_requests") or 20)
    tb.results = []
    real = tb.call

    def call(name, args):
        out = real(name, args)
        tb.results.append(out[0])           # everything the model would read
        return out
    tb.call = call
    return tb


def get(tb, path="/api/me", account=""):
    text, err = tb.call("http_request", {"method": "GET", "url": f"http://{HOST}{path}", "headers": [],
                                         "view": "raw", "as_account": account})
    return (text if err else json.loads(text)), err


def propose(tb, method="POST", path="/api/basket", body='{"item": 1}', account="A", item=1, reason="add an item"):
    text, err = tb.call("propose_write", {"method": method, "url": f"http://{HOST}{path}",
                                          "headers": [{"name": "Content-Type", "value": "application/json"}],
                                          "body": body, "as_account": account, "item_idx": item, "reason": reason})
    return (text if err else json.loads(text)), err


def status(tb, *ids):
    text, err = tb.call("write_status", {"proposal_ids": list(ids), "wait_seconds": 0})
    assert not err, text
    return {w["proposal_id"]: w for w in json.loads(text)["writes"]}


def queue(stack, e):
    return stack.api.get(f"/engagements/{e}/approvals").json()


def approve(stack, e, pid, sha=None, note="ok for the lab"):
    item = next(i for i in queue(stack, e)["items"] if i["id"] == pid)
    return stack.api.post(f"/engagements/{e}/approvals/{pid}/approve",
                          json={"request_sha256": sha or item["request_sha256"], "note": note})


def actions(stack, e):
    with stack.Session() as s:
        return [a.action for a in s.scalars(select(AuditEntry).where(AuditEntry.engagement_id == e)
                                             .order_by(AuditEntry.seq))]


# ---- session material: parsing and storage ------------------------------------------------

@pytest.mark.parametrize("kind,value,why", [
    ("cookie", "no-equals-sign", "name=value"),
    ("cookie", "a=b\r\nX-Evil: 1", "one line"),
    ("bearer", "two words", "one word"),
    ("headers", "Host: evil.test", "set by AttackLedger"),
    ("headers", "X-AttackLedger-As: B", "set by AttackLedger"),
    ("headers", "X-Bug-Bounty: someone-else", "set by AttackLedger"),
    ("headers", "Proxy-Authorization: Basic x", "set by AttackLedger"),
    ("headers", "X-Api-Key: 1\nX-Api-Key: 2", "twice"),
    ("headers", "not a header line", "Name: value"),
    ("other", "x=1", "kind must be"),
])
def test_malformed_or_reserved_material_is_refused(kind, value, why):
    eng = Engagement(name="x", research_header="X-Bug-Bounty: r1")
    with pytest.raises(ValueError, match=why):
        testaccounts.material(kind, value, eng)


def test_material_becomes_headers():
    eng = Engagement(name="x", research_header="X-Bug-Bounty: r1")
    assert testaccounts.material("cookie", "Cookie: a=1; b=2", eng) == [["Cookie", "a=1; b=2"]]
    assert testaccounts.material("bearer", "Bearer abc.def", eng) == [["Authorization", "Bearer abc.def"]]
    assert testaccounts.material("headers", "X-Api-Key: k1\nX-CSRF-Token: t", eng) == [
        ["X-Api-Key", "k1"], ["X-CSRF-Token", "t"]]


def test_the_api_never_returns_the_material_and_audits_without_it(stack):
    e = stack.engagement(name="acc")
    a = add(stack, e, "A", "customer", "cookie", A_COOKIE)
    assert a["fingerprint"].startswith("sha256:") and a["header_names"] == ["Cookie"]
    listed = stack.api.get(f"/engagements/{e}/test-accounts")
    fp1 = listed.json()[0]["fingerprint"]
    replaced = stack.api.put(f"/engagements/{e}/test-accounts/{a['id']}",
                             json={"value": "sid=A-session-new-0000000000000000"})
    assert replaced.status_code == 200 and replaced.json()["fingerprint"] != fp1 and replaced.json()["replaced_at"]
    for r in (listed, replaced):
        assert A_SESSION not in r.text and "A-session-new" not in r.text
    assert stack.api.post(f"/engagements/{e}/test-accounts/{a['id']}/delete").status_code == 200
    assert stack.api.get(f"/engagements/{e}/test-accounts").json() == []
    assert actions(stack, e)[-3:] == ["account.added", "account.replaced", "account.deleted"]
    audit = stack.api.get(f"/engagements/{e}/audit").text
    assert A_SESSION not in audit and "A-session-new" not in audit and "session material" in audit
    with stack.Session() as s:
        for row in s.execute(text("SELECT * FROM audit_log")).all():
            assert "A-session" not in str(row)


def test_accounts_name_in_scope_hosts_need_redaction_and_unique_labels(stack):
    e = stack.engagement(name="hosts")
    add(stack, e, "A", "r", "cookie", "a=1", hosts=("evil.test",), status=422)
    add(stack, e, "A", "r", "cookie", "a=1", hosts=("*.example.com",), status=422)
    add(stack, e, "bad label!", "r", "cookie", "a=1", status=422)
    add(stack, e, "A", "r", "cookie", "a=1")
    add(stack, e, "A", "r", "cookie", "a=2", status=409)
    off = stack.engagement(name="no-redaction", redact=False)
    r = add(stack, off, "A", "r", "cookie", "a=1", status=409)
    assert "redaction" in r["detail"]


def test_the_lane_context_lists_labels_and_roles_only(stack):
    e, lane, job = setup(stack, writes=False)
    ctx = job.spec["context"]
    assert ctx["test_accounts"] == [{"label": "A", "role": "customer", "usable_on_this_host": True},
                                    {"label": "B", "role": "customer", "usable_on_this_host": True}]
    assert ctx["writes"]["allowed"] is False
    assert not any(s in json.dumps(ctx) for s in SECRETS) and "Cookie" not in json.dumps(ctx["test_accounts"])
    assert [t["name"] for t in agenttools.tools_for(ctx)] == list(agenttools.TOOL_NAMES)


# ---- the gateway's account route ------------------------------------------------------------

def gw_account(stack, job, label="A", host=HOST, secret=None):
    r = stack.api.post("/gateway/account", headers={"authorization": f"Bearer {GW_TOKEN}"},
                       json={"job_id": job.id, "secret": secret or job.gateway_secret, "label": label, "host": host})
    return r.status_code, r.json()


def test_the_account_route_answers_the_gateway_only_for_agent_jobs_and_named_hosts(stack, monkeypatch):
    monkeypatch.setenv("ATTACKLEDGER_GATEWAY_TOKEN", GW_TOKEN)
    e, lane, job = setup(stack, writes=False)
    assert gw_account(stack, job) == (200, {"label": "A", "headers": [["Cookie", A_COOKIE]]})
    assert gw_account(stack, job, host="other.example.com")[0] == 403     # in scope, not named for A
    assert gw_account(stack, job, label="C")[0] == 403
    assert gw_account(stack, job, secret="x" * 40)[0] == 403
    # Not for people, the operator or the worker: only the gateway token opens it.
    r = stack.api.post("/gateway/account", json={"job_id": job.id, "secret": job.gateway_secret, "label": "A",
                                                 "host": HOST})
    assert r.status_code == 401
    stack.queue(e, "probe", [HOST])
    recon = stack.claim()
    assert gw_account(stack, recon)[0] == 403
    with stack.Session() as s:
        assert s.scalar(select(TestAccount).where(TestAccount.label == "A")).last_used_at is not None


# ---- requests as a test account, through the gateway ----------------------------------------------

def test_a_request_as_a_has_as_session_and_the_worker_never_sees_it(stack, gw):
    e, lane, job = setup(stack)
    tb = tools(gw, job)
    shown, err = get(tb, account="A")
    assert not err, shown
    up = gw.up.requests[0]
    assert gw.up.header(0, "Cookie") == [A_COOKIE] and gw.up.header(0, "X-AttackLedger-As") == []
    assert gw.up.header(0, "Accept-Encoding") == ["identity"] and gw.up.header(0, "X-Bug-Bounty") == ["r1"]
    assert B_TOKEN not in json.dumps(up["headers"])
    # The target echoed the cookie and set a new one: the worker got neither.
    assert A_SESSION not in json.dumps(shown) and "rotated-session-value" not in json.dumps(shown)
    assert shown["as_account"] == "A"
    gw.flush()
    with stack.Session() as s:
        row = s.scalars(select(GatewayRequest).where(GatewayRequest.method == "GET")).one()
        assert row.account == "A" and row.verdict == "allowed"


def test_a_tools_own_cookie_is_replaced_by_the_accounts(stack, gw):
    e, lane, job = setup(stack)
    tb = tools(gw, job)
    tb.call("http_request", {"method": "GET", "url": f"http://{HOST}/x", "view": "raw", "as_account": "A",
                             "headers": [{"name": "Cookie", "value": "sid=forged"}]})
    assert gw.up.header(0, "Cookie") == [A_COOKIE]


@pytest.mark.parametrize("label,host,why", [("A", "other.example.com", "not for"), ("C", HOST, "no test account")])
def test_injection_only_for_the_accounts_hosts(stack, gw, label, host, why):
    e, lane, job = setup(stack)
    status_, body = gw.raw(job, "GET", f"http://{host}/", headers={"X-AttackLedger-As": label})
    assert status_ == 403 and why.encode() in body
    assert gw.up.requests == []


def test_recon_jobs_cannot_send_as_a_test_account(stack, gw):
    e, lane, job = setup(stack)
    stack.queue(e, "probe", [HOST])
    recon = stack.claim()
    status_, body = gw.raw(recon, "GET", f"http://{HOST}/", headers={"X-AttackLedger-As": "A"})
    assert status_ == 403 and b"does not send requests as a test account" in body
    assert gw.up.requests == []


def test_no_injection_when_redaction_was_turned_off(stack, gw):
    e, lane, job = setup(stack)
    stack.api.patch(f"/engagements/{e}", json={"redact_evidence": False})
    time.sleep(gateway.RULES_TTL + 0.1)
    status_, body = gw.raw(job, "GET", f"http://{HOST}/", headers={"X-AttackLedger-As": "A"})
    assert status_ == 403 and b"redaction" in body and gw.up.requests == []


def test_the_agent_cannot_set_the_gateways_headers(stack, gw):
    e, lane, job = setup(stack)
    tb = tools(gw, job)
    for name in ("X-AttackLedger-As", "X-AttackLedger-Approval", "x-attackledger-anything"):
        text_, err = tb.call("http_request", {"method": "GET", "url": f"http://{HOST}/", "view": "raw",
                                              "as_account": "", "headers": [{"name": name, "value": "1"}]})
        assert err and "set by AttackLedger" in text_
    assert get(tb, account="C")[1] and get(tb, account="Z")[1]
    assert gw.up.requests == []


# ---- writes: refused while the rule is off -------------------------------------------------------

def test_writes_are_refused_when_the_rule_is_off(stack, gw):
    e, lane, job = setup(stack, writes=False)
    tb = tools(gw, job)
    assert "propose_write" not in [t["name"] for t in tb.definitions]
    text_, err = tb.call("http_request", {"method": "POST", "url": f"http://{HOST}/api/basket", "headers": [],
                                          "view": "raw", "as_account": ""})
    assert err and "read-only requests only" in text_
    out, err = propose(tb)
    assert err and "does not allow writes" in out
    status_, body = gw.raw(job, "POST", f"http://{HOST}/api/basket", body=b"{}")
    assert status_ == 403 and b"approval" in body
    with stack.Session() as s:
        assert s.scalars(select(WriteProposal)).all() == []
    assert gw.up.requests == []


# ---- writes: proposed, approved, sent once -------------------------------------------------------

def test_an_unapproved_write_is_never_sent(stack, gw):
    e, lane, job = setup(stack)
    tb = tools(gw, job)
    p, err = propose(tb)
    assert not err and p["status"] == "pending"
    assert status(tb)[p["proposal_id"]]["status"] == "pending"
    # A tool that sends it anyway, with or without naming the proposal, is refused at the gateway.
    assert gw.raw(job, "POST", f"http://{HOST}/api/basket", body=b'{"item": 1}')[0] == 403
    status_, body = gw.raw(job, "POST", f"http://{HOST}/api/basket", body=b'{"item": 1}',
                           headers={"X-AttackLedger-Approval": str(p["proposal_id"]), "X-AttackLedger-As": "A",
                                    "Content-Type": "application/json"})
    assert status_ == 403 and b"pending, not approved" in body
    assert gw.up.requests == []


def test_an_approved_write_is_sent_once_as_approved_and_becomes_evidence(stack, gw):
    e, lane, job = setup(stack)
    tb = tools(gw, job)
    p, _ = propose(tb)
    pid = p["proposal_id"]
    q = queue(stack, e)
    item = q["items"][0]
    assert q["waiting"] == 1 and item["request"]["body"] == '{"item": 1}' and item["request"]["account"] == "A"
    assert approve(stack, e, pid, sha="0" * 64).status_code == 409         # not the request that was read
    assert approve(stack, e, pid).json()["status"] == "approved"
    w = status(tb)[pid]
    assert w["status"] == "sent" and w["note"] == "approved and sent: status 200" and w["exchange_id"]
    assert len(gw.up.requests) == 1
    up = gw.up.requests[0]
    assert up["method"] == "POST" and up["body"] == b'{"item": 1}' and gw.up.header(0, "Cookie") == [A_COOKIE]
    assert gw.up.header(0, "Content-Type") == ["application/json"] and gw.up.header(0, "X-AttackLedger-Approval") == []
    # Used once: asking again sends nothing, and so does replaying it by hand.
    assert status(tb)[pid]["status"] == "sent" and len(gw.up.requests) == 1
    status_, body = gw.raw(job, "POST", f"http://{HOST}/api/basket", body=b'{"item": 1}',
                           headers={"X-AttackLedger-Approval": str(pid), "X-AttackLedger-As": "A"})
    assert status_ == 403 and b"used once" in body and len(gw.up.requests) == 1
    gw.flush()
    with stack.Session() as s:
        ev = s.get(Evidence, s.get(WriteProposal, pid).evidence_id)
        summary = vault.summary_of(ev)
        assert ev.source == "agent" and "as test account A" in summary and "approved it" in summary
        raw = blobs.get(ev.sha256, engagement_id=e)
        meta = json.loads(raw.split(b"\n\n", 1)[0])
        assert meta["request"]["as_account"] == "A" and meta["approval"]["id"] == pid
        assert A_SESSION not in raw.decode() and "rotated-session" not in raw.decode()
        logged = s.scalars(select(GatewayRequest).where(GatewayRequest.method == "POST",
                                                        GatewayRequest.verdict == "allowed")).all()
        assert [(g.account, g.approval_id, g.status) for g in logged] == [("A", pid, 200)]
    assert actions(stack, e)[-2:] == ["write.approved", "write.sent"]


def test_an_approval_binds_the_exact_request(stack, gw):
    e, lane, job = setup(stack)
    tb = tools(gw, job)
    pid = propose(tb)[0]["proposal_id"]
    approve(stack, e, pid)
    h = {"X-AttackLedger-Approval": str(pid), "X-AttackLedger-As": "A"}
    for url, body, hh in [(f"http://{HOST}/api/basket", b'{"item": 2}', h),            # changed body
                          (f"http://{HOST}/api/basket/2", b'{"item": 1}', h),          # changed URL
                          (f"http://{HOST}/api/basket", b'{"item": 1}', {**h, "X-AttackLedger-As": "B"}),
                          (f"http://{HOST}/api/basket", b'{"item": 1}', {"X-AttackLedger-Approval": str(pid)})]:
        status_, text_ = gw.raw(job, "POST", url, body=body, headers=hh)
        assert status_ == 403, text_
    status_, text_ = gw.raw(job, "PUT", f"http://{HOST}/api/basket", body=b'{"item": 1}', headers=h)
    assert status_ == 403
    assert gw.up.requests == []
    # None of these used the approval: the approved request still goes, once.
    assert status(tb)[pid]["status"] == "sent" and len(gw.up.requests) == 1


def test_an_approval_expires(stack, gw):
    e, lane, job = setup(stack)
    tb = tools(gw, job)
    pid = propose(tb)[0]["proposal_id"]
    approve(stack, e, pid)
    with stack.Session() as s:
        s.get(WriteProposal, pid).expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        s.commit()
    w = status(tb)[pid]
    assert w["status"] == "expired" and gw.up.requests == []


def test_a_delete_needs_its_second_confirmation(stack, gw):
    e, lane, job = setup(stack)
    tb = tools(gw, job)
    out, err = propose(tb, method="DELETE", path="/api/basket/7", body="")
    pid = out["proposal_id"]
    assert approve(stack, e, pid).json()["status"] == "confirming"
    assert status(tb)[pid]["status"] == "confirming" and gw.up.requests == []
    status_, _ = gw.raw(job, "DELETE", f"http://{HOST}/api/basket/7",
                        headers={"X-AttackLedger-Approval": str(pid), "X-AttackLedger-As": "A"})
    assert status_ == 403 and gw.up.requests == []
    sha = queue(stack, e)["items"][0]["request_sha256"]
    r = stack.api.post(f"/engagements/{e}/approvals/{pid}/confirm-delete",
                       json={"request_sha256": sha, "confirm_path": "/api/basket/8"})
    assert r.status_code == 422 and gw.up.requests == []
    r = stack.api.post(f"/engagements/{e}/approvals/{pid}/confirm-delete",
                       json={"request_sha256": sha, "confirm_path": "DELETE"})
    assert r.status_code == 422
    r = stack.api.post(f"/engagements/{e}/approvals/{pid}/confirm-delete",
                       json={"request_sha256": sha, "confirm_path": "/api/basket/7"})
    assert r.status_code == 200 and r.json()["status"] == "approved"
    assert status(tb)[pid]["status"] == "sent"
    assert [(u["method"], u["target"]) for u in gw.up.requests] == [("DELETE", "/api/basket/7")]
    assert actions(stack, e)[-3:] == ["write.approved", "write.delete_confirmed", "write.sent"]


def test_a_rejection_is_reported_with_the_note_and_nothing_is_sent(stack, gw):
    e, lane, job = setup(stack)
    tb = tools(gw, job)
    pid = propose(tb)[0]["proposal_id"]
    assert stack.api.post(f"/engagements/{e}/approvals/{pid}/reject", json={"note": ""}).status_code == 422
    r = stack.api.post(f"/engagements/{e}/approvals/{pid}/reject", json={"note": "not on the shared basket"})
    assert r.json()["status"] == "rejected"
    assert status(tb)[pid]["note"] == "rejected by a person: not on the shared basket"
    assert approve(stack, e, pid).status_code == 409 and gw.up.requests == []
    assert actions(stack, e)[-1] == "write.rejected"


def test_the_loop_keeps_working_while_a_write_waits(stack, gw):
    """Propose, read, read, check: nothing blocks, and the waiting write is still waiting."""
    e, lane, job = setup(stack)
    tb = tools(gw, job)
    pid = propose(tb)[0]["proposal_id"]
    assert not get(tb, "/a")[1] and not get(tb, "/b", account="B")[1]
    text_, err = tb.call("write_status", {"proposal_ids": [pid], "wait_seconds": 10})
    assert not err and json.loads(text_)["writes"][0]["status"] == "pending"
    assert [u["method"] for u in gw.up.requests] == ["GET", "GET"]
    assert gw.up.header(1, "Authorization") == [f"Bearer {B_TOKEN}"]       # B used here, by name only


def test_a_run_that_ends_cannot_send_its_writes(stack, gw):
    e, lane, job = setup(stack)
    tb = tools(gw, job)
    pid = propose(tb)[0]["proposal_id"]
    job.finish(agent={"status": "ended"})
    with stack.Session() as s:
        assert s.get(WriteProposal, pid).status == "expired"
    assert approve(stack, e, pid).status_code == 409


def test_write_proposals_are_checked_like_requests(stack, gw):
    e, lane, job = setup(stack)
    tb = tools(gw, job)
    bad = [dict(method="GET"), dict(account="C"), dict(item=99), dict(reason=""),
           dict(method="DELETE", body="x")]
    for kw in bad:
        out, err = propose(tb, **kw)
        assert err, kw
    text_, err = tb.call("propose_write", {"method": "POST", "url": "http://evil.test/", "headers": [], "body": "",
                                           "as_account": "", "item_idx": 1, "reason": "r"})
    assert err
    text_, err = tb.call("propose_write", {"method": "POST", "url": f"http://{HOST}/", "body": "", "as_account": "",
                                           "item_idx": 1, "reason": "r",
                                           "headers": [{"name": "X-HTTP-Method-Override", "value": "DELETE"}]})
    assert err and "change the method" in text_


# ---- who may decide ------------------------------------------------------------------------------

def test_viewers_and_reviewers_cannot_see_or_decide_and_separation_of_duties_holds(stack, monkeypatch):
    from app import auth
    auth._failures.clear()
    e, lane, job = setup(stack)
    with stack.Session() as s:
        pid = approvals.propose(s, eng=s.get(Engagement, e), lane=s.get(Lane, lane), job_id=job.id, method="POST", url=f"https://{HOST}/x", headers=[], body=b"{}",
                                account=None, item_idx=1, reason="r").id
        s.commit()
    c = stack.api
    pw = "correct horse battery"
    ids = {}
    for n, owner in (("olive", True), ("tess", False), ("rita", False), ("vic", False)):
        ids[n] = c.post("/people", json={"email": f"{n}@lab.test", "name": n.title(), "password": pw,
                                         "is_owner": owner}).json()["id"]
        if owner:
            assert c.post("/auth/login", json={"email": "olive@lab.test", "password": pw}).status_code == 200
    c.put(f"/engagements/{e}/members", json={"members": [
        {"user_id": ids["tess"], "roles": ["tester"]}, {"user_id": ids["rita"], "roles": ["reviewer"]},
        {"user_id": ids["vic"], "roles": ["viewer"]}]})
    with stack.Session() as s:
        s.get(Job, job.id).created_by = ids["tess"]
        s.get(Engagement, e).separation_of_duties = True
        s.commit()

    def as_(who):
        c.cookies.clear()
        assert c.post("/auth/login", json={"email": f"{who}@lab.test", "password": pw}).status_code == 200
    sha = None
    for who in ("vic", "rita"):
        as_(who)
        assert c.get(f"/engagements/{e}/approvals").status_code == 403
        assert c.post(f"/engagements/{e}/approvals/{pid}/approve",
                      json={"request_sha256": "0" * 64}).status_code == 403
        assert c.post(f"/engagements/{e}/test-accounts", json={"label": "Z", "role": "r", "hosts": [HOST],
                                                              "kind": "cookie", "value": "a=1"}).status_code == 403
    as_("tess")
    sha = c.get(f"/engagements/{e}/approvals").json()["items"][0]["request_sha256"]
    r = c.post(f"/engagements/{e}/approvals/{pid}/approve", json={"request_sha256": sha})
    assert r.status_code == 403 and "started the agent run" in r.json()["detail"]
    as_("olive")
    r = c.post(f"/engagements/{e}/approvals/{pid}/approve", json={"request_sha256": sha})
    assert r.status_code == 200 and r.json()["decided_by"] == "Olive (olive@lab.test)"
    c.cookies.clear()


# ---- content deletion and the secret scan ----------------------------------------------------------

def test_content_deletion_removes_the_accounts_and_the_waiting_writes(stack, gw):
    e, lane, job = setup(stack)
    tb = tools(gw, job)
    waiting = propose(tb)[0]["proposal_id"]
    sent = propose(tb, path="/api/basket/2")[0]["proposal_id"]
    approve(stack, e, sent)
    status(tb, sent)
    r = stack.api.post(f"/engagements/{e}/content/delete", json={"confirm_name": "lab"})
    assert r.status_code == 200, r.text
    with stack.Session() as s:
        assert s.scalars(select(TestAccount).where(TestAccount.engagement_id == e)).all() == []
        assert s.get(WriteProposal, waiting) is None
        kept = s.get(WriteProposal, sent)
        assert kept.status == "sent" and kept.request_enc is None
    assert stack.api.get(f"/engagements/{e}/test-accounts").json() == []
    assert gw_account(stack, job)[0] in (403, 404)


def test_the_raw_credentials_appear_nowhere_that_is_stored_or_shown(stack, gw, tmp_path):
    e, lane, job = setup(stack)
    tb = tools(gw, job)
    get(tb, account="A")
    get(tb, "/other", account="B")
    pid = propose(tb)[0]["proposal_id"]
    approve(stack, e, pid)
    status(tb, pid)
    tb.call("add_evidence", {"item_idx": 2, "exchange_ids": ["x1", "x2"], "summary": "who am I, as A and B"})
    job.log("done")
    gw.flush()
    # B's token went to the target (that is the point) and nowhere else.
    assert gw.up.header(1, "Authorization") == [f"Bearer {B_TOKEN}"]
    shown = [stack.api.get(p).text for p in (
        f"/engagements/{e}/test-accounts", f"/engagements/{e}/approvals", f"/engagements/{e}/gateway-log",
        f"/engagements/{e}/audit", f"/engagements/{e}/report", f"/engagements/{e}/report.html",
        f"/lanes/{lane}", f"/lanes/{lane}/context", f"/lanes/{lane}/agent-runs", f"/jobs/{job.id}")]
    with stack.Session() as s:
        for ev in s.scalars(select(Evidence)):
            shown.append(blobs.get(ev.sha256, engagement_id=e).decode("utf-8", "replace"))
        tables = [r[0] for r in s.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))]
        for t in tables:
            shown += [str(row) for row in s.execute(text(f"SELECT * FROM {t}")).all()]
    for path in Path(os.environ["ATTACKLEDGER_BLOBS"]).rglob("*"):
        if path.is_file():
            shown.append(path.read_bytes().decode("latin-1"))
    shown += tb.results + [json.dumps(job.spec, default=str)]
    everything = "\n".join(shown)
    assert len(everything) > 10_000
    for secret in SECRETS + (A_COOKIE, base64.b64encode(A_SESSION.encode()).decode()):
        assert secret not in everything, secret
    assert "as test account A" in everything and "as test account B" in everything


def test_the_gateway_scrubs_the_response_before_the_worker_gets_it(stack, gw):
    """What leaves the gateway towards the worker, before the API redacts anything."""
    e, lane, job = setup(stack)
    for label, secret in (("A", A_SESSION), ("B", B_TOKEN)):
        status_, body = gw.raw(job, "GET", f"http://{HOST}/me", headers={"X-AttackLedger-As": label})
        assert status_ == 200 and b"hello" in body
        assert secret.encode() not in body and b"rotated-session-value" not in body
    assert gw.up.header(0, "Cookie") == [A_COOKIE] and gw.up.header(1, "Authorization") == [f"Bearer {B_TOKEN}"]


def test_the_gateway_itself_refuses_accounts_without_redaction(tmp_path):
    from test_gateway import Stack as FakeStack
    st = FakeStack(tmp_path)
    try:
        st.api.add(1, traffic="agent", redact=False)
        st.api.account = None           # never asked: the gateway refuses first
        status_, _, body = st.get("http://app.example.com/", headers={"X-AttackLedger-As": "A"})
        assert status_ == 403 and b"redaction" in body and st.up.requests == []
        st.api.add(2, traffic="target")
        status_, _, body = st.get("http://app.example.com/", headers={"X-AttackLedger-As": "A"}, auth=st.auth(job=2))
        assert status_ == 403 and b"does not send requests as a test account" in body and st.up.requests == []
        status_, _, body = st.get("http://app.example.com/", headers={"X-AttackLedger-Approval": "3"})
        assert status_ == 400 and st.up.requests == []
    finally:
        st.close()


def test_write_tools_are_strict_offered_only_when_allowed_and_close_nothing():
    for t in agenttools.WRITE_TOOLS:
        assert t["strict"] is True and t["input_schema"]["additionalProperties"] is False
        assert set(t["input_schema"]["required"]) == set(t["input_schema"]["properties"])
    blob = json.dumps(agenttools.WRITE_TOOLS).lower()
    assert "receipt" not in blob and "close" not in blob
    assert agenttools.tools_for({"writes": {"allowed": False}}) == agenttools.TOOLS
    names = [t["name"] for t in agenttools.tools_for({"writes": {"allowed": True}})]
    assert names[-2:] == ["propose_write", "write_status"]
    params = __import__("app.agentloop", fromlist=["x"]).request_params(
        "claude-opus-5-5", [], agenttools.tools_for({"writes": {"allowed": True}}))
    assert [t["name"] for t in params["tools"]][-1] == "write_status"


def test_in_one_process_an_approved_write_is_sent_once_with_the_account(tmp_path):
    """agenttools.Toolbox with a transport (tests, and anything with a database): the gateway's
    part, using the approval, is played by the toolbox itself."""
    from test_agent import Clock, FakeTransport, make_lane
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from app import db
    eng_ = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    db.Base.metadata.create_all(eng_)
    s = sessionmaker(bind=eng_, autoflush=False, expire_on_commit=False)()
    lane, job = make_lane(s)
    lane.asset.engagement.allow_writes = True
    pairs = [["Cookie", A_COOKIE]]
    sealed, fp = vault.seal_secret(lane.asset.engagement_id, testaccounts.PURPOSE,
                                   __import__("app.ledger", fromlist=["x"]).canonical({"headers": pairs}))
    s.add(TestAccount(engagement_id=lane.asset.engagement_id, label="A", role="customer", hosts=[lane.asset.host],
                      kind="cookie", header_names=["Cookie"], material_enc=sealed, fingerprint=fp))
    s.commit()
    tr, clock = FakeTransport(status=201, body=b'{"ok":1}'), Clock()
    tb = agenttools.Toolbox(s, lane, job.id, transport=tr, sleep=clock.sleep, clock=clock.now)
    out = json.loads(tb.call("propose_write", {"method": "POST", "url": f"https://{lane.asset.host}/api/b",
                                               "headers": [], "body": "{}", "as_account": "A", "item_idx": 1,
                                               "reason": "r"})[0])
    assert tr.calls == []
    p = s.get(WriteProposal, out["proposal_id"])
    p.status, p.approved_sha256, p.decided_by_name = "approved", p.request_sha256, "Tess (tess@lab.test)"
    p.decided_at = datetime.now(timezone.utc)
    p.expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    s.commit()
    w = json.loads(tb.call("write_status", {"proposal_ids": [], "wait_seconds": 0})[0])["writes"][0]
    assert w["status"] == "sent" and w["note"] == "approved and sent: status 201"
    assert [c["method"] for c in tr.calls] == ["POST"]
    assert tr.calls[0]["headers"]["X-AttackLedger-As"] == "A" and "Cookie" not in tr.calls[0]["headers"]
    json.loads(tb.call("write_status", {"proposal_ids": [], "wait_seconds": 0})[0])
    assert len(tr.calls) == 1
    assert "as test account A" in vault.summary_of(s.get(Evidence, p.evidence_id))
