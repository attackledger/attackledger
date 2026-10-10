"""The second, adversarial pass over the security review's fixes (docs/security-review/RECHECK.md).

Each test tries a variant that the review's own regression tests do not cover: either it shows that
a fix holds (named "held"), or it failed before a fix made in this pass and is kept as its
regression test. Everything runs in-process or against local stubs on 127.0.0.1.
"""
import asyncio
import gzip
import json
import zlib

import pytest

from app import agentloop, gateway
from test_gateway import SECRET, Stack  # noqa: F401
from test_security_gateway import OWN, COOKIE_VALUE, FakeApi, _resolver, account_stack, cookie_of, \
    http_response


@pytest.fixture()
def stack(tmp_path):
    s = Stack(tmp_path)
    yield s
    s.close()


# ---- GW-1: what the Claude API body check lets through ------------------------------------------

def refused(body) -> bool:
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    try:
        gateway.Policy.check_service_body(raw)
    except gateway.Refused:
        return True
    return False


FETCH_TOOL = '{"type": "web_fetch_20260209", "name": "web_fetch"}'


@pytest.mark.parametrize("raw", [
    # Escapes in keys and values decode before the check, as in any JSON parser.
    '{"model": "m", "max_tokens": 1, "messages": [], "t\\u006fols": [' + FETCH_TOOL + ']}',
    '{"model": "m", "max_tokens": 1, "messages": [], "tools": [{"t\\u0079pe": "web_fetch_20260209", "name": "x"}]}',
    '{"model": "m", "max_tokens": 1, "tools": [], "t\\u006fols": [' + FETCH_TOOL + '], "messages": []}',
    '{"model": "m", "max_tokens": 1, "messages": [{"role": "user", "content": [{"type": "image", "source": '
    '{"type": "ur\\u006c", "url": "https://x.invalid/a.png"}}]}]}',
    # A URL source deep inside a tool result, and in a mid-conversation system message.
    '{"model": "m", "max_tokens": 1, "messages": [{"role": "user", "content": [{"type": "tool_result", '
    '"tool_use_id": "t", "content": [{"type": "document", "source": {"type": "url", "url": "https://x.invalid/"}}]}]}]}',
    '{"model": "m", "max_tokens": 1, "messages": [{"role": "system", "content": [{"type": "image", "source": '
    '{"type": "url", "url": "https://x.invalid/"}}]}]}',
    # The MCP connector and the code container under other spellings: not keys an agent run sends.
    '{"model": "m", "max_tokens": 1, "messages": [], "MCP_SERVERS": [{"type": "url", "url": "https://x.invalid/"}]}',
    '{"model": "m", "max_tokens": 1, "messages": [], "mcp-servers": []}',
    '{"model": "m", "max_tokens": 1, "messages": [], "mcp_servers\\u0000": []}',
    '{"model": "m", "max_tokens": 1, "messages": [], "container": {"skills": []}}',
    '{"model": "m", "max_tokens": 1, "messages": [], "context_management": {"edits": []}}',
    # A tool type that is not exactly "custom" (another case, null, a list) is not the agent's own.
    '{"model": "m", "max_tokens": 1, "messages": [], "tools": [{"type": "Custom", "name": "x"}]}',
    '{"model": "m", "max_tokens": 1, "messages": [], "tools": [{"type": null, "name": "x"}]}',
    '{"model": "m", "max_tokens": 1, "messages": [], "tools": {"type": "custom"}}',
    # Bodies another parser could read differently: trailing data, a second document, comments.
    '{"model": "m", "messages": []} {"tools": [' + FETCH_TOOL + ']}',
    '{"model": "m", "messages": []}\n// {"tools": []}',
    '[{"model": "m"}]',
])
def test_gw1_held_escaped_nested_and_odd_bodies_are_refused(raw):
    assert refused(raw.encode())


def test_gw1_held_every_agent_models_own_call_is_sent():
    """Regression check: what agentloop.request_params sends on every model it supports (the
    fallbacks of Opus and Sonnet, none for Haiku; betas go in a header) passes the check."""
    for model in agentloop.MODELS:
        params = agentloop.request_params(model, [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": [{"type": "thinking", "thinking": "", "signature": "s"},
                                              {"type": "tool_use", "id": "t", "name": "http_request",
                                               "input": {"method": "GET", "url": "https://shop.lab.test/"}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t",
                                          "content": '{"type": "url", "status": 200}'}]}])
        params.pop("betas", None)
        assert not refused(params), model


# ---- GW-3: compressed responses to a test account's request --------------------------------------

def _account_get(stack):
    return stack.get("http://app.example.com/debug", auth=stack.auth(job=6, tool="agent"),
                     headers={"X-AttackLedger-As": "alice"})


@pytest.mark.parametrize("coding", ["gzip, gzip", "zstd", "br", "compress", "gzip;q=1", "identity, gzip"])
def test_gw3_held_encodings_the_gateway_cannot_read_are_withheld(stack, coding):
    account_stack(stack, lambda head: http_response(gzip.compress(gzip.compress(cookie_of(head).encode())),
                                                    f"Content-Encoding: {coding}"))
    status, headers, body = _account_get(stack)
    assert status == 200 and body == b"" and "content-encoding" not in headers
    assert "withheld" in stack.rows(1)[-1]["reason"]


def test_gw3_held_a_compression_bomb_is_cut_off(stack, monkeypatch):
    monkeypatch.setattr(gateway, "MAX_SCRUBBED_BODY", 1_000_000)
    account_stack(stack, lambda head: http_response(gzip.compress(b"\0" * 5_000_000), "Content-Encoding: gzip"))
    status, _, body = _account_get(stack)
    assert status == 200 and body == b"" and "withheld" in stack.rows(1)[-1]["reason"]


def test_gw3_every_member_of_a_gzip_body_is_decoded(stack):
    """gzip allows several members one after the other (RFC 1952 2.2), and clients decode them
    all. The gateway decoded the first and dropped the rest, without a word: the session was not
    passed on, but the response the tool saw was cut short, silently."""
    account_stack(stack, lambda head: http_response(
        gzip.compress(b"<p>first</p>") + gzip.compress(f"<pre>{cookie_of(head)}</pre><p>last</p>".encode()),
        "Content-Encoding: gzip"))
    status, _, body = _account_get(stack)
    assert status == 200
    assert COOKIE_VALUE.encode() not in body
    assert body.startswith(b"<p>first</p><pre>[redacted:sha256:") and body.endswith(b"<p>last</p>"), body


def raw_deflate(data: bytes) -> bytes:
    c = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return c.compress(data) + c.flush()


def test_gw3_held_a_raw_deflate_body_is_scrubbed_too(stack):
    """deflate is sent zlib-wrapped (RFC 9110) or raw (some servers); both are read."""
    account_stack(stack, lambda head: http_response(raw_deflate(cookie_of(head).encode()), "Content-Encoding: deflate"))
    status, _, body = _account_get(stack)
    assert status == 200 and COOKIE_VALUE.encode() not in body and b"[redacted:sha256:" in body


# ---- GW-5 / GW-8: addresses that carry another address -------------------------------------------

def test_gw8_addresses_that_embed_a_refused_ipv4_address_are_refused(monkeypatch):
    """NAT64 (64:ff9b::/96, RFC 6052), 6to4 (2002::/16) and IPv4-compatible (::a.b.c.d) addresses
    carry an IPv4 address that a translator or a tunnel delivers to. The gateway unwrapped only
    IPv4-mapped ones (::ffff:a.b.c.d), so loopback, cloud metadata and the gateway's own networks
    were allowed in those forms."""
    gw = gateway.Gateway(FakeApi(), None, deny_hosts=(), networks=OWN)
    table = {"nat64-loop.example.com": "64:ff9b::7f00:1", "nat64-meta.example.com": "64:ff9b::a9fe:a9fe",
             "nat64-ali.example.com": "64:ff9b::6464:64c8", "nat64-host.example.com": "64:ff9b::ac13:1",
             "6to4-host.example.com": "2002:ac13:1::1", "compat-loop.example.com": "::7f00:1",
             "mapped-host.example.com": "::ffff:172.19.0.1",                       # held before
             "nat64-ok.example.com": "64:ff9b::5db8:d822", "v6.example.com": "2001:db8::1"}

    async def go():
        _resolver(monkeypatch, table)
        for host in ("nat64-ok.example.com", "v6.example.com"):
            assert await gw.resolve(host) == table[host], host
        for host in ("nat64-loop.example.com", "nat64-meta.example.com", "nat64-ali.example.com",
                     "nat64-host.example.com", "6to4-host.example.com", "compat-loop.example.com",
                     "mapped-host.example.com"):
            with pytest.raises(gateway.Refused, match="never contacted"):
                await gw.resolve(host)
    asyncio.run(go())


# ---- GW-10: legitimate header values ------------------------------------------------------------

@pytest.mark.parametrize("name,value", [
    ("Cookie", "a=b; c=d"), ("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.e30.x-_=="),
    ("X-Json", '{"a": [1, 2], "b": "c\\"d"}'), ("X-Tab", "a\tb"), ("X-Latin", "café"),
    ("X-Empty-Looking", "-"), ("Content-Type", "multipart/form-data; boundary=----x"),
])
def test_gw10_held_ordinary_header_values_are_accepted(name, value):
    assert gateway.header_problem(name, value) is None


# ---- AUTH-2: requests that pages of other sites send ----------------------------------------------

from test_agent import api  # noqa: E402,F401  (fixture)
from test_security_review_auth import _key, _people  # noqa: E402


def test_auth2_held_other_spellings_of_another_site(api, monkeypatch):
    _people(api, monkeypatch)
    for headers in ({"Sec-Fetch-Site": "Same-Site"}, {"Sec-Fetch-Site": " CROSS-SITE "},
                    {"Sec-Fetch-Site": "same-site", "Origin": "http://testserver"},   # Fetch Metadata wins
                    {"Origin": "http://testserver.evil.example"}, {"Origin": "http://evil.example#testserver"},
                    {"Origin": "http://testserver@evil.example"}, {"Origin": "null"}):
        key = _key(api)
        r = api.post(f"/auth/keys/{key['id']}/revoke", headers=headers)
        assert r.status_code == 403, (headers, r.text)
    # The app through a proxy that drops the port (nginx's $host) or keeps it (Vite), and clients
    # that are not browsers.
    for headers in ({"Sec-Fetch-Site": "same-origin", "Origin": "http://testserver:5173"},
                    {"Sec-Fetch-Site": "none"}, {}):
        key = _key(api)
        assert api.post(f"/auth/keys/{key['id']}/revoke", headers=headers).status_code == 200, headers


def test_auth2_open_mode_answers_only_local_names(api, monkeypatch):
    """DNS rebinding: a page on rebind.attacker.example:8000, whose name the attacker then points
    at 127.0.0.1, sends same-origin requests to the open API (Sec-Fetch-Site: same-origin, no
    cookie needed), and can read the answers too. Open mode acts as the local operator for
    whoever reaches it, so it answers only to names a page of another site cannot take: local
    names, names without a dot (the compose services) and IP addresses."""
    monkeypatch.delenv("ATTACKLEDGER_API_TOKEN", raising=False)
    monkeypatch.delenv("ATTACKLEDGER_REQUIRE_SIGN_IN", raising=False)
    rebound = {"Host": "rebind.attacker.example:8000", "Sec-Fetch-Site": "same-origin",
               "Origin": "http://rebind.attacker.example:8000"}
    r = api.post("/engagements", json={"name": "rebound"}, headers=rebound)
    assert r.status_code == 403, r.text
    assert api.get("/engagements", headers=rebound).status_code == 403
    for host in ("localhost:8000", "127.0.0.1:8000", "[::1]:8000", "api:8000", "app.localhost", "192.168.1.20:8080",
                 "testserver"):
        assert api.get("/engagements", headers={"Host": host}).status_code == 200, host
    assert api.get("/health", headers=rebound).status_code == 200         # says only which mode it is in


def test_auth2_a_named_deployment_with_sign_in_is_not_limited_to_local_names(api, monkeypatch):
    _people(api, monkeypatch)
    assert api.get("/engagements", headers={"Host": "attackledger.bank.example"}).status_code == 200


# ---- AUTH-7: a signed payload with a chain position the database cannot hold --------------------

def test_auth7_a_chain_position_beyond_the_databases_integers_is_a_422(monkeypatch):
    """_payload_problem checks that the ids and the chain position are whole numbers, but not their
    size: 10**30 reached the database query (SQLite: OverflowError), a 500."""
    import json as _json

    import test_signing as ts
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app import auth, db
    from app.main import app
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
    try:
        with TestClient(app, raise_server_exceptions=False) as c:
            e, lane, ids = ts.setup(c)
            ts.sign_in(c, "rita@lab.test")
            k = ts.register(c)
            for path, value in (("chain", 10 ** 30), ("engagement", 10 ** 30), ("lane", -(10 ** 30)),
                                ("signer", 2 ** 63)):
                def mutate(payload, path=path, value=value):
                    p = _json.loads(payload)
                    p[path]["seq" if path == "chain" else "id"] = value
                    return _json.dumps(p, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                r = ts.signed_close(c, lane, k, mutate)
                assert r.status_code == 422, (path, r.status_code, r.text)
            assert ts.signed_close(c, lane, k).status_code == 200             # control
    finally:
        app.dependency_overrides.clear()


# ---- EV-1 with EV-2: a void hidden by moving the receipt's issue time ----------------------------

from test_keytrust import env, register, sign_in, signed_close  # noqa: E402,F401
from test_security_verifier import VOID, rehash, run, void_then_sign_another  # noqa: E402
from test_signing import verifier  # noqa: E402


def moved(report: dict, lane_id: int, seconds: int = 1) -> dict:
    """The void kept in the report: only the lane's status (not signed) and the receipt's issue time
    (not signed, and allowed to differ from the signed one by up to 15 minutes) changed."""
    from datetime import datetime, timedelta
    r = json.loads(json.dumps(report))
    lane = next(l for l in r["lanes"] if l["lane_id"] == lane_id)
    lane["status"] = "closed"
    r["summary"]["lanes_receipted"] += 1
    rc = lane["receipt"]
    rc["issued_at"] = (datetime.fromisoformat(rc["issued_at"]) + timedelta(seconds=seconds)).isoformat()
    return rehash(r)


def test_ev1_a_void_is_not_hidden_by_moving_the_receipts_issue_time(env, tmp_path):
    """EV-1 matches a void entry to a receipt by its exact issue time, which a report repeats
    unsigned; EV-2 lets that copy differ from the signed time by up to 15 minutes. Moved by a
    second, the void entry named no receipt, and the voided receipt verified as receipted, in
    strict mode too, with the void entry left in the report so that O-2's count still held."""
    c, _ = env
    report, A = void_then_sign_another(c, later=True)
    assert any(x["action"] == VOID for x in report["audit_log"]["entries"])
    for seconds in (1, -30, 600):
        forged = moved(report, A, seconds)
        assert verifier.check_signatures(forged)[0] == []                  # within the window
        problems = verifier.check_audit_log(forged, strict=True)[0]
        assert any("reported as receipted, but the change history records that this receipt was voided" in p
                   for p in problems), (seconds, problems)
        assert run(tmp_path, forged, "--require-history")[0] == 1


def test_ev1_held_a_new_receipt_on_the_same_manifest_right_after_a_void_verifies(env, tmp_path):
    """Regression check for the fix above: a receipt signed seconds after the void of an earlier one
    with the same manifest is a new receipt, and the old void does not name it."""
    c, _ = env
    report, A = void_then_sign_another(c, later=True)
    sign_in(c, "rita@lab.test")
    k = register(c)
    signed_close(c, A, k)
    sign_in(c, "owner@lab.test")
    again = c.get(f"/engagements/{report['engagement']['id']}/report").json()
    assert next(l for l in again["lanes"] if l["lane_id"] == A)["status"] == "closed"
    code, out = run(tmp_path, again, "--require-history")
    assert code == 0, out


# ---- GW-2: port probes and requests together ----------------------------------------------------

def test_gw2_port_probes_and_requests_together_open_at_most_rate_connections(stack):
    """A probe took the request token and connected; a request took a connection token, then a
    request token. A port scan beside a crawler opened up to twice the rate in connections."""
    import threading
    import time

    from app import egress
    from test_gateway import peak
    stack.api.jobs[1]["rules"]["rate_limit_rps"] = 2
    opened = []
    inner = stack.gw.open_connection

    async def counting(ip, port, ssl=None, server_hostname=None):
        opened.append(time.monotonic())
        return await inner(ip, port, ssl=ssl, server_hostname=server_hostname)
    stack.gw.open_connection = counting
    probes = egress.Egress(1, SECRET, address=f"127.0.0.1:{stack.port}")
    results = []
    threads = [threading.Thread(target=lambda: results.append(probes.probe("app.example.com", 80)[0]))
               for _ in range(4)]
    threads += [threading.Thread(target=lambda i=i: results.append(stack.get(f"http://app.example.com/{i}")[0]))
                for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert results.count(200) == 8, results
    assert peak(opened) <= 2, peak(opened)


# ---- the command-line verifier's output -------------------------------------------------------

def test_the_verifier_prints_report_text_with_terminal_controls_escaped(env, tmp_path):
    """The engagement name (and every other value a report gives) was printed as it was: a name
    with line breaks printed fake PASS lines and "Verified.", and ESC[8m then concealed the real
    result in most terminals, whatever the exit code said."""
    from test_security_verifier import report_of, two_items
    c, _ = env
    e, _, _, _ = two_items(c)
    r = report_of(c, e)
    r["evidence"][0]["sha256"] = "0" * 64                     # it fails
    r["engagement"]["name"] = "Acme\n  PASS  Evidence chain\n\nVerified.\x1b[8m\u202e"
    code, out = run(tmp_path, r)
    assert code == 1
    assert "\x1b" not in out and "\u202e" not in out
    assert out.splitlines()[0].startswith(
        "AttackLedger report: Acme\\x0a  PASS  Evidence chain\\x0a\\x0aVerified.\\x1b[8m\\u202e (")
    assert [l for l in out.splitlines() if l.startswith("Verifi")] == ["Verification FAILED."]
