"""Regression tests for what the second fuzzing pass found (docs/security-review/FUZZING.md,
"Second pass", FZ-20 onwards).

Each input is a failing case of the fuzzers in test_fuzz2.py (or of a probe written while
building them), minimised by hand. The tests failed before the fix named in FUZZING.md and pass
after it. The gateway ones use the in-process gateway of test_gateway.py on 127.0.0.1, in front
of local stub upstreams; nothing leaves the machine.
"""
import asyncio
import json
import time

import pytest
from sqlalchemy import select

from app import gateway, gatewayapi, gatewaylog, redact
from app.models import GatewayRequest
from fuzzing import time_limit
from harness import stack  # noqa: F401  (fixture)
from test_gateway import Stack as GatewayStack, parse


@pytest.fixture()
def gw(tmp_path):
    s = GatewayStack(tmp_path)
    yield s
    s.close()


def _upstream(stack, handle):
    """Every connection the gateway opens goes to handle(reader, writer) on 127.0.0.1."""
    server = stack.run(asyncio.start_server(handle, "127.0.0.1", 0))
    stack.servers.append(server)
    port = server.sockets[0].getsockname()[1]

    async def connector(ip, p, ssl=None, server_hostname=None):
        return await asyncio.open_connection("127.0.0.1", port)
    stack.gw.open_connection = connector


def _head(stack, target="http://app.example.com/", method="GET", *lines: str, auth=None) -> bytes:
    return (f"{method} {target} HTTP/1.1\r\nHost: app.example.com\r\nConnection: close\r\n"
            f"Proxy-Authorization: {auth or stack.auth()}\r\n" + "".join(l + "\r\n" for l in lines) + "\r\n"
            ).encode("latin-1")


# ---- FZ-20: a request the gateway's own checks raised on ------------------------------------------

@pytest.mark.parametrize("raw", [
    "GET http://[shop/ HTTP/1.1",                                # urlsplit: "Invalid IPv6 URL"
    "approval \xb2",                                             # "²".isdigit() is True, int("²") raises
])
def test_fz20_a_request_the_checks_raise_on_is_a_refused_row(gw, raw):
    """It ended the connection with no answer and no row in the request log (the handler's
    catch-all printed a line on stderr)."""
    if raw.startswith("approval"):
        data = _head(gw, "http://app.example.com/", "GET", "X-AttackLedger-Approval: " + raw.split(" ", 1)[1])
    else:
        method, target, _ = raw.split(" ")
        data = _head(gw, target, method)
    with time_limit(10):
        status, headers, body = parse(gw.raw(data))
    assert status == 400 and headers["x-attackledger-gateway"] == "refused"
    row = gw.rows(1)[-1]
    assert row["verdict"] == "refused" and row["status"] == 400
    assert gw.up.requests == [] and gw.connects == []


def test_fz20_a_path_that_urlsplit_reads_as_an_authority_is_checked_and_sent(gw):
    """"//[x/" is a path: the _method check read it with urlsplit, which raised."""
    status, _, _ = parse(gw.raw(_head(gw, "http://app.example.com//[x/?_method=DELETE")))
    assert status == 403 and gw.up.requests == []
    status, _, _ = parse(gw.raw(_head(gw, "http://app.example.com//[x/?a=1")))
    assert status == 200 and gw.up.requests[0]["target"] == "//[x/?a=1"
    assert [r["verdict"] for r in gw.rows(2)] == ["refused", "allowed"]


@pytest.mark.parametrize("authority", ["app.example.com:4\xb23", "app.example.com:\xb9", "[::1]:\xb3"])
def test_fz20_a_port_of_superscript_digits_is_refused(authority):
    with pytest.raises(gateway.Refused, match="port"):
        gateway.split_authority(authority)


def test_fz20_a_credential_that_is_not_ascii_is_a_407_row(gw):
    """base64.b64decode raises ValueError, not binascii.Error, for text that is not ASCII (test_fuzz2)."""
    status, headers, _ = parse(gw.raw(_head(gw, auth="Basic am9iLTEuaHR0cHg6\xe9")))
    assert status == 407 and headers["proxy-authenticate"].startswith("Basic")
    row = gw.rows(1)[-1]
    assert row["verdict"] == "refused" and row["status"] == 407 and "malformed" in row["reason"]


def test_fz20_a_bug_in_the_checks_is_still_a_row(gw, monkeypatch):
    """Whatever raises while a request is checked, the request is refused and logged, not dropped."""
    def broken(*a, **k):
        raise KeyError("a bug")
    monkeypatch.setattr(gw.gw.policy, "check", broken)
    status, _, body = parse(gw.raw(_head(gw)))
    assert status == 500 and b"could not check" in body
    row = gw.rows(1)[-1]
    assert row["verdict"] == "failed" and row["status"] == 500 and "KeyError" in row["reason"]
    assert gw.up.requests == []


# ---- FZ-21: a request h11 cannot read --------------------------------------------------------------

@pytest.mark.parametrize("data, status", [
    (b"GET http://app.example.com/\xb2 HTTP/1.1\r\nHost: app.example.com\r\n\r\n", 400),     # not ASCII
    (b"GET http://app.example.com/ HTTP/1.1\r\nHost: app.example.com\r\nContent-Length: 1x\r\n\r\n", 400),
    (b"GET http://app.example.com/ HTTP/1.1\r\nHost: app.example.com\r\nno colon here\r\n\r\n", 400),
    (b"GET http://app.example.com/ HTTP/1.1\r\nHost: app.example.com\r\nX-A: b\r\n c\r\n\r\n", None),   # obs-fold: read
    (b"GET http://app.example.com/ HTTP/1.1\r\nHost: app.example.com\r\nX-Big: " + b"a" * 200_000 + b"\r\n\r\n", 431),
])
def test_fz21_a_request_head_h11_refuses_is_answered_and_logged(gw, data, status):
    """The connection was closed without an answer and without a row: a tool saw an empty reply
    and the request log did not show that anything was tried."""
    with time_limit(10):
        try:
            got, headers, body = parse(gw.raw(data))
        except ConnectionResetError:        # the gateway closed with the rest of a huge head unread
            got, headers, body = status, {"x-attackledger-gateway": "refused"}, b"HTTP/1.1"
    if status is None:          # h11 reads it; no credential, so a 407 like any other
        assert got == 407
        return
    assert got == status and headers["x-attackledger-gateway"] == "refused" and b"HTTP/1.1" in body
    row = gw.rows(1)[-1]
    assert row["verdict"] == "refused" and row["status"] == status and "not valid HTTP/1.1" in row["reason"]
    assert row["url"] == "" and gw.up.requests == [] and gw.connects == []
    assert b"\xb2" not in row["reason"].encode("latin-1", "replace")


def test_fz21_inside_a_tunnel_the_row_names_the_job_and_the_host(gw):
    import socket
    import ssl
    with socket.create_connection(("127.0.0.1", gw.port), timeout=10) as raw:
        raw.sendall(f"CONNECT app.example.com:443 HTTP/1.1\r\nHost: app.example.com:443\r\n"
                    f"Proxy-Authorization: {gw.auth()}\r\n\r\n".encode())
        assert raw.recv(4096).startswith(b"HTTP/1.1 200")
        ctx = ssl.create_default_context(cafile=gw.ca_file)
        with ctx.wrap_socket(raw, server_hostname="app.example.com") as tls:
            tls.sendall(b"GET /\xb2 HTTP/1.1\r\nHost: app.example.com\r\n\r\n")
            status, _, _ = parse(tls.recv(65536))
    assert status == 400
    row = gw.rows(1)[-1]
    assert row["job_id"] == 1 and row["host"] == "app.example.com" and row["port"] == 443
    assert row["verdict"] == "refused" and "not valid HTTP/1.1" in row["reason"]


def test_fz21_an_approved_writes_body_h11_refuses_is_logged_and_the_approval_is_not_used(gw):
    gw.api.add(6, kind="agent", traffic="agent")
    used = []

    async def approval(*a):
        used.append(a)
        return 200, {}
    gw.api.approval = approval
    data = _head(gw, "http://app.example.com/api/basket", "POST", "X-AttackLedger-Approval: 7",
                 "Transfer-Encoding: chunked", auth=gw.auth(job=6, tool="agent")) + b"zz\r\n{}\r\n0\r\n\r\n"
    with time_limit(10):
        status, _, _ = parse(gw.raw(data))
    assert status == 400 and used == [] and gw.up.requests == []
    row = gw.rows(1)[-1]
    assert row["verdict"] == "refused" and row["approval_id"] == 7 and "not valid HTTP/1.1" in row["reason"]


# ---- FZ-22: a target that never finishes its response head ---------------------------------------

def _hung_up(reader):
    """Done once the gateway closes its side of the connection to a stub."""
    f = asyncio.ensure_future(reader.read())
    f.add_done_callback(lambda f: f.cancelled() or f.exception())
    return f


async def _endless_1xx(reader, writer):
    await reader.readuntil(b"\r\n\r\n")
    closed = _hung_up(reader)      # the gateway hung up: stop
    try:
        for _ in range(10_000_000):
            if closed.done():
                break
            writer.write(b"HTTP/1.1 100 Continue\r\n\r\n" * 50)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        writer.close()


async def _dripping_head(reader, writer):
    await reader.readuntil(b"\r\n\r\n")
    closed = _hung_up(reader)
    try:
        writer.write(b"HTTP/1.1 200 OK\r\n")
        for _ in range(300):
            await asyncio.sleep(0.1)
            if closed.done():
                break
            writer.write(b"X-Slow: a\r\n")
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        writer.close()


@pytest.mark.parametrize("handle, why", [(_endless_1xx, "informational"), (_dripping_head, "in time")])
def test_fz22_a_target_that_never_ends_its_head_is_a_failed_row_in_bounded_time(gw, monkeypatch, handle, why):
    """Endless 100 Continue answers, or a head sent a line at a time, held the gateway's
    connection (and the tool's) for as long as the target liked: each read came within
    READ_TIMEOUT, and nothing bounded the head as a whole. No row was written until it ended."""
    monkeypatch.setattr(gateway, "HEAD_TIMEOUT", 1.5)
    _upstream(gw, handle)
    start = time.monotonic()
    with time_limit(15):
        status, headers, body = parse(gw.raw(_head(gw, "http://app.example.com/", "GET", "X-AttackLedger-Errors: 1"),
                                             timeout=15))
    assert time.monotonic() - start < 8
    assert status == 502 and headers["x-attackledger-gateway"] == "refused"
    row = gw.rows(1)[-1]
    assert row["verdict"] == "failed" and row["status"] == 502 and why in row["reason"]
    time.sleep(0.3)


def test_fz22_a_test_accounts_response_body_is_read_in_bounded_time(gw, monkeypatch):
    """A response sent as a test account is read whole before anything goes back (to scrub it), so
    a body sent a byte at a time held the connection with nothing sent to the tool."""
    monkeypatch.setattr(gateway, "SCRUBBED_BODY_TIMEOUT", 1.5)
    gw.api.add(6, kind="agent", traffic="agent")

    async def account(job_id, secret, label, host):
        return 200, {"label": "alice", "headers": [["Cookie", "sid=lab-fz22-session"]]}
    gw.api.account = account

    async def drip(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        closed = _hung_up(reader)
        try:
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")
            for _ in range(300):
                await asyncio.sleep(0.1)
                if closed.done():
                    break
                writer.write(b"a")
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()
    _upstream(gw, drip)
    start = time.monotonic()
    with time_limit(15):
        gw.raw(_head(gw, "http://app.example.com/", "GET", "X-AttackLedger-As: alice", auth=gw.auth(job=6, tool="agent")),
               timeout=15)
    assert time.monotonic() - start < 8
    time.sleep(0.3)             # the stub sees the gateway hang up
    row = gw.rows(1)[-1]
    assert row["account"] == "alice" and "in time" in row["reason"]


# ---- FZ-23 to FZ-27: redaction of XML, SAML, multipart, form and GraphQL bodies -----------------------

LAB = "lab-" + "Zq9" + "secretVALUE"        # split: the secret scan must not read test data as a credential


def redacted(text: str) -> str:
    out = redact.text(text, redact.Report())
    assert redact.text(out, redact.Report()) == out, "not idempotent"
    return out


@pytest.mark.parametrize("body", [
    f"<login><password>{LAB}</password></login>",
    f'<soap:Header><wsse:Security><wsse:UsernameToken><wsse:Username>tess</wsse:Username><wsse:Password '
    f'Type="http://docs.oasis-open.org/wss#PasswordText">{LAB}</wsse:Password></wsse:UsernameToken></wsse:Security>',
    f'<wsse:BinarySecurityToken ValueType="x" EncodingType="y">\n  {LAB}\n</wsse:BinarySecurityToken>',
    f"<Password><![CDATA[{LAB}]]></Password>",
    f"<p:apiKey>{LAB}</p:apiKey >",
    f'<cred password = "{LAB}"/>',
    f"<cred token='{LAB}'>",
    f"<methodCall><methodName>login</methodName><params><param><value><struct><member><name>password</name>"
    f"<value><string>{LAB}</string></value></member></struct></value></param></params></methodCall>",
    f"<member><name>session_id</name><value>{LAB}</value></member>",
    f"<dict><key>Password</key>\n\t<string>{LAB}</string></dict>",
    f'<configuration><add key="DbPassword" value="{LAB}"/></configuration>',
    f'<input type="hidden" name="csrf_token" value="{LAB}">',
    f'<meta name="csrf-token" content="{LAB}">',
])
def test_fz23_secrets_in_xml_and_html_are_redacted(body):
    """SOAP (WS-Security), XML-RPC, plists, .NET settings and HTML forms kept their secrets: only
    name="value" attributes were read."""
    out = redacted(body)
    assert LAB not in out and redact.marker(LAB) in out


@pytest.mark.parametrize("body", [
    "<ListBucketResult><Contents><Key>backups/password.txt</Key><Size>12</Size></Contents></ListBucketResult>",
    "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>",
    "<wsse:UsernameToken><wsse:Username>tess</wsse:Username></wsse:UsernameToken>",
    "<sessionInfo><user>tess</user></sessionInfo>",
    '<input type="password" name="password" value="">',
    "<p>Enter your <b>password</b> below</p>",
])
def test_fz23_xml_that_holds_no_secret_is_kept(body):
    """An S3 object key, an error code, an element holding other elements, an empty value, prose."""
    assert redacted(body) == body


@pytest.mark.parametrize("name", ["SAMLResponse", "SAMLart"])
def test_fz24_a_saml_response_or_artifact_is_redacted(name):
    """A signed SAML response (or the artifact that fetches it) logs its bearer in; both are posted
    as form fields (HTTP-POST and artifact bindings) and were stored as they were."""
    body = f"{name}=PHNhbWxwOlJlc3BvbnNlPg{LAB}%3D&RelayState=%2Fhome"
    out = redacted(body)
    assert LAB not in out and "RelayState=%2Fhome" in out
    raw = f"POST /acs HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n{body}".encode()
    assert LAB.encode() not in redact.http_message(raw, redact.Report())


@pytest.mark.parametrize("part", [
    f'Content-Disposition: form-data; name="password"\r\n\r\nfirst line\r\n{LAB}',
    f'Content-Disposition: form-data; name="private_key"\r\nContent-Type: text/plain\r\n\r\nline\n{LAB}\nline',
    f"Content-Disposition: form-data; name=password\r\n\r\n{LAB}",
    f'Content-Disposition: form-data; name="token"\r\n\r\n--not the boundary\r\n{LAB}',
])
def test_fz25_a_multipart_value_is_redacted_to_its_boundary(part):
    """Only the first line of a field was read (and only a quoted name), so the rest of a
    multi-line value, or a field named without quotes, was stored."""
    body = f"--xyz\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\ntess\r\n--xyz\r\n{part}\r\n--xyz--\r\n"
    out = redacted(body)
    assert LAB not in out and "tess" in out and out.endswith("\r\n--xyz--\r\n")
    raw = (f"POST /f HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=xyz\r\nContent-Length: {len(body)}\r\n\r\n"
           + body).encode()
    stored = redact.http_message(raw, redact.Report())
    assert LAB.encode() not in stored and f"Content-Length: {len(stored.split(b'\r\n\r\n', 1)[1])}".encode() in stored


@pytest.mark.parametrize("form", [
    f"user=tess&pass%77ord={LAB}",                  # a percent-encoded name
    f"user=tess&password=ab;{LAB}&x=1",             # characters a form value may hold raw
    f"user=tess&password=ab,{LAB}&x=1",
    f"user=tess&password=ab){LAB}&x=1",
    f"user=tess&password=ab'{LAB}&x=1",
    f"user=tess&password=ab#{LAB}&x=1",
    f'user=tess&password=ab"{LAB}&x=1',
    f"user=tess&password=ab<{LAB}&x=1",
])
def test_fz26_a_form_value_is_redacted_whole(form):
    """A value stopped at ; , ) ' # " or < (the rules are written for text, where those end a
    value), so the rest of a password a client sent unencoded was kept; a percent-encoded name
    was not recognised."""
    raw = f"POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n{form}".encode()
    out = redact.http_message(raw, redact.Report())
    assert LAB.encode() not in out and b"user=tess" in out
    assert redact.http_message(out, redact.Report()) == out
    target = "/login?" + form
    line = redact.http_message(f"GET {target} HTTP/1.1\r\nHost: shop.example.com\r\n\r\n".encode(), redact.Report())
    assert LAB.encode() not in line
    stored = redact.url("https://shop.example.com" + target.split("#")[0], redact.Report())
    assert LAB not in stored


def test_fz26_text_and_the_query_of_a_url_are_still_read_as_text():
    """Outside a form body or a query, those characters still end a value: code and prose."""
    assert redacted(f"f(password={LAB}); next") == f"f(password={redact.marker(LAB)}); next"


@pytest.mark.parametrize("body", [
    '{"query":"mutation { login(username: \\"tess\\", password: \\"%s\\") { token } }"}' % LAB,
    'mutation { login(username: "tess", password: "%s") { token } }' % LAB,
    "query=mutation%7Blogin(username%3A%22tess%22%2C%20password%3A%20%22" + LAB + "%22)%7D",
    '{"query":"{ me(sessionToken: \\"%s\\") { id } }"}' % LAB,
])
def test_fz27_a_secret_graphql_argument_is_redacted(body):
    """Variables were redacted (they are JSON), an argument written in the query was not."""
    out = redacted(body)
    assert LAB not in out and ("tess" in out or "me(" in out)


def test_fz27_graphql_that_holds_no_secret_is_kept():
    for body in ['{"query":"mutation($password: String!) { login(password: $password) { ok } }"}',
                 'query { country(code: "FR") { name } }', '{"query":"{ a(token: 5) }"}']:
        assert redacted(body) == body


# ---- FZ-28 and FZ-29: the gateway log ----------------------------------------------------------------

GATEWAY_TOKEN = "gateway-token-for-tests-000000000"


def _log_row(**change) -> dict:
    return {"at": "2026-10-10T12:00:00+00:00", "tool": "httpx", "kind": "target", "method": "GET",
            "url": "https://app.example.com/", "host": "app.example.com", "verdict": "allowed", **change}


def test_fz28_a_nul_and_a_lone_surrogate_in_one_batch_is_not_a_500(stack, monkeypatch):
    """The NUL guard rewrites a machine route's JSON (a NUL becomes U+FFFD) and wrote it back with
    ensure_ascii=False, which cannot encode a lone surrogate: the whole batch was a 500, which the
    gateway sends again for ever (and the worker's channel the same)."""
    monkeypatch.setenv("ATTACKLEDGER_GATEWAY_TOKEN", GATEWAY_TOKEN)
    body = json.dumps({"rows": [_log_row(url="https://app.example.com/\x00"), _log_row(reason="r\udc80")]})
    r = stack.api.post("/gateway/log", content=body, headers={"authorization": f"Bearer {GATEWAY_TOKEN}",
                                                              "content-type": "application/json"})
    assert r.status_code == 200 and r.json() == {"written": 2, "unlogged": []}
    with stack.Session() as s:
        got = s.scalars(select(GatewayRequest).order_by(GatewayRequest.id)).all()
    assert [g.url for g in got] == ["https://app.example.com/�", "https://app.example.com/"]
    assert got[1].reason == "r�"


@pytest.mark.parametrize("why", ["\ud800", "x\udfff\x00"])
def test_fz29_a_placeholder_is_storable_whatever_the_reason_says(why):
    """placeholder() is meant to be valid by construction; a reason (the API's own words, from an
    answer the gateway read) with a lone surrogate made the API refuse it, so the row stayed queued."""
    p = gatewaylog.placeholder({"verdict": "allowed", "tool": "a\ud800"}, why)
    gatewayapi._checked(p)
    assert "\ud800" not in p["reason"] + p["tool"]


@pytest.mark.parametrize("data", [{"unlogged": True}, {"unlogged": {"index": 0}}, {"unlogged": "0"},
                                  {"detail": [{"loc": 5, "msg": "m"}]}, {"detail": [{"loc": "body", "msg": 1}]}])
def test_fz30_the_gateway_reads_an_answer_of_any_shape(data):
    """A log answer of another shape (a proxy in front of the API) raised TypeError in the task that
    sends the log, which then stopped for good: rows queued up and the gateway refused all traffic."""
    assert gateway._unlogged(data, 3) == []
    assert isinstance(gateway._detail(data), str)


def test_fz30_the_log_task_survives_an_error_and_sends_the_rows_later(tmp_path, monkeypatch):
    from test_gateway import FakeApi
    api = FakeApi()
    gw = gateway.Gateway(api, None, deny_hosts=(), networks=[], quarantine=str(tmp_path / "q.jsonl"))
    gw.record(rules=None, tool="httpx", kind="target", method="GET", url="http://app.example.com/", verdict="allowed")
    calls = []
    real = api.post_log

    async def flaky(rows):
        calls.append(len(rows))
        if len(calls) == 1:
            raise RuntimeError("a bug")
        return await real(rows)
    api.post_log = flaky
    real_sleep = asyncio.sleep
    monkeypatch.setattr(asyncio, "sleep", lambda s: real_sleep(0))

    async def run():
        task = asyncio.ensure_future(gw.flush_forever())
        for _ in range(500):
            await asyncio.sleep(0)
            if api.logged:
                break
        task.cancel()
    with time_limit(10):
        asyncio.run(run())
    assert len(calls) >= 2 and len(api.logged) == 1 and not gw.log_rows


# ---- FZ-31 to FZ-33: text the database cannot hold, and the inbox filter --------------------------

from test_import import team, upload  # noqa: E402
from test_people import client  # noqa: E402,F401  (fixture)


def _json(c, method, url, body: str):
    return c.request(method, url, content=body, headers={"content-type": "application/json"})


@pytest.mark.parametrize("spelled", ['"\\ud800"', '"a\\uDFFFb"', '"\\udc80\\ud83d\\ude00"'])
def test_fz31_a_lone_surrogate_in_a_persons_json_is_a_422_not_a_500(client, spelled):
    """JSON can spell a lone surrogate and Python's reader accepts it; UTF-8, and so the database
    driver, cannot hold one: the commit raised and every route that stores text answered 500 (the
    report fuzz found it in an item's N/A reason). Refused like a NUL now."""
    _, e, a = team(client)
    r = _json(client, "POST", "/engagements", '{"name": %s, "pack_id": "web-pentest-wstg"}' % spelled)
    assert r.status_code == 422 and "surrogate" in r.text
    lane = client.post("/lanes", json={"asset_id": a, "role": "conf"}).json()["id"]
    r = _json(client, "PATCH", f"/lanes/{lane}/items/1", '{"state": "na", "na_reason": %s}' % spelled)
    assert r.status_code == 422 and "surrogate" in r.text
    r = client.request("POST", f"/lanes/{lane}/evidence", headers={"content-type": "application/json"},
                       content=b'{"kind": "note", "sha256": "' + b"a" * 64 + b'", "summary": "raw \xed\xa0\x80"}')
    assert r.status_code == 422 and "surrogate" in r.text           # the same, as raw (invalid) UTF-8 bytes
    ok = _json(client, "POST", "/engagements", '{"name": "pair \\ud83d\\ude00", "pack_id": "web-pentest-wstg"}')
    assert ok.status_code == 201 and ok.json()["name"] == "pair \U0001F600"         # a valid pair is text


def test_fz31_a_lone_surrogate_from_the_machine_channels_becomes_the_replacement_character(stack, monkeypatch):
    monkeypatch.setenv("ATTACKLEDGER_GATEWAY_TOKEN", GATEWAY_TOKEN)
    body = '{"rows": [{"at": "2026-10-10T12:00:00+00:00", "tool": "httpx", "kind": "target", "method": "GET", ' \
           '"url": "https://app.example.com/\\ud800", "host": "app.example.com", "verdict": "allowed"}]}'
    r = stack.api.post("/gateway/log", content=body.encode(), headers={"authorization": f"Bearer {GATEWAY_TOKEN}",
                                                                      "content-type": "application/json"})
    assert r.status_code == 200 and r.json()["written"] == 1


def test_fz32_a_json_body_without_a_content_type_is_guarded_too(client):
    """FastAPI reads a body without Content-Type as JSON; the NUL guard only looked at bodies that
    said they were JSON, so a NUL got through to the database (a 500 on Postgres)."""
    team(client)
    r = client.request("POST", "/engagements", content=b'{"name": "a\\u0000b", "pack_id": "web-pentest-wstg"}')
    assert r.status_code == 422 and "NUL" in r.text


@pytest.mark.parametrize("status", ["\xb2", "1" * 5000, "99999999999999999999"])
def test_fz33_an_inbox_status_filter_that_is_not_a_status_is_a_422(client, status):
    _, e, _ = team(client)
    r = client.get(f"/engagements/{e}/inbox", params={"status": status})
    assert r.status_code == 422 and "status is a code" in r.text


# ---- FZ-34: a lone surrogate in an export -----------------------------------------------------------

@pytest.mark.parametrize("where", ["postData", "content", "header", "comment", "creator", "statusText", "url"])
def test_fz34_a_lone_surrogate_in_a_har_is_imported_not_a_500(client, where):
    """The HAR adapter encoded body text with surrogateescape, which takes \\udc80 to \\udcff only:
    "\\ud800" raised and the whole import was a 500. Text fields kept the surrogate, and the commit
    raised. Each becomes U+FFFD; a URL with one is one unreadable row."""
    _, e, _ = team(client)
    s = "lab\ud800fz34"
    entry = {"request": {"method": "POST", "url": "https://shop.example.com/a",
                         "headers": [{"name": "X-Note", "value": s if where == "header" else "n"}],
                         "postData": {"mimeType": "text/plain", "text": s if where == "postData" else "p"}},
             "response": {"status": 200, "statusText": s if where == "statusText" else "OK", "headers": [],
                          "content": {"text": s if where == "content" else "ok"}},
             "comment": s if where == "comment" else "c"}
    if where == "url":
        entry["request"]["url"] = "https://shop.example.com/" + s
    har = {"log": {"version": "1.2", "creator": {"name": s if where == "creator" else "fz"},
                   "entries": [entry, {"request": {"method": "GET", "url": "https://shop.example.com/b"},
                                       "response": {"status": 200}}]}}
    r = upload(client, e, json.dumps(har).encode(), "har", name="s.har")
    assert r.status_code == 201, r.text[:300]
    got = client.get(f"/engagements/{e}/inbox").json()["entries"]
    assert len(got) == (1 if where == "url" else 2)
    for x in got:
        assert client.get(f"/engagements/{e}/inbox/{x['id']}").status_code == 200


# ---- FZ-35: a DNS label with a dot in it ------------------------------------------------------------

def _dns(labels: list[bytes], qtype: int = 1) -> bytes:
    import struct
    q = b"".join(bytes([len(p)]) + p for p in labels) + b"\0"
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, 1)


@pytest.mark.parametrize("labels", [[b"x.shop", b"example", b"com"], [b"x", b"shop.example", b"com"],
                                    [b"x", b"shop", b"example.com"], [b"x\\", b"shop", b"example", b"com"]])
def test_fz35_the_dns_name_checked_is_the_name_forwarded(labels):
    """A label may hold any byte, a dot too. The labels were joined with dots, so the question
    for the two labels "x.shop" and "example.com"... read as x.shop.example.com, in scope of
    *.shop.example.com, and the packet forwarded asked another name, which is not under
    shop.example.com at all. A dot (or backslash) in a label is now escaped as DNS writes it."""
    from test_gateway import FakeApi
    api = FakeApi()
    api.scopes = [{"engagement_id": 1, "include": ["*.shop.example.com"], "exclude": [], "rate_limit_rps": 5}]
    g = gateway.Gateway(api, None, deny_hosts=())
    forwarded = []

    async def forward(q):
        forwarded.append(q)
        return q[:2] + b"\x81\x80" + q[4:]
    g._dns_forward = forward
    reply = asyncio.run(g.dns_answer(_dns(labels)))
    assert reply[3] & 0x0F == 5 and forwarded == []                       # REFUSED, nothing forwarded
    assert g.log_rows[-1]["verdict"] == "refused" and "\\" in g.log_rows[-1]["host"]
    assert asyncio.run(g.dns_answer(_dns([b"x", b"shop", b"example", b"com"])))[3] & 0x0F == 0
