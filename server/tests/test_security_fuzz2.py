"""Regression tests for what the second fuzzing pass found (docs/security-review/FUZZING.md,
"Second pass", FZ-20 onwards).

Each input is a failing case of the fuzzers in test_fuzz2.py (or of a probe written while
building them), minimised by hand. The tests failed before the fix named in FUZZING.md and pass
after it. The gateway ones use the in-process gateway of test_gateway.py on 127.0.0.1, in front
of local stub upstreams; nothing leaves the machine.
"""
import asyncio
import time

import pytest

from app import gateway
from fuzzing import time_limit
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
