"""Regression tests for what the third fuzzing pass found (docs/security-review/FUZZING.md,
"Third pass", FZ-36 onwards).

Each input is a failing case of the fuzzers in test_fuzz3.py (or of a probe written while
building them), minimised by hand. The tests failed before the fix named in FUZZING.md and pass
after it. The gateway ones use the in-process gateway of test_gateway.py on 127.0.0.1, in front
of local stub upstreams, and Python's ssl with the gateway's own CA; nothing leaves the machine.
"""
import asyncio
import socket
import ssl
import sys
import time

import pytest

from app import gateway
from fuzzing import time_limit
from test_gateway import Stack as GatewayStack, parse
from tlsfuzz import client_hello, connect, drain


@pytest.fixture()
def gw(tmp_path, monkeypatch):
    monkeypatch.setattr(gateway, "HEAD_TIMEOUT", 1.0)
    monkeypatch.setattr(gateway, "HANDSHAKE_TIMEOUT", 1.0)
    s = GatewayStack(tmp_path)
    yield s
    s.close()


def _connect_head(stack, *lines: str) -> bytes:
    return (f"CONNECT app.example.com:443 HTTP/1.1\r\nHost: app.example.com:443\r\n"
            f"Proxy-Authorization: {stack.auth()}\r\n" + "".join(l + "\r\n" for l in lines) + "\r\n").encode()


def _rows_after(stack, before: int, want: int = 1, timeout: float = 3.0) -> list:
    end = time.time() + timeout
    while len(stack.gw.log_rows) - before < want and time.time() < end:
        time.sleep(0.005)
    time.sleep(0.05)
    return stack.gw.log_rows[before:]


def _one(stack, data: bytes, *, close: bool = True, timeout: float = 5.0) -> bytes:
    with socket.create_connection(("127.0.0.1", stack.port), timeout=timeout) as s:
        s.sendall(data)
        if close:
            s.shutdown(socket.SHUT_WR)
        return drain(s, timeout)


# ---- FZ-36: a CONNECT with a body, or bytes before the 200 ---------------------------------------

@pytest.mark.parametrize("extra, body", [
    (["Content-Length: 5"], b"hello"),
    (["Content-Length: 5"], b"he"),                         # cut off
    (["Transfer-Encoding: chunked"], b"5\r\nhello\r\n0\r\n\r\n"),
    ([], b"\x16\x03\x01\x00\x05hello"),                     # a ClientHello sent without waiting for the 200
])
def test_fz36_a_connect_with_a_body_or_early_bytes_is_refused_and_logged(gw, extra, body):
    """The connection was closed with no answer and no row (with early bytes, after a 200)."""
    with time_limit(10):
        out = _one(gw, _connect_head(gw, *extra) + body)
    status, headers, _ = parse(out)
    assert status == 400 and headers["x-attackledger-gateway"] == "refused"
    row = _rows_after(gw, 0)[-1]
    assert row["method"] == "CONNECT" and row["verdict"] == "refused" and row["job_id"] == 1
    assert row["host"] == "app.example.com" and "nothing was relayed" in row["reason"]
    assert gw.up.requests == [] and gw.connects == []


# ---- FZ-37: plain bytes sent before the tunnel was open were read as if they came through TLS ------

def test_fz37_plain_bytes_before_the_tunnel_opens_are_never_read_inside_it(gw):
    """A client sent CONNECT, then (before the 200 came back) a plain HTTP request, then made the
    TLS handshake: the plain request was read from the stream's buffer as the tunnel's first
    request and sent to the target, against "every tunnel is TLS". The checks still applied
    (scope, Host), so nothing out of scope was reachable."""
    original = gw.api.session

    async def slow(job_id, secret):               # an API call takes a moment, as in a deployment
        await asyncio.sleep(0.3)
        return await original(job_id, secret)
    gw.api.session = slow
    with time_limit(10), socket.create_connection(("127.0.0.1", gw.port), timeout=5) as s:
        s.sendall(_connect_head(gw))
        time.sleep(0.1)
        s.sendall(b"GET /plain HTTP/1.1\r\nHost: app.example.com\r\n\r\n")
        assert s.recv(4096).startswith(b"HTTP/1.1 200")
        ctx = ssl.create_default_context(cafile=gw.ca_file)
        with pytest.raises((ssl.SSLError, OSError)):
            with ctx.wrap_socket(s, server_hostname="app.example.com") as tls:
                tls.settimeout(3)
                assert tls.recv(4096) == b""
                raise ConnectionResetError("closed")
    row = _rows_after(gw, 0)[-1]
    assert gw.up.requests == [] and row["method"] == "CONNECT" and row["verdict"] == "refused"
    assert "before the tunnel was open" in row["reason"]


# ---- FZ-38: a tunnel that carried no request, a request head that never ended --------------------

def test_fz38_a_tunnel_without_a_request_has_one_row(gw):
    """A failed handshake (plain HTTP, a client that does not trust the CA, garbage, nothing at all)
    and a tunnel closed or left idle after a good one: no row before, so a tool that only made
    handshakes (a TLS scanner) or failed every one did not appear in the request log."""
    ctx = ssl.create_default_context(cafile=gw.ca_file)

    def plain():
        s = connect(gw.port, gw.auth())
        s.sendall(b"GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n")
        return drain(s)

    def untrusted():
        s = connect(gw.port, gw.auth())
        with pytest.raises(ssl.SSLCertVerificationError):
            ssl.create_default_context().wrap_socket(s, server_hostname="app.example.com")
        return b""                  # the failed handshake closed the socket

    def garbage():
        s = connect(gw.port, gw.auth())
        s.sendall(b"\x00\x01\x02\x03" * 10)
        return drain(s)

    def idle():
        return drain(ctx.wrap_socket(connect(gw.port, gw.auth(tool="testssl")), server_hostname="app.example.com"))

    def closed():
        ctx.wrap_socket(connect(gw.port, gw.auth()), server_hostname="app.example.com").close()
        return b""
    # The last one may also end while the gateway still writes its TLS 1.3 session tickets.
    cases = [(plain, ("plain HTTP, not TLS",)), (untrusted, ("trust the gateway CA",)),
             (garbage, ("the TLS handshake failed",)),
             (lambda: drain(connect(gw.port, gw.auth())), (f"no TLS handshake within {gateway.HANDSHAKE_TIMEOUT:g} s",)),
             (idle, (f"carried no request in {gateway.HEAD_TIMEOUT:g} s",)),
             (closed, ("before sending a request", "closed the connection"))]
    for case, why in cases:
        before = len(gw.gw.log_rows)
        with time_limit(10):
            out = case()
            rows = _rows_after(gw, before)
        name = getattr(case, "__name__", "nothing")
        assert len(rows) == 1 and b"HTTP/1.1" not in out, (name, [r["reason"] for r in rows])
        row = rows[0]
        assert row["method"] == "CONNECT" and row["job_id"] == 1 and row["host"] == "app.example.com", name
        assert row["verdict"] in ("refused", "failed") and any(w in row["reason"] for w in why), (name, row["reason"])
        assert "nothing was relayed" in row["reason"] and row["status"] is None, name
        if case is idle:
            assert row["tool"] == "testssl" and row["verdict"] == "failed"
    assert gw.up.requests == [] and gw.connects == []


def test_fz38_a_tunnel_that_carried_requests_has_no_row_of_its_own(gw):
    ctx = ssl.create_default_context(cafile=gw.ca_file)
    with time_limit(10):
        tls = ctx.wrap_socket(connect(gw.port, gw.auth()), server_hostname="app.example.com")
        tls.sendall(b"GET /a HTTP/1.1\r\nHost: app.example.com\r\n\r\n")
        drain(tls)
    rows = _rows_after(gw, 0, 2, timeout=1.0)
    assert [(r["method"], r["verdict"]) for r in rows] == [("GET", "allowed")]


@pytest.mark.parametrize("partial", [
    b"GET http://app.example.com/ HTTP/1.1\r\nHost: app",
    b"CONNECT app.example.com:443 HTTP/1.1\r\n",
    b"G",
])
def test_fz38_a_request_head_that_never_ends_is_answered_408_and_logged(gw, partial):
    """The client sent part of a head and then nothing: the connection timed out with no answer
    and no row."""
    with time_limit(10):
        out = _one(gw, partial, close=False)
    status, headers, _ = parse(out)
    assert status == 408 and headers["x-attackledger-gateway"] == "refused"
    row = _rows_after(gw, 0)[-1]
    assert row["verdict"] == "refused" and row["status"] == 408 and row["url"] == ""
    assert "did not arrive in time" in row["reason"] and row["duration_ms"] >= 900


def test_fz38_inside_a_tunnel_a_head_that_never_ends_names_the_job_once(gw):
    ctx = ssl.create_default_context(cafile=gw.ca_file)
    with time_limit(10):
        tls = ctx.wrap_socket(connect(gw.port, gw.auth()), server_hostname="app.example.com")
        tls.sendall(b"GET /a HTTP/1.1\r\nHost: app.exa")
        status, _, _ = parse(drain(tls))
    rows = _rows_after(gw, 0, 2, timeout=1.0)
    assert status == 408 and len(rows) == 1
    assert rows[0]["job_id"] == 1 and rows[0]["host"] == "app.example.com" and rows[0]["status"] == 408


def test_fz38_an_idle_connection_leaves_no_row(gw):
    """No flood: a connection that sent nothing (the healthcheck connects every 3 s) and a
    keep-alive connection idle after its request have nothing to log."""
    with time_limit(10):
        _one(gw, b"", close=False)
        _one(gw, (f"GET http://app.example.com/ HTTP/1.1\r\nHost: app.example.com\r\n"
                  f"Proxy-Authorization: {gw.auth()}\r\n\r\n").encode(), close=False)
    rows = _rows_after(gw, 0, 2, timeout=1.0)
    assert [(r["method"], r["verdict"]) for r in rows] == [("GET", "allowed")]


# ---- FZ-39: a TLS server name (SNI) that is not the CONNECT host ----------------------------------

@pytest.mark.parametrize("sni", ["other.example.com", "evil.example.net", "admin.example.com"])
def test_fz39_a_server_name_other_than_the_connect_host_is_refused(gw, sni):
    """A client that does not check the certificate (-k) made a handshake for another name than
    it had CONNECTed to: the gateway did not look. Its requests still had to name the CONNECT
    host in Host, so nothing reached another host; now the tunnel is refused and says why."""
    ctx = ssl.create_default_context(cafile=gw.ca_file)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    with time_limit(10):
        tls = ctx.wrap_socket(connect(gw.port, gw.auth()), server_hostname=sni)
        try:
            tls.sendall(b"GET / HTTP/1.1\r\nHost: app.example.com\r\nConnection: close\r\n\r\n")
        except OSError:
            pass
        out = drain(tls)
    row = _rows_after(gw, 0)[-1]
    assert b"HTTP/1.1" not in out and gw.up.requests == [] and gw.connects == []
    assert row["method"] == "CONNECT" and row["verdict"] == "refused" and f"(SNI) {sni} is not" in row["reason"]


@pytest.mark.parametrize("sni", [None, "APP.EXAMPLE.COM", "app.example.com."])
def test_fz39_no_server_name_or_the_same_one_in_another_case_is_accepted(gw, sni):
    ctx = ssl.create_default_context(cafile=gw.ca_file)
    ctx.check_hostname = False
    with time_limit(10):
        tls = ctx.wrap_socket(connect(gw.port, gw.auth()), server_hostname=sni)
        tls.sendall(b"GET / HTTP/1.1\r\nHost: app.example.com\r\nConnection: close\r\n\r\n")
        assert parse(drain(tls))[0] == 200
    assert len(gw.up.requests) == 1


@pytest.mark.parametrize("sni", [b"192.0.2.10", b"evil.example.net", b"", b"a" * 300, "é.example.com".encode(),
                                 b"\xff\xfe", b"app\x00.example.com"])
def test_fz39_odd_server_names_in_a_raw_client_hello_end_in_one_row(gw, sni, capfd, monkeypatch):
    """IP literal, another host, empty, overlong, not ASCII, NUL: OpenSSL or Python refuses the
    handshake, or the gateway answers and the handshake goes no further. Never a crash, one row,
    and the not-ASCII case is one line on stderr, not a traceback (gateway.quiet_unraisable)."""
    monkeypatch.setattr(sys, "unraisablehook", gateway.quiet_unraisable(sys.unraisablehook))
    with time_limit(10):
        s = connect(gw.port, gw.auth())
        s.sendall(client_hello(sni))
        drain(s, 3)
        s.close()
    rows = _rows_after(gw, 0)
    err = capfd.readouterr().err
    assert len(rows) == 1 and rows[0]["method"] == "CONNECT" and rows[0]["verdict"] == "refused", rows
    assert "Traceback" not in err and "connection ended by an error" not in err, err[:500]
    assert gw.up.requests == [] and gw.connects == []


# ---- FZ-40: a refusal inside a tunnel did not name the tunnel's job --------------------------------

@pytest.mark.parametrize("request_line, why", [
    (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "HTTP/2 is not spoken here"),
    (b"GET http://app.example.com/ HTTP/1.1\r\nHost: app.example.com\r\n\r\n", "use a path"),
    (b"GET / HTTP/1.1\r\nHost: evil.example.net\r\n\r\n", "Host header"),
])
def test_fz40_a_refusal_inside_a_tunnel_names_its_job(gw, request_line, why):
    """Refused before the credential was looked up, so the row had no job and no engagement and
    the engagement's log did not show it. An HTTP/2 client (ALPN h2 only, which the gateway does
    not acknowledge) now reads why."""
    ctx = ssl.create_default_context(cafile=gw.ca_file)
    ctx.set_alpn_protocols(["h2"])
    with time_limit(10):
        tls = ctx.wrap_socket(connect(gw.port, gw.auth()), server_hostname="app.example.com")
        assert tls.selected_alpn_protocol() is None
        tls.sendall(request_line)
        status, _, body = parse(drain(tls))
    row = _rows_after(gw, 0)[-1]
    assert status in (400, 403) and why.encode() in body
    assert row["job_id"] == 1 and row["engagement_id"] == 1 and why in row["reason"]
    assert gw.up.requests == []


def test_quiet_unraisable_passes_anything_else_on():
    seen = []
    hook = gateway.quiet_unraisable(seen.append)

    class U:
        def __init__(self, exc, obj):
            self.exc_value, self.object = exc, obj
    hook(U(UnicodeDecodeError("ascii", b"\xff", 0, 1, "x"), b"\xff"))
    hook(U(ValueError("other"), None))
    assert [type(u.exc_value) for u in seen] == [ValueError]
