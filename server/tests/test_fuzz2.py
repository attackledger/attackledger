"""Property-based fuzzing, second pass (docs/security-review/FUZZING.md, "Second pass").

The targets the first pass left out: the gateway's own HTTP parsing (requests from tools and
responses from targets, through h11), the gateway log ingestion (POST /gateway/log), redaction
of XML, multipart, form and GraphQL bodies, and the inbox mapping and report builder. Same
harness as test_fuzz.py (fuzzing.py): seeded, offline, time-limited; a failure names the seed and
the iteration. ATTACKLEDGER_FUZZ_ITERATIONS makes every test run that many inputs.
"""
import asyncio
import json
import socket
import time

import pytest

from app import gateway
from fuzzing import INTERESTING, iterations, mutate_bytes, rng, show, time_limit
from test_gateway import Stack as GatewayStack


@pytest.fixture()
def gw(tmp_path):
    s = GatewayStack(tmp_path)
    yield s
    s.close()


def _send(stack, data: bytes, timeout: float = 5.0) -> bytes:
    """One connection: the bytes, then end of input, then whatever comes back until close."""
    with socket.create_connection(("127.0.0.1", stack.port), timeout=timeout) as s:
        try:
            s.sendall(data)
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        out = b""
        try:
            while chunk := s.recv(65536):
                out += chunk
        except (ConnectionResetError, socket.timeout):
            pass
    return out


def _settle(stack, before: int, want: int, timeout: float = 3.0) -> list:
    end = time.time() + timeout
    while len(stack.gw.log_rows) - before < want and time.time() < end:
        time.sleep(0.005)
    time.sleep(0.02)
    return stack.gw.log_rows[before:]


# ---- the gateway: requests from a tool -------------------------------------------------------------

def _request_seeds(stack) -> list[bytes]:
    a = stack.auth()
    agent = stack.auth(job=6, tool="agent")
    return [
        f"GET http://app.example.com/a?q=1 HTTP/1.1\r\nHost: app.example.com\r\nProxy-Authorization: {a}\r\n"
        "Accept: */*\r\nConnection: close\r\n\r\n".encode(),
        f"HEAD http://app.example.com/ HTTP/1.1\r\nHost: app.example.com\r\nProxy-Authorization: {a}\r\n\r\n".encode(),
        f"OPTIONS http://app.example.com:8080/x HTTP/1.1\r\nHost: app.example.com:8080\r\nProxy-Authorization: {a}\r\n"
        "X-AttackLedger-Errors: 1\r\n\r\n".encode(),
        f"POST http://app.example.com/api HTTP/1.1\r\nHost: app.example.com\r\nProxy-Authorization: {agent}\r\n"
        "X-AttackLedger-Approval: 7\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n".encode(),
        f"POST http://app.example.com/api HTTP/1.1\r\nHost: app.example.com\r\nProxy-Authorization: {agent}\r\n"
        "X-AttackLedger-Approval: 7\r\nContent-Length: 2\r\n\r\n{}".encode(),
        f"CONNECT app.example.com:443 HTTP/1.1\r\nHost: app.example.com:443\r\nProxy-Authorization: {a}\r\n"
        "X-AttackLedger-Probe: connect\r\n\r\n".encode(),
        f"GET http://app.example.com/1 HTTP/1.1\r\nHost: app.example.com\r\nProxy-Authorization: {a}\r\n\r\n"
        f"GET http://app.example.com/2 HTTP/1.1\r\nHost: app.example.com\r\nProxy-Authorization: {a}\r\n\r\n".encode(),
        f"GET http://evil.example.net/ HTTP/1.1\r\nHost: evil.example.net\r\nProxy-Authorization: {a}\r\n\r\n".encode(),
    ]


HEAD_TOKENS = INTERESTING + [b"\r\nTransfer-Encoding: chunked", b"\r\nContent-Length: 5", b"\r\nContent-Length: -1",
                             b"\r\nUpgrade: h2c", b"\r\nX-HTTP-Method-Override: DELETE", b" HTTP/1.0", b"\r\n ",
                             b"\r\nX-AttackLedger-As: alice", b"\r\nX-AttackLedger-Approval: \xb9", b"[", b"//",
                             b"?_method=DELETE", b"ffffffffffffffffffff\r\n", b"\r\n0\r\n\r\n", b":99999", b":0",
                             b"\x85", b"\xa0", b"\t", b"%", b"\\"]


def _mutate_head(r, data: bytes) -> bytes:
    out = bytearray(mutate_bytes(r, data, r.randint(1, 3)))
    for _ in range(r.randint(0, 2)):
        i = r.randrange(len(out) + 1)
        out[i:i] = r.choice(HEAD_TOKENS)
    return bytes(out)


def test_fuzz_gateway_requests_are_answered_and_logged_never_dropped(gw, capfd):
    """Mutated request heads and bodies: the handler never ends by an error, every input that
    holds a whole head leaves a row, and nothing reaches the upstream that is not an allowed row."""
    r = rng("gateway-requests")
    gw.api.add(6, kind="agent", traffic="agent")

    async def approval(job_id, secret, approval_id, method, url, body_sha256, acct):
        return 200, {"approval_id": approval_id, "method": method, "url": url, "headers": [], "account": acct}

    async def account(job_id, secret, label, host):
        return 200, {"label": label, "headers": [["Cookie", "sid=lab-fuzz-session"]]}
    gw.api.approval, gw.api.account = approval, account
    seeds = _request_seeds(gw)
    for i in range(iterations(120)):
        data = _mutate_head(r, r.choice(seeds))
        before, sent_before = len(gw.gw.log_rows), len(gw.up.requests)
        with time_limit(15, f"iteration {i}"):
            out = _send(gw, data)
            # A tunnel that was opened and never carried a request sent nothing: it has no row of its own.
            tunnel = out.startswith(b"HTTP/1.1 200 Connection established")
            whole = b"\r\n\r\n" in data and not tunnel
            rows = _settle(gw, before, 1 if whole else 0, timeout=2.0 if whole else 0.05)
        allowed = [x for x in rows if x["verdict"] == "allowed" and x["method"] != "PROBE"]
        if whole:
            assert rows, f"no row for iteration {i}: {show(data)}"
        assert len(gw.up.requests) - sent_before <= len(allowed), f"sent without an allowed row, {i}: {show(data)}"
        err = capfd.readouterr().err
        assert "connection ended by an error" not in err and "could not be checked" not in err, \
            f"iteration {i}: {err[:500]} {show(data)}"


# ---- the gateway: responses from a target --------------------------------------------------------

RESPONSE_SEEDS = [
    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n3\r\nabc\r\n0\r\nX-T: 1\r\n\r\n",
    b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\nSet-Cookie: s=1\r\n\r\n",
    b"HTTP/1.0 302 Found\r\nLocation: http://app.example.com/b\r\n\r\nbody until close",
    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
]
RESPONSE_TOKENS = INTERESTING + [b"\r\nContent-Length: 10", b"\r\nTransfer-Encoding: gzip", b"\r\nConnection: Upgrade",
                                 b"\r\nUpgrade: x", b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
                                 b"HTTP/1.1 100 Continue\r\n\r\n" * 40, b"\r\n ", b"\x80\xff", b"999", b"1xx"]


def test_fuzz_gateway_responses_never_hang_and_always_leave_a_row(gw, capfd, monkeypatch):
    """Mutated responses from a target: within a bounded time, the gateway sends the tool a
    response or closes the connection, and logs one row for the request."""
    monkeypatch.setattr(gateway, "HEAD_TIMEOUT", 2.0)
    r = rng("gateway-responses")
    answer = {}

    async def handle(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(answer["data"])
            await writer.drain()
        except (ConnectionError, OSError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
    server = gw.run(asyncio.start_server(handle, "127.0.0.1", 0))
    gw.servers.append(server)
    port = server.sockets[0].getsockname()[1]

    async def connector(ip, p, ssl=None, server_hostname=None):
        return await asyncio.open_connection("127.0.0.1", port)
    gw.gw.open_connection = connector
    req = (f"GET http://app.example.com/ HTTP/1.1\r\nHost: app.example.com\r\nProxy-Authorization: {gw.auth()}\r\n"
           "X-AttackLedger-Errors: 1\r\nConnection: close\r\n\r\n").encode()
    for i in range(iterations(120)):
        data = bytearray(mutate_bytes(r, r.choice(RESPONSE_SEEDS), r.randint(1, 3)))
        if r.random() < 0.5:
            j = r.randrange(len(data) + 1)
            data[j:j] = r.choice(RESPONSE_TOKENS)
        answer["data"] = bytes(data)
        before = len(gw.gw.log_rows)
        with time_limit(15, f"iteration {i}"):
            _send(gw, req, timeout=10)
            rows = _settle(gw, before, 1)
        assert len(rows) == 1, f"iteration {i}: {len(rows)} rows for {show(bytes(data))}"
        assert rows[0]["verdict"] in ("allowed", "failed"), rows[0]
        err = capfd.readouterr().err
        assert "connection ended by an error" not in err, f"iteration {i}: {err[:500]} {show(bytes(data))}"
