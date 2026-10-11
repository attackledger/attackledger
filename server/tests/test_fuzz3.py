"""Property-based fuzzing, third pass (docs/security-review/FUZZING.md, "Third pass").

The targets the second pass left out: the gateway's TLS layer (CONNECT, its CA's leaf
certificates, the server name and ALPN a client sends, a client sending anything at all after the
200), request heads that never end, redaction of positional XML-RPC parameters, SAML assertions,
unquoted HTML attributes and JSON values under a secret key that are objects or arrays, and the
report from histories with signed receipts, voids, content deletion and the seal. Same harness as
test_fuzz.py (fuzzing.py): seeded, offline, time-limited; a failure names the seed and the
iteration. ATTACKLEDGER_FUZZ_ITERATIONS makes every test run that many inputs.
"""
import socket
import ssl
import sys
import time

import pytest

from app import gateway
from fuzzing import INTERESTING, iterations, mutate_bytes, rng, show, time_limit
from test_gateway import Stack as GatewayStack
from tlsfuzz import ALPNS, SNIS, client_hello, connect, drain


@pytest.fixture()
def gw(tmp_path, monkeypatch):
    monkeypatch.setattr(gateway, "HEAD_TIMEOUT", 0.6)
    monkeypatch.setattr(gateway, "HANDSHAKE_TIMEOUT", 0.6)
    monkeypatch.setattr(sys, "unraisablehook", gateway.quiet_unraisable(sys.unraisablehook))
    s = GatewayStack(tmp_path)
    yield s
    s.close()


def _settle(stack, before: int, want: int, timeout: float = 3.0) -> list:
    end = time.time() + timeout
    while len(stack.gw.log_rows) - before < want and time.time() < end:
        time.sleep(0.005)
    time.sleep(0.02)
    return stack.gw.log_rows[before:]


def _clean_stderr(capfd, what: str) -> None:
    err = capfd.readouterr().err
    assert "connection ended by an error" not in err and "could not be checked" not in err \
        and "Traceback" not in err, f"{what}: {err[:800]}"


# ---- the gateway's TLS layer ---------------------------------------------------------------------

REQUESTS = [b"GET / HTTP/1.1\r\nHost: app.example.com\r\nConnection: close\r\n\r\n",
            b"HEAD /a?b=1 HTTP/1.1\r\nHost: app.example.com:443\r\nConnection: close\r\n\r\n",
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: evil.example.net\r\nConnection: close\r\n\r\n",
            b"GET http://app.example.com/ HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: app.example.com\r\nContent-Length: 2\r\n\r\n{}"]


def test_fuzz_tls_raw_client_hellos_end_in_one_row_and_relay_nothing(gw, capfd):
    """A ClientHello with any server name (IP literal, empty, overlong, not ASCII, NUL, another
    host) and any ALPN list, mutated byte by byte or not, sent after CONNECT, then the connection
    closed or left idle: never a crash, exactly one row for the connection (the tunnel's own,
    refused or failed), nothing sent upstream, within a bounded time."""
    r = rng("tls-hellos")
    hellos = [client_hello(sni, alpn, tls13=t) for sni in SNIS for alpn in ALPNS[:3] for t in (True, False)]
    hellos += [client_hello(r.choice(SNIS), alpn) for alpn in ALPNS[3:]]
    for i in range(iterations(60)):
        hello = r.choice(hellos)
        if r.random() < 0.6:
            hello = mutate_bytes(r, hello, r.randint(1, 4))
        tail = r.choice([b"", b"", b"\x15\x03\x03\x00\x02\x02\x28", hello, r.choice(INTERESTING)])
        before = len(gw.gw.log_rows)
        with time_limit(15, f"iteration {i}"):
            s = connect(gw.port, gw.auth())
            try:
                s.sendall(hello + tail)
                if r.random() < 0.7:
                    s.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            out = drain(s, 5)
            s.close()
            rows = _settle(gw, before, 1)
        assert len(rows) == 1, f"iteration {i}: {len(rows)} rows for {show(hello)}"
        assert rows[0]["method"] == "CONNECT" and rows[0]["verdict"] in ("refused", "failed"), rows[0]
        assert rows[0]["job_id"] == 1 and rows[0]["host"] == "app.example.com", rows[0]
        assert b"HTTP/1.1" not in out and gw.up.requests == [] and gw.connects == [], f"iteration {i}"
        _clean_stderr(capfd, f"iteration {i}")


def test_fuzz_tls_handshakes_with_odd_names_and_requests(gw, capfd):
    """Whole handshakes with Python's ssl (the gateway's CA, or none checked), server names and
    ALPN of every kind, then nothing, a request or a mutated one: one row per connection, a
    request reaches the upstream only when the server name was the CONNECT host's (or none) and
    the row says allowed, and nothing reaches it for another name."""
    r = rng("tls-handshakes")
    names = [None, "app.example.com", "APP.example.COM", "app.example.com.", "other.example.com",
             "evil.example.net", "192.0.2.10", "admin.example.com", "a" * 63 + ".example.com"]
    for i in range(iterations(40)):
        sni = r.choice(names)
        ctx = ssl.create_default_context(cafile=gw.ca_file)
        if sni != "app.example.com" or r.random() < 0.3:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        alpn = r.choice(ALPNS)
        if alpn and all(p for p in alpn):
            ctx.set_alpn_protocols([p.decode() for p in alpn])
        request = r.choice(REQUESTS + [None, None])
        if request is not None and r.random() < 0.4:
            request = mutate_bytes(r, request, r.randint(1, 3))
        before, sent_before = len(gw.gw.log_rows), len(gw.up.requests)
        with time_limit(15, f"iteration {i}"):
            raw = connect(gw.port, gw.auth())
            try:
                tls = ctx.wrap_socket(raw, server_hostname=sni)
            except (ssl.SSLError, OSError):
                tls = None
                raw.close()
            if tls is not None:
                assert tls.selected_alpn_protocol() in (None, "http/1.1"), f"iteration {i}"
                try:
                    if request:
                        tls.sendall(request)
                    if r.random() < 0.5:
                        tls.unwrap() if r.random() < 0.3 else tls.shutdown(socket.SHUT_WR)
                except (ssl.SSLError, OSError):
                    pass
                drain(tls, 5)
                tls.close()
            rows = _settle(gw, before, 1)
        matching = sni is None or sni == "192.0.2.10" or sni.lower().rstrip(".") == "app.example.com"
        sent = len(gw.up.requests) - sent_before
        tunnel_rows = [x for x in rows if x["method"] == "CONNECT"]
        what = f"iteration {i}: {[(x['method'], x['reason']) for x in rows]} {sni!r} {show(request)}"
        assert rows and (len(rows) == 1 if not request or tunnel_rows else True), what
        assert sent <= sum(1 for x in rows if x["verdict"] == "allowed"), f"iteration {i}"
        if not matching:
            assert sent == 0 and rows[0]["method"] == "CONNECT" and rows[0]["verdict"] == "refused", \
                f"iteration {i}: {sni!r} {rows[0]}"
        assert rows[0]["job_id"] == 1 and rows[0]["host"] == "app.example.com", rows[0]
        _clean_stderr(capfd, f"iteration {i}")


HEAD_SEEDS = [b"GET http://app.example.com/a?q=1 HTTP/1.1\r\nHost: app.example.com\r\nProxy-Authorization: %s\r\n\r\n",
              b"CONNECT app.example.com:443 HTTP/1.1\r\nHost: app.example.com:443\r\nProxy-Authorization: %s\r\n\r\n",
              b"OPTIONS http://app.example.com:8080/x HTTP/1.1\r\nHost: app.example.com:8080\r\n\r\n"]


def test_fuzz_a_head_cut_anywhere_is_one_row(gw, capfd):
    """Any non-empty part of a request head (plain, CONNECT, or inside a tunnel), then the
    connection closed or left idle until the head timeout: exactly one row (a 400 or a 408), the
    tool answered, nothing sent upstream."""
    r = rng("cut-heads")
    ctx = ssl.create_default_context(cafile=gw.ca_file)
    for i in range(iterations(40)):
        seed = r.choice(HEAD_SEEDS)
        data = seed.replace(b"%s", gw.auth().encode()) if b"%s" in seed else seed
        if r.random() < 0.3:
            data = mutate_bytes(r, data, 1)
        end = data.find(b"\r\n\r\n")
        data = data[:r.randint(1, end + 3 if end >= 0 else len(data))]
        if b"\r\n\r\n" in data or not data:
            continue
        in_tunnel = r.random() < 0.3 and not data.startswith(b"CONNECT")
        idle = r.random() < 0.4
        before = len(gw.gw.log_rows)
        with time_limit(15, f"iteration {i}"):
            if in_tunnel:
                s = ctx.wrap_socket(connect(gw.port, gw.auth()), server_hostname="app.example.com")
            else:
                s = socket.create_connection(("127.0.0.1", gw.port), timeout=5)
            s.sendall(data)
            if not idle:
                (s.unwrap() if in_tunnel else s).shutdown(socket.SHUT_WR)
            out = drain(s, 5)
            s.close()
            rows = _settle(gw, before, 1)
        assert len(rows) == 1, f"iteration {i}: {len(rows)} rows for {show(data)} (idle {idle}, tunnel {in_tunnel})"
        assert rows[0]["verdict"] in ("refused", "failed") and gw.up.requests == [], f"iteration {i}: {rows[0]}"
        if in_tunnel:
            assert rows[0]["job_id"] == 1 and rows[0]["host"] == "app.example.com", rows[0]
        if idle and not in_tunnel:
            assert out.startswith(b"HTTP/1.1 408") or rows[0]["method"] == "CONNECT", f"iteration {i}: {show(out)}"
        _clean_stderr(capfd, f"iteration {i}")
