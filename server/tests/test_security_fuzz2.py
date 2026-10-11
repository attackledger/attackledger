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
