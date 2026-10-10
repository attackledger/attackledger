"""Regression tests from the gateway and worker-isolation security review (docs/security-review/GATEWAY.md).

Each test names the finding it covers. They use the in-process gateway of test_gateway.py (a real
gateway on localhost in front of local stub upstreams); nothing leaves the machine.
"""
import asyncio
import gzip
import http.client
import json
import socket
import ssl
import threading
import time
import zlib
from pathlib import Path

import pytest
import yaml

from app import gateway, jobgates, modules
from test_gateway import SECRET, Stack, parse, peak  # noqa: F401

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture()
def stack(tmp_path):
    s = Stack(tmp_path)
    yield s
    s.close()


# ---- GW-1: Claude API server tools and URL sources are egress the gateway does not check -------

def claude_call(stack, job, body: bytes, path="/v1/messages"):
    ctx = ssl.create_default_context(cafile=stack.ca_file)
    c = http.client.HTTPSConnection("127.0.0.1", stack.port, context=ctx, timeout=10)
    c.set_tunnel("api.anthropic.com", 443, headers={"Proxy-Authorization": stack.auth(job=job, tool="claude")})
    try:
        c.request("POST", path, body=body, headers={"content-type": "application/json"})
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


AGENT_TOOL = {"name": "http_request", "description": "d", "input_schema": {
    "type": "object", "properties": {"url": {"type": "string"}, "type": {"type": "string"}}}}


@pytest.mark.parametrize("body", [
    # Server tools: Anthropic's servers fetch or search on the request's behalf (web fetch, web search),
    # or run code; none of it passes the gateway's scope, identification, rate or log.
    {"model": "m", "max_tokens": 1, "messages": [], "tools": [{"type": "web_fetch_20250910", "name": "web_fetch"}]},
    {"model": "m", "max_tokens": 1, "messages": [], "tools": [AGENT_TOOL, {"type": "web_search_20250305",
                                                                           "name": "web_search"}]},
    # The MCP connector: Anthropic connects to any URL the request names.
    {"model": "m", "max_tokens": 1, "messages": [],
     "mcp_servers": [{"type": "url", "url": "https://collector.invalid/sse", "name": "x"}]},
    # Image and document blocks with a URL source: Anthropic fetches the URL.
    {"model": "m", "max_tokens": 1, "messages": [{"role": "user", "content": [
        {"type": "image", "source": {"type": "url", "url": "https://out-of-scope.invalid/a.png"}}]}]},
    {"model": "m", "max_tokens": 1, "system": [{"type": "text", "text": "x"}], "messages": [{"role": "user", "content": [
        {"type": "document", "source": {"type": "url", "url": "https://out-of-scope.invalid/a.pdf"}}]}]},
])
def test_gw1_claude_api_calls_cannot_make_anthropic_fetch_for_the_worker(stack, body):
    stack.api.add(6, kind="agent", traffic="agent")
    status, text = claude_call(stack, 6, json.dumps(body).encode())
    assert status == 403 and b"not sent" in text
    assert stack.up.requests == []


def test_gw1_duplicate_keys_and_non_json_bodies_are_refused(stack):
    """A parser that keeps the first of two keys would see the server tool the gateway did not."""
    stack.api.add(6, kind="agent", traffic="agent")
    dup = (b'{"model": "m", "max_tokens": 1, "messages": [], "tools": [{"type": "web_fetch_20250910", '
           b'"name": "web_fetch"}], "tools": []}')
    assert claude_call(stack, 6, dup)[0] == 403
    assert claude_call(stack, 6, b"not json")[0] == 403
    assert claude_call(stack, 6, gzip.compress(b'{"model": "m"}'))[0] == 403
    assert stack.up.requests == []


def test_gw1_the_agents_own_calls_are_still_sent(stack):
    from app import agentloop
    stack.api.add(6, kind="agent", traffic="agent")
    model = next(iter(agentloop.MODELS))
    params = agentloop.request_params(model, [{"role": "user", "content": [
        {"type": "text", "text": "go"}, {"type": "tool_result", "tool_use_id": "t", "content": "{\"type\": \"url\"}"}]}])
    params.pop("betas", None)                          # the SDK sends these as a header
    assert claude_call(stack, 6, json.dumps(params).encode())[0] == 200
    assert claude_call(stack, 6, json.dumps({"model": model, "messages": [], "tools": [AGENT_TOOL]}).encode(),
                       path="/v1/messages/count_tokens")[0] == 200
    assert len(stack.up.requests) == 2


# ---- GW-2: upstream connections were opened before the rate token ------------------------------

def test_gw2_connections_to_targets_are_paced_like_requests(stack):
    stack.api.jobs[1]["rules"]["rate_limit_rps"] = 3
    opened = []
    inner = stack.gw.open_connection

    async def counting(ip, port, ssl=None, server_hostname=None):
        opened.append(time.monotonic())
        return await inner(ip, port, ssl=ssl, server_hostname=server_hostname)
    stack.gw.open_connection = counting
    results = []
    threads = [threading.Thread(target=lambda i=i: results.append(stack.get(f"http://app.example.com/{i}")[0]))
               for i in range(9)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert results.count(200) == 9
    # Before the fix all nine TCP (and TLS) connections were opened at once; only the request
    # heads waited for a token.
    assert peak(opened) <= 3 and peak([r["t"] for r in stack.up.requests]) <= 3


def test_gw2_a_request_refused_for_the_rate_opens_no_connection(stack, monkeypatch):
    monkeypatch.setattr(gateway, "MAX_WAIT", 0.2)
    stack.api.jobs[1]["rules"]["rate_limit_rps"] = 1
    opened = []
    inner = stack.gw.open_connection

    async def counting(ip, port, ssl=None, server_hostname=None):
        opened.append(port)
        return await inner(ip, port, ssl=ssl, server_hostname=server_hostname)
    stack.gw.open_connection = counting
    results = []
    threads = [threading.Thread(target=lambda: results.append(stack.get("http://app.example.com/")[0]))
               for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert sorted(results) == [200, 429, 429, 429, 429]
    assert len(opened) == 1 and len(stack.up.requests) == 1


# ---- GW-3 / GW-4: a test account's session in an encoded response ---------------------------------

COOKIE_VALUE = "eyJpdiI6IlpYaGhiWEJzWlE9PSIsInZhbHVlIjoic2VjcmV0In0%3D"
ACCOUNT = {"label": "alice", "headers": [["Cookie", f"laravel_session={COOKIE_VALUE}"]]}


def account_stack(stack, respond):
    """The agent job 6 may send as test account alice; the upstream answers with respond(request head)."""
    stack.api.add(6, kind="agent", traffic="agent")

    async def account(job_id, secret, label, host):
        return 200, ACCOUNT
    stack.api.account = account

    async def handle(reader, writer):
        head = await reader.readuntil(b"\r\n\r\n")
        writer.write(respond(head))
        await writer.drain()
        writer.close()

    async def start():
        return await asyncio.start_server(handle, "127.0.0.1", 0)
    server = stack.run(start())
    stack.servers.append(server)
    port = server.sockets[0].getsockname()[1]

    async def connector(ip, p, ssl=None, server_hostname=None):
        return await asyncio.open_connection("127.0.0.1", port)
    stack.gw.open_connection = connector


def http_response(body: bytes, *headers: str) -> bytes:
    return (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n" + "".join(h + "\r\n" for h in headers).encode()
            + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)


def cookie_of(head: bytes) -> str:
    return next(l.split(":", 1)[1].strip() for l in head.decode("latin-1").split("\r\n") if l.lower().startswith("cookie:"))


@pytest.mark.parametrize("encoding,encode", [
    ("gzip", gzip.compress),
    ("deflate", zlib.compress),
])
def test_gw3_a_compressed_response_is_scrubbed_too(stack, encoding, encode):
    """The gateway asks for Accept-Encoding: identity, but a target may compress anyway."""
    account_stack(stack, lambda head: http_response(encode(f"<pre>{cookie_of(head)}</pre>".encode()),
                                                    f"Content-Encoding: {encoding}"))
    status, headers, body = stack.get("http://app.example.com/debug", auth=stack.auth(job=6, tool="agent"),
                                      headers={"X-AttackLedger-As": "alice"})
    assert status == 200
    if headers.get("content-encoding") == encoding:
        body = gzip.decompress(body) if encoding == "gzip" else zlib.decompress(body)
    assert COOKIE_VALUE.encode() not in body and b"[redacted:sha256:" in body
    assert "content-encoding" not in headers


def test_gw3_an_encoding_the_gateway_cannot_read_is_not_passed_on(stack):
    account_stack(stack, lambda head: http_response(cookie_of(head).encode()[::-1], "Content-Encoding: br"))
    status, headers, body = stack.get("http://app.example.com/debug", auth=stack.auth(job=6, tool="agent"),
                                      headers={"X-AttackLedger-As": "alice"})
    assert status == 200 and body == b"" and "content-encoding" not in headers
    assert "withheld" in stack.rows(1)[-1]["reason"]


def test_gw4_a_reflected_session_is_scrubbed_in_its_decoded_and_escaped_forms():
    """phpinfo() and framework debug pages show $_COOKIE decoded; JSON and HTML escape it."""
    decoded = COOKIE_VALUE.replace("%3D", "=")
    slashed = "abc/def+ghi/jkl=mno&pqr"
    page = (f"<td>$_COOKIE['laravel_session']</td><td>{decoded}</td>"
            f"<script>var c = \"{slashed.replace('/', chr(92) + '/')}\";</script>"
            f"<a href=\"/x?s={slashed.replace('&', '&amp;')}\">").encode()
    account = {"label": "a", "headers": [["Cookie", f"laravel_session={COOKIE_VALUE}"], ["X-Session", slashed]]}
    _, body = gateway.scrub_response(account, [], page)
    assert decoded.encode() not in body
    assert slashed.replace("/", "\\/").encode() not in body
    assert slashed.replace("&", "&amp;").encode() not in body
    assert b"abc" not in body


# ---- GW-5: cloud metadata services outside link-local -------------------------------------------

def test_gw5_metadata_addresses_outside_link_local_are_refused(monkeypatch):
    from test_gateway import FakeApi
    gw = gateway.Gateway(FakeApi(), None, deny_hosts=())
    table = {"ali.example.com": "100.100.100.200", "aws6.example.com": "fd00:ec2::254",
             "azure.example.com": "168.63.129.16", "oci.example.com": "192.0.0.192",
             "ok.example.com": "100.100.100.201"}

    async def getaddrinfo(host, port, type=None):
        if host not in table:
            raise socket.gaierror("no such host")
        return [(None, None, None, "", (table[host], 0))]

    async def go():
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", getaddrinfo)
        assert await gw.resolve("ok.example.com") == "100.100.100.201"
        for host in ("ali.example.com", "aws6.example.com", "azure.example.com", "oci.example.com"):
            with pytest.raises(gateway.Refused, match="never contacted"):
                await gw.resolve(host)
        with pytest.raises(gateway.Refused, match="never contacted"):
            await gw.resolve("100.100.100.200")
    asyncio.run(go())
