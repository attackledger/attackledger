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
