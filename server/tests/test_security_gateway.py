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


# ---- GW-6: the deployment's containers on two networks -------------------------------------------

class _ComposeLoader(yaml.SafeLoader):
    """Compose's merge tags (!reset, !override) as plain values."""


for _tag in ("!reset", "!override"):
    _ComposeLoader.add_constructor(_tag, lambda loader, node: (
        loader.construct_sequence(node) if isinstance(node, yaml.SequenceNode) else
        loader.construct_mapping(node) if isinstance(node, yaml.MappingNode) else loader.construct_scalar(node)))


def _networks(service: dict) -> dict:
    nets = service.get("networks") or ["default"]
    return {n: {} for n in nets} if isinstance(nets, list) else {n: (v or {}) for n, v in nets.items()}


@pytest.mark.parametrize("files", [["docker-compose.yml"], ["docker-compose.yml", "deploy/compose.prod.yml"]])
def test_gw6_every_address_of_the_deployments_containers_is_refused(files):
    """Docker's resolver answers a service name with one address, on one shared network. A
    container the gateway shares two networks with is reachable at its other address unless that
    one has a name of its own (a network alias) in the deny list."""
    services: dict = {}
    for f in files:
        for name, svc in (yaml.load((ROOT / f).read_text(), Loader=_ComposeLoader).get("services") or {}).items():
            merged = services.setdefault(name, {})
            if "networks" in svc:
                merged["networks"] = svc["networks"]
    gw_nets = set(_networks(services.pop("gateway")))
    deny = set(gateway.DENY_HOSTS)
    for name, svc in services.items():
        if name == "lab":                                  # the practice target: a target on purpose
            continue
        shared = {n: v for n, v in _networks(svc).items() if n in gw_nets}
        if len(shared) == 1:
            assert name in deny, f"{name} is not in gateway.DENY_HOSTS"
        for net, conf in shared.items() if len(shared) > 1 else ():
            aliases = set(conf.get("aliases") or [])
            assert aliases & deny, f"{name} on network {net}: no alias of it is in gateway.DENY_HOSTS"


# ---- GW-7: job targets with control characters ---------------------------------------------------

class _Eng:
    scope_include = ["*.example.com"]
    scope_exclude = []


@pytest.mark.parametrize("target", [
    "https://app.example.com/\nhttps://evil.test/",
    "https://app.example.com/\rhttps://evil.test/",
    "https://app.example.com/\thttps://evil.test/",
    "https://app.example.com/a b",
    "https://app.example.com/\x00",
])
def test_gw7_a_target_cannot_carry_a_second_line_to_the_tools(target):
    """Targets reach tools one per line on stdin. urlsplit drops tabs and newlines, so the scope
    check saw only the first URL; the tool was given both."""
    m = next(m for m in modules.MODULES if m.input == "urls")
    allowed, refused = jobgates.split_targets(_Eng(), m, [target, "https://app.example.com/ok"])
    assert allowed == ["https://app.example.com/ok"] and refused == [target]


# ---- Second pass (2026-10-10): the recommendations of the first review --------------------------

import ipaddress  # noqa: E402
import struct  # noqa: E402

from test_gateway import FakeApi  # noqa: E402

OWN = [ipaddress.ip_network("172.18.0.0/16"),      # e.g. internal: the worker's network
       ipaddress.ip_network("172.19.0.0/16"),      # default: the Docker host is 172.19.0.1
       ipaddress.ip_network("172.20.0.0/16"),      # lab
       ipaddress.ip_network("fd00:18::/64")]


def _resolver(monkeypatch, table: dict):
    async def getaddrinfo(host, port, type=None):
        if host not in table:
            raise socket.gaierror("no such host")
        return [(None, None, None, "", (a, 0)) for a in ([table[host]] if isinstance(table[host], str)
                                                           else table[host])]
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", getaddrinfo)


def test_gw8_the_gateways_own_networks_are_refused_except_the_labs(monkeypatch):
    """The Docker host has an address on every network the gateway is on (172.x.0.1), and the
    deployment's containers are there too. A target is never in those subnets (they are routed to
    Docker, not to a customer's network), except on the lab's network, which holds targets."""
    gw = gateway.Gateway(FakeApi(), None, deny_hosts=(), networks=OWN, target_networks=("gateway-lab",))
    table = {"gateway-lab": "172.20.0.2",
             "host.example.com": "172.19.0.1", "inside.example.com": "172.18.0.7", "v6.example.com": "fd00:18::5",
             "lab.example.com": "172.20.0.9",                                   # the lab: a target
             "bank.example.com": "10.4.0.9", "corp.example.com": "172.16.5.5",  # real internal targets
             "edge.example.com": "172.21.0.1"}                                  # a network the gateway is not on

    async def go():
        _resolver(monkeypatch, table)
        for host in ("lab.example.com", "bank.example.com", "corp.example.com", "edge.example.com"):
            assert await gw.resolve(host) == table[host], host
        for host in ("host.example.com", "inside.example.com", "v6.example.com", "172.19.0.1"):
            with pytest.raises(gateway.Refused, match="gateway's own network"):
                await gw.resolve(host)
        assert [str(n) for n in (await gw.own_networks())[1]] == ["172.20.0.0/16"]
    asyncio.run(go())


def test_gw8_without_its_lab_alias_every_own_network_is_refused(monkeypatch):
    """Fail closed: a target network named by an alias that does not resolve (the gateway is not
    on it) is not a target network. An address or a subnet (a deployment on a customer's LAN)
    works too."""
    async def go():
        _resolver(monkeypatch, {"lab.example.com": "172.20.0.9"})
        gw = gateway.Gateway(FakeApi(), None, deny_hosts=(), networks=OWN, target_networks=("gateway-lab",))
        with pytest.raises(gateway.Refused, match="gateway's own network"):
            await gw.resolve("lab.example.com")
        for mark in ("172.20.0.2", "172.20.0.0/24"):
            gw = gateway.Gateway(FakeApi(), None, deny_hosts=(), networks=OWN, target_networks=(mark,))
            assert await gw.resolve("lab.example.com") == "172.20.0.9"
    asyncio.run(go())


def _hex(addr: str) -> str:
    """An IPv4 address as Linux prints it in /proc/net/route (a native-order 32-bit number)."""
    return "%08X" % struct.unpack("=I", socket.inet_aton(addr))[0]


def test_gw8_the_gateway_reads_its_networks_from_proc(tmp_path):
    route = tmp_path / "route"
    head = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
    rows = [("eth0", "0.0.0.0", "172.19.0.1", 3, "0.0.0.0"),          # the default route: not a subnet
            ("eth0", "172.19.0.0", "0.0.0.0", 1, "255.255.0.0"),
            ("eth1", "172.18.0.0", "0.0.0.0", 1, "255.255.0.0"),
            ("eth2", "192.168.240.0", "0.0.0.0", 1, "255.255.240.0"),
            ("eth3", "10.50.0.0", "172.19.0.254", 3, "255.255.0.0"),   # through a router: a real network
            ("eth4", "172.30.0.0", "0.0.0.0", 0, "255.255.0.0"),       # down
            ("lo", "127.0.0.0", "0.0.0.0", 1, "255.0.0.0")]
    route.write_text(head + "".join(f"{i}\t{_hex(d)}\t{_hex(g)}\t{f:04X}\t0\t0\t0\t{_hex(m)}\t0\t0\t0\n"
                                    for i, d, g, f, m in rows))
    inet6 = tmp_path / "if_inet6"
    inet6.write_text("00000000000000000000000000000001 01 80 10 80       lo\n"
                     "fe800000000000000042acfffe120002 02 40 20 80     eth0\n"
                     "fd000000000000180000000000000002 02 40 00 80     eth0\n")
    nets = gateway.interface_networks(str(route), str(inet6))
    assert [str(n) for n in nets] == ["172.19.0.0/16", "172.18.0.0/16", "192.168.240.0/20", "fd00:0:0:18::/64"]
    assert gateway.interface_networks(str(tmp_path / "none"), str(tmp_path / "none")) == []


def _merged(files) -> dict:
    """services -> {"networks": ..., "environment": {...}} after compose's merge of the files."""
    services: dict = {}
    for f in files:
        for name, svc in (yaml.load((ROOT / f).read_text(), Loader=_ComposeLoader).get("services") or {}).items():
            merged = services.setdefault(name, {"environment": {}})
            if "networks" in svc:
                merged["networks"] = svc["networks"]
            env = svc.get("environment") or {}
            if isinstance(env, list):
                env = dict(e.split("=", 1) for e in env)
            merged["environment"].update(env)
    return services


@pytest.mark.parametrize("files", [["docker-compose.yml"], ["docker-compose.yml", "deploy/compose.prod.yml"],
                                   ["docker-compose.yml", "tools/benchmark/compose.override.yml"]])
def test_gw8_gw9_the_compose_files_name_the_lab_network_and_the_workers_network(files):
    """The gateway learns which of its networks holds targets (the lab's) and which one the worker
    is on from aliases of its own, set in the compose files: ATTACKLEDGER_GATEWAY_TARGET_NETWORKS and
    ATTACKLEDGER_GATEWAY_LISTEN. Docker answers an alias with the address on that network only."""
    services = _merged(files)
    gw = services["gateway"]
    nets = _networks(gw)
    aliases = {a: net for net, conf in nets.items() for a in (conf.get("aliases") or [])}
    targets = [t.strip() for t in gw["environment"].get("ATTACKLEDGER_GATEWAY_TARGET_NETWORKS", "").split(",") if t.strip()]
    listen = [t.strip() for t in gw["environment"].get("ATTACKLEDGER_GATEWAY_LISTEN", "").split(",") if t.strip()]
    assert targets and all(aliases.get(t) == "lab" for t in targets), "the lab's network is named by an alias on it"
    assert all(t in gateway.DENY_HOSTS for t in targets), "the gateway's own lab address is never contacted"
    assert listen and all(aliases.get(t) == "internal" for t in listen), "it listens on the worker's network only"
    worker = services["worker"]
    assert set(_networks(worker)) == {"internal"}
    for key in ("ATTACKLEDGER_GATEWAY", "ATTACKLEDGER_GATEWAY_DNS", "ATTACKLEDGER_WORKER_API"):
        host = worker["environment"][key].removeprefix("http://").rsplit(":", 1)[0]
        assert host in ("gateway", *listen), (key, host)       # the worker reaches the address it listens on


@pytest.mark.parametrize("files", [["docker-compose.yml"], ["docker-compose.yml", "deploy/compose.prod.yml"],
                                   ["docker-compose.yml", "tools/benchmark/compose.override.yml"]])
def test_gw8_the_docker_host_has_no_address_on_the_worker_and_gateway_internal_networks(files):
    """Measured on Docker 29.5: the host holds the first address of every bridge network, internal
    ones too, and a container on the internal network (the worker) reached a service the host ran
    there directly, without the gateway. With inhibit_ipv4 the bridge has no address: nothing
    of the host's is on those networks. The default network keeps one (it is the way out)."""
    nets: dict = {}
    for f in files:
        for name, conf in (yaml.load((ROOT / f).read_text(), Loader=_ComposeLoader).get("networks") or {}).items():
            nets.setdefault(name, {}).update(conf or {})
    services = _merged(files)
    used = set(_networks(services["gateway"])) | set(_networks(services["worker"]))
    for name in sorted(used):
        conf = nets.get(name) or {}
        if not conf.get("internal"):
            assert name == "default", f"{name} is not internal"
            continue
        assert (conf.get("driver_opts") or {}).get("com.docker.network.bridge.inhibit_ipv4") == "true", name


def test_gw9_listen_names_become_this_containers_own_addresses():
    calls = []

    def resolve(name, port, type=None):
        calls.append(name)
        if name == "gateway-internal":         # a second gateway sharing the alias: not this one's
            return [(None, None, None, "", ("172.18.0.3", 0)), (None, None, None, "", ("172.18.0.9", 0))]
        raise socket.gaierror("no such host")
    own = lambda a: a in ("172.18.0.3", "127.0.0.1")      # noqa: E731
    assert gateway.listen_addresses("gateway-internal", resolve=resolve, bindable=own) == ["172.18.0.3"]
    assert gateway.listen_addresses("", resolve=resolve, bindable=own) == ["0.0.0.0"]
    assert gateway.listen_addresses("127.0.0.1, gateway-internal", resolve=resolve, bindable=own) == [
        "127.0.0.1", "172.18.0.3"]
    waits = []
    with pytest.raises(RuntimeError, match="gateway-elsewhere is not an address of this container"):
        gateway.listen_addresses("gateway-elsewhere", resolve=resolve, bindable=own, wait=2, sleep=waits.append)
    assert waits                                   # retried: Docker's resolver may not answer at once


def _bindable(addr: str) -> bool:
    with socket.socket() as s:
        try:
            s.bind((addr, 0))
            return True
        except OSError:
            return False


@pytest.mark.skipif(not _bindable("127.0.0.2"), reason="needs 127.0.0.0/8 on loopback (Linux)")
def test_gw9_the_relay_the_proxy_and_the_resolver_answer_on_the_listen_address_only(tmp_path):
    """Before, every part listened on 0.0.0.0, so on the control, default and lab networks too.
    127.0.0.2 stands for the address on the worker's network, 127.0.0.3 for another network's."""
    gw = gateway.Gateway(FakeApi(), None, deny_hosts=(), networks=[])
    loop = asyncio.new_event_loop()
    try:
        parts = loop.run_until_complete(gw.start("127.0.0.2", port=0, dns_port=0, control_port=0))
        proxy, control, dns = parts
        assert {s.getsockname()[0] for s in proxy.sockets} == {"127.0.0.2", "127.0.0.1"}   # loopback: healthcheck
        assert {s.getsockname()[0] for s in control.sockets} == {"127.0.0.2"}
        assert dns.get_extra_info("sockname")[0] == "127.0.0.2"
        for server in (proxy, control):
            # Port 0: each address gets its own free port, so take the one bound to 127.0.0.2.
            port = next(s.getsockname()[1] for s in server.sockets if s.getsockname()[0] == "127.0.0.2")
            socket.create_connection(("127.0.0.2", port), 2).close()
            with pytest.raises(ConnectionRefusedError):
                socket.create_connection(("127.0.0.3", port), 2)
        for p in parts:
            p.close()
        for server in (proxy, control):
            loop.run_until_complete(server.wait_closed())
    finally:
        loop.close()
