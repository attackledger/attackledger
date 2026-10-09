"""The traffic gateway (D-039): refusals first, then what is allowed and how it is sent.

A real gateway runs on localhost in a background event loop, in front of a fake upstream that
records every request it receives. The API is a fake too (FakeApi), so the rules, the job
credentials and the request log are under the test's control. Name resolution is replaced, so
every host the tests use "resolves" to a documentation address the fake connector maps to the
fake upstream; resolve() itself is tested separately.
"""
import asyncio
import base64
import http.client
import socket
import ssl
import struct
import threading
import time
import urllib.error
import urllib.request

import pytest

from app import egress, gateway

SECRET = "s3cret-job-credential-0001"
RULES = {"engagement_id": 1, "kind": "probe", "traffic": "target", "include": ["*.example.com", "example.com"],
         "exclude": ["admin.example.com"], "rate_limit_rps": 50, "research_header": "X-Bug-Bounty: r1",
         "research_user_agent": "AttackLedger/0.7 (r1)", "redact": True}


class FakeApi:
    base = "fake-api"

    def __init__(self):
        self.jobs: dict[int, dict] = {}
        self.logged: list[dict] = []
        self.scopes: list[dict] = []
        self.down = False
        self.log_down = False
        self.calls = 0

    def add(self, job_id, secret=SECRET, running=True, **rules):
        self.jobs[job_id] = {"secret": secret, "running": running, "rules": {**RULES, **rules, "job_id": job_id}}

    async def session(self, job_id, secret):
        self.calls += 1
        if self.down:
            return 0, {"detail": "API unreachable: connection refused"}
        j = self.jobs.get(job_id)
        if j is None:
            return 404, {"detail": f"job {job_id} has no gateway credential"}
        if j["secret"] != secret:
            return 403, {"detail": f"wrong secret for job {job_id}"}
        if not j["running"]:
            return 403, {"detail": f"job {job_id} is done, not running"}
        return 200, j["rules"]

    async def dns_scopes(self):
        return 200, self.scopes

    async def post_log(self, rows):
        if self.log_down:
            return 0, {"detail": "API unreachable"}
        self.logged += rows
        return 200, {"written": len(rows)}


class Upstream:
    """Records each request head (and body) it receives; answers 200 "ok" and closes."""

    def __init__(self):
        self.requests: list[dict] = []
        self.port = self.tls_port = None

    async def handle(self, reader, writer):
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, ConnectionError):
            writer.close()
            return
        lines = head.decode("latin-1").split("\r\n")
        method, target, _ = lines[0].split(" ", 2)
        headers = [tuple(x.strip() for x in l.split(":", 1)) for l in lines[1:] if ":" in l]
        n = int(dict((k.lower(), v) for k, v in headers).get("content-length", "0"))
        body = await reader.readexactly(n) if n else b""
        self.requests.append({"t": time.monotonic(), "method": method, "target": target, "headers": headers,
                              "body": body})
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n"
                     b"Set-Cookie: s=1\r\nConnection: close\r\n\r\nok")
        await writer.drain()
        writer.close()

    def header(self, i, name):
        return [v for k, v in self.requests[i]["headers"] if k.lower() == name.lower()]


class Stack:
    def __init__(self, tmp_path):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        self.api = FakeApi()
        self.api.add(1)
        self.up = Upstream()
        self.ca = gateway.CA(str(tmp_path / "gw-private"), str(tmp_path / "gw-public"))
        self.ca_file = str(tmp_path / "gw-public" / "ca.pem")
        upstream_ca = gateway.CA(str(tmp_path / "up-private"))
        self.gw = gateway.Gateway(self.api, self.ca, deny_hosts=())
        self.connects: list[dict] = []

        async def resolve(host):
            if host.endswith(".invalid"):
                raise gateway.Refused(502, f"{host} does not resolve")
            return "192.0.2.10"

        async def connector(ip, port, ssl=None, server_hostname=None):
            self.connects.append({"ip": ip, "port": port, "ssl": ssl, "sni": server_hostname})
            if port in (81, 8081):
                raise ConnectionRefusedError(111, "Connection refused")
            if ssl is not None:
                return await asyncio.open_connection("127.0.0.1", self.up.tls_port, ssl=self.client_ssl(ssl),
                                                     server_hostname=server_hostname)
            return await asyncio.open_connection("127.0.0.1", self.up.port)
        self.gw.resolve = resolve
        self.gw.open_connection = connector

        async def start():
            plain = await asyncio.start_server(self.up.handle, "127.0.0.1", 0)
            tls = await asyncio.start_server(self.up.handle, "127.0.0.1", 0,
                                             ssl=upstream_ca.server_context("app.example.com"))
            proxy = await asyncio.start_server(self.gw.handle_client, "127.0.0.1", 0)
            return [plain, tls, proxy]
        self.servers = self.run(start())
        self.up.port = self.servers[0].sockets[0].getsockname()[1]
        self.up.tls_port = self.servers[1].sockets[0].getsockname()[1]
        self.port = self.servers[2].sockets[0].getsockname()[1]

    def client_ssl(self, ctx):
        """The gateway's verifying context cannot verify the fake upstream's test CA; the
        decision of which context to use is what the tests check (self.connects)."""
        c = ssl.create_default_context()
        c.check_hostname, c.verify_mode = False, ssl.CERT_NONE
        return c

    def run(self, coro, timeout=30):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def close(self):
        for s in self.servers:
            self.loop.call_soon_threadsafe(s.close)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)

    def auth(self, job=1, secret=SECRET, tool="httpx") -> str:
        return "Basic " + base64.b64encode(f"job-{job}.{tool}:{secret}".encode()).decode()

    def raw(self, data: bytes, timeout=10) -> bytes:
        with socket.create_connection(("127.0.0.1", self.port), timeout=timeout) as s:
            s.sendall(data)
            out = b""
            while chunk := s.recv(65536):
                out += chunk
        return out

    def get(self, url, *, method="GET", headers=None, auth=None, body=b"") -> tuple[int, dict, bytes]:
        """One absolute-form request through the gateway; (status, headers, body)."""
        h = {"Connection": "close", **(headers or {})}
        if auth is not False:
            h["Proxy-Authorization"] = auth or self.auth()
        if body:
            h["Content-Length"] = str(len(body))
        host = url.split("/")[2]
        head = f"{method} {url} HTTP/1.1\r\nHost: {host}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items())
        return parse(self.raw(head.encode() + b"\r\n" + body))

    def rows(self, n, timeout=5):
        end = time.time() + timeout
        while len(self.gw.log_rows) < n and time.time() < end:
            time.sleep(0.01)
        return self.gw.log_rows


def parse(resp: bytes) -> tuple[int, dict, bytes]:
    head, _, body = resp.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split(" ")[1]) if lines[0] else 0
    return status, {k.strip().lower(): v.strip() for k, _, v in (l.partition(":") for l in lines[1:])}, body


@pytest.fixture()
def stack(tmp_path):
    s = Stack(tmp_path)
    yield s
    s.close()


# ---- refusals ----------------------------------------------------------------------

@pytest.mark.parametrize("host", ["evil.test", "admin.example.com", "example.com.evil.test"])
def test_out_of_scope_hosts_are_refused_and_nothing_is_sent(stack, host):
    status, headers, body = stack.get(f"http://{host}/")
    assert status == 403 and headers["x-attackledger-gateway"] == "refused"
    assert b"not in scope" in body
    assert stack.up.requests == [] and stack.connects == []
    row = stack.rows(1)[0]
    assert row["verdict"] == "refused" and row["host"] == host and row["job_id"] == 1 and "not in scope" in row["reason"]


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "DEBUG", "TRACE", "PROPFIND", "MKCOL", "get"])
def test_write_and_unusual_methods_are_refused(stack, method):
    body = b"{}" if method in ("POST", "PUT", "PATCH") else b""
    status, headers, text = stack.get("http://app.example.com/api/items", method=method, body=body)
    assert status == 403 and headers["x-attackledger-gateway"] == "refused"
    assert b"only GET, HEAD and OPTIONS" in text and b"D-041" in text
    assert stack.up.requests == [] and stack.connects == []
    row = stack.rows(1)[0]
    assert row["verdict"] == "refused" and row["method"] == method


@pytest.mark.parametrize("headers,body,why", [
    ({"Content-Length": "2"}, b"{}", b"without a body"),
    ({"Transfer-Encoding": "chunked"}, b"2\r\n{}\r\n0\r\n\r\n", b"without a body"),
    ({"X-HTTP-Method-Override": "DELETE"}, b"", b"method override"),
    ({"X-Method-Override": "put"}, b"", b"method override"),
    ({"Upgrade": "websocket", "Connection": "Upgrade"}, b"", b"upgrades"),
])
def test_bodies_overrides_and_upgrades_are_refused(stack, headers, body, why):
    head = ("GET http://app.example.com/x HTTP/1.1\r\nHost: app.example.com\r\n"
            f"Proxy-Authorization: {stack.auth()}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()))
    status, _, text = parse(stack.raw(head.encode() + b"\r\n" + body))
    assert status == 403 and why in text
    assert stack.up.requests == []


def test_method_parameter_naming_a_write_is_refused(stack):
    status, _, text = stack.get("http://app.example.com/x?_method=DELETE")
    assert status == 403 and b"_method" in text and stack.up.requests == []
    assert stack.get("http://app.example.com/x?_method=GET")[0] == 200


def test_missing_or_wrong_credentials_are_refused(stack):
    cases = [(False, b"credential is required"),
             (stack.auth(secret="wrong-secret-0000000000"), b"wrong secret"),
             (stack.auth(job=99), b"no gateway credential"),
             ("Basic " + base64.b64encode(b"admin:" + SECRET.encode()).decode(), b"malformed"),
             ("Bearer " + SECRET, b"Basic")]
    for auth, why in cases:
        status, headers, text = stack.get("http://app.example.com/", auth=auth)
        assert status == 407 and why in text, (auth, text)
        assert headers["proxy-authenticate"].startswith("Basic")
    assert stack.up.requests == []
    rows = stack.rows(len(cases))
    assert all(r["verdict"] == "refused" and r["job_id"] is None for r in rows)


def test_a_finished_job_or_an_unreachable_api_sends_nothing(stack):
    stack.api.jobs[1]["running"] = False
    status, _, text = stack.get("http://app.example.com/")
    assert status == 407 and b"not running" in text
    stack.api.add(2)
    stack.api.down = True
    status, _, text = stack.get("http://app.example.com/", auth=stack.auth(job=2))
    assert status == 503 and b"cannot check" in text
    assert stack.up.requests == []
    stack.api.down = False                                    # a passing outage is not remembered
    assert stack.get("http://app.example.com/", auth=stack.auth(job=2))[0] == 200


def test_cancelling_a_job_stops_its_traffic_within_the_cache_time(stack, monkeypatch):
    monkeypatch.setattr(gateway, "RULES_TTL", 0.3)
    assert stack.get("http://app.example.com/")[0] == 200
    stack.api.jobs[1]["running"] = False
    time.sleep(0.35)
    status, _, text = stack.get("http://app.example.com/")
    assert status == 407 and b"not running" in text and len(stack.up.requests) == 1


def test_a_job_cannot_use_another_engagements_rules(stack):
    stack.api.add(2, engagement_id=2, include=["other.test"], exclude=[])
    assert stack.get("http://other.test/", auth=stack.auth(job=2))[0] == 200
    status, _, text = stack.get("http://other.test/")              # job 1: engagement 1's scope only
    assert status == 403 and b"not in scope" in text
    assert len(stack.up.requests) == 1


def test_target_traffic_needs_identification(stack):
    stack.api.add(3, research_header=None, research_user_agent=None)
    status, _, text = stack.get("http://app.example.com/", auth=stack.auth(job=3))
    assert status == 403 and b"no research header" in text and stack.up.requests == []


def test_credentials_in_urls_https_in_absolute_form_and_port_25_are_refused(stack):
    assert stack.get("http://u:p@app.example.com/")[0] == 403
    assert stack.get("https://app.example.com/")[0] == 400
    assert stack.get("http://app.example.com:25/")[0] == 403
    assert stack.up.requests == [] and stack.connects == []


def test_a_full_request_log_stops_all_traffic(stack, monkeypatch):
    monkeypatch.setattr(gateway, "LOG_BACKLOG", 2)
    stack.api.log_down = True
    assert stack.get("http://app.example.com/a")[0] == 200
    assert stack.get("http://app.example.com/b")[0] == 200
    status, _, text = stack.get("http://app.example.com/c")
    assert status == 503 and b"request log" in text and len(stack.up.requests) == 2
    assert stack.run(stack.gw.flush_log()) is False
    stack.api.log_down = False
    while stack.gw.log_rows:
        assert stack.run(stack.gw.flush_log())
    assert stack.get("http://app.example.com/d")[0] == 200


# ---- what is sent ------------------------------------------------------------------

def test_allowed_request_carries_only_the_engagements_identification(stack):
    status, headers, body = stack.get("http://app.example.com/p?q=1", headers={
        "X-Bug-Bounty": "forged", "User-Agent": "sqlmap/1.0", "Accept": "text/html"})
    assert status == 200 and body == b"ok" and headers["set-cookie"] == "s=1"
    req = stack.up.requests[0]
    assert req["method"] == "GET" and req["target"] == "/p?q=1"
    assert stack.up.header(0, "X-Bug-Bounty") == ["r1"]
    assert stack.up.header(0, "User-Agent") == ["AttackLedger/0.7 (r1)"]
    assert stack.up.header(0, "Accept") == ["text/html"] and stack.up.header(0, "Host") == ["app.example.com"]
    assert stack.up.header(0, "Proxy-Authorization") == [] and stack.up.header(0, "Connection") == ["close"]
    row = stack.rows(1)[0]
    assert row["verdict"] == "allowed" and row["status"] == 200 and row["bytes_received"] == 2
    assert row["tool"] == "httpx" and row["kind"] == "target" and row["url"] == "http://app.example.com/p?q=1"
    assert row["engagement_id"] == 1 and row["job_id"] == 1


def test_head_and_options_are_allowed(stack):
    assert stack.get("http://app.example.com/", method="HEAD")[0] == 200
    assert stack.get("http://app.example.com/", method="OPTIONS")[0] == 200
    assert [r["method"] for r in stack.up.requests] == ["HEAD", "OPTIONS"]


def test_logged_urls_are_redacted(stack):
    stack.get("http://app.example.com/cb?access_token=abcdef0123456789")
    assert "abcdef0123456789" not in stack.rows(1)[0]["url"] and "redacted" in stack.rows(1)[0]["url"]


def test_https_is_intercepted_with_the_gateway_ca(stack):
    ctx = ssl.create_default_context(cafile=stack.ca_file)
    c = http.client.HTTPSConnection("127.0.0.1", stack.port, context=ctx, timeout=10)
    c.set_tunnel("app.example.com", 443, headers={"Proxy-Authorization": stack.auth(tool="katana")})
    c.request("GET", "/login", headers={"User-Agent": "katana"})
    r = c.getresponse()
    assert r.status == 200 and r.read() == b"ok"
    c.request("GET", "/second")                              # keep-alive inside the tunnel
    assert c.getresponse().status == 200
    c.close()
    assert [x["target"] for x in stack.up.requests] == ["/login", "/second"]
    assert stack.up.header(0, "User-Agent") == ["AttackLedger/0.7 (r1)"]
    assert stack.connects[0]["ssl"] is stack.gw.insecure_ctx and stack.connects[0]["sni"] == "app.example.com"
    assert stack.rows(2)[0]["url"] == "https://app.example.com/login" and stack.rows(2)[0]["tool"] == "katana"


def test_urllib_through_the_gateway_like_the_worker(stack, monkeypatch):
    monkeypatch.setenv("ATTACKLEDGER_GATEWAY_CA", stack.ca_file)
    gw = egress.Egress(1, SECRET, address=f"127.0.0.1:{stack.port}", ca_file=stack.ca_file)
    with gw.opener("jsanalyze").open("https://app.example.com/app.js", timeout=10) as r:
        assert r.status == 200
    with gw.opener("jsanalyze").open("http://app.example.com/app.js", timeout=10) as r:
        assert r.read() == b"ok"
    with pytest.raises(urllib.error.HTTPError) as e:
        gw.opener("jsanalyze").open("http://evil.test/", timeout=10)
    assert egress.refusal(e.value.headers.items())
    with pytest.raises(urllib.error.HTTPError) as e:                 # unreachable: the reason, for our clients
        gw.opener("jsanalyze").open("http://app.example.com:8081/", timeout=10)
    assert e.value.code == 502 and b"could not connect" in e.value.read()


def test_a_tunnel_that_does_not_start_tls_is_closed_and_nothing_is_relayed(stack):
    with socket.create_connection(("127.0.0.1", stack.port), timeout=10) as s:
        s.sendall(f"CONNECT app.example.com:443 HTTP/1.1\r\nHost: app.example.com:443\r\n"
                  f"Proxy-Authorization: {stack.auth()}\r\n\r\n".encode())
        assert s.recv(4096).startswith(b"HTTP/1.1 200")
        s.sendall(b"GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n")      # plain HTTP, not TLS
        s.settimeout(10)
        rest = b""
        while chunk := s.recv(4096):
            rest += chunk
    assert b"ok" not in rest and stack.up.requests == [] and stack.connects == []


def test_a_client_that_does_not_trust_the_ca_gets_nothing_through(stack):
    c = http.client.HTTPSConnection("127.0.0.1", stack.port, context=ssl.create_default_context(), timeout=10)
    c.set_tunnel("app.example.com", 443, headers={"Proxy-Authorization": stack.auth()})
    with pytest.raises(ssl.SSLCertVerificationError):
        c.request("GET", "/")
    assert stack.up.requests == []


def test_connect_is_checked_before_the_tunnel_opens(stack):
    for target, status in (("evil.test:443", 403), ("app.example.com:25", 403), ("app.example.com", 400)):
        resp = stack.raw(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
                         f"Proxy-Authorization: {stack.auth()}\r\n\r\n".encode())
        assert parse(resp)[0] == status, target
    resp = stack.raw(b"CONNECT app.example.com:443 HTTP/1.1\r\nHost: app.example.com:443\r\n\r\n")
    assert parse(resp)[0] == 407
    assert stack.connects == []


def test_host_header_must_match_the_tunnel(stack):
    ctx = ssl.create_default_context(cafile=stack.ca_file)
    c = http.client.HTTPSConnection("127.0.0.1", stack.port, context=ctx, timeout=10)
    c.set_tunnel("app.example.com", 443, headers={"Proxy-Authorization": stack.auth()})
    c.request("GET", "/", headers={"Host": "evil.test"})
    r = c.getresponse()
    assert r.status == 403 and b"Host header" in r.read() and stack.up.requests == []


def test_an_unreachable_target_looks_unreachable_to_tools(stack):
    """A scanner must not record the gateway's 502 as the target's answer: it gets a closed
    connection, as from the target itself. AttackLedger's own clients ask for the reason."""
    status, _, _ = stack.get("http://app.example.com:81/")
    assert status == 0                                        # no HTTP response at all
    status, headers, text = stack.get("http://app.example.com:81/", headers={"X-AttackLedger-Errors": "respond"})
    assert status == 502 and b"could not connect" in text and headers["x-attackledger-gateway"] == "refused"
    assert [r["verdict"] for r in stack.rows(2)] == ["failed", "failed"]
    stack.get("http://app.example.com/", headers={"X-AttackLedger-Errors": "respond"})
    assert stack.up.header(0, "X-AttackLedger-Errors") == []            # never forwarded


def test_passive_sources_over_plain_http_on_port_80_only(stack):
    stack.api.add(5, kind="archive", traffic="passive")
    assert stack.get("http://web.archive.org/cdx?url=x", auth=stack.auth(job=5, tool="wayback"))[0] == 200
    assert stack.get("http://web.archive.org:8080/", auth=stack.auth(job=5))[0] == 403


# ---- rate ceiling ----------------------------------------------------------------------

def peak(times, window=1.0):
    times, best, j = sorted(times), 0, 0
    for i, t in enumerate(times):
        while times[j] <= t - window:
            j += 1
        best = max(best, i - j + 1)
    return best


def test_rate_ceiling_holds_for_concurrent_clients_and_jobs(stack):
    stack.api.jobs[1]["rules"]["rate_limit_rps"] = 8
    stack.api.add(2, rate_limit_rps=8)                       # a second job (or worker), same engagement
    results = []

    def client(i):
        results.append(stack.get(f"http://app.example.com/{i}", auth=stack.auth(job=1 + i % 2))[0])
    threads = [threading.Thread(target=client, args=(i,)) for i in range(40)]
    t0 = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert results.count(200) == 40
    times = [r["t"] for r in stack.up.requests]
    assert len(times) == 40 and peak(times) <= 8
    assert time.monotonic() - t0 >= 4 * 1.0                 # 40 requests at 8 per 1.05 s


def test_limiter_refuses_a_wait_longer_than_the_maximum():
    now = [0.0]
    slept = []

    async def sleep(s):
        slept.append(s)
        now[0] += s

    async def go():
        lim = gateway.Limiter(2, clock=lambda: now[0], sleep=sleep)
        assert [await lim.acquire() for _ in range(4)] == [0.0, 0.0, gateway.WINDOW, gateway.WINDOW]
        with pytest.raises(gateway.Refused) as e:
            await lim.acquire(max_wait=0.5)
        assert e.value.status == 429
    asyncio.run(go())
    assert slept == [gateway.WINDOW]


# ---- port probes -----------------------------------------------------------------------

def test_port_probes_connect_check_scope_and_relay_nothing(stack):
    gw = egress.Egress(1, SECRET, address=f"127.0.0.1:{stack.port}")
    assert gw.probe("app.example.com", 80) == (200, "open")
    assert gw.probe("app.example.com", 81) == (502, "closed")
    status, reason = gw.probe("evil.test", 80)
    assert status == 403 and "not in scope" in reason
    assert gw.probe("app.example.com", 25)[0] == 403
    assert [(c["port"], c["ssl"]) for c in stack.connects] == [(80, None), (81, None)]
    assert stack.up.requests == []
    rows = stack.rows(4)
    assert [r["method"] for r in rows] == ["PROBE"] * 4 and rows[0]["tool"] == "ports"


# ---- passive sources and the Claude API ----------------------------------------------

def test_passive_sources_are_get_only_unidentified_verified_and_not_counted(stack):
    stack.api.add(5, kind="archive", traffic="passive")
    ctx = ssl.create_default_context(cafile=stack.ca_file)
    c = http.client.HTTPSConnection("127.0.0.1", stack.port, context=ctx, timeout=10)
    c.set_tunnel("web.archive.org", 443, headers={"Proxy-Authorization": stack.auth(job=5, tool="gau")})
    c.request("GET", "/cdx/search/cdx?url=example.com/*", headers={"User-Agent": "gau"})
    assert c.getresponse().status == 200
    c.close()
    assert stack.up.header(0, "User-Agent") == ["gau"] and stack.up.header(0, "X-Bug-Bounty") == []
    assert stack.connects[0]["ssl"] is stack.gw.verify_ctx
    assert stack.gw.limiters == {} and stack.rows(1)[0]["kind"] == "passive"
    c = http.client.HTTPSConnection("127.0.0.1", stack.port, context=ctx, timeout=10)
    c.set_tunnel("web.archive.org", 443, headers={"Proxy-Authorization": stack.auth(job=5, tool="gau")})
    c.request("POST", "/save", body=b"x")
    assert c.getresponse().status == 403 and len(stack.up.requests) == 1
    # A passive job cannot reach targets, and a target job cannot reach passive sources.
    assert stack.get("http://app.example.com/", auth=stack.auth(job=5))[0] == 403
    resp = stack.raw(f"CONNECT crt.sh:443 HTTP/1.1\r\nHost: crt.sh:443\r\nProxy-Authorization: {stack.auth()}\r\n\r\n"
                     .encode())
    assert parse(resp)[0] == 403


def test_the_claude_api_is_reachable_from_agent_runs_only(stack):
    stack.api.add(6, kind="agent", traffic="agent")
    ctx = ssl.create_default_context(cafile=stack.ca_file)

    def call(job, method, path, body=b""):
        c = http.client.HTTPSConnection("127.0.0.1", stack.port, context=ctx, timeout=10)
        c.set_tunnel("api.anthropic.com", 443, headers={"Proxy-Authorization": stack.auth(job=job, tool="claude")})
        try:
            c.request(method, path, body=body or None, headers={"x-api-key": "sk-test"})
            return c.getresponse().status
        except (ssl.SSLError, ConnectionError, http.client.HTTPException, OSError):
            return 0
        finally:
            c.close()
    assert call(6, "POST", "/v1/messages?beta=true", b'{"model":"m"}') == 200
    assert stack.up.requests[0]["body"] == b'{"model":"m"}' and stack.up.header(0, "x-api-key") == ["sk-test"]
    assert stack.up.header(0, "X-Bug-Bounty") == [] and stack.connects[0]["ssl"] is stack.gw.verify_ctx
    assert call(6, "GET", "/v1/models") == 403
    assert call(1, "POST", "/v1/messages") != 200             # a recon job: refused at CONNECT
    assert len(stack.up.requests) == 1


def test_computed_jobs_get_no_egress(stack):
    stack.api.add(7, kind="dorks", traffic="none")
    assert stack.get("http://app.example.com/", auth=stack.auth(job=7))[0] == 403
    assert stack.up.requests == []


# ---- addresses and DNS ---------------------------------------------------------------------

def test_resolve_refuses_loopback_link_local_and_the_deployment(monkeypatch):
    gw = gateway.Gateway(FakeApi(), None, deny_hosts=("db",))
    table = {"meta.example.com": "169.254.169.254", "lo.example.com": "127.0.0.1", "db": "10.9.0.5",
             "inside.example.com": "10.9.0.5", "app.example.com": "10.20.0.7", "v6.example.com": "::1"}

    async def getaddrinfo(host, port, type=None):
        if host not in table:
            raise socket.gaierror("no such host")
        return [(None, None, None, "", (table[host], 0))]

    async def go():
        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", getaddrinfo)
        assert await gw.resolve("app.example.com") == "10.20.0.7"       # private addresses are allowed
        for host, why in (("meta.example.com", "never contacted"), ("lo.example.com", "never contacted"),
                          ("v6.example.com", "never contacted"), ("inside.example.com", "this deployment"),
                          ("db", "this deployment"), ("nx.example.com", "does not resolve")):
            with pytest.raises(gateway.Refused, match=why):
                await gw.resolve(host)
    asyncio.run(go())


def dns_query(name: str, qtype: int, qid: int = 0x1234) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, 1)


def test_dns_answers_only_in_scope_names_of_running_jobs(monkeypatch):
    api = FakeApi()
    api.scopes = [{"engagement_id": 1, "include": ["*.example.com"], "exclude": ["admin.example.com"],
                   "rate_limit_rps": 5}]
    gw = gateway.Gateway(api, None, deny_hosts=())
    forwarded = []

    async def forward(q):
        forwarded.append(q)
        return q[:2] + b"\x81\x80" + q[4:]
    gw._dns_forward = forward

    async def go():
        ok = await gw.dns_answer(dns_query("app.example.com", 1))
        assert ok[3] & 0x0F == 0 and len(forwarded) == 1
        for name, qtype in (("evil.test", 1), ("admin.example.com", 1), ("app.example.com", 15)):
            r = await gw.dns_answer(dns_query(name, qtype))
            assert r[:2] == b"\x12\x34" and r[3] & 0x0F == 5 and r[2] & 0x80   # REFUSED reply
        assert len(forwarded) == 1
        assert await gw.dns_answer(b"\x00" * 5) is None
    asyncio.run(go())
    assert [(r["verdict"], r["engagement_id"]) for r in gw.log_rows] == [
        ("allowed", 1), ("refused", None), ("refused", None), ("refused", None)]
    assert gateway.parse_question(dns_query("A.Example.com", 28))[1:3] == ("a.example.com", 28)


# ---- the CA ------------------------------------------------------------------------------

def test_ca_is_created_once_and_only_its_certificate_is_public(tmp_path):
    from cryptography import x509
    a = gateway.CA(str(tmp_path / "p"), str(tmp_path / "pub"))
    b = gateway.CA(str(tmp_path / "p"), str(tmp_path / "pub"))
    assert a.cert_pem == b.cert_pem
    assert sorted(p.name for p in (tmp_path / "pub").iterdir()) == ["ca.pem"]
    assert (tmp_path / "p" / "ca.key").stat().st_mode & 0o077 == 0
    cert = x509.load_pem_x509_certificate((tmp_path / "pub" / "ca.pem").read_bytes())
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    leaf = x509.load_pem_x509_certificate(a.leaf_pem("app.example.com"))
    assert leaf.issuer == cert.subject
    assert leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
        x509.DNSName) == ["app.example.com"]


def test_gateway_token_is_created_by_the_gateway_and_read_by_the_api(tmp_path, monkeypatch):
    path = tmp_path / "control" / "token"
    monkeypatch.setenv("ATTACKLEDGER_GATEWAY_TOKEN_FILE", str(path))
    assert gateway.gateway_token() is None
    tok = gateway.gateway_token(create=True)
    assert len(tok) > 30 and gateway.gateway_token() == tok and gateway.gateway_token(create=True) == tok
    monkeypatch.setenv("ATTACKLEDGER_GATEWAY_TOKEN", "from-env")
    assert gateway.gateway_token() == "from-env"
