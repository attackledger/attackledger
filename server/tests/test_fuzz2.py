"""Property-based fuzzing, second pass (docs/security-review/FUZZING.md, "Second pass").

The targets the first pass left out: the gateway's own HTTP parsing (requests from tools and
responses from targets, through h11), the gateway log ingestion (POST /gateway/log), redaction
of XML, multipart, form and GraphQL bodies, and the inbox mapping and report builder. Same
harness as test_fuzz.py (fuzzing.py): seeded, offline, time-limited; a failure names the seed and
the iteration. ATTACKLEDGER_FUZZ_ITERATIONS makes every test run that many inputs.
"""
import asyncio
import json
import os
import socket
import time
from urllib.parse import quote, unquote

import pytest

from sqlalchemy import func, select

from app import gateway, gatewayapi, gatewaylog, redact
from app.models import GatewayRequest
from fuzzing import (INTERESTING, NUMBERS, STRINGS, Obj, Raw, dumps, elapsed, iterations, loads, mutate_bytes,
                     mutate_tree, rng, show, time_limit, value)
from harness import stack  # noqa: F401  (fixture)
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


# ---- redaction: XML, multipart, forms, GraphQL ---------------------------------------------------

SIZE = int(os.environ.get("ATTACKLEDGER_FUZZ_SIZE") or 40_000)
BUDGET = float(os.environ.get("ATTACKLEDGER_FUZZ_BUDGET") or 2.0)
NAMES = ["password", "Password", "PASSWD", "api_key", "apiKey", "X-Api-Key", "access_token", "sessionToken",
         "client_secret", "SAMLResponse", "otp", "pwd", "db-password", "refreshToken", "privateKey"]
PLAIN = ["user", "email", "q", "page", "name", "Username", "lang", "redirect", "id", "value"]


def _secret(r, avoid: str) -> str:
    """A value with the characters that ended one too early (FZ-26), minus those the format
    itself cannot hold unescaped (avoid)."""
    chars = [c for c in "abcXYZ0129;,)(' #!$*+-./:?@[]^_`{|}~=" + '"<>\\' if c not in avoid]
    core = "lab" + "".join(r.choice(chars) for _ in range(r.randint(6, 30))) + str(r.randrange(10**6))
    return core.strip()


def _xml_doc(r) -> tuple[str, str]:
    name = r.choice(NAMES)
    prefix = r.choice(["", "wsse:", "ns1:", "s:"])
    v = _secret(r, "<&>\"'")
    sp = r.choice(["", " ", "\n  ", "\t"])
    form = r.randrange(7)
    if form == 0:
        doc = f"<{prefix}{name}>{sp}{v}{sp}</{prefix}{name}>"
    elif form == 1:
        doc = f'<{prefix}{name} Type="t" a="1">{v}</{prefix}{name} >'
    elif form == 2:
        doc = f"<{prefix}{name}><![CDATA[{v}]]></{prefix}{name}>"
    elif form == 3:
        q = r.choice("\"'")
        doc = f"<cred {name}{r.choice(['=', ' = ', '='])}{q}{v}{q} user={q}tess{q}/>"
    elif form == 4:
        doc = (f"<member><name>{name}</name>{sp}<value>{r.choice(['<string>%s</string>', '%s', '<base64>%s</base64>'])}"
               f"</value></member>") % v
    elif form == 5:
        doc = f"<dict><key>{name}</key>{sp}<string>{v}</string></dict>"
    else:
        attr = r.choice(["name", "key", "property"])
        doc = f'<{r.choice(["input", "meta", "add"])} {attr}="{name}" {r.choice(["value", "content"])}="{v}">'
    wrap = r.choice(["%s", "<?xml version=\"1.0\"?><soap:Envelope><soap:Body>%s</soap:Body></soap:Envelope>",
                     "<html><form>%s</form></html>", "<methodCall><params><param><value><struct>%s</struct>"
                     "</value></param></params></methodCall>"])
    return wrap % doc, v


def _multipart_doc(r) -> tuple[str, str]:
    b = "----b" + str(r.randrange(10**6))
    v = _secret(r, "")
    if r.random() < 0.5:
        v = v[:8] + r.choice(["\r\n", "\n"]) + v[8:] + r.choice(["", "\r\n--not-it"])
    quoted = r.random() < 0.8
    name = r.choice(NAMES)
    part = (f'Content-Disposition: form-data; name={chr(34) + name + chr(34) if quoted else name}'
            f'{r.choice(["", "; x=1"])}\r\n{r.choice(["", "Content-Type: text/plain" + chr(13) + chr(10)])}\r\n{v}')
    doc = (f"--{b}\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\ntess\r\n--{b}\r\n{part}\r\n"
           f"--{b}{r.choice(['--', ''])}\r\n")
    return doc, v.strip()


def _form_doc(r) -> tuple[str, str]:
    name = r.choice(NAMES)
    if r.random() < 0.3:
        name = "".join(f"%{ord(c):02X}" if r.random() < 0.3 else c for c in name)
    v = _secret(r, "&\r\n\t ")
    pairs = [f"{n}={r.choice(['x', 'tess', '1'])}" for n in r.sample(PLAIN, 2)]
    pairs.insert(r.randrange(3), f"{name}={v}")
    return "&".join(pairs), v


def _graphql_doc(r) -> tuple[str, str]:
    name = r.choice([n for n in NAMES if "-" not in n])
    v = _secret(r, '"\\\r\n&#%+')
    query = f'mutation {{ login(user: "tess", {name}:{r.choice(["", " "])}"{v}") {{ ok }} }}'
    form = r.randrange(3)
    if form == 0:
        return json.dumps({"query": query, "variables": {}}), v
    if form == 1:
        return query, v
    return "query=" + quote(query, safe="") + "&operationName=Login", v


FORMATS = {"xml": _xml_doc, "multipart": _multipart_doc, "form": _form_doc, "graphql": _graphql_doc}


@pytest.mark.parametrize("fmt", sorted(FORMATS))
def test_fuzz_redaction_of_bodies_leaves_no_placed_secret(fmt):
    """A secret with a secret name, placed in an XML, multipart, form or GraphQL body: it never
    survives, in text or in a whole HTTP message (with its Content-Type), and a second pass
    changes nothing."""
    r = rng(f"redact-body-{fmt}")
    ctype = {"xml": "text/xml", "multipart": "multipart/form-data; boundary=x", "graphql": "application/json",
             "form": "application/x-www-form-urlencoded"}[fmt]
    for i in range(iterations(400)):
        doc, v = FORMATS[fmt](r)
        with time_limit(2, f"iteration {i}"):
            once = redact.text(doc, redact.Report())
            twice = redact.text(once, redact.Report())
            raw = f"POST /x HTTP/1.1\r\nContent-Type: {ctype}\r\nContent-Length: {len(doc)}\r\n\r\n{doc}".encode()
            msg = redact.http_message(raw, redact.Report())
            again = redact.http_message(msg, redact.Report())
        assert v not in once and v.encode() not in msg, f"{fmt} iteration {i}: {v!r} survived in {show(once)}"
        assert twice == once and again == msg, f"{fmt} iteration {i}: not idempotent: {show(once)}"
        if fmt in ("multipart", "graphql"):
            assert "tess" in once, f"{fmt} iteration {i}: more than the secret went: {show(once)}"


@pytest.mark.parametrize("fmt", sorted(FORMATS))
def test_fuzz_redaction_of_bodies_without_secrets_keeps_them(fmt):
    """The same documents with a name that is not secret come out as they went in."""
    r = rng(f"redact-plain-{fmt}")
    for i in range(iterations(200)):
        doc, v = FORMATS[fmt](r)
        for n in sorted(NAMES, key=len, reverse=True):
            doc = doc.replace(n, "nickname")
        doc = doc.replace(quote("nickname", safe=""), "nickname")
        if any(redact.secret_name(t) for t in ("".join(c if c.isalnum() else " " for c in unquote(doc))).split()):
            continue            # a random value spelled a secret name
        assert redact.text(doc, redact.Report()) == doc, f"{fmt} iteration {i}: {show(doc)}"


PUMP = ["<password>", "<password>a", "<a:password x='1'>", "<password><![CDATA[", "<![CDATA[", "]]>",
        "<name>password</name>", "<name>password</name><value>", "<key>token</key>", "<value>", "</password>",
        '<input name="token" value="', 'name="token" ', "password = '", "<a b=\"", "<a\n",
        'Content-Disposition: form-data; name=password\r\n\r\n', "--b\r\n",
        'Content-Disposition: form-data; name="token"\r\n\r\nx\r\n',
        "password: \"", 'password:\\"', "password%3A%22", "%20token%3A%22a", "token:\"a", "&password=",
        "password=a;", "pass%77ord=", "SAMLResponse=", "a:\"", "\\\""]


def _pumped_units(r):
    return PUMP + [u + "y" for u in PUMP] + ["".join(r.choice(PUMP) for _ in range(r.randint(2, 3)))
                                             for _ in range(iterations(25))]


@pytest.mark.parametrize("where", ["text", "form body", "url"])
def test_fuzz_redaction_of_bodies_is_linear(where):
    """The new rules on pumped input: four times the input takes at most eight times as long."""
    f = {"text": lambda s: redact.text(s, redact.Report()),
         "form body": lambda s: redact.http_message(
             b"POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" + s.encode(), redact.Report()),
         "url": lambda s: redact.url("https://shop.example.com/a?" + s, redact.Report())}[where]
    r = rng(f"redact-pump-{where}")
    for i, unit in enumerate(_pumped_units(r)):
        times = []
        for size in (SIZE // 4, SIZE):
            s = unit * max(1, size // len(unit))
            with time_limit(10 * BUDGET, f"{where} on {unit!r}"):
                times.append(elapsed(f, s)[1])
        assert times[1] <= 8 * times[0] + 0.05 and times[1] <= BUDGET, \
            f"{where} is not linear on {unit!r}: {times[0]:.3f} s, then {times[1]:.3f} s"


# ---- the gateway log: POST /gateway/log --------------------------------------------------------

GATEWAY_TOKEN = "gateway-token-for-fuzz-0000000000"
FIELDS = {"at": ["2026-10-10T12:00:00+00:00", "2026-10-10T12:00:00", "0001-01-01T00:00:00+01:00",
                 "9999-12-31T23:59:59-01:00", "2026-13-40", 1791540000, 1e20, "", None],
          "engagement_id": [None, 0, -1, 2**31, 2**63, 10**30, "1", 1.5, True], "job_id": [None, 0, 2**40, "x"],
          "tool": ["httpx", "", "t" * 33, "\x00", "\ud800", "é" * 32, 5], "kind": ["target", "dns", "TARGET", "", None],
          "method": ["GET", "", "M" * 17, "\u202e"], "url": ["https://app.example.com/", "x" * 2001, "\x00", "\udc80"],
          "host": ["app.example.com", "h" * 256, ""], "port": [443, -1, 65536, 2**70, "443", None, 1e400],
          "status": [200, 1000, -1, 2**70, None, "200"], "verdict": ["allowed", "refused", "failed", "unlogged",
                                                                        "maybe", None],
          "reason": ["", "r" * 301, "\ud800\x00"], "bytes_sent": [0, -1, 2**63, 2**80, 1.0],
          "bytes_received": [0, 10**40], "duration_ms": [None, -5, 2**64, 0.5],
          "account": [None, "alice", "a" * 17, 3], "approval_id": [None, 7, 0, 2**33]}


def _log_row(r):
    row = Obj()
    for k, choices in FIELDS.items():
        if r.random() < 0.9:
            v = choices[0] if r.random() < 0.6 else r.choice(choices)
            row.append((k, Raw("1e400") if v == float("inf") else v))
    if r.random() < 0.2:
        row = mutate_tree(r, row)
    return row if r.random() < 0.95 else value(r)


def test_fuzz_the_gateway_log_answers_per_row_and_never_fails_a_batch_for_one(stack, monkeypatch):
    """Random rows (types, sizes, characters, missing fields): the API answers 200, writes every
    row it can and a placeholder (verdict "unlogged", no URL) for each it cannot, so the gateway
    never has to keep resending a batch for a row in it."""
    monkeypatch.setenv("ATTACKLEDGER_GATEWAY_TOKEN", GATEWAY_TOKEN)
    r = rng("gateway-log")
    stack.engagement()
    for i in range(iterations(25)):
        rows = [_log_row(r) for _ in range(r.randint(1, 30))]
        body = dumps(Obj([("rows", rows)]), r).encode("utf-8", "surrogatepass")
        try:
            json.loads(body)
        except (ValueError, RecursionError):
            continue            # the body itself cannot be read: a 400 or 422 for the batch is right
        with stack.Session() as s:
            before = s.scalar(select(func.count()).select_from(GatewayRequest))
        with time_limit(10, f"iteration {i}"):
            resp = stack.api.post("/gateway/log", content=body, headers={
                "authorization": f"Bearer {GATEWAY_TOKEN}", "content-type": "application/json"})
        assert resp.status_code == 200, f"iteration {i}: {resp.status_code} {resp.text[:300]} {show(body)}"
        out = resp.json()
        bad = [u["index"] for u in out["unlogged"]]
        assert sorted(set(bad)) == bad and all(0 <= b < len(rows) for b in bad)
        assert out["written"] + len(bad) == len(rows)
        with stack.Session() as s:
            got = s.scalars(select(GatewayRequest).order_by(GatewayRequest.id).offset(before)).all()
        assert len(got) == len(rows), f"iteration {i}: {len(got)} stored for {len(rows)} rows"
        for b in bad:
            assert got[b].verdict == "unlogged" and got[b].url == "" and got[b].reason.startswith("not stored ("), b
        assert all(g.verdict != "unlogged" for k, g in enumerate(got) if k not in bad and not
                   (isinstance(rows[k], Obj) and ("verdict", "unlogged") in rows[k]))


def test_fuzz_a_placeholder_is_always_a_row_the_api_stores():
    """gatewaylog.placeholder, from anything at all, passes the API's own row check."""
    r = rng("gateway-placeholder")
    for i in range(iterations(2000)):
        try:
            raw = json.loads(dumps(_log_row(r)))
        except ValueError:
            continue
        p = gatewaylog.placeholder(gatewayapi._clean(raw), r.choice(STRINGS))
        gatewayapi._checked(p)
        assert p["url"] == "" and p["verdict"] == "unlogged"


def test_fuzz_the_gateway_reads_any_answer_to_a_log_batch():
    """_unlogged and _detail read the API's answer (JSON of any shape) without raising."""
    r = rng("gateway-answers")
    for i in range(iterations(2000)):
        try:
            tree = json.loads(dumps(value(r)))
        except ValueError:
            continue            # a number Python will not read: never an answer the gateway gets
        data = tree if r.random() < 0.5 else {
            "unlogged": [r.choice([{"index": value(r), "reason": value(r)}, value(r), {"index": r.randint(-2, 40)}])
                         for _ in range(r.randint(0, 5))],
            "detail": r.choice([value(r), [{"loc": value(r), "msg": value(r)}], [value(r)]])}
        data = json.loads(json.dumps(data, default=str))
        out = gateway._unlogged(data, r.randint(0, 40))
        assert all(isinstance(k, int) for k, _ in out)
        assert isinstance(gateway._detail(data if isinstance(data, dict) else {}), str)
