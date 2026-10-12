"""Property-based fuzzing, third pass (docs/security-review/FUZZING.md, "Third pass").

The targets the second pass left out: the gateway's TLS layer (CONNECT, its CA's leaf
certificates, the server name and ALPN a client sends, a client sending anything at all after the
200), request heads that never end, redaction of positional XML-RPC parameters, SAML assertions,
unquoted HTML attributes and JSON values under a secret key that are objects or arrays, and the
report from histories with signed receipts, voids, content deletion and the seal. Same harness as
test_fuzz.py (fuzzing.py): seeded, offline, time-limited; a failure names the seed and the
iteration. ATTACKLEDGER_FUZZ_ITERATIONS makes every test run that many inputs.
"""
import base64
import json
import os
import socket
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import quote

import pytest
from sqlalchemy import select

from app import gateway, redact
from fuzzing import FIXED_NOW, INTERESTING, elapsed, fixed_clock, iterations, mutate_bytes, rng, show, time_limit
from test_gateway import Stack as GatewayStack
from test_fuzz2 import NAMES, _secret
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


# ---- redaction: positional XML-RPC, SAML, unquoted HTML attributes, nested JSON ----------------------

SIZE = int(os.environ.get("ATTACKLEDGER_FUZZ_SIZE") or 40_000)
BUDGET = float(os.environ.get("ATTACKLEDGER_FUZZ_BUDGET") or 2.0)
RPC_SECRET = ["wp.getUsersBlogs", "wp.getPosts", "metaWeblog.newPost", "blogger.getUsersBlogs", "mt.getCategoryList",
              "system.login", "auth.authenticate", "user.getToken", "Session.Login", "api.signIn", "x.setPassword"]
RPC_PLAIN = ["demo.sayHello", "pingback.ping", "system.listMethods", "examples.getStateName", "weather.get"]
JSON_SECRET = ["password", "credentials", "Credentials", "credential", "token", "api_key", "clientSecret",
               "\\u0070assword", "session"]
SAML_PREFIXES = ["saml:", "saml2:", "", "ns2:", "s:"]


def _value(r, v: str, sp: str) -> str:
    return r.choice([f"<value>{sp}<string>{v}</string>{sp}</value>", f"<value>{sp}{v}{sp}</value>",
                     f"<value><base64>{v}</base64></value>"])


def _rpc_params(r, v: str, sp: str) -> list[str]:
    params = [_value(r, r.choice(["tess", "blog-1", "en"]), sp) if r.random() < 0.5 else
              f"<value><int>{r.randrange(100)}</int></value>" for _ in range(r.randint(1, 3))]
    params.insert(r.randrange(len(params) + 1), _value(r, v, sp))
    return params


def _rpc_doc(r, method: str) -> tuple[str, str]:
    """A call of `method` with a value at a random position among its parameters, sent alone or
    in system.multicall (the brute-force amplifier)."""
    v = _secret(r, "<&>\"'")
    sp = r.choice(["", " ", "\n  ", "\t"])
    params = _rpc_params(r, v, sp)
    if r.random() < 0.6:
        doc = (f"<?xml version=\"1.0\"?><methodCall>{sp}<methodName>{sp}{method}{sp}</methodName>{sp}<params>"
               + "".join(f"<param>{sp}{p}{sp}</param>" for p in params) + "</params></methodCall>")
    else:
        other = [f"<value><struct><member><name>methodName</name><value><string>{m}</string></value></member>"
                 f"<member><name>params</name><value><array><data>"
                 + "".join(_rpc_params(r, "tess", sp)) + "</data></array></value></member></struct></value>"
                 for m in r.sample(RPC_PLAIN, r.randint(0, 2))]
        call = (f"<value><struct><member><name>methodName</name><value>{r.choice(['<string>%s</string>', '%s'])}"
                f"</value></member><member><name>params</name><value><array><data>{sp}" % method
                + sp.join(params) + "</data></array></value></member></struct></value>")
        other.insert(r.randrange(len(other) + 1), call)
        doc = ("<methodCall><methodName>system.multicall</methodName><params><param><value><array><data>"
               + "".join(other) + "</data></array></value></param></params></methodCall>")
    return doc, v


def _saml_assertion(r, v: str) -> tuple[str, str]:
    p = r.choice(SAML_PREFIXES)
    ns = "" if "saml" in p and r.random() < 0.5 else ' xmlns="urn:oasis:names:tc:SAML:2.0:assertion"'
    if r.random() < 0.3:
        return (f"<{p}EncryptedAssertion{ns}><xenc:EncryptedData><xenc:CipherData><xenc:CipherValue>{v}"
                f"</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></{p}EncryptedAssertion>"), p
    leaf = r.choice([f"<{p}NameID>{v}</{p}NameID>", f"<{p}AttributeValue>{v}</{p}AttributeValue>",
                     f"<ds:X509Certificate>{v}</ds:X509Certificate>"])
    advice = r.choice(["", "", f"<{p}Advice><{p}AssertionIDRef>r</{p}AssertionIDRef><{p}Assertion ID=\"i\">in"
                                f"</{p}Assertion></{p}Advice>"])        # an assertion inside this one
    return (f"<{p}Assertion ID=\"_a{r.randrange(10**6)}\" Version=\"2.0\"{ns}><{p}Issuer>idp</{p}Issuer>{advice}"
            f"<{p}Subject>{leaf}</{p}Subject><ds:SignatureValue>sig</ds:SignatureValue></{p}Assertion>"), p


def _saml_doc(r) -> tuple[str, str]:
    """An assertion inside other XML (SOAP, WS-Security, ECP, an artifact response), or a SAML
    response in base64 under a name that is not secret, in a form or JSON."""
    v = _secret(r, "<&>\"'")
    assertion, p = _saml_assertion(r, v)
    wrap = r.choice(["%s", "<soap:Envelope xmlns:soap=\"x\"><soap:Header><wsse:Security>%s</wsse:Security></soap:Header>"
                     "<soap:Body/></soap:Envelope>",
                     "<S:Envelope><S:Body><samlp:ArtifactResponse><samlp:Response>%s</samlp:Response>"
                     "</samlp:ArtifactResponse></S:Body></S:Envelope>",
                     "<trust:RequestSecurityTokenResponse><trust:RequestedSecurityToken>%s"
                     "</trust:RequestedSecurityToken></trust:RequestSecurityTokenResponse>"])
    doc = wrap % assertion
    if r.random() < 0.35:
        response = (f"<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">{assertion}</samlp:Response>"
                    if r.random() < 0.5 else '<?xml version="1.0"?>' + doc)
        if "urn:oasis:names:tc:SAML" not in response:
            response = response.replace(">", ' xmlns:x="urn:oasis:names:tc:SAML:2.0:assertion">', 1)
        b64 = base64.b64encode(response.encode()).decode()
        if r.random() < 0.3:
            b64 = "\r\n".join(b64[i:i + 76] for i in range(0, len(b64), 76))
        name = r.choice(["data", "RelayStateX", "msg", "payload"])
        form = r.randrange(3)
        doc = [f"{name}={quote(b64, safe='')}&x=1", json.dumps({name: b64}), b64][form]
        return doc, quote(b64[:60], safe="") if form == 0 else b64[:60]
    return doc, v


def _html_doc(r) -> tuple[str, str]:
    """<input name=password value=x>, unquoted, quoted or mixed, in any order, upper case too."""
    name = r.choice(NAMES + ["csrf_token", "authenticity_token", "csrf-token"])
    v = _secret(r, "<>\"'=` \t\r\n&")
    q = r.choice(["", "", '"', "'"])
    attr = r.choice(["value", "VALUE", "content"])
    nq = r.choice(["", '"', "'"])
    pair = [f"{r.choice(['name', 'NAME', 'key', 'property'])}={nq}{name}{nq}", f"{attr}={q}{v}{q}"]
    r.shuffle(pair)
    tag = r.choice(["input", "meta", "INPUT", "add"])
    extra = r.choice(["", " type=hidden", " id=f1", ' class="a b"'])
    doc = r.choice([f"<{tag}{extra} {pair[0]} {pair[1]}>", f"<{tag} {pair[0]}{extra} {pair[1]} />",
                    f"<{tag} data-{name}={v}>"])
    return f"<html><form method=post>{doc}</form></html>", v


def _json_tree(r, v: str, depth: int):
    if depth == 0:
        return v
    if r.random() < 0.5:
        items = [r.choice(["tess", 7, True, None]) for _ in range(r.randint(0, 2))]
        items.insert(r.randrange(len(items) + 1), _json_tree(r, v, depth - 1))
        return items
    obj = {k: r.choice(["tess", 7, False]) for k in r.sample(["user", "id", "kind", "n"], r.randint(0, 2))}
    obj[r.choice(["value", "pin", "secret", "x", "data"])] = _json_tree(r, v, depth - 1)
    return dict(r.sample(list(obj.items()), len(obj)))


def _json_doc(r) -> tuple[str, str]:
    """A secret key whose value is an object or an array holding the secret anywhere in it."""
    v = _secret(r, "\"\\\r\n")
    key = r.choice(JSON_SECRET)
    inner = json.dumps(_json_tree(r, v, r.randint(1, 4)), indent=r.choice([None, 2]))
    if not inner.startswith(("{", "[")):
        inner = "[" + inner + "]"
    doc = '{"ok": 1, "%s":%s%s, "after": "tess"}' % (key, r.choice(["", " ", "\n "]), inner)
    return doc, v


NEW_FORMATS = {"xmlrpc": lambda r: _rpc_doc(r, r.choice(RPC_SECRET)), "saml": _saml_doc, "html": _html_doc,
               "json": _json_doc}


@pytest.mark.parametrize("fmt", sorted(NEW_FORMATS))
def test_fuzz_redaction_of_the_new_forms_leaves_no_placed_secret(fmt):
    """A secret placed where the second pass left it (a positional XML-RPC parameter, a SAML
    assertion in other XML or in base64 under any name, an unquoted HTML attribute, a JSON object
    or array under a secret key): it never survives text or a whole HTTP message; a second pass
    changes nothing; JSON stays JSON with the same keys."""
    r = rng(f"redact3-{fmt}")
    ctype = {"xmlrpc": "text/xml", "saml": "application/soap+xml", "html": "text/html",
             "json": "application/json"}[fmt]
    for i in range(iterations(400)):
        doc, v = NEW_FORMATS[fmt](r)
        with time_limit(2, f"iteration {i}"):
            once = redact.text(doc, redact.Report())
            twice = redact.text(once, redact.Report())
            raw = f"POST /x HTTP/1.1\r\nContent-Type: {ctype}\r\nContent-Length: {len(doc)}\r\n\r\n{doc}".encode()
            msg = redact.http_message(raw, redact.Report())
            again = redact.http_message(msg, redact.Report())
        assert v not in once and v.encode() not in msg, f"{fmt} iteration {i}: {v!r} survived in {show(once)}"
        assert twice == once and again == msg, f"{fmt} iteration {i}: not idempotent: {show(once)}"
        if fmt == "json":
            before, after = json.loads(doc), json.loads(once)
            assert list(after) == list(before) and after["after"] == "tess", f"iteration {i}: {show(once)}"
        if fmt == "xmlrpc":
            assert "methodName" in once and ("<int>" in once) == ("<int>" in doc), f"iteration {i}: {show(once)}"


def _plain_rpc(r):
    doc, _ = _rpc_doc(r, r.choice(RPC_PLAIN))
    return doc.replace("system.multicall", "demo.batch")


def _plain_saml(r):
    v = _secret(r, "<&>\"'")
    return f"<test:Results><test:Assertion ID=\"a1\"><test:NameID>{v}</test:NameID></test:Assertion></test:Results>"


def _plain_html(r):
    doc, _ = _html_doc(r)
    for n in sorted(NAMES + ["csrf_token", "authenticity_token", "csrf-token"], key=len, reverse=True):
        doc = doc.replace(n, "nickname")
    return doc


def _plain_json(r):
    doc, _ = _json_doc(r)
    for n in sorted(JSON_SECRET, key=len, reverse=True):
        doc = doc.replace(f'"{n}"', '"profile"')
    return doc


@pytest.mark.parametrize("fmt, make", [("xmlrpc", _plain_rpc), ("saml", _plain_saml), ("html", _plain_html),
                                       ("json", _plain_json)])
def test_fuzz_redaction_of_the_new_forms_without_secrets_keeps_them(fmt, make):
    """The same documents without a secret name, method or SAML namespace come out as they went in."""
    r = rng(f"redact3-plain-{fmt}")
    for i in range(iterations(200)):
        doc = make(r)
        words = [w for w in "".join(c if c.isalnum() else " " for c in doc).split() if w != "Assertion"]
        if any(redact.secret_name(t) for t in words) or any(redact.rpc_secret_method(t) for t in doc.split(">")):
            continue            # a random value spelled a secret name
        assert redact.text(doc, redact.Report()) == doc, f"{fmt} iteration {i}: {show(doc)}"


PUMP3 = ["<methodName>wp.a</methodName>", "<methodName>wp.a</methodName><param><value>", "<param><value>",
         "<value><string>", "</value><value>", "</value><value>x", "<data><value><string>a</string></value>",
         "<name>methodName</name><value>auth.x</value>", "<saml:Assertion>", "<saml:Assertion>x",
         "</saml:Assertion", "<Assertion xmlns='urn:oasis:names:tc:SAML:2.0:assertion'>", "<saml:Artifact>",
         "<saml:Assertion><saml:Advice><saml:Assertion></saml:Assertion>", "<saml:AssertionIDRef>",
         '"token": {', '"token": [', '"password": [[', '"credentials":{"a":"', '{"token": {"a": "\\', '"\\',
         '"token": {"', "<input name=password value=", "<a value=", "name=token content=", "<i b=c d=e ",
         "PHNhbWw", "P" + "A" * 120, "PD94bWw%2B", "P" + "A" * 99 + "\r\n"]


@pytest.mark.parametrize("where", ["text", "form body"])
def test_fuzz_redaction_of_the_new_forms_is_linear(where):
    """The new rules on pumped input: four times the input takes at most eight times as long
    (the fastest of three runs when one measurement looks slow, as in the first pass)."""
    f = {"text": lambda s: redact.text(s, redact.Report()),
         "form body": lambda s: redact.http_message(
             b"POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" + s.encode(),
             redact.Report())}[where]
    r = rng(f"redact3-pump-{where}")
    units = PUMP3 + [u + "y" for u in PUMP3] + ["".join(r.choice(PUMP3) for _ in range(r.randint(2, 3)))
                                                for _ in range(iterations(25))]

    def measure(unit, runs):
        times = []
        for size in (SIZE // 4, SIZE):
            s = unit * max(1, size // len(unit))
            with time_limit(10 * BUDGET, f"{where} on {unit!r}"):
                times.append(min(elapsed(f, s)[1] for _ in range(runs)))
        return times
    for unit in units:
        times = measure(unit, 1)
        if times[1] > 8 * times[0] + 0.05 or times[1] > BUDGET:
            times = measure(unit, 3)
        assert times[1] <= 8 * times[0] + 0.05 and times[1] <= BUDGET, \
            f"{where} is not linear on {unit!r}: {times[0]:.3f} s, then {times[1]:.3f} s"


# ---- the report: signed receipts, voids, revoked keys, content deletion, the seal ---------------------

ROOT = Path(__file__).resolve().parents[2]
SIGNERS = {"owner": "owner@lab.test", "rita": "rita@lab.test", "tess": "tess@lab.test"}   # tess may not sign

# Run in a separate process: the reports of the given engagements, from the database alone, with
# the clock fixed. Two of these, with different hash seeds, must write the same bytes.
EXPORT = r"""
import datetime as dt, hashlib, json, sys
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from fastapi.responses import JSONResponse
from app import main, report, seal

FIXED = dt.datetime.fromisoformat(sys.argv[4])

class Fixed(dt.datetime):
    @classmethod
    def now(cls, tz=None):
        return FIXED.replace(tzinfo=tz)
report.datetime = seal.datetime = Fixed
url, out = sys.argv[1], sys.argv[2]
engine = create_engine(url)
with Session(engine) as s:
    for e in json.loads(sys.argv[3]):
        r = main._report(e, s)
        with open(f"{out}/{e}.json", "wb") as f:
            f.write(JSONResponse(r).body)
        with open(f"{out}/{e}.html", "wb") as f:
            f.write(report.render_html(r).encode())
engine.dispose()
"""


@pytest.fixture()
def file_client(tmp_path, monkeypatch):
    """The API on a database file (Postgres under tools/test_postgres.sh) another process can read."""
    import testdb
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app import auth, db, people
    from app.main import app
    monkeypatch.delenv("ATTACKLEDGER_API_TOKEN", raising=False)
    auth._failures.clear()
    eng = testdb.file_engine(tmp_path / "report-fuzz.db")
    db.Base.metadata.create_all(eng)
    Session = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)

    def _session():
        s = Session()
        try:
            yield s
        finally:
            s.close()
    app.dependency_overrides[db.get_session] = _session
    monkeypatch.setattr(people, "SessionLocal", Session)
    with TestClient(app) as c:
        yield c, eng
    app.dependency_overrides.clear()
    eng.dispose()


def _lanes_of(c, e: int) -> list[int]:
    from app.models import Asset, Lane
    from test_import import db
    return list(db(c).scalars(select(Lane.id).join(Asset).where(Asset.engagement_id == e).order_by(Lane.id)))


def _as(c, email: str) -> bool:
    """Signed in as this person; False (and signed in as the owner) when they cannot sign in now:
    disabled, which is part of the history."""
    from test_people import sign_in
    got = sign_in(c, email)
    assert got.status_code in (200, 401), got.text[:300]
    if got.status_code != 200:
        assert sign_in(c, "owner@lab.test").status_code == 200
    return got.status_code == 200


def _key(c, r, keys: dict, who: str):
    """The person's signing key, registered (as the person signed in now)."""
    from test_signing import BrowserKey
    k = keys.get(who)
    if k is None:
        k = BrowserKey(r.choice(["Ed25519", "ECDSA-P256"]))
        res = c.post("/auth/keys", json={"algorithm": k.algorithm, "public_key": k.spki})
        assert res.status_code == 201, res.text
        k.fingerprint, k.id = res.json()["fingerprint"], res.json()["id"]
        keys[who] = k
    return k


def _ops3(c, r, e: int, name: str, keys: dict, seen: dict, why: dict, emails: dict, disabled: set) -> None:
    """Signed closes (by a reviewer, an owner, and a tester who may not), unsigned ones, voids
    (an item reopened, evidence added to a receipted lane), keys revoked after signing, and, now
    and then, the engagement's content deleted. Refusals (4xx) are part of it; a 5xx never is."""
    from test_fuzz2 import _send_json, _text
    for _ in range(r.randint(2, 6)):
        lanes = [c.get(f"/lanes/{x}").json() for x in _lanes_of(c, e)]
        if not lanes:
            return
        op = r.choice(["sign", "sign", "sign", "close", "void", "void", "revoke", "delete", "person", "roles"])
        # Other lanes sign only once their host's information lane is receipted: that one first, mostly.
        first = [x for x in lanes if x.get("role") == "info" and x.get("status") != "closed"]
        lane = r.choice(first if first and op in ("sign", "close") and r.random() < 0.7 else lanes)
        who = r.choice(sorted(w for w in emails if w not in disabled))
        if not _as(c, emails[who]):
            continue
        res = None
        if op in ("sign", "close"):
            for it in lane["items"]:
                if it["state"] == "open":
                    if r.random() < 0.6:
                        _send_json(c, "post", f"/lanes/{lane['id']}/attach",
                                   {"item_idx": it["idx"], "kind": "note", "text": _text(r)[:2000]})
                        _send_json(c, "patch", f"/lanes/{lane['id']}/items/{it['idx']}", {"state": "done"})
                    else:
                        _send_json(c, "patch", f"/lanes/{lane['id']}/items/{it['idx']}",
                                   {"state": "na", "na_reason": _text(r)})
            for it in c.get(f"/lanes/{lane['id']}").json()["items"]:      # what the random text could not settle
                if it["state"] == "open":
                    c.patch(f"/lanes/{lane['id']}/items/{it['idx']}", json={"state": "na", "na_reason": "lab"})
            if op == "sign":
                k = _key(c, r, keys, who)
                got = c.get(f"/lanes/{lane['id']}/receipt-payload", params={"key": k.fingerprint})
                assert got.status_code < 500, got.text[:300]
                if got.status_code != 200:
                    why[str(got.json().get("detail", ""))[:80]] = why.get(str(got.json().get("detail", ""))[:80], 0) + 1
                if got.status_code == 200:
                    payload = got.json()["payload"]
                    res = c.post(f"/lanes/{lane['id']}/close", json={"reviewed": True, "payload": payload,
                                                                    "signature": k.sign(payload),
                                                                    "key_fingerprint": k.fingerprint})
            else:
                res = c.post(f"/lanes/{lane['id']}/close", json={"reviewed": True})
        elif op == "void":
            items = lane["items"]
            it = r.choice(items)
            if r.random() < 0.5:
                res = _send_json(c, "patch", f"/lanes/{lane['id']}/items/{it['idx']}", {"state": "open"})
            else:
                res = _send_json(c, "post", f"/lanes/{lane['id']}/attach",
                                 {"item_idx": it["idx"], "kind": "note", "text": _text(r)[:2000]})
        elif op == "revoke" and who in keys:
            res = c.post(f"/auth/keys/{keys.pop(who).id}/revoke")
        elif op == "person":
            # The signer renamed, given another email, disabled or enabled again after signing: the
            # verifier checks each receipt against who the signer was when it was issued.
            _as(c, "owner@lab.test")
            change = r.choice([{"name": _text(r)[:200]}, {"name": "Rita " + str(r.randrange(99))},
                               {"email": f"rita{r.randrange(99)}@lab.test"}, {"disabled": True}, {"disabled": False}])
            res = _send_json(c, "patch", "/people/3", change)
            if res.status_code == 200 and "email" in change:
                emails["rita"] = change["email"]
            if res.status_code == 200 and change.get("disabled") is True and r.random() < 0.7:
                res = _send_json(c, "patch", "/people/3", {"disabled": False})
                change = {"disabled": False}
            if res.status_code == 200 and "disabled" in change:
                (disabled.add if change["disabled"] else disabled.discard)("rita")
        elif op == "roles":
            _as(c, "owner@lab.test")
            res = c.put(f"/engagements/{e}/members", json={"members": [
                {"user_id": 3, "roles": r.choice([["reviewer"], ["tester"], ["tester", "reviewer"], ["viewer"]])},
                {"user_id": 2, "roles": ["tester"]}]})
        elif op == "delete" and r.random() < 0.3:
            _as(c, "owner@lab.test")
            res = c.post(f"/engagements/{e}/content/delete", json={"confirm_name": name})
        if res is not None:
            assert res.status_code < 500, f"{op}: {res.status_code} {res.text[:300]}"
            seen[(op, res.status_code)] = seen.get((op, res.status_code), 0) + 1
    _as(c, "owner@lab.test")


def _verify(verify, tmp_path, data: bytes, ext: str, *flags) -> tuple[int, str]:
    import contextlib
    import io
    p = tmp_path / f"r.{ext}"
    p.write_bytes(data)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = verify.main(["verify_report.py", str(p), *flags])
    return code, out.getvalue()


def test_fuzz_the_report_with_signatures_voids_and_deletion_verifies_strictly_and_is_byte_stable(
        file_client, tmp_path, monkeypatch):
    """Random histories (the second pass's, plus signed and unsigned receipts, voids, keys revoked
    after signing, content deleted): the JSON and HTML reports build and verify; in strict mode
    (--require-history) exactly when every receipt in force is signed; and two other processes,
    with other hash seeds, reading the same database with the clock fixed, write the same bytes."""
    import datetime as dt
    import importlib.util
    import subprocess
    from app import report, seal
    from test_fuzz2 import _ops, _send_json, _text
    from test_import import team
    c, engine = file_client
    spec = importlib.util.spec_from_file_location("verify_report_fz3", ROOT / "tools" / "verify_report.py")
    verify = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verify)

    Fixed = fixed_clock()
    _, e, _ = team(c)
    names = {e: "Import"}
    r = rng("report3")
    seen: dict = {}
    why: dict = {}              # why a receipt payload was refused
    keys: dict = {}
    emails, disabled = dict(SIGNERS), set()
    engagements = []
    for i in range(iterations(5)):
        with time_limit(90, f"iteration {i}"):
            if i:
                name = _text(r)[:200]
                made = _send_json(c, "post", "/engagements", {"name": name, "pack_id": "web-pentest-wstg"})
                assert made.status_code < 500, made.text[:300]
                if made.status_code != 201:
                    continue
                e = made.json()["id"]
                names[e] = made.json()["name"]
                c.put(f"/engagements/{e}/scope", json={"include": ["shop.example.com", "*.shop.example.com"]})
                c.put(f"/engagements/{e}/members", json={"members": [
                    {"user_id": 3, "roles": ["reviewer"]}, {"user_id": 2, "roles": ["tester"]}]})
            engagements.append(e)
            _ops(c, r, e, "web-pentest-wstg", seen)
            _ops3(c, r, e, names[e], keys, seen, why, emails, disabled)
            _ops(c, r, e, "web-pentest-wstg", seen)
            _ops3(c, r, e, names[e], keys, seen, why, emails, disabled)
            with monkeypatch.context() as m:
                m.setattr(report, "datetime", Fixed)
                m.setattr(seal, "datetime", Fixed)
                first = c.get(f"/engagements/{e}/report")
                html = c.get(f"/engagements/{e}/report.html")
        assert first.status_code == 200 and html.status_code == 200, f"iteration {i}: {first.text[:300]}"
        assert html.text == report.render_html(json.loads(first.content)), f"iteration {i}: HTML is not the JSON"
        rep = json.loads(first.content)
        in_force = [l for l in rep["lanes"] if l["receipt"] and l["status"] == "closed"]
        all_signed = all(l["receipt"].get("signature") for l in in_force)
        for ext, data in (("json", first.content), ("html", html.content)):
            code, out = _verify(verify, tmp_path, data, ext)
            assert code == 0, f"iteration {i}: {ext} does not verify:\n{out[-3000:]}"
            code, out = _verify(verify, tmp_path, data, ext, "--require-history")
            assert code == (0 if all_signed else 1), f"iteration {i}: {ext} strict {code}, all signed {all_signed}:\n" \
                                                      f"{out[-3000:]}"
            if not all_signed:
                assert "the receipt is not signed" in out, out[-2000:]
    ok = {op for (op, code), n in seen.items() if code < 300}
    assert {"sign", "void", "person", "roles", 4, 5, 6} <= ok, "; ".join(map(str, sorted(seen.items(), key=str))) + f" {why}"

    # The same database, read by two other processes with other hash seeds and the clock fixed.
    with monkeypatch.context() as m:
        m.setattr(report, "datetime", Fixed)
        m.setattr(seal, "datetime", Fixed)
        here = {e: (c.get(f"/engagements/{e}/report").content, c.get(f"/engagements/{e}/report.html").content)
                for e in engagements}
    url = engine.url.render_as_string(hide_password=False)
    for seed in ("1", "4242"):
        out = tmp_path / f"export-{seed}"
        out.mkdir()
        env = {**os.environ, "PYTHONHASHSEED": seed, "PYTHONDONTWRITEBYTECODE": "1"}
        done = subprocess.run([sys.executable, "-c", EXPORT, url, str(out), json.dumps(engagements), FIXED_NOW.isoformat()],
                              cwd=ROOT / "server", env=env, capture_output=True, text=True, timeout=180)
        assert done.returncode == 0, done.stderr[-3000:]
        for e, (j, h) in here.items():
            assert (out / f"{e}.json").read_bytes() == j, f"engagement {e}: the JSON differs in a process seeded {seed}"
            assert (out / f"{e}.html").read_bytes() == h, f"engagement {e}: the HTML differs in a process seeded {seed}"
