"""Property-based and mutation fuzzing of everything that parses hostile input
(docs/security-review/FUZZING.md).

Inputs come from fuzzing.py: seeded, standard library only, small by default so the suite
stays fast and offline. Set ATTACKLEDGER_FUZZ_ITERATIONS (and ATTACKLEDGER_FUZZ_SEED) for a
long run. The properties:

- importers: only ImportRefused (or a listed row) for any file, within a time limit; every
  entry has a valid URL, method, status and bounded parts;
- the inbox: every accepted row's host is in scope by scope.py, and its stored, redacted URL
  still names that host; the entry and its suggestions can be read back;
- redaction: idempotent, and no secret placed in a header, cookie, query, form, multipart
  field, JSON key or JWT survives it;
- scope and URLs: the gateway, the inbox and recon read the same host from the same URL, as a
  browser would; host and pattern normalisation are idempotent;
- the text parsers (redaction, JS analysis, page text, surface, scope CSV): no catastrophic
  backtracking on pumped inputs, no crash on binary input.
"""
import base64
import json
import os
import random
import re
import string
from urllib.parse import urlsplit

import pytest
from sqlalchemy import select

from app import gateway, importers, inbox, jsanalysis, pagetext, redact, scope, scopeimport, surface, urls
from app.models import InboxEntry
from fuzzing import elapsed, iterations, mutate_bytes, mutate_json, rng, show, time_limit
from test_import import BURP, CAIDO, HAR, db, team, upload
from test_people import client  # noqa: F401  (fixture)

SIZE = int(os.environ.get("ATTACKLEDGER_FUZZ_SIZE") or 40_000)     # characters in a pumped input
BUDGET = float(os.environ.get("ATTACKLEDGER_FUZZ_BUDGET") or 2.0)  # seconds; a linear parser needs ~0.01 for SIZE


def fail(what: str, i: int, data, e: BaseException | None = None):
    pytest.fail(f"{what}, iteration {i}: {type(e).__name__ + ': ' + str(e)[:200] if e else ''}\n"
                f"input: {show(data)}", pytrace=False)


# ---- importers --------------------------------------------------------------------------------

XML_FIELDS = re.compile(rb"(<(url|host|port|protocol|method|path|status|time|comment|request|response)\b[^>]*>)"
                        rb"(<!\[CDATA\[.*?\]\]>|[^<]*)(</\2>)", re.S)
FIELD_VALUES = [b"", b" ", b"0", b"1e400", b"99999", b"-1", b"200.5", b"GET", b"g e t", b"http://[::1", b"https://",
                b"https://shop.example.com\\@evil.example.net/", b"ftp://shop.example.com/", b"QUJD", b"QQ", b"=",
                b"not base64!", b"&#0;", b"&amp;", b"<![CDATA[]]]]><![CDATA[>]]>", b"\xc3\x28", b"A" * 70_000]


def mutate_xml(r: random.Random, data: bytes) -> bytes:
    fields = list(XML_FIELDS.finditer(data))
    for _ in range(r.randint(1, 3)):
        m = r.choice(fields)
        new = r.choice(FIELD_VALUES)
        if r.random() < 0.3:
            new = base64.b64encode(mutate_bytes(r, base64.b64decode(b"R0VUIC8gSFRUUC8xLjENCg0K")))
        data = data[:m.start(3)] + new + data[m.end(3):]
        fields = list(XML_FIELDS.finditer(data))
        if not fields:
            break
    return mutate_bytes(r, data, 1) if r.random() < 0.3 else data


def mutate_export(r: random.Random, fmt: str, base: bytes) -> bytes:
    if r.random() < 0.3:
        return mutate_bytes(r, base)
    if fmt == "burp":
        return mutate_xml(r, base)
    return mutate_json(r, base.decode())


def check_parsed(parsed: importers.Parsed):
    rows = [e.row for e in parsed.entries] + [n for n, _ in parsed.unreadable]
    assert len(rows) == len(set(rows)) and all(n >= 1 for n in rows)
    assert len(parsed.entries) + len(parsed.unreadable) <= importers.MAX_ENTRIES
    for e in parsed.entries:
        assert importers.http_url(e.url) == e.url and urlsplit(e.url).hostname
        assert re.fullmatch(r"[A-Z][A-Z0-9_-]{0,19}", e.method)
        assert e.status is None or (type(e.status) is int and 100 <= e.status <= 599)
        for part in (e.request, e.response):
            assert part is None or (isinstance(part, bytes) and len(part) <= importers.MAX_PART_BYTES * 2)
        for t in (e.tool_id, e.time, e.label):
            assert t is None or (isinstance(t, str) and "\x00" not in t)
    assert parsed.creator is None or "\x00" not in parsed.creator


@pytest.mark.parametrize("fmt", ["har", "burp", "caido"])
def test_fuzz_importers_refuse_or_read_never_crash(fmt):
    """Any file: ImportRefused, or entries that meet the contract. Never another exception,
    never more than a few seconds."""
    base = {"har": HAR, "burp": BURP, "caido": CAIDO}[fmt]
    r = rng(f"importers-{fmt}")
    for i in range(iterations(150)):
        data = mutate_export(r, fmt, base)
        for asked in (fmt, None):
            try:
                with time_limit(5, f"{fmt} import"):
                    _, parsed = importers.parse(data, asked)
            except importers.ImportRefused:
                continue
            except Exception as e:  # noqa: BLE001 - the property under test
                fail(f"importers.parse({asked!r}) raised", i, data, e)
            check_parsed(parsed)


# ---- URLs: one grammar for the differential tests ----------------------------------------------

SCHEMES = ["http", "https", "HTTP", "hTtPs", "ftp", "ws", ""]
SEPS = ["://", "://", "://", ":/", ":\\\\", ":///", "//"]
USERINFO = ["", "", "", "user@", "user:pw@", "a@b@", "evil.example.net@", "%40@", "shop.example.com@", ":@"]
HOSTS = ["shop.example.com", "SHOP.Example.COM", "shop.example.com.", "shop.example.com..", "a.shop.example.com",
         "static.shop.example.com", "STATIC.shop.example.com.", "evil.example.net", "shop.example.com.evil.example.net",
         "evil.example.net\\@shop.example.com", "shop.example.com\\@evil.example.net", "xn--shp-sna.shop.example.com",
         "sh\u00f6p.example.com", "\u212a.shop.example.com", "\uff53hop.example.com", "shop.example.com%2e",
         "[::1]", "[shop.example.com]", "127.0.0.1", "shop.example.com\t", " shop.example.com", "shop..example.com",
         "-a.shop.example.com", "*.shop.example.com", "shop.example.com\n", "shop.example.com\n.", "a_b.shop.example.com",
         "shop.example.com:443@evil.example.net", "shop.example.com#@evil.example.net", "shop.example.com?@evil.example.net",
         "shop.example.com/@evil.example.net", "shop.example.com\x00.evil.example.net", "", "a" * 64 + ".shop.example.com"]
PORTS = ["", "", "", ":443", ":80", ":8443", ":0", ":65535", ":65536", ":99999", ":", ":abc", ":+1", ": 1", ":\u0661"]
PATHS = ["", "/", "/a?b=c", "\\@evil.example.net/", "?x", "#f", "/../", "@evil.example.net", "/x\\y", "\\\\evil.example.net/"]
INCLUDE = ["shop.example.com", "*.shop.example.com"]
EXCLUDE = ["static.shop.example.com"]


def gen_url(r: random.Random) -> str:
    return (r.choice(SCHEMES) + r.choice(SEPS) + r.choice(USERINFO) + r.choice(HOSTS) + r.choice(PORTS)
            + r.choice(PATHS))


def browser_host(url: str) -> str | None:
    """The host a browser (WHATWG URL) sends a special-scheme URL to, for the URLs the grammar
    makes: a backslash ends the authority like a slash, and the host is after the last @."""
    url = re.sub("[\t\r\n]", "", url)
    m = re.match(r"(?i)^\s*(https?)://([^/\\?#]*)", url)
    if not m:
        return None
    authority = m.group(2).rsplit("@", 1)[-1]
    host = authority[1:].split("]", 1)[0] if authority.startswith("[") else authority.rsplit(":", 1)[0] \
        if authority.count(":") == 1 else authority
    return host.strip().lower().rstrip(".") or None


def inbox_decision(url: str, include=INCLUDE, exclude=EXCLUDE) -> tuple[str, str | None]:
    """As inbox.import_file decides: (verdict, host)."""
    try:
        u = importers.http_url(url)
    except importers.RowError:
        return "unreadable", None
    host = urlsplit(u).hostname or ""
    try:
        host = scope.normalize_host(host)
    except scope.ScopeError:
        return "unreadable", None
    return ("in" if scope.in_scope(host, include, exclude) else "out"), host


def gateway_decision(url: str, include=INCLUDE, exclude=EXCLUDE) -> tuple[str, str | None]:
    """As Gateway._request decides for an absolute-form http:// request (https:// arrives as
    CONNECT host:port, the same split_authority): (verdict, host)."""
    if not url.lower().startswith(("http://", "https://")):
        return "refused", None
    try:
        parts = urlsplit(url)
        if parts.username is not None or parts.password is not None:
            return "refused", None
        host, _port = gateway.split_authority(parts.netloc, 443 if url.lower().startswith("https") else 80)
    except (ValueError, gateway.Refused):
        return "refused", None
    return ("in" if scope.in_scope(host, include, exclude) else "out"), host


def recon_decision(url: str, include=INCLUDE, exclude=EXCLUDE) -> tuple[str, str | None]:
    host = urls.host_of(url)
    if not host:
        return "unreadable", None
    return ("in" if scope.in_scope(host, include, exclude) else "out"), host


def test_fuzz_the_gateway_the_inbox_and_recon_read_the_same_host():
    """For any URL string: whatever reads it as in scope reads the host a browser would
    contact, and the gateway and the inbox never put the same URL on different hosts."""
    r = rng("url-differential")
    for i in range(iterations(3000)):
        url = gen_url(r)
        want = browser_host(url)
        decisions = {"inbox": inbox_decision(url), "gateway": gateway_decision(url), "recon": recon_decision(url)}
        for who, (verdict, host) in decisions.items():
            if verdict == "in" and scope.normalize_host(host) != want:
                fail(f"{who} reads {host!r} in scope where a browser contacts {want!r}", i, url)
        (gv, gh), (iv, ih) = decisions["gateway"], decisions["inbox"]
        if gv == "in" and iv in ("in", "out") and ih != scope.normalize_host(gh):
            fail(f"the gateway reads {gh!r}, the inbox {ih!r}", i, url)


def test_fuzz_host_and_pattern_normalisation_is_idempotent_and_case_blind():
    r = rng("normalise")
    pieces = HOSTS + ["*." + h for h in HOSTS[:12]] + ["*", "*.", "a.*.b", "\u0130.example.com", "\u017f.example.com"]
    for i in range(iterations(3000)):
        h = r.choice(pieces) + r.choice(["", "", ".", "..", " ", "\n", "\n.", "\t.", "\r\n"])
        if r.random() < 0.3:
            h = "".join(c.upper() if r.random() < 0.5 else c for c in h)
        for norm in (scope.normalize_host, scope.normalize_pattern):
            try:
                once = norm(h)
            except scope.ScopeError:
                continue
            if norm(once) != once or once != once.strip() or not once.isascii() or once != once.lower():
                fail(f"{norm.__name__} is not idempotent: {once!r}", i, h)
        try:
            n = scope.normalize_host(h)
        except scope.ScopeError:
            continue
        for variant in (n.upper(), n + ".", " " + n):
            if scope.in_scope(variant, INCLUDE, EXCLUDE) != scope.in_scope(n, INCLUDE, EXCLUDE):
                fail(f"in_scope differs for {variant!r} and {n!r}", i, h)


def test_fuzz_a_scope_rule_matches_what_it_says():
    """An exclude rule, however it was written (case, trailing dots, spaces, line ends),
    excludes the host it names; it never silently matches nothing."""
    r = rng("scope-rules")
    for i in range(iterations(2000)):
        host = r.choice(["static.shop.example.com", "a.static.shop.example.com", "admin.shop.example.com"])
        rule = "*." + host.split(".", 1)[1] if r.random() < 0.3 else host       # a rule that covers the host
        written = r.choice(["", " ", "\t"]) + rule + r.choice(["", ".", "\n.", ". ", "\n", "\r\n.", "\t."])
        written = "".join(c.upper() if r.random() < 0.3 else c for c in written)
        try:
            pattern = scope.normalize_pattern(written)
        except scope.ScopeError:
            continue
        if scope.in_scope(host, ["*.shop.example.com"], [pattern]):
            fail(f"the exclude rule {pattern!r} (written {written!r}) does not exclude {host}", i, written)


# ---- the inbox: end to end -------------------------------------------------------------------

def gen_har(r: random.Random, n: int) -> bytes:
    entries = []
    for k in range(n):
        url = gen_url(r) if r.random() < 0.7 else r.choice([
            "https://shop.example.com/", "https://AKIA" + "ABCDEFGHIJKLMNOP.shop.example.com/x",
            "https://xox" + "b-1234567890-abc.shop.example.com/", "https://user:pw@shop.example.com/?token=t1",
            "https://eyJabcdefghij.eyJabcdefghij.sig.shop.example.com/", "https://a@b.shop.example.com/"])
        req = {"method": r.choice(["GET", "POST", "get", "PUT"]), "url": url, "httpVersion": "HTTP/1.1",
               "headers": [{"name": "Cookie", "value": f"sid=zq{k}secret"}]}
        resp = {"status": r.choice([200, 403, 0, 500]), "statusText": "", "headers": [],
                "content": {"text": r.choice(["", "<html><title>x</title></html>", "{\"token\":\"zqbody\"}"])}}
        entries.append({"request": req, "response": resp, "comment": r.choice(["", "x", None])})
    return json.dumps({"log": {"version": "1.2", "creator": {"name": "fuzz"}, "entries": entries}}).encode()


def test_fuzz_every_accepted_row_is_in_scope_and_keeps_its_host(client):
    _, e, _ = team(client, receipt_info=False)
    r = rng("inbox")
    include, exclude = ["shop.example.com", "*.shop.example.com"], ["static.shop.example.com"]
    for i in range(iterations(12)):
        data = gen_har(r, 25)
        if r.random() < 0.3:
            data = mutate_export(r, "har", data)
        res = upload(client, e, data, "har", name=f"f{i}.har", reimport=True)
        assert res.status_code in (201, 422), (i, res.status_code, res.text[:300])
        if res.status_code != 201:
            continue
        for row in res.json()["refused"]:
            if row["reason"] == "out_of_scope":
                assert not scope.in_scope(row["host"], include, exclude), row
    s = db(client)
    entries = s.scalars(select(InboxEntry).where(InboxEntry.engagement_id == e)).all()
    assert entries
    for x in entries:
        assert scope.in_scope(x.host, include, exclude), x.url
        stored = urlsplit(x.url)                      # raises if redaction broke the URL
        assert scope.normalize_host(stored.hostname or "") == x.host, (x.url, x.host)
        got = client.get(f"/engagements/{e}/inbox/{x.id}")
        assert got.status_code == 200, (x.url, got.text[:300])


# ---- redaction --------------------------------------------------------------------------------

SECRET_HEADERS = ["X-Api-Key", "x-auth-token", "X-CSRF-Token", "api_key", "Ocp-Apim-Subscription-Key",
                  "X-Functions-Key", "X-Amz-Security-Token", "X-Session-Id", "Private-Key"]
SECRET_PARAMS = ["token", "access_token", "password", "api_key", "apiKey", "sig", "code", "client_secret",
                 "refresh-token", "sessionid", "X-Amz-Signature", "passwd", "otp"]
JSON_KEYS = [k for k in SECRET_PARAMS if k != "code"] + ["accessToken", "jwt", "auth"]


def secret(r: random.Random) -> str:
    alphabet = string.ascii_letters + string.digits + "-_.~+/"
    return "zq" + "".join(r.choice(alphabet) for _ in range(r.randint(10, 40))) + r.choice(["", "=", "=="])


def jwt(r: random.Random) -> str:
    part = lambda n: base64.urlsafe_b64encode(bytes(r.randrange(256) for _ in range(n))).decode().rstrip("=")
    return "eyJ" + part(18) + "." + "eyJ" + part(24) + "." + part(32)


def esc_key(r: random.Random, k: str) -> str:
    """A JSON key as some serializers write it: plain, or with characters as \\u escapes."""
    if r.random() < 0.7:
        return k
    return "".join(f"\\u{ord(c):04x}" if r.random() < 0.4 else c for c in k)


def placements(r: random.Random, s: str) -> tuple[list[str], list[str], str, str, str | None]:
    """(request headers, response headers, query, body) with the secret in one place."""
    where = r.randrange(12)
    req_h, resp_h, query, body = ["Host: shop.example.com", "Accept: */*"], ["Content-Type: text/plain"], "q=1", ""
    hname = lambda n: "".join(c.upper() if r.random() < 0.3 else c for c in n)
    if where == 0:
        req_h.append(f"{hname(r.choice(['Authorization', 'Proxy-Authorization']))}: "
                     f"{r.choice(['Bearer ', 'Basic ', 'Token ', 'AWS4-HMAC-SHA256 Credential=', ''])}{s}")
    elif where == 1:
        req_h.append(f"{hname('Cookie')}: {r.choice(['', 'lang=en; ', 'a=b;'])}{r.choice(['sid', 'x', 'a_b'])}={s}"
                     f"{r.choice(['', '; theme=dark', ';'])}")
    elif where == 2:
        resp_h.append(f"{hname('Set-Cookie')}: {r.choice(['sid', 'refresh'])}={s}; Path=/; "
                      f"Expires=Wed, 21 Oct 2026 07:28:00 GMT; HttpOnly")
    elif where == 3:
        req_h.append(f"{hname(r.choice(SECRET_HEADERS))}: {s}")
    elif where == 4:
        query = f"q=1&{r.choice(SECRET_PARAMS)}={s}&page=2"
    elif where == 5:
        body = f"user=tess&{r.choice(SECRET_PARAMS)}={s}"
    elif where == 6:
        key = esc_key(r, r.choice(JSON_KEYS))
        val = json.dumps(s) if r.random() < 0.8 else f"[{json.dumps(s)}, \"other\"]"
        body = r.choice(['{"%s": %s}', '{"data": {"user": "t", "%s" : %s}}', '[{"%s":%s}]']) % (key, val)
    elif where == 7:
        body = f"see {jwt(r)} here"
        s = body.split()[1]
    elif where == 8:
        b = "----x" + str(r.randrange(10**6))
        body = (f"--{b}\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\ntess\r\n"
                f"--{b}\r\nContent-Disposition: form-data; name=\"{r.choice(SECRET_PARAMS)}\"\r\n\r\n{s}\r\n--{b}--\r\n")
        req_h.append(f"Content-Type: multipart/form-data; boundary={b}")
    elif where == 9:
        name = r.choice(["Authorization", "Cookie", "X-Api-Key", "Set-Cookie"])
        body = json.dumps({"headers": [{"name": name, "value": {"Authorization": "Bearer ", "X-Api-Key": ""}.get(
            name, "sid=") + s}]})
    elif where == 10:
        req_h.append(f"Authorization: Bearer {s}")
        query = f"{r.choice(SECRET_PARAMS)}={s}"
    else:
        num = str(r.randrange(10**5, 10**9))
        body = '{"%s": %s}' % (r.choice(["otp", "pin_code", "password"]), num)
        s = num if '"pin_code"' not in body else None
    return req_h, resp_h, query, body, s


def test_fuzz_redaction_leaves_no_placed_secret_and_is_idempotent():
    r = rng("redact")
    for i in range(iterations(1500)):
        s = secret(r)
        req_h, resp_h, query, body, s = placements(r, s)
        nl = r.choice(["\r\n", "\n"])
        req = (f"POST /p?{query} HTTP/1.1{nl}" + nl.join(req_h) + nl + nl + body).encode()
        resp = (f"HTTP/1.1 200 OK{nl}" + nl.join(resp_h) + nl + nl + (body if r.random() < 0.3 else "ok")).encode()
        for raw in (req, resp):
            rep = redact.Report()
            try:
                with time_limit(2, "redaction"):
                    out = redact.http_message(raw, rep, personal=True)
                    again = redact.http_message(out, redact.Report(), personal=True)
            except Exception as e:  # noqa: BLE001
                fail("redact.http_message raised", i, raw, e)
            if s and s.encode() in out:
                fail(f"the secret {s!r} survived redaction: {out!r}", i, raw)
            if again != out:
                fail(f"redaction is not idempotent: {out!r} -> {again!r}", i, raw)
        text = req.decode()
        once = redact.text(text, redact.Report())
        if redact.text(once, redact.Report()) != once:
            fail("redact.text is not idempotent", i, text)


def test_fuzz_redaction_never_crashes_on_mutated_messages():
    r = rng("redact-mutate")
    base = [b"POST /a?token=t1&x=1 HTTP/1.1\r\nHost: shop.example.com\r\nCookie: a=1; b=2\r\nContent-Length: 13\r\n"
            b"Authorization: Bearer abcdefghijklmnop1\r\n\r\npassword=abc1",
            b"HTTP/1.1 200 OK\r\nSet-Cookie: s=1; Path=/\r\nContent-Length: 20\r\n\r\n{\"token\": \"abcdef12\"}",
            b"HTTP/2 200\r\n:status: 200\r\ncontent-length: 5\r\n\r\n\x00\x01\x02\x03\x04"]
    for i in range(iterations(1500)):
        raw = mutate_bytes(r, r.choice(base), r.randint(1, 6))
        try:
            with time_limit(2, "redaction"):
                out = redact.http_message(raw, redact.Report(), personal=True)
                assert redact.http_message(out, redact.Report(), personal=True) == out
        except Exception as e:  # noqa: BLE001
            fail("redact.http_message", i, raw, e)


# ---- text parsers: pumped inputs, binary input ------------------------------------------------

TOKENS = ["'", '"', "`", "/", "\\", " ", "\t", "\n", "\r\n", "<", ">", "<!--", "-->", "<script>", "<script",
          "</script>", "<title>", "<style>", "{", "}", "[", "]", "(", ")", ":", ";", ",", "=", "&", "?", "#", "@",
          ".", "a", "0", "1", "eyJ", "eyJabcdefgh.", "-----BEGIN PRIVATE KEY-----", "Bearer ", "bearer x",
          "path:'a',", "component:X,", "children:[", "query Q{", "gql`", "a@b", "%", "\\u0041", "Cookie: ",
          "Authorization: Bearer x", "Authorization: Basic ", "token=", '"token":', '"token":"',
          '"name":"Authorization","value":"', "a=", "\"a\":", "-", "_", "4111", "user:pw@", "://", "http://",
          "<a href=", "<!", "<![CDATA[", "&#", "Content-Disposition: form-data; name=\"password\"\r\n\r\n",
          "Content-Length: 9", "xox" + "b-", "AK" + "IA", "Index of /", "Disallow: /", "Contact: ",
          "//# sourceMappingURL=", "postgres://a:b", "mongodb+srv://u:", "{path:'a',component:X,children:[",
          "{path:'a',children:[]}", "https://", "-----BEGIN RSA PRIVATE KEY-----\n", "SG.", "sk_live_", "<title",
          "<h1>Index of ", "Set-Cookie: a=b, ", "\\n", "\\\""]
SUFFIXES = ["", "y", "'", '"', ">", "\n", "=", "@", "-"]


def pumped(unit: str, size: int) -> str:
    unit, _, suffix = unit.partition("\0")
    return unit * max(1, size // len(unit)) + suffix


def units(r: random.Random) -> list[str]:
    """Every token alone and followed by "y" (a run of spaces is linear until something follows
    it), then random pairs and triples of them, with a random suffix. "\\0" separates the suffix."""
    return TOKENS + [t + "\0y" for t in TOKENS] + [
        "".join(r.choice(TOKENS) for _ in range(r.randint(2, 3))) + "\0" + r.choice(SUFFIXES)
        for _ in range(iterations(20))]


def _js_url():
    return "https://shop.example.com/static/main.js"


PARSERS = {
    "redact.text": lambda s: redact.text(s, redact.Report(), personal=True),
    "redact.http_message": lambda s: redact.http_message(("GET / HTTP/1.1\r\n" + s).encode("utf-8", "surrogatepass"),
                                                         redact.Report(), personal=True),
    "redact.header Authorization": lambda s: redact.header_value("Authorization", "Bearer x" + s, redact.Report()),
    "redact.header Cookie": lambda s: redact.header_value("Cookie", s, redact.Report()),
    "redact.header Set-Cookie": lambda s: redact.header_value("Set-Cookie", s, redact.Report()),
    "jsanalysis.extract_endpoints": lambda s: jsanalysis.extract_endpoints(s, _js_url()),
    "jsanalysis.scan_secrets": jsanalysis.scan_secrets,
    "jsanalysis.spa_routes": jsanalysis.spa_routes,
    "jsanalysis.graphql_operations": jsanalysis.graphql_operations,
    "jsanalysis.sourcemap_ref": lambda s: jsanalysis.sourcemap_ref(s, _js_url()),
    "pagetext.view html": lambda s: pagetext.view("<html><head><style>x</style></head>" + s, "https://shop.example.com/"),
    "pagetext.view js": lambda s: pagetext.view(s, _js_url(), "application/javascript"),
    "pagetext.strip_html": pagetext.strip_html,
    "pagetext.directory_listing": lambda s: pagetext.directory_listing("<title>Index of /</title>" + s,
                                                                       "https://shop.example.com/ftp/"),
    "pagetext.robots": pagetext.robots,
    "pagetext.security_txt": pagetext.security_txt,
    "pagetext.title_of": pagetext.title_of,
    "surface.score": lambda s: surface.score("https://shop.example.com/" + s[:8000]),
    "urls.clean": lambda s: urls.clean(s.split("\n")[:2000], INCLUDE, EXCLUDE),
    "scopeimport.parse": lambda s: _scope_csv(s),
}


def _scope_csv(s: str):
    try:
        return scopeimport.parse("identifier,asset_type,eligible_for_submission\n" + s)
    except ValueError:
        return None


@pytest.mark.parametrize("name", sorted(PARSERS))
def test_fuzz_parsers_are_linear_on_pumped_input(name):
    """One short unit repeated, at SIZE / 4 and at SIZE characters: four times the input may
    take about four times as long (allowed: eight, plus 50 ms of noise), not sixteen. A
    catastrophic backtrack fails the time limit instead of hanging the run."""
    f, r = PARSERS[name], rng(f"pump-{name}")
    for i, unit in enumerate(units(r)):
        times = []
        for size in (SIZE // 4, SIZE):
            s = pumped(unit, size)
            try:
                with time_limit(10 * BUDGET, name):
                    times.append(elapsed(f, s)[1])
            except Exception as e:  # noqa: BLE001
                fail(f"{name} on {unit!r} repeated to {size} characters", i, unit, e)
        if times[1] > 8 * times[0] + 0.05 or times[1] > BUDGET:
            fail(f"{name} is not linear on {unit!r} repeated: {times[0]:.3f} s for {SIZE // 4} characters, "
                 f"{times[1]:.3f} s for {SIZE}", i, unit)


@pytest.mark.parametrize("name", sorted(PARSERS))
def test_fuzz_parsers_take_binary_and_odd_text(name):
    f, r = PARSERS[name], rng(f"binary-{name}")
    for i in range(iterations(25)):
        raw = bytes(r.randrange(256) for _ in range(r.choice([1, 100, 5000])))
        s = raw.decode(r.choice(["latin-1", "utf-8"]), "replace" if r.random() < 0.5 else "surrogateescape")
        if r.random() < 0.3:
            s = "\ud800" + s + "\udfff\x00"
        try:
            with time_limit(BUDGET, name):
                f(s)
        except Exception as e:  # noqa: BLE001
            fail(f"{name} on binary input", i, s[:200], e)


def test_fuzz_scope_csv_never_crashes():
    r = rng("scope-csv")
    for i in range(iterations(1500)):
        rows = ["identifier,asset_type,eligible_for_submission"]
        for _ in range(r.randint(1, 6)):
            ident = r.choice([gen_url(r), r.choice(HOSTS), "*." + r.choice(HOSTS), '"' + gen_url(r) + '"'])
            rows.append(f"{ident},{r.choice(['URL', 'WILDCARD', 'url', 'CIDR', ''])},{r.choice(['true', 'false', ''])}")
        text = "\n".join(rows)
        if r.random() < 0.4:
            text = mutate_bytes(r, text.encode()).decode("utf-8", "replace")
        try:
            with time_limit(2, "scope csv"):
                out = scopeimport.parse(text)
        except ValueError:
            continue
        except Exception as e:  # noqa: BLE001
            fail("scopeimport.parse raised", i, text, e)
        for p in out["include"] + out["exclude"]:
            assert scope.normalize_pattern(p) == p, (p, text)
