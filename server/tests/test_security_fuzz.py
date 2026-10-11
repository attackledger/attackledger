"""Regression tests for what fuzzing found (docs/security-review/FUZZING.md, FZ-1 to FZ-15).

Each input is the fuzzer's failing case minimised by hand. The tests failed before the fix
named in FUZZING.md and pass after it; the property tests that found most of them are in
test_fuzz.py."""
import importlib.util
import json
import time
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from sqlalchemy import select

from app import gateway, importers, jsanalysis, pagetext, redact, scope, scopeimport, urls
from app.models import Engagement, InboxEntry
from fuzzing import time_limit
from test_import import db, team, upload
from test_people import client  # noqa: F401  (fixture)


def har(*entries) -> bytes:
    return json.dumps({"log": {"version": "1.2", "creator": {"name": "fz"}, "entries": list(entries)}}).encode()


def har_entry(url="https://shop.example.com/", status=200, **request) -> dict:
    return {"request": {"method": "GET", "url": url, "headers": [], **request},
            "response": {"status": status, "headers": [], "content": {"text": "ok"}}}


def fast(f, *a, seconds=1.0):
    start = time.perf_counter()
    with time_limit(10 * seconds, getattr(f, "__name__", "call")):
        out = f(*a)
    took = time.perf_counter() - start
    assert took < seconds, f"took {took:.2f} s"
    return out


# ---- FZ-1: a status that is not a whole number --------------------------------------------------

@pytest.mark.parametrize("status", ["1e400", "-1e400", "200.5", "NaN", "true"])
def test_fz1_a_status_that_is_not_a_whole_number_is_one_unreadable_row(status):
    data = (b'{"log":{"version":"1.2","entries":[{"request":{"method":"GET","url":"https://shop.example.com/a"},'
            b'"response":{"status":' + status.encode() + b'}},{"request":{"method":"GET","url":'
            b'"https://shop.example.com/b"},"response":{"status":200}}]}}')
    _, p = importers.parse(data, "har")
    assert [e.url for e in p.entries] == ["https://shop.example.com/b"]
    assert [n for n, _ in p.unreadable] == [1]
    caido = json.loads('[{"host":"shop.example.com","is_tls":true,"method":"GET","path":"/",'
                       '"response":{"status_code":' + status + '}}]')
    _, p = importers.parse(json.dumps(caido).encode(), "caido")
    assert p.unreadable and not p.entries


def test_fz1_a_whole_float_status_is_still_read():
    _, p = importers.parse(har(har_entry(status=403.0)), "har")
    assert p.entries[0].status == 403


# ---- FZ-2: a Content-Length too long to be a number ------------------------------------------

def test_fz2_a_content_length_of_thousands_of_digits_does_not_stop_redaction():
    raw = b"POST / HTTP/1.1\r\nContent-Length: " + b"9" * 5000 + b"\r\n\r\npassword=lab-fz2"
    out = redact.http_message(raw, redact.Report())
    assert b"lab-fz2" not in out and b"9" * 5000 in out          # redacted; the odd length is left as written
    ok = redact.http_message(b"POST / HTTP/1.1\r\nContent-Length: 16\r\n\r\npassword=lab-fz2", redact.Report())
    assert b"Content-Length: 39\r\n" in ok                       # a length that matched is still rewritten


# ---- FZ-3: a backslash in the authority ----------------------------------------------------------

@pytest.mark.parametrize("url", ["https://evil.example.net\\@shop.example.com/", "http://user@evil.example.net\\@shop.example.com#f",
                                 "https://evil.example.net\\.shop.example.com/"])
def test_fz3_a_url_a_browser_sends_elsewhere_is_never_read_as_in_scope(url):
    assert urlsplit(url).hostname.endswith("shop.example.com")     # what Python reads
    with pytest.raises(importers.RowError, match="backslash"):
        importers.http_url(url)
    assert urls.host_of(url) is None
    with pytest.raises(gateway.Refused):                            # the gateway already refused it
        gateway.split_authority(urlsplit(url).netloc, 443)


def test_fz3_the_import_lists_the_row_as_unreadable(client):
    _, e, _ = team(client, receipt_info=False)
    res = upload(client, e, har(har_entry("https://evil.example.net\\@shop.example.com/"), har_entry()), "har")
    assert res.status_code == 201
    batch = res.json()
    assert batch["accepted"] == 1 and batch["refused"][0]["reason"] == "unreadable"
    assert "backslash" in batch["refused"][0]["detail"]


# ---- FZ-4: a host or rule written with a line end before its last dot ---------------------------

@pytest.mark.parametrize("written", ["static.shop.example.com\n.", "STATIC.shop.example.com\r\n.", "static.shop.example.com\t.",
                                     " static.shop.example.com. \n"])
def test_fz4_an_exclude_rule_with_a_line_end_still_excludes(written):
    p = scope.normalize_pattern(written)
    assert p == "static.shop.example.com" and scope.normalize_pattern(p) == p
    assert not scope.in_scope("static.shop.example.com", ["*.shop.example.com"], [p])


def test_fz4_host_names_never_keep_a_line_end():
    assert scope.normalize_host("x.shop.example.com\n.") == "x.shop.example.com"
    assert scope.normalize_pattern("*.SHOP.Example.COM\t.") == "*.shop.example.com"
    for bad in ("x.shop.example.com\nevil", "x.shop.example.com\n\nx", "a b.example.com"):
        with pytest.raises(scope.ScopeError):
            scope.normalize_host(bad)


def test_fz4_the_scope_api_stores_the_rule_that_excludes(client):
    _, e, _ = team(client, receipt_info=False)
    r = client.put(f"/engagements/{e}/scope", json={"include": ["*.shop.example.com"],
                                                    "exclude": ["static.shop.example.com\n."]})
    assert r.status_code == 200
    eng = db(client).get(Engagement, e)
    assert eng.scope_exclude == ["static.shop.example.com"]
    assert not scope.in_scope("static.shop.example.com", eng.scope_include, eng.scope_exclude)
    csv = scopeimport.parse('identifier,asset_type,eligible_for_submission\n*.shop.example.com,WILDCARD,true\n'
                            '"static.shop.example.com\n.",URL,false\n')
    assert csv["exclude"] == ["static.shop.example.com"]


# ---- FZ-5: a lone surrogate in a JSON string --------------------------------------------------

def test_fz5_a_lone_surrogate_in_json_is_a_422_not_a_500(client):
    _, e, a = team(client, receipt_info=False)
    lane = client.post("/lanes", json={"asset_id": a, "role": "info"}).json()
    body = '{"item_idx": %d, "kind": "note", "text": "token=\\ud800lab"}' % lane["items"][0]["idx"]
    r = client.post(f"/lanes/{lane['id']}/attach", content=body, headers={"content-type": "application/json"})
    # Since FZ-31 the NUL guard refuses a lone surrogate before FastAPI reads the body; still a 422.
    assert r.status_code == 422 and r.content.isascii() and "lone surrogate" in r.text


def test_fz5_fastapis_own_422_is_ascii_whatever_it_echoes():
    """The handler that FZ-5 added, still in place behind the NUL guard (FZ-31)."""
    import asyncio
    from fastapi.exceptions import RequestValidationError
    from app.main import _invalid_request
    exc = RequestValidationError([{"type": "missing", "loc": ("body", "sha256"), "msg": "Field required",
                                   "input": {"text": "token=\ud800lab"}}])
    r = asyncio.run(_invalid_request(None, exc))
    assert r.status_code == 422 and r.body.isascii() and b"\\ud800" in r.body


def test_fz5_redaction_takes_a_lone_surrogate():
    for value in ("\ud800lab", "a\udfffb"):
        assert redact.MARKER_RE.fullmatch(redact.header_value("X-Api-Key", value, redact.Report()))
        assert value not in redact.text(f"token={value}", redact.Report())
    assert redact.marker("\udcff") == redact.marker("\udcff")       # bytes that were not UTF-8: as before


# ---- FZ-6: spaces inside an Authorization value ----------------------------------------------

def test_fz6_spaces_inside_an_authorization_value_are_linear():
    value = "Bearer x" + " " * 200_000 + "y"
    out = fast(redact.header_value, "Authorization", value, redact.Report())
    assert out.startswith("Bearer [redacted:sha256:") and "y" not in out
    body = ("Authorization: Bearer x" + " " * 200_000 + "y\n").encode()
    fast(redact.data, body, redact.Report())
    assert redact.header_value("Authorization", "Bearer abc  ", redact.Report()).endswith("]  ")
    assert redact.header_value("Proxy-Authorization", " Basic  dXNlcg==", redact.Report()).startswith(" Basic  [")


# ---- FZ-7: the stored URL keeps its host -------------------------------------------------------

@pytest.mark.parametrize("url", [
    "https://AKIA" + "ABCDEFGHIJKLMNOP.shop.example.com/x",            # a label shaped like an AWS key id
    "https://xox" + "b-1234567890-abc.shop.example.com/",              # like a Slack token
    "https://eyJabcdefghij.eyJabcdefghij.sig.shop.example.com/",       # like a JWT
    "https://user:" + "lab-fz7@shop.example.com/?token=lab-q",        # a password: its marker had brackets
])
def test_fz7_a_redacted_url_still_names_its_host(url):
    out = redact.url(url, redact.Report())
    assert urlsplit(out).hostname == urlsplit(url).hostname
    assert "lab-fz7" not in out and "lab-q" not in out
    assert redact.url(out, redact.Report()) == out


def test_fz7_imported_rows_with_such_urls_can_be_opened(client):
    _, e, _ = team(client, receipt_info=False)
    urls_in = ["https://AKIA" + "ABCDEFGHIJKLMNOP.shop.example.com/x", "https://user:" + "lab-fz7@shop.example.com/"]
    assert upload(client, e, har(*[har_entry(u) for u in urls_in]), "har").json()["accepted"] == 2
    for x in db(client).scalars(select(InboxEntry).where(InboxEntry.engagement_id == e)):
        assert urlsplit(x.url).hostname == x.host and "lab-fz7" not in x.url
        assert client.get(f"/engagements/{e}/inbox/{x.id}").status_code == 200


# ---- FZ-8: a line in a message head that only contains a colon ---------------------------------

def test_fz8_a_head_line_that_is_not_a_header_is_redacted_as_text():
    raw = b"GET / HTTP/1.1\r\nHost: shop.example.com\npassword=lab-fz8a:lab-fz8b\r\n\r\n"
    out = redact.http_message(raw, redact.Report())
    assert b"lab-fz8" not in out
    assert redact.http_message(out, redact.Report()) == out           # idempotent: a marker has colons
    assert redact.http_message(b"GET / HTTP/1.1\r\nX-Api-Key: lab-k\r\n\r\n", redact.Report()).count(b"[redacted") == 1


# ---- FZ-9: cookies without a name ----------------------------------------------------------------

def test_fz9_a_cookie_without_a_name_is_redacted():
    for name, value in (("Cookie", "lab-fz9-nameless"), ("Cookie", "theme=dark; lab-fz9-nameless"),
                        ("Set-Cookie", "lab-fz9-nameless; Path=/; HttpOnly"), ("Cookie", "=lab-fz9-nameless")):
        out = redact.header_value(name, value, redact.Report())
        assert "lab-fz9" not in out and redact.header_value(name, out, redact.Report()) == out
    joined = redact.header_value("Set-Cookie", "a=1; Path=/, b=2; Max-Age=60", redact.Report())
    assert ", b=[redacted:" in joined and joined.count("[redacted") == 2


# ---- FZ-10: a JSON key written with escapes ----------------------------------------------------------

def test_fz10_an_escaped_json_key_is_read_as_its_reader_reads_it():
    for body in ('{"\\u0074oken": "lab-fz10"}', '{"pass\\u0077ord":"lab-fz10"}',
                 '{"headers":[{"name":"\\u0041uthorization","value":"Bearer lab-fz10"}]}'):
        out = redact.text(body, redact.Report())
        assert "lab-fz10" not in out and json.loads(out)


# ---- FZ-11, FZ-12, FZ-13: quadratic page and bundle parsing ------------------------------------------

@pytest.mark.parametrize("page", ["<!--" * 100_000, "<script" * 60_000, "<title>" * 30_000 + "x" * 100_000])
def test_fz11_unclosed_comments_scripts_and_titles_are_linear(page):
    fast(pagetext.strip_html, page)
    fast(pagetext.view, "<html><style>x</style>" + page, "https://shop.example.com/")
    fast(pagetext.title_of, page)


def test_fz11_comments_scripts_and_titles_are_read_as_before():
    page = ("<html><head><title> A &amp; B </title><style>p{}</style></head><body><!-- hidden --><p>one</p>"
            "<!--x--><script>var a='<p>';</script><a href='/x'>two</a><!-- unclosed <p>three</p>")
    text, links = pagetext.strip_html(page)
    assert "one" in text and "two" in text and "hidden" not in text and "var a" not in text
    assert links == ["/x"] and pagetext.title_of(page) == "A & B"
    assert pagetext._strip_comments("a<!--b-->c<!-->d-->e<!--f") == "a c e<!--f"
    assert pagetext._drop_blocks("a<script x>b</script >c<STYLE>d</style>e<svg>f") == "a c e<svg>f"


def test_fz12_a_long_run_of_digits_in_a_bundle_is_linear():
    found = fast(jsanalysis.scan_secrets, "0" * 400_000)
    assert found == []
    cid = "1234567890-" + "a" * 32 + ".apps.googleusercontent.com"
    assert [s["kind"] for s in jsanalysis.scan_secrets("x" + "9" * 50 + cid)] == ["Google OAuth client id"]


def test_fz13_unclosed_children_arrays_are_linear():
    bundle = "{path:'a',component:X,children:[" * 40_000
    fast(jsanalysis.spa_routes, bundle, seconds=3.0)
    fast(pagetext.view, bundle, "https://shop.example.com/main.js", "application/javascript", seconds=3.0)
    nested = "const r=[{path:'privacy-security',component:P,children:[{path:'privacy-policy',component:Q}," \
             "{path:'change-password',component:R}]},{path:'score-board',component:S}];"
    assert jsanalysis.spa_routes(nested) == ["/privacy-security", "/privacy-security/change-password",
                                             "/privacy-security/privacy-policy", "/score-board"]


# ---- FZ-14: a scope CSV with one bad row, or csv's own errors --------------------------------------

def test_fz14_one_invalid_url_is_one_invalid_row():
    out = scopeimport.parse("identifier,asset_type\nhttps://[shop/,URL\nshop.example.com,URL\n")
    assert out["include"] == ["shop.example.com"] and out["invalid"][0]["identifier"] == "https://[shop/"


def test_fz14_csv_errors_are_a_message_not_a_crash(client):
    assert scopeimport.parse("identifier,asset_type\rshop.example.com,URL\r")["include"] == ["shop.example.com"]
    with pytest.raises(ValueError, match="the CSV cannot be read"):
        scopeimport.parse('identifier\n"' + "a" * 200_000 + '"\n')
    _, e, _ = team(client, receipt_info=False)
    r = client.post(f"/engagements/{e}/scope/import", json={"csv": 'identifier\n"' + "a" * 200_000 + '"\n'})
    assert r.status_code == 422 and "cannot be read" in r.text


# ---- FZ-15: multipart form fields ------------------------------------------------------------------------

def test_fz15_a_secret_multipart_field_is_redacted_and_a_file_part_is_not_read():
    body = ("--b\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\ntess\r\n"
            "--b\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nlab-fz15\r\n"
            "--b\r\ncontent-disposition: form-data; filename=\"k.txt\"; name=\"key\"\r\nContent-Type: text/plain\r\n\r\n"
            "file text\r\n--b--\r\n")
    raw = ("POST /login HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=b\r\nContent-Length: "
           f"{len(body)}\r\n\r\n{body}").encode()
    out = redact.http_message(raw, redact.Report())
    assert b"lab-fz15" not in out and b"tess" in out and b"file text" in out
    assert redact.http_message(out, redact.Report()) == out
    head, _, stored = out.partition(b"\r\n\r\n")
    assert f"Content-Length: {len(stored)}".encode() in head


# ---- FZ-16 to FZ-19: the command-line verifier -----------------------------------------------------

FIXTURES = Path(__file__).resolve().parents[2] / "tools" / "verifier_equivalence" / "fixtures"


@pytest.mark.parametrize("name, code, says", [
    ("fuzz-key-missing.json", 2, "its content is not what an AttackLedger report holds"),
    ("fuzz-wrong-type.json", 2, "its content is not what an AttackLedger report holds"),
    ("fuzz-not-utf8.json", 2, "the file is not UTF-8 text"),
    ("fuzz-not-json.json", 2, "the file is not valid JSON"),
    ("fuzz-nested-too-deep.json", 2, "the file is not valid JSON"),
    ("fuzz-lone-surrogate.json", 2, "its content is not what an AttackLedger report holds"),
    ("fuzz-nested-500.json", 1, "Verification FAILED."),
    ("fuzz-item-without-text.json", 1, "Verification FAILED."),
])
def test_fz16_the_verifier_never_stops_with_a_traceback(name, code, says, capsys):
    spec = importlib.util.spec_from_file_location("verify_report_fz", FIXTURES.parents[1] / "verify_report.py")
    vr = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vr)
    assert vr.main(["verify_report.py", str(FIXTURES / name)]) == code
    out = capsys.readouterr().out
    assert says in out
    if code == 2:
        assert out == f"the report cannot be checked: {says}\n"


def test_fz18_a_lone_surrogate_is_printed_escaped():
    spec = importlib.util.spec_from_file_location("verify_report_fz", FIXTURES.parents[1] / "verify_report.py")
    vr = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vr)
    assert vr.shown("a\ud800b") == "a\\ud800b"
