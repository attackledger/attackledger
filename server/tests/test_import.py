"""Evidence import (D-029): adapters, the pipeline and the inbox.

The adapters are tested on small hand-made exports (tests/data/import, example.com hosts
only), on malformed files and on hostile XML. The pipeline is tested end to end through the
API, and every file in the blob store and every inbox row is read back to check that no
secret and nothing from an out-of-scope row reached storage."""
import base64
import importlib.util
import json
import re
import socket
import time
from pathlib import Path

import pytest
from sqlalchemy import select

from app import auditlog, blobs, importers, inbox, ledger, redact
from app.importers import burp, caido, har
from app.models import Asset, AuditEntry, Evidence, ImportBatch, InboxEntry
from test_people import client, person, sign_in  # noqa: F401  (fixture and helpers)

DATA = Path(__file__).resolve().parent / "data" / "import"
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("verify_report", ROOT / "tools" / "verify_report.py")
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)

HAR = (DATA / "sample.har").read_bytes()
BURP = (DATA / "sample-burp.xml").read_bytes()
CAIDO = (DATA / "sample-caido.json").read_bytes()
JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsYWItdXNlciIsInJvbGUiOiJjdXN0b21lciJ9.c2lnbmF0dXJlLWZvci10aGUtbGFi"
# Every secret in the fixtures, as it appears there (Basic credentials stay base64).
SECRETS = ["lab-session-cookie-1", "lab-password-1", JWT, "lab-query-token-2", "lab-api-key-3",
           "lab-burp-cookie-5", "lab-burp-key-6", "bGFiOmxhYi1idXJwLXBhc3M=", "lab-caido-token-7",
           "bGFiOmxhYi1jYWlkby1wYXNz", "tess@example.com"]
OUT_OF_SCOPE = ["tracker.example.net", "lab-out-of-scope", "cdn.example.org", "lib.js"]


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Adapters only parse: any attempt to open a connection fails the test."""
    def refuse(*_a, **_k):
        raise AssertionError("an import adapter tried to open a network connection")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def refused(data: bytes, fmt: str | None = None) -> str:
    with pytest.raises(importers.ImportRefused) as e:
        importers.parse(data, fmt)
    return str(e.value)


# ---- adapters: field mappings --------------------------------------------------------------

def test_har_entries_are_rebuilt_from_its_fields():
    a, p = importers.parse(HAR)
    assert a.id == "har" and p.creator == "Hand-made fixture 1.0"
    assert [e.row for e in p.entries] == [1, 2, 3, 4, 6] and p.unreadable == [(5, "no readable URL")]
    login = p.entries[0]
    assert (login.method, login.url, login.status, login.label) == (
        "POST", "https://shop.example.com/rest/user/login", 200, "sign-in")
    assert login.time == "2026-10-09T10:00:00.000Z" and login.rebuilt
    assert login.request.startswith(b"POST /rest/user/login HTTP/1.1\r\nHost: shop.example.com\r\n")
    assert login.request.endswith(b'\r\n\r\n{"email":"tess@example.com","password":"lab-password-1"}')
    assert login.response.startswith(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: token=")
    users = p.entries[1]
    assert users.request.startswith(b"GET /api/Users/7?access_token=lab-query-token-2&fields=name HTTP/2\r\n"
                                    b":authority: shop.example.com\r\n")
    assert users.status == 403 and users.response.startswith(b"HTTP/2 403 Forbidden")
    robots = p.entries[3]
    assert robots.response.endswith(b"\r\n\r\nUser-agent: *\nDisallow: /ftp\n")      # base64 content decoded


def test_burp_items_keep_their_raw_bytes():
    a, p = importers.parse(BURP)
    assert a.id == "burp" and p.creator == "Burp Suite 2026.9"
    assert len(p.entries) == 3 and p.unreadable == [(4, "no readable HTTP method")]
    basket = p.entries[0]
    assert basket.url == "https://shop.example.com/api/Basket/3" and basket.status == 200
    assert basket.request == (b"GET /api/Basket/3 HTTP/1.1\r\nHost: shop.example.com\r\n"
                              b"Cookie: token=lab-burp-cookie-5\r\nX-Api-Key: lab-burp-key-6\r\n\r\n")
    assert basket.response.endswith(b'{"id":3,"owner":"lab-user"}')
    assert basket.label == "basket of another user" and basket.time == "Thu Oct 09 10:00:00 UTC 2026"
    assert not basket.rebuilt and basket.tool_id is None
    options = p.entries[2]                                   # base64="false", and no response
    assert options.method == "OPTIONS" and options.status is None and options.response is None
    # XML turns CR LF into LF even inside CDATA, which is why Burp offers base64.
    assert options.request.startswith(b"OPTIONS /admin?next=/home HTTP/1.1\nHost: shop.example.com:8080\n")
    assert options.url == "http://shop.example.com:8080/admin?next=/home"


def test_burp_url_is_built_from_parts_when_missing():
    xml = (b'<?xml version="1.0"?><items burpVersion="1"><item><url></url><host>shop.example.com</host>'
           b'<port>443</port><protocol>https</protocol><method>GET</method><path>/a?b=1</path>'
           b'<request base64="false">GET /a?b=1 HTTP/1.1</request><status>204</status>'
           b'<response base64="true"></response></item></items>')
    e = importers.parse(xml)[1].entries[0]
    assert e.url == "https://shop.example.com/a?b=1" and e.status == 204 and e.response is None


def test_caido_rows_with_and_without_raw_bytes():
    a, p = importers.parse(CAIDO)
    assert a.id == "caido" and p.creator == "Caido"
    assert len(p.entries) == 3 and p.unreadable == [(4, "the port is not a port number")]
    search = p.entries[0]
    assert search.url == "https://shop.example.com/rest/products/search?q=apple&session_token=lab-caido-token-7"
    assert (search.tool_id, search.time, search.status) == ("101", "2026-10-09T10:00:00.000+00:00", 200)
    assert search.request.startswith(b"GET /rest/products/search?q=apple") and b"Apple Juice" in search.response
    bare = p.entries[1]                                      # accepted with what it has
    assert (bare.request, bare.response, bare.status) == (None, None, 500)
    assert p.entries[2].status is None and p.entries[2].response is None   # no response object
    wrapped = json.dumps({"requests": json.loads(CAIDO)}).encode()
    assert len(importers.parse(wrapped, "caido")[1].entries) == 3
    port = json.dumps([{"host": "shop.example.com", "port": 8443, "is_tls": True, "method": "GET",
                        "path": "x", "query": "?a=1"}]).encode()
    assert importers.parse(port)[1].entries[0].url == "https://shop.example.com:8443/x?a=1"


def test_detection_chooses_one_adapter_or_refuses():
    assert [importers.choose(d).id for d in (HAR, BURP, CAIDO)] == ["har", "burp", "caido"]
    assert "not in a format AttackLedger can import" in refused(b'{"hello": "world"}')
    assert "not in a format" in refused(b"GET / HTTP/1.1\r\n\r\n")
    assert "the file is empty" in refused(b"  \n")
    assert "unknown import format 'zap'" in refused(HAR, "zap")
    assert "not a readable Burp Suite XML export" in refused(HAR, "burp")
    assert "not a Caido HTTP history export" in refused(b'{"log": {}}', "caido")
    assert "no log with entries" in refused(json.dumps([{"is_tls": True}]).encode(), "har")


def test_the_registry_is_checked_and_closed(monkeypatch):
    assert set(importers.registry()) == {"har", "burp", "caido"}
    broken = importers.Adapter(id="Bad Id", title="x", summary="", extensions=(".x",), detect=bool, parse=bool)
    monkeypatch.setattr(har, "ADAPTER", broken)
    monkeypatch.setattr(importers, "_REGISTRY", None)
    with pytest.raises(RuntimeError, match="does not meet the adapter contract"):
        importers.registry()
    monkeypatch.setattr(har, "ADAPTER", burp.ADAPTER)
    monkeypatch.setattr(importers, "_REGISTRY", None)
    with pytest.raises(RuntimeError, match="two import adapters use the id burp"):
        importers.registry()


def test_adapters_import_nothing_that_reaches_the_network():
    banned = re.compile(r"^\s*(?:import|from)\s+(?:socket|urllib\.request|http\.client|httpx|requests|ftplib)\b", re.M)
    for mod in (importers, har, burp, caido):
        src = Path(mod.__file__).read_text()
        assert not banned.search(src) and "open(" not in src, mod.__name__


# ---- malformed and hostile files -------------------------------------------------------

@pytest.mark.parametrize("data,fmt,expect", [
    (b'{"log": {"version": "1.2", "entries": [', "har", "not valid JSON"),
    (b'{"log": {"version": "2.0", "entries": []}}', "har", "HAR version 2.0 is not supported"),
    (b'{"log": {"version": "1.2", "entries": []}}', "har", "the file has no entries"),
    (b'{"log": {"version": "1.2", "entries": {}}}', "har", "no log with entries"),
    (b"\xff\xfe\x00{", "har", "not valid JSON"),
    (b'{"log": {"version": "1.2", "entries": [{"request": {"url": "x", "method": "GET"}, "status": ' + b"9" * 5000
     + b"}]}}", "har", "not valid JSON"),                    # an integer too long to convert
    (b"[" * 200_000 + b"]" * 200_000, "caido", "not valid JSON"),   # nesting deeper than the JSON parser goes
    (b'{"requests": 5}', "caido", "no list of requests"),
    (b"<items><item><url>https://shop.example.com/</url>", "burp", "not well formed"),
    (b"<html><body>hello</body></html>", "burp", "does not start with <items>"),
    (b"<items>" + b"<a>" * 5_000 + b"</a>" * 5_000 + b"</items>", "burp", "nested more than 32 levels"),
])
def test_malformed_files_are_refused_with_a_reason(data, fmt, expect):
    assert expect in refused(data, fmt)


def test_bad_rows_are_listed_and_the_rest_imported():
    doc = {"log": {"version": "1.2", "entries": [
        "not an object",
        {"request": {"url": "ftp://shop.example.com/x", "method": "GET"}},
        {"request": {"url": "https://shop.example.com/x", "method": "GE T"}},
        {"request": {"url": "https://shop.example.com/x", "method": "GET", "headers": "Cookie: x"}},
        {"request": {"url": "https://shop.example.com/x", "method": "GET"}, "response": {"status": 999}},
        {"request": {"url": "https://shop.example.com/x", "method": "GET"},
         "response": {"status": 200, "content": {"encoding": "base64", "text": "@@@"}}},
        {"request": {"url": "https://shop.example.com/ok", "method": "get"}, "response": {"status": "200"}},
    ]}}
    p = importers.parse(json.dumps(doc).encode())[1]
    assert [r for r, _ in p.unreadable] == [1, 2, 3, 4, 5, 6]
    assert dict(p.unreadable)[2] == "the URL is not an http or https URL with a host"
    assert dict(p.unreadable)[5] == "the status 999 is not an HTTP status"
    assert dict(p.unreadable)[6] == "the response is not valid base64"
    assert [(e.row, e.method, e.status) for e in p.entries] == [(7, "GET", 200)]


XXE = [
    # A classic external entity reading a local file.
    b'<?xml version="1.0"?><!DOCTYPE items [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    b"<items><item><url>https://shop.example.com/&xxe;</url><method>GET</method></item></items>",
    # The same over the network.
    b'<?xml version="1.0"?><!DOCTYPE items [<!ENTITY xxe SYSTEM "http://127.0.0.1:9/x">]>'
    b"<items><item><comment>&xxe;</comment></item></items>",
    # A parameter entity pulling in an external DTD.
    b'<?xml version="1.0"?><!DOCTYPE items [<!ENTITY % ext SYSTEM "http://127.0.0.1:9/evil.dtd"> %ext;]><items/>',
    # Billion laughs: entity expansion.
    b'<?xml version="1.0"?><!DOCTYPE items [<!ENTITY a "aaaaaaaaaa">'
    + b"".join(b'<!ENTITY %s "%s">' % (chr(98 + i).encode(), (b"&" + chr(97 + i).encode() + b";") * 10)
               for i in range(9))
    + b"]><items><item><comment>&j;</comment></item></items>",
    # An internal entity, harmless on its own: refused too, a Burp export has none.
    b'<?xml version="1.0"?><!DOCTYPE items [<!ENTITY x "y">]><items><item><comment>&x;</comment></item></items>',
]


@pytest.mark.parametrize("xml", XXE)
def test_xml_entities_and_external_references_are_refused(xml):
    started = time.monotonic()
    assert "entities or external references" in refused(xml, "burp")
    assert time.monotonic() - started < 2                     # nothing was expanded


def test_an_external_dtd_is_never_fetched():
    # No entity declared, so the file parses; the DTD is not loaded (the network guard is on).
    xml = (b'<?xml version="1.0"?><!DOCTYPE items SYSTEM "http://127.0.0.1:9/items.dtd">'
           b"<items><item><url>https://shop.example.com/</url><method>GET</method></item></items>")
    assert [e.url for e in importers.parse(xml, "burp")[1].entries] == ["https://shop.example.com/"]


# ---- size limits -----------------------------------------------------------------------

def test_file_and_entry_limits(monkeypatch):
    monkeypatch.setattr(importers, "MAX_FILE_BYTES", len(HAR) - 1)
    assert "larger than" in refused(HAR)
    monkeypatch.setattr(importers, "MAX_FILE_BYTES", 50_000_000)
    for mod in (har, burp, caido):
        monkeypatch.setattr(mod, "MAX_ENTRIES", 2)
    assert "the limit is 2 per file" in refused(HAR)
    assert "the limit is 2 per file" in refused(BURP)
    assert "the limit is 2 per file" in refused(CAIDO)


def test_large_parts_are_cut_and_say_so(monkeypatch):
    monkeypatch.setattr(importers, "MAX_PART_BYTES", 40)
    p = importers.parse(BURP)[1]
    assert p.entries[0].truncated == ("request", "response") and len(p.entries[0].request) == 40
    huge = base64.b64encode(b"A" * 3_000_000).decode()      # decoding stops at the limit
    started = time.monotonic()
    out = importers.b64(huge, "response", cut := [])
    assert len(out) == 40 and cut == ["response"] and time.monotonic() - started < 1
    big = json.dumps([{"host": "shop.example.com", "is_tls": True, "method": "GET", "path": "/",
                       "raw": huge, "response": {"status_code": 200, "raw": huge}}]).encode()
    e = importers.parse(big)[1].entries[0]
    assert e.truncated == ("request", "response") and len(e.response) == 40


# ---- the API: import, scope, redaction, dedupe -------------------------------------------

def team(c, pack="web-pentest-wstg"):
    """People mode: an owner, a tester, a viewer and an outsider; an engagement scoped to
    shop.example.com with an open lane per WSTG category used here."""
    person(c, "owner@lab.test", "Olive Owner", owner=True)
    sign_in(c, "owner@lab.test")
    ids = {n: person(c, f"{n}@lab.test", n.title()) for n in ("tess", "vic", "out")}
    e = c.post("/engagements", json={"name": "Import", "pack_id": pack}).json()["id"]
    assert c.put(f"/engagements/{e}/scope", json={"include": ["shop.example.com", "*.shop.example.com"],
                                                  "exclude": ["static.shop.example.com"]}).status_code == 200
    c.put(f"/engagements/{e}/members", json={"members": [{"user_id": ids["tess"], "roles": ["tester"]},
                                                         {"user_id": ids["vic"], "roles": ["viewer"]}]})
    # Setting the scope added shop.example.com as a host.
    a = db(c).scalar(select(Asset.id).where(Asset.engagement_id == e, Asset.host == "shop.example.com"))
    if pack == "web-pentest-wstg":          # the other lanes open on a receipted information lane
        info = c.post("/lanes", json={"asset_id": a, "role": "info"}).json()
        for it in info["items"]:
            c.patch(f"/lanes/{info['id']}/items/{it['idx']}", json={"state": "na", "na_reason": "lab"})
        assert c.post(f"/lanes/{info['id']}/close", json={"reviewed": True}).status_code == 200
    return ids, e, a


def upload(c, e, data, fmt=None, name="export.har"):
    params = {"filename": name} | ({"format": fmt} if fmt else {})
    return c.post(f"/engagements/{e}/imports", params=params, content=data,
                  headers={"content-type": "application/octet-stream"})


def db(c):
    from app import db as dbmod
    from app.main import app
    return next(app.dependency_overrides[dbmod.get_session]())


def stored_bytes(c) -> bytes:
    """Everything the import could have written: every blob, every inbox and batch row."""
    out = b"".join(p.read_bytes() for p in blobs.root().rglob("*") if p.is_file())
    s = db(c)
    for model in (InboxEntry, ImportBatch, Evidence):
        for row in s.scalars(select(model)):
            out += json.dumps({k: str(v) for k, v in vars(row).items() if not k.startswith("_")}).encode()
    return out


def test_import_refuses_out_of_scope_rows_and_stores_none_of_them(client):
    _, e, _ = team(client)
    sign_in(client, "tess@lab.test")
    r = upload(client, e, HAR)
    assert r.status_code == 201, r.text
    b = r.json()
    assert (b["format"], b["rows"], b["accepted"], b["out_of_scope"], b["duplicates"], b["unreadable"]) == \
        ("har", 6, 3, 1, 1, 1)
    assert {(x["row"], x["host"], x["reason"]) for x in b["refused"]} == {
        (3, "tracker.example.net", "out_of_scope"), (6, "shop.example.com", "duplicate"), (5, None, "unreadable")}
    caido_b = upload(client, e, CAIDO, name="history.json").json()
    assert (caido_b["accepted"], caido_b["out_of_scope"], caido_b["unreadable"]) == (2, 1, 1)
    burp_b = upload(client, e, BURP, name="items.xml").json()
    assert (burp_b["accepted"], burp_b["out_of_scope"], burp_b["unreadable"]) == (2, 1, 1)
    everything = stored_bytes(client)
    # Only the batch's list of refused rows names an out-of-scope host; no URL, byte or path.
    for s in ("lab-out-of-scope", "/collect", "/pixel", "lib.js", "lab-burp-out-of-scope"):
        assert s.encode() not in everything
    inbox_rows = db(client).scalars(select(InboxEntry)).all()
    assert len(inbox_rows) == 7 and {x.host for x in inbox_rows} == {"shop.example.com"}
    excluded = json.dumps([{"host": "static.shop.example.com", "is_tls": True, "method": "GET", "path": "/a.js"}])
    assert upload(client, e, excluded.encode(), name="x.json").json()["out_of_scope"] == 1   # exclusions win


def test_an_engagement_without_scope_imports_nothing(client):
    person(client, "owner@lab.test", "Olive Owner", owner=True)
    sign_in(client, "owner@lab.test")
    e = client.post("/engagements", json={"name": "No scope"}).json()["id"]
    r = upload(client, e, HAR)
    assert r.status_code == 422 and "no scope rules yet" in r.json()["detail"]
    assert db(client).scalars(select(ImportBatch)).all() == []


def test_secrets_are_redacted_in_everything_stored(client):
    _, e, _ = team(client)
    for data in (HAR, BURP, CAIDO):
        assert upload(client, e, data).status_code == 201
    everything = stored_bytes(client)
    for s in SECRETS:
        assert s.encode() not in everything, s
    assert redact.marker("lab-session-cookie-1").encode() in everything
    entries = client.get(f"/engagements/{e}/inbox").json()["entries"]
    login = next(x for x in entries if x["url"].endswith("/rest/user/login"))
    assert set(login["redaction"]["kinds"]) >= {"Cookie", "Set-Cookie", "password", "email address"}
    users = next(x for x in entries if "/api/Users/7" in x["url"])
    assert users["url"] == f"https://shop.example.com/api/Users/7?access_token={redact.marker('lab-query-token-2')}" \
                           "&fields=name"
    req = client.get(f"/engagements/{e}/inbox/{users['id']}/raw/request").text
    assert f"Authorization: Bearer {redact.marker(JWT)}" in req and f"X-Api-Key: {redact.marker('lab-api-key-3')}" in req
    record = json.loads(client.get(f"/engagements/{e}/inbox/{users['id']}/raw/record").text)
    assert record["format"] == inbox.RECORD_FORMAT and record["request_sha256"] == users["request_sha256"]
    assert record["notes"] == ["raw bytes rebuilt from the export's fields"]


def test_with_redaction_off_the_bytes_are_kept_and_say_so(client):
    _, e, _ = team(client)
    client.patch(f"/engagements/{e}", json={"redact_evidence": False})
    upload(client, e, BURP)
    assert b"lab-burp-cookie-5" in stored_bytes(client)
    entry = client.get(f"/engagements/{e}/inbox").json()["entries"][0]
    assert entry["redaction"]["not_redacted"] == [redact.NOT_REDACTED_OFF]


def test_dedupe_by_content_across_files(client):
    _, e, _ = team(client)
    upload(client, e, HAR)
    again = upload(client, e, HAR).json()
    assert (again["accepted"], again["duplicates"]) == (0, 4)
    # The same exchange from another tool's file is the same content.
    p = importers.parse(HAR)[1].entries[3]                    # robots.txt
    xml = (b'<?xml version="1.0"?><items burpVersion="1"><item><url>https://shop.example.com/robots.txt</url>'
           b"<method>GET</method><request base64=\"true\">" + base64.b64encode(p.request) + b"</request>"
           b"<status>200</status><response base64=\"true\">" + base64.b64encode(p.response)
           + b"</response></item></items>")
    assert upload(client, e, xml).json()["duplicates"] == 1
    # Rows without raw bytes are told apart by the tool's id.
    rows = [{"id": str(i), "host": "shop.example.com", "is_tls": True, "method": "GET", "path": "/same"} for i in (1, 2, 2)]
    b = upload(client, e, json.dumps(rows).encode()).json()
    assert (b["accepted"], b["duplicates"]) == (2, 1)


def test_upload_size_limit_at_the_api(client, monkeypatch):
    _, e, _ = team(client)
    monkeypatch.setattr(importers, "MAX_FILE_BYTES", 1000)
    r = upload(client, e, HAR)
    assert r.status_code == 413 and "larger than" in r.json()["detail"]


# ---- the inbox: mapping, dismissal, roles, audit -------------------------------------------

def lane(c, a, role):
    r = c.post("/lanes", json={"asset_id": a, "role": role})
    assert r.status_code == 201, r.text
    return r.json()


def by_url(c, e, end):
    return next(x for x in c.get(f"/engagements/{e}/inbox").json()["entries"] if x["url"].endswith(end))


def test_nothing_reaches_the_ledger_until_a_person_maps_it(client, tmp_path):
    ids, e, a = team(client)
    athn, sess = lane(client, a, "athn"), lane(client, a, "sess")
    sign_in(client, "tess@lab.test")
    upload(client, e, HAR)
    s = db(client)
    assert s.scalars(select(Evidence)).all() == []
    login = by_url(client, e, "/rest/user/login")
    r = client.post(f"/engagements/{e}/inbox/map", json={
        "entry_ids": [login["id"]], "note": "lockout tested with password=lab-note-secret",
        "targets": [{"lane_id": athn["id"], "item_idx": 3}, {"lane_id": sess["id"], "item_idx": 2}]})
    assert r.status_code == 200, r.text
    assert len(r.json()["evidence_added"]) == 2 and r.json()["entries"][0]["state"] == "mapped"
    evs = db(client).scalars(select(Evidence).order_by(Evidence.seq)).all()
    assert [(ev.lane_id, ev.kind, ev.sha256, ev.created_by) for ev in evs] == [
        (athn["id"], "response", login["record_sha256"], ids["tess"]),
        (sess["id"], "response", login["record_sha256"], ids["tess"])]
    assert evs[0].summary.startswith("Imported from HAR 1.2, row 1: POST https://shop.example.com/rest/user/login "
                                     "-> 200 (sign-in). lockout tested with password=[redacted:sha256:")
    assert "lab-note-secret" not in evs[0].summary and "values redacted" in evs[0].summary
    if hasattr(Evidence, "source"):                          # the column comes with chain record v2
        assert {ev.source for ev in evs} == {"import:har"}
    # Mapping again adds nothing; the chain still verifies, offline, from the report.
    again = client.post(f"/engagements/{e}/inbox/map", json={
        "entry_ids": [login["id"]], "targets": [{"lane_id": athn["id"], "item_idx": 3}]})
    assert again.json()["evidence_added"] == []
    view = client.get(f"/lanes/{athn['id']}").json()
    assert view["evidence"][0]["item_idx"] == 3
    assert json.loads(client.get(f"/blobs/{login['record_sha256']}").text)["url"] == login["url"]
    report = client.get(f"/engagements/{e}/report").json()
    assert verify.check_body(report) + verify.check_chain(report) == []
    path = tmp_path / "r.json"
    path.write_text(json.dumps(report))
    assert verify.main(["v", str(path)]) == 0
    roles = {athn["id"]: "athn", sess["id"]: "sess"}
    assert ledger.verify_chain([
        {**ledger.evidence_record(ev, "shop.example.com", roles[ev.lane_id]), "prev_hash": ev.prev_hash,
         "chain_hash": ev.chain_hash} for ev in evs]) == []


def test_mapping_refusals(client):
    _, e, a = team(client)
    athn = lane(client, a, "athn")
    other = client.post(f"/engagements/{e}/assets", json={"host": "api.shop.example.com"}).json()["id"]
    assert other
    elsewhere = lane(client, other, "info")
    upload(client, e, HAR)
    login = by_url(client, e, "/rest/user/login")

    def mapping(entries, targets):
        return client.post(f"/engagements/{e}/inbox/map", json={"entry_ids": entries, "targets": targets})
    r = mapping([login["id"]], [{"lane_id": elsewhere["id"], "item_idx": 1}])
    assert r.status_code == 422 and "map it to a lane on shop.example.com" in r.json()["detail"]
    assert mapping([login["id"]], [{"lane_id": athn["id"], "item_idx": 99}]).status_code == 422
    assert mapping([999], [{"lane_id": athn["id"], "item_idx": 1}]).status_code == 422
    assert mapping([login["id"]], []).status_code == 422
    e2 = client.post("/engagements", json={"name": "Other", "pack_id": "web-pentest-wstg"}).json()["id"]
    r = client.post(f"/engagements/{e2}/inbox/map", json={"entry_ids": [login["id"]],
                                                          "targets": [{"lane_id": athn["id"], "item_idx": 1}]})
    assert r.status_code == 422 and "in this engagement" in r.json()["detail"]
    assert db(client).scalars(select(Evidence)).all() == []      # a refused mapping writes nothing


def test_dismissal_is_recorded_not_deleted_and_audited(client):
    ids, e, a = team(client)
    athn = lane(client, a, "athn")
    sign_in(client, "tess@lab.test")
    upload(client, e, HAR)
    robots = by_url(client, e, "/robots.txt")
    r = client.post(f"/engagements/{e}/inbox/dismiss", json={"entry_ids": [robots["id"]],
                                                             "reason": "static file, nothing to test"})
    assert r.status_code == 200
    d = r.json()["entries"][0]
    assert d["state"] == "dismissed" and d["dismissed"]["by"] == ids["tess"]
    assert d["dismissed"]["reason"] == "static file, nothing to test"
    assert client.get(f"/engagements/{e}/inbox", params={"state": "dismissed"}).json()["total"] == 1
    r = client.post(f"/engagements/{e}/inbox/map", json={"entry_ids": [robots["id"]],
                                                         "targets": [{"lane_id": athn["id"], "item_idx": 1}]})
    assert r.status_code == 422 and "restore it" in r.json()["detail"]
    assert client.post(f"/engagements/{e}/inbox/dismiss", json={"entry_ids": [robots["id"]]}).status_code == 422
    assert client.post(f"/engagements/{e}/inbox/restore", json={"entry_ids": [robots["id"]]}).status_code == 200
    assert client.get(f"/engagements/{e}/inbox/{robots['id']}").json()["state"] == "new"
    s = db(client)
    actions = [x.action for x in s.scalars(select(AuditEntry).where(AuditEntry.engagement_id == e)
                                           .order_by(AuditEntry.seq))]
    assert actions[-3:] == ["import.batch", "import.dismissed", "import.restored"]
    assert auditlog.verify(s) == []
    texts = [x["text"] for x in client.get(f"/engagements/{e}/audit").json()["entries"]][-3:]
    assert texts[0] == ("Imported “export.har” (har, Hand-made fixture 1.0): 3 entries to the inbox, 1 refused as "
                        "out of scope, 1 duplicate, 1 unreadable; refused hosts tracker.example.net")
    assert texts[1] == f"Dismissed 1 inbox entry ({robots['id']}): static file, nothing to test"
    assert texts[2] == f"Restored 1 inbox entry ({robots['id']})"
    batch = s.scalars(select(AuditEntry).where(AuditEntry.action == "import.batch")).one()
    after = json.loads(batch.change)["after"]
    assert after["file_sha256"] == __import__("hashlib").sha256(HAR).hexdigest() and after["accepted"] == 3
    assert batch.actor_user_id == ids["tess"]


def test_viewers_read_testers_import_outsiders_see_nothing(client):
    _, e, a = team(client)
    athn = lane(client, a, "athn")
    upload(client, e, HAR)
    entry = by_url(client, e, "/rest/user/login")
    sign_in(client, "vic@lab.test")
    assert upload(client, e, BURP).status_code == 403
    assert client.post(f"/engagements/{e}/inbox/map", json={
        "entry_ids": [entry["id"]], "targets": [{"lane_id": athn["id"], "item_idx": 1}]}).status_code == 403
    assert client.post(f"/engagements/{e}/inbox/dismiss", json={"entry_ids": [entry["id"]]}).status_code == 403
    assert client.post(f"/engagements/{e}/inbox/restore", json={"entry_ids": [entry["id"]]}).status_code == 403
    assert client.get(f"/engagements/{e}/inbox").status_code == 200
    assert client.get(f"/engagements/{e}/imports").json()[0]["accepted"] == 3
    assert client.get(f"/engagements/{e}/inbox/{entry['id']}/raw/response").status_code == 200
    assert len(db(client).scalars(select(ImportBatch)).all()) == 1      # the refused upload left nothing
    sign_in(client, "out@lab.test")
    for path in (f"/engagements/{e}/inbox", f"/engagements/{e}/imports", f"/engagements/{e}/inbox/{entry['id']}"):
        assert client.get(path).status_code == 404
    assert upload(client, e, HAR).status_code == 404


def test_inbox_filters(client):
    _, e, _ = team(client)
    upload(client, e, HAR)
    upload(client, e, CAIDO)

    def total(**params):
        return client.get(f"/engagements/{e}/inbox", params=params).json()["total"]
    assert total() == 5 and total(state="new") == 5 and total(method="post") == 1
    assert total(status="4xx") == 1 and total(status="500") == 1 and total(status="none") == 0
    assert total(q="robots") == 1 and total(host="shop.example.com") == 5
    first = client.get(f"/engagements/{e}/imports").json()[-1]["id"]
    assert total(batch=first) == 3
    assert client.get(f"/engagements/{e}/inbox", params={"status": "abc"}).status_code == 422
    assert client.get(f"/engagements/{e}/inbox", params={"state": "gone"}).status_code == 422
    page = client.get(f"/engagements/{e}/inbox", params={"limit": 2, "offset": 2}).json()
    assert len(page["entries"]) == 2 and page["counts"]["new"] == 5 and page["hosts"] == ["shop.example.com"]


def test_suggestions_come_with_reasons(client):
    _, e, a = team(client)
    for role in ("athn", "athz", "sess", "errh"):
        lane(client, a, role)
    upload(client, e, HAR)
    upload(client, e, CAIDO)

    def keys(end):
        entry = client.get(f"/engagements/{e}/inbox/{by_url(client, e, end)['id']}").json()
        assert entry["targets"] and all(s["why"] for s in entry["suggestions"])
        return [s["key"] for s in entry["suggestions"]], entry["suggestions"]
    login, sug = keys("/rest/user/login")
    assert "WSTG-ATHN-03" in login and "WSTG-SESS-02" in login
    assert any("rule “Sign-in pages”" in w for s in sug for w in s["why"])
    users, _ = keys("fields=name")
    assert "WSTG-ATHZ-04" in users                              # an id in the path, and status 403
    robots, _ = keys("/robots.txt")
    assert robots[0] == "WSTG-INFO-03"                          # metafiles
    version, _ = keys("/application-version")
    assert "WSTG-ERRH-01" in version
    assert client.get("/imports/formats").json()["suggestion_rules"][0]["id"] == "sign-in"
