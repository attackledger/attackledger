#!/usr/bin/env python3
"""Make the demo's import files from the local lab: a browser HAR and a Burp Suite XML export.

The "Client web app" demo engagement tests app.client.test and api.client.test, which do not
exist. This script asks the lab (shop.lab.test, api.lab.test) for each page a tester would
visit, keeps the lab's real status, headers and body, and writes the exchanges as if they had
been captured on the engagement's hosts:

    http://shop.lab.test/...      ->  https://app.client.test/...
    http://api.lab.test/api/...   ->  https://api.client.test/api/...

The request headers are a browser's, with a made-up session cookie and bearer token, so the
import's redaction has something to remove. A few rows are for hosts outside the scope
(sso.client.test, telemetry.client.test); they get no lab answer and the import refuses them.

Run it on the demo stack's lab network only (nothing else is reachable from there):

    docker run --rm -i --network <project>_lab -v "$PWD/tools/demo/imports":/out \\
      attackledger-api:latest python - < tools/demo/make_imports.py

The output (tools/demo/imports/) is committed, so seeding the demo does not need this step.
"""
import base64
import http.client
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path("/out")
START = datetime(2026, 10, 8, 9, 12, 4, tzinfo=timezone.utc)   # a fixed day, so the files stay the same
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/141.0.0.0 Safari/537.36")
# Fictional values, there for the redaction to find. They open nothing anywhere.
COOKIE = "session=demo-3f9c1a7e5b2d48c6a0e1f7b9d3c5a8e2; theme=light"
BEARER = ("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZW1vLXRlc3RlciIsImF1ZCI6ImFwaS5jbGllbnQudGVzdCJ9"
          ".c2lnbmF0dXJlLW9mLWEtZGVtby10b2tlbg")
BASIC = "Basic " + base64.b64encode(b"admin:admin").decode()   # a default-credentials try

LAB = {"app.client.test": "shop.lab.test", "api.client.test": "api.lab.test"}


def fetch(host: str, path: str, headers: list[tuple[str, str]]):
    """One GET to the lab, as the engagement host's lab stand-in. Returns status, reason, headers, body."""
    c = http.client.HTTPConnection(LAB[host], 80, timeout=10)
    c.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
    c.putheader("Host", LAB[host])
    for k, v in headers:
        c.putheader(k, v)
    c.endheaders()
    r = c.getresponse()
    body = r.read().replace(b".lab.test", b".client.test")      # the lab's own names, as the client's
    c.close()
    headers = [(k, str(len(body)) if k.lower() == "content-length" else v) for k, v in r.getheaders()]
    return r.status, r.reason, headers, body


def browser_headers(host: str, accept: str, referer: str | None, api: bool) -> list[tuple[str, str]]:
    h = [("Host", host), ("User-Agent", UA), ("Accept", accept), ("Accept-Language", "en-GB,en;q=0.9"),
         ("Accept-Encoding", "identity")]
    if referer:
        h.append(("Referer", referer))
    h.append(("Authorization", BEARER) if api else ("Cookie", COOKIE))
    return h


HTML = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

# The tester's browser session: (host, path, accept, label). The script fetched twice within
# a second (a preload, then the script tag) and the site icon are there on purpose: a
# duplicate, and an entry to dismiss.
BROWSED = [
    ("app.client.test", "/", HTML, None),
    ("app.client.test", "/static/app.js", "*/*", None),
    ("app.client.test", "/static/app.js", "*/*", None),
    ("api.client.test", "/api/v1/items?page=1", "application/json", None),
    ("api.client.test", "/api/v1/cart", "application/json", None),
    ("app.client.test", "/favicon.ico", "image/avif,image/webp,image/png,*/*;q=0.8", None),
    ("telemetry.client.test", "/collect?v=2&page=%2F", "*/*", None),
    ("app.client.test", "/products?id=1", HTML, None),
    ("app.client.test", "/products?id=2", HTML, None),
    ("app.client.test", "/about", HTML, None),
    ("app.client.test", "/search.php?q=shoes", HTML, None),
    ("app.client.test", "/admin/", HTML, None),
    ("app.client.test", "/", HTML, None),
    ("app.client.test", "/account/logout", HTML, None),
]

# Items the tester saved from Burp (Proxy history and Repeater), with Burp's comments.
SAVED = [
    ("app.client.test", "/search.php?q=shoes&debug=1", "Hidden debug parameter changes the page", None),
    ("app.client.test", "/search.php?q=%3Cb%3Eshoes%3C%2Fb%3E", "Is q encoded in the page?", None),
    ("app.client.test", "/admin/", "Default credentials on the admin area", BASIC),
    ("app.client.test", "/robots.txt", None, None),
    ("app.client.test", "/backup/", "Listed in robots.txt", None),
    ("app.client.test", "/.git/config", None, None),
    ("sso.client.test", "/login?next=https%3A%2F%2Fapp.client.test%2F", None, None),
]


def har() -> dict:
    entries, t, page = [], START, "https://app.client.test/"
    for host, path, accept, label in BROWSED:
        api = host == "api.client.test"
        headers = browser_headers(host, accept, None if path == "/" else page, api)
        url = f"https://{host}{path}"
        if host in LAB:
            code, reason, rh, body = fetch(host, path, headers[1:])
        else:   # outside the scope: the import refuses the row, so its answer does not matter
            code, reason, rh, body = 204, "No Content", [("Content-Length", "0")], b""
        query = [{"name": k, "value": v} for k, _, v in (p.partition("=") for p in path.partition("?")[2].split("&") if p)]
        entries.append({
            "startedDateTime": t.isoformat().replace("+00:00", "Z"), "time": 38.4,
            "request": {"method": "GET", "url": url, "httpVersion": "HTTP/1.1",
                        "headers": [{"name": k, "value": v} for k, v in headers], "queryString": query,
                        "cookies": [], "headersSize": -1, "bodySize": 0},
            "response": {"status": code, "statusText": reason, "httpVersion": "HTTP/1.1",
                         "headers": [{"name": k, "value": v} for k, v in rh], "cookies": [],
                         "content": {"size": len(body), "mimeType": dict((k.lower(), v) for k, v in rh)
                                     .get("content-type", "text/plain"), "text": body.decode("utf-8", "replace")},
                         "redirectURL": "", "headersSize": -1, "bodySize": len(body)},
            "cache": {}, "timings": {"send": 0.2, "wait": 36.1, "receive": 2.1},
            **({"comment": label} if label else {})})
        same = len(entries) < len(BROWSED) and BROWSED[len(entries)][:2] == (host, path)
        t += timedelta(seconds=0.3 if same else 7)
    return {"log": {"version": "1.2", "creator": {"name": "WebInspector", "version": "537.36"}, "pages": [],
                    "entries": entries}}


def raw_request(host: str, path: str, auth: str | None) -> bytes:
    lines = [f"GET {path} HTTP/1.1", f"Host: {host}", f"User-Agent: {UA}", f"Accept: {HTML}",
             "Accept-Encoding: identity", f"Cookie: {COOKIE}"]
    if auth:
        lines.append(f"Authorization: {auth}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def burp() -> str:
    items, t = [], START + timedelta(minutes=41)
    for host, path, comment, auth in SAVED:
        if host in LAB:
            sent = [("User-Agent", UA), ("Accept", HTML), ("Accept-Encoding", "identity"), ("Cookie", COOKIE)]
            if auth:
                sent.append(("Authorization", auth))
            code, reason, rh, body = fetch(host, path, sent)
            rh = [(k, t.strftime("%a, %d %b %Y %H:%M:%S GMT") if k.lower() == "date" else v) for k, v in rh]
            resp =(f"HTTP/1.1 {code} {reason}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in rh) + "\r\n").encode() + body
        else:
            code, body = 302, b""
            resp = (b"HTTP/1.1 302 Found\r\nLocation: https://app.client.test/\r\nContent-Length: 0\r\n\r\n")
        req = raw_request(host, path, auth)
        when = t.strftime("%a %b %d %H:%M:%S UTC %Y")
        items.append(f"""  <item>
    <time>{when}</time>
    <url><![CDATA[https://{host}{path}]]></url>
    <host ip="">{host}</host>
    <port>443</port>
    <protocol>https</protocol>
    <method><![CDATA[GET]]></method>
    <path><![CDATA[{path}]]></path>
    <extension>null</extension>
    <request base64="true"><![CDATA[{base64.b64encode(req).decode()}]]></request>
    <status>{code}</status>
    <responselength>{len(resp)}</responselength>
    <mimetype>{"HTML" if b"<html" in body else "text"}</mimetype>
    <response base64="true"><![CDATA[{base64.b64encode(resp).decode()}]]></response>
    <comment>{comment or ""}</comment>
  </item>""")
        t += timedelta(minutes=2)
    return ('<?xml version="1.0"?>\n<!DOCTYPE items [\n<!ELEMENT items (item*)>\n<!ATTLIST items burpVersion CDATA "">\n'
            '<!ATTLIST items exportTime CDATA "">\n<!ELEMENT item (time, url, host, port, protocol, method, path, '
            'extension, request, status, responselength, mimetype, response, comment)>\n]>\n'
            f'<items burpVersion="2025.9.4" exportTime="{t.strftime("%a %b %d %H:%M:%S UTC %Y")}">\n'
            + "\n".join(items) + "\n</items>\n")


# The lab's Date header is the day this ran; set it to the capture's own time.
def _fix_dates(doc: dict) -> dict:
    for e in doc["log"]["entries"]:
        t = datetime.fromisoformat(e["startedDateTime"].replace("Z", "+00:00"))
        for h in e["response"]["headers"]:
            if h["name"].lower() == "date":
                h["value"] = t.strftime("%a, %d %b %Y %H:%M:%S GMT")
    return doc


OUT.mkdir(parents=True, exist_ok=True)
(OUT / "client-web-app.har").write_text(json.dumps(_fix_dates(har()), indent=1) + "\n")
(OUT / "client-web-app-burp.xml").write_text(burp())
print("wrote", *sorted(p.name for p in OUT.iterdir()))
