"""HAR 1.2 (HTTP Archive), as saved by browsers, Burp, ZAP and Caido.

Field mapping:
  url, method        request.url, request.method
  status             response.status (0 or absent: no response)
  request bytes      rebuilt: "<method> <path?query> <httpVersion>", request.headers,
                     then request.postData.text (or its params, joined as a form body)
  response bytes     rebuilt: "<httpVersion> <status> <statusText>", response.headers,
                     then response.content.text (base64-decoded when encoding is "base64")
  time               startedDateTime
  tool id            _id or _requestId when the writer adds one (browsers do not)
  label              comment
  creator            log.creator.name and version

HAR keeps no raw bytes, so the request and response are rebuilt from these fields and the
entry says so. Cookies and query strings are also listed in separate HAR fields; they are
not read, because the same values are in the headers and the URL.
"""
import json
import re

from . import (Adapter, Entry, ImportRefused, MAX_ENTRIES, Parsed, RowError, b64, cut, head, http_url, http_version,
               message, method, status, target, text)


_START = re.compile(r'^\{\s*"log"\s*:\s*\{')


def detect(data: bytes) -> bool:
    return bool(_START.match(head(data, 4096)))


def _headers(value) -> list[tuple[str, str]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise RowError("headers are not a list")
    out = []
    for h in value[:500]:
        if not isinstance(h, dict) or not isinstance(h.get("name"), str) or not isinstance(h.get("value", ""), str):
            raise RowError("a header is not a name and a value")
        out.append((h["name"], h.get("value", "")))
    return out


def _body_text(value: str, part: str, truncated: list[str]) -> bytes:
    return cut(value.encode("utf-8", "surrogateescape"), part, truncated)


def _entry(row: int, e) -> Entry:
    if not isinstance(e, dict):
        raise RowError("the entry is not an object")
    req, resp = e.get("request"), e.get("response")
    if not isinstance(req, dict):
        raise RowError("the entry has no request")
    url, verb = http_url(req.get("url")), method(req.get("method"))
    truncated: list[str] = []

    body = b""
    post = req.get("postData")
    if isinstance(post, dict):
        if isinstance(post.get("text"), str):
            body = _body_text(post["text"], "request", truncated)
        elif isinstance(post.get("params"), list):
            pairs = [f"{p.get('name', '')}={p.get('value', '')}" for p in post["params"][:1000] if isinstance(p, dict)]
            body = _body_text("&".join(pairs), "request", truncated)
    request = message(f"{verb} {target(url)} {http_version(req.get('httpVersion'))}", _headers(req.get("headers")), body)

    code, response = None, None
    if isinstance(resp, dict):
        code = status(resp.get("status"))
    if code is not None:
        content = resp.get("content") if isinstance(resp.get("content"), dict) else {}
        raw = content.get("text")
        rbody = b""
        if isinstance(raw, str):
            if str(content.get("encoding", "")).lower() == "base64":
                rbody = b64(raw, "response", truncated)
            else:
                rbody = _body_text(raw, "response", truncated)
        reason = resp.get("statusText") if isinstance(resp.get("statusText"), str) else ""
        response = message(f"{http_version(resp.get('httpVersion'))} {code} {reason}".rstrip(),
                           _headers(resp.get("headers")), rbody)

    return Entry(row=row, url=url, method=verb, status=code, request=request, response=response,
                 tool_id=text(e.get("_id", e.get("_requestId")), 100), time=text(e.get("startedDateTime"), 64),
                 label=text(e.get("comment"), 300), rebuilt=True, truncated=tuple(truncated))


def parse(data: bytes) -> Parsed:
    try:
        doc = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ImportRefused("this is not a readable HAR file: it is not valid JSON") from None
    log = doc.get("log") if isinstance(doc, dict) else None
    if not isinstance(log, dict) or not isinstance(log.get("entries"), list):
        raise ImportRefused("this is not a HAR file: it has no log with entries")
    version = str(log.get("version", ""))
    if version not in ("1.1", "1.2"):
        raise ImportRefused(f"HAR version {version or 'missing'} is not supported (1.2 and 1.1 are)")
    entries = log["entries"]
    if len(entries) > MAX_ENTRIES:
        raise ImportRefused(f"the file has {len(entries)} entries; the limit is {MAX_ENTRIES} per file")
    creator = log.get("creator") if isinstance(log.get("creator"), dict) else {}
    name = " ".join(str(creator.get(k, "")).strip() for k in ("name", "version")).strip()
    out = Parsed(creator=name[:200] or None)
    for n, e in enumerate(entries, start=1):
        try:
            out.entries.append(_entry(n, e))
        except RowError as err:
            out.unreadable.append((n, str(err)))
    return out


ADAPTER = Adapter(id="har", title="HAR 1.2", extensions=(".har", ".json"), detect=detect, parse=parse,
                  summary="HTTP Archive from a browser's developer tools, Burp, ZAP or Caido.")
