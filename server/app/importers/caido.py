"""Caido HTTP history, exported as JSON (Exports page, or the export task of Caido's API).

The layout follows the sample in Caido's documentation ("Exporting Request Data"), not an
export from a running Caido; docs/IMPORT.md lists what to check against one. Field mapping:
  url              "https" if is_tls else "http", "://", host, ":" port when it is not the
                   default for the scheme, path, then "?" query when query is not empty
  method           method
  status           response.status_code (no response object: no response)
  request bytes    raw, base64-decoded
  response bytes   response.raw, base64-decoded
  time             created_at: epoch milliseconds (an ISO 8601 string is kept as it is)
  tool id          id
  label            source (intercept, replay, automate, ...), with "edited" when edited is true
                   and the alteration when it is not "none"

Raw bytes are present only when the export included them. A row without them is still
imported with its URL, method and status, and says that the raw bytes were not exported.
The file is a JSON array of rows, or an object holding that array under "requests".
"""
import json
from datetime import datetime, timezone

from . import har
from . import (MAX_ENTRIES, Adapter, Entry, ImportRefused, Parsed, RowError, b64, head, http_url, method, status,
               text)


def detect(data: bytes) -> bool:
    start = head(data)
    return start[:1] in ("[", "{") and '"is_tls"' in start and not har.detect(data)


def _time(value) -> str | None:
    if isinstance(value, bool):
        raise RowError("created_at is not a time")
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value / 1000, timezone.utc).isoformat(timespec="milliseconds")
        except (OverflowError, OSError, ValueError):
            raise RowError("created_at is not a time") from None
    return text(value, 64)


def _url(r: dict) -> str:
    host = r.get("host")
    if not isinstance(host, str) or not host.strip():
        raise RowError("the row has no host")
    tls = r.get("is_tls")
    if not isinstance(tls, bool):
        raise RowError("is_tls is not true or false")
    scheme, port = ("https" if tls else "http"), r.get("port")
    if port is not None and (isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536):
        raise RowError("the port is not a port number")
    shown = "" if port in (None, 443 if tls else 80) else f":{port}"
    path = r.get("path") if isinstance(r.get("path"), str) and r.get("path") else "/"
    query = r.get("query") if isinstance(r.get("query"), str) else ""
    if not path.startswith("/"):
        path = "/" + path
    return http_url(f"{scheme}://{host.strip()}{shown}{path}{'?' + query.lstrip('?') if query else ''}")


def _entry(row: int, r) -> Entry:
    if not isinstance(r, dict):
        raise RowError("the row is not an object")
    truncated: list[str] = []
    url, verb = _url(r), method(r.get("method"))
    request = b64(r["raw"], "request", truncated) if r.get("raw") else None
    resp = r.get("response")
    if resp is not None and not isinstance(resp, dict):
        raise RowError("the response is not an object")
    code = status(resp.get("status_code")) if resp else None
    response = b64(resp["raw"], "response", truncated) if resp and resp.get("raw") else None
    label = [text(r.get("source"), 40)] if isinstance(r.get("source"), str) else []
    if r.get("edited") is True:
        label.append("edited")
    if isinstance(r.get("alteration"), str) and r["alteration"] not in ("", "none"):
        label.append(f"alteration {r['alteration'][:40]}")
    return Entry(row=row, url=url, method=verb, status=code, request=request, response=response,
                 tool_id=text(r.get("id"), 100), time=_time(r.get("created_at")),
                 label=", ".join(x for x in label if x) or None, truncated=tuple(truncated))


def parse(data: bytes) -> Parsed:
    try:
        doc = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ImportRefused("this is not a readable Caido export: it is not valid JSON") from None
    rows = doc.get("requests") if isinstance(doc, dict) else doc
    if not isinstance(rows, list):
        raise ImportRefused("this is not a Caido HTTP history export: it has no list of requests")
    if len(rows) > MAX_ENTRIES:
        raise ImportRefused(f"the file has {len(rows)} rows; the limit is {MAX_ENTRIES} per file")
    out = Parsed(creator="Caido")
    for n, r in enumerate(rows, start=1):
        try:
            out.entries.append(_entry(n, r))
        except RowError as err:
            out.unreadable.append((n, str(err)))
    return out


ADAPTER = Adapter(id="caido", title="Caido JSON", extensions=(".json",), detect=detect, parse=parse,
                  summary="HTTP history exported from Caido as JSON, with raw requests and responses when "
                          "the export includes them.")
