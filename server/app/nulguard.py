"""NUL characters in requests, decided before any route sees them.

Postgres cannot store U+0000 in a text column; SQLite can. Without this, a NUL in a JSON
string, a query parameter or a path made the same request succeed on SQLite and fail with a
500 on Postgres, after part of the work was done. Worse, on the machine channels a NUL that
came from the target (a URL an agent was steered to, a tool's output line) made the API refuse
the whole batch: the gateway keeps an unwritten log batch and sends it again, so one such row
stopped its request log for good and, once the backlog was full, all traffic (the gateway
fails closed). Now, on every database:

  - a NUL in the path or the query string is refused (400);
  - in a JSON body from a person or the operator, it is refused (422): nothing is stored in
    part, and no hashed record ever holds a character the database would change;
  - in a JSON body on the worker's and the gateway's channels (/worker/, /gateway/), which
    carry what targets and tools produced and must be kept, each NUL becomes U+FFFD, the
    replacement character, before the route reads the body (so before anything is hashed).

A lone surrogate (U+D800 to U+DFFF on its own) is handled the same way: JSON can spell one
("\ud800") and Python's reader accepts it, as it does the bytes ED A0 80, but UTF-8, and so
every database driver, cannot hold one, and the commit raised: a 500 on every route that
stores text (fuzzing, FZ-31). A body without a Content-Type is checked too: FastAPI reads it
as JSON (FZ-32).

The import upload (POST /engagements/{id}/imports) is the export file itself, kept byte for
byte; the import adapters handle NUL in the fields they read (importers.text, http_url).
"""
import json
import re

REPLACEMENT = "�"
MACHINE = ("/worker/", "/gateway/")
RAW_BODY = re.compile(r"^/engagements/[^/]+/imports$")


_UNSTORABLE = re.compile("[\x00\ud800-\udfff]")
_SURROGATE = re.compile("[\ud800-\udfff]")
# How JSON spells a NUL or a surrogate (a valid pair too: it is only parsed to be sure), and
# UTF-8's bytes for a surrogate, which Python's JSON reader takes from bytes (surrogatepass).
_SPELLED = re.compile(rb"\\u(?:0000|[dD][89a-fA-F][0-9a-fA-F]{2})|\xed[\xa0-\xbf]")


def _find(value, rx) -> bool:
    if isinstance(value, str):
        return rx.search(value) is not None
    if isinstance(value, dict):
        return any(_find(k, rx) or _find(v, rx) for k, v in value.items())
    if isinstance(value, list):
        return any(_find(v, rx) for v in value)
    return False


def _has_nul(value) -> bool:
    return _find(value, re.compile("\x00"))


def replace(value):
    """The same JSON value with every NUL and lone surrogate in its strings (keys included) replaced."""
    if isinstance(value, str):
        return _UNSTORABLE.sub(REPLACEMENT, value)
    if isinstance(value, dict):
        return {replace(k): replace(v) for k, v in value.items()}
    if isinstance(value, list):
        return [replace(v) for v in value]
    return value


async def _respond(send, status: int, detail: str) -> None:
    body = json.dumps({"detail": detail}).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


def _is_json(scope) -> bool:
    for name, value in scope.get("headers") or []:
        if name == b"content-type":
            kind = value.split(b";")[0].strip().lower()
            return kind == b"application/json" or kind.endswith(b"+json")
    return True             # no Content-Type: FastAPI reads the body as JSON (FZ-32)


class NulGuard:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path") or ""
        query = scope.get("query_string") or b""
        if "\x00" in path or b"\x00" in query or b"%00" in query.lower():
            return await _respond(send, 400, "the URL contains a NUL character")
        if not _is_json(scope) or RAW_BODY.match(path):
            return await self.app(scope, receive, send)

        chunks, more = [], True
        while more:
            message = await receive()
            if message["type"] != "http.request":       # the client went away
                return await self.app(scope, _replay([message], receive), send)
            chunks.append(message.get("body", b""))
            more = message.get("more_body", False)
        body = b"".join(chunks)
        if _SPELLED.search(body):                      # a NUL or a surrogate may be in it; then look properly
            try:
                data = json.loads(body)
            except (ValueError, RecursionError):
                data = None                             # not JSON: the route refuses it
            if data is not None and _find(data, _UNSTORABLE):
                if not path.startswith(MACHINE):
                    if _has_nul(data):
                        return await _respond(send, 422, "text in the request contains a NUL character (U+0000), "
                                                         "which is not stored; remove it and send the request again")
                    return await _respond(send, 422, "text in the request contains a lone surrogate (U+D800 to "
                                                     "U+DFFF), which is not text and is not stored; remove it and "
                                                     "send the request again")
                # ASCII, with escapes: a lone surrogate ("\udc80", which JSON can spell) cannot be
                # encoded as UTF-8, and the whole request was a 500 (fuzzing, FZ-28). Read back,
                # the escapes are the same text; the route deals with the surrogate.
                body = json.dumps(replace(data)).encode()
                scope = {**scope, "headers": [(n, str(len(body)).encode() if n == b"content-length" else v)
                                              for n, v in scope["headers"]]}
        return await self.app(scope, _replay([{"type": "http.request", "body": body, "more_body": False}], receive),
                              send)


def _replay(messages, receive):
    pending = list(messages)

    async def again():
        if pending:
            return pending.pop(0)
        return await receive()
    return again
