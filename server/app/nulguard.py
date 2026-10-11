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

The import upload (POST /engagements/{id}/imports) is the export file itself, kept byte for
byte; the import adapters handle NUL in the fields they read (importers.text, http_url).
"""
import json
import re

REPLACEMENT = "�"
MACHINE = ("/worker/", "/gateway/")
RAW_BODY = re.compile(r"^/engagements/[^/]+/imports$")


def _has_nul(value) -> bool:
    if isinstance(value, str):
        return "\x00" in value
    if isinstance(value, dict):
        return any(_has_nul(k) or _has_nul(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_has_nul(v) for v in value)
    return False


def replace(value):
    """The same JSON value with every NUL in its strings (keys included) replaced."""
    if isinstance(value, str):
        return value.replace("\x00", REPLACEMENT)
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
    return False


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
        if b"\\u0000" in body:                         # how JSON writes a NUL; then look properly
            try:
                data = json.loads(body)
            except ValueError:
                data = None                             # not JSON: the route refuses it
            if data is not None and _has_nul(data):
                if not path.startswith(MACHINE):
                    return await _respond(send, 422, "text in the request contains a NUL character (U+0000), "
                                                     "which is not stored; remove it and send the request again")
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
