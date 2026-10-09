#!/usr/bin/env python3
"""Pull HTTP history out of your own Caido and write it as a Caido JSON export.

    export CAIDO_TOKEN=...            # or put it in a file and pass --token-file
    python3 tools/caido_pull.py --filter 'req.host.eq:"shop.example.com"' --out shop.json
    python3 tools/caido_pull.py --filter 'req.host.eq:"shop.example.com"' --since 2026-10-01 \\
        --redact-locally --out shop.json --upload https://attackledger.example.com --engagement 12

Runs on the tester's own machine, with the standard library only, so it needs nothing
installed. It reads the history through Caido's GraphQL API (the `requests` query, paged,
with an HTTPQL filter) and writes a JSON array in the layout AttackLedger's Caido adapter
reads (server/app/importers/caido.py). With --upload it then sends that file to the
engagement's import endpoint, signed in as you.

Where each secret goes:

  Caido token        read from an environment variable or a file you name, never from the
                     command line (shell history keeps it). It is sent only to the Caido
                     address you give, in the Authorization header, and never to
                     AttackLedger. It is never printed, logged or written to the file.
  AttackLedger sign-in   the operator token (environment variable or file) or your email,
                     with the password asked for at the prompt. Sent only to the
                     AttackLedger address you give; the session is ended afterwards.

Requests never go through a proxy from the environment (a tester's HTTP_PROXY is often
Caido itself, which would record the token in its own history) and never follow a redirect
(urllib would resend the Authorization header to the new address). Plain HTTP is refused
to any address that is not this machine, unless --insecure-http is given.

The queries are pinned to Caido's public GraphQL schema (github.com/caido/schemas,
proxy schema v0.58.3) and to the query shapes of Caido's own client SDK
(github.com/caido/sdk-js, sdk-client documents/request.graphql). They were not run against
a live Caido. An answer of any other shape stops the pull with a message naming the field.

Redaction: AttackLedger redacts cookies, authorization headers and other secrets when the
file is imported, whatever this tool does. --redact-locally applies the same rules before
the file is written, so the secrets never reach the disk: the server's own rules
(server/app/redact.py) when this tool runs from the repository on Python 3.10 or later,
otherwise a minimal copy of its header and parameter rules kept below (tests check it
matches the server's).
"""
from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
import re
import stat
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "0.58.3"          # the Caido proxy schema the queries were checked against
DEFAULT_CAIDO = "http://127.0.0.1:8080"
DEFAULT_TOKEN_ENV = "CAIDO_TOKEN"
DEFAULT_AL_TOKEN_ENV = "ATTACKLEDGER_TOKEN"
# AttackLedger's import limits (server/app/importers/__init__.py; a test checks they match).
MAX_ENTRIES = 5_000
MAX_FILE_BYTES = 50_000_000
TIMEOUT = 30
SESSION_COOKIE = "al_session"

# Caido's `requests` query, as its client SDK sends it (fragment RequestFull and
# ResponseFull), plus the fields the export layout carries (source, alteration, edited).
REQUESTS_QUERY = """\
query AttackLedgerPull($first: Int, $after: String, $filter: HTTPQLInput, $order: RequestResponseOrderInput) {
  requests(first: $first, after: $after, filter: $filter, order: $order) {
    edges {
      cursor
      node {
        id
        host
        port
        method
        path
        query
        isTls
        createdAt
        source
        alteration
        edited
        length
        raw
        response {
          id
          statusCode
          roundtripTime
          length
          createdAt
          alteration
          edited
          raw
        }
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}"""
VERSION_QUERY = "query AttackLedgerVersion { runtime { version } }"
# Messages GraphQL servers give when a query names something the schema does not have.
_SCHEMA_WORDS = re.compile(r"(?i)cannot query field|unknown (field|argument|type)|unknown enum|"
                           r"is not defined|expected type|did you mean|must have a selection")


class PullError(Exception):
    """A refusal or failure, with a message for the tester. Never holds a secret."""


class AuthFailed(PullError):
    pass


class ShapeError(PullError):
    pass


# ---- secrets -------------------------------------------------------------------------------

class Secrets:
    """Every secret this run holds, so that no message ever prints one."""

    def __init__(self):
        self.values: list[tuple[str, str]] = []

    def add(self, value: str | None, label: str) -> None:
        if value:
            self.values.append((value, label))

    def scrub(self, text: str) -> str:
        for value, label in self.values:
            text = text.replace(value, f"[{label}]")
        return text


SECRETS = Secrets()


def say(msg: str) -> None:
    print(SECRETS.scrub(msg), file=sys.stderr)


def _clean_token(value: str, where: str) -> str:
    tok = value.strip()
    if not tok:
        raise PullError(f"{where} is empty")
    if any(c.isspace() or not c.isprintable() or ord(c) > 126 for c in tok):
        raise PullError(f"{where} holds spaces, line breaks or other characters a token does not have")
    return tok


def read_secret(env_name: str, file: str | None, what: str) -> str | None:
    """A token from the file named (first) or the environment variable. The file's
    permissions are checked like ssh does: readable by others means a warning."""
    if file:
        p = Path(file).expanduser()
        try:
            mode = p.stat().st_mode
            raw = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            raise PullError(f"cannot read the {what} file {p}: {getattr(e, 'strerror', None) or 'not text'}") from None
        if os.name == "posix" and mode & (stat.S_IRWXG | stat.S_IRWXO):
            say(f"warning: the {what} file {p} can be read by other users of this machine; chmod 600 it")
        return _clean_token(raw, f"the {what} file")
    value = os.environ.get(env_name)
    return _clean_token(value, f"the environment variable {env_name}") if value is not None else None


def caido_token(args) -> str:
    tok = read_secret(args.token_env, args.token_file, "Caido token")
    if tok is None:
        raise PullError(f"no Caido token: set the environment variable {args.token_env} or pass --token-file "
                        "(the token is never read from the command line)")
    SECRETS.add(tok, "Caido token")
    if tok.startswith("caido_"):
        # A personal access token is for Caido's cloud API; an instance takes an access token.
        raise PullError("this is a Caido personal access token (it starts with caido_). Caido's instance API "
                        "takes an access token instead; docs/IMPORT.md, section \"Pull from Caido\", says how "
                        "to get one. Nothing was sent.")
    return tok


# ---- HTTP: no proxies, no redirects ---------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise PullError(f"{req.full_url.split('?')[0]} answered with a redirect ({code}); this tool does not "
                        "follow redirects, so the token is never sent anywhere else. Give the final address.")


def _opener():
    # Built for each request: an empty ProxyHandler replaces the one that reads *_PROXY.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def _loopback(host: str) -> bool:
    if host.lower() in ("localhost", "localhost.") or host.lower().endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def base_url(url: str, what: str, insecure_http: bool) -> str:
    parts = urllib.parse.urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise PullError(f"the {what} address must start with http:// or https:// and name a host")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise PullError(f"the {what} address must not hold a user name, a password, a query or a fragment")
    if parts.scheme == "http" and not _loopback(parts.hostname) and not insecure_http:
        raise PullError(f"the {what} address uses plain HTTP to another machine, which would send your "
                        "credentials unencrypted; use https://, or --insecure-http if you accept that")
    return f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}"


def _send(url: str, body: bytes | None, headers: dict, method: str = "POST"):
    """One request. Returns (status, headers, body); HTTP errors are answers too."""
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with _opener().open(req, timeout=TIMEOUT) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        with e:
            return e.code, e.headers, e.read()
    except PullError:
        raise
    except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as e:
        reason = getattr(e, "reason", e)
        raise PullError(f"could not reach {url.split('?')[0]}: {reason}") from None


# ---- Caido ------------------------------------------------------------------------------

class Caido:
    def __init__(self, url: str, token: str):
        self.endpoint = url + "/graphql"
        self.token = token
        self.version: str | None = None

    def query(self, document: str, variables: dict | None = None) -> dict:
        body = json.dumps({"query": document, "variables": variables or {}}).encode()
        status, _h, raw = _send(self.endpoint, body, {"Content-Type": "application/json", "Accept": "application/json",
                                                      "Authorization": f"Bearer {self.token}"})
        if status in (401, 403):
            raise AuthFailed(f"Caido refused the token (HTTP {status}). It may have expired (access tokens last "
                             "about 7 days); get a new one and try again.")
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ShapeError(f"{self.endpoint} did not answer with GraphQL (HTTP {status}); is this Caido's "
                             "address?") from None
        if not isinstance(doc, dict):
            raise ShapeError("Caido's answer is not a GraphQL response object")
        errors = doc.get("errors")
        if errors:
            self._raise(errors)
        if status != 200:
            raise PullError(f"Caido answered HTTP {status}")
        if not isinstance(doc.get("data"), dict):
            raise ShapeError("Caido's answer has no data")
        return doc["data"]

    def _raise(self, errors) -> None:
        if not isinstance(errors, list):
            raise ShapeError("Caido's answer has errors in an unexpected shape")
        messages = []
        for err in errors:
            err = err if isinstance(err, dict) else {}
            ext = (err.get("extensions") or {}).get("CAIDO") if isinstance(err.get("extensions"), dict) else None
            if isinstance(ext, dict) and ext.get("code") == "AUTHORIZATION":
                reason = ext.get("reason")
                why = {"INVALID_TOKEN": "the token has expired or is not valid; get a new one",
                       "FORBIDDEN": "this account may not read the history",
                       "MISSING_SCOPE": "the token lacks a permission this query needs"}.get(reason, "not allowed")
                raise AuthFailed(f"Caido refused the token ({reason}): {why}.")
            messages.append(str(err.get("message", ""))[:300])
        text = "; ".join(m for m in messages if m) or "no message"
        if _SCHEMA_WORDS.search(text):
            raise ShapeError(f"Caido did not accept this tool's query: {text}. The query follows Caido's schema "
                             f"v{SCHEMA_VERSION}; your Caido runs {self.version or 'an unknown version'}, whose "
                             "schema has changed. Use Caido's own export (docs/TESTER_GUIDE.md, section 5) until "
                             "this tool is updated.")
        raise PullError(f"Caido refused the query: {text}")

    def check_version(self) -> str | None:
        data = self.query(VERSION_QUERY)
        rt = data.get("runtime")
        if not isinstance(rt, dict) or not isinstance(rt.get("version"), str):
            raise ShapeError("Caido's answer to runtime { version } has an unexpected shape")
        self.version = rt["version"][:40]
        return self.version


def _need(obj: dict, key: str, types, where: str, nullable: bool = False):
    if not isinstance(obj, dict) or key not in obj:
        raise ShapeError(f"Caido's answer has an unexpected shape: {where}.{key} is missing "
                         f"(checked against schema v{SCHEMA_VERSION})")
    v = obj[key]
    if v is None and nullable:
        return None
    if isinstance(v, bool) and bool not in (types if isinstance(types, tuple) else (types,)):
        v = object()                                     # true is an int in Python, not here
    if not isinstance(v, types):
        raise ShapeError(f"Caido's answer has an unexpected shape: {where}.{key} is "
                         f"{'null' if obj[key] is None else type(obj[key]).__name__} "
                         f"(checked against schema v{SCHEMA_VERSION})")
    return v


def _millis(value, where: str) -> int:
    """Caido's Timestamp scalar as epoch milliseconds, the export's layout. It is read as a
    number of milliseconds, a string of digits, or an ISO 8601 / RFC 3339 time."""
    if isinstance(value, bool):
        raise ShapeError(f"Caido's answer has an unexpected shape: {where} is not a time")
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        if value.isdigit():
            return int(value)
        try:
            t = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
        else:
            return int((t if t.tzinfo else t.replace(tzinfo=timezone.utc)).timestamp() * 1000)
    raise ShapeError(f"Caido's answer has an unexpected shape: {where} is not a time")


def _blob(value, where: str) -> bytes | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ShapeError(f"Caido's answer has an unexpected shape: {where} is not base64 text")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ShapeError(f"Caido's answer has an unexpected shape: {where} is not valid base64") from None


def _lower(value, where: str) -> str:
    if not isinstance(value, str):
        raise ShapeError(f"Caido's answer has an unexpected shape: {where} is not text")
    return value.lower()


def row_from(node: dict, n: int) -> tuple[dict, bytes | None, bytes | None]:
    """One Caido request as an export row, plus its decoded raw bytes."""
    w = f"requests.edges[{n}].node"
    if not isinstance(node, dict):
        raise ShapeError(f"Caido's answer has an unexpected shape: {w} is not an object")
    rid = _need(node, "id", (str, int), w)
    port = _need(node, "port", int, w)
    row = {"id": rid, "host": _need(node, "host", str, w), "port": port, "is_tls": _need(node, "isTls", bool, w),
           "method": _need(node, "method", str, w), "path": _need(node, "path", str, w),
           "query": _need(node, "query", str, w), "created_at": _millis(_need(node, "createdAt", (int, str), w),
                                                                         w + ".createdAt")}
    request = _blob(node.get("raw"), w + ".raw")
    resp = _need(node, "response", dict, w, nullable=True)
    response = None
    if resp is not None:
        rw = w + ".response"
        out = {"id": _need(resp, "id", (str, int), rw), "status_code": _need(resp, "statusCode", int, rw)}
        response = _blob(resp.get("raw"), rw + ".raw")
        for key, src in (("length", "length"), ("roundtrip_time", "roundtripTime")):
            if isinstance(resp.get(src), int) and not isinstance(resp.get(src), bool):
                out[key] = resp[src]
        if resp.get("createdAt") is not None:
            out["created_at"] = _millis(resp["createdAt"], rw + ".createdAt")
        if resp.get("alteration") is not None:
            out["alteration"] = _lower(resp["alteration"], rw + ".alteration")
        if isinstance(resp.get("edited"), bool):
            out["edited"] = resp["edited"]
        row["response"] = out
    else:
        row["response"] = None
    if node.get("source") is not None:
        row["source"] = _lower(node["source"], w + ".source")
    if node.get("alteration") is not None:
        row["alteration"] = _lower(node["alteration"], w + ".alteration")
    if isinstance(node.get("edited"), bool):
        row["edited"] = node["edited"]
    if isinstance(node.get("length"), int) and not isinstance(node.get("length"), bool):
        row["length"] = node["length"]
    return row, request, response


def _when(value: str, flag: str) -> str:
    """--since / --until as RFC 3339 in UTC, the form HTTPQL's created_at takes."""
    try:
        t = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        raise PullError(f"{flag} is not a date or time; use ISO 8601, such as 2026-10-01 or "
                        "2026-10-01T09:00:00Z") from None
    t = t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def httpql(filter_: str, since: str | None, until: str | None) -> str:
    parts = [f"({filter_.strip()})"]
    if since:
        parts.append(f'req.created_at.gt:"{_when(since, "--since")}"')
    if until:
        parts.append(f'req.created_at.lt:"{_when(until, "--until")}"')
    return " AND ".join(parts)


def pull(caido: Caido, code: str, page_size: int, max_rows: int, redactor) -> dict:
    """Page through the matching requests, oldest first, until the end or one file's worth."""
    rows: list[dict] = []
    size, after, more, cut = 2, None, True, None
    no_raw = 0
    while more:
        data = caido.query(REQUESTS_QUERY, {"first": page_size, "after": after, "filter": {"code": code},
                                            "order": {"by": "CREATED_AT", "ordering": "ASC"}})
        conn = _need(data, "requests", dict, "data")
        edges = _need(conn, "edges", list, "requests")
        info = _need(conn, "pageInfo", dict, "requests")
        more = _need(info, "hasNextPage", bool, "requests.pageInfo")
        after = _need(info, "endCursor", str, "requests.pageInfo", nullable=True)
        if more and not after:
            raise ShapeError("Caido's answer has an unexpected shape: hasNextPage is true without an endCursor")
        if not edges and more:
            raise ShapeError("Caido's answer has an unexpected shape: an empty page that says more follow")
        for edge in edges:
            node = _need(edge, "node", dict, f"requests.edges[{len(rows)}]")
            row, request, response = row_from(node, len(rows))
            had_raw = request is not None
            if redactor:
                row, request, response = redactor.row(row, request, response)
            if request is not None:
                row["raw"] = base64.b64encode(request).decode()
            if response is not None:
                row["response"]["raw"] = base64.b64encode(response).decode()
            extra = len(json.dumps(row)) + 2         # as write_export writes it, with ", " between rows
            if len(rows) >= max_rows or size + extra > MAX_FILE_BYTES:
                if not rows:
                    raise PullError("the first matching request alone is larger than one import file "
                                    f"({MAX_FILE_BYTES // 1_000_000} MB); narrow the filter")
                cut = row["created_at"]
                more = False
                break
            rows.append(row)
            size += extra
            no_raw += not had_raw
    return {"rows": rows, "cut_at": cut, "no_raw": no_raw}


# ---- local redaction -----------------------------------------------------------------------

_REDACT_PY = Path(__file__).resolve().parents[1] / "server" / "app" / "redact.py"


def _load_repo_redact():
    """server/app/redact.py when this tool runs from the repository, loaded under a private
    package name so it cannot clash with anything else called `app`."""
    pkg_dir = _REDACT_PY.parent
    if not _REDACT_PY.is_file() or not (pkg_dir / "jsanalysis.py").is_file():
        return None
    name = "_attackledger_server_app"
    try:
        spec = importlib.util.spec_from_file_location(name, pkg_dir / "__init__.py",
                                                      submodule_search_locations=[str(pkg_dir)])
        pkg = importlib.util.module_from_spec(spec)
        sys.modules[name] = pkg
        spec.loader.exec_module(pkg)
        return importlib.import_module(name + ".redact")
    except Exception:          # noqa: BLE001  a broken checkout falls back to the copy below
        sys.modules.pop(name, None)
        return None


class Vendored:
    """A minimal copy of server/app/redact.py's header and parameter rules, for when this file
    is used outside the repository or on Python 3.9. It covers header lines in the raw request and response
    (Cookie and Set-Cookie values, Authorization and Proxy-Authorization with the scheme
    kept, any header with a secret name) and secret query or form parameters in the request
    line, headers and the query field. It does not cover bodies, JWTs and key formats in
    other places, or personal data: the server applies those at import."""

    SECRET_NAMES = frozenset({"key", "pwd", "pass", "sid", "sig", "code", "auth", "jwt", "otp",
                              "cookie", "setcookie", "authorization", "proxyauthorization"})
    SECRET_PARTS = ("token", "secret", "password", "passwd", "apikey", "session", "signature", "privatekey")
    MARKER_PREFIX = "[redacted:sha256:"
    MARKER_RE = re.compile(r"\[redacted:sha256:[0-9a-f]{12}\]")
    _COOKIE_PAIR = re.compile(r"(^|;)(\s*[^=;\s][^=;]*=)([^;]*)")
    _SETCOOKIE_SPLIT = re.compile(r"(,\s*(?=[!#$%&'*+\-.^_`|~0-9A-Za-z]+=))")
    _SCHEME = re.compile(r"^(\s*[A-Za-z][\w.\-]*\s+)(\S.*?)(\s*)$", re.S)
    _KV = re.compile(r"""(?<![\w.\-\[\]%])([A-Za-z0-9_.\-\[\]%]{1,64})=(?!=)("[^"\r\n]{0,4000}"|'[^'\r\n]{0,4000}'|[^&\s#"'<>;,)]*)""")
    _HEAD_END = re.compile(rb"\r?\n\r?\n")

    class Report:
        def __init__(self):
            self.kinds: dict[str, int] = {}

        @property
        def count(self) -> int:
            return sum(self.kinds.values())

        def add(self, kind: str) -> None:
            kind = re.sub(r"[^\w.\-\[\] ]", "", kind)[:40] or "value"
            self.kinds[kind] = self.kinds.get(kind, 0) + 1

    @staticmethod
    def _norm(name: str) -> str:
        return re.sub(r"[-_.\s]", "", name.lower())

    @classmethod
    def secret_name(cls, name: str) -> bool:
        n = cls._norm(name)
        return bool(n) and (n in cls.SECRET_NAMES or any(p in n for p in cls.SECRET_PARTS))

    @classmethod
    def marker(cls, value: str) -> str:
        return f"{cls.MARKER_PREFIX}{hashlib.sha256(value.encode('utf-8', 'surrogateescape')).hexdigest()[:12]}]"

    @classmethod
    def _mask(cls, value: str, kind: str, rep) -> str:
        if not value or cls.MARKER_RE.fullmatch(value):
            return value
        rep.add(kind)
        return cls.marker(value)

    @classmethod
    def _cookie_values(cls, value: str, kind: str, rep) -> str:
        def sub(m):
            v = m.group(3)
            core = v.strip()
            if not core:
                return m.group(0)
            lead, trail = v[:len(v) - len(v.lstrip())], v[len(v.rstrip()):]
            return f"{m.group(1)}{m.group(2)}{lead}{cls._mask(core, kind, rep)}{trail}"
        return cls._COOKIE_PAIR.sub(sub, value)

    @classmethod
    def _set_cookie(cls, value: str, kind: str, rep) -> str:
        out = []
        for piece in cls._SETCOOKIE_SPLIT.split(value):
            if cls._SETCOOKIE_SPLIT.fullmatch(piece):
                out.append(piece)
                continue
            pair, sep, attrs = piece.partition(";")
            out.append(cls._cookie_values(pair, kind, rep) + sep + attrs)
        return "".join(out)

    @classmethod
    def header_value(cls, name: str, value: str, rep) -> str:
        n = cls._norm(name)
        if not value:
            return value
        if n == "cookie":
            return cls._cookie_values(value, name, rep)
        if n == "setcookie":
            return cls._set_cookie(value, name, rep)
        if not cls.secret_name(name):
            return value
        if n in ("authorization", "proxyauthorization"):
            m = cls._SCHEME.match(value)
            if m:
                return m.group(1) + cls._mask(m.group(2), name, rep) + m.group(3)
        return cls._mask(value, name, rep)

    @classmethod
    def params(cls, s: str, rep) -> str:
        def sub(m):
            name, v = m.group(1), m.group(2)
            if not cls.secret_name(name):
                return m.group(0)
            if len(v) >= 2 and v[0] in "\"'" and v[-1] == v[0]:
                return f"{name}={v[0]}{cls._mask(v[1:-1], name, rep)}{v[0]}"
            return f"{name}={cls._mask(v, name, rep)}"
        return cls._KV.sub(sub, s) if s else s

    @classmethod
    def header_line(cls, line: str, rep) -> str:
        name, sep, value = (line[1:].partition(":") if line.startswith(":") else line.partition(":"))
        if not sep:
            return cls.params(line, rep)
        name = (":" + name) if line.startswith(":") else name
        lead = value[:len(value) - len(value.lstrip())]
        v = value.strip()
        new = cls.header_value(name.strip(), v, rep)
        if new == v:
            new = cls.params(v, rep)
        return f"{name}{sep}{lead}{new}"

    @classmethod
    def http_message(cls, raw: bytes | None, rep, **_kw) -> bytes | None:
        """The head of one raw message (start line and headers); the body is kept as it is."""
        if not raw:
            return raw
        m = cls._HEAD_END.search(raw)
        head_b, rest = (raw[:m.start()], raw[m.start():]) if m else (raw, b"")
        lines = re.split(r"(\r?\n)", head_b.decode("utf-8", "surrogateescape"))
        out = [cls.params(lines[0], rep)] if lines else []
        for i, part in enumerate(lines[1:], start=1):
            out.append(part if i % 2 else cls.header_line(part, rep))
        return "".join(out).encode("utf-8", "surrogateescape") + rest


class Redactor:
    """Applies the server's redaction to each row before it is written: the raw request and
    response as the import pipeline does (server/app/inbox.py), and the path and query
    fields, from which the import builds the URL."""

    def __init__(self, module=None):
        self.module = module if module is not None else _load_repo_redact()
        self.full = self.module is not None
        if not self.full:
            self.module = Vendored
        self.rep = self.module.Report()

    def _text(self, s: str) -> str:
        return self.module.text(s, self.rep) if self.full else Vendored.params(s, self.rep)

    def row(self, row: dict, request: bytes | None, response: bytes | None):
        row = dict(row, path=self._text(row["path"]), query=self._text(row["query"]))
        request = self.module.http_message(request, self.rep, personal=True, what="binary request body")
        response = self.module.http_message(response, self.rep, personal=True, what="binary response body")
        return row, request, response

    def summary(self) -> str:
        why = ("this tool runs outside the repository" if not _REDACT_PY.is_file() else
               "server/app/redact.py needs Python 3.10 or later" if sys.version_info < (3, 10) else
               "server/app/redact.py could not be loaded")
        rules = ("AttackLedger's redaction rules (server/app/redact.py)" if self.full else
                 f"the header and parameter rules only ({why}; bodies are redacted by the server at import)")
        kinds = ", ".join(list(self.rep.kinds)[:8])
        return f"redacted locally with {rules}: {self.rep.count} value(s){' (' + kinds + ')' if kinds else ''}"


# ---- the file -------------------------------------------------------------------------------

def write_export(path: Path, rows: list[dict], overwrite: bool) -> int:
    """The export as a JSON array, written to a temporary file next to it and renamed, with
    permissions for its owner only: it holds captured traffic."""
    if path.exists() and not overwrite:
        raise PullError(f"{path} exists; choose another --out or pass --overwrite")
    data = (json.dumps(rows) + "\n").encode()
    fd, tmp = tempfile.mkstemp(prefix=".caido-pull-", suffix=".json", dir=str(path.parent or "."))
    try:                                       # mkstemp creates it readable by its owner only
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return len(data)


# ---- AttackLedger -----------------------------------------------------------------------------

def _answer(raw: bytes) -> dict:
    try:
        doc = json.loads(raw.decode("utf-8"))
        return doc if isinstance(doc, dict) else {}
    except (UnicodeDecodeError, ValueError):
        return {}


def _detail(raw: bytes) -> str:
    d = _answer(raw).get("detail")
    if isinstance(d, dict):
        d = d.get("message") or d.get("error")
    return str(d)[:300] if d else "no detail"


def engagement_id(server: str, value: str, headers: dict) -> int:
    """--engagement as a number, or as the engagement's name among those you can read."""
    if value.strip().isdigit():
        return int(value.strip())
    status, _h, raw = _send(server + "/engagements", None, {k: v for k, v in headers.items() if k != "Content-Type"},
                            method="GET")
    if status != 200:
        raise PullError(f"AttackLedger did not list your engagements (HTTP {status}): {_detail(raw)}")
    try:
        engs = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        engs = None
    if not isinstance(engs, list):
        raise PullError("AttackLedger's list of engagements has an unexpected shape")
    found = [e["id"] for e in engs if isinstance(e, dict) and isinstance(e.get("name"), str)
             and e["name"].strip().lower() == value.strip().lower() and isinstance(e.get("id"), int)]
    if len(found) != 1:
        raise PullError(f"{'no' if not found else 'more than one'} engagement you can read is named "
                        f"\"{value.strip()}\"; give its number instead")
    return found[0]


def upload(args, path: Path) -> dict:
    """POST the file to /engagements/<id>/imports as the tester. Signs in with email and a
    prompted password (and signs out after), or sends the operator token."""
    server = base_url(args.upload, "AttackLedger", args.insecure_http)
    headers = {"Content-Type": "application/octet-stream", "Accept": "application/json"}
    session = None
    if args.al_email:
        password = getpass.getpass(f"AttackLedger password for {args.al_email}: ")
        SECRETS.add(password, "password")
        status, h, raw = _send(server + "/auth/login", json.dumps({"email": args.al_email, "password": password}).encode(),
                               {"Content-Type": "application/json", "Accept": "application/json"})
        del password
        if status != 200:
            raise AuthFailed(f"AttackLedger did not sign you in (HTTP {status}): {_detail(raw)}")
        for value in h.get_all("Set-Cookie") or []:
            m = re.match(rf"\s*{SESSION_COOKIE}=([^;]+)", value)
            if m:
                session = m.group(1)
        if not session:
            raise AuthFailed("AttackLedger signed you in but sent no session cookie")
        SECRETS.add(session, "AttackLedger session")
        headers["Cookie"] = f"{SESSION_COOKIE}={session}"
    else:
        tok = read_secret(args.al_token_env, args.al_token_file, "AttackLedger token")
        if tok:
            SECRETS.add(tok, "AttackLedger token")
            headers["Authorization"] = f"Bearer {tok}"
    query = urllib.parse.urlencode({"format": "caido", "filename": path.name} |
                                   ({"reimport": "true"} if args.reimport else {}))
    try:
        eng = engagement_id(server, args.engagement, headers)
        status, _h, raw = _send(f"{server}/engagements/{eng}/imports?{query}", path.read_bytes(), headers)
    finally:
        if session:
            try:
                _send(server + "/auth/logout", b"", {"Cookie": f"{SESSION_COOKIE}={session}"})
            except PullError:
                say("warning: signing out of AttackLedger failed; the session ends on its own")
    if status == 201:
        return dict(_answer(raw), engagement_id=eng)
    if status in (401, 403):
        raise AuthFailed(f"AttackLedger refused the upload (HTTP {status}): {_detail(raw)}. You need the tester "
                         "role on this engagement.")
    if status == 409 and "already_imported" in raw.decode("utf-8", "replace"):
        raise PullError("AttackLedger already has this exact file. Pass --reimport to import it again; its rows "
                        "already in the inbox count as duplicates.")
    raise PullError(f"AttackLedger refused the upload (HTTP {status}): {_detail(raw)}")


# ---- command line ---------------------------------------------------------------------------

def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="caido_pull.py", allow_abbrev=False, description="Pull HTTP history from your own Caido into a Caido JSON export "
        "that AttackLedger imports. The Caido token is read from an environment variable or a file, never "
        "from the command line.")
    p.add_argument("--filter", required=True, help='HTTPQL filter, such as req.host.eq:"shop.example.com"')
    p.add_argument("--since", help="only requests after this time (ISO 8601, UTC if no zone is given)")
    p.add_argument("--until", help="only requests before this time")
    p.add_argument("--caido", default=DEFAULT_CAIDO, help=f"your Caido's address (default {DEFAULT_CAIDO})")
    p.add_argument("--token-env", default=DEFAULT_TOKEN_ENV, metavar="NAME",
                   help=f"environment variable holding the Caido token (default {DEFAULT_TOKEN_ENV})")
    p.add_argument("--token-file", metavar="PATH", help="file holding the Caido token (used instead of the variable)")
    p.add_argument("--out", help="the file to write (default caido-<time>.json here)")
    p.add_argument("--overwrite", action="store_true", help="replace --out if it exists")
    p.add_argument("--redact-locally", action="store_true",
                   help="redact cookies, authorization headers and other secrets before the file is written")
    p.add_argument("--page-size", type=int, default=100, help="requests per page (1 to 1000, default 100)")
    p.add_argument("--max-rows", type=int, default=MAX_ENTRIES,
                   help=f"stop after this many requests (at most {MAX_ENTRIES}, one import file's worth)")
    p.add_argument("--upload", metavar="URL", help="also upload the file to this AttackLedger")
    p.add_argument("--engagement", help="the engagement in AttackLedger, by name or number (with --upload)")
    p.add_argument("--al-email", help="sign in to AttackLedger with this email; the password is asked for")
    p.add_argument("--al-token-env", default=DEFAULT_AL_TOKEN_ENV, metavar="NAME",
                   help=f"environment variable holding an AttackLedger operator token (default {DEFAULT_AL_TOKEN_ENV})")
    p.add_argument("--al-token-file", metavar="PATH", help="file holding an AttackLedger operator token")
    p.add_argument("--reimport", action="store_true", help="import the file again if AttackLedger already has it")
    p.add_argument("--insecure-http", action="store_true",
                   help="allow plain http:// to another machine (sends credentials unencrypted)")
    return p


def parse_args(argv: list[str]):
    p = parser()
    args, unknown = p.parse_known_args(argv)
    if unknown:
        # argparse would print the unknown arguments, values included: a token typed on the
        # command line would be echoed. Name the options only.
        names = sorted({a.split("=", 1)[0] for a in unknown if a.startswith("-")})
        hint = (" A token is never read from the command line: set CAIDO_TOKEN or use --token-file."
                if any("token" in n.lower() or "password" in n.lower() for n in names) else "")
        p.print_usage(sys.stderr)
        print(f"caido_pull.py: error: unknown option{'s' if len(names) != 1 else ''} "
              f"{', '.join(names) or '(a value without an option)'}.{hint}", file=sys.stderr)
        raise SystemExit(2)
    if not args.filter.strip():
        p.error("--filter is empty")
    if not 1 <= args.page_size <= 1000:
        p.error("--page-size must be between 1 and 1000")
    if not 1 <= args.max_rows <= MAX_ENTRIES:
        p.error(f"--max-rows must be between 1 and {MAX_ENTRIES}")
    if args.upload and args.engagement is None:
        p.error("--upload needs --engagement")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        url = base_url(args.caido, "Caido", args.insecure_http)
        code = httpql(args.filter, args.since, args.until)
        if args.upload:
            base_url(args.upload, "AttackLedger", args.insecure_http)       # refuse before pulling
        out = Path(args.out or f"caido-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json")
        if out.exists() and not args.overwrite:
            raise PullError(f"{out} exists; choose another --out or pass --overwrite")
        redactor = Redactor() if args.redact_locally else None
        caido = Caido(url, caido_token(args))
        version = caido.check_version()
        say(f"Caido {version} at {url} (queries checked against schema v{SCHEMA_VERSION})")
        result = pull(caido, code, args.page_size, args.max_rows, redactor)
        size = write_export(out, result["rows"], args.overwrite)
        say(f"wrote {len(result['rows'])} request(s) to {out} ({size:,} bytes)")
        if result["no_raw"]:
            say(f"{result['no_raw']} request(s) had no raw bytes in Caido; they import with URL, method and status")
        if redactor:
            say(redactor.summary())
        else:
            say("not redacted locally: AttackLedger redacts cookies and authorization headers when it imports "
                "the file (use --redact-locally to do it before the file is written)")
        if result["cut_at"] is not None:
            # HTTPQL's created_at.gt takes whole seconds: start one second early. Rows exported
            # twice count as duplicates at import, and nothing is skipped.
            nxt = datetime.fromtimestamp((result["cut_at"] - 1) // 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            say(f"more requests match than one file holds; the file has the oldest {len(result['rows'])}. "
                f"For the rest, run again with --since {nxt} and another --out.")
        if args.upload:
            b = upload(args, out)
            say(f"uploaded to AttackLedger, engagement {b['engagement_id']}: batch {b.get('id')}, "
                f"{b.get('accepted', 0)} in the inbox, {b.get('out_of_scope', 0)} out of scope, "
                f"{b.get('duplicates', 0)} duplicate(s), {b.get('unreadable', 0)} unreadable")
        return 0
    except PullError as e:
        say(f"caido_pull.py: {e}")
        return 1
    except KeyboardInterrupt:
        say("caido_pull.py: stopped")
        return 130


if __name__ == "__main__":
    sys.exit(main())
