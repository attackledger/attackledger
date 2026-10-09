"""Import adapters: an export file from another tool becomes inbox entries (D-029).

Each adapter is a pure parser. It reads the bytes of one export file and returns entries
(URL, method, status, raw request and response bytes, the tool's own id, time and label);
it never opens a network connection, a file or a URL named inside the export. Everything
after parsing (the scope check, redaction, dedupe and storage) happens in inbox.py, the same
way for every tool.

The registry is checked when the API starts, as modules and packs are: an adapter that does
not meet the contract stops the start. An unknown format, a file no adapter recognises, or a
file two adapters both claim is refused with a message; nothing is guessed.

Limits (a file over any of them is refused, never imported in part):
  MAX_FILE_BYTES   the size of the uploaded file
  MAX_ENTRIES      entries in one file
  MAX_XML_DEPTH    element nesting in XML (Burp's export is four levels deep)
A request or response larger than MAX_PART_BYTES is kept up to that size, and the entry
says it was cut.
"""
import base64
import binascii
import re
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit

MAX_FILE_BYTES = 50_000_000
MAX_ENTRIES = 5_000
MAX_PART_BYTES = 5_000_000
MAX_XML_DEPTH = 32

_ID = re.compile(r"^[a-z][a-z0-9-]{1,15}$")
_METHOD = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,19}$")
_VERSION = re.compile(r"^HTTP/\d(?:\.\d)?$", re.I)


class ImportRefused(ValueError):
    """The file as a whole cannot be imported. The message is shown to the person."""


class RowError(ValueError):
    """One row of an otherwise readable file cannot be read; it is listed, not imported."""


@dataclass(frozen=True)
class Entry:
    row: int                          # position in the file, from 1, so a person can find it
    url: str
    method: str
    status: int | None                # None: no response was recorded
    request: bytes | None             # raw bytes as the tool kept them (None: not in the export)
    response: bytes | None
    tool_id: str | None = None        # the tool's own id for the row
    time: str | None = None           # the tool's time for the row, as text
    label: str | None = None          # the tool's label: a comment, a finding name
    rebuilt: bool = False             # raw bytes rebuilt from the export's fields, not captured
    truncated: tuple[str, ...] = ()   # parts cut at MAX_PART_BYTES: "request", "response"


@dataclass
class Parsed:
    entries: list[Entry] = field(default_factory=list)
    unreadable: list[tuple[int, str]] = field(default_factory=list)   # (row, why)
    creator: str | None = None        # the tool (and version) the file says made it


@dataclass(frozen=True)
class Adapter:
    id: str                           # source "import:<id>" in the evidence chain
    title: str
    summary: str
    extensions: tuple[str, ...]
    detect: Callable[[bytes], bool]   # cheap look at the start of the file
    parse: Callable[[bytes], Parsed]


# ---- helpers the adapters share ----------------------------------------------------------

def text(value, limit: int) -> str | None:
    """A short string field from an export: None when absent or empty, cut to a limit."""
    if value is None:
        return None
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        raise RowError("a text field has the wrong type")
    s = str(value).strip()
    return s[:limit] or None


def method(value) -> str:
    if not isinstance(value, str) or not _METHOD.match(value.strip()):
        raise RowError("no readable HTTP method")
    return value.strip().upper()


def http_url(value) -> str:
    if not isinstance(value, str) or len(value) > 8_000:
        raise RowError("no readable URL")
    u = value.strip()
    try:
        parts = urlsplit(u)
        host = parts.hostname
    except ValueError:
        raise RowError("no readable URL") from None
    if parts.scheme.lower() not in ("http", "https") or not host:
        raise RowError("the URL is not an http or https URL with a host")
    return u


def status(value) -> int | None:
    """An HTTP status; 0, empty or absent means there was no response."""
    if value in (None, "", 0, "0"):
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise RowError("the status is not a number") from None
    if not 100 <= n <= 599:
        raise RowError(f"the status {n} is not an HTTP status")
    return n


def http_version(value) -> str:
    v = (value or "").strip() if isinstance(value, str) else ""
    if v.lower() in ("h2", "http/2.0"):
        return "HTTP/2"
    if v.lower() in ("h3", "http/3.0"):
        return "HTTP/3"
    return v.upper() if _VERSION.match(v) else "HTTP/1.1"


def cut(data: bytes, part: str, truncated: list[str]) -> bytes:
    if len(data) > MAX_PART_BYTES:
        truncated.append(part)
        return data[:MAX_PART_BYTES]
    return data


def b64(value, part: str, truncated: list[str]) -> bytes:
    """Decode base64 without ever decoding more than MAX_PART_BYTES of it: a huge field
    costs only the prefix that is kept."""
    if not isinstance(value, str):
        raise RowError(f"the {part} is not base64 text")
    room = (MAX_PART_BYTES + 2) // 3 * 4          # base64 characters for MAX_PART_BYTES
    window = value[:2 * room]                      # room for line breaks; the rest is never read
    s = "".join(window.split())
    if len(s) > room or len(window) < len(value):
        truncated.append(part)
        s = s[:room]
    try:
        out = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        raise RowError(f"the {part} is not valid base64") from None
    return out[:MAX_PART_BYTES]


def _clean(s: str) -> str:
    return s.replace("\r", " ").replace("\n", " ")


def message(start: str, headers: list[tuple[str, str]], body: bytes) -> bytes:
    """Raw HTTP bytes rebuilt from an export's fields (HAR keeps no raw bytes). Line breaks
    inside a field are replaced, so one field can never become two headers."""
    head = "\r\n".join([_clean(start)] + [f"{_clean(n)}: {_clean(v)}" for n, v in headers])
    return (head + "\r\n\r\n").encode("utf-8", "surrogateescape") + body


def target(url: str) -> str:
    """The request target as it appears on the request line: path and query."""
    p = urlsplit(url)
    return (p.path or "/") + (f"?{p.query}" if p.query else "")


# ---- the registry --------------------------------------------------------------------------

def _load() -> dict[str, Adapter]:
    from . import burp, caido, har      # noqa: PLC0415  (the adapters import the helpers above)
    found = {}
    for a in (har.ADAPTER, burp.ADAPTER, caido.ADAPTER):
        if not isinstance(a, Adapter) or not _ID.match(a.id) or not a.title or not a.extensions:
            raise RuntimeError(f"import adapter {getattr(a, 'id', a)!r} does not meet the adapter contract")
        if not callable(a.detect) or not callable(a.parse):
            raise RuntimeError(f"import adapter {a.id}: detect and parse must be functions")
        if a.id in found:
            raise RuntimeError(f"two import adapters use the id {a.id}")
        found[a.id] = a
    return found


_REGISTRY: dict[str, Adapter] | None = None


def registry() -> dict[str, Adapter]:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = _load()
    return _REGISTRY


def names() -> str:
    return ", ".join(a.title for a in registry().values())


def get(adapter_id: str) -> Adapter:
    try:
        return registry()[adapter_id]
    except KeyError:
        raise ImportRefused(f"unknown import format {adapter_id!r}; AttackLedger imports {names()}") from None


def choose(data: bytes, adapter_id: str | None = None) -> Adapter:
    """The adapter for a file: the one asked for, or the only one that recognises it."""
    if not data or not data.strip():
        raise ImportRefused("the file is empty")
    if len(data) > MAX_FILE_BYTES:
        raise ImportRefused(f"the file is larger than {MAX_FILE_BYTES // 1_000_000} MB; export fewer items")
    if adapter_id:
        return get(adapter_id)
    hits = [a for a in registry().values() if a.detect(data)]
    if len(hits) == 1:
        return hits[0]
    if not hits:
        raise ImportRefused(f"this file is not in a format AttackLedger can import ({names()})")
    raise ImportRefused("more than one format matches this file; choose the format")


def parse(data: bytes, adapter_id: str | None = None) -> tuple[Adapter, Parsed]:
    adapter = choose(data, adapter_id)
    parsed = adapter.parse(data)
    if not parsed.entries and not parsed.unreadable:
        raise ImportRefused("the file has no entries")
    return adapter, parsed


def head(data: bytes, n: int = 65_536) -> str:
    """The start of a file as text, for detection: byte order mark and leading space removed."""
    return data[:n].decode("utf-8", "replace").lstrip("﻿ \t\r\n")
