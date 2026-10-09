"""Redaction of sensitive values before anything is stored as evidence (D-038).

Evidence is append-only: once bytes are in the blob store and their hash is in the chain,
they cannot be removed without breaking every hash after them. So credentials, and two
kinds of personal data, are replaced before the bytes are stored, with a marker

    [redacted:sha256:<first 12 hex of the value's SHA-256>]

The same value always gives the same marker, so two occurrences can be correlated without
the value being kept. Every function reports what it redacted (a count and the kinds:
header, parameter and key names, pattern names), never the values. Everything else is
kept byte for byte, so the evidence still shows what happened.

Rules, in the order they run:

  headers      Authorization and Proxy-Authorization (the scheme is kept), Cookie and
               Set-Cookie (names and attributes kept, values replaced), and any header
               whose name is secret (SECRET_NAMES, SECRET_PARTS: X-Api-Key, X-Auth-Token,
               X-CSRF-Token, ...). The engagement's identification header is kept.
               In text, "Name: value" lines are checked too when the name is one of these
               headers or looks like an identifier (contains "-" or "_").
  JSON         "key": value at any depth when the key is secret (strings, numbers and flat
               arrays of them), and HAR-style {"name": <secret header>, "value": ...}.
               "code" counts in query strings and forms only: in JSON it is a status code.
  parameters   name=value in query strings, form bodies and text, when the name is secret.
  formats      JWTs, PEM private keys, bearer tokens, passwords in URLs (user:pass@), and
               the credential formats recon already looks for (jsanalysis.REAL: AWS access
               key ids, Stripe, Slack, GitHub, GitLab, npm, ... tokens).
  personal     (response bodies and attached files only) email addresses, and runs of 13
               to 19 digits that pass the Luhn check and start like a card number.

What this does not do: general detection of personal data (names, addresses, phone
numbers), values under a secret key that are nested objects, secrets with no telling name
or format, and binary content (images, PDFs, compressed bodies), which is stored as it is
and recorded as not redacted. A marker is a short hash: it does not reveal a strong secret,
but someone who guesses a weak value (a short password) can confirm the guess.

Everything here is linear in the size of the input: each rule is one regular expression
pass whose repetitions are bounded or anchored (measured at about 5 MB per second).
"""
import hashlib
import re

from . import jsanalysis

# Names whose values are secret wherever they appear: a header, a query or form parameter,
# a JSON key. Compared in lower case with "-", "_" and "." removed, so api_key, api-key and
# apiKey are the same name. Exact names first, then parts: a name containing a part is
# secret too (access_token, X-Auth-Token, db_password, sessionid, X-Amz-Signature).
SECRET_NAMES = frozenset({
    "key", "pwd", "pass", "sid", "sig", "code", "auth", "jwt", "otp",
    "cookie", "setcookie", "authorization", "proxyauthorization",
})
SECRET_PARTS = ("token", "secret", "password", "passwd", "apikey", "session", "signature", "privatekey")
# In JSON, "code" is nearly always a status or error code; it stays secret in query strings
# and form bodies, where it is the OAuth authorization code.
JSON_NOT_SECRET = frozenset({"code"})

MARKER_PREFIX = "[redacted:sha256:"
MARKER_RE = re.compile(r"\[redacted:sha256:[0-9a-f]{12}\]")
NOT_REDACTED_OFF = "redaction is off for this engagement"

# Attached files with these extensions are binary whatever their bytes look like.
BINARY_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "bmp", "tif", "tiff", "ico", "pdf", "zip", "gz",
                     "tgz", "7z", "rar", "docx", "xlsx", "pptx", "odt", "mp4", "mov", "webm", "mp3", "wav",
                     "pcap", "pcapng", "bin", "exe", "dll", "so", "dylib", "class", "jar", "der", "p12", "pfx"}


def _norm(name: str) -> str:
    return re.sub(r"[-_.\s]", "", name.lower())


def secret_name(name: str) -> bool:
    n = _norm(name)
    return bool(n) and (n in SECRET_NAMES or any(p in n for p in SECRET_PARTS))


def marker(value: str) -> str:
    return f"{MARKER_PREFIX}{hashlib.sha256(value.encode('utf-8', 'surrogateescape')).hexdigest()[:12]}]"


_KIND_CLEAN = re.compile(r"[^\w.\-\[\] ]")


class Report:
    """What was redacted from one piece of evidence: counts per kind, never the values."""

    def __init__(self, off: bool = False):
        self.kinds: dict[str, int] = {}
        self.not_redacted: list[str] = [NOT_REDACTED_OFF] if off else []

    @property
    def count(self) -> int:
        return sum(self.kinds.values())

    def add(self, kind: str) -> None:
        kind = _KIND_CLEAN.sub("", kind)[:40] or "value"
        self.kinds[kind] = self.kinds.get(kind, 0) + 1

    def skipped(self, what: str) -> None:
        if what not in self.not_redacted:
            self.not_redacted.append(what)

    def update(self, other: "Report") -> "Report":
        for k, n in other.kinds.items():
            self.kinds[k] = self.kinds.get(k, 0) + n
        for w in other.not_redacted:
            self.skipped(w)
        return self

    def as_dict(self) -> dict:
        return {"redacted": self.count, "kinds": list(self.kinds), "not_redacted": list(self.not_redacted)}

    def suffix(self) -> str:
        """The note appended to an evidence summary, so the hash chain commits to it."""
        parts = []
        if self.count:
            kinds = list(self.kinds)
            shown = ", ".join(kinds[:6]) + (f" and {len(kinds) - 6} more" if len(kinds) > 6 else "")
            parts.append(f"{self.count} value{'s' if self.count != 1 else ''} redacted: {shown}")
        if self.not_redacted:
            parts.append("not redacted: " + ", ".join(self.not_redacted))
        return f" [{'; '.join(parts)}]" if parts else ""


def enabled(eng) -> bool:
    """On unless the engagement's owner turned it off (a lab)."""
    return getattr(eng, "redact_evidence", True) is not False


def _mask(value: str, kind: str, rep: Report) -> str:
    if not value or MARKER_RE.fullmatch(value):
        return value
    rep.add(kind)
    return marker(value)


# ---- headers ------------------------------------------------------------------

_AUTH_HEADERS = {"authorization", "proxyauthorization"}
_COOKIE_PAIR = re.compile(r"(^|;)(\s*[^=;\s][^=;]*=)([^;]*)")
# Several Set-Cookie values joined into one: split before "name=", not inside an Expires date.
_SETCOOKIE_SPLIT = re.compile(r"(,\s*(?=[!#$%&'*+\-.^_`|~0-9A-Za-z]+=))")
_SCHEME = re.compile(r"^(\s*[A-Za-z][\w.\-]*\s+)(\S.*?)(\s*)$", re.S)


def _cookie_values(value: str, kind: str, rep: Report) -> str:
    def sub(m):
        v = m.group(3)
        core = v.strip()
        if not core:
            return m.group(0)
        lead = v[:len(v) - len(v.lstrip())]
        trail = v[len(v.rstrip()):]
        return f"{m.group(1)}{m.group(2)}{lead}{_mask(core, kind, rep)}{trail}"
    return _COOKIE_PAIR.sub(sub, value)


def _set_cookie(value: str, kind: str, rep: Report) -> str:
    out = []
    for piece in _SETCOOKIE_SPLIT.split(value):
        if _SETCOOKIE_SPLIT.fullmatch(piece):
            out.append(piece)
            continue
        pair, sep, attrs = piece.partition(";")
        out.append(_cookie_values(pair, kind, rep) + sep + attrs)   # attributes are not secret
    return "".join(out)


def header_value(name: str, value: str, rep: Report) -> str:
    """One header's value, redacted if the header is sensitive. The caller decides which
    headers to keep (the identification header)."""
    n = _norm(name)
    if not value:
        return value
    if n == "cookie":
        return _cookie_values(value, name, rep)
    if n == "setcookie":
        return _set_cookie(value, name, rep)
    if not secret_name(name):
        return value
    if n in _AUTH_HEADERS:
        m = _SCHEME.match(value)
        if m:       # "Bearer <token>": the scheme stays readable
            return m.group(1) + _mask(m.group(2), name, rep) + m.group(3)
    return _mask(value, name, rep)


def headers(items, rep: Report, keep=()):
    """Headers as a dict or a list of (name, value) pairs, in the same shape."""
    keep = {k.lower() for k in keep}

    def one(k, v):
        return v if k.lower() in keep or not isinstance(v, str) else header_value(k, v, rep)
    if isinstance(items, dict):
        return {k: one(k, v) for k, v in items.items()}
    return [[k, one(k, v)] for k, v in items]


# ---- text ---------------------------------------------------------------------

# "Name: value" lines (raw HTTP pasted into a note or file).
_HEADER_LINE = re.compile(r"(?m)^([A-Za-z0-9][A-Za-z0-9_\-]{0,63})([ \t]*:[ \t]*)([^\r\n]*)")
# name=value: query strings, form bodies, cookies and configuration files. The lookbehind
# starts a name only at its first character (30x faster on long base64 runs).
_KV = re.compile(r"""(?<![\w.\-\[\]%])([A-Za-z0-9_.\-\[\]%]{1,64})=(?!=)("[^"\r\n]{0,4000}"|'[^'\r\n]{0,4000}'|[^&\s#"'<>;,)]*)""")
_JSON_KV = re.compile(r'("((?:[^"\\\r\n]|\\.){1,100})")(\s*:\s*)'
                      r'("(?:[^"\\]|\\.)*"|-?\d[0-9.eE+\-]{0,40}|\[[^\[\]{}]{0,20000}\])')
_JSON_SCALAR = re.compile(r'"(?:[^"\\]|\\.)*"|-?\d[0-9.eE+\-]{0,40}')
_HAR_HEADER = re.compile(r'("name"\s*:\s*"([^"\\\r\n]{1,100})"\s*,\s*"value"\s*:\s*")((?:[^"\\]|\\.)*)(")')

# A whole block, or, without its END line (cut off), the header and the base64 lines after it.
_PEM_BEGIN = re.compile(r"-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY-----")
_PEM_LINES = re.compile(r"(?:[ \t]*(?:\r?\n|\\n)[A-Za-z0-9+/=]{4,100})*")
PEM_MAX = 12_000        # an 8192-bit RSA key is about 6,500 characters
_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*(?:\.[A-Za-z0-9_\-]+){0,2}")
_BEARER = re.compile(r"(?i)\b(bearer)(\s+)([A-Za-z0-9\-._~+/]{16,4000}=*)")
_URL_PASSWORD = re.compile(r"(?<=://)([^\s:@/\"'<>\[\]]{1,200}):([^\s@/\"'<>]{1,400})@")
# Recon's credential formats (jsanalysis.REAL), except the ones covered above or that are
# not secrets themselves: the private key header, the service account marker, credentials
# in database URIs (the password is replaced, not the host).
_SKIP_REAL = {"Private key", "GCP service account JSON", "Database or broker URI with credentials"}
_FORMATS = [(re.compile(p), why) for p, _sev, why in jsanalysis.REAL if why not in _SKIP_REAL]

_EMAIL = re.compile(r"(?<![\w.%+\-])[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63}){0,8}"
                    r"\.[A-Za-z]{2,24}\b")
# Card networks start with 2 to 6; this keeps millisecond timestamps and most ids (1...) out.
_CARD = re.compile(r"(?<![\d.])(?:[2-6]\d{12,18}|[2-6]\d{3}([ \-])\d{4}\1\d{4}\1\d{4}|3[47]\d{2}([ \-])\d{6}\2\d{5})(?!\d)")


def luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _header_lines(s: str, rep: Report) -> str:
    def sub(m):
        name = m.group(1)
        n = _norm(name)
        header_like = n in ("cookie", "setcookie") or n in _AUTH_HEADERS or "-" in name or "_" in name
        if not header_like or not m.group(3):
            return m.group(0)
        new = header_value(name, m.group(3), rep)
        return m.group(0) if new == m.group(3) else m.group(1) + m.group(2) + new
    return _HEADER_LINE.sub(sub, s)


def _kv(s: str, rep: Report) -> str:
    def sub(m):
        name, v = m.group(1), m.group(2)
        if not secret_name(name):
            return m.group(0)
        if len(v) >= 2 and v[0] in "\"'" and v[-1] == v[0]:
            return f"{name}={v[0]}{_mask(v[1:-1], name, rep)}{v[0]}"
        return f"{name}={_mask(v, name, rep)}"
    return _KV.sub(sub, s)


def _json(s: str, rep: Report) -> str:
    def scalar(lit: str, kind: str) -> str:
        if lit.startswith('"'):
            return f'"{_mask(lit[1:-1], kind, rep)}"'
        return f'"{_mask(lit, kind, rep)}"'

    def sub(m):
        key, value = m.group(2), m.group(4)
        if not secret_name(key) or _norm(key) in JSON_NOT_SECRET:
            return m.group(0)
        if value.startswith("["):
            value = _JSON_SCALAR.sub(lambda x: scalar(x.group(0), key), value)
        else:
            value = scalar(value, key)
        return m.group(1) + m.group(3) + value

    def har(m):
        name, value = m.group(2), m.group(3)
        if not (secret_name(name) or _norm(name) in ("cookie", "setcookie")):
            return m.group(0)
        return m.group(1) + header_value(name, value, rep) + m.group(4)
    return _HAR_HEADER.sub(har, _JSON_KV.sub(sub, s))


def _pem(s: str, rep: Report) -> str:
    out, pos = [], 0
    for m in _PEM_BEGIN.finditer(s):
        if m.start() < pos:
            continue
        end = f"-----END {m.group(1)}PRIVATE KEY-----"
        j = s.find(end, m.end(), m.end() + PEM_MAX)      # bounded: many headers stay linear
        stop = j + len(end) if j >= 0 else _PEM_LINES.match(s, m.end()).end()
        out += [s[pos:m.start()], _mask(s[m.start():stop], "private key", rep)]
        pos = stop
    return "".join(out) + s[pos:] if out else s


def _formats(s: str, rep: Report) -> str:
    s = _pem(s, rep)
    s = _JWT.sub(lambda m: _mask(m.group(0), "JWT", rep), s)

    def bearer(m):
        tok = m.group(3)
        if not (len(tok) >= 32 or any(c.isdigit() for c in tok)):    # "Bearer authentication" is prose
            return m.group(0)
        return m.group(1) + m.group(2) + _mask(tok, "bearer token", rep)
    s = _BEARER.sub(bearer, s)
    s = _URL_PASSWORD.sub(lambda m: f"{m.group(1)}:{_mask(m.group(2), 'password in URL', rep)}@", s)
    for rx, why in _FORMATS:
        s = rx.sub(lambda m, why=why: _mask(m.group(0), why, rep), s)
    return s


def _personal(s: str, rep: Report) -> str:
    s = _EMAIL.sub(lambda m: _mask(m.group(0), "email address", rep), s)

    def card(m):
        digits = re.sub(r"\D", "", m.group(0))
        return _mask(m.group(0), "card number", rep) if 13 <= len(digits) <= 19 and luhn(digits) else m.group(0)
    return _CARD.sub(card, s)


def text(s: str, rep: Report, *, personal: bool = False) -> str:
    """Every rule over one piece of text: a URL, a note, a body, a summary."""
    if not s:
        return s
    s = _formats(_kv(_json(_header_lines(s, rep), rep), rep), rep)
    return _personal(s, rep) if personal else s


def looks_binary(data: bytes, filename: str | None = None) -> bool:
    ext = (filename or "").rsplit(".", 1)[-1].lower() if filename and "." in filename else ""
    if ext in BINARY_EXTENSIONS:
        return True
    sample = data[:8192]
    if b"\x00" in sample:
        return True
    s = sample.decode("utf-8", "replace")
    bad = s.count("�") + sum(1 for c in s if ord(c) < 32 and c not in "\t\n\r\f\b\x1b")
    return bad > len(s) * 0.1


def data(raw: bytes, rep: Report, *, personal: bool = False, filename: str | None = None,
         what: str = "binary content") -> bytes:
    """Bytes as stored: text is redacted (bytes that are not valid UTF-8 are kept as they
    are); binary content is kept unchanged and recorded as not redacted."""
    if not raw:
        return raw
    if looks_binary(raw, filename):
        rep.skipped(what)
        return raw
    s = raw.decode("utf-8", "surrogateescape")
    out = text(s, rep, personal=personal)
    return raw if out == s else out.encode("utf-8", "surrogateescape")


def walk(value, rep: Report):
    """Every string inside a JSON-like value (recon output stored in the database)."""
    if isinstance(value, str):
        return text(value, rep)
    if isinstance(value, list):
        return [walk(v, rep) for v in value]
    if isinstance(value, dict):
        return {k: walk(v, rep) for k, v in value.items()}
    return value
