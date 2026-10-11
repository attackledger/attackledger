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
  JSON         "key": value at any depth when the key is secret: strings, numbers, and every
               string and number inside an object or array under it, keys kept
               ("credentials": {...}, "password": [["..."]]); and HAR-style {"name": <secret
               header>, "value": ...}. "code" counts in query strings and forms only: in JSON
               it is a status code (and "assertion" is WebAuthn's).
  XML, HTML    the text of an element with a secret name (<wsse:Password>, <apiKey>, in
               CDATA too) when it holds no other element; an attribute with a secret name
               (spaces around "=" too, unquoted in HTML, data-* by what follows); the value
               after a secret <name> (XML-RPC) or <key> (plist); value= or content= of a tag
               whose name=, key= or property= is secret (<input name=csrf_token value=...>,
               <add key="DbPassword" value=...>); the whole content of a SAML <Assertion>,
               <EncryptedAssertion> or <Artifact> wherever it is (SOAP, WS-Security, ECP).
  XML-RPC      every string parameter of a call whose parameters are credentials by position:
               the WordPress, Blogger, MetaWeblog and Movable Type APIs (wp.getUsersBlogs(
               username, password)) and methods named for a login (system.login, auth.*,
               *Token, *Session), in system.multicall too.
  multipart    a field with a secret name, up to its boundary (every line of it).
  GraphQL      a string argument with a secret name written in the query, as it appears in
               JSON, in a GraphQL body and URL-encoded in a GET query.
  parameters   name=value in query strings, form bodies and text, when the name is secret
               (percent-encoded too). In a URL's query and a form body, the whole value up to
               the next "&"; in other text, the value ends where code or prose ends it.
  formats      JWTs, PEM private keys, bearer tokens, passwords in URLs (user:pass@), a SAML
               message in base64 under any name (it is decoded to see), and the credential
               formats recon already looks for (jsanalysis.REAL: AWS access key ids, Stripe,
               Slack, GitHub, GitLab, npm, ... tokens).
  personal     (response bodies and attached files only) email addresses, and runs of 13
               to 19 digits that pass the Luhn check and start like a card number.

What this does not do: general detection of personal data (names, addresses, phone
numbers), an XML element with a secret name that holds other elements (other than a SAML
assertion), JSON written as JavaScript (unquoted keys), secrets with no telling name, method
or format (an XML-RPC call of another API, a deflated SAML message under another name than
SAMLResponse), and binary content (images, PDFs, compressed bodies), which is stored as it is
and recorded as not redacted. A marker is a short hash: it does not reveal a strong secret,
but someone who guesses a weak value (a short password) can confirm the guess.

Everything here is linear in the size of the input: each rule is one regular expression
pass whose repetitions are bounded or anchored (measured at about 5 MB per second).
"""
import base64
import hashlib
import json
import re
from urllib.parse import quote, unquote, unquote_plus

from . import jsanalysis

# Names whose values are secret wherever they appear: a header, a query or form parameter,
# a JSON key. Compared in lower case with "-", "_" and "." removed, so api_key, api-key and
# apiKey are the same name. Exact names first, then parts: a name containing a part is
# secret too (access_token, X-Auth-Token, db_password, sessionid, X-Amz-Signature, and the
# key headers of Azure API Management and Azure Functions: Ocp-Apim-Subscription-Key, X-Functions-Key).
SECRET_NAMES = frozenset({
    "key", "pwd", "pass", "sid", "sig", "code", "auth", "jwt", "otp",
    "cookie", "setcookie", "authorization", "proxyauthorization",
    # A signed SAML response logs its bearer in, and the artifact fetches one (FZ-24). A SAML
    # assertion also travels as "assertion" (OAuth's SAML and JWT bearer grants) and inside
    # WS-Federation's "wresult"; "credentials" holds a login (third pass, FZ-41).
    "samlresponse", "samlart", "assertion", "wresult", "credential", "credentials",
})
SECRET_PARTS = ("token", "secret", "password", "passwd", "apikey", "session", "signature", "privatekey",
                "subscriptionkey", "functionskey", "masterkey")
# In JSON, "code" is nearly always a status or error code; it stays secret in query strings
# and form bodies, where it is the OAuth authorization code.
# A JSON "assertion" is WebAuthn's: bound to one challenge, and evidence of how a login was made.
JSON_NOT_SECRET = frozenset({"code", "assertion"})
# In XML, <Code> is an error code (S3, SOAP faults) and <Key> an object's name (an S3 listing).
# A SAML <Assertion> is replaced whole by its own rule (_xml), which knows it is SAML's.
XML_NOT_SECRET = frozenset({"code", "key", "assertion"})

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
    try:
        raw = value.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:      # a lone surrogate from JSON ("\ud800"), not from undecodable bytes
        raw = value.encode("utf-8", "surrogatepass")
    return f"{MARKER_PREFIX}{hashlib.sha256(raw).hexdigest()[:12]}]"


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
# Several Set-Cookie values joined into one: split before "name=", not inside an Expires date.
_SETCOOKIE_SPLIT = re.compile(r"(,\s*(?=[!#$%&'*+\-.^_`|~0-9A-Za-z]+=))")
# "Scheme credentials". Matched on the value without its trailing space: a lazy ".*?" followed
# by "\s*$" was quadratic in a run of spaces inside the value (fuzzing, FZ-6).
_SCHEME = re.compile(r"(\s*[A-Za-z][\w.\-]*\s+)(\S.*)", re.S)
# A header name (RFC 9110 token), with an HTTP/2 pseudo-header's leading colon.
_TOKEN = re.compile(r":?[!#$%&'*+\-.^_`|~0-9A-Za-z]+")


def _cookie_values(value: str, kind: str, rep: Report) -> str:
    """name=value pairs separated by ";": every value is replaced, names kept. A piece without
    "=" is a cookie without a name (RFC 6265 allows one, and document.cookie = "x" sends it),
    so it is replaced too (fuzzing, FZ-9)."""
    out = []
    for piece in value.split(";"):
        name, eq, v = piece.partition("=") if "=" in piece else ("", "", piece)
        core = v.strip()
        if core and (eq or not MARKER_RE.search(core)):     # a nameless piece already redacted stays
            lead, trail = v[:len(v) - len(v.lstrip())], v[len(v.rstrip()):]
            piece = f"{name}{eq}{lead}{_mask(core, kind, rep)}{trail}"
        out.append(piece)
    return ";".join(out)


def _set_cookie(value: str, kind: str, rep: Report) -> str:
    out = []
    for i, piece in enumerate(_SETCOOKIE_SPLIT.split(value)):
        if i % 2:                   # a separator (the split keeps them at the odd places)
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
        core = value.rstrip()
        m = _SCHEME.fullmatch(core)
        if m:       # "Bearer <token>": the scheme stays readable
            return m.group(1) + _mask(m.group(2), name, rep) + value[len(core):]
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
# A secret key whose value is an object or an array that holds more than scalars (FZ-44):
# "credentials": {"user": ..., "pin": ...}, "password": [["..."]]. Strings never cross a line end
# and an unclosed one ends there, so each search moves forward only.
_JSON_NESTED = re.compile(r'"((?:[^"\\\r\n]|\\.){1,100})"\s*:\s*([\[{])')
_JSON_STRING = r'"(?:[^"\\\r\n]|\\[^\r\n])*(?:"|(?=[\\\r\n])|\Z)'
_JSON_STRUCT = re.compile(_JSON_STRING + r'|[\[\]{}]')
_JSON_SPAN = re.compile(rf'({_JSON_STRING})(\s*:)?|(?<![\w.\-])-?\d[0-9.eE+\-]{{0,40}}')
JSON_NESTED_MAX = 1_000_000     # characters of one value looked through for its end
_HAR_HEADER = re.compile(r'("name"\s*:\s*"((?:[^"\\\r\n]|\\.){1,100})"\s*,\s*"value"\s*:\s*")((?:[^"\\]|\\.)*)(")')
# A form field in a multipart/form-data body: its headers (the name quoted or not), a blank
# line, then its value, which ends at the part's boundary. A file part is not a field.
_MULTIPART = re.compile(r'(?im)^(content-disposition[ \t]*:[^\r\n]{0,500}?;[ \t]*name=(?:"([^"\r\n]{1,100})"'
                        r'|([^\s;"]{1,100}))([^\r\n]{0,500})\r?\n(?:[^\r\n]{1,1000}\r?\n){0,10}\r?\n)')
MULTIPART_MAX = 64_000          # characters of one field's value that are looked through for its end

# XML and HTML (FZ-23). An opening tag: its name (with a namespace prefix) and its attributes,
# between two angle brackets, so each match reads at most up to the next "<" (linear).
_XML_OPEN = re.compile(r"<((?:[A-Za-z_][\w.\-]{0,63}:)?([A-Za-z_][\w.\-]{0,63}))((?:\s[^<>]{0,4000})?)>")
_XML_ATTR = re.compile(r"""(?<![\w.\-:])((?:[A-Za-z_][\w.\-]{0,63}:)?([A-Za-z_][\w.\-]{0,63}))([ \t\r\n]*=[ \t\r\n]*)"""
                       r"""("[^"<]{0,4000}"|'[^'<]{0,4000}'|[^\s"'=<>`]{1,4000})""")      # HTML: unquoted too (FZ-43)
# After <name>password</name> (XML-RPC) or <key>password</key> (a plist): the value element.
_XML_NEXT = re.compile(r"\s{0,200}(?:<value>\s{0,200})?<(string|value|base64|data)>([^<]{1,20000})</\1\s{0,20}>")
XML_MAX = 20_000                # characters of one element's text
# A SAML assertion (signed, it logs its subject in until it expires; encrypted, the service
# provider decrypts and accepts it as it is) and an artifact, which fetches one: their whole
# content is replaced, wherever the XML holds them (SOAP, WS-Security, ECP; FZ-41).
SAML_ELEMENTS = frozenset({"assertion", "encryptedassertion", "artifact"})
SAML_MAX = 200_000              # characters of one assertion looked through for its end
_XML_PAIR_NAMES = ("name", "key", "property")
_XML_PAIR_VALUES = ("value", "content")

# GraphQL string arguments with a secret name (FZ-27), written in the query: in a GraphQL body,
# inside a JSON string (the quotes escaped), and URL-encoded in a GET query. "$name: Type" is a
# variable's definition, not a value.
_GQL_ARGS = [
    re.compile(r'(?<![\w$])([A-Za-z_]\w{0,63})([ \t]*:[ \t]*")((?:[^"\\\r\n]|\\.){1,4000})(")'),
    re.compile(r'(?<![\w$])([A-Za-z_]\w{0,63})([ \t]*:[ \t]*\\")((?:[^"\\\r\n]|\\[^"\r\n]){1,4000})(\\")'),
    re.compile(r'(?:(?<=%20)|(?<=%2[Cc8])|(?<=%7[Bb])|(?<=%0[Aa])|(?<![\w$%]))'      # after a space , ( { or line end
               r'([A-Za-z_]\w{0,63})((?:%20|\+)*(?:%3[Aa]|:)(?:%20|\+)*%22)((?:(?!%22)[^&\s#"]){1,4000})(%22)'),
]

# A whole block, or, without its END line (cut off), the header and the base64 lines after it.
_PEM_BEGIN = re.compile(r"-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY-----")
_PEM_LINES = re.compile(r"(?:[ \t]*(?:\r?\n|\\n)[A-Za-z0-9+/=]{4,100})*")
PEM_MAX = 12_000        # an 8192-bit RSA key is about 6,500 characters
_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*(?:\.[A-Za-z0-9_\-]+){0,2}")
_BEARER = re.compile(r"(?i)\b(bearer)(\s+)([A-Za-z0-9\-._~+/]{16,4000}=*)")
# A SAML message or assertion in base64, under any name (a form field, a JSON value; FZ-41):
# base64 of XML starts with "P" ("<"). The start of each run is decoded, and the run is replaced
# when that names SAML's namespace. (The redirect binding's deflated messages travel as
# SAMLResponse and SAMLRequest, which the name rules cover.)
_B64_RUN = re.compile(r"(?<![A-Za-z0-9+/%])P(?:[A-Za-z0-9+/=]|%2[BbFfDd]|%3[Dd]|\r?\n|%0[Dd]%0[Aa]|%0[Aa]"
                      r"|(?:\\r)?\\n|\\/){99,}")         # wrapped, percent-encoded, or in a JSON string
SAML_B64_PEEK = 6000            # characters of a run that are decoded to look for SAML
_SAML_NS = b"urn:oasis:names:tc:SAML"
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


def _multipart(s: str, rep: Report) -> str:
    """Each field with a secret name, up to the line before its boundary: the "--" line that
    opened its part, found again after the value (FZ-25). Without one (a body cut off), up to
    the end when that is near, else the first line."""
    out, pos = [], 0
    absent: dict[str, int] = {}             # boundary -> no boundary line before this index
    for m in _MULTIPART.finditer(s):
        name = m.group(2) or m.group(3)
        if m.start() < pos or not secret_name(name) or "filename" in m.group(1).lower():
            continue
        start = m.end()
        opened = s.rfind("\n--", max(0, m.start() - 2000), m.start())
        line = s[opened + 1:s.find("\n", opened + 1)] if opened >= 0 else (
            s[:s.find("\n")] if s.startswith("--") else "")
        boundary = line.rstrip("\r")
        end = -1
        if boundary and absent.get(boundary, -1) < start:
            end = s.find("\n" + boundary, start, start + MULTIPART_MAX)
            if end < 0:
                absent[boundary] = min(len(s), start + MULTIPART_MAX)
        if end >= 0:
            end -= 1 if s[end - 1:end] == "\r" else 0
        elif len(s) - start <= MULTIPART_MAX:
            end = len(s.rstrip("\r\n")) if len(s.rstrip("\r\n")) > start else len(s)
        else:
            eol = s.find("\n", start, start + 4001)
            end = (eol - (s[eol - 1:eol] == "\r")) if eol >= 0 else min(len(s), start + 4000)
        value = s[start:end]
        if not value:
            continue
        out += [s[pos:start], _mask(value, name, rep)]
        pos = end
    return "".join(out) + s[pos:] if out else s


def _xml_secret(local: str) -> bool:
    return secret_name(local) and _norm(local) not in XML_NOT_SECRET


def _attr_value(m, attrs: str) -> tuple[int, int]:
    """Where an attribute's value is, without its quotes. Unquoted (HTML: name=password value=x,
    FZ-43), it ends before a "/" that closes the tag (<input value=x/>)."""
    a, b = m.start(4), m.end(4)
    if attrs[a] in "\"'":
        return a + 1, b - 1
    if b == len(attrs) and attrs[b - 1] == "/" and b - 1 > a:
        b -= 1
    return a, b


def _xml_attrs(attrs: str, rep: Report) -> str:
    found = list(_XML_ATTR.finditer(attrs))
    if not found:
        return attrs
    spans = [_attr_value(m, attrs) for m in found]
    # <input name="csrf_token" value=...>, <meta name="csrf-token" content=...>, <add key="DbPassword" value=...>
    pair = next((attrs[a:b] for m, (a, b) in zip(found, spans)
                 if m.group(2).lower() in _XML_PAIR_NAMES and secret_name(attrs[a:b])), None)
    out, pos = [], 0
    for m, (a, b) in zip(found, spans):
        local = m.group(2)
        # HTML's data-* attributes are named by what follows: data-pwd, data-sid (FZ-43).
        secret = _xml_secret(local[5:] if local[:5].lower() == "data-" else local)
        if (secret or (pair and local.lower() in _XML_PAIR_VALUES)) and b > a:
            out += [attrs[pos:a], _mask(attrs[a:b], local if secret else pair, rep)]
            pos = b
    return "".join(out) + attrs[pos:] if out else attrs


def _xml(s: str, rep: Report) -> str:
    """Secrets in XML and HTML (FZ-23): see the module's rules. One pass over the opening tags;
    each search for an element's end is bounded, and remembered when it fails, so the pass is
    linear in the input."""
    if "<" not in s:
        return s
    out, pos, i = [], 0, 0
    no_cdata_end = -1                   # no "]]>" before this index
    saml = "urn:oasis:names:tc:SAML" in s
    no_close: dict[str, int] = {}       # "</saml:Assertion" -> not found before this index
    while True:
        m = _XML_OPEN.search(s, i)
        if not m:
            break
        i = m.end()
        qname, local, attrs = m.group(1), m.group(2), m.group(3)
        if attrs:
            new = _xml_attrs(attrs, rep)
            if new != attrs and m.start(3) >= pos:
                out += [s[pos:m.start(3)], new]
                pos = m.end(3)
        if attrs.endswith("/"):
            continue
        low = local.lower()
        if low in SAML_ELEMENTS and (saml or "saml" in qname.lower()):
            close, a = "</" + qname, m.end()
            j = s.find(close, max(a, no_close.get(close, a)), a + SAML_MAX)
            if j < 0:
                no_close[close] = min(len(s), a + SAML_MAX)
                continue
            if s[j + len(close):j + len(close) + 1] not in (">", " ", "\t", "\r", "\n") or a < pos:
                continue
            if s[a:j].strip():
                out += [s[pos:a], _mask(s[a:j], local, rep)]
                pos = j
            i = max(i, j)
            continue
        if not (_xml_secret(local) or low in ("name", "key")):
            continue
        start = m.end()
        if s.startswith("<![CDATA[", start):
            a = start + 9
            j = -1 if no_cdata_end > a else s.find("]]>", a, a + XML_MAX)
            if j < 0:
                no_cdata_end = min(len(s), a + XML_MAX)
                continue
            v0, v1, close = a, j, j + 3
        else:
            j = s.find("<", start, start + XML_MAX)
            if j < 0:
                continue
            v0, v1, close = start, j, j
        if not s.startswith("</" + qname, close):
            continue
        after = close + 2 + len(qname)
        if after < len(s) and s[after] not in "> \t\r\n":
            continue
        text = s[v0:v1]
        core = text.strip()
        if not core:
            continue
        kind = local
        if low in ("name", "key") and not _xml_secret(local):
            # XML-RPC <member><name>password</name><value>..., a plist <key>password</key><string>...
            if not secret_name(core):
                continue
            end = s.find(">", after, after + 22)
            nxt = _XML_NEXT.match(s, end + 1) if end >= 0 else None
            if not nxt or not nxt.group(2).strip():
                continue
            v0, v1, text, kind = nxt.start(2), nxt.end(2), nxt.group(2), core
            core = text.strip()
            i = max(i, nxt.end())
        if v0 < pos:
            continue
        lead = text[:len(text) - len(text.lstrip())]
        out += [s[pos:v0], lead, _mask(core, kind, rep), text[len(lead) + len(core):]]
        pos = v1
    return "".join(out) + s[pos:] if out else s


# XML-RPC calls whose parameters are credentials by position (FZ-42): the WordPress, Blogger,
# MetaWeblog and Movable Type APIs take a user name and a password in every call
# (wp.getUsersBlogs(username, password), metaWeblog.newPost(blogid, username, password, ...)), and
# a method named for a login (system.login, auth.authenticate, user.getToken) takes its secret
# that way too. In such a call every string parameter is replaced: a parameter's own value, and
# each value of an array (system.multicall's params) directly in it. Numbers, booleans, dates and
# struct members with names that are not secret stay.
_RPC_METHOD = re.compile(r"<methodName>\s{0,200}([^<\s]{1,200})\s{0,200}</methodName>"
                         r"|<name>\s{0,200}methodName\s{0,200}</name>\s{0,200}<value>\s{0,200}(?:<string>)?"
                         r"\s{0,200}([^<\s]{1,200})\s{0,200}(?:</string>)?\s{0,200}</value>")
_RPC_SCALAR = re.compile(r"(?:(?<=<param>)|(?<=<data>)|(?<=</value>))\s{0,200}<value>(?:\s{0,200}<(string|base64)>([^<]{0,20000})"
                         r"</\1\s{0,20}>\s{0,200}|([^<]{1,20000}))</value>")
_RPC_APIS = ("wp.", "blogger.", "metaweblog.", "mt.")
_RPC_WORDS = ("login", "logon", "signin", "auth", "password", "passwd", "credential", "token", "session",
              "secret", "apikey")


def rpc_secret_method(name: str) -> bool:
    """A method whose parameters are credentials by position (FZ-42)."""
    low = name.lower()
    return low.startswith(_RPC_APIS) or any(w in _norm(low) for w in _RPC_WORDS)


def _xmlrpc(s: str, rep: Report) -> str:
    if "ethodName" not in s:
        return s
    calls = list(_RPC_METHOD.finditer(s))
    out, pos = [], 0
    for k, m in enumerate(calls):
        name = m.group(1) or m.group(2)
        if not rpc_secret_method(name):
            continue
        end = calls[k + 1].start() if k + 1 < len(calls) else len(s)
        for v in _RPC_SCALAR.finditer(s, m.end(), end):
            g = 2 if v.group(1) else 3
            text = v.group(g)
            core = text.strip()
            if not core or v.start(g) < pos:
                continue
            lead = text[:len(text) - len(text.lstrip())]
            out += [s[pos:v.start(g)], lead, _mask(core, name, rep), text[len(lead) + len(core):]]
            pos = v.end(g)
    return "".join(out) + s[pos:] if out else s


def _graphql(s: str, rep: Report) -> str:
    if ":" not in s and "%3" not in s:
        return s

    def sub(m):
        name = m.group(1)
        if not secret_name(name) or _norm(name) in JSON_NOT_SECRET:
            return m.group(0)
        return m.group(1) + m.group(2) + _mask(m.group(3), name, rep) + m.group(4)
    for rx in _GQL_ARGS:
        s = rx.sub(sub, s)
    return s


def _json_name(raw: str) -> str:
    """A JSON key as the reader of the JSON sees it: "\\u0074oken" is "token" (FZ-10)."""
    if "\\" not in raw:
        return raw
    try:
        return json.loads(f'"{raw}"')
    except ValueError:
        return raw


def _kv(s: str, rep: Report) -> str:
    def sub(m):
        name, v = m.group(1), m.group(2)
        if not (secret_name(name) or ("%" in name and secret_name(unquote(name)))):     # pass%77ord (FZ-26)
            return m.group(0)
        if len(v) >= 2 and v[0] in "\"'" and v[-1] == v[0]:
            return f"{name}={v[0]}{_mask(v[1:-1], name, rep)}{v[0]}"
        return f"{name}={_mask(v, name, rep)}"
    return _KV.sub(sub, s)


def params(q: str, rep: Report) -> str:
    """A URL's query or a form body (application/x-www-form-urlencoded): each value whose name
    is secret, decoded, is replaced whole, up to the next "&" (FZ-26). The text rules stop a
    value at ; , ) ' # " < and spaces, which end one in code and prose but not in a form a
    client sent without encoding them; the rest of such a password was kept."""
    if "=" not in q:
        return q
    out = []
    for piece in q.split("&"):
        name, eq, value = piece.partition("=")
        core = value.rstrip()
        if eq and core and secret_name(unquote_plus(name)):
            piece = f"{name}={_mask(core, name, rep)}{value[len(core):]}"
        out.append(piece)
    return "&".join(out)


def _json_nested(s: str, rep: Report) -> str:
    """Every string and number inside an object or array under a secret key, keys kept (FZ-44).
    Its end is found by counting brackets outside strings, at most JSON_NESTED_MAX characters on;
    one that does not end there (a body cut off) is replaced up to where the search stopped. The
    spans replaced never overlap, so each character is looked at a bounded number of times."""
    if "{" not in s and "[" not in s:
        return s
    out, pos = [], 0
    for m in _JSON_NESTED.finditer(s):
        key = _json_name(m.group(1))
        if m.start() < pos or not secret_name(key) or _norm(key) in JSON_NOT_SECRET:
            continue
        start, depth, end = m.start(2), 0, -1
        limit = min(len(s), start + JSON_NESTED_MAX)
        for t in _JSON_STRUCT.finditer(s, start, limit):
            c = t.group(0)
            if c in "[{":
                depth += 1
            elif c in "]}":
                depth -= 1
                if depth == 0:
                    end = t.end()
                    break
        end = limit if end < 0 else end

        def sub(x, key=key):
            if x.group(2):                          # a key
                return x.group(0)
            if x.group(1) is None:                  # a number, replaced by a string as _json does
                return f'"{_mask(x.group(0), key, rep)}"'
            lit = x.group(1)
            close = '"' if len(lit) > 1 and lit.endswith('"') else ""
            return '"' + _mask(lit[1:len(lit) - len(close)], key, rep) + close
        out += [s[pos:start], _JSON_SPAN.sub(sub, s[start:end])]
        pos = end
    return "".join(out) + s[pos:] if out else s


def _json(s: str, rep: Report) -> str:
    s = _json_nested(s, rep)

    def scalar(lit: str, kind: str) -> str:
        if lit.startswith('"'):
            return f'"{_mask(lit[1:-1], kind, rep)}"'
        return f'"{_mask(lit, kind, rep)}"'

    def sub(m):
        key, value = _json_name(m.group(2)), m.group(4)
        if not secret_name(key) or _norm(key) in JSON_NOT_SECRET:
            return m.group(0)
        if value.startswith("["):
            value = _JSON_SCALAR.sub(lambda x: scalar(x.group(0), key), value)
        else:
            value = scalar(value, key)
        return m.group(1) + m.group(3) + value

    def har(m):
        name, value = _json_name(m.group(2)), m.group(3)
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


def saml_base64(run: str) -> bool:
    """Whether a base64 run (percent-encoded or not, wrapped or not) starts a SAML message."""
    head = re.sub(r"\s|\\[rn]", "", unquote(run[:SAML_B64_PEEK])).replace("\\/", "/")
    head = head[:len(head) - len(head) % 4]
    try:
        raw = base64.b64decode(head)
    except ValueError:
        return False
    return _SAML_NS in raw


def _saml_runs(s: str, rep: Report) -> str:
    if "P" not in s:
        return s
    return _B64_RUN.sub(lambda m: _mask(m.group(0), "SAML message (base64)", rep) if saml_base64(m.group(0))
                        else m.group(0), s)


def _formats(s: str, rep: Report) -> str:
    s = _saml_runs(_pem(s, rep), rep)
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
    s = _formats(_kv(_graphql(_json(_xml(_xmlrpc(_header_lines(_multipart(s, rep), rep), rep), rep), rep), rep), rep),
                 rep)
    return _personal(s, rep) if personal else s


_AUTHORITY = re.compile(r"(\s*[A-Za-z][A-Za-z0-9+.\-]*://)([^/?#\\]*)(.*)", re.S)


def url(u: str, rep: Report) -> str:
    """A URL for storage: the text rules on everything after the authority, and a password
    in the authority replaced. The host itself is kept as it is: it names a place in scope,
    not a secret, and a rule matching inside it (a label shaped like an AWS key id or a Slack
    token) made the stored URL name no host (fuzzing, FZ-7)."""
    m = _AUTHORITY.fullmatch(u or "")
    if not m:
        return text(u, rep)
    start, authority, rest = m.groups()
    userinfo, at, hostport = authority.rpartition("@")
    if at:
        user, colon, password = userinfo.partition(":")
        if colon and password and not MARKER_RE.fullmatch(unquote(password)):
            # Percent-encoded: a marker's brackets in the authority make Python's urlsplit
            # refuse the whole URL ("Invalid IPv6 URL"), so the stored URL named no host.
            password = quote(_mask(password, "password in URL", rep), safe=":")
        userinfo = text(user, rep) + colon + password
    path, q, query = rest.partition("?")
    if q:
        query, h, fragment = query.partition("#")
        rest = path + q + params(query, rep) + h + fragment
    return start + userinfo + at + hostport + text(rest, rep)


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
         what: str = "binary content", form: bool = False) -> bytes:
    """Bytes as stored: text is redacted (bytes that are not valid UTF-8 are kept as they
    are); binary content is kept unchanged and recorded as not redacted. form: the body of a
    message whose Content-Type is application/x-www-form-urlencoded."""
    if not raw:
        return raw
    if looks_binary(raw, filename):
        rep.skipped(what)
        return raw
    s = raw.decode("utf-8", "surrogateescape")
    out = text(params(s, rep) if form else s, rep, personal=personal)
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


# ---- raw HTTP messages ----------------------------------------------------------------

_HEAD_END = re.compile(rb"\r?\n\r?\n")


def _header_line(line: str, rep: Report) -> str:
    # HTTP/2 pseudo-headers (":authority: x") start with a colon that is part of the name.
    name, sep, value = (line[1:].partition(":") if line.startswith(":") else line.partition(":"))
    name = (":" + name) if line.startswith(":") else name
    if not sep or not _TOKEN.fullmatch(name.strip()):
        # Not "Name: value": a line that only contains a colon ("password=a:b", or a marker,
        # whose text has colons) is text; read as a header, its first part was kept (FZ-8).
        return text(line, rep)
    lead = value[:len(value) - len(value.lstrip())]
    v = value.strip()
    new = header_value(name.strip(), v, rep)
    if new == v:            # not a secret header: a token or a secret parameter may still be in it
        new = text(v, rep)
    return f"{name}{sep}{lead}{new}"


def http_message(raw: bytes | None, rep: Report, *, personal: bool = False,
                 what: str = "binary body") -> bytes | None:
    """One raw HTTP request or response, as an import or a proxy recorded it. Every header
    line is a header, so each one goes through the header rules whatever its name; the
    start line (the URL) and the body go through the text rules; a binary or compressed
    body is kept as it is and noted."""
    if not raw:
        return raw
    m = _HEAD_END.search(raw)
    head_b, sep, body = (raw[:m.start()], raw[m.start():m.end()], raw[m.end():]) if m else (raw, b"", b"")
    head = head_b.decode("utf-8", "surrogateescape")
    lines = re.split(r"(\r?\n)", head)
    out = [text(start_line(lines[0], rep), rep)] if lines else []
    for i, part in enumerate(lines[1:], start=1):
        out.append(part if i % 2 else _header_line(part, rep))
    form = any(_FORM_TYPE.match(lines[i]) for i in range(2, len(lines), 2))
    new_body = data(body, rep, personal=personal, what=what, form=form)
    if new_body != body:
        _fix_content_length(out, len(body), len(new_body))
    new_head = "".join(out).encode("utf-8", "surrogateescape")
    return new_head + sep + new_body


_FORM_TYPE = re.compile(r"(?i)content-type[ \t]*:[ \t]*application/x-www-form-urlencoded\b")
_REQUEST_LINE = re.compile(r"([A-Za-z]{1,20} +)([^ ?]*\?)([^ ]*)(.*)", re.S)


def start_line(line: str, rep: Report) -> str:
    """A request line's query, read as a query (params): everything after "?" in the target,
    as servers read it; a request target has no fragment."""
    m = _REQUEST_LINE.fullmatch(line)
    return line if not m else m.group(1) + m.group(2) + params(m.group(3), rep) + m.group(4)


_CONTENT_LENGTH = re.compile(r"(content-length[ \t]*:[ \t]*)([0-9]{1,18})([ \t]*)", re.I)   # FZ-2


def _fix_content_length(lines: list[str], before: int, after: int) -> None:
    """Redaction changed the body's length, so a Content-Length that described it now
    describes the old body. Rewrite it to the stored body's length. A value that did not
    match the body before (an export that decoded or cut it) is left as the tool wrote it."""
    for i in range(2, len(lines), 2):
        m = _CONTENT_LENGTH.fullmatch(lines[i])
        if m and int(m.group(2)) == before:
            lines[i] = f"{m.group(1)}{after}{m.group(3)}"
