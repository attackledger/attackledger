"""The traffic gateway (D-039, docs/GATEWAY.md): the only way out of the worker.

The worker container has no route to the internet. Every request a recon tool or the agent
sends leaves through this process, which enforces the engagement's rules in one place:

  scope      the host must be in the engagement's scope (exclusions win), or an allowlisted
             passive source (passive modules) or the Claude API (agent runs);
  methods    GET, HEAD and OPTIONS only, with no body, no method override, no Upgrade.
             Every write is refused until a person can approve it (D-041);
  rate       one limiter per engagement, shared by every tool and worker: no window of
             WINDOW seconds holds more than the engagement's requests per second;
  identity   the research header and user agent are always set from the rules; whatever the
             tool sent under those names is removed first.

It logs every request, probe and DNS question, allowed or refused, with the reason, through
the API (POST /gateway/log). It holds no database credentials: who a job credential belongs
to, and that engagement's rules, come from the API (POST /gateway/session).

How a tool reaches it:

  http://host/...    absolute-form request to the proxy, with Proxy-Authorization
  https://host/...   CONNECT host:port, then TLS with a certificate from the gateway's own CA
                     (trusted only inside the worker). A tunnel that does not start TLS is
                     closed: no byte is ever relayed without being parsed.
  port probe         CONNECT host:port with "X-AttackLedger-Probe: connect": the gateway opens
                     a TCP connection, answers 200 (open) or 502 (closed) and closes it.
  DNS                UDP port 53: A, AAAA and CNAME questions for names in scope of an
                     engagement that has a running job.

Credentials are HTTP Basic: user "job-<id>.<tool>", password the job's secret. The tool name
is self-declared and only used for the log.

Everything is HTTP/1.1, parsed and written by h11. One upstream connection per request, opened
only after every check passed, to the address the gateway resolved and checked itself.

Run: python -m app.gateway
"""
import asyncio
import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import struct
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections import OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, urlsplit

import h11

from . import redact, scope

READ_ONLY = frozenset({"GET", "HEAD", "OPTIONS"})
# Never forwarded: they describe one hop, not the request (RFC 9110 7.6.1), or carry our credential.
HOP_BY_HOP = frozenset({"connection", "keep-alive", "proxy-authorization", "proxy-authenticate", "proxy-connection",
                        "te", "trailer", "transfer-encoding", "upgrade", "expect", "host", "content-length"})
OVERRIDE_HEADERS = frozenset({"x-http-method-override", "x-http-method", "x-method-override"})
PROBE_HEADER = b"x-attackledger-probe"
REFUSED_HEADER = "X-AttackLedger-Gateway"
REALM = 'Basic realm="AttackLedger gateway"'
USER_RE = re.compile(r"^job-(\d{1,12})(?:\.([a-z0-9][a-z0-9-]{0,31}))?$")

WINDOW = 1.05            # no window this long holds more than the rate: 50 ms for network jitter
MAX_WAIT = 30.0          # a request that would wait longer for a rate token is refused (429)
DNS_MAX_WAIT = 2.0       # DNS clients give up after a few seconds
PASSIVE_RPS = 10         # per passive-source host; not counted against any engagement
RULES_TTL = 2.0          # a cancelled job or a changed rule takes effect within this
DNS_SCOPES_TTL = 3.0
LOG_BACKLOG = 5000       # unsent log rows; above this, nothing is sent (fail closed)
LOG_BATCH = 500
CONNECT_TIMEOUT = 10.0
PROBE_TIMEOUT = 3.0
READ_TIMEOUT = 60.0      # between two reads from either side
HANDSHAKE_TIMEOUT = 10.0
MAX_HEAD = 64 * 1024
MAX_SERVICE_BODY = 20 * 1024 * 1024
SMTP_PORT = 25

# Hosts compiled into subfinder, assetfinder, gau and waybackurls that answer without a key
# (and the keyed ones an operator may configure). GET only, port 443 only, not target traffic.
PASSIVE_HOSTS = frozenset({
    "crt.sh", "api.certspotter.com", "certspotter.com", "api.hackertarget.com", "otx.alienvault.com",
    "web.archive.org", "archive.org", "index.commoncrawl.org", "rapiddns.io", "www.sitedossier.com",
    "jonlu.ca", "certificatedetails.com", "leakix.net", "api.subdomain.center", "columbus.elmasy.com",
    "dnsrepo.noc.org", "urlscan.io", "www.threatcrowd.org", "dns.bufferover.run", "tls.bufferover.run",
    "www.virustotal.com", "api.securitytrails.com", "api.shodan.io", "search.censys.io", "fullhunt.io",
    "api.binaryedge.io", "app.netlas.io", "api.c99.nl", "api.passivetotal.org", "proapi.robtex.com",
})
SERVICE_HOSTS = frozenset({"api.anthropic.com"})
# The Claude API calls an agent run makes (agentloop: client.beta.messages.create).
SERVICE_ROUTES = (("POST", "/v1/messages"), ("POST", "/v1/messages/count_tokens"))
DENY_HOSTS = ("db", "api", "web", "worker", "gateway")
DNS_TYPES = {1: "A", 5: "CNAME", 28: "AAAA"}


class Refused(Exception):
    """The request is not sent. status and reason go back to the tool and into the log."""

    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status, self.reason = status, reason


@dataclass(frozen=True)
class Rules:
    """One job's view of its engagement, as the API gave it (POST /gateway/session)."""
    job_id: int
    engagement_id: int
    kind: str                 # job kind (module kind, or "agent")
    traffic: str              # passive, dns, target or agent (modules.py)
    include: tuple
    exclude: tuple
    rate_limit_rps: int
    research_header: str | None
    research_user_agent: str | None
    redact: bool = True

    @classmethod
    def from_api(cls, d: dict) -> "Rules":
        return cls(job_id=int(d["job_id"]), engagement_id=int(d["engagement_id"]), kind=str(d["kind"]),
                   traffic=str(d["traffic"]), include=tuple(d.get("include") or ()),
                   exclude=tuple(d.get("exclude") or ()), rate_limit_rps=max(1, int(d["rate_limit_rps"])),
                   research_header=d.get("research_header") or None,
                   research_user_agent=d.get("research_user_agent") or None, redact=bool(d.get("redact", True)))

    def identification(self) -> list[tuple[str, str]]:
        """The headers every target request carries (D-008). Empty: no target traffic at all."""
        out = []
        if self.research_header:
            name, sep, value = self.research_header.partition(":")
            if sep and name.strip() and not any(c in self.research_header for c in "\r\n\0"):
                out.append((name.strip(), value.strip()))
        if self.research_user_agent and not any(c in self.research_user_agent for c in "\r\n\0"):
            out.append(("User-Agent", self.research_user_agent.strip()))
        return out


class Limiter:
    """A token bucket with `rate` tokens, each returned WINDOW seconds after it was spent.

    So no WINDOW-second window (and no one-second window measured downstream) holds more than
    `rate` requests: the hard ceiling of D-014. A bucket that refills continuously with a burst
    of B lets B + rate requests into one second. Waiters are served in order."""

    def __init__(self, rate: int, window: float = WINDOW, clock=time.monotonic, sleep=asyncio.sleep):
        self.rate, self.window, self.clock, self.sleep = max(1, int(rate)), window, clock, sleep
        self.spent: deque[float] = deque()
        self.lock = asyncio.Lock()

    async def acquire(self, max_wait: float = MAX_WAIT) -> float:
        start = self.clock()
        async with self.lock:
            now = self.clock()
            while len(self.spent) >= self.rate:
                back = self.spent[0] + self.window
                if back <= now:
                    self.spent.popleft()
                    continue
                if now - start + (back - now) > max_wait:
                    raise Refused(429, f"rate ceiling of {self.rate}/s: the queue is longer than "
                                       f"{max_wait:.0f} seconds")
                await self.sleep(back - now)
                now = self.clock()
            self.spent.append(now)
            return now


# ---- certificates -----------------------------------------------------------------

class CA:
    """The deployment's interception CA, created on first start. Only the worker trusts it.

    The private key stays in `private_dir` (a volume only the gateway mounts); the certificate
    is copied to `public_dir` for the worker. Leaf certificates are made per host on demand."""

    LEAF_DAYS = 30

    def __init__(self, private_dir: str, public_dir: str | None = None):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
        self._x509, self._hashes, self._ser, self._ec = x509, hashes, serialization, ec
        self._eku, self._name = ExtendedKeyUsageOID, NameOID
        os.makedirs(private_dir, exist_ok=True)
        key_path, cert_path = os.path.join(private_dir, "ca.key"), os.path.join(private_dir, "ca.pem")
        if os.path.exists(key_path) and os.path.exists(cert_path):
            with open(key_path, "rb") as f:
                self.key = serialization.load_pem_private_key(f.read(), None)
            with open(cert_path, "rb") as f:
                self.cert = x509.load_pem_x509_certificate(f.read())
        else:
            self.key, self.cert = self._create()
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
            with open(cert_path, "wb") as f:
                f.write(self.cert_pem)
        if public_dir:
            os.makedirs(public_dir, exist_ok=True)
            tmp = os.path.join(public_dir, ".ca.pem.tmp")
            with open(tmp, "wb") as f:
                f.write(self.cert_pem)
            os.chmod(tmp, 0o644)
            os.replace(tmp, os.path.join(public_dir, "ca.pem"))
        self.leaf_key = ec.generate_private_key(ec.SECP256R1())
        self._dir = tempfile.mkdtemp(prefix="al-gateway-leaf-")       # 0700
        self._contexts: OrderedDict[str, tuple[float, ssl.SSLContext]] = OrderedDict()

    @property
    def cert_pem(self) -> bytes:
        return self.cert.public_bytes(self._ser.Encoding.PEM)

    def _create(self):
        x509, ec, hashes = self._x509, self._ec, self._hashes
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(self._name.ORGANIZATION_NAME, "AttackLedger"),
                          x509.NameAttribute(self._name.COMMON_NAME,
                                             f"AttackLedger gateway CA {secrets.token_hex(4)}")])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(hours=1)).not_valid_after(now + timedelta(days=5 * 365))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                             content_commitment=False, key_encipherment=False,
                                             data_encipherment=False, key_agreement=False,
                                             encipher_only=False, decipher_only=False), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                .sign(key, hashes.SHA256()))
        return key, cert

    def leaf_pem(self, host: str) -> bytes:
        x509, hashes = self._x509, self._hashes
        try:
            san = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            san = x509.DNSName(host)
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(self._name.COMMON_NAME, host[:64])]))
                .issuer_name(self.cert.subject).public_key(self.leaf_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(hours=1)).not_valid_after(now + timedelta(days=self.LEAF_DAYS))
                .add_extension(x509.SubjectAlternativeName([san]), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage([self._eku.SERVER_AUTH]), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()),
                               critical=False)
                .sign(self.key, hashes.SHA256()))
        return cert.public_bytes(self._ser.Encoding.PEM)

    def server_context(self, host: str) -> ssl.SSLContext:
        """A TLS server context presenting a certificate for `host`, offering only HTTP/1.1."""
        hit = self._contexts.get(host)
        if hit and hit[0] > time.time():
            self._contexts.move_to_end(host)
            return hit[1]
        path = os.path.join(self._dir, hashlib.sha256(host.encode()).hexdigest() + ".pem")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(self.leaf_pem(host) + self.cert_pem + self.leaf_key.private_bytes(
                self._ser.Encoding.PEM, self._ser.PrivateFormat.PKCS8, self._ser.NoEncryption()))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(path)
        os.unlink(path)
        ctx.set_alpn_protocols(["http/1.1"])
        self._contexts[host] = (time.time() + (self.LEAF_DAYS - 1) * 86400, ctx)
        while len(self._contexts) > 1024:
            self._contexts.popitem(last=False)
        return ctx


def _client_contexts() -> tuple[ssl.SSLContext, ssl.SSLContext]:
    """(verifying, not verifying) upstream TLS contexts, HTTP/1.1 only."""
    try:
        import certifi
        verify = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        verify = ssl.create_default_context()
    insecure = ssl.create_default_context()
    insecure.check_hostname = False        # targets often have odd certificates; the tools used -k
    insecure.verify_mode = ssl.CERT_NONE
    for c in (verify, insecure):
        c.set_alpn_protocols(["http/1.1"])
    return verify, insecure


# ---- the API: rules in, log out ---------------------------------------------------

class Api:
    """The gateway's only channel to the rest of AttackLedger (D-042: no database access)."""

    def __init__(self, base: str, token: str | None):
        self.base, self.token = base.rstrip("/"), token

    def _call(self, method: str, path: str, body=None) -> tuple[int, dict | list]:
        if not self.token:
            return 0, {"detail": "no gateway token is configured"}
        req = urllib.request.Request(self.base + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"authorization": f"Bearer {self.token}",
                                              "content-type": "application/json"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # never through a proxy
        try:
            with opener.open(req, timeout=10) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except ValueError:
                return e.code, {"detail": f"HTTP {e.code}"}
        except (OSError, ValueError) as e:
            return 0, {"detail": f"API unreachable: {str(e)[:120] or type(e).__name__}"}

    async def session(self, job_id: int, secret: str):
        return await asyncio.to_thread(self._call, "POST", "/gateway/session", {"job_id": job_id, "secret": secret})

    async def dns_scopes(self):
        return await asyncio.to_thread(self._call, "GET", "/gateway/dns-scopes")

    async def post_log(self, rows: list[dict]):
        return await asyncio.to_thread(self._call, "POST", "/gateway/log", {"rows": rows})


def gateway_token(create: bool = False) -> str | None:
    """ATTACKLEDGER_GATEWAY_TOKEN, or the token file in the volume the gateway shares with the
    API only. The gateway creates the file on first start; the API only reads it."""
    tok = os.environ.get("ATTACKLEDGER_GATEWAY_TOKEN", "").strip()
    if tok:
        return tok
    path = os.environ.get("ATTACKLEDGER_GATEWAY_TOKEN_FILE", "/data/gateway-control/token")
    try:
        with open(path) as f:
            return f.read().strip() or None
    except FileNotFoundError:
        if not create:
            return None
    except OSError:
        return None
    os.makedirs(os.path.dirname(path), exist_ok=True)
    value = secrets.token_urlsafe(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
    with os.fdopen(fd, "w") as f:
        f.write(value)
    return value


# ---- policy -------------------------------------------------------------------------

def _header(headers, name: bytes) -> str | None:
    for k, v in headers:
        if k == name:
            return v.decode("latin-1")
    return None


def split_authority(authority: str, default_port: int | None = None) -> tuple[str, int]:
    """host[:port] (or [v6]:port) -> (lower-case host, port). Raises Refused."""
    a = authority.strip()
    if not a or any(c in a for c in "/@?#\\ \t"):
        raise Refused(400, "not a valid host and port")
    if a.startswith("["):
        host, _, rest = a[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    else:
        host, _, port = a.rpartition(":") if a.count(":") == 1 else (a, "", "")
    if not port:
        if default_port is None:
            raise Refused(400, "a port is required")
        port = str(default_port)
    if not port.isdigit() or not 0 < int(port) < 65536:
        raise Refused(400, "not a valid port")
    return host.lower().rstrip("."), int(port)


class Policy:
    """What may be sent. One place, so the hooks for D-040 and D-041 have one home too."""

    def __init__(self, passive_hosts=PASSIVE_HOSTS, service_hosts=SERVICE_HOSTS):
        self.passive_hosts, self.service_hosts = frozenset(passive_hosts), frozenset(service_hosts)

    def classify(self, rules: Rules, host: str, port: int, scheme: str) -> str:
        """target, passive or service; Refused otherwise."""
        if port == SMTP_PORT:
            raise Refused(403, "port 25 (SMTP) is never contacted")
        if scope.in_scope(host, list(rules.include), list(rules.exclude)):
            if rules.traffic not in ("target", "agent"):
                raise Refused(403, f"a {rules.kind} job sends no traffic to targets")
            return "target"
        if host in self.passive_hosts:
            if rules.traffic not in ("passive", "dns"):
                raise Refused(403, f"{host} is a passive source; a {rules.kind} job does not use passive sources")
            if scheme != "https" or port != 443:
                raise Refused(403, f"passive sources are reached over HTTPS on port 443 only")
            return "passive"
        if host in self.service_hosts:
            if rules.traffic != "agent" or scheme != "https" or port != 443:
                raise Refused(403, f"{host} is reachable from agent runs only, over HTTPS")
            return "service"
        raise Refused(403, f"{host} is not in scope")

    def check(self, rules: Rules, kind: str, method: str, path: str, headers) -> None:
        """Method, body and header rules for one request."""
        if kind == "service":
            if not any(method == m and (path == p or path.startswith(p + "?")) for m, p in SERVICE_ROUTES):
                raise Refused(403, f"{method} {path.split('?')[0][:100]} is not a Claude API call an agent run makes")
            return
        if method not in READ_ONLY:
            if self.approved_write(rules, method, path, None) is None:
                raise Refused(403, f"{method[:20]} is refused: only GET, HEAD and OPTIONS are sent; writes need a "
                                   f"person's approval (D-041), which is not built yet")
        if path.startswith("*"):
            raise Refused(403, "asterisk-form requests are not sent")
        names = {k for k, _ in headers}
        if b"upgrade" in names:
            raise Refused(403, "protocol upgrades (WebSocket, h2c) are not sent")
        if b"transfer-encoding" in names or int(_header(headers, b"content-length") or 0) > 0:
            raise Refused(403, "read-only requests are sent without a body")
        for k, v in headers:
            if k.decode("latin-1") in OVERRIDE_HEADERS and v.decode("latin-1").strip().upper() not in READ_ONLY:
                raise Refused(403, f"method override to {v.decode('latin-1')[:20]} is refused")
        query = urlsplit(path).query
        for k, v in parse_qsl(query, keep_blank_values=True):
            if k.lower() == "_method" and v.strip().upper() not in READ_ONLY:
                raise Refused(403, f"_method={v[:20]} is refused")
        if kind == "target" and not rules.identification():
            raise Refused(403, "the engagement has no research header or user agent; nothing is sent to targets")

    def headers(self, rules: Rules, kind: str, headers, host_header: str) -> list[tuple[bytes, bytes]]:
        """The headers sent upstream: the tool's (as received), minus hop-by-hop and
        identification names, then Host, the identification (targets) and Connection: close."""
        drop = set(HOP_BY_HOP)
        conn = _header(headers, b"connection") or ""
        drop |= {t.strip().lower() for t in conn.split(",") if t.strip()}
        ident = [(n.encode(), v.encode()) for n, v in rules.identification()] if kind == "target" else []
        drop |= {n.decode().lower() for n, _ in ident}
        out = [(b"Host", host_header.encode("idna" if not host_header.isascii() else "ascii"))]
        out += [(k, v) for k, v in headers if k.decode("latin-1") not in drop]
        out += ident
        out = self.inject_credentials(rules, kind, out)
        out.append((b"Connection", b"close"))
        return out

    # ---- hooks for later decisions -------------------------------------------------

    def inject_credentials(self, rules: Rules, kind: str, headers: list) -> list:
        """D-040: a test account's session (cookie or token) will be added here, to allowed
        target requests that ask for it. The log never holds header values. Not built yet."""
        return headers

    def approved_write(self, rules: Rules, method: str, path: str, body_sha256: str | None):
        """D-041: the person's approval for exactly this write, sent once. The approval queue
        is not built yet, so there is none and every write is refused."""
        return None


# ---- the gateway --------------------------------------------------------------------

@dataclass
class Tunnel:
    host: str
    port: int
    auth: str | None


class Gateway:
    def __init__(self, api: Api, ca: CA | None, *, policy: Policy | None = None,
                 deny_hosts=DENY_HOSTS, upstream_dns: str | None = None, clock=time.monotonic):
        self.api, self.ca, self.policy = api, ca, policy or Policy()
        self.deny_hosts = tuple(deny_hosts)
        self.upstream_dns = upstream_dns or _resolv_conf_nameserver()
        self.clock = clock
        self.verify_ctx, self.insecure_ctx = _client_contexts()
        self.limiters: dict[int, Limiter] = {}
        self.dns_limiters: dict[int, Limiter] = {}
        self.passive_limiters: dict[str, Limiter] = {}
        self._rules: dict[tuple, tuple[float, Rules | Refused]] = {}
        self._rules_locks: dict[tuple, asyncio.Lock] = {}
        self._dns_scopes: tuple[float, list] = (0.0, [])
        self._denied: tuple[float, set] = (0.0, set())
        self.log_rows: list[dict] = []
        self.dropped = 0
        # Upstream connector, replaced in tests.
        self.open_connection = asyncio.open_connection

    # ---- identity and rules -----------------------------------------------------

    async def identify(self, auth: str | None) -> tuple[Rules, str]:
        if not auth:
            raise Refused(407, "a job credential is required (proxy user job-<id>.<tool>)")
        scheme, _, value = auth.partition(" ")
        if scheme.lower() != "basic":
            raise Refused(407, "use Basic proxy authentication with the job credential")
        try:
            user, sep, secret = base64.b64decode(value.strip(), validate=True).decode().partition(":")
        except (binascii.Error, UnicodeDecodeError):
            raise Refused(407, "the job credential is malformed")
        m = USER_RE.match(user)
        if not sep or not m or not secret:
            raise Refused(407, "the job credential is malformed (user job-<id>.<tool>)")
        rules = await self.rules_for(int(m.group(1)), secret)
        return rules, m.group(2) or "unknown"

    async def rules_for(self, job_id: int, secret: str) -> Rules:
        key = (job_id, hashlib.sha256(secret.encode()).hexdigest())
        hit = self._rules.get(key)
        if hit is None or hit[0] <= self.clock():
            lock = self._rules_locks.setdefault(key, asyncio.Lock())
            async with lock:
                hit = self._rules.get(key)
                if hit is None or hit[0] <= self.clock():
                    hit = (self.clock() + RULES_TTL, await self._ask(job_id, secret))
                    if not (isinstance(hit[1], Refused) and hit[1].status == 503):
                        self._rules[key] = hit
                    if len(self._rules) > 4096:
                        self._rules.clear()
            self._rules_locks.pop(key, None)
        if isinstance(hit[1], Refused):
            raise hit[1]
        return hit[1]

    async def _ask(self, job_id: int, secret: str) -> Rules | Refused:
        status, data = await self.api.session(job_id, secret)
        if status == 200:
            try:
                return Rules.from_api(data)
            except (KeyError, TypeError, ValueError):
                return Refused(503, "the API's answer about this job could not be read")
        detail = data.get("detail") if isinstance(data, dict) else None
        if status in (403, 404):
            return Refused(407, f"job credential refused: {detail or 'unknown job'}")
        return Refused(503, f"cannot check the job credential: {detail or f'API answered {status}'}")

    # ---- addresses ------------------------------------------------------------------

    async def _denied_addresses(self) -> set:
        """The deployment's own containers, which no request may reach, refreshed every minute."""
        if self._denied[0] > self.clock():
            return self._denied[1]
        loop = asyncio.get_running_loop()
        out = set()
        for name in self.deny_hosts + (socket.gethostname(),):
            try:
                for info in await loop.getaddrinfo(name, None, type=socket.SOCK_STREAM):
                    out.add(ipaddress.ip_address(info[4][0]))
            except (OSError, ValueError):
                pass
        self._denied = (self.clock() + 60, out)
        return out

    async def resolve(self, host: str) -> str:
        """The address to connect to, checked. The connection goes to this address, so a DNS
        answer cannot change between the check and the use."""
        if host in self.deny_hosts:
            raise Refused(403, f"{host} is part of this deployment and is never contacted")
        try:
            addrs = [ipaddress.ip_address(host)]
        except ValueError:
            try:
                infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
            except OSError:
                raise Refused(502, f"{host} does not resolve")
            addrs = [ipaddress.ip_address(i[4][0].split("%")[0]) for i in infos]
        if not addrs:
            raise Refused(502, f"{host} does not resolve")
        ip = addrs[0]
        if getattr(ip, "ipv4_mapped", None):
            ip = ip.ipv4_mapped
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise Refused(403, f"{host} resolves to {ip}, which is never contacted (loopback, link-local or "
                               f"special address)")
        if ip in await self._denied_addresses():
            raise Refused(403, f"{host} resolves to an address of this deployment, which is never contacted")
        return str(ip)

    def limiter(self, rules: Rules) -> Limiter:
        lim = self.limiters.get(rules.engagement_id)
        if lim is None:
            lim = self.limiters[rules.engagement_id] = Limiter(rules.rate_limit_rps, clock=self.clock)
        lim.rate = rules.rate_limit_rps          # a changed rule applies to the next request
        return lim

    # ---- log ------------------------------------------------------------------------

    def log_full(self) -> bool:
        return len(self.log_rows) >= LOG_BACKLOG

    def record(self, *, rules: Rules | None, tool: str, kind: str, method: str, url: str, host: str = "",
               port: int | None = None, status: int | None = None, verdict: str, reason: str = "",
               sent: int = 0, received: int = 0, started: float | None = None, engagement_id: int | None = None,
               job_id: int | None = None) -> None:
        if rules is None or rules.redact:
            url = redact.text(url, redact.Report())
        row = {"at": datetime.now(timezone.utc).isoformat(),
               "engagement_id": rules.engagement_id if rules else engagement_id,
               "job_id": rules.job_id if rules else job_id, "tool": tool[:32], "kind": kind, "method": method[:16],
               "url": url[:2000], "host": host[:255], "port": port, "status": status, "verdict": verdict,
               "reason": reason[:300], "bytes_sent": sent, "bytes_received": received,
               "duration_ms": int((self.clock() - started) * 1000) if started is not None else None}
        if len(self.log_rows) >= 2 * LOG_BACKLOG:
            self.dropped += 1         # only refusals get here: nothing is sent while the log is full
            return
        self.log_rows.append(row)

    async def flush_log(self) -> bool:
        if not self.log_rows:
            return True
        batch = self.log_rows[:LOG_BATCH]
        status, data = await self.api.post_log(batch)
        if status == 200:
            del self.log_rows[:len(batch)]
            return True
        print(f"gateway: request log not written ({status}: {str(data)[:200]}); "
              f"{len(self.log_rows)} rows waiting", file=sys.stderr, flush=True)
        return False

    async def flush_forever(self) -> None:
        while True:
            ok = await self.flush_log()
            await asyncio.sleep(0.5 if ok else 2.0)

    # ---- HTTP -----------------------------------------------------------------------

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await self._serve(reader, writer, None)
        except (ConnectionError, asyncio.TimeoutError, asyncio.IncompleteReadError, h11.ProtocolError, ssl.SSLError,
                OSError):
            pass
        except Exception as e:      # a bug: the connection is closed, nothing more is sent
            print(f"gateway: connection ended by an error: {type(e).__name__}: {str(e)[:300]}",
                  file=sys.stderr, flush=True)
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _serve(self, reader, writer, tunnel: Tunnel | None) -> None:
        conn = h11.Connection(h11.SERVER, max_incomplete_event_size=MAX_HEAD)
        while True:
            ev = await _next(conn, reader)
            if not isinstance(ev, h11.Request):
                return
            if tunnel is None and ev.method == b"CONNECT":
                await self._connect(conn, reader, writer, ev)
                return
            keep = await self._request(conn, reader, writer, ev, tunnel)
            if not keep or conn.our_state is not h11.DONE or conn.their_state is not h11.DONE:
                return
            conn.start_next_cycle()

    async def _refuse(self, conn, writer, req_method: bytes, e: Refused) -> None:
        body = b"" if req_method == b"HEAD" else (f"AttackLedger gateway: {e.reason}\n").encode()
        headers = [("Content-Type", "text/plain; charset=utf-8"), ("Content-Length", str(len(body))),
                   (REFUSED_HEADER, "refused"), ("Connection", "close")]
        if e.status == 407:
            headers.append(("Proxy-Authenticate", REALM))
        try:
            writer.write(conn.send(h11.Response(status_code=e.status, headers=headers)))
            if body:
                writer.write(conn.send(h11.Data(data=body)))
            writer.write(conn.send(h11.EndOfMessage()))
            await writer.drain()
        except (h11.LocalProtocolError, ConnectionError, OSError):
            pass

    async def _connect(self, conn, reader, writer, ev) -> None:
        started = self.clock()
        auth = _header(ev.headers, b"proxy-authorization")
        probe = (_header(ev.headers, PROBE_HEADER) or "").strip().lower() == "connect"
        authority = ev.target.decode("latin-1")
        rules, tool, kind, host, port = None, "unknown", "target", "", None
        try:
            if self.log_full():
                raise Refused(503, "the request log is not being written; nothing is sent until it is")
            host, port = split_authority(authority)
            rules, tool = await self.identify(auth)
            kind = self.policy.classify(rules, host, port, "https")
            if probe:
                if kind != "target":
                    raise Refused(403, "port probes are for in-scope hosts only")
                await self._probe(conn, writer, rules, tool, host, port, started)
                return
        except Refused as e:
            self.record(rules=rules, tool=tool, kind=kind, method="PROBE" if probe else "CONNECT",
                        url=f"{host or authority[:200]}:{port or ''}", host=host, port=port, status=e.status,
                        verdict="refused", reason=e.reason, started=started)
            await self._refuse(conn, writer, b"CONNECT", e)
            return
        ev2 = await _next(conn, reader)
        if not isinstance(ev2, h11.EndOfMessage):
            return
        writer.write(conn.send(h11.Response(status_code=200, headers=[], reason=b"Connection established")))
        await writer.drain()
        data, closed = conn.trailing_data
        if data or closed or conn.our_state is not h11.SWITCHED_PROTOCOL:
            return      # bytes sent before the tunnel was open: not supported, nothing relayed
        # Every tunnel is TLS with the gateway's certificate. A client that sends anything else,
        # or does not trust the CA, fails the handshake and is disconnected: nothing is relayed.
        await writer.start_tls(self.ca.server_context(host), ssl_handshake_timeout=HANDSHAKE_TIMEOUT)
        await self._serve(reader, writer, Tunnel(host, port, auth))

    async def _probe(self, conn, writer, rules: Rules, tool: str, host: str, port: int, started: float) -> None:
        ip = await self.resolve(host)
        await self.limiter(rules).acquire()
        status, reason = 200, "open"
        try:
            _, w = await asyncio.wait_for(self.open_connection(ip, port), PROBE_TIMEOUT)
            w.close()
        except asyncio.TimeoutError:
            status, reason = 502, "timed out"
        except OSError as e:
            status, reason = 502, "closed" if isinstance(e, ConnectionRefusedError) else f"failed: {e.strerror or e}"
        self.record(rules=rules, tool=tool, kind="target", method="PROBE", url=f"{host}:{port}", host=host, port=port,
                    status=status, verdict="allowed", reason=reason, started=started)
        # Written by hand: to h11, a 2xx answer to CONNECT opens a tunnel, and this one never does.
        body = (reason + "\n").encode()
        writer.write(f"HTTP/1.1 {status} {'Open' if status == 200 else 'Bad Gateway'}\r\n"
                     f"{REFUSED_HEADER}: probe\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                     .encode() + body)
        await writer.drain()

    async def _request(self, conn, reader, writer, ev, tunnel: Tunnel | None) -> bool:
        """One request from a tool. True if the client connection may carry another."""
        started = self.clock()
        method = ev.method.decode("latin-1")
        target = ev.target.decode("latin-1")
        rules, tool, kind, url, host, port = None, "unknown", "target", target[:2000], "", None
        try:
            if self.log_full():
                raise Refused(503, "the request log is not being written; nothing is sent until it is")
            if tunnel is None:
                auth = _header(ev.headers, b"proxy-authorization")
                if not target.lower().startswith("http://"):
                    raise Refused(400, "send http:// URLs in absolute form, and https:// through CONNECT")
                parts = urlsplit(target)
                if parts.username is not None or parts.password is not None:
                    raise Refused(403, "URLs with credentials are not sent")
                host, port = split_authority(parts.netloc, 80)
                scheme, path = "http", (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
            else:
                auth, host, port, scheme, path = tunnel.auth, tunnel.host, tunnel.port, "https", target
                if not path.startswith("/"):
                    raise Refused(400, "requests inside a tunnel use a path")
                h = _header(ev.headers, b"host")
                if h is None or split_authority(h, 443)[0] != host:
                    raise Refused(403, f"the Host header does not name the tunnel's host {host}")
            default = 443 if scheme == "https" else 80
            url = f"{scheme}://{host}{'' if port == default else f':{port}'}{path}"
            rules, tool = await self.identify(auth)
            kind = self.policy.classify(rules, host, port, scheme)
            self.policy.check(rules, kind, method, path, ev.headers)
            body = b""
            if kind == "service":
                body = await _read_body(conn, reader, MAX_SERVICE_BODY)
            else:
                end = await _next(conn, reader)
                if not isinstance(end, h11.EndOfMessage):
                    raise Refused(403, "read-only requests are sent without a body")
            out = self.policy.headers(rules, kind, ev.headers, host if port == default else f"{host}:{port}")
            if body:
                out.append((b"Content-Length", str(len(body)).encode()))
        except Refused as e:
            self.record(rules=rules, tool=tool, kind=kind, method=method, url=url, host=host, port=port,
                        status=e.status, verdict="refused", reason=e.reason, started=started)
            await self._refuse(conn, writer, ev.method, e)
            return False
        return await self._forward(conn, writer, rules, tool, kind, method, scheme, host, port, path, out, body,
                                   url, started)

    async def _forward(self, conn, writer, rules, tool, kind, method, scheme, host, port, path, headers, body,
                       url, started) -> bool:
        status, received, reason = None, 0, ""
        upw = None
        try:
            try:
                ip = await self.resolve(host)
                ctx = None if scheme == "http" else (self.insecure_ctx if kind == "target" else self.verify_ctx)
                upr, upw = await asyncio.wait_for(
                    self.open_connection(ip, port, ssl=ctx, server_hostname=host if ctx else None),
                    CONNECT_TIMEOUT)
            except Refused:
                raise
            except ssl.SSLCertVerificationError as e:
                raise Refused(502, f"the certificate of {host} did not verify: {e.verify_message}")
            except (OSError, asyncio.TimeoutError) as e:
                raise Refused(502, f"could not connect to {host}:{port}: "
                                   f"{'timed out' if isinstance(e, asyncio.TimeoutError) else (e.strerror or e)}")
            if kind == "target":
                await self.limiter(rules).acquire()
            elif kind == "passive":
                lim = self.passive_limiters.setdefault(host, Limiter(PASSIVE_RPS, clock=self.clock))
                await lim.acquire()
            # Nothing between the token and the write: the head leaves with the token's time.
            upc = h11.Connection(h11.CLIENT, max_incomplete_event_size=MAX_HEAD)
            upw.write(upc.send(h11.Request(method=method, target=path, headers=headers)))
            if body:
                upw.write(upc.send(h11.Data(data=body)))
            upw.write(upc.send(h11.EndOfMessage()))
            await upw.drain()
            try:
                while True:
                    resp = await _next(upc, upr)
                    if isinstance(resp, h11.InformationalResponse):
                        continue
                    break
            except (h11.ProtocolError, OSError, asyncio.TimeoutError) as e:
                raise Refused(502, f"{host} sent no valid response: {str(e)[:120] or type(e).__name__}")
            if not isinstance(resp, h11.Response):
                raise Refused(502, f"{host} closed the connection without a response")
        except Refused as e:
            if upw is not None:
                upw.close()
            self.record(rules=rules, tool=tool, kind=kind, method=method, url=url, host=host, port=port,
                        status=e.status, verdict="refused" if e.status in (403, 429) else "failed",
                        reason=e.reason, sent=0, started=started)
            await self._refuse(conn, writer, method.encode(), e)
            return False
        status = resp.status_code
        keep = True
        try:
            # h11 frames the body for the client again; a chunked upstream body has no valid length.
            drop = HOP_BY_HOP if any(k == b"transfer-encoding" for k, _ in resp.headers) \
                else HOP_BY_HOP - {"content-length"}
            out = [(k, v) for k, v in resp.headers if k.decode("latin-1") not in drop]
            writer.write(conn.send(h11.Response(status_code=status, headers=out, reason=resp.reason)))
            while True:
                ev = await _next(upc, upr)
                if isinstance(ev, h11.Data):
                    received += len(ev.data)
                    writer.write(conn.send(h11.Data(data=ev.data)))
                    await writer.drain()
                elif isinstance(ev, h11.EndOfMessage):
                    writer.write(conn.send(h11.EndOfMessage()))
                    await writer.drain()
                    break
                else:
                    reason, keep = "the response ended early", False
                    break
        except (h11.ProtocolError, OSError, asyncio.TimeoutError) as e:
            reason, keep = f"the response was cut off: {str(e)[:120] or type(e).__name__}", False
        finally:
            upw.close()
            self.record(rules=rules, tool=tool, kind=kind, method=method, url=url, host=host, port=port,
                        status=status, verdict="allowed", reason=reason, sent=len(body), received=received,
                        started=started)
        return keep

    # ---- DNS ------------------------------------------------------------------------

    async def dns_scopes(self) -> list:
        if self._dns_scopes[0] > self.clock():
            return self._dns_scopes[1]
        status, data = await self.api.dns_scopes()
        scopes = data if status == 200 and isinstance(data, list) else None
        if scopes is None:
            raise Refused(503, f"cannot read the scopes of running jobs ({status})")
        self._dns_scopes = (self.clock() + DNS_SCOPES_TTL, scopes)
        return scopes

    async def dns_answer(self, query: bytes) -> bytes | None:
        """The reply to one DNS query packet: forwarded if allowed, REFUSED otherwise."""
        started = self.clock()
        q = parse_question(query)
        if q is None:
            return None                     # not a single standard query: dropped
        qid, name, qtype, end = q
        url = f"dns:{name}/{DNS_TYPES.get(qtype, qtype)}"
        eng_id = None
        try:
            if self.log_full():
                raise Refused(503, "the request log is not being written")
            if qtype not in DNS_TYPES:
                raise Refused(403, "only A, AAAA and CNAME questions are answered")
            match = next((s for s in await self.dns_scopes()
                          if scope.in_scope(name, s.get("include") or [], s.get("exclude") or [])), None)
            if match is None:
                raise Refused(403, f"{name} is not in scope of a running job")
            eng_id = int(match["engagement_id"])
            lim = self.dns_limiters.setdefault(eng_id, Limiter(int(match.get("rate_limit_rps") or 1), clock=self.clock))
            lim.rate = max(1, int(match.get("rate_limit_rps") or 1))
            await lim.acquire(DNS_MAX_WAIT)
            reply = await self._dns_forward(query)
            if reply is None or len(reply) < 12 or reply[:2] != query[:2]:
                raise Refused(502, "no answer from the resolver")
        except Refused as e:
            self.record(rules=None, tool="dns", kind="dns", method="DNS", url=url, host=name, status=None,
                        verdict="refused" if e.status in (403, 429, 503) else "failed", reason=e.reason,
                        started=started, engagement_id=eng_id)
            return refused_reply(query, end)
        self.record(rules=None, tool="dns", kind="dns", method="DNS", url=url, host=name, status=reply[3] & 0x0F,
                    verdict="allowed", received=len(reply), started=started, engagement_id=eng_id)
        return reply

    async def _dns_forward(self, query: bytes) -> bytes | None:
        loop = asyncio.get_running_loop()
        fut = loop.create_future()

        class _Reply(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                if not fut.done():
                    fut.set_result(data)

            def error_received(self, exc):
                if not fut.done():
                    fut.set_exception(exc)

        transport, _ = await loop.create_datagram_endpoint(_Reply, remote_addr=(self.upstream_dns, 53))
        try:
            transport.sendto(query)
            return await asyncio.wait_for(fut, 4.0)
        except (OSError, asyncio.TimeoutError):
            return None
        finally:
            transport.close()

    # ---- run ------------------------------------------------------------------------

    async def serve(self, host: str = "0.0.0.0", port: int = 8080, dns_port: int | None = 53) -> None:
        server = await asyncio.start_server(self.handle_client, host, port, limit=MAX_HEAD)
        loop = asyncio.get_running_loop()
        if dns_port:
            gw = self

            class _Dns(asyncio.DatagramProtocol):
                def connection_made(self, transport):
                    self.transport = transport

                def datagram_received(self, data, addr):
                    async def answer():
                        reply = await gw.dns_answer(data)
                        if reply:
                            self.transport.sendto(reply, addr)
                    loop.create_task(answer())
            await loop.create_datagram_endpoint(_Dns, local_addr=(host, dns_port))
        flusher = loop.create_task(self.flush_forever())
        print(f"gateway ready: proxy {host}:{port}, dns {dns_port}, api {self.api.base}", flush=True)
        try:
            async with server:
                await server.serve_forever()
        finally:
            flusher.cancel()


async def _next(conn: h11.Connection, reader: asyncio.StreamReader):
    """The next h11 event, reading as needed. EOF gives ConnectionClosed (or an error)."""
    while True:
        ev = conn.next_event()
        if ev is h11.NEED_DATA:
            data = await asyncio.wait_for(reader.read(65536), READ_TIMEOUT)
            conn.receive_data(data)
            continue
        if ev is h11.PAUSED:
            return h11.ConnectionClosed()
        return ev


async def _read_body(conn, reader, limit: int) -> bytes:
    chunks, size = [], 0
    while True:
        ev = await _next(conn, reader)
        if isinstance(ev, h11.Data):
            size += len(ev.data)
            if size > limit:
                raise Refused(413, "the request body is too large")
            chunks.append(ev.data)
        elif isinstance(ev, h11.EndOfMessage):
            return b"".join(chunks)
        else:
            raise Refused(400, "the request ended early")


# ---- DNS packets ----------------------------------------------------------------------

def parse_question(data: bytes):
    """(id, name, qtype, end of question) for a standard query with one question, else None."""
    if len(data) < 17:
        return None
    qid, flags, qd = struct.unpack("!HHH", data[:6])
    if flags & 0x8000 or (flags >> 11) & 0xF or qd != 1:
        return None
    i, labels = 12, []
    while True:
        if i >= len(data):
            return None
        n = data[i]
        i += 1
        if n == 0:
            break
        if n & 0xC0 or i + n > len(data) or len(labels) > 127:
            return None
        labels.append(data[i:i + n])
        i += n
    if i + 4 > len(data):
        return None
    qtype, _qclass = struct.unpack("!HH", data[i:i + 4])
    try:
        name = b".".join(labels).decode("ascii").lower()
    except UnicodeDecodeError:
        return None
    return qid, name, qtype, i + 4


def refused_reply(query: bytes, end: int) -> bytes:
    """REFUSED (RCODE 5), echoing the question, nothing else."""
    qid, flags = struct.unpack("!HH", query[:4])
    flags = 0x8000 | (flags & 0x0100) | 0x0080 | 5        # QR, RD copied, RA, REFUSED
    return struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0) + query[12:end]


def _resolv_conf_nameserver() -> str:
    try:
        for line in open("/etc/resolv.conf"):
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                return parts[1]
    except OSError:
        pass
    return "127.0.0.11"


def _env_hosts(name: str, base) -> frozenset:
    extra = {h.strip().lower() for h in os.environ.get(name, "").split(",") if h.strip()}
    return frozenset(base) | extra


def main() -> None:
    token = gateway_token(create=True)
    ca = CA(os.environ.get("ATTACKLEDGER_GATEWAY_STATE", "/data/gateway"),
            os.environ.get("ATTACKLEDGER_GATEWAY_PUBLIC", "/data/gateway-public"))
    deny = tuple(h.strip() for h in os.environ.get("ATTACKLEDGER_GATEWAY_DENY_HOSTS", ",".join(DENY_HOSTS)).split(",")
                 if h.strip())
    gw = Gateway(Api(os.environ.get("ATTACKLEDGER_API_URL", "http://api:8000"), token), ca,
                 policy=Policy(_env_hosts("ATTACKLEDGER_GATEWAY_PASSIVE_HOSTS", PASSIVE_HOSTS),
                               _env_hosts("ATTACKLEDGER_GATEWAY_SERVICE_HOSTS", SERVICE_HOSTS)),
                 deny_hosts=deny, upstream_dns=os.environ.get("ATTACKLEDGER_GATEWAY_UPSTREAM_DNS") or None)
    dns_port = int(os.environ.get("ATTACKLEDGER_GATEWAY_DNS_PORT", "53"))
    asyncio.run(gw.serve(port=int(os.environ.get("ATTACKLEDGER_GATEWAY_PORT", "8080")), dns_port=dns_port or None))


if __name__ == "__main__":
    main()
