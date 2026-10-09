"""The traffic gateway (D-039, docs/GATEWAY.md): the only way out of the worker.

The worker container has no route to the internet. Every request a recon tool or the agent
sends leaves through this process, which enforces the engagement's rules in one place:

  scope      the host must be in the engagement's scope (exclusions win), or an allowlisted
             passive source (passive modules) or the Claude API (agent runs);
  methods    GET, HEAD and OPTIONS only, with no body, no method override, no Upgrade.
             A write (POST, PUT, PATCH, DELETE) is sent only for an agent run, only with a
             person's approval of that exact request, and only once (D-041): the gateway asks
             the API to use the approval and sends the approved request, not the tool's;
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

Test accounts (D-040): an agent run asks for a request "as" a test account with the header
X-AttackLedger-As: <label>. The gateway removes it, asks the API for that account's headers
(POST /gateway/account: only for agent jobs, only for the hosts named for the account, in scope)
and adds them. The worker never holds them; the response is scrubbed of them (and of new
cookies and tokens) before it goes back, so the worker never sees them either.

The Claude API key (ANTHROPIC_API_KEY) is held here, not in the worker: the gateway adds it to
an agent job's Claude API calls, after removing any key the client sent (D-042,
docs/WORKER_API.md). Without one, those calls are refused.

The worker's channel to the API (D-042): a second port (8081) relays /worker/* requests to the
API and nothing else, so the worker's network holds the gateway only. The API checks every
token; the relay passes only Authorization and Content-Type.

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
# Sent by AttackLedger's own clients (app.egress): they want the gateway's reason when a
# target cannot be reached. Other tools get what an unreachable target gives them, a closed
# connection, so a scanner never records the gateway's 502 as the target's answer.
ERRORS_HEADER = b"x-attackledger-errors"
# An agent run's request "as" a test account (D-040), and the approved write it sends (D-041).
# Both are read and removed here, never forwarded.
AS_HEADER = b"x-attackledger-as"
APPROVAL_HEADER = b"x-attackledger-approval"
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
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
MAX_WRITE_BODY = 1_000_000       # an approved write's body (approvals.MAX_BODY)
MAX_SCRUBBED_BODY = 20 * 1024 * 1024   # a response sent as a test account is read whole, then scrubbed
ACCOUNT_TTL = 2.0                # a replaced or deleted test account takes effect within this
MIN_SCRUB = 6                    # shorter values are not searched for in responses
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
# Removed from an agent's Claude API call; the gateway's own key goes in their place.
SERVICE_KEY_HEADERS = frozenset({"x-api-key", "authorization"})
# The worker's channel (D-042): what the control port relays to the API, and nothing else.
CONTROL_PATH = re.compile(r"^/worker/[a-z0-9/_-]{0,200}$")
CONTROL_METHODS = frozenset({"GET", "POST"})
MAX_CONTROL_BODY = 16 * 1024 * 1024
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

    def relay(self, method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, str, bytes]:
        """One worker call to the API: (status, content type, body)."""
        req = urllib.request.Request(self.base + path, method=method, data=body if method == "POST" else None,
                                     headers=headers)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=120) as r:
                return r.status, r.headers.get("content-type", "application/json"), r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("content-type", "application/json"), e.read()
        except (OSError, ValueError) as e:
            detail = json.dumps({"detail": f"API unreachable: {str(e)[:120] or type(e).__name__}"}).encode()
            return 502, "application/json", detail

    async def session(self, job_id: int, secret: str):
        return await asyncio.to_thread(self._call, "POST", "/gateway/session", {"job_id": job_id, "secret": secret})

    async def dns_scopes(self):
        return await asyncio.to_thread(self._call, "GET", "/gateway/dns-scopes")

    async def account(self, job_id: int, secret: str, label: str, host: str):
        return await asyncio.to_thread(self._call, "POST", "/gateway/account",
                                       {"job_id": job_id, "secret": secret, "label": label, "host": host})

    async def approval(self, job_id: int, secret: str, approval_id: int, method: str, url: str, body_sha256: str,
                       account: str | None):
        return await asyncio.to_thread(self._call, "POST", "/gateway/approval", {
            "job_id": job_id, "secret": secret, "approval_id": approval_id, "method": method, "url": url,
            "body_sha256": body_sha256, "account": account})

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
    # Readable by the API's user: only the gateway and the API mount this volume, never the worker.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "w") as f:
        f.write(value)
    return value


# ---- policy -------------------------------------------------------------------------

def credential(auth: str | None) -> tuple[int, str, str]:
    """(job id, tool, secret) from a Proxy-Authorization value. Raises Refused (407)."""
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
    return int(m.group(1)), m.group(2) or "unknown", secret


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
    """What may be sent: one place for the rules, the test accounts' headers (D-040) and the
    approved writes' (D-041)."""

    def __init__(self, passive_hosts=PASSIVE_HOSTS, service_hosts=SERVICE_HOSTS, service_key: str | None = None):
        self.passive_hosts, self.service_hosts = frozenset(passive_hosts), frozenset(service_hosts)
        self.service_key = (service_key or "").strip() or None

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
            if (scheme, port) not in (("https", 443), ("http", 80)):
                raise Refused(403, "passive sources are reached on ports 443 (HTTPS) and 80 (HTTP) only")
            return "passive"
        if host in self.service_hosts:
            if rules.traffic != "agent" or scheme != "https" or port != 443:
                raise Refused(403, f"{host} is reachable from agent runs only, over HTTPS")
            return "service"
        raise Refused(403, f"{host} is not in scope")

    def check(self, rules: Rules, kind: str, method: str, path: str, headers, *, write: bool = False) -> None:
        """Method, body and header rules for one request. write: it carries an approval (D-041),
        which the gateway checks with the API before anything is sent."""
        if kind == "service":
            if not any(method == m and (path == p or path.startswith(p + "?")) for m, p in SERVICE_ROUTES):
                raise Refused(403, f"{method} {path.split('?')[0][:100]} is not a Claude API call an agent run makes")
            if not self.service_key:
                raise Refused(503, "no Claude API key is configured at the gateway (ANTHROPIC_API_KEY)")
            return
        if method not in READ_ONLY:
            if not write:
                raise Refused(403, f"{method[:20]} is refused: only GET, HEAD and OPTIONS are sent; a write needs a "
                                   f"person's approval of that exact request (D-041)")
            if method not in WRITE_METHODS or kind != "target" or rules.traffic != "agent":
                raise Refused(403, f"{method[:20]} is refused: approved writes are POST, PUT, PATCH or DELETE from "
                                   f"agent runs to targets only")
        elif write:
            raise Refused(400, "an approval is for a write, not a read-only request")
        if path.startswith("*"):
            raise Refused(403, "asterisk-form requests are not sent")
        names = {k for k, _ in headers}
        if b"upgrade" in names:
            raise Refused(403, "protocol upgrades (WebSocket, h2c) are not sent")
        if not write and (b"transfer-encoding" in names or int(_header(headers, b"content-length") or 0) > 0):
            raise Refused(403, "read-only requests are sent without a body")
        for k, v in headers:
            if k.decode("latin-1") in OVERRIDE_HEADERS and v.decode("latin-1").strip().upper() not in READ_ONLY:
                raise Refused(403, f"method override to {v.decode('latin-1')[:20]} is refused")
        # _method=DELETE and the like. Only a value that can be a method name counts: parameter
        # discovery (Arjun) and scanners send _method with numbers or payloads, which no
        # framework reads as a method.
        query = urlsplit(path).query
        for k, v in parse_qsl(query, keep_blank_values=True):
            m = v.strip().upper()
            if k.lower() == "_method" and m.isalpha() and m not in READ_ONLY and m != method:
                raise Refused(403, f"_method={v[:20]} is refused")
        if kind == "target" and not rules.identification():
            raise Refused(403, "the engagement has no research header or user agent; nothing is sent to targets")

    def headers(self, rules: Rules, kind: str, headers, host_header: str, *, account: dict | None = None,
                approved: list | None = None) -> list[tuple[bytes, bytes]]:
        """The headers sent upstream: the tool's (as received), or for an approved write the
        approved ones, minus hop-by-hop and identification names, then Host, the identification
        (targets), the test account's headers and Connection: close."""
        if approved is not None:
            headers = [(str(k).lower().encode("latin-1"), str(v).encode("latin-1")) for k, v in approved]
        drop = set(HOP_BY_HOP) | {ERRORS_HEADER.decode(), AS_HEADER.decode(), APPROVAL_HEADER.decode()}
        conn = _header(headers, b"connection") or ""
        drop |= {t.strip().lower() for t in conn.split(",") if t.strip()}
        ident = [(n.encode(), v.encode()) for n, v in rules.identification()] if kind == "target" else []
        drop |= {n.decode().lower() for n, _ in ident}
        if kind == "service":       # the client's key, if any, never leaves; the gateway's goes instead
            drop |= SERVICE_KEY_HEADERS
            ident = [(b"x-api-key", self.service_key.encode())] if self.service_key else []
        out = [(b"Host", host_header.encode("idna" if not host_header.isascii() else "ascii"))]
        out += [(k, v) for k, v in headers if k.decode("latin-1") not in drop]
        out += ident
        out = self.inject_credentials(rules, kind, out, account)
        out.append((b"Connection", b"close"))
        return out

    # ---- hooks for later decisions -------------------------------------------------

    def inject_credentials(self, rules: Rules, kind: str, headers: list, account: dict | None) -> list:
        """D-040: a test account's headers replace any of the same names the tool sent. The
        response is then read whole, uncompressed, so it can be scrubbed (scrub_response). The log
        never holds header values."""
        if not account or kind != "target":
            return headers
        names = {str(n).lower() for n, _ in account["headers"]} | {"accept-encoding"}
        out = [(k, v) for k, v in headers if k.decode("latin-1").lower() not in names]
        out += [(str(n).encode("latin-1"), str(v).encode("latin-1")) for n, v in account["headers"]]
        out.append((b"Accept-Encoding", b"identity"))
        return out


def account_values(account: dict) -> list[str]:
    """The secret values an account's headers carry: each header value, each cookie's value and a
    bearer token on its own, longest first, so a response that echoes them can be scrubbed."""
    out = set()
    for name, value in account.get("headers") or []:
        value = str(value)
        out.add(value)
        if str(name).lower() == "cookie":
            for part in value.split(";"):
                out.add(part.partition("=")[2].strip())
        scheme, _, rest = value.partition(" ")
        if rest and scheme.isalpha():
            out.add(rest.strip())
    return sorted((v for v in out if len(v) >= MIN_SCRUB), key=len, reverse=True)


def scrub_response(account: dict, headers: list, body: bytes) -> tuple[list, bytes]:
    """A response to a request sent as a test account, before it goes back to the worker: the
    account's own values become redaction markers wherever they appear, and so do cookies,
    tokens and other credentials (redact.py), so the worker never holds a session of the account."""
    rep = redact.Report()
    values = account_values(account)
    out = []
    for k, v in headers:
        name, value = k.decode("latin-1"), v.decode("latin-1")
        for s in values:
            value = value.replace(s, redact.marker(s))
        value = redact.header_value(name, value, rep)
        out.append((k, value.encode("latin-1", "replace")))
    for s in values:
        body = body.replace(s.encode(), redact.marker(s).encode())
    return out, redact.data(body, rep)


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
        self._accounts: dict[tuple, tuple[float, dict | Refused]] = {}
        self._dns_scopes: tuple[float, list] = (0.0, [])
        self._denied: tuple[float, set] = (0.0, set())
        self.log_rows: list[dict] = []
        self.dropped = 0
        # Upstream connector, replaced in tests.
        self.open_connection = asyncio.open_connection

    # ---- identity and rules -----------------------------------------------------

    async def identify(self, auth: str | None) -> tuple[Rules, str]:
        job_id, tool, secret = credential(auth)
        rules = await self.rules_for(job_id, secret)
        return rules, tool

    # ---- test accounts and approved writes (D-040, D-041) ----------------------------

    async def account_for(self, rules: Rules, auth: str, label: str, host: str) -> dict:
        """The test account's headers for this request, from the API (cached ACCOUNT_TTL)."""
        if rules.traffic != "agent":
            raise Refused(403, f"a {rules.kind} job does not send requests as a test account")
        if not rules.redact:
            raise Refused(403, "test accounts are used only while evidence redaction is on (D-038)")
        if not label or len(label) > 16 or any(c in label for c in "\r\n\0 "):
            raise Refused(400, "X-AttackLedger-As names a test account label")
        job_id, _, secret = credential(auth)
        key = (job_id, hashlib.sha256(secret.encode()).hexdigest(), label, host)
        hit = self._accounts.get(key)
        if hit is None or hit[0] <= self.clock():
            status, data = await self.api.account(job_id, secret, label, host)
            detail = data.get("detail") if isinstance(data, dict) else None
            if status == 200 and isinstance(data, dict) and isinstance(data.get("headers"), list):
                hit = (self.clock() + ACCOUNT_TTL, {"label": str(data.get("label") or label), "headers": data["headers"]})
            elif status in (403, 404):
                hit = (self.clock() + ACCOUNT_TTL, Refused(403, f"not sent as test account {label}: "
                                                                f"{detail or 'refused by the API'}"))
            else:
                raise Refused(503, f"cannot get test account {label}: {detail or f'API answered {status}'}")
            self._accounts[key] = hit
            if len(self._accounts) > 4096:
                self._accounts.clear()
        if isinstance(hit[1], Refused):
            raise hit[1]
        return hit[1]

    async def use_approval(self, rules: Rules, auth: str, approval_id: int, method: str, url: str, body: bytes,
                           account: str | None) -> dict:
        """Use a person's approval (D-041). The API checks that it is this job's, approved, not
        expired and not used, and that method, URL, body and account are the approved ones, and
        marks it used: it is never asked again. The answer is the request to send."""
        job_id, _, secret = credential(auth)
        status, data = await self.api.approval(job_id, secret, approval_id, method, url,
                                               hashlib.sha256(body).hexdigest(), account)
        detail = data.get("detail") if isinstance(data, dict) else None
        if status == 200 and isinstance(data, dict) and isinstance(data.get("headers"), list):
            return data
        if status in (403, 404, 409, 422):
            raise Refused(403, f"write not sent: {detail or 'the approval was refused'}")
        raise Refused(503, f"cannot check the approval: {detail or f'API answered {status}'}")

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
               job_id: int | None = None, account: str | None = None, approval_id: int | None = None) -> None:
        if rules is None or rules.redact:
            url = redact.text(url, redact.Report())
        row = {"at": datetime.now(timezone.utc).isoformat(),
               "engagement_id": rules.engagement_id if rules else engagement_id,
               "job_id": rules.job_id if rules else job_id, "tool": tool[:32], "kind": kind, "method": method[:16],
               "url": url[:2000], "host": host[:255], "port": port, "status": status, "verdict": verdict,
               "reason": reason[:300], "bytes_sent": sent, "bytes_received": received,
               "duration_ms": int((self.clock() - started) * 1000) if started is not None else None,
               "account": account, "approval_id": approval_id}
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
        label = (_header(ev.headers, AS_HEADER) or "").strip() or None
        approval_text = (_header(ev.headers, APPROVAL_HEADER) or "").strip() or None
        approval_id = None
        account = None
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
            if (label or approval_text) and kind != "target":
                raise Refused(403, "test accounts and approved writes are for target requests only")
            if approval_text is not None:
                if not approval_text.isdigit() or len(approval_text) > 12:
                    raise Refused(400, "X-AttackLedger-Approval names an approval by its number")
                approval_id = int(approval_text)
            self.policy.check(rules, kind, method, path, ev.headers, write=approval_id is not None)
            body = b""
            if kind == "service":
                body = await _read_body(conn, reader, MAX_SERVICE_BODY)
            elif approval_id is not None:
                body = await _read_body(conn, reader, MAX_WRITE_BODY)
            else:
                end = await _next(conn, reader)
                if not isinstance(end, h11.EndOfMessage):
                    raise Refused(403, "read-only requests are sent without a body")
            if label:
                account = await self.account_for(rules, auth, label, host)
            approved = None
            if approval_id is not None:
                # Last, after every other check: from here on the approval is used, sent or not.
                approved = await self.use_approval(rules, auth, approval_id, method, url, body,
                                                   account["label"] if account else None)
                self.policy.check(rules, kind, method, path,
                                  [(str(k).lower().encode("latin-1"), str(v).encode("latin-1"))
                                   for k, v in approved["headers"]], write=True)
            out = self.policy.headers(rules, kind, ev.headers, host if port == default else f"{host}:{port}",
                                      account=account, approved=approved["headers"] if approved else None)
            if body:
                out.append((b"Content-Length", str(len(body)).encode()))
        except Refused as e:
            self.record(rules=rules, tool=tool, kind=kind, method=method, url=url, host=host, port=port,
                        status=e.status, verdict="refused", reason=e.reason, started=started,
                        account=account["label"] if account else label, approval_id=approval_id)
            await self._refuse(conn, writer, ev.method, e)
            return False
        return await self._forward(conn, writer, rules, tool, kind, method, scheme, host, port, path, out, body,
                                   url, started, wants_errors=_header(ev.headers, ERRORS_HEADER) is not None,
                                   account=account, approval_id=approval_id)

    async def _forward(self, conn, writer, rules, tool, kind, method, scheme, host, port, path, headers, body,
                       url, started, wants_errors: bool = True, account: dict | None = None,
                       approval_id: int | None = None) -> bool:
        status, received, reason = None, 0, ""
        upw = None
        label = account["label"] if account else None
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
                if upc.their_state is h11.SEND_RESPONSE and isinstance(e, h11.RemoteProtocolError):
                    raise Refused(502, f"{host} closed the connection without a response")
                raise Refused(502, f"{host} sent no valid response: {str(e)[:120] or type(e).__name__}")
            if not isinstance(resp, h11.Response):
                raise Refused(502, f"{host} closed the connection without a response")
        except Refused as e:
            if upw is not None:
                upw.close()
            self.record(rules=rules, tool=tool, kind=kind, method=method, url=url, host=host, port=port,
                        status=e.status, verdict="refused" if e.status in (403, 429) else "failed",
                        reason=e.reason, sent=0, started=started, account=label, approval_id=approval_id)
            if e.status != 502 or wants_errors:
                await self._refuse(conn, writer, method.encode(), e)
            return False
        status = resp.status_code
        keep = True
        try:
            if account is not None:
                # Read whole, then scrubbed (D-040): what goes back never holds the account's session.
                keep, reason, received = await self._scrubbed(conn, writer, upc, upr, resp, account, method)
            else:
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
                        started=started, account=label, approval_id=approval_id)
        return keep

    async def _scrubbed(self, conn, writer, upc, upr, resp, account: dict, method: str) -> tuple[bool, str, int]:
        """A response to a request sent as a test account: read whole, scrubbed, then sent on with
        its new length. (keep the client connection, reason, bytes received)."""
        chunks, size, reason = [], 0, ""
        while True:
            ev = await _next(upc, upr)
            if isinstance(ev, h11.Data):
                size += len(ev.data)
                if size > MAX_SCRUBBED_BODY:
                    reason = f"the response is larger than {MAX_SCRUBBED_BODY} bytes; it was cut off"
                    break
                chunks.append(ev.data)
            elif isinstance(ev, h11.EndOfMessage):
                break
            else:
                reason = "the response ended early"
                break
        head = [(k, v) for k, v in resp.headers if k.decode("latin-1") not in HOP_BY_HOP]
        head, body = scrub_response(account, head, b"".join(chunks))
        if method == "HEAD":
            length = _header(resp.headers, b"content-length")
            head += [(b"Content-Length", length.encode())] if length else []
            body = b""
        else:
            head.append((b"Content-Length", str(len(body)).encode()))
        writer.write(conn.send(h11.Response(status_code=resp.status_code, headers=head, reason=resp.reason)))
        if body:
            writer.write(conn.send(h11.Data(data=body)))
        writer.write(conn.send(h11.EndOfMessage()))
        await writer.drain()
        return not reason, reason, size

    # ---- the worker's channel (D-042) ------------------------------------------------------

    async def handle_control(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """One request on the control port: a /worker/* call relayed to the API, or refused."""
        conn = h11.Connection(h11.SERVER, max_incomplete_event_size=MAX_HEAD)
        try:
            ev = await _next(conn, reader)
            if not isinstance(ev, h11.Request):
                return
            method, path = ev.method.decode("latin-1"), ev.target.decode("latin-1")
            try:
                if method not in CONTROL_METHODS:
                    raise Refused(405, "the control port relays GET and POST only")
                if not CONTROL_PATH.match(path):
                    raise Refused(404, "the control port relays the worker's /worker/ routes only")
                body = await _read_body(conn, reader, MAX_CONTROL_BODY)
                headers = {}
                for name in (b"authorization", b"content-type"):
                    v = _header(ev.headers, name)
                    if v is not None:
                        headers[name.decode()] = v
                status, ctype, data = await asyncio.to_thread(self.api.relay, method, path, headers, body)
            except Refused as e:
                await self._refuse(conn, writer, ev.method, e)
                return
            writer.write(conn.send(h11.Response(status_code=status, headers=[
                ("Content-Type", ctype), ("Content-Length", str(len(data))), ("Connection", "close")])))
            if data:
                writer.write(conn.send(h11.Data(data=data)))
            writer.write(conn.send(h11.EndOfMessage()))
            await writer.drain()
        except (ConnectionError, asyncio.TimeoutError, asyncio.IncompleteReadError, h11.ProtocolError, OSError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

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

    async def serve(self, host: str = "0.0.0.0", port: int = 8080, dns_port: int | None = 53,
                    control_port: int | None = 8081) -> None:
        server = await asyncio.start_server(self.handle_client, host, port, limit=MAX_HEAD)
        control = (await asyncio.start_server(self.handle_control, host, control_port, limit=MAX_HEAD)
                   if control_port else None)
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
        print(f"gateway ready: proxy {host}:{port}, dns {dns_port}, control {control_port}, api {self.api.base}, "
              f"claude key {'set' if self.policy.service_key else 'not set'}", flush=True)
        try:
            async with server:
                await server.serve_forever()
        finally:
            flusher.cancel()
            if control is not None:
                control.close()


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
                               _env_hosts("ATTACKLEDGER_GATEWAY_SERVICE_HOSTS", SERVICE_HOSTS),
                               service_key=os.environ.get("ANTHROPIC_API_KEY")),
                 deny_hosts=deny, upstream_dns=os.environ.get("ATTACKLEDGER_GATEWAY_UPSTREAM_DNS") or None)
    dns_port = int(os.environ.get("ATTACKLEDGER_GATEWAY_DNS_PORT", "53"))
    control_port = int(os.environ.get("ATTACKLEDGER_GATEWAY_CONTROL_PORT", "8081"))
    asyncio.run(gw.serve(port=int(os.environ.get("ATTACKLEDGER_GATEWAY_PORT", "8080")), dns_port=dns_port or None,
                         control_port=control_port or None))


if __name__ == "__main__":
    main()
