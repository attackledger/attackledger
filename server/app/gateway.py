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
import hashlib
import html
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
import zlib
import urllib.error
import urllib.request
from collections import OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, quote, unquote, unquote_plus, urlsplit

import h11

from . import gatewaylog, redact, scope

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
# katana, given -proxy, first asks the proxy whether it is Burp Suite (projectdiscovery's proxy
# helper: GET http://burpsuite/, looking for Burp's start page); it has no flag to skip that. The
# gateway answers it itself: nothing is sent and, as it is the tool talking to its proxy and not a
# request towards anyone, it is not a row in the request log a client reads.
PROXY_SELF_CHECKS = frozenset({"http://burpsuite/", "http://burpsuite"})
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
# The API refused what it was sent, not a fault resending fixes: a body it cannot read, too large,
# or a row it cannot take. The batch is halved until the row is found; that row is set aside (the
# quarantine file) and a placeholder is logged in its place (gatewaylog.py). Every other answer
# (no answer, 5xx, 401, 403, 404, 429) keeps the rows queued, to be sent again.
LOG_REFUSED = frozenset({400, 413, 422})
QUARANTINE_MAX_BYTES = 16 * 1024 * 1024    # rows past this are not kept in the file; their placeholders still are
# How often the gateway asks the API which engagements of its quarantine file had their content
# deleted, and removes their rows (and once at start, for a deletion made while it was down).
QUARANTINE_PURGE_SECONDS = 60.0
PURGE_IDS = 5000                           # ids per question (gatewayapi.PURGE_IDS)
CONNECT_TIMEOUT = 10.0
PROBE_TIMEOUT = 3.0
READ_TIMEOUT = 60.0      # between two reads from either side
# A head as a whole, a target's informational (1xx) answers included: each read coming within
# READ_TIMEOUT did not bound it, so a target sending a line at a time, or 100 Continue for ever,
# held the connection as long as it liked (fuzzing, FZ-22).
HEAD_TIMEOUT = 90.0
MAX_INFORMATIONAL = 32
SCRUBBED_BODY_TIMEOUT = 300.0    # a test account's response, read whole before anything goes back
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
# The deployment's own containers, by every name that resolves to one of their addresses. Docker
# answers a service name with its address on one shared network only, so a container the gateway
# shares two networks with has an alias per network (docker-compose.yml; security review GW-6).
# The gateway's own aliases are here too: gateway-lab is its address on the lab's network, which
# is otherwise a target network (ATTACKLEDGER_GATEWAY_TARGET_NETWORKS).
DENY_HOSTS = ("db", "api", "api-control", "api-default", "web", "worker", "gateway", "gateway-internal",
              "gateway-lab", "caddy", "lab-proxy", "lab-proxy-lab", "lab-proxy-default")
# Cloud metadata services outside link-local (169.254.0.0/16 is refused as link-local): Alibaba
# Cloud, AWS over IPv6, Azure's WireServer, Oracle Cloud Classic (security review GW-5).
METADATA_ADDRESSES = frozenset(ipaddress.ip_address(a) for a in (
    "100.100.100.200", "fd00:ec2::254", "168.63.129.16", "192.0.0.192"))
# Removed from an agent's Claude API call; the gateway's own key goes in their place.
SERVICE_KEY_HEADERS = frozenset({"x-api-key", "authorization"})
# What an agent run's Claude API call may carry (agentloop.request_params, and what count_tokens
# takes). Anything else is refused: server tools (web fetch, web search, code execution), the MCP
# connector (mcp_servers) and URL sources in content make Anthropic's servers reach hosts the
# gateway never checks, so they would be a way out of the scope (security review GW-1).
SERVICE_BODY_KEYS = frozenset({"model", "max_tokens", "system", "tools", "messages", "thinking", "output_config",
                               "cache_control", "fallbacks", "tool_choice", "stream", "metadata", "temperature",
                               "top_p", "top_k", "stop_sequences", "service_tier"})
# The worker's channel (D-042): what the control port relays to the API, and nothing else.
CONTROL_PATH = re.compile(r"^/worker/[a-z0-9/_-]{0,200}$")
CONTROL_METHODS = frozenset({"GET", "POST"})
MAX_CONTROL_BODY = 16 * 1024 * 1024
DNS_TYPES = {1: "A", 5: "CNAME", 28: "AAAA"}
# A header name as HTTP/1.1 allows it (RFC 9110 5.1, a token), and what h11 accepts in a value
# when it writes one: no NUL, no CR, LF or other whitespace but spaces and tabs inside.
HEADER_NAME = re.compile(r"[-!#$%&'*+.^_`|~0-9A-Za-z]+")
_WIRE_NAME = re.compile(rb"[-!#$%&'*+.^_`|~0-9A-Za-z]+")
_WIRE_VALUE = re.compile(rb"(?:[^\x00\s]+(?:[ \t]+[^\x00\s]+)*)?")
NETWORK_REFRESH = 60.0   # the deployment's addresses and the gateway's own networks are re-read this often


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
    organization_id: int | None = None   # the job's (D-042); the API answers only for its own

    @classmethod
    def from_api(cls, d: dict) -> "Rules":
        return cls(job_id=int(d["job_id"]), engagement_id=int(d["engagement_id"]), kind=str(d["kind"]),
                   traffic=str(d["traffic"]), include=tuple(d.get("include") or ()),
                   exclude=tuple(d.get("exclude") or ()), rate_limit_rps=max(1, int(d["rate_limit_rps"])),
                   research_header=d.get("research_header") or None,
                   research_user_agent=d.get("research_user_agent") or None, redact=bool(d.get("redact", True)),
                   organization_id=int(d["organization_id"]) if d.get("organization_id") is not None else None)

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
        ctx.sni_callback = _keep_server_name
        self._contexts[host] = (time.time() + (self.LEAF_DAYS - 1) * 86400, ctx)
        while len(self._contexts) > 1024:
            self._contexts.popitem(last=False)
        return ctx


def _keep_server_name(ssl_object, server_name, _ctx):
    """The TLS server name (SNI) a client asked for, kept on its connection so the tunnel can
    compare it with the CONNECT host once the handshake is done (server_name_of). The leaf is the
    CONNECT host's whatever is asked; OpenSSL has already refused an empty, overlong or
    NUL-holding name, and Python one that is not ASCII, before this is called. Never raises:
    an exception here would be printed and fail the handshake with an internal error."""
    try:
        ssl_object.attackledger_server_name = server_name
    except Exception:                       # noqa: BLE001  (an object that takes no attribute)
        pass
    return None


def server_name_of(ssl_object) -> str | None:
    """The SNI a client sent in this TLS connection's handshake, or None (it sent none)."""
    name = getattr(ssl_object, "attackledger_server_name", None)
    return name if isinstance(name, str) else None


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

    async def content_deleted(self, engagements: list[int], jobs: list[int]):
        return await asyncio.to_thread(self._call, "POST", "/gateway/content-deleted",
                                       {"engagements": engagements, "jobs": jobs})


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
    except ValueError:      # binascii.Error, UnicodeDecodeError, and a value that is not ASCII (FZ-20)
        raise Refused(407, "the job credential is malformed")
    m = USER_RE.match(user)
    if not sep or not m or not secret:
        raise Refused(407, "the job credential is malformed (user job-<id>.<tool>)")
    return int(m.group(1)), m.group(2) or "unknown", secret


def header_problem(name, value) -> str | None:
    """Why a header that a person or the API gave (a test account's, D-040, or an approved
    write's, D-041) cannot be sent as it is, or None. Stricter than what h11 accepts when it
    writes a request: no control character at all (tab inside a value aside), and Latin-1 only,
    which is how the gateway writes header values. Checked where the value comes in (the API
    answers 422) and again here before anything is sent. The sentence never repeats the value."""
    if not isinstance(name, str) or not HEADER_NAME.fullmatch(name):
        return "its name is not a header name (letters, digits and !#$%&'*+-.^_`|~ only)"
    if not isinstance(value, str):
        return "its value is not text"
    if "\r" in value or "\n" in value:
        return "its value has a line break (CR or LF)"
    if any((ord(c) < 32 and c != "\t") or ord(c) == 127 for c in value):
        return "its value has a control character"
    if any(ord(c) > 255 for c in value):
        return "its value has a character outside Latin-1"
    if value != value.strip(" \t"):
        return "its value starts or ends with a space"
    return None


def checked_headers(pairs, what: str) -> list[tuple[bytes, bytes]]:
    """[name, value] pairs from the API (an approved request's headers, a test account's) as
    bytes to send. Raises Refused, naming the header but never its value."""
    out = []
    for pair in pairs or []:
        try:
            name, value = pair
        except (TypeError, ValueError):
            raise Refused(400, f"not sent: {what} has a header that is not a name and a value")
        problem = header_problem(name, value)
        if problem:
            label = name[:60] if isinstance(name, str) and HEADER_NAME.fullmatch(name) else "(unnamed)"
            raise Refused(400, f"not sent: {what} has a header {label} that cannot be sent: {problem}")
        out.append((name.encode("ascii"), value.encode("latin-1")))
    return out


def _wire_problem(headers) -> str | None:
    """Why h11 would refuse to write these headers, or None. Checked before anything is sent, so
    a header the gateway cannot write is a refusal in the log, not a connection ended by an error
    (the value is never named: it may be a test account's session)."""
    for k, v in headers:
        if not _WIRE_NAME.fullmatch(k):
            return "a header name is not a valid token"
        if not _WIRE_VALUE.fullmatch(v):
            name = k.decode("ascii")[:60]
            return f"the value of header {name} has a line break, a NUL or another character HTTP/1.1 does not allow"
    return None


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
    # ASCII digits only: "²".isdigit() is True and int("²") raises (fuzzing, FZ-20).
    if not (port.isascii() and port.isdigit()) or not 0 < int(port) < 65536:
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
        # What urlsplit reads as the query, without urlsplit: a path such as "//[x/" made it
        # raise (Invalid IPv6 URL) and the request was dropped without a row (FZ-20).
        query = path.partition("#")[0].partition("?")[2]
        for k, v in parse_qsl(query, keep_blank_values=True):
            m = v.strip().upper()
            if k.lower() == "_method" and m.isalpha() and m not in READ_ONLY and m != method:
                raise Refused(403, f"_method={v[:20]} is refused")
        if kind == "target" and not rules.identification():
            raise Refused(403, "the engagement has no research header or user agent; nothing is sent to targets")

    @staticmethod
    def check_service_body(body: bytes) -> None:
        """A Claude API call is sent only if Anthropic will not reach anything on its behalf: no
        server tools, no MCP servers, no URL sources (SERVICE_BODY_KEYS). The body is forwarded as
        received, so it is parsed strictly: a key given twice is refused, as another parser might
        keep the other one."""
        def unique(pairs):
            out = {}
            for k, v in pairs:
                if k in out:
                    raise ValueError(f"the key {k[:40]} is given twice")
                out[k] = v
            return out
        try:
            doc = json.loads(body, object_pairs_hook=unique)
        except (ValueError, RecursionError) as e:
            raise Refused(403, f"Claude API call not sent: the body is not one JSON object ({str(e)[:80]})")
        if not isinstance(doc, dict):
            raise Refused(403, "Claude API call not sent: the body is not one JSON object")
        extra = sorted(set(doc) - SERVICE_BODY_KEYS)
        if extra:
            raise Refused(403, f"Claude API call not sent: {', '.join(extra)[:100]} is not what an agent run sends")
        tools = doc.get("tools") or []
        if not isinstance(tools, list) or any(not isinstance(t, dict) or t.get("type", "custom") != "custom"
                                              for t in tools):
            raise Refused(403, "Claude API call not sent: only the agent's own tools are allowed, no server tools "
                               "(they would reach hosts the gateway does not check)")
        stack = [doc.get("messages"), doc.get("system")]
        while stack:
            v = stack.pop()
            if isinstance(v, list):
                stack += v
            elif isinstance(v, dict):
                if v.get("type") == "url":
                    raise Refused(403, "Claude API call not sent: a URL source would be fetched by Anthropic, "
                                       "not through the gateway")
                stack += v.values()

    def headers(self, rules: Rules, kind: str, headers, host_header: str, *, account: dict | None = None,
                approved: list | None = None) -> list[tuple[bytes, bytes]]:
        """The headers sent upstream: the tool's (as received), or for an approved write the
        approved ones, minus hop-by-hop and identification names, then Host, the identification
        (targets), the test account's headers and Connection: close."""
        if approved is not None:
            headers = [(k.lower(), v) for k, v in checked_headers(approved, "the approved request")]
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
        problem = _wire_problem(out)
        if problem:
            raise Refused(400, f"not sent: {problem}")
        return out

    # ---- hooks for later decisions -------------------------------------------------

    def inject_credentials(self, rules: Rules, kind: str, headers: list, account: dict | None) -> list:
        """D-040: a test account's headers replace any of the same names the tool sent. The
        response is then read whole, uncompressed, so it can be scrubbed (scrub_response). The log
        never holds header values."""
        if not account or kind != "target":
            return headers
        extra = checked_headers(account["headers"], f"test account {account.get('label', '')}".strip())
        names = {n.decode("ascii").lower() for n, _ in extra} | {"accept-encoding"}
        out = [(k, v) for k, v in headers if k.decode("latin-1").lower() not in names]
        out += extra
        out.append((b"Accept-Encoding", b"identity"))
        return out


def account_values(account: dict) -> list[str]:
    """The secret values an account's headers carry: each header value, each cookie's value and a
    bearer token on its own, longest first, so a response that echoes them can be scrubbed. Each
    also in the forms a page shows it in (security review GW-4): URL-decoded (phpinfo's $_COOKIE,
    debug pages) and URL-encoded, HTML-escaped and with escaped slashes (JSON)."""
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
    forms = set()
    for v in out:
        for form in (v, unquote(v), unquote_plus(v)):
            forms |= {form, quote(form, safe=""), html.escape(form), html.escape(form, quote=False),
                      form.replace("/", "\\/")}
    return sorted((v for v in forms if len(v) >= MIN_SCRUB), key=len, reverse=True)


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
    rules: "Rules | None" = None
    tool: str = "unknown"
    kind: str = "target"
    rows: int = 0               # rows logged for what the tunnel carried; none: the tunnel gets one
    idle: bool = False          # it ended because no request came within HEAD_TIMEOUT


class Gateway:
    def __init__(self, api: Api, ca: CA | None, *, policy: Policy | None = None,
                 deny_hosts=DENY_HOSTS, upstream_dns: str | None = None, clock=time.monotonic,
                 networks=None, target_networks=(), quarantine: str | None = None):
        self.api, self.ca, self.policy = api, ca, policy or Policy()
        # Where request log rows the API refused are set aside (in the gateway's private volume).
        self.quarantine_path = quarantine
        self.deny_hosts = tuple(deny_hosts)
        # The networks the gateway is attached to (a callable: interface_networks, or a list in
        # tests), and the names or addresses that mark which of them hold targets (the lab's).
        self.networks = networks if networks is not None else interface_networks
        self.target_networks = tuple(t for t in target_networks if t)
        self.upstream_dns = upstream_dns or _resolv_conf_nameserver()
        self.clock = clock
        self.verify_ctx, self.insecure_ctx = _client_contexts()
        self.limiters: dict[int, Limiter] = {}
        self.dns_limiters: dict[int, Limiter] = {}
        self.passive_limiters: dict[str, Limiter] = {}
        # Upstream connections are paced too, before they are opened: the request token is taken
        # only once the connection is open, so without these a tool's concurrency would open
        # connections (and TLS handshakes) to a target at any rate (security review GW-2).
        self.connect_limiters: dict[object, Limiter] = {}
        self._rules: dict[tuple, tuple[float, Rules | Refused]] = {}
        self._rules_locks: dict[tuple, asyncio.Lock] = {}
        self._accounts: dict[tuple, tuple[float, dict | Refused]] = {}
        self._dns_scopes: tuple[float, list] = (0.0, [])
        self._denied: tuple[float, set] = (0.0, set())
        self._own_networks: tuple[float, list, list] = (0.0, [], [])
        self.log_rows: list[dict] = []
        self.dropped = 0
        self.log_batch = LOG_BATCH        # smaller while the row the API refuses is searched for
        self.quarantined = 0              # rows set aside, and how many of them the file could not keep
        self.quarantine_lost = 0
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
                try:            # checked here, before an approval is used for a request as this account
                    checked_headers(data["headers"], f"test account {label}")
                except Refused as e:
                    hit = (hit[0], Refused(403, e.reason))
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
        self._denied = (self.clock() + NETWORK_REFRESH, out)
        return out

    async def own_networks(self) -> tuple[list, list]:
        """(refused, target): the subnets of the gateway's own interfaces, split into those no
        request may reach and those that hold targets (the lab's network, named by an address of
        the gateway on it: target_networks). Refreshed every minute.

        Why the gateway's own networks are refused although private addresses are allowed: the
        Docker host has an address on each of them (the bridge, 172.x.0.1 on the default network),
        and so do the deployment's containers, so an in-scope name that resolves into one of them
        reaches the host's services or the stack itself. A real internal target (a bank's 10.x or
        172.16/12 network) is never there: a destination inside the subnet of one of the gateway's
        interfaces is routed to that Docker network, never to the customer's network, so refusing
        it takes nothing away. Other private addresses stay allowed."""
        if self._own_networks[0] > self.clock():
            return self._own_networks[1], self._own_networks[2]
        nets = self.networks() if callable(self.networks) else list(self.networks)
        marks = []
        loop = asyncio.get_running_loop()
        for entry in self.target_networks:
            try:
                marks.append(ipaddress.ip_network(entry, strict=False))
                continue
            except ValueError:
                pass
            try:
                for info in await loop.getaddrinfo(entry, None, type=socket.SOCK_STREAM):
                    marks.append(ipaddress.ip_network(info[4][0].split("%")[0]))
            except (OSError, ValueError):
                pass                      # not attached (yet): its network stays refused
        target = [n for n in nets if any(m.version == n.version and m.overlaps(n) for m in marks)]
        refused = [n for n in nets if n not in target]
        self._own_networks = (self.clock() + NETWORK_REFRESH, refused, target)
        return refused, target

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
        # The address connected to, and the IPv4 address it carries, if any (embedded_ipv4).
        for ip in dict.fromkeys(a for a in (embedded_ipv4(addrs[0]), addrs[0]) if a is not None):
            if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip in METADATA_ADDRESSES:
                raise Refused(403, f"{host} resolves to {ip}, which is never contacted (loopback, link-local, cloud "
                                   f"metadata or special address)")
            if ip in await self._denied_addresses():
                raise Refused(403, f"{host} resolves to an address of this deployment, which is never contacted")
            refused, _ = await self.own_networks()
            net = next((n for n in refused if ip.version == n.version and ip in n), None)
            if net is not None:
                raise Refused(403, f"{host} resolves to {ip}, on the gateway's own network {net} (the Docker host and "
                                   f"this deployment), which is never contacted; only the lab's network is a target "
                                   f"there")
        mapped = addrs[0].ipv4_mapped if addrs[0].version == 6 else None
        return str(mapped or addrs[0])          # an IPv4-mapped address is connected to as IPv4, as before

    def connect_limiter(self, rules: Rules, kind: str, host: str) -> Limiter | None:
        """The limiter a new upstream connection waits for: the engagement's rate for targets,
        PASSIVE_RPS per passive host. Service calls (the Claude API) are not paced."""
        if kind == "target":
            key, rate = rules.engagement_id, rules.rate_limit_rps
        elif kind == "passive":
            key, rate = ("passive", host), PASSIVE_RPS
        else:
            return None
        lim = self.connect_limiters.get(key)
        if lim is None:
            lim = self.connect_limiters[key] = Limiter(rate, clock=self.clock)
        lim.rate = rate
        return lim

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
            # The reason too: some quote the request (a write that is not the approved one names its URL).
            url, reason = redact.text(url, redact.Report()), redact.text(reason, redact.Report())
        row = {"at": datetime.now(timezone.utc).isoformat(),
               "engagement_id": rules.engagement_id if rules else engagement_id,
               "job_id": rules.job_id if rules else job_id, "tool": tool[:32], "kind": kind, "method": method[:16],
               "url": url[:2000], "host": host[:255], "port": port, "status": status, "verdict": verdict,
               "reason": reason[:300], "bytes_sent": sent, "bytes_received": received,
               "duration_ms": int((self.clock() - started) * 1000) if started is not None else None,
               "account": account[:16] if account else None, "approval_id": approval_id}
        if len(self.log_rows) >= 2 * LOG_BACKLOG:
            self.dropped += 1         # only refusals get here: nothing is sent while the log is full
            return
        self.log_rows.append(row)

    async def flush_log(self) -> bool:
        """Sends the oldest waiting rows. True if the log moved on (written, or a refused row found
        and set aside); False if nothing was written, and the rows wait to be sent again."""
        if not self.log_rows:
            self.log_batch = LOG_BATCH
            return True
        batch = self.log_rows[:max(1, min(LOG_BATCH, self.log_batch))]
        status, data = await self.api.post_log(batch)
        if status == 200:
            for i, why in _unlogged(data, len(batch)):
                self.set_aside(batch[i], f"the API stored a placeholder instead: {why}")
            del self.log_rows[:len(batch)]
            return True
        if status in LOG_REFUSED:
            if len(batch) > 1:
                self.log_batch = len(batch) // 2          # the row it refuses is in here: halve until it is alone
                return True
            # One row, refused. Only if the API takes its placeholder is it this row and not the API.
            why = f"the API refused it with {status}{_detail(data)}"
            p_status, _ = await self.api.post_log([gatewaylog.placeholder(batch[0], why)])
            if p_status == 200:
                self.set_aside(batch[0], why)
                del self.log_rows[:1]
                self.log_batch = LOG_BATCH
                return True
            status, data = p_status, {"detail": "the API refused a placeholder row too"}
        print(f"gateway: request log not written ({status}: {str(data)[:200]}); "
              f"{len(self.log_rows)} rows waiting", file=sys.stderr, flush=True)
        return False

    def set_aside(self, row: dict, why: str) -> None:
        """Keeps a row the API would not store in the quarantine file, one JSON line each. The row is
        what the API was sent, so the file holds nothing the log would not (URLs redacted as there,
        no header values). The file is bounded: past QUARANTINE_MAX_BYTES a row is only counted, and
        its placeholder in the log still says it existed."""
        self.quarantined += 1
        line = (json.dumps({"set_aside_at": datetime.now(timezone.utc).isoformat(), "why": why[:300], "row": row},
                           separators=(",", ":")) + "\n").encode()
        kept = ""
        try:
            if not self.quarantine_path:
                raise OSError("no quarantine file is configured")
            fd = os.open(self.quarantine_path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "ab") as f:
                size = os.fstat(fd).st_size
                if size + len(line) > QUARANTINE_MAX_BYTES:
                    raise OSError(f"the file is full ({QUARANTINE_MAX_BYTES} bytes)")
                if size and os.pread(fd, 1, size - 1) != b"\n":
                    line = b"\n" + line        # after a line cut short (a crash): this row stays whole
                f.write(line)
            kept = f"kept in {self.quarantine_path}"
        except OSError as e:
            self.quarantine_lost += 1
            kept = f"not kept: {str(e)[:120]}; {self.quarantine_lost} rows not kept so far"
        print(f"gateway: a request log row the API refused was set aside, a placeholder logged in its place "
              f"({why[:160]}; {kept})", file=sys.stderr, flush=True)

    def _quarantined_lines(self) -> list[tuple[bytes, dict | None]]:
        """The quarantine file's lines, each with its row (None for a line that is not one)."""
        try:
            with open(self.quarantine_path, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            return []
        out = []
        for line in data.splitlines(keepends=True):
            try:
                doc = json.loads(line)
                row = doc.get("row") if isinstance(doc, dict) and line.endswith(b"\n") else None
            except ValueError:
                row = None
            out.append((line, row if isinstance(row, dict) else None))
        return out

    async def purge_quarantine(self) -> int:
        """Removes from the quarantine file the rows of engagements whose content was deleted (by
        their engagement, or by their job for a row that names no engagement), as the API answers
        (POST /gateway/content-deleted): the file is in the gateway's private volume, which the API
        does not mount. Without an answer nothing is removed, and the next pass asks again. A line
        that is not a whole row (a write cut short) cannot be attributed and goes too. Returns how
        many lines were removed."""
        if not self.quarantine_path:
            return 0
        lines = self._quarantined_lines()
        engs = sorted({r["engagement_id"] for _, r in lines if r and type(r.get("engagement_id")) is int})
        jobs = sorted({r["job_id"] for _, r in lines if r and type(r.get("job_id")) is int})
        gone_engs, gone_jobs = set(), set()
        for i in range(0, max(len(engs), len(jobs)), PURGE_IDS):
            status, data = await self.api.content_deleted(engs[i:i + PURGE_IDS], jobs[i:i + PURGE_IDS])
            if status != 200 or not isinstance(data, dict):
                print(f"gateway: cannot ask which quarantined rows belong to deleted content ({status}: "
                      f"{_detail(data) or 'no detail'}); the file is kept as it is", file=sys.stderr, flush=True)
                return 0
            gone_engs |= {v for v in data.get("engagements") or [] if type(v) is int}
            gone_jobs |= {v for v in data.get("jobs") or [] if type(v) is int}
        # No await from here on: set_aside runs on this event loop too, so the file is read again
        # and replaced with no row appended in between (one set aside while the API answered stays).
        lines = self._quarantined_lines()
        keep = [line for line, r in lines
                if r is not None and r.get("engagement_id") not in gone_engs and r.get("job_id") not in gone_jobs]
        removed = len(lines) - len(keep)
        if removed:
            self._replace_quarantine(b"".join(keep))
            print(f"gateway: removed {removed} rows of deleted engagements from the quarantine file",
                  file=sys.stderr, flush=True)
        return removed

    def _replace_quarantine(self, data: bytes) -> None:
        tmp = f"{self.quarantine_path}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.quarantine_path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    async def purge_forever(self) -> None:
        while True:
            try:
                await self.purge_quarantine()
            except Exception as e:  # noqa: BLE001 - the next pass tries again; the proxy keeps running
                print(f"gateway: the quarantine purge failed ({type(e).__name__}: {str(e)[:120]})",
                      file=sys.stderr, flush=True)
            await asyncio.sleep(QUARANTINE_PURGE_SECONDS)

    async def flush_forever(self) -> None:
        while True:
            try:
                ok = await self.flush_log()
            except Exception as e:  # noqa: BLE001 - one bad answer must not stop the log for good (FZ-30)
                print(f"gateway: sending the request log failed ({type(e).__name__}: {str(e)[:120]}); "
                      f"{len(self.log_rows)} rows waiting", file=sys.stderr, flush=True)
                ok = False
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
            waited = self.clock()
            try:
                ev = await asyncio.wait_for(_next(conn, reader), HEAD_TIMEOUT)
            except h11.RemoteProtocolError as e:
                await self._unreadable(conn, writer, tunnel, e)
                return
            except asyncio.TimeoutError:
                await self._head_timed_out(conn, writer, tunnel, waited)
                return
            if not isinstance(ev, h11.Request):
                return
            if tunnel is None and ev.method == b"CONNECT":
                await self._connect(conn, reader, writer, ev)
                return
            if tunnel is not None:
                tunnel.rows += 1            # _request logs it, whatever happens to it
            keep = await self._request(conn, reader, writer, ev, tunnel)
            if not keep or conn.our_state is not h11.DONE or conn.their_state is not h11.DONE:
                return
            conn.start_next_cycle()

    async def _unreadable(self, conn, writer, tunnel: Tunnel | None, e: h11.RemoteProtocolError) -> None:
        """A request head h11 refuses (not ASCII, a bad Content-Length, a line that is not a header,
        too large): answered with h11's status and logged, without the URL, which was not read
        (FZ-21). Before, the connection was closed with no answer and no row."""
        started, rules, tool = self.clock(), None, "unknown"
        if tunnel is not None:
            rules, tool = tunnel.rules, tunnel.tool
            try:
                rules, tool = await self.identify(tunnel.auth)
            except Refused:
                pass
        hint = getattr(e, "error_status_hint", 400)
        refusal = Refused(hint if 400 <= hint < 500 else 400,
                          f"the request is not valid HTTP/1.1 ({str(e).split(':')[0][:80]})")
        self._unread_row(tunnel, rules, tool, refusal, started)
        await self._refuse(conn, writer, b"GET", refusal)

    def _unread_row(self, tunnel: Tunnel | None, rules, tool: str, refusal: Refused, started: float) -> None:
        if tunnel is not None:
            tunnel.rows += 1
        self.record(rules=rules, tool=tool, kind="target", method="", url="", host=tunnel.host if tunnel else "",
                    port=tunnel.port if tunnel else None, status=refusal.status, verdict="refused",
                    reason=refusal.reason, started=started)

    async def _head_timed_out(self, conn, writer, tunnel: Tunnel | None, waited: float) -> None:
        """No whole request head within HEAD_TIMEOUT (or READ_TIMEOUT between two reads). If part
        of one had arrived, the connection is answered 408 and logged like a head h11 refuses: before,
        it was closed with no row (fuzzing, third pass). An idle connection (a keep-alive between two
        requests, the healthcheck's connect) has nothing to log and is closed."""
        conn.receive_data(b"")                  # as if the client had closed: h11 says what it holds
        try:
            conn.next_event()
        except h11.RemoteProtocolError:
            refusal = Refused(408, "the request head did not arrive in time; nothing was sent")
            rules, tool = (tunnel.rules, tunnel.tool) if tunnel else (None, "unknown")
            self._unread_row(tunnel, rules, tool, refusal, waited)
            await self._refuse(conn, writer, b"GET", refusal)
            return
        if tunnel is not None:
            tunnel.idle = True

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
        def row(verdict: str, status: int | None, reason: str) -> None:
            self.record(rules=rules, tool=tool, kind=kind, method="CONNECT", url=f"{host}:{port}", host=host,
                        port=port, status=status, verdict=verdict, reason=reason, started=started)
        try:
            # A CONNECT has no content (RFC 9110 9.3.6), and nothing may come before the 200. Both
            # ended the connection with no answer and no row before (fuzzing, third pass).
            try:
                end = await asyncio.wait_for(_next(conn, reader), HEAD_TIMEOUT)
            except Exception as e:                  # cut off, timed out, unreadable
                raise _not_checked(e)
            if not isinstance(end, h11.EndOfMessage):
                raise Refused(400, "a CONNECT request has no body; nothing was relayed")
            data, closed = conn.trailing_data
            if data:
                raise Refused(400, EARLY_BYTES)
        except Refused as e:
            row("failed" if e.status >= 500 else "refused", e.status, e.reason)
            await self._refuse(conn, writer, b"CONNECT", e)
            return
        if closed:
            row("failed", None, "the client closed the connection before the tunnel was open; nothing was relayed")
            return
        writer.write(conn.send(h11.Response(status_code=200, headers=[], reason=b"Connection established")))
        await writer.drain()
        # From here on, the tunnel has one row of its own unless a request in it was logged: a tunnel
        # that never carried one (a failed handshake, a TLS scanner, a client that went away) was not
        # in the log at all before (fuzzing, third pass). One row per connection, never more.
        tunnel = Tunnel(host, port, auth, rules=rules, tool=tool, kind=kind)
        verdict, why = "failed", "the client closed the tunnel before sending a request; nothing was relayed"
        try:
            # Bytes read from the client but not yet consumed would be read inside the tunnel as if
            # they had come through TLS (fuzzing, third pass). No await between this check and
            # start_tls, which stops reading before it gives the loop a turn.
            if conn.our_state is not h11.SWITCHED_PROTOCOL or _buffered(reader):
                verdict, why = "refused", EARLY_BYTES
                return
            # Every tunnel is TLS with the gateway's certificate. A client that sends anything else,
            # or does not trust the CA, fails the handshake and is disconnected: nothing is relayed.
            try:
                await writer.start_tls(self.ca.server_context(host), ssl_handshake_timeout=HANDSHAKE_TIMEOUT)
            except (ssl.SSLError, OSError, asyncio.TimeoutError) as e:
                verdict, why = "refused", _tls_failure(e) + "; nothing was relayed"
                return
            sni = server_name_of(writer.get_extra_info("ssl_object"))
            if sni is not None and sni.lower().rstrip(".") != host:
                # The certificate was the CONNECT host's, and every request must name it in Host:
                # nothing could reach another host. Refused all the same, and said so.
                verdict, why = "refused", (f"the TLS server name (SNI) {sni[:100]} is not the tunnel's host "
                                           f"{host[:100]}; nothing was relayed")
                return
            try:
                await self._serve(reader, writer, tunnel)
            except (ssl.SSLError, OSError, asyncio.TimeoutError, h11.ProtocolError) as e:
                why = f"the tunnel ended before a request ({_tls_failure(e, handshake=False)}); nothing was relayed"
                raise
            if tunnel.idle:
                why = f"the tunnel carried no request in {HEAD_TIMEOUT:g} s; nothing was relayed"
        finally:
            if not tunnel.rows:
                row(verdict, None, why)

    async def _probe(self, conn, writer, rules: Rules, tool: str, host: str, port: int, started: float) -> None:
        # A probe is a connection too: it waits for the connection limiter like a request does, so
        # probes and requests together open at most the rate in connections (security recheck GW-2).
        await self.connect_limiter(rules, "target", host).acquire(MAX_WAIT)
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
                if method == "GET" and target.lower() in PROXY_SELF_CHECKS:
                    await self.identify(auth)        # a job's tool, or refused and logged as usual
                    return await self._answer_self_check(conn, reader, writer)
                if not target.lower().startswith("http://"):
                    raise Refused(400, "send http:// URLs in absolute form, and https:// through CONNECT")
                try:
                    parts = urlsplit(target)
                except ValueError:              # "http://[shop/": Invalid IPv6 URL (FZ-20)
                    raise Refused(400, "not a valid URL")
                if parts.username is not None or parts.password is not None:
                    raise Refused(403, "URLs with credentials are not sent")
                host, port = split_authority(parts.netloc, 80)
                scheme, path = "http", (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
            else:
                auth, host, port, scheme, path = tunnel.auth, tunnel.host, tunnel.port, "https", target
                # The tunnel's job and host, named in every row its requests leave, refusals too.
                rules, tool, kind = tunnel.rules, tunnel.tool, tunnel.kind
                rules, tool = await self.identify(auth)
                if method == "PRI" and target == "*":
                    raise Refused(400, "HTTP/2 is not spoken here: the gateway offers HTTP/1.1 only (ALPN http/1.1)")
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
                if not (approval_text.isascii() and approval_text.isdigit()) or len(approval_text) > 12:
                    raise Refused(400, "X-AttackLedger-Approval names an approval by its number")
                approval_id = int(approval_text)
            self.policy.check(rules, kind, method, path, ev.headers, write=approval_id is not None)
            body = b""
            if kind == "service":
                body = await _read_body(conn, reader, MAX_SERVICE_BODY)
                self.policy.check_service_body(body)
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
                                  [(k.lower(), v) for k, v in checked_headers(approved["headers"],
                                                                              "the approved request")], write=True)
            out = self.policy.headers(rules, kind, ev.headers, host if port == default else f"{host}:{port}",
                                      account=account, approved=approved["headers"] if approved else None)
            if body:
                out.append((b"Content-Length", str(len(body)).encode()))
        except Exception as e:
            # Every request that gets here is answered and logged, whatever stopped it: a refusal,
            # a request h11 could not read to the end, or a bug in a check (FZ-20, FZ-21). Before,
            # anything but Refused ended the connection with no answer and no row.
            if not isinstance(e, Refused):
                e = _not_checked(e)
            self.record(rules=rules, tool=tool, kind=kind, method=method, url=url, host=host, port=port,
                        status=e.status, verdict="failed" if e.status >= 500 else "refused", reason=e.reason,
                        started=started, account=account["label"] if account else label, approval_id=approval_id)
            await self._refuse(conn, writer, ev.method, e)
            return False
        return await self._forward(conn, writer, rules, tool, kind, method, scheme, host, port, path, out, body,
                                   url, started, wants_errors=_header(ev.headers, ERRORS_HEADER) is not None,
                                   account=account, approval_id=approval_id)

    async def _answer_self_check(self, conn, reader, writer) -> bool:
        """katana's "are you Burp Suite?" question (PROXY_SELF_CHECKS): no, answered here."""
        await _next(conn, reader)
        body = b"AttackLedger gateway\n"
        writer.write(conn.send(h11.Response(status_code=404, headers=[
            ("Content-Type", "text/plain; charset=utf-8"), ("Content-Length", str(len(body))),
            (REFUSED_HEADER, "proxy"), ("Connection", "close")])))
        writer.write(conn.send(h11.Data(data=body)))
        writer.write(conn.send(h11.EndOfMessage()))
        await writer.drain()
        return False

    async def _forward(self, conn, writer, rules, tool, kind, method, scheme, host, port, path, headers, body,
                       url, started, wants_errors: bool = True, account: dict | None = None,
                       approval_id: int | None = None) -> bool:
        status, received, reason, sent = None, 0, "", 0
        upw = None
        label = account["label"] if account else None
        try:
            try:        # h11 checks the head here, before anything is connected or sent
                request = h11.Request(method=method, target=path, headers=headers)
            except (h11.LocalProtocolError, UnicodeError):
                raise Refused(400, "not sent: the request cannot be written as HTTP/1.1")
            pace = self.connect_limiter(rules, kind, host)
            if pace is not None:
                await pace.acquire(MAX_WAIT)        # before anything reaches the target, the handshake too
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
            out = upc.send(request)
            if body:
                out += upc.send(h11.Data(data=body))
            out += upc.send(h11.EndOfMessage())
            upw.write(out)
            sent = len(out)           # the request as it left: head and body, in bytes
            await upw.drain()
            try:
                resp = await asyncio.wait_for(_final_head(upc, upr, host), HEAD_TIMEOUT)
            except asyncio.TimeoutError:
                raise Refused(502, f"{host} did not send its response head in time")
            except (h11.ProtocolError, OSError) as e:
                if upc.their_state is h11.SEND_RESPONSE and isinstance(e, h11.RemoteProtocolError):
                    raise Refused(502, f"{host} closed the connection without a response")
                raise Refused(502, f"{host} sent no valid response: {str(e)[:120] or type(e).__name__}")
            if not isinstance(resp, h11.Response):
                raise Refused(502, f"{host} closed the connection without a response")
        except Refused as e:
            if upw is not None:
                upw.close()
            self.record(rules=rules, tool=tool, kind=kind, method=method, url=url, host=host, port=port,
                        status=e.status, verdict="refused" if e.status in (400, 403, 429) else "failed",
                        reason=e.reason, sent=sent, started=started, account=label, approval_id=approval_id)
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
                        status=status, verdict="allowed", reason=reason, sent=sent, received=received,
                        started=started, account=label, approval_id=approval_id)
        return keep

    async def _scrubbed(self, conn, writer, upc, upr, resp, account: dict, method: str) -> tuple[bool, str, int]:
        """A response to a request sent as a test account: read whole, scrubbed, then sent on with
        its new length. (keep the client connection, reason, bytes received)."""
        chunks, size, reason = [], 0, ""

        async def read() -> str:
            nonlocal size
            while True:
                ev = await _next(upc, upr)
                if isinstance(ev, h11.Data):
                    size += len(ev.data)
                    if size > MAX_SCRUBBED_BODY:
                        return f"the response is larger than {MAX_SCRUBBED_BODY} bytes; it was cut off"
                    chunks.append(ev.data)
                elif isinstance(ev, h11.EndOfMessage):
                    return ""
                else:
                    return "the response ended early"
        try:        # nothing goes back before the end, so the whole body is bounded in time (FZ-22)
            reason = await asyncio.wait_for(read(), SCRUBBED_BODY_TIMEOUT)
        except asyncio.TimeoutError:
            reason = f"the response body did not arrive in time ({SCRUBBED_BODY_TIMEOUT:g} s); it was cut off"
        head = [(k, v) for k, v in resp.headers if k.decode("latin-1") not in HOP_BY_HOP]
        body = b"".join(chunks)
        # Accept-Encoding: identity was asked for, but a target may compress anyway, and the
        # account's values cannot be found in compressed bytes (security review GW-3): the body
        # is decoded here, or withheld when it cannot be.
        coding = ",".join(v.decode("latin-1") for k, v in head if k == b"content-encoding").strip().lower()
        if coding and coding != "identity":
            head = [(k, v) for k, v in head if k != b"content-encoding"]
            try:
                body = _decode(coding, body, MAX_SCRUBBED_BODY)
            except (ValueError, zlib.error) as e:
                body, reason = b"", reason or f"the response body was withheld: {str(e)[:100]}"
        head, body = scrub_response(account, head, body)
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

    async def start(self, host="0.0.0.0", port: int = 8080, dns_port: int | None = 53,
                    control_port: int | None = 8081) -> list:
        """Listen: the proxy, the control relay and the resolver on `host` (an address or a list
        of them: the gateway's address on the worker's network, see listen_addresses), and the
        proxy also on loopback, for the container's healthcheck. Port 0 picks a free port, None
        turns the part off. Returns the servers and the DNS transports."""
        hosts = [host] if isinstance(host, str) else list(host)
        everywhere = any(h in ("", "0.0.0.0", "::") for h in hosts)
        proxy_hosts = hosts if everywhere or "127.0.0.1" in hosts else [*hosts, "127.0.0.1"]
        out = [await asyncio.start_server(self.handle_client, proxy_hosts, port, limit=MAX_HEAD)]
        if control_port is not None:
            out.append(await asyncio.start_server(self.handle_control, hosts, control_port, limit=MAX_HEAD))
        loop = asyncio.get_running_loop()
        if dns_port is not None:
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
            for h in hosts:
                transport, _ = await loop.create_datagram_endpoint(_Dns, local_addr=(h, dns_port))
                out.append(transport)
        return out

    async def serve(self, host="0.0.0.0", port: int = 8080, dns_port: int | None = 53,
                    control_port: int | None = 8081) -> None:
        parts = await self.start(host, port, dns_port, control_port)
        server = parts[0]
        loop = asyncio.get_running_loop()
        flusher = loop.create_task(self.flush_forever())
        purger = loop.create_task(self.purge_forever())
        refused, target = await self.own_networks()
        hosts = [host] if isinstance(host, str) else list(host)
        print(f"gateway ready: proxy, dns and control on {', '.join(hosts)} (ports {port}, {dns_port}, {control_port}), "
              f"api {self.api.base}, claude key {'set' if self.policy.service_key else 'not set'}; own networks "
              f"refused: {', '.join(map(str, refused)) or 'none'}; target networks: "
              f"{', '.join(map(str, target)) or 'none'}", flush=True)
        try:
            async with server:
                await server.serve_forever()
        finally:
            flusher.cancel()
            purger.cancel()
            for p in parts[1:]:
                p.close()


def listen_addresses(value: str, *, wait: float = 30.0, resolve=socket.getaddrinfo, sleep=time.sleep,
                     bindable=None) -> list[str]:
    """The addresses ATTACKLEDGER_GATEWAY_LISTEN names (comma-separated names or addresses):
    in the compose files, the gateway's alias on the worker's network (gateway-internal), so
    the proxy, the resolver and the control relay answer there only, not on the control, default
    and lab networks. Docker's resolver answers a network alias with the address on that network.
    Only this container's own addresses count (a name another container shares is skipped).
    Empty: every interface (0.0.0.0), as before. A name that does not resolve within `wait`
    seconds is an error: the gateway does not start, so nothing is sent."""
    names = [v.strip() for v in (value or "").split(",") if v.strip()]
    if not names:
        return ["0.0.0.0"]
    bindable = bindable or _bindable
    deadline = time.monotonic() + wait
    while True:
        out, missing = [], []
        for name in names:
            try:
                addrs = [str(ipaddress.ip_address(name))]
            except ValueError:
                try:
                    addrs = sorted({i[4][0] for i in resolve(name, None, type=socket.SOCK_STREAM)})
                except OSError:
                    addrs = []
            own = [a for a in addrs if bindable(a)]
            if not own:
                missing.append(name)
            out += [a for a in own if a not in out]
        if not missing:
            return out
        if time.monotonic() >= deadline:
            raise RuntimeError(f"ATTACKLEDGER_GATEWAY_LISTEN: {', '.join(missing)} is not an address of this "
                               f"container; the gateway does not start")
        sleep(1.0)


NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")      # the well-known prefix; another one cannot be known


def embedded_ipv4(ip):
    """The IPv4 address an IPv6 address carries and is delivered to, or None: IPv4-mapped
    (::ffff:a.b.c.d), NAT64 (the well-known prefix of RFC 6052, delivered by a translator), 6to4
    (2002:aabb:ccdd::) and IPv4-compatible (::a.b.c.d). The checks apply to that address, so
    loopback, metadata and the gateway's own networks are refused in these forms too (security
    recheck)."""
    if ip.version != 6:
        return None
    if ip.ipv4_mapped:
        return ip.ipv4_mapped
    if ip in NAT64_PREFIX:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip.sixtofour:
        return ip.sixtofour
    if int(ip) >> 32 == 0 and int(ip) > 1:        # ::a.b.c.d (not :: and ::1)
        return ipaddress.IPv4Address(int(ip))
    return None


def _bindable(address: str) -> bool:
    """Whether this machine has the address (a socket can be bound to it)."""
    ip = ipaddress.ip_address(address)
    with socket.socket(socket.AF_INET6 if ip.version == 6 else socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.bind((address, 0))
            return True
        except OSError:
            return False


EARLY_BYTES = "the client sent bytes before the tunnel was open (wait for the 200 answer); nothing was relayed"


def _buffered(reader: asyncio.StreamReader) -> bool:
    """Whether the stream holds bytes nobody has read yet. asyncio has no public way to ask: this
    is the buffer StreamReader.read takes from (CPython 3.8 to 3.13)."""
    return bool(getattr(reader, "_buffer", b""))


def _tls_failure(e: Exception, handshake: bool = True) -> str:
    """Why a TLS handshake, or the TLS connection after it, failed, for the log."""
    if isinstance(e, ssl.SSLError):
        why = (e.reason or "").upper()
        if why in ("TLSV1_ALERT_UNKNOWN_CA", "SSLV3_ALERT_BAD_CERTIFICATE", "SSLV3_ALERT_CERTIFICATE_UNKNOWN"):
            return "the client refused the gateway's certificate: does it trust the gateway CA?"
        if why == "HTTP_REQUEST":
            return "the client sent plain HTTP, not TLS"
        return f"the TLS {'handshake ' if handshake else ''}failed: {(e.reason or type(e).__name__)[:80]}"
    if isinstance(e, asyncio.TimeoutError) or (isinstance(e, ConnectionAbortedError) and "longer than" in str(e)):
        return f"no TLS handshake within {HANDSHAKE_TIMEOUT:g} s" if handshake else "timed out"
    if isinstance(e, h11.ProtocolError):
        return "not valid HTTP/1.1"
    return f"the client closed the connection{' during the TLS handshake' if handshake else ''}"


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


async def _final_head(upc: h11.Connection, upr, host: str):
    """The response to a request, after at most MAX_INFORMATIONAL informational (1xx) answers."""
    for _ in range(MAX_INFORMATIONAL + 1):
        resp = await _next(upc, upr)
        if not isinstance(resp, h11.InformationalResponse):
            return resp
    raise Refused(502, f"{host} sent more than {MAX_INFORMATIONAL} informational (1xx) responses")


def _not_checked(e: Exception) -> Refused:
    """The refusal for a request whose checks stopped with something other than Refused: the
    client's message could not be read to the end, or a check has a bug. Never the exception's
    text for a bug: it may quote the request."""
    if isinstance(e, h11.RemoteProtocolError):
        return Refused(400, f"the request is not valid HTTP/1.1 ({str(e).split(':')[0][:80]})")
    if isinstance(e, asyncio.TimeoutError):
        return Refused(408, "the request did not arrive in time")
    if isinstance(e, (ConnectionError, asyncio.IncompleteReadError)):
        return Refused(400, "the client closed the connection before the request was complete")
    print(f"gateway: a request could not be checked: {type(e).__name__}: {str(e)[:300]}", file=sys.stderr, flush=True)
    return Refused(500, f"the gateway could not check this request ({type(e).__name__}); nothing was sent")


def _decode(coding: str, body: bytes, limit: int) -> bytes:
    """A body in Content-Encoding gzip or deflate, decoded (at most `limit` bytes). ValueError for
    any other encoding, or a body that decodes to more. A gzip body may hold several members one
    after the other (RFC 1952 2.2), as clients read it: each one is decoded (security recheck)."""
    if coding in ("gzip", "x-gzip"):
        wbits = 16 + zlib.MAX_WBITS
    elif coding == "deflate":
        wbits = zlib.MAX_WBITS if body[:1] == b"\x78" else -zlib.MAX_WBITS
    else:
        raise ValueError(f"it is encoded as {coding[:40]}, which the gateway cannot read to scrub it")
    out, rest, first = b"", body, True
    while True:
        d = zlib.decompressobj(wbits)
        try:
            out += d.decompress(rest, limit + 1 - len(out))
        except zlib.error:
            if first:
                raise
            return out        # bytes after the last member that are not one: dropped, never passed on
        if len(out) > limit or d.unconsumed_tail:
            raise ValueError(f"it decodes to more than {limit} bytes")
        rest, first = d.unused_data, False
        if wbits != 16 + zlib.MAX_WBITS or not d.eof or not rest.strip(b"\0"):
            return out        # trailing zeros pad some gzip files; anything else after deflate is ignored, as before


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
        # A label may hold a dot: escaped as DNS writes it, so the name checked is the name the
        # forwarded packet asks; joined as they were, ["x.shop", "example", "com"] read as
        # x.shop.example.com, in scope of *.shop.example.com (fuzzing, FZ-35).
        labels.append(data[i:i + n].replace(b"\\", b"\\\\").replace(b".", b"\\."))
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


def interface_networks(route: str = "/proc/net/route", inet6: str = "/proc/net/if_inet6") -> list:
    """The subnets of this machine's network interfaces, read from Linux's /proc (the gateway
    runs in a container): every directly connected IPv4 route (no gateway, not the default
    route), and the prefix of every global IPv6 address. Loopback and link-local are left out
    (resolve refuses them anyway). Elsewhere, or without /proc, the list is empty."""
    out: list = []
    try:
        with open(route) as f:
            next(f, None)
            for line in f:
                p = line.split()
                if len(p) < 8 or p[0] == "lo":
                    continue
                try:
                    dest, gw, flags, mask = (int(p[1], 16), int(p[2], 16), int(p[3], 16), int(p[7], 16))
                except ValueError:
                    continue
                if not flags & 0x1 or flags & 0x2 or gw or not mask:      # up, connected, not the default route
                    continue
                net = ipaddress.IPv4Network((socket.inet_ntoa(struct.pack("=I", dest)),
                                             socket.inet_ntoa(struct.pack("=I", mask))), strict=False)
                if net not in out:
                    out.append(net)
    except OSError:
        pass
    try:
        with open(inet6) as f:
            for line in f:
                p = line.split()
                if len(p) < 6 or len(p[0]) != 32:
                    continue
                addr = ipaddress.IPv6Address(int(p[0], 16))
                if addr.is_loopback or addr.is_link_local:
                    continue
                net = ipaddress.IPv6Network((addr, int(p[2], 16)), strict=False)
                if net not in out:
                    out.append(net)
    except (OSError, ValueError):
        pass
    return out


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


def _unlogged(data, n: int) -> list[tuple[int, str]]:
    """The rows of a batch of n that the API answered as not stored (POST /gateway/log)."""
    out = {}
    unlogged = data.get("unlogged") if isinstance(data, dict) else None
    for u in unlogged if isinstance(unlogged, list) else []:      # any other shape: none (FZ-30)
        i = u.get("index") if isinstance(u, dict) else None
        if type(i) is int and 0 <= i < n:
            out[i] = str(u.get("reason") or "")[:200]
    return sorted(out.items())


def _detail(data) -> str:
    """Where the API says a refused batch went wrong (FastAPI's field and message, never the
    value it repeats as "input")."""
    detail = data.get("detail") if isinstance(data, dict) else None
    if isinstance(detail, list) and detail and isinstance(detail[0], dict):
        where = detail[0].get("loc")
        loc = ".".join(x for x in (where if isinstance(where, list) else []) if isinstance(x, str)
                       and x not in ("body", "rows"))
        return f" ({loc}: {str(detail[0].get('msg', ''))[:120]})"
    return f" ({detail[:120]})" if isinstance(detail, str) else ""


def quiet_unraisable(previous=None):
    """An unraisable-exception hook for the gateway's process. Python decodes a TLS server name
    (SNI) as ASCII before the gateway's callback sees it; a client sending another one fails the
    handshake (the tunnel's row says so) and Python prints a traceback for it, which a job's tool
    could repeat at will. That case is one line here; anything else goes to the previous hook."""
    previous = previous or sys.unraisablehook

    def hook(u):
        if isinstance(u.exc_value, UnicodeDecodeError) and isinstance(u.object, bytes):
            print("gateway: a TLS client sent a server name (SNI) that is not ASCII; the handshake was refused",
                  file=sys.stderr, flush=True)
            return
        previous(u)
    return hook


def main() -> None:
    sys.unraisablehook = quiet_unraisable()
    token = gateway_token(create=True)
    state = os.environ.get("ATTACKLEDGER_GATEWAY_STATE", "/data/gateway")
    ca = CA(state, os.environ.get("ATTACKLEDGER_GATEWAY_PUBLIC", "/data/gateway-public"))
    deny = tuple(h.strip() for h in os.environ.get("ATTACKLEDGER_GATEWAY_DENY_HOSTS", ",".join(DENY_HOSTS)).split(",")
                 if h.strip())
    gw = Gateway(Api(os.environ.get("ATTACKLEDGER_API_URL", "http://api:8000"), token), ca,
                 policy=Policy(_env_hosts("ATTACKLEDGER_GATEWAY_PASSIVE_HOSTS", PASSIVE_HOSTS),
                               _env_hosts("ATTACKLEDGER_GATEWAY_SERVICE_HOSTS", SERVICE_HOSTS),
                               service_key=os.environ.get("ANTHROPIC_API_KEY")),
                 deny_hosts=deny, upstream_dns=os.environ.get("ATTACKLEDGER_GATEWAY_UPSTREAM_DNS") or None,
                 target_networks=tuple(t.strip() for t in os.environ.get("ATTACKLEDGER_GATEWAY_TARGET_NETWORKS", "")
                                       .split(",") if t.strip()),
                 quarantine=os.environ.get("ATTACKLEDGER_GATEWAY_QUARANTINE") or os.path.join(state, "log-quarantine.jsonl"))
    dns_port = int(os.environ.get("ATTACKLEDGER_GATEWAY_DNS_PORT", "53"))
    control_port = int(os.environ.get("ATTACKLEDGER_GATEWAY_CONTROL_PORT", "8081"))
    hosts = listen_addresses(os.environ.get("ATTACKLEDGER_GATEWAY_LISTEN", ""))
    asyncio.run(gw.serve(hosts, port=int(os.environ.get("ATTACKLEDGER_GATEWAY_PORT", "8080")),
                         dns_port=dns_port or None, control_port=control_port or None))


if __name__ == "__main__":
    main()
