"""How the worker reaches the outside world: only through the gateway (D-039, docs/GATEWAY.md).

The worker container has no route to the internet. Each job gets a credential when the worker
claims it (`issue`): a random secret whose SHA-256 is stored on the job. Every tool the job runs
authenticates to the gateway as "job-<id>.<tool>" with that secret, and the gateway asks the
API what the job may do. When the job ends, the credential stops working.

An Egress gives a job's tools what they need, and nothing else:

  proxy_url(tool)   http://job-<id>.<tool>:<secret>@gateway:8080, for the tools' proxy flags
  env(tool)         a minimal environment: PATH, HOME, locale, the proxy variables and
                    SSL_CERT_FILE (the gateway's CA). Not the worker's own environment, so
                    tools never see DATABASE_URL or ANTHROPIC_API_KEY
  resolver()        the gateway's DNS resolver as ip:port, for dnsx, httpx, katana, nuclei
  opener(tool)      a urllib opener through the gateway, never following redirects
  probe(host, port) a port probe through the gateway (the ports module)
  mask(text)        the secret replaced, for anything written to a job log

Without a configured gateway, or without its CA, nothing that sends traffic runs (fail closed).
"""
import base64
import hashlib
import os
import secrets
import socket
import ssl
import urllib.request
from dataclasses import dataclass, field

DEFAULT_CA = "/data/gateway-public/ca.pem"
REFUSED_HEADER = "X-AttackLedger-Gateway"
# Nmap's top 100 TCP ports, as naabu's -top-ports 100 (port 25 is never probed).
TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199,
    389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025,
    1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306,
    3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646,
    7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156,
    49157]
PROBE_TIMEOUT = 45          # the gateway may queue a probe for a rate token (up to 30 s)


class NoGateway(RuntimeError):
    """There is no gateway to send through, so nothing is sent."""


def issue(job) -> str:
    """A new credential for a job the worker just claimed. Only the hash is stored."""
    secret = secrets.token_urlsafe(32)
    job.gateway_secret_sha256 = hashlib.sha256(secret.encode()).hexdigest()
    return secret


def _tool_name(tool: str) -> str:
    name = "".join(c if c.isalnum() else "-" for c in tool.lower()).strip("-")[:32]
    return name or "tool"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


@dataclass
class Egress:
    job_id: int
    secret: str
    address: str = field(default_factory=lambda: os.environ.get("ATTACKLEDGER_GATEWAY", "").strip())
    dns: str = field(default_factory=lambda: os.environ.get("ATTACKLEDGER_GATEWAY_DNS", "").strip())
    ca_file: str = field(default_factory=lambda: os.environ.get("ATTACKLEDGER_GATEWAY_CA", DEFAULT_CA))

    def check(self) -> "Egress":
        """Fail closed: refuse to run anything that sends traffic without the gateway."""
        if not self.address or ":" not in self.address:
            raise NoGateway("no gateway is configured (ATTACKLEDGER_GATEWAY); nothing is sent")
        if not os.path.isfile(self.ca_file):
            raise NoGateway(f"the gateway's CA certificate is missing ({self.ca_file}); nothing is sent")
        return self

    def user(self, tool: str) -> str:
        return f"job-{self.job_id}.{_tool_name(tool)}"

    def proxy_url(self, tool: str) -> str:
        return f"http://{self.user(tool)}:{self.secret}@{self.address}"

    def mask(self, text: str) -> str:
        return text.replace(self.secret, "********") if self.secret else text

    def env(self, tool: str) -> dict[str, str]:
        url = self.proxy_url(tool)
        env = {k: os.environ[k] for k in ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TZ") if k in os.environ}
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            env[k] = env[k.lower()] = url
        env["NO_PROXY"] = env["no_proxy"] = ""
        env["SSL_CERT_FILE"] = env["REQUESTS_CA_BUNDLE"] = self.ca_file
        return env

    def _host_port(self, value: str, default_port: int) -> tuple[str, int]:
        host, _, port = value.rpartition(":") if ":" in value else (value, "", "")
        return host, int(port or default_port)

    def resolver(self) -> str:
        """The gateway's resolver as ip:port (the DNS tools want an address, not a name)."""
        if not self.dns:
            raise NoGateway("no gateway resolver is configured (ATTACKLEDGER_GATEWAY_DNS); nothing is resolved")
        host, port = self._host_port(self.dns, 53)
        try:
            return f"{socket.gethostbyname(host)}:{port}"
        except OSError as e:
            raise NoGateway(f"the gateway resolver {host} cannot be found: {e}")

    def ssl_context(self, verify: bool) -> ssl.SSLContext:
        """verify: trust only the gateway's CA (it checks the real certificate upstream for passive
        sources and the Claude API). Otherwise none, as for targets with odd certificates."""
        if verify:
            return ssl.create_default_context(cafile=self.ca_file)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def opener(self, tool: str, *, verify: bool = False) -> urllib.request.OpenerDirector:
        url = self.proxy_url(tool)
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": url, "https": url}), _NoRedirect,
            urllib.request.HTTPSHandler(context=self.ssl_context(verify)))

    def probe(self, host: str, port: int, timeout: float = PROBE_TIMEOUT) -> tuple[int, str]:
        """(status, reason) of a port probe: 200 open, 502 closed or timed out, 403/407/503 refused."""
        gw_host, gw_port = self._host_port(self.address, 8080)
        auth = base64.b64encode(f"{self.user('ports')}:{self.secret}".encode()).decode()
        with socket.create_connection((gw_host, gw_port), timeout=timeout) as s:
            s.sendall((f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
                       f"Proxy-Authorization: Basic {auth}\r\nX-AttackLedger-Probe: connect\r\n\r\n").encode())
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            head, _, body = data.partition(b"\r\n\r\n")
            length = 0
            for line in head.split(b"\r\n")[1:]:
                k, _, v = line.partition(b":")
                if k.strip().lower() == b"content-length" and v.strip().isdigit():
                    length = int(v.strip())
            while len(body) < length:
                chunk = s.recv(4096)
                if not chunk:
                    break
                body += chunk
        try:
            status = int(head.split(b" ", 2)[1])
        except (IndexError, ValueError):
            return 502, "no answer from the gateway"
        reason = body.decode("utf-8", "replace").strip().removeprefix("AttackLedger gateway: ")
        return status, reason


def refusal(headers) -> bool:
    """Whether a response came from the gateway refusing the request, not from the target."""
    for k, v in headers:
        if k.lower() == REFUSED_HEADER.lower() and v.strip().lower() == "refused":
            return True
    return False
