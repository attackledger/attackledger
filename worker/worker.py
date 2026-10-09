"""AttackLedger worker: claims queued jobs and runs the recon pipeline.

Job kinds mirror the original pipeline's modules:

  subdomains  M1  passive sources (subfinder -all, assetfinder, crt.sh), then DNS
  resolve         A/AAAA/CNAME for in-scope hosts
  ports       M2  top-100 TCP ports (connect probes through the gateway), only if the engagement allows it
  probe       M2  HTTP(S) fingerprint per host and open port
  crawl       M4  katana over golden hosts, same-host only, destructive paths skipped
  archive     M4  gau + waybackurls (passive archives)
  jsanalyze   M8  JS files: endpoints, GraphQL operations, sourcemaps, secret candidates
  nuclei      M7  known issues: takeovers, exposures, stack-matched templates, golden-host CVEs
  content     M3  feroxbuster content discovery on golden hosts, after a baseline check
  params      M5  Arjun hidden-parameter discovery on dynamic endpoints
  paramclass  M6  route parameters to hunt lanes by gf-style class (computed, no traffic)
  dorks       M10 Google-dork checklist per wildcard root (computed, no traffic)
  agent           a Claude agent working one hunt lane through agenttools (v0.6)

The worker has no database (D-042, docs/WORKER_API.md). It claims a job from the API with
its worker token and gets the job's specification and a job token: the targets, the
engagement's rules and what the job kind reads. Everything it writes (observations,
endpoints, leads, an agent's exchanges and ledger calls, logs, progress, the outcome) goes
back through the API's /worker/* routes, relayed by the gateway; the API checks each write
against what the job kind may write, the scope and redaction, and decides the job's status.

Defense in depth: the API validates targets when a job is created and again when it is
claimed; the worker re-checks every host or URL a tool reports before sending it, and the
API checks it once more before storing it. Nothing outside the engagement's scope rules is
recorded.

The worker has no route to the internet (D-039, docs/GATEWAY.md). Each job gets a gateway
credential when it starts; every tool is pointed at the gateway (GATEWAY_FLAGS plus the proxy
environment, app.egress) and the gateway enforces scope, methods, rate and identification
again, in one place. The tools' own flags below stay as the first layer.

Recon output that carries URLs or response data (endpoints, leads, observations) is
redacted by the API before it is stored (app.redact, D-038): a token in an archived URL is
kept as a marker, so it is neither stored nor sent again by a later step.
"""
import hashlib
import json
import math
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict
from contextlib import contextmanager
from types import SimpleNamespace

sys.path.insert(0, "/srv")  # server package (app.*) is copied next to the worker

from app import egress, jsanalysis, modules, scope, urls, workerclient  # noqa: E402
from app import agentloop, agenttools, nucleisafe, passive  # noqa: E402
from app.text import plural  # noqa: E402

POLL_SECONDS = float(os.environ.get("WORKER_POLL_SECONDS", "2"))
JOB_TIMEOUT = int(os.environ.get("WORKER_JOB_TIMEOUT", "1800"))
# The API marks a running job interrupted when its worker has not reported for two minutes
# (workerapi.STALE_SECONDS); this is how often the worker reports while a job runs.
HEARTBEAT_SECONDS = float(os.environ.get("WORKER_HEARTBEAT_SECONDS", "15"))
# Targets run in batches so a stopped job knows exactly which targets were not run.
CHUNK_SIZE = max(1, int(os.environ.get("WORKER_CHUNK_SIZE", "20")))
# Results are sent to the API in one call per batch, or sooner when this many are waiting.
FLUSH_ROWS = 2000
TOOLS = os.environ.get("WORKER_TOOLS_DIR", "/opt/pd/bin")

# Never follow these during a crawl: they can log out, delete or change state.
CRAWL_OUT_OF_SCOPE = (r"logout|log-out|signout|sign-out|/delete|/destroy|/remove|/revoke|/deactivate|"
                      r"/close-account|/unsubscribe")


JS_MAX_BYTES = 5 * 1024 * 1024
JS_TIMEOUT = 15


class Cancelled(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects: a redirect could lead outside scope."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def tool(name: str) -> str:
    return os.path.join(TOOLS, name)


def identification_flags(eng) -> list[str]:
    flags = []
    if eng.research_header:
        flags += ["-H", eng.research_header]
    if eng.research_user_agent:
        flags += ["-H", f"User-Agent: {eng.research_user_agent}"]
    return flags


def require_identification(eng) -> list[str]:
    flags = identification_flags(eng)
    if not flags:  # fail closed, independent of the API check
        raise RuntimeError("no research header or user agent set; refusing to send traffic")
    return flags


def gateway_flags(cmd: list[str], gw: "egress.Egress", r: "Run | None" = None) -> list[str]:
    """The flags that point a tool at the gateway: its proxy and, for tools that resolve
    names themselves, the gateway's resolver. Tools without a proxy flag (assetfinder,
    waybackurls, Arjun) use the proxy environment. The worker has no other route, so a tool
    that ignored both would fail, never bypass the gateway."""
    tool = os.path.basename(cmd[0])
    url = gw.proxy_url(tool)
    if tool == "subfinder":
        return ["-proxy", url]
    if tool == "dnsx":
        return ["-r", gw.resolver()]
    if tool in ("httpx", "katana"):
        return ["-proxy", url, "-r", gw.resolver()]
    if tool == "gau":
        return ["--proxy", url]
    if tool == "feroxbuster":
        return ["--proxy", url]
    if tool == "nuclei":
        # -pi: nuclei's own internal requests too. Its resolver flag takes a file.
        return ["-p", url, "-pi", "-r", r.resolver_file() if r else gw.resolver()]
    return []


def commands(kind: str, eng) -> list[tuple[str, list[str]]]:
    """The tool invocations for a job kind, in order. Targets are fed on stdin. The gateway's
    flags are added when they run (gateway_flags)."""
    rps = str(eng.rate_limit_rps)
    if kind == "subdomains":
        return [("subfinder", [tool("subfinder"), "-silent", "-all", "-timeout", "25"]),
                ("assetfinder", [tool("assetfinder"), "--subs-only"])]
    if kind == "resolve":
        # Two passes: with some resolvers, asking for CNAME together with A/AAAA makes dnsx
        # drop hosts that have no CNAME record at all.
        return [("dnsx", [tool("dnsx"), "-silent", "-json", "-a", "-aaaa", "-rl", rps]),
                ("dnsx-cname", [tool("dnsx"), "-silent", "-json", "-cname", "-rl", rps])]
    if kind == "probe":
        flags = require_identification(eng)
        # No redirect following: a redirect could lead outside scope.
        return [("httpx", [tool("httpx"), "-silent", "-json", "-status-code", "-title", "-tech-detect",
                           "-web-server", "-ip", "-cdn", "-cname", "-location", "-rl", rps, "-t", "10",
                           *flags])]
    if kind == "crawl":
        flags = require_identification(eng)
        return [("katana", [tool("katana"), "-silent", "-j", "-d", str(eng.crawl_depth), "-jc",
                            "-fs", "fqdn", "-cos", CRAWL_OUT_OF_SCOPE, "-rl", rps, "-c", "5",
                            "-ct", "10m", *flags])]
    if kind == "archive":
        return [("gau", [tool("gau"), "--subs", "--threads", "2", "--timeout", "30"]),
                ("wayback", [tool("waybackurls")])]
    raise ValueError(f"unknown job kind {kind}")


def parse_probe(rec: dict) -> tuple[str | None, dict]:
    host = (rec.get("input") or rec.get("host") or "").split(":")[0]
    return host, {"url": rec.get("url"), "port": rec.get("port"), "scheme": rec.get("scheme"),
                  "status_code": rec.get("status_code"), "title": rec.get("title"),
                  "tech": rec.get("tech", []), "webserver": rec.get("webserver"),
                  "cdn": rec.get("cdn_name") if rec.get("cdn") else None,
                  "location": rec.get("location"), "live": True}


def crtsh_names(root: str, gw: "egress.Egress") -> list[str]:
    """Certificate transparency names for a root domain (a third-party source, not the target),
    through the gateway, which checks crt.sh's real certificate."""
    url = f"https://crt.sh/?q=%25.{root}&output=json"
    try:
        with gw.opener("crtsh", verify=True).open(urllib.request.Request(url, headers={"User-Agent": "AttackLedger"}),
                                                  timeout=60) as r:
            rows = json.loads(r.read().decode(errors="replace") or "[]")
    except Exception:
        return []
    names = set()
    for row in rows:
        for n in str(row.get("name_value", "")).splitlines():
            names.add(n.strip().lower().lstrip("*."))
    return sorted(names)


def engagement_of(spec: dict) -> SimpleNamespace:
    """The engagement's rules as the claim gave them (the worker reads nothing else)."""
    e = spec["engagement"]
    return SimpleNamespace(id=e["id"], scope_include=e["scope_include"], scope_exclude=e["scope_exclude"],
                           rate_limit_rps=e["rate_limit_rps"], research_header=e["research_header"],
                           research_user_agent=e["research_user_agent"], crawl_depth=e["crawl_depth"],
                           enabled_modules=e["enabled_modules"])


class Run:
    """One job execution: runs tools, tracks output hash, log and cancellation, and sends
    results to the API in batches."""

    def __init__(self, job: "workerclient.JobChannel", gw: "egress.Egress | None" = None):
        self.job, self.spec = job, job.spec
        self.eng = engagement_of(job.spec)
        self.inputs = job.spec.get("inputs") or {}
        self.gw = gw or egress.Egress(job.id, job.gateway_secret)
        self._resolver_file: str | None = None
        self.inc, self.exc = self.eng.scope_include, self.eng.scope_exclude
        self.digest = hashlib.sha256()
        self.started = time.monotonic()
        self.failed_tools: list[str] = []
        self.stopped: str | None = None
        self.fetch_failures = 0
        self.kept = 0
        self.agent_result: dict | None = None
        self.lead_fps: set[str] = set()     # within this run; the API deduplicates across runs
        self.pending = {"observations": [], "endpoints": [], "leads": []}
        self.totals = {"observations": 0, "endpoints_seen": 0, "endpoints_in_scope": 0, "endpoints_added": 0,
                       "leads_added": 0, "refused": 0}
        self.redacted_count = 0
        self.redacted_kinds: dict[str, None] = {}
        self.cancelled = threading.Event()
        self.proc = None
        job.current = self

    def log(self, line: str) -> None:
        self.job.log(self.gw.mask(line))

    def remaining_time(self) -> float:
        return JOB_TIMEOUT - (time.monotonic() - self.started)

    def check_stop(self) -> None:
        if self.cancelled.is_set() or self.job.heartbeat() == "cancelled":
            self.cancelled.set()
            raise Cancelled("cancelled")
        if self.remaining_time() <= 0:
            raise Cancelled("timed out")

    @contextmanager
    def heartbeats(self):
        """Report every HEARTBEAT_SECONDS while the job runs, also while a tool prints nothing,
        and stop the running tool at once when the job is cancelled."""
        stop = threading.Event()

        def beat():
            while not stop.wait(HEARTBEAT_SECONDS):
                try:
                    if self.job.heartbeat() == "cancelled":
                        self.cancelled.set()
                        if self.proc is not None:
                            self.proc.kill()
                except Exception:  # noqa: BLE001 - the next beat, or the job's own calls, will tell
                    pass
        t = threading.Thread(target=beat, daemon=True)
        t.start()
        try:
            yield
        finally:
            stop.set()

    def resolver_file(self) -> str:
        """A file naming the gateway's resolver, for tools whose resolver flag takes a file."""
        if self._resolver_file is None:
            import tempfile
            fd, path = tempfile.mkstemp(prefix="al-resolvers-", suffix=".txt")
            with os.fdopen(fd, "w") as f:
                f.write(self.gw.resolver() + "\n")
            self._resolver_file = path
        return self._resolver_file

    def tool_lines(self, name: str, cmd: list[str], stdin_lines: list[str]):
        cmd = [*cmd, *gateway_flags(cmd, self.gw, self)]
        self.log(f"$ {' '.join(cmd)}  ({plural(len(stdin_lines), 'input line')})")
        # Only what the tool needs: the proxy, the gateway's CA, PATH and HOME. Not the
        # worker's own environment or tokens.
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, env=self.gw.env(name))
        self.proc = proc
        proc.stdin.write("\n".join(stdin_lines) + "\n")
        proc.stdin.close()
        # Enforce the time limit even when a tool prints nothing for a long time.
        timed_out = threading.Event()

        def _expire():
            timed_out.set()
            proc.kill()
        watchdog = threading.Timer(max(self.remaining_time(), 0), _expire)
        watchdog.daemon = True
        watchdog.start()
        try:
            for n, line in enumerate(proc.stdout, start=1):
                self.digest.update(f"{name}\t{line}".encode())
                yield line.strip()
                if n % 50 == 0:
                    self.check_stop()
        except Cancelled:
            proc.kill()
            raise
        finally:
            watchdog.cancel()
            proc.wait()
            self.proc = None
        if timed_out.is_set():
            raise Cancelled("timed out")
        if self.cancelled.is_set():
            raise Cancelled("cancelled")
        err = proc.stderr.read().strip()
        if err:
            self.log(err[-2000:])
        if proc.returncode not in (0, None):
            self.failed_tools.append(name)
            self.log(f"{name} exited with code {proc.returncode}")

    def in_scope(self, host: str | None) -> bool:
        return bool(host) and scope.in_scope(host, self.inc, self.exc)

    def observe(self, host: str, data: dict) -> None:
        self._queue("observations", {"host": scope.normalize_host(host), "data": data})

    def lead(self, host: str, source_url: str, kind: str, title: str, bucket: str = "", severity: str = "",
             detail: dict | None = None, key: str = "") -> bool:
        """Queue a lead; False if this run already has it. The API deduplicates against
        earlier runs and redacts it."""
        fp = hashlib.sha256(f"{kind}|{host}|{title}|{key}".encode()).hexdigest()
        if fp in self.lead_fps:
            return False
        self.lead_fps.add(fp)
        self._queue("leads", {"host": host, "source_url": source_url, "kind": kind, "title": title,
                              "bucket": bucket, "severity": severity, "detail": detail or {}, "key": key})
        return True

    def _queue(self, what: str, row: dict) -> None:
        self.pending[what].append(row)
        if sum(len(v) for v in self.pending.values()) >= FLUSH_ROWS:
            self.flush()

    def flush(self) -> dict:
        """Send what is waiting, at most 5,000 rows of each kind per call."""
        while any(self.pending.values()):
            batch = {k: v[:5000] for k, v in self.pending.items()}
            self.pending = {k: v[5000:] for k, v in self.pending.items()}
            out = self.job.results(**batch)
            for k in self.totals:
                self.totals[k] += out.get(k, 0)
            red = out.get("redacted") or {}
            self.redacted_count += red.get("count", 0)
            self.redacted_kinds.update(dict.fromkeys(red.get("kinds", [])))
        return self.totals


# ---- job kinds ----------------------------------------------------------------

def run_subdomains(r: Run, roots: list[str]) -> int:
    found: dict[str, set] = defaultdict(set)
    for name, cmd in commands("subdomains", r.eng):
        for line in r.tool_lines(name, cmd, roots):
            found[line.lower().lstrip("*.")].add(name)
    for root in roots:
        names = crtsh_names(root, r.gw)
        r.digest.update(("crtsh\t" + "\n".join(names)).encode())
        r.log(f"crt.sh {root}: {plural(len(names), 'name')}")
        for n in names:
            found[n].add("crtsh")
        r.check_stop()

    # Ownership + scope filter before anything is resolved.
    candidates = sorted(h for h in found if r.in_scope(h))
    r.log(f"{plural(len(found), 'candidate name')}, {len(candidates)} in scope")
    if not candidates:
        return 0
    records = resolve_hosts(r, candidates)
    for host, rec in records.items():
        r.observe(host, {"sources": sorted(found.get(host, [])), **rec})
    r.log(f"{len(records)} resolved, {len(candidates) - len(records)} did not resolve")
    return len(records)


def resolve_hosts(r: Run, hosts: list[str]) -> dict[str, dict]:
    """A/AAAA pass decides what resolves; the CNAME pass only adds detail."""
    out: dict[str, dict] = {}
    for name, cmd in commands("resolve", r.eng):
        for line in r.tool_lines(name, cmd, hosts):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = (rec.get("host") or "").lower()
            if not r.in_scope(host):
                continue
            if name == "dnsx":
                # Some resolvers answer NOERROR with no records for names that do not exist,
                # and dnsx still prints a line. Only an address means "resolves".
                if rec.get("a") or rec.get("aaaa"):
                    out[host] = {"a": rec.get("a", []), "aaaa": rec.get("aaaa", []), "cname": []}
            elif host in out:
                out[host]["cname"] = rec.get("cname", [])
    return out


def run_resolve(r: Run, hosts: list[str]) -> int:
    records = resolve_hosts(r, hosts)
    for host, rec in records.items():
        r.observe(host, rec)
    return len(records)


PROBE_PORTS = [p for p in egress.TOP_100_PORTS if p != 25]


def run_ports(r: Run, hosts: list[str]) -> int:
    """Top 100 TCP ports per host, as TCP connect probes made by the gateway (D-039): it checks
    the host name against the scope, takes a rate token per probe and relays no byte. naabu
    is not used: it resolves names itself and connects to addresses, which host-name scope
    cannot check."""
    from concurrent.futures import ThreadPoolExecutor
    if "ports" not in (r.eng.enabled_modules or []):
        raise RuntimeError("port scanning is not allowed for this engagement")
    hosts = [h for h in hosts if r.in_scope(h)]
    pairs = [(h, p) for h in hosts for p in PROBE_PORTS]
    ports: dict[str, set] = defaultdict(set)
    refused: dict[str, int] = defaultdict(int)
    r.log(f"probing {plural(len(PROBE_PORTS), 'port')} on {plural(len(hosts), 'host')} through the gateway")

    def one(pair):
        try:
            return pair, r.gw.probe(*pair)
        except OSError as e:
            return pair, (503, f"gateway unreachable: {e}")
    with ThreadPoolExecutor(max_workers=max(1, min(25, r.eng.rate_limit_rps))) as pool:
        for n, ((host, port), (status, reason)) in enumerate(pool.map(one, pairs), start=1):
            r.digest.update(f"probe\t{host}:{port}\t{status}\n".encode())
            if status == 200:
                ports[host].add(port)
            elif status != 502:                  # 502: closed or timed out; anything else: refused
                refused[reason[:120]] += 1
            if n % 100 == 0:
                r.check_stop()
    if refused:
        r.fetch_failures += sum(refused.values())
        r.log("refused by the gateway: " + ", ".join(f"{k} ×{v}" for k, v in sorted(refused.items())))
    for host, ps in ports.items():
        r.observe(host, {"open_ports": sorted(ps)})
    return len(ports)


def run_probe(r: Run, hosts: list[str]) -> int:
    known_ports = r.inputs.get("ports") or {}       # the latest open ports per host, from the claim
    inputs = []
    for h in hosts:
        ps = [p for p in known_ports.get(h, []) if p != 25]
        inputs += [f"{h}:{p}" for p in ps] if ps else [h]
    name, cmd = commands("probe", r.eng)[0]
    kept = 0
    for line in r.tool_lines(name, cmd, inputs):
        try:
            host, data = parse_probe(json.loads(line))
        except json.JSONDecodeError:
            continue
        if r.in_scope(host):
            r.observe(host, data)
            kept += 1
    return kept


def store_endpoints(r: Run, raw_urls: dict[str, set]) -> int:
    """Send URLs to the API, which cleans them up (urls.clean), checks scope, redacts and
    deduplicates them. Only URLs whose host is in scope are sent."""
    r.flush()
    before = dict(r.totals)
    rows = [{"url": u, "sources": sorted(src)[:10]} for u, src in raw_urls.items() if r.in_scope(urls.host_of(u))]
    for i in range(0, len(rows), 5000):
        r.pending["endpoints"] = rows[i:i + 5000]
        r.flush()
    added = r.totals["endpoints_added"] - before["endpoints_added"]
    in_scope = r.totals["endpoints_in_scope"] - before["endpoints_in_scope"]
    r.log(f"{plural(len(raw_urls), 'URL')} seen, {in_scope} in scope after clean-up, {added} new")
    return added


def run_crawl(r: Run, seeds: list[str]) -> int:
    seeds = [u for u in seeds if r.in_scope(urls.host_of(u))]
    seen: dict[str, set] = defaultdict(set)
    name, cmd = commands("crawl", r.eng)[0]
    for line in r.tool_lines(name, cmd, seeds):
        try:
            ep = json.loads(line).get("request", {}).get("endpoint")
        except json.JSONDecodeError:
            continue
        if ep:
            seen[ep].add("katana")
    return store_endpoints(r, seen)


def run_archive(r: Run, roots: list[str]) -> int:
    seen: dict[str, set] = defaultdict(set)
    for name, cmd in commands("archive", r.eng):
        for line in r.tool_lines(name, cmd, roots):
            if line.startswith(("http://", "https://")):
                seen[line].add(name)
    return store_endpoints(r, seen)


def fetcher(eng, gw: "egress.Egress | None" = None, tool_name: str = "fetch"):
    """A GET function that sends the research identification and follows no redirects,
    through the gateway (which sets the identification again and refuses everything else)."""
    flags = require_identification(eng)
    if gw is None:
        raise egress.NoGateway("no gateway credential for this fetch; nothing is sent")
    headers = {flags[i + 1].split(":", 1)[0].strip(): flags[i + 1].split(":", 1)[1].strip()
               for i in range(0, len(flags), 2)}
    headers.setdefault("User-Agent", "AttackLedger")
    # Targets often have odd certificates; we only read public files (the gateway does not verify them either).
    opener = gw.opener(tool_name)
    delay = 1.0 / max(eng.rate_limit_rps, 1)

    def get(url: str) -> tuple[bytes | None, str]:
        """(body, "") on a 200; (None, reason) otherwise. Failures are reported, never hidden."""
        time.sleep(delay)
        try:
            with opener.open(urllib.request.Request(url, headers=headers), timeout=JS_TIMEOUT) as resp:
                if resp.status != 200:
                    return None, f"HTTP {resp.status}"
                return resp.read(JS_MAX_BYTES), ""
        except urllib.error.HTTPError as e:
            if egress.refusal(e.headers.items()):
                return None, "refused by the gateway: " + e.read(300).decode("utf-8", "replace").strip()
            return None, f"HTTP {e.code}" + (" (redirect not followed)" if 300 <= e.code < 400 else "")
        except Exception as e:
            reason = getattr(e, "reason", e)
            return None, type(reason).__name__ if not str(reason) else str(reason)[:120]
    return get


def add_lead(r: Run, host: str, source_url: str, kind: str, title: str, bucket: str = "",
             severity: str = "", detail: dict | None = None, key: str = "") -> bool:
    return r.lead(host, source_url, kind, title, bucket, severity, detail, key)


def leads_added(r: Run, before: int) -> int:
    """New leads since `before`, as the API counted them (it knows earlier runs' leads)."""
    r.flush()
    return r.totals["leads_added"] - before


def run_jsanalyze(r: Run, js_urls: list[str]) -> int:
    get = fetcher(r.eng, r.gw, "jsanalyze")
    before = r.totals["leads_added"]
    js_urls = [u for u in js_urls if r.in_scope(urls.host_of(u))]   # the per-run cap lives in the registry
    endpoints: dict[str, set] = defaultdict(set)
    analysed = leads = noise = 0
    failures: dict[str, int] = defaultdict(int)
    r.log(f"analysing {plural(len(js_urls), 'JavaScript file')}")
    for n, url in enumerate(js_urls, start=1):
        body, why = get(url)
        if body is None:
            failures[why] += 1
            if sum(failures.values()) <= 5:
                r.log(f"could not fetch {url}: {why}")
            continue
        analysed += 1
        r.digest.update(f"js\t{url}\t{hashlib.sha256(body).hexdigest()}\n".encode())
        text = body.decode("utf-8", "replace")
        host = urls.host_of(url)

        for ep in jsanalysis.extract_endpoints(text, url):
            endpoints[ep].add("js")
        for op in jsanalysis.graphql_operations(text):
            leads += add_lead(r, host, url, "graphql", op)
        for s in jsanalysis.scan_secrets(text):
            if s["bucket"] == "noise":
                noise += 1
                continue
            leads += add_lead(r, host, url, "secret", s["kind"], s["bucket"], s["severity"],
                              {"preview": s["preview"], "value_sha256": s["value_sha256"]}, s["value_sha256"])

        ref = jsanalysis.sourcemap_ref(text, url)
        if ref == "inline":
            leads += add_lead(r, host, url, "sourcemap", "Inline sourcemap (source embedded in the file)",
                              detail={"inline": True})
        elif ref and r.in_scope(urls.host_of(ref)):
            raw, _ = get(ref)
            try:
                m = json.loads(raw.decode("utf-8", "replace")) if raw else None
            except ValueError:
                m = None
            if isinstance(m, dict):
                srcs = [str(x) for x in (m.get("sources") or [])]
                leads += add_lead(r, host, url, "sourcemap",
                                  f"Sourcemap with {plural(len(srcs), 'source file')}"
                                  + (" and embedded source" if m.get("sourcesContent") else ""),
                                  detail={"map_url": ref, "sources": srcs[:50],
                                          "sources_content": bool(m.get("sourcesContent"))})
        if n % 10 == 0:
            r.check_stop()
    leads = leads_added(r, before)
    added = store_endpoints(r, endpoints) if endpoints else 0
    if failures:
        r.fetch_failures += sum(failures.values())
        r.log("fetch failures: " + ", ".join(f"{k} ×{v}" for k, v in sorted(failures.items())))
    r.log(f"{plural(analysed, 'file')} analysed, {plural(leads, 'new lead')}, "
          f"{plural(noise, 'noise match', 'noise matches')} ignored, {plural(added, 'new endpoint')}")
    return analysed


NUCLEI_TEMPLATES = os.environ.get("WORKER_NUCLEI_TEMPLATES", "/opt/nuclei-templates")
# Never run these, whatever a template's own tags say. Tags are a second line only: upstream
# tags have typos ("instrusive"), so what may run is decided by content (app/nucleisafe.py).
NUCLEI_EXCLUDE_TAGS = ("dos,fuzz,fuzzing,intrusive,instrusive,bruteforce,brute-force,default-login,"
                       "credential-stuffing,token-spray")
NUCLEI_SEVERITY = "medium,high,critical"
NUCLEI_EXCLUDE_FILE = os.environ.get("WORKER_NUCLEI_EXCLUDE", "/opt/nuclei-exclude.txt")
# Seconds between nuclei passes, so one process's last requests and the next one's first
# never share a one-second window.
NUCLEI_PASS_GAP = 1.1


def nuclei_pacing(rps: int) -> tuple[str, str]:
    """-rl/-rld for a hard ceiling of rps requests in ANY one-second window.

    nuclei's limiter hands out -rl tokens per -rld tick and refills them all at once, so
    "-rl 20" lets 20 requests through at the end of one tick and 20 more at the start of the
    next (measured: 40 in one sliding second, 29 in one calendar second, at a limit of 20).
    With one token per tick, a window holds at most one request per tick inside it plus one
    refilled just before it, so the tick must be at least 1/(rps-1) s. Five per cent more
    absorbs scheduling and network jitter. Effective rate: (rps-1)/1.05 per second."""
    if rps < 2:
        raise RuntimeError("nuclei needs a rate limit of at least 2/s to keep every one-second window "
                           "at or under the limit")
    return "1", f"{math.ceil(1000 * 1.05 / (rps - 1))}ms"


def nuclei_cmd(eng, templates: list[str] | None = None, tags: list[str] | None = None,
               severity: str | None = NUCLEI_SEVERITY) -> list[str]:
    flags = require_identification(eng)
    if not os.path.isfile(NUCLEI_EXCLUDE_FILE) or os.path.getsize(NUCLEI_EXCLUDE_FILE) == 0:
        # Fail closed: without the exclusion list, templates that write or call out would run.
        raise RuntimeError(f"nuclei exclusion list missing ({NUCLEI_EXCLUDE_FILE}); refusing to scan")
    rl, rld = nuclei_pacing(eng.rate_limit_rps)
    cmd = [tool("nuclei"), "-silent", "-jsonl", "-nc", "-duc",
           "-et", NUCLEI_EXCLUDE_FILE,  # every template not provably read-only (app/nucleisafe.py)
           "-ni",                       # no interactsh: no out-of-band callbacks to third parties
           "-dr",                       # follow no redirects, whatever a template asks for
           "-etags", NUCLEI_EXCLUDE_TAGS,
           "-rl", rl, "-rld", rld,      # one request per tick: a hard ceiling (nuclei_pacing)
           "-c", str(min(5, eng.rate_limit_rps)), "-bs", "5",
           # No retries: a retry is sent by the HTTP client inside one rate-limit token.
           "-retries", "0", "-timeout", "8", *flags]
    for t in templates or [os.path.join(NUCLEI_TEMPLATES, "http")]:
        cmd += ["-t", t]
    if tags:
        cmd += ["-tags", ",".join(tags)]
    if severity:
        cmd += ["-severity", severity]
    return cmd


_verified: dict = {}


def verify_nuclei_templates() -> dict:
    """Re-classify the templates once per process and refuse to scan if the image's
    exclusion list misses one that is not provably read-only (fail closed)."""
    st = os.stat(NUCLEI_EXCLUDE_FILE) if os.path.isfile(NUCLEI_EXCLUDE_FILE) else None
    key = (NUCLEI_TEMPLATES, NUCLEI_EXCLUDE_FILE, st.st_mtime_ns if st else None, st.st_size if st else None)
    if key not in _verified:
        _verified.clear()
        _verified[key] = nucleisafe.verify(NUCLEI_TEMPLATES, NUCLEI_EXCLUDE_FILE)
    return _verified[key]


def _tpl(*dirs: str) -> list[str]:
    return [os.path.join(NUCLEI_TEMPLATES, "http", d) + "/" for d in dirs]


def run_nuclei(r: Run, urls_: list[str]) -> int:
    if not hasattr(r, "nuclei_plan"):
        counts = verify_nuclei_templates()      # before any request; raises if not provably safe
        r.log(f"nuclei templates: {counts['safe']} provably read-only, {counts['excluded']} excluded")
        plan = r.inputs["nuclei_plan"]     # computed by the API from the probes (workerapi.nuclei_plan)
        r.nuclei_plan = {"reps": set(plan["reps"]), "golden": set(plan["golden"]),
                         "tags": {u: set(t) for u, t in plan["tags"].items()}}
        r.log(f"{plural(len(r.spec['targets']), 'live service')}, "
              f"{plural(len(r.nuclei_plan['reps']), 'cluster representative')}, "
              f"{len(r.nuclei_plan['golden'])} on golden hosts")
    plan = r.nuclei_plan
    urls_ = [u for u in urls_ if r.in_scope(urls.host_of(u))]
    reps = [u for u in urls_ if u in plan["reps"]]
    golden = [u for u in reps if u in plan["golden"]]
    stack_tags = sorted({t for u in reps for t in plan["tags"].get(u, ())})

    passes = [("takeovers", nuclei_cmd(r.eng, _tpl("takeovers"), severity=None), urls_)]
    if reps:
        passes.append(("generic", nuclei_cmd(r.eng, _tpl("exposures", "misconfiguration")), reps))
    if reps and stack_tags:
        passes.append(("stack", nuclei_cmd(r.eng, tags=stack_tags), reps))
    if golden:
        passes.append(("golden", nuclei_cmd(r.eng, _tpl("exposed-panels", "vulnerabilities", "cves")), golden))

    before = r.totals["leads_added"]
    for name, cmd, inputs in passes:
        if getattr(r, "nuclei_passes", 0):      # also between target batches
            time.sleep(NUCLEI_PASS_GAP)
        r.nuclei_passes = getattr(r, "nuclei_passes", 0) + 1
        for line in r.tool_lines(f"nuclei-{name}", cmd, inputs):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            where = rec.get("matched-at") or rec.get("url") or rec.get("host") or ""
            host = urls.host_of(where) if "://" in where else where.split(":")[0]
            if not r.in_scope(host):
                continue
            info = rec.get("info") or {}
            tid = rec.get("template-id", "?")
            add_lead(r, host, where, "nuclei", f"{info.get('name') or tid}",
                              severity=str(info.get("severity", "")).lower(),
                              detail={"template": tid, "matched_at": where, "matcher": rec.get("matcher-name"),
                                      "tags": info.get("tags"), "pass": name,
                                      "extracted": (rec.get("extracted-results") or [])[:5]},
                              key=f"{tid}|{where}|{rec.get('matcher-name')}")
    return leads_added(r, before)


CONTENT_WORDLIST = os.environ.get("WORKER_CONTENT_WORDLIST", "/opt/wordlists/common.txt")
CONTENT_TIME_LIMIT = os.environ.get("WORKER_CONTENT_TIME_LIMIT", "10m")


# feroxbuster sends this many requests to the start URL, unthrottled, when each scan begins
# (measured on the lab). Its own rate is lowered by as much, so the total stays at the limit.
FEROX_UNTHROTTLED = 2


def ferox_cmd(eng) -> list[str]:
    flags = require_identification(eng)
    if eng.rate_limit_rps < FEROX_UNTHROTTLED + 1:
        raise RuntimeError(f"content discovery needs a rate limit of at least {FEROX_UNTHROTTLED + 1}/s: "
                           f"feroxbuster sends {FEROX_UNTHROTTLED} unthrottled requests when each scan starts")
    rate = eng.rate_limit_rps - FEROX_UNTHROTTLED
    headers = [v for i, v in enumerate(flags) if i % 2 == 1]
    cmd = [tool("feroxbuster"), "--stdin", "--silent", "--json", "-k", "--no-state",
           "-w", CONTENT_WORDLIST,
           # One scan per process. --rate-limit is per scan, and every new scan (each recursed
           # directory) starts with a full budget, so recursion bursts above the limit at the
           # hand-over (measured: 29/s at a limit of 20). Depth 1, one URL at a time, stays at it.
           "--depth", "1", "--scan-limit", "1", "--rate-limit", str(rate),
           "-t", str(min(10, rate)),
           # Its wildcard detection sends a burst of unthrottled requests (measured: 9 in the
           # first second at a limit of 2). The baseline check before each scan does that job.
           "--dont-filter",
           "--time-limit", CONTENT_TIME_LIMIT, "--auto-tune",
           "--filter-status", "404", "500", "502", "503",
           "--dont-extract-links",                      # only wordlist paths under the given URL
           "--dont-scan", CRAWL_OUT_OF_SCOPE]           # never logout/delete/revoke
    for h in headers:
        if h.lower().startswith("user-agent:"):
            cmd += ["-a", h.split(":", 1)[1].strip()]
        else:
            cmd += ["-H", h]
    return cmd


ARJUN_PATH = os.environ.get("WORKER_ARJUN_PATH", "/opt/arjun")


def arjun_cmd(eng, url: str, out_file: str) -> list[str]:
    flags = require_identification(eng)
    headers = "\n".join(v for i, v in enumerate(flags) if i % 2 == 1)
    # Arjun lives in its own directory so its dependencies never shadow the worker's.
    launcher = (f"import sys, runpy; sys.path.insert(0, {ARJUN_PATH!r}); "
                "sys.argv = ['arjun'] + sys.argv[1:]; runpy.run_module('arjun', run_name='__main__')")
    return [sys.executable, "-c", launcher, "-u", url, "-o", out_file, "-m", "GET",
            # One thread with a fixed delay: --rate-limit alone let bursts through with
            # several threads (measured 17/s at a limit of 10).
            "--rate-limit", str(eng.rate_limit_rps), "-t", "1", "-d", f"{1 / max(eng.rate_limit_rps, 1):.3f}",
            "--headers", headers]


def run_params(r: Run, urls_: list[str]) -> int:
    import tempfile
    before = r.totals["leads_added"]
    for u in urls_:
        if not r.in_scope(urls.host_of(u)):
            continue
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "arjun.json")
            for _ in r.tool_lines("arjun", arjun_cmd(r.eng, u, out), []):
                pass
            try:
                data = json.load(open(out)) if os.path.exists(out) else {}
            except ValueError:
                data = {}
        r.digest.update(f"arjun\t{u}\t{json.dumps(data, sort_keys=True)}\n".encode())
        for url, res in (data or {}).items():
            params = sorted(set((res or {}).get("params") or []))
            host = urls.host_of(url)
            if params and r.in_scope(host):
                add_lead(r, host, url, "parameter", f"{plural(len(params), 'hidden parameter')}: "
                                  + ", ".join(params[:8]) + ("…" if len(params) > 8 else ""),
                                  detail={"params": params, "method": (res or {}).get("method", "GET")},
                                  key=",".join(params))
    return leads_added(r, before)


def run_paramclass(r: Run, urls_: list[str]) -> int:
    """Computed: no request leaves the worker."""
    hidden = r.inputs.get("hidden_params") or {}    # what 'params' found, from the claim
    before = r.totals["leads_added"]
    params = {}
    for u in urls_:
        if r.in_scope(urls.host_of(u)):
            params[u] = sorted(set(passive.params_of(u)) | set(hidden.get(u, [])))
    rows = passive.route(params)
    r.digest.update(json.dumps(rows, sort_keys=True).encode())
    for row in rows:
        add_lead(r, row["host"], row["urls"][0], "param-class",
                          f"{row['class']}-prone parameter: {row['param']}",
                          detail={"class": row["class"], "param": row["param"], "lane": row["lane"],
                                  "urls": row["urls"]},
                          key=f"{row['class']}|{row['param']}")
    found = leads_added(r, before)
    r.log(f"{plural(len(params), 'URL')} with parameters, {plural(len(rows), 'routed parameter')}, "
          f"{plural(found, 'new lead')}")
    return found


def run_dorks(r: Run, roots: list[str]) -> int:
    """Computed: no request leaves the worker. The operator runs the dorks by hand."""
    before = r.totals["leads_added"]
    for root in roots:
        for d in passive.dorks_for(root):
            r.digest.update(d["query"].encode())
            add_lead(r, root, d["url"], "dork", d["title"], detail={"query": d["query"], "url": d["url"]},
                     key=d["query"])
    return leads_added(r, before)


RUNNERS = {"subdomains": run_subdomains, "resolve": run_resolve, "ports": run_ports,
           "probe": run_probe, "crawl": run_crawl, "archive": run_archive, "jsanalyze": run_jsanalyze,
           "nuclei": run_nuclei, "params": run_params,
           "paramclass": run_paramclass, "dorks": run_dorks}
RUNNERS.update(__import__("app.reconsteps").reconsteps.runners(globals()))  # wellknown, content (app/reconsteps.py)
def check_registry() -> None:
    """The worker and the module registry must describe the same job kinds."""
    missing = set(modules.BY_KIND) - set(RUNNERS)
    extra = set(RUNNERS) - set(modules.BY_KIND)
    if missing or extra:
        raise SystemExit(f"module registry and worker disagree: no runner for {sorted(missing)}, "
                         f"runner without module {sorted(extra)}")


def run(job: "workerclient.JobChannel", gw: "egress.Egress | None" = None) -> "Run":
    """A recon job the API claimed for this worker: its gates passed and its targets were chosen
    there (workerapi.claim). Runs the targets in batches; each finished batch is reported, so a
    stopped job lists exactly what it did not run."""
    spec = job.spec
    m = modules.get(job.kind)
    gw = gw or egress.Egress(job.id, job.gateway_secret)
    if not m.computed:
        gw.check()                       # fail closed: no gateway, nothing is sent
    r = Run(job, gw)
    targets = list(spec["targets"])
    done, stopped = [], None
    chunks = [targets[i:i + CHUNK_SIZE] for i in range(0, len(targets), CHUNK_SIZE)]
    with r.heartbeats():
        for chunk in chunks:
            try:
                r.check_stop()
                r.kept += RUNNERS[job.kind](r, chunk)
                r.flush()
            except Cancelled as e:
                stopped = str(e)
                break
            done += chunk                      # a batch counts only once it finished
            job.progress(chunk)
    over_limit = spec.get("over_limit") or 0
    if over_limit and not stopped:
        stopped = "target limit"
    remaining = len(targets) - len(done) + over_limit
    if r.redacted_count:
        r.log(f"{plural(r.redacted_count, 'sensitive value')} redacted before storage: "
              + ", ".join(list(r.redacted_kinds)[:10]))
    if stopped:
        r.log(f"stopped ({stopped}) after {len(done)} of {plural(len(targets), 'target')}; "
              f"{remaining} not run")
    r.stopped = stopped
    if not stopped and r.kept == 0 and (r.failed_tools or r.fetch_failures):
        # A tool or fetch error that produced nothing is a failure, not an empty result.
        what = ", ".join(sorted(set(r.failed_tools))) or "every fetch"
        raise RuntimeError(f"{what} failed and nothing was found; see the log")
    return r


# Agent outcomes that leave work undone: the API makes the job partial, never done.
AGENT_PARTIAL = {"ended", "turn_limit", "cost_limit", "cancelled"}
# The Claude API key is the gateway's (D-042): it replaces this placeholder on every call.
GATEWAY_HOLDS_THE_KEY = "added-by-the-attackledger-gateway"


def anthropic_client(gw: "egress.Egress | None" = None):
    """The Messages API client, through the gateway: it reaches api.anthropic.com for agent
    runs only, checks its real certificate and adds the API key, which the worker never has."""
    if gw is None:
        raise egress.NoGateway("no gateway credential for the Claude API; nothing is sent")
    import anthropic
    return anthropic.Anthropic(api_key=GATEWAY_HOLDS_THE_KEY, http_client=anthropic.DefaultHttpxClient(
        proxy=gw.proxy_url("claude"), verify=gw.ssl_context(verify=True), trust_env=False))


def run_agent(job: "workerclient.JobChannel", client=None, transport=None) -> "Run":
    """An agent run on one lane. The API checked the lane's gates when it gave out the job, and
    checks them again on every write (agenttools.Toolbox in the API)."""
    spec = job.spec
    limits = spec.get("limits") or {}
    try:
        model = agentloop.configured_model()
    except ValueError as e:
        raise RuntimeError(str(e))
    gw = egress.Egress(job.id, job.gateway_secret).check()     # fail closed: no gateway, nothing is sent
    r = Run(job, gw)
    r.log(f"agent model: {model}")
    tools = agenttools.RemoteToolbox(job, spec["context"], transport=transport or agenttools.urllib_transport(gw),
                                     max_requests=limits.get("max_requests") or agentloop.DEFAULT_LIMITS["max_requests"])

    def should_stop() -> bool:
        try:
            r.check_stop()
        except Cancelled:
            return True
        return False

    with r.heartbeats():
        res = agentloop.run_loop(tools, spec["context"], client or anthropic_client(gw), model=model,
                                 **{k: limits.get(k, v) for k, v in agentloop.DEFAULT_LIMITS.items()
                                    if k != "max_requests"},
                                 should_stop=should_stop, log=r.log)
    if res.status == "cancelled" and not r.cancelled.is_set():
        res.status, res.detail = "timed_out", "stopped at the worker time limit"
    r.agent_result = res.as_dict()
    r.kept = res.evidence_added
    r.log(f"agent {res.status}: {plural(res.turns, 'turn')}, {plural(res.requests, 'request')}, "
          f"{plural(res.evidence_added, 'evidence entry', 'evidence entries')}, {plural(res.items_marked, 'item')} marked, "
          f"~${res.cost_usd:.2f} estimated" + (f"; {res.detail}" if res.detail else ""))
    if res.status == "refused":
        raise RuntimeError(f"the model {res.detail}; nothing further was run")
    if res.status in AGENT_PARTIAL | {"timed_out"}:
        r.stopped = res.status
    return r


def execute(job: "workerclient.JobChannel", client=None, transport=None) -> dict:
    """Run a claimed job and tell the API how it ended. The API decides the status (done,
    partial, cancelled or failed) from that and from what it holds."""
    job.current = None
    try:
        r = run_agent(job, client=client, transport=transport) if job.kind == "agent" else run(job)
        body = {"stopped": r.stopped}
    except Exception as e:  # report, never crash the loop
        r = job.current
        body = {"error": str(e)[:4000] or type(e).__name__}
    if r is not None:
        try:
            r.flush()                    # whatever a failed batch left waiting is still evidence of the run
        except Exception:  # noqa: BLE001
            pass
        body |= {"output_sha256": r.digest.hexdigest(), "result_count": r.kept}
        if r.agent_result is not None:
            body["agent"] = r.agent_result
    return job.finish(**body)


def main():
    check_registry()
    worker = workerclient.Worker.from_env(create_token=True)
    waiting = False
    while True:                          # the API owns migrations: wait until it answers
        try:
            worker.ping()
            break
        except workerclient.ApiError as e:
            if not waiting:
                print(f"waiting for the API: {e}", flush=True)
                waiting = True
            time.sleep(POLL_SECONDS)
    print(f"worker ready (API through {worker.client.base})", flush=True)
    while True:
        try:
            spec = worker.claim()
        except workerclient.ApiError as e:
            print(f"claim failed: {e}", flush=True)
            time.sleep(POLL_SECONDS)
            continue
        if not spec:
            time.sleep(POLL_SECONDS)
            continue
        job = workerclient.JobChannel(worker.client, spec)
        print(f"job {job.id} {job.kind}", flush=True)
        try:
            execute(job)
        except workerclient.ApiError as e:   # e.g. the API ended the job meanwhile
            print(f"job {job.id}: could not report its outcome: {e}", flush=True)


if __name__ == "__main__":
    main()
