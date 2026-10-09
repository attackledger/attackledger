"""AttackLedger worker: claims queued jobs and runs the recon pipeline.

Job kinds mirror the original pipeline's modules:

  subdomains  M1  passive sources (subfinder -all, assetfinder, crt.sh), then DNS
  resolve         A/AAAA/CNAME for in-scope hosts
  ports       M2  top-100 TCP ports (connect scan), only if the engagement allows it
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

Defense in depth: the API validates targets when a job is created; the worker
re-checks every target before running and every host or URL a tool reports
before storing it. Nothing outside the engagement's scope rules is recorded.
"""
import hashlib
import json
import os
import re
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone

sys.path.insert(0, "/srv")  # server package (app.*) is copied next to the worker

from sqlalchemy import select  # noqa: E402

from app import jobgates, jsanalysis, ledger, migrate, modules, packs, scope, urls  # noqa: E402
from app import targets as targeting  # noqa: E402
from app import agentloop, agenttools, passive, triage  # noqa: E402
from app.db import SessionLocal, engine  # noqa: E402
from app.models import Asset, Endpoint, Engagement, Job, JobStatus, Lane, Lead, Observation  # noqa: E402

POLL_SECONDS = float(os.environ.get("WORKER_POLL_SECONDS", "2"))
JOB_TIMEOUT = int(os.environ.get("WORKER_JOB_TIMEOUT", "1800"))
# A running job older than the time limit plus this grace period has no live worker.
STALE_GRACE = int(os.environ.get("WORKER_STALE_GRACE", "600"))
# Targets run in batches so a stopped job knows exactly which targets were not run.
CHUNK_SIZE = max(1, int(os.environ.get("WORKER_CHUNK_SIZE", "20")))
TOOLS = os.environ.get("WORKER_TOOLS_DIR", "/opt/pd/bin")
# Optional DNS resolvers for dnsx/naabu (comma-separated). Unset: the tools' defaults.
RESOLVERS = os.environ.get("WORKER_RESOLVERS", "").strip()

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


def now():
    return datetime.now(timezone.utc)


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


def commands(kind: str, eng) -> list[tuple[str, list[str]]]:
    """The tool invocations for a job kind, in order. Targets are fed on stdin."""
    rps = str(eng.rate_limit_rps)
    resolvers = ["-r", RESOLVERS] if RESOLVERS else []
    if kind == "subdomains":
        return [("subfinder", [tool("subfinder"), "-silent", "-all", "-timeout", "25"]),
                ("assetfinder", [tool("assetfinder"), "--subs-only"])]
    if kind == "resolve":
        # Two passes: with some resolvers, asking for CNAME together with A/AAAA makes dnsx
        # drop hosts that have no CNAME record at all.
        return [("dnsx", [tool("dnsx"), "-silent", "-json", "-a", "-aaaa", *resolvers, "-rl", rps]),
                ("dnsx-cname", [tool("dnsx"), "-silent", "-json", "-cname", *resolvers, "-rl", rps])]
    if kind == "ports":
        if "ports" not in (eng.enabled_modules or []):
            raise RuntimeError("port scanning is not allowed for this engagement")
        # Connect scan (no raw sockets), port 25 excluded. The engagement's requests-per-second
        # limit is a hard ceiling for every step, port scanning included: no multiplier.
        return [("naabu", [tool("naabu"), "-silent", "-json", "-top-ports", "100", "-exclude-ports", "25",
                           "-scan-type", "c", "-rate", rps, "-c", str(min(25, eng.rate_limit_rps)),
                           *resolvers])]
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


def crtsh_names(root: str) -> list[str]:
    """Certificate transparency names for a root domain (a third-party source, not the target)."""
    url = f"https://crt.sh/?q=%25.{root}&output=json"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "AttackLedger"}),
                                    timeout=60) as r:
            rows = json.loads(r.read().decode(errors="replace") or "[]")
    except Exception:
        return []
    names = set()
    for row in rows:
        for n in str(row.get("name_value", "")).splitlines():
            names.add(n.strip().lower().lstrip("*."))
    return sorted(names)


class Run:
    """One job execution: runs tools, tracks output hash, log and cancellation."""

    def __init__(self, session, job: Job):
        self.session, self.job, self.eng = session, job, job.engagement
        self.inc, self.exc = self.eng.scope_include, self.eng.scope_exclude
        self.digest = hashlib.sha256()
        self.started = time.monotonic()
        self.known = {a.host: a for a in self.eng.assets}
        self.failed_tools: list[str] = []
        self.stopped: str | None = None
        self.fetch_failures = 0
        self.skipped = False

    def log(self, line: str) -> None:
        self.job.log = (self.job.log + line + "\n")[-20000:]
        self.session.commit()

    def remaining_time(self) -> float:
        return JOB_TIMEOUT - (time.monotonic() - self.started)

    def check_stop(self) -> None:
        self.session.refresh(self.job, ["status"])
        if self.job.status == JobStatus.cancelled:
            raise Cancelled("cancelled")
        if self.remaining_time() <= 0:
            raise Cancelled("timed out")

    def tool_lines(self, name: str, cmd: list[str], stdin_lines: list[str]):
        self.log(f"$ {' '.join(cmd)}  ({len(stdin_lines)} input line(s))")
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
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
                    self.session.commit()
                    self.check_stop()
        except Cancelled:
            proc.kill()
            raise
        finally:
            watchdog.cancel()
            proc.wait()
        if timed_out.is_set():
            raise Cancelled("timed out")
        err = proc.stderr.read().strip()
        if err:
            self.log(err[-2000:])
        if proc.returncode not in (0, None):
            self.failed_tools.append(name)
            self.log(f"{name} exited with code {proc.returncode}")

    def in_scope(self, host: str | None) -> bool:
        return bool(host) and scope.in_scope(host, self.inc, self.exc)

    def observe(self, host: str, data: dict, create_asset: bool = True) -> None:
        host = scope.normalize_host(host)
        self.session.add(Observation(job_id=self.job.id, engagement_id=self.eng.id, host=host, data=data))
        if create_asset and host not in self.known:
            self.known[host] = Asset(engagement_id=self.eng.id, host=host, in_scope=True)
            self.session.add(self.known[host])


# ---- job kinds ----------------------------------------------------------------

def run_subdomains(r: Run, roots: list[str]) -> int:
    found: dict[str, set] = defaultdict(set)
    for name, cmd in commands("subdomains", r.eng):
        for line in r.tool_lines(name, cmd, roots):
            found[line.lower().lstrip("*.")].add(name)
    for root in roots:
        names = crtsh_names(root)
        r.digest.update(("crtsh\t" + "\n".join(names)).encode())
        r.log(f"crt.sh {root}: {len(names)} name(s)")
        for n in names:
            found[n].add("crtsh")
        r.check_stop()

    # Ownership + scope filter before anything is resolved.
    candidates = sorted(h for h in found if r.in_scope(h))
    r.log(f"{len(found)} candidate name(s), {len(candidates)} in scope")
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


def run_ports(r: Run, hosts: list[str]) -> int:
    ports: dict[str, set] = defaultdict(set)
    name, cmd = commands("ports", r.eng)[0]
    for line in r.tool_lines(name, cmd, hosts):
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if r.in_scope(rec.get("host")) and rec.get("port"):
            ports[rec["host"]].add(int(rec["port"]))
    for host, ps in ports.items():
        r.observe(host, {"open_ports": sorted(ps)})
    return len(ports)


def latest_ports(session, eng_id: int) -> dict[str, list[int]]:
    rows = session.scalars(select(Observation).where(Observation.engagement_id == eng_id)
                           .order_by(Observation.id.desc())).all()
    out: dict[str, list[int]] = {}
    for o in rows:
        if "open_ports" in o.data and o.host not in out:
            out[o.host] = o.data["open_ports"]
    return out


def run_probe(r: Run, hosts: list[str]) -> int:
    known_ports = latest_ports(r.session, r.eng.id)
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
    existing = set(r.session.scalars(select(Endpoint.url_sha256).where(Endpoint.engagement_id == r.eng.id)))
    cleaned = urls.clean(raw_urls.keys(), r.inc, r.exc)
    added = 0
    for host, url, is_js in cleaned:
        h = hashlib.sha256(url.encode()).hexdigest()
        if h in existing:
            continue
        existing.add(h)
        src = ",".join(sorted(raw_urls.get(url, {"?"})))[:32]
        r.session.add(Endpoint(engagement_id=r.eng.id, job_id=r.job.id, host=host, url=url,
                               url_sha256=h, source=src, is_js=is_js))
        added += 1
    r.log(f"{len(raw_urls)} URL(s) seen, {len(cleaned)} in scope after clean-up, {added} new")
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


def fetcher(eng):
    """A GET function that sends the research identification and follows no redirects."""
    flags = require_identification(eng)
    headers = {flags[i + 1].split(":", 1)[0].strip(): flags[i + 1].split(":", 1)[1].strip()
               for i in range(0, len(flags), 2)}
    headers.setdefault("User-Agent", "AttackLedger")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False          # targets often have odd certificates; we only read public files
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))
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
            return None, f"HTTP {e.code}" + (" (redirect not followed)" if 300 <= e.code < 400 else "")
        except Exception as e:
            reason = getattr(e, "reason", e)
            return None, type(reason).__name__ if not str(reason) else str(reason)[:120]
    return get


def add_lead(r: Run, host: str, source_url: str, kind: str, title: str, bucket: str = "",
             severity: str = "", detail: dict | None = None, key: str = "") -> bool:
    fp = hashlib.sha256(f"{kind}|{host}|{title}|{key}".encode()).hexdigest()
    if fp in r.lead_fps:
        return False
    r.lead_fps.add(fp)
    r.session.add(Lead(engagement_id=r.eng.id, job_id=r.job.id, host=host, source_url=source_url,
                       kind=kind, title=title[:300], bucket=bucket, severity=severity,
                       detail=detail or {}, fingerprint=fp))
    return True


def run_jsanalyze(r: Run, js_urls: list[str]) -> int:
    get = fetcher(r.eng)
    r.lead_fps = set(r.session.scalars(select(Lead.fingerprint).where(Lead.engagement_id == r.eng.id)))
    js_urls = [u for u in js_urls if r.in_scope(urls.host_of(u))]   # the per-run cap lives in the registry
    endpoints: dict[str, set] = defaultdict(set)
    analysed = leads = noise = 0
    failures: dict[str, int] = defaultdict(int)
    r.log(f"analysing {len(js_urls)} JavaScript file(s)")
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
                                  f"Sourcemap with {len(srcs)} source file(s)"
                                  + (" and embedded source" if m.get("sourcesContent") else ""),
                                  detail={"map_url": ref, "sources": srcs[:50],
                                          "sources_content": bool(m.get("sourcesContent"))})
        if n % 10 == 0:
            r.session.commit()
            r.check_stop()
    added = store_endpoints(r, endpoints) if endpoints else 0
    if failures:
        r.fetch_failures += sum(failures.values())
        r.log("fetch failures: " + ", ".join(f"{k} ×{v}" for k, v in sorted(failures.items())))
    r.log(f"{analysed} file(s) analysed, {leads} new lead(s), {noise} noise match(es) ignored, "
          f"{added} new endpoint(s)")
    return analysed


NUCLEI_TEMPLATES = os.environ.get("WORKER_NUCLEI_TEMPLATES", "/opt/nuclei-templates")
# Never run these, whatever a template's own tags say.
NUCLEI_EXCLUDE_TAGS = "dos,fuzz,fuzzing,intrusive,bruteforce,brute-force,default-login,credential-stuffing,token-spray"
NUCLEI_SEVERITY = "medium,high,critical"
NUCLEI_EXCLUDE_FILE = os.environ.get("WORKER_NUCLEI_EXCLUDE", "/opt/nuclei-exclude.txt")


def nuclei_cmd(eng, templates: list[str] | None = None, tags: list[str] | None = None,
               severity: str | None = NUCLEI_SEVERITY) -> list[str]:
    flags = require_identification(eng)
    if not os.path.isfile(NUCLEI_EXCLUDE_FILE) or os.path.getsize(NUCLEI_EXCLUDE_FILE) == 0:
        # Fail closed: without the exclusion list, raw and out-of-band templates would run.
        raise RuntimeError(f"nuclei exclusion list missing ({NUCLEI_EXCLUDE_FILE}); refusing to scan")
    cmd = [tool("nuclei"), "-silent", "-jsonl", "-nc", "-duc",
           "-et", NUCLEI_EXCLUDE_FILE,  # raw/unsafe and out-of-band templates (see Dockerfile)
           "-ni",                       # no interactsh: no out-of-band callbacks to third parties
           "-dr",                       # follow no redirects, whatever a template asks for
           "-etags", NUCLEI_EXCLUDE_TAGS,
           "-rl", str(eng.rate_limit_rps), "-c", str(min(5, eng.rate_limit_rps)), "-bs", "5",
           "-retries", "1", "-timeout", "8", *flags]
    for t in templates or [os.path.join(NUCLEI_TEMPLATES, "http")]:
        cmd += ["-t", t]
    if tags:
        cmd += ["-tags", ",".join(tags)]
    if severity:
        cmd += ["-severity", severity]
    return cmd


def _tpl(*dirs: str) -> list[str]:
    return [os.path.join(NUCLEI_TEMPLATES, "http", d) + "/" for d in dirs]


def nuclei_plan(session, eng, urls_: list[str]) -> dict:
    """Clusters (status, title, server, stack) -> one representative URL; stack tags; golden URLs."""
    probes = targeting.probes_by_host(session, eng.id)
    by_url = {p.get("url"): p for ps in probes.values() for p in ps if p.get("url")}
    reps, seen = [], set()
    tags: dict[str, set] = defaultdict(set)
    for u in urls_:
        p = by_url.get(u, {})
        stack = tuple(sorted(triage._tech_name(t) for t in (p.get("tech") or [])))
        key = (p.get("status_code"), (p.get("title") or "").strip().lower(), p.get("webserver"), stack)
        for t in stack:
            if t and not triage._BORING.match(t):
                tags[u].add(re.sub(r"[^a-z0-9-]", "", t))
        if key in seen and p:
            continue
        seen.add(key)
        reps.append(u)
    golden_hosts = {r["host"] for r in targeting.ranked(session, eng) if r["golden"]}
    return {"reps": set(reps), "tags": tags,
            "golden": {u for u in urls_ if urls.host_of(u) in golden_hosts}}


def run_nuclei(r: Run, urls_: list[str]) -> int:
    if not hasattr(r, "nuclei_plan"):
        r.nuclei_plan = nuclei_plan(r.session, r.eng, r.job.targets)
        r.lead_fps = set(r.session.scalars(select(Lead.fingerprint).where(Lead.engagement_id == r.eng.id)))
        r.log(f"{len(r.job.targets)} live service(s), {len(r.nuclei_plan['reps'])} cluster representative(s), "
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

    found = 0
    for name, cmd, inputs in passes:
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
            found += add_lead(r, host, where, "nuclei", f"{info.get('name') or tid}",
                              severity=str(info.get("severity", "")).lower(),
                              detail={"template": tid, "matched_at": where, "matcher": rec.get("matcher-name"),
                                      "tags": info.get("tags"), "pass": name,
                                      "extracted": (rec.get("extracted-results") or [])[:5]},
                              key=f"{tid}|{where}|{rec.get('matcher-name')}")
    return found


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


def baseline_status(get_status, url: str) -> tuple[str, str]:
    """Two random non-existent paths: if both answer the same non-404 code, the host
    answers everything that way and content discovery would only produce noise."""
    a = get_status(url.rstrip("/") + f"/zzq-al-{os.urandom(4).hex()}")
    b = get_status(url.rstrip("/") + f"/xnf-al-{os.urandom(4).hex()}/{os.urandom(2).hex()}")
    return a, b


def run_content(r: Run, urls_: list[str]) -> int:
    get = fetcher(r.eng)

    def status(u: str) -> str:
        body, why = get(u)
        return "200" if body is not None else (why.split()[1] if why.startswith("HTTP ") else "000")

    keep = []
    for u in urls_:
        if not r.in_scope(urls.host_of(u)):
            continue
        a, b = baseline_status(status, u)
        if a == b and a not in ("404", "000"):
            r.log(f"skipped {u}: every path answers {a}")
            continue
        keep.append(u)
    if not keep:
        return 0
    seen: dict[str, set] = defaultdict(set)
    for u in keep:
        time.sleep(1.5)   # let the previous budget drain before the next scan starts
        for line in r.tool_lines("feroxbuster", ferox_cmd(r.eng), [u]):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("type") == "response" and rec.get("url"):
                seen[rec["url"]].add("ferox")
    return store_endpoints(r, seen)


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
    r.lead_fps = set(r.session.scalars(select(Lead.fingerprint).where(Lead.engagement_id == r.eng.id)))
    found = 0
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
                found += add_lead(r, host, url, "parameter", f"{len(params)} hidden parameter(s): "
                                  + ", ".join(params[:8]) + ("…" if len(params) > 8 else ""),
                                  detail={"params": params, "method": (res or {}).get("method", "GET")},
                                  key=",".join(params))
    return found


def run_paramclass(r: Run, urls_: list[str]) -> int:
    """Computed: no request leaves the worker."""
    r.lead_fps = set(r.session.scalars(select(Lead.fingerprint).where(Lead.engagement_id == r.eng.id)))
    hidden = {l.source_url: (l.detail or {}).get("params", [])
              for l in r.session.scalars(select(Lead).where(Lead.engagement_id == r.eng.id, Lead.kind == "parameter"))}
    params = {}
    for u in urls_:
        if r.in_scope(urls.host_of(u)):
            params[u] = sorted(set(passive.params_of(u)) | set(hidden.get(u, [])))
    rows = passive.route(params)
    r.digest.update(json.dumps(rows, sort_keys=True).encode())
    found = 0
    for row in rows:
        found += add_lead(r, row["host"], row["urls"][0], "param-class",
                          f"{row['class']}-prone parameter: {row['param']}",
                          detail={"class": row["class"], "param": row["param"], "lane": row["lane"],
                                  "urls": row["urls"]},
                          key=f"{row['class']}|{row['param']}")
    r.log(f"{len(params)} URL(s) with parameters, {len(rows)} routed parameter(s), {found} new lead(s)")
    return found


def run_dorks(r: Run, roots: list[str]) -> int:
    """Computed: no request leaves the worker. The operator runs the dorks by hand."""
    r.lead_fps = set(r.session.scalars(select(Lead.fingerprint).where(Lead.engagement_id == r.eng.id)))
    found = 0
    for root in roots:
        for d in passive.dorks_for(root):
            r.digest.update(d["query"].encode())
            found += add_lead(r, root, d["url"], "dork", d["title"], detail={"query": d["query"], "url": d["url"]},
                              key=d["query"])
    return found


RUNNERS = {"subdomains": run_subdomains, "resolve": run_resolve, "ports": run_ports,
           "probe": run_probe, "crawl": run_crawl, "archive": run_archive, "jsanalyze": run_jsanalyze,
           "nuclei": run_nuclei, "content": run_content, "params": run_params,
           "paramclass": run_paramclass, "dorks": run_dorks}
def check_registry() -> None:
    """The worker and the module registry must describe the same job kinds."""
    missing = set(modules.BY_KIND) - set(RUNNERS)
    extra = set(RUNNERS) - set(modules.BY_KIND)
    if missing or extra:
        raise SystemExit(f"module registry and worker disagree: no runner for {sorted(missing)}, "
                         f"runner without module {sorted(extra)}")


def run(session, job: Job) -> "Run":
    eng: Engagement = job.engagement
    try:  # the engagement may have changed since the job was queued
        m = jobgates.check_engagement(eng, job.kind)
    except jobgates.GateError as e:
        raise RuntimeError(str(e))
    if job.deferred and not job.targets:
        # Pipeline step: pick targets now, from what the earlier steps produced.
        job.targets = jobgates.normalize_targets(m, targeting.default_targets(session, eng, m))
        session.commit()
        if not job.targets:
            hint = targeting.NO_TARGET_HINT.get(m.kind, "earlier steps produced nothing to work on")
            job.log += f"nothing to run: {hint}\n"
            session.commit()
            r = Run(session, job)
            r.skipped = True
            return r
    targets, _ = jobgates.split_targets(eng, m, job.targets)
    over_limit: list[str] = []
    if m.max_targets and len(targets) > m.max_targets:
        # Never drop silently: what does not fit is listed as remaining.
        targets, over_limit = targets[:m.max_targets], targets[m.max_targets:]
    if len(targets) != len(job.targets):
        job.log += f"skipped {len(job.targets) - len(targets)} target(s) outside scope\n"
    if not targets:
        raise RuntimeError("no in-scope targets")

    r = Run(session, job)
    kept, done, stopped = 0, [], None
    chunks = [targets[i:i + CHUNK_SIZE] for i in range(0, len(targets), CHUNK_SIZE)]
    for chunk in chunks:
        try:
            r.check_stop()
            kept += RUNNERS[job.kind](r, chunk)
        except Cancelled as e:
            stopped = str(e)
            break
        done += chunk                      # a batch counts only once it finished
        job.targets_done = len(done)
        session.commit()
    if over_limit and not stopped:
        stopped = "target limit"
    remaining = [t for t in targets if t not in set(done)] + over_limit
    job.remaining_targets = remaining or None
    job.targets_done = len(done)
    job.output_sha256 = r.digest.hexdigest()
    job.result_count = kept
    session.commit()
    if stopped:
        r.log(f"stopped ({stopped}) after {len(done)} of {len(targets)} target(s); "
              f"{len(remaining)} not run")
    r.stopped = stopped
    if not stopped and kept == 0 and (r.failed_tools or r.fetch_failures):
        # A tool or fetch error that produced nothing is a failure, not an empty result.
        what = ", ".join(sorted(set(r.failed_tools))) or "every fetch"
        raise RuntimeError(f"{what} failed and nothing was found; see the log")

    # Record the run as evidence on each touched host's recon lane, if one is open.
    # It is attached to the lane, not to a checklist item: a person or agent still
    # decides which item it proves.
    recon_lane = packs.get_pack(eng.pack_id).recon_lane
    touched = {o.host for o in session.scalars(select(Observation).where(Observation.job_id == job.id))}
    touched |= set(session.scalars(select(Endpoint.host).where(Endpoint.job_id == job.id)))
    touched |= set(session.scalars(select(Lead.host).where(Lead.job_id == job.id)))
    for host in touched:
        asset = r.known.get(host)
        lane = next((l for l in asset.lanes if l.role == recon_lane), None) if asset and asset.id else None
        if lane:
            ledger.append_evidence(session, lane, kind="file", sha256_hex=job.output_sha256,
                                   uri=f"job:{job.id}", summary=f"{job.kind} run, job {job.id}")
    session.commit()
    return r


# Agent outcomes that leave work undone: the job is partial, never done.
AGENT_PARTIAL = {"ended", "turn_limit", "cost_limit", "cancelled"}


def anthropic_client():
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError("ANTHROPIC_API_KEY is not set for the worker")
    import anthropic
    return anthropic.Anthropic()


def run_agent(session, job: Job, client=None) -> "Run":
    """An agent run on one lane. Gates are checked again here (agenttools.check_lane):
    the engagement may have changed since the run was queued."""
    lane = session.get(Lane, job.lane_id) if job.lane_id else None
    if lane is None:
        raise RuntimeError("the lane for this agent run no longer exists")
    if lane.executor != "agent":
        raise RuntimeError("this lane's executor is no longer the Claude agent")
    limits = (job.result or {}).get("limits", {})
    try:
        model = agentloop.configured_model()
    except ValueError as e:
        raise RuntimeError(str(e))
    r = Run(session, job)
    r.log(f"agent model: {model}")

    def should_stop() -> bool:
        session.refresh(job, ["status"])
        return job.status == JobStatus.cancelled or r.remaining_time() <= 0

    try:
        res = agentloop.run(session, lane, job.id, client or anthropic_client(), model=model,
                            **{k: limits.get(k, v) for k, v in agentloop.DEFAULT_LIMITS.items()},
                            should_stop=should_stop, log=r.log)
    except agenttools.RunRefused as e:
        raise RuntimeError(str(e))
    session.refresh(job, ["status"])
    if res.status == "cancelled" and job.status != JobStatus.cancelled:
        res.status, res.detail = "timed_out", "stopped at the worker time limit"
    job.result = {"limits": limits, **res.as_dict()}
    job.result_count = res.evidence_added
    job.targets_done = 1 if res.status == "finished" else 0
    session.commit()
    r.log(f"agent {res.status}: {res.turns} turn(s), {res.requests} request(s), "
          f"{res.evidence_added} evidence, {res.items_marked} item(s) marked, "
          f"~${res.cost_usd:.2f} estimated" + (f"; {res.detail}" if res.detail else ""))
    if res.status == "refused":
        raise RuntimeError(f"the model {res.detail}; nothing further was run")
    if res.status in AGENT_PARTIAL | {"timed_out"}:
        r.stopped = res.status
    return r


INTERRUPTED = ("interrupted: the worker stopped while this job was running. Results from finished "
               "batches (and an agent's evidence up to its last turn) were kept; run it again for the rest.")


def _aware(t: datetime | None) -> datetime | None:
    return t.replace(tzinfo=timezone.utc) if t is not None and t.tzinfo is None else t


def recover_interrupted(session, *, all_running: bool) -> list[int]:
    """Jobs left "running" by a worker that is gone are marked failed, so a run never
    looks active or complete when it is neither.

    At startup every running job is stale: one worker serves a database (the rate limit
    is enforced per worker process). Between jobs, a running job past the time limit
    plus a grace period is stale too, whoever started it."""
    cutoff = now().timestamp() - JOB_TIMEOUT - STALE_GRACE
    recovered = []
    for job in session.scalars(select(Job).where(Job.status == JobStatus.running)):
        started = _aware(job.started_at)
        if all_running or started is None or started.timestamp() < cutoff:
            job.status, job.finished_at = JobStatus.failed, now()
            job.log = (job.log + INTERRUPTED + "\n")[-20000:]
            recovered.append(job.id)
    session.commit()
    return recovered


def claim(session):
    stmt = select(Job).where(Job.status == JobStatus.queued).order_by(Job.id).limit(1)
    if engine.dialect.name == "postgresql":
        stmt = stmt.with_for_update(skip_locked=True)
    job = session.scalars(stmt).first()
    if job:
        job.status, job.started_at = JobStatus.running, now()
        session.commit()
    return job


def main():
    check_registry()
    migrate.wait_for_head()  # the API owns migrations
    with SessionLocal() as session:
        stale = recover_interrupted(session, all_running=True)
    if stale:
        print(f"marked {len(stale)} interrupted job(s) failed: {stale}", flush=True)
    print("worker ready", flush=True)
    while True:
        with SessionLocal() as session:
            recover_interrupted(session, all_running=False)
            job = claim(session)
            if not job:
                time.sleep(POLL_SECONDS)
                continue
            print(f"job {job.id} {job.kind}", flush=True)
            try:
                r = run_agent(session, job) if job.kind == "agent" else run(session, job)
                session.refresh(job, ["status"])
                if job.status == JobStatus.cancelled:
                    pass
                elif r.stopped:                       # time limit or target limit
                    job.status = JobStatus.partial   # never "done" with targets left
                else:
                    job.status = JobStatus.done
            except Exception as e:  # report, never crash the loop
                session.rollback()
                job = session.get(Job, job.id)
                job.log = (job.log + f"error: {e}\n")[-20000:]
                job.status = JobStatus.failed
            job.finished_at = now()
            session.commit()


if __name__ == "__main__":
    main()
