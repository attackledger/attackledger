"""AttackLedger worker: claims queued jobs and runs the recon pipeline.

Job kinds mirror the original pipeline's modules:

  subdomains  M1  passive sources (subfinder -all, assetfinder, crt.sh), then DNS
  resolve         A/AAAA/CNAME for in-scope hosts
  ports       M2  top-100 TCP ports (connect scan), only if the engagement allows it
  probe       M2  HTTP(S) fingerprint per host and open port
  crawl       M4  katana over golden hosts, same-host only, destructive paths skipped
  archive     M4  gau + waybackurls (passive archives)
  jsanalyze   M8  JS files: endpoints, GraphQL operations, sourcemaps, secret candidates

Defense in depth: the API validates targets when a job is created; the worker
re-checks every target before running and every host or URL a tool reports
before storing it. Nothing outside the engagement's scope rules is recorded.
"""
import hashlib
import json
import os
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone

sys.path.insert(0, "/srv")  # server package (app.*) is copied next to the worker

from sqlalchemy import select  # noqa: E402

from app import jsanalysis, ledger, migrate, packs, scope, urls  # noqa: E402
from app.db import SessionLocal, engine  # noqa: E402
from app.models import Asset, Endpoint, Engagement, Job, JobStatus, Lead, Observation  # noqa: E402

POLL_SECONDS = float(os.environ.get("WORKER_POLL_SECONDS", "2"))
JOB_TIMEOUT = int(os.environ.get("WORKER_JOB_TIMEOUT", "1800"))
TOOLS = os.environ.get("WORKER_TOOLS_DIR", "/opt/pd/bin")
# Optional DNS resolvers for dnsx/naabu (comma-separated). Unset: the tools' defaults.
RESOLVERS = os.environ.get("WORKER_RESOLVERS", "").strip()

# Never follow these during a crawl: they can log out, delete or change state.
CRAWL_OUT_OF_SCOPE = (r"logout|log-out|signout|sign-out|/delete|/destroy|/remove|/revoke|/deactivate|"
                      r"/close-account|/unsubscribe")


JS_MAX_FILES = 250
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
        if not eng.allow_port_scan:
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

    def log(self, line: str) -> None:
        self.job.log = (self.job.log + line + "\n")[-20000:]
        self.session.commit()

    def check_stop(self) -> None:
        self.session.refresh(self.job, ["status"])
        if self.job.status == JobStatus.cancelled:
            raise Cancelled("cancelled")
        if time.monotonic() - self.started > JOB_TIMEOUT:
            raise Cancelled("timed out")

    def tool_lines(self, name: str, cmd: list[str], stdin_lines: list[str]):
        self.log(f"$ {' '.join(cmd)}  ({len(stdin_lines)} input line(s))")
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        proc.stdin.write("\n".join(stdin_lines) + "\n")
        proc.stdin.close()
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
            proc.wait()
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
    js_urls = [u for u in js_urls if r.in_scope(urls.host_of(u))][:JS_MAX_FILES]
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
        r.log("fetch failures: " + ", ".join(f"{k} ×{v}" for k, v in sorted(failures.items())))
    r.log(f"{analysed} file(s) analysed, {leads} new lead(s), {noise} noise match(es) ignored, "
          f"{added} new endpoint(s)")
    if js_urls and analysed == 0:
        raise RuntimeError("no JavaScript file could be fetched; see the log for reasons")
    return analysed


RUNNERS = {"subdomains": run_subdomains, "resolve": run_resolve, "ports": run_ports,
           "probe": run_probe, "crawl": run_crawl, "archive": run_archive, "jsanalyze": run_jsanalyze}
ROOT_KINDS = {"subdomains", "archive"}  # targets are wildcard roots, not hosts
URL_KINDS = {"crawl", "jsanalyze"}      # targets are URLs


def allowed_targets(job: Job) -> list[str]:
    eng = job.engagement
    inc, exc = eng.scope_include, eng.scope_exclude
    if job.kind in ROOT_KINDS:
        roots = {p[2:] for p in inc if p.startswith("*.")}
        return [t for t in job.targets if t in roots]
    if job.kind in URL_KINDS:
        return [t for t in job.targets if scope.in_scope(urls.host_of(t) or "", inc, exc)]
    return [t for t in job.targets if scope.in_scope(t, inc, exc)]


def run(session, job: Job) -> None:
    eng: Engagement = job.engagement
    if eng.authorized_at is None or not eng.scope_include:
        raise RuntimeError("engagement is not authorized or has no scope")
    targets = allowed_targets(job)
    if len(targets) != len(job.targets):
        job.log += f"skipped {len(job.targets) - len(targets)} target(s) outside scope\n"
    if not targets:
        raise RuntimeError("no in-scope targets")

    r = Run(session, job)
    try:
        kept = RUNNERS[job.kind](r, targets)
    except Cancelled as e:
        r.log(f"stopped: {e}")
        kept = None
    session.commit()
    job.output_sha256 = r.digest.hexdigest()
    if kept is not None:
        job.result_count = kept
    session.commit()
    if kept == 0 and r.failed_tools:
        # A tool error that produced nothing is a failure, not an empty result.
        raise RuntimeError(f"{', '.join(r.failed_tools)} failed and nothing was found; see the log")

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
    migrate.wait_for_head()  # the API owns migrations
    print("worker ready", flush=True)
    while True:
        with SessionLocal() as session:
            job = claim(session)
            if not job:
                time.sleep(POLL_SECONDS)
                continue
            print(f"job {job.id} {job.kind}", flush=True)
            try:
                run(session, job)
                session.refresh(job, ["status"])
                if job.status != JobStatus.cancelled:
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
