#!/usr/bin/env python3
"""A first live agent run on the lab, measured: pre-flight, one run, a benchmark section.

  python3 tools/agent_live.py preflight [--dry-run] [--no-prepare]
  python3 tools/agent_live.py run       [--dry-run] [--any-model] [--max-turns N] [--max-requests N]
                                        [--no-append]
  python3 tools/agent_live.py dryrun    [--project NAME] [--port PORT] [--usage-scale X] [--keep]

tools/agent_preflight.sh and tools/agent_live_run.sh call the first two. Options for every
command: --project NAME, --compose-file FILE (repeatable), --env-file FILE, --api URL (default
http://127.0.0.1:8000), --benchmark FILE (default docs/BENCHMARK.md). Without them, the commands
use this folder's compose setup (docker compose with its .env), like every other command here.

preflight  checks, without sending anything to the Claude API or the target:
           - the stack's api, gateway and worker run, and the lab answers (TCP from the gateway);
           - in the worker: the model, the budget (ATTACKLEDGER_AGENT_MAX_USD must be set), and
             what the SDK sends for the model's call, captured by a transport that answers itself;
           - in the gateway, with its own environment: the API key (set or missing and a length
             class, never the value), that it would forward that call (service route, key swap)
             and that the GW-1 body filter passes it;
           - in the API: agents are enabled, and the lab engagement (scope shop.lab.test only,
             authorized, research header) and its lane exist with open items and no run active.
           Without --no-prepare it first creates them if they do not exist (lab data only).
           --dry-run: a stub Claude API is expected (tools/agent_dryrun), so the checks that only
           a live setup passes (the SDK calls api.anthropic.com, no test CA, a real-looking key)
           are not applied. Exit status 1, with a plain message, if anything failed.

run        starts the lab if needed, prepares the engagement and lane, runs preflight (it stops
           if that fails), starts ONE agent run with the worker's model (it must be the cheapest
           configured, unless --any-model), waits for it and prints a summary of what was sent and
           spent, from the job's result, the gateway's request log and the lab's access log. It
           appends that summary to the benchmark file as a dated section (unless --no-append) and
           writes the numbers next to it as JSON (tools/benchmark/results-<date>-agent-<n>.json).

dryrun     the whole of it against a stub Claude API, in its own compose project built from this
           tree, with no route out: no key, no traffic outside the stack. Then it removes that
           project (its containers, networks and volumes) unless --keep.

The API token is read from the env file (ATTACKLEDGER_API_TOKEN, the operator token) and never
printed. Standard library only.
"""
import argparse
import datetime as dt
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAB_HOST = "shop.lab.test"
ENG_NAME = "Agent live run (lab)"
LANE_ROLE = "errh"              # WSTG Error handling: two items, both testable with read-only requests
PACK = "web-pentest-wstg"
HEADER = "X-Bug-Bounty: agent-live-run"     # the lab's access log records this header (lab/nginx.conf)
USER_AGENT = "AttackLedger agent live run"
POLICY = "https://example.com/policy"
WAIT_SECONDS = 15 * 60
STUB_HOST = "claude-stub.test"


class Failed(Exception):
    pass


# ---- the stack -------------------------------------------------------------------------------

class Stack:
    def __init__(self, args):
        self.args = args
        cmd = ["docker", "compose", "--project-directory", str(ROOT)]
        if args.project:
            cmd += ["-p", args.project]
        for f in args.compose_file or []:
            cmd += ["-f", f]
        if args.env_file:
            cmd += ["--env-file", args.env_file]
        self.compose = cmd
        self.api_base = args.api.rstrip("/")
        self._token = None

    def run(self, *argv, input=None, check=True, capture=True, timeout=600) -> subprocess.CompletedProcess:
        p = subprocess.run(self.compose + list(argv), input=input, cwd=ROOT, text=True, timeout=timeout,
                           stdout=subprocess.PIPE if capture else None, stderr=subprocess.PIPE if capture else None)
        if check and p.returncode != 0:
            raise Failed(f"docker compose {' '.join(argv[:3])} failed: {(p.stderr or '').strip()[-400:]}")
        return p

    def running(self) -> set:
        p = self.run("ps", "--format", "json", check=False)
        out = set()
        for line in (p.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            rows = json.loads(line)
            for r in rows if isinstance(rows, list) else [rows]:
                if r.get("State") == "running":
                    out.add(r.get("Service"))
        return out

    def env_value(self, name: str) -> str:
        """A value from the env file, without printing it (empty if absent)."""
        path = Path(self.args.env_file) if self.args.env_file else ROOT / ".env"
        try:
            for line in path.read_text().splitlines():
                if line.startswith(name + "="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
        except OSError:
            pass
        return os.environ.get(name, "")

    def token(self) -> str:
        if self._token is None:
            self._token = self.env_value("ATTACKLEDGER_API_TOKEN")
            if not self._token:
                raise Failed("no operator token: set ATTACKLEDGER_API_TOKEN in .env (docs/INSTALL.md, section 4, "
                             "step 5) and recreate the API (docker compose up -d)")
        return self._token

    def api(self, method: str, path: str, body=None):
        req = urllib.request.Request(self.api_base + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"content-type": "application/json",
                                              "authorization": f"Bearer {self.token()}"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:300]
            raise Failed(f"{method} {path}: HTTP {e.code} {detail}")
        except urllib.error.URLError as e:
            raise Failed(f"the API at {self.api_base} does not answer ({e.reason}); is the stack up?")


# ---- preflight -------------------------------------------------------------------------------

def say(ok: bool, name: str, detail: str) -> None:
    print(f"  [{'ok' if ok else 'FAIL'}] {name}: {detail}", flush=True)


def container_checks(stack: Stack, live: bool) -> tuple[list, dict]:
    p = stack.run("exec", "-T", "worker", "python", "-m", "app.agentcheck", "worker",
                  *(["--live"] if live else []), check=False)
    try:
        worker = json.loads(p.stdout)
    except ValueError:
        raise Failed(f"the worker's check did not run: {(p.stderr or p.stdout or '').strip()[-300:]}")
    g = stack.run("exec", "-T", "gateway", "python", "-m", "app.agentcheck", "gateway", "--lab", LAB_HOST,
                  *(["--live"] if live else []), input=json.dumps(worker), check=False)
    try:
        gw = json.loads(g.stdout)
    except ValueError:
        raise Failed(f"the gateway's check did not run: {(g.stderr or g.stdout or '').strip()[-300:]}")
    checks = [("worker " + c["name"], c["ok"], c["detail"]) for c in worker["checks"]]
    checks += [("gateway " + c["name"], c["ok"], c["detail"]) for c in gw["checks"]]
    return checks, worker


def find_lane(stack: Stack, prepare: bool) -> tuple[dict, dict, str]:
    """The lab engagement and its lane: reused while the lane has open items and no active run,
    created otherwise (if prepare). (engagement, lane, what was done)."""
    for e in stack.api("GET", "/engagements"):
        if not e["name"].startswith(ENG_NAME):
            continue
        scope = stack.api("GET", f"/engagements/{e['id']}/scope")
        if scope["include"] != [LAB_HOST] or scope["exclude"] or not scope["authorized_at"] \
                or scope["research_header"] != HEADER or scope["content_deleted"]:
            continue
        cov = stack.api("GET", f"/engagements/{e['id']}/coverage")
        asset = next((a for a in cov["assets"] if a["host"] == LAB_HOST), None)
        cell = (asset or {}).get("roles", {}).get(LANE_ROLE, {})
        if "lane_id" not in cell:
            if not prepare or asset is None:
                continue
            lane = stack.api("POST", "/lanes", {"asset_id": asset["asset_id"], "role": LANE_ROLE})
        else:
            lane = stack.api("GET", f"/lanes/{cell['lane_id']}")
        runs = stack.api("GET", f"/lanes/{lane['id']}/agent-runs")
        if any(i["state"] == "open" for i in lane["items"]) and lane["status"] != "closed" \
                and not any(r["status"] in ("queued", "running") for r in runs):
            return e, lane, "reused"
    if not prepare:
        raise Failed(f"no usable engagement named {ENG_NAME!r} with a {LANE_ROLE} lane on {LAB_HOST}; "
                     f"run without --no-prepare to create it")
    n = sum(1 for e in stack.api("GET", "/engagements") if e["name"].startswith(ENG_NAME))
    name = ENG_NAME if n == 0 else f"{ENG_NAME} {n + 1}"
    e = stack.api("POST", "/engagements", {"name": name, "pack_id": PACK, "engagement_type": "pentest"})
    stack.api("PUT", f"/engagements/{e['id']}/scope", {
        "include": [LAB_HOST], "exclude": [], "rate_limit_rps": 2, "research_header": HEADER,
        "research_user_agent": USER_AGENT, "enabled_modules": [], "crawl_depth": 1})
    stack.api("POST", f"/engagements/{e['id']}/attest",
              {"operator": "agent_live.py (lab)", "policy_url": POLICY, "confirm": True})
    asset = next(a for a in stack.api("GET", f"/engagements/{e['id']}/coverage")["assets"] if a["host"] == LAB_HOST)
    lane = stack.api("POST", "/lanes", {"asset_id": asset["asset_id"], "role": LANE_ROLE})
    return e, lane, "created"


def preflight(stack: Stack, live: bool, prepare: bool = True) -> dict:
    print(f"Pre-flight ({'live run' if live else 'dry run against a stub Claude API'}); nothing is sent "
          f"to the Claude API or the target.", flush=True)
    checks = []
    up = stack.running()
    missing = [s for s in ("api", "gateway", "worker", "lab") if s not in up]
    checks.append(("stack", not missing, "api, gateway, worker and lab are running" if not missing
                   else f"not running: {', '.join(missing)} (docker compose up -d; docker compose --profile lab "
                        f"up -d lab)"))
    worker = {}
    if not missing:
        more, worker = container_checks(stack, live)
        checks += more
    eng = lane = None
    try:
        agent = next((x for x in stack.api("GET", "/executors") if x["key"] == "agent"), {})
        checks.append(("api agents", bool(agent.get("available")),
                       "enabled" if agent.get("available") else agent.get("unavailable_reason", "not listed")))
        eng, lane, how = find_lane(stack, prepare)
        if lane["executor"] != "agent" and agent.get("available"):
            lane = stack.api("PATCH", f"/lanes/{lane['id']}", {"executor": "agent"})
        open_items = sum(1 for i in lane["items"] if i["state"] == "open")
        checks.append(("api engagement", True, f"{how}: {eng['name']} (id {eng['id']}), scope {LAB_HOST} only, "
                                               f"authorized, header {HEADER.split(':')[0]}"))
        checks.append(("api lane", lane["executor"] == "agent",
                       f"lane {lane['id']} ({LANE_ROLE}) on {LAB_HOST}: {open_items} open item(s), no run active, "
                       f"executor {lane['executor']}"))
    except Failed as e:
        checks.append(("api", False, str(e)))
    for name, ok, detail in checks:
        say(ok, name, detail)
    failed = [c for c in checks if not c[1]]
    if failed:
        raise Failed(f"pre-flight failed: {', '.join(c[0] for c in failed)}. Nothing was started.")
    print("Pre-flight passed.", flush=True)
    return {"engagement": eng, "lane": lane, "worker": worker}


# ---- the run ---------------------------------------------------------------------------------

LAB_LINE = re.compile(r'^(?P<port>\d+) "(?P<method>[A-Z]+) (?P<path>\S*) [^"]*" (?P<status>\d+) '
                      r'ua="(?P<ua>[^"]*)" research="(?P<research>[^"]*)" t=(?P<t>[\d.]+)')


def lab_requests(stack: Stack, since: float, until: float) -> list[dict]:
    """The lab's own access log (lab/nginx.conf) between two times: an independent count."""
    stamp = dt.datetime.fromtimestamp(since - 5, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    p = stack.run("logs", "--no-log-prefix", "--since", stamp, "lab", check=False)
    out = []
    for line in (p.stdout or "").splitlines():
        m = LAB_LINE.match(line.strip())
        if m and since <= float(m["t"]) <= until + 2:
            out.append(m.groupdict())
    return out


def gateway_rows(stack: Stack, eng_id: int, job_id: int) -> dict:
    """The gateway's rows for the job, once the gateway has sent them all (it sends in batches)."""
    last, data = -1, None
    for _ in range(20):
        data = stack.api("GET", f"/engagements/{eng_id}/gateway-log?job_id={job_id}&limit=1000")
        if data["total"] == last:
            break
        last = data["total"]
        time.sleep(3)
    return data


def measure(job: dict, log: dict, lab: list, lane: dict, started: float, ended: float, header: str) -> dict:
    res = job.get("result") or {}
    rows = log["rows"]
    target = [r for r in rows if r["kind"] == "target"]
    service = [r for r in rows if r["kind"] == "service"]
    hosts = sorted({re.sub(r"^https?://([^/:]+).*$", r"\1", r["url"]) for r in target})
    by_method: dict = {}
    for r in target:
        by_method[r["method"]] = by_method.get(r["method"], 0) + 1
    refused = [r for r in rows if r["verdict"] != "allowed"]
    value = header.split(":", 1)[1].strip()
    t0 = dt.datetime.fromisoformat(job["started_at"].replace("Z", "+00:00")) if job.get("started_at") else None
    ev = [e for e in lane.get("evidence", []) if e.get("source") == "agent" and t0 is not None
          and dt.datetime.fromisoformat(e["created_at"].replace("Z", "+00:00")) >= t0]
    t1 = dt.datetime.fromisoformat(job["finished_at"].replace("Z", "+00:00")) if job.get("finished_at") else None
    return {
        "job_id": job["id"], "job_status": job["status"], "agent_status": res.get("status"),
        "model": res.get("model"), "turns": res.get("turns"), "detail": res.get("detail", ""),
        "summary": res.get("summary", ""), "limits": res.get("limits", {}),
        "claude_api_calls": len(service), "claude_api_hosts": sorted({r["url"].split("/")[2] for r in service}),
        "target_requests": len(target), "target_by_method": by_method, "target_hosts": hosts,
        "only_lab_host": hosts in ([], [LAB_HOST]),
        "refused_rows": [{"kind": r["kind"], "method": r["method"], "url": r["url"][:200], "reason": r["reason"]}
                         for r in refused],
        "agent_requests": res.get("requests"),
        "lab_requests": len(lab), "lab_with_header": sum(1 for x in lab if x["research"] == value),
        "lab_with_user_agent": sum(1 for x in lab if x["ua"] == USER_AGENT),
        # Every request the lab saw carried it, and the lab saw as many as the gateway sent.
        "header_on_every_request": all(x["research"] == value for x in lab)
                                    and len(lab) == sum(1 for r in target if r["verdict"] == "allowed"),
        "evidence_entries": len(ev), "items_evidenced": len({e["item_idx"] for e in ev if e["item_idx"] is not None}),
        "items_marked": res.get("items_marked"), "leads": res.get("leads_added"),
        "usage": res.get("usage", {}), "cost_usd_estimate": res.get("cost_usd_estimate"),
        "wall_seconds": round(ended - started, 1),
        "job_seconds": round((t1 - t0).total_seconds(), 1) if t0 and t1 else None,
    }


def project_name(stack: Stack) -> str:
    p = stack.run("config", "--format", "json", check=False)
    try:
        return json.loads(p.stdout).get("name") or "?"
    except ValueError:
        return "?"


def commit_of() -> str:
    try:
        head = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True,
                              check=True).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT,
                               capture_output=True, text=True, check=True).stdout.strip()
        return head + (" with uncommitted changes" if dirty else "")
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def section(m: dict, *, dry: bool, today: str, project: str, prices: str, label: str = "") -> str:
    u = m["usage"] or {}
    methods = ", ".join(f"{k} {v}" for k, v in sorted(m["target_by_method"].items())) or "none"
    refused = "; ".join(f"{r['kind']} {r['method']} {r['url']}: {r['reason']}" for r in m["refused_rows"]) or "none"
    title = (f"## Agent run dry run against a stub Claude API ({today}{', ' + label if label else ''})" if dry
             else f"## Live agent run ({today}{', ' + label if label else ''})")
    lead = ("Not a measurement of the model: the Claude API was a local stub (`tools/agent_dryrun/claude_stub.py`) "
            "playing a fixed run, so the turns, tokens and cost are the stub's. It shows the path and the "
            "accounting end to end: the worker's SDK, the gateway's route, key swap and GW-1 body check, the "
            "budget, the tools, the evidence and this write-up." if dry else
            "One agent run through the Messages API, on the lab, with the cheapest configured model. The cost is "
            "the loop's estimate from the token counts the API returned; the Console bill is authoritative.")
    rows = [
        ("Model", f"`{m['model']}`"),
        ("Stack", f"compose project `{project}`, commit `{commit_of()}`, prices of {prices} (`agentloop.MODELS`)"),
        ("Lane", f"`{LANE_ROLE}` on `{LAB_HOST}`, scope `{LAB_HOST}` only, `{HEADER}`, job {m['job_id']}"),
        ("Outcome", f"job `{m['job_status']}`, agent `{m['agent_status']}`, {m['turns']} turn(s)"
                    + (f"; {m['detail']}" if m["detail"] else "")),
        ("Limits", (", ".join(f"{k} {v}" for k, v in m["limits"].items()) or "defaults")
                   + (f"; applied by the worker: {m['budget']}" if m.get("budget") else "")),
        ("Wall time", f"{m['wall_seconds']} s (job {m['job_seconds']} s)"),
        ("Claude API calls (gateway log)", f"{m['claude_api_calls']} to {', '.join(m['claude_api_hosts']) or 'none'}"),
        ("Target requests (gateway log)", f"{m['target_requests']}: {methods}; hosts: "
                                          f"{', '.join(m['target_hosts']) or 'none'}"
                                          f" ({'all' if m['only_lab_host'] else 'NOT all'} {LAB_HOST})"),
        ("Refused or failed rows", refused),
        ("Lab access log", f"{m['lab_requests']} request(s), {m['lab_with_header']} with the research header, "
                           f"{m['lab_with_user_agent']} with the user agent"),
        ("Research header on every request", ("yes" if m["lab_requests"] else "yes (no request was sent)")
                                             if m["header_on_every_request"] else "NO"),
        ("Evidence", f"{m['evidence_entries']} entr{'y' if m['evidence_entries'] == 1 else 'ies'} on "
                     f"{m['items_evidenced']} item(s); {m['items_marked']} item(s) marked; {m['leads']} lead(s)"),
        ("Tokens", f"input {u.get('input', 0):,}, output {u.get('output', 0):,}, cache read "
                   f"{u.get('cache_read', 0):,}, cache write {u.get('cache_write', 0):,}"),
        ("Cost (estimate)", f"${(m['cost_usd_estimate'] or 0):.4f} of a ${m['budget_usd']:.4g} budget"
                            if m.get("budget_usd") is not None else f"${(m['cost_usd_estimate'] or 0):.4f}"),
    ]
    table = "\n".join(f"| {k} | {v} |" for k, v in rows)
    summary = (m["summary"] or "").replace("\n", " ")[:600]
    return (f"\n{title}\n\n{lead}\n\n| | |\n|---|---|\n{table}\n\n"
            f"Agent summary for the reviewer: \"{summary}\"\n")


def run(stack: Stack, args) -> dict:
    live = not args.dry_run
    if "lab" not in stack.running():
        print(f"Starting the lab ({LAB_HOST}).", flush=True)
        stack.run("--profile", "lab", "up", "-d", "lab")
    pre = preflight(stack, live=live, prepare=True)
    worker = pre["worker"]
    if worker.get("model") != worker.get("cheapest") and not args.any_model:
        raise Failed(f"the worker runs {worker.get('model')}; a first run uses the cheapest, {worker.get('cheapest')}: "
                     f"set ATTACKLEDGER_AGENT_MODEL={worker.get('cheapest')} in .env and recreate the worker "
                     f"(docker compose up -d worker), or pass --any-model")
    budget = float(worker["ceilings"]["max_cost_usd"])
    eng, lane = pre["engagement"], pre["lane"]
    started = time.time()
    job = stack.api("POST", f"/lanes/{lane['id']}/agent-runs",
                    {"max_turns": args.max_turns, "max_requests": args.max_requests,
                     "max_cost_usd": max(0.05, min(20.0, budget))})
    print(f"Agent run queued: job {job['id']} on lane {lane['id']}, model {worker['model']}, "
          f"budget ${budget:g}. Waiting (up to {WAIT_SECONDS // 60} minutes).", flush=True)
    while True:
        job = stack.api("GET", f"/jobs/{job['id']}")
        if job["status"] not in ("queued", "running"):
            break
        if time.time() - started > WAIT_SECONDS:
            stack.api("POST", f"/jobs/{job['id']}/cancel")
            raise Failed(f"job {job['id']} did not end in {WAIT_SECONDS // 60} minutes; it was cancelled")
        time.sleep(3)
    ended = time.time()
    log = gateway_rows(stack, eng["id"], job["id"])
    lab = lab_requests(stack, started, ended)
    lane_now = stack.api("GET", f"/lanes/{lane['id']}")
    m = measure(job, log, lab, lane_now, started, ended, HEADER)
    applied = re.search(r"budget: (\$([0-9.]+), .*?) \(worker", job.get("log") or "")
    m["budget"], m["budget_usd"] = (applied[1], float(applied[2])) if applied else (None, None)
    prices = re.search(r"prices of ([0-9-]+)", job.get("log") or "")
    today = dt.date.today().isoformat()
    project = args.project or project_name(stack)
    text = section(m, dry=args.dry_run, today=today, project=project, prices=prices[1] if prices else "?",
                   label=getattr(args, "label", "") or "")
    print(text, flush=True)
    for line in (job.get("log") or "").splitlines()[-12:]:
        print(f"  log: {line[:200]}")
    if not args.no_append:
        bench = Path(args.benchmark) if args.benchmark else ROOT / "docs" / "BENCHMARK.md"
        with open(bench, "a") as f:
            f.write(text)
        out_dir = ROOT / "tools" / "benchmark"
        kind = "agent-dryrun" if args.dry_run else "agent-live"
        n = 1 + sum(1 for _ in out_dir.glob(f"results-{today}-{kind}*.json"))
        out = out_dir / f"results-{today}-{kind}{'' if n == 1 else f'-{n}'}.json"
        out.write_text(json.dumps({"date": today, "dry_run": args.dry_run, "project": project, **m}, indent=2) + "\n")
        print(f"Appended to {bench.relative_to(ROOT) if bench.is_relative_to(ROOT) else bench}; numbers in "
              f"{out.relative_to(ROOT)}.", flush=True)
    problems = []
    if not m["only_lab_host"]:
        problems.append(f"requests went to hosts other than {LAB_HOST}: {m['target_hosts']}")
    if not m["header_on_every_request"]:
        problems.append("the lab saw a request without the research header (or a count did not match)")
    if m["job_status"] == "failed":
        problems.append(f"the job failed: {(job.get('log') or '').strip().splitlines()[-1:]}")
    if problems:
        raise Failed("; ".join(problems))
    return m


# ---- the dry run -----------------------------------------------------------------------------

def free_port() -> int:
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def stub_saw(stack: Stack) -> None:
    """What the stub received: every call must pass the GW-1 check and carry the gateway's key."""
    stub = stack.run("logs", "--no-log-prefix", "claude-stub", check=False).stdout or ""
    calls = [json.loads(x) for x in stub.splitlines() if x.startswith('{"stub": "request"')]
    print("The stub Claude API saw:", flush=True)
    for c in calls:
        print(f"  turn {c['turn']}: {c['model']}, max_tokens {c['max_tokens']}, GW-1 {c['gw1']}, key: {c['key']}, "
              f"anthropic-beta {c['anthropic_beta']}, {c['bytes']} bytes, output tokens {c['usage']['output_tokens']}",
              flush=True)
    if not calls or any(c["gw1"] != "passes" or c["key"] != "the gateway's" for c in calls):
        raise Failed("the stub saw a call that the GW-1 check refuses or that did not carry the gateway's key")


def dryrun(args) -> None:
    project = args.project or "al-agent-dryrun"
    tmp = Path(tempfile.mkdtemp(prefix="al-agent-dryrun-"))
    os.chmod(tmp, 0o700)
    env_file = tmp / "env"
    port = args.port or free_port()
    values = {
        "ATTACKLEDGER_API_TOKEN": secrets.token_hex(24), "POSTGRES_PASSWORD": secrets.token_hex(16),
        # Not a key: the stub checks that the gateway sends this one instead of the worker's placeholder.
        "ANTHROPIC_API_KEY": "dry-run-stub-" + secrets.token_hex(8),
        "ATTACKLEDGER_AGENT_MODEL": args.model, "ATTACKLEDGER_AGENT_MAX_USD": args.max_usd,
        "AL_DRYRUN_PORT": str(port), "AL_DRYRUN_STUB_IMAGE": f"{project}-api",
        "AL_DRYRUN_USAGE_SCALE": str(args.usage_scale),
    }
    fd = os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("".join(f"{k}={v}\n" for k, v in values.items()))
    args.project, args.env_file, args.api = project, str(env_file), f"http://127.0.0.1:{port}"
    args.compose_file = ["docker-compose.yml", "tools/agent_dryrun/compose.dryrun.yml"]
    args.dry_run = True
    stack = Stack(args)
    try:
        print(f"Dry run: compose project {project}, API on 127.0.0.1:{port}, stub Claude API at {STUB_HOST}.",
              flush=True)
        if not args.no_build:
            stack.run("build", "api", "gateway", "worker", capture=False, timeout=3600)
        stack.run("--profile", "lab", "up", "-d", "--no-build", "db", "api", "claude-stub", "gateway", "worker", "lab",
                  timeout=900)
        for _ in range(60):
            try:
                stack.api("GET", "/executors")
                break
            except Failed:
                time.sleep(2)
        args.label = "fixed run"
        first = run(stack, args)
        stub_saw(stack)
        if first["agent_status"] != "finished":
            raise Failed(f"the stub's fixed run should finish; it ended {first['agent_status']}")
        # Then a budget that cannot pay for the run: the stub answers with long outputs (up to the
        # call's max_tokens), and the worker's ceiling is a fraction of a cent. The run must stop
        # before a call that could go over, as partial, and stay under the ceiling.
        values |= {"ATTACKLEDGER_AGENT_MAX_USD": "0.004", "AL_DRYRUN_USAGE_SCALE": "20"}
        fd = os.open(env_file, os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("".join(f"{k}={v}\n" for k, v in values.items()))
        print("Second run: worker ceiling $0.004, long stub outputs.", flush=True)
        stack.run("--profile", "lab", "up", "-d", "--no-build", "--force-recreate", "claude-stub", "gateway", "worker",
                  timeout=600)
        args.label = "budget stop"
        second = run(stack, args)
        if second["agent_status"] != "cost_limit" or second["job_status"] != "partial" \
                or (second["cost_usd_estimate"] or 0) > 0.004:
            raise Failed(f"the budget did not stop the run as it should: {second['agent_status']}, job "
                         f"{second['job_status']}, ${second['cost_usd_estimate']}")
        stub_saw(stack)
    finally:
        if args.keep:
            print(f"Kept: docker compose -p {project} --env-file {env_file} ... down -v when done.", flush=True)
        else:
            stack.run("--profile", "lab", "down", "-v", "--remove-orphans", check=False, timeout=300)
            env_file.unlink(missing_ok=True)
            tmp.rmdir()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("command", choices=["preflight", "run", "dryrun"])
    ap.add_argument("--project")
    ap.add_argument("--compose-file", action="append")
    ap.add_argument("--env-file")
    ap.add_argument("--api", default=os.environ.get("AL_API", "http://127.0.0.1:8000"))
    ap.add_argument("--benchmark")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-prepare", action="store_true")
    ap.add_argument("--any-model", action="store_true")
    ap.add_argument("--max-turns", type=int, default=15)
    ap.add_argument("--max-requests", type=int, default=20)
    ap.add_argument("--no-append", action="store_true")
    ap.add_argument("--port", type=int)
    ap.add_argument("--usage-scale", type=float, default=1.0)
    ap.add_argument("--model", default="claude-haiku-5-5")
    ap.add_argument("--max-usd", default="0.05")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--label", default="", help="added to the benchmark section's title")
    ap.add_argument("--no-build", action="store_true")
    args = ap.parse_args(argv)
    try:
        if args.command == "preflight":
            preflight(Stack(args), live=not args.dry_run, prepare=not args.no_prepare)
        elif args.command == "run":
            run(Stack(args), args)
        else:
            dryrun(args)
    except Failed as e:
        print(f"STOPPED: {e}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
