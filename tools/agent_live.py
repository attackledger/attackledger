#!/usr/bin/env python3
"""A first live agent run on the lab, measured: pre-flight, one run, a benchmark section.

  python3 tools/agent_live.py preflight [--dry-run] [--no-prepare]
  python3 tools/agent_live.py run       [--dry-run] [--any-model] [--max-turns N] [--max-requests N]
                                        [--min-requests N] [--no-append]
  python3 tools/agent_live.py dryrun    [--project NAME] [--port PORT] [--usage-scale X] [--keep]

tools/agent_preflight.sh and tools/agent_live_run.sh call the first two. Options for every
command: --project NAME, --compose-file FILE (repeatable), --env-file FILE, --api URL (default
http://127.0.0.1:8000), --benchmark FILE (default docs/BENCHMARK.md), --role LANE (default errh),
--target shop|juiceshop (default shop: shop.lab.test).
Without them, the commands use this folder's compose setup (docker compose with its .env), like
every other command here.

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

           --role athn, sess, athz, cryp, clnt or apit (the lanes that need a signed-in user) use
           their own lab engagement, `Agent live run (lab, test accounts)`, with the lab's two fictional
           accounts as test accounts (D-040): user (alice, a customer) and admin (carol). Without
           --no-prepare, a missing one is signed in to the lab as a person would (POST /login,
           from inside the lab container) and its session cookie added through the API; the
           cookie is never printed. The other lanes use an engagement without test accounts.

run        starts the lab if needed, prepares the engagement and lane, runs preflight (it stops
           if that fails), starts ONE agent run with the worker's model (it must be the cheapest
           configured, unless --any-model), waits for it and prints a summary of what was sent and
           spent, from the job's result, the gateway's request log and the lab's access log. It
           appends that summary to the benchmark file as a dated section (unless --no-append) and
           writes the numbers next to it as JSON (tools/benchmark/results-<date>-agent-<n>.json).
           --min-requests N gives the run a depth floor (D-061, default 0: none): a finish below N
           requests is declined, at most twice, while turns and budget remain; the section and the
           JSON say when the run still ended below it.

dryrun     the whole of it against a stub Claude API, in its own compose project built from this
           tree, with no route out: no key, no traffic outside the stack. Then it removes that
           project (its containers, networks and volumes) unless --keep.

--target juiceshop  the second practice target, OWASP Juice Shop (D-060), as juice.lab.test: its own
           engagement, `Agent live run (Juice Shop)` (scope juice.lab.test only, authorized, the same
           research header), a lane per role as for the shop, and every lane signed out (Juice Shop's
           own accounts are not used: signing in as one solves challenges by itself). Pre-flight also
           checks that Juice Shop and its front run and reads Juice Shop's challenge list from inside
           the stack (the front's container asks Juice Shop directly: nothing goes through the
           gateway or into the front's access log). A run reads that list before and after, recreates
           Juice Shop first if a challenge is already solved, writes a snapshot of the run's leads,
           evidence and items with both lists (tools/benchmark/juiceshop-<date>-<kind>[-n].json, or
           --snapshot FILE) and prints the score of tools/juiceshop_score.py.

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
# The practice targets a run can take (--target). The shop is lab/nginx.conf; Juice Shop (D-060) is
# reached through its front (lab/juiceshop.conf), whose access log is the independent count.
#   host        what the engagement's scope holds and the agent is given
#   services    the compose services that make it up (started with --profile lab)
#   log_service the one whose access log, in the format of LAB_LINE, counts what arrived
TARGETS = {
    "shop": {"host": "shop.lab.test", "eng_name": "Agent live run (lab)", "services": ("lab",),
             "log_service": "lab", "label": ""},
    "juiceshop": {"host": "juice.lab.test", "eng_name": "Agent live run (Juice Shop)",
                  "services": ("juiceshop", "juiceshop-front"), "log_service": "juiceshop-front",
                  "label": "Juice Shop"},
}
TARGET = "shop"
LAB_HOST = TARGETS[TARGET]["host"]
ENG_NAME = TARGETS[TARGET]["eng_name"]
LAB_SERVICES = TARGETS[TARGET]["services"]
LAB_LOG_SERVICE = TARGETS[TARGET]["log_service"]
# Juice Shop's own API, from inside its front's container (the juiceshop network): the challenge
# list with its solved flags, and the version.
JUICE_API = "http://juiceshop:3000"
LANE_ROLE = "errh"              # WSTG Error handling: two items, both testable with read-only requests
# Lanes that need a signed-in user: their runs use the lab's fictional accounts as test accounts
# (D-040), on an engagement of their own, so the other lanes' runs stay comparable (no accounts).
# Why each needs one (lab/nginx.conf lists what is planted):
#   athn, sess  the sign-in, the session cookie and the signed-in pages are what they test;
#   athz        two roles to compare (a customer reads an admin's data);
#   cryp        the weak encoding and hashing sit behind the sign-in (the invoice link on the
#               account page, the data export);
#   clnt        the credentialed CORS read only shows a user's data when one is signed in, and the
#               page to frame is the signed-in password change;
#   apit        the GraphQL field that exposes another customer answers signed-in users only.
# idnt and busl run signed out: account enumeration, registration and the cart's checks are what
# anyone sees, and a session would only hide that.
ACCOUNT_ROLES = ("athn", "sess", "athz", "cryp", "clnt", "apit")
# Lanes a run may take (--role): each has issues planted in lab/nginx.conf for an agent to find.
ROLES = ("errh", "info", "conf", "inpv", "idnt", "busl") + ACCOUNT_ROLES
ACCOUNTS_ENG_NAME = "Agent live run (lab, test accounts)"
# The lab's fictional accounts (lab/nginx.conf): test account label, its role in the shop, and the
# username and password a person would sign in with. Fictional, and the lab is reachable only
# inside the compose network.
LAB_ACCOUNTS = (("user", "customer", "alice", "shop-alice-2026"),
                ("admin", "admin", "carol", "shop-carol-admin-2026"))
SESSION_COOKIE = "lab_session"
PACK = "web-pentest-wstg"
HEADER = "X-Bug-Bounty: agent-live-run"     # the lab's access log records this header (lab/nginx.conf)
USER_AGENT = "AttackLedger agent live run"
POLICY = "https://example.com/policy"
WAIT_SECONDS = 15 * 60
STUB_HOST = "claude-stub.test"


def use_target(name: str) -> None:
    """Point the module at a practice target (--target)."""
    global TARGET, LAB_HOST, ENG_NAME, LAB_SERVICES, LAB_LOG_SERVICE
    t = TARGETS[name]
    TARGET, LAB_HOST, ENG_NAME = name, t["host"], t["eng_name"]
    LAB_SERVICES, LAB_LOG_SERVICE = t["services"], t["log_service"]


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


def uses_accounts() -> bool:
    # Juice Shop's lanes all run signed out: its accounts are its challenges (signing in as the
    # administrator with admin123 solves one), and its registration is a write the agents do not send.
    return TARGET == "shop" and LANE_ROLE in ACCOUNT_ROLES


def eng_name() -> str:
    return ACCOUNTS_ENG_NAME if uses_accounts() else ENG_NAME


def session_cookie(wget_output: str) -> str | None:
    """The lab's session cookie ("lab_session=<value>") from a sign-in's response headers (busybox
    wget -S), or None."""
    m = re.search(rf"^\s*Set-Cookie:\s*({SESSION_COOKIE}=[^;\s]+)", wget_output, re.M | re.I)
    return m[1] if m else None


def sign_in(stack: Stack, username: str, password: str) -> str:
    """Sign in to the lab as a person would, with its sign-in form (POST /login), from inside the lab's
    own container (the lab has no other way in but the gateway, which sends no writes without an
    approval). The session cookie it answers with; never printed."""
    p = stack.run("exec", "-T", "lab", "wget", "-S", "-O", "/dev/null", "-U", USER_AGENT, "--header", HEADER,
                  "--post-data", f"username={username}&password={password}", "http://127.0.0.1/login", check=False)
    cookie = session_cookie((p.stderr or "") + (p.stdout or ""))
    if not cookie:
        status = re.search(r"HTTP/1\.[01] (\d{3})", (p.stderr or "") + (p.stdout or ""))
        raise Failed(f"signing in to the lab as {username} gave no session cookie "
                     f"({'HTTP ' + status[1] if status else 'no answer'}); is the lab running this tree's "
                     f"lab/nginx.conf? (docker compose --profile lab up -d --force-recreate lab)")
    return cookie


def accounts_state(stack: Stack, eng_id: int) -> tuple[list, list]:
    """(the engagement's test accounts, the labels of LAB_ACCOUNTS missing or not for the lab host only)."""
    have = stack.api("GET", f"/engagements/{eng_id}/test-accounts")
    by_label = {a["label"]: a for a in have}
    missing = [label for label, *_ in LAB_ACCOUNTS
               if label not in by_label or by_label[label]["hosts"] != [LAB_HOST]]
    return have, missing


def add_accounts(stack: Stack, eng_id: int, labels) -> None:
    """Sign in to the lab for each label and add its session as a test account (D-040), or replace an
    account of that label made for other hosts. The cookie goes to the API only."""
    have = {a["label"]: a for a in stack.api("GET", f"/engagements/{eng_id}/test-accounts")}
    for label, role, username, password in LAB_ACCOUNTS:
        if label not in labels:
            continue
        body = {"role": f"{role} ({username})", "hosts": [LAB_HOST], "kind": "cookie",
                "value": sign_in(stack, username, password)}
        if label in have:
            stack.api("PUT", f"/engagements/{eng_id}/test-accounts/{have[label]['id']}", body)
        else:
            stack.api("POST", f"/engagements/{eng_id}/test-accounts", {"label": label, **body})
        print(f"  Signed in to the lab as {username} and added the session as test account {label} "
              f"({role}).", flush=True)


def find_lane(stack: Stack, prepare: bool) -> tuple[dict, dict, str]:
    """The lab engagement and its lane: reused while every item of the lane is open and no run is active,
    created otherwise (if prepare). (engagement, lane, what was done). A lane that needs a signed-in
    user (ACCOUNT_ROLES) takes the engagement with the lab's test accounts, the others one without."""
    name = eng_name()
    for e in stack.api("GET", "/engagements"):
        if not e["name"].startswith(name):
            continue
        scope = stack.api("GET", f"/engagements/{e['id']}/scope")
        if scope["include"] != [LAB_HOST] or scope["exclude"] or not scope["authorized_at"] \
                or scope["research_header"] != HEADER or scope["content_deleted"]:
            continue
        have, missing = accounts_state(stack, e["id"])
        if not uses_accounts() and have:
            continue
        if uses_accounts() and (scope.get("redact_evidence") is False or (missing and not prepare)):
            # The gateway uses test accounts only while redaction is on (D-038); missing ones are
            # signed in below, once the lane is known to be usable.
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
        # Only a lane no run has worked on: one with some items already done is not a comparable measurement.
        if all(i["state"] == "open" for i in lane["items"]) and lane["status"] != "closed" \
                and not any(r["status"] in ("queued", "running") for r in runs):
            if uses_accounts() and missing:
                add_accounts(stack, e["id"], missing)
            return e, lane, "reused"
    if not prepare:
        raise Failed(f"no usable engagement named {name!r} with a {LANE_ROLE} lane on {LAB_HOST}"
                     f"{' and its test accounts' if uses_accounts() else ''}; run without --no-prepare to create it")
    n = sum(1 for e in stack.api("GET", "/engagements") if e["name"].startswith(name))
    name = name if n == 0 else f"{name} {n + 1}"
    e = stack.api("POST", "/engagements", {"name": name, "pack_id": PACK, "engagement_type": "pentest"})
    stack.api("PUT", f"/engagements/{e['id']}/scope", {
        "include": [LAB_HOST], "exclude": [], "rate_limit_rps": 2, "research_header": HEADER,
        "research_user_agent": USER_AGENT, "enabled_modules": [], "crawl_depth": 1})
    stack.api("POST", f"/engagements/{e['id']}/attest",
              {"operator": f"agent_live.py ({'lab' if TARGET == 'shop' else TARGET})", "policy_url": POLICY,
               "confirm": True})
    asset = next(a for a in stack.api("GET", f"/engagements/{e['id']}/coverage")["assets"] if a["host"] == LAB_HOST)
    lane = stack.api("POST", "/lanes", {"asset_id": asset["asset_id"], "role": LANE_ROLE})
    if uses_accounts():
        add_accounts(stack, e["id"], [label for label, *_ in LAB_ACCOUNTS])
    return e, lane, "created"


def preflight(stack: Stack, live: bool, prepare: bool = True) -> dict:
    print(f"Pre-flight ({'live run' if live else 'dry run against a stub Claude API'}); nothing is sent "
          f"to the Claude API or the target" + (", but the lab's sign-in for a missing test account"
                                                if uses_accounts() and prepare else "") + ".", flush=True)
    checks = []
    up = stack.running()
    missing = [s for s in ("api", "gateway", "worker", *LAB_SERVICES) if s not in up]
    checks.append(("stack", not missing, f"api, gateway, worker and {' and '.join(LAB_SERVICES)} are running"
                   if not missing else f"not running: {', '.join(missing)} (docker compose up -d; docker compose "
                                       f"--profile lab up -d {' '.join(LAB_SERVICES)})"))
    worker = {}
    if not missing:
        more, worker = container_checks(stack, live)
        checks += more
        if TARGET == "juiceshop":
            checks.append(juice_check(stack))
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
        have, missing = accounts_state(stack, eng["id"])
        if uses_accounts():
            checks.append(("api test accounts", not missing,
                           ", ".join(f"{a['label']} ({a['role']}, {a['kind']})" for a in have
                                     if a["label"] in {x[0] for x in LAB_ACCOUNTS}) + f" for {LAB_HOST} only"
                           if not missing else f"missing: {', '.join(missing)}"))
        else:
            checks.append(("api test accounts", not have, "none (this lane runs signed out)" if not have
                           else f"the engagement has test accounts ({', '.join(a['label'] for a in have)}): "
                                f"this lane's runs are measured signed out"))
    except Failed as e:
        checks.append(("api", False, str(e)))
    for name, ok, detail in checks:
        say(ok, name, detail)
    failed = [c for c in checks if not c[1]]
    if failed:
        raise Failed(f"pre-flight failed: {', '.join(c[0] for c in failed)}. Nothing was started.")
    print("Pre-flight passed.", flush=True)
    return {"engagement": eng, "lane": lane, "worker": worker}


# ---- Juice Shop (D-060) ----------------------------------------------------------------------

def juice_get(stack: Stack, path: str):
    """GET a path of Juice Shop's own API from inside its front's container, straight to Juice Shop on
    the juiceshop network: not through the gateway, and not through the front (so not in its access
    log, which counts the agent's requests). JSON, or Failed."""
    p = stack.run("exec", "-T", TARGETS["juiceshop"]["log_service"], "wget", "-q", "-T", "15", "-O", "-",
                  JUICE_API + path, check=False)
    try:
        return json.loads(p.stdout)
    except ValueError:
        raise Failed(f"Juice Shop did not answer {path} from inside the stack: "
                     f"{(p.stderr or p.stdout or '').strip()[-200:] or 'no answer'}")


def juice_challenges(stack: Stack) -> list[dict]:
    """Juice Shop's challenge list with its solved flags (/api/Challenges), the fields scoring needs."""
    data = juice_get(stack, "/api/Challenges")
    rows = data.get("data") if isinstance(data, dict) else None
    if not rows:
        raise Failed("Juice Shop's /api/Challenges answered without a challenge list")
    return [{"key": c["key"], "name": c["name"], "category": c["category"], "difficulty": c.get("difficulty"),
             "solved": bool(c.get("solved")), "disabledEnv": c.get("disabledEnv") or []} for c in rows]


def juice_version(stack: Stack) -> str:
    try:
        return str(juice_get(stack, "/rest/admin/application-version").get("version") or "?")
    except (Failed, AttributeError):
        return "?"


def juice_check(stack: Stack) -> tuple:
    """Pre-flight: Juice Shop answers inside the stack, and no challenge is solved yet."""
    try:
        rows = juice_challenges(stack)
    except Failed as e:
        return ("juice shop", False, f"{e} (docker compose --profile lab up -d {' '.join(LAB_SERVICES)})")
    solved = sum(c["solved"] for c in rows)
    return ("juice shop", not solved,
            f"Juice Shop {juice_version(stack)}: {len(rows)} challenges, none solved (read inside the stack, "
            f"not through the gateway)" if not solved else
            f"{solved} challenge(s) already solved: a run starts on a fresh shop (agent_live.py run recreates it; "
            f"or docker compose --profile lab up -d --force-recreate juiceshop)")


def fresh_juice_shop(stack: Stack) -> list[dict]:
    """The challenge list before a run, on a fresh shop: Juice Shop is recreated (its writes are in the
    container's own layer, so a new container has no challenge solved) if any is solved."""
    rows = None
    for _ in range(40):
        try:
            rows = juice_challenges(stack)
            break
        except Failed:
            time.sleep(3)
    if rows is None:
        rows = juice_challenges(stack)
    if not any(c["solved"] for c in rows):
        return rows
    print(f"Juice Shop has {sum(c['solved'] for c in rows)} challenge(s) solved already: recreating it for a "
          f"fresh shop.", flush=True)
    stack.run("--profile", "lab", "up", "-d", "--force-recreate", "--wait", "juiceshop", timeout=600)
    for _ in range(40):
        try:
            rows = juice_challenges(stack)
            if not any(c["solved"] for c in rows):
                return rows
        except Failed:
            pass
        time.sleep(3)
    raise Failed("Juice Shop still has solved challenges after it was recreated")


def scorer():
    """tools/juiceshop_score.py, loaded from this tree."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("juiceshop_score", ROOT / "tools" / "juiceshop_score.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def juice_snapshot(stack: Stack, args, job: dict, eng: dict, lane: dict, m: dict, before: list, today: str) -> str:
    """After a run on Juice Shop: the run's leads, agent evidence and items, with the challenge list read
    before and after, written for tools/juiceshop_score.py (offline); returns that score (Markdown)."""
    after = juice_challenges(stack)
    t0 = job.get("started_at")
    t0 = dt.datetime.fromisoformat(t0.replace("Z", "+00:00")) if t0 else None
    leads = [{"id": x["id"], "title": x["title"], "detail": x["detail"], "severity": x["severity"],
              "source_url": x["source_url"]}
             for x in stack.api("GET", f"/engagements/{eng['id']}/leads?kind=agent")
             if isinstance(x.get("detail"), dict) and x["detail"].get("lane_id") == lane["id"]]
    evidence = [{"id": e["id"], "item_idx": e["item_idx"], "kind": e.get("kind"), "uri": e.get("uri"),
                 "summary": e.get("summary")}
                for e in lane.get("evidence", []) if e.get("source") == "agent" and t0 is not None
                and dt.datetime.fromisoformat(e["created_at"].replace("Z", "+00:00")) >= t0]
    snap = {"format": "attackledger-juiceshop-snapshot/1", "date": today, "dry_run": bool(args.dry_run),
            "juice_shop_version": juice_version(stack), "in_docker": True, "target_host": LAB_HOST,
            "engagement_id": eng["id"], "job_id": job["id"], "lane": {"id": lane["id"], "role": lane["role"]},
            "agent_status": m.get("agent_status"), "agent_summary": m.get("summary", ""),
            "leads": leads, "evidence": evidence,
            "items": [{"idx": i["idx"], "key": i["key"], "text": i["text"], "state": i["state"],
                       "na_reason": i.get("na_reason")} for i in lane.get("items", [])],
            "challenges_before": before, "challenges_after": after}
    path = Path(args.snapshot) if args.snapshot else None
    if path is None and not args.no_append:
        kind = "agent-dryrun" if args.dry_run else "agent-live"
        out_dir = ROOT / "tools" / "benchmark"
        n = 1 + sum(1 for _ in out_dir.glob(f"juiceshop-{today}-{kind}*.json"))
        path = out_dir / f"juiceshop-{today}-{kind}{'' if n == 1 else f'-{n}'}.json"
    # The snapshot is written before it is scored, so a scoring failure never loses the run's data.
    if path is not None:
        path.write_text(json.dumps(snap, indent=2) + "\n")
        shown = path.relative_to(ROOT) if path.resolve().is_relative_to(ROOT) else path
        print(f"Snapshot for scoring in {shown}: python3 tools/juiceshop_score.py {shown} [--review FILE]",
              flush=True)
    sc = scorer()
    text = sc.markdown(sc.score(snap, sc.load_map()))
    print(text, flush=True)
    return text


# ---- the run ---------------------------------------------------------------------------------

LAB_LINE = re.compile(r'^(?P<port>\d+) "(?P<method>[A-Z]+) (?P<path>\S*) [^"]*" (?P<status>\d+) '
                      r'ua="(?P<ua>[^"]*)" research="(?P<research>[^"]*)" t=(?P<t>[\d.]+)'
                      r'(?: user="(?P<user>[^"]*)")?')


def lab_requests(stack: Stack, since: float, until: float) -> list[dict]:
    """The target's own access log (lab/nginx.conf, or Juice Shop's front, lab/juiceshop.conf) between
    two times: an independent count."""
    stamp = dt.datetime.fromtimestamp(since - 5, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    p = stack.run("logs", "--no-log-prefix", "--since", stamp, LAB_LOG_SERVICE, check=False)
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
    # nginx answers 400 before it reads the headers when a path climbs above the root (/..%2f..%2f),
    # and logs "-" for both: the header is not observable on those, so they are counted, not judged.
    blind = [x for x in lab if x["status"] == "400" and x["research"] == "-" and x["ua"] == "-"]
    seen = [x for x in lab if not (x["status"] == "400" and x["research"] == "-" and x["ua"] == "-")]
    return {
        "job_id": job["id"], "job_status": job["status"], "agent_status": res.get("status"),
        "model": res.get("model"), "turns": res.get("turns"), "detail": res.get("detail", ""),
        "summary": res.get("summary", ""), "limits": res.get("limits", {}),
        "min_requests": (res.get("limits") or {}).get("min_requests", 0),
        "depth_floor": res.get("depth_floor"), "below_depth_floor": bool(res.get("below_depth_floor")),
        "claude_api_calls": len(service), "claude_api_hosts": sorted({r["url"].split("/")[2] for r in service}),
        "target_requests": len(target), "target_by_method": by_method, "target_hosts": hosts,
        "only_lab_host": hosts in ([], [LAB_HOST]),
        "refused_rows": [{"kind": r["kind"], "method": r["method"], "url": r["url"][:200], "reason": r["reason"]}
                         for r in refused],
        "agent_requests": res.get("requests"),
        "lab_requests": len(lab), "lab_with_header": sum(1 for x in lab if x["research"] == value),
        "lab_with_user_agent": sum(1 for x in lab if x["ua"] == USER_AGENT),
        "lab_headers_unread": len(blind),
        # The lab's own view of which fictional user each request was signed in as (lab/nginx.conf).
        "lab_signed_in": {u: sum(1 for x in lab if x.get("user") == u)
                          for u in sorted({x.get("user") for x in lab if x.get("user") not in (None, "", "-")})},
        # Every request whose headers the lab read carried it, and the lab saw as many as the gateway sent.
        "header_on_every_request": all(x["research"] == value for x in seen)
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
        # The benchmark file this script appends to does not count as a change to what ran.
        dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no", "--", ".",
                                ":!docs/BENCHMARK.md"], cwd=ROOT, capture_output=True, text=True,
                               check=True).stdout.strip()
        return head + (" with uncommitted changes" if dirty else "")
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def floor_note(m: dict) -> str:
    """The depth floor's outcome for the Outcome row (D-061); nothing for a run without one."""
    floor = m.get("depth_floor") or {}
    if not floor:
        return ""
    if m.get("below_depth_floor"):
        return (f"; **below the depth floor**: {floor.get('requests')} of {floor.get('min_requests')} requests"
                + (f" ({floor['reason']})" if floor.get("reason") else ""))
    return (f"; depth floor of {floor.get('min_requests')} reached, finish declined "
            f"{floor.get('refusals', 0)} time(s)")


def section(m: dict, *, dry: bool, today: str, project: str, prices: str, label: str = "") -> str:
    u = m["usage"] or {}
    methods = ", ".join(f"{k} {v}" for k, v in sorted(m["target_by_method"].items())) or "none"
    refused = "; ".join(f"{r['kind']} {r['method']} {r['url']}: {r['reason']}" for r in m["refused_rows"]) or "none"
    where = TARGETS[TARGET]["label"]
    label = ", ".join(x for x in (where, label) if x)
    title = (f"## Agent run dry run against a stub Claude API ({today}{', ' + label if label else ''})" if dry
             else f"## Live agent run ({today}{', ' + label if label else ''})")
    lead = ("Not a measurement of the model: the Claude API was a local stub (`tools/agent_dryrun/claude_stub.py`) "
            "playing a fixed run, so the turns, tokens and cost are the stub's. It shows the path and the "
            "accounting end to end: the worker's SDK, the gateway's route, key swap and GW-1 body check, the "
            "budget, the tools, the evidence and this write-up." if dry else
            "One agent run through the Messages API, on the lab, with the worker's configured model. The cost is "
            "the loop's estimate from the token counts the API returned; the Console bill is authoritative.")
    rows = [
        ("Model", f"`{m['model']}`"),
        ("Stack", f"compose project `{project}`, commit `{commit_of()}`, prices of {prices} (`agentloop.MODELS`)"),
        ("Lane", f"`{LANE_ROLE}` on `{LAB_HOST}`, scope `{LAB_HOST}` only, `{HEADER}`, job {m['job_id']}"
                 + (", test accounts " + ", ".join(f"`{label}` ({role}, {user})" for label, role, user, _ in LAB_ACCOUNTS)
                    if uses_accounts() else "")),
        ("Outcome", f"job `{m['job_status']}`, agent `{m['agent_status']}`, {m['turns']} turn(s)"
                    + (f"; {m['detail']}" if m["detail"] else "") + floor_note(m)),
        ("Limits", (", ".join(f"{k} {v}" for k, v in m["limits"].items()) or "defaults")
                   + ("" if "min_requests" in m["limits"] else ", min_requests 0 (no depth floor)")
                   + (f"; applied by the worker: {m['budget']}" if m.get("budget") else "")),
        ("Wall time", f"{m['wall_seconds']} s (job {m['job_seconds']} s)"),
        ("Claude API calls (gateway log)", f"{m['claude_api_calls']} to {', '.join(m['claude_api_hosts']) or 'none'}"),
        ("Target requests (gateway log)", f"{m['target_requests']}: {methods}; hosts: "
                                          f"{', '.join(m['target_hosts']) or 'none'}"
                                          f" ({'all' if m['only_lab_host'] else 'NOT all'} {LAB_HOST})"),
        ("Refused or failed rows", refused),
        ("Lab access log", f"{m['lab_requests']} request(s), {m['lab_with_header']} with the research header, "
                           f"{m['lab_with_user_agent']} with the user agent"
                           + (f"; {unread} answered 400 by the lab's nginx before it read the headers"
                              if (unread := m.get("lab_headers_unread")) else "")
                           + ("; signed in as " + ", ".join(f"{u} {n}" for u, n in signed.items())
                              if (signed := m.get("lab_signed_in")) else "")),
        ("Research header on every request", (("yes" if m["lab_requests"] else "yes (no request was sent)")
                                              + (f" (on the {m['lab_requests'] - unread} whose headers the lab "
                                                 f"read; {unread} not observable)" if unread else ""))
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
    if not set(LAB_SERVICES) <= stack.running():
        print(f"Starting the lab ({LAB_HOST}).", flush=True)
        stack.run("--profile", "lab", "up", "-d", *LAB_SERVICES)
    juice_before = fresh_juice_shop(stack) if TARGET == "juiceshop" else None
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
                     "max_cost_usd": max(0.05, min(20.0, budget)), "min_requests": args.min_requests})
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
    if juice_before is not None:
        text += "\n" + juice_snapshot(stack, args, job, eng, lane_now, m, juice_before, today)
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
        stack.run("--profile", "lab", "up", "-d", "--no-build", "db", "api", "claude-stub", "gateway", "worker",
                  *LAB_SERVICES, timeout=900)
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
        # With test accounts, the stub sends its first request as one: the lab must have seen it signed in,
        # so the gateway added the account's session (D-040).
        if uses_accounts() and not first.get("lab_signed_in"):
            raise Failed("the stub's request as a test account reached the lab signed out")
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
    global LANE_ROLE
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
    ap.add_argument("--min-requests", type=int, default=0,
                    help="depth floor (D-061): finish below this many requests is declined, at most twice, "
                         "while turns and budget remain; 0 (default) is none")
    ap.add_argument("--no-append", action="store_true")
    ap.add_argument("--port", type=int)
    ap.add_argument("--usage-scale", type=float, default=1.0)
    ap.add_argument("--model", default="claude-haiku-5-5")
    ap.add_argument("--max-usd", default="0.05")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--label", default="", help="added to the benchmark section's title")
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--role", choices=ROLES, default=LANE_ROLE, help="the WSTG lane on the lab to run")
    ap.add_argument("--target", choices=sorted(TARGETS), default="shop",
                    help="the practice target: the shop (shop.lab.test) or OWASP Juice Shop (juice.lab.test, D-060)")
    ap.add_argument("--snapshot", help="with --target juiceshop: where to write the run's snapshot for "
                                       "tools/juiceshop_score.py")
    args = ap.parse_args(argv)
    LANE_ROLE = args.role
    use_target(args.target)
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
