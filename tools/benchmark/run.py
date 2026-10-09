#!/usr/bin/env python3
"""AttackLedger benchmark against OWASP Juice Shop (docs/BENCHMARK.md).

  python3 tools/benchmark/run.py up        retag the main stack's images, start the bench stack
                                           (BENCH_KEEP_IMAGES=1: use attackledger-bench-* images
                                           built from a branch instead of retagging)
  python3 tools/benchmark/run.py recon     engagement, scope, authorization, lanes, full pipeline;
                                           waits, then writes the recon part of the results
  python3 tools/benchmark/run.py score     reads agent runs, the agent findings file and Juice
                                           Shop's challenge state; writes the final results
  python3 tools/benchmark/run.py down      removes the bench stack and its volumes

Everything runs in the attackledger-bench compose project (API on 127.0.0.1:8099); the main
and demo stacks are never touched. Traffic goes only to the lab containers on the internal
network. Request counts come from juice-proxy, which logs every request head it relays.

Files (DATE defaults to today, UTC):
  tools/benchmark/results-DATE.json         machine-readable results (written by recon, completed by score)
  tools/benchmark/agent-findings-DATE.json  the agent part, recorded by hand (see BENCHMARK.md)
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / "tools" / "benchmark"
BASE = "http://127.0.0.1:8099"
COMPOSE = ["docker", "compose", "-f", str(ROOT / "docker-compose.yml"), "-f", str(HERE / "compose.override.yml")]
SERVICES = ["db", "api", "worker", "juice", "juice-proxy"]
HOST = "juice.lab.test"
JUICE_IMAGE = ("bkimminich/juice-shop:v20.2.0@sha256:"
               "8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b")
SETTINGS = {
    "include": [HOST], "exclude": [],
    "rate_limit_rps": 20,                       # what the demo's lab recon uses; a hard ceiling
    "research_header": "X-Bug-Bounty: bench-researcher",
    "research_user_agent": "AttackLedger/0.6 (bench-researcher)",
    "enabled_modules": ["ports", "content", "params", "nuclei"],   # our own lab: every opt-in module
    "crawl_depth": 3,
}
POLICY = "https://example.com/policy"
DATE = (sys.argv[2] if len(sys.argv) > 2 else datetime.now(timezone.utc).strftime("%Y-%m-%d"))
RESULTS = HERE / f"results-{DATE}.json"
FINDINGS = HERE / f"agent-findings-{DATE}.json"


def call(method, path, body=None):
    req = urllib.request.Request(BASE + path, method=method, headers={"content-type": "application/json"},
                                 data=json.dumps(body).encode() if body is not None else None)
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def compose(*args, capture=False) -> str:
    out = subprocess.run([*COMPOSE, *args], check=True, text=True,
                         stdout=subprocess.PIPE if capture else None)
    return out.stdout if capture else ""


def in_net(code: str) -> str:
    """Run Python in the worker container (inside the lab network), never through the relay."""
    return compose("exec", "-T", "worker", "python", "-c", code, capture=True)


def ts(s: str | None) -> float | None:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() if s else None


# ---- stack -------------------------------------------------------------------

def up() -> None:
    for name in ("api", "worker"):
        if os.environ.get("BENCH_KEEP_IMAGES") == "1":
            subprocess.run(["docker", "image", "inspect", f"attackledger-bench-{name}:latest"], check=True,
                           stdout=subprocess.DEVNULL)
            continue
        subprocess.run(["docker", "tag", f"attackledger-{name}:latest", f"attackledger-bench-{name}:latest"],
                       check=True)
    compose("up", "-d", *SERVICES)
    for _ in range(60):
        try:
            call("GET", "/health")
            break
        except Exception:
            time.sleep(2)
    print("bench stack up:", call("GET", "/health"))


def down() -> None:
    compose("down", "-v")


# ---- measurement ---------------------------------------------------------------

def proxy_log() -> list[dict]:
    raw = compose("exec", "-T", "juice-proxy", "cat", "/tmp/requests.jsonl", capture=True)
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def peak(times: list[float]) -> int:
    """Most requests inside any one-second window."""
    times, best, j = sorted(times), 0, 0
    for i, t in enumerate(times):
        while times[j] <= t - 1.0:
            j += 1
        best = max(best, i - j + 1)
    return best


def per_second(times: list[float]) -> int:
    """Most requests inside one calendar second (how a per-second limiter counts)."""
    return max(Counter(int(t) for t in times).values(), default=0)


def traffic_by_job(jobs: list[dict], log: list[dict]) -> tuple[dict, dict]:
    """Jobs run one at a time, so a request belongs to the last job that started before it
    (and had not finished more than 2 s earlier); anything else is unattributed."""
    windows = sorted((ts(j["started_at"]), ts(j["finished_at"]) or time.time(), j["id"])
                     for j in jobs if j["started_at"])
    ident_value = SETTINGS["research_header"].split(":", 1)[1].strip()
    per = defaultdict(lambda: {"requests": 0, "times": [], "missing_identification": 0, "non_http": 0,
                               "connects": 0, "methods": Counter()})

    def owner(t):
        last = None
        for a, b, i in windows:
            if a <= t:
                last = (b, i)
        return last[1] if last and t <= last[0] + 2 else "unattributed"

    for e in log:
        jid = owner(e["t"])
        p = per[jid]
        if e["event"] == "request":
            p["requests"] += 1
            p["times"].append(e["t"])
            p["methods"][e["method"]] += 1
            if e.get("research") != ident_value or e.get("ua") != SETTINGS["research_user_agent"]:
                p["missing_identification"] += 1
        elif e["event"] == "non-http":
            p["non_http"] += 1
        elif e["event"] == "connect":
            p["connects"] += 1
    out = {}
    for jid, p in per.items():
        out[jid] = {"requests": p["requests"], "peak_rps_1s": peak(p["times"]),
                    "peak_per_calendar_second": per_second(p["times"]),
                    "seconds_over_limit": sum(1 for c in Counter(int(t) for t in p["times"]).values()
                                              if c > SETTINGS["rate_limit_rps"]),
                    "missing_identification": p["missing_identification"], "non_http_connections": p["non_http"],
                    "connections": p["connects"], "methods": dict(p["methods"])}
    all_req = [e for e in log if e["event"] == "request"]
    totals = {"requests": len(all_req), "peak_rps_1s": peak([e["t"] for e in all_req]),
              "peak_per_calendar_second": per_second([e["t"] for e in all_req]),
              "non_get": [{"job": owner(e["t"]), "method": e["method"], "target": e["target"][:200]}
                          for e in all_req if e["method"] not in ("GET", "HEAD", "OPTIONS")],
              "missing_identification": sum(v["missing_identification"] for v in out.values()),
              "methods": dict(Counter(e["method"] for e in all_req))}
    return out, totals


def recon_items(eng_id: int) -> tuple[list[str], list[dict]]:
    urls, off = [], 0
    while True:
        page = call("GET", f"/engagements/{eng_id}/endpoints?limit=1000&offset={off}")
        urls += [e["url"] for e in page["items"]]
        off += 1000
        if off >= page["total"]:
            break
    return urls, call("GET", f"/engagements/{eng_id}/leads")


def lead_text(lead: dict) -> str:
    return f"{lead['title']} {lead['source_url']} {json.dumps(lead['detail'], ensure_ascii=False)}"


def match(rules, urls: list[str], leads: list[dict]) -> list[str]:
    hits = []
    for where, rx in rules or []:
        r = re.compile(rx, re.I)
        if where in ("endpoint", "any"):
            hits += [f"endpoint {u}" for u in urls if r.search(u)]
        if where in ("lead", "any"):
            hits += [f"lead [{l['kind']}] {l['title']} @ {l['source_url']}" for l in leads if r.search(lead_text(l))]
    return list(dict.fromkeys(hits))[:5]


def challenge_state() -> list[dict]:
    code = ("import json,urllib.request;d=json.load(urllib.request.urlopen('http://juice:3000/api/Challenges'))"
            "['data'];print(json.dumps([{k:c[k] for k in ('key','name','category','difficulty','solved',"
            "'disabledEnv')} for c in d]))")
    return json.loads(in_net(code))


# ---- recon -------------------------------------------------------------------------

def recon() -> None:
    if call("GET", "/engagements"):
        sys.exit("the bench API already has engagements; start from an empty stack (run.py down, run.py up)")
    before = challenge_state()
    if any(c["solved"] for c in before):
        sys.exit("Juice Shop already has solved challenges; restart it before a measured run")
    eng = call("POST", "/engagements", {"name": "Juice Shop benchmark", "policy_url": POLICY})["id"]
    call("PUT", f"/engagements/{eng}/scope", SETTINGS)
    call("POST", f"/engagements/{eng}/attest", {"operator": "benchmark operator", "policy_url": POLICY, "confirm": True})
    asset = next(a for a in call("GET", f"/engagements/{eng}/coverage")["assets"] if a["host"] == HOST)
    lanes = {role: call("POST", "/lanes", {"asset_id": asset["asset_id"], "role": role})["id"]
             for role in ("recon", "mapper")}
    t0 = time.time()
    queued = call("POST", f"/engagements/{eng}/pipeline", {})["queued"]
    print(f"engagement {eng}, lanes {lanes}, pipeline queued: {queued}", flush=True)
    while True:
        jobs = call("GET", f"/engagements/{eng}/jobs")
        if all(j["status"] not in ("queued", "running") for j in jobs):
            break
        running = [j["kind"] for j in jobs if j["status"] == "running"]
        print(f"  {time.time() - t0:6.0f}s running: {running}", flush=True)
        time.sleep(15)
    wall = time.time() - t0
    jobs = sorted(jobs, key=lambda j: j["id"])
    traffic, totals = traffic_by_job(jobs, proxy_log())
    rows = []
    for j in jobs:
        full = call("GET", f"/jobs/{j['id']}")
        a, b = ts(j["started_at"]), ts(j["finished_at"])
        rows.append({"id": j["id"], "kind": j["kind"], "status": j["status"], "result_count": j["result_count"],
                     "targets": j["targets"], "seconds": round(b - a, 1) if a and b else None,
                     "skipped_reason": (j["result"] or {}).get("skipped_reason"),
                     **traffic.get(j["id"], {"requests": 0, "peak_rps_1s": 0, "missing_identification": 0}),
                     "log_tail": (full.get("log") or "")[-1500:]})
        print(f"  {j['kind']:<11} {j['status']:<8} {j['result_count']:>5} results "
              f"{rows[-1]['seconds']}s {rows[-1]['requests']} req peak {rows[-1]['peak_rps_1s']}/s", flush=True)
    urls, leads = recon_items(eng)
    results = {
        "date": DATE, "benchmark": "AttackLedger vs OWASP Juice Shop",
        "versions": versions(),
        "settings": {**SETTINGS, "policy_url": POLICY},
        "engagement_id": eng, "lanes": lanes,
        "recon": {"wall_seconds": round(wall, 1), "jobs": rows, "traffic_totals": totals,
                  "unattributed_traffic": traffic.get("unattributed"),
                  "endpoints_total": len(urls), "leads_total": len(leads),
                  "leads_by_kind": dict(Counter(l["kind"] for l in leads)),
                  "nuclei_leads": [{"title": l["title"], "severity": l["severity"], "url": l["source_url"],
                                    "template": (l["detail"] or {}).get("template")}
                                   for l in leads if l["kind"] == "nuclei"],
                  "endpoints": sorted(urls),
                  "leads": [{"kind": l["kind"], "title": l["title"], "url": l["source_url"]} for l in leads]},
        "challenges_after_recon": [c["key"] for c in challenge_state() if c["solved"]],
    }
    RESULTS.write_text(json.dumps(results, indent=1, ensure_ascii=False) + "\n")
    print(f"recon results: {RESULTS}")


def versions() -> dict:
    commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True,
                            stdout=subprocess.PIPE).stdout.strip()
    ids = {}
    for name in ("attackledger-bench-api:latest", "attackledger-bench-worker:latest", JUICE_IMAGE):
        ids[name] = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", name], text=True,
                                   stdout=subprocess.PIPE).stdout.strip()
    tools = in_net("import subprocess as s;print(s.run(['/opt/pd/bin/nuclei','-version'],capture_output=True,"
                   "text=True).stderr.strip().splitlines()[-1])").strip()
    return {"attackledger_commit": commit, "images": ids, "juice_shop": "v20.2.0", "nuclei": tools,
            "nuclei_templates": "v10.4.9 (worker/Dockerfile)"}


# ---- score ---------------------------------------------------------------------------

def score() -> None:
    results = json.loads(RESULTS.read_text())
    gt = json.loads((HERE / "ground_truth.json").read_text())
    eng = results["engagement_id"]
    urls, leads = recon_items(eng)
    state = {c["key"]: c for c in challenge_state()}
    if set(state) != set(gt["challenges"]):
        sys.exit(f"ground truth and image disagree: {sorted(set(state) ^ set(gt['challenges']))}")
    findings = json.loads(FINDINGS.read_text()) if FINDINGS.exists() else {"lanes": [], "items": {}}
    jobs = sorted(call("GET", f"/engagements/{eng}/jobs"), key=lambda j: j["id"])
    traffic, totals = traffic_by_job(jobs, proxy_log())
    for row in results["recon"]["jobs"]:          # re-attributed with the final rules
        row.update(traffic.get(row["id"], {"requests": 0, "peak_rps_1s": 0, "missing_identification": 0}))
    rj = [traffic.get(r["id"], {}) for r in results["recon"]["jobs"]]
    results["recon"]["traffic_totals"] = {
        "requests": sum(t.get("requests", 0) for t in rj),
        "peak_per_calendar_second": max(t.get("peak_per_calendar_second", 0) for t in rj),
        "peak_rps_1s": max(t.get("peak_rps_1s", 0) for t in rj),
        "missing_identification": sum(t.get("missing_identification", 0) for t in rj),
        "non_get": [n for n in totals["non_get"] if n["job"] in {r["id"] for r in results["recon"]["jobs"]}]}
    results["recon"]["unattributed_traffic"] = traffic.get("unattributed")
    agent_jobs = [{"id": j["id"], "lane_id": j["lane_id"], "status": j["status"],
                   "seconds": round(ts(j["finished_at"]) - ts(j["started_at"]), 1) if j["finished_at"] else None,
                   "result": j["result"], **traffic.get(j["id"], {})}
                  for j in jobs if j["kind"] == "agent"]

    items = []
    for key, g in gt["challenges"].items():
        c = state[key]
        items.append({"id": key, "type": "challenge", "name": c["name"], "category": c["category"],
                      "difficulty": c["difficulty"], "in_reach": g["in_reach"],
                      "reason": None if g["in_reach"] else gt["reasons"][g["reason"]],
                      "reason_code": g.get("reason"),
                      "recon": match(g.get("recon"), urls, leads) if g["in_reach"] else [],
                      "agent": findings["items"].get(key), "solved": c["solved"]})
    for sid, g in gt["surface"].items():
        items.append({"id": sid, "type": "surface", "name": g["title"], "in_reach": True,
                      "recon": match(g.get("recon"), urls, leads), "agent": findings["items"].get(sid),
                      "solved": None})

    reach = [i for i in items if i["in_reach"]]
    enabled = [i for i in items if i["type"] == "surface" or i["reason_code"] != "docker"]

    def recall(field):
        n = sum(1 for i in reach if (i[field] if field == "recon" else (i[field] or {}).get("found")))
        return {"found": n, "of": len(reach), "recall": round(n / len(reach), 3)}

    either = sum(1 for i in reach if i["recon"] or (i["agent"] or {}).get("found"))
    results.update({
        "agent": {"driver": findings.get("driver"), "note": findings.get("note"), "lanes": findings.get("lanes"),
                  "jobs": agent_jobs, "refusals": findings.get("refusals", [])},
        "traffic_totals_all": totals,
        "items": items,
        "summary": {
            "challenges_total": len(gt["challenges"]),
            "challenges_disabled_in_docker": sum(1 for g in gt["challenges"].values() if g.get("reason") == "docker"),
            "challenges_in_reach": sum(1 for g in gt["challenges"].values() if g["in_reach"]),
            "challenges_enabled_out_of_reach": sum(1 for g in gt["challenges"].values()
                                                   if not g["in_reach"] and g["reason"] != "docker"),
            "out_of_reach_by_reason": dict(Counter(g["reason"] for g in gt["challenges"].values()
                                                   if not g["in_reach"])),
            "surface_items": len(gt["surface"]),
            "in_reach_items": len(reach),
            "recon": recall("recon"), "agent": recall("agent"),
            "recon_or_agent": {"found": either, "of": len(reach), "recall": round(either / len(reach), 3)},
            "solved": sorted(k for k, c in state.items() if c["solved"]),
            "solved_in_reach": sum(1 for i in reach if i["solved"]),
            "solved_out_of_reach": sorted(i["id"] for i in enabled if i["solved"] and not i["in_reach"]),
        },
    })
    RESULTS.write_text(json.dumps(results, indent=1, ensure_ascii=False) + "\n")
    print(json.dumps(results["summary"], indent=1))


if __name__ == "__main__":
    cmds = {"up": up, "recon": recon, "score": score, "down": down}
    if len(sys.argv) < 2 or sys.argv[1] not in cmds:
        sys.exit(__doc__)
    cmds[sys.argv[1]]()
