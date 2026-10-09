#!/usr/bin/env python3
"""Fill an empty demo stack with the demo data, including a real recon run on the lab.

  1. tools/seed_demo.py (three engagements, fictional hosts, signed demo lanes)
  2. scope rules and an authorization record for each engagement
  3. Lab recon: every opt-in module allowed (the target is our own lab), a recon lane on
     shop.lab.test, two more names (api.lab.test answers, old.lab.test does not exist),
     then the full pipeline. It waits until every job has finished.

Run it only against the demo stack (see tools/demo/compose.override.yml): traffic goes
to the lab container and nowhere else. Then: tools/build_demo.sh API_BASE 2 3 1

Usage: python3 tools/demo_stack.py [API_BASE]   (default http://localhost:8098)
"""
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8098").rstrip("/")
ROOT = Path(__file__).resolve().parents[1]


def call(method, path, body=None):
    req = urllib.request.Request(BASE + path, method=method, headers={"content-type": "application/json"},
                                 data=json.dumps(body).encode() if body is not None else None)
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


if call("GET", "/engagements"):
    sys.exit("the demo API already has engagements; start from an empty demo stack")
subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "seed_demo.py"), BASE], check=True)
eng = {e["name"]: e["id"] for e in call("GET", "/engagements")}

RULES = {
    "Juice Shop lab": (["*.lab.test"], [], 5, "X-Bug-Bounty: lab-researcher", None, [], "https://example.com/policy"),
    "Client web app": (["app.client.test", "api.client.test"], [], 5, "X-Pentest: client-engagement", None, [],
                       "https://example.com/statement-of-work"),
    "Lab recon": (["*.lab.test"], ["admin.lab.test"], 20, "X-Bug-Bounty: lab-researcher",
                  "AttackLedger/0.6 (lab-researcher)", ["ports", "content", "params", "nuclei"],
                  "https://example.com/policy"),
}
for name, (inc, exc, rps, header, ua, mods, policy) in RULES.items():
    call("PUT", f"/engagements/{eng[name]}/scope", {
        "include": inc, "exclude": exc, "rate_limit_rps": rps, "research_header": header,
        "research_user_agent": ua, "enabled_modules": mods, "crawl_depth": 3})
    call("POST", f"/engagements/{eng[name]}/attest",
         {"operator": "demo operator", "policy_url": policy, "confirm": True})

lab = eng["Lab recon"]
shop = next(a for a in call("GET", f"/engagements/{lab}/coverage")["assets"] if a["host"] == "shop.lab.test")
call("POST", "/lanes", {"asset_id": shop["asset_id"], "role": "recon"})   # recon runs attach evidence to it
for host in ("api.lab.test", "old.lab.test"):
    call("POST", f"/engagements/{lab}/assets", {"host": host})
print("pipeline:", call("POST", f"/engagements/{lab}/pipeline", {})["queued"], flush=True)

while True:
    jobs = call("GET", f"/engagements/{lab}/jobs")
    if all(j["status"] not in ("queued", "running") for j in jobs):
        break
    time.sleep(15)
for j in reversed(jobs):
    print(f"  {j['kind']:<11} {j['status']:<8} {j['result_count']}")
print("summary:", call("GET", f"/engagements/{lab}/recon/summary"))
print(f"engagements: {eng}")
