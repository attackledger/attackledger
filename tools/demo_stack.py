#!/usr/bin/env python3
"""Fill an empty demo stack with the demo data, including a real recon run on the lab.

  1. tools/seed_demo.py (three engagements, fictional hosts, signed demo lanes)
  2. scope rules and an authorization record for each engagement
  3. An evidence import on "Client web app", by a demo tester (fictional, signed in with a
     random password that is thrown away): a browser HAR and a Burp Suite XML export made
     from lab answers (tools/demo/make_imports.py), some entries mapped to WSTG items (which
     opens the lanes they need), one dismissed with a reason, the rest left to map.
  4. Lab recon: every opt-in module allowed (the target is our own lab), a recon lane on
     shop.lab.test, two more names (api.lab.test answers, old.lab.test does not exist),
     then the full pipeline. It waits until every job has finished.

Run it only against the demo stack (see tools/demo/compose.override.yml): traffic goes
to the lab container and nowhere else. Then tools/demo_sign.py, tools/demo_retention.py and
tools/build_demo.sh API_BASE 2 3 1 4 (site/README.md).

Usage: ATTACKLEDGER_API_TOKEN=... python3 tools/demo_stack.py [API_BASE]   (default http://localhost:8098)
"""
import http.cookiejar
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8098").rstrip("/")
ROOT = Path(__file__).resolve().parents[1]
TOKEN = os.environ.get("ATTACKLEDGER_API_TOKEN") or sys.exit("set ATTACKLEDGER_API_TOKEN to the demo API's token")
AUTH = {"authorization": f"Bearer {TOKEN}"}


def call(method, path, body=None, opener=None, headers=AUTH):
    req = urllib.request.Request(BASE + path, method=method, headers={"content-type": "application/json", **headers},
                                 data=json.dumps(body).encode() if body is not None else None)
    with (opener.open if opener else urllib.request.urlopen)(req) as r:
        return json.loads(r.read())


def upload(opener, path, data: bytes):
    req = urllib.request.Request(BASE + path, method="POST", data=data,
                                 headers={"content-type": "application/octet-stream"})
    with opener.open(req) as r:
        return json.loads(r.read())


if call("GET", "/engagements"):
    sys.exit("the demo API already has engagements; start from an empty demo stack")
subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "seed_demo.py"), BASE], check=True)
eng = {e["name"]: e["id"] for e in call("GET", "/engagements")}

RULES = {
    "Juice Shop lab": (["*.lab.test"], [], 5, "X-Bug-Bounty: lab-researcher", None, [], "https://example.com/policy"),
    "Client web app": (["app.client.test", "api.client.test"], [], 5, "X-Pentest: client-engagement", None, [],
                       "https://example.com/statement-of-work"),
    "Client portal 2025": (["portal.client.test"], [], 5, "X-Pentest: client-engagement", None, [],
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


# ---- the import, as a tester would do it in the browser ------------------------------------
pt = eng["Client web app"]
password = secrets.token_urlsafe(18)
# The first person must be an owner; tools/demo_sign.py and tools/demo_retention.py use this one.
call("POST", "/people", {"email": "owner@demo.test", "name": "Demo Owner", "password": secrets.token_urlsafe(18),
                         "is_owner": True})
call("POST", "/people", {"email": "tester@demo.test", "name": "Demo Tester", "password": password, "is_owner": False})
tester_id = next(p["id"] for p in call("GET", "/people") if p["email"] == "tester@demo.test")
call("PUT", f"/engagements/{pt}/members", {"members": [{"user_id": tester_id, "roles": ["tester"]}]})
tester = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
call("POST", "/auth/login", {"email": "tester@demo.test", "password": password}, tester, {})
call("POST", "/auth/password", {"current_password": password, "new_password": secrets.token_urlsafe(18)}, tester, {})

files = ROOT / "tools" / "demo" / "imports"
for name in ("client-web-app.har", "client-web-app-burp.xml"):
    b = upload(tester, f"/engagements/{pt}/imports?filename={name}", (files / name).read_bytes())
    print(f"import {name}: {b['accepted']} in the inbox, {b['out_of_scope']} out of scope, "
          f"{b['duplicates']} duplicate, {b['unreadable']} unreadable", flush=True)
entries = call("GET", f"/engagements/{pt}/inbox?limit=500", opener=tester, headers={})["entries"]


def entry(fmt, url):
    return next(e for e in entries if e["format"] == fmt and e["url"] == url)


def map_to(e, role, idx, note=None):
    """Map an entry to item idx of the lane of this role on its host; mapping opens the lane if needed."""
    detail = call("GET", f"/engagements/{pt}/inbox/{e['id']}", opener=tester, headers={})
    lane = next(t for t in detail["targets"] if t["role"] == role)
    assert lane["status"] != "closed", f"{role} on {e['host']} is receipted; mapping to it would void the receipt"
    target = {"lane_id": lane["lane_id"], "item_idx": idx} if lane["opened"] else {"role": role, "item_idx": idx}
    call("POST", f"/engagements/{pt}/inbox/map", {"entry_ids": [e["id"]], "targets": [target], "note": note},
         tester, {})


APP, API = "https://app.client.test", "https://api.client.test"
map_to(entry("har", f"{APP}/account/logout"), "sess", 6, "Sign-out answers 200; the session is checked after it.")
map_to(entry("har", f"{APP}/admin/"), "athn", 4, "The admin area answers 401 without a session.")
map_to(entry("burp", f"{APP}/admin/"), "athn", 2, "admin:admin is refused with 401.")
map_to(entry("har", f"{APP}/search.php?q=shoes"), "inpv", 1)
map_to(entry("burp", f"{APP}/search.php?q=%3Cb%3Eshoes%3C%2Fb%3E"), "inpv", 1,
       "q comes back still URL-encoded, so the markup is not rendered.")
map_to(entry("har", f"{API}/api/v1/items?page=1"), "inpv", 5)
call("POST", f"/engagements/{pt}/inbox/dismiss",
     {"entry_ids": [entry("har", f"{APP}/favicon.ico")["id"]],
      "reason": "The browser's request for the site icon; nothing to test."}, tester, {})
counts = call("GET", f"/engagements/{pt}/inbox", opener=tester, headers={})["counts"]
print(f"inbox: {counts}", flush=True)

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
