#!/usr/bin/env python3
"""Seed a demo engagement so every ledger state is visible in the UI.

Uses only fictional *.lab.test and *.client.test hosts. Usage: python3 tools/seed_demo.py [API_BASE]
Set ATTACKLEDGER_API_TOKEN when the API requires sign-in.
"""
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

SIGN = {"closed_by": "demo reviewer", "reviewed": True}
BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000").rstrip("/")


TOKEN = os.environ.get("ATTACKLEDGER_API_TOKEN")


def call(method, path, body=None):
    req = urllib.request.Request(
        BASE + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"content-type": "application/json", **({"authorization": f"Bearer {TOKEN}"} if TOKEN else {})},
    )
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        sys.exit(f"{method} {path} -> {e.code}: {e.read().decode()}")


def resolve(lane, leave_open=0, na_every=4):
    items = lane["items"]
    for item in items[: len(items) - leave_open]:
        if item["idx"] % na_every == 0:
            call("PATCH", f"/lanes/{lane['id']}/items/{item['idx']}",
                 {"state": "na", "na_reason": "not present on this host"})
            continue
        note = f"lane {lane['id']} item {item['idx']} checked"
        call("POST", f"/lanes/{lane['id']}/evidence",
             {"item_idx": item["idx"], "kind": "note",
              "sha256": hashlib.sha256(note.encode()).hexdigest(), "summary": note})
        call("PATCH", f"/lanes/{lane['id']}/items/{item['idx']}", {"state": "done"})


eng = call("POST", "/engagements", {"name": "Juice Shop lab"})
shop = call("POST", f"/engagements/{eng['id']}/assets", {"host": "shop.lab.test"})
api = call("POST", f"/engagements/{eng['id']}/assets", {"host": "api.lab.test"})
call("POST", f"/engagements/{eng['id']}/assets", {"host": "cdn.lab.test", "in_scope": False})

for role in ("recon", "mapper"):
    lane = call("POST", "/lanes", {"asset_id": shop["id"], "role": role})
    resolve(lane)
    call("POST", f"/lanes/{lane['id']}/close", SIGN)

authz = call("POST", "/lanes", {"asset_id": shop["id"], "role": "authz"})
resolve(authz, leave_open=5)

stale = call("POST", "/lanes", {"asset_id": api["id"], "role": "recon"})
resolve(stale)
call("POST", f"/lanes/{stale['id']}/close", SIGN)
call("POST", f"/lanes/{stale['id']}/evidence",
     {"kind": "note", "sha256": hashlib.sha256(b"new subdomain").hexdigest(),
      "summary": "new subdomain found after the receipt was issued"})

# A recon-ready lab engagement (the compose "lab" service answers as shop.lab.test).
lab = call("POST", "/engagements", {"name": "Lab recon"})
call("PUT", f"/engagements/{lab['id']}/scope", {
    "include": ["*.lab.test"], "exclude": ["admin.lab.test"], "rate_limit_rps": 2,
    "research_header": "X-Bug-Bounty: lab-researcher",
    "research_user_agent": "AttackLedger/0.1 (lab-researcher)"})
call("POST", f"/engagements/{lab['id']}/attest", {
    "operator": "lab-operator", "policy_url": "https://example.com/policy", "confirm": True})
call("POST", f"/engagements/{lab['id']}/assets", {"host": "shop.lab.test"})

# A WSTG pentest so the Controls view has something to show. Information gathering is
# receipted on both hosts; Authentication is in progress next to it (lanes are worked in
# parallel and signed only once their dependency is receipted, D-047). The import that
# tools/demo_stack.py adds opens Session management and Input validation the same way.
pt = call("POST", "/engagements", {"name": "Client web app", "pack_id": "web-pentest-wstg"})
app_host = call("POST", f"/engagements/{pt['id']}/assets", {"host": "app.client.test"})
api_host = call("POST", f"/engagements/{pt['id']}/assets", {"host": "api.client.test"})
for asset in (app_host, api_host):
    info = call("POST", "/lanes", {"asset_id": asset["id"], "role": "info"})
    resolve(info, na_every=5)
    call("POST", f"/lanes/{info['id']}/close", SIGN)
for key in ("conf", "athz"):
    lane = call("POST", "/lanes", {"asset_id": app_host["id"], "role": key})
    resolve(lane, na_every=5)
    call("POST", f"/lanes/{lane['id']}/close", SIGN)
athn = call("POST", "/lanes", {"asset_id": app_host["id"], "role": "athn"})
resolve(athn, leave_open=3, na_every=5)

# A finished pentest from last year. tools/demo_retention.py deletes its content after the
# lanes are signed, so the demo shows deleted content next to a report that still verifies.
old = call("POST", "/engagements", {"name": "Client portal 2025", "pack_id": "web-pentest-wstg"})
portal = call("POST", f"/engagements/{old['id']}/assets", {"host": "portal.client.test"})
for key in ("info", "conf", "athn"):
    lane = call("POST", "/lanes", {"asset_id": portal["id"], "role": key})
    resolve(lane, na_every=5)
    call("POST", f"/lanes/{lane['id']}/close", SIGN)

print(f"seeded demo engagements: {BASE}")
