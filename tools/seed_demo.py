#!/usr/bin/env python3
"""Seed a demo engagement so every ledger state is visible in the UI.

Uses only fictional *.lab.test hosts. Usage: python3 tools/seed_demo.py [API_BASE]
"""
import hashlib
import json
import sys
import urllib.error
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000").rstrip("/")


def call(method, path, body=None):
    req = urllib.request.Request(
        BASE + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"content-type": "application/json"},
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
    call("POST", f"/lanes/{lane['id']}/close")

authz = call("POST", "/lanes", {"asset_id": shop["id"], "role": "authz"})
resolve(authz, leave_open=5)

stale = call("POST", "/lanes", {"asset_id": api["id"], "role": "recon"})
resolve(stale)
call("POST", f"/lanes/{stale['id']}/close")
call("POST", f"/lanes/{stale['id']}/evidence",
     {"kind": "note", "sha256": hashlib.sha256(b"new subdomain").hexdigest(),
      "summary": "new subdomain found after the receipt was issued"})

print(f"seeded engagement {eng['id']}: {BASE}")
