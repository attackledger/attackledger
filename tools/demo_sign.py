#!/usr/bin/env python3
"""Sign the demo's closed lanes as a demo reviewer, so the demo shows signed receipts.

Runs inside the demo API container (it needs httpx and cryptography, which the image has):

    docker exec -i -e DEMO_TOKEN=... attackledger-demo-api-1 python - < tools/demo_sign.py

DEMO_TOKEN is the demo API's ATTACKLEDGER_API_TOKEN; DEMO_LANES=12,13 signs only those
lanes. The script adds a demo owner and a
"Demo Reviewer" (fictional, random passwords that are thrown away), makes the reviewer a
reviewer on every engagement, signs in as the reviewer, who chooses their own password,
creates an Ed25519 key in memory as a browser would, and signs every lane that is closed
now. The API sets nobody else's password (D-036), so on a rerun the reviewer's password is
reset the way an operator does it, with python -m app.people on the server. Each signature issues a new receipt on top of the
existing one; lanes that are VOID stay VOID. With a timestamp authority set, each new
receipt is also timestamped. "Client web app" then requires signed receipts.

The private key exists only while the script runs. In the product it lives in the
reviewer's browser (D-033); here a script stands in for the browser.
"""
import base64
import os
import secrets
import subprocess
import sys

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

BASE = os.environ.get("DEMO_API", "http://localhost:8000")
TOKEN = os.environ["DEMO_TOKEN"]
ONLY = {int(x) for x in os.environ.get("DEMO_LANES", "").split(",") if x.strip()}   # sign only these lane ids

owner = httpx.Client(base_url=BASE, headers={"authorization": f"Bearer {TOKEN}"}, timeout=60)


def ok(r: httpx.Response) -> dict:
    if r.status_code >= 400:
        raise SystemExit(f"{r.request.method} {r.request.url.path}: {r.status_code} {r.text}")
    return r.json()


password = secrets.token_urlsafe(18)    # the reviewer's first password, for this run only
emails = {p["email"] for p in ok(owner.get("/people"))}
if "owner@demo.test" not in emails:
    ok(owner.post("/people", json={"email": "owner@demo.test", "name": "Demo Owner",
                                   "password": secrets.token_urlsafe(18), "is_owner": True}))
if "reviewer@demo.test" not in emails:
    ok(owner.post("/people", json={"email": "reviewer@demo.test", "name": "Demo Reviewer",
                                   "password": password, "is_owner": False}))
else:
    subprocess.run([sys.executable, "-m", "app.people", "set-password", "--email", "reviewer@demo.test"],
                   env={**os.environ, "ATTACKLEDGER_NEW_PASSWORD": password}, check=True, stdout=subprocess.DEVNULL)
reviewer_id = next(p["id"] for p in ok(owner.get("/people")) if p["email"] == "reviewer@demo.test")

engagements = ok(owner.get("/engagements"))
for e in engagements:
    members = [{"user_id": m["user_id"], "roles": m["roles"]} for m in ok(owner.get(f"/engagements/{e['id']}/members"))
               if m["user_id"] != reviewer_id]
    ok(owner.put(f"/engagements/{e['id']}/members", json={"members": members + [{"user_id": reviewer_id,
                                                                                    "roles": ["reviewer"]}]}))

rev = httpx.Client(base_url=BASE, timeout=60)
ok(rev.post("/auth/login", json={"email": "reviewer@demo.test", "password": password}))
ok(rev.post("/auth/password", json={"current_password": password, "new_password": secrets.token_urlsafe(18)}))
key = ed25519.Ed25519PrivateKey.generate()
spki = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.DER,
                                                      serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
fp = ok(rev.post("/auth/keys", json={"algorithm": "Ed25519", "public_key": spki}))["fingerprint"]
print(f"Demo Reviewer key {fp[:16]} (Ed25519)")

for e in engagements:
    for lane in ok(rev.get(f"/engagements/{e['id']}/report"))["lanes"]:
        if lane["status"] != "closed" or (ONLY and lane["lane_id"] not in ONLY):
            continue
        payload = ok(rev.get(f"/lanes/{lane['lane_id']}/receipt-payload", params={"key": fp}))["payload"]
        sig = base64.b64encode(key.sign(payload.encode())).decode()
        rc = ok(rev.post(f"/lanes/{lane['lane_id']}/close", json={
            "reviewed": True, "payload": payload, "signature": sig, "key_fingerprint": fp}))["receipt"]
        ts = rc.get("timestamp")
        print(f"  {e['name']} / {lane['host']} / {lane['name']}: signed"
              + (f", timestamped {ts['time']}" if ts else f", not timestamped ({rc.get('timestamp_error')})"))

client_app = next(e["id"] for e in engagements if e["name"] == "Client web app")
ok(owner.patch(f"/engagements/{client_app}", json={"require_signatures": True}))
