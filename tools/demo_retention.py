#!/usr/bin/env python3
"""Retention in the demo: the Demo Owner sets a retention date on "Client web app" and deletes
the content of "Client portal 2025", as an owner does on the Team tab (D-043).

Runs inside the demo API container after tools/demo_sign.py, because the lanes must be signed
before the content goes (a deleted engagement takes no new receipts):

    docker exec -i -e DEMO_TOKEN=... <demo api container> python - < tools/demo_retention.py

DEMO_TOKEN is the demo API's ATTACKLEDGER_API_TOKEN. The owner's password is reset the way an
operator does it (python -m app.people on the server), used once to sign in and replaced with
a random one that is thrown away. Deleting the content removes the engagement's key, its raw
evidence and its summaries; the hashes, receipts, signatures and timestamps stay, so its
report still verifies with tools/verify_report.py.
"""
import os
import secrets
import subprocess
import sys

import httpx

BASE = os.environ.get("DEMO_API", "http://localhost:8000")
TOKEN = os.environ["DEMO_TOKEN"]
KEEP_UNTIL = "2027-10-31"           # Client web app: a year after the demo's fictional fieldwork
PAST = "Client portal 2025"

operator = httpx.Client(base_url=BASE, headers={"authorization": f"Bearer {TOKEN}"}, timeout=60)


def ok(r: httpx.Response) -> dict:
    if r.status_code >= 400:
        raise SystemExit(f"{r.request.method} {r.request.url.path}: {r.status_code} {r.text}")
    return r.json()


if not any(p["email"] == "owner@demo.test" for p in ok(operator.get("/people"))):
    raise SystemExit("no Demo Owner yet: run tools/demo_sign.py first")
password = secrets.token_urlsafe(18)
subprocess.run([sys.executable, "-m", "app.people", "set-password", "--email", "owner@demo.test"],
               env={**os.environ, "ATTACKLEDGER_NEW_PASSWORD": password}, check=True, stdout=subprocess.DEVNULL)
owner = httpx.Client(base_url=BASE, timeout=60)
ok(owner.post("/auth/login", json={"email": "owner@demo.test", "password": password}))
ok(owner.post("/auth/password", json={"current_password": password, "new_password": secrets.token_urlsafe(18)}))

eng = {e["name"]: e["id"] for e in ok(owner.get("/engagements"))}
r = ok(owner.patch(f"/engagements/{eng['Client web app']}", json={"retain_until": KEEP_UNTIL}))
print(f"Client web app: content kept until {r['retain_until']}")

st = ok(owner.get(f"/engagements/{eng[PAST]}/content"))
if st["content_deleted"]:
    print(f"{PAST}: content already deleted on {st['content_deleted']['at'][:10]}")
else:
    st = ok(owner.post(f"/engagements/{eng[PAST]}/content/delete", json={"confirm_name": PAST}))
    print(f"{PAST}: content deleted by {st['content_deleted']['by']}; removed {st['removed']}")
