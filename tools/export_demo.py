#!/usr/bin/env python3
"""Export a read-only demo snapshot from a running AttackLedger API.

Writes OUT/demo-data.json (every read the web app makes, for the given engagements),
OUT/reports/<id>.html|json and OUT/inbox/<id>/<entry>-<part>.txt (the redacted request,
response and record of each imported entry). Build the app with VITE_DEMO=1 into the same
OUT directory; tools/build_demo.sh does both.

The snapshot also holds each engagement's gateway log (GET /engagements/<id>/gateway-log,
its latest 1,000 rows and the totals), so a reader can check that recon traffic went through
the gateway. The web app has no view of it yet; it is in demo-data.json under "get".

Use it only on an API seeded with fictional data (tools/seed_demo.py plus lab runs):
everything exported is published with the demo.

Usage: python3 tools/export_demo.py API_BASE OUT_DIR ENGAGEMENT_ID [ENGAGEMENT_ID ...]
Set ATTACKLEDGER_API_TOKEN when the demo API requires sign-in.
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

PERSONAL_PATH = re.compile(r"/Users/[A-Za-z0-9_]+|/home/[A-Za-z0-9_]+")   # the release gate's pattern

def main(base: str, out: Path, eng_ids: list[int]) -> None:
    base = base.rstrip("/")

    token = os.environ.get("ATTACKLEDGER_API_TOKEN")
    headers = {"authorization": f"Bearer {token}"} if token else {}

    def raw(path: str) -> bytes:
        with urllib.request.urlopen(urllib.request.Request(base + path, headers=headers)) as r:
            return r.read()

    def get(path: str):
        return json.loads(raw(path))

    snap: dict = {"get": {}, "endpoints": {}, "leads": {}, "inbox": {}}
    put = snap["get"].__setitem__

    put("/health", {"ok": True, "auth_required": False, "demo": True})
    # In the order given: the app opens the first one.
    by_id = {e["id"]: e for e in get("/engagements")}
    put("/engagements", [by_id[i] for i in eng_ids])
    for path in ("/packs", "/modules", "/recon/phases", "/imports/formats"):
        put(path, get(path))
    put("/executors", [{**e, "available": e["key"] == "manual",
                        "unavailable_reason": "" if e["key"] == "manual" else "Not available in the demo."}
                       for e in get("/executors")])
    kinds = [m["kind"] for m in snap["get"]["/modules"]]

    reports = out / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    for eid in eng_ids:
        e = f"/engagements/{eid}"
        for sub in ("/coverage", "/scope", "/jobs", "/triage", "/recon/summary", "/observations",
                    "/controls", "/report", "/audit", "/content", "/imports"):
            put(e + sub, get(e + sub))
        # The log is the tools' own requests, scanner payloads included. A payload path such as
        # /home/<name>/... reads like a personal path to the release gate (tools/release_gate.sh),
        # so such rows are left out of the sample and counted; the totals still include them.
        log = get(e + "/gateway-log?limit=1000")
        kept = [r for r in log["rows"] if not PERSONAL_PATH.search(r["url"] or "")]
        put(e + "/gateway-log", {**log, "rows": kept, "rows_left_out": len(log["rows"]) - len(kept)})

        # The inbox is filtered in the browser (web/src/demo.ts), so every entry goes in, in the
        # API's order; each entry's detail and its redacted parts go in as well.
        inbox = get(e + "/inbox?limit=500")
        if inbox["total"] > len(inbox["entries"]):
            sys.exit(f"engagement {eid}: {inbox['total']} inbox entries; the demo export takes 500")
        snap["inbox"][str(eid)] = inbox["entries"]
        for entry in inbox["entries"]:
            put(f"{e}/inbox/{entry['id']}", get(f"{e}/inbox/{entry['id']}"))
            for part in ("request", "response", "record"):
                try:
                    blob = raw(f"{e}/inbox/{entry['id']}/raw/{part}")
                except urllib.error.HTTPError:
                    continue            # not in the export, or the content was deleted
                (out / "inbox" / str(eid)).mkdir(parents=True, exist_ok=True)
                (out / "inbox" / str(eid) / f"{entry['id']}-{part}.txt").write_bytes(blob)
        for job in snap["get"][e + "/jobs"]:
            j = get(f"/jobs/{job['id']}")
            # Tool warnings name the worker container's home directory; show it as ~.
            j["log"] = re.sub(r"/home/\w+", "~", j.get("log") or "")
            put(f"/jobs/{job['id']}", j)
        for asset in snap["get"][e + "/coverage"]["assets"]:
            for cell in asset["roles"].values():
                if cell.get("lane_id"):
                    lid = cell["lane_id"]
                    put(f"/lanes/{lid}", get(f"/lanes/{lid}"))
                    put(f"/lanes/{lid}/context", get(f"/lanes/{lid}/context"))
                    runs = get(f"/lanes/{lid}/agent-runs")
                    put(f"/lanes/{lid}/agent-runs", runs)
                    for job in runs:
                        put(f"/jobs/{job['id']}", get(f"/jobs/{job['id']}"))
                    # The raw exchanges and notes behind an agent's evidence, so "View raw" works.
                    for ev in snap["get"][f"/lanes/{lid}"]["evidence"]:
                        if ev.get("source") == "agent" or (ev["summary"] or "").startswith("[agent] "):
                            try:
                                blob = raw(f"/blobs/{ev['sha256']}")
                            except urllib.error.HTTPError:
                                continue
                            (out / "blobs").mkdir(exist_ok=True)
                            (out / "blobs" / ev["sha256"]).write_bytes(blob)

        # Endpoints and leads are filtered in the browser, so each row records its module.
        module_of: dict[str, str] = {}
        for k in kinds:
            for row in get(f"{e}/endpoints?module={k}&limit=1000")["items"]:
                module_of.setdefault(row["url"], k)
        rows, offset = [], 0
        while True:
            page = get(f"{e}/endpoints?limit=1000&offset={offset}")
            rows += page["items"]
            offset += 1000
            if offset >= page["total"]:
                break
        snap["endpoints"][str(eid)] = [{**r, "module": module_of.get(r["url"])} for r in rows]

        lead_module = {l["id"]: k for k in kinds for l in get(f"{e}/leads?module={k}")}
        snap["leads"][str(eid)] = [{**l, "module": lead_module.get(l["id"])} for l in get(f"{e}/leads")]

        (reports / f"{eid}.html").write_bytes(raw(f"{e}/report.html"))
        (reports / f"{eid}.json").write_bytes(raw(f"{e}/report"))

    (out / "demo-data.json").write_text(json.dumps(snap, separators=(",", ":")))
    print(f"demo snapshot: {len(snap['get'])} reads, {len(eng_ids)} engagements -> {out}")


if __name__ == "__main__":
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    main(sys.argv[1], Path(sys.argv[2]), [int(x) for x in sys.argv[3:]])
