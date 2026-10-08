#!/usr/bin/env python3
"""Verify an AttackLedger report offline.

    python3 tools/verify_report.py report.json
    python3 tools/verify_report.py report.html

Standard library only, and independent of the AttackLedger code base on
purpose: it re-derives every hash itself. Checks:

  1. the report body matches its recorded SHA-256,
  2. the evidence chain is unbroken from the genesis value,
  3. every lane reported as receipted has a receipt that matches a manifest
     rebuilt from the report's own items and evidence.

Exit code 0 means every check passed.
"""
import hashlib
import json
import re
import sys

GENESIS = "0" * 64
CHAIN_FIELDS = ("seq", "lane_id", "host", "role", "item_id", "kind", "sha256", "uri", "summary")


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if path.endswith((".html", ".htm")):
        m = re.search(r'<script type="application/json" id="attackledger-report">(.*?)</script>', text, re.S)
        if not m:
            raise SystemExit("no embedded report found in the HTML file")
        text = m.group(1)
    return json.loads(text)


def check_body(r: dict) -> list[str]:
    body = {k: v for k, v in r.items() if k != "integrity"}
    want = r.get("integrity", {}).get("body_sha256")
    got = sha(canonical(body))
    return [] if got == want else [f"report body hash mismatch (recorded {want}, computed {got})"]


def check_chain(r: dict) -> list[str]:
    problems, prev = [], r.get("integrity", {}).get("chain_genesis", GENESIS)
    if prev != GENESIS:
        problems.append("unexpected chain genesis value")
    for n, e in enumerate(r["evidence"], start=1):
        if e["seq"] != n:
            problems.append(f"evidence #{e['seq']}: out of sequence (expected #{n})")
        if e["prev_hash"] != prev:
            problems.append(f"evidence #{e['seq']}: does not link to the previous entry")
        rec = {k: e[k] for k in CHAIN_FIELDS}
        if sha(e["prev_hash"] + canonical(rec)) != e["chain_hash"]:
            problems.append(f"evidence #{e['seq']}: content does not match its chain hash")
        prev = e["chain_hash"]
    head = r["summary"]["chain_head"]
    if head != prev:
        problems.append("summary chain head does not match the last evidence entry")
    return problems


def manifest(lane: dict, evidence: list[dict]) -> dict:
    # Mirrors the ledger's receipt manifest: items in order, the lane's evidence by id.
    evs = sorted((e for e in evidence if e["lane_id"] == lane["lane_id"]), key=lambda e: e["id"])
    return {
        "lane": lane["lane_id"],
        "role": lane["role"],
        "host": lane["host"],
        "items": [{"idx": i["idx"], "key": i["key"], "state": i["state"], "na_reason": i["na_reason"]}
                  for i in sorted(lane["items"], key=lambda i: i["idx"])],
        "evidence": [{"id": e["id"], "item": e["item_id"], "kind": e["kind"], "sha256": e["sha256"]} for e in evs],
    }


def check_receipts(r: dict) -> tuple[list[str], list[str]]:
    problems, notes = [], []
    for lane in r["lanes"]:
        label = f"{lane['host']} / {lane['name']}"
        evs = [e for e in r["evidence"] if e["lane_id"] == lane["lane_id"]]
        if sorted(e["id"] for e in evs) != sorted(lane["evidence_ids"]):
            problems.append(f"{label}: evidence list does not match the ledger")
        proven = {e["item_id"] for e in evs if e["item_id"] is not None}
        for i in lane["items"]:
            if i["state"] == "done" and i["item_id"] not in proven:
                problems.append(f"{label}: item {i['key']} is marked done without evidence")
            if i["state"] == "na" and not (i["na_reason"] or "").strip():
                problems.append(f"{label}: item {i['key']} is N/A without a reason")

        rc = lane["receipt"]
        if lane["status"] == "closed":
            if not rc:
                problems.append(f"{label}: reported as receipted but has no receipt")
                continue
            # The ledger hashes the manifest with ASCII-escaped JSON.
            got = sha(json.dumps(manifest(lane, r["evidence"]), sort_keys=True, separators=(",", ":")))
            if got != rc["manifest_sha256"]:
                problems.append(f"{label}: receipt does not match its items and evidence")
            if any(i["state"] == "open" for i in lane["items"]):
                problems.append(f"{label}: reported as receipted with open items")
        elif lane["status"] == "stale":
            notes.append(f"{label}: receipt is void (the ledger changed after it was issued)")
    return problems, notes


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip())
        return 2
    r = load(argv[1])
    if r.get("format") != "attackledger-report/1":
        print(f"unsupported report format: {r.get('format')}")
        return 2

    results = [("Report body hash", check_body(r)), ("Evidence chain", check_chain(r))]
    receipt_problems, notes = check_receipts(r)
    results.append(("Lane receipts", receipt_problems))

    eng, s = r["engagement"], r["summary"]
    print(f"AttackLedger report: {eng['name']} ({eng['pack']['name']} {eng['pack']['version']})")
    print(f"  {s['lanes_receipted']} receipted lanes, {s['evidence_entries']} evidence entries\n")
    ok = True
    for name, problems in results:
        print(f"  {'PASS' if not problems else 'FAIL'}  {name}")
        for p in problems:
            print(f"        - {p}")
        ok = ok and not problems
    for n in notes:
        print(f"  NOTE  {n}")
    print("\nVerified." if ok else "\nVerification FAILED.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
