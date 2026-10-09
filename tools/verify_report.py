#!/usr/bin/env python3
"""Verify an AttackLedger report offline.

    python3 tools/verify_report.py report.json
    python3 tools/verify_report.py report.html

Standard library only, and independent of the AttackLedger code base on
purpose: it re-derives every hash itself. Checks:

  1. the report body matches its recorded SHA-256,
  2. the evidence chain is unbroken from the genesis value,
  3. every lane reported as receipted has a receipt that matches a manifest
     rebuilt from the report's own items and evidence,
  4. (format 2) every signed receipt: the signature verifies with the public key in the
     report, the key matches its fingerprint, and the signed payload names this lane,
     this manifest and an evidence chain head that is in the report.

Signatures are Ed25519 or ECDSA P-256 with SHA-256, checked with the pure-Python
code below (RFC 8032 and SEC 1), so no third-party package is needed. A signature
proves the key holder signed; to tie the key to a person, compare its fingerprint
with the one the signer gives you.

Exit code 0 means every check passed.
"""
import hashlib
import json
import re
import sys

GENESIS = "0" * 64
FORMATS = ("attackledger-report/1", "attackledger-report/2")
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
            if not (rc.get("closed_by") or "").strip():
                notes.append(f"{label}: receipt has no signer (issued before signatures were required)")
        elif lane["status"] == "stale":
            notes.append(f"{label}: receipt is void (the ledger changed after it was issued)")
    return problems, notes


# ---- signatures, standard library only -------------------------------------------

_ED_P = 2 ** 255 - 19
_ED_Q = 2 ** 252 + 27742317777372353535851937790883648493
_ED_D = -121665 * pow(121666, _ED_P - 2, _ED_P) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)                      # sqrt(-1)


def _ed_add(P, Q):
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % _ED_P
    b = (y1 + x1) * (y2 + x2) % _ED_P
    c = t1 * 2 * _ED_D * t2 % _ED_P
    d = z1 * 2 * z2 % _ED_P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _ED_P, g * h % _ED_P, f * g % _ED_P, e * h % _ED_P)


def _ed_mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _ed_add(Q, P)
        P = _ed_add(P, P)
        s >>= 1
    return Q


def _ed_equal(P, Q):
    return (P[0] * Q[2] - Q[0] * P[2]) % _ED_P == 0 and (P[1] * Q[2] - Q[1] * P[2]) % _ED_P == 0


def _ed_decompress(b: bytes):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _ED_P:
        return None
    x2 = (y * y - 1) * pow(_ED_D * y * y + 1, _ED_P - 2, _ED_P) % _ED_P
    if x2 == 0:
        if sign:
            return None
        x = 0
    else:
        x = pow(x2, (_ED_P + 3) // 8, _ED_P)
        if (x * x - x2) % _ED_P != 0:
            x = x * _ED_I % _ED_P
        if (x * x - x2) % _ED_P != 0:
            return None
        if (x & 1) != sign:
            x = _ED_P - x
    return (x, y, 1, x * y % _ED_P)


_ED_G = _ed_decompress(bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666"))


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(signature) != 64:
        return False
    A, R = _ed_decompress(public), _ed_decompress(signature[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _ED_Q:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _ED_Q
    return _ed_equal(_ed_mul(s, _ED_G), _ed_add(R, _ed_mul(h, A)))


_P256 = {
    "p": 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
    "a": 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
    "b": 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
    "n": 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
    "G": (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
          0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5),
}


def _ec_add(P, Q):
    p = _P256["p"]
    if P is None:
        return Q
    if Q is None:
        return P
    if P[0] == Q[0] and (P[1] + Q[1]) % p == 0:
        return None
    if P == Q:
        lam = (3 * P[0] * P[0] + _P256["a"]) * pow(2 * P[1], p - 2, p) % p
    else:
        lam = (Q[1] - P[1]) * pow(Q[0] - P[0], p - 2, p) % p
    x = (lam * lam - P[0] - Q[0]) % p
    return (x, (lam * (P[0] - x) - P[1]) % p)


def _ec_mul(k, P):
    R = None
    while k:
        if k & 1:
            R = _ec_add(R, P)
        P = _ec_add(P, P)
        k >>= 1
    return R


def p256_verify(point: bytes, message: bytes, signature: bytes) -> bool:
    p, n = _P256["p"], _P256["n"]
    if len(point) != 65 or point[0] != 4 or len(signature) != 64:
        return False
    Q = (int.from_bytes(point[1:33], "big"), int.from_bytes(point[33:], "big"))
    if not (Q[0] < p and Q[1] < p and (Q[1] ** 2 - Q[0] ** 3 - _P256["a"] * Q[0] - _P256["b"]) % p == 0):
        return False
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    if not (1 <= r < n and 1 <= s < n):
        return False
    e = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, n - 2, n)
    X = _ec_add(_ec_mul(e * w % n, _P256["G"]), _ec_mul(r * w % n, Q))
    return X is not None and X[0] % n == r


# SubjectPublicKeyInfo prefixes (DER) for the two key types.
_SPKI = {"Ed25519": bytes.fromhex("302a300506032b6570032100"),
         "ECDSA-P256": bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")}


def verify_signature(algorithm: str, spki: bytes, message: bytes, signature: bytes) -> bool:
    prefix = _SPKI.get(algorithm)
    if prefix is None or not spki.startswith(prefix):
        return False
    raw = spki[len(prefix):]
    return ed25519_verify(raw, message, signature) if algorithm == "Ed25519" else p256_verify(raw, message, signature)


def check_signatures(r: dict) -> tuple[list[str], list[str]]:
    import base64
    problems, notes, signed, receipted = [], [], 0, 0
    chain = {e["seq"]: e["chain_hash"] for e in r["evidence"]}
    for lane in r["lanes"]:
        rc = lane["receipt"]
        if not rc or lane["status"] != "closed":
            continue
        receipted += 1
        sig = rc.get("signature")
        label = f"{lane['host']} / {lane['name']}"
        if not sig:
            continue
        signed += 1
        try:
            spki = base64.b64decode(sig["public_key"], validate=True)
            value = base64.b64decode(sig["value"], validate=True)
            payload = json.loads(sig["payload"])
        except (ValueError, KeyError, TypeError):
            problems.append(f"{label}: signature fields cannot be read")
            continue
        if hashlib.sha256(spki).hexdigest() != sig.get("key_fingerprint"):
            problems.append(f"{label}: the public key does not match its fingerprint")
        if not verify_signature(sig.get("algorithm", ""), spki, sig["payload"].encode(), value):
            problems.append(f"{label}: the signature does not verify")
        if payload.get("format") != "attackledger-receipt-v2":
            problems.append(f"{label}: unknown signed payload format")
        if payload.get("manifest_sha256") != rc["manifest_sha256"]:
            problems.append(f"{label}: the signature covers a different manifest")
        if (payload.get("lane") or {}).get("id") != lane["lane_id"]:
            problems.append(f"{label}: the signature names another lane")
        if payload.get("key_fingerprint") != sig.get("key_fingerprint"):
            problems.append(f"{label}: the signed payload names another key")
        c = payload.get("chain") or {}
        if not (c.get("seq") == 0 and c.get("head") == GENESIS) and chain.get(c.get("seq")) != c.get("head"):
            problems.append(f"{label}: the signed evidence chain head is not in this report")
        if not problems:
            notes.append(f"{label}: signed by {(payload.get('signer') or {}).get('name')} with key "
                         f"{sig.get('key_fingerprint', '')[:16]} ({sig.get('algorithm')})")
    if receipted and signed < receipted:
        notes.append(f"{receipted - signed} of {receipted} receipts are not signed (a name only)")
    return problems, notes


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip())
        return 2
    r = load(argv[1])
    if r.get("format") not in FORMATS:
        print(f"unsupported report format: {r.get('format')}")
        return 2

    results = [("Report body hash", check_body(r)), ("Evidence chain", check_chain(r))]
    receipt_problems, notes = check_receipts(r)
    results.append(("Lane receipts", receipt_problems))
    if r["format"] != "attackledger-report/1":
        sig_problems, sig_notes = check_signatures(r)
        results.append(("Receipt signatures", sig_problems))
        notes += sig_notes

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
