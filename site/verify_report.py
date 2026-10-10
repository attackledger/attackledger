#!/usr/bin/env python3
"""Verify an AttackLedger report offline.

    python3 tools/verify_report.py report.json
    python3 tools/verify_report.py report.html
    python3 tools/verify_report.py report.json --tsa-root authority-root.pem
    python3 tools/verify_report.py report.json --require-signatures
    python3 tools/verify_report.py report.json --require-history

Standard library only, and independent of the AttackLedger code base on
purpose: it re-derives every hash itself. Checks:

  1. the report body matches its recorded SHA-256,
  2. the evidence chain is unbroken from the genesis value, and every summary matches the
     hash a chain record v2 commits to (a summary deleted with its engagement's key is
     reported as unavailable, and the chain is still checked),
  3. every lane reported as receipted has a receipt that matches a manifest
     rebuilt from the report's own items and evidence (manifest version 2 names each item's
     id and text, so it binds every piece of evidence to its item; a receipt made with
     version 1 does not, and a NOTE says so),
  4. (format 2) every signed receipt: the signature verifies with the public key in the
     report, the key matches its fingerprint, and the signed payload names this lane,
     this manifest and an evidence chain head that is in the report,
  5. (format 2) every timestamped receipt: the RFC 3161 token covers this receipt's
     manifest hash and signature, the timestamp authority's signature verifies, its
     certificate is for timestamping, and its chain reaches a root you trust and was
     valid at the token's time. Trusted roots are the PEM files in tsa-roots/ next to
     this script and any you pass with --tsa-root,
  6. (format 2, reports with a key log) every signing key: its key log entries hash
     correctly and link into the log in order up to the head the report names, it was
     registered to the signer before the receipt's payload was issued, and it was not
     revoked before that,
  7. (format 2, reports with an audit log) the change history: its entries hash correctly
     and link into the audit log in order up to the head, and for every receipt issued
     while the log covered the engagement, the signer held the reviewer role on it (or was
     an owner), had an active account, and had the name and email the receipt names, at
     the time it was issued. A NOTE gives the scope in force and who gave the role.
     A receipt signed as format v4 names the heads of both logs when it was signed, and
     how many audit entries of the engagement and its signer led up to it: the logs must
     reach those heads, and none of those entries may be missing,
  8. (format 2, sealed reports) the report's seal: the server that exported the report signed
     its body hash and the heads of its audit log and key log with its own Ed25519 key. The
     signature verifies, the key is registered in the report's key log as the instance's
     key, the body is the one sealed, and the logs end at the sealed heads. A timestamp on
     the seal is checked like a receipt's and must be from when it was sealed.

Checks 4 and 5 print SKIP, which is neither a pass nor a failure, when no receipt in
the report is signed or timestamped: there is nothing for them to check. With
--require-signatures, every receipt must be signed, and an unsigned one fails check 4.
With --require-history, a report must carry the key log and the audit log, every
receipt must be signed as format v4, so that its history is bound to its signature, and
the report must be sealed, so that the history after the newest signature is bound too; a
report without them, a receipt signed before v4, unsigned or issued before the audit log,
or an unsealed report, fails. What strict mode can and cannot prove is in docs/VERIFIER.md.

An HTML report that verifies is followed by what its embedded JSON says (engagement,
scope, receipted lanes, signers, dates and counts), to compare with the text the page shows.

Signatures are Ed25519 or ECDSA P-256 with SHA-256, checked with the pure-Python
code below (RFC 8032 and SEC 1), so no third-party package is needed; timestamp
authorities may also use RSA (PKCS #1 v1.5) or ECDSA P-384. A signature
proves the key holder signed. The key log says when and how each key was registered
to its signer; for high assurance, also compare each fingerprint with the one the
signer gives you.

Exit code 0 means no check failed; 1 means one did; 2 means the report or the
arguments could not be used.
"""
import hashlib
import json
import re
import sys
from datetime import timedelta

GENESIS = "0" * 64
FORMATS = ("attackledger-report/1", "attackledger-report/2")
CHAIN_FIELDS = ("seq", "lane_id", "host", "role", "item_id", "kind", "sha256", "uri", "summary")
# Chain record v2 commits to the summary's hash, so the summary can be deleted (D-043).
CHAIN_FIELDS_V2 = ("v", "seq", "lane_id", "host", "role", "item_id", "kind", "sha256", "uri", "summary_sha256", "source")
KEY_LOG_FIELDS = ("seq", "user_id", "user_name", "key_fingerprint", "algorithm", "event", "at", "via")
AUDIT_FIELDS = ("seq", "at", "actor", "action", "engagement_id", "subject_id", "change")
# v3 adds the signer's email; v4 the change history heads it was signed against (D-054).
PAYLOAD_FORMATS = ("attackledger-receipt-v2", "attackledger-receipt-v3", "attackledger-receipt-v4")
HISTORY_FORMAT = PAYLOAD_FORMATS[2]
VOID_ACTION = "lane.receipt_voided"     # D-052: a voided receipt stays void
# How long after its signed payload was issued the server may issue a receipt: the payload is
# valid for ten minutes (and may be dated up to a minute ahead), then the timestamp authority answers.
PAYLOAD_WINDOW = (timedelta(seconds=-60), timedelta(minutes=15))
KEY_VIA = {
    "own_session": "from their own session",
    "assigned_password": "from a session signed in with a password someone else set",
    "operator_cli": "by the operator on the server",
    "backfill": "before the key log existed (recorded when it was added)",
    "instance": "as the server's report seal key",
}
# The report seal (D-055): the exporting instance signs the body hash and the logs' heads.
SEAL_FORMAT = "attackledger-seal-v1"
SEAL_TS_STATEMENT = "attackledger-seal-timestamp-v1"
# A seal is made right after the report is built, and timestamped right after it is signed.
SEAL_WINDOW = (timedelta(seconds=-60), timedelta(minutes=10))


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


# The checks read the JSON report embedded in an HTML report, not the text the page shows.
HTML_NOTE = ("this is an HTML report: the checks cover the JSON report embedded in it, not the text the page "
             "displays, so an edit to the page's text alone would not be detected; what was verified is the JSON")


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
        version = e.get("v", 1)
        if version not in (1, 2) or "v" in e and version == 1:
            problems.append(f"evidence #{e['seq']}: unknown chain record version {e.get('v')!r}")
            prev = e["chain_hash"]
            continue
        try:
            rec = {k: e[k] for k in (CHAIN_FIELDS_V2 if version == 2 else CHAIN_FIELDS)}
        except KeyError as missing:
            problems.append(f"evidence #{e['seq']}: the record has no {missing.args[0]}")
            prev = e["chain_hash"]
            continue
        if sha(e["prev_hash"] + canonical(rec)) != e["chain_hash"]:
            problems.append(f"evidence #{e['seq']}: content does not match its chain hash")
        if version == 2 and e.get("summary") is not None and (
                not isinstance(e["summary"], str) or sha(e["summary"]) != e["summary_sha256"]):
            problems.append(f"evidence #{e['seq']}: the summary does not match the hash the chain commits to")
        prev = e["chain_hash"]
    head = r["summary"]["chain_head"]
    if head != prev:
        problems.append("summary chain head does not match the last evidence entry")
    # The count printed at the top of the output: it must be the report's own, not a claim.
    count = r["summary"].get("evidence_entries")
    if count != len(r["evidence"]):
        problems.append(f"the summary counts {count} evidence entries, but the report has {len(r['evidence'])}")
    return problems


def content_notes(r: dict) -> list[str]:
    """Summaries a chain record v2 commits to by hash only, because the engagement's key
    was deleted: the content is gone, the chain and the receipts are still checked."""
    gone = sum(1 for e in r["evidence"] if e.get("v") == 2 and e.get("summary") is None)
    if not gone:
        return []
    d = r.get("engagement", {}).get("content_deleted") or {}
    why = (f"key deleted on {(d.get('at') or '')[:10] or 'an unknown date'} by {d.get('by') or 'someone'}"
           if d else "the report does not say it was deleted")
    return [f"{gone} evidence entr{'y' if gone == 1 else 'ies'}: content unavailable ({why}); "
            "the chain and the receipts were still checked"]


def manifest(lane: dict, evidence: list[dict], version: int = 2) -> dict:
    # Mirrors the ledger's receipt manifest: items in order, the lane's evidence by id. Version 2
    # (D-054) also names each item's id and text, so the item id each piece of evidence names is
    # bound to the item it supports; version 1 did not.
    evs = sorted((e for e in evidence if e["lane_id"] == lane["lane_id"]), key=lambda e: e["id"])
    m = {
        "lane": lane["lane_id"],
        "role": lane["role"],
        "host": lane["host"],
        "items": [{"idx": i["idx"], "key": i["key"], "state": i["state"], "na_reason": i["na_reason"],
                   **({"id": i["item_id"], "text": i["text"]} if version == 2 else {})}
                  for i in sorted(lane["items"], key=lambda i: i["idx"])],
        "evidence": [{"id": e["id"], "item": e["item_id"], "kind": e["kind"], "sha256": e["sha256"]} for e in evs],
    }
    if version == 2:
        m["v"] = 2
    return m


def manifest_sha256(lane: dict, evidence: list[dict], version: int) -> str:
    # The ledger hashes the manifest with ASCII-escaped JSON.
    return sha(json.dumps(manifest(lane, evidence, version), sort_keys=True, separators=(",", ":")))


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
            # A receipt is over manifest version 2, or version 1 if it was issued before it. The
            # version is inside what is hashed, so one cannot pass for the other.
            if manifest_sha256(lane, r["evidence"], 2) == rc["manifest_sha256"]:
                pass
            elif manifest_sha256(lane, r["evidence"], 1) == rc["manifest_sha256"]:
                notes.append(f"{label}: the receipt's manifest is version 1, which does not name each item's id and "
                             "text, so which item each piece of evidence supports is not covered by it")
            else:
                problems.append(f"{label}: receipt does not match its items and evidence")
            if any(i["state"] == "open" for i in lane["items"]):
                problems.append(f"{label}: reported as receipted with open items")
            if not (rc.get("closed_by") or "").strip():
                notes.append(f"{label}: receipt has no signer (issued before signatures were required)")
        elif lane["status"] == "stale":
            notes.append(f"{label}: receipt is void (the ledger changed after it was issued)")
    # The count printed at the top of the output, as the server counts it: receipted lanes on
    # in-scope hosts. It must be the report's own, not a claim.
    in_scope = {h["host"] for h in r.get("hosts") or [] if h["in_scope"]}
    receipted = sum(1 for lane in r["lanes"] if lane["status"] == "closed" and lane["host"] in in_scope)
    claimed = r["summary"].get("lanes_receipted")
    if claimed != receipted:
        problems.append(f"the summary says {claimed} lanes are receipted, but {receipted} in-scope lanes are")
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


_P384 = {
    "p": 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
    "a": 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc,
    "b": 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
    "n": 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
    "G": (0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
          0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f),
}


def _ec_add(P, Q, C=_P256):
    p = C["p"]
    if P is None:
        return Q
    if Q is None:
        return P
    if P[0] == Q[0] and (P[1] + Q[1]) % p == 0:
        return None
    if P == Q:
        lam = (3 * P[0] * P[0] + C["a"]) * pow(2 * P[1], p - 2, p) % p
    else:
        lam = (Q[1] - P[1]) * pow(Q[0] - P[0], p - 2, p) % p
    x = (lam * lam - P[0] - Q[0]) % p
    return (x, (lam * (P[0] - x) - P[1]) % p)


def _ec_mul(k, P, C=_P256):
    R = None
    while k:
        if k & 1:
            R = _ec_add(R, P, C)
        P = _ec_add(P, P, C)
        k >>= 1
    return R


def ecdsa_verify(C: dict, point: bytes, digest: bytes, r: int, s: int) -> bool:
    """ECDSA over curve C (SEC 1, 4.1.4), given the message digest and (r, s)."""
    p, n = C["p"], C["n"]
    size = (p.bit_length() + 7) // 8
    if len(point) != 1 + 2 * size or point[0] != 4:
        return False
    Q = (int.from_bytes(point[1:1 + size], "big"), int.from_bytes(point[1 + size:], "big"))
    if not (Q[0] < p and Q[1] < p and (Q[1] ** 2 - Q[0] ** 3 - C["a"] * Q[0] - C["b"]) % p == 0):
        return False
    if not (1 <= r < n and 1 <= s < n):
        return False
    e = int.from_bytes(digest, "big")
    if len(digest) * 8 > n.bit_length():
        e >>= len(digest) * 8 - n.bit_length()
    w = pow(s, n - 2, n)
    X = _ec_add(_ec_mul(e * w % n, C["G"], C), _ec_mul(r * w % n, Q, C), C)
    return X is not None and X[0] % n == r


def p256_verify(point: bytes, message: bytes, signature: bytes) -> bool:
    if len(signature) != 64:
        return False
    return ecdsa_verify(_P256, point, hashlib.sha256(message).digest(),
                        int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))


# SubjectPublicKeyInfo prefixes (DER) for the two key types.
_SPKI = {"Ed25519": bytes.fromhex("302a300506032b6570032100"),
         "ECDSA-P256": bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")}


def verify_signature(algorithm: str, spki: bytes, message: bytes, signature: bytes) -> bool:
    prefix = _SPKI.get(algorithm)
    if prefix is None or not spki.startswith(prefix):
        return False
    raw = spki[len(prefix):]
    return ed25519_verify(raw, message, signature) if algorithm == "Ed25519" else p256_verify(raw, message, signature)


def _receipts(n: int) -> str:
    return f"{n} receipt" + ("" if n == 1 else "s")


def count_receipts(r: dict, field: str) -> tuple[int, int]:
    """(receipts carrying field, receipts) over the lanes reported as receipted."""
    rcs = [l["receipt"] for l in r["lanes"] if l["receipt"] and l["status"] == "closed"]
    return sum(1 for rc in rcs if rc.get(field)), len(rcs)


def _history(payload: dict) -> tuple[dict, dict] | None:
    """The audit log and key log heads a v4 payload names, or None if it names none."""
    h = payload.get("history")
    if not isinstance(h, dict) or not isinstance(h.get("audit"), dict) or not isinstance(h.get("key_log"), dict):
        return None
    return h["audit"], h["key_log"]


def _payload(rc: dict) -> dict | None:
    """A signed receipt's payload, if it is format v4 and can be read; None otherwise."""
    try:
        p = json.loads((rc.get("signature") or {})["payload"])
    except (ValueError, KeyError, TypeError):
        return None
    return p if isinstance(p, dict) and p.get("format") == HISTORY_FORMAT and _history(p) else None


def _upto(log: dict, seq, head):
    """The sequence numbers of a log's links up to and including the one at seq, if that link
    has entry hash head; None if the log's links do not include seq, False if the link there
    has another hash."""
    links = log.get("links") or []
    if seq == 0 and head == GENESIS:
        return []
    for n, ln in enumerate(links):
        if ln["seq"] == seq:
            return [x["seq"] for x in links[:n + 1]] if ln["entry_hash"] == head else False
    return None


def _signer(s) -> str:
    """A payload's signer as "Name (email)"; v2 payloads have no email."""
    s = s if isinstance(s, dict) else {}
    return f"{s.get('name')} ({s['email']})" if s.get("email") else str(s.get("name"))


def check_signatures(r: dict, require: bool = False) -> tuple[list[str], list[str]]:
    """With require, an unsigned receipt is a problem."""
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
            if require:
                problems.append(f"{label}: the receipt is not signed")
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
        if payload.get("format") not in PAYLOAD_FORMATS:
            problems.append(f"{label}: unknown signed payload format")
        elif payload["format"] != PAYLOAD_FORMATS[0] and not isinstance((payload.get("signer") or {}).get("email"), str):
            problems.append(f"{label}: the signed payload does not name the signer's email")
        elif payload["format"] == HISTORY_FORMAT and not _history(payload):
            problems.append(f"{label}: the signed payload does not name the change history heads")
        if payload.get("manifest_sha256") != rc["manifest_sha256"]:
            problems.append(f"{label}: the signature covers a different manifest")
        if (payload.get("lane") or {}).get("id") != lane["lane_id"]:
            problems.append(f"{label}: the signature names another lane")
        if payload.get("key_fingerprint") != sig.get("key_fingerprint"):
            problems.append(f"{label}: the signed payload names another key")
        c = payload.get("chain") or {}
        if not (c.get("seq") == 0 and c.get("head") == GENESIS) and chain.get(c.get("seq")) != c.get("head"):
            problems.append(f"{label}: the signed evidence chain head is not in this report")
        # The engagement and the issue time are in the signed text; the report's own copies are not
        # signed, so they must agree with it. The server issues a receipt at most PAYLOAD_WINDOW
        # after the payload (ten minutes to sign, then the timestamp authority's answer).
        eng, signed_eng = r.get("engagement") or {}, payload.get("engagement") or {}
        if signed_eng.get("id") != eng.get("id"):
            problems.append(f"{label}: the signature names another engagement")
        try:
            gap = _utc(rc["issued_at"]) - _utc(payload["issued_at"])
        except (ValueError, KeyError, TypeError):
            gap = None
        if gap is None or not PAYLOAD_WINDOW[0] <= gap <= PAYLOAD_WINDOW[1]:
            problems.append(f"{label}: the receipt's issue time is not the time its signed payload was issued")
        if not problems:
            notes.append(f"{label}: signed by {_signer(payload.get('signer'))} with key "
                         f"{sig.get('key_fingerprint', '')[:16]} ({sig.get('algorithm')})")
            if signed_eng.get("name") != eng.get("name"):
                notes.append(f"{label}: signed when the engagement was named \"{signed_eng.get('name')}\"")
    if receipted and signed < receipted:
        notes.append(f"{receipted - signed} of {_receipts(receipted)} {'is' if receipted - signed == 1 else 'are'} "
                     "not signed (a name only)")
    return problems, notes


# ---- the key log ------------------------------------------------------------------
#
# Every key registration and revocation on the server is an entry in one hash chain:
# entry_hash = sha256(prev_hash + sha256(canonical(record))). The report carries the full
# records of the keys that signed it, and the links (hashes only) from the first of them
# to the head, so the records can be placed in the chain without seeing anyone else's.

def _utc(text: str, whole_seconds: bool = False):
    from datetime import datetime, timezone
    t = datetime.fromisoformat(text)
    t = t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    return t.replace(microsecond=0) if whole_seconds else t


def check_log(log: dict, what: str, fields: tuple) -> tuple[list[str], list[tuple] | None]:
    """The links and records of a hash-chained log in a report (the key log, the audit log).
    Returns the problems and the records in chain order as (time, record), or None for the
    records when the links cannot be read."""
    problems = []
    if log.get("genesis") != GENESIS:
        problems.append(f"unexpected {what} genesis value")
    links, prev = log.get("links") or [], None
    for n, ln in enumerate(links):
        try:
            seq, ph, rsha, eh = ln["seq"], ln["prev_hash"], ln["record_sha256"], ln["entry_hash"]
        except (KeyError, TypeError):
            problems.append(f"a {what} link cannot be read")
            return problems, None
        if n == 0 and seq == 1 and ph != GENESIS:
            problems.append(f"{what} entry #1 does not start from the genesis value")
        if n > 0 and seq != links[n - 1]["seq"] + 1:
            problems.append(f"{what} entry #{seq}: out of sequence (expected #{links[n - 1]['seq'] + 1})")
        if n > 0 and ph != prev:
            problems.append(f"{what} entry #{seq}: does not link to the previous entry")
        if sha(ph + rsha) != eh:
            problems.append(f"{what} entry #{seq}: does not match its chain hash")
        prev = eh
    head = log.get("head") or {}
    if links and (head.get("seq") != links[-1]["seq"] or head.get("entry_hash") != links[-1]["entry_hash"]):
        problems.append(f"the {what} head does not match its last link")
    by_seq = {ln["seq"]: ln for ln in links}
    records, latest = [], None
    for e in sorted(log.get("entries") or [], key=lambda e: e.get("seq") or 0):
        ln = by_seq.get(e.get("seq"))
        if ln is None:
            problems.append(f"{what} entry #{e.get('seq')} is not in the chain the report carries")
        elif sha(canonical({k: e.get(k) for k in fields})) != ln["record_sha256"]:
            problems.append(f"{what} entry #{e.get('seq')}: content does not match its record hash")
        try:
            at = _utc(e["at"])
        except (ValueError, KeyError, TypeError):
            problems.append(f"{what} entry #{e.get('seq')}: its time cannot be read")
            continue
        if latest is not None and at < latest:          # appended later, but dated earlier
            problems.append(f"{what} entry #{e.get('seq')} is dated before an earlier entry")
        latest = max(at, latest or at)
        records.append((at, e))
    return problems, records


def check_key_log(r: dict, strict: bool = False) -> tuple[list[str], list[str]]:
    """With strict (--require-history), a report with signed receipts must carry the key log."""
    notes = []
    signed = [l for l in r["lanes"] if l["receipt"] and l["status"] == "closed" and l["receipt"].get("signature")]
    log = r.get("key_log")
    if log is None:
        if signed and strict:
            return ["this report has no key history, which --require-history requires"], notes
        if signed:
            notes.append("this report has no key history (made before the key log); compare each signer's key "
                         "fingerprint with the one they give you")
        return [], notes
    problems, records = check_log(log, "key log", KEY_LOG_FIELDS)
    if records is None:
        return problems, notes
    history: dict[str, list[dict]] = {}
    for _, e in records:
        history.setdefault(e.get("key_fingerprint"), []).append(e)

    described = set()
    for lane in signed:
        label = f"{lane['host']} / {lane['name']}"
        sig = lane["receipt"]["signature"]
        fp = sig.get("key_fingerprint") or ""
        try:
            payload = json.loads(sig["payload"])
            issued, signer = _utc(payload["issued_at"]), payload["signer"]
        except (ValueError, KeyError, TypeError):
            problems.append(f"{label}: the signed payload cannot be read")
            continue
        events = history.get(fp, [])
        reg = next((e for e in events if e.get("event") == "registered"), None)
        if reg is None:
            problems.append(f"{label}: the key log has no registration for key {fp[:16]}")
            continue
        mine = []
        try:
            if reg.get("user_id") != signer.get("id"):
                mine.append(f"{label}: key {fp[:16]} is registered to {reg.get('user_name')}, not the signer")
            # A payload's issue time is in whole seconds; compare key log times the same way.
            if _utc(reg["at"], True) > issued:
                mine.append(f"{label}: key {fp[:16]} was registered after the receipt was issued")
            revoked = [e for e in events if e.get("event") == "revoked"]
            for e in revoked:
                if e["seq"] < reg["seq"]:
                    mine.append(f"{label}: key {fp[:16]} was revoked before it was registered")
                if _utc(e["at"], True) < issued:
                    mine.append(f"{label}: key {fp[:16]} was revoked before the receipt was issued")
        except (ValueError, KeyError, TypeError, AttributeError):
            mine.append(f"{label}: the key log entries for key {fp[:16]} cannot be read")
            revoked = []
        v4 = _payload(lane["receipt"])
        if v4 is not None:          # the key log head when it was signed (D-054)
            k = _history(v4)[1]
            upto = _upto(log, k.get("seq"), k.get("head"))
            if upto is None:
                mine.append(f"{label}: the key log in this report does not reach the head the signature names "
                            f"(#{k.get('seq')})")
            elif upto is False:
                mine.append(f"{label}: the key log entry #{k.get('seq')} the signature names is not the one in this report")
            elif reg.get("seq") not in upto:
                mine.append(f"{label}: key {fp[:16]} is not registered in the key log up to the head the signature names")
        problems += mine
        if not mine and fp not in described:
            described.add(fp)
            when = _utc(reg["at"]).strftime("%Y-%m-%d %H:%M UTC")
            later = (f"; revoked {_utc(revoked[0]['at']).strftime('%Y-%m-%d %H:%M UTC')}, after it signed"
                     if revoked else "")
            notes.append(f"{_signer(signer)} signed with key {fp[:16]}, registered {when} "
                         f"{KEY_VIA.get(reg.get('via'), 'in a way this verifier does not know')}{later}")
    return problems, notes


# ---- the audit log ------------------------------------------------------------------
#
# Administrative changes (scope, settings, roles, authorization, people) are entries in
# another hash chain, built like the key log. The report carries its engagement's entries
# and the person events of its signers and members in full, and the links from the first of
# them to the head. From them the verifier rebuilds who held which role, under which name,
# and which scope was in force, at the time each receipt was issued.

_ACTORS = {"token": "the operator token", "cli": "the operator on the server", "open": "open mode",
           "backfill": "the audit log backfill", "retention": "the retention policy"}


def _actor(a) -> str:
    a = a if isinstance(a, dict) else {}
    if a.get("kind") == "person":
        return f"{a.get('name')} ({a.get('email')})" if a.get("email") else str(a.get("name"))
    return _ACTORS.get(a.get("kind"), str(a.get("kind")))


def _scope_text(s: dict) -> str:
    def words(v):
        return ", ".join(v) if v else "none"
    out = [f"in scope {words(s.get('include'))}", f"out of scope {words(s.get('exclude'))}",
           f"{s.get('rate_limit_rps')} requests per second"]
    if s.get("research_header"):
        out.append(f"header {s['research_header']}")
    if s.get("research_user_agent"):
        out.append(f"user agent {s['research_user_agent']}")
    if s.get("enabled_modules"):
        out.append(f"opt-in modules {words(s['enabled_modules'])}")
    return "; ".join(out)


def _state_at(records: list[tuple], eng_id, when) -> dict:
    """Scope, roles and people as the log has them at a time: entries at or before it."""
    st = {"scope": None, "roles": {}, "since": {}, "people": {}}
    for at, e in records:
        if at > when:
            break
        action, ch = e.get("action"), e.get("change") or {}
        after = ch.get("after")
        if e.get("engagement_id") == eng_id and action == "scope.updated":
            st["scope"] = (at, e)
        elif e.get("engagement_id") == eng_id and action == "members.updated":
            roles = {m["user_id"]: m.get("roles") or [] for m in after or []}
            for uid, rs in roles.items():                  # since when each person has held "reviewer"
                if "reviewer" in rs and "reviewer" not in st["roles"].get(uid, []):
                    st["since"][uid] = (at, e)
            st["roles"] = roles
        elif action in ("person.created", "person.renamed", "person.owner", "person.disabled", "person.enabled"):
            st["people"].setdefault(e.get("subject_id"), {}).update(after or {})
    return st


def _voids(e: dict, lane: dict, rc: dict, issued) -> bool:
    """Whether an audit entry voiding a receipt names this one. The entry has the server's
    receipt id, which a report does not; it is matched by lane, manifest hash and issue time."""
    ch = e.get("change") or {}
    lane_ref, receipt = ch.get("lane") or {}, ch.get("receipt") or {}
    if lane_ref.get("id") != lane["lane_id"] or receipt.get("manifest_sha256") != rc["manifest_sha256"]:
        return False
    try:
        return _utc(receipt["issued_at"]) == issued
    except (ValueError, KeyError, TypeError):
        return False


def check_audit_log(r: dict, strict: bool = False, sealed=None) -> tuple[list[str], list[str]]:
    """With strict (--require-history), the report must carry the audit log and every receipt
    must commit to it (format v4); see docs/VERIFIER.md for what that proves. sealed is the
    audit log entry up to which a valid seal binds the history (check_seal), or None."""
    notes = []
    receipted = [l for l in r["lanes"] if l["receipt"] and l["status"] == "closed"]
    log = r.get("audit_log")
    if log is None:
        if receipted and strict:
            return ["this report has no change history, which --require-history requires"], notes
        if receipted:
            notes.append("this report has no change history (made before the audit log); who held the reviewer "
                         "role and which scope was in force when each receipt was issued are not shown")
        return [], notes
    problems, records = check_log(log, "audit log", AUDIT_FIELDS)
    if records is None:
        return problems, notes
    eng_id = r["engagement"]["id"]
    start = next((at for at, e in records if e.get("engagement_id") == eng_id), None)
    voids = [(at, e) for at, e in records if e.get("engagement_id") == eng_id and e.get("action") == VOID_ACTION]
    covered = None          # the newest audit log head a v4 signature names: (seq, the receipt's issue time)
    for lane in receipted:
        label, rc = f"{lane['host']} / {lane['name']}", lane["receipt"]
        sig, payload = rc.get("signature"), None
        try:
            if sig:
                payload = json.loads(sig["payload"])
                uid, name, email = payload["signer"]["id"], payload["signer"]["name"], payload["signer"].get("email")
            else:
                uid, name, email = rc.get("closed_by_user"), rc.get("closed_by"), rc.get("closed_by_email")
            issued = _utc(rc["issued_at"])
        except (ValueError, KeyError, TypeError):
            problems.append(f"{label}: the receipt's signer or issue time cannot be read")
            continue
        void = next((v for v in voids if _voids(v[1], lane, rc, issued)), None)
        if void is not None:     # a void is for good (D-052): the lane's status in the report is not signed
            problems.append(f"{label}: reported as receipted, but the change history records that this receipt was "
                            f"voided {void[0].strftime('%Y-%m-%d %H:%M UTC')}")
        v4 = _payload(rc)
        if v4 is not None:          # the history it was signed against must all be here (D-054)
            a = _history(v4)[0]
            upto = _upto(log, a.get("seq"), a.get("head"))
            if upto is None:
                problems.append(f"{label}: the change history in this report does not reach the audit log head the "
                                f"signature names (#{a.get('seq')})")
            elif upto is False:
                problems.append(f"{label}: the audit log entry #{a.get('seq')} the signature names is not the one in "
                                "this report")
            else:
                seqs = [e.get("seq") for _, e in records if e.get("seq") in upto and (
                    e.get("engagement_id") == eng_id
                    or (str(e.get("action") or "").startswith("person.") and e.get("subject_id") == uid))]
                if len(seqs) != a.get("entries") or sha(canonical(seqs)) != a.get("sha256"):
                    problems.append(f"{label}: the change history leaves out entries the signature covers: it names "
                                    f"{a.get('entries')} entries of this engagement and its signer up to audit log "
                                    f"entry #{a.get('seq')}, and the report has {len(seqs)} such entries")
                elif covered is None or a["seq"] > covered[0]:
                    covered = (a["seq"], issued)
        elif strict:
            problems.append(f"{label}: {'its signed payload is not format v4' if sig else 'the receipt is not signed'}, "
                            "so nothing binds its change history, and an entry left out of this report would not be "
                            "detected")
        if start is None or issued < start:
            (problems if strict else notes).append(
                f"{label}: issued before the audit log covered this engagement, so the roles and scope "
                "at that time are not recorded")
            continue
        st = _state_at(records, eng_id, issued)
        scope = (f"scope set {st['scope'][0].strftime('%Y-%m-%d %H:%M UTC')} by {_actor(st['scope'][1].get('actor'))}: "
                 f"{_scope_text((st['scope'][1].get('change') or {}).get('after') or {})}") if st["scope"] \
            else "no scope recorded"
        if uid is None:
            notes.append(f"{label}: closed by \"{name}\" with the operator token or in open mode, so no account or "
                         f"role applies; {scope}")
            continue
        person = st["people"].get(uid)
        mine = []
        if person is None:
            mine.append(f"{label}: the audit log has no record of the signer {name} (id {uid})")
        else:
            if person.get("name") != name:
                mine.append(f"{label}: the receipt names the signer {name}, but the audit log names them "
                            f"{person.get('name')} at that time")
            if email is not None and person.get("email") != email:
                mine.append(f"{label}: the receipt names the signer's email {email}, but the audit log has "
                            f"{person.get('email')}")
            if person.get("disabled"):
                mine.append(f"{label}: the signer's account was disabled when the receipt was issued")
        held = "reviewer" in st["roles"].get(uid, [])
        if not held and not (person or {}).get("is_owner"):
            mine.append(f"{label}: {name} did not hold the reviewer role on this engagement when the receipt was "
                        "issued, and was not an owner")
        problems += mine
        if not mine:
            since = st["since"].get(uid)
            role = (f"held the reviewer role, given {since[0].strftime('%Y-%m-%d %H:%M UTC')} by {_actor(since[1].get('actor'))}"
                    if held and since else "was an owner, who may sign any receipt")
            who = f"{name} ({person.get('email')})" if person.get("email") else name
            notes.append(f"{label}: issued {issued.strftime('%Y-%m-%d %H:%M UTC')}; {who} {role}; {scope}")
    if strict and covered is not None and sealed is not None:
        notes.append(f"the change history is complete, as far as receipt signatures show, up to audit log entry "
                     f"#{covered[0]} (the receipt issued {covered[1].strftime('%Y-%m-%d %H:%M UTC')}), and as far as "
                     f"the report's seal shows, up to entry #{sealed}, when the report was made")
    elif strict and covered is not None:
        notes.append(f"the change history is complete, as far as signatures show, up to audit log entry #{covered[0]} "
                     f"(the receipt issued {covered[1].strftime('%Y-%m-%d %H:%M UTC')}); entries after it are as the "
                     "report gives them, so one left out, such as a later void of a receipt, would not be detected")
    return problems, notes


# ---- the report seal ------------------------------------------------------------------
#
# When the server exports a report it signs, with its own Ed25519 key, a text naming the body
# hash and the heads of the audit log and the key log the report carries (D-055). Its public
# key is registered in the key log like a reviewer's. What the seal proves and what it does
# not is in docs/VERIFIER.md: it is the server's statement, not a reviewer's.

def _sealed_head(want, log, what: str) -> list[str]:
    """A log as the seal names it: the report's log must end at that head and reach it."""
    if want is None and log is None:
        return []
    if log is None:
        return [f"the seal names the {what} up to entry #{(want or {}).get('seq')}, which this report leaves out"]
    if not isinstance(want, dict):
        return [f"this report carries a {what} the seal does not name"]
    head = log.get("head") or {}
    if want.get("seq") != head.get("seq") or want.get("head") != head.get("entry_hash"):
        return [f"the {what} in this report ends at entry #{head.get('seq')}, not at entry #{want.get('seq')}, "
                "where the seal says it ended when the report was made"]
    if _upto(log, want.get("seq"), want.get("head")) in (None, False):
        return [f"the {what} in this report does not reach entry #{want.get('seq')}, which the seal names"]
    return []


def check_seal(r: dict, roots: list[dict], strict: bool = False) -> tuple[list[str], list[str], object]:
    """The report's seal. Returns the problems, the notes, and the audit log entry up to which the
    seal binds the history when it holds (None otherwise). With strict, a report must be sealed."""
    import base64
    seal = r.get("integrity", {}).get("seal")
    if seal is None:
        if strict:
            return ["this report is not sealed, which --require-history requires"], [], None
        return [], ["this report is not sealed (made before report seals), so nothing the server signed when it "
                    "exported the report says its change history was complete then"], None
    try:
        spki = base64.b64decode(seal["public_key"], validate=True)
        value = base64.b64decode(seal["value"], validate=True)
        p = json.loads(seal["payload"])
        if not isinstance(p, dict):
            raise TypeError("the payload is not an object")
    except (ValueError, KeyError, TypeError):
        return ["the seal's fields cannot be read"], [], None
    problems, fp = [], seal.get("key_fingerprint")
    if hashlib.sha256(spki).hexdigest() != fp:
        problems.append("the seal's public key does not match its fingerprint")
    if seal.get("algorithm") != "Ed25519" or not verify_signature("Ed25519", spki, seal["payload"].encode(), value):
        problems.append("the seal's signature does not verify")
    if p.get("format") != SEAL_FORMAT:
        problems.append("unknown seal format")
    if p.get("key_fingerprint") != fp:
        problems.append("the sealed text names another key")
    if p.get("report_sha256") != sha(canonical({k: v for k, v in r.items() if k != "integrity"})):
        problems.append("the report is not the one that was sealed: its body was changed after the seal was made")
    if (p.get("engagement") or {}).get("id") != (r.get("engagement") or {}).get("id"):
        problems.append("the seal names another engagement")
    try:
        sealed_at = _utc(p["sealed_at"])
        gap = sealed_at - _utc(r["generated_at"])
    except (ValueError, KeyError, TypeError):
        sealed_at = gap = None
    if gap is None or not SEAL_WINDOW[0] <= gap <= SEAL_WINDOW[1]:
        problems.append("the seal was not made when the report was generated")
    h = p.get("history") if isinstance(p.get("history"), dict) else {}
    problems += _sealed_head(h.get("audit"), r.get("audit_log"), "change history")
    problems += _sealed_head(h.get("key_log"), r.get("key_log"), "key log")
    # The seal key must be registered in the key log, as the instance's, up to the sealed head.
    entries = [e for e in (r.get("key_log") or {}).get("entries") or [] if e.get("key_fingerprint") == fp]
    reg = next((e for e in entries if e.get("event") == "registered"), None)
    k = h.get("key_log") if isinstance(h.get("key_log"), dict) else {}
    try:
        if reg is None or reg.get("via") != "instance" or reg.get("user_id") is not None:
            problems.append(f"the key log in this report does not register the seal's key {str(fp)[:16]} as the "
                            "server's seal key")
        elif reg["seq"] > k.get("seq") or (sealed_at is not None and _utc(reg["at"]) > sealed_at):
            problems.append(f"the seal's key {str(fp)[:16]} was registered after the report was sealed")
        elif sealed_at is not None and any(e.get("event") == "revoked" and _utc(e["at"]) < sealed_at for e in entries):
            problems.append(f"the seal's key {str(fp)[:16]} was revoked before the report was sealed")
    except (ValueError, KeyError, TypeError):
        problems.append(f"the key log entries for the seal's key {str(fp)[:16]} cannot be read")
    ts, when = seal.get("timestamp"), None
    if ts:
        try:
            t = read_token(base64.b64decode(ts["token"], validate=True))
        except (ValueError, IndexError, KeyError, TypeError):
            problems.append("the seal's timestamp token cannot be read")
        else:
            statement = f"{SEAL_TS_STATEMENT}\n{p.get('report_sha256')}\n{seal.get('value')}\n"
            if t["imprint_alg"] not in _HASH or _HASH[t["imprint_alg"]](statement.encode()).digest() != t["imprint"]:
                problems.append("the seal's timestamp covers something else")
            found, tsa = token_problems(t, roots)
            problems += [f"the seal's timestamp: {x}" for x in found]
            try:
                shown = _utc(ts.get("time") or "")
            except ValueError:
                shown = None
            if shown != t["time"]:
                problems.append("the time shown for the seal's timestamp is not the token's time")
            if sealed_at is None or not SEAL_WINDOW[0] <= t["time"] - sealed_at <= SEAL_WINDOW[1]:
                problems.append("the seal's timestamp is not from when the report was sealed")
            when = (t["time"], tsa)
    if problems:
        return problems, [], None
    a = h.get("audit")
    upto = " and ".join(f"{what} entry #{x['seq']}" for what, x in (("audit log", a), ("key log", k)) if x)
    # A receipt signed over a key log head that includes the seal key's registration ties the key to
    # the server the reviewer signed on; a key registered after every signature has only its fingerprint.
    heads = [_history(v4)[1].get("seq") for v4 in (_payload(l["receipt"]) for l in r["lanes"]
                                                   if l["receipt"] and l["status"] == "closed") if v4 is not None]
    bound = any(type(x) is int and x >= reg["seq"] for x in heads)
    notes = [f"sealed {sealed_at.strftime('%Y-%m-%d %H:%M UTC')} with the server's seal key {fp[:16]} (Ed25519): the "
             f"server that made this report says it was complete, up to {upto or 'no log entry'}, when it was exported",
             f"the seal key was registered in the key log {_utc(reg['at']).strftime('%Y-%m-%d %H:%M UTC')} (entry "
             f"#{reg['seq']}), " + ("and a receipt signature covers that entry, so it was the key of the server the "
                                    "reviewer signed on; whoever holds it could still seal another report" if bound else
                                    "and no receipt signature covers that entry, so only its fingerprint, compared with "
                                    "the one the tester gives you, ties it to the server")]
    notes.append(f"the seal was timestamped {when[0].isoformat()} by {when[1]}" if when
                 else "the seal is not timestamped, so its time is the server's clock")
    return [], notes, (a["seq"] if a else 0)


# ---- what a verified HTML report says -----------------------------------------------------
#
# The checks cover the JSON an HTML report embeds, not the text the page shows (EV-5). After an
# HTML report verifies, its JSON's own facts are printed, so a reader can compare them with the page.

FACTS_TITLE = "What the verified JSON in this HTML report says (compare it with the text the page shows):"


def _day(text) -> str:
    try:
        return _utc(text).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, TypeError):
        return str(text)


def _words(v) -> str:
    if isinstance(v, list):
        return ", ".join(str(x) for x in v) if v else "none"
    return str(v) if v else "none"


def facts(r: dict) -> list[str]:
    eng, s = r.get("engagement") or {}, r.get("summary") or {}
    pack = eng.get("pack") or {}
    scope = eng["scope"] if isinstance(eng.get("scope"), dict) else {}
    out = [f"Engagement: {eng.get('name')} (id {eng.get('id')}), pack {pack.get('name')} {pack.get('version')}"]
    if eng.get("authorized_by"):
        out.append(f"Authorized by {eng['authorized_by']}"
                   + (f" on {_day(eng['authorized_at'])}" if eng.get("authorized_at") else "")
                   + (f", under {eng['policy_url']}" if eng.get("policy_url") else ""))
    else:
        out.append("Authorization: not recorded")
    out.append(f"Scope: in scope {_words(scope.get('include'))}; out of scope {_words(scope.get('exclude'))}")
    hosts = [h for h in r.get("hosts") or [] if isinstance(h, dict)]
    out.append(f"Hosts: {sum(1 for h in hosts if h.get('in_scope'))} in scope, "
               f"{sum(1 for h in hosts if not h.get('in_scope'))} out of scope")
    lanes = r["lanes"]
    out.append(f"Lanes: {sum(1 for l in lanes if l['status'] == 'closed')} receipted, "
               f"{sum(1 for l in lanes if l['status'] == 'stale')} with a void receipt, "
               f"{sum(1 for l in lanes if l['status'] == 'open')} open")
    for lane in lanes:
        rc = lane["receipt"]
        if not rc or lane["status"] not in ("closed", "stale"):
            continue
        label = f"{lane['host']} / {lane['name']}"
        if lane["status"] == "stale":
            out.append(f"Void: {label}: receipt issued {_day(rc.get('issued_at'))}, no longer valid")
            continue
        done = sum(1 for i in lane["items"] if i["state"] == "done")
        na = sum(1 for i in lane["items"] if i["state"] == "na")
        try:
            payload = json.loads(rc["signature"]["payload"]) if rc.get("signature") else None
        except (ValueError, KeyError, TypeError):
            payload = None
        who = (f"signed by {_signer(payload.get('signer'))}" if isinstance(payload, dict)
               else f"closed by {rc.get('closed_by')}, not signed")
        ts = rc.get("timestamp")
        out.append(f"Receipted: {label}: {done} done, {na} not applicable; {who}, {_day(rc.get('issued_at'))}"
                   + (f"; timestamped {_day(ts.get('time'))}" if isinstance(ts, dict) else ""))
    out.append(f"Evidence: {len(r['evidence'])} entr{'y' if len(r['evidence']) == 1 else 'ies'}, "
               f"chain head {s.get('chain_head')}")
    out.append(f"Report generated: {_day(r.get('generated_at'))}")
    seal = (r.get("integrity") or {}).get("seal")
    if isinstance(seal, dict):
        try:
            p = json.loads(seal["payload"])
        except (ValueError, KeyError, TypeError):
            p = {}
        ts = seal.get("timestamp")
        out.append(f"Sealed: {_day(p.get('sealed_at'))} by the server's key {str(seal.get('key_fingerprint'))[:16]}"
                   + (f"; timestamped {_day(ts.get('time'))}" if isinstance(ts, dict) else ""))
    return out


# ---- RFC 3161 timestamps ---------------------------------------------------------------
#
# A timestamp token is CMS SignedData over a TSTInfo. The TSTInfo names the hash of what
# was timestamped and the time; the signer is the timestamp authority, whose certificate
# must chain to a root the reader trusts. Only what these checks need is parsed.

TS_STATEMENT = "attackledger-timestamp-v1"
_HASH = {"2.16.840.1.101.3.4.2.1": hashlib.sha256, "2.16.840.1.101.3.4.2.2": hashlib.sha384,
         "2.16.840.1.101.3.4.2.3": hashlib.sha512}
_RSA_WITH = {"1.2.840.113549.1.1.11": "2.16.840.1.101.3.4.2.1", "1.2.840.113549.1.1.12": "2.16.840.1.101.3.4.2.2",
             "1.2.840.113549.1.1.13": "2.16.840.1.101.3.4.2.3"}
_ECDSA_WITH = {"1.2.840.10045.4.3.2": "2.16.840.1.101.3.4.2.1", "1.2.840.10045.4.3.3": "2.16.840.1.101.3.4.2.2",
               "1.2.840.10045.4.3.4": "2.16.840.1.101.3.4.2.3"}
_RSA, _EC = "1.2.840.113549.1.1.1", "1.2.840.10045.2.1"
_CURVES = {"1.2.840.10045.3.1.7": _P256, "1.3.132.0.34": _P384}
_DIGEST_INFO = {"2.16.840.1.101.3.4.2.1": "3031300d060960864801650304020105000420",
                "2.16.840.1.101.3.4.2.2": "3041300d060960864801650304020205000430",
                "2.16.840.1.101.3.4.2.3": "3051300d060960864801650304020305000440"}
_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"


def _der(buf: bytes, pos: int) -> tuple:
    """One DER element at pos: (tag, start, content start, end)."""
    tag = buf[pos]
    if tag & 0x1f == 0x1f:
        raise ValueError("unsupported tag")
    n, p = buf[pos + 1], pos + 2
    if n & 0x80:
        k = n & 0x7f
        if not 1 <= k <= 4:
            raise ValueError("bad length")
        n, p = int.from_bytes(buf[p:p + k], "big"), p + k
    if p + n > len(buf):
        raise ValueError("truncated")
    return tag, pos, p, p + n


def _kids(buf: bytes, node: tuple) -> list:
    out, p = [], node[2]
    while p < node[3]:
        k = _der(buf, p)
        out.append(k)
        p = k[3]
    return out


def _val(buf: bytes, node: tuple) -> bytes:
    return buf[node[2]:node[3]]


def _whole(buf: bytes, node: tuple) -> bytes:
    return buf[node[1]:node[3]]


def _oid(b: bytes) -> str:
    first = min(b[0] // 40, 2)
    parts, v = [first, b[0] - 40 * first], 0
    for c in b[1:]:
        v = (v << 7) | (c & 0x7f)
        if not c & 0x80:
            parts.append(v)
            v = 0
    return ".".join(map(str, parts))


def _time(buf: bytes, node: tuple):
    from datetime import datetime, timezone
    s = _val(buf, node).decode("ascii")
    if not s.endswith("Z"):
        raise ValueError("time not in UTC")
    if node[0] == 0x17:                                     # UTCTime, YYMMDDHHMMSSZ
        year = int(s[:2])
        s = ("19" if year >= 50 else "20") + s
    elif node[0] != 0x18:
        raise ValueError("not a time")
    t = datetime.strptime(s[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    frac = s[14:-1]
    if frac:
        t = t.replace(microsecond=int((frac.lstrip(".") + "000000")[:6]))
    return t


def _alg(buf: bytes, node: tuple) -> str:
    return _oid(_val(buf, _kids(buf, node)[0]))


def _name_cn(name: bytes) -> str:
    """The common name in an X.509 Name, for messages."""
    try:
        for rdn in _kids(name, _der(name, 0)):
            for atv in _kids(name, rdn):
                k = _kids(name, atv)
                if _oid(_val(name, k[0])) == "2.5.4.3":
                    return _val(name, k[1]).decode("utf-8", "replace")
    except (ValueError, IndexError):
        pass
    return "(no common name)"


def parse_cert(der: bytes) -> dict:
    c = _der(der, 0)
    tbs, sig_alg, sig = _kids(der, c)
    t = _kids(der, tbs)
    i = 1 if t[0][0] == 0xa0 else 0
    nb, na = (_time(der, x) for x in _kids(der, t[i + 3]))
    out = {"der": der, "tbs": _whole(der, tbs), "sig_alg": _alg(der, sig_alg), "sig": _val(der, sig)[1:],
           "serial": int.from_bytes(_val(der, t[i]), "big", signed=True), "issuer": _whole(der, t[i + 2]),
           "subject": _whole(der, t[i + 4]), "spki": _whole(der, t[i + 5]), "not_before": nb, "not_after": na,
           "eku": None, "ca": False, "ski": None}
    for ext_wrap in (x for x in t[i + 6:] if x[0] == 0xa3):
        for ext in _kids(der, _kids(der, ext_wrap)[0]):
            k = _kids(der, ext)
            oid, value = _oid(_val(der, k[0])), _val(der, k[-1])
            if oid == "2.5.29.37":
                out["eku"] = [_oid(_val(value, x)) for x in _kids(value, _der(value, 0))]
            elif oid == "2.5.29.19":
                bc = _kids(value, _der(value, 0))
                out["ca"] = bool(bc) and bc[0][0] == 0x01 and _val(value, bc[0]) != b"\x00"
            elif oid == "2.5.29.14":
                out["ski"] = _val(value, _der(value, 0))
    out["name"] = _name_cn(out["subject"])
    return out


def verify_with_key(spki: bytes, sig_alg: str, digest_alg: str | None, message: bytes, sig: bytes) -> bool:
    """Check an X.509 or CMS signature: RSA PKCS #1 v1.5 or ECDSA, with SHA-2."""
    k = _kids(spki, _der(spki, 0))
    alg = _kids(spki, k[0])
    key_type = _oid(_val(spki, alg[0]))
    key_bits = _val(spki, k[1])[1:]
    if sig_alg in _RSA_WITH:
        digest_alg = _RSA_WITH[sig_alg]
        sig_alg = _RSA
    elif sig_alg in _ECDSA_WITH:
        digest_alg = _ECDSA_WITH[sig_alg]
        sig_alg = _EC
    if digest_alg not in _HASH or sig_alg != key_type:
        return False
    digest = _HASH[digest_alg](message).digest()
    if key_type == _RSA:
        nk = _kids(key_bits, _der(key_bits, 0))
        n, e = (int.from_bytes(_val(key_bits, x), "big") for x in nk[:2])
        size = (n.bit_length() + 7) // 8
        t = bytes.fromhex(_DIGEST_INFO[digest_alg]) + digest
        if len(sig) != size or size < len(t) + 11:
            return False
        em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(size, "big")
        return em == b"\x00\x01" + b"\xff" * (size - len(t) - 3) + b"\x00" + t
    if key_type == _EC:
        curve = _CURVES.get(_oid(_val(spki, alg[1]))) if len(alg) > 1 else None
        if curve is None:
            return False
        rs = _kids(sig, _der(sig, 0))
        r, s = (int.from_bytes(_val(sig, x), "big") for x in rs[:2])
        return ecdsa_verify(curve, key_bits, digest, r, s)
    return False


def read_token(token: bytes) -> dict:
    """The TSTInfo fields, the signer's signed attributes and the certificates in a token."""
    ci = _kids(token, _der(token, 0))
    if _oid(_val(token, ci[0])) != "1.2.840.113549.1.7.2":
        raise ValueError("not CMS signed data")
    sd = _kids(token, _kids(token, ci[1])[0])
    encap = _kids(token, sd[2])
    if _oid(_val(token, encap[0])) != "1.2.840.113549.1.9.16.1.4":
        raise ValueError("not a timestamp")
    econtent = _val(token, _kids(token, encap[1])[0])
    certs, signers = [], None
    for part in sd[3:]:
        if part[0] == 0xa0:
            certs = [parse_cert(_whole(token, x)) for x in _kids(token, part)]
        elif part[0] == 0x31:
            signers = _kids(token, part)
    if not signers or len(signers) != 1:
        raise ValueError("a timestamp has exactly one signer")
    si = _kids(token, signers[0])
    sid, digest_alg = si[1], _alg(token, si[2])
    attrs_node = si[3] if si[3][0] == 0xa0 else None
    if attrs_node is None:
        raise ValueError("the signer has no signed attributes")
    sig_alg, sig = _alg(token, si[4]), _val(token, si[5])
    attrs = {}
    for a in _kids(token, attrs_node):
        k = _kids(token, a)
        attrs[_oid(_val(token, k[0]))] = _kids(token, k[1])
    f = _kids(econtent, _der(econtent, 0))
    imprint = _kids(econtent, f[2])
    signed_attrs = b"\x31" + _whole(token, attrs_node)[1:]
    if sid[0] == 0x30:
        iss = _kids(token, sid)
        match = {"issuer": _whole(token, iss[0]), "serial": int.from_bytes(_val(token, iss[1]), "big", signed=True)}
    else:
        match = {"ski": _val(token, sid)}
    ct = attrs.get("1.2.840.113549.1.9.3", [])
    md = attrs.get("1.2.840.113549.1.9.4", [])
    return {"imprint_alg": _alg(econtent, imprint[0]), "imprint": _val(econtent, imprint[1]),
            "time": _time(econtent, f[4]), "certs": certs, "match": match, "digest_alg": digest_alg,
            "sig_alg": sig_alg, "sig": sig, "signed_attrs": signed_attrs, "econtent": econtent,
            "content_type": _oid(_val(token, ct[0])) if ct else None,
            "message_digest": _val(token, md[0]) if md else None}


def load_roots(paths: list[str]) -> list[dict]:
    import base64
    roots = []
    for path in paths:
        try:
            with open(path, encoding="ascii") as f:
                text = f.read()
        except OSError as e:
            raise SystemExit(f"cannot read the trusted root {path}: {e.strerror}")
        blocks = re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", text, re.S)
        if not blocks:
            raise SystemExit(f"no certificate found in {path}")
        roots += [parse_cert(base64.b64decode("".join(b.split()))) for b in blocks]
    return roots


def token_problems(t: dict, roots: list[dict]) -> tuple[list[str], str]:
    """Check the TSA's signature and its certificate chain at the token's time."""
    if t["content_type"] != "1.2.840.113549.1.9.16.1.4":
        return ["the signed attributes do not name a timestamp"], ""
    if t["digest_alg"] not in _HASH or t["message_digest"] != _HASH[t["digest_alg"]](t["econtent"]).digest():
        return ["the timestamp's content does not match what the authority signed"], ""
    m = t["match"]
    signer = next((c for c in t["certs"] if ("ski" in m and c["ski"] == m["ski"]) or
                   ("issuer" in m and c["issuer"] == m["issuer"] and c["serial"] == m["serial"])), None)
    if signer is None:
        return ["the token does not include the authority's certificate"], ""
    if not verify_with_key(signer["spki"], t["sig_alg"], t["digest_alg"], t["signed_attrs"], t["sig"]):
        return ["the authority's signature does not verify"], signer["name"]
    if not signer["eku"] or _TIME_STAMPING not in signer["eku"]:
        return [f"{signer['name']} is not a timestamping certificate"], signer["name"]
    problems, cur, when = [], signer, t["time"]
    for _ in range(8):
        if not (cur["not_before"] <= when <= cur["not_after"]):
            problems.append(f"{cur['name']} was not valid at the token's time")
        if any(r["subject"] == cur["subject"] and r["spki"] == cur["spki"] for r in roots):
            return problems, signer["name"]
        issuer = next((c for c in roots + t["certs"] if c["subject"] == cur["issuer"] and c is not cur
                       and verify_with_key(c["spki"], cur["sig_alg"], None, cur["tbs"], cur["sig"])), None)
        if issuer is None:
            if cur["issuer"] == cur["subject"]:
                problems.append(f"it chains to {cur['name']}, which you have not trusted "
                                "(pass --tsa-root FILE if you trust it)")
            else:
                problems.append(f"the certificate that issued {cur['name']} is not in the token and no root you "
                                "trusted issued it (pass --tsa-root FILE with the authority's root)")
            return problems, signer["name"]
        if not issuer["ca"]:
            problems.append(f"{issuer['name']} is not a certificate authority")
        cur = issuer
    return problems + ["the certificate chain is too long"], signer["name"]


def check_timestamps(r: dict, roots: list[dict]) -> tuple[list[str], list[str]]:
    import base64
    from datetime import datetime, timezone
    problems, notes, stamped, receipted = [], [], 0, 0
    for lane in r["lanes"]:
        rc = lane["receipt"]
        if not rc or lane["status"] != "closed":
            continue
        receipted += 1
        ts = rc.get("timestamp")
        if not ts:
            continue
        stamped += 1
        label = f"{lane['host']} / {lane['name']}"
        try:
            t = read_token(base64.b64decode(ts["token"], validate=True))
        except (ValueError, IndexError, KeyError, TypeError):
            problems.append(f"{label}: the timestamp token cannot be read")
            continue
        statement = f"{TS_STATEMENT}\n{rc['manifest_sha256']}\n{(rc.get('signature') or {}).get('value') or ''}\n"
        mine = []
        if t["imprint_alg"] not in _HASH or _HASH[t["imprint_alg"]](statement.encode()).digest() != t["imprint"]:
            mine.append(f"{label}: the timestamp covers a different receipt")
        found, tsa = token_problems(t, roots)
        mine += [f"{label}: {p}" for p in found]
        try:
            shown = datetime.fromisoformat(ts.get("time") or "")
            shown = shown if shown.tzinfo else shown.replace(tzinfo=timezone.utc)
        except ValueError:
            shown = None
        if shown != t["time"]:
            mine.append(f"{label}: the time shown in the report is not the token's time")
        problems += mine
        if not mine:
            notes.append(f"{label}: timestamped {t['time'].isoformat()} by {tsa}")
    if receipted and stamped < receipted:
        notes.append(f"{receipted - stamped} of {_receipts(receipted)} {'is' if receipted - stamped == 1 else 'are'} "
                     "not timestamped")
    return problems, notes


def main(argv: list[str]) -> int:
    args, root_files, require, strict, rest = [], [], False, False, iter(argv[1:])
    for a in rest:
        if a == "--tsa-root":
            root_files.append(next(rest, None))
        elif a == "--require-signatures":
            require = True
        elif a == "--require-history":
            strict = True
        else:
            args.append(a)
    if len(args) != 1 or None in root_files:
        print(__doc__.strip())
        return 2
    import os
    default = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tsa-roots")
    if os.path.isdir(default):
        root_files += sorted(os.path.join(default, f) for f in os.listdir(default) if f.endswith(".pem"))
    roots = load_roots(root_files)
    r = load(args[0])
    if r.get("format") not in FORMATS:
        print(f"unsupported report format: {r.get('format')}")
        return 2

    # (name, problems, skip): a check with a skip reason found nothing to check.
    results = [("Report body hash", check_body(r), None), ("Evidence chain", check_chain(r), None)]
    receipt_problems, notes = check_receipts(r)
    if args[0].endswith((".html", ".htm")):
        notes.insert(0, HTML_NOTE)
    notes += content_notes(r)
    results.append(("Lane receipts", receipt_problems, None))
    if r["format"] != "attackledger-report/1":
        seal_problems, seal_notes, sealed = check_seal(r, roots, strict)
        for name, field, check in (("Receipt signatures", "signature", lambda: check_signatures(r, require)),
                                   ("Receipt timestamps", "timestamp", lambda: check_timestamps(r, roots))):
            problems, more = check()
            have, receipted = count_receipts(r, field)
            done = "signed" if field == "signature" else "timestamped"
            skip = None if have else (f"0 of {_receipts(receipted)} {done}" if receipted else "no receipts")
            results.append((name, problems, skip))
            notes += more
            if field == "signature":
                key_problems, key_notes = check_key_log(r, strict)
                if "key_log" in r or key_problems:
                    results.append(("Signing key history", key_problems, None))
                notes += key_notes
                audit_problems, audit_notes = check_audit_log(r, strict, sealed)
                if "audit_log" in r or audit_problems:
                    results.append(("Change history", audit_problems, None))
                notes += audit_notes
        if "seal" in r.get("integrity", {}) or seal_problems:
            results.append(("Report seal", seal_problems, None))
        notes += seal_notes
    else:
        if require:
            results.append(("Receipt signatures", ["this report format carries no signatures"], None))
        if strict:
            results.append(("Change history", ["this report format carries no change history"], None))
            results.append(("Report seal", ["this report format carries no seal"], None))

    eng, s = r["engagement"], r["summary"]
    lanes, entries = s["lanes_receipted"], s["evidence_entries"]
    print(f"AttackLedger report: {eng['name']} ({eng['pack']['name']} {eng['pack']['version']})")
    print(f"  {lanes} receipted lane{'' if lanes == 1 else 's'}, "
          f"{entries} evidence entr{'y' if entries == 1 else 'ies'}\n")
    ok = True
    for name, problems, skip in results:
        if skip and not problems:
            print(f"  SKIP  {name} ({skip})")
            continue
        print(f"  {'PASS' if not problems else 'FAIL'}  {name}")
        for p in problems:
            print(f"        - {p}")
        ok = ok and not problems
    for n in notes:
        print(f"  NOTE  {n}")
    print("\nVerified." if ok else "\nVerification FAILED.")
    if ok and args[0].endswith((".html", ".htm")):
        print(f"\n{FACTS_TITLE}")
        for line in facts(r):
            print(f"  {line}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
