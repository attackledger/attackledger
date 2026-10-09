#!/usr/bin/env python3
"""Verify an AttackLedger report offline.

    python3 tools/verify_report.py report.json
    python3 tools/verify_report.py report.html
    python3 tools/verify_report.py report.json --tsa-root authority-root.pem

Standard library only, and independent of the AttackLedger code base on
purpose: it re-derives every hash itself. Checks:

  1. the report body matches its recorded SHA-256,
  2. the evidence chain is unbroken from the genesis value,
  3. every lane reported as receipted has a receipt that matches a manifest
     rebuilt from the report's own items and evidence,
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
     revoked before that.

Signatures are Ed25519 or ECDSA P-256 with SHA-256, checked with the pure-Python
code below (RFC 8032 and SEC 1), so no third-party package is needed; timestamp
authorities may also use RSA (PKCS #1 v1.5) or ECDSA P-384. A signature
proves the key holder signed. The key log says when and how each key was registered
to its signer; for high assurance, also compare each fingerprint with the one the
signer gives you.

Exit code 0 means every check passed.
"""
import hashlib
import json
import re
import sys

GENESIS = "0" * 64
FORMATS = ("attackledger-report/1", "attackledger-report/2")
CHAIN_FIELDS = ("seq", "lane_id", "host", "role", "item_id", "kind", "sha256", "uri", "summary")
KEY_LOG_FIELDS = ("seq", "user_id", "user_name", "key_fingerprint", "algorithm", "event", "at", "via")
KEY_VIA = {
    "own_session": "from their own session",
    "assigned_password": "from a session signed in with a password someone else set",
    "operator_cli": "by the operator on the server",
    "backfill": "before the key log existed (recorded when it was added)",
}


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


def check_key_log(r: dict) -> tuple[list[str], list[str]]:
    problems, notes = [], []
    signed = [l for l in r["lanes"] if l["receipt"] and l["status"] == "closed" and l["receipt"].get("signature")]
    log = r.get("key_log")
    if log is None:
        if signed:
            notes.append("this report has no key history (made before the key log); compare each signer's key "
                         "fingerprint with the one they give you")
        return problems, notes
    if log.get("genesis") != GENESIS:
        problems.append("unexpected key log genesis value")
    links, prev = log.get("links") or [], None
    for n, ln in enumerate(links):
        try:
            seq, ph, rsha, eh = ln["seq"], ln["prev_hash"], ln["record_sha256"], ln["entry_hash"]
        except (KeyError, TypeError):
            problems.append("a key log link cannot be read")
            return problems, notes
        if n == 0 and seq == 1 and ph != GENESIS:
            problems.append("key log entry #1 does not start from the genesis value")
        if n > 0 and seq != links[n - 1]["seq"] + 1:
            problems.append(f"key log entry #{seq}: out of sequence (expected #{links[n - 1]['seq'] + 1})")
        if n > 0 and ph != prev:
            problems.append(f"key log entry #{seq}: does not link to the previous entry")
        if sha(ph + rsha) != eh:
            problems.append(f"key log entry #{seq}: does not match its chain hash")
        prev = eh
    head = log.get("head") or {}
    if links and (head.get("seq") != links[-1]["seq"] or head.get("entry_hash") != links[-1]["entry_hash"]):
        problems.append("the key log head does not match its last link")
    by_seq = {ln["seq"]: ln for ln in links}
    history: dict[str, list[dict]] = {}
    latest = None
    for e in sorted(log.get("entries") or [], key=lambda e: e.get("seq") or 0):
        ln = by_seq.get(e.get("seq"))
        if ln is None:
            problems.append(f"key log entry #{e.get('seq')} is not in the chain the report carries")
        elif sha(canonical({k: e.get(k) for k in KEY_LOG_FIELDS})) != ln["record_sha256"]:
            problems.append(f"key log entry #{e.get('seq')}: content does not match its record hash")
        try:
            at = _utc(e["at"])
        except (ValueError, KeyError, TypeError):
            problems.append(f"key log entry #{e.get('seq')}: its time cannot be read")
            continue
        if latest is not None and at < latest:          # appended later, but dated earlier
            problems.append(f"key log entry #{e.get('seq')} is dated before an earlier entry")
        latest = max(at, latest or at)
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
        problems += mine
        if not mine and fp not in described:
            described.add(fp)
            when = _utc(reg["at"]).strftime("%Y-%m-%d %H:%M UTC")
            later = (f"; revoked {_utc(revoked[0]['at']).strftime('%Y-%m-%d %H:%M UTC')}, after it signed"
                     if revoked else "")
            notes.append(f"{signer.get('name')} signed with key {fp[:16]}, registered {when} "
                         f"{KEY_VIA.get(reg.get('via'), 'in a way this verifier does not know')}{later}")
    return problems, notes


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
        notes.append(f"{receipted - stamped} of {receipted} receipts are not timestamped")
    return problems, notes


def main(argv: list[str]) -> int:
    args, root_files, rest = [], [], iter(argv[1:])
    for a in rest:
        if a == "--tsa-root":
            root_files.append(next(rest, None))
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

    results = [("Report body hash", check_body(r)), ("Evidence chain", check_chain(r))]
    receipt_problems, notes = check_receipts(r)
    results.append(("Lane receipts", receipt_problems))
    if r["format"] != "attackledger-report/1":
        sig_problems, sig_notes = check_signatures(r)
        results.append(("Receipt signatures", sig_problems))
        notes += sig_notes
        key_problems, key_notes = check_key_log(r)
        if "key_log" in r:
            results.append(("Signing key history", key_problems))
        notes += key_notes
        ts_problems, ts_notes = check_timestamps(r, roots)
        if any(l["receipt"] and l["receipt"].get("timestamp") for l in r["lanes"]):
            results.append(("Receipt timestamps", ts_problems))
        notes += ts_notes

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
