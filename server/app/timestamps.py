"""RFC 3161 timestamps on receipts (D-027, step 2b).

When a lane closes, the server asks a timestamp authority (TSA) to timestamp a short
statement that binds the receipt's manifest hash and its signature. Only the SHA-256 of
that statement leaves the deployment, never evidence. The token the TSA returns proves
the receipt existed at that time; the report carries it, and verify_report.py checks the
TSA's signature and certificate chain offline.

The server checks only that the reply answers this request (same hash, same nonce). It
does not decide whether to trust the TSA: the reader of the report does that, with the
roots they trust.

Off unless ATTACKLEDGER_TSA_URL is set.
"""
import base64
import hashlib
import os
import secrets
from datetime import datetime, timezone

import httpx

STATEMENT_FORMAT = "attackledger-timestamp-v1"
SHA256 = "2.16.840.1.101.3.4.2.1"
SIGNED_DATA = "1.2.840.113549.1.7.2"
TST_INFO = "1.2.840.113549.1.9.16.1.4"
MAX_REPLY_BYTES = 64 * 1024


class TimestampError(Exception):
    pass


def tsa_url() -> str | None:
    return os.environ.get("ATTACKLEDGER_TSA_URL", "").strip() or None


def statement(manifest_sha256: str, signature_b64: str | None) -> bytes:
    """The bytes whose hash is timestamped. The verifier rebuilds them from the report."""
    return f"{STATEMENT_FORMAT}\n{manifest_sha256}\n{signature_b64 or ''}\n".encode()


# ---- DER, only as much as a timestamp request and token need ---------------------------

def _tlv(tag: int, content: bytes) -> bytes:
    n = len(content)
    length = bytes([n]) if n < 0x80 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + length + content


def _int(n: int) -> bytes:
    return _tlv(0x02, n.to_bytes(n.bit_length() // 8 + 1, "big"))


def _oid(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.split(".")]
    out = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7f]
        while p > 0x7f:
            p >>= 7
            chunk.insert(0, 0x80 | (p & 0x7f))
        out += bytes(chunk)
    return _tlv(0x06, out)


def _read(buf: bytes, pos: int) -> tuple[int, int, int, int]:
    """One element at pos: (tag, start of element, start of content, end)."""
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


def _kids(buf: bytes, node) -> list:
    out, p = [], node[2]
    while p < node[3]:
        k = _read(buf, p)
        out.append(k)
        p = k[3]
    return out


def _oid_str(b: bytes) -> str:
    parts = [min(b[0] // 40, 2), b[0] - 40 * min(b[0] // 40, 2)]
    v = 0
    for c in b[1:]:
        v = (v << 7) | (c & 0x7f)
        if not c & 0x80:
            parts.append(v)
            v = 0
    return ".".join(map(str, parts))


def request(digest: bytes, nonce: int) -> bytes:
    """TimeStampReq: version 1, SHA-256 imprint, nonce, and ask for the TSA's certificate."""
    imprint = _tlv(0x30, _tlv(0x30, _oid(SHA256) + b"\x05\x00") + _tlv(0x04, digest))
    return _tlv(0x30, _int(1) + imprint + _int(nonce) + b"\x01\x01\xff")


def token_from_reply(reply: bytes) -> bytes:
    """The TimeStampToken in a TimeStampResp, or an error saying why there is none."""
    try:
        resp = _read(reply, 0)
        parts = _kids(reply, resp)
        status = _kids(reply, parts[0])[0]
        code = int.from_bytes(reply[status[2]:status[3]], "big")
    except (ValueError, IndexError):
        raise TimestampError("the timestamp authority's reply cannot be read")
    if code not in (0, 1):                      # granted, granted with modifications
        raise TimestampError(f"the timestamp authority refused the request (status {code})")
    if len(parts) < 2:
        raise TimestampError("the timestamp authority's reply has no token")
    return reply[parts[1][1]:parts[1][3]]


def tst_info(token: bytes) -> dict:
    """The parts of the token's TSTInfo the server checks and shows."""
    try:
        ci = _kids(token, _read(token, 0))
        if _oid_str(token[ci[0][2]:ci[0][3]]) != SIGNED_DATA:
            raise ValueError("not signed data")
        sd = _kids(token, _kids(token, ci[1])[0])
        encap = _kids(token, sd[2])
        if _oid_str(token[encap[0][2]:encap[0][3]]) != TST_INFO:
            raise ValueError("not a timestamp")
        octets = _kids(token, encap[1])[0]
        tst = token[octets[2]:octets[3]]
        f = _kids(tst, _read(tst, 0))
        imprint = _kids(tst, f[2])
        alg = _kids(tst, imprint[0])[0]
        gen = tst[f[4][2]:f[4][3]].decode("ascii")
        nonce = next((int.from_bytes(tst[x[2]:x[3]], "big") for x in f[5:] if x[0] == 0x02), None)
    except (ValueError, IndexError, UnicodeDecodeError):
        raise TimestampError("the timestamp token cannot be read")
    return {"alg": _oid_str(tst[alg[2]:alg[3]]), "digest": tst[imprint[1][2]:imprint[1][3]],
            "time": _generalized_time(gen), "nonce": nonce}


def _generalized_time(s: str) -> datetime:
    if not s.endswith("Z") or len(s) < 15:
        raise TimestampError("the timestamp token's time is not in UTC")
    base = datetime.strptime(s[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    frac = s[14:-1]
    if frac:
        if not (frac.startswith(".") and frac[1:].isdigit()):
            raise TimestampError("the timestamp token's time cannot be read")
        base = base.replace(microsecond=int((frac[1:] + "000000")[:6]))
    return base


def _post(url: str, body: bytes) -> bytes:
    with httpx.Client(timeout=10, follow_redirects=False) as c:
        r = c.post(url, content=body, headers={"content-type": "application/timestamp-query",
                                               "accept": "application/timestamp-reply",
                                               "user-agent": "AttackLedger"})
        r.raise_for_status()
        if len(r.content) > MAX_REPLY_BYTES:
            raise TimestampError("the timestamp authority's reply is too large")
        return r.content


POST = _post   # replaced in tests


def fetch(url: str, data: bytes) -> tuple[str, datetime]:
    """Timestamp the SHA-256 of data. Returns the token (base64 DER) and its time."""
    digest, nonce = hashlib.sha256(data).digest(), secrets.randbits(63)
    try:
        reply = POST(url, request(digest, nonce))
    except httpx.HTTPError as e:
        raise TimestampError(f"the timestamp authority did not answer ({type(e).__name__})")
    token = token_from_reply(reply)
    info = tst_info(token)
    if info["alg"] != SHA256 or info["digest"] != digest:
        raise TimestampError("the timestamp authority timestamped something else")
    if info["nonce"] != nonce:
        raise TimestampError("the timestamp authority's reply is not for this request (nonce)")
    return base64.b64encode(token).decode(), info["time"]
