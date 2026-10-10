"""Report seals (D-055): the instance signs every report it exports.

A receipt binds the change history only up to the moment it was signed (D-054), so a void, or
any audit or key log entry, recorded after the newest signature could be left out of a report
and nothing signed would say so. A seal is made when the report is exported: this instance
signs, with its own Ed25519 key, a short text naming the report's body hash and the heads of
the audit log and the key log the report carries. A report that leaves out or changes anything,
including an entry up to those heads, no longer matches the seal.

    integrity.seal = {"algorithm": "Ed25519", "public_key": <SPKI, base64>, "key_fingerprint": <sha256 of it>,
                      "payload": <canonical JSON, below>, "value": <signature, base64>,
                      "timestamp": {"tsa", "time", "token"}}          # when a timestamp authority is set
    payload = {"format": "attackledger-seal-v1", "engagement": {"id", "name"}, "report_sha256": <body hash>,
               "history": {"audit": {"seq", "head"} | null, "key_log": {"seq", "head"} | null},
               "key_fingerprint": ..., "sealed_at": <ISO time>}

The seal sits in the report's integrity section, which the body hash leaves out, so the body
hash is unchanged by it. The key is kept in the blob store, wrapped by the master key like an
engagement's data key (vault.seal_key). Its public key is registered, once, in each
organization's key log (keylog.append_instance), so the report carries it in its key history
and it is chained with the reviewers' keys. With a timestamp authority set, the seal is
timestamped (the same service as receipts): only the SHA-256 of a statement naming the body
hash and the seal's signature leaves the deployment.

What it proves: the instance holding this key said, at that time, that this was the report and
its history up to those heads. Whoever holds the key (the server's operator) could still seal a
different report; reviewers' signatures remain the evidence of the review (docs/VERIFIER.md).
"""
import base64
import hashlib
import json
import logging
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import keylog, ledger, timestamps, vault

FORMAT = "attackledger-seal-v1"
STATEMENT_FORMAT = "attackledger-seal-timestamp-v1"
ALGORITHM = "Ed25519"
log = logging.getLogger(__name__)


def _key() -> tuple[ed25519.Ed25519PrivateKey, str]:
    private = ed25519.Ed25519PrivateKey.from_private_bytes(vault.seal_key())
    spki = private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return private, base64.b64encode(spki).decode()


def public_key() -> dict:
    """The instance's seal key, as the report and the key log name it (made on first use)."""
    _, spki = _key()
    return {"algorithm": ALGORITHM, "public_key": spki,
            "key_fingerprint": hashlib.sha256(base64.b64decode(spki)).hexdigest()}


def register(session, organization_id: int) -> str:
    """Make sure the organization's key log registers the seal key; commits when it adds the
    entry. Call it before the report is built, so the report's key history includes the
    registration. Returns the key's fingerprint."""
    k = public_key()
    if keylog.instance_registration(session, organization_id, k["key_fingerprint"]) is None:
        keylog.append_instance(session, organization_id=organization_id, fingerprint=k["key_fingerprint"],
                               algorithm=ALGORITHM)
        session.commit()
    return k["key_fingerprint"]


def statement(report_sha256: str, signature_b64: str) -> bytes:
    """The bytes whose hash is timestamped. The verifier rebuilds them from the report."""
    return f"{STATEMENT_FORMAT}\n{report_sha256}\n{signature_b64}\n".encode()


def _head(log_section: dict | None) -> dict | None:
    if log_section is None:
        return None
    return {"seq": log_section["head"]["seq"], "head": log_section["head"]["entry_hash"]}


def payload_for(report: dict, key_fingerprint: str, sealed_at: str) -> str:
    """The exact text the instance signs, for a report as report.build made it."""
    return json.dumps({
        "format": FORMAT,
        "engagement": {"id": report["engagement"]["id"], "name": report["engagement"]["name"]},
        "report_sha256": report["integrity"]["body_sha256"],
        "history": {"audit": _head(report.get("audit_log")), "key_log": _head(report.get("key_log"))},
        "key_fingerprint": key_fingerprint,
        "sealed_at": sealed_at,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def seal(report: dict) -> dict:
    """Seal a report made by report.build (with the seal key in its key history): returns it
    with integrity.seal. The body, and so its hash, is not changed."""
    body = {k: v for k, v in report.items() if k != "integrity"}
    if ledger.sha256(ledger.canonical(body)) != report["integrity"]["body_sha256"]:
        raise ValueError("the report's body hash does not match its body")
    private, spki = _key()
    fp = hashlib.sha256(base64.b64decode(spki)).hexdigest()
    payload = payload_for(report, fp, datetime.now(timezone.utc).isoformat())
    value = base64.b64encode(private.sign(payload.encode())).decode()
    out = {"algorithm": ALGORITHM, "public_key": spki, "key_fingerprint": fp, "payload": payload, "value": value}
    url = timestamps.tsa_url()
    if url:
        try:
            token, when = timestamps.fetch(url, statement(report["integrity"]["body_sha256"], value))
            out["timestamp"] = {"tsa": url, "time": when.isoformat(), "token": token}
        except timestamps.TimestampError as e:      # the report is still sealed, with the server's clock
            log.warning("report seal not timestamped: %s", e)
    return {**report, "integrity": {**report["integrity"], "seal": out}}
