"""Receipt signatures (D-027, step 2a).

A reviewer's browser holds a private key that never leaves it (WebCrypto,
non-extractable). The server stores the public key and checks every signature.

What is signed is the receipt payload: canonical JSON naming the engagement, the lane,
its manifest hash, the head of the evidence chain, the signer, the key and the time.
Format v3 (D-037) names the signer by id, name and email, so a name alone cannot pass for
someone else's: v2 named only the id and the name. The server issues and accepts v3 for
new receipts; receipts signed as v2 keep their payload and verify as before.
The report carries the payload, the signature and the public key, so anyone can check
the signature offline (tools/verify_report.py, standard library only).

Algorithms: Ed25519 (raw 64-byte signatures) and ECDSA P-256 with SHA-256 (WebCrypto's
raw r||s, 64 bytes), for browsers without Ed25519 in WebCrypto.
"""
import base64
import binascii
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

ALGORITHMS = ("Ed25519", "ECDSA-P256")
PAYLOAD_FORMAT = "attackledger-receipt-v3"
PAYLOAD_FORMATS = ("attackledger-receipt-v2", PAYLOAD_FORMAT)   # what a verifier reads
PAYLOAD_MAX_AGE_SECONDS = 600


class SigningError(ValueError):
    pass


def _b64(data: str) -> bytes:
    try:
        return base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        raise SigningError("not valid base64")


def load_public_key(algorithm: str, spki_b64: str):
    """Parse an SPKI public key and check that it is the key type the algorithm names."""
    if algorithm not in ALGORITHMS:
        raise SigningError(f"unsupported algorithm: {algorithm} (use {', '.join(ALGORITHMS)})")
    try:
        key = serialization.load_der_public_key(_b64(spki_b64))
    except ValueError:
        raise SigningError("not a public key in SPKI form")
    if algorithm == "Ed25519" and not isinstance(key, ed25519.Ed25519PublicKey):
        raise SigningError("the key is not an Ed25519 key")
    if algorithm == "ECDSA-P256" and not (isinstance(key, ec.EllipticCurvePublicKey)
                                          and isinstance(key.curve, ec.SECP256R1)):
        raise SigningError("the key is not a P-256 key")
    return key


def fingerprint(spki_b64: str) -> str:
    return hashlib.sha256(_b64(spki_b64)).hexdigest()


def verify(algorithm: str, spki_b64: str, payload: str, signature_b64: str) -> bool:
    key = load_public_key(algorithm, spki_b64)
    sig = _b64(signature_b64)
    data = payload.encode()
    try:
        if algorithm == "Ed25519":
            key.verify(sig, data)
        else:
            if len(sig) != 64:
                return False
            der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
            key.verify(der, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def payload_for(*, engagement_id: int, engagement_name: str, lane_id: int, host: str, role: str,
                manifest_sha256: str, chain_seq: int, chain_head: str, signer_id: int, signer_name: str,
                signer_email: str, key_fingerprint: str, issued_at: str) -> str:
    """The exact text a reviewer signs. Canonical JSON, so the verifier can rebuild it."""
    return json.dumps({
        "format": PAYLOAD_FORMAT,
        "engagement": {"id": engagement_id, "name": engagement_name},
        "lane": {"id": lane_id, "host": host, "role": role},
        "manifest_sha256": manifest_sha256,
        "chain": {"seq": chain_seq, "head": chain_head},
        "signer": {"id": signer_id, "name": signer_name, "email": signer_email},
        "key_fingerprint": key_fingerprint,
        "issued_at": issued_at,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
