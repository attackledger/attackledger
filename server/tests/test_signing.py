"""Signed receipts: browser-held keys, server checks, and the offline verifier."""
import base64
import copy
import importlib.util
import json
import os
import secrets
import sys
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite://")
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "server"))

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import auth, db, signing
from app.main import app

spec = importlib.util.spec_from_file_location("verify_report", ROOT / "tools" / "verify_report.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)

PW = "correct horse battery"


# ---- the browser side, as WebCrypto does it ------------------------------------------

class BrowserKey:
    """Holds a private key the way the browser does, and signs like WebCrypto (raw bytes)."""

    def __init__(self, algorithm: str):
        self.algorithm = algorithm
        self.private = ed25519.Ed25519PrivateKey.generate() if algorithm == "Ed25519" \
            else ec.generate_private_key(ec.SECP256R1())
        self.spki = base64.b64encode(self.private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()

    def sign(self, text: str) -> str:
        if self.algorithm == "Ed25519":
            raw = self.private.sign(text.encode())
        else:
            r, s = decode_dss_signature(self.private.sign(text.encode(), ec.ECDSA(hashes.SHA256())))
            raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return base64.b64encode(raw).decode()


# ---- the offline verifier's own cryptography -------------------------------------------

def test_ed25519_rfc8032_vector():
    # RFC 8032, section 7.1, test 1 (empty message).
    pub = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    assert verifier.ed25519_verify(pub, b"", sig)
    assert not verifier.ed25519_verify(pub, b"x", sig)


@pytest.mark.parametrize("alg", ["Ed25519", "ECDSA-P256"])
def test_pure_python_verifier_agrees_with_cryptography(alg):
    for _ in range(8):
        k = BrowserKey(alg)
        msg = secrets.token_hex(40)
        sig = base64.b64decode(k.sign(msg))
        spki = base64.b64decode(k.spki)
        assert signing.verify(alg, k.spki, msg, base64.b64encode(sig).decode())
        assert verifier.verify_signature(alg, spki, msg.encode(), sig)
        bad = bytearray(sig)
        bad[5] ^= 1
        assert not verifier.verify_signature(alg, spki, msg.encode(), bytes(bad))
        assert not signing.verify(alg, k.spki, msg, base64.b64encode(bytes(bad)).decode())
        assert not verifier.verify_signature(alg, spki, (msg + "!").encode(), sig)
    other = "ECDSA-P256" if alg == "Ed25519" else "Ed25519"
    with pytest.raises(signing.SigningError):
        signing.load_public_key(other, BrowserKey(alg).spki)


# ---- the API --------------------------------------------------------------------

@pytest.fixture()
def client(monkeypatch):
    monkeypatch.delenv("ATTACKLEDGER_API_TOKEN", raising=False)
    auth._failures.clear()
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    db.Base.metadata.create_all(eng)
    Session = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)

    def _session():
        s = Session()
        try:
            yield s
        finally:
            s.close()
    app.dependency_overrides[db.get_session] = _session
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def sign_in(c, email):
    c.cookies.clear()
    assert c.post("/auth/login", json={"email": email, "password": PW}).status_code == 200


def setup(c):
    c.post("/people", json={"email": "owner@lab.test", "name": "Olive Owner", "password": PW, "is_owner": True})
    sign_in(c, "owner@lab.test")
    ids = {}
    for n in ("rita", "ray"):
        ids[n] = c.post("/people", json={"email": f"{n}@lab.test", "name": n.title(), "password": PW}).json()["id"]
    e = c.post("/engagements", json={"name": "Signed"}).json()["id"]
    c.put(f"/engagements/{e}/members", json={"members": [{"user_id": i, "roles": ["tester", "reviewer"]}
                                                         for i in ids.values()]})
    a = c.post(f"/engagements/{e}/assets", json={"host": "shop.lab.test"}).json()["id"]
    lane = c.post("/lanes", json={"asset_id": a, "role": "recon"}).json()
    c.post(f"/lanes/{lane['id']}/attach", json={"item_idx": 1, "kind": "note", "text": "scope confirmed"})
    for it in lane["items"]:
        state = {"state": "done"} if it["idx"] == 1 else {"state": "na", "na_reason": "lab"}
        c.patch(f"/lanes/{lane['id']}/items/{it['idx']}", json=state)
    return e, lane["id"], ids


def register(c, alg="Ed25519"):
    k = BrowserKey(alg)
    r = c.post("/auth/keys", json={"algorithm": alg, "public_key": k.spki})
    assert r.status_code == 201, r.text
    k.fingerprint = r.json()["fingerprint"]
    return k


def signed_close(c, lane_id, k, mutate=None):
    payload = c.get(f"/lanes/{lane_id}/receipt-payload", params={"key": k.fingerprint}).json()["payload"]
    if mutate:
        payload = mutate(payload)
    return c.post(f"/lanes/{lane_id}/close", json={"reviewed": True, "payload": payload,
                                                   "signature": k.sign(payload), "key_fingerprint": k.fingerprint})


@pytest.mark.parametrize("alg", ["Ed25519", "ECDSA-P256"])
def test_signed_receipt_end_to_end_and_offline(client, alg):
    e, lane, ids = setup(client)
    sign_in(client, "rita@lab.test")
    k = register(client, alg)
    r = signed_close(client, lane, k)
    assert r.status_code == 200, r.text
    rc = client.get(f"/lanes/{lane}").json()["receipt"]
    assert rc["signed"] and rc["algorithm"] == alg and rc["key_fingerprint"] == k.fingerprint
    report = client.get(f"/engagements/{e}/report").json()
    assert report["format"] == "attackledger-report/2"
    problems, notes = verifier.check_signatures(report)
    assert problems == [] and any("signed by Rita" in n for n in notes)
    assert verifier.check_body(report) == []

    # Tampering is caught offline: a changed payload, a swapped key, a changed manifest.
    lane_rc = next(l for l in report["lanes"] if l["lane_id"] == lane)["receipt"]
    for change in (
        lambda s: s.__setitem__("payload", s["payload"].replace("Rita", "Ray")),
        lambda s: s.__setitem__("public_key", BrowserKey(alg).spki),
        lambda s: s.__setitem__("value", BrowserKey(alg).sign(s["payload"])),
    ):
        bad = copy.deepcopy(report)
        change(next(l for l in bad["lanes"] if l["lane_id"] == lane)["receipt"]["signature"])
        assert verifier.check_signatures(bad)[0], change
    assert lane_rc["signature"]["payload"] and lane_rc["signature"]["value"]
    # Someone without the key rewrites the lane and recomputes its receipt hash: the
    # signature still covers the old manifest, so the verifier flags it.
    bad = copy.deepcopy(report)
    next(l for l in bad["lanes"] if l["lane_id"] == lane)["receipt"]["manifest_sha256"] = "f" * 64
    assert any("different manifest" in p for p in verifier.check_signatures(bad)[0])


def test_html_report_shows_the_signature(client):
    e, lane, _ = setup(client)
    sign_in(client, "rita@lab.test")
    k = register(client)
    assert signed_close(client, lane, k).status_code == 200
    page = client.get(f"/engagements/{e}/report.html").text
    receipts = page[page.index('id="receipts"'):page.index('id="verify"')]
    assert f"Ed25519 key <code>{k.fingerprint}</code>" in receipts and "Rita" in receipts
    assert "1 of 1" in page and "Receipts signed with a key; 0 timestamped" in page


def test_signed_close_refusals(client):
    e, lane, ids = setup(client)
    sign_in(client, "ray@lab.test")
    ray_key = register(client)
    sign_in(client, "rita@lab.test")
    k = register(client)

    # Another person's key, an unknown key.
    assert client.get(f"/lanes/{lane}/receipt-payload", params={"key": ray_key.fingerprint}).status_code == 422
    assert client.get(f"/lanes/{lane}/receipt-payload", params={"key": "0" * 64}).status_code == 422
    # A payload that is not the canonical text, or says something else.
    spaced = lambda p: p.replace('{"chain"', '{ "chain"')                      # noqa: E731
    assert spaced('{"chain":1}') != '{"chain":1}'
    assert signed_close(client, lane, k, spaced).status_code == 422
    assert signed_close(client, lane, k, lambda p: json.dumps({**json.loads(p), "signer": {"id": ids["ray"], "name": "Ray"}},
                                                              sort_keys=True, separators=(",", ":"))).status_code == 422
    # A signature that does not verify.
    payload = client.get(f"/lanes/{lane}/receipt-payload", params={"key": k.fingerprint}).json()["payload"]
    r = client.post(f"/lanes/{lane}/close", json={"reviewed": True, "payload": payload, "key_fingerprint": k.fingerprint,
                                                  "signature": BrowserKey("Ed25519").sign(payload)})
    assert r.status_code == 422 and "does not verify" in r.json()["detail"]
    # The lane changed after the payload was issued.
    client.post(f"/lanes/{lane}/attach", json={"item_idx": 1, "kind": "note", "text": "one more check"})
    r = client.post(f"/lanes/{lane}/close", json={"reviewed": True, "payload": payload, "key_fingerprint": k.fingerprint,
                                                  "signature": k.sign(payload)})
    assert r.status_code == 422 and "changed" in r.json()["detail"]
    # Too old.
    p = json.loads(client.get(f"/lanes/{lane}/receipt-payload", params={"key": k.fingerprint}).json()["payload"])
    p["issued_at"] = "2020-01-01T00:00:00+00:00"
    old = json.dumps(p, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    r = client.post(f"/lanes/{lane}/close", json={"reviewed": True, "payload": old, "key_fingerprint": k.fingerprint,
                                                  "signature": k.sign(old)})
    assert r.status_code == 422 and "too old" in r.json()["detail"]
    # A revoked key signs nothing new.
    kid = next(x["id"] for x in client.get("/auth/keys").json() if x["fingerprint"] == k.fingerprint)
    assert client.post(f"/auth/keys/{kid}/revoke").json()["revoked"] is True
    assert client.get(f"/lanes/{lane}/receipt-payload", params={"key": k.fingerprint}).status_code == 422
    # Keys are personal: you cannot revoke someone else's.
    ray_id = None
    sign_in(client, "ray@lab.test")
    ray_id = client.get("/auth/keys").json()[0]["id"]
    sign_in(client, "rita@lab.test")
    assert client.post(f"/auth/keys/{ray_id}/revoke").status_code == 404


def test_required_signatures(client):
    e, lane, ids = setup(client)
    client.patch(f"/engagements/{e}", json={"require_signatures": True})
    sign_in(client, "rita@lab.test")
    r = client.post(f"/lanes/{lane}/close", json={"reviewed": True})
    assert r.status_code == 422 and "requires signed receipts" in r.json()["detail"]
    k = register(client)
    assert signed_close(client, lane, k).status_code == 200


def test_keys_need_a_person_and_a_valid_key(client, monkeypatch):
    monkeypatch.setenv("ATTACKLEDGER_API_TOKEN", "tok-1")
    h = {"authorization": "Bearer tok-1"}
    assert client.post("/auth/keys", headers=h, json={"algorithm": "Ed25519", "public_key": BrowserKey("Ed25519").spki}).status_code == 422
    monkeypatch.delenv("ATTACKLEDGER_API_TOKEN")
    setup(client)
    sign_in(client, "rita@lab.test")
    assert client.post("/auth/keys", json={"algorithm": "RSA", "public_key": BrowserKey("Ed25519").spki}).status_code == 422
    assert client.post("/auth/keys", json={"algorithm": "Ed25519", "public_key": "bm90IGEga2V5"}).status_code == 422
    k = BrowserKey("Ed25519")
    assert client.post("/auth/keys", json={"algorithm": "Ed25519", "public_key": k.spki}).status_code == 201
    assert client.post("/auth/keys", json={"algorithm": "Ed25519", "public_key": k.spki}).status_code == 409


def run_verifier(tmp_path, report, *flags):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))
    import contextlib
    import io
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = verifier.main(["verify_report.py", str(path), *flags])
    return code, out.getvalue()


def test_verifier_skips_signatures_when_none_are_signed(client, tmp_path, monkeypatch):
    monkeypatch.delenv("ATTACKLEDGER_TSA_URL", raising=False)
    e, lane, _ = setup(client)
    assert client.post(f"/lanes/{lane}/close", json={"reviewed": True}).status_code == 200
    report = client.get(f"/engagements/{e}/report").json()
    code, out = run_verifier(tmp_path, report)
    assert code == 0 and "Verified." in out and "1 receipted lane," in out
    assert "SKIP  Receipt signatures (0 of 1 receipt signed)" in out
    assert "SKIP  Receipt timestamps (0 of 1 receipt timestamped)" in out
    assert "PASS  Receipt signatures" not in out and "PASS  Receipt timestamps" not in out
    code, out = run_verifier(tmp_path, report, "--require-signatures")
    assert code == 1 and "FAIL  Receipt signatures" in out and "the receipt is not signed" in out


def test_verifier_passes_signed_receipts_and_skips_without_receipts(client, tmp_path, monkeypatch):
    monkeypatch.delenv("ATTACKLEDGER_TSA_URL", raising=False)
    e, lane, _ = setup(client)
    code, out = run_verifier(tmp_path, client.get(f"/engagements/{e}/report").json(), "--require-signatures")
    assert code == 0 and "SKIP  Receipt signatures (no receipts)" in out
    sign_in(client, "rita@lab.test")
    assert signed_close(client, lane, register(client)).status_code == 200
    report = client.get(f"/engagements/{e}/report").json()
    for flags in ((), ("--require-signatures",)):
        code, out = run_verifier(tmp_path, report, *flags)
        assert code == 0 and "PASS  Receipt signatures" in out and "SKIP  Receipt timestamps" in out
    report["format"] = "attackledger-report/1"
    report["integrity"]["body_sha256"] = verifier.sha(verifier.canonical(
        {k: v for k, v in report.items() if k != "integrity"}))
    code, out = run_verifier(tmp_path, report, "--require-signatures")
    assert code == 1 and "carries no signatures" in out
