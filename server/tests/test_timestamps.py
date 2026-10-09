"""RFC 3161 timestamps: the request, the server's checks, and the offline verifier.

The timestamp authority here is OpenSSL's own (`openssl ts -reply`), so the request
encoding and the token parsing are checked against an independent implementation, and
`openssl ts -verify` cross-checks the tokens the verifier accepts.
"""
import base64
import copy
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import httpx
import pytest

from app import timestamps
from test_signing import client, register, setup, sign_in, signed_close, verifier  # noqa: F401 (fixture)

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="needs the openssl command")


def run(*args, cwd, data=None):
    p = subprocess.run(["openssl", *args], cwd=cwd, input=data, capture_output=True)
    assert p.returncode == 0, p.stderr.decode()
    return p.stdout


class TSA:
    """A throwaway timestamp authority: root CA, intermediate CA and TSA certificate."""

    def __init__(self, d: Path, kind: str, inter_is_ca=True, tsa_dates=("-days", "20"), chain_has_root=False):
        self.d = d
        self.chain = "chain.pem" if chain_has_root else "inter.pem"
        keys = {"rsa": (["-newkey", "rsa:2048"], ["-newkey", "rsa:2048"], ["-newkey", "rsa:2048"]),
                "ec": (["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"],
                       ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-384"],
                       ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-384"])}[kind]
        (d / "ca.ext").write_text("basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
                                  "subjectKeyIdentifier=hash\n" if inter_is_ca else
                                  "basicConstraints=CA:FALSE\nsubjectKeyIdentifier=hash\n")
        (d / "tsa.ext").write_text("basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                                   "extendedKeyUsage=critical,timeStamping\nsubjectKeyIdentifier=hash\n")
        run("req", "-x509", *keys[0], "-nodes", "-keyout", "root.key", "-out", "root.pem", "-days", "30",
            "-subj", f"/CN=Test {kind} root", "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign", cwd=d)
        for name, key, issuer, ext, dates in (("inter", keys[1], "root", "ca.ext", ("-days", "20")),
                                              ("tsa", keys[2], "inter", "tsa.ext", tsa_dates)):
            run("req", *key, "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.csr",
                "-subj", f"/CN=Test {kind} {name}", cwd=d)
            run("x509", "-req", "-in", f"{name}.csr", "-CA", f"{issuer}.pem", "-CAkey", f"{issuer}.key",
                "-CAcreateserial", "-out", f"{name}.pem", *dates, "-extfile", ext, cwd=d)
        (d / "tsaserial").write_text("01\n")
        (d / "ts.cnf").write_text(f"""[ tsa ]
default_tsa = t
[ t ]
dir = {d}
serial = $dir/tsaserial
crypto_device = builtin
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_alg = sha256
""")
        self.root = str(d / "root.pem")
        (d / "chain.pem").write_text((d / "inter.pem").read_text() + (d / "root.pem").read_text())
        self.status = None

    def reply(self, query: bytes) -> bytes:
        (self.d / "q.der").write_bytes(query)
        run("ts", "-reply", "-config", "ts.cnf", "-queryfile", "q.der", "-signer", "tsa.pem",
            "-inkey", "tsa.key", "-chain", self.chain, "-out", "r.der", cwd=self.d)
        return (self.d / "r.der").read_bytes()

    def post(self, url, body):
        return self.reply(body)


@pytest.fixture(params=["rsa", "ec"])
def tsa(request, tmp_path):
    return TSA(tmp_path, request.param)


def receipt_report(token_b64, when, manifest="ab" * 32, signature="c2lnbmF0dXJl"):
    """The smallest report the timestamp check reads."""
    return {"lanes": [{"lane_id": 1, "host": "shop.lab.test", "name": "Recon", "status": "closed",
                       "receipt": {"manifest_sha256": manifest, "signature": {"value": signature},
                                   "timestamp": {"tsa": "test", "time": when.isoformat(), "token": token_b64}}}]}


def test_request_is_what_openssl_reads(tmp_path):
    digest = hashlib.sha256(b"x").digest()
    (tmp_path / "q.der").write_bytes(timestamps.request(digest, 0x1234567890))
    text = run("ts", "-query", "-in", "q.der", "-text", cwd=tmp_path).decode()
    assert "Hash Algorithm: sha256" in text and "Certificate required: yes" in text
    assert "0x1234567890" in text.replace(" ", "") or "1234567890" in text
    assert digest.hex()[:8] in text.replace(" ", "").replace("-", "").lower()


def test_token_verifies_offline_and_tampering_is_caught(tsa, monkeypatch):
    monkeypatch.setattr(timestamps, "POST", tsa.post)
    stmt = timestamps.statement("ab" * 32, "c2lnbmF0dXJl")
    token, when = timestamps.fetch("http://tsa.test", stmt)

    # OpenSSL agrees the token is valid for these bytes and this root.
    (tsa.d / "stmt").write_bytes(stmt)
    (tsa.d / "tok.der").write_bytes(base64.b64decode(token))
    run("ts", "-verify", "-data", "stmt", "-in", "tok.der", "-token_in", "-CAfile", "root.pem",
        "-untrusted", "inter.pem", cwd=tsa.d)

    roots = verifier.load_roots([tsa.root])
    report = receipt_report(token, when)
    problems, notes = verifier.check_timestamps(report, roots)
    assert problems == [] and any("timestamped" in n and "tsa" in n for n in notes), (problems, notes)

    # Not trusted: no roots, or someone else's root.
    assert any("--tsa-root" in p for p in verifier.check_timestamps(report, [])[0])
    (tsa.d / "other").mkdir()
    other = TSA(tsa.d / "other", "rsa")
    assert verifier.check_timestamps(report, verifier.load_roots([other.root]))[0]

    # The token belongs to a different receipt: another manifest, or another signature.
    for bad in (receipt_report(token, when, manifest="cd" * 32), receipt_report(token, when, signature="b3RoZXI=")):
        assert any("different receipt" in p for p in verifier.check_timestamps(bad, roots)[0])

    # The report shows a time the token does not say.
    bad = copy.deepcopy(report)
    bad["lanes"][0]["receipt"]["timestamp"]["time"] = "2020-01-01T00:00:00+00:00"
    assert any("not the token's time" in p for p in verifier.check_timestamps(bad, roots)[0])

    # Any change to the token's signed content or signature.
    raw = bytearray(base64.b64decode(token))
    t = verifier.read_token(bytes(raw))
    at = bytes(raw).find(t["econtent"]) + len(t["econtent"]) - 3      # inside TSTInfo
    for pos in (at, len(raw) - 5):                                     # TSTInfo, then the signature
        bad_raw = bytearray(raw)
        bad_raw[pos] ^= 1
        bad = receipt_report(base64.b64encode(bytes(bad_raw)).decode(), when)
        assert verifier.check_timestamps(bad, roots)[0], pos


def test_chain_rules(tmp_path, monkeypatch):
    """An issuer that is not a CA, a TSA certificate not valid at the token's time, and a
    certificate without the timestamping purpose are each refused."""
    def token_from(t):
        monkeypatch.setattr(timestamps, "POST", t.post)
        stmt = timestamps.statement("ab" * 32, "c2lnbmF0dXJl")
        return receipt_report(*timestamps.fetch("http://tsa.test", stmt)), verifier.load_roots([t.root])

    for sub, opts, why in (("noca", {"inter_is_ca": False}, "is not a certificate authority"),
                           ("future", {"tsa_dates": ("-not_before", "20990101000000Z",
                                                     "-not_after", "20991231000000Z")}, "was not valid")):
        (tmp_path / sub).mkdir()
        report, roots = token_from(TSA(tmp_path / sub, "rsa", **opts))
        problems = verifier.check_timestamps(report, roots)[0]
        assert any(why in p for p in problems), (sub, problems)

    # A token can carry its own root; carrying it does not make it trusted.
    (tmp_path / "own").mkdir()
    report, roots = token_from(TSA(tmp_path / "own", "rsa", chain_has_root=True))
    assert verifier.check_timestamps(report, roots)[0] == []
    assert any("which you have not trusted" in p for p in verifier.check_timestamps(report, [])[0])

    (tmp_path / "ok").mkdir()
    report, roots = token_from(TSA(tmp_path / "ok", "ec"))
    assert verifier.check_timestamps(report, roots)[0] == []
    real = verifier.parse_cert
    monkeypatch.setattr(verifier, "parse_cert", lambda der: {**real(der), "eku": ["1.3.6.1.5.5.7.3.3"]})
    assert any("not a timestamping certificate" in p for p in verifier.check_timestamps(report, roots)[0])


def test_rsa_padding_is_checked_exactly():
    """PKCS #1 v1.5: the whole encoded block must match, not only the digest at its end."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    msg, sha256_rsa = b"statement", "1.2.840.113549.1.1.11"
    good = key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
    assert verifier.verify_with_key(spki, sha256_rsa, None, msg, good)
    assert not verifier.verify_with_key(spki, sha256_rsa, None, msg + b"!", good)
    n, d = key.public_key().public_numbers().n, key.private_numbers().d
    t = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(msg).digest()
    for em in (b"\x00\x02" + b"\x11" * (256 - len(t) - 3) + b"\x00" + t,        # wrong block type
               b"\x00\x01" + b"\xff" * 8 + b"\x00" + b"\x42" * (256 - len(t) - 11) + t):  # garbage before it
        forged = pow(int.from_bytes(em, "big"), d, n).to_bytes(256, "big")
        assert not verifier.verify_with_key(spki, sha256_rsa, None, msg, forged)


def test_server_refuses_replies_for_other_requests(tsa, monkeypatch):
    stmt = timestamps.statement("ab" * 32, None)
    # A reply for a different hash.
    monkeypatch.setattr(timestamps, "POST", lambda url, body: tsa.reply(
        timestamps.request(hashlib.sha256(b"other").digest(), 7)))
    with pytest.raises(timestamps.TimestampError, match="something else"):
        timestamps.fetch("http://tsa.test", stmt)
    # A reply for the same hash but another nonce (a replayed answer).
    monkeypatch.setattr(timestamps, "POST", lambda url, body: tsa.reply(
        timestamps.request(hashlib.sha256(stmt).digest(), 7)))
    with pytest.raises(timestamps.TimestampError, match="nonce"):
        timestamps.fetch("http://tsa.test", stmt)
    # A refusal, and something that is not a reply.
    refused = timestamps._tlv(0x30, timestamps._tlv(0x30, timestamps._int(2)))
    for reply, why in ((refused, "refused"), (b"<html>", "cannot be read")):
        monkeypatch.setattr(timestamps, "POST", lambda url, body, r=reply: r)
        with pytest.raises(timestamps.TimestampError, match=why):
            timestamps.fetch("http://tsa.test", stmt)


def test_signed_close_is_timestamped_end_to_end(client, tsa, monkeypatch, tmp_path):
    monkeypatch.setenv("ATTACKLEDGER_TSA_URL", "http://tsa.test/")
    monkeypatch.setattr(timestamps, "POST", tsa.post)
    e, lane, _ = setup(client)
    assert client.get("/health").json()["timestamps"] is True
    sign_in(client, "rita@lab.test")
    k = register(client)
    assert signed_close(client, lane, k).status_code == 200
    rc = client.get(f"/lanes/{lane}").json()["receipt"]
    assert rc["timestamp"]["tsa"] == "http://tsa.test/" and rc["timestamp_error"] is None

    report = client.get(f"/engagements/{e}/report").json()
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))
    assert verifier.main(["verify", str(path), "--tsa-root", tsa.root]) == 0
    assert verifier.main(["verify", str(path)]) == 1                 # the test root is not trusted


def test_unreachable_tsa_keeps_the_receipt_and_can_retry(client, tsa, monkeypatch):
    monkeypatch.setenv("ATTACKLEDGER_TSA_URL", "http://tsa.test/")

    def down(url, body):
        raise httpx.ConnectError("no route")
    monkeypatch.setattr(timestamps, "POST", down)
    e, lane, _ = setup(client)
    sign_in(client, "rita@lab.test")
    k = register(client)
    assert signed_close(client, lane, k).status_code == 200
    rc = client.get(f"/lanes/{lane}").json()["receipt"]
    assert rc["timestamp"] is None and "did not answer" in rc["timestamp_error"]
    assert client.post(f"/lanes/{lane}/receipt/timestamp").status_code == 502

    monkeypatch.setattr(timestamps, "POST", tsa.post)
    r = client.post(f"/lanes/{lane}/receipt/timestamp")
    assert r.status_code == 200 and r.json()["receipt"]["timestamp"] and r.json()["receipt"]["timestamp_error"] is None
    assert client.post(f"/lanes/{lane}/receipt/timestamp").status_code == 409
    report = client.get(f"/engagements/{e}/report").json()
    assert verifier.check_timestamps(report, verifier.load_roots([tsa.root]))[0] == []

    monkeypatch.delenv("ATTACKLEDGER_TSA_URL")
    assert client.post(f"/lanes/{lane}/receipt/timestamp").status_code == 422


def test_no_tsa_means_no_timestamp_and_no_traffic(client, monkeypatch):
    monkeypatch.delenv("ATTACKLEDGER_TSA_URL", raising=False)

    def never(url, body):
        raise AssertionError("no timestamp authority is set, so nothing may be sent")
    monkeypatch.setattr(timestamps, "POST", never)
    e, lane, _ = setup(client)
    sign_in(client, "rita@lab.test")
    assert signed_close(client, lane, register(client)).status_code == 200
    rc = client.get(f"/lanes/{lane}").json()["receipt"]
    assert rc["timestamp"] is None and rc["timestamp_error"] is None
    problems, notes = verifier.check_timestamps(client.get(f"/engagements/{e}/report").json(), [])
    assert problems == [] and any("not timestamped" in n for n in notes)
