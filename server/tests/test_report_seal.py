"""Report seals (D-055, docs/security-review/EVIDENCE.md O-2): the server signs every report it
exports, over the body hash and the heads of the audit log and the key log, with its own Ed25519
key, registered in the key log. A void (or any entry) recorded after the newest receipt signature
can no longer be left out: the seal no longer matches, and strict mode requires a seal.
"""
import base64
import copy
import hashlib
import json
import os
import stat

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import select

from app import keylog, people, seal, timestamps, vault
from app.models import KeyLogEntry
from test_keytrust import env, register, sign_in, signed_close  # noqa: F401  (env is a fixture)
from test_security_verifier import hide_the_void, rehash, report_of, reseal, run, two_items, void_then_sign_another
from test_signing import verifier
from test_timestamps import TSA


def payload(r: dict) -> dict:
    return json.loads(r["integrity"]["seal"]["payload"])


def other_seal(r: dict, key: ed25519.Ed25519PrivateKey) -> dict:
    """The report sealed as seal.seal does, but with another key: another instance's, or a forger's."""
    r = rehash(copy.deepcopy(r))
    spki = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.DER,
                                                          serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    fp = hashlib.sha256(base64.b64decode(spki)).hexdigest()
    text = seal.payload_for(r, fp, payload(r)["sealed_at"])
    r["integrity"]["seal"] = {"algorithm": "Ed25519", "public_key": spki, "key_fingerprint": fp, "payload": text,
                              "value": base64.b64encode(key.sign(text.encode())).decode()}
    return r


def test_exported_reports_are_sealed_over_the_body_and_both_heads(env, tmp_path):
    c, Session = env
    e, L, _, _ = two_items(c)
    r = report_of(c, e)
    sl, p = r["integrity"]["seal"], payload(r)
    assert sl["algorithm"] == "Ed25519" and "timestamp" not in sl          # no timestamp authority set here
    assert p["format"] == "attackledger-seal-v1" and p["engagement"]["id"] == e
    assert p["report_sha256"] == r["integrity"]["body_sha256"] == verifier.sha(
        verifier.canonical({k: v for k, v in r.items() if k != "integrity"}))
    assert p["history"] == {"audit": {"seq": r["audit_log"]["head"]["seq"], "head": r["audit_log"]["head"]["entry_hash"]},
                            "key_log": {"seq": r["key_log"]["head"]["seq"], "head": r["key_log"]["head"]["entry_hash"]}}
    assert seal.payload_for(r, sl["key_fingerprint"], p["sealed_at"]) == sl["payload"]   # canonical
    # Its key is registered in the key log as the instance's, before the receipt was signed.
    reg = next(x for x in r["key_log"]["entries"] if x["key_fingerprint"] == sl["key_fingerprint"])
    assert (reg["via"], reg["user_id"], reg["user_name"], reg["event"]) == ("instance", None, keylog.INSTANCE_NAME,
                                                                             "registered")
    signed_head = json.loads(next(l for l in r["lanes"] if l["lane_id"] == L)["receipt"]["signature"]["payload"])
    assert reg["seq"] <= signed_head["history"]["key_log"]["seq"]
    with Session() as s:
        assert keylog.verify(s) == []
    for flags in ((), ("--require-history",)):
        code, out = run(tmp_path, r, *flags)
        assert code == 0 and "PASS  Report seal" in out, out
    assert "NOTE  sealed " in out and f"with the server's seal key {sl['key_fingerprint'][:16]} (Ed25519)" in out
    assert "and a receipt signature covers that entry" in out
    assert "NOTE  the seal is not timestamped, so its time is the server's clock" in out
    assert "as far as the report's seal shows, up to entry #" in out

    # Each export is sealed anew; the key is registered once per organization.
    again = c.get(f"/engagements/{e}/report").json()
    assert again["integrity"]["seal"]["key_fingerprint"] == sl["key_fingerprint"]
    with Session() as s:
        rows = s.scalars(select(KeyLogEntry).where(KeyLogEntry.via == "instance")).all()
        assert len(rows) == 1


def test_a_report_with_an_entry_left_out_fails_the_seal_in_every_mode(env, tmp_path):
    c, _ = env
    report, A = void_then_sign_another(c, later=False)         # the void after the last signature
    forged = hide_the_void(report, A)
    for flags in ((), ("--require-history",)):
        code, out = run(tmp_path, forged, *flags)
        assert code == 1 and "FAIL  Report seal" in out
    # The heads, too: a log cut after the newest signature, sealed heads kept.
    cut = copy.deepcopy(report)
    log = cut["audit_log"]
    log["links"], log["entries"] = log["links"][:-1], [x for x in log["entries"] if x["seq"] < log["links"][-1]["seq"]]
    log["head"] = {"seq": log["links"][-1]["seq"], "entry_hash": log["links"][-1]["entry_hash"]}
    problems = verifier.check_seal(rehash(cut), [])[0]
    assert any("the change history in this report ends at entry #" in x for x in problems), problems


def test_a_tampered_seal_fails(env, tmp_path):
    c, _ = env
    e, _, _, _ = two_items(c)
    r = report_of(c, e)

    def problems(change):
        bad = copy.deepcopy(r)
        change(bad["integrity"]["seal"])
        return verifier.check_seal(bad, [])[0]
    flip = bytearray(base64.b64decode(r["integrity"]["seal"]["value"]))
    flip[5] ^= 1
    assert problems(lambda sl: sl.__setitem__("value", base64.b64encode(bytes(flip)).decode())) == [
        "the seal's signature does not verify"]
    assert "the seal's signature does not verify" in problems(
        lambda sl: sl.__setitem__("payload", sl["payload"].replace('"sealed_at":"', '"sealed_at":"1')))
    assert problems(lambda sl: sl.__setitem__("public_key", "not base64!")) == ["the seal's fields cannot be read"]
    assert "the seal's public key does not match its fingerprint" in problems(
        lambda sl: sl.__setitem__("key_fingerprint", "0" * 64))
    # Moved to another engagement's report: the body hash and the engagement differ.
    other = copy.deepcopy(r)
    other["engagement"]["id"] += 1
    found = verifier.check_seal(rehash(other), [])[0]
    assert "the seal names another engagement" in found and any("not the one that was sealed" in x for x in found)


def test_a_seal_from_another_instance_key_fails(env, tmp_path):
    c, _ = env
    e, _, _, _ = two_items(c)
    r = report_of(c, e)
    forged = other_seal(r, ed25519.Ed25519PrivateKey.generate())
    code, out = run(tmp_path, forged)
    assert code == 1 and "FAIL  Report seal" in out
    assert "does not register the seal's key" in out and "as the server's seal key" in out
    # A forger who also adds a registration of their key to the end of the key log: the receipt
    # signed over the key log head before it, so their key is not bound, and the NOTE says so.
    key = ed25519.Ed25519PrivateKey.generate()
    forged = other_seal(r, key)
    fp = forged["integrity"]["seal"]["key_fingerprint"]
    kl = forged["key_log"]
    last = kl["links"][-1]
    rec = {"seq": last["seq"] + 1, "user_id": None, "user_name": keylog.INSTANCE_NAME, "key_fingerprint": fp,
           "algorithm": "Ed25519", "event": "registered", "at": kl["entries"][-1]["at"], "via": "instance"}
    rsha = verifier.sha(verifier.canonical(rec))
    eh = verifier.sha(last["entry_hash"] + rsha)
    kl["links"].append({"seq": rec["seq"], "prev_hash": last["entry_hash"], "record_sha256": rsha, "entry_hash": eh})
    kl["entries"] = [x for x in kl["entries"] if x["via"] != "instance"] + [rec]
    kl["head"] = {"seq": rec["seq"], "entry_hash": eh}
    forged = other_seal(forged, key)
    code, out = run(tmp_path, forged)
    assert code == 0, out
    assert "and no receipt signature covers that entry, so only its fingerprint" in out
    assert "and a receipt signature covers that entry" in run(tmp_path, r)[1]


def test_unsealed_reports_verify_with_a_note_and_fail_strict_mode(env, tmp_path):
    c, _ = env
    e, _, _, _ = two_items(c)
    old = copy.deepcopy(report_of(c, e))
    del old["integrity"]["seal"]
    code, out = run(tmp_path, old)
    assert code == 0 and "Report seal" not in out.split("NOTE", 1)[0]
    assert "NOTE  this report is not sealed (made before report seals)" in out
    code, out = run(tmp_path, old, "--require-history")
    assert code == 1 and "FAIL  Report seal" in out and "this report is not sealed, which --require-history requires" in out
    assert "would not be detected" in out          # the receipts alone bind no later entry
    fmt1 = rehash({**copy.deepcopy(old), "format": "attackledger-report/1"})
    assert "this report format carries no seal" in run(tmp_path, fmt1, "--require-history")[1]


def test_the_seal_key_is_kept_like_a_data_key(env, monkeypatch):
    c, _ = env
    e, _, _, _ = two_items(c)
    report_of(c, e)
    path = vault.seal_key_path()
    doc = json.loads(path.read_text())
    assert doc["format"] == "attackledger-seal-key/1" and doc["master_key_id"] == vault.master_key().id
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    private = vault.seal_key()
    assert len(private) == 32 and base64.b64encode(private).decode() not in path.read_text()
    fp = seal.public_key()["key_fingerprint"]
    other = base64.b64encode(b"\x01" * 32).decode()
    monkeypatch.setenv("ATTACKLEDGER_MASTER_KEY", other)
    with pytest.raises(vault.StoreError, match="report seal key"):
        vault.check_store()
    with pytest.raises(vault.StoreError, match="another master key"):
        vault.seal_key()
    assert vault.rotate_master(vault.DEV_KEY)["seal_key"] == "rewrapped"
    vault.check_store()
    assert seal.public_key()["key_fingerprint"] == fp                   # the same key, wrapped anew
    assert vault.rotate_master(vault.DEV_KEY)["seal_key"] == "already"


def test_the_seal_is_timestamped_when_a_tsa_is_set(env, tmp_path, monkeypatch):
    c, _ = env
    tsa = TSA(tmp_path, "ec")
    e, _, _, _ = two_items(c)
    monkeypatch.setenv("ATTACKLEDGER_TSA_URL", "http://tsa.test/")
    sent = []
    monkeypatch.setattr(timestamps, "POST", lambda url, body: sent.append(body) or tsa.post(url, body))
    r = report_of(c, e)
    ts = r["integrity"]["seal"]["timestamp"]
    assert ts["tsa"] == "http://tsa.test/" and len(sent) == 1
    roots = verifier.load_roots([tsa.root])
    assert verifier.check_seal(r, roots)[0] == []
    assert any(n.startswith("the seal was timestamped ") for n in verifier.check_seal(r, roots)[1])
    assert any("the seal's timestamp: " in x for x in verifier.check_seal(r, [])[0])      # the test root not trusted
    # The token covers this seal: another statement, or a time moved, fails.
    moved = copy.deepcopy(r)
    moved["integrity"]["seal"]["timestamp"]["time"] = "2020-01-01T00:00:00+00:00"
    assert "the time shown for the seal's timestamp is not the token's time" in verifier.check_seal(moved, roots)[0]
    receipt_token = copy.deepcopy(r)
    tsa_token, _ = timestamps.fetch("http://tsa.test/", b"something else")
    receipt_token["integrity"]["seal"]["timestamp"]["token"] = tsa_token
    assert "the seal's timestamp covers something else" in verifier.check_seal(receipt_token, roots)[0]
    page = c.get(f"/engagements/{e}/report.html").text
    assert "Report sealed" in page and "Seal timestamp" in page and "by tsa.test" in page

    # An authority that does not answer: the report is still sealed, without a timestamp.
    def down(url, body):
        raise httpx.ConnectError("no route")
    monkeypatch.setattr(timestamps, "POST", down)
    r = c.get(f"/engagements/{e}/report").json()
    assert "timestamp" not in r["integrity"]["seal"] and verifier.check_seal(r, roots)[0] == []


def test_a_sealed_html_report_says_so(env, tmp_path):
    c, _ = env
    e, _, _, _ = two_items(c)
    sign_in(c, "owner@lab.test")
    page = c.get(f"/engagements/{e}/report.html").text
    assert "Report sealed" in page and "Seal key" in page and "What the seal says" in page
    code, out = run(tmp_path, None, name="r.html", text=page)
    assert code == 0 and "PASS  Report seal" in out
    assert "  Sealed: " in out.split(verifier.FACTS_TITLE, 1)[1]


def test_reseal_helper_is_the_servers_seal(env, tmp_path):
    """reseal (used by the tests above) seals with the server's own key, as an export does."""
    c, _ = env
    e, _, _, _ = two_items(c)
    r = report_of(c, e)
    again = reseal(copy.deepcopy(r))
    assert again["integrity"]["seal"]["key_fingerprint"] == r["integrity"]["seal"]["key_fingerprint"]
    assert run(tmp_path, again, "--require-history")[0] == 0


def test_the_operator_cli_lists_the_seal_key(env, capsys):
    c, _ = env
    e, _, _, _ = two_items(c)
    fp = report_of(c, e)["integrity"]["seal"]["key_fingerprint"]
    capsys.readouterr()
    assert people.main(["key-log"]) == 0
    line = next(x for x in capsys.readouterr().out.splitlines() if fp[:16] in x)
    assert line.endswith(f"{keylog.INSTANCE_NAME}, {keylog.VIA['instance']}") and "(id None)" not in line
