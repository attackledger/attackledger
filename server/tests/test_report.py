import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "server"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_ledger import client, h, resolve_all  # noqa: F401  (fixture + helpers)

spec = importlib.util.spec_from_file_location("verify_report", ROOT / "tools" / "verify_report.py")
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


def build(c):
    eng = c.post("/engagements", json={"name": "Report test", "pack_id": "web-pentest-wstg"}).json()["id"]
    a = c.post(f"/engagements/{eng}/assets", json={"host": "app.example.com"}).json()
    info = c.post("/lanes", json={"asset_id": a["id"], "role": "info"}).json()
    resolve_all(c, info)
    c.post(f"/lanes/{info['id']}/close")
    conf = c.post("/lanes", json={"asset_id": a["id"], "role": "conf"}).json()
    c.post(f"/lanes/{conf['id']}/evidence", json={
        "item_idx": 1, "kind": "note", "sha256": h("x"),
        "summary": "</script><script>alert(1)</script> & <b>bold</b>"})
    return eng, info["id"]


def rehash(r):
    body = {k: v for k, v in r.items() if k != "integrity"}
    r["integrity"]["body_sha256"] = verify.sha(verify.canonical(body))
    return r


def problems(r):
    return verify.check_body(r) + verify.check_chain(r) + verify.check_receipts(r)[0]


def test_report_verifies(client, tmp_path):
    eng, _ = build(client)
    r = client.get(f"/engagements/{eng}/report").json()
    assert problems(r) == []
    assert r["summary"]["lanes_receipted"] == 1 and r["summary"]["evidence_entries"] == 11
    p = tmp_path / "r.json"
    p.write_text(json.dumps(r))
    assert verify.main(["v", str(p)]) == 0


def test_html_report_embeds_verifiable_bundle_and_escapes_text(client, tmp_path):
    eng, _ = build(client)
    resp = client.get(f"/engagements/{eng}/report.html")
    assert "script-src" not in resp.headers["content-security-policy"]
    assert resp.headers["content-security-policy"].startswith("default-src 'none'")
    text = resp.text
    assert "<script>alert(1)</script>" not in text
    assert text.count("</script>") == 1  # only the closing tag of the JSON bundle
    p = tmp_path / "r.html"
    p.write_text(text)
    assert verify.main(["v", str(p)]) == 0


def test_editing_evidence_is_detected_even_if_body_hash_is_redone(client):
    eng, _ = build(client)
    r = client.get(f"/engagements/{eng}/report").json()
    t = copy.deepcopy(r)
    t["evidence"][0]["summary"] = "something else"
    assert verify.check_body(t)                  # body hash catches a naive edit
    rehash(t)
    assert verify.check_body(t) == []
    assert verify.check_chain(t)                 # the chain still catches it


def test_deleting_evidence_breaks_the_chain(client):
    eng, _ = build(client)
    t = copy.deepcopy(client.get(f"/engagements/{eng}/report").json())
    del t["evidence"][3]
    rehash(t)
    assert any("sequence" in p or "link" in p for p in verify.check_chain(t))


def test_rewriting_the_whole_chain_still_breaks_the_receipt(client):
    eng, info_id = build(client)
    t = copy.deepcopy(client.get(f"/engagements/{eng}/report").json())
    # Attacker swaps an evidence hash and recomputes the entire chain and body.
    victim = next(e for e in t["evidence"] if e["lane_id"] == info_id)
    victim["sha256"] = hashlib.sha256(b"forged").hexdigest()
    prev = verify.GENESIS
    for e in t["evidence"]:
        e["prev_hash"] = prev
        e["chain_hash"] = verify.sha(prev + verify.canonical({k: e[k] for k in verify.CHAIN_FIELDS}))
        prev = e["chain_hash"]
    t["summary"]["chain_head"] = prev
    rehash(t)
    assert verify.check_body(t) == [] and verify.check_chain(t) == []
    assert any("receipt does not match" in p for p in verify.check_receipts(t)[0])


def test_promoting_an_open_lane_to_receipted_is_detected(client):
    eng, _ = build(client)
    t = copy.deepcopy(client.get(f"/engagements/{eng}/report").json())
    conf = next(l for l in t["lanes"] if l["role"] == "conf")
    conf["status"] = "closed"
    rehash(t)
    assert any("no receipt" in p for p in verify.check_receipts(t)[0])


def test_api_evidence_is_chained(client):
    eng, _ = build(client)
    ev = client.get(f"/engagements/{eng}/report").json()["evidence"]
    assert [e["seq"] for e in ev] == list(range(1, len(ev) + 1))
    assert ev[0]["prev_hash"] == verify.GENESIS
    assert all(ev[i]["prev_hash"] == ev[i - 1]["chain_hash"] for i in range(1, len(ev)))
