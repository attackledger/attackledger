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


SIGN = {"closed_by": "test reviewer", "reviewed": True}


def build(c):
    eng = c.post("/engagements", json={"name": "Report test", "pack_id": "web-pentest-wstg"}).json()["id"]
    a = c.post(f"/engagements/{eng}/assets", json={"host": "app.example.com"}).json()
    info = c.post("/lanes", json={"asset_id": a["id"], "role": "info"}).json()
    resolve_all(c, info)
    c.post(f"/lanes/{info['id']}/close", json=SIGN)
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


def test_report_carries_the_receipt_signer(client):
    eng, info_id = build(client)
    r = client.get(f"/engagements/{eng}/report").json()
    lane = next(l for l in r["lanes"] if l["lane_id"] == info_id)
    assert lane["receipt"]["closed_by"] == "test reviewer"
    assert "test reviewer" in client.get(f"/engagements/{eng}/report.html").text


def test_html_report_has_the_client_sections_in_order(client):
    eng, info_id = build(client)
    r = client.get(f"/engagements/{eng}/report").json()
    assert [l["key"] for l in r["engagement"]["pack"]["lanes"]][:2] == ["info", "conf"]
    assert r["engagement"]["separation_of_duties"] is False and r["engagement"]["require_signatures"] is False
    page = client.get(f"/engagements/{eng}/report.html").text
    ids = ["summary", "scope", "coverage", "receipts", "verify", "controls", "items", "integrity"]
    pos = [page.index(f'<section id="{i}"') if f'<section id="{i}"' in page else page.index(f"<section id='{i}'")
           for i in ids]
    assert pos == sorted(pos)
    assert "Penetration test" in page and "attackledger-report/2" in page and "Web application pentest" in page
    # Summary: tiles and what the report does and does not prove.
    assert "1 of 2" in page and "Items with evidence" in page and "does not prove" in page
    # Matrix: the receipted lane, the open one and the pack's other lanes.
    matrix = page[page.index('id="coverage"'):page.index('id="receipts"')]
    assert matrix.count("st-closed'>Receipted") == 2        # legend + info lane
    assert "st-open'>In progress" in matrix and matrix.count("Not opened") == 1 + 10
    assert "1 of 12" in matrix
    # Receipts: the full manifest hash, the signer, and that it is not signed or timestamped.
    lane = next(l for l in r["lanes"] if l["lane_id"] == info_id)
    receipts = page[page.index('id="receipts"'):page.index('id="verify"')]
    assert lane["receipt"]["manifest_sha256"] in receipts and "test reviewer" in receipts
    assert "Name only, not signed" in receipts and "Not timestamped" in receipts
    # How to verify: the command and the pinned root.
    assert "python3 verify_report.py report.json --tsa-root &lt;root.pem&gt;" in page
    assert "tools/tsa-roots/digicert-trusted-root-g4.pem" in page and "552F7BDCF1A7AF9E" in page


def test_void_receipt_is_shown_as_void(client):
    eng, info_id = build(client)
    client.post(f"/lanes/{info_id}/evidence", json={"item_idx": 1, "kind": "note", "sha256": h("late"), "summary": "late"})
    r = client.get(f"/engagements/{eng}/report").json()
    assert r["summary"]["lanes_stale"] == 1
    page = client.get(f"/engagements/{eng}/report.html").text
    receipts = page[page.index('id="receipts"'):page.index('id="verify"')]
    assert "st-stale'>Void" in receipts and "ledger changed after this receipt" in receipts
    assert "1 receipt is void" in page


def test_html_report_escapes_every_database_string(client, tmp_path):
    from app import report
    bad = '"><script>alert(1)</script>'
    eng = client.post("/engagements", json={"name": "Acme " + bad, "pack_id": "web-pentest-wstg",
                                            "policy_url": "https://x.test/" + bad}).json()["id"]
    a = client.post(f"/engagements/{eng}/assets", json={"host": "app.example.com"}).json()
    lane = client.post("/lanes", json={"asset_id": a["id"], "role": "info"}).json()
    resolve_all(client, lane)
    client.post(f"/lanes/{lane['id']}/evidence", json={"item_idx": 1, "kind": "note", "sha256": h("y"), "summary": bad})
    assert client.post(f"/lanes/{lane['id']}/close", json={"closed_by": "Eve " + bad, "reviewed": True}).status_code == 200
    r = client.get(f"/engagements/{eng}/report").json()
    # Hosts and scope rules are normalized by the API; a report from another source may still carry anything.
    for x in r["hosts"] + r["lanes"] + r["evidence"]:
        x["host"] = "app.example.com" + bad
    r["engagement"]["scope"]["include"] = [bad]
    r["engagement"]["research_identification"]["header"] = "X-Id: " + bad
    for page in (client.get(f"/engagements/{eng}/report.html").text, report.render_html(r)):
        assert "<script>alert" not in page and '"><script' not in page
        assert page.count("<script") == 1 and page.count("</script>") == 1
        assert "&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;" in page
    page = report.render_html(r)
    for where in ("Acme ", "https://x.test/", "Eve ", "app.example.com", "X-Id: "):
        assert where + "&quot;&gt;&lt;script&gt;" in page, where
    p = tmp_path / "r.html"
    p.write_text(client.get(f"/engagements/{eng}/report.html").text)
    assert verify.main(["v", str(p)]) == 0
