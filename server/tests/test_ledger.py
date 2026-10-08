import hashlib
import os
import sys
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite://"
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import db
from app.main import app


@pytest.fixture()
def client():
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


def h(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def setup_asset(c):
    eng = c.post("/engagements", json={"name": "lab"}).json()
    asset = c.post(f"/engagements/{eng['id']}/assets", json={"host": "app.example.com"}).json()
    return eng["id"], asset["id"]


def resolve_all(c, lane):
    for item in lane["items"]:
        c.post(f"/lanes/{lane['id']}/evidence",
               json={"item_idx": item["idx"], "kind": "note", "sha256": h(item["text"]),
                     "summary": "recorded"})
        r = c.patch(f"/lanes/{lane['id']}/items/{item['idx']}", json={"state": "done"})
        assert r.status_code == 200, r.text


def test_model_gated_lane_needs_closed_mapper(client):
    _, asset_id = setup_asset(client)
    r = client.post("/lanes", json={"asset_id": asset_id, "role": "authz"})
    assert r.status_code == 422 and "Model" in r.json()["detail"]

    mapper = client.post("/lanes", json={"asset_id": asset_id, "role": "mapper"}).json()
    r = client.post("/lanes", json={"asset_id": asset_id, "role": "authz"})
    assert r.status_code == 422  # mapper open, not closed

    resolve_all(client, mapper)
    assert client.post(f"/lanes/{mapper['id']}/close").status_code == 200
    assert client.post("/lanes", json={"asset_id": asset_id, "role": "authz"}).status_code == 201


def test_done_requires_evidence_and_na_requires_reason(client):
    _, asset_id = setup_asset(client)
    lane = client.post("/lanes", json={"asset_id": asset_id, "role": "recon"}).json()
    assert client.patch(f"/lanes/{lane['id']}/items/1", json={"state": "done"}).status_code == 422
    assert client.patch(f"/lanes/{lane['id']}/items/1", json={"state": "na"}).status_code == 422
    r = client.patch(f"/lanes/{lane['id']}/items/1", json={"state": "na", "na_reason": "no API"})
    assert r.status_code == 200


def test_close_fails_while_items_open(client):
    _, asset_id = setup_asset(client)
    lane = client.post("/lanes", json={"asset_id": asset_id, "role": "recon"}).json()
    r = client.post(f"/lanes/{lane['id']}/close")
    assert r.status_code == 422
    assert client.get(f"/lanes/{lane['id']}").json()["status"] == "open"


def test_receipt_goes_stale_when_ledger_changes(client):
    _, asset_id = setup_asset(client)
    lane = client.post("/lanes", json={"asset_id": asset_id, "role": "recon"}).json()
    resolve_all(client, lane)
    assert client.post(f"/lanes/{lane['id']}/close").json()["status"] == "closed"

    client.post(f"/lanes/{lane['id']}/evidence",
                json={"kind": "note", "sha256": h("late"), "summary": "added after close"})
    assert client.get(f"/lanes/{lane['id']}").json()["status"] == "stale"


def test_coverage_counts_only_closed_cells(client):
    eng_id, asset_id = setup_asset(client)
    lane = client.post("/lanes", json={"asset_id": asset_id, "role": "recon"}).json()
    resolve_all(client, lane)
    client.post(f"/lanes/{lane['id']}/close")
    cov = client.get(f"/engagements/{eng_id}/coverage").json()
    assert cov["closed_cells"] == 1 and cov["total_cells"] == 7
    assert cov["assets"][0]["roles"]["mapper"]["status"] == "not_opened"
    recon = cov["assets"][0]["roles"]["recon"]
    assert recon["status"] == "closed" and len(recon["receipt"]) == 8
    assert client.get("/engagements").json()[0]["assets"] == 1


def test_out_of_scope_asset_cannot_open_lane(client):
    eng = client.post("/engagements", json={"name": "lab2"}).json()
    a = client.post(f"/engagements/{eng['id']}/assets",
                    json={"host": "cdn.example.net", "in_scope": False}).json()
    assert client.post("/lanes", json={"asset_id": a["id"], "role": "recon"}).status_code == 422


def ready_engagement(c, name="prog"):
    eng = c.post("/engagements", json={"name": name}).json()["id"]
    c.put(f"/engagements/{eng}/scope", json={"include": ["*.example.com", "example.com"],
                                             "exclude": ["status.example.com"]})
    return eng


def test_jobs_need_authorization_and_scope(client):
    eng = client.post("/engagements", json={"name": "noauth"}).json()["id"]
    r = client.post(f"/engagements/{eng}/jobs", json={"kind": "subdomains"})
    assert r.status_code == 422 and "authorization" in r.json()["detail"]

    client.post(f"/engagements/{eng}/attest",
                json={"operator": "op", "policy_url": "https://example.com/policy", "confirm": True})
    r = client.post(f"/engagements/{eng}/jobs", json={"kind": "subdomains"})
    assert r.status_code == 422 and "scope" in r.json()["detail"]


def test_attest_requires_confirmation_and_https_policy(client):
    eng = ready_engagement(client)
    assert client.post(f"/engagements/{eng}/attest", json={
        "operator": "op", "policy_url": "https://example.com/p", "confirm": False}).status_code == 422
    assert client.post(f"/engagements/{eng}/attest", json={
        "operator": "op", "policy_url": "http://example.com/p", "confirm": True}).status_code == 422


def test_job_targets_must_be_in_scope(client):
    eng = ready_engagement(client)
    client.post(f"/engagements/{eng}/attest",
                json={"operator": "op", "policy_url": "https://example.com/p", "confirm": True})
    r = client.post(f"/engagements/{eng}/jobs", json={"kind": "subdomains"})
    assert r.status_code == 201 and r.json()["targets"] == ["example.com"]

    r = client.post(f"/engagements/{eng}/jobs", json={"kind": "subdomains", "targets": ["other.test"]})
    assert r.status_code == 422
    client.put(f"/engagements/{eng}/scope", json={
        "include": ["*.example.com", "example.com"], "exclude": ["status.example.com"],
        "research_header": "X-Bug-Bounty: researcher1"})
    r = client.post(f"/engagements/{eng}/jobs", json={"kind": "probe", "targets": ["status.example.com"]})
    assert r.status_code == 422
    r = client.post(f"/engagements/{eng}/jobs", json={"kind": "probe", "targets": ["app.example.com"]})
    assert r.status_code == 201


def test_scope_rules_decide_asset_scope(client):
    eng = ready_engagement(client)
    a = client.post(f"/engagements/{eng}/assets", json={"host": "evil.test"}).json()
    b = client.post(f"/engagements/{eng}/assets", json={"host": "app.example.com"}).json()
    cov = {r["host"]: r["in_scope"] for r in client.get(f"/engagements/{eng}/coverage").json()["assets"]}
    assert cov == {"evil.test": False, "app.example.com": True}


def attested(c, eng):
    c.post(f"/engagements/{eng}/attest",
           json={"operator": "op", "policy_url": "https://example.com/p", "confirm": True})


def test_probe_requires_research_identification(client):
    eng = ready_engagement(client, "hdr")
    attested(client, eng)
    r = client.post(f"/engagements/{eng}/jobs", json={"kind": "probe", "targets": ["app.example.com"]})
    assert r.status_code == 422 and "research header" in r.json()["detail"]
    # Passive / DNS kinds do not touch the target's web servers.
    assert client.post(f"/engagements/{eng}/jobs", json={"kind": "subdomains"}).status_code == 201

    client.put(f"/engagements/{eng}/scope", json={
        "include": ["*.example.com"], "research_header": "X-Bug-Bounty: researcher1"})
    r = client.post(f"/engagements/{eng}/jobs", json={"kind": "probe", "targets": ["app.example.com"]})
    assert r.status_code == 201


@pytest.mark.parametrize("bad", ["X-Test: a\r\nX-Evil: b", "no-colon-here", "Bad Name: v"])
def test_research_header_rejects_injection(client, bad):
    eng = ready_engagement(client, "inj")
    r = client.put(f"/engagements/{eng}/scope", json={"include": ["*.example.com"], "research_header": bad})
    assert r.status_code == 422


def test_wstg_pack_engagement_uses_pack_lanes(client):
    eng = client.post("/engagements", json={"name": "pt", "pack_id": "web-pentest-wstg"}).json()
    assert eng["engagement_type"] == "pentest"
    a = client.post(f"/engagements/{eng['id']}/assets", json={"host": "app.example.com"}).json()
    r = client.post("/lanes", json={"asset_id": a["id"], "role": "athz"})
    assert r.status_code == 422 and "Information gathering" in r.json()["detail"]
    info = client.post("/lanes", json={"asset_id": a["id"], "role": "info"}).json()
    assert info["items"][0]["key"] == "WSTG-INFO-01"
    assert "ISO-A.5.9" in info["items"][0]["controls"]
    assert client.post("/lanes", json={"asset_id": a["id"], "role": "authz"}).status_code == 422


def test_unknown_pack_is_rejected(client):
    assert client.post("/engagements", json={"name": "x", "pack_id": "nope"}).status_code == 422


def test_control_coverage_counts_only_receipted_lanes(client):
    eng = client.post("/engagements", json={"name": "ctl", "pack_id": "web-pentest-wstg"}).json()["id"]
    a = client.post(f"/engagements/{eng}/assets", json={"host": "app.example.com"}).json()
    info = client.post("/lanes", json={"asset_id": a["id"], "role": "info"}).json()

    def status(cid):
        rows = client.get(f"/engagements/{eng}/controls").json()["controls"]
        return next(r for r in rows if r["id"] == cid)

    resolve_all(client, info)
    assert status("DORA-ART8")["status"] == "none"       # proven but not receipted
    client.post(f"/lanes/{info['id']}/close")
    assert status("DORA-ART8")["status"] == "evidenced"  # info lane is the only DORA-ART8 source
    assert status("PCI-11.4.1")["status"] == "evidenced"
    assert status("ISO-A.5.15")["status"] == "none"      # authz/idnt lanes not done
