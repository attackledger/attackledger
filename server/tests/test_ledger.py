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
    assert r.status_code == 422 and "mapper" in r.json()["detail"]

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
