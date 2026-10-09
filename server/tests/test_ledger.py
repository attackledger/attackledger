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


SIGN = {"closed_by": "test reviewer", "reviewed": True}


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
    assert client.post(f"/lanes/{mapper['id']}/close", json=SIGN).status_code == 200
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
    r = client.post(f"/lanes/{lane['id']}/close", json=SIGN)
    assert r.status_code == 422
    assert client.get(f"/lanes/{lane['id']}").json()["status"] == "open"


def test_receipt_goes_stale_when_ledger_changes(client):
    _, asset_id = setup_asset(client)
    lane = client.post("/lanes", json={"asset_id": asset_id, "role": "recon"}).json()
    resolve_all(client, lane)
    assert client.post(f"/lanes/{lane['id']}/close", json=SIGN).json()["status"] == "closed"

    client.post(f"/lanes/{lane['id']}/evidence",
                json={"kind": "note", "sha256": h("late"), "summary": "added after close"})
    assert client.get(f"/lanes/{lane['id']}").json()["status"] == "stale"


def test_coverage_counts_only_closed_cells(client):
    eng_id, asset_id = setup_asset(client)
    lane = client.post("/lanes", json={"asset_id": asset_id, "role": "recon"}).json()
    resolve_all(client, lane)
    client.post(f"/lanes/{lane['id']}/close", json=SIGN)
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
    for bad in ("http://example.com/p", "example.com/policy", "", "https://"):
        r = client.post(f"/engagements/{eng}/attest", json={"operator": "op", "policy_url": bad, "confirm": True})
        assert r.status_code == 422 and isinstance(r.json()["detail"], str), bad
        assert "https://" in r.json()["detail"] and "statement of work" in r.json()["detail"]
    assert client.get(f"/engagements/{eng}/scope").json()["authorized_at"] is None
    r = client.post(f"/engagements/{eng}/attest", json={"operator": "op", "confirm": True,
                                                         "policy_url": " https://example.com/policy "})
    assert r.status_code == 200 and r.json()["policy_url"] == "https://example.com/policy"
    r = client.post("/engagements", json={"name": "plain-http", "policy_url": "http://example.com/p"})
    assert r.status_code == 422 and "https://" in r.json()["detail"]


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
    assert cov == {"evil.test": False, "app.example.com": True, "example.com": True}   # example.com: exact rule


def test_exact_scope_entries_become_hosts(client):
    e = client.post("/engagements", json={"name": "exact"}).json()["id"]
    client.post(f"/engagements/{e}/assets", json={"host": "old.lab.test", "in_scope": False})
    rules = {"include": ["Shop.Lab.Test", "*.lab.test", "lab.test", "admin.lab.test", "old.lab.test",
                         "x.legacy.lab.test"],
             "exclude": ["admin.lab.test", "*.legacy.lab.test"]}
    r = client.put(f"/engagements/{e}/scope", json=rules)
    assert r.status_code == 200 and r.json()["hosts_added"] == ["lab.test", "shop.lab.test"]
    cov = {a["host"]: a["in_scope"] for a in client.get(f"/engagements/{e}/coverage").json()["assets"]}
    # Exclusions win, wildcards stay rules, and an existing host is left as the operator set it.
    assert cov == {"lab.test": True, "shop.lab.test": True, "old.lab.test": False}
    assert client.put(f"/engagements/{e}/scope", json=rules).json()["hosts_added"] == []
    assert client.get(f"/engagements/{e}/recon/summary").json()["hosts"] == 2
    attested(client, e)
    assert client.post(f"/engagements/{e}/jobs", json={"kind": "resolve"}).json()["targets"] == \
        ["lab.test", "shop.lab.test"]


def test_wildcard_only_scope_adds_no_hosts(client):
    e = client.post("/engagements", json={"name": "wild"}).json()["id"]
    assert client.put(f"/engagements/{e}/scope", json={"include": ["*.lab.test"]}).json()["hosts_added"] == []
    assert client.get(f"/engagements/{e}/coverage").json()["assets"] == []


def test_scope_import_adds_exact_hosts(client):
    e = client.post("/engagements", json={"name": "imp-hosts"}).json()["id"]
    csv_ = ("identifier,asset_type,eligible_for_submission\n*.example.com,WILDCARD,true\n"
            "api.example.com,URL,true\nold.example.com,URL,false\n")
    assert client.post(f"/engagements/{e}/scope/import", json={"csv": csv_}).json().get("hosts_added") is None
    done = client.post(f"/engagements/{e}/scope/import", json={"csv": csv_, "apply": True}).json()
    assert done["hosts_added"] == ["api.example.com"]


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
    client.post(f"/lanes/{info['id']}/close", json=SIGN)
    assert status("DORA-ART8")["status"] == "evidenced"  # info lane is the only DORA-ART8 source
    assert status("PCI-11.4.1")["status"] == "evidenced"
    assert status("ISO-A.5.15")["status"] == "none"      # authz/idnt lanes not done


def test_not_applicable_is_never_counted_as_evidence(client):
    """N/A items are counted apart: all N/A is "not_applicable", a mix is "resolved"."""
    def info_lane(name, with_evidence: bool):
        eng = client.post("/engagements", json={"name": name, "pack_id": "web-pentest-wstg"}).json()["id"]
        a = client.post(f"/engagements/{eng}/assets", json={"host": "app.example.com"}).json()
        lane = client.post("/lanes", json={"asset_id": a["id"], "role": "info"}).json()
        for n, it in enumerate(lane["items"]):
            if with_evidence and n == 0:
                client.post(f"/lanes/{lane['id']}/evidence", json={"item_idx": it["idx"], "kind": "note",
                                                                   "sha256": h(it["text"]), "summary": "recorded"})
                client.patch(f"/lanes/{lane['id']}/items/{it['idx']}", json={"state": "done"})
            else:
                client.patch(f"/lanes/{lane['id']}/items/{it['idx']}", json={"state": "na", "na_reason": "out of reach"})
        assert client.post(f"/lanes/{lane['id']}/close", json=SIGN).status_code == 200
        return eng, {r["id"]: r for r in client.get(f"/engagements/{eng}/controls").json()["controls"]}

    # DORA-ART8 comes only from the information gathering lane.
    _, rows = info_lane("na-only", with_evidence=False)
    dora = rows["DORA-ART8"]
    assert dora["evidenced"] == 0 and dora["not_applicable"] == dora["required"] and dora["status"] == "not_applicable"
    eng, rows = info_lane("mixed", with_evidence=True)
    dora = rows["DORA-ART8"]
    assert 0 < dora["evidenced"] < dora["required"] and dora["status"] == "resolved"
    assert not any(r["status"] == "evidenced" and r["not_applicable"] for r in rows.values())
    page = client.get(f"/engagements/{eng}/report.html").text
    assert "not applicable" in page and "Resolved, partly not applicable" in page


def recon_ready(c, name, **extra):
    eng = c.post("/engagements", json={"name": name}).json()["id"]
    c.put(f"/engagements/{eng}/scope", json={"include": ["*.example.com"], **extra})
    attested(c, eng)
    return eng


def test_ports_need_explicit_permission(client):
    eng = recon_ready(client, "ports-off")
    client.post(f"/engagements/{eng}/assets", json={"host": "app.example.com"})
    r = client.post(f"/engagements/{eng}/jobs", json={"kind": "ports"})
    assert r.status_code == 422 and "scan ports is off" in r.json()["detail"]
    client.put(f"/engagements/{eng}/scope", json={"include": ["*.example.com"], "allow_port_scan": True})
    assert client.post(f"/engagements/{eng}/jobs", json={"kind": "ports"}).status_code == 201


def test_crawl_needs_identification_and_probe_results(client):
    eng = recon_ready(client, "crawl")
    r = client.post(f"/engagements/{eng}/jobs", json={"kind": "crawl"})
    assert r.status_code == 422 and "research header" in r.json()["detail"]
    client.put(f"/engagements/{eng}/scope", json={"include": ["*.example.com"],
                                                  "research_header": "X-Bug-Bounty: r1"})
    r = client.post(f"/engagements/{eng}/jobs", json={"kind": "crawl"})
    assert r.status_code == 422 and "live web servers" in r.json()["detail"]
    r = client.post(f"/engagements/{eng}/jobs", json={"kind": "crawl", "targets": ["https://evil.test/"]})
    assert r.status_code == 422 and "out of scope" in r.json()["detail"]
    r = client.post(f"/engagements/{eng}/jobs", json={"kind": "crawl", "targets": ["https://app.example.com/"]})
    assert r.status_code == 201


def test_archive_targets_wildcard_roots(client):
    eng = recon_ready(client, "archive")
    r = client.post(f"/engagements/{eng}/jobs", json={"kind": "archive"})
    assert r.status_code == 201 and r.json()["targets"] == ["example.com"]
    assert client.get(f"/engagements/{eng}/triage").json()["hosts"] == []
    assert client.get(f"/engagements/{eng}/endpoints").json() == {"total": 0, "items": []}


def test_jsanalyze_needs_identification_and_js_files(client):
    eng = recon_ready(client, "js")
    r = client.post(f"/engagements/{eng}/jobs", json={"kind": "jsanalyze"})
    assert r.status_code == 422 and "research header" in r.json()["detail"]
    client.put(f"/engagements/{eng}/scope", json={"include": ["*.example.com"],
                                                  "research_header": "X-Bug-Bounty: r1"})
    r = client.post(f"/engagements/{eng}/jobs", json={"kind": "jsanalyze"})
    assert r.status_code == 422 and "crawl golden hosts" in r.json()["detail"]
    r = client.post(f"/engagements/{eng}/jobs", json={"kind": "jsanalyze",
                                                      "targets": ["https://cdn.evil.test/a.js"]})
    assert r.status_code == 422
    assert client.get(f"/engagements/{eng}/leads").json() == []


def test_resume_only_for_runs_with_remaining_targets(client):
    eng = recon_ready(client, "resume")
    client.post(f"/engagements/{eng}/assets", json={"host": "app.example.com"})
    job = client.post(f"/engagements/{eng}/jobs", json={"kind": "resolve"}).json()
    assert job["targets_done"] == 0 and job["remaining"] == 0
    assert client.post(f"/jobs/{job['id']}/resume").status_code == 422


def test_cancelling_a_queued_run_keeps_all_targets_resumable(client):
    eng = recon_ready(client, "cancel-queued")
    client.post(f"/engagements/{eng}/assets", json={"host": "app.example.com"})
    job = client.post(f"/engagements/{eng}/jobs", json={"kind": "resolve"}).json()
    c = client.post(f"/jobs/{job['id']}/cancel").json()
    assert c["status"] == "cancelled" and c["remaining"] == 1
    r = client.post(f"/jobs/{job['id']}/resume")
    assert r.status_code == 201 and r.json()["targets"] == ["app.example.com"]


def test_modules_endpoint_lists_registry(client):
    mods = {m["kind"]: m for m in client.get("/modules").json()}
    assert mods["ports"]["opt_in"] and mods["ports"]["traffic"] == "target"
    assert mods["subdomains"]["traffic"] == "passive" and not mods["subdomains"]["needs_identification"]


def test_only_opt_in_modules_can_be_enabled(client):
    eng = recon_ready(client, "optin")
    r = client.put(f"/engagements/{eng}/scope", json={"include": ["*.example.com"], "enabled_modules": ["probe"]})
    assert r.status_code == 422 and "not an opt-in module" in r.json()["detail"]
    r = client.put(f"/engagements/{eng}/scope", json={"include": ["*.example.com"], "enabled_modules": ["ports"]})
    assert r.json()["enabled_modules"] == ["ports"]


def test_executors_and_lane_context(client, monkeypatch):
    eng = recon_ready(client, "ctx", research_header="X-Bug-Bounty: r1")
    a = client.post(f"/engagements/{eng}/assets", json={"host": "app.example.com"}).json()
    lane = client.post("/lanes", json={"asset_id": a["id"], "role": "recon"}).json()
    assert lane["executor"] == "manual"

    ex = {e["key"]: e for e in client.get("/executors").json()}
    assert ex["manual"]["available"] and not ex["agent"]["available"]
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    r = client.patch(f"/lanes/{lane['id']}", json={"executor": "agent"})
    assert r.status_code == 422 and "ANTHROPIC_API_KEY" in r.json()["detail"]
    assert client.patch(f"/lanes/{lane['id']}", json={"executor": "nope"}).status_code == 422

    ctx = client.get(f"/lanes/{lane['id']}/context").json()
    assert ctx["host"] == "app.example.com" and ctx["lane"]["role"] == "recon"
    assert ctx["rules"]["research_header"] == "X-Bug-Bounty: r1" and ctx["rules"]["authorized"]
    assert len(ctx["items"]) == len(lane["items"])
    assert set(ctx["recon"]) == {"observations", "endpoints", "leads"}


def test_receipt_needs_a_signer_and_review(client):
    _, asset_id = setup_asset(client)
    lane = client.post("/lanes", json={"asset_id": asset_id, "role": "recon"}).json()
    resolve_all(client, lane)
    assert client.post(f"/lanes/{lane['id']}/close").status_code == 422                     # no signer
    assert client.post(f"/lanes/{lane['id']}/close",
                       json={"closed_by": "m", "reviewed": False}).status_code == 422       # not reviewed
    assert client.post(f"/lanes/{lane['id']}/close",
                       json={"closed_by": "  ", "reviewed": True}).status_code == 422       # blank signer
    r = client.post(f"/lanes/{lane['id']}/close", json={"closed_by": "Murat Kabak", "reviewed": True}).json()
    assert r["status"] == "closed" and r["receipt"]["closed_by"] == "Murat Kabak"


def test_pipeline_queues_steps_that_pass_their_gates(client):
    eng = recon_ready(client, "pipe")
    r = client.post(f"/engagements/{eng}/pipeline")
    assert r.status_code == 201
    body = r.json()
    assert body["queued"] == ["subdomains", "resolve", "archive", "paramclass", "dorks"]   # passive + DNS only
    assert "off for this engagement" in {x["kind"]: x["reason"] for x in body["skipped"]}["nuclei"]
    reasons = {s["kind"]: s["reason"] for s in body["skipped"]}
    assert "off for this engagement" in reasons["ports"]
    assert "research header" in reasons["probe"]
    jobs = client.get(f"/engagements/{eng}/jobs").json()
    assert all(j["deferred"] and j["targets"] == [] for j in jobs)


def test_pipeline_does_not_queue_steps_that_cannot_apply(client):
    e = client.post("/engagements", json={"name": "pipe-exact"}).json()["id"]
    client.put(f"/engagements/{e}/scope", json={"include": ["shop.lab.test"]})
    attested(client, e)
    body = client.post(f"/engagements/{e}/pipeline").json()
    assert body["queued"] == ["resolve", "paramclass"]
    reasons = {s["kind"]: s["reason"] for s in body["skipped"]}
    assert all("needs a wildcard in scope" in reasons[k] for k in ("subdomains", "archive", "dorks"))

    e = client.post("/engagements", json={"name": "pipe-nohosts"}).json()["id"]
    client.put(f"/engagements/{e}/scope", json={"include": ["old.lab.test"], "exclude": ["old.lab.test"]})
    attested(client, e)
    body = client.post(f"/engagements/{e}/pipeline").json()
    assert body["queued"] == ["paramclass"] and "no in-scope hosts" in \
        {s["kind"]: s["reason"] for s in body["skipped"]}["resolve"]


def test_pipeline_refuses_when_nothing_can_run(client):
    eng = client.post("/engagements", json={"name": "pipe-none"}).json()["id"]
    r = client.post(f"/engagements/{eng}/pipeline")
    assert r.status_code == 422 and r.json()["detail"]["error"] == "no step can run"


def test_scope_import_previews_then_applies(client):
    eng = client.post("/engagements", json={"name": "import"}).json()["id"]
    csv_ = "identifier,asset_type,eligible_for_submission\n*.example.com,WILDCARD,true\nold.example.com,URL,false\n"
    prev = client.post(f"/engagements/{eng}/scope/import", json={"csv": csv_}).json()
    assert prev["applied"] is False and client.get(f"/engagements/{eng}/scope").json()["include"] == []
    done = client.post(f"/engagements/{eng}/scope/import", json={"csv": csv_, "apply": True}).json()
    assert done["applied"] and done["result"] == {"include": ["*.example.com"], "exclude": ["old.example.com"]}
    s = client.get(f"/engagements/{eng}/scope").json()
    assert s["include"] == ["*.example.com"] and s["exclude"] == ["old.example.com"]


def test_recon_phases_follow_the_registry(client):
    phases = client.get("/recon/phases").json()
    kinds = [k for p in phases for k in p["kinds"]]
    mods = client.get("/modules").json()
    assert kinds == [m["kind"] for m in mods]
    assert all(m["phase"] in {p["key"] for p in phases} and m["tools"] for m in mods)
    assert all(p["help"] and p["summary"] for p in phases)


def test_recon_summary_counts_only_in_scope_hosts(client):
    e = client.post("/engagements", json={"name": "sum"}).json()["id"]
    client.put(f"/engagements/{e}/scope", json={"include": ["*.lab.test"], "exclude": ["old.lab.test"]})
    for h in ("a.lab.test", "b.lab.test", "old.lab.test"):
        client.post(f"/engagements/{e}/assets", json={"host": h})
    s = client.get(f"/engagements/{e}/recon/summary").json()
    assert s["hosts"] == 2 and s["resolved"] == 0 and s["live"] == 0 and s["urls"] == 0
    assert client.get(f"/engagements/{e}/endpoints?module=crawl").json() == {"total": 0, "items": []}
    assert client.get(f"/engagements/{e}/leads?module=nuclei").json() == []


def _lane(client):
    e = client.post("/engagements", json={"name": "attach"}).json()["id"]
    a = client.post(f"/engagements/{e}/assets", json={"host": "shop.lab.test"}).json()["id"]
    return e, client.post("/lanes", json={"asset_id": a, "role": "recon"}).json()["id"]


def test_attach_note_and_file_store_the_bytes_behind_the_hash(client, tmp_path, monkeypatch):
    import base64
    from app import blobs
    monkeypatch.setenv("ATTACKLEDGER_BLOBS", str(tmp_path / "blobs"))
    e, lane = _lane(client)
    r = client.post(f"/lanes/{lane}/attach", json={"item_idx": 1, "kind": "note", "text": "robots.txt lists /backup/"})
    assert r.status_code == 201
    ev = r.json()["evidence"][-1]
    assert ev["kind"] == "note" and ev["item_idx"] == 1 and blobs.get(ev["sha256"], engagement_id=e) == b"robots.txt lists /backup/"

    data = b"\x89PNG fake screenshot"
    r = client.post(f"/lanes/{lane}/attach", json={"item_idx": 2, "kind": "file", "filename": "C:\\shots\\a.png",
                                                  "content_b64": base64.b64encode(data).decode(),
                                                  "summary": "Admin panel answers 401."})
    ev = r.json()["evidence"][-1]
    assert ev["uri"] == "file:a.png" and ev["sha256"] == h_bytes(data) and blobs.get(ev["sha256"], engagement_id=e) == data
    assert client.get(f"/blobs/{ev['sha256']}").content == data
    # A file without a summary, an empty note, bad base64 and a missing item are refused.
    assert client.post(f"/lanes/{lane}/attach", json={"item_idx": 2, "kind": "file", "filename": "a.png",
                                                     "content_b64": base64.b64encode(data).decode()}).status_code == 422
    assert client.post(f"/lanes/{lane}/attach", json={"item_idx": 1, "kind": "note", "text": "  "}).status_code == 422
    assert client.post(f"/lanes/{lane}/attach", json={"item_idx": 1, "kind": "file", "filename": "a",
                                                     "content_b64": "%%%", "summary": "s"}).status_code == 422
    assert client.post(f"/lanes/{lane}/attach", json={"item_idx": 99, "kind": "note", "text": "x"}).status_code == 404
    # Evidence makes "done" possible, as with the plain evidence route.
    assert client.patch(f"/lanes/{lane}/items/1", json={"state": "done"}).status_code == 200


def test_attach_run_needs_a_finished_run_from_the_same_engagement(client):
    from app import db
    from app.models import Job, JobStatus
    e, lane = _lane(client)
    other = client.post("/engagements", json={"name": "other"}).json()["id"]
    s = next(app.dependency_overrides[db.get_session]())
    done = Job(engagement_id=e, kind="probe", targets=["shop.lab.test"], status=JobStatus.done, output_sha256="a" * 64)
    running = Job(engagement_id=e, kind="probe", targets=["x"], status=JobStatus.running)
    foreign = Job(engagement_id=other, kind="probe", targets=["x"], status=JobStatus.done, output_sha256="b" * 64)
    s.add_all([done, running, foreign])
    s.commit()
    r = client.post(f"/lanes/{lane}/attach", json={"item_idx": 3, "kind": "run", "job_id": done.id, "summary": "2 live services"})
    ev = r.json()["evidence"][-1]
    assert r.status_code == 201 and ev["sha256"] == "a" * 64 and ev["uri"] == f"job:{done.id}"
    assert ev["summary"] == f"Find live web servers run, job {done.id}: 2 live services"
    for j in (running, foreign):
        assert client.post(f"/lanes/{lane}/attach", json={"item_idx": 3, "kind": "run", "job_id": j.id}).status_code == 422


def h_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def test_report_labels_recon_runs_and_counts(client):
    from app import db
    from app.models import Job, JobStatus
    e, lane = _lane(client)
    s = next(app.dependency_overrides[db.get_session]())
    run = Job(engagement_id=e, kind="probe", targets=["shop.lab.test"], status=JobStatus.done, output_sha256="a" * 64)
    skipped = Job(engagement_id=e, kind="archive", targets=[], status=JobStatus.skipped, deferred=True)
    s.add_all([run, skipped])
    s.commit()
    client.post(f"/lanes/{lane}/attach", json={"item_idx": 1, "kind": "run", "job_id": run.id})
    client.post(f"/lanes/{lane}/attach", json={"item_idx": 1, "kind": "note", "text": "checked by hand"})
    page = client.get(f"/engagements/{e}/report.html").text
    items = page[page.index("id='items'"):]
    assert f"Recon run: Find live web servers run, job {run.id}" in items and " file: " not in items
    assert "Note: checked by hand" in items
    recon = page[page.index("id='recon'"):]
    assert "Find live web servers" in recon and "Skipped" in recon and "Collect archived URLs" in recon
    assert "1 in-scope host " in page or "1 in-scope host\n" in page


def test_plural():
    from app.text import plural
    assert plural(1, "result") == "1 result" and plural(0, "result") == "0 results"
    assert plural(2, "match", "matches") == "2 matches"
