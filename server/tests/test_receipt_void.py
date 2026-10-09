"""Receipts that a later change voids, and the read-only check before signing.

- A change to a receipted lane voids its receipt for good: changing the lane back (reopen,
  then mark done again) does not bring the old receipt back. Only a new signature does.
  The audit log, the report's change history and the verifier show what happened.
- Mapping imported entries onto a lane whose receipt is in force is refused with 409 unless
  the person confirms it, and suggestions say which lanes are receipted.
- can_sign in the lane view says whether the caller could sign now, and why not, with the
  same sentence the close route refuses with.
"""
import json

from sqlalchemy import select

from app import gates
from app.models import AuditEntry, Evidence, Lane
from test_import import HAR, by_url, db, lane, team, upload, verify
from test_people import client, person, setup_team, sign_in  # noqa: F401  (fixture and helpers)


def entries(c, action):
    return [json.loads(e.change) for e in db(c).scalars(select(AuditEntry).where(AuditEntry.action == action)
                                                         .order_by(AuditEntry.seq))]


def receipted_recon_lane(c):
    """Tess attaches and marks item 1 done, the rest N/A; Rita signs. Returns (ids, e, lane id)."""
    _, ids, e, _a, ln = setup_team(c)
    L = ln["id"]
    sign_in(c, "tess@lab.test")
    assert c.post(f"/lanes/{L}/attach", json={"item_idx": 1, "kind": "note", "text": "robots.txt read"}).status_code == 201
    assert c.patch(f"/lanes/{L}/items/1", json={"state": "done"}).status_code == 200
    for it in ln["items"][1:]:
        c.patch(f"/lanes/{L}/items/{it['idx']}", json={"state": "na", "na_reason": "lab"})
    sign_in(c, "rita@lab.test")
    r = c.post(f"/lanes/{L}/close", json={"reviewed": True})
    assert r.status_code == 200 and r.json()["status"] == "closed"
    return ids, e, L


# ---- a change voids the receipt for good (option A) ------------------------------------

def test_reopen_then_done_keeps_the_receipt_void_until_signed_again(client, tmp_path):
    ids, e, L = receipted_recon_lane(client)
    first = client.get(f"/lanes/{L}").json()["receipt"]
    assert first["void"] is None
    sign_in(client, "tess@lab.test")
    view = client.patch(f"/lanes/{L}/items/1", json={"state": "open"}).json()
    assert view["status"] == "stale"
    void = view["receipt"]["void"]
    assert void["by"] == "Tess (tess@lab.test)" and void["cause"]["before"] == {"state": "done"}
    assert "Reopened item 1" in void["text"] and "voided its receipt" in void["text"]
    # Back as it was: the manifest matches the old receipt again, and the lane stays void.
    view = client.patch(f"/lanes/{L}/items/1", json={"state": "done"}).json()
    assert gates.manifest_hash(db(client).get(Lane, L)) == first["sha256"]
    assert view["status"] == "stale" and view["receipt"]["sha256"] == first["sha256"]
    assert client.get(f"/engagements/{e}/coverage").json()["assets"][0]["roles"]["recon"]["status"] == "stale"

    # The audit log records both changes, and names the receipt so a reader can match it.
    voided, updated = entries(client, "lane.receipt_voided"), entries(client, "lane.item_updated")
    assert len(voided) == 1 and voided[0]["receipt"]["manifest_sha256"] == first["sha256"]
    cause = {k: v for k, v in voided[0]["cause"].items() if k != "key"}
    assert cause == {"kind": "item", "idx": 1, "before": {"state": "done"}, "after": {"state": "open"}}
    assert len(updated) == 1 and updated[0]["cause"]["after"] == {"state": "done"}

    # The report shows the lane as void with its old receipt, and its history says why.
    sign_in(client, "owner@lab.test")
    report = client.get(f"/engagements/{e}/report").json()
    lane_r = next(x for x in report["lanes"] if x["lane_id"] == L)
    assert lane_r["status"] == "stale" and lane_r["receipt"]["manifest_sha256"] == first["sha256"]
    assert report["summary"]["lanes_receipted"] == 0 and report["summary"]["lanes_stale"] == 1
    actions = [x["action"] for x in report["audit_log"]["entries"]]
    assert actions.count("lane.receipt_voided") == 1 and actions.count("lane.item_updated") == 1
    problems, notes = verify.check_receipts(report)
    assert problems == [] and any("receipt is void" in n for n in notes)
    path = tmp_path / "r.json"
    path.write_text(json.dumps(report))
    assert verify.main(["v", str(path)]) == 0                  # the chain and the history verify
    page = client.get(f"/engagements/{e}/report.html").text
    assert "Reopened item 1" in page and "The lane needs a new signature" in page

    # A new signature closes it again; the void stays on the old receipt only.
    sign_in(client, "rita@lab.test")
    r = client.post(f"/lanes/{L}/close", json={"reviewed": True})
    assert r.status_code == 200 and r.json()["status"] == "closed" and r.json()["receipt"]["void"] is None
    assert len(db(client).get(Lane, L).receipts) == 2


def test_every_kind_of_change_voids_and_no_change_does_not(client):
    ids, e, L = receipted_recon_lane(client)
    sign_in(client, "tess@lab.test")
    # The same state again changes nothing: no void.
    client.patch(f"/lanes/{L}/items/1", json={"state": "done"})
    assert client.get(f"/lanes/{L}").json()["status"] == "closed" and entries(client, "lane.receipt_voided") == []
    # A new N/A reason is a change.
    view = client.patch(f"/lanes/{L}/items/2", json={"state": "na", "na_reason": "out of reach"}).json()
    assert view["status"] == "stale" and "not-applicable reason" in view["receipt"]["void"]["text"]
    view = client.patch(f"/lanes/{L}/items/2", json={"state": "na", "na_reason": "lab"}).json()
    assert view["status"] == "stale"                            # changed back: still void
    assert len(entries(client, "lane.receipt_voided")) == 1


def test_new_evidence_voids_the_receipt_in_the_history(client):
    _, e, L = receipted_recon_lane(client)
    sign_in(client, "tess@lab.test")
    view = client.post(f"/lanes/{L}/attach", json={"item_idx": 2, "kind": "note", "text": "more"}).json()
    assert view["status"] == "stale"
    (v,) = entries(client, "lane.receipt_voided")
    assert v["cause"]["kind"] == "evidence" and v["cause"]["evidence_id"] == view["evidence"][-1]["id"]
    assert "Added evidence" in view["receipt"]["void"]["text"]


def test_recon_evidence_on_a_receipted_recon_lane_is_recorded(client):
    from datetime import datetime, timezone

    from app import workerapi
    from app.models import Engagement, Job, JobStatus, Observation
    _, e, L = receipted_recon_lane(client)
    s = db(client)
    job = Job(engagement_id=e, kind="probe", targets=["shop.lab.test"], status=JobStatus.done,
              output_sha256="a" * 64, finished_at=datetime.now(timezone.utc))
    s.add(job)
    s.flush()
    s.add(Observation(engagement_id=e, job_id=job.id, host="shop.lab.test", data={}))
    s.flush()
    workerapi.recon_evidence(s, job, s.get(Engagement, e))
    s.commit()
    (v,) = entries(client, "lane.receipt_voided")
    assert v["cause"]["source"] == "recon" and v["lane"]["id"] == L
    sign_in(client, "owner@lab.test")
    assert client.get(f"/lanes/{L}").json()["status"] == "stale"


# ---- mapping onto a receipted lane asks first --------------------------------------------

def test_mapping_onto_a_receipted_lane_needs_confirmation(client):
    _, e, a = team(client)          # the information lane is receipted
    info_id = db(client).scalar(select(Lane.id).where(Lane.role == "info"))
    info_sha = client.get(f"/lanes/{info_id}").json()["receipt"]["sha256"]
    sign_in(client, "tess@lab.test")
    upload(client, e, HAR)
    login = by_url(client, e, "/rest/user/login")
    detail = client.get(f"/engagements/{e}/inbox/{login['id']}").json()
    info_t = next(t for t in detail["targets"] if t["role"] == "info")
    assert info_t["receipted"] is True and info_t["status"] == "closed"
    assert {(i["lane_status"], i["receipted"]) for i in info_t["items"]} == {("closed", True)}
    athn_t = next(t for t in detail["targets"] if t["role"] == "athn")
    assert athn_t["receipted"] is False and athn_t["items"][0]["lane_status"] == "not_opened"
    assert all(s["receipted"] == (s["lane_status"] == "closed") for s in detail["suggestions"])

    body = {"entry_ids": [login["id"]], "mark_done": True, "targets": [{"lane_id": info_id, "item_idx": 1},
                                                                       {"role": "athn", "item_idx": 3}]}
    r = client.post(f"/engagements/{e}/inbox/map", json=body)
    assert r.status_code == 409, r.text
    d = r.json()["detail"]
    assert d["error"] == "would_void_receipts" and "voids its receipt" in d["message"]
    assert [(x["lane_id"], x["role"], x["host"]) for x in d["lanes"]] == [(info_id, "info", "shop.example.com")]
    assert d["lanes"][0]["receipt_sha256"] == info_sha
    # Nothing was written: no evidence, no lane opened, the receipt still in force.
    s = db(client)
    assert s.scalars(select(Evidence)).all() == [] and {x.role for x in s.get(Lane, info_id).asset.lanes} == {"info"}
    assert client.get(f"/lanes/{info_id}").json()["status"] == "closed"
    assert entries(client, "lane.receipt_voided") == []

    r = client.post(f"/engagements/{e}/inbox/map", json=body | {"confirm_void": True})
    assert r.status_code == 200, r.text
    assert r.json()["receipts_voided"] == [{"lane_id": info_id, "receipt_sha256": d["lanes"][0]["receipt_sha256"]}]
    assert client.get(f"/lanes/{info_id}").json()["status"] == "stale"
    (v,) = entries(client, "lane.receipt_voided")
    assert v["cause"]["kind"] == "import" and v["cause"]["confirmed"] is True
    assert v["cause"]["entries"] == [login["id"]] and len(v["cause"]["evidence"]) == 1
    # Mapping onto a lane without a receipt in force never asks.
    robots = by_url(client, e, "/robots.txt")
    assert client.post(f"/engagements/{e}/inbox/map", json={
        "entry_ids": [robots["id"]], "targets": [{"lane_id": info_id, "item_idx": 2}]}).status_code == 200


def test_an_entry_already_mapped_there_voids_nothing(client):
    _, e, a = team(client, receipt_info=False)
    info = lane(client, a, "info")
    upload(client, e, HAR)
    login = by_url(client, e, "/rest/user/login")
    body = {"entry_ids": [login["id"]], "targets": [{"lane_id": info["id"], "item_idx": 1}]}
    assert client.post(f"/engagements/{e}/inbox/map", json=body).status_code == 200
    for it in info["items"]:
        if it["idx"] == 1:
            client.patch(f"/lanes/{info['id']}/items/1", json={"state": "done"})
        else:
            client.patch(f"/lanes/{info['id']}/items/{it['idx']}", json={"state": "na", "na_reason": "lab"})
    assert client.post(f"/lanes/{info['id']}/close", json={"reviewed": True}).status_code == 200
    # The same mapping again adds no evidence, so it voids nothing and needs no confirmation.
    r = client.post(f"/engagements/{e}/inbox/map", json=body)
    assert r.status_code == 200 and r.json()["evidence_added"] == [] and r.json()["receipts_voided"] == []
    assert client.get(f"/lanes/{info['id']}").json()["status"] == "closed"


# ---- can_sign: asked before a key is created ---------------------------------------------

def test_can_sign_matches_what_the_close_refuses(client, monkeypatch):
    _, ids, e, a, ln = setup_team(client)
    L = ln["id"]
    client.patch(f"/engagements/{e}", json={"separation_of_duties": True})
    sign_in(client, "rita@lab.test")                                     # tester and reviewer
    cs = client.get(f"/lanes/{L}").json()["can_sign"]
    assert cs["ok"] is False and cs["reason"].startswith("Resolve every item first: item 1 still open")
    client.post(f"/lanes/{L}/attach", json={"item_idx": 1, "kind": "note", "text": "my own test"})
    client.patch(f"/lanes/{L}/items/1", json={"state": "done"})
    for it in ln["items"][1:]:
        client.patch(f"/lanes/{L}/items/{it['idx']}", json={"state": "na", "na_reason": "lab"})
    cs = client.get(f"/lanes/{L}").json()["can_sign"]
    sod = "Separation of duties is on: you attached evidence to this lane, so someone else must sign its receipt."
    assert cs == {"ok": False, "reason": sod, "signature_required": False}
    r = client.post(f"/lanes/{L}/close", json={"reviewed": True})
    assert r.status_code == 422 and r.json()["detail"] == sod           # the same sentence, capitalized

    sign_in(client, "tess@lab.test")                                     # tester only
    cs = client.get(f"/lanes/{L}").json()["can_sign"]
    assert cs["ok"] is False and cs["reason"] == "Signing needs the reviewer role on this engagement."
    monkeypatch.setenv("ATTACKLEDGER_API_TOKEN", "tok-123")
    client.cookies.clear()
    cs = client.get(f"/lanes/{L}", headers={"authorization": "Bearer tok-123"}).json()["can_sign"]
    assert cs["ok"] is False and cs["reason"] == "Separation of duties is on: sign in as a person to sign receipts."
    monkeypatch.delenv("ATTACKLEDGER_API_TOKEN")

    sign_in(client, "owner@lab.test")
    client.patch(f"/engagements/{e}", json={"separation_of_duties": False, "require_signatures": True})
    monkeypatch.setenv("ATTACKLEDGER_API_TOKEN", "tok-123")
    client.cookies.clear()
    cs = client.get(f"/lanes/{L}", headers={"authorization": "Bearer tok-123"}).json()["can_sign"]
    assert cs["ok"] is False and "requires signed receipts" in cs["reason"] and cs["signature_required"] is True
    monkeypatch.delenv("ATTACKLEDGER_API_TOKEN")
    sign_in(client, "rita@lab.test")
    assert client.get(f"/lanes/{L}").json()["can_sign"] == {"ok": True, "reason": None, "signature_required": True}


def test_can_sign_reports_the_dependency_and_deleted_content(client):
    _, e, a = team(client, receipt_info=False)
    athn = lane(client, a, "athn")
    for it in athn["items"]:
        client.patch(f"/lanes/{athn['id']}/items/{it['idx']}", json={"state": "na", "na_reason": "lab"})
    cs = client.get(f"/lanes/{athn['id']}").json()["can_sign"]
    assert cs["ok"] is False and "can be signed only after" in cs["reason"] and cs["reason"].endswith(".")
    r = client.post(f"/lanes/{athn['id']}/close", json={"reviewed": True})
    assert r.status_code == 422 and r.json()["detail"] + "." == cs["reason"]
    assert client.post(f"/engagements/{e}/content/delete", json={"confirm_name": "Import"}).status_code == 200
    cs = client.get(f"/lanes/{athn['id']}").json()["can_sign"]
    assert cs["ok"] is False and "no new receipt is issued" in cs["reason"]
    assert client.post(f"/lanes/{athn['id']}/close", json={"reviewed": True}).status_code == 409
