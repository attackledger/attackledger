"""Lab write rules (D-062, labrules.py): an owner's standing approval of writes on a practice lab.

The rule approves a write when it is proposed; everything else of D-041 stays: one proposal per
write, a single-use approval, the gateway sends it, the evidence and the audit log name the rule.
Two gates, both off by default (the deployment's switch, the engagement's rule), lab hosts in
scope only, the DELETE only when listed, a cap and an end, and separation of duties recorded.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from harness import stack  # noqa: F401
from test_test_accounts import GW_TOKEN, Gw, actions, queue, status, tools  # noqa: F401

from app import labrules, vault
from app.models import Engagement, Evidence, Job, LabWriteRule, User, WriteProposal

LAB = "juice.lab.test"


@pytest.fixture()
def gw(stack, tmp_path, monkeypatch):
    monkeypatch.setenv("ATTACKLEDGER_GATEWAY_TOKEN", GW_TOKEN)
    g = Gw(stack.api, tmp_path)
    yield g
    g.close()


@pytest.fixture()
def on(monkeypatch):
    monkeypatch.setenv(labrules.ENV, "1")


def setup(stack, include=(LAB, "shop.example.com")):
    e = stack.engagement(name="lab", include=include)
    lane = stack.lane(e, LAB, items=3, executor="agent")
    assert stack.api.patch(f"/engagements/{e}", json={"allow_writes": True}).status_code == 200
    return e, lane


def start(stack, e, lane):
    stack.queue(e, "agent", [LAB], lane_id=lane, result={"limits": {"max_requests": 20}})
    job = stack.claim()
    assert job is not None
    return job


def rule(stack, e, status_code=201, **kw):
    body = {"methods": ["POST", "PUT", "PATCH"], "hosts": [LAB], **kw}
    r = stack.api.post(f"/engagements/{e}/lab-write-rules", json=body)
    assert r.status_code == status_code, r.text
    return r.json()


def propose(tb, method="POST", path="/api/Users", body='{"email": "agent@juice.lab.test"}'):
    text, err = tb.call("propose_write", {"method": method, "url": f"http://{LAB}{path}",
                                          "headers": [{"name": "Content-Type", "value": "application/json"}],
                                          "body": body, "as_account": "", "item_idx": 1, "reason": "lab"})
    assert not err, text
    return json.loads(text)


# ---- the gates ------------------------------------------------------------------------------

def test_off_on_the_deployment_no_rule_is_made_and_nothing_is_approved(stack, gw, monkeypatch):
    monkeypatch.delenv(labrules.ENV, raising=False)
    e, lane = setup(stack)
    r = rule(stack, e, status_code=403)
    assert labrules.ENV in r["detail"]
    tb = tools(gw, start(stack, e, lane))
    assert propose(tb)["status"] == "pending" and gw.up.requests == []
    # A rule made while it was on approves nothing once it is off.
    monkeypatch.setenv(labrules.ENV, "1")
    rule(stack, e)
    monkeypatch.setenv(labrules.ENV, "0")
    assert propose(tb)["status"] == "pending" and gw.up.requests == []


def test_only_lab_hosts_in_scope(stack, on):
    e, lane = setup(stack, include=(LAB, "shop.example.com", "*.example.test"))
    assert "not a lab host" in rule(stack, e, 422, hosts=["shop.example.com"])["detail"]
    assert "not in this engagement's scope" in rule(stack, e, 422, hosts=["other.lab.test"])["detail"]
    assert "not a lab host" in rule(stack, e, 422, hosts=[LAB, "shop.example.com"])["detail"]
    assert "not a lab host" in rule(stack, e, 422, hosts=["test"])["detail"]
    assert rule(stack, e, 422, methods=["GET"])
    assert rule(stack, e, 422, paths=["api/*"])
    assert rule(stack, e, 422, hours=24 * 8)
    assert rule(stack, e, hosts=["a.example.test"])["state"] == "active"


def test_viewers_cannot_make_or_end_a_rule(stack, on):
    from app import auth
    auth._failures.clear()
    e, lane = setup(stack)
    made = rule(stack, e)
    c, pw = stack.api, "correct horse battery"
    ids = {}
    for n, owner in (("olive", True), ("tess", False)):
        ids[n] = c.post("/people", json={"email": f"{n}@lab.test", "name": n.title(), "password": pw,
                                         "is_owner": owner}).json()["id"]
        if owner:
            assert c.post("/auth/login", json={"email": "olive@lab.test", "password": pw}).status_code == 200
    c.put(f"/engagements/{e}/members", json={"members": [{"user_id": ids["tess"], "roles": ["tester"]}]})
    c.cookies.clear()
    assert c.post("/auth/login", json={"email": "tess@lab.test", "password": pw}).status_code == 200
    assert c.get(f"/engagements/{e}/lab-write-rules").status_code == 200
    assert c.post(f"/engagements/{e}/lab-write-rules", json={"methods": ["POST"], "hosts": [LAB]}).status_code == 403
    assert c.post(f"/engagements/{e}/lab-write-rules/{made['id']}/revoke").status_code == 403
    assert c.post(f"/engagements/{e}/lab-write-rules/99999/revoke").status_code == 404
    c.cookies.clear()
    assert c.post("/auth/login", json={"email": "olive@lab.test", "password": pw}).status_code == 200
    assert c.post(f"/engagements/{e}/lab-write-rules/{made['id']}/revoke").json()["state"] == "revoked"
    c.cookies.clear()


# ---- approving ------------------------------------------------------------------------------

def test_a_matching_write_is_approved_sent_once_and_names_the_rule(stack, gw, on):
    e, lane = setup(stack)
    made = rule(stack, e, note="Juice Shop demo")
    job = start(stack, e, lane)
    assert job.spec["context"]["writes"]["lab_write_rules"][0]["rule"] == made["id"]
    tb = tools(gw, job)
    p = propose(tb)
    assert p["status"] == "approved" and "lab write rule" in p["note"] and gw.up.requests == []
    w = status(tb)[p["proposal_id"]]
    assert w["status"] == "sent" and "lab write rule" in w["approved_by"]
    assert [(u["method"], u["target"]) for u in gw.up.requests] == [("POST", "/api/Users")]
    # Used once, as any approval.
    assert status(tb)[p["proposal_id"]]["status"] == "sent" and len(gw.up.requests) == 1
    gw.flush()
    with stack.Session() as s:
        wp = s.get(WriteProposal, p["proposal_id"])
        assert wp.rule_id == made["id"] and wp.rule_sod_met is False
        summary = vault.summary_of(s.get(Evidence, wp.evidence_id))
        assert "a lab write rule approved it" in summary and "not a person reading this request" in summary
        assert "separation of duties not met" in summary
        assert s.get(LabWriteRule, made["id"]).used == 1
    assert actions(stack, e)[-3:] == ["lab_rule.created", "write.rule_approved", "write.sent"]
    item = queue(stack, e)["items"][0]
    assert item["rule_id"] == made["id"] and item["separation_of_duties_met"] is False
    listed = stack.api.get(f"/engagements/{e}/lab-write-rules").json()
    assert listed["deployment_allows"] and listed["rules"][0]["used"] == 1


def test_a_delete_only_when_the_rule_lists_it(stack, gw, on):
    e, lane = setup(stack)
    rule(stack, e)                                            # POST, PUT, PATCH
    tb = tools(gw, start(stack, e, lane))
    d = propose(tb, method="DELETE", path="/api/Feedbacks/7", body="")
    assert d["status"] == "pending"
    assert status(tb)[d["proposal_id"]]["status"] == "pending" and gw.up.requests == []
    rule(stack, e, methods=["DELETE"], paths=["/api/Feedbacks/*"])
    d2 = propose(tb, method="DELETE", path="/api/Feedbacks/8", body="")
    assert d2["status"] == "approved"
    assert status(tb, d2["proposal_id"])[d2["proposal_id"]]["status"] == "sent"
    assert [(u["method"], u["target"]) for u in gw.up.requests] == [("DELETE", "/api/Feedbacks/8")]
    # The first DELETE still waits for a person: a rule approves what is proposed after it.
    assert status(tb)[d["proposal_id"]]["status"] == "pending"


def test_paths_cap_end_and_revoke(stack, gw, on):
    e, lane = setup(stack)
    made = rule(stack, e, paths=["/api/Users", "/rest/user/*"], max_writes=2)
    tb = tools(gw, start(stack, e, lane))
    assert propose(tb, path="/api/Products")["status"] == "pending"           # not one of its paths
    assert propose(tb, path="/rest/user/login")["status"] == "approved"
    assert propose(tb)["status"] == "approved"
    assert propose(tb)["status"] == "pending"                                # the cap of 2 is used
    with stack.Session() as s:
        s.get(LabWriteRule, made["id"]).max_writes = 10
        s.get(LabWriteRule, made["id"]).expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        s.commit()
    assert propose(tb)["status"] == "pending"                                # ended
    second = rule(stack, e)
    assert propose(tb)["status"] == "approved"
    assert stack.api.post(f"/engagements/{e}/lab-write-rules/{second['id']}/revoke").json()["state"] == "revoked"
    assert propose(tb)["status"] == "pending"
    assert actions(stack, e).count("write.rule_approved") == 3 and "lab_rule.revoked" in actions(stack, e)


def test_separation_of_duties(stack, gw, on):
    e, lane = setup(stack)
    made = rule(stack, e)
    with stack.Session() as s:
        s.add_all([User(email="maker@lab.test", name="Maker", password_hash="x"), User(email="starter@lab.test", name="Starter", password_hash="x")])
        s.commit()
        maker, starter = (s.scalar(select(User.id).where(User.email == m))
                          for m in ("maker@lab.test", "starter@lab.test"))
        s.get(Engagement, e).separation_of_duties = True
        s.commit()
    job = start(stack, e, lane)
    tb = tools(gw, job)
    # The setting on and the same caller (the operator) made the rule and started the run: a person decides.
    assert propose(tb)["status"] == "pending"
    with stack.Session() as s:
        s.get(LabWriteRule, made["id"]).created_by = maker
        s.get(Job, job.id).created_by = maker
        s.commit()
    assert propose(tb)["status"] == "pending"
    with stack.Session() as s:
        s.get(Job, job.id).created_by = starter
        s.commit()
    p = propose(tb)
    assert p["status"] == "approved"
    with stack.Session() as s:
        assert s.get(WriteProposal, p["proposal_id"]).rule_sod_met is True
    assert status(tb)[p["proposal_id"]]["status"] == "sent"


def test_the_per_request_flow_is_unchanged_without_a_rule(stack, gw, on):
    e, lane = setup(stack)
    tb = tools(gw, start(stack, e, lane))
    p = propose(tb)
    assert p["status"] == "pending" and gw.up.requests == []
    item = queue(stack, e)["items"][0]
    assert item["rule_id"] is None and item["needs_delete_confirmation"] is False
    r = stack.api.post(f"/engagements/{e}/approvals/{p['proposal_id']}/approve",
                       json={"request_sha256": item["request_sha256"]})
    assert r.json()["status"] == "approved"
    assert status(tb)[p["proposal_id"]]["status"] == "sent"
    assert actions(stack, e)[-2:] == ["write.approved", "write.sent"]


def test_the_audit_descriptions():
    from app import auditlog
    made = auditlog.describe({"action": "lab_rule.created", "change": {"after": {
        "rule": 3, "methods": ["POST", "DELETE"], "hosts": [LAB], "paths": ["/*"], "max_writes": 300,
        "expires_at": "2026-10-17T00:00:00Z", "note": "demo"}}, "actor": {"kind": "token"}})
    assert "lab write rule #3" in made and "POST, DELETE" in made and LAB in made
    sent = auditlog.describe({"action": "write.rule_approved", "change": {"after": {
        "proposal": 9, "method": "POST", "host": LAB, "request_sha256": "a" * 64, "rule": 3, "used": 1,
        "max_writes": 300, "separation_of_duties_met": False}}, "actor": {"kind": "token"}})
    assert "lab write rule #3" in sent and "separation of duties not met" in sent
