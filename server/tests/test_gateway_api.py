"""The API's gateway routes (gatewayapi.py): only the gateway's token opens them, a job
credential is valid only while its job runs, and the request log is written and read back."""
import hashlib
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import db
from app.models import Engagement, Job, JobStatus

TOKEN = "gateway-token-for-tests-000000000"
SECRET = "job-secret-for-tests-0000000000"


@pytest.fixture()
def api(monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app
    monkeypatch.setenv("ATTACKLEDGER_GATEWAY_TOKEN", TOKEN)
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
        c.Session = Session
        yield c
    app.dependency_overrides.clear()


def setup(api, kind="probe", status=JobStatus.running, authorized=True, name="e1"):
    with api.Session() as s:
        e = Engagement(name=name, scope_include=["*.example.com"], scope_exclude=["admin.example.com"],
                       rate_limit_rps=7, research_header="X-Bug-Bounty: r1",
                       authorized_by="op" if authorized else None,
                       authorized_at=datetime.now(timezone.utc) if authorized else None)
        s.add(e)
        s.commit()
        j = Job(engagement_id=e.id, kind=kind, targets=[], status=status,
                gateway_secret_sha256=hashlib.sha256(SECRET.encode()).hexdigest())
        s.add(j)
        s.commit()
        return e.id, j.id


def gw(api, method, path, token=TOKEN, **kw):
    return api.request(method, path, headers={"authorization": f"Bearer {token}"} if token else {}, **kw)


def test_gateway_routes_need_the_gateway_token(api, monkeypatch):
    _, job = setup(api)
    body = {"job_id": job, "secret": SECRET}
    assert gw(api, "POST", "/gateway/session", token=None, json=body).status_code == 401
    assert gw(api, "POST", "/gateway/session", token="wrong", json=body).status_code == 401
    assert gw(api, "GET", "/gateway/dns-scopes", token=None).status_code == 401
    assert gw(api, "POST", "/gateway/log", token=None, json={"rows": []}).status_code == 401
    monkeypatch.setenv("ATTACKLEDGER_API_TOKEN", "operator-token")            # an owner is not the gateway
    assert gw(api, "POST", "/gateway/session", token="operator-token", json=body).status_code == 401
    monkeypatch.delenv("ATTACKLEDGER_GATEWAY_TOKEN")                         # no token configured: closed
    assert gw(api, "POST", "/gateway/session", token=TOKEN, json=body).status_code == 503


def test_session_gives_the_rules_of_a_running_job_only(api):
    eng, job = setup(api)
    r = gw(api, "POST", "/gateway/session", json={"job_id": job, "secret": SECRET})
    assert r.status_code == 200
    assert r.json() == {"job_id": job, "engagement_id": eng, "organization_id": 1, "kind": "probe", "traffic": "target",
                        "include": ["*.example.com"], "exclude": ["admin.example.com"], "rate_limit_rps": 7,
                        "research_header": "X-Bug-Bounty: r1", "research_user_agent": None, "redact": True}
    r = gw(api, "POST", "/gateway/session", json={"job_id": job, "secret": "x" * 31})
    assert r.status_code == 403 and "wrong secret" in r.json()["detail"]
    assert gw(api, "POST", "/gateway/session", json={"job_id": 999, "secret": SECRET}).status_code == 404
    with api.Session() as s:
        s.get(Job, job).status = JobStatus.cancelled
        s.commit()
    r = gw(api, "POST", "/gateway/session", json={"job_id": job, "secret": SECRET})
    assert r.status_code == 403 and "cancelled, not running" in r.json()["detail"]


def test_session_refuses_unauthorized_engagements_and_names_the_traffic_class(api):
    _, job = setup(api, authorized=False)
    r = gw(api, "POST", "/gateway/session", json={"job_id": job, "secret": SECRET})
    assert r.status_code == 403 and "authorization" in r.json()["detail"]
    for i, (kind, traffic) in enumerate((("archive", "passive"), ("resolve", "dns"), ("agent", "agent"),
                                         ("dorks", "none"), ("paramclass", "none"), ("nuclei", "target"))):
        _, job = setup(api, kind=kind, name=f"e{i + 2}")
        assert gw(api, "POST", "/gateway/session", json={"job_id": job, "secret": SECRET}).json()["traffic"] == traffic


def test_dns_scopes_list_engagements_with_running_jobs(api):
    eng, _ = setup(api)
    setup(api, status=JobStatus.done, name="idle")
    assert gw(api, "GET", "/gateway/dns-scopes").json() == [
        {"engagement_id": eng, "include": ["*.example.com"], "exclude": ["admin.example.com"], "rate_limit_rps": 7}]


def test_request_log_is_written_by_the_gateway_and_read_by_members(api):
    eng, job = setup(api)
    rows = [{"at": "2026-10-09T12:00:00+00:00", "engagement_id": eng, "job_id": job, "tool": "httpx",
             "kind": "target", "method": "GET", "url": "https://app.example.com/", "host": "app.example.com",
             "port": 443, "status": 200, "verdict": "allowed", "bytes_received": 10, "duration_ms": 5},
            {"at": "2026-10-09T12:00:01+00:00", "engagement_id": eng, "job_id": job, "tool": "nuclei",
             "kind": "target", "method": "POST", "url": "https://app.example.com/x", "status": 403,
             "verdict": "refused", "reason": "POST is refused"},
            {"at": "2026-10-09T12:00:02+00:00", "engagement_id": None, "job_id": 12345, "tool": "unknown",
             "kind": "target", "method": "GET", "url": "http://evil.test/", "status": 407, "verdict": "refused"}]
    assert gw(api, "POST", "/gateway/log", json={"rows": rows}).json() == {"written": 3}
    bad = {**rows[0], "verdict": "maybe"}
    assert gw(api, "POST", "/gateway/log", json={"rows": [bad]}).status_code == 422
    log = api.get(f"/engagements/{eng}/gateway-log").json()     # open mode: the local operator reads it
    assert log["total"] == 2 and log["by_verdict"] == {"allowed": 1, "refused": 1}
    assert log["by_method"] == {"GET": 1, "POST": 1} and log["rows"][0]["method"] == "POST"
    assert log["rows"][1]["at"].startswith("2026-10-09T12:00:00")
    assert api.get(f"/engagements/{eng}/gateway-log?verdict=refused").json()["total"] == 1
    # The row for an unknown job is kept, without a job the database does not have.
    from app.models import GatewayRequest
    with api.Session() as s:
        orphan = s.query(GatewayRequest).filter(GatewayRequest.url == "http://evil.test/").one()
        assert orphan.job_id is None and orphan.engagement_id is None
