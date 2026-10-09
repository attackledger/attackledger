"""The API's side of the traffic gateway (D-039, docs/GATEWAY.md).

The gateway holds no database credentials. It learns who a job credential belongs to, and that
engagement's rules, from these routes, and writes its request log through them. They are
authenticated with the gateway token (authz permission "gateway"), which only the gateway and
the API can read. A gateway token belongs to one organization (the deployment's own token to the
default one, orgs.py): it sees that organization's jobs, scopes and log only. This is the channel D-042 asks for: in a later hybrid service the gateway can
stay in the customer's network and talk to a hosted API the same way.

  POST /gateway/session        a job credential -> the job's engagement, traffic class and rules
  GET  /gateway/dns-scopes     scope rules of every engagement that has a running job
  POST /gateway/log            a batch of request-log rows
  POST /gateway/account        a job credential, a test account label and a host -> the headers to
                               add (D-040). The material leaves the API only here, to the gateway
  POST /gateway/approval       a job credential and an approved write -> the request to send, once
                               (D-041); the approval is used by this call

And for people:

  GET  /engagements/{id}/gateway-log   totals and the latest rows of an engagement's log
"""
import hashlib
import hmac
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import approvals, modules, testaccounts
from .db import get_session
from .models import Engagement, GatewayRequest, Job, JobStatus, iso_utc

router = APIRouter()


class SessionIn(BaseModel):
    job_id: int
    secret: str = Field(min_length=16, max_length=200)


def traffic_of(kind: str) -> str | None:
    """What a job may send: its module's traffic class (modules.py), "agent", or "none" for a
    module that only computes (the gateway then refuses everything it might send)."""
    if kind == "agent":
        return "agent"
    m = modules.get(kind)
    if m is None:
        return None
    return "none" if m.computed else m.traffic


def _running_job(session, job_id: int, secret: str) -> Job:
    """The job a credential belongs to, while it runs on an authorized engagement with scope."""
    job = session.get(Job, job_id)
    if job is None or not job.gateway_secret_sha256:
        raise HTTPException(404, f"job {job_id} has no gateway credential")
    if not hmac.compare_digest(hashlib.sha256(secret.encode()).hexdigest(), job.gateway_secret_sha256):
        raise HTTPException(403, f"wrong secret for job {job.id}")
    if job.status != JobStatus.running:
        raise HTTPException(403, f"job {job.id} is {job.status.value}, not running")
    eng: Engagement = job.engagement
    if eng.authorized_at is None:
        raise HTTPException(403, "no authorization is recorded for this engagement")
    if not eng.scope_include:
        raise HTTPException(403, "the engagement has no scope rules")
    return job


@router.post("/gateway/session")
def gateway_session(body: SessionIn, session: Session = Depends(get_session)):
    job = _running_job(session, body.job_id, body.secret)
    eng: Engagement = job.engagement
    traffic = traffic_of(job.kind)
    if traffic is None:
        raise HTTPException(403, f"unknown job kind {job.kind}")
    return {"job_id": job.id, "engagement_id": eng.id, "organization_id": job.organization_id,
            "kind": job.kind, "traffic": traffic,
            "include": list(eng.scope_include), "exclude": list(eng.scope_exclude or []),
            "rate_limit_rps": eng.rate_limit_rps, "research_header": eng.research_header,
            "research_user_agent": eng.research_user_agent, "redact": bool(eng.redact_evidence)}


class AccountIn(SessionIn):
    label: str = Field(min_length=1, max_length=16)
    host: str = Field(min_length=1, max_length=255)


@router.post("/gateway/account")
def gateway_account(body: AccountIn, session: Session = Depends(get_session)):
    """A test account's headers for one request of an agent job to one of its hosts (D-040).
    Only agent runs may send as a test account; recon tools stay unauthenticated."""
    job = _running_job(session, body.job_id, body.secret)
    if job.kind != "agent":
        raise HTTPException(403, f"a {job.kind} job does not send requests as a test account")
    eng = job.engagement
    if eng.content_deleted_at is not None:
        raise HTTPException(403, "this engagement's content was deleted, its test accounts with it")
    try:
        a = testaccounts.usable(session, eng, body.label, body.host.lower().rstrip("."))
    except ValueError as e:
        raise HTTPException(403, str(e))
    pairs = testaccounts.open_material(a)
    if pairs is None:
        raise HTTPException(503, f"the material of test account {a.label} cannot be opened")
    a.last_used_at = datetime.now(timezone.utc)
    session.commit()
    return {"label": a.label, "headers": pairs}


class ApprovalIn(SessionIn):
    approval_id: int
    method: str = Field(max_length=16)
    url: str = Field(max_length=4000)
    body_sha256: str = Field(pattern="^[0-9a-f]{64}$")
    account: str | None = Field(default=None, max_length=16)


@router.post("/gateway/approval")
def gateway_approval(body: ApprovalIn, session: Session = Depends(get_session)):
    """Use an approval (D-041): the gateway sends the request this answers with, once."""
    job = _running_job(session, body.job_id, body.secret)
    if job.kind != "agent":
        raise HTTPException(403, f"a {job.kind} job sends no writes")
    if not job.engagement.allow_writes:
        raise HTTPException(403, "this engagement does not allow writes")
    try:
        return approvals.consume(session, job=job, proposal_id=body.approval_id, method=body.method, url=body.url,
                                 body_sha256=body.body_sha256, account=body.account)
    except PermissionError as e:
        raise HTTPException(403, str(e))


@router.get("/gateway/dns-scopes")
def gateway_dns_scopes(session: Session = Depends(get_session)):
    ids = set(session.scalars(select(Job.engagement_id).where(Job.status == JobStatus.running)))
    out = []
    for eng in session.scalars(select(Engagement).where(Engagement.id.in_(ids)).order_by(Engagement.id)):
        if eng.authorized_at is not None and eng.scope_include:
            out.append({"engagement_id": eng.id, "include": list(eng.scope_include),
                        "exclude": list(eng.scope_exclude or []), "rate_limit_rps": eng.rate_limit_rps})
    return out


class LogRow(BaseModel):
    at: datetime
    engagement_id: int | None = None
    job_id: int | None = None
    tool: str = Field(max_length=32)
    kind: str = Field(pattern="^(target|passive|service|dns)$")
    method: str = Field(max_length=16)
    url: str = Field(max_length=2000)
    host: str = Field(default="", max_length=255)
    port: int | None = None
    status: int | None = None
    verdict: str = Field(pattern="^(allowed|refused|failed)$")
    reason: str = Field(default="", max_length=300)
    bytes_sent: int = Field(default=0, ge=0)
    bytes_received: int = Field(default=0, ge=0)
    duration_ms: int | None = None
    account: str | None = Field(default=None, max_length=16)
    approval_id: int | None = None


class LogIn(BaseModel):
    rows: list[LogRow] = Field(max_length=1000)


@router.post("/gateway/log")
def gateway_log(body: LogIn, session: Session = Depends(get_session)):
    engs = {r.engagement_id for r in body.rows if r.engagement_id is not None}
    jobs = {r.job_id for r in body.rows if r.job_id is not None}
    known_engs = set(session.scalars(select(Engagement.id).where(Engagement.id.in_(engs)))) if engs else set()
    known_jobs = set(session.scalars(select(Job.id).where(Job.id.in_(jobs)))) if jobs else set()
    for r in body.rows:
        at = r.at if r.at.tzinfo else r.at.replace(tzinfo=timezone.utc)
        session.add(GatewayRequest(
            at=at.astimezone(timezone.utc).replace(tzinfo=None),
            engagement_id=r.engagement_id if r.engagement_id in known_engs else None,
            job_id=r.job_id if r.job_id in known_jobs else None, tool=r.tool, kind=r.kind, method=r.method,
            url=r.url, host=r.host, port=r.port, status=r.status, verdict=r.verdict, reason=r.reason,
            bytes_sent=r.bytes_sent, bytes_received=r.bytes_received, duration_ms=r.duration_ms,
            account=r.account, approval_id=r.approval_id))
        if r.approval_id is not None:
            approvals.gateway_outcome(session, r.approval_id, r.verdict, r.status, r.reason)
    session.commit()
    return {"written": len(body.rows)}


def _row_view(g: GatewayRequest) -> dict:
    return {"id": g.id, "at": iso_utc(g.at), "job_id": g.job_id, "tool": g.tool, "kind": g.kind,
            "method": g.method, "url": g.url, "status": g.status, "verdict": g.verdict, "reason": g.reason,
            "bytes_sent": g.bytes_sent, "bytes_received": g.bytes_received, "duration_ms": g.duration_ms,
            "account": g.account, "approval_id": g.approval_id}


@router.get("/engagements/{eng_id}/gateway-log")
def engagement_gateway_log(eng_id: int, limit: int = 100, offset: int = 0, verdict: str | None = None,
                           job_id: int | None = None, session: Session = Depends(get_session)):
    if session.get(Engagement, eng_id) is None:
        raise HTTPException(404, "not found")
    where = [GatewayRequest.engagement_id == eng_id]
    if verdict:
        where.append(GatewayRequest.verdict == verdict)
    if job_id is not None:
        where.append(GatewayRequest.job_id == job_id)

    def totals(col):
        return dict(session.execute(select(col, func.count()).where(*where).group_by(col)).all())
    rows = session.scalars(select(GatewayRequest).where(*where).order_by(GatewayRequest.id.desc())
                           .limit(max(1, min(limit, 1000))).offset(max(0, offset))).all()
    return {"total": session.scalar(select(func.count()).select_from(GatewayRequest).where(*where)),
            "by_verdict": totals(GatewayRequest.verdict), "by_kind": totals(GatewayRequest.kind),
            "by_method": totals(GatewayRequest.method), "rows": [_row_view(g) for g in rows]}
