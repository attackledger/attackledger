"""Writes only with a person's approval (D-041, docs/APPROVALS.md).

An engagement rule, off by default (Engagement.allow_writes), decides whether an agent may
propose a state-changing request at all. When it is off, POST, PUT, PATCH and DELETE are refused
before anything is sent, as before. When it is on:

  1. the agent proposes one (agenttools propose_write): method, URL, headers, body, the test
     account it is sent as, the checklist item and its reason. The request is sealed with the
     engagement's key and hashed (request_sha256). Nothing is sent;
  2. a person with the tester role (or an owner) reads the full request in the approval queue and
     approves it, naming the hash they read, or rejects it with a note. A DELETE needs a second,
     separate step: the person types the URL's path to confirm it;
  3. the approval is for that exact request, and it expires (APPROVAL_MINUTES). The agent's run
     sends it through the gateway, which asks the API to use the approval (consume): the method,
     URL, body and account must match the approved request, and an approval is used once. The
     gateway then sends the approved request itself (its headers, not the worker's), under the same
     scope, rate and identification rules as any other request;
  4. the exchange becomes evidence (source "agent") with a note that a person approved it. The
     approval, the rejection, the DELETE confirmation and the sending are audit-logged.

With separation of duties on, the person who started the agent run cannot approve its writes,
and neither can the operator token. Viewers and reviewers cannot approve: approving a write is
changing the target, which is the tester's work under the rules of engagement; reviewing evidence
and signing receipts stays a separate duty.

  GET  /engagements/{id}/approvals                         the queue and recent decisions (tester)
  POST /engagements/{id}/approvals/{pid}/approve           approve (tester); a DELETE then waits
  POST /engagements/{id}/approvals/{pid}/confirm-delete    the DELETE's second step (tester)
  POST /engagements/{id}/approvals/{pid}/reject            reject, with a note (tester)
"""
import base64
import binascii
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete as sa_delete, func, select, update
from sqlalchemy.orm import Session

from . import auditlog, authz, ledger, redact, vault
from .db import get_session
from .models import Engagement, Job, JobStatus, Lane, User, WriteProposal, iso_utc

router = APIRouter()

WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
STATUSES = ("pending", "confirming", "approved", "rejected", "sent", "failed", "expired")
OPEN = ("pending", "confirming", "approved")     # not decided for good, nothing sent yet
PURPOSE = "write-proposal"
MAX_BODY = 1_000_000            # bytes of a proposed body
MAX_PENDING = 20                # undecided proposals per run
APPROVAL_MINUTES = int(os.environ.get("ATTACKLEDGER_APPROVAL_MINUTES", "15"))
GATEWAY_ACTOR = {"kind": "gateway", "user_id": None, "name": "the traffic gateway", "email": None}


def now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(t: datetime | None) -> datetime | None:
    return t.replace(tzinfo=timezone.utc) if t is not None and t.tzinfo is None else t


def canonical_request(method: str, url: str, headers: list, body: bytes, account: str | None) -> str:
    """What an approval binds: its SHA-256 is request_sha256. Headers keep their order."""
    return ledger.canonical({"method": method, "url": url, "headers": [[str(k), str(v)] for k, v in headers],
                             "body_b64": base64.b64encode(body).decode(), "account": account or None})


def norm_url(url: str) -> str:
    """The URL as compared: scheme and host in lower case, no default port, no fragment."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().rstrip(".")
    port = parts.port
    default = {"http": 80, "https": 443}.get(parts.scheme.lower())
    netloc = host if port in (None, default) else f"{host}:{port}"
    return parts._replace(scheme=parts.scheme.lower(), netloc=netloc, fragment="").geturl()


def body_sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def request_of(p: WriteProposal) -> dict | None:
    """The exact request, opened; None once the engagement's content was deleted."""
    text = vault.open_secret(p.engagement_id, PURPOSE, p.request_enc, p.request_sha256)
    return None if text is None else json.loads(text)


def expire_if_due(p: WriteProposal, at: datetime | None = None) -> bool:
    if p.status in OPEN and p.expires_at is not None and _aware(p.expires_at) <= (at or now()):
        p.status = "expired"
        p.decision_note = (p.decision_note or "") + (" " if p.decision_note else "") + "(the approval expired unused)"
        return True
    return False


# ---- proposing (the agent's side, run in the API by agenttools.Toolbox) ----------------

def propose(session, *, eng: Engagement, lane: Lane, job_id: int | None, method: str, url: str, headers: list,
            body: bytes, account: str | None, item_idx: int, reason: str) -> WriteProposal:
    """Store a proposal. The caller has checked the URL, headers, account and item; this checks
    the engagement's rule and the run's limit. Raises ValueError for the agent to read."""
    if not eng.allow_writes:
        raise ValueError(f"{method} is not allowed; this engagement does not allow writes, so only read-only "
                         "requests are sent (an owner can allow agents to propose writes)")
    if method not in WRITE_METHODS:
        raise ValueError(f"propose_write is for {', '.join(WRITE_METHODS)}; send {method} with http_request")
    if len(body) > MAX_BODY:
        raise ValueError(f"the body is longer than {MAX_BODY} bytes")
    if job_id is not None:
        waiting = session.scalar(select(func.count()).select_from(WriteProposal).where(
            WriteProposal.job_id == job_id, WriteProposal.status.in_(OPEN))) or 0
        if waiting >= MAX_PENDING:
            raise ValueError(f"this run already has {MAX_PENDING} writes waiting; check write_status first")
    vault.check_writable(eng)
    text = canonical_request(method, url, headers, body, account)
    sealed, digest = vault.seal_secret(eng.id, PURPOSE, text)
    rep = redact.Report()
    p = WriteProposal(engagement_id=eng.id, lane_id=lane.id, job_id=job_id, item_idx=item_idx, method=method,
                      url=redact.text(url, rep)[:4000], host=lane.asset.host, account=account or None,
                      reason=redact.text(reason, rep), request_enc=sealed, request_sha256=digest,
                      body_sha256=body_sha(body), status="pending")
    session.add(p)
    session.flush()
    return p


def status_for_agent(p: WriteProposal) -> dict:
    """One proposal as the agent reads it (write_status): what happened, in a sentence."""
    out = {"proposal_id": p.id, "method": p.method, "url": p.url, "account": p.account, "status": p.status}
    if p.status == "pending":
        out["note"] = "waiting for a person's approval; nothing has been sent"
    elif p.status == "confirming":
        out["note"] = "approved, waiting for the person's DELETE confirmation; nothing has been sent"
    elif p.status == "approved":
        out["note"] = "approved by a person; it is sent once, now"
    elif p.status == "rejected":
        out["note"] = f"rejected by a person: {p.decision_note or 'no note'}"
    elif p.status == "sent":
        out["note"] = (f"approved and sent: status {p.response_status}" if p.response_status is not None
                       else "approved and sent; no response was recorded")
        if p.exchange_id:
            out["exchange_id"] = p.exchange_id
    elif p.status == "failed":
        out["note"] = f"approved, but the gateway could not send it: {p.decision_note or 'no reason recorded'}"
    elif p.status == "expired":
        out["note"] = p.decision_note or "expired before it was sent"
    return out


def for_job(session, job_id: int, ids: list[int] | None = None) -> list[WriteProposal]:
    q = select(WriteProposal).where(WriteProposal.job_id == job_id)
    if ids:
        q = q.where(WriteProposal.id.in_(ids))
    rows = list(session.scalars(q.order_by(WriteProposal.id)))
    for p in rows:
        expire_if_due(p)
    return rows


def end_job(session, job_id: int) -> None:
    """A run that ends can no longer send its writes: undecided and unsent ones expire."""
    session.execute(update(WriteProposal).where(WriteProposal.job_id == job_id, WriteProposal.status.in_(OPEN))
                    .values(status="expired", decision_note="the agent run ended before it was sent"))


def wipe(session, eng_id: int) -> dict:
    """Deleting an engagement's content (D-043) deletes the proposals still waiting, and the
    sealed request of the others (their method, host, decision and hash stay with the history)."""
    n = session.execute(sa_delete(WriteProposal).where(WriteProposal.engagement_id == eng_id,
                                                       WriteProposal.status.in_(OPEN))).rowcount or 0
    session.execute(update(WriteProposal).where(WriteProposal.engagement_id == eng_id)
                    .values(request_enc=None, url="", reason="", decision_note=None))
    return {"write_proposals": n}


# ---- the gateway's side --------------------------------------------------------------------

def consume(session, *, job: Job, proposal_id: int, method: str, url: str, body_sha256: str,
            account: str | None) -> dict:
    """The gateway is about to send an approved write: check that it is this job's, approved, not
    expired and not used, and that the method, URL, body and account are the approved ones; then
    mark it sent, so it is never used again. Returns the request the gateway sends. Raises
    PermissionError with the reason."""
    if session.bind.dialect.name == "postgresql":
        p = session.scalars(select(WriteProposal).where(WriteProposal.id == proposal_id).with_for_update()).first()
    else:
        p = session.get(WriteProposal, proposal_id)
    if p is None or p.job_id != job.id:
        raise PermissionError(f"approval {proposal_id} is not one of this run's writes")
    if expire_if_due(p):
        session.commit()
        raise PermissionError(f"approval {proposal_id} expired before it was used")
    if p.status != "approved":
        raise PermissionError(f"write {proposal_id} is {p.status}, not approved" +
                              ("; an approval is used once" if p.status in ("sent", "failed") else ""))
    req = request_of(p)
    if req is None or p.approved_sha256 != p.request_sha256:
        raise PermissionError(f"the approved request {proposal_id} can no longer be read")
    if (method, norm_url(url)) != (req["method"], norm_url(req["url"])):
        raise PermissionError(f"the request is not the approved one: {method} {url[:200]} differs from what "
                              "the person approved")
    if body_sha256 != p.body_sha256:
        raise PermissionError("the body is not the approved one")
    if (account or None) != (req.get("account") or None):
        raise PermissionError("the test account is not the approved one")
    p.status, p.sent_at = "sent", now()
    auditlog.append(session, actor=GATEWAY_ACTOR, action="write.sent", engagement_id=p.engagement_id,
                    change={"after": _audit_ref(p)})
    session.commit()
    return {"approval_id": p.id, "method": req["method"], "url": req["url"], "headers": req["headers"],
            "account": req.get("account")}


def gateway_outcome(session, approval_id: int, verdict: str, status: int | None, reason: str) -> None:
    """The gateway's log row for an approved write: the response status, or why it failed."""
    p = session.get(WriteProposal, approval_id)
    if p is None or p.status != "sent" or p.response_status is not None:
        return
    if verdict == "allowed":
        p.response_status = status
    else:
        p.status, p.decision_note = "failed", (reason or verdict)[:500]


# ---- people: the queue --------------------------------------------------------------------

def _audit_ref(p: WriteProposal) -> dict:
    return {"proposal": p.id, "method": p.method, "host": p.host, "account": p.account, "lane_id": p.lane_id,
            "job_id": p.job_id, "request_sha256": p.request_sha256}


def _who_label(who) -> str:
    return auditlog.actor_label(auditlog.actor(who))


def view(session, p: WriteProposal, names: dict[int, str], full: bool) -> dict:
    lane = session.get(Lane, p.lane_id)
    job = session.get(Job, p.job_id) if p.job_id else None
    out = {"id": p.id, "status": p.status, "method": p.method, "url": p.url, "host": p.host, "account": p.account,
           "reason": p.reason, "item_idx": p.item_idx, "lane_id": p.lane_id, "lane_role": lane.role if lane else None,
           "job_id": p.job_id, "job_running": bool(job and job.status == JobStatus.running),
           "proposed_by": (f"agent run {p.job_id}" + (f", driven by {job.driver}" if job and job.driver else "")
                           + (f", started by {names.get(job.created_by)}" if job and job.created_by else "")),
           "request_sha256": p.request_sha256, "created_at": iso_utc(p.created_at),
           "decided_by": p.decided_by_name, "decided_at": iso_utc(p.decided_at), "note": p.decision_note,
           "expires_at": iso_utc(p.expires_at), "sent_at": iso_utc(p.sent_at), "response_status": p.response_status,
           "evidence_id": p.evidence_id, "needs_delete_confirmation": p.method == "DELETE",
           "confirm_path": urlsplit(p.url).path or "/"}
    if full and p.status in OPEN:
        req = request_of(p)
        if req is not None:
            body = base64.b64decode(req["body_b64"])
            rep = redact.Report()
            out["request"] = {"method": req["method"], "url": req["url"], "account": req.get("account"),
                              "headers": redact.headers(req["headers"], rep),
                              "body": body.decode("utf-8", "replace"), "body_bytes": len(body)}
            out["confirm_path"] = urlsplit(req["url"]).path or "/"
    return out


class DecideIn(BaseModel):
    request_sha256: str = Field(pattern="^[0-9a-f]{64}$")     # the request the person read
    note: str | None = Field(default=None, max_length=2000)


class ConfirmDeleteIn(BaseModel):
    request_sha256: str = Field(pattern="^[0-9a-f]{64}$")
    confirm_path: str = Field(max_length=4000)                 # the URL's path, typed by the person


class RejectIn(BaseModel):
    note: str = Field(min_length=1, max_length=2000)


def _proposal(session, eng_id: int, pid: int) -> WriteProposal:
    p = session.get(WriteProposal, pid)
    if p is None or p.engagement_id != eng_id:
        raise HTTPException(404, "no such write on this engagement")
    if expire_if_due(p):
        session.commit()
    return p


def _check_decider(session, eng: Engagement, p: WriteProposal, who) -> None:
    if eng.content_deleted_at is not None:
        raise HTTPException(409, vault.deleted_sentence(vault.deleted_info(eng)))
    job = session.get(Job, p.job_id) if p.job_id else None
    if job is None or job.status != JobStatus.running:
        raise HTTPException(409, "the agent run that proposed this write has ended; it can no longer be sent")
    if eng.separation_of_duties:
        if who.kind != "person":
            raise HTTPException(403, "separation of duties is on: a person approves writes, not the operator token")
        if job.created_by is not None and who.user_id == job.created_by:
            raise HTTPException(403, "separation of duties is on: whoever started the agent run cannot approve its "
                                     "writes")


def _note(text: str | None) -> str | None:
    t = (text or "").strip()
    return redact.text(t, redact.Report()) if t else None


@router.get("/engagements/{eng_id}/approvals")
def list_approvals(eng_id: int, status: str | None = None, session: Session = Depends(get_session)):
    eng = session.get(Engagement, eng_id)
    if eng is None:
        raise HTTPException(404, "not found")
    q = select(WriteProposal).where(WriteProposal.engagement_id == eng_id)
    if status == "open":
        q = q.where(WriteProposal.status.in_(OPEN))
    elif status:
        q = q.where(WriteProposal.status == status)
    rows = list(session.scalars(q.order_by(WriteProposal.id.desc()).limit(100)))
    if any(expire_if_due(p) for p in rows):
        session.commit()
    names = {u.id: u.name for u in session.scalars(select(User))}
    waiting = session.scalar(select(func.count()).select_from(WriteProposal).where(
        WriteProposal.engagement_id == eng_id, WriteProposal.status.in_(("pending", "confirming")))) or 0
    return {"allow_writes": bool(eng.allow_writes), "separation_of_duties": bool(eng.separation_of_duties),
            "approval_minutes": APPROVAL_MINUTES, "waiting": waiting,
            "items": [view(session, p, names, full=True) for p in rows]}


@router.post("/engagements/{eng_id}/approvals/{pid}/approve")
def approve(eng_id: int, pid: int, body: DecideIn, request: Request, session: Session = Depends(get_session)):
    eng = session.get(Engagement, eng_id)
    p = _proposal(session, eng_id, pid)
    who = authz.current(request)
    if p.status != "pending":
        raise HTTPException(409, f"this write is {p.status}; only a pending write can be approved")
    _check_decider(session, eng, p, who)
    if body.request_sha256 != p.request_sha256:
        raise HTTPException(409, "the request you read is not the one waiting; reload and read it again")
    if request_of(p) is None:
        raise HTTPException(409, "the request can no longer be read")
    p.decided_by, p.decided_by_name, p.decided_at = who.user_id, _who_label(who), now()
    p.decision_note, p.approved_sha256 = _note(body.note), p.request_sha256
    p.status = "confirming" if p.method == "DELETE" else "approved"
    if p.status == "approved":
        p.expires_at = now() + timedelta(minutes=APPROVAL_MINUTES)
    auditlog.append(session, actor=auditlog.actor(who), action="write.approved", engagement_id=eng_id,
                    change={"after": {**_audit_ref(p), "note": p.decision_note,
                                      "waits_for_delete_confirmation": p.method == "DELETE"}})
    session.commit()
    return view(session, p, {}, full=True)


@router.post("/engagements/{eng_id}/approvals/{pid}/confirm-delete")
def confirm_delete(eng_id: int, pid: int, body: ConfirmDeleteIn, request: Request,
                   session: Session = Depends(get_session)):
    eng = session.get(Engagement, eng_id)
    p = _proposal(session, eng_id, pid)
    who = authz.current(request)
    if p.method != "DELETE" or p.status != "confirming":
        raise HTTPException(409, "only an approved DELETE waits for this confirmation")
    _check_decider(session, eng, p, who)
    if who.user_id != p.decided_by or _who_label(who) != p.decided_by_name:
        raise HTTPException(403, "the person who approved this DELETE confirms it")
    if body.request_sha256 != p.request_sha256:
        raise HTTPException(409, "the request you read is not the one waiting; reload and read it again")
    req = request_of(p)
    path = (urlsplit(req["url"]).path or "/") if req else None
    if path is None or body.confirm_path.strip() != path:
        raise HTTPException(422, "type the URL's path exactly to confirm the DELETE; nothing was approved")
    p.status, p.delete_confirmed_at = "approved", now()
    p.expires_at = now() + timedelta(minutes=APPROVAL_MINUTES)
    auditlog.append(session, actor=auditlog.actor(who), action="write.delete_confirmed", engagement_id=eng_id,
                    change={"after": {**_audit_ref(p), "path": path}})
    session.commit()
    return view(session, p, {}, full=True)


@router.post("/engagements/{eng_id}/approvals/{pid}/reject")
def reject(eng_id: int, pid: int, body: RejectIn, request: Request, session: Session = Depends(get_session)):
    p = _proposal(session, eng_id, pid)
    who = authz.current(request)
    if p.status not in OPEN:
        raise HTTPException(409, f"this write is {p.status}; it can no longer be rejected")
    p.status, p.decided_by, p.decided_by_name, p.decided_at = "rejected", who.user_id, _who_label(who), now()
    p.decision_note = _note(body.note)
    auditlog.append(session, actor=auditlog.actor(who), action="write.rejected", engagement_id=eng_id,
                    change={"after": {**_audit_ref(p), "note": p.decision_note}})
    session.commit()
    return view(session, p, {}, full=False)


def decode_body(b64: str) -> bytes:
    try:
        return base64.b64decode(b64 or "", validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("body_b64 is not base64")
