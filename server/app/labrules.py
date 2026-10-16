"""Lab write rules: a standing approval of writes on an intentionally vulnerable lab (D-062).

D-041 has a person read and approve every write an agent proposes. On a practice target that
exists to be broken (OWASP Juice Shop, the bundled shop) that is hundreds of approvals a run, so an
owner may approve a class of writes in advance instead. Two gates, both off by default:

  - the deployment: ATTACKLEDGER_LAB_WRITE_RULES=1 on the API. Without it no rule can be made and
    none approves anything, so a customer's install never has one unless its operator sets it;
  - the engagement: an owner makes a rule naming the methods (POST, PUT, PATCH, DELETE; a DELETE
    only when it is listed), the hosts, the paths (shell patterns, default "/*"), a cap on the
    writes it approves (default 300) and when it ends (default 24 hours, at most 7 days).

A rule is refused unless every host is in the engagement's scope and is a lab name: under .test
or .localhost, which are never delegated on the internet (RFC 6761). It is checked again each
time it would approve, so a scope change or turning the deployment's switch off ends it at once.

What stays the same: each write is still its own proposal, sealed and hashed, with a single-use
approval that expires, sent by the gateway under the same scope, rate and identification rules,
and recorded as evidence. The difference is who approved it: the evidence and the audit log say
"approved by lab write rule #N, made by X", not a person who read that request.

Separation of duties: when the rule's maker is the run's starter (or either is the operator token),
it is not met. With the engagement's separation-of-duties setting on, such a rule approves nothing
(the write waits for a person, as before); with it off (a solo demo) the write is approved and
every record of it says "separation of duties not met".

  GET  /engagements/{id}/lab-write-rules                 the rules (tester)
  POST /engagements/{id}/lab-write-rules                 make one (owner)
  POST /engagements/{id}/lab-write-rules/{rid}/revoke    end one now (owner)
"""
import fnmatch
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote, urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from . import auditlog, authz, redact, scope
from .db import get_session
from .models import Engagement, Job, LabWriteRule, User, WriteProposal, iso_utc

router = APIRouter()

ENV = "ATTACKLEDGER_LAB_WRITE_RULES"
METHODS = ("POST", "PUT", "PATCH", "DELETE")
LAB_SUFFIXES = (".test", ".localhost")
DEFAULT_MAX = 300
MAX_MAX = 10_000
DEFAULT_HOURS = 24
MAX_HOURS = 7 * 24
SOD_NOT_MET = "separation of duties not met: the rule's maker also started the run"


def enabled() -> bool:
    return os.environ.get(ENV, "").strip() == "1"


def now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(t: datetime | None) -> datetime | None:
    return t.replace(tzinfo=timezone.utc) if t is not None and t.tzinfo is None else t


def is_lab_host(host: str) -> bool:
    h = (host or "").lower().rstrip(".")
    return any(h.endswith(s) and len(h) > len(s) for s in LAB_SUFFIXES)


def why_not(eng: Engagement, hosts: list[str]) -> str | None:
    """Why these hosts cannot have a rule on this engagement, or None."""
    if not enabled():
        return (f"lab write rules are off on this deployment (set {ENV}=1 on the API to allow them, for a "
                "practice lab only)")
    if not hosts:
        return "name at least one host"
    for h in hosts:
        if not is_lab_host(h):
            return f"{h} is not a lab host: a rule is only for names under {' or '.join(LAB_SUFFIXES)}"
        if not scope.in_scope(h, eng.scope_include or [], eng.scope_exclude or []):
            return f"{h} is not in this engagement's scope"
    return None


def path_of(url: str) -> str:
    return unquote(urlsplit(url).path or "/")


def sod_met(rule: LabWriteRule, job: Job | None) -> bool:
    """Met only when two different people are named: the rule's maker and the run's starter."""
    return rule.created_by is not None and job is not None and job.created_by is not None \
        and job.created_by != rule.created_by


def active(session, eng: Engagement, method: str, url: str, at: datetime | None = None) -> list[LabWriteRule]:
    """The engagement's rules that would approve this write now, oldest first."""
    if not enabled() or eng.content_deleted_at is not None:
        return []
    at = at or now()
    parts = urlsplit(url)
    host, path = (parts.hostname or "").lower().rstrip("."), path_of(url)
    out = []
    for r in session.scalars(select(LabWriteRule).where(LabWriteRule.engagement_id == eng.id,
                                                        LabWriteRule.revoked_at.is_(None))
                             .order_by(LabWriteRule.id)):
        if _aware(r.expires_at) <= at or r.used >= r.max_writes:
            continue
        if method not in (r.methods or []) or host not in (r.hosts or []):
            continue
        if why_not(eng, [host]) is not None:
            continue
        if not any(fnmatch.fnmatchcase(path, p) for p in (r.paths or ["/*"])):
            continue
        out.append(r)
    return out


def label(r: LabWriteRule) -> str:
    return f"lab write rule #{r.id} (made by {r.created_by_name})"


def try_approve(session, eng: Engagement, p: WriteProposal, url: str, minutes: int) -> bool:
    """Approve a new proposal by a matching rule, if one has room. One conditional UPDATE takes a
    place under the cap, so two writes never both take its last one. The caller commits."""
    job = session.get(Job, p.job_id) if p.job_id else None
    for r in active(session, eng, p.method, url):
        met = sod_met(r, job)
        if eng.separation_of_duties and not met:
            continue                    # the setting holds: a person approves this one
        took = session.execute(update(LabWriteRule).where(LabWriteRule.id == r.id,
                                                          LabWriteRule.used < LabWriteRule.max_writes)
                               .values(used=LabWriteRule.used + 1)
                               .execution_options(synchronize_session=False)).rowcount == 1
        if not took:
            continue
        session.refresh(r)
        at = now()
        note = f"approved by {label(r)}, not by a person reading this request" + ("" if met else f"; {SOD_NOT_MET}")
        p.status, p.decided_by, p.decided_by_name, p.decided_at = "approved", r.created_by, label(r), at
        p.decision_note, p.approved_sha256 = note, p.request_sha256
        p.expires_at = at + timedelta(minutes=minutes)
        if p.method == "DELETE":
            p.delete_confirmed_at = at  # the rule lists DELETE (active() checked the method)
        p.rule_id, p.rule_sod_met = r.id, met
        session.flush()
        auditlog.append(session, actor=_rule_actor(session, r), action="write.rule_approved", engagement_id=eng.id,
                        change={"after": {"proposal": p.id, "method": p.method, "host": p.host, "account": p.account,
                                          "lane_id": p.lane_id, "job_id": p.job_id,
                                          "request_sha256": p.request_sha256, "rule": r.id,
                                          "separation_of_duties_met": met, "used": r.used,
                                          "max_writes": r.max_writes}})
        return True
    return False


def _rule_actor(session, r: LabWriteRule) -> dict:
    """The rule's maker: the approval is theirs, given in advance."""
    u = session.get(User, r.created_by) if r.created_by is not None else None
    if u is not None:
        return {"kind": "person", "user_id": u.id, "name": u.name, "email": u.email or None}
    return {"kind": "token", "user_id": None, "name": "operator token", "email": None}


def view(r: LabWriteRule, at: datetime | None = None) -> dict:
    at = at or now()
    state = ("revoked" if r.revoked_at else "expired" if _aware(r.expires_at) <= at
             else "used up" if r.used >= r.max_writes else "active")
    return {"id": r.id, "methods": list(r.methods or []), "hosts": list(r.hosts or []), "paths": list(r.paths or []),
            "max_writes": r.max_writes, "used": r.used, "expires_at": iso_utc(r.expires_at), "note": r.note,
            "created_by": r.created_by_name, "created_at": iso_utc(r.created_at), "revoked_at": iso_utc(r.revoked_at),
            "state": state, "deployment_allows": enabled()}


class RuleIn(BaseModel):
    methods: list[str] = Field(min_length=1, max_length=4)
    hosts: list[str] = Field(min_length=1, max_length=20)
    paths: list[str] = Field(default_factory=lambda: ["/*"], min_length=1, max_length=50)
    max_writes: int = Field(default=DEFAULT_MAX, ge=1, le=MAX_MAX)
    hours: float = Field(default=DEFAULT_HOURS, gt=0, le=MAX_HOURS)
    note: str | None = Field(default=None, max_length=2000)


def _eng(session, eng_id: int) -> Engagement:
    eng = session.get(Engagement, eng_id)
    if eng is None:
        raise HTTPException(404, "not found")
    return eng


@router.get("/engagements/{eng_id}/lab-write-rules")
def list_rules(eng_id: int, session: Session = Depends(get_session)):
    _eng(session, eng_id)
    rows = session.scalars(select(LabWriteRule).where(LabWriteRule.engagement_id == eng_id)
                           .order_by(LabWriteRule.id.desc()))
    return {"deployment_allows": enabled(), "rules": [view(r) for r in rows]}


@router.post("/engagements/{eng_id}/lab-write-rules", status_code=201)
def create_rule(eng_id: int, body: RuleIn, request: Request, session: Session = Depends(get_session)):
    eng = _eng(session, eng_id)
    if eng.content_deleted_at is not None:
        raise HTTPException(409, "this engagement's content was deleted")
    methods = sorted({m.strip().upper() for m in body.methods}, key=METHODS.index) \
        if all(m.strip().upper() in METHODS for m in body.methods) else None
    if not methods:
        raise HTTPException(422, f"methods are {', '.join(METHODS)} (a DELETE only when listed)")
    hosts = sorted({h.strip().lower().rstrip(".") for h in body.hosts})
    problem = why_not(eng, hosts)
    if problem:
        raise HTTPException(422 if enabled() else 403, problem)
    paths = []
    for p in body.paths:
        p = p.strip()
        if not p.startswith("/") or any(c in p for c in "\r\n"):
            raise HTTPException(422, f"a path pattern starts with / (e.g. /api/*): {p[:80]}")
        paths.append(p)
    who = authz.current(request)
    actor = auditlog.actor(who)
    note = redact.text(body.note.strip(), redact.Report()) if body.note and body.note.strip() else None
    r = LabWriteRule(engagement_id=eng.id, methods=methods, hosts=hosts, paths=paths, max_writes=body.max_writes,
                     used=0, expires_at=now() + timedelta(hours=body.hours), note=note,
                     created_by=who.user_id if who.kind == "person" else None,
                     created_by_name=auditlog.actor_label(actor))
    session.add(r)
    session.flush()
    auditlog.append(session, actor=actor, action="lab_rule.created", engagement_id=eng.id,
                    change={"after": {"rule": r.id, "methods": methods, "hosts": hosts, "paths": paths,
                                      "max_writes": r.max_writes, "expires_at": iso_utc(r.expires_at),
                                      "note": note}})
    session.commit()
    return view(r)


@router.post("/engagements/{eng_id}/lab-write-rules/{rid}/revoke")
def revoke_rule(eng_id: int, rid: int, request: Request, session: Session = Depends(get_session)):
    _eng(session, eng_id)
    r = session.get(LabWriteRule, rid)
    if r is None or r.engagement_id != eng_id:
        raise HTTPException(404, "no such rule on this engagement")
    who = authz.current(request)
    if not getattr(who, "is_owner", False):
        raise HTTPException(403, "only an owner can do this")
    if r.revoked_at is None:
        r.revoked_at = now()
        auditlog.append(session, actor=auditlog.actor(authz.current(request)), action="lab_rule.revoked",
                        engagement_id=eng_id, change={"after": {"rule": r.id, "used": r.used}})
        session.commit()
    return view(r)


def for_agent(session, eng: Engagement, host: str) -> list[dict]:
    """The lane context's view: what the agent may send without waiting, on this host."""
    if not enabled():
        return []
    at = now()
    rows = session.scalars(select(LabWriteRule).where(LabWriteRule.engagement_id == eng.id,
                                                      LabWriteRule.revoked_at.is_(None)))
    return [{"rule": r.id, "methods": list(r.methods), "paths": list(r.paths), "left": r.max_writes - r.used,
             "until": iso_utc(r.expires_at), "owner_note": r.note}
            for r in rows if host in (r.hosts or []) and _aware(r.expires_at) > at and r.used < r.max_writes]
