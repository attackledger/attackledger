"""Who may call which route: one table, checked before every handler.

Every route needs an entry (a test enforces it). A route without one is refused to
everyone but owners, so a new route is closed until someone decides who may use it.

Permissions
  public     no sign-in (health, sign-in, sign-out)
  signed_in  any signed-in caller (lists that are filtered, or reference data)
  owner      owners only: engagements, rules, authorization, people, roles, the whole audit log
  read       any role on the engagement (viewer, tester, reviewer)
  tester     the tester role on the engagement: recon, lanes, evidence, agent runs
  reviewer   the reviewer role on the engagement: sign receipts
  handler    the handler checks, because the engagement is in the request body
  gateway    the traffic gateway only, with the gateway token (gatewayapi.py, D-039);
             no person or operator token can use these routes
  worker     the worker only, with the worker token (workerapi.py, D-042): ping and claim
  job        one job's own routes, with the job token the claim issued, while the job is
             held by its worker (running, or cancelled and not yet finished). "running" in
             the second column: only while it runs. No person, operator or worker token opens
             them, and a job token opens no other job
"""
import hmac

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select

from . import auth, gateway, workerclient
from .db import get_session
from .models import Evidence, Job, Lane

ENG, LANE, JOB, BLOB, USER = "eng", "lane", "job", "blob", "user"

RULES: dict[tuple[str, str], tuple[str, str | None]] = {
    ("GET", "/health"): ("public", None),
    ("POST", "/auth/login"): ("public", None),
    ("POST", "/auth/logout"): ("public", None),
    ("GET", "/auth/me"): ("signed_in", None),
    ("GET", "/auth/keys"): ("signed_in", None),             # the handler limits it to your own keys
    ("POST", "/auth/keys"): ("signed_in", None),
    ("POST", "/auth/keys/{key_id}/revoke"): ("signed_in", None),
    ("POST", "/auth/password"): ("signed_in", None),          # your own, with your current password

    ("GET", "/engagements"): ("signed_in", None),
    ("GET", "/modules"): ("signed_in", None),
    ("GET", "/recon/phases"): ("signed_in", None),
    ("GET", "/packs"): ("signed_in", None),
    ("GET", "/executors"): ("signed_in", None),
    ("GET", "/imports/formats"): ("signed_in", None),
    # The API's own documentation (main.py serves it as ordinary routes, so this table
    # applies): whenever the API asks for sign-in, so does its map of every route.
    ("GET", "/openapi.json"): ("signed_in", None),
    ("GET", "/docs"): ("signed_in", None),
    # The offline verifier and the timestamp roots it trusts, for the Report and Verify tabs.
    ("GET", "/verifier"): ("signed_in", None),
    ("GET", "/verifier/verify_report.py"): ("signed_in", None),
    ("GET", "/verifier/tsa-roots/{name}"): ("signed_in", None),
    ("GET", "/verifier/attackledger-verifier.zip"): ("signed_in", None),

    ("POST", "/engagements"): ("owner", None),
    ("PATCH", "/engagements/{eng_id}"): ("owner", ENG),
    ("PUT", "/engagements/{eng_id}/scope"): ("owner", ENG),
    ("POST", "/engagements/{eng_id}/attest"): ("owner", ENG),
    ("POST", "/engagements/{eng_id}/scope/import"): ("owner", ENG),
    ("GET", "/engagements/{eng_id}/members"): ("owner", ENG),
    ("PUT", "/engagements/{eng_id}/members"): ("owner", ENG),
    ("GET", "/people"): ("owner", None),
    ("POST", "/people"): ("owner", None),
    ("PATCH", "/people/{user_id}"): ("owner", USER),
    ("GET", "/audit"): ("owner", None),                       # every engagement's history and every person's
    ("POST", "/engagements/{eng_id}/content/delete"): ("owner", ENG),   # cannot be undone; confirmed by name

    ("GET", "/engagements/{eng_id}/coverage"): ("read", ENG),
    ("GET", "/engagements/{eng_id}/scope"): ("read", ENG),
    ("GET", "/engagements/{eng_id}/recon/summary"): ("read", ENG),
    ("GET", "/engagements/{eng_id}/jobs"): ("read", ENG),
    ("GET", "/engagements/{eng_id}/observations"): ("read", ENG),
    ("GET", "/engagements/{eng_id}/controls"): ("read", ENG),
    ("GET", "/engagements/{eng_id}/report"): ("read", ENG),
    ("GET", "/engagements/{eng_id}/report.html"): ("read", ENG),
    ("GET", "/engagements/{eng_id}/triage"): ("read", ENG),
    ("GET", "/engagements/{eng_id}/endpoints"): ("read", ENG),
    ("GET", "/engagements/{eng_id}/leads"): ("read", ENG),
    ("GET", "/engagements/{eng_id}/audit"): ("read", ENG),    # its history, and its people's
    ("GET", "/engagements/{eng_id}/content"): ("read", ENG),  # what is kept, or when it was deleted
    ("GET", "/lanes/{lane_id}"): ("read", LANE),
    ("GET", "/lanes/{lane_id}/context"): ("read", LANE),
    ("GET", "/lanes/{lane_id}/agent-runs"): ("read", LANE),
    ("GET", "/jobs/{job_id}"): ("read", JOB),
    ("GET", "/blobs/{digest}"): ("read", BLOB),
    ("GET", "/engagements/{eng_id}/imports"): ("read", ENG),
    ("GET", "/engagements/{eng_id}/inbox"): ("read", ENG),
    ("GET", "/engagements/{eng_id}/inbox/{entry_id}"): ("read", ENG),
    ("GET", "/engagements/{eng_id}/inbox/{entry_id}/raw/{part}"): ("read", ENG),

    ("POST", "/engagements/{eng_id}/assets"): ("tester", ENG),
    ("POST", "/engagements/{eng_id}/jobs"): ("tester", ENG),
    ("POST", "/engagements/{eng_id}/pipeline"): ("tester", ENG),
    ("POST", "/jobs/{job_id}/resume"): ("tester", JOB),
    ("POST", "/jobs/{job_id}/cancel"): ("tester", JOB),
    ("POST", "/lanes"): ("handler", None),
    ("PATCH", "/lanes/{lane_id}"): ("tester", LANE),
    ("POST", "/lanes/{lane_id}/evidence"): ("tester", LANE),
    ("POST", "/lanes/{lane_id}/attach"): ("tester", LANE),
    ("PATCH", "/lanes/{lane_id}/items/{idx}"): ("tester", LANE),
    ("POST", "/lanes/{lane_id}/agent-runs"): ("tester", LANE),
    ("POST", "/engagements/{eng_id}/imports"): ("tester", ENG),          # evidence import (D-029)
    ("POST", "/engagements/{eng_id}/inbox/map"): ("tester", ENG),
    ("POST", "/engagements/{eng_id}/inbox/dismiss"): ("tester", ENG),
    ("POST", "/engagements/{eng_id}/inbox/restore"): ("tester", ENG),

    ("GET", "/engagements/{eng_id}/gateway-log"): ("read", ENG),

    # Test accounts (D-040): who may add, replace and delete them; nobody can read the material.
    ("GET", "/engagements/{eng_id}/test-accounts"): ("read", ENG),
    ("POST", "/engagements/{eng_id}/test-accounts"): ("tester", ENG),
    ("PUT", "/engagements/{eng_id}/test-accounts/{account_id}"): ("tester", ENG),
    ("POST", "/engagements/{eng_id}/test-accounts/{account_id}/delete"): ("tester", ENG),
    # Writes with a person's approval (D-041): testers decide, viewers and reviewers do not.
    ("GET", "/engagements/{eng_id}/approvals"): ("tester", ENG),
    ("POST", "/engagements/{eng_id}/approvals/{pid}/approve"): ("tester", ENG),
    ("POST", "/engagements/{eng_id}/approvals/{pid}/confirm-delete"): ("tester", ENG),
    ("POST", "/engagements/{eng_id}/approvals/{pid}/reject"): ("tester", ENG),

    ("POST", "/gateway/session"): ("gateway", None),
    ("POST", "/gateway/account"): ("gateway", None),
    ("POST", "/gateway/approval"): ("gateway", None),
    ("GET", "/gateway/dns-scopes"): ("gateway", None),
    ("POST", "/gateway/log"): ("gateway", None),

    ("GET", "/worker/ping"): ("worker", None),
    ("POST", "/worker/claim"): ("worker", None),
    ("POST", "/worker/jobs/{job_id}/heartbeat"): ("job", None),
    ("POST", "/worker/jobs/{job_id}/log"): ("job", None),
    ("POST", "/worker/jobs/{job_id}/progress"): ("job", None),
    ("POST", "/worker/jobs/{job_id}/results"): ("job", None),
    ("POST", "/worker/jobs/{job_id}/finish"): ("job", None),
    ("POST", "/worker/jobs/{job_id}/agent/exchange"): ("job", "running"),
    ("POST", "/worker/jobs/{job_id}/agent/call"): ("job", "running"),

    ("POST", "/lanes/{lane_id}/close"): ("reviewer", LANE),
    ("GET", "/lanes/{lane_id}/receipt-payload"): ("reviewer", LANE),
    ("POST", "/lanes/{lane_id}/receipt/timestamp"): ("reviewer", LANE),
}



def _engagements(session, kind: str, params: dict) -> set[int] | None:
    """The engagement(s) a route's path points at; None if the object does not exist
    (the handler then answers 404)."""
    try:
        if kind == ENG:
            return {int(params["eng_id"])}
        if kind == LANE:
            lane = session.get(Lane, int(params["lane_id"]))
            return {lane.asset.engagement_id} if lane else None
        if kind == JOB:
            job = session.get(Job, int(params["job_id"]))
            return {job.engagement_id} if job else None
        if kind == BLOB:
            ids = set(session.scalars(select(Evidence.engagement_id).where(Evidence.sha256 == params["digest"])))
            return ids or None
    except (KeyError, ValueError):
        return None
    return None


def authorize(request: Request, session=Depends(get_session)) -> None:
    route = request.scope.get("route")
    path = getattr(route, "path", request.url.path)
    rule = RULES.get((request.method, path))
    if rule and rule[0] == "public":
        return
    if rule and rule[0] == "gateway":
        _gateway_caller(request)
        return
    if rule and rule[0] == "worker":
        _worker_caller(request)
        return
    if rule and rule[0] == "job":
        _job_caller(request, session, running_only=rule[1] == "running")
        return
    who = auth.principal(session, request)
    if who is None:
        raise HTTPException(401, auth.SETUP_HINT if auth.mode(session) == "setup" else "sign in first")
    request.state.principal = who
    if rule is None:
        if who.is_owner:
            return
        raise HTTPException(403, "this route has no permission rule; only owners may use it")
    perm, kind = rule
    if perm in ("signed_in", "handler"):
        return
    if perm == "owner":
        if not who.is_owner:
            raise HTTPException(403, "only an owner can do this")
        return
    engs = _engagements(session, kind, request.path_params)
    if engs is None:
        if who.is_owner:
            return                      # the handler answers 404
        raise HTTPException(404, "not found")
    if perm == "read":
        if not any(who.can_read(e) for e in engs):
            raise HTTPException(404, "not found")   # do not confirm that it exists
        return
    if not any(who.has(e, perm) for e in engs):
        if any(who.can_read(e) for e in engs):
            raise HTTPException(403, f"this needs the {perm} role on the engagement")
        raise HTTPException(404, "not found")


def _gateway_caller(request: Request) -> None:
    """The gateway's token, and nothing else, opens the gateway routes. Without a configured
    token they are closed (fail closed: the gateway then refuses all traffic)."""
    tok = gateway.gateway_token()
    if not tok:
        raise HTTPException(503, "no gateway token is configured")
    header = request.headers.get("authorization", "")
    if not (header.lower().startswith("bearer ") and hmac.compare_digest(header[7:].strip(), tok)):
        raise HTTPException(401, "the gateway token is required")


def _bearer(request: Request) -> str:
    header = request.headers.get("authorization", "")
    return header[7:].strip() if header.lower().startswith("bearer ") else ""


def _worker_caller(request: Request) -> None:
    """The worker's token, and nothing else, opens ping and claim. Without a configured token
    they are closed (fail closed: the worker then runs nothing)."""
    tok = workerclient.worker_token()
    if not tok:
        raise HTTPException(503, "no worker token is configured")
    if not hmac.compare_digest(_bearer(request), tok):
        raise HTTPException(401, "the worker token is required")


def _job_caller(request: Request, session, running_only: bool) -> None:
    """A job token opens its own job's routes only, while its worker holds the job. Every call
    is a heartbeat."""
    from datetime import datetime, timezone

    from . import workerapi
    from .models import JobStatus
    try:
        job = session.get(Job, int(request.path_params["job_id"]))
    except (KeyError, ValueError):
        job = None
    token = _bearer(request)
    if job is None or not token or not workerapi.token_matches(job, token):
        raise HTTPException(401, "this job's token is required")
    if job.status not in (JobStatus.running, JobStatus.cancelled) or (
            running_only and job.status != JobStatus.running):
        raise HTTPException(403, f"job {job.id} is {job.status.value}; its token no longer writes")
    job.heartbeat_at = datetime.now(timezone.utc)
    session.commit()


def current(request: Request) -> auth.Principal:
    who = getattr(request.state, "principal", None)
    if who is None:                     # authorize did not run: refuse, never assume an owner
        raise HTTPException(401, "sign in first")
    return who
