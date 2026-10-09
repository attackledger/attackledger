"""Who may call which route: one table, checked before every handler.

Every route needs an entry (a test enforces it). A route without one is refused to
everyone but owners, so a new route is closed until someone decides who may use it.

Permissions
  public     no sign-in (health, sign-in, sign-out)
  signed_in  any signed-in caller (lists that are filtered, or reference data)
  owner      owners only: engagements, rules, authorization, people, roles
  read       any role on the engagement (viewer, tester, reviewer)
  tester     the tester role on the engagement: recon, lanes, evidence, agent runs
  reviewer   the reviewer role on the engagement: sign receipts
  handler    the handler checks, because the engagement is in the request body
"""
from fastapi import Depends, HTTPException, Request
from sqlalchemy import select

from . import auth
from .db import get_session
from .models import Evidence, Job, Lane

ENG, LANE, JOB, BLOB, USER = "eng", "lane", "job", "blob", "user"

RULES: dict[tuple[str, str], tuple[str, str | None]] = {
    ("GET", "/health"): ("public", None),
    ("POST", "/auth/login"): ("public", None),
    ("POST", "/auth/logout"): ("public", None),
    ("GET", "/auth/me"): ("signed_in", None),

    ("GET", "/engagements"): ("signed_in", None),
    ("GET", "/modules"): ("signed_in", None),
    ("GET", "/recon/phases"): ("signed_in", None),
    ("GET", "/packs"): ("signed_in", None),
    ("GET", "/executors"): ("signed_in", None),

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
    ("GET", "/lanes/{lane_id}"): ("read", LANE),
    ("GET", "/lanes/{lane_id}/context"): ("read", LANE),
    ("GET", "/lanes/{lane_id}/agent-runs"): ("read", LANE),
    ("GET", "/jobs/{job_id}"): ("read", JOB),
    ("GET", "/blobs/{digest}"): ("read", BLOB),

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

    ("POST", "/lanes/{lane_id}/close"): ("reviewer", LANE),
}

# FastAPI's own documentation routes.
DOC_ROUTES = {"/docs", "/docs/oauth2-redirect", "/openapi.json", "/redoc"}


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
    if path in DOC_ROUTES:
        return
    rule = RULES.get((request.method, path))
    if rule and rule[0] == "public":
        return
    who = auth.principal(session, request)
    if who is None:
        raise HTTPException(401, "sign in first")
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


def current(request: Request) -> auth.Principal:
    who = getattr(request.state, "principal", None)
    if who is None:                     # authorize did not run: refuse, never assume an owner
        raise HTTPException(401, "sign in first")
    return who
