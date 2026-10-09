"""The API's side of the worker channel (D-042, docs/WORKER_API.md).

The worker has no database credentials and no database network. It reaches these routes
through the gateway's relay, which forwards /worker/* and nothing else:

  GET  /worker/ping                          worker token: the worker's health check
  POST /worker/claim                         worker token: take the next queued job (atomic), run
                                             its gates, return its specification and a job token
  POST /worker/jobs/{id}/heartbeat           job token: the job's status (running or cancelled)
  POST /worker/jobs/{id}/log                 job token: lines for the job's log
  POST /worker/jobs/{id}/progress            job token: a batch of targets finished
  POST /worker/jobs/{id}/results             job token: observations, endpoints, leads (by kind)
  POST /worker/jobs/{id}/agent/exchange      job token, agent runs: an HTTP exchange to record
  POST /worker/jobs/{id}/agent/call          job token, agent runs: add_evidence, mark_item, record_lead
  POST /worker/jobs/{id}/finish              job token: the outcome; the token stops working

A job token opens only its own job, and only while the job runs (authz.py, permission "job").
What a job may write is decided by its kind (WRITES); every host and URL is checked against the
engagement's current scope and redacted here, before storage, whatever the worker sent.

The API also runs what the worker used to run on its own: retention (vault.apply_retention)
and marking jobs whose worker went away as interrupted (maintenance, started by main.py).
"""
import base64
import binascii
import hashlib
import os
import re
import secrets
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import delete as sa_delete, select
from sqlalchemy.orm import Session

from . import agentloop, agenttools, egress, executors, jobgates, ledger, modules, packs, redact, scope, triage, urls
from . import targets as targeting
from . import vault
from .db import SessionLocal, get_session
from .models import AgentExchange, Asset, Endpoint, Engagement, Job, JobStatus, Lane, Lead, Observation
from .text import plural

router = APIRouter()

MAX_ROWS = 5000                 # per list, per results call
LOG_CAP = 20000                 # characters of a job's log that are kept (the tail)
# A running job whose worker has not reported for this long has no live worker. The worker
# heartbeats every 15 seconds while a job runs, also while a tool prints nothing.
STALE_SECONDS = int(os.environ.get("ATTACKLEDGER_WORKER_STALE_SECONDS", "120"))
# A run made by an outside driver (tools/agent_bridge.py) reports only when its driver calls a
# tool, which may be minutes apart: it gets the worker's whole time limit and a grace period.
DRIVER_STALE_SECONDS = int(os.environ.get("ATTACKLEDGER_DRIVER_STALE_SECONDS", "2400"))
INTERRUPTED = ("interrupted: the worker stopped while this job was running. Results from finished "
               "batches (and an agent's evidence up to its last turn) were kept; run it again for the rest.")

# What each job kind may write. Observations are limited to the fields its tools produce;
# leads to the kinds its runner records. A test checks this against the module registry.
_PROBE = frozenset({"url", "port", "scheme", "status_code", "title", "tech", "webserver", "cdn", "location", "live"})
WRITES: dict[str, dict] = {
    "subdomains": {"observations": frozenset({"sources", "a", "aaaa", "cname"})},
    "resolve": {"observations": frozenset({"a", "aaaa", "cname"})},
    "ports": {"observations": frozenset({"open_ports"})},
    "probe": {"observations": _PROBE},
    "wellknown": {"endpoints": True, "leads": frozenset({"robots", "security-txt", "listing"})},
    "crawl": {"endpoints": True},
    "archive": {"endpoints": True},
    "content": {"endpoints": True, "leads": frozenset({"listing"})},
    "jsanalyze": {"endpoints": True, "leads": frozenset({"graphql", "secret", "sourcemap"})},
    "nuclei": {"leads": frozenset({"nuclei"})},
    "params": {"leads": frozenset({"parameter"})},
    "paramclass": {"leads": frozenset({"param-class"})},
    "dorks": {"leads": frozenset({"dork"})},
    # Agent runs write only through agent/exchange and agent/call (agenttools.Toolbox).
    "agent": {"agent": True},
}
AGENT_CALLS = ("add_evidence", "mark_item", "record_lead")
AGENT_OUTCOMES = {"finished", "ended", "turn_limit", "cost_limit", "cancelled", "timed_out", "refused"}


def now() -> datetime:
    return datetime.now(timezone.utc)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def token_matches(job: Job, token: str) -> bool:
    import hmac
    return bool(job.worker_token_sha256) and hmac.compare_digest(_sha(token), job.worker_token_sha256)


def end_tokens(session, job: Job) -> None:
    """The job's token and its gateway secret stop working; its exchange ids are forgotten."""
    job.worker_token_sha256 = None
    job.gateway_secret_sha256 = None
    session.execute(sa_delete(AgentExchange).where(AgentExchange.job_id == job.id))


def _log(job: Job, *lines: str) -> None:
    job.log = ((job.log or "") + "".join(line[:4000] + "\n" for line in lines))[-LOG_CAP:]


def _end(session, job: Job, status: JobStatus, *lines: str) -> None:
    _log(job, *lines)
    job.status, job.finished_at = status, now()
    end_tokens(session, job)
    session.commit()


class Ended(Exception):
    """The claimed job ended before it reached the worker (a gate, or nothing to do)."""


# ---- ping and claim -----------------------------------------------------------------------

@router.get("/worker/ping")
def ping():
    return {"ok": True}


class ClaimIn(BaseModel):
    job_id: int | None = None       # an agent run for an outside driver (tools/agent_bridge.py)


def _take(session, job_id: int | None) -> tuple[Job, str, str] | None:
    """Mark the oldest queued job running and issue its two secrets, in one transaction."""
    stmt = select(Job).where(Job.status == JobStatus.queued)
    if job_id is None:
        stmt = stmt.where(Job.driver.is_(None))         # outside drivers claim their own runs
    else:
        stmt = stmt.where(Job.id == job_id, Job.driver.is_not(None))
    stmt = stmt.order_by(Job.id).limit(1)
    if session.bind.dialect.name == "postgresql":
        stmt = stmt.with_for_update(skip_locked=True)
    job = session.scalars(stmt).first()
    if job is None:
        return None
    token = secrets.token_urlsafe(32)
    job.worker_token_sha256 = _sha(token)
    secret = egress.issue(job)          # the gateway credential for the job's tools (D-039)
    job.status, job.started_at, job.heartbeat_at = JobStatus.running, now(), now()
    session.commit()
    return job, token, secret


def engagement_rules(eng: Engagement) -> dict:
    return {"id": eng.id, "scope_include": list(eng.scope_include or []),
            "scope_exclude": list(eng.scope_exclude or []), "rate_limit_rps": eng.rate_limit_rps,
            "research_header": eng.research_header, "research_user_agent": eng.research_user_agent,
            "crawl_depth": eng.crawl_depth, "enabled_modules": list(eng.enabled_modules or []),
            "redact": redact.enabled(eng)}


def latest_ports(session, eng_id: int) -> dict[str, list[int]]:
    out: dict[str, list[int]] = {}
    for o in session.scalars(select(Observation).where(Observation.engagement_id == eng_id)
                             .order_by(Observation.id.desc())):
        if "open_ports" in o.data and o.host not in out:
            out[o.host] = o.data["open_ports"]
    return out


def nuclei_plan(session, eng: Engagement, urls_: list[str]) -> dict:
    """Clusters (status, title, server, stack) -> one representative URL; stack tags; golden URLs."""
    probes = targeting.probes_by_host(session, eng.id)
    by_url = {p.get("url"): p for ps in probes.values() for p in ps if p.get("url")}
    reps, seen = [], set()
    tags: dict[str, set] = defaultdict(set)
    for u in urls_:
        p = by_url.get(u, {})
        stack = tuple(sorted(triage._tech_name(t) for t in (p.get("tech") or [])))
        key = (p.get("status_code"), (p.get("title") or "").strip().lower(), p.get("webserver"), stack)
        for t in stack:
            if t and not triage._BORING.match(t):
                tags[u].add(re.sub(r"[^a-z0-9-]", "", t))
        if key in seen and p:
            continue
        seen.add(key)
        reps.append(u)
    golden_hosts = {r["host"] for r in targeting.ranked(session, eng) if r["golden"]}
    return {"reps": reps, "tags": {u: sorted(t) for u, t in tags.items()},
            "golden": [u for u in urls_ if urls.host_of(u) in golden_hosts]}


def inputs_for(session, job: Job, eng: Engagement) -> dict:
    """What a job of this kind reads, beyond its targets and the rules. Nothing else is readable."""
    if job.kind == "probe":
        return {"ports": latest_ports(session, eng.id)}
    if job.kind == "nuclei":
        return {"nuclei_plan": nuclei_plan(session, eng, job.targets)}
    if job.kind == "paramclass":
        return {"hidden_params": {l.source_url: (l.detail or {}).get("params", []) for l in session.scalars(
            select(Lead).where(Lead.engagement_id == eng.id, Lead.kind == "parameter"))}}
    return {}


def _prepare_recon(session, job: Job, eng: Engagement) -> dict:
    """The gates and target choice the worker made before (D-016, D-019), now made here."""
    try:  # the engagement may have changed since the job was queued
        m = jobgates.check_engagement(eng, job.kind)
    except jobgates.GateError as e:
        _end(session, job, JobStatus.failed, f"error: {e}")
        raise Ended
    if job.deferred and not job.targets:
        # Pipeline step: pick targets now, from what the earlier steps produced.
        job.targets = jobgates.normalize_targets(m, targeting.default_targets(session, eng, m))
        if not job.targets:
            reason = targeting.skip_reason(m)
            job.result = {"skipped_reason": reason}
            _end(session, job, JobStatus.skipped, f"skipped, nothing to run: {reason}")
            raise Ended
    targets, _ = jobgates.split_targets(eng, m, job.targets)
    over_limit: list[str] = []
    if m.max_targets and len(targets) > m.max_targets:
        # Never drop silently: what does not fit is listed as remaining.
        targets, over_limit = targets[:m.max_targets], targets[m.max_targets:]
    if len(targets) + len(over_limit) != len(job.targets):
        _log(job, f"skipped {plural(len(job.targets) - len(targets) - len(over_limit), 'target')} outside scope")
    if not targets:
        _end(session, job, JobStatus.failed, "error: no in-scope targets")
        raise Ended
    # Everything is remaining until a batch reports it done: a worker that dies leaves it so.
    job.remaining_targets = targets + over_limit
    job.targets_done = 0
    session.commit()
    return {"targets": targets, "over_limit": len(over_limit), "computed": m.computed, "title": m.title,
            "inputs": inputs_for(session, job, eng)}


def _prepare_agent(session, job: Job) -> dict:
    lane = session.get(Lane, job.lane_id) if job.lane_id else None
    why = None
    if lane is None:
        why = "the lane for this agent run no longer exists"
    elif lane.executor != "agent":
        why = "this lane's executor is no longer the Claude agent"
    else:
        try:
            agenttools.check_lane(lane)
        except agenttools.RunRefused as e:
            why = str(e)
    if why:
        _end(session, job, JobStatus.failed, f"error: {why}")
        raise Ended
    limits = (job.result or {}).get("limits", {})
    return {"lane_id": lane.id, "limits": limits, "driver": job.driver,
            "context": executors.lane_context(session, lane, limit=agentloop.CONTEXT_LIMIT)}


@router.post("/worker/claim")
def claim(body: ClaimIn | None = None, session: Session = Depends(get_session)):
    """The next job, gated and prepared, or {"job": null}. A job that fails its gates or has
    nothing to do is ended here, with the reason in its log, and the next one is taken."""
    job_id = body.job_id if body else None
    for _ in range(50):
        taken = _take(session, job_id)
        if taken is None:
            return {"job": None}
        job, token, secret = taken
        eng = job.engagement
        try:
            extra = _prepare_agent(session, job) if job.kind == "agent" else _prepare_recon(session, job, eng)
        except Ended:
            if job_id is not None:
                return {"job": None, "ended": job.status.value, "log": job.log[-1000:]}
            continue
        except Exception as e:  # noqa: BLE001 - a bug must not leave the job running
            session.rollback()
            job = session.get(Job, job.id)
            _end(session, job, JobStatus.failed, f"error: {type(e).__name__}: {str(e)[:300]}")
            raise
        return {"job": {"id": job.id, "kind": job.kind, "token": token, "gateway_secret": secret,
                        "engagement": engagement_rules(eng), **extra}}
    return {"job": None}


# ---- every job ----------------------------------------------------------------------------

def _job(session, job_id: int) -> Job:
    job = session.get(Job, job_id)
    if job is None:                      # authz has checked the token already; defensive only
        raise HTTPException(404, "not found")
    return job


@router.post("/worker/jobs/{job_id}/heartbeat")
def heartbeat(job_id: int, session: Session = Depends(get_session)):
    job = _job(session, job_id)
    return {"status": job.status.value}


class LogIn(BaseModel):
    lines: list[str] = Field(max_length=200)


@router.post("/worker/jobs/{job_id}/log")
def job_log(job_id: int, body: LogIn, session: Session = Depends(get_session)):
    job = _job(session, job_id)
    _log(job, *body.lines)
    session.commit()
    return {"ok": True}


class ProgressIn(BaseModel):
    done: list[str] = Field(max_length=MAX_ROWS)


@router.post("/worker/jobs/{job_id}/progress")
def progress(job_id: int, body: ProgressIn, session: Session = Depends(get_session)):
    """A batch finished: its targets leave the remaining list. Only targets the job still has."""
    job = _job(session, job_id)
    remaining = list(job.remaining_targets or [])
    unknown = [t for t in body.done if t not in remaining]
    if unknown:
        raise HTTPException(422, f"not targets of this job (or already done): {', '.join(unknown[:5])}")
    gone = set(body.done)
    job.remaining_targets = [t for t in remaining if t not in gone]
    job.targets_done = (job.targets_done or 0) + len(gone)
    session.commit()
    return {"targets_done": job.targets_done, "remaining": len(job.remaining_targets)}


# ---- recon results --------------------------------------------------------------------------

class ObservationIn(BaseModel):
    host: str = Field(max_length=255)
    data: dict


class EndpointIn(BaseModel):
    url: str = Field(max_length=8000)
    sources: list[str] = Field(default_factory=list, max_length=10)


class LeadIn(BaseModel):
    host: str = Field(max_length=255)
    source_url: str = Field(max_length=8000)
    kind: str = Field(max_length=32)
    title: str = Field(max_length=2000)
    bucket: str = Field(default="", max_length=16)
    severity: str = Field(default="", max_length=16)
    detail: dict = Field(default_factory=dict)
    key: str = Field(default="", max_length=4000)


class ResultsIn(BaseModel):
    observations: list[ObservationIn] = Field(default_factory=list, max_length=MAX_ROWS)
    endpoints: list[EndpointIn] = Field(default_factory=list, max_length=MAX_ROWS)
    leads: list[LeadIn] = Field(default_factory=list, max_length=MAX_ROWS)


def _host(value: str) -> str | None:
    try:
        return scope.normalize_host(value)
    except scope.ScopeError:
        return None


def _where(url: str) -> str:
    """The host a lead was seen on: a URL, or host:port as nuclei reports some matches."""
    return (urls.host_of(url) if "://" in url else url.split(":")[0]) or ""


@router.post("/worker/jobs/{job_id}/results")
def results(job_id: int, body: ResultsIn, session: Session = Depends(get_session)):
    """Recon output of one job, as its kind allows: in scope, redacted, deduplicated."""
    job = _job(session, job_id)
    eng = job.engagement
    may = WRITES.get(job.kind, {})
    for what in ("observations", "endpoints", "leads"):
        if getattr(body, what) and not may.get(what):
            raise HTTPException(403, f"a {job.kind} job does not write {what}")
    if eng.content_deleted_at is not None:
        raise HTTPException(409, "this engagement's content was deleted; it takes no new results")
    inc, exc = eng.scope_include, eng.scope_exclude
    rep = redact.Report()
    clean = (lambda v: redact.walk(v, rep)) if redact.enabled(eng) else (lambda v: v)
    out = {"observations": 0, "endpoints_seen": len(body.endpoints), "endpoints_in_scope": 0,
           "endpoints_added": 0, "leads_added": 0, "refused": 0}

    allowed = may.get("observations") or frozenset()
    known = {a.host for a in eng.assets}
    for o in body.observations:
        extra = set(o.data) - allowed
        if extra:
            raise HTTPException(422, f"a {job.kind} job does not record {', '.join(sorted(extra))}")
        host = _host(o.host)
        if not host or not scope.in_scope(host, inc, exc):
            out["refused"] += 1
            continue
        session.add(Observation(job_id=job.id, engagement_id=eng.id, host=host, data=clean(o.data)))
        if host not in known:
            known.add(host)
            session.add(Asset(engagement_id=eng.id, host=host, in_scope=True))
        out["observations"] += 1

    if body.endpoints:
        raw: dict[str, set] = defaultdict(set)
        for e in body.endpoints:
            raw[e.url].update(s[:32] for s in e.sources)
        cleaned = urls.clean(raw.keys(), inc, exc)
        out["endpoints_in_scope"] = len(cleaned)
        rows = []
        for host, url, is_js in cleaned:
            stored = clean(url)
            rows.append((host, url, stored, hashlib.sha256(stored.encode()).hexdigest(), is_js))
        hashes = [r[3] for r in rows]
        existing = set()
        for i in range(0, len(hashes), 500):
            existing |= set(session.scalars(select(Endpoint.url_sha256).where(
                Endpoint.engagement_id == eng.id, Endpoint.url_sha256.in_(hashes[i:i + 500]))))
        for host, url, stored, h, is_js in rows:
            if h in existing:
                continue
            existing.add(h)
            src = ",".join(sorted(raw.get(url) or {"?"}))[:32]
            session.add(Endpoint(engagement_id=eng.id, job_id=job.id, host=host, url=stored, url_sha256=h,
                                 source=src, is_js=is_js))
            out["endpoints_added"] += 1

    if body.leads:
        kinds = may.get("leads") or frozenset()
        roots = jobgates.roots(eng)
        fps = {}
        for l in body.leads:
            if l.kind not in kinds:
                raise HTTPException(422, f"a {job.kind} job does not record {l.kind} leads")
            host = _host(l.host)
            # Dorks name the wildcard's root, and their URL is the search engine's.
            ok = host is not None and (host in roots if l.kind == "dork" else
                                       scope.in_scope(host, inc, exc) and scope.in_scope(_where(l.source_url), inc, exc))
            if not ok:
                out["refused"] += 1
                continue
            fps[hashlib.sha256(f"{l.kind}|{host}|{l.title}|{l.key}".encode()).hexdigest()] = (host, l)
        have = set()
        keys = list(fps)
        for i in range(0, len(keys), 500):
            have |= set(session.scalars(select(Lead.fingerprint).where(
                Lead.engagement_id == eng.id, Lead.fingerprint.in_(keys[i:i + 500]))))
        for fp, (host, l) in fps.items():
            if fp in have:
                continue
            session.add(Lead(engagement_id=eng.id, job_id=job.id, host=host, source_url=clean(l.source_url),
                             kind=l.kind, title=clean(l.title)[:300], bucket=l.bucket, severity=l.severity,
                             detail=clean(l.detail), fingerprint=fp))
            out["leads_added"] += 1
    session.commit()
    out["redacted"] = {"count": rep.count, "kinds": list(rep.kinds)}
    return out


# ---- agent runs -------------------------------------------------------------------------------

def _toolbox(session, job: Job) -> agenttools.Toolbox:
    """The API's side of a running agent: the lane's gates again, the run's exchange ids."""
    if job.kind != "agent":
        raise HTTPException(403, f"a {job.kind} job has no agent tools")
    lane = session.get(Lane, job.lane_id) if job.lane_id else None
    if lane is None or lane.executor != "agent":
        raise HTTPException(409, "this lane is no longer worked by the agent")
    limits = (job.result or {}).get("limits") or {}
    try:
        tb = agenttools.Toolbox(session, lane, job.id, recording=True,
                                max_requests=limits.get("max_requests") or agentloop.DEFAULT_LIMITS["max_requests"])
    except agenttools.RunRefused as e:
        raise HTTPException(409, str(e))
    for x in session.scalars(select(AgentExchange).where(AgentExchange.job_id == job.id).order_by(AgentExchange.id)):
        rep = redact.Report()
        rep.kinds = dict((x.redaction or {}).get("kinds") or {})
        rep.not_redacted = list((x.redaction or {}).get("not_redacted") or [])
        tb.exchanges[x.xid] = {"sha256": x.sha256, "method": x.method, "url": x.url, "status": x.status,
                               "redaction": rep}
    return tb


class ExchangeIn(BaseModel):
    method: str = Field(max_length=16)
    url: str = Field(max_length=4000)
    headers: dict[str, str] = Field(max_length=40)
    status: int
    response_headers: list[tuple[str, str]] = Field(max_length=200)
    body_b64: str = Field(max_length=(agenttools.MAX_READ_BYTES * 4) // 3 + 8)
    at: str = Field(max_length=64)
    view: str = Field(default="auto", max_length=8)    # what the model is shown (agenttools.VIEWS)


@router.post("/worker/jobs/{job_id}/agent/exchange")
def agent_exchange(job_id: int, body: ExchangeIn, session: Session = Depends(get_session)):
    """Record an exchange the worker sent through the gateway: checked, redacted, encrypted
    with the engagement's key and stored here. Answers with what the model may see."""
    job = _job(session, job_id)
    tb = _toolbox(session, job)
    try:
        raw = base64.b64decode(body.body_b64, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(422, "body_b64 is not base64")
    try:
        rec = tb.record_sent(body.method.upper(), body.url, body.headers, body.status, body.response_headers,
                             raw, body.at, body.view)
    except agenttools.ToolError as e:
        raise HTTPException(422, str(e))
    x = tb.exchanges[rec["exchange_id"]]
    session.add(AgentExchange(job_id=job.id, xid=rec["exchange_id"], sha256=x["sha256"], method=x["method"],
                              url=x["url"], status=x["status"],
                              redaction={"kinds": x["redaction"].kinds, "not_redacted": x["redaction"].not_redacted}))
    session.commit()
    text = rec["text"]
    return {**rec, "text": text[:agenttools.MAX_BODY_CHARS], "text_chars": len(text)}


class CallIn(BaseModel):
    name: str = Field(max_length=32)
    args: dict


@router.post("/worker/jobs/{job_id}/agent/call")
def agent_call(job_id: int, body: CallIn, session: Session = Depends(get_session)):
    """One of the agent's ledger tools, with the same gates as in one process."""
    job = _job(session, job_id)
    if body.name not in AGENT_CALLS:
        raise HTTPException(422, f"{body.name[:32]} is not a tool the API runs for an agent")
    tb = _toolbox(session, job)
    text, is_error = tb.call(body.name, body.args)
    session.commit()
    return {"text": text, "is_error": is_error, "evidence_added": tb.evidence_added,
            "items_marked": tb.items_marked, "leads_added": tb.leads_added}


# ---- finish -------------------------------------------------------------------------------------

class FinishIn(BaseModel):
    error: str | None = Field(default=None, max_length=4000)
    stopped: str | None = Field(default=None, max_length=200)
    output_sha256: str | None = Field(default=None, pattern="^[0-9a-f]{64}$")
    result_count: int = Field(default=0, ge=0)
    agent: dict | None = None


def recon_evidence(session, job: Job, eng: Engagement) -> None:
    """The run as evidence on each touched host's recon lane, if one is open. It is attached to
    the lane, not to a checklist item: a person or agent still decides which item it proves."""
    if not job.output_sha256:
        return
    m = modules.get(job.kind)
    recon_lane = packs.get_pack(eng.pack_id).recon_lane
    touched = set(session.scalars(select(Observation.host).where(Observation.job_id == job.id)))
    touched |= set(session.scalars(select(Endpoint.host).where(Endpoint.job_id == job.id)))
    touched |= set(session.scalars(select(Lead.host).where(Lead.job_id == job.id)))
    assets = {a.host: a for a in eng.assets}
    for host in sorted(touched):
        asset = assets.get(host)
        lane = next((l for l in asset.lanes if l.role == recon_lane), None) if asset else None
        if lane:
            ledger.append_evidence(session, lane, kind="file", sha256_hex=job.output_sha256, source="recon",
                                   uri=f"job:{job.id}", summary=f"{m.title} run, job {job.id}",
                                   created_by=job.created_by)


def _agent_result(job: Job, res: dict) -> dict:
    keep = {}
    for k in ("status", "model", "turns", "requests", "evidence_added", "items_marked", "leads_added",
              "tool_calls", "summary", "detail", "usage", "cost_usd_estimate"):
        if k in res:
            v = res[k]
            keep[k] = v[:8000] if isinstance(v, str) else v
    if keep.get("status") not in AGENT_OUTCOMES:
        raise HTTPException(422, f"unknown agent outcome {str(keep.get('status'))[:40]}")
    return {"limits": (job.result or {}).get("limits", {}), **keep}


@router.post("/worker/jobs/{job_id}/finish")
def finish(job_id: int, body: FinishIn, session: Session = Depends(get_session)):
    """The worker's outcome. The status is decided here: never done with targets left, never
    done for an agent that did not finish. Then the job's token stops working."""
    job = _job(session, job_id)
    eng = job.engagement
    cancelled = job.status == JobStatus.cancelled
    if body.output_sha256:
        job.output_sha256 = body.output_sha256
    job.result_count = body.result_count
    lines = []
    if job.kind == "agent":
        res = body.agent or {}
        if res:
            job.result = _agent_result(job, res)
        status_ = (job.result or {}).get("status")
        job.targets_done = 1 if status_ == "finished" else 0
        if body.error:
            status, lines = JobStatus.failed, [f"error: {body.error}"]
        elif cancelled:
            status = JobStatus.cancelled
        else:
            status = JobStatus.done if status_ == "finished" else JobStatus.partial
    else:
        job.remaining_targets = job.remaining_targets or None
        if body.error:
            status, lines = JobStatus.failed, [f"error: {body.error}"]
        else:
            try:
                recon_evidence(session, job, eng)
            except vault.ContentDeleted:
                pass
            status = (JobStatus.cancelled if cancelled else
                      JobStatus.partial if (job.remaining_targets or body.stopped) else JobStatus.done)
    _log(job, *lines)
    job.status = status
    job.finished_at = job.finished_at if cancelled and job.finished_at else now()
    end_tokens(session, job)
    session.commit()
    return {"status": job.status.value}


# ---- maintenance: retention and interrupted jobs ------------------------------------------------

def _aware(t: datetime | None) -> datetime | None:
    return t.replace(tzinfo=timezone.utc) if t is not None and t.tzinfo is None else t


def sweep(session, at: datetime | None = None) -> list[int]:
    """Running jobs whose worker stopped reporting are marked failed (interrupted), so a run
    never looks active or complete when it is neither. A cancelled job whose worker never
    finished it loses its token too."""
    at = at or now()
    ended = []
    held = (Job.status == JobStatus.running) | ((Job.status == JobStatus.cancelled) & Job.worker_token_sha256.is_not(None))
    for job in session.scalars(select(Job).where(held)):
        last = _aware(job.heartbeat_at) or _aware(job.started_at)
        window = DRIVER_STALE_SECONDS if job.driver else STALE_SECONDS
        if last is not None and last > at - timedelta(seconds=window):
            continue
        if job.status == JobStatus.running:
            job.status, job.finished_at = JobStatus.failed, now()
            _log(job, INTERRUPTED)
            ended.append(job.id)
        end_tokens(session, job)
    session.commit()
    return ended


def retention_pass(session) -> list[int]:
    """Delete the content of engagements past their retention date (D-043, vault.py), and
    finish a deletion whose file step was interrupted. A failure is reported, never fatal."""
    try:
        done = vault.apply_retention(session)
    except Exception as e:  # noqa: BLE001
        session.rollback()
        print(f"retention pass failed: {e}", flush=True)
        return []
    for eng_id in done:
        print(f"retention: deleted the content of engagement {eng_id}", flush=True)
    return done


RETENTION_SECONDS = 60


def start_maintenance(seconds: float | None = None):
    """The API's background passes. Returns a function that stops them. Off with
    ATTACKLEDGER_MAINTENANCE_SECONDS=0 (tests, or a second API process)."""
    every = float(os.environ.get("ATTACKLEDGER_MAINTENANCE_SECONDS", "15")) if seconds is None else seconds
    if every <= 0:
        return lambda: None
    stop = threading.Event()

    def loop():
        next_retention = 0.0
        while not stop.is_set():
            try:
                with SessionLocal() as s:
                    if time.monotonic() >= next_retention:
                        retention_pass(s)
                        next_retention = time.monotonic() + RETENTION_SECONDS
                    for job_id in sweep(s):
                        print(f"job {job_id}: interrupted (no word from its worker for {STALE_SECONDS} s)", flush=True)
            except Exception as e:  # noqa: BLE001 - reported, never fatal
                print(f"maintenance pass failed: {type(e).__name__}: {str(e)[:300]}", flush=True)
            stop.wait(every)
    t = threading.Thread(target=loop, name="attackledger-maintenance", daemon=True)
    t.start()
    return stop.set
