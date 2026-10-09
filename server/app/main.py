import hmac
from contextlib import asynccontextmanager

from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import (agenttools, auth, blobs, executors, gates, jobgates, ledger, migrate, modules, packs, report,
               scope, scopeimport, triage, urls)
from . import targets as targeting
from .db import get_session
from .models import (Asset, ChecklistItem, Endpoint, Engagement, Evidence, ItemState, Job, JobStatus,
                     Lane, Lead, Observation, Receipt)

ENGAGEMENT_TYPES = {"bug_bounty", "pentest", "internal"}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    packs.all_packs()  # fail fast on a broken pack
    migrate.upgrade_head()
    yield


app = FastAPI(title="AttackLedger", version="0.6.0.dev0", lifespan=lifespan)
app.middleware("http")(auth.middleware)


# ---- schemas ---------------------------------------------------------------

class EngagementIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    policy_url: str | None = None
    pack_id: str = "bug-bounty"
    engagement_type: str | None = None  # defaults to the pack's first type


class AssetIn(BaseModel):
    host: str
    in_scope: bool = True


class LaneIn(BaseModel):
    asset_id: int
    role: str  # lane key from the engagement's pack


class EvidenceIn(BaseModel):
    item_idx: int | None = None
    kind: str = Field(pattern="^(request|response|file|note)$")
    sha256: str = Field(pattern="^[0-9a-f]{64}$")
    uri: str | None = None
    summary: str = Field(min_length=1)


class ItemUpdate(BaseModel):
    state: ItemState
    na_reason: str | None = None


# ---- helpers ---------------------------------------------------------------

def _get(session: Session, model, obj_id: int):
    obj = session.get(model, obj_id)
    if obj is None:
        raise HTTPException(404, f"{model.__name__} {obj_id} not found")
    return obj


def _item(lane: Lane, idx: int) -> ChecklistItem:
    for item in lane.items:
        if item.idx == idx:
            return item
    raise HTTPException(404, f"lane {lane.id} has no item {idx}")


def _pack_of(eng: Engagement) -> packs.Pack:
    try:
        return packs.get_pack(eng.pack_id)
    except packs.PackError as e:
        raise HTTPException(500, str(e))


def _lane_view(lane: Lane) -> dict:
    pack = _pack_of(lane.asset.engagement)
    return {
        "id": lane.id,
        "host": lane.asset.host,
        "role": lane.role,
        "role_name": pack.lane(lane.role).name if lane.role in pack.lane_index else lane.role,
        "executor": lane.executor,
        "status": gates.lane_status(lane).value,
        "unresolved": gates.unresolved(lane),
        "items": [
            {"idx": i.idx, "key": i.item_key, "text": i.text, "state": i.state.value,
             "na_reason": i.na_reason, "controls": i.controls}
            for i in lane.items
        ],
        "evidence_count": len(lane.evidence),
        "evidence": [
            {"id": e.id, "item_idx": next((i.idx for i in lane.items if i.id == e.item_id), None),
             "kind": e.kind, "sha256": e.sha256, "uri": e.uri, "summary": e.summary,
             "created_at": e.created_at.isoformat()}
            for e in lane.evidence
        ],
        "receipt": (
            {"sha256": lane.receipts[-1].manifest_sha256,
             "closed_by": lane.receipts[-1].closed_by,
             "created_at": lane.receipts[-1].created_at.isoformat()}
            if lane.receipts else None
        ),
    }


# ---- routes ----------------------------------------------------------------

@app.get("/health")
def health():
    # Says whether the API requires a token: an open API must not leave localhost.
    return {"ok": True, "auth_required": auth.token() is not None}


class LoginIn(BaseModel):
    token: str = Field(min_length=1, max_length=500)


@app.post("/auth/login")
def login(body: LoginIn):
    tok = auth.token()
    if tok is None:
        return {"ok": True, "auth_required": False}
    if not hmac.compare_digest(body.token.strip(), tok):
        raise HTTPException(401, "wrong token")
    resp = JSONResponse({"ok": True, "auth_required": True})
    resp.set_cookie(auth.COOKIE, auth.session_value(tok), httponly=True, samesite="strict",
                    secure=False, max_age=12 * 3600, path="/")
    return resp


@app.post("/auth/logout")
def logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(auth.COOKIE, path="/")
    return resp


@app.post("/engagements", status_code=201)
def create_engagement(body: EngagementIn, session: Session = Depends(get_session)):
    try:
        pack = packs.get_pack(body.pack_id)
    except packs.PackError as e:
        raise HTTPException(422, str(e))
    etype = body.engagement_type or (pack.engagement_types[0] if pack.engagement_types else "pentest")
    if etype not in ENGAGEMENT_TYPES:
        raise HTTPException(422, f"unknown engagement type: {etype}")
    eng = Engagement(name=body.name.strip(), policy_url=body.policy_url, pack_id=pack.id,
                     engagement_type=etype)
    session.add(eng)
    try:
        session.commit()
    except IntegrityError:
        raise HTTPException(409, "engagement name already exists")
    return {"id": eng.id, "name": eng.name, "pack_id": eng.pack_id,
            "engagement_type": eng.engagement_type}


@app.post("/engagements/{eng_id}/assets", status_code=201)
def add_asset(eng_id: int, body: AssetIn, session: Session = Depends(get_session)):
    eng = _get(session, Engagement, eng_id)
    try:
        host = scope.normalize_host(body.host)
    except scope.ScopeError as e:
        raise HTTPException(422, str(e))
    # With scope rules defined, the rules decide; an operator can only narrow, never widen.
    allowed = scope.in_scope(host, eng.scope_include, eng.scope_exclude) if eng.scope_include else True
    asset = Asset(engagement_id=eng_id, host=host, in_scope=body.in_scope and allowed)
    session.add(asset)
    try:
        session.commit()
    except IntegrityError:
        raise HTTPException(409, "asset already exists in this engagement")
    return {"id": asset.id, "host": asset.host}


@app.post("/lanes", status_code=201)
def open_lane(body: LaneIn, session: Session = Depends(get_session)):
    asset = _get(session, Asset, body.asset_id)
    if not asset.in_scope:
        raise HTTPException(422, f"{asset.host} is out of scope")
    pack = _pack_of(asset.engagement)
    try:
        lane_def = pack.lane(body.role)
        gates.check_can_open(asset, lane_def, pack)
    except (gates.GateError, packs.PackError) as e:
        raise HTTPException(422, str(e))
    lane = Lane(asset_id=asset.id, role=lane_def.key)
    lane.items = [ChecklistItem(idx=n, item_key=it.id, text=it.text, controls=list(it.controls))
                  for n, it in enumerate(lane_def.items, start=1)]
    session.add(lane)
    try:
        session.commit()
    except IntegrityError:
        raise HTTPException(409, "lane already open for this asset and role")
    return _lane_view(lane)


@app.get("/lanes/{lane_id}")
def get_lane(lane_id: int, session: Session = Depends(get_session)):
    return _lane_view(_get(session, Lane, lane_id))


@app.post("/lanes/{lane_id}/evidence", status_code=201)
def add_evidence(lane_id: int, body: EvidenceIn, session: Session = Depends(get_session)):
    lane = _get(session, Lane, lane_id)
    item_id = _item(lane, body.item_idx).id if body.item_idx is not None else None
    ev = ledger.append_evidence(session, lane, kind=body.kind, sha256_hex=body.sha256,
                                summary=body.summary, uri=body.uri, item_id=item_id)
    session.commit()
    return {"id": ev.id}


@app.patch("/lanes/{lane_id}/items/{idx}")
def update_item(lane_id: int, idx: int, body: ItemUpdate, session: Session = Depends(get_session)):
    lane = _get(session, Lane, lane_id)
    item = _item(lane, idx)
    if body.state == ItemState.done and not any(e.item_id == item.id for e in lane.evidence):
        raise HTTPException(422, "attach evidence to this item before marking it done")
    if body.state == ItemState.na and not (body.na_reason or "").strip():
        raise HTTPException(422, "N/A needs a reason")
    item.state = body.state
    item.na_reason = body.na_reason if body.state == ItemState.na else None
    session.commit()
    return _lane_view(lane)


class CloseIn(BaseModel):
    closed_by: str = Field(min_length=1, max_length=200)   # the person signing the receipt
    reviewed: bool                                         # "I reviewed this lane's evidence"


@app.post("/lanes/{lane_id}/close")
def close_lane(lane_id: int, body: CloseIn, session: Session = Depends(get_session)):
    """Issue a receipt. Only a person does this (D-018): executors, agents included,
    attach evidence and mark items, but the receipt carries a human signature."""
    lane = _get(session, Lane, lane_id)
    if not body.reviewed:
        raise HTTPException(422, "confirm that you reviewed this lane's evidence before closing it")
    if not body.closed_by.strip():
        raise HTTPException(422, "a receipt needs the name of the person signing it")
    problems = gates.unresolved(lane)
    if problems:
        raise HTTPException(422, {"error": "lane cannot close", "unresolved": problems})
    receipt = Receipt(lane_id=lane.id, manifest_sha256=gates.manifest_hash(lane),
                      closed_by=body.closed_by.strip())
    session.add(receipt)
    session.commit()
    session.refresh(lane)
    return {"receipt": receipt.manifest_sha256, **_lane_view(lane)}


@app.get("/engagements")
def list_engagements(session: Session = Depends(get_session)):
    engs = session.scalars(select(Engagement).order_by(Engagement.created_at.desc())).all()
    return [{"id": e.id, "name": e.name, "policy_url": e.policy_url, "assets": len(e.assets),
             "pack_id": e.pack_id, "engagement_type": e.engagement_type} for e in engs]


def _cell(lane: Lane | None) -> dict:
    if lane is None:
        return {"status": "not_opened"}
    status = gates.lane_status(lane).value
    cell = {"status": status, "lane_id": lane.id, "unresolved": len(gates.unresolved(lane))}
    if lane.receipts:
        cell["receipt"] = lane.receipts[-1].manifest_sha256[:8]
    return cell


@app.get("/engagements/{eng_id}/coverage")
def coverage(eng_id: int, session: Session = Depends(get_session)):
    eng = _get(session, Engagement, eng_id)
    pack = _pack_of(eng)
    keys = [l.key for l in pack.lanes]
    rows = []
    for asset in sorted(eng.assets, key=lambda a: a.host):
        by_role = {l.role: l for l in asset.lanes}
        rows.append({
            "asset_id": asset.id,
            "host": asset.host,
            "in_scope": asset.in_scope,
            "roles": {k: _cell(by_role.get(k)) for k in keys},
        })
    in_scope = [r for r in rows if r["in_scope"]]
    total = sum(len(r["roles"]) for r in in_scope)
    closed = sum(1 for r in in_scope for c in r["roles"].values() if c["status"] == "closed")
    return {"engagement": eng.name, "pack": {"id": pack.id, "name": pack.name},
            "roles": keys,
            "lanes": [{"key": l.key, "name": l.name, "needs": list(l.needs)} for l in pack.lanes],
            "closed_cells": closed, "total_cells": total, "assets": rows}


# ---- scope & authorization -------------------------------------------------

class ScopeIn(BaseModel):
    include: list[str]
    exclude: list[str] = []
    rate_limit_rps: int = Field(default=5, ge=1, le=50)
    # "Name: value", one header. No CR/LF, so it cannot smuggle extra headers.
    research_header: str | None = Field(default=None, pattern=r"^[A-Za-z0-9-]{1,64}: [^\r\n]{1,200}$")
    research_user_agent: str | None = Field(default=None, pattern=r"^[^\r\n]{1,300}$")
    enabled_modules: list[str] | None = None   # opt-in module kinds the program allows
    allow_port_scan: bool | None = None         # deprecated alias for enabled_modules ["ports"]
    crawl_depth: int = Field(default=3, ge=1, le=5)


class AttestIn(BaseModel):
    operator: str = Field(min_length=1, max_length=200)
    policy_url: str = Field(pattern="^https://")
    confirm: bool


def _scope_view(eng: Engagement) -> dict:
    return {
        "include": eng.scope_include, "exclude": eng.scope_exclude,
        "rate_limit_rps": eng.rate_limit_rps, "policy_url": eng.policy_url,
        "research_header": eng.research_header, "research_user_agent": eng.research_user_agent,
        "enabled_modules": sorted(eng.enabled_modules or []), "crawl_depth": eng.crawl_depth,
        "authorized_by": eng.authorized_by,
        "authorized_at": eng.authorized_at.isoformat() if eng.authorized_at else None,
    }


@app.get("/engagements/{eng_id}/scope")
def get_scope(eng_id: int, session: Session = Depends(get_session)):
    return _scope_view(_get(session, Engagement, eng_id))


@app.put("/engagements/{eng_id}/scope")
def put_scope(eng_id: int, body: ScopeIn, session: Session = Depends(get_session)):
    eng = _get(session, Engagement, eng_id)
    try:
        inc = sorted({scope.normalize_pattern(p) for p in body.include if p.strip()})
        exc = sorted({scope.normalize_pattern(p) for p in body.exclude if p.strip()})
    except scope.ScopeError as e:
        raise HTTPException(422, str(e))
    eng.scope_include, eng.scope_exclude, eng.rate_limit_rps = inc, exc, body.rate_limit_rps
    eng.research_header = (body.research_header or "").strip() or None
    eng.research_user_agent = (body.research_user_agent or "").strip() or None
    enabled = set(body.enabled_modules if body.enabled_modules is not None else (eng.enabled_modules or []))
    if body.allow_port_scan is not None:
        enabled = (enabled | {"ports"}) if body.allow_port_scan else (enabled - {"ports"})
    unknown = enabled - modules.OPT_IN_KINDS
    if unknown:
        raise HTTPException(422, f"not an opt-in module: {', '.join(sorted(unknown))}")
    eng.enabled_modules, eng.crawl_depth = sorted(enabled), body.crawl_depth
    # Re-evaluate existing assets: rules can move hosts out of scope, never into it silently.
    for a in eng.assets:
        if not scope.in_scope(a.host, inc, exc):
            a.in_scope = False
    session.commit()
    return _scope_view(eng)


@app.post("/engagements/{eng_id}/attest")
def attest(eng_id: int, body: AttestIn, session: Session = Depends(get_session)):
    if not body.confirm:
        raise HTTPException(422, "confirm that you are authorized to test this program")
    eng = _get(session, Engagement, eng_id)
    eng.authorized_by, eng.policy_url = body.operator.strip(), body.policy_url
    eng.authorized_at = datetime.now(timezone.utc)
    session.commit()
    return _scope_view(eng)


# ---- jobs ------------------------------------------------------------------

class JobIn(BaseModel):
    kind: str
    targets: list[str] = []  # empty = derive from scope / assets


def _job_view(j: Job, with_log: bool = False) -> dict:
    v = {"id": j.id, "kind": j.kind, "status": j.status.value, "targets": j.targets,
         "result_count": j.result_count, "output_sha256": j.output_sha256,
         "targets_done": j.targets_done, "remaining": len(j.remaining_targets or []),
         "deferred": j.deferred, "lane_id": j.lane_id, "result": j.result,
         "created_at": j.created_at.isoformat(),
         "started_at": j.started_at.isoformat() if j.started_at else None,
         "finished_at": j.finished_at.isoformat() if j.finished_at else None}
    if with_log:
        v["log"] = j.log
    return v


@app.get("/modules")
def list_modules():
    """The recon pipeline as the UI renders it, straight from the registry."""
    return [modules.as_dict(m) for m in modules.MODULES]


@app.get("/recon/phases")
def recon_phases():
    """The recon steps the UI shows, each with the modules it runs, in pipeline order."""
    return [modules.phase_dict(p) for p in modules.PHASES]


@app.get("/engagements/{eng_id}/recon/summary")
def recon_summary(eng_id: int, session: Session = Depends(get_session)):
    """How the surface narrows from step to step: names found, resolved, live, golden,
    then URLs and leads. Counts only what is inside the current scope rules."""
    eng = _get(session, Engagement, eng_id)
    inc, exc = eng.scope_include, eng.scope_exclude
    in_scope = lambda h: scope.in_scope(h or "", inc, exc)  # noqa: E731
    hosts = {a.host for a in eng.assets if a.in_scope and in_scope(a.host)}
    resolved = set()
    for o in session.scalars(select(Observation).where(Observation.engagement_id == eng_id)):
        if (o.data.get("a") or o.data.get("aaaa")) and o.host in hosts:
            resolved.add(o.host)
    ranked = targeting.ranked(session, eng)
    eps = [e for e in session.scalars(select(Endpoint).where(Endpoint.engagement_id == eng_id))
           if in_scope(e.host)]
    lead_kinds: dict[str, int] = {}
    for l in session.scalars(select(Lead).where(Lead.engagement_id == eng_id)):
        lead_kinds[l.kind] = lead_kinds.get(l.kind, 0) + 1
    return {"hosts": len(hosts), "resolved": len(resolved), "live": len(ranked),
            "golden": sum(1 for r in ranked if r["golden"]),
            "urls": len(eps), "js": sum(1 for e in eps if e.is_js),
            "leads": sum(lead_kinds.values()), "lead_kinds": lead_kinds}


@app.post("/engagements/{eng_id}/jobs", status_code=201)
def create_job(eng_id: int, body: JobIn, session: Session = Depends(get_session)):
    eng = _get(session, Engagement, eng_id)
    try:
        m = jobgates.check_engagement(eng, body.kind)
    except jobgates.GateError as e:
        raise HTTPException(422, str(e))
    targets = jobgates.normalize_targets(m, body.targets) or targeting.default_targets(session, eng, m)
    if not targets:
        hint = targeting.NO_TARGET_HINT.get(m.kind) or (
            "add a wildcard scope rule such as *.example.com" if m.input == "roots"
            else "add in-scope hosts or a wildcard scope rule first")
        raise HTTPException(422, f"no targets: {hint}")
    _, bad = jobgates.split_targets(eng, m, targets)
    if bad:
        raise HTTPException(422, f"out of scope: {', '.join(bad[:10])}")
    job = Job(engagement_id=eng.id, kind=body.kind, targets=targets)
    session.add(job)
    session.commit()
    return _job_view(job)


class PipelineIn(BaseModel):
    kinds: list[str] | None = None   # default: every module in registry order


@app.post("/engagements/{eng_id}/pipeline", status_code=201)
def run_pipeline(eng_id: int, body: PipelineIn | None = None, session: Session = Depends(get_session)):
    """Queue every step that passes its gates, in registry order. Each step resolves
    its targets when it starts, from what the steps before it produced."""
    eng = _get(session, Engagement, eng_id)
    wanted = (body.kinds if body and body.kinds else [m.kind for m in modules.MODULES])
    unknown = [k for k in wanted if k not in modules.BY_KIND]
    if unknown:
        raise HTTPException(422, f"unknown module: {', '.join(unknown)}")
    queued, skipped = [], []
    for m in modules.MODULES:                       # registry order is pipeline order
        if m.kind not in wanted:
            continue
        try:
            jobgates.check_engagement(eng, m.kind)
        except jobgates.GateError as e:
            skipped.append({"kind": m.kind, "reason": str(e)})
            continue
        job = Job(engagement_id=eng.id, kind=m.kind, targets=[], deferred=True)
        session.add(job)
        queued.append(m.kind)
    if not queued:
        raise HTTPException(422, {"error": "no step can run", "skipped": skipped})
    session.commit()
    return {"queued": queued, "skipped": skipped}


@app.get("/engagements/{eng_id}/jobs")
def list_jobs(eng_id: int, session: Session = Depends(get_session)):
    eng = _get(session, Engagement, eng_id)
    return [_job_view(j) for j in eng.jobs[:100]]


@app.get("/jobs/{job_id}")
def get_job(job_id: int, session: Session = Depends(get_session)):
    return _job_view(_get(session, Job, job_id), with_log=True)


@app.post("/jobs/{job_id}/resume", status_code=201)
def resume_job(job_id: int, session: Session = Depends(get_session)):
    """Run the targets a stopped job did not reach. Every gate is checked again."""
    job = _get(session, Job, job_id)
    if job.kind == "agent":
        raise HTTPException(422, "an agent run is not resumed; start a new run on the lane")
    if job.status not in (JobStatus.partial, JobStatus.cancelled) or not job.remaining_targets:
        raise HTTPException(422, "this run has no remaining targets")
    return create_job(job.engagement_id, JobIn(kind=job.kind, targets=job.remaining_targets), session)


@app.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: int, session: Session = Depends(get_session)):
    job = _get(session, Job, job_id)
    if job.status in (JobStatus.queued, JobStatus.running):
        if job.status == JobStatus.queued and job.kind != "agent":
            job.remaining_targets = list(job.targets)   # never ran: every target is still open
        job.status = JobStatus.cancelled
        job.finished_at = datetime.now(timezone.utc)
        session.commit()
    return _job_view(job)


@app.get("/engagements/{eng_id}/observations")
def observations(eng_id: int, session: Session = Depends(get_session)):
    rows = session.scalars(
        select(Observation).where(Observation.engagement_id == eng_id).order_by(Observation.id.desc())
    ).all()
    latest: dict[str, dict] = {}
    for o in rows:  # newest first; merge older fields underneath
        cur = latest.setdefault(o.host, {"host": o.host})
        for k, v in o.data.items():
            cur.setdefault(k, v)
    return sorted(latest.values(), key=lambda r: r["host"])


# ---- packs & controls ------------------------------------------------------

def _pack_summary(p: packs.Pack) -> dict:
    return {"id": p.id, "name": p.name, "version": p.version, "description": p.description,
            "engagement_types": list(p.engagement_types),
            "lanes": [{"key": l.key, "name": l.name, "needs": list(l.needs), "items": len(l.items)}
                      for l in p.lanes]}


@app.get("/packs")
def list_packs():
    return [_pack_summary(p) for p in packs.all_packs().values()]


@app.get("/engagements/{eng_id}/controls")
def control_coverage(eng_id: int, session: Session = Depends(get_session)):
    """For each control the pack maps to, how much of it is backed by receipted evidence.

    A mapped item on an in-scope host counts as evidenced only when its lane is
    receipted (closed) and the item is done or N/A with a reason. A control is
    "evidenced" when every mapped item on every in-scope host is evidenced.
    """
    eng = _get(session, Engagement, eng_id)
    pack = _pack_of(eng)
    cat = packs.catalog().controls
    hosts = [a for a in eng.assets if a.in_scope]
    out: dict[str, dict] = {}
    for lane_def in pack.lanes:
        for item in lane_def.items:
            for cid in item.controls:
                c = out.setdefault(cid, {**cat[cid], "required": 0, "evidenced": 0, "lanes": set()})
                c["lanes"].add(lane_def.name)
                for a in hosts:
                    c["required"] += 1
                    lane = next((l for l in a.lanes if l.role == lane_def.key), None)
                    if lane is None or gates.lane_status(lane) != gates.LaneStatus.closed:
                        continue
                    li = next((i for i in lane.items if i.item_key == item.id), None)
                    if li is not None and li.state in (ItemState.done, ItemState.na):
                        c["evidenced"] += 1
    rows = []
    for c in out.values():
        c["lanes"] = sorted(c["lanes"])
        if c["required"] and c["evidenced"] == c["required"]:
            c["status"] = "evidenced"
        elif c["evidenced"]:
            c["status"] = "partial"
        else:
            c["status"] = "none"
        rows.append(c)
    rows.sort(key=lambda c: (c["framework"], c["id"]))
    return {"engagement": eng.name, "pack": pack.id, "hosts_in_scope": len(hosts),
            "disclaimer": "Indicative mapping of tests to controls; not a compliance determination.",
            "controls": rows}


# ---- audit report ----------------------------------------------------------

def _report(eng_id: int, session: Session) -> dict:
    eng = _get(session, Engagement, eng_id)
    return report.build(session, eng, control_coverage(eng_id, session))


def _filename(eng: dict, ext: str) -> str:
    slug = "".join(ch if ch.isalnum() else "-" for ch in eng["name"].lower()).strip("-")[:60] or "engagement"
    return f"attackledger-{slug}-{eng['id']}.{ext}"


@app.get("/engagements/{eng_id}/report")
def report_json(eng_id: int, download: bool = False, session: Session = Depends(get_session)):
    r = _report(eng_id, session)
    headers = {"Content-Disposition": f'attachment; filename="{_filename(r["engagement"], "json")}"'} if download else {}
    return JSONResponse(r, headers=headers)


@app.get("/engagements/{eng_id}/report.html")
def report_html(eng_id: int, download: bool = False, session: Session = Depends(get_session)):
    r = _report(eng_id, session)
    headers = {
        # The report is a static document: no scripts run and nothing is fetched.
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:",
        "X-Content-Type-Options": "nosniff",
    }
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{_filename(r["engagement"], "html")}"'
    return HTMLResponse(report.render_html(r), headers=headers)


# ---- triage & endpoints ----------------------------------------------------

@app.get("/engagements/{eng_id}/triage")
def triage_view(eng_id: int, session: Session = Depends(get_session)):
    eng = _get(session, Engagement, eng_id)
    rows = targeting.ranked(session, eng)
    counts = {}
    for e in session.scalars(select(Endpoint).where(Endpoint.engagement_id == eng_id)):
        c = counts.setdefault(e.host, [0, 0])
        c[0] += 1
        c[1] += int(e.is_js)
    lead_counts: dict[str, int] = {}
    for l in session.scalars(select(Lead).where(Lead.engagement_id == eng_id)):
        lead_counts[l.host] = lead_counts.get(l.host, 0) + 1
    for r in rows:
        r["endpoints"], r["js"] = counts.get(r["host"], [0, 0])
        r["leads"] = lead_counts.get(r["host"], 0)
    return {"golden_min_score": triage.GOLDEN_MIN_SCORE, "weights": triage.WEIGHTS, "hosts": rows}


@app.get("/engagements/{eng_id}/endpoints")
def endpoints(eng_id: int, host: str | None = None, js: bool | None = None, q: str | None = None,
              module: str | None = None, limit: int = 200, offset: int = 0,
              session: Session = Depends(get_session)):
    _get(session, Engagement, eng_id)
    stmt = select(Endpoint).where(Endpoint.engagement_id == eng_id)
    if module:   # what one recon module produced
        stmt = stmt.join(Job, Job.id == Endpoint.job_id).where(Job.kind == module)
    if host:
        stmt = stmt.where(Endpoint.host == host.lower())
    if js is not None:
        stmt = stmt.where(Endpoint.is_js == js)
    if q:
        stmt = stmt.where(Endpoint.url.contains(q))
    total = len(session.scalars(stmt).all())
    rows = session.scalars(stmt.order_by(Endpoint.host, Endpoint.url).offset(offset).limit(min(limit, 1000))).all()
    return {"total": total, "items": [{"host": e.host, "url": e.url, "source": e.source, "js": e.is_js}
                                      for e in rows]}


@app.get("/engagements/{eng_id}/leads")
def leads(eng_id: int, kind: str | None = None, module: str | None = None,
          session: Session = Depends(get_session)):
    _get(session, Engagement, eng_id)
    stmt = select(Lead).where(Lead.engagement_id == eng_id)
    if kind:
        stmt = stmt.where(Lead.kind == kind)
    if module:   # what one recon module produced
        stmt = stmt.join(Job, Job.id == Lead.job_id).where(Job.kind == module)
    order = {"real": 0, "": 1, "public": 2}
    rows = sorted(session.scalars(stmt).all(),
                  key=lambda l: (order.get(l.bucket, 1), l.kind, l.host, l.title))
    return [{"id": l.id, "host": l.host, "source_url": l.source_url, "kind": l.kind, "title": l.title,
             "bucket": l.bucket, "severity": l.severity, "detail": l.detail} for l in rows]


# ---- hunt executors ----------------------------------------------------------

class LanePatch(BaseModel):
    executor: str


@app.get("/executors")
def list_executors():
    return [executors.as_dict(e) for e in executors.EXECUTORS.values()]


@app.patch("/lanes/{lane_id}")
def patch_lane(lane_id: int, body: LanePatch, session: Session = Depends(get_session)):
    lane = _get(session, Lane, lane_id)
    ex = executors.EXECUTORS.get(body.executor)
    if ex is None:
        raise HTTPException(422, f"unknown executor: {body.executor}")
    ok, why = ex.available()
    if not ok:
        raise HTTPException(422, why)
    lane.executor = ex.key
    session.commit()
    return _lane_view(lane)


@app.get("/lanes/{lane_id}/context")
def lane_context(lane_id: int, session: Session = Depends(get_session)):
    """What an executor working this lane may read: its items, the rules, and recon for its host only."""
    return executors.lane_context(session, _get(session, Lane, lane_id))


class AgentRunIn(BaseModel):
    max_turns: int = Field(default=15, ge=1, le=100)
    max_requests: int = Field(default=30, ge=1, le=1000)
    max_cost_usd: float = Field(default=0.50, ge=0.05, le=20)   # estimated; checked after each turn


@app.post("/lanes/{lane_id}/agent-runs", status_code=201)
def start_agent_run(lane_id: int, body: AgentRunIn | None = None, session: Session = Depends(get_session)):
    """Queue a Claude agent on this lane. It attaches evidence and marks items; it never
    closes the lane (D-018). Every gate is checked again when the worker starts it."""
    lane = _get(session, Lane, lane_id)
    body = body or AgentRunIn()
    ok, why = executors.EXECUTORS["agent"].available()
    if not ok:
        raise HTTPException(422, why)
    if lane.executor != "agent":
        raise HTTPException(422, "set this lane's executor to the Claude agent first")
    try:
        agenttools.check_lane(lane)
    except agenttools.RunRefused as e:
        raise HTTPException(422, str(e))
    busy = session.scalar(select(Job.id).where(Job.lane_id == lane.id, Job.kind == "agent",
                                               Job.status.in_([JobStatus.queued, JobStatus.running])))
    if busy is not None:
        raise HTTPException(409, f"an agent run is already queued or running on this lane (job {busy})")
    job = Job(engagement_id=lane.asset.engagement_id, kind="agent", lane_id=lane.id,
              targets=[lane.asset.host],
              result={"limits": {"max_turns": body.max_turns, "max_requests": body.max_requests,
                                 "max_cost_usd": body.max_cost_usd}})
    session.add(job)
    session.commit()
    return _job_view(job)


@app.get("/lanes/{lane_id}/agent-runs")
def list_agent_runs(lane_id: int, session: Session = Depends(get_session)):
    _get(session, Lane, lane_id)
    jobs = session.scalars(select(Job).where(Job.lane_id == lane_id, Job.kind == "agent")
                           .order_by(Job.id.desc()).limit(20)).all()
    return [_job_view(j, with_log=True) for j in jobs]


@app.get("/blobs/{digest}")
def get_blob(digest: str, session: Session = Depends(get_session)):
    """The raw bytes behind an evidence hash (an agent's HTTP exchange or note), for review.
    Only blobs that evidence refers to are served."""
    if session.scalar(select(Evidence.id).where(Evidence.sha256 == digest).limit(1)) is None:
        raise HTTPException(404, "no evidence refers to this hash")
    data = blobs.get(digest)
    if data is None:
        raise HTTPException(404, "the bytes for this hash are not in the blob store")
    # Target content: served as inert text, never rendered.
    return Response(data, media_type="text/plain; charset=utf-8",
                    headers={"Content-Security-Policy": "default-src 'none'; sandbox",
                             "X-Content-Type-Options": "nosniff"})


# ---- scope import ----------------------------------------------------------

class ScopeImportIn(BaseModel):
    csv: str = Field(min_length=1, max_length=2_000_000)
    apply: bool = False          # False: preview only
    mode: str = Field(default="merge", pattern="^(merge|replace)$")


@app.post("/engagements/{eng_id}/scope/import")
def import_scope(eng_id: int, body: ScopeImportIn, session: Session = Depends(get_session)):
    """Preview (default) or apply a HackerOne scope CSV. Ineligible assets become excludes."""
    eng = _get(session, Engagement, eng_id)
    try:
        parsed = scopeimport.parse(body.csv)
    except ValueError as e:
        raise HTTPException(422, str(e))
    if body.mode == "merge":
        inc = sorted((set(eng.scope_include) | set(parsed["include"])) - set(parsed["exclude"]))
        exc = sorted(set(eng.scope_exclude) | set(parsed["exclude"]))
    else:
        inc, exc = parsed["include"], parsed["exclude"]
    result = {**parsed, "result": {"include": inc, "exclude": exc}, "applied": False}
    if body.apply:
        eng.scope_include, eng.scope_exclude = inc, exc
        for a in eng.assets:            # rules can move hosts out of scope, never into it silently
            if not scope.in_scope(a.host, inc, exc):
                a.in_scope = False
        session.commit()
        result["applied"] = True
    return result
