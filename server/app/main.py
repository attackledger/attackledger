from contextlib import asynccontextmanager

from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import gates, packs, scope
from .db import Base, engine, get_session
from .models import (Asset, ChecklistItem, Engagement, Evidence, ItemState, Job, JobStatus, Lane,
                     Observation, Receipt)

ENGAGEMENT_TYPES = {"bug_bounty", "pentest", "internal"}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    packs.all_packs()  # fail fast on a broken pack
    Base.metadata.create_all(engine)
    yield


app = FastAPI(title="AttackLedger", version="0.1.0", lifespan=lifespan)


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
             "created_at": lane.receipts[-1].created_at.isoformat()}
            if lane.receipts else None
        ),
    }


# ---- routes ----------------------------------------------------------------

@app.get("/health")
def health():
    return {"ok": True}


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
    ev = Evidence(lane_id=lane.id, item_id=item_id, kind=body.kind, sha256=body.sha256,
                  uri=body.uri, summary=body.summary)
    session.add(ev)
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


@app.post("/lanes/{lane_id}/close")
def close_lane(lane_id: int, session: Session = Depends(get_session)):
    lane = _get(session, Lane, lane_id)
    problems = gates.unresolved(lane)
    if problems:
        raise HTTPException(422, {"error": "lane cannot close", "unresolved": problems})
    receipt = Receipt(lane_id=lane.id, manifest_sha256=gates.manifest_hash(lane))
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


# Job kinds that send requests to the target itself (not DNS or passive sources).
TARGET_TRAFFIC_KINDS = {"probe"}


def identification_missing(eng: Engagement) -> bool:
    return not (eng.research_header or eng.research_user_agent)


class AttestIn(BaseModel):
    operator: str = Field(min_length=1, max_length=200)
    policy_url: str = Field(pattern="^https://")
    confirm: bool


def _scope_view(eng: Engagement) -> dict:
    return {
        "include": eng.scope_include, "exclude": eng.scope_exclude,
        "rate_limit_rps": eng.rate_limit_rps, "policy_url": eng.policy_url,
        "research_header": eng.research_header, "research_user_agent": eng.research_user_agent,
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

JOB_KINDS = {
    "subdomains": "Find subdomains of the in-scope wildcard roots",
    "resolve": "Resolve in-scope hosts to IP addresses",
    "probe": "Check which in-scope hosts serve HTTP(S) and fingerprint them",
}


class JobIn(BaseModel):
    kind: str
    targets: list[str] = []  # empty = derive from scope / assets


def _job_view(j: Job, with_log: bool = False) -> dict:
    v = {"id": j.id, "kind": j.kind, "status": j.status.value, "targets": j.targets,
         "result_count": j.result_count, "output_sha256": j.output_sha256,
         "created_at": j.created_at.isoformat(),
         "started_at": j.started_at.isoformat() if j.started_at else None,
         "finished_at": j.finished_at.isoformat() if j.finished_at else None}
    if with_log:
        v["log"] = j.log
    return v


def _default_targets(eng: Engagement, kind: str) -> list[str]:
    if kind == "subdomains":
        return sorted({p[2:] for p in eng.scope_include if p.startswith("*.")})
    return sorted(a.host for a in eng.assets if a.in_scope)


@app.get("/jobs/kinds")
def job_kinds():
    return JOB_KINDS


@app.post("/engagements/{eng_id}/jobs", status_code=201)
def create_job(eng_id: int, body: JobIn, session: Session = Depends(get_session)):
    eng = _get(session, Engagement, eng_id)
    if body.kind not in JOB_KINDS:
        raise HTTPException(422, f"unknown job kind: {body.kind}")
    if eng.authorized_at is None:
        raise HTTPException(422, "record your authorization for this program before running jobs")
    if not eng.scope_include:
        raise HTTPException(422, "define the program scope before running jobs")
    if body.kind in TARGET_TRAFFIC_KINDS and identification_missing(eng):
        raise HTTPException(422, "set the research header or user agent the program requires "
                                 "before sending traffic to its hosts")
    targets = [t.strip().lower() for t in body.targets if t.strip()] or _default_targets(eng, body.kind)
    if not targets:
        raise HTTPException(422, "no targets: add in-scope hosts or a wildcard scope rule first")
    if body.kind == "subdomains":
        roots = {p[2:] for p in eng.scope_include if p.startswith("*.")}
        bad = [t for t in targets if t not in roots]
    else:
        bad = [t for t in targets if not scope.in_scope(t, eng.scope_include, eng.scope_exclude)]
    if bad:
        raise HTTPException(422, f"out of scope: {', '.join(bad[:10])}")
    job = Job(engagement_id=eng.id, kind=body.kind, targets=targets)
    session.add(job)
    session.commit()
    return _job_view(job)


@app.get("/engagements/{eng_id}/jobs")
def list_jobs(eng_id: int, session: Session = Depends(get_session)):
    eng = _get(session, Engagement, eng_id)
    return [_job_view(j) for j in eng.jobs[:100]]


@app.get("/jobs/{job_id}")
def get_job(job_id: int, session: Session = Depends(get_session)):
    return _job_view(_get(session, Job, job_id), with_log=True)


@app.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: int, session: Session = Depends(get_session)):
    job = _get(session, Job, job_id)
    if job.status in (JobStatus.queued, JobStatus.running):
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
