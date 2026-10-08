from contextlib import asynccontextmanager

from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import executors, gates, jobgates, ledger, migrate, modules, packs, report, scope, triage, urls
from .db import get_session
from .models import (Asset, ChecklistItem, Endpoint, Engagement, Evidence, ItemState, Job, JobStatus,
                     Lane, Lead, Observation, Receipt)

ENGAGEMENT_TYPES = {"bug_bounty", "pentest", "internal"}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    packs.all_packs()  # fail fast on a broken pack
    migrate.upgrade_head()
    yield


app = FastAPI(title="AttackLedger", version="0.4.1", lifespan=lifespan)


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
         "created_at": j.created_at.isoformat(),
         "started_at": j.started_at.isoformat() if j.started_at else None,
         "finished_at": j.finished_at.isoformat() if j.finished_at else None}
    if with_log:
        v["log"] = j.log
    return v


def _probes_by_host(session: Session, eng_id: int) -> dict[str, list[dict]]:
    rows = session.scalars(select(Observation).where(Observation.engagement_id == eng_id)
                           .order_by(Observation.id.desc())).all()
    latest_job: dict[str, int] = {}
    out: dict[str, list[dict]] = {}
    for o in rows:
        if not o.data.get("live"):
            continue
        # Keep only the newest probe run per host (all its ports).
        if latest_job.setdefault(o.host, o.job_id) != o.job_id:
            continue
        out.setdefault(o.host, []).append(o.data)
    return out


def _ranked(session: Session, eng: Engagement) -> list[dict]:
    probes = {h: p for h, p in _probes_by_host(session, eng.id).items()
              if scope.in_scope(h, eng.scope_include, eng.scope_exclude)}
    rows = triage.rank(probes)
    for r in rows:
        r["urls"] = sorted({p["url"] for p in probes[r["host"]] if p.get("url")})
    return rows


# Hints when a module has nothing to run on, keyed by kind.
_NO_TARGET_HINT = {
    "crawl": "run 'Find live web servers' first",
    "jsanalyze": "crawl golden hosts or collect archived URLs first",
}


def _default_targets(session: Session, eng: Engagement, m: modules.Module) -> list[str]:
    kind = m.kind
    if m.input == "roots":
        return sorted(jobgates.roots(eng))
    if kind == "jsanalyze":
        js = session.scalars(select(Endpoint.url).where(Endpoint.engagement_id == eng.id,
                                                        Endpoint.is_js.is_(True))).all()
        js = [u for u in js if scope.in_scope(urls.host_of(u) or "", eng.scope_include, eng.scope_exclude)]
        # Highest-scoring hosts first, so a per-run cap spends itself where it matters.
        score = {r["host"]: r["score"] for r in _ranked(session, eng)}
        return sorted(js, key=lambda u: (-score.get(urls.host_of(u) or "", -1), u))
    if kind == "crawl":
        ranked = _ranked(session, eng)
        golden = [r for r in ranked if r["golden"]] or ranked
        return sorted({u for r in golden for u in r["urls"]})
    return sorted(a.host for a in eng.assets if a.in_scope)


@app.get("/modules")
def list_modules():
    """The recon pipeline as the UI renders it, straight from the registry."""
    return [modules.as_dict(m) for m in modules.MODULES]


@app.post("/engagements/{eng_id}/jobs", status_code=201)
def create_job(eng_id: int, body: JobIn, session: Session = Depends(get_session)):
    eng = _get(session, Engagement, eng_id)
    try:
        m = jobgates.check_engagement(eng, body.kind)
    except jobgates.GateError as e:
        raise HTTPException(422, str(e))
    targets = jobgates.normalize_targets(m, body.targets) or _default_targets(session, eng, m)
    if not targets:
        hint = _NO_TARGET_HINT.get(m.kind) or (
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
    if job.status not in (JobStatus.partial, JobStatus.cancelled) or not job.remaining_targets:
        raise HTTPException(422, "this run has no remaining targets")
    return create_job(job.engagement_id, JobIn(kind=job.kind, targets=job.remaining_targets), session)


@app.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: int, session: Session = Depends(get_session)):
    job = _get(session, Job, job_id)
    if job.status in (JobStatus.queued, JobStatus.running):
        if job.status == JobStatus.queued:
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
    rows = _ranked(session, eng)
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
              limit: int = 200, offset: int = 0, session: Session = Depends(get_session)):
    _get(session, Engagement, eng_id)
    stmt = select(Endpoint).where(Endpoint.engagement_id == eng_id)
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
def leads(eng_id: int, kind: str | None = None, session: Session = Depends(get_session)):
    _get(session, Engagement, eng_id)
    stmt = select(Lead).where(Lead.engagement_id == eng_id)
    if kind:
        stmt = stmt.where(Lead.kind == kind)
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
