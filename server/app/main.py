from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import checklists, gates
from .db import Base, engine, get_session
from .models import Asset, ChecklistItem, Engagement, Evidence, ItemState, Lane, Receipt, Role

@asynccontextmanager
async def lifespan(_app: FastAPI):
    Base.metadata.create_all(engine)
    yield


app = FastAPI(title="AttackLedger", version="0.1.0", lifespan=lifespan)


# ---- schemas ---------------------------------------------------------------

class EngagementIn(BaseModel):
    name: str
    policy_url: str | None = None


class AssetIn(BaseModel):
    host: str
    in_scope: bool = True


class LaneIn(BaseModel):
    asset_id: int
    role: Role


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


def _lane_view(lane: Lane) -> dict:
    return {
        "id": lane.id,
        "host": lane.asset.host,
        "role": lane.role.value,
        "status": gates.lane_status(lane).value,
        "unresolved": gates.unresolved(lane),
        "items": [
            {"idx": i.idx, "text": i.text, "state": i.state.value, "na_reason": i.na_reason}
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
    eng = Engagement(name=body.name, policy_url=body.policy_url)
    session.add(eng)
    try:
        session.commit()
    except IntegrityError:
        raise HTTPException(409, "engagement name already exists")
    return {"id": eng.id, "name": eng.name}


@app.post("/engagements/{eng_id}/assets", status_code=201)
def add_asset(eng_id: int, body: AssetIn, session: Session = Depends(get_session)):
    _get(session, Engagement, eng_id)
    asset = Asset(engagement_id=eng_id, host=body.host.strip().lower(), in_scope=body.in_scope)
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
    try:
        gates.check_can_open(asset, body.role)
        texts = checklists.load_items(body.role)
    except (gates.GateError, FileNotFoundError, ValueError) as e:
        raise HTTPException(422, str(e))
    lane = Lane(asset_id=asset.id, role=body.role)
    lane.items = [ChecklistItem(idx=i, text=t) for i, t in enumerate(texts, start=1)]
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
    return [{"id": e.id, "name": e.name, "policy_url": e.policy_url, "assets": len(e.assets)}
            for e in engs]


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
    rows = []
    for asset in sorted(eng.assets, key=lambda a: a.host):
        by_role = {l.role: l for l in asset.lanes}
        rows.append({
            "asset_id": asset.id,
            "host": asset.host,
            "in_scope": asset.in_scope,
            "roles": {r.value: _cell(by_role.get(r)) for r in Role},
        })
    in_scope = [r for r in rows if r["in_scope"]]
    total = sum(len(r["roles"]) for r in in_scope)
    closed = sum(1 for r in in_scope for c in r["roles"].values() if c["status"] == "closed")
    return {"engagement": eng.name, "roles": [r.value for r in Role],
            "closed_cells": closed, "total_cells": total, "assets": rows}
