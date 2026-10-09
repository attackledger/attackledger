import base64
import binascii
import hmac
import json
import os
from contextlib import asynccontextmanager

from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import (agenttools, auth, authz, blobs, signing, executors, gates, jobgates, ledger, migrate, modules, packs, report,
               scope, scopeimport, triage, urls)
from . import targets as targeting
from .db import get_session
from .models import (ROLES, Asset, ChecklistItem, Endpoint, Engagement, Evidence, ItemState, Job, JobStatus,
                     Lane, Lead, Membership, Observation, Receipt, SigningKey, User)

ENGAGEMENT_TYPES = {"bug_bounty", "pentest", "internal"}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    packs.all_packs()  # fail fast on a broken pack
    migrate.upgrade_head()
    yield


# Every route passes authz.authorize first: who is calling, and may they use this route.
app = FastAPI(title="AttackLedger", version="0.6.0.dev0", lifespan=lifespan,
              dependencies=[Depends(authz.authorize)])
COOKIE_SECURE = os.environ.get("ATTACKLEDGER_COOKIE_SECURE", "") == "1"   # set behind HTTPS


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
        "engagement_id": lane.asset.engagement_id,
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
             "created_at": e.created_at.isoformat(), "created_by": e.created_by}
            for e in lane.evidence
        ],
        "receipt": (
            {"sha256": lane.receipts[-1].manifest_sha256,
             "closed_by": lane.receipts[-1].closed_by,
             "closed_by_user": lane.receipts[-1].closed_by_user,
             "signed": bool(lane.receipts[-1].signature),
             "algorithm": lane.receipts[-1].algorithm,
             "key_fingerprint": lane.receipts[-1].key_fingerprint,
             "created_at": lane.receipts[-1].created_at.isoformat()}
            if lane.receipts else None
        ),
    }


# ---- routes ----------------------------------------------------------------

@app.get("/health")
def health(session: Session = Depends(get_session)):
    # Says how callers sign in. An open API (no people, no token) must not leave localhost.
    m = auth.mode(session)
    return {"ok": True, "auth_required": m != "open", "mode": m}


class LoginIn(BaseModel):
    token: str | None = Field(default=None, max_length=500)
    email: str | None = Field(default=None, max_length=254)
    password: str | None = Field(default=None, max_length=256)


def _session_cookie(resp: JSONResponse, value: str) -> JSONResponse:
    resp.set_cookie(auth.COOKIE, value, httponly=True, samesite="strict", secure=COOKIE_SECURE,
                    max_age=auth.SESSION_HOURS * 3600, path="/")
    return resp


@app.post("/auth/login")
def login(body: LoginIn, request: Request, session: Session = Depends(get_session)):
    m = auth.mode(session)
    if body.email is not None:
        if m != "people":
            raise HTTPException(422, "nobody has an account yet; sign in with the operator token or create the first owner")
        email, addr = body.email.strip().lower(), request.client.host if request.client else ""
        if auth.locked(email, addr):
            raise HTTPException(429, "too many failed sign-ins; try again in 15 minutes")
        user = session.scalar(select(User).where(User.email == email))
        ok = auth.verify_password(body.password or "", user.password_hash if user else auth._DUMMY_HASH)
        if not ok or user is None or user.disabled:
            auth.record_failure(email, addr)
            raise HTTPException(401, "wrong email or password")
        auth.clear_failures(email, addr)
        return _session_cookie(JSONResponse({"ok": True, "mode": m, "name": user.name}),
                               auth.new_session(session, user.id))
    tok = auth.token()
    if tok is None:
        if m == "open":
            return {"ok": True, "mode": m}
        raise HTTPException(422, "sign in with your email and password")
    if not hmac.compare_digest((body.token or "").strip(), tok):
        raise HTTPException(401, "wrong token")
    return _session_cookie(JSONResponse({"ok": True, "mode": m}), auth.token_session_value(tok))


@app.post("/auth/logout")
def logout(request: Request, session: Session = Depends(get_session)):
    value = request.cookies.get(auth.COOKIE, "")
    if value:
        auth.end_session(session, value)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(auth.COOKIE, path="/")
    return resp


class KeyIn(BaseModel):
    algorithm: str
    public_key: str = Field(min_length=1, max_length=2000)     # SPKI, base64


def _key_view(k: SigningKey) -> dict:
    return {"id": k.id, "algorithm": k.algorithm, "fingerprint": k.fingerprint,
            "created_at": k.created_at.isoformat(), "revoked": k.revoked_at is not None}


def _person(request: Request):
    who = authz.current(request)
    if who.kind != "person":
        raise HTTPException(422, "signing keys belong to people; sign in with your account")
    return who


@app.get("/auth/keys")
def my_keys(request: Request, session: Session = Depends(get_session)):
    who = _person(request)
    return [_key_view(k) for k in session.scalars(select(SigningKey).where(SigningKey.user_id == who.user_id)
                                                  .order_by(SigningKey.id))]


@app.post("/auth/keys", status_code=201)
def add_key(body: KeyIn, request: Request, session: Session = Depends(get_session)):
    """Register the public half of a key created in your browser."""
    who = _person(request)
    try:
        signing.load_public_key(body.algorithm, body.public_key)
        fp = signing.fingerprint(body.public_key)
    except signing.SigningError as e:
        raise HTTPException(422, str(e))
    key = SigningKey(user_id=who.user_id, algorithm=body.algorithm, public_key=body.public_key, fingerprint=fp)
    session.add(key)
    try:
        session.commit()
    except IntegrityError:
        raise HTTPException(409, "that key is already registered")
    return _key_view(key)


@app.post("/auth/keys/{key_id}/revoke")
def revoke_key(key_id: int, request: Request, session: Session = Depends(get_session)):
    who = _person(request)
    key = session.get(SigningKey, key_id)
    if key is None or key.user_id != who.user_id:
        raise HTTPException(404, "not found")
    if key.revoked_at is None:
        key.revoked_at = datetime.now(timezone.utc)
        session.commit()
    return _key_view(key)


@app.get("/auth/me")
def me(request: Request, session: Session = Depends(get_session)):
    who = authz.current(request)
    return {"kind": who.kind, "user_id": who.user_id, "name": who.name, "is_owner": who.is_owner,
            "mode": auth.mode(session), "roles": {str(k): list(v) for k, v in who.roles.items()}}


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
def open_lane(body: LaneIn, request: Request, session: Session = Depends(get_session)):
    asset = _get(session, Asset, body.asset_id)
    who = authz.current(request)
    if not who.has(asset.engagement_id, "tester"):
        raise HTTPException(403 if who.can_read(asset.engagement_id) else 404,
                            "this needs the tester role on the engagement")
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
def add_evidence(lane_id: int, body: EvidenceIn, request: Request, session: Session = Depends(get_session)):
    lane = _get(session, Lane, lane_id)
    item_id = _item(lane, body.item_idx).id if body.item_idx is not None else None
    ev = ledger.append_evidence(session, lane, kind=body.kind, sha256_hex=body.sha256,
                                summary=body.summary, uri=body.uri, item_id=item_id,
                                created_by=authz.current(request).user_id)
    session.commit()
    return {"id": ev.id}


MAX_ATTACH_BYTES = 5_000_000


class AttachIn(BaseModel):
    """Evidence a person attaches from the lane panel. The server hashes and keeps the bytes."""
    item_idx: int
    kind: str = Field(pattern="^(note|file|run)$")
    text: str | None = Field(default=None, max_length=20_000)       # note
    filename: str | None = Field(default=None, max_length=200)      # file
    content_b64: str | None = Field(default=None, max_length=7_000_000)
    job_id: int | None = None                                       # run
    summary: str | None = Field(default=None, max_length=2_000)


@app.post("/lanes/{lane_id}/attach", status_code=201)
def attach_evidence(lane_id: int, body: AttachIn, request: Request, session: Session = Depends(get_session)):
    """Attach a note, a file or a recon run to one checklist item. Notes and files are
    stored in the blob store, so the evidence hash can be opened and checked later."""
    lane = _get(session, Lane, lane_id)
    item = _item(lane, body.item_idx)
    summary = (body.summary or "").strip()
    if body.kind == "note":
        text = (body.text or "").strip()
        if not text:
            raise HTTPException(422, "write the note first")
        digest, uri, kind, summary = blobs.put(text.encode()), None, "note", summary or text[:2_000]
    elif body.kind == "file":
        name = (body.filename or "").strip().replace("\\", "/").rsplit("/", 1)[-1]
        if not name or not body.content_b64:
            raise HTTPException(422, "choose a file to attach")
        try:
            data = base64.b64decode(body.content_b64, validate=True)
        except (binascii.Error, ValueError):
            raise HTTPException(422, "the file could not be read")
        if len(data) > MAX_ATTACH_BYTES:
            raise HTTPException(422, f"files are limited to {MAX_ATTACH_BYTES // 1_000_000} MB")
        if not summary:
            raise HTTPException(422, "say in a sentence what the file shows")
        digest, uri, kind = blobs.put(data), f"file:{name}", "file"
    else:
        job = session.get(Job, body.job_id) if body.job_id else None
        if job is None or job.engagement_id != lane.asset.engagement_id:
            raise HTTPException(422, "choose a recon run from this engagement")
        if job.status not in (JobStatus.done, JobStatus.partial) or not job.output_sha256:
            raise HTTPException(422, "only a finished run with recorded output can be evidence")
        m = modules.get(job.kind)
        label = f"{m.title if m else job.kind} run, job {job.id}"
        digest, uri, kind = job.output_sha256, f"job:{job.id}", "file"
        summary = f"{label}: {summary}" if summary else label
    ev = ledger.append_evidence(session, lane, kind=kind, sha256_hex=digest, summary=summary, uri=uri,
                                item_id=item.id, created_by=authz.current(request).user_id)
    session.commit()
    session.refresh(lane)
    return {"id": ev.id, **_lane_view(lane)}


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
    # The person signing. Taken from the account when people sign in; typed otherwise.
    closed_by: str | None = Field(default=None, max_length=200)
    reviewed: bool                                         # "I reviewed this lane's evidence"
    # A signed receipt: the payload from /receipt-payload, signed with the reviewer's key.
    payload: str | None = Field(default=None, max_length=4000)
    signature: str | None = Field(default=None, max_length=200)
    key_fingerprint: str | None = Field(default=None, pattern="^[0-9a-f]{64}$")


def _key_of(session, who, fp: str | None) -> SigningKey:
    key = session.scalar(select(SigningKey).where(SigningKey.fingerprint == (fp or "")))
    if key is None or key.user_id != who.user_id:
        raise HTTPException(422, "that signing key is not registered to you")
    if key.revoked_at is not None:
        raise HTTPException(422, "that signing key was revoked; create a new one")
    return key


def _check_signed(session, lane: Lane, who, body: "CloseIn") -> SigningKey:
    """A signed receipt must sign this lane as it is now, by this person, with their key."""
    if who.kind != "person":
        raise HTTPException(422, "only a signed-in person can sign a receipt")
    key = _key_of(session, who, body.key_fingerprint)
    try:
        p = json.loads(body.payload or "")
    except ValueError:
        raise HTTPException(422, "the signed payload is not valid JSON")
    if not isinstance(p, dict) or signing.payload_for(**_payload_fields(p)) != body.payload:
        raise HTTPException(422, "the signed payload is not in canonical form")
    eng = lane.asset.engagement
    checks = [
        (p["engagement"]["id"] == eng.id and p["lane"]["id"] == lane.id
         and p["lane"]["host"] == lane.asset.host and p["lane"]["role"] == lane.role, "it names another lane"),
        (p["manifest_sha256"] == gates.manifest_hash(lane), "the lane changed after the payload was issued"),
        (p["signer"]["id"] == who.user_id, "it names another signer"),
        (p["key_fingerprint"] == key.fingerprint, "it names another key"),
    ]
    head = session.scalar(select(Evidence).where(Evidence.engagement_id == eng.id,
                                                  Evidence.seq == p["chain"]["seq"]))
    checks.append((p["chain"]["seq"] == 0 and p["chain"]["head"] == ledger.GENESIS
                   or (head is not None and head.chain_hash == p["chain"]["head"]),
                   "its evidence chain head is not in this ledger"))
    try:
        issued = datetime.fromisoformat(p["issued_at"])
    except (TypeError, ValueError):
        issued = None
    age = (datetime.now(timezone.utc) - issued).total_seconds() if issued else None
    checks.append((age is not None and -60 <= age <= signing.PAYLOAD_MAX_AGE_SECONDS,
                   "it is too old; ask for a new payload"))
    for ok, why in checks:
        if not ok:
            raise HTTPException(422, f"the signed payload does not match: {why}")
    try:
        valid = signing.verify(key.algorithm, key.public_key, body.payload, body.signature or "")
    except signing.SigningError as e:
        raise HTTPException(422, f"signature: {e}")
    if not valid:
        raise HTTPException(422, "the signature does not verify with your key")
    return key


def _payload_fields(p: dict) -> dict:
    try:
        return {"engagement_id": p["engagement"]["id"], "engagement_name": p["engagement"]["name"],
                "lane_id": p["lane"]["id"], "host": p["lane"]["host"], "role": p["lane"]["role"],
                "manifest_sha256": p["manifest_sha256"], "chain_seq": p["chain"]["seq"],
                "chain_head": p["chain"]["head"], "signer_id": p["signer"]["id"],
                "signer_name": p["signer"]["name"], "key_fingerprint": p["key_fingerprint"],
                "issued_at": p["issued_at"]}
    except (KeyError, TypeError):
        raise HTTPException(422, "the signed payload is missing fields")


@app.get("/lanes/{lane_id}/receipt-payload")
def receipt_payload(lane_id: int, key: str, request: Request, session: Session = Depends(get_session)):
    """The text to sign for this lane as it is now. Valid for ten minutes."""
    lane = _get(session, Lane, lane_id)
    who = authz.current(request)
    if who.kind != "person":
        raise HTTPException(422, "only a signed-in person can sign a receipt")
    k = _key_of(session, who, key)
    eng = lane.asset.engagement
    seq, head = ledger.chain_head(session, eng.id)
    return {"payload": signing.payload_for(
        engagement_id=eng.id, engagement_name=eng.name, lane_id=lane.id, host=lane.asset.host, role=lane.role,
        manifest_sha256=gates.manifest_hash(lane), chain_seq=seq, chain_head=head, signer_id=who.user_id,
        signer_name=who.name, key_fingerprint=k.fingerprint,
        issued_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))}


@app.post("/lanes/{lane_id}/close")
def close_lane(lane_id: int, body: CloseIn, request: Request, session: Session = Depends(get_session)):
    """Issue a receipt. Only a person does this (D-018): executors, agents included,
    attach evidence and mark items, but the receipt carries a human signature."""
    lane = _get(session, Lane, lane_id)
    who = authz.current(request)
    if not body.reviewed:
        raise HTTPException(422, "confirm that you reviewed this lane's evidence before closing it")
    signer = who.name if who.kind == "person" else (body.closed_by or "").strip()
    if not signer:
        raise HTTPException(422, "a receipt needs the name of the person signing it")
    if lane.asset.engagement.separation_of_duties:
        if who.kind != "person":
            raise HTTPException(422, "separation of duties is on: sign in as a person to sign receipts")
        if any(e.created_by == who.user_id for e in lane.evidence):
            raise HTTPException(422, "separation of duties is on: you attached evidence to this lane, "
                                     "so someone else must sign its receipt")
    problems = gates.unresolved(lane)
    if problems:
        raise HTTPException(422, {"error": "lane cannot close", "unresolved": problems})
    key = None
    if body.signature or body.payload:
        key = _check_signed(session, lane, who, body)
    elif lane.asset.engagement.require_signatures:
        raise HTTPException(422, "this engagement requires signed receipts: sign with your key")
    receipt = Receipt(lane_id=lane.id, manifest_sha256=gates.manifest_hash(lane),
                      closed_by=signer, closed_by_user=who.user_id)
    if key is not None:
        receipt.payload, receipt.signature = body.payload, body.signature
        receipt.algorithm, receipt.public_key, receipt.key_fingerprint = key.algorithm, key.public_key, key.fingerprint
    session.add(receipt)
    session.commit()
    session.refresh(lane)
    return {"receipt": receipt.manifest_sha256, **_lane_view(lane)}


@app.get("/engagements")
def list_engagements(request: Request, session: Session = Depends(get_session)):
    who = authz.current(request)
    engs = [e for e in session.scalars(select(Engagement).order_by(Engagement.created_at.desc()))
            if who.can_read(e.id)]
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
            "separation_of_duties": eng.separation_of_duties,
            "require_signatures": eng.require_signatures,
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
        "separation_of_duties": eng.separation_of_duties,
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
def create_job(eng_id: int, body: JobIn, request: Request, session: Session = Depends(get_session)):
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
    job = Job(engagement_id=eng.id, kind=body.kind, targets=targets, created_by=authz.current(request).user_id)
    session.add(job)
    session.commit()
    return _job_view(job)


class PipelineIn(BaseModel):
    kinds: list[str] | None = None   # default: every module in registry order


@app.post("/engagements/{eng_id}/pipeline", status_code=201)
def run_pipeline(eng_id: int, request: Request, body: PipelineIn | None = None,
                 session: Session = Depends(get_session)):
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
        job = Job(engagement_id=eng.id, kind=m.kind, targets=[], deferred=True,
                  created_by=authz.current(request).user_id)
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
def resume_job(job_id: int, request: Request, session: Session = Depends(get_session)):
    """Run the targets a stopped job did not reach. Every gate is checked again."""
    job = _get(session, Job, job_id)
    if job.kind == "agent":
        raise HTTPException(422, "an agent run is not resumed; start a new run on the lane")
    if job.status not in (JobStatus.partial, JobStatus.cancelled) or not job.remaining_targets:
        raise HTTPException(422, "this run has no remaining targets")
    return create_job(job.engagement_id, JobIn(kind=job.kind, targets=job.remaining_targets), request, session)


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
def start_agent_run(lane_id: int, request: Request, body: AgentRunIn | None = None,
                    session: Session = Depends(get_session)):
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
              created_by=authz.current(request).user_id,
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


# ---- people and roles ---------------------------------------------------------

class PersonIn(BaseModel):
    email: str = Field(min_length=3, max_length=254, pattern=r"^[^@\s]+@[^@\s]+$")
    name: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=1, max_length=256)
    is_owner: bool = False


class PersonPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    password: str | None = Field(default=None, max_length=256)
    is_owner: bool | None = None
    disabled: bool | None = None


def _person_view(u: User) -> dict:
    return {"id": u.id, "email": u.email, "name": u.name, "is_owner": u.is_owner, "disabled": u.disabled}


def _active_owners(session) -> int:
    return len([u for u in session.scalars(select(User).where(User.is_owner.is_(True))) if not u.disabled])


@app.get("/people")
def list_people(session: Session = Depends(get_session)):
    return [_person_view(u) for u in session.scalars(select(User).order_by(User.name))]


@app.post("/people", status_code=201)
def create_person(body: PersonIn, session: Session = Depends(get_session)):
    """Add a person. The first one must be an owner: from then on, everyone signs in."""
    if not auth.people_exist(session) and not body.is_owner:
        raise HTTPException(422, "the first person must be an owner, or nobody could manage the ledger")
    why = auth.check_password_rules(body.password)
    if why:
        raise HTTPException(422, f"password: {why}")
    user = User(email=body.email.strip().lower(), name=body.name.strip(),
                password_hash=auth.hash_password(body.password), is_owner=body.is_owner)
    session.add(user)
    try:
        session.commit()
    except IntegrityError:
        raise HTTPException(409, "someone with that email already exists")
    return _person_view(user)


@app.patch("/people/{user_id}")
def update_person(user_id: int, body: PersonPatch, session: Session = Depends(get_session)):
    user = _get(session, User, user_id)
    losing_owner = (body.is_owner is False or body.disabled is True) and user.is_owner and not user.disabled
    if losing_owner and _active_owners(session) <= 1:
        raise HTTPException(422, "this is the last active owner; make someone else an owner first")
    if body.password is not None:
        why = auth.check_password_rules(body.password)
        if why:
            raise HTTPException(422, f"password: {why}")
        user.password_hash = auth.hash_password(body.password)
    if body.name is not None:
        user.name = body.name.strip()
    if body.is_owner is not None:
        user.is_owner = body.is_owner
    if body.disabled is not None:
        user.disabled = body.disabled
    session.commit()
    return _person_view(user)


class MemberIn(BaseModel):
    user_id: int
    roles: list[str]


class MembersIn(BaseModel):
    members: list[MemberIn]


@app.get("/engagements/{eng_id}/members")
def list_members(eng_id: int, session: Session = Depends(get_session)):
    _get(session, Engagement, eng_id)
    rows = session.scalars(select(Membership).where(Membership.engagement_id == eng_id)).all()
    users = {u.id: u for u in session.scalars(select(User))}
    return [{"user_id": m.user_id, "name": users[m.user_id].name, "email": users[m.user_id].email,
             "roles": m.roles} for m in rows if m.user_id in users]


@app.put("/engagements/{eng_id}/members")
def set_members(eng_id: int, body: MembersIn, session: Session = Depends(get_session)):
    """Replace who works on this engagement and in which roles."""
    _get(session, Engagement, eng_id)
    for m in body.members:
        bad = [r for r in m.roles if r not in ROLES]
        if bad:
            raise HTTPException(422, f"unknown role: {', '.join(bad)} (roles: {', '.join(ROLES)})")
        if session.get(User, m.user_id) is None:
            raise HTTPException(422, f"no person with id {m.user_id}")
    for old in session.scalars(select(Membership).where(Membership.engagement_id == eng_id)):
        session.delete(old)
    session.flush()
    for m in body.members:
        if m.roles:
            session.add(Membership(engagement_id=eng_id, user_id=m.user_id, roles=sorted(set(m.roles))))
    session.commit()
    return list_members(eng_id, session)


class EngagementPatch(BaseModel):
    separation_of_duties: bool | None = None
    require_signatures: bool | None = None


@app.patch("/engagements/{eng_id}")
def update_engagement(eng_id: int, body: EngagementPatch, session: Session = Depends(get_session)):
    eng = _get(session, Engagement, eng_id)
    if body.separation_of_duties is not None:
        eng.separation_of_duties = body.separation_of_duties
    if body.require_signatures is not None:
        eng.require_signatures = body.require_signatures
    session.commit()
    return {"id": eng.id, "separation_of_duties": eng.separation_of_duties,
            "require_signatures": eng.require_signatures}


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
