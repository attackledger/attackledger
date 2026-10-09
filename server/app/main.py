import base64
import binascii
import hashlib
import hmac
import io
import json
import os
import zipfile
from contextlib import asynccontextmanager

from datetime import date, datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, object_session

from . import (agenttools, auth, authz, blobs, signing, timestamps, executors, gates, jobgates, ledger, migrate, modules, packs, report,
               scope, scopeimport, triage, urls)
from . import auditlog, gatewayapi, importers, inbox, keylog, redact, vault
from . import targets as targeting
from .db import SessionLocal, get_session
from .models import (ROLES, iso_utc, Asset, ChecklistItem, Endpoint, Engagement, Evidence, ImportBatch, InboxEntry,
                     ItemState, Job, JobStatus, Lane, Lead, Membership, Observation, Receipt, SigningKey, User)

ENGAGEMENT_TYPES = {"bug_bounty", "pentest", "internal"}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    packs.all_packs()  # fail fast on a broken pack
    vault.master_key()  # fail closed: no master key, no API (D-043)
    importers.registry()  # and on an import adapter that does not meet the contract
    migrate.upgrade_head()
    with SessionLocal() as s:
        vault.check_store(s)
    yield


# Every route passes authz.authorize first: who is calling, and may they use this route.
# FastAPI's own documentation routes would skip that dependency, so they are off and served
# below as ordinary routes, which the permission table covers (sign-in whenever it is needed).
app = FastAPI(title="AttackLedger", version="0.6.0.dev0", lifespan=lifespan,
              dependencies=[Depends(authz.authorize)], docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(gatewayapi.router)
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


def _content(e: Evidence, text: str | None, eng: Engagement) -> str:
    """available, deleted (the engagement's key was deleted) or unreadable (a ciphertext that
    does not open while the key exists: a damaged row)."""
    if text is not None:
        return "available"
    return "deleted" if eng.content_deleted_at is not None else "unreadable"


def _evidence_view(lane: Lane, e: Evidence, keys: vault.Keys) -> dict:
    text = vault.summary_of(e, keys)
    return {"id": e.id, "item_idx": next((i.idx for i in lane.items if i.id == e.item_id), None),
            "kind": e.kind, "sha256": e.sha256, "uri": e.uri, "summary": text,
            "content": _content(e, text, lane.asset.engagement), "v": e.record_version, "source": e.source,
            "summary_sha256": e.summary_sha256,
            "redaction": e.redaction, "created_at": iso_utc(e.created_at), "created_by": e.created_by}


def _inbox_counts(lane: Lane) -> dict:
    """Imported entries on the lane's host, by state, so whoever signs sees what was imported
    and not mapped or set aside (the entries themselves are in the Import tab)."""
    session = object_session(lane)
    counts = dict.fromkeys(inbox.STATES, 0)
    if session is not None:
        counts |= dict(session.execute(
            select(InboxEntry.state, func.count()).where(InboxEntry.engagement_id == lane.asset.engagement_id,
                                                          InboxEntry.host == lane.asset.host)
            .group_by(InboxEntry.state)).all())
    return counts


def _lane_view(lane: Lane) -> dict:
    pack = _pack_of(lane.asset.engagement)
    keys = vault.Keys()
    by_role = {l.role: l for l in lane.asset.lanes}
    waiting = gates.waiting_on(lane.asset, pack.lane(lane.role)) if lane.role in pack.lane_index else []
    return {
        "id": lane.id,
        "engagement_id": lane.asset.engagement_id,
        "host": lane.asset.host,
        "role": lane.role,
        "role_name": pack.lane(lane.role).name if lane.role in pack.lane_index else lane.role,
        "executor": lane.executor,
        "status": gates.lane_status(lane).value,
        "unresolved": gates.unresolved(lane),
        # Lanes this one needs that are not receipted on this host: it can be worked, not signed.
        "waiting_on": [{"key": k, "name": pack.lane(k).name, "lane_id": by_role[k].id if k in by_role else None,
                        "status": gates.lane_status(by_role[k]).value if k in by_role else "not_opened"}
                       for k in waiting],
        # Items with evidence that are still open: they wait to be marked done, not for evidence.
        "awaiting_done": gates.awaiting_done(lane),
        "inbox": _inbox_counts(lane),
        "items": [
            {"idx": i.idx, "key": i.item_key, "text": i.text, "state": i.state.value,
             "na_reason": i.na_reason, "controls": i.controls}
            for i in lane.items
        ],
        "evidence_count": len(lane.evidence),
        "evidence": [_evidence_view(lane, e, keys) for e in lane.evidence],
        "content_deleted": vault.deleted_info(lane.asset.engagement),
        "receipt": (
            {"sha256": lane.receipts[-1].manifest_sha256,
             "closed_by": lane.receipts[-1].closed_by,
             "closed_by_user": lane.receipts[-1].closed_by_user,
             "closed_by_email": lane.receipts[-1].closed_by_email,
             "signed": bool(lane.receipts[-1].signature),
             "algorithm": lane.receipts[-1].algorithm,
             "key_fingerprint": lane.receipts[-1].key_fingerprint,
             "timestamp": ({"time": iso_utc(lane.receipts[-1].timestamp_time),
                            "tsa": lane.receipts[-1].timestamp_tsa}
                           if lane.receipts[-1].timestamp_token else None),
             "timestamp_error": lane.receipts[-1].timestamp_error,
             "created_at": iso_utc(lane.receipts[-1].created_at)}
            if lane.receipts else None
        ),
    }


# ---- routes ----------------------------------------------------------------

@app.get("/health")
def health(session: Session = Depends(get_session)):
    # Says how callers sign in. An open API (no people, no token) must not leave localhost.
    m = auth.mode(session)
    return {"ok": True, "auth_required": m != "open", "mode": m, "timestamps": bool(timestamps.tsa_url()),
            "encryption": vault.describe_master()}


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
    if m == "setup":
        raise HTTPException(422, auth.SETUP_HINT)
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
        user.previous_sign_in_at, user.last_sign_in_at = user.last_sign_in_at, datetime.now(timezone.utc)
        value = auth.new_session(session, user.id)
        return _session_cookie(JSONResponse({"ok": True, "mode": m, "name": user.name,
                                             "key_notice": _key_notice(session, user)}), value)
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
            "created_at": iso_utc(k.created_at), "revoked": k.revoked_at is not None}


def _key_notice(session, user: User) -> dict:
    """Keys registered or revoked for this person since their previous sign-in (all of them
    at the first sign-in), so a key they did not make does not go unseen."""
    keys = {k.fingerprint: k for k in session.scalars(select(SigningKey).where(SigningKey.user_id == user.id))}
    events = []
    for e in keylog.since(session, user.id, user.previous_sign_in_at):
        k = keys.get(e.key_fingerprint)
        events.append({"event": e.event, "key_fingerprint": e.key_fingerprint, "algorithm": e.algorithm,
                       "at": e.at, "via": e.via, "key_id": k.id if k else None,
                       "key_revoked": bool(k and k.revoked_at is not None)})
    return {"since": iso_utc(user.previous_sign_in_at), "events": events}


def _via(user: User) -> str:
    return "own_session" if user.password_chosen else "assigned_password"


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
        session.flush()
    except IntegrityError:
        session.rollback()
        raise HTTPException(409, "that key is already registered")
    user = session.get(User, who.user_id)
    keylog.append(session, user=user, key=key, event="registered", via=_via(user))
    session.commit()
    return _key_view(key)


@app.post("/auth/keys/{key_id}/revoke")
def revoke_key(key_id: int, request: Request, session: Session = Depends(get_session)):
    who = _person(request)
    key = session.get(SigningKey, key_id)
    if key is None or key.user_id != who.user_id:
        raise HTTPException(404, "not found")
    if key.revoked_at is None:
        key.revoked_at = datetime.now(timezone.utc)
        user = session.get(User, who.user_id)
        keylog.append(session, user=user, key=key, event="revoked", via=_via(user))
        session.commit()
    return _key_view(key)


@app.get("/auth/me")
def me(request: Request, session: Session = Depends(get_session)):
    who = authz.current(request)
    out = {"kind": who.kind, "user_id": who.user_id, "name": who.name, "is_owner": who.is_owner,
           "mode": auth.mode(session), "roles": {str(k): list(v) for k, v in who.roles.items()}}
    if who.kind == "person":
        user = session.get(User, who.user_id)
        out.update(password_chosen=user.password_chosen, key_notice=_key_notice(session, user))
    return out


class PasswordIn(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


@app.post("/auth/password")
def change_password(body: PasswordIn, request: Request, session: Session = Depends(get_session)):
    """Change your own password. It needs the current one, and signs you out everywhere else."""
    who = authz.current(request)
    if who.kind != "person":
        raise HTTPException(422, "only a person signed in with their account has a password")
    user = session.get(User, who.user_id)
    addr = request.client.host if request.client else ""
    if auth.locked(user.email, addr):
        raise HTTPException(429, "too many failed attempts; try again in 15 minutes")
    if not auth.verify_password(body.current_password, user.password_hash):
        auth.record_failure(user.email, addr)
        raise HTTPException(403, "your current password is not right")
    why = auth.check_password_rules(body.new_password)
    if why:
        raise HTTPException(422, f"new password: {why}")
    auth.clear_failures(user.email, addr)
    user.password_hash, user.password_chosen = auth.hash_password(body.new_password), True
    auth.end_sessions(session, user.id, keep=request.cookies.get(auth.COOKIE, ""))
    auditlog.append(session, actor=auditlog.actor(who), action="person.password_changed", subject_id=user.id,
                    change={"person": auditlog.person_ref(user), "password_chosen": True})
    session.commit()
    return {"ok": True}


@app.post("/engagements", status_code=201)
def create_engagement(body: EngagementIn, request: Request, session: Session = Depends(get_session)):
    try:
        pack = packs.get_pack(body.pack_id)
    except packs.PackError as e:
        raise HTTPException(422, str(e))
    etype = body.engagement_type or (pack.engagement_types[0] if pack.engagement_types else "pentest")
    if etype not in ENGAGEMENT_TYPES:
        raise HTTPException(422, f"unknown engagement type: {etype}")
    eng = Engagement(name=body.name.strip(), policy_url=_policy_url(body.policy_url, required=False), pack_id=pack.id,
                     engagement_type=etype)
    session.add(eng)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        raise HTTPException(409, "engagement name already exists")
    auditlog.append(session, actor=auditlog.actor(authz.current(request)), action="engagement.created",
                    engagement_id=eng.id, change={"after": {"name": eng.name, "pack_id": eng.pack_id,
                                                            "engagement_type": eng.engagement_type,
                                                            "policy_url": eng.policy_url}})
    session.commit()
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
    # Asked for in scope and stored out of scope: say so and why, rather than only storing it.
    note = "stored as out of scope: not in the scope rules" if body.in_scope and not allowed else None
    return {"id": asset.id, "host": asset.host, "in_scope": asset.in_scope, "scope_note": note}


@app.post("/lanes", status_code=201)
def open_lane(body: LaneIn, request: Request, session: Session = Depends(get_session)):
    asset = _get(session, Asset, body.asset_id)
    who = authz.current(request)
    if not who.has(asset.engagement_id, "tester"):
        raise HTTPException(403 if who.can_read(asset.engagement_id) else 404,
                            "this needs the tester role on the engagement")
    if asset.engagement.content_deleted_at is not None:    # no lane can be receipted again
        raise HTTPException(409, vault.deleted_sentence(vault.deleted_info(asset.engagement)))
    pack = _pack_of(asset.engagement)
    if any(l.role == body.role for l in asset.lanes):
        raise HTTPException(409, "lane already open for this asset and role")
    try:
        lane = gates.open_lane(session, asset, pack, body.role)
    except gates.GateError as e:
        raise HTTPException(422, str(e))
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
    # The bytes behind the hash are the caller's; the summary and URI are stored here, so a
    # credential in them is redacted. Nothing is noted when nothing was found.
    summary, uri, rep = body.summary, body.uri, redact.Report()
    if redact.enabled(lane.asset.engagement):
        summary, uri = redact.text(summary, rep), redact.text(uri, rep) if uri else uri
    try:
        ev = ledger.append_evidence(session, lane, kind=body.kind, sha256_hex=body.sha256,
                                    summary=summary + rep.suffix(), uri=uri, item_id=item_id, source="manual",
                                    created_by=authz.current(request).user_id,
                                    redaction=rep.as_dict() if rep.count else None)
    except vault.ContentDeleted as e:
        raise HTTPException(409, f"{e} It takes no new evidence.")
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
    eng_id = lane.asset.engagement_id
    try:
        vault.check_writable(lane.asset.engagement)
    except vault.ContentDeleted as e:
        raise HTTPException(409, f"{e} It takes no new evidence.")
    summary = (body.summary or "").strip()
    # Notes and files are redacted before they are stored (D-038); the summary says what was.
    on = redact.enabled(lane.asset.engagement)
    rep, redaction = redact.Report(off=not on), None
    if on and summary:
        summary = redact.text(summary, rep)
    if body.kind == "note":
        text = (body.text or "").strip()
        if not text:
            raise HTTPException(422, "write the note first")
        if on:
            text = redact.text(text, rep)
        digest, uri, kind, summary = blobs.put(text.encode(), engagement_id=eng_id), None, "note", summary or text[:2_000]
        redaction = rep.as_dict()
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
        if on:      # text formats are redacted; binary files are kept as they are, and the summary says so
            data = redact.data(data, rep, personal=True, filename=name)
        digest, uri, kind = blobs.put(data, engagement_id=eng_id), f"file:{name}", "file"
        redaction = rep.as_dict()
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
        if rep.count:
            redaction = rep.as_dict()
    if redaction is not None:
        summary += rep.suffix()
    ev = ledger.append_evidence(session, lane, kind=kind, sha256_hex=digest, summary=summary, uri=uri,
                                item_id=item.id, source="manual", created_by=authz.current(request).user_id,
                                redaction=redaction)
    session.commit()
    session.refresh(lane)
    return {"id": ev.id, **_lane_view(lane)}


@app.patch("/lanes/{lane_id}/items/{idx}")
def update_item(lane_id: int, idx: int, body: ItemUpdate, session: Session = Depends(get_session)):
    lane = _get(session, Lane, lane_id)
    item = _item(lane, idx)
    if lane.asset.engagement.content_deleted_at is not None:    # the evidence can no longer be reviewed
        raise HTTPException(409, vault.deleted_sentence(vault.deleted_info(lane.asset.engagement)))
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
    if isinstance(p, dict) and p.get("format") != signing.PAYLOAD_FORMAT:
        raise HTTPException(422, "the signed payload is in another format; ask for a new payload")
    if not isinstance(p, dict) or signing.payload_for(**_payload_fields(p)) != body.payload:
        raise HTTPException(422, "the signed payload is not in canonical form")
    eng = lane.asset.engagement
    checks = [
        (p["engagement"]["id"] == eng.id and p["lane"]["id"] == lane.id
         and p["lane"]["host"] == lane.asset.host and p["lane"]["role"] == lane.role, "it names another lane"),
        (p["manifest_sha256"] == gates.manifest_hash(lane), "the lane changed after the payload was issued"),
        (p["signer"]["id"] == who.user_id and p["signer"]["name"] == who.name
         and p["signer"]["email"] == who.email, "it names another signer, or your name or email changed"),
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
                "signer_name": p["signer"]["name"], "signer_email": p["signer"]["email"],
                "key_fingerprint": p["key_fingerprint"],
                "issued_at": p["issued_at"]}
    except (KeyError, TypeError):
        raise HTTPException(422, "the signed payload is missing fields")


def _check_can_close(lane: Lane) -> None:
    try:
        gates.check_can_close(lane, _pack_of(lane.asset.engagement))
    except gates.GateError as e:
        raise HTTPException(422, str(e))


@app.get("/lanes/{lane_id}/receipt-payload")
def receipt_payload(lane_id: int, key: str, request: Request, session: Session = Depends(get_session)):
    """The text to sign for this lane as it is now. Valid for ten minutes."""
    lane = _get(session, Lane, lane_id)
    who = authz.current(request)
    if who.kind != "person":
        raise HTTPException(422, "only a signed-in person can sign a receipt")
    k = _key_of(session, who, key)
    _check_can_close(lane)          # do not hand out a payload the close would refuse
    eng = lane.asset.engagement
    seq, head = ledger.chain_head(session, eng.id)
    return {"payload": signing.payload_for(
        engagement_id=eng.id, engagement_name=eng.name, lane_id=lane.id, host=lane.asset.host, role=lane.role,
        manifest_sha256=gates.manifest_hash(lane), chain_seq=seq, chain_head=head, signer_id=who.user_id,
        signer_name=who.name, signer_email=who.email, key_fingerprint=k.fingerprint,
        issued_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))}


@app.post("/lanes/{lane_id}/close")
def close_lane(lane_id: int, body: CloseIn, request: Request, session: Session = Depends(get_session)):
    """Issue a receipt. Only a person does this (D-018): executors, agents included,
    attach evidence and mark items, but the receipt carries a human signature."""
    lane = _get(session, Lane, lane_id)
    who = authz.current(request)
    if not body.reviewed:
        raise HTTPException(422, "confirm that you reviewed this lane's evidence before closing it")
    if lane.asset.engagement.content_deleted_at is not None:     # nobody can review what can no longer be read
        raise HTTPException(409, vault.deleted_sentence(vault.deleted_info(lane.asset.engagement))
                            + " Its evidence can no longer be reviewed, so no new receipt is issued.")
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
    _check_can_close(lane)
    key = None
    if body.signature or body.payload:
        key = _check_signed(session, lane, who, body)
    elif lane.asset.engagement.require_signatures:
        raise HTTPException(422, "this engagement requires signed receipts: sign with your key")
    receipt = Receipt(lane_id=lane.id, manifest_sha256=gates.manifest_hash(lane),
                      closed_by=signer, closed_by_user=who.user_id, closed_by_email=who.email or None)
    if key is not None:
        receipt.payload, receipt.signature = body.payload, body.signature
        receipt.algorithm, receipt.public_key, receipt.key_fingerprint = key.algorithm, key.public_key, key.fingerprint
    _timestamp(receipt)
    session.add(receipt)
    session.commit()
    session.refresh(lane)
    return {"receipt": receipt.manifest_sha256, **_lane_view(lane)}


def _timestamp(receipt: Receipt) -> None:
    """Ask the timestamp authority, if one is set. A failure leaves the receipt valid but
    untimestamped, with the reason, so the close is never lost to an unreachable TSA."""
    url = timestamps.tsa_url()
    if not url:
        return
    try:
        token, when = timestamps.fetch(url, timestamps.statement(receipt.manifest_sha256, receipt.signature))
    except timestamps.TimestampError as e:
        receipt.timestamp_error = str(e)[:500]
        return
    receipt.timestamp_token, receipt.timestamp_time, receipt.timestamp_tsa = token, when, url
    receipt.timestamp_error = None


@app.post("/lanes/{lane_id}/receipt/timestamp")
def timestamp_receipt(lane_id: int, session: Session = Depends(get_session)):
    """Timestamp the lane's current receipt now, after an earlier attempt failed or for a
    receipt issued before a timestamp authority was set. The token shows the later time."""
    lane = _get(session, Lane, lane_id)
    if not timestamps.tsa_url():
        raise HTTPException(422, "no timestamp authority is set (ATTACKLEDGER_TSA_URL)")
    if gates.lane_status(lane) != gates.LaneStatus.closed or not lane.receipts:
        raise HTTPException(422, "this lane has no current receipt")
    receipt = lane.receipts[-1]
    if receipt.timestamp_token:
        raise HTTPException(409, "this receipt is already timestamped")
    _timestamp(receipt)
    session.commit()
    session.refresh(lane)
    if receipt.timestamp_error:
        raise HTTPException(502, receipt.timestamp_error)
    return _lane_view(lane)


@app.get("/engagements")
def list_engagements(request: Request, session: Session = Depends(get_session)):
    who = authz.current(request)
    engs = [e for e in session.scalars(select(Engagement).order_by(Engagement.created_at.desc()))
            if who.can_read(e.id)]
    return [{"id": e.id, "name": e.name, "policy_url": e.policy_url, "assets": len(e.assets),
             "pack_id": e.pack_id, "engagement_type": e.engagement_type} for e in engs]


def _cell(lane: Lane | None, waiting: list[str]) -> dict:
    """waiting_on: lanes this one needs that are not receipted on the host. Under the pack's
    needs_gate "close" the lane can still be opened and worked; under "open" it cannot open."""
    if lane is None:
        return {"status": "not_opened", "waiting_on": waiting}
    status = gates.lane_status(lane).value
    cell = {"status": status, "lane_id": lane.id, "unresolved": len(gates.unresolved(lane)),
            "awaiting_done": gates.awaiting_done(lane), "waiting_on": waiting}
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
            "roles": {k: _cell(by_role.get(k), gates.waiting_on(asset, pack.lane(k))) for k in keys},
        })
    in_scope = [r for r in rows if r["in_scope"]]
    total = sum(len(r["roles"]) for r in in_scope)
    closed = sum(1 for r in in_scope for c in r["roles"].values() if c["status"] == "closed")
    return {"engagement": eng.name, "pack": {"id": pack.id, "name": pack.name, "needs_gate": pack.needs_gate},
            "separation_of_duties": eng.separation_of_duties,
            "require_signatures": eng.require_signatures,
            "retain_until": eng.retain_until.isoformat() if eng.retain_until else None,
            "content_deleted": vault.deleted_info(eng),
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
    policy_url: str | None = None      # checked by _policy_url, for a message a person can act on
    confirm: bool


POLICY_URL_HINT = ("enter the address of the program policy or statement of work that permits this test, "
                   "such as https://hackerone.com/<program>; for the bundled lab, any HTTPS page that describes "
                   "it will do, such as https://example.com/policy")


def _policy_url(value: str | None, required: bool) -> str | None:
    url = (value or "").strip()
    if not url:
        if required:
            raise HTTPException(422, f"a policy URL is required: {POLICY_URL_HINT}")
        return None
    if not url.startswith("https://") or not urls.host_of(url):
        raise HTTPException(422, f"the policy URL must start with https://; {POLICY_URL_HINT}")
    if len(url) > 500:
        raise HTTPException(422, "the policy URL is longer than 500 characters")
    return url


def _scope_view(eng: Engagement) -> dict:
    return {
        "include": eng.scope_include, "exclude": eng.scope_exclude,
        "rate_limit_rps": eng.rate_limit_rps, "policy_url": eng.policy_url,
        "research_header": eng.research_header, "research_user_agent": eng.research_user_agent,
        "enabled_modules": sorted(eng.enabled_modules or []), "crawl_depth": eng.crawl_depth,
        "authorized_by": eng.authorized_by,
        "authorized_at": iso_utc(eng.authorized_at),
        "separation_of_duties": eng.separation_of_duties,
        "redact_evidence": eng.redact_evidence,
        "retain_until": eng.retain_until.isoformat() if eng.retain_until else None,
        "content_deleted": vault.deleted_info(eng),
    }


@app.get("/engagements/{eng_id}/scope")
def get_scope(eng_id: int, session: Session = Depends(get_session)):
    return _scope_view(_get(session, Engagement, eng_id))


@app.put("/engagements/{eng_id}/scope")
def put_scope(eng_id: int, body: ScopeIn, request: Request, session: Session = Depends(get_session)):
    eng = _get(session, Engagement, eng_id)
    before = auditlog.scope_snapshot(eng)
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
    added = _apply_scope_to_assets(eng, inc, exc)
    _audit_scope(session, request, eng, before, added)
    session.commit()
    return {**_scope_view(eng), "hosts_added": added}


def _audit_scope(session, request: Request, eng: Engagement, before: dict, added: list[str],
                 imported: str | None = None) -> None:
    """One scope.updated entry, if a rule or a host changed."""
    after = auditlog.scope_snapshot(eng)
    if after == before and not added:
        return
    change = {"before": before, "after": after}
    if added:
        change["hosts_added"] = added
    if imported:
        change["import"] = imported
    auditlog.append(session, actor=auditlog.actor(authz.current(request)), action="scope.updated",
                    engagement_id=eng.id, change=change)


def _apply_scope_to_assets(eng: Engagement, inc: list[str], exc: list[str]) -> list[str]:
    """Rules can move existing hosts out of scope, never into it silently. Each exact
    include rule that no exclusion matches becomes a host, if it is not one already;
    wildcards stay rules, and recon finds their hosts. Returns the hosts added."""
    for a in eng.assets:
        if not scope.in_scope(a.host, inc, exc):
            a.in_scope = False
    known = {a.host for a in eng.assets}
    added = [p for p in inc if not p.startswith("*.") and p not in known and scope.in_scope(p, inc, exc)]
    for host in added:
        eng.assets.append(Asset(host=host, in_scope=True))
    return added


@app.post("/engagements/{eng_id}/attest")
def attest(eng_id: int, body: AttestIn, request: Request, session: Session = Depends(get_session)):
    if not body.confirm:
        raise HTTPException(422, "confirm that you are authorized to test this program")
    policy_url = _policy_url(body.policy_url, required=True)
    eng = _get(session, Engagement, eng_id)
    before = auditlog.authorization_snapshot(eng)
    eng.authorized_by, eng.policy_url = body.operator.strip(), policy_url
    eng.authorized_at = datetime.now(timezone.utc)
    auditlog.append(session, actor=auditlog.actor(authz.current(request)), action="engagement.authorized",
                    engagement_id=eng.id, change={"before": before, "after": auditlog.authorization_snapshot(eng)})
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
         "created_at": iso_utc(j.created_at),
         "started_at": iso_utc(j.started_at),
         "finished_at": iso_utc(j.finished_at)}
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
    """Queue every step that passes its gates and can apply to this scope, in registry
    order. Each step resolves its targets when it starts, from what the steps before it
    produced; one that finds none ends "skipped", with the reason."""
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
        why = targeting.cannot_apply(eng, m)
        if why:
            skipped.append({"kind": m.kind, "reason": why})
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
            "engagement_types": list(p.engagement_types), "needs_gate": p.needs_gate,
            "lanes": [{"key": l.key, "name": l.name, "needs": list(l.needs), "items": len(l.items)}
                      for l in p.lanes]}


@app.get("/packs")
def list_packs():
    return [_pack_summary(p) for p in packs.all_packs().values()]


@app.get("/engagements/{eng_id}/controls")
def control_coverage(eng_id: int, session: Session = Depends(get_session)):
    """For each control the pack maps to, how much of it is backed by receipted evidence.

    Only items in receipted (closed) lanes on in-scope hosts count. An item done with
    evidence counts as evidenced; an item marked not applicable, with its reason, is
    counted separately and never as evidence. Status: "evidenced" when every mapped
    item has evidence, "resolved" when every item is resolved but some are not
    applicable, "not_applicable" when all are, "partial" when some are resolved,
    "none" otherwise.
    """
    eng = _get(session, Engagement, eng_id)
    pack = _pack_of(eng)
    cat = packs.catalog().controls
    hosts = [a for a in eng.assets if a.in_scope]
    out: dict[str, dict] = {}
    for lane_def in pack.lanes:
        for item in lane_def.items:
            for cid in item.controls:
                c = out.setdefault(cid, {**cat[cid], "required": 0, "evidenced": 0, "not_applicable": 0,
                                         "lanes": set()})
                c["lanes"].add(lane_def.name)
                for a in hosts:
                    c["required"] += 1
                    lane = next((l for l in a.lanes if l.role == lane_def.key), None)
                    if lane is None or gates.lane_status(lane) != gates.LaneStatus.closed:
                        continue
                    li = next((i for i in lane.items if i.item_key == item.id), None)
                    if li is not None and li.state == ItemState.done:
                        c["evidenced"] += 1
                    elif li is not None and li.state == ItemState.na:
                        c["not_applicable"] += 1
    rows = []
    for c in out.values():
        c["lanes"] = sorted(c["lanes"])
        resolved = c["evidenced"] + c["not_applicable"]
        if c["required"] and c["evidenced"] == c["required"]:
            c["status"] = "evidenced"
        elif c["required"] and resolved == c["required"]:
            c["status"] = "resolved" if c["evidenced"] else "not_applicable"
        elif resolved:
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
def get_blob(digest: str, request: Request, session: Session = Depends(get_session)):
    """The raw bytes behind an evidence hash (an agent's HTTP exchange or note), for review.
    Only blobs that evidence refers to are served."""
    who = authz.current(request)
    eng_ids = sorted(set(session.scalars(select(Evidence.engagement_id).where(Evidence.sha256 == digest))))
    eng_ids = [i for i in eng_ids if who.can_read(i)]
    if not eng_ids:
        raise HTTPException(404, "no evidence refers to this hash")
    data, deleted = None, []
    for eng_id in eng_ids:          # each engagement keeps its own encrypted copy
        eng = session.get(Engagement, eng_id)
        if eng.content_deleted_at is not None:
            deleted.append(eng)
            continue
        data = blobs.get(digest, engagement_id=eng_id)
        if data is not None:
            break
    if data is None and deleted and len(deleted) == len(eng_ids):
        raise HTTPException(410, vault.deleted_sentence(vault.deleted_info(deleted[0])))
    if data is None:
        raise HTTPException(404, "the bytes for this hash are not in the blob store, or do not match it")
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
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=200)
    password: str | None = Field(default=None, max_length=256)   # refused: see update_person
    is_owner: bool | None = None
    disabled: bool | None = None


def _person_view(u: User) -> dict:
    return {"id": u.id, "email": u.email, "name": u.name, "is_owner": u.is_owner, "disabled": u.disabled,
            "password_chosen": u.password_chosen}


def _active_owners(session) -> int:
    return len([u for u in session.scalars(select(User).where(User.is_owner.is_(True))) if not u.disabled])


@app.get("/people")
def list_people(session: Session = Depends(get_session)):
    return [_person_view(u) for u in session.scalars(select(User).order_by(User.name))]


@app.post("/people", status_code=201)
def create_person(body: PersonIn, request: Request, session: Session = Depends(get_session)):
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
        session.flush()
    except IntegrityError:
        session.rollback()
        raise HTTPException(409, "someone with that email already exists")
    # The fact that the creator chose the first password is recorded; the password is not.
    auditlog.append(session, actor=auditlog.actor(authz.current(request)), action="person.created",
                    subject_id=user.id, change={"person": auditlog.person_ref(user),
                                                "after": auditlog.person_snapshot(user), "password": "assigned"})
    session.commit()
    return _person_view(user)


@app.patch("/people/{user_id}")
def update_person(user_id: int, body: PersonPatch, request: Request, session: Session = Depends(get_session)):
    user = _get(session, User, user_id)
    losing_owner = (body.is_owner is False or body.disabled is True) and user.is_owner and not user.disabled
    if losing_owner and _active_owners(session) <= 1:
        raise HTTPException(422, "this is the last active owner; make someone else an owner first")
    if body.password is not None:
        # Whoever can set a password can sign in as that person and register a key in their
        # name. People change their own (POST /auth/password); an operator with access to the
        # server resets a forgotten one there.
        raise HTTPException(422, "people change their own password; to reset a forgotten one, run "
                                 "python -m app.people set-password on the server")
    who, ref = auditlog.actor(authz.current(request)), auditlog.person_ref(user)

    def audit(action: str, field: str, old, new) -> None:
        auditlog.append(session, actor=who, action=action, subject_id=user.id,
                        change={"person": ref, "before": {field: old}, "after": {field: new}})
    if body.name is not None and body.name.strip() != user.name:
        audit("person.renamed", "name", user.name, body.name.strip())
        user.name = body.name.strip()
    if body.is_owner is not None and body.is_owner != user.is_owner:
        audit("person.owner", "is_owner", user.is_owner, body.is_owner)
        user.is_owner = body.is_owner
    if body.disabled is not None:
        if body.disabled != user.disabled:
            audit("person.disabled" if body.disabled else "person.enabled", "disabled", user.disabled, body.disabled)
        user.disabled = body.disabled
        if body.disabled:
            auth.end_sessions(session, user.id)
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
def set_members(eng_id: int, body: MembersIn, request: Request, session: Session = Depends(get_session)):
    """Replace who works on this engagement and in which roles."""
    _get(session, Engagement, eng_id)
    before = auditlog.members_snapshot(session, eng_id)
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
    session.flush()
    after = auditlog.members_snapshot(session, eng_id)
    if after != before:
        auditlog.append(session, actor=auditlog.actor(authz.current(request)), action="members.updated",
                        engagement_id=eng_id, change={"before": before, "after": after})
    session.commit()
    return list_members(eng_id, session)


class EngagementPatch(BaseModel):
    separation_of_duties: bool | None = None
    require_signatures: bool | None = None
    redact_evidence: bool | None = None         # off only for a lab: raw evidence is then stored as captured
    retain_until: date | None = None            # keep the content through this UTC date; null removes the date


@app.patch("/engagements/{eng_id}")
def update_engagement(eng_id: int, body: EngagementPatch, request: Request, session: Session = Depends(get_session)):
    eng = _get(session, Engagement, eng_id)
    if "retain_until" in body.model_fields_set and body.retain_until != eng.retain_until:
        if eng.content_deleted_at is not None:
            raise HTTPException(409, vault.deleted_sentence(vault.deleted_info(eng)))
        if body.retain_until is not None and body.retain_until < datetime.now(timezone.utc).date():
            raise HTTPException(422, "the retention date is in the past; to delete the content now, use "
                                     "Delete this engagement's data")
        old = eng.retain_until
        eng.retain_until = body.retain_until
        auditlog.append(session, actor=auditlog.actor(authz.current(request)), action="engagement.retention",
                        engagement_id=eng.id,
                        change={"before": {"retain_until": old.isoformat() if old else None},
                                "after": {"retain_until": eng.retain_until.isoformat() if eng.retain_until else None}})
    before = auditlog.settings_snapshot(eng)
    if body.separation_of_duties is not None:
        eng.separation_of_duties = body.separation_of_duties
    if body.require_signatures is not None:
        eng.require_signatures = body.require_signatures
    if body.redact_evidence is not None:
        eng.redact_evidence = body.redact_evidence
    after = auditlog.settings_snapshot(eng)
    if after != before:
        auditlog.append(session, actor=auditlog.actor(authz.current(request)), action="engagement.settings",
                        engagement_id=eng.id, change={"before": before, "after": after})
    session.commit()
    return {"id": eng.id, "separation_of_duties": eng.separation_of_duties,
            "require_signatures": eng.require_signatures, "redact_evidence": eng.redact_evidence,
            "retain_until": eng.retain_until.isoformat() if eng.retain_until else None,
            "content_deleted": vault.deleted_info(eng)}


# ---- retention and deleting content (D-043) -----------------------------------

def _content_status(session, eng: Engagement) -> dict:
    rows = session.scalars(select(Evidence).where(Evidence.engagement_id == eng.id)).all()
    return {"engagement": eng.name, "retain_until": eng.retain_until.isoformat() if eng.retain_until else None,
            "content_deleted": vault.deleted_info(eng),
            "encryption": vault.describe_master(),
            "evidence_entries": len(rows),
            "encrypted_summaries": sum(1 for e in rows if e.summary_enc is not None),
            "v1_summaries": sum(1 for e in rows if e.summary is not None),
            "observations": session.scalar(select(func.count()).select_from(Observation)
                                           .where(Observation.engagement_id == eng.id)) or 0,
            "endpoints": session.scalar(select(func.count()).select_from(Endpoint)
                                        .where(Endpoint.engagement_id == eng.id)) or 0,
            "leads": session.scalar(select(func.count()).select_from(Lead).where(Lead.engagement_id == eng.id)) or 0}


@app.get("/engagements/{eng_id}/content")
def content_status(eng_id: int, session: Session = Depends(get_session)):
    """What deleting this engagement's data would remove and keep, or when it was deleted."""
    return _content_status(session, _get(session, Engagement, eng_id))


class DeleteContentIn(BaseModel):
    confirm_name: str = Field(max_length=200)     # the engagement's name, typed by the owner


@app.post("/engagements/{eng_id}/content/delete")
def delete_content(eng_id: int, body: DeleteContentIn, request: Request, session: Session = Depends(get_session)):
    """Delete the engagement's key, raw evidence, summaries and recon results. Cannot be
    undone. Hashes, receipts, signatures, timestamps and the audit log remain, so reports
    still verify."""
    eng = _get(session, Engagement, eng_id)
    if eng.content_deleted_at is not None:
        raise HTTPException(409, vault.deleted_sentence(vault.deleted_info(eng)))
    if body.confirm_name != eng.name:
        raise HTTPException(422, "type the engagement's name exactly to confirm; nothing was deleted")
    res = vault.delete_content(session, eng, actor=auditlog.actor(authz.current(request)), reason="owner")
    return {**_content_status(session, eng), "removed": {k: res.get(k, 0) for k in (
        "summaries_removed", "observations", "endpoints", "leads", "inbox_entries", "import_batches",
        "blobs_removed", "plaintext_blobs_removed")}}


# ---- scope import ----------------------------------------------------------

class ScopeImportIn(BaseModel):
    csv: str = Field(min_length=1, max_length=2_000_000)
    apply: bool = False          # False: preview only
    mode: str = Field(default="merge", pattern="^(merge|replace)$")


@app.post("/engagements/{eng_id}/scope/import")
def import_scope(eng_id: int, body: ScopeImportIn, request: Request, session: Session = Depends(get_session)):
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
        before = auditlog.scope_snapshot(eng)
        eng.scope_include, eng.scope_exclude = inc, exc
        result["hosts_added"] = _apply_scope_to_assets(eng, inc, exc)
        _audit_scope(session, request, eng, before, result["hosts_added"], imported=body.mode)
        session.commit()
        result["applied"] = True
    return result


# ---- audit log ----------------------------------------------------------------

def _audit_view(session, entries) -> dict:
    problems = auditlog.verify(session)
    return {"chain": {"intact": not problems, "problems": problems, "head": auditlog.head(session)},
            "entries": [auditlog.view(e) for e in entries]}


@app.get("/engagements/{eng_id}/audit")
def engagement_audit(eng_id: int, session: Session = Depends(get_session)):
    """This engagement's administrative history, and the person events of its people."""
    _get(session, Engagement, eng_id)
    signers = {u for u in session.scalars(select(Receipt.closed_by_user).join(Lane).join(Asset)
                                          .where(Asset.engagement_id == eng_id)) if u is not None}
    return _audit_view(session, auditlog.for_engagement(session, eng_id, auditlog.people_of(session, eng_id, signers)))


@app.get("/audit")
def audit_all(session: Session = Depends(get_session)):
    """Every administrative change in this deployment, and whether the chain is intact."""
    return _audit_view(session, session.scalars(select(auditlog.AuditEntry).order_by(auditlog.AuditEntry.seq)))


# ---- evidence import (D-029) ----------------------------------------------------------
#
# A tester uploads an export file; its in-scope entries wait in the engagement's inbox,
# redacted, until a person maps them to checklist items (inbox.py). The file is sent as the
# request body, not as JSON, so a 50 MB export is not inflated by base64 on the way.

async def _upload_body(request: Request) -> bytes:
    """The request body, read up to the import limit and no further."""
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > importers.MAX_FILE_BYTES:
        raise HTTPException(413, f"the file is larger than {importers.MAX_FILE_BYTES // 1_000_000} MB; "
                                 "export fewer items")
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > importers.MAX_FILE_BYTES:
            raise HTTPException(413, f"the file is larger than {importers.MAX_FILE_BYTES // 1_000_000} MB; "
                                     "export fewer items")
        chunks.append(chunk)
    return b"".join(chunks)


@app.get("/imports/formats")
def import_formats():
    """What can be imported, the limits, and the rules that make suggestions."""
    return {"formats": [{"id": a.id, "title": a.title, "summary": a.summary, "extensions": list(a.extensions)}
                        for a in importers.registry().values()],
            "limits": {"file_bytes": importers.MAX_FILE_BYTES, "entries": importers.MAX_ENTRIES,
                       "part_bytes": importers.MAX_PART_BYTES},
            "suggestion_rules": inbox.RULE_HELP}


@app.post("/engagements/{eng_id}/imports", status_code=201)
def import_file(eng_id: int, request: Request, format: str | None = None, filename: str | None = None,
                reimport: bool = False, data: bytes = Depends(_upload_body), session: Session = Depends(get_session)):
    """Import one export file. A file with the same SHA-256 as an earlier import is refused
    with 409 and the earlier import's details; send it again with reimport=true to import it
    anyway (its rows already in the inbox count as duplicates)."""
    eng = _get(session, Engagement, eng_id)
    who = authz.current(request)
    try:
        batch = inbox.import_file(session, eng, data, fmt=format or None, filename=filename,
                                  actor=auditlog.actor(who), user_id=who.user_id, reimport=reimport)
    except vault.ContentDeleted as e:
        session.rollback()
        raise HTTPException(409, f"{e} It takes no new imports.")
    except inbox.AlreadyImported as e:
        session.rollback()
        raise HTTPException(409, {"error": "already_imported", "message": f"{e} Import it again only if you mean to; "
                                  "its rows already in the inbox will count as duplicates.",
                                  "earlier": inbox.batch_view(e.earlier)})
    except importers.ImportRefused as e:
        session.rollback()
        raise HTTPException(422, str(e))
    session.commit()
    return inbox.batch_view(batch, repeat_of=_first_imports(session, eng_id).get(batch.file_sha256))


def _first_imports(session, eng_id: int) -> dict[str, int]:
    """The first batch of each file hash in an engagement, so later ones can say they repeat it."""
    return {sha: first for sha, first in session.execute(
        select(ImportBatch.file_sha256, func.min(ImportBatch.id)).where(ImportBatch.engagement_id == eng_id)
        .group_by(ImportBatch.file_sha256)).all()}


@app.get("/engagements/{eng_id}/imports")
def list_imports(eng_id: int, session: Session = Depends(get_session)):
    _get(session, Engagement, eng_id)
    first = _first_imports(session, eng_id)
    rows = session.scalars(select(ImportBatch).where(ImportBatch.engagement_id == eng_id)
                           .order_by(ImportBatch.id.desc()).limit(200))
    return [inbox.batch_view(b, repeat_of=first.get(b.file_sha256)) for b in rows]


def _entry_of(session, eng_id: int, entry_id: int) -> InboxEntry:
    e = session.get(InboxEntry, entry_id)
    if e is None or e.engagement_id != eng_id:
        raise HTTPException(404, f"no inbox entry {entry_id} in this engagement")
    return e


@app.get("/engagements/{eng_id}/inbox")
def list_inbox(eng_id: int, state: str | None = None, host: str | None = None, method: str | None = None,
               status: str | None = None, batch: int | None = None, q: str | None = None,
               offset: int = 0, limit: int = 100, session: Session = Depends(get_session)):
    """Inbox entries, newest batch first, with filters. status: a code (404) or a class (4xx),
    or "none" for entries without a response."""
    _get(session, Engagement, eng_id)
    if state is not None and state not in inbox.STATES:
        raise HTTPException(422, f"state is one of {', '.join(inbox.STATES)}")
    query = select(InboxEntry).where(InboxEntry.engagement_id == eng_id)
    if state:
        query = query.where(InboxEntry.state == state)
    if host:
        query = query.where(InboxEntry.host == host.strip().lower())
    if method:
        query = query.where(InboxEntry.method == method.strip().upper())
    if batch is not None:
        query = query.where(InboxEntry.batch_id == batch)
    if status:
        s = status.strip().lower()
        if s == "none":
            query = query.where(InboxEntry.status.is_(None))
        elif len(s) == 3 and s[0] in "12345" and s[1:] == "xx":
            query = query.where(InboxEntry.status >= int(s[0]) * 100, InboxEntry.status < int(s[0]) * 100 + 100)
        elif s.isdigit():
            query = query.where(InboxEntry.status == int(s))
        else:
            raise HTTPException(422, "status is a code such as 404, a class such as 4xx, or none")
    if q:
        query = query.where(InboxEntry.url.contains(q.strip()[:200], autoescape=True))
    limit, offset = max(1, min(limit, 500)), max(offset, 0)
    total = session.scalar(select(func.count()).select_from(query.subquery()))
    rows = session.scalars(query.order_by(InboxEntry.batch_id.desc(), InboxEntry.row).offset(offset).limit(limit))
    counts = dict.fromkeys(inbox.STATES, 0) | dict(session.execute(
        select(InboxEntry.state, func.count()).where(InboxEntry.engagement_id == eng_id).group_by(InboxEntry.state)).all())
    hosts = sorted(session.scalars(select(InboxEntry.host).where(InboxEntry.engagement_id == eng_id).distinct()))
    return {"total": total, "offset": offset, "limit": limit, "counts": counts, "hosts": hosts,
            "entries": [inbox.entry_view(e) for e in rows]}


@app.get("/engagements/{eng_id}/inbox/{entry_id}")
def get_inbox_entry(eng_id: int, entry_id: int, session: Session = Depends(get_session)):
    """One entry, every lane of the pack on its host (open ones, and the others with whether
    mapping can open them), and suggested items."""
    e = _entry_of(session, eng_id, entry_id)
    eng = _get(session, Engagement, eng_id)
    targets = inbox.target_lanes(session, eng, e.host)
    asset = inbox.asset_on(session, eng_id, e.host)
    return {**inbox.entry_view(e), "targets": targets, "suggestions": inbox.suggest(e, targets),
            "asset": {"id": asset.id, "in_scope": asset.in_scope} if asset else None}


@app.get("/engagements/{eng_id}/inbox/{entry_id}/raw/{part}")
def get_inbox_raw(eng_id: int, entry_id: int, part: str, session: Session = Depends(get_session)):
    """The stored (redacted) request, response, or the record that evidence commits to."""
    e = _entry_of(session, eng_id, entry_id)
    digest = {"request": e.request_sha256, "response": e.response_sha256, "record": e.record_sha256}.get(part, "")
    if part not in ("request", "response", "record"):
        raise HTTPException(404, "part is request, response or record")
    if not digest:
        raise HTTPException(404, f"the export had no raw {part} for this entry")
    eng = _get(session, Engagement, eng_id)
    if eng.content_deleted_at is not None:
        raise HTTPException(410, vault.deleted_sentence(vault.deleted_info(eng)))
    data = blobs.get(digest, engagement_id=eng_id)
    if data is None:
        raise HTTPException(404, "the bytes for this hash are not in the blob store, or do not match it")
    return Response(data, media_type="text/plain; charset=utf-8",
                    headers={"Content-Security-Policy": "default-src 'none'; sandbox",
                             "X-Content-Type-Options": "nosniff"})


class MapTarget(BaseModel):
    """An item on an open lane (lane_id), or on the lane of this role on the entries' host
    (role), which mapping opens if it is not open yet."""
    lane_id: int | None = None
    role: str | None = Field(default=None, max_length=32)
    item_idx: int


class MapIn(BaseModel):
    entry_ids: list[int] = Field(min_length=1, max_length=inbox.MAX_MAP_ENTRIES)
    targets: list[MapTarget] = Field(min_length=1, max_length=inbox.MAX_MAP_TARGETS)
    note: str | None = Field(default=None, max_length=2_000)
    # Off unless asked: an imported exchange is often part of a test, not all of it, and
    # "done" says the test was performed. The lane shows items waiting to be marked done.
    mark_done: bool = False


class EntryIdsIn(BaseModel):
    entry_ids: list[int] = Field(min_length=1, max_length=inbox.MAX_MAP_ENTRIES)
    reason: str | None = Field(default=None, max_length=500)


@app.post("/engagements/{eng_id}/inbox/map")
def map_inbox(eng_id: int, body: MapIn, request: Request, session: Session = Depends(get_session)):
    """Map entries to checklist items: one evidence entry per entry and item, source import:<tool>.
    A target given by role opens that lane on the entries' host first if needed."""
    eng = _get(session, Engagement, eng_id)
    who = authz.current(request)
    if any((t.lane_id is None) == (t.role is None) for t in body.targets):
        raise HTTPException(422, "each item names either its lane_id or its lane's role, not both")
    try:
        done = inbox.map_entries(session, eng, body.entry_ids,
                                 [(t.lane_id, t.role, t.item_idx) for t in body.targets],
                                 note=body.note, user_id=who.user_id, mark_done=body.mark_done,
                                 user_name=auditlog.actor_label(auditlog.actor(who)))
    except vault.ContentDeleted as e:
        session.rollback()
        raise HTTPException(409, f"{e} It takes no new evidence.")
    except inbox.InboxError as e:
        session.rollback()
        raise HTTPException(422, str(e))
    session.commit()
    return {**done, "entries": [inbox.entry_view(_entry_of(session, eng_id, i)) for i in dict.fromkeys(body.entry_ids)]}


@app.post("/engagements/{eng_id}/inbox/dismiss")
def dismiss_inbox(eng_id: int, body: EntryIdsIn, request: Request, session: Session = Depends(get_session)):
    """Set entries aside. They stay in the inbox as dismissed, and the audit log records it."""
    eng = _get(session, Engagement, eng_id)
    who = authz.current(request)
    try:
        rows = inbox.dismiss(session, eng, body.entry_ids, reason=body.reason, actor=auditlog.actor(who),
                             user_id=who.user_id)
    except inbox.InboxError as e:
        session.rollback()
        raise HTTPException(422, str(e))
    session.commit()
    return {"entries": [inbox.entry_view(e) for e in rows]}


@app.post("/engagements/{eng_id}/inbox/restore")
def restore_inbox(eng_id: int, body: EntryIdsIn, request: Request, session: Session = Depends(get_session)):
    eng = _get(session, Engagement, eng_id)
    try:
        rows = inbox.restore(session, eng, body.entry_ids, actor=auditlog.actor(authz.current(request)))
    except inbox.InboxError as e:
        session.rollback()
        raise HTTPException(422, str(e))
    session.commit()
    return {"entries": [inbox.entry_view(e) for e in rows]}


# ---- API documentation and the offline verifier ------------------------------------------
#
# Both are ordinary routes so the permission table applies (authz.RULES: signed_in). The
# verifier is not secret (AGPL-3.0, and attackledger.com publishes the same script); it is
# served here so a signed-in client or auditor can download it from the Report and Verify
# tabs instead of from a repository they cannot read. The independent copy stays the one on
# attackledger.com: a reader who does not trust this server compares the two hashes.

VERIFIER_DIR = packs.ITEMS_BASE / "tools"
VERIFIER_PAGE = "https://attackledger.com/verify"
VERIFIER_PUBLIC_COPY = "https://attackledger.com/verify_report.py"
_NOSNIFF = {"X-Content-Type-Options": "nosniff"}


@app.get("/openapi.json", include_in_schema=False)
def openapi_schema():
    return app.openapi()


@app.get("/docs", include_in_schema=False)
def api_docs():
    # Relative, so it resolves under whatever prefix the web server forwards (/api/).
    return get_swagger_ui_html(openapi_url="openapi.json", title="AttackLedger API")


def _verifier_files() -> tuple[bytes, dict[str, bytes]]:
    """The script and the trusted roots next to it (tools/tsa-roots/*.pem), as shipped."""
    script = VERIFIER_DIR / "verify_report.py"
    if not script.is_file():
        raise HTTPException(404, "the verifier is not part of this install; get it from " + VERIFIER_PUBLIC_COPY)
    roots = {p.name: p.read_bytes() for p in sorted((VERIFIER_DIR / "tsa-roots").glob("*.pem"))}
    return script.read_bytes(), roots


def _cert_fingerprint(pem: bytes) -> str | None:
    """SHA-256 of the certificate (DER), as tools/tsa-roots/README.md and root stores show it."""
    text = pem.decode("ascii", "replace")
    if "-----BEGIN CERTIFICATE-----" not in text:
        return None
    body = text.split("-----BEGIN CERTIFICATE-----", 1)[1].split("-----END CERTIFICATE-----", 1)[0]
    try:
        return hashlib.sha256(base64.b64decode("".join(body.split()), validate=True)).hexdigest().upper()
    except (binascii.Error, ValueError):
        return None


def _verifier_zip(script: bytes, roots: dict[str, bytes]) -> bytes:
    """One folder with the script and tsa-roots/ beside it, as the report's instructions ask.
    Fixed times and order, so the same files always give the same archive and hash."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in [("verify_report.py", script)] + [(f"tsa-roots/{n}", b) for n, b in roots.items()]:
            info = zipfile.ZipInfo(f"attackledger-verifier/{name}", date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
    return buf.getvalue()


@app.get("/verifier")
def verifier_index():
    """What the verifier downloads are, with their SHA-256, and where the independent copy is."""
    script, roots = _verifier_files()
    bundle = _verifier_zip(script, roots)
    sha = lambda b: hashlib.sha256(b).hexdigest()  # noqa: E731
    return {"script": {"name": "verify_report.py", "path": "/verifier/verify_report.py", "sha256": sha(script),
                       "bytes": len(script)},
            "tsa_roots": [{"name": n, "path": f"/verifier/tsa-roots/{n}", "sha256": sha(b), "bytes": len(b),
                           "certificate_sha256": _cert_fingerprint(b)} for n, b in roots.items()],
            "bundle": {"name": "attackledger-verifier.zip", "path": "/verifier/attackledger-verifier.zip",
                       "sha256": sha(bundle), "bytes": len(bundle)},
            "page": VERIFIER_PAGE, "public_copy": VERIFIER_PUBLIC_COPY, "license": "AGPL-3.0-only",
            "run": "python3 -I verify_report.py report.html"}


def _download(data: bytes, media_type: str, name: str) -> Response:
    return Response(data, media_type=media_type,
                    headers={"Content-Disposition": f'attachment; filename="{name}"', **_NOSNIFF})


@app.get("/verifier/verify_report.py")
def verifier_script():
    return _download(_verifier_files()[0], "text/x-python; charset=utf-8", "verify_report.py")


@app.get("/verifier/tsa-roots/{name}")
def verifier_root(name: str):
    roots = _verifier_files()[1]
    if name not in roots:               # only the files shipped in tsa-roots/, by exact name
        raise HTTPException(404, f"no timestamp root named {name!r}; the roots are {', '.join(roots) or 'none'}")
    return _download(roots[name], "application/x-pem-file", name)


@app.get("/verifier/attackledger-verifier.zip")
def verifier_bundle():
    return _download(_verifier_zip(*_verifier_files()), "application/zip", "attackledger-verifier.zip")
