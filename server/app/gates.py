"""Fail-closed gates.

A lane is CLOSED only when its latest receipt matches the current manifest
(items + evidence) and the lane has not changed since the receipt was issued.
"Done" is computed, never stored.

A change to a lane after its receipt voids the receipt for good, even if a later change
puts the lane back as it was (an item reopened, then marked done again): the auditor
must see the gap, and only a new signature closes the lane again. The void is an entry
in the audit log (lane.receipt_voided, naming the receipt), so it is hash-chained,
goes into the report's change history and cannot be taken back by editing a row.
"""
import hashlib
import json
from enum import Enum

from sqlalchemy import event, select
from sqlalchemy.orm import Session, object_session

from . import auditlog
from .models import AuditEntry, ChecklistItem, ItemState, Lane, Receipt
from .packs import LaneDef, PackError

VOID_ACTION = "lane.receipt_voided"
ITEM_ACTION = "lane.item_updated"
_CACHE = "voided_receipts"


class LaneStatus(str, Enum):
    open = "open"
    closed = "closed"
    stale = "stale"  # had a receipt, but the ledger changed afterwards


class GateError(Exception):
    pass


def manifest(lane: Lane) -> dict:
    return {
        "lane": lane.id,
        "role": lane.role,
        "host": lane.asset.host,
        "items": [
            {"idx": i.idx, "key": i.item_key, "state": i.state.value, "na_reason": i.na_reason}
            for i in lane.items
        ],
        "evidence": [
            {"id": e.id, "item": e.item_id, "kind": e.kind, "sha256": e.sha256}
            for e in lane.evidence
        ],
    }


def manifest_hash(lane: Lane) -> str:
    blob = json.dumps(manifest(lane), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def unresolved(lane: Lane) -> list[str]:
    problems = []
    with_evidence = {e.item_id for e in lane.evidence if e.item_id is not None}
    for item in lane.items:
        if item.state == ItemState.open:
            problems.append(f"item {item.idx} still open: {item.text}")
        elif item.state == ItemState.done and item.id not in with_evidence:
            problems.append(f"item {item.idx} marked done without evidence")
        elif item.state == ItemState.na and not (item.na_reason or "").strip():
            problems.append(f"item {item.idx} marked N/A without a reason")
    return problems


def lane_status(lane: Lane) -> LaneStatus:
    if not lane.receipts:
        return LaneStatus.open
    rc = lane.receipts[-1]
    if rc.manifest_sha256 == manifest_hash(lane) and not unresolved(lane) and not is_voided(rc):
        return LaneStatus.closed
    return LaneStatus.stale


# ---- voided receipts ---------------------------------------------------------------------

def _voided(session, eng_id: int) -> dict[int, dict]:
    """The receipts of an engagement that a change voided, by receipt id, with the audit entry
    that says so. Read once per transaction; void_receipt adds to it."""
    cache = session.info.setdefault(_CACHE, {})
    if eng_id not in cache:
        with session.no_autoflush:
            rows = session.scalars(select(AuditEntry).where(AuditEntry.engagement_id == eng_id,
                                                            AuditEntry.action == VOID_ACTION))
            cache[eng_id] = {json.loads(e.change)["receipt"]["id"]: _void_view(e) for e in rows}
    return cache[eng_id]


def _void_view(e: AuditEntry) -> dict:
    rec = auditlog.record(e)
    return {"at": e.at, "by": auditlog.actor_label(rec["actor"]), "cause": rec["change"].get("cause") or {},
            "text": auditlog.describe(rec)}


@event.listens_for(Session, "after_commit")
@event.listens_for(Session, "after_rollback")
def _forget_voided(session) -> None:
    session.info.pop(_CACHE, None)


def void_of(rc: Receipt | None) -> dict | None:
    """When and why a receipt was voided ({at, by, cause, text}), or None if it was not."""
    session = object_session(rc) if rc is not None else None
    if session is None or rc.id is None:
        return None
    return _voided(session, rc.lane.asset.engagement_id).get(rc.id)


def is_voided(rc: Receipt) -> bool:
    return void_of(rc) is not None


def _lane_ref(lane: Lane) -> dict:
    return {"id": lane.id, "host": lane.asset.host, "role": lane.role}


def _receipt_ref(rc: Receipt) -> dict:
    # The id is the server's; a report has none, so a reader matches the receipt by lane,
    # manifest hash and issue time.
    issued = rc.created_at.isoformat() if rc.created_at else None
    return {"id": rc.id, "manifest_sha256": rc.manifest_sha256, "closed_by": rc.closed_by, "issued_at": issued}


def void_receipt(session, lane: Lane, *, actor: dict, cause: dict) -> bool:
    """Record that a change to the lane voids its latest receipt, unless it was voided already.
    Call it after a change that altered the lane (an item's state or reason, new evidence).
    Returns whether a receipt was voided. The caller commits, with the change."""
    if not lane.receipts:
        return False
    rc = lane.receipts[-1]
    if is_voided(rc):
        return False
    e = auditlog.append(session, actor=actor, action=VOID_ACTION, engagement_id=lane.asset.engagement_id,
                        change={"lane": _lane_ref(lane), "receipt": _receipt_ref(rc), "cause": cause})
    _voided(session, lane.asset.engagement_id)[rc.id] = _void_view(e)
    return True


def record_change(session, lane: Lane, *, actor: dict, cause: dict) -> None:
    """After a person changed a lane that was receipted at least once: void its latest
    receipt if that has not happened yet, or else record the item change in the audit log,
    so the history shows everything done to the lane between its receipts."""
    if not lane.receipts:
        return
    if void_receipt(session, lane, actor=actor, cause=cause):
        return
    if cause.get("kind") == "item":
        auditlog.append(session, actor=actor, action=ITEM_ACTION, engagement_id=lane.asset.engagement_id,
                        change={"lane": _lane_ref(lane), "receipt": _receipt_ref(lane.receipts[-1]), "cause": cause})


def waiting_on(asset, lane_def: LaneDef) -> list[str]:
    """The lanes this one needs that are not receipted on the same asset, in pack order."""
    by_key = {l.role: l for l in asset.lanes}
    return [n for n in lane_def.needs if n not in by_key or lane_status(by_key[n]) != LaneStatus.closed]


def check_can_open(asset, lane_def: LaneDef, pack) -> None:
    """Every lane opens at once, unless the pack's needs gate opening too (needs_gate: open)."""
    missing = waiting_on(asset, lane_def) if pack.needs_gate == "open" else []
    if missing:
        names = ", ".join(pack.lane(n).name for n in missing)
        raise GateError(f"{lane_def.name} needs a receipted {names} lane on {asset.host}")


def check_can_close(lane: Lane, pack) -> None:
    """A lane is signed only after every lane it needs is receipted on the same asset. Its
    work and evidence can come first; the receipt says the dependency was in place."""
    if lane.role not in pack.lane_index:
        return
    missing = waiting_on(lane.asset, pack.lane(lane.role))
    if missing:
        names = ", ".join(pack.lane(n).name for n in missing)
        raise GateError(f"{pack.lane(lane.role).name} can be signed only after {names} on {lane.asset.host} "
                        "is receipted")


def open_lane(session, asset, pack, role: str) -> Lane:
    """Open a lane of the pack on an in-scope asset, with the pack's items. Raises GateError
    when it cannot open. The caller checks the tester role and commits."""
    if not asset.in_scope:
        raise GateError(f"{asset.host} is out of scope")
    try:
        lane_def = pack.lane(role)
    except PackError as e:
        raise GateError(str(e)) from None
    check_can_open(asset, lane_def, pack)
    lane = Lane(asset=asset, role=lane_def.key)
    lane.items = [ChecklistItem(idx=n, item_key=it.id, text=it.text, controls=list(it.controls))
                  for n, it in enumerate(lane_def.items, start=1)]
    session.add(lane)
    return lane


def awaiting_done(lane: Lane) -> int:
    """Items that have evidence but are still open: someone has to mark them done (or N/A)."""
    with_evidence = {e.item_id for e in lane.evidence if e.item_id is not None}
    return sum(1 for i in lane.items if i.state == ItemState.open and i.id in with_evidence)
