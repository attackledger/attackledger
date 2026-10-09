"""Fail-closed gates.

A lane is CLOSED only when its latest receipt matches the current manifest
(items + evidence). Any later change makes the receipt stale and the lane is
treated as open again. "Done" is computed, never stored.
"""
import hashlib
import json
from enum import Enum

from .models import ChecklistItem, ItemState, Lane
from .packs import LaneDef, PackError


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
    if lane.receipts[-1].manifest_sha256 == manifest_hash(lane) and not unresolved(lane):
        return LaneStatus.closed
    return LaneStatus.stale


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
