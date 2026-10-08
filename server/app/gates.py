"""Fail-closed gates.

A lane is CLOSED only when its latest receipt matches the current manifest
(items + evidence). Any later change makes the receipt stale and the lane is
treated as open again. "Done" is computed, never stored.
"""
import hashlib
import json
from enum import Enum

from .models import ItemState, Lane
from .packs import LaneDef


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


def check_can_open(asset, lane_def: LaneDef, pack) -> None:
    """A lane opens only when every lane it needs is receipted on the same asset."""
    by_key = {l.role: l for l in asset.lanes}
    missing = [n for n in lane_def.needs
               if n not in by_key or lane_status(by_key[n]) != LaneStatus.closed]
    if missing:
        names = ", ".join(pack.lane(n).name for n in missing)
        raise GateError(f"{lane_def.name} needs a receipted {names} lane on {asset.host}")
