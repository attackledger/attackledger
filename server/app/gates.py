"""Fail-closed gates.

A lane is CLOSED only when its latest receipt matches the current manifest
(items + evidence). Any later change makes the receipt stale and the lane is
treated as open again. "Done" is computed, never stored.
"""
import hashlib
import json
from enum import Enum

from .models import ItemState, Lane, MODEL_GATED_ROLES, Role


class LaneStatus(str, Enum):
    open = "open"
    closed = "closed"
    stale = "stale"  # had a receipt, but the ledger changed afterwards


class GateError(Exception):
    pass


def manifest(lane: Lane) -> dict:
    return {
        "lane": lane.id,
        "role": lane.role.value,
        "host": lane.asset.host,
        "items": [
            {"idx": i.idx, "state": i.state.value, "na_reason": i.na_reason}
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


def check_can_open(asset, role: Role) -> None:
    if role not in MODEL_GATED_ROLES:
        return
    mapper = next((l for l in asset.lanes if l.role == Role.mapper), None)
    if mapper is None or lane_status(mapper) != LaneStatus.closed:
        raise GateError(
            f"{role.value} lane needs a closed mapper lane (application model) on {asset.host}"
        )
