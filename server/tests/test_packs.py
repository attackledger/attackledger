import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from app import packs

KNOWN = {"C-1": {}, "C-2": {}}


def lane(key, needs=(), controls=("C-1",), items=None):
    return {"key": key, "name": key.title(), "needs": list(needs), "controls": list(controls),
            "items": items or [{"id": f"{key}-1", "text": "do it"}]}


def test_shipped_packs_load_and_reference_known_controls():
    all_packs = packs.all_packs()
    assert {"bug-bounty", "web-pentest-wstg"} <= set(all_packs)
    wstg = all_packs["web-pentest-wstg"]
    assert sum(len(l.items) for l in wstg.lanes) == 97
    bb = all_packs["bug-bounty"]
    assert bb.lane("authz").needs == ("mapper",) and bb.recon_lane == "recon"


def test_unknown_control_fails_closed():
    with pytest.raises(packs.PackError, match="unknown control"):
        packs._parse_pack({"id": "p", "lanes": [lane("a", controls=["NOPE"])]}, KNOWN)


def test_dependency_cycle_fails_closed():
    with pytest.raises(packs.PackError, match="cycle"):
        packs._parse_pack({"id": "p", "lanes": [lane("a", needs=["b"]), lane("b", needs=["a"])]}, KNOWN)


def test_lane_without_items_fails_closed():
    bad = lane("a")
    bad["items"] = []
    with pytest.raises(packs.PackError, match="no items"):
        packs._parse_pack({"id": "p", "lanes": [bad]}, KNOWN)


def test_items_from_cannot_escape_project():
    with pytest.raises(packs.PackError, match="inside the project"):
        packs._parse_pack({"id": "p", "lanes": [{"key": "a", "items_from": "../../etc/passwd"}]}, KNOWN)


def test_item_controls_merge_lane_controls():
    p = packs._parse_pack({"id": "p", "lanes": [lane("a", items=[
        {"id": "x", "text": "t", "controls": ["C-2"]}])]}, KNOWN)
    assert p.lane("a").items[0].controls == ("C-1", "C-2")
