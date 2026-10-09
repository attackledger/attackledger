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


# ---- control mappings: strength, notes and the review statement (docs/CONTROLS.md) ----

def test_bare_control_id_means_supporting_and_strength_is_kept():
    p = packs._parse_pack({"id": "p", "lanes": [lane("a", controls=["C-1", {"id": "C-2", "strength": "partial"}])]}, KNOWN)
    item = p.lane("a").items[0]
    assert item.controls == ("C-1", "C-2")
    assert item.strengths == {"C-1": "supporting", "C-2": "partial"}
    assert p.control_strengths == {"C-1": "supporting", "C-2": "partial"}


@pytest.mark.parametrize("mapping, error", [
    ({"id": "C-1", "strength": "strong"}, "strength of C-1 is one of"),
    ({"id": "C-1", "strength": "partial", "why": "x"}, "a control mapping is an id or"),
    ({"strength": "partial"}, "a control mapping is an id or"),
    (["C-1"], "a control mapping is an id or"),
])
def test_bad_control_mapping_fails_closed(mapping, error):
    with pytest.raises(packs.PackError, match=error):
        packs._parse_pack({"id": "p", "lanes": [lane("a", controls=[mapping])]}, KNOWN)


def test_control_mapped_twice_in_one_list_fails_closed():
    with pytest.raises(packs.PackError, match="mapped twice"):
        packs._parse_pack({"id": "p", "lanes": [lane("a", controls=["C-1", {"id": "C-1", "strength": "partial"}])]},
                          KNOWN)


def test_one_strength_per_control_in_a_pack():
    """A control row states one claim, so two lanes may not map it at different strengths."""
    lanes = [lane("a", controls=[{"id": "C-1", "strength": "partial"}]), lane("b", controls=["C-1"])]
    with pytest.raises(packs.PackError, match="C-1 is mapped as both partial and supporting"):
        packs._parse_pack({"id": "p", "lanes": lanes}, KNOWN)
    # An item may not quietly raise its lane's claim either.
    items = [{"id": "x", "text": "t"}, {"id": "y", "text": "t", "controls": [{"id": "C-1", "strength": "full"}]}]
    with pytest.raises(packs.PackError, match="mapped as both"):
        packs._parse_pack({"id": "p", "lanes": [lane("a", items=items)]}, KNOWN)


def test_catalog_controls_take_a_title_or_title_and_note():
    cat = packs._parse_catalog({"frameworks": {"f": {"name": "F", "controls": {
        "C-1": "Plain title", "C-2": {"title": "With note", "note": "Only  when\n  it holds."}}}}})
    assert cat.controls["C-1"]["text"] == "Plain title" and cat.controls["C-1"]["note"] == ""
    assert cat.controls["C-2"]["note"] == "Only when it holds."
    for bad in ({"note": "no title"}, {"title": "t", "status": "compliant"}, 3):
        with pytest.raises(packs.PackError, match="expected a title"):
            packs._parse_catalog({"frameworks": {"f": {"name": "F", "controls": {"C-1": bad}}}})
    with pytest.raises(packs.PackError, match="strengths must describe exactly"):
        packs._parse_catalog({"strengths": {"full": "x", "strong": "y"}, "frameworks": {}})


def test_shipped_catalog_carries_the_review_statement_and_sources():
    cat = packs.catalog()
    assert cat.reviewed["statement"] == (
        "Reviewed against public sources by Claude on 2026-10-10; not reviewed by a qualified assessor "
        "(QSA, ISO lead auditor or DORA TLPT authority).")
    assert cat.reviewed["date"] == "2026-10-10"
    frameworks = {fw for c in cat.controls.values() for fw in [c["framework"]]}
    sourced = {s["framework"] for s in cat.reviewed["sources"]}
    assert frameworks <= sourced
    assert all(s["url"].startswith("https://") and s["version"] and s["checked"] for s in cat.reviewed["sources"])
    assert list(cat.strengths) == list(packs.STRENGTHS)


def test_shipped_mappings_do_not_overstate():
    """The review's conclusions, held as tests so a later edit cannot quietly undo them."""
    cat, all_packs = packs.catalog(), packs.all_packs()
    # Withdrawn: an ASV scan (11.3.2), a WAF requirement superseded in 2025 (6.4.1),
    # segmentation testing (11.4.5) and TLPT (DORA Articles 26 and 27) are not what these lanes do.
    for cid in ("PCI-11.3.2", "PCI-6.4.1", "PCI-11.4.5", "DORA-ART26", "DORA-ART27"):
        assert cid not in cat.controls
    for p in all_packs.values():
        assert "full" not in p.control_strengths.values(), p.id
        assert set(p.control_strengths) <= set(cat.controls)
    bb, wstg = all_packs["bug-bounty"], all_packs["web-pentest-wstg"]
    # A bug bounty is not a PCI penetration test and not release acceptance testing.
    assert bb.control_strengths["PCI-11.4.3"] == "supporting"
    assert "PCI-11.4.1" not in bb.control_strengths and "ISO-A.8.29" not in bb.control_strengths
    assert bb.lane("mapper").controls == ()
    assert wstg.control_strengths["PCI-11.4.3"] == "partial" and wstg.control_strengths["ISO-A.8.8"] == "partial"
    # Conditional mappings say when they hold.
    for cid in ("PCI-4.2.1", "PCI-11.4.3", "ISO-A.8.29", "DORA-ART25"):
        assert cat.controls[cid]["note"], cid
    # Every control the catalog lists is used by some pack: nothing is shown that no test evidences.
    assert set(cat.controls) == {c for p in all_packs.values() for c in p.control_strengths}
