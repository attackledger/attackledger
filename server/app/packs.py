"""Methodology packs: lanes, their items and the controls each item evidences.

Packs are data (packs/*.yaml). Loading is strict and fails closed: an unknown
control id, an unknown evidence strength, a control mapped at two strengths in one
pack, a dependency cycle or a lane without items stops the load.
"""
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

ITEMS_BASE = Path(os.environ.get("ATTACKLEDGER_HOME", Path(__file__).resolve().parents[2]))
PACK_DIR = Path(os.environ.get("ATTACKLEDGER_PACKS", ITEMS_BASE / "packs"))

_MD_ITEM = re.compile(r"^\s*- \[ \]\s+(.+?)\s*$")
_KEY = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
NEEDS_GATES = ("close", "open")
# How strongly an item's result evidences a control, strongest first (docs/CONTROLS.md).
# A mapping written as a bare id is "supporting", so an unreviewed pack never overstates.
STRENGTHS = ("full", "partial", "supporting")
DEFAULT_STRENGTH = "supporting"


class PackError(ValueError):
    pass


@dataclass(frozen=True)
class Item:
    id: str
    text: str
    controls: tuple[str, ...]
    # Control id -> strength, for every id in controls.
    strengths: dict = field(default_factory=dict, compare=False, hash=False)


@dataclass(frozen=True)
class LaneDef:
    key: str
    name: str
    needs: tuple[str, ...]
    items: tuple[Item, ...]
    controls: tuple[str, ...]


@dataclass(frozen=True)
class Pack:
    id: str
    name: str
    version: str
    description: str
    engagement_types: tuple[str, ...]
    lanes: tuple[LaneDef, ...]
    recon_lane: str  # lane that receives recon job evidence
    # When a lane's "needs" apply. "close" (the default): every lane opens and is worked at
    # once, as pentest teams work in parallel, and a lane is signed only after the lanes it
    # needs are receipted. "open": a lane does not even open before then, for methods that
    # depend on an earlier lane's output (the bug bounty pack's application model).
    needs_gate: str = "close"
    lane_index: dict = field(default_factory=dict, compare=False, hash=False)
    # Control id -> the one strength this pack's items evidence it at.
    control_strengths: dict = field(default_factory=dict, compare=False, hash=False)

    def lane(self, key: str) -> LaneDef:
        try:
            return self.lane_index[key]
        except KeyError:
            raise PackError(f"pack {self.id} has no lane '{key}'") from None


@dataclass(frozen=True)
class Catalog:
    controls: dict  # id -> {"id", "text", "note", "framework", "framework_name"}
    # Who reviewed the mappings, when and against which sources; shown with every control view.
    reviewed: dict = field(default_factory=dict)
    strengths: dict = field(default_factory=dict)  # strength -> what it means


def _load_yaml(path: Path) -> dict:
    with path.open() as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise PackError(f"{path.name}: expected a mapping")
    return data


@lru_cache(maxsize=1)
def catalog() -> Catalog:
    return _parse_catalog(_load_yaml(PACK_DIR / "controls.yaml"))


def _parse_catalog(data: dict) -> Catalog:
    controls = {}
    for fw_id, fw in data.get("frameworks", {}).items():
        for cid, spec in fw.get("controls", {}).items():
            if cid in controls:
                raise PackError(f"duplicate control id {cid}")
            # A control is a short title, or {title, note} when the mapping holds only under a condition.
            if isinstance(spec, str):
                text, note = spec, ""
            elif isinstance(spec, dict) and isinstance(spec.get("title"), str) and set(spec) <= {"title", "note"}:
                text, note = spec["title"], " ".join(str(spec.get("note", "")).split())
            else:
                raise PackError(f"control {cid}: expected a title or {{title, note}}")
            controls[cid] = {"id": cid, "text": text, "note": note, "framework": fw_id, "framework_name": fw["name"]}
    strengths = {k: " ".join(str(v).split()) for k, v in (data.get("strengths") or {}).items()}
    if strengths and set(strengths) != set(STRENGTHS):
        raise PackError(f"strengths must describe exactly {', '.join(STRENGTHS)}")
    strengths = {k: strengths[k] for k in STRENGTHS if k in strengths}  # strongest first
    reviewed = dict(data.get("reviewed") or {})
    if "statement" in reviewed:
        reviewed["statement"] = " ".join(str(reviewed["statement"]).split())
    return Catalog(controls=controls, reviewed=reviewed, strengths=strengths)


def _mappings(raw, where: str) -> dict[str, str]:
    """Control mappings as {id: strength}. Each entry is an id or {id, strength}."""
    out: dict[str, str] = {}
    for m in raw or []:
        if isinstance(m, str):
            cid, strength = m, DEFAULT_STRENGTH
        elif isinstance(m, dict) and isinstance(m.get("id"), str) and set(m) <= {"id", "strength"}:
            cid, strength = m["id"], m.get("strength", DEFAULT_STRENGTH)
        else:
            raise PackError(f"{where}: a control mapping is an id or {{id, strength}}, not {m!r}")
        if strength not in STRENGTHS:
            raise PackError(f"{where}: strength of {cid} is one of {', '.join(STRENGTHS)}, not {strength!r}")
        if cid in out:
            raise PackError(f"{where}: control {cid} is mapped twice")
        out[cid] = strength
    return out


def _items_from_md(rel: str, prefix: str) -> list[Item]:
    path = (ITEMS_BASE / rel).resolve()
    if ITEMS_BASE.resolve() not in path.parents:
        raise PackError(f"items_from must stay inside the project: {rel}")
    if not path.is_file():
        raise PackError(f"items_from file not found: {rel}")
    texts = [m.group(1) for line in path.read_text().splitlines() if (m := _MD_ITEM.match(line))]
    return [Item(id=f"{prefix}-{i:02d}", text=t, controls=()) for i, t in enumerate(texts, start=1)]


def _parse_pack(data: dict, known_controls: dict) -> Pack:
    pid = data.get("id", "")
    if not _KEY.match(pid):
        raise PackError(f"invalid pack id: {pid!r}")
    lanes = []
    control_strengths: dict[str, str] = {}
    for raw in data.get("lanes", []):
        key = raw.get("key", "")
        if not _KEY.match(key):
            raise PackError(f"{pid}: invalid lane key {key!r}")
        lane_map = _mappings(raw.get("controls"), f"{pid}/{key}")
        lane_controls = tuple(lane_map)
        if "items_from" in raw:
            items = [(i, {}) for i in _items_from_md(raw["items_from"], f"{pid.upper()}-{key.upper()}")]
        else:
            items = [(Item(id=str(i["id"]), text=str(i["text"]), controls=()),
                      _mappings(i.get("controls"), f"{pid}/{key}/{i.get('id')}"))
                     for i in raw.get("items", [])]
        if not items:
            raise PackError(f"{pid}/{key}: lane has no items")
        # An item evidences its lane's controls plus any of its own.
        items = [Item(id=i.id, text=i.text, controls=tuple(dict.fromkeys(lane_controls + tuple(own))),
                      strengths={**lane_map, **own})
                 for i, own in items]
        for c in {c for i in items for c in i.controls}:
            if c not in known_controls:
                raise PackError(f"{pid}/{key}: unknown control id {c}")
        # One strength per control in a pack, so a control row states a single claim.
        for i in items:
            for c, strength in i.strengths.items():
                if control_strengths.setdefault(c, strength) != strength:
                    raise PackError(f"{pid}: control {c} is mapped as both {control_strengths[c]} and {strength}; "
                                    "use one strength per control in a pack")
        if len({i.id for i in items}) != len(items):
            raise PackError(f"{pid}/{key}: duplicate item ids")
        lanes.append(LaneDef(key=key, name=raw.get("name", key), needs=tuple(raw.get("needs", [])),
                             items=tuple(items), controls=lane_controls))

    index = {l.key: l for l in lanes}
    if len(index) != len(lanes):
        raise PackError(f"{pid}: duplicate lane keys")
    for l in lanes:
        for n in l.needs:
            if n not in index:
                raise PackError(f"{pid}/{l.key}: needs unknown lane {n}")
    _check_acyclic(pid, index)
    recon_lane = data.get("recon_lane", lanes[0].key if lanes else "")
    if recon_lane not in index:
        raise PackError(f"{pid}: recon_lane {recon_lane!r} is not a lane")
    needs_gate = data.get("needs_gate", "close")
    if needs_gate not in NEEDS_GATES:
        raise PackError(f"{pid}: needs_gate is one of {', '.join(NEEDS_GATES)}, not {needs_gate!r}")
    return Pack(recon_lane=recon_lane, needs_gate=needs_gate, id=pid, name=data.get("name", pid), version=str(data.get("version", "0")),
                description=" ".join(str(data.get("description", "")).split()),
                engagement_types=tuple(data.get("engagement_types", [])),
                lanes=tuple(lanes), lane_index=index, control_strengths=control_strengths)


def _check_acyclic(pid: str, index: dict) -> None:
    state: dict[str, int] = {}

    def visit(k: str) -> None:
        if state.get(k) == 1:
            raise PackError(f"{pid}: dependency cycle at lane {k}")
        if state.get(k) == 2:
            return
        state[k] = 1
        for n in index[k].needs:
            visit(n)
        state[k] = 2

    for k in index:
        visit(k)


@lru_cache(maxsize=1)
def all_packs() -> dict[str, Pack]:
    known = catalog().controls
    packs = {}
    for path in sorted(PACK_DIR.glob("*.yaml")):
        if path.name == "controls.yaml":
            continue
        pack = _parse_pack(_load_yaml(path), known)
        if pack.id in packs:
            raise PackError(f"duplicate pack id {pack.id}")
        packs[pack.id] = pack
    if not packs:
        raise PackError(f"no packs found in {PACK_DIR}")
    return packs


def get_pack(pack_id: str) -> Pack:
    try:
        return all_packs()[pack_id]
    except KeyError:
        raise PackError(f"unknown pack: {pack_id}") from None
