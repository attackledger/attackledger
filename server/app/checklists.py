"""Load per-role lane checklists from checklists/CHECKLIST_<role>.md."""
import os
import re
from pathlib import Path

from .models import Role

_DEFAULT_DIR = Path(__file__).resolve().parents[2] / "checklists"
CHECKLIST_DIR = Path(os.environ.get("ATTACKLEDGER_CHECKLISTS", _DEFAULT_DIR))

_ITEM = re.compile(r"^\s*- \[ \]\s+(.+?)\s*$")


def load_items(role: Role) -> list[str]:
    path = CHECKLIST_DIR / f"CHECKLIST_{role.value}.md"
    if not path.is_file():
        # Fail closed: a lane without a checklist could never be audited.
        raise FileNotFoundError(f"no checklist for role {role.value}: {path}")
    items = [m.group(1) for line in path.read_text().splitlines() if (m := _ITEM.match(line))]
    if not items:
        raise ValueError(f"checklist for role {role.value} has no items: {path}")
    return items
