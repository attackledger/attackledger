"""Import a HackerOne scope CSV into include/exclude rules.

Based on the original csv_to_scope.py, with one deliberate change: an asset marked
not eligible for submission becomes an **exclude** rule instead of being skipped.
Ineligible rows are usually exceptions under a wildcard that is in scope (for
example community.example.com under *.example.com). Skipping them would leave them
covered by the wildcard.
"""
import csv
import io
from urllib.parse import urlsplit

from . import scope

DOMAIN_TYPES = {"URL", "WILDCARD", "API", "DOMAIN"}
FALSE = {"false", "no", "0", "n", "f"}


def _col(fieldnames, *cands):
    low = {f.lower().strip(): f for f in fieldnames or []}
    for c in cands:
        if c in low:
            return low[c]
    return None


def _host_from(identifier: str) -> str:
    v = identifier.strip()
    if "://" in v:
        v = urlsplit(v).hostname or ""
    v = v.split("/", 1)[0]
    if v.count(":") == 1 and not v.startswith("["):
        v = v.split(":", 1)[0]
    return v.strip().lower().rstrip(".")


def parse(text: str) -> dict:
    reader = csv.DictReader(io.StringIO(text))
    id_col = _col(reader.fieldnames, "identifier", "asset_identifier", "asset", "domain", "host")
    if not id_col:
        raise ValueError("no identifier column; expected a HackerOne scope export")
    type_col = _col(reader.fieldnames, "asset_type", "type")
    elig_col = _col(reader.fieldnames, "eligible_for_submission", "eligible")

    include, exclude, skipped, invalid = set(), set(), [], []
    for row in reader:
        raw = (row.get(id_col) or "").strip()
        if not raw:
            continue
        atype = (row.get(type_col) or "").strip().upper() if type_col else "URL"
        if atype not in DOMAIN_TYPES:
            skipped.append({"identifier": raw, "type": atype})   # apps, CIDRs, source code, hardware...
            continue
        wildcard = raw.lstrip().startswith("*.") or atype == "WILDCARD"
        host = _host_from(raw[2:] if raw.lstrip().startswith("*.") else raw)
        pattern = f"*.{host}" if wildcard else host
        try:
            pattern = scope.normalize_pattern(pattern)
        except scope.ScopeError as e:
            invalid.append({"identifier": raw, "reason": str(e)})
            continue
        eligible = not (elig_col and (row.get(elig_col) or "").strip().lower() in FALSE)
        (include if eligible else exclude).add(pattern)
    include -= exclude
    return {"include": sorted(include), "exclude": sorted(exclude),
            "not_imported": skipped, "invalid": invalid}
