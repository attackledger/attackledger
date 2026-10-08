#!/usr/bin/env python3
"""Role partition integrity check.

Verifies three things:
  1. each of the 13 webapp-checklist sections (3-15) appears in EXACTLY ONE ROLE_*.md
  2. every SKILL_MAP.md row is assigned to exactly ONE valid role
  3. each of the 7 roles receives >= 1 SKILL_MAP row

Usage: python3 lanes/check_partition.py
Exit code 0 = PASS, 1 = FAIL.
"""
import io, os, re, sys, glob

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root
ROLES = ["recon", "mapper", "authz", "authflow", "logic", "injection", "mobile"]
# checklist section -> role expected to own it
SECTIONS = {3: "recon", 4: "recon", 5: "recon", 6: "authflow", 7: "authflow",
            8: "authz", 9: "injection", 10: "logic", 11: "logic", 12: "recon",
            13: "injection", 14: "logic", 15: "injection"}

fails = []

# --- 1. checklist sections ---
owners = {n: [] for n in SECTIONS}
for rf in sorted(glob.glob(os.path.join(BASE, "roles", "ROLE_*.md"))):
    role = os.path.basename(rf)[5:-3]
    txt = io.open(rf, encoding="utf-8").read()
    m = re.search(r"OWNED CHECKLIST SLICE.*?\n(.*?)\n\n", txt, re.S)
    if not m:
        fails.append("%s: no OWNED CHECKLIST SLICE block" % role)
        continue
    for num in re.findall(r"^\s{2}(\d+)\s", m.group(1), re.M):
        n = int(num)
        if n not in owners:
            fails.append("%s: section number %d does not exist in the checklist" % (role, n))
        else:
            owners[n].append(role)

for n, who in sorted(owners.items()):
    if len(who) == 0:
        fails.append("checklist section %d has NO OWNER (expected: %s)" % (n, SECTIONS[n]))
    elif len(who) > 1:
        fails.append("checklist section %d has MULTIPLE OWNERS: %s" % (n, ", ".join(who)))
    elif who[0] != SECTIONS[n]:
        fails.append("checklist section %d is in the wrong role: %s (expected %s)" % (n, who[0], SECTIONS[n]))

# --- 2 & 3. SKILL_MAP rows ---
counts = {r: 0 for r in ROLES}
rows = 0
table = [l for l in io.open(os.path.join(BASE, "methodology", "SKILL_MAP.md"), encoding="utf-8")
         if l.startswith("|")]
# language-neutral: drop the |--- separator rows and the header row right before each
header_idx = {i - 1 for i, l in enumerate(table) if l.startswith("|---")}
for i, line in enumerate(table):
    if line.startswith("|---") or i in header_idx:
        continue
    cols = [c.strip() for c in line.strip().strip("|").split("|")]
    if len(cols) != 4:
        fails.append("SKILL_MAP row does not have 4 columns: %s" % cols[0][:40])
        continue
    rows += 1
    cell = cols[3]
    if cell.startswith("_"):          # matrix-style row, not assigned to a role
        continue
    named = [r for r in ROLES if re.match(r"^%s\b" % r, cell)]
    if len(named) != 1:
        fails.append("SKILL_MAP '%s': role cell is not exactly one valid role -> %r" % (cols[0][:40], cell))
    else:
        counts[named[0]] += 1

for r in ROLES:
    if counts[r] == 0:
        fails.append("role '%s' receives no SKILL_MAP row" % r)

print("SKILL_MAP rows: %d" % rows)
print("rows per role: %s" % ", ".join("%s=%d" % (r, counts[r]) for r in ROLES))
print("checklist sections: %d/13 with exactly one correct owner" % sum(1 for n, w in owners.items() if len(w) == 1 and w[0] == SECTIONS[n]))

if fails:
    print("\nFAIL (%d):" % len(fails))
    for f in fails:
        print("  - " + f)
    sys.exit(1)
print("\nPASS -- partition is intact.")
