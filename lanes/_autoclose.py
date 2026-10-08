#!/usr/bin/env python3
"""Archive the briefs of lanes that have delivered. Shared by open_lane.py and class_matrix.py."""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.environ.get("ATTACKLEDGER_WORKDIR") or os.path.join(os.environ.get("ATTACKLEDGER_HOME") or ROOT, "work")
prog = sys.argv[1] if len(sys.argv) > 1 else None
bd = os.path.join(BASE, "briefs")
eng = os.path.join(BASE, "engagements", prog) if prog else None
if not (os.path.isdir(bd) and eng and os.path.isdir(eng)):
    sys.exit(0)
done = os.path.join(bd, "done")
os.makedirs(done, exist_ok=True)
for f in os.listdir(bd):
    if not (f.startswith("BRIEF_") and f.endswith(".md")):
        continue
    bp = os.path.join(bd, f)
    bt = os.path.getmtime(bp)
    target = f[len("BRIEF_"):-3].split("_", 1)[-1]
    label = target.split(".")[0]          # artifact names use abbreviations of the host label
    hit = False
    # 1) full host or short label in the file NAME
    for root, dirs, files in os.walk(eng):
        dirs[:] = [d for d in dirs if d != "done"]
        for g in files:
            if os.path.getmtime(os.path.join(root, g)) <= bt + 60:
                continue
            if target in g or (len(label) > 3 and label in g):
                hit = True
                break
        if hit:
            break
    # NOTE: the "shared ledger" rule was REMOVED: when ANOTHER lane wrote to
    #    CLASS_MATRIX_NOTES/CROSS_LANE_LEADS, a still-RUNNING lane whose name appeared
    #    inside was wrongly considered finished. The mtime of a shared file marks the
    #    last writer, not this lane. Do not infer.
    #    Remaining rule: only an artifact whose FILE NAME contains the host/label and
    #    that was written AFTER the brief counts.
    if hit:
        os.replace(bp, os.path.join(done, f))
        print("archived: %s" % f)
