#!/usr/bin/env python3
"""CLASS_MATRIX.tsv -- per-engagement host x checklist-section coverage ledger.

Row = host, column = the 13 sections of the webapp-checklist (grouped by role).
Cell: PASS | FINDING | N/A | BLOCKED | UNVERIFIED | .   ('.' = not touched yet)

  init <program> <host>...        create the matrix / add hosts
  set  <program> <host> <section> <verdict>
  show <program>                  print grouped by role
  gaps <program>                  list unfilled cells per role
  next <program>                  print the NEXT role per host (queue view)

Data lives under $ATTACKLEDGER_WORKDIR (default: <repo>/work).
"""
import io, os, sys

BASE = os.environ.get("ATTACKLEDGER_WORKDIR") or os.path.join(
    os.environ.get("ATTACKLEDGER_HOME") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "work")
SEC = [(3, "InfoGath", "recon"), (4, "ConfigMgmt", "recon"), (5, "SecTransmit", "recon"),
       (12, "Crypto", "recon"), (6, "AuthN", "authflow"), (7, "Session", "authflow"),
       (8, "AuthZ", "authz"), (10, "DoS", "logic"), (11, "BizLogic", "logic"),
       (14, "CardPay", "logic"), (9, "DataValid", "injection"), (13, "FileUpload", "injection"),
       (15, "HTML5", "injection")]
COLS = ["host"] + ["%d_%s" % (n, name) for n, name, _ in SEC]
OK = {"PASS", "FINDING", "N/A", "BLOCKED", "UNVERIFIED", "."}


def path(prog):
    d = os.path.join(BASE, "engagements", prog)
    if not os.path.isdir(d):
        sys.exit("engagement directory not found: %s" % d)
    return os.path.join(d, "CLASS_MATRIX.tsv")


def load(prog):
    p = path(prog)
    if not os.path.exists(p):
        return []
    rows = [l.rstrip("\n").split("\t") for l in io.open(p, encoding="utf-8") if l.strip()]
    return rows[1:] if rows else []


def save(prog, rows):
    p = path(prog)
    with io.open(p, "w", encoding="utf-8") as f:
        f.write("\t".join(COLS) + "\n")
        for r in sorted(rows):
            f.write("\t".join(r) + "\n")
    print("written: %s  (%d hosts)" % (p, len(rows)))


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    cmd, prog = sys.argv[1], sys.argv[2]
    rows = load(prog)
    have = {r[0] for r in rows}

    if cmd == "init":
        for h in sys.argv[3:]:
            if h not in have:
                rows.append([h] + ["."] * len(SEC))
        save(prog, rows)

    elif cmd == "set":
        host, sec, verdict = sys.argv[3], sys.argv[4], sys.argv[5].upper()
        if verdict not in OK:
            sys.exit("invalid verdict %r -- %s" % (verdict, "|".join(sorted(OK))))
        idx = next((i for i, c in enumerate(COLS) if c.startswith(sec + "_")), None)
        if idx is None:
            sys.exit("section number not found: %s" % sec)
        row = next((r for r in rows if r[0] == host), None)
        if row is None:
            row = [host] + ["."] * len(SEC)
            rows.append(row)
        row[idx] = verdict
        save(prog, rows)

    elif cmd in ("show", "gaps"):
        if not rows:
            sys.exit("matrix empty or missing: %s" % path(prog))
        for role in ["recon", "authflow", "authz", "logic", "injection"]:
            mine = [(i + 1, n, nm) for i, (n, nm, r) in enumerate(SEC) if r == role]
            print("\n== %s ==" % role)
            for r in sorted(rows):
                cells = ["%s:%s" % (nm, r[i]) for i, n, nm in mine]
                if cmd == "gaps":
                    cells = [c for c in cells if c.endswith(":.")]
                    if not cells:
                        continue
                print("  %-34s %s" % (r[0], "  ".join(cells)))
    elif cmd == "next":
        if not rows:
            sys.exit("matrix empty or missing: %s" % path(prog))
        order = ["recon", "mapper", "authz", "authflow", "logic", "injection"]
        eng = os.path.dirname(path(prog))
        todo = []
        for r in sorted(rows):
            host = r[0]
            has_model = os.path.exists(os.path.join(eng, "APP_MODEL_%s.md" % host))
            nxt, why = None, ""
            for role in order:
                if role == "mapper":
                    if not has_model:
                        nxt, why = "mapper", "no APP_MODEL"
                        break
                    continue
                idx = [i + 1 for i, (n, nm, rr) in enumerate(SEC) if rr == role]
                if not idx:
                    continue
                if all(r[i] == "." for i in idx):
                    if role != "recon" and not has_model:
                        nxt, why = "mapper", "no APP_MODEL (gate)"
                    else:
                        nxt, why = role, "%d sections empty" % len(idx)
                    break
            if nxt:
                todo.append((host, nxt, why))
        # OPEN LANES = the brief files under briefs/ THEMSELVES.
        # Do NOT intersect with matrix rows -- a new host may not be in the matrix yet,
        # and the counter would come out too low.
        bd = os.path.join(BASE, "briefs")
        # NO auto-archive here: file-based liveness inference can count a lane that is
        # still writing its artifact as finished. Archiving runs only inside `open_lane.py`.
        openb = [f for f in (os.listdir(bd) if os.path.isdir(bd) else [])
                 if f.startswith("BRIEF_") and f.endswith(".md")]
        open_targets = [f[len("BRIEF_"):-3].split("_", 1)[-1] for f in openb]
        running = {h for h, _, _ in todo if h in open_targets}
        if not todo:
            print("queue EMPTY -- every role of every host has been processed.")
            return
        w = max(len(h) for h, _, _ in todo) + 2
        print("NEXT LANES (ONE role per host; at most 2 concurrent, on DIFFERENT hosts)\n")
        slot = 0
        for h, role, why in todo:
            if h in running:
                mark = "RUNNING (brief exists)"
            elif slot < max(0, 2 - len(running)):
                mark = "<= OPEN NOW"
                slot += 1
            else:
                mark = ""
            print("  %-*s %-10s %-20s %s" % (w, h, role, why, mark))
        n_open = len(openb)
        warn = "  WARNING: exceeds 2 -- may be a stale brief, open_lane.py auto-archives" if n_open > 2 else ""
        print("\n  OPEN LANES: %d/2%s   (from brief files; for the exact count use ListAgents -> running)"
              % (n_open, warn))
        for t in sorted(open_targets):
            print("     - %s" % t)
        print("  command: python3 lanes/open_lane.py %s <host> <role>" % prog)

    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
