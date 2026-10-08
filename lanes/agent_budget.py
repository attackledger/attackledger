#!/usr/bin/env python3
"""agent_budget.py -- measures the OPENING CONTEXT cost of an agent brief.

Rule: check the opening cost and do not let it exceed ~20k tokens; check and optimize
on every agent launch.

Usage:
  python3 agent_budget.py <brief.md> [--ceiling 20000]

Parses the read commands found in the brief's STEP 0, measures file sizes (locally and,
if AL_REMOTE_HOST is set, over ssh), estimates tokens and returns PASS/FAIL against the ceiling.

Counting rules:
  cat / Read <file>           -> the WHOLE file
  sed -n 'A,Bp' <file>        -> only that line range
  head -N / sed -n '1,Np'     -> first N lines
  grep/wc/ls                  -> small constant (short output), counted as 200 tokens
Token estimate: bytes / 4 (conservative).

Environment:
  AL_REMOTE_HOST  optional ssh alias of a remote recon box; files not found locally are measured there
  AL_REMOTE_BASE  remote directory that relative paths in the brief resolve against
"""
import os, re, subprocess, sys

CEIL = 20000
args = [a for a in sys.argv[1:] if not a.startswith("--")]
if "--ceiling" in sys.argv:
    CEIL = int(sys.argv[sys.argv.index("--ceiling") + 1])
if not args:
    sys.exit("usage: agent_budget.py <brief.md> [--ceiling N]")
brief = args[0]
text = open(brief, encoding="utf-8").read()

def local_stat(path):
    path = os.path.expanduser(path)
    if os.path.exists(path):
        with open(path, "rb") as fh:
            b = fh.read()
        return len(b), b.count(b"\n") + 1
    return None

REMOTE_HOST = os.environ.get("AL_REMOTE_HOST", "")
REMOTE_BASE = os.environ.get("AL_REMOTE_BASE", "")
_remote_cache = {}
def remote_stat(path):
    if not REMOTE_HOST:
        return None
    if path in _remote_cache:
        return _remote_cache[path]
    try:
        out = subprocess.run(
            ["ssh", REMOTE_HOST, "wc -c -l < %s 2>/dev/null" % path],
            capture_output=True, text=True, timeout=25).stdout.split()
        r = (int(out[1]), int(out[0])) if len(out) >= 2 else None
    except Exception:
        r = None
    _remote_cache[path] = r
    return r

def stat(path):
    return local_stat(path) or remote_stat(path)

def resolve(p):
    p = p.strip().strip("`\"'")
    if p.startswith(("~", "/")):
        return p
    return os.path.join(REMOTE_BASE, p) if REMOTE_BASE else p

FILE = r"([~/\w][\w./~-]*\.(?:md|txt|tsv|json|html|py|sh))"
items, seen = [], set()

def add(path, kind, lines=None, note=""):
    key = (path, kind, lines)
    if key in seen:
        return
    seen.add(key)
    st = stat(path)
    if st is None:
        items.append((path, kind, None, 0, "FILE MISSING"))
        return
    nbytes, nlines = st
    if kind == "full":
        cost = nbytes
    elif kind == "range" and lines:
        a, b = lines
        frac = max(0, min(nlines, b) - a + 1) / max(nlines, 1)
        cost = int(nbytes * frac)
    elif kind == "head" and lines:
        cost = int(nbytes * min(nlines, lines[1]) / max(nlines, 1))
    else:
        cost = 800
    items.append((path, kind, nbytes, cost, note))

# cat / Read -> full read
for m in re.finditer(r"(?:^|[\s`(])(?:cat|Read)\s+" + FILE, text, re.M):
    add(resolve(m.group(1)), "full")
# sed -n 'A,Bp' <file>
for m in re.finditer(r"sed\s+-n\s+['\"](\d+),(?:\+?)(\d+)p['\"]\s+" + FILE, text):
    a, b = int(m.group(1)), int(m.group(2))
    if "+" in m.group(0):
        b = a + b
    add(resolve(m.group(3)), "range", (a, b))
# head -N <file>
for m in re.finditer(r"head\s+-n?\s*(\d+)\s+" + FILE, text):
    add(resolve(m.group(2)), "head", (1, int(m.group(1))))
# grep / wc / ls -> small constant
for m in re.finditer(r"(?:grep|wc|ls)\b[^\n|]*?" + FILE, text):
    p = resolve(m.group(1))
    if not any(p == it[0] and it[1] in ("full", "range", "head") for it in items):
        add(p, "grep")

brief_bytes = len(text.encode())
total = brief_bytes + sum(i[3] for i in items)

print("BRIEF: %s" % brief)
print("-" * 86)
print("%-46s %-7s %10s %10s" % ("file / source", "read", "size b", "~tokens"))
print("-" * 86)
print("%-46s %-7s %10d %10d" % ("(the brief text itself)", "-", brief_bytes, brief_bytes // 4))
for path, kind, nbytes, cost, note in sorted(items, key=lambda x: -x[3]):
    disp = path if len(path) <= 46 else "..." + path[-43:]
    print("%-46s %-7s %10s %10d %s" % (
        disp, kind, (nbytes if nbytes is not None else "?"), cost // 4, note))
print("-" * 86)
print("TOTAL OPENING: ~%d tokens   (ceiling %d)" % (total // 4, CEIL))
if total // 4 > CEIL:
    print("\n\033[31mFAIL\033[0m -- exceeds the ceiling by %d tokens. Optimize:" % (total // 4 - CEIL))
    for path, kind, nbytes, cost, note in sorted(items, key=lambda x: -x[3])[:4]:
        if kind == "full" and cost // 4 > 2000:
            print("  * %s is read in full (~%d tokens) -> use `sed -n 'A,Bp'` or a derived index"
                  % (os.path.basename(path), cost // 4))
    print("  * methodology/AGENT_EXECUTION_PROMPT.md must NOT be shortened (measured reason) -- save elsewhere")
    sys.exit(1)
print("\n\033[32mPASS\033[0m -- %d tokens under the ceiling." % (CEIL - total // 4))
