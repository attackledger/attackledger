#!/usr/bin/env python3
"""watch_enroll.py <program> [--apply] -- enroll an engagement into a continuous-monitoring (watch.sh) worker.

What it does:
  1. Collect the FULL host inventory under $ATTACKLEDGER_WORKDIR/engagements/<program>/
     (all.txt, scanned_ok.txt, ALL_SURFACES_*, scope.txt regex-filtered, CLASS_MATRIX
     col1 comma-separated, hosts from ENDPOINTS_*).
  2. ENUM_ROOTS = registrable apexes from those hosts + the scope wildcards.
     LITERAL_HOSTS = bare hosts that are not wildcards.
  3. --apply: write to the remote worker: <AL_REMOTE_BASE>/targets/<program>/{scope.txt, watch.conf}
     and SEED watch_state/seen_hosts.txt (with the existing hosts) -> the first cron run is SILENT.
     (Without seeding, the first run would treat ALL hosts as "new" and spam notifications.)
  Without --apply: only prints what it would do (dry run).

It does NOT start a live scan -- the remote worker's cron (weekly) does that.

Env (needed only for --apply):
  AL_REMOTE_HOST   ssh host alias of the remote worker
  AL_REMOTE_BASE   remote base directory (the remote dir is $AL_REMOTE_BASE/targets/<program>)
  ATTACKLEDGER_WORKDIR   local data dir (default: <repo>/work)
"""
import io, os, re, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.environ.get("ATTACKLEDGER_WORKDIR") or os.path.join(os.environ.get("ATTACKLEDGER_HOME", ROOT), "work")
# two-part TLDs (apex = last 3 labels). Weighted toward Latin American ccTLDs.
TWO_PART = {"co.uk","com.br","com.ar","com.mx","com.au","co.jp","com.co","com.ve",
            "co.za","com.tr","com.sg","com.hk","co.kr","com.cn","co.in","com.pl",
            "com.bo","com.cl","com.do","com.ec","com.pe","com.py","com.uy","com.pa",
            "com.gt","com.hn","com.ni","com.sv","co.cr","com.gu","com.pr","co.id"}
HOST_RE = re.compile(r"^\*?\.?([a-z0-9-]+\.)+[a-z]{2,}$")

def apex(host):
    h = host.lstrip("*.").lower().strip(".")
    parts = h.split(".")
    if len(parts) < 2:
        return None
    last2 = ".".join(parts[-2:])
    if last2 in TWO_PART and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last2

def load_oos(eng):
    oos = set()
    p = os.path.join(eng, "oos.txt")
    if os.path.exists(p):
        for l in io.open(p, encoding="utf-8", errors="ignore"):
            t = l.strip().lower().replace("https://","").replace("http://","").rstrip("/")
            if t:
                oos.add(t.lstrip("*."))
    return oos

def is_oos(host, oos):
    h = host.lstrip("*.")
    for t in oos:
        if h == t or h.endswith("." + t):
            return True
    return False

def collect(prog):
    """scope_wild = *.x.y entries in the scope (AUTHORITATIVE in-scope for ENUM).
       scope_bare = non-wildcard hosts in the scope.
       known = ALL inventory hosts (for seeding ONLY -- NOT an enum source)."""
    eng = os.path.join(BASE, "engagements", prog)
    if not os.path.isdir(eng):
        sys.exit("no such engagement: %s" % eng)
    scope_wild, scope_bare, known = set(), set(), set()
    def valid(s):
        s = s.strip().lower()
        return s if (s and " " not in s and "\t" not in s and HOST_RE.match(s)) else None
    # scope.txt -- the ONLY ENUM source (authoritative). May be TSV; first field.
    sc = os.path.join(eng, "scope.txt")
    if os.path.exists(sc):
        for l in io.open(sc, encoding="utf-8", errors="ignore"):
            v = valid(l.split("\t")[0])
            if not v:
                continue
            if v.startswith("*."):
                scope_wild.add(v); known.add(v.lstrip("*."))
            else:
                scope_bare.add(v); known.add(v)
    # known seed sources (do NOT go to enum, only for first-run silence)
    def add_known(s):
        v = valid(s)
        if v: known.add(v.lstrip("*."))
    for fn in ["all.txt", "scanned_ok.txt"]:
        p = os.path.join(eng, fn)
        if os.path.exists(p):
            for l in io.open(p, encoding="utf-8", errors="ignore"):
                add_known(l)
    for fn in os.listdir(eng):
        if fn.startswith("ALL_SURFACES") and fn.endswith(".txt"):
            for l in io.open(os.path.join(eng, fn), encoding="utf-8", errors="ignore"):
                add_known(l)
    cm = os.path.join(eng, "CLASS_MATRIX.tsv")
    if os.path.exists(cm):
        for l in io.open(cm, encoding="utf-8", errors="ignore"):
            c0 = re.sub(r"\(.*?\)", "", l.split("\t")[0])
            for tok in c0.split(","):
                add_known(tok)
    for fn in os.listdir(eng):
        if fn.startswith("ENDPOINTS_") and fn.endswith(".tsv"):
            for l in io.open(os.path.join(eng, fn), encoding="utf-8", errors="ignore"):
                m = re.search(r"https?://([a-z0-9.-]+)", l.lower())
                if m: add_known(m.group(1))
    return scope_wild, scope_bare, known, load_oos(eng)

def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    prog = sys.argv[1]
    apply = "--apply" in sys.argv
    scope_wild, scope_bare, known, oos = collect(prog)
    # ENUM_ROOTS: ONLY scope wildcard apexes, OOS removed (deny wins).
    roots = set()
    for w in scope_wild:
        if is_oos(w, oos):
            continue
        a = apex(w)
        if a: roots.add(a)
    # LITERAL: bare hosts in scope; SKIP those whose apex is an ENUM_ROOT (enum finds them anyway).
    literals = sorted(h for h in scope_bare
                      if not is_oos(h, oos) and apex(h) not in roots)
    # seed: all known, minus OOS
    all_known = sorted(h for h in known if not is_oos(h, oos))

    print("=== watch enroll: %s ===" % prog)
    print("  scope wildcards: %d · scope bare: %d · known(seed): %d · oos: %d"
          % (len(scope_wild), len(scope_bare), len(known), len(oos)))
    print("  ENUM_ROOTS (%d): %s" % (len(roots), " ".join(sorted(roots)) or "(none)"))
    print("  LITERAL_HOSTS (%d): %s" % (len(literals),
          " ".join(literals[:8]) + (" ..." if len(literals) > 8 else "") or "(none)"))
    if not roots and not literals:
        print("  WARNING: no ENUM/LITERAL host came out of the scope (scope may be prose) -- SKIPPED, check by hand.")
        return 2
    if not apply:
        print("  (dry run -- use --apply to write to the remote worker)")
        return 0

    host = os.environ.get("AL_REMOTE_HOST", "")
    rbase = os.environ.get("AL_REMOTE_BASE", "")
    if not host or not rbase:
        print("  ERROR: --apply needs AL_REMOTE_HOST (ssh alias) and AL_REMOTE_BASE (remote base dir) set.")
        return 1
    tdir = "%s/targets/%s" % (rbase.rstrip("/"), prog)
    conf = ('ENUM_ROOTS="%s"\nLITERAL_HOSTS="%s"\nRATE_LIMIT=40\n'
            % (" ".join(sorted(roots)), " ".join(literals)))
    scope_body = "\n".join(sorted(roots)) + "\n"          # apexes for the pipeline scope filter
    seed_body = "\n".join(all_known) + "\n"               # seed for first-run silence
    # write to the remote worker with a single SSH call
    remote = (
        "mkdir -p %s/watch_state && "
        "cat > %s/watch.conf <<'EOF'\n%sEOF\n"
        "cat > %s/scope.txt <<'EOF'\n%sEOF\n"
        "cat > %s/watch_state/seen_hosts.txt <<'EOF'\n%sEOF\n"
        "echo remote-written: $(wc -l < %s/watch_state/seen_hosts.txt) hosts seeded"
    ) % (tdir, tdir, conf, tdir, scope_body, tdir, seed_body, tdir)
    try:
        r = subprocess.run(["ssh","-o","ConnectTimeout=12","-o","ServerAliveInterval=5",
                            "-o","ServerAliveCountMax=3",host, remote],
                           capture_output=True, text=True, timeout=45)
    except subprocess.TimeoutExpired:
        print("  ERROR: remote SSH did not answer within 45s -- SKIPPED")
        return 1
    print("  " + (r.stdout.strip() or r.stderr.strip() or "(empty reply)"))
    return 0 if r.returncode == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
