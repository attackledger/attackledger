#!/usr/bin/env python3
"""open_lane.py <program> <host> <role> -- reduces opening a lane to ONE command.

In order:
  1. SCOPE GATE      -- does the host match the scope.txt patterns, is it in oos.txt (deny-wins)
  2. PRECHECK        -- existing lane/artifact files for this host + their DATES
  3. GATE            -- authz/authflow/logic/injection require APP_MODEL_<host>.md
  4. OVERLAP         -- warn if another role's brief exists on the same host (one role per host)
  5. ATTESTATION     -- picks a RANDOM, non-empty line from two files and prints the expected
                        value (for the orchestrator to verify; the agent only gets the line NUMBERS)
  6. BRIEF           -- writes briefs/BRIEF_<role>_<host>.md (skeleton from roles/BRIEF_TEMPLATE.md)
  7. BUDGET          -- runs agent_budget.py, says FAIL if the 20k ceiling is exceeded

Exit 0 = the lane may be opened.

Environment:
  ATTACKLEDGER_WORKDIR  data directory holding engagements/ and briefs/ (default: <repo>/work)
  AL_REMOTE_HOST        optional ssh alias of a remote recon box (adds a remote precheck)
  AL_REMOTE_BASE        remote directory holding per-program recon output (required with AL_REMOTE_HOST)
"""
import io, os, random, re, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # repo root (code, roles, methodology)
BASE = os.environ.get("ATTACKLEDGER_WORKDIR") or os.path.join(os.environ.get("ATTACKLEDGER_HOME") or ROOT, "work")  # data dir
NEEDS_MODEL = {"authz", "authflow", "logic", "injection"}

ROLE_COLS = {
    "recon":     ["3_InfoGath", "4_ConfigMgmt", "5_SecTransmit", "12_Crypto"],
    "authz":     ["8_AuthZ"],
    "authflow":  ["6_AuthN", "7_Session"],
    "logic":     ["10_DoS", "11_BizLogic", "14_CardPay"],
    "injection": ["9_DataValid", "13_FileUpload", "15_HTML5"],
    "mapper":    [],
    "mobile":    [],
}
ROLES = ["recon", "mapper", "authz", "authflow", "logic", "injection", "mobile"]
SLICE = {"recon": "3 InfoGath, 4 ConfigMgmt, 5 SecTransmit, 12 Crypto",
         "mapper": "none -- produces APP_MODEL", "authz": "8 Authorization",
         "authflow": "6 Authentication, 7 Session Management",
         "logic": "10 DoS, 11 BizLogic, 14 CardPay",
         "injection": "9 DataValid, 13 FileUpload, 15 HTML5",
         "mobile": "none -- produces MOBILE_SURFACE"}


def die(msg):
    print("FAIL: " + msg)
    sys.exit(1)


def _role_skills(role):
    """READ the role's REQUIRED skill set from ROLE_*.md + SKILL_MAP.md.

    WHY: writing the skill line into a brief by hand can assign a skill to the wrong
    role and breaks the partition; the tool reads it from the sources instead.
    """
    out = {"role_md": [], "skill_map": []}
    rp = os.path.join(ROOT, "roles", "ROLE_%s.md" % role)
    if os.path.exists(rp):
        grab = False
        for l in io.open(rp, encoding="utf-8"):
            if l.startswith("REQUIRED SKILL SET"):
                grab = True; continue
            if grab:
                if not l.startswith("  ") or not l.strip():
                    break
                out["role_md"].append(l.strip())
    sp = os.path.join(ROOT, "methodology", "SKILL_MAP.md")
    if os.path.exists(sp):
        for l in io.open(sp, encoding="utf-8"):
            c = [x.strip() for x in l.split("|")]
            if len(c) >= 5 and c[4].split("_")[0].strip().startswith(role):
                out["skill_map"].append("%s -> %s" % (c[2], c[3]))
    return out


def _matrix_row(eng, host, role):
    """Read this host's CLASS_MATRIX row and check whether the ROLE'S OWN slice is filled.

    WHY: a precheck that only prints file NAMES can lead to a lane being opened twice
    for the same host+role. A coverage claim is read from the matrix CELL, not from a file list.
    """
    fp = os.path.join(eng, "CLASS_MATRIX.tsv")
    if not os.path.exists(fp):
        return None, [], "CLASS_MATRIX.tsv missing"
    rows = [l.rstrip("\n").split("\t")
            for l in io.open(fp, encoding="utf-8", errors="ignore") if l.strip()]
    if not rows:
        return None, [], "CLASS_MATRIX.tsv empty"
    head = rows[0]
    for r in rows[1:]:
        if r and r[0] == host:
            cell = dict(zip(head, r))
            mine = [(c, cell.get(c, ".")) for c in ROLE_COLS.get(role, [])]
            filled = [(c, v) for c, v in mine if v not in (".", "", "-")]
            return cell, filled, None
    return None, [], "this host is NOT in CLASS_MATRIX (not initialized)"


def _remote_precheck(host, timeout=25):
    """Search a remote recon box's output for this host (optional).

    WHY: `engagements/` only holds HUNT records. Recon pipeline output
    (httpx/naabu/ferox/golden/priority) may live on a remote box under
    `$AL_REMOTE_BASE/<root>/`. A precheck that only looks locally would wrongly report
    'this host was never touched'. Returns None when AL_REMOTE_HOST is not set.
    """
    rhost = os.environ.get("AL_REMOTE_HOST", "")
    rbase = os.environ.get("AL_REMOTE_BASE", "")
    if not rhost or not rbase:
        return None
    root = ".".join(host.split(".")[-2:])
    cmd = (
        "d=%s/%s; "
        "if [ -d \"$d\" ]; then "
        "  echo \"DIR EXISTS: $d\"; "
        "  a=$(ls -1 $d/triage/alive_*.txt 2>/dev/null | head -1); "
        "  if [ -n \"$a\" ]; then "
        "    t=$(wc -l < \"$a\" | tr -d ' '); "
        "    m=$(grep -c -- %s \"$a\" 2>/dev/null || echo 0); "
        "    echo \"  alive: $t lines, of which for this apex: $m\"; "
        "    [ \"$m\" = \"0\" ] && echo '  !! DIRECTORY MISLABELED -- data belongs to ANOTHER domain, DO NOT USE'; "
        "  fi; "
        "  g=$(grep -rl -- %s $d/triage/ 2>/dev/null | head -4); "
        "  [ -n \"$g\" ] && echo \"$g\" | sed 's|.*/||; s|^|  seen in: |'; "
        "  grep -rh -- %s $d/triage/priority_*.tsv 2>/dev/null | head -2 | sed 's|^|  priority: |'; "
        "  grep -rlq -- %s $d/triage/golden_*.txt 2>/dev/null && echo '  !! in the GOLDEN list'; "
        "  ls -1 $d/endpoints/ 2>/dev/null | head -3 | sed 's|^|  endpoints/: |'; "
        "else echo \"no such dir: $d\"; fi"
    ) % (rbase, root, root, host, host, host)
    try:
        r = subprocess.run(["ssh", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes", rhost, cmd],
                           capture_output=True, text=True, timeout=timeout)
        out = [l for l in r.stdout.strip().split("\n") if l.strip()]
        return out or ["(no record of this host on the remote box)"]
    except subprocess.TimeoutExpired:
        return ["!! remote timeout -- CHECK MANUALLY: ssh %s 'ls %s/%s/'" % (rhost, rbase, root)]
    except Exception as e:
        return ["!! remote check COULD NOT RUN (%s) -- CHECK MANUALLY, do NOT assume 'untouched'" % type(e).__name__]


def pick_line(path, lo_frac=0.15):
    """Pick a random NON-EMPTY (>=25 chars) line from the file. Returns (number, text)."""
    lines = io.open(path, encoding="utf-8").read().split("\n")
    cand = [i + 1 for i, l in enumerate(lines)
            if len(l.strip()) >= 25 and i > len(lines) * lo_frac]
    if not cand:
        die("no suitable attestation line in %s" % path)
    n = random.choice(cand)
    return n, lines[n - 1]


def _autoclose(bd, eng):
    """Automatically archive the briefs of lanes that have delivered.

    The open-lane counter is derived from the brief files; relying on manual archiving
    makes the counter overcount.
    Criterion: an artifact whose name contains the brief's host and that was written
    AFTER the brief means the lane has delivered.
    """
    done = os.path.join(bd, "done")
    os.makedirs(done, exist_ok=True)
    moved = []
    for f in os.listdir(bd):
        if not f.startswith("BRIEF_") or not f.endswith(".md"):
            continue
        bp = os.path.join(bd, f)
        bt = os.path.getmtime(bp)
        # BRIEF_<role>_<target>.md
        target = f[len("BRIEF_"):-3].split("_", 1)[-1]
        delivered = False
        for root, dirs, files in os.walk(eng):
            dirs[:] = [d for d in dirs if d != "done"]
            for g in files:
                if target in g and os.path.getmtime(os.path.join(root, g)) > bt + 60:
                    delivered = True
                    break
            if delivered:
                break
        if delivered:
            os.replace(bp, os.path.join(done, f))
            moved.append(f)
    if moved:
        print("[0] AUTO-ARCHIVE  %d delivered briefs -> briefs/done/" % len(moved))
        for m in moved:
            print("      %s" % m)


def _scope_gate(eng, host):
    oos = os.path.join(eng, "oos.txt")
    if os.path.exists(oos):
        for line in io.open(oos, encoding="utf-8"):
            t = line.strip().replace("https://", "").replace("http://", "").rstrip("/")
            if t and (host == t or host.endswith("." + t)):
                die("host is in the OOS list (deny-wins): %s" % t)
    sc = os.path.join(eng, "scope.txt")
    if not os.path.exists(sc):
        die("scope.txt missing: %s" % sc)
    ok = False
    for line in io.open(sc, encoding="utf-8"):
        p = line.strip()
        if not p:
            continue
        if p.startswith("*."):
            if host == p[2:] or host.endswith("." + p[2:]):
                ok = True
        elif host == p:
            ok = True
    if not ok:
        die("host matches NONE of the scope.txt patterns: %s" % host)
    print("[1] SCOPE       OK -- %s is in scope and not in OOS" % host)



FORCE = False
CHECK = False


def main():
    global FORCE, CHECK
    FORCE = "--force" in sys.argv
    CHECK = "--check" in sys.argv
    sys.argv = [a for a in sys.argv if a not in ("--force", "--check")]
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    prog, host, role = sys.argv[1], sys.argv[2], sys.argv[3]
    if role not in ROLES:
        die("invalid role %r -- %s" % (role, "|".join(ROLES)))
    eng = os.path.join(BASE, "engagements", prog)
    if not os.path.isdir(eng):
        die("engagement not found: %s" % eng)

    # 1 -- scope gate. For the mobile role the target is a PACKAGE NAME, not a host -> apps.txt
    if role == "mobile":
        ap = os.path.join(eng, "apps.txt")
        if not os.path.exists(ap):
            die("apps.txt missing: %s" % ap)
        # apps.txt may be a plain list or a TSV (package<TAB>platform<TAB>...): first column is the package name
        pkgs = [l.split("\t")[0].strip() for l in io.open(ap, encoding="utf-8")
                if l.strip() and not l.lstrip().startswith("#")]
        if host not in pkgs:
            die("package is NOT in apps.txt: %s\n      present: %s" % (host, ", ".join(pkgs)))
        print("[1] SCOPE       OK -- %s is declared in apps.txt (mobile asset)" % host)
        print("[1b] ELIGIBILITY  WARNING: BEFORE any APK work, VERIFY `eligible_for_submission` "
              "from the live program policy/API -- and write it into the brief.")
    else:
        _scope_gate(eng, host)

    # 2 -- precheck: file NAME *and* CONTENT. Looking only at names produced a false
    #     "untouched"; earlier work is recorded INSIDE files.
    print("[2] PRECHECK    files that mention this host (name + CONTENT):")
    hits = {}
    for root, dirs, files in os.walk(BASE):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "briefs")]
        for f in files:
            if not f.endswith((".md", ".txt", ".tsv", ".json")):
                continue
            fp = os.path.join(root, f)
            why = []
            if host in f:
                why.append("name")
            try:
                if host in io.open(fp, encoding="utf-8", errors="ignore").read():
                    why.append("content")
            except OSError:
                pass
            if why:
                hits[fp] = "+".join(why)
    for fp, why in sorted(hits.items(), key=lambda kv: -os.path.getmtime(kv[0]))[:12]:
        d = subprocess.run(["date", "-r", fp, "+%Y-%m-%d %H:%M"],
                           capture_output=True, text=True).stdout.strip()
        print("      %-58s %-12s %s" % (os.path.relpath(fp, BASE)[:58], why, d))
    if not hits:
        print("      (none locally)")
    else:
        print("      -> CHECK THE DATES. Do not reopen a closed item; record it in brief section 6.")

    # 2b -- REMOTE SIDE (optional). The local `engagements/` does not see recon work that
    # lives on a remote box, so a lane could be briefed "never touched" wrongly.
    remote = _remote_precheck(host)
    if remote is not None:
        print("      REMOTE (%s):" % os.environ.get("AL_REMOTE_BASE", ""))
        for line in remote:
            print("        " + line)

    # 2c -- MATRIX CELL. Not file names: the coverage claim itself.
    cell, filled, err = _matrix_row(eng, host, role)
    if err:
        print("      CLASS_MATRIX: %s" % err)
    else:
        cols = ROLE_COLS.get(role, [])
        shown = "  ".join("%s=%s" % (c, cell.get(c, ".")) for c in cols) or "(role owns no slice)"
        print("      CLASS_MATRIX slice of this role: %s" % shown)
        if filled:
            print("      " + "=" * 66)
            print("      !!  THIS LANE PROBABLY ALREADY RAN  !!")
            for c, v in filled:
                print("        %-14s = %s" % (c, v))
            print("      Do NOT write 'this slice was NEVER covered' in the brief -- it would be WRONG.")
            print("      Either do NOT open the lane, or set the brief up as GAP-FILLING:")
            print("        - first READ `CLASS_MATRIX_NOTES.md` + `findings/SKILL_ARTIFACTS_%s_*`" % role)
            print("        - record in brief section 12 WHAT THE PREVIOUS PASS FOUND")
            print("        - target only UNVERIFIED/BLOCKED items, do not repeat PASSes")
            print("      " + "=" * 66)

    # 3 -- APP_MODEL gate
    model = os.path.join(eng, "APP_MODEL_%s.md" % host)
    if role in NEEDS_MODEL:
        if not os.path.exists(model):
            die("role '%s' requires APP_MODEL but it is missing: %s\n      -> open the `mapper` lane first." % (role, model))
        kb = os.path.getsize(model) / 1024.0
        flag = "  WARNING: 30KB CAP EXCEEDED -- move the raw endpoint list to ENDPOINTS_*.tsv" if kb > 30 else ""
        print("[3] APP_MODEL   OK -- %.1f KB%s" % (kb, flag))
    else:
        print("[3] APP_MODEL   exempt (role=%s)" % role)

    # 4 -- is there another role's brief on the same host?
    bd = os.path.join(BASE, "briefs")
    os.makedirs(bd, exist_ok=True)
    _autoclose(bd, eng)
    clash = [f for f in os.listdir(bd) if host in f and "_%s_" % role not in f]
    print("[4] OVERLAP     %s" % ("WARNING: another role has a brief on this host: %s -- ONE role per host!"
                                  % ", ".join(clash) if clash else "OK -- no other role's brief on this host"))

    # 5 -- attestation lines
    hp = os.path.join(ROOT, "methodology", "AGENT_EXECUTION_PROMPT.md")
    rp = os.path.join(ROOT, "roles", "ROLE_%s.md" % role)
    n1, t1 = pick_line(hp)
    n2, t2 = pick_line(rp)
    print("[5] ATTESTATION AGENT_EXECUTION_PROMPT.md line %d  |  ROLE_%s.md line %d" % (n1, role, n2))
    print("      EXPECTED (do NOT give to the agent; keep it to verify the report):")
    print("      %d: %s" % (n1, t1))
    print("      %d: %s" % (n2, t2))

    # 6 -- brief
    tpl = io.open(os.path.join(ROOT, "roles", "BRIEF_TEMPLATE.md"), encoding="utf-8").read()
    b = (tpl.replace("<program>", prog).replace("<host>", host).replace("<role>", role)
            .replace("checklist sections <...>", "checklist sections: " + SLICE[role])
            .replace("<N1>", str(n1)).replace("<N2>", str(n2)))
    bp = os.path.join(bd, "BRIEF_%s_%s.md" % (role, host))
    # 6 -- BRIEF. NEVER OVERWRITE AN EXISTING BRIEF.
    # Re-running `open_lane.py` on a LIVE lane must not overwrite that lane's brief with the
    # blank template while the agent is running. If the file exists we do NOT write.
    # Use `--check` for diagnosis.
    if CHECK:
        print("[6] BRIEF       --check mode: brief NOT written (diagnosis only).")
        return
    if os.path.exists(bp) and not FORCE:
        print("[6] BRIEF       WARNING: ALREADY EXISTS, NOT overwritten: %s" % os.path.relpath(bp, BASE))
        age = subprocess.run(["date", "-r", bp, "+%Y-%m-%d %H:%M"],
                             capture_output=True, text=True).stdout.strip()
        print("                written: %s" % age)
        print("                The lane may be RUNNING -- overwriting would pull the rug from under the agent.")
        print("                To regenerate: --force  |  to only look: --check")
        return

    io.open(bp, "w", encoding="utf-8").write(b)
    print("[6] BRIEF       written: %s  (FILL IN the <> placeholders)" % os.path.relpath(bp, BASE))

    # 6b -- LANE CHECKLIST. The SubagentStop lane-gate hook catches the unticked boxes of
    # this file (completion bias). Copy the template per lane; the agent ticks it as work
    # progresses. If a box remains, the hook sends the agent back.
    tpl_cl = os.path.join(ROOT, "checklists", "CHECKLIST_%s.md" % role)
    lane_cl = os.path.join(bd, "LANE_CHECKLIST_%s_%s.md" % (role, host))
    if os.path.exists(tpl_cl) and (not os.path.exists(lane_cl) or FORCE):
        txt = io.open(tpl_cl, encoding="utf-8").read().replace("<host>", host).replace("<package>", host)
        io.open(lane_cl, "w", encoding="utf-8").write(txt)
        print("      LANE CHECKLIST: %s  (the agent ticks it as work progresses)"
              % os.path.relpath(lane_cl, BASE))
    elif os.path.exists(lane_cl):
        print("      LANE CHECKLIST already exists: %s" % os.path.relpath(lane_cl, BASE))
    sk = _role_skills(role)
    print("      REQUIRED SKILL SET (from ROLE_%s.md -- put THESE in the brief, do not invent):" % role)
    for x in sk["role_md"]:
        print("        " + x)
    if not sk["role_md"]:
        print("        (no required set defined in the role file)")
    if sk["skill_map"]:
        print("      SKILL_MAP rows for this role:")
        for x in sk["skill_map"][:6]:
            print("        " + x)

    # 7 -- budget
    print("[7] BUDGET")
    r = subprocess.run([sys.executable, os.path.join(ROOT, "lanes", "agent_budget.py"), bp],
                       capture_output=True, text=True)
    for l in r.stdout.strip().split("\n")[-2:]:
        print("      " + l)
    if r.returncode != 0:
        die("opening budget exceeds the 20k ceiling -- shrink the brief")
    print("\nLANE MAY BE OPENED -- use this spawn call EXACTLY, do not improvise:")
    print('    subagent_type: "%s-agent"' % role)
    print('    description:   "%s - %s"' % (role, host))
    print('    model:         "sonnet"')
    print("  STOP: do NOT open a hunting lane with `general-purpose` -- it shows up unnamed on the")
    print("     board and the gates in the role definition (no sub-agents, three gates, tool permission) do not apply.")
    print("     If the role type is not registered, first run `python3 lanes/gen_agents.py`.")


if __name__ == "__main__":
    main()
