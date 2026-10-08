#!/usr/bin/env python3
"""
priority_board.py <domains.txt> <base_dir> [crown_jewels.txt] [sweep.log]

Merges the priority_<DATE>.tsv of EVERY root in a sweep into ONE prioritized host
list. run_pipeline.sh produces one table per root; the step that merges the roots was
done by hand until now.

Why a script:
  - The same host shows up in the tables of several roots (hosts named in scope.txt
    are exempt from the target-ownership filter; one API host was listed in the runs
    of two different roots). Merging by hand either double counts or drops one.
  - A root can hold more than one priority_*.tsv (a run that was cancelled and
    restarted). `ls | head -1` picks the OLDEST -- that happened once and a root
    showed 11 hosts instead of 30. Here the DATE in .pipeline_state is always used;
    file-name ordering is never trusted.
  - When an Imperva/WAF-style device answers on every port, the ODDPORT signal becomes
    meaningless and pushes marketing pages up. Hosts over the threshold are flagged.

Output:
  stdout -- TSV: rank, score, raw, signal, host, status, ports, title, tech, roots, note
  stderr -- roots read + COVERAGE STATEMENT
  file   -- <program dir>/COVERAGE_STATEMENT.md (program-specific, NOT in <base> --
            fix: it used to be a shared path and the next program's run overwrote the previous one)

Why a COVERAGE STATEMENT: the board is NOT "the whole scope", and counting that by
hand every time depended on a prose rule -- prose rules were forgotten three times in
this project. Now the script prints the numbers. What it cannot count it writes as
"unknown"; it does not guess.
"""
import sys, os, glob, re

PORT_ARTIFACT_THRESHOLD = 20   # this many open ports = a firewall is answering on all of them


def latest_priority(root_dir):
    """Take DATE from .pipeline_state; otherwise fall back to the file with the NEWEST mtime.
    NEVER trust file-name ordering (head -1 returns the oldest)."""
    state = os.path.join(root_dir, ".pipeline_state")
    date = None
    if os.path.isfile(state):
        for line in open(state, encoding="utf-8", errors="replace"):
            if line.startswith("DATE="):
                date = line.strip().split("=", 1)[1]
    if date:
        p = os.path.join(root_dir, "triage", f"priority_{date}.tsv")
        if os.path.isfile(p):
            return p
    cands = glob.glob(os.path.join(root_dir, "triage", "priority_*.tsv"))
    if not cands:
        return None
    return max(cands, key=os.path.getmtime)


def _wc(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return sum(1 for _ in f)
    except OSError:
        return None


def _date_of(root_dir):
    st = os.path.join(root_dir, ".pipeline_state")
    try:
        for line in open(st, encoding="utf-8", errors="replace"):
            if line.startswith("DATE="):
                return line.strip().split("=", 1)[1]
    except OSError:
        pass
    return None


def _dated(root_dir, *parts):
    """Builds the EXACT name <root>/<sub>/<prefix>_<DATE>.<ext>.

    Do NOT use glob: the pattern 'alive_*.txt' also matches alive_raw_*, alive_scan_*
    and alive_scan_suspicious_*, and picking by mtime then counts the wrong file
    (field lesson: a root showed 7 hosts instead of 22). The priority_*.tsv version of
    the same bug is the reason this script exists; do not repeat it here.
    """
    date = _date_of(root_dir)
    if not date:
        return None
    *sub, name = parts
    prefix, ext = name.rsplit(".", 1)
    path = os.path.join(root_dir, *sub, f"{prefix}_{date}.{ext}")
    return path if os.path.isfile(path) else None


def coverage_statement(roots, base, domains_file, log_file, used_roots):
    """Mechanically counts what the board does NOT contain. What it cannot count it writes as 'unknown'."""
    L = []
    A = L.append
    A("# COVERAGE STATEMENT")
    A("")
    A("This board is **not the whole scope**. Every line below was produced by counting; nothing is guessed.")
    A("")

    # -- mobile --
    apps = os.path.join(os.path.dirname(os.path.abspath(domains_file)), "apps.txt")
    if os.path.isfile(apps):
        ids = [l.strip() for l in open(apps) if l.strip()]
        ios = [i for i in ids if re.fullmatch(r"[Ii]?d?\d{6,}", i.replace(" ", ""))]
        android = [i for i in ids if i not in ios]
        processed = 0
        for r in roots:
            processed += len(glob.glob(os.path.join(base, r, "mobile*", "*", "")))
        A(f"## MOBILE -- {len(ids)} assets declared")
        A(f"- **{len(ios)} iOS** -> NO TOOL. The mobile recon script only downloads Android packages.")
        A(f"- **{len(android)} Android** -> processed: **{processed}**")
        if processed == 0:
            A("  - WARNING: `APK_PACKAGES` was not passed. The mobile surface was not touched at all.")
        if len(android) > 3:
            A(f"  - WARNING: default limit `MOBILE_MAX_PKGS=3` -- only 3 of {len(android)} packages are processed.")
        with_space = [i for i in android if " " in i]
        if with_space:
            A(f"  - WARNING: package id containing a space (breaks in apkeep): {', '.join(with_space)}")
        A("- **Verify the publisher** of any automatically found package (a look-alike APK may belong to someone else).")
    else:
        A("## MOBILE -- unknown")
        A(f"- `apps.txt` not found ({apps}). Unknown whether there are mobile assets.")
    A("")

    # -- not alive / dropped --
    dead = foreign = oos = pq = 0
    for r in roots:
        d = os.path.join(base, r)
        ins = _dated(d, "subdomains", "resolved_inscope.txt")
        al = _dated(d, "triage", "alive.txt")
        if ins and al:
            n_ins = _wc(ins) or 0
            try:
                uniq = {re.sub(r"[:/].*", "", re.sub(r"^[a-z]+://", "", l.strip()))
                        for l in open(al, encoding="utf-8", errors="replace") if l.strip()}
            except OSError:
                uniq = set()
            dead += max(0, n_ins - len(uniq))
        for nm in ("resolved_foreign.txt", "resolved_preemptive_oos.txt", "promote_queue.txt"):
            f = _dated(d, "subdomains", nm)
            n = (_wc(f) or 0) if f else 0
            if nm.startswith("resolved_foreign"): foreign += n
            elif nm.startswith("resolved_pre"):   oos += n
            else:                                  pq += n

    # -- wildcard DNS --
    wz_top = wh_top = 0
    wz_roots = []
    for r in roots:
        zf = os.path.join(base, r, "wildcard_zones.txt")
        hf = os.path.join(base, r, "wildcard_hosts.txt")
        if os.path.isfile(zf):
            n = _wc(zf) or 0
            if n:
                wz_top += n; wz_roots.append(r)
                wz_roots_ips = [l.strip() for l in open(zf, encoding="utf-8", errors="replace") if l.strip()]
        if os.path.isfile(hf):
            wh_top += _wc(hf) or 0
    A("## WILDCARD DNS")
    if not any(os.path.isfile(os.path.join(base, r, "wildcard_zones.txt")) for r in roots):
        A("- WARNING: **not scanned.** `wildcard_guard.py <root> --write` was not run, so")
        A("  resolution counts may be inflated and we do not know it.")
    elif wz_top == 0:
        A("- No wildcard zones -- the \"resolved\" signal is reliable.")
    else:
        A(f"- **{wz_top} wildcard zones**, **{wh_top} hosts** resolve ONLY thanks to a wildcard.")
        A(f"  Affected roots: {', '.join(wz_roots)}")
        A("  These hosts were not deleted but cannot be counted as \"existing\"; look at httpx output, not DNS.")
        A("  For a wildcard behind a CDN the distinguishing signal is the response BODY")
        A("  (CloudFront \"ERROR: The request could not be satisfied\" = no distribution).")
    A("")

    A("## HOSTS NOT ON THE BOARD")
    A(f"- **{dead}** hosts resolved but did not answer httpx -> not on the board.")
    A("  - \"not in naabu\" != \"not alive\". Send one curl to 443 for each, and add any that answer to the table.")
    A(f"- **{foreign}** hosts do not belong to the target (another apex) -> `resolved_foreign_*`")
    A(f"- **{oos}** hosts dropped by the OOS deny list -> `resolved_preemptive_oos_*`")
    A(f"- **{pq}** apex in the promote-queue, each needs a decision")
    A("")

    # -- content discovery: PENDING_DECISIONS is authoritative --
    did_not_run = empty = unknown = 0
    for r in roots:
        pend = _dated(os.path.join(base, r), "PENDING_DECISIONS.tsv")
        if not pend:
            unknown += 1
            continue
        txt = open(pend, encoding="utf-8", errors="replace").read()
        if "CONTENT_DISCOVERY_NOT_RUN" in txt: did_not_run += 1
        elif "CONTENT_DISCOVERY_EMPTY" in txt:   empty += 1
        else:                                   unknown += 1
    A("## CONTENT DISCOVERY")
    A(f"- **{did_not_run}/{len(roots)}** roots: the module did not run at all (sweep default)")
    A(f"- **{empty}/{len(roots)}** roots: it ran but returned 0 results (verify baseline/WAF calibration)")
    if unknown:
        A(f"- **{unknown}/{len(roots)}** roots: status unknown (PENDING_DECISIONS unreadable)")
    A("- So the board says \"which host\", it does NOT say \"which path on that host\".")
    A("")

    # -- module flags: read the log if present, otherwise say unknown --
    A("## MODULES THAT DID NOT RUN")
    if log_file and os.path.isfile(log_file):
        txt = open(log_file, encoding="utf-8", errors="replace").read()
        # NOTE: these markers match the messages printed by recon/run_pipeline.sh
        # ("Module 3 ... OFF", "Module 4b ... will be SKIPPED"); keep them in sync.
        for label, marker in (("DNS wordlist bruteforce", "Module 1c"),
                              ("ferox content discovery", "Module 3"),
                              ("arjun parameter mining", "Module 5"),
                              ("cloud bucket enum", "Module 9a"),
                              ("authenticated crawl (session)", "Module 4b")):
            if marker in txt and (" OFF" in txt or "SKIPPED" in txt):
                lines_ = [l for l in txt.splitlines() if marker in l]
                state = "OFF" if lines_ and " OFF" in lines_[0] else (
                        "SKIPPED" if lines_ and "SKIPPED" in lines_[0] else "unknown")
                A(f"- {label}: **{state}**")
    else:
        A("- unknown -- no sweep log was given. Pass `sweep.log` as the 4th argument.")
    A("")

    # -- counters --
    dec = cand = 0
    for r in roots:
        st = os.path.join(base, r, ".pipeline_state")
        if not os.path.isfile(st):
            continue
        for line in open(st, encoding="utf-8", errors="replace"):
            if line.startswith("DECISIONS_PENDING="):
                dec += int(line.strip().split("=")[1] or 0)
            elif line.startswith("FINDING_CANDIDATES="):
                cand += int(line.strip().split("=")[1] or 0)
    # -- wildcard inflation among finding candidates --
    # MANY candidates resolving to the same IP set = one wildcard DNS record, not that
    # many separate findings. Most candidates can be one
    # *.sub.internal.example.com wildcard (any made-up name resolves to the same IPs).
    # Printing the raw count would give the impression of that many findings.
    from collections import Counter
    ipsets = Counter()
    total_cand = 0
    for r in roots:
        f = _dated(os.path.join(base, r), "FINDING_CANDIDATES.tsv")
        if not f:
            continue
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                next(fh, None)
                for line in fh:
                    c = line.rstrip("\n").split("\t")
                    if len(c) >= 3 and c[0] == "INTERNAL_IP":
                        total_cand += 1
                        ipsets[",".join(sorted(c[2].split(",")))] += 1
        except OSError:
            pass
    if total_cand:
        inflated = [(k, v) for k, v in ipsets.items() if v >= 20]
        inflated_n = sum(v for _, v in inflated)
        A("## FINDING CANDIDATES -- do not trust the raw count")
        A(f"- **{total_cand}** INTERNAL_IP candidates, **{len(ipsets)}** distinct IP sets")
        if inflated:
            A(f"- WARNING: **{inflated_n}** candidates share only **{len(inflated)}** IP sets "
              f"-> most likely **wildcard DNS**, NOT that many separate findings.")
            for k, v in sorted(inflated, key=lambda x: -x[1])[:3]:
                A(f"  - {v} candidates -> `{k}`")
            A(f"- Genuinely distinct-looking: **{total_cand - inflated_n}**")
            A("- Verify: does a made-up subdomain resolve in that zone?")
        else:
            A("- No sign of wildcard inflation (no IP set repeats across 20+ candidates).")
        A("")

    A("## PENDING DECISIONS")
    A(f"- **{dec}** rows awaiting a decision -- resolve BEFORE using the board")
    A(f"- **{cand}** finding candidates -- straight to the finding validator, without holding up the hunt")
    A("")
    A(f"_Roots read: {len(used_roots)}/{len(roots)}_")

    return "\n".join(L) + "\n"


def main():
    if len(sys.argv) < 3:
        print("usage: priority_board.py <domains.txt> <base_dir> [crown_jewels.txt] [sweep.log]")
        sys.exit(1)
    domains_file, base = sys.argv[1], sys.argv[2]
    crown = set()
    if len(sys.argv) > 3 and os.path.isfile(sys.argv[3]):
        crown = {l.strip().lower() for l in open(sys.argv[3]) if l.strip() and not l.startswith("#")}

    roots = [l.strip() for l in open(domains_file) if l.strip()]
    hosts = {}
    missing, used = [], []

    for r in roots:
        rd = os.path.join(base, r)
        pf = latest_priority(rd)
        if not pf:
            missing.append(r)
            continue
        used.append((r, os.path.basename(pf)))
        with open(pf, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                c = line.rstrip("\n").split("\t")
                if len(c) < 8:
                    continue
                _, score, sig, host, status, ports, title, tech = c[:8]
                try:
                    score = int(score)
                except ValueError:
                    continue
                host = host.strip().lower()
                nports = len([p for p in ports.split(",") if p.strip()])
                e = hosts.get(host)
                if e is None:
                    hosts[host] = {
                        "score": score, "sig": set(sig.split("+")) - {"-"},
                        "status": set(status.split(",")), "nports": nports,
                        "title": title, "tech": tech, "roots": {r},
                    }
                else:
                    # same host under several roots: keep the highest score, merge the signals
                    e["score"] = max(e["score"], score)
                    e["sig"] |= set(sig.split("+")) - {"-"}
                    e["status"] |= set(status.split(","))
                    e["nports"] = max(e["nports"], nports)
                    e["roots"].add(r)
                    if len(title) > len(e["title"]):
                        e["title"] = title
                    if len(tech) > len(e["tech"]):
                        e["tech"] = tech

    rows = []
    for host, e in hosts.items():
        notes = []
        adj = e["score"]
        if e["nports"] > PORT_ARTIFACT_THRESHOLD and "ODDPORT" in e["sig"]:
            adj -= 1
            notes.append(f"PORT_ARTIFACT({e['nports']}p)")
        if host in crown:
            adj += 5
            notes.append("POLICY_CRITICAL")
        if len(e["roots"]) > 1:
            notes.append("MULTI_ROOT")
        rows.append((adj, e["score"], host, e, notes))

    rows.sort(key=lambda x: (-x[0], -x[1], x[2]))

    print("#\tscore\traw\tsignal\thost\tstatus\tports\ttitle\ttech\troots\tnote")
    for i, (adj, raw, host, e, notes) in enumerate(rows, 1):
        print("\t".join([
            str(i), str(adj), str(raw),
            "+".join(sorted(e["sig"])) or "-",
            host,
            ",".join(sorted(e["status"])),
            str(e["nports"]),
            e["title"][:60],
            e["tech"][:40],
            ",".join(sorted(e["roots"])),
            ";".join(notes),
        ]))

    sys.stderr.write(f"\n[+] read {len(used)}/{len(roots)} roots, {len(hosts)} unique hosts\n")
    for r, f in used:
        sys.stderr.write(f"      {r:<24} {f}\n")
    if missing:
        sys.stderr.write(f"[!] {len(missing)} roots WITHOUT a priority table "
                         f"(did not run or was cut short): {', '.join(missing)}\n")

    log_file = sys.argv[4] if len(sys.argv) > 4 else None
    statement = coverage_statement(roots, base, domains_file, log_file, [r for r, _ in used])
    out_md = os.path.join(os.path.dirname(domains_file), "COVERAGE_STATEMENT.md")
    try:
        with open(out_md, "w", encoding="utf-8") as f:
            f.write(statement)
        sys.stderr.write(f"\n[+] coverage statement: {out_md}\n")
    except OSError as e:
        sys.stderr.write(f"\n[!] could NOT write the coverage statement ({e}) -- shown below:\n")
    sys.stderr.write("\n" + statement)


if __name__ == "__main__":
    main()
