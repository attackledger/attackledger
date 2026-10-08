#!/usr/bin/env python3
"""priority_board_to_tierboard.py -- converts the BOARD.tsv + COVERAGE_STATEMENT.md
produced by recon/priority_board.py into the config.json expected by the canonical
Tier Board generator (tier_board_gen.py + TIER_BOARD_TEMPLATE.html).

Step 1 of 2: BOARD.tsv -> config.json. Step 2:
    python3 board/tier_board_gen.py <config.json> <output.html>

Input is program-agnostic: it works with whatever root domains appear (tier = first
value of the "roots" column). There is no "to-do"/pack split at this stage because a
raw post-recon priority board has no role pipeline opened on any host yet, so tier and
pack simply carry the same value (so the template's "pack" grouping mode is not empty).

Expected BOARD.tsv columns (legacy Turkish names are still accepted):
  score, signal, host, status, title, tech, roots

The COVERAGE_STATEMENT.md phrases matched below must stay in sync with the text
emitted by recon/priority_board.py.

Usage:
  python3 priority_board_to_tierboard.py <BOARD.tsv> <program_handle> <config.json_out> \
      [COVERAGE_STATEMENT.md] [total_root_count]
"""
import csv, io, json, os, re, sys
from collections import defaultdict

PALETTE = ["var(--t1)", "var(--t2)", "var(--t3)", "var(--t4)", "var(--t5)"]


def slug(s):
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:40] or "d"


def md_inline(s):
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    return s


def col(r, *names):
    """First non-empty value among the given column names (supports legacy names)."""
    for n in names:
        v = r.get(n)
        if v not in (None, ""):
            return v
    return ""


def parse_coverage_gaps(path):
    """Turn the '## Heading' sections of COVERAGE_STATEMENT.md into gaps[] rows.
    Writes no program-specific text; it renders whatever the file contains."""
    if not path or not os.path.isfile(path):
        return [], ""
    text = io.open(path, encoding="utf-8").read()
    sections = re.split(r"(?m)^## ", text)[1:]
    gaps = []
    for sec in sections:
        lines = sec.strip().split("\n")
        title = lines[0].strip()
        body = [l.strip() for l in lines[1:] if l.strip()]
        dd = "<br>".join(md_inline(l.lstrip("-").strip()) for l in body) or "(no lines in this section)"
        fail = bool(re.search(r"unknown|did not run|not scanned|not found|⚠️|🔴", sec, re.I))
        gaps.append({"dt": title, "dd": dd, "fail": fail})
    return gaps, text


def extract_coverage_numbers(text):
    """Best-effort regex extraction of a few known counts for the funnel steps.
    Returns None on no match and the caller skips that step -- no invented numbers."""
    def find(pat):
        m = re.search(pat, text)
        return m.group(1) if m else None
    return {
        "foreign": find(r"\*\*(\d+)\*\* hosts? do(?:es)? not belong to the target"),
        "oos": find(r"\*\*(\d+)\*\* hosts? dropped by the OOS deny list"),
        "no_response": find(r"\*\*(\d+)\*\* hosts? resolved but did not answer httpx"),
        "wildcard_only": find(r"\*\*(\d+) hosts?\*\* resolve ONLY thanks to a wildcard"),
        "promote_queue": find(r"\*\*(\d+)\*\* apex(?:es)? in the promote-queue"),
        "decisions_pending": find(r"\*\*(\d+)\*\* rows? awaiting a decision"),
        "candidates": find(r"\*\*(\d+)\*\* .*?[Cc]andidate"),
    }


def main():
    board_tsv, program = sys.argv[1], sys.argv[2]
    out_json = sys.argv[3]
    coverage_path = sys.argv[4] if len(sys.argv) > 4 else None
    total_roots = sys.argv[5] if len(sys.argv) > 5 else None

    rows_by_dom = defaultdict(list)
    with io.open(board_tsv, encoding="utf-8") as fh:
        for r in csv.DictReader(fh, delimiter="\t"):
            host = (r.get("host") or "").strip()
            if not host:
                continue
            roots = col(r, "roots").strip()
            dom = roots.split(",")[0].strip() if roots else "other"
            rows_by_dom[dom].append(r)

    doms_sorted = sorted(
        rows_by_dom.keys(),
        key=lambda d: (-max(int(col(r, "score") or 0) for r in rows_by_dom[d]), -len(rows_by_dom[d])),
    )

    tiers, rows = [], []
    all_scores = []
    for i, dom in enumerate(doms_sorted):
        k = slug(dom)
        rs = rows_by_dom[dom]
        maxscore = max(int(col(r, "score") or 0) for r in rs)
        tiers.append({"k": k, "name": dom, "color": PALETTE[i % len(PALETTE)],
                      "why": f"{len(rs)} hosts | top score {maxscore} | never looked at"})
        for r in sorted(rs, key=lambda r: -int(col(r, "score") or 0)):
            score = int(col(r, "score") or 0)
            all_scores.append(score)
            rows.append({
                "t": k, "p": k,
                "h": r.get("host", ""),
                "c": r.get("status", ""),
                "s": str(score),
                "g": col(r, "signal"),
                "b": col(r, "title")[:80],
                "k": (r.get("tech") or "")[:60],
                "w": 1, "r": "",
                "n": 0, "cp": [], "sz": "", "loc": "",
            })

    packs = [{"k": t["k"], "name": t["name"], "color": t["color"], "auth": "", "why": t["why"]}
              for t in tiers]

    total_kept = len(rows)
    gaps, coverage_text = parse_coverage_gaps(coverage_path)
    nums = extract_coverage_numbers(coverage_text) if coverage_text else {}

    funnel = [{"n": total_roots or str(len(tiers)), "lab": "root domains",
               "why": f"scope.txt/domains.txt - {program} org-wide"}]
    dropped_bits = []
    if nums.get("foreign"):
        dropped_bits.append(f"{nums['foreign']} foreign apex")
    if nums.get("oos"):
        dropped_bits.append(f"{nums['oos']} OOS (deny-wins)")
    if dropped_bits:
        funnel.append({"n": "+".join(re.findall(r"\d+", " ".join(dropped_bits))),
                        "lab": "dropped", "why": ", ".join(dropped_bits)})
    uncertain_bits = []
    if nums.get("wildcard_only"):
        uncertain_bits.append(f"{nums['wildcard_only']} wildcard-only")
    if nums.get("no_response"):
        uncertain_bits.append(f"{nums['no_response']} no response")
    if uncertain_bits:
        funnel.append({"n": "+".join(re.findall(r"\d+", " ".join(uncertain_bits))),
                        "lab": "uncertain", "why": ", ".join(uncertain_bits)})
    funnel.append({"n": str(total_kept), "lab": "on the board (live+scored)",
                    "why": "priority_board.py output - no role pipeline opened on any of them yet, raw priority order"})

    # score-distribution warning -- computed from the data, never invented
    warns = []
    if all_scores:
        maxs = max(all_scores)
        at_max = sum(1 for s in all_scores if s == maxs)
        second = max((s for s in all_scores if s != maxs), default=None)
        at_second = sum(1 for s in all_scores if s == second) if second is not None else 0
        warns.append({
            "title": "The score threshold alone may not discriminate",
            "body": (f"Of {len(all_scores)} hosts, {at_second} have score={second} and "
                     f"{at_max} have score={maxs} (highest). If the distribution is flat "
                     f"(most hosts share a score), read root domain + signal class together."),
        })
    if nums.get("oos") or nums.get("promote_queue"):
        body = []
        if nums.get("oos"):
            body.append(f"{nums['oos']} hosts dropped by the OOS list, NOT on the board.")
        if nums.get("promote_queue"):
            body.append(f"{nums['promote_queue']} apex domains still in the \"promote-queue\" (undecided).")
        warns.append({"title": "OOS deny-wins applied", "body": " ".join(body), "color": "var(--warn)"})

    cfg = {
        "title": f"{program} Tier Board",
        "h1": f"{program} - Attack Surface Tier Board",
        "sub": f"{len(tiers)} root domains (surviving) | {total_kept} live/scored hosts | recon done, hunting state is marked on the board",
        "hdrmeta": f"Program: <code>{program}</code> | Source: priority_board.py",
        "funnel": funnel,
        "warns": warns,
        "gaps": gaps,
        "gaps_intro": "Verbatim from COVERAGE_STATEMENT.md - counted, not guessed.",
        "tiers": tiers,
        "packs": packs,
        "short": {},
        "rows": rows,
    }
    json.dump(cfg, open(out_json, "w"), ensure_ascii=False)
    print(f"{len(rows)} rows, {len(tiers)} tiers -> {out_json}", file=sys.stderr)


if __name__ == "__main__":
    main()
