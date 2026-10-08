#!/usr/bin/env python3
"""board_gen.py -- builds the three-list board seed from a real inventory.

Design: the board answers "look again / never looked at / done", ordered from
important to unimportant, 3-4 words per row. No detail on the board itself.

Input : a worklist TSV (columns: tier, score, status, host, reason) plus the
        manual overrides below
Output: board_seed.json (JSON on stdout) -> embedded into the board page

Usage: python3 board/board_gen.py <worklist.tsv> <program> > board_seed.json
"""
import csv, io, json, os, sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TIER_ORD = {"1-MONEY": 0, "2-PORTAL": 1, "3-CHAIN": 2, "4-INTERNAL": 3, "5-OTHER": 4}
TIER_W = {"1-MONEY": "money", "2-PORTAL": "portal", "3-CHAIN": "chain",
          "4-INTERNAL": "internal system", "5-OTHER": ""}
# Canonical status vocabulary: deep | probe | revisit | "" (untouched)

# Manual closures/notes: host -> (status, 3-4 word reason). Sample data only.
OVERRIDE = {
    "rewards.example.com":     ("revisit", "finding in validator"),
    "api.example.com":         ("probe",   "2 prefixes mapped"),
    "issuer.example.com":      ("probe",   "authflow running"),
    "portal.example.com":      ("revisit", "mapped, not hunted"),
    "docs.example.com":        ("probe",   "only CORS checked"),
    "issuer-test.example.net": ("deep",    "backend is dead"),
    "sso.example.com":         ("deep",    "not a real backend"),
    "www.example.org":         ("",        "waiting for login"),
}


def short(reason, tier):
    g = (reason or "").lower()
    if "wall" in g:
        return "walled"
    if "unclassified" in g or "to review" in g:
        return "unclassified"
    if "auth provider" in g or "redirect" in g:
        return "behind SSO"
    return TIER_W.get(tier, "")


def main():
    wl, prog = sys.argv[1], sys.argv[2]
    rows, seen = [], set()
    with io.open(wl, encoding="utf-8") as fh:
        for r in csv.DictReader(fh, delimiter="\t"):
            h = (r.get("host") or "").strip()
            if not h or h in seen:
                continue
            seen.add(h)
            tier = (r.get("tier") or "5-OTHER").strip()
            try:
                score = int(r.get("score") or 0)
            except ValueError:
                score = 0
            st, w = OVERRIDE.get(h, ("", short(r.get("reason"), tier)))
            rows.append({"s": st, "h": h, "w": w, "t": tier,
                         "c": (r.get("status") or "").strip(),
                         "_t": TIER_ORD.get(tier, 9), "_s": -score})

    # hosts not in the worklist but added by hand
    for h, (st, w) in OVERRIDE.items():
        if h not in seen:
            rows.append({"s": st, "h": h, "w": w, "t": "2-PORTAL", "c": "",
                         "_t": 1, "_s": 0})

    # importance order: tier, then score
    rows.sort(key=lambda r: (r["_t"], r["_s"], r["h"]))
    out = [{"ord": i, "t": r["t"], "h": r["h"], "c": r["c"],
            "w": r["w"], "s": r["s"]} for i, r in enumerate(rows)]
    sys.stderr.write("total %d - deep %d | probe %d | revisit %d | untouched %d\n" % (
        len(out), *[sum(1 for r in out if r["s"] == k)
                    for k in ("deep", "probe", "revisit", "")]))
    print(json.dumps(out, ensure_ascii=False, indent=0))


if __name__ == "__main__":
    main()
