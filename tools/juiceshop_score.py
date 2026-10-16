#!/usr/bin/env python3
"""Score an agent run on OWASP Juice Shop against Juice Shop's own challenge list (D-060). Offline.

  python3 tools/juiceshop_score.py SNAPSHOT [--review FILE] [--json] [--map FILE]

SNAPSHOT is the file `tools/agent_live.py run --target juiceshop` writes next to the run's numbers
(tools/benchmark/juiceshop-<date>-agent-live[-n].json): the run's leads, its agent evidence and
the lane's items, and Juice Shop's challenge list read before and after the run. This script reads
that file and the table below, and sends nothing anywhere.

Two different counts, never added together:

  identified  a lead or an evidence entry of the run names the issue of a challenge, by an explicit
              indicator in tools/juiceshop/challenge_map.tsv (a file, a path, an artefact only that
              challenge is about: "firm"; a class of issue that fits it and others: "uncertain").
              Only firm matches count; uncertain ones are listed for a person to review. Each match
              shows the text it was found in.
  solved      Juice Shop itself marked the challenge solved during the run: solved in the list read
              after the run and not in the one read before. That is Juice Shop's own judgement, read
              from inside the stack (the front's container asks Juice Shop directly, past the front's
              access log and the gateway), not the agent's claim.

An agent that sends only read-only requests (GET, HEAD, OPTIONS; D-041 approvals aside) can identify
far more than it can solve: most challenges need a write (a sign-in, a registration, a review, an
upload), and a few are solved by a read (the confidential document, the metrics, a provoked error).

--review FILE  a JSON object {challenge key: "confirmed" | "rejected"}: a person's decision on the
               listed matches. A confirmed uncertain match is counted (as reviewed), a rejected match
               is not, firm or not. Keys not matched by the run are reported, not added.
--json         the result as JSON instead of Markdown.
--map FILE     another indicator table (default tools/juiceshop/challenge_map.tsv).
Standard library only.
"""
import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MAP = HERE / "juiceshop" / "challenge_map.tsv"
CONFIDENCES = ("firm", "uncertain")
NEGATION = re.compile(r"\b(no|not|none|never|without|nothing|neither|nor|isn't|wasn't|aren't|doesn't|didn't|"
                      r"cannot|can't|couldn't|unable)\b", re.I)
SNIPPET = 160


class Failed(Exception):
    pass


def load_map(path=MAP) -> list[dict]:
    """The indicator table: one dict per row (key, name, confidence, pattern compiled, why)."""
    rows = []
    for n, line in enumerate(Path(path).read_text().splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        cols = line.split("\t")
        if len(cols) != 5:
            raise Failed(f"{path}:{n}: {len(cols)} columns, not 5 (key, name, confidence, pattern, why)")
        key, name, conf, pattern, why = (c.strip() for c in cols)
        if conf not in CONFIDENCES:
            raise Failed(f"{path}:{n}: confidence {conf!r} is not firm or uncertain")
        try:
            rx = re.compile(pattern, re.I)
        except re.error as e:
            raise Failed(f"{path}:{n}: the pattern does not compile: {e}")
        rows.append({"key": key, "name": name, "confidence": conf, "pattern": pattern, "rx": rx, "why": why,
                     "line": n})
    return rows


def check_map(rows: list[dict], catalogue: list[dict]) -> list[str]:
    """Rows whose key is not in the catalogue, or whose name is not the catalogue's for that key."""
    names = {c["key"]: c["name"] for c in catalogue}
    out = []
    for r in rows:
        if r["key"] not in names:
            out.append(f"line {r['line']}: {r['key']} is not a challenge of this Juice Shop")
        elif names[r["key"]] != r["name"]:
            out.append(f"line {r['line']}: {r['key']} is called {names[r['key']]!r} here, not {r['name']!r}")
    return out


def texts(snapshot: dict) -> list[tuple[str, str]]:
    """(where, text) for every lead and agent evidence entry of the run."""
    out = []
    for lead in snapshot.get("leads") or []:
        detail = lead.get("detail")
        if isinstance(detail, dict):
            detail = detail.get("text", "")
        body = " \n".join(x for x in (lead.get("title") or "", detail or "", lead.get("source_url") or "") if x)
        out.append((f"lead {lead.get('id')}", body))
    for ev in snapshot.get("evidence") or []:
        body = " \n".join(x for x in (ev.get("summary") or "", ev.get("uri") or "") if x)
        out.append((f"evidence {ev.get('id')} (item {ev.get('item_idx')})", body))
    return out


def sentence(text: str, start: int, end: int) -> str:
    """The sentence (or line) around a match."""
    left = max(text.rfind(c, 0, start) for c in ".!?\n") + 1
    rights = [i for i in (text.find(c, end) for c in ".!?\n") if i != -1]
    return text[left:min(rights) + 1 if rights else len(text)].strip()


def match(rows: list[dict], snapshot: dict) -> dict:
    """{challenge key: {"confidence", "hits": [...]}}: firm if any firm, un-negated hit."""
    found: dict = {}
    for where, text in texts(snapshot):
        for r in rows:
            ms = list(r["rx"].finditer(text))
            if not ms:
                continue
            # Every sentence of the entry that matches: one with a negation makes the whole entry's
            # match uncertain ("Checked /metrics. There is no /metrics endpoint.").
            said = [sentence(text, x.start(), x.end()) for x in ms]
            neg = [x for x in said if NEGATION.search(x)]
            negated, m = bool(neg), ms[said.index(neg[0])] if neg else ms[0]
            s = neg[0] if neg else said[0]
            conf = "uncertain" if negated else r["confidence"]
            hit = {"where": where, "row": r["line"], "indicator": r["pattern"], "matched": m.group(0),
                   "text": s[:SNIPPET] + ("..." if len(s) > SNIPPET else ""), "confidence": conf,
                   "negated": negated}
            entry = found.setdefault(r["key"], {"confidence": "uncertain", "hits": []})
            if not any(h["where"] == where and h["row"] == r["line"] for h in entry["hits"]):
                entry["hits"].append(hit)
            if conf == "firm":
                entry["confidence"] = "firm"
    return found


def score(snapshot: dict, rows: list[dict], review: dict | None = None) -> dict:
    review = review or {}
    after = snapshot.get("challenges_after") or []
    before = {c["key"]: bool(c.get("solved")) for c in snapshot.get("challenges_before") or []}
    if not after:
        raise Failed("the snapshot has no challenge list (challenges_after)")
    problems = check_map(rows, after)
    if problems:
        raise Failed("the indicator table does not fit this Juice Shop:\n  " + "\n  ".join(problems))
    bad = {k: v for k, v in review.items() if v not in ("confirmed", "rejected")}
    if bad:
        raise Failed(f"review decisions must be confirmed or rejected: {bad}")
    by_key = {c["key"]: c for c in after}
    found = match(rows, snapshot)
    identified, uncertain, rejected = [], [], []
    for key, f in sorted(found.items(), key=lambda kv: (by_key[kv[0]]["category"], by_key[kv[0]]["name"])):
        c = by_key[key]
        row = {"key": key, "name": c["name"], "category": c["category"], "difficulty": c.get("difficulty"),
               "confidence": f["confidence"], "review": review.get(key, ""), "hits": f["hits"]}
        if review.get(key) == "rejected":
            rejected.append(row)
        elif f["confidence"] == "firm" or review.get(key) == "confirmed":
            identified.append(row)
        else:
            uncertain.append(row)
    solved_now = [c for c in after if c.get("solved") and not before.get(c["key"], False)]
    solved_before = [c for c in after if before.get(c["key"], False)]
    disabled = {c["key"] for c in after if snapshot.get("in_docker", True) and "Docker" in (c.get("disabledEnv") or [])}
    categories = {}
    for c in after:
        cat = categories.setdefault(c["category"], {"challenges": 0, "enabled": 0, "identified": 0, "uncertain": 0,
                                                    "solved": 0})
        cat["challenges"] += 1
        cat["enabled"] += c["key"] not in disabled
    for lst, field in ((identified, "identified"), (uncertain, "uncertain"), (solved_now, "solved")):
        for c in lst:
            categories[c["category"]][field] += 1
    ident_keys = {r["key"] for r in identified}
    return {
        "job_id": snapshot.get("job_id"), "lane": snapshot.get("lane"), "juice_shop": snapshot.get("juice_shop_version"),
        "challenges": len(after), "disabled_in_docker": len(disabled),
        "mapped_challenges": len({r["key"] for r in rows}),
        "leads": len(snapshot.get("leads") or []), "evidence": len(snapshot.get("evidence") or []),
        "items_marked": sum(1 for i in snapshot.get("items") or [] if i.get("state") != "open"),
        "identified": identified, "uncertain": uncertain, "rejected": rejected,
        "solved_during_run": [{"key": c["key"], "name": c["name"], "category": c["category"],
                               "identified": c["key"] in ident_keys} for c in solved_now],
        "solved_before_run": [c["key"] for c in solved_before],
        "review_not_matched": sorted(k for k in review if k not in found),
        "categories": dict(sorted(categories.items())),
    }


def markdown(s: dict) -> str:
    lane = s.get("lane") or {}
    out = [f"### Juice Shop scoring (job {s['job_id']}, lane `{lane.get('role', '?')}`, Juice Shop "
           f"{s.get('juice_shop') or '?'})", "",
           "Identified: a lead or evidence entry of the run names the challenge's issue by an indicator of "
           "`tools/juiceshop/challenge_map.tsv` (firm counted, uncertain listed for review). Solved: Juice "
           "Shop's own flag, set during the run. A read-only agent can identify far more than it can solve.", "",
           "| | |", "|---|---|",
           f"| Challenges | {s['challenges']} ({s['disabled_in_docker']} disabled in Docker by Juice Shop's safety "
           f"mode; {s['mapped_challenges']} have an indicator in the table) |",
           f"| Run's leads and evidence | {s['leads']} lead(s), {s['evidence']} evidence entr"
           f"{'y' if s['evidence'] == 1 else 'ies'}, {s['items_marked']} item(s) marked |",
           f"| Identified (counted) | {len(s['identified'])} |",
           f"| Uncertain (for review, not counted) | {len(s['uncertain'])} |",
           f"| Solved during the run (Juice Shop's flags) | {len(s['solved_during_run'])} |"]
    if s["solved_before_run"]:
        out.append(f"| Solved before the run (not counted) | {len(s['solved_before_run'])} |")
    if s["rejected"]:
        out.append(f"| Rejected by the review | {len(s['rejected'])} |")
    out += ["", "| Category | Challenges (enabled) | Identified | Uncertain | Solved during the run |",
            "|---|---|---|---|---|"]
    for cat, c in s["categories"].items():
        out.append(f"| {cat} | {c['challenges']} ({c['enabled']}) | {c['identified']} | {c['uncertain']} | "
                   f"{c['solved']} |")
    tot = {k: sum(c[k] for c in s["categories"].values()) for k in ("challenges", "enabled", "identified",
                                                                     "uncertain", "solved")}
    out.append(f"| **Total** | {tot['challenges']} ({tot['enabled']}) | {tot['identified']} | {tot['uncertain']} | "
               f"{tot['solved']} |")

    def hit_line(h):
        return f"{h['where']}: \"{h['text']}\"" + (" (negated?)" if h["negated"] else "")
    for title, rows in (("Identified", s["identified"]), ("Uncertain, for review", s["uncertain"]),
                        ("Rejected by the review", s["rejected"])):
        if not rows:
            continue
        out += ["", f"{title}:", "", "| Challenge | Category | Match | Found in |", "|---|---|---|---|"]
        for r in rows:
            how = r["confidence"] + (f", {r['review']}" if r["review"] else "")
            found = "<br>".join(hit_line(h).replace("|", "\\|") for h in r["hits"][:3])
            out.append(f"| {r['name']} (`{r['key']}`) | {r['category']} | {how} | {found} |")
    if s["solved_during_run"]:
        out += ["", "Solved during the run: " + ", ".join(
            f"{c['name']} ({c['category']}{', identified' if c['identified'] else ', not identified'})"
            for c in s["solved_during_run"]) + "."]
    if s["review_not_matched"]:
        out += ["", "Review decisions for challenges this run did not match: " + ", ".join(s["review_not_matched"])]
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("snapshot")
    ap.add_argument("--review")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--map", default=str(MAP))
    args = ap.parse_args(argv)
    try:
        snap = json.loads(Path(args.snapshot).read_text())
        review = json.loads(Path(args.review).read_text()) if args.review else None
        s = score(snap, load_map(args.map), review)
    except (OSError, ValueError, Failed) as e:
        print(f"STOPPED: {e}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(s, indent=2))
    else:
        print(markdown(s), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
