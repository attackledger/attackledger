#!/usr/bin/env python3
"""Score an agent run on OWASP Juice Shop against Juice Shop's own challenge list (D-060). Offline.

  python3 tools/juiceshop_score.py SNAPSHOT [SNAPSHOT ...] [--review FILE] [--json] [--map FILE] [--reach FILE]

SNAPSHOT is the file `tools/agent_live.py run --target juiceshop` writes next to the run's numbers
(tools/benchmark/juiceshop-<date>-agent-live[-n].json): the run's leads, its agent evidence and
the lane's items, and Juice Shop's challenge list read before and after the run. This script reads
that file and the two tables below, and sends nothing anywhere. With several snapshots (the lanes of
one run, say), each is scored and then their union: a challenge counts once however many lanes name it.

Two different counts, never added together:

  identified  a lead or an evidence entry of the run names the issue of a challenge, by an explicit
              indicator in tools/juiceshop/challenge_map.tsv (the issue's file, path, parameter or
              behaviour: "firm"; a class of issue that fits it and others: "uncertain"). Only firm
              matches count; uncertain ones are listed for a person to review. Each match shows the
              text it was found in. The table's header gives the rules for sentences that say the
              issue is absent, that only suppose it, for files only listed, and for one issue shared
              by several challenges.
  solved      Juice Shop itself marked the challenge solved during the run: solved in the list read
              after the run and not in the one read before. That is Juice Shop's own judgement, read
              from inside the stack (the front's container asks Juice Shop directly, past the front's
              access log and the gateway), not the agent's claim.

The denominator is tools/juiceshop/reachable.tsv: the challenges enabled in Docker that this lab can
reach offline (no LLM, no blockchain, nothing that lives only on the internet, nothing the lab's front
refuses), each with what observing its issue needs (read: signed out, GET/HEAD/OPTIONS; write: a
state-changing request; account: a session of a user the tester registered) and whether Juice Shop
marks it solved only through its browser page. Identified and solved are both reported against it.

An agent that sends only read-only requests (GET, HEAD, OPTIONS; D-041 approvals aside) can identify
far more than it can solve: most challenges need a write (a sign-in, a registration, a review, an
upload), and a few are solved by a read (the confidential document, the metrics, a provoked error).

--review FILE  a JSON object {challenge key: "confirmed" | "rejected"}: a person's decision on the
               listed matches. A confirmed uncertain match is counted (as reviewed), a rejected match
               is not, firm or not. Keys not matched by the run are reported, not added.
--json         the result as JSON instead of Markdown.
--map FILE     another indicator table (default tools/juiceshop/challenge_map.tsv).
--reach FILE   another reachability table (default tools/juiceshop/reachable.tsv).
Standard library only.
"""
import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MAP = HERE / "juiceshop" / "challenge_map.tsv"
REACH = HERE / "juiceshop" / "reachable.tsv"
CONFIDENCES = ("firm", "uncertain")
REACHES = ("yes", "no-docker", "no-llm", "no-chain", "no-internet", "no-front")
NEEDS = ("read", "write", "account")
SNIPPET = 160

# A sentence ends at . ! or ? followed by white space, or at a line break; "e.g." and "i.e." do not end one.
SENTENCE_END = re.compile(r"[.!?](?=\s|$)|\n")
ABBREVIATIONS = re.compile(r"\b(e\.g|i\.e|etc|vs)\.", re.I)
# Clauses, for the rules that look at the part of a sentence a match is in.
CLAUSE_SPLIT = re.compile(r";|\s[-–—]\s|,\s*(?:but|while|whereas|although|however)\b|\s(?:but|whereas|however)\s", re.I)

NEGATION = re.compile(r"\b(no|not|none|never|without|nothing|neither|nor|isn't|wasn't|aren't|weren't|doesn't|"
                      r"didn't|don't|cannot|can't|couldn't|unable)\b", re.I)
# "should not be web-accessible" says the issue is there.
NORMATIVE = re.compile(r"\b(should|must|ought to|needs? to)\s*$", re.I)
# A negated protection names the issue ("with no authentication"); a negated issue does not.
PROTECTION = (r"auth\w*|log-?in|sign[- ]?in|sessions?|credentials?|current password|password\w*|access control|"
              r"authori[sz]ation|protection|validation|saniti[sz]ation|escaping|output encoding|rate[- ]?limit\w*|"
              r"captcha|csrf(?: token)?|csp|content-security-policy|hsts|strict-transport-security|allow-?list|"
              r"whitelist|signature(?: check)?|integrity check|restrictions?|checks? on")
PROTECTION_AFTER = re.compile(r"^\W*(?:\w+\W+){0,3}?(" + PROTECTION + r")\b", re.I)
PROTECTION_BEFORE = re.compile(r"\b(" + PROTECTION + r")\b(?:\W+\w+){0,3}?\W*$", re.I)
PROTECTION_VERB = re.compile(r"^\s*(required|enforced|checked|validated|verified|needed|applied|compared|set|sent|"
                             r"present|configured)\b", re.I)
NEAR = 80
# "cannot be confirmed", "not yet verified": the agent could not show it, which is speculation, not absence.
NOT_YET_SHOWN = re.compile(r"^(?:cannot|can't|couldn't|could not)\s+be\s+(?:confirmed|demonstrated|tested|observed|"
                           r"verified|done)\b|^not\s+(?:yet\s+)?(?:confirmed|verified|tested|demonstrated)\b", re.I)
QUOTED = re.compile(r"\"[^\"]{0,300}\"|\u201c[^\u201d]{0,300}\u201d")
SPECULATIVE = re.compile(
    r"\b(would|could|might|may|potential(?:ly)?|possibl[ey]|suspect(?:ed)?|presumabl[ey]|unconfirmed|left open|"
    r"warrants?|worth (?:reviewing|testing|checking|investigating))\b"
    r"|\bshould\s+(?:an?|the|any|it|this|that|they|one|such)\b"
    r"|\bif\b[^.;]{0,80}?\b(?:exists?|is present|are present|reachable|available|enabled|vulnerable)\b"
    r"|\b(?:requires?|required|needs?|needed)\b[^.;]{0,60}\bbrowser\b"
    r"|\bcannot be (?:confirmed|demonstrated|tested|observed|verified|done)\b"
    r"|\bnot (?:yet )?(?:confirmed|verified|tested|demonstrated)\b", re.I)
# A file behind a protection: counted where the clause shows it was obtained, not only listed or refused.
OBTAINED = re.compile(r"->\s*2\d\d\b|\b(?:returned|returns|returning|answered|answers|served|serves|gave|gives)\b"
                      r"[^;]{0,60}\b(?:2\d\d|contents?|body|bytes)\b|\bbypass\w*|\bretriev\w*|\bdownload\w*|"
                      r"\bread (?:the|its)\b", re.I)
REFUSED = re.compile(r"->\s*[45]\d\d\b|\b(?:40[0-9]|blocked|forbidden|denied|refused|rejected)\b", re.I)
FILE_NAME = re.compile(r"\b[A-Za-z][\w-]*(?:\.[\w-]+)*\.(?:md|bak|kdbx|ya?ml|pyc|gg|json|pdf|txt|log|tf|stl|key|pub|"
                       r"zip|js|xml)\b", re.I)
LISTING = 3


class Failed(Exception):
    pass


def _rows(path):
    for n, line in enumerate(Path(path).read_text().splitlines(), 1):
        if line.strip() and not line.startswith("#"):
            yield n, line.split("\t")


def load_map(path=MAP) -> list[dict]:
    """The indicator table: one dict per row (key, name, confidence, kind, pattern compiled, why)."""
    rows = []
    for n, cols in _rows(path):
        if len(cols) != 6:
            raise Failed(f"{path}:{n}: {len(cols)} columns, not 6 (key, name, confidence, kind, pattern, why)")
        key, name, conf, kind, pattern, why = (c.strip() for c in cols)
        if conf not in CONFIDENCES:
            raise Failed(f"{path}:{n}: confidence {conf!r} is not firm or uncertain")
        if kind not in ("issue", "obtained") and not re.fullmatch(r"group:[a-z0-9-]+", kind):
            raise Failed(f"{path}:{n}: kind {kind!r} is not issue, obtained or group:NAME")
        try:
            rx = re.compile(pattern, re.I)
        except re.error as e:
            raise Failed(f"{path}:{n}: the pattern does not compile: {e}")
        rows.append({"key": key, "name": name, "confidence": conf, "kind": kind, "pattern": pattern, "rx": rx,
                     "why": why, "line": n})
    return rows


def load_reach(path=REACH) -> dict:
    """The reachability table: {key: {name, reach, needs, solve, browser, source, note}}."""
    out = {}
    for n, cols in _rows(path):
        if len(cols) != 8:
            raise Failed(f"{path}:{n}: {len(cols)} columns, not 8 (key, name, reach, needs, solve, browser, source, "
                         f"note)")
        key, name, reach, needs, solve, browser, source, note = (c.strip() for c in cols)
        if key in out:
            raise Failed(f"{path}:{n}: {key} is listed twice")
        if reach not in REACHES:
            raise Failed(f"{path}:{n}: reach {reach!r} is not one of {', '.join(REACHES)}")
        if reach == "yes":
            if needs not in NEEDS or solve not in NEEDS or browser not in ("yes", "no") or source == "-":
                raise Failed(f"{path}:{n}: a reachable challenge needs read, write or account (needs and solve), "
                             f"browser yes or no, and a source")
        elif (needs, solve, browser) != ("-", "-", "-") or source == "" or (reach != "no-docker" and source == "-"):
            raise Failed(f"{path}:{n}: an unreachable challenge has - for needs, solve and browser, and says why")
        out[key] = {"key": key, "name": name, "reach": reach, "needs": needs, "solve": solve, "browser": browser,
                    "source": source, "note": note, "line": n}
    return out


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


def check_reach(reach: dict, catalogue: list[dict], in_docker=True) -> list[str]:
    """Every challenge once, with the catalogue's name; disabled in Docker exactly when Juice Shop says so."""
    out = check_map(list(reach.values()), catalogue)
    for c in catalogue:
        r = reach.get(c["key"])
        if r is None:
            out.append(f"{c['key']} ({c['name']}) has no row")
        elif in_docker and ("Docker" in (c.get("disabledEnv") or [])) != (r["reach"] == "no-docker"):
            out.append(f"line {r['line']}: {c['key']} is {'' if r['reach'] == 'no-docker' else 'not '}no-docker here, "
                       f"but Juice Shop {'enables' if r['reach'] == 'no-docker' else 'disables'} it in Docker")
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
        summary, uri = ev.get("summary") or "", ev.get("uri") or ""
        # The summary's first sentence is the request with its answer ("GET <uri> -> 403."): the URI is
        # read there, with its status, not again on its own.
        first = summary.split("\n", 1)[0][:300]
        body = summary if uri and uri in first else " \n".join(x for x in (summary, uri) if x)
        out.append((f"evidence {ev.get('id')} (item {ev.get('item_idx')})", body))
    return out


def sentences(text: str) -> list[tuple[int, int]]:
    """(start, end) of each sentence or line of the text."""
    masked = ABBREVIATIONS.sub(lambda m: m.group(0).replace(".", "_"), text)
    out, start = [], 0
    for m in SENTENCE_END.finditer(masked):
        out.append((start, m.end()))
        start = m.end()
    out.append((start, len(text)))
    return [(a, b) for a, b in out if text[a:b].strip()]


def sentence(text: str, start: int, end: int) -> str:
    """The sentence (or line) around a match."""
    for a, b in sentences(text):
        if a <= start < b:
            return text[a:b].strip()
    return text.strip()


def clause(s: str, pos: int) -> tuple[str, int]:
    """The clause of sentence s that holds position pos, and pos within it."""
    start = 0
    for m in CLAUSE_SPLIT.finditer(s):
        if m.start() > pos:
            return s[start:m.start()], pos - start
        start = m.end()
    return s[start:], pos - start


def says_absent(s: str, start: int, end: int) -> bool:
    """The clause around the match says the issue itself is absent: a negation near it that is not a
    negated protection ("no authentication") nor a normative one ("should not be")."""
    c, pos = clause(s, start)
    # A quoted message is the target's words, not the agent's ("SELECTs ... do not have the same number").
    c = QUOTED.sub(lambda q: " " * len(q.group(0)), c)
    for m in NEGATION.finditer(c):
        if m.start() > pos + (end - start) + NEAR or m.end() < pos - NEAR:
            continue
        before, after = c[:m.start()], c[m.end():]
        if NORMATIVE.search(before) or NOT_YET_SHOWN.search(m.group(0) + after):
            continue
        if PROTECTION_AFTER.search(after):
            continue
        if PROTECTION_BEFORE.search(before) and PROTECTION_VERB.search(after):
            continue
        return True
    return False


def obtained(s: str, start: int) -> bool:
    """The clause around the match shows the file was obtained: not only listed with others, not refused."""
    c, _ = clause(s, start)
    if len({x.group(0).lower() for x in FILE_NAME.finditer(c)}) >= LISTING:
        return False
    return bool(OBTAINED.search(c)) and not REFUSED.search(c)


def classify(row: dict, s: str, m: re.Match) -> tuple[str, str]:
    """(confidence, reason) of one match in one sentence. reason is "" for a counted firm match."""
    if says_absent(s, m.start(), m.end()):
        return "uncertain", "absent"
    if row["confidence"] != "firm":
        return "uncertain", "uncertain indicator"
    if SPECULATIVE.search(s):
        return "uncertain", "speculative"
    if row["kind"] == "obtained" and not obtained(s, m.start()):
        return "uncertain", "not obtained"
    return "firm", ""


def match(rows: list[dict], snapshot: dict) -> dict:
    """{challenge key: {"confidence", "hits": [...]}}: firm if any entry has a firm hit for the challenge.

    Within one entry, a sentence that says the issue is absent makes that row's match uncertain ("Checked
    /metrics. There is no /metrics endpoint."); speculative or not-obtained sentences only do not count.
    A firm match through a group:NAME row counts for the group's first challenge in the table only."""
    found: dict = {}
    for where, text in texts(snapshot):
        spans = sentences(text)
        for r in rows:
            hits = []
            for a, b in spans:
                s = text[a:b].strip()
                m = r["rx"].search(s)
                if m:
                    conf, reason = classify(r, s, m)
                    hits.append((conf, reason, s, m))
            if not hits:
                continue
            absent = [h for h in hits if h[1] == "absent"]
            firm = [h for h in hits if h[0] == "firm"]
            conf, reason, s, m = absent[0] if absent else (firm[0] if firm else hits[0])
            hit = {"where": where, "row": r["line"], "kind": r["kind"], "indicator": r["pattern"],
                   "matched": m.group(0), "text": s[:SNIPPET] + ("..." if len(s) > SNIPPET else ""),
                   "confidence": conf, "reason": reason, "negated": reason == "absent"}
            entry = found.setdefault(r["key"], {"confidence": "uncertain", "hits": []})
            if not any(h["where"] == where and h["row"] == r["line"] for h in entry["hits"]):
                entry["hits"].append(hit)
    # One issue shared by several challenges counts once: for the group's first challenge in the table.
    first: dict = {}
    for r in rows:
        if r["kind"].startswith("group:"):
            first.setdefault(r["kind"], r)
    for key, entry in found.items():
        for h in entry["hits"]:
            g = first.get(h["kind"])
            if h["confidence"] == "firm" and g and g["key"] != key:
                h["confidence"], h["reason"] = "uncertain", f"counted once, for {g['name']}"
        if any(h["confidence"] == "firm" for h in entry["hits"]):
            entry["confidence"] = "firm"
    return found


def reachable_summary(reach: dict) -> dict:
    yes = [r for r in reach.values() if r["reach"] == "yes"]
    return {"total": len(yes), "needs": {n: sum(r["needs"] == n for r in yes) for n in NEEDS},
            "solve": {n: sum(r["solve"] == n for r in yes) for n in NEEDS},
            "browser_only": sum(r["browser"] == "yes" for r in yes),
            "not_reachable": {x: sum(r["reach"] == x for r in reach.values()) for x in REACHES if x != "yes"}}


def score(snapshot: dict, rows: list[dict], review: dict | None = None, reach: dict | None = None) -> dict:
    review = review or {}
    reach = load_reach() if reach is None else reach
    after = snapshot.get("challenges_after") or []
    before = {c["key"]: bool(c.get("solved")) for c in snapshot.get("challenges_before") or []}
    if not after:
        raise Failed("the snapshot has no challenge list (challenges_after)")
    problems = check_map(rows, after)
    if problems:
        raise Failed("the indicator table does not fit this Juice Shop:\n  " + "\n  ".join(problems))
    problems = check_reach(reach, after, snapshot.get("in_docker", True))
    if problems:
        raise Failed("the reachability table does not fit this Juice Shop:\n  " + "\n  ".join(problems))
    bad = {k: v for k, v in review.items() if v not in ("confirmed", "rejected")}
    if bad:
        raise Failed(f"review decisions must be confirmed or rejected: {bad}")
    by_key = {c["key"]: c for c in after}
    found = match(rows, snapshot)
    identified, uncertain, rejected = [], [], []
    for key, f in sorted(found.items(), key=lambda kv: (by_key[kv[0]]["category"], by_key[kv[0]]["name"])):
        c = by_key[key]
        row = {"key": key, "name": c["name"], "category": c["category"], "difficulty": c.get("difficulty"),
               "confidence": f["confidence"], "review": review.get(key, ""), "reach": reach[key]["reach"],
               "needs": reach[key]["needs"], "hits": f["hits"]}
        if review.get(key) == "rejected":
            rejected.append(row)
        elif f["confidence"] == "firm" or review.get(key) == "confirmed":
            identified.append(row)
        else:
            uncertain.append(row)
    solved_now = [c for c in after if c.get("solved") and not before.get(c["key"], False)]
    solved_before = [c for c in after if before.get(c["key"], False)]
    disabled = {c["key"] for c in after if snapshot.get("in_docker", True) and "Docker" in (c.get("disabledEnv") or [])}
    reachable = {k for k, r in reach.items() if r["reach"] == "yes"}
    categories = {}
    for c in after:
        cat = categories.setdefault(c["category"], {"challenges": 0, "enabled": 0, "reachable": 0, "identified": 0,
                                                    "uncertain": 0, "solved": 0})
        cat["challenges"] += 1
        cat["enabled"] += c["key"] not in disabled
        cat["reachable"] += c["key"] in reachable
    for lst, field in ((identified, "identified"), (uncertain, "uncertain"), (solved_now, "solved")):
        for c in lst:
            categories[c["category"]][field] += 1
    ident_keys = {r["key"] for r in identified}
    summary = reachable_summary(reach)
    mapped = {r["key"] for r in rows}
    summary["with_indicator"] = len(reachable & mapped)
    summary["with_firm_indicator"] = len(reachable & {r["key"] for r in rows if r["confidence"] == "firm"})
    summary["identified"] = len(ident_keys & reachable)
    summary["identified_by_needs"] = {n: sum(1 for k in ident_keys & reachable if reach[k]["needs"] == n)
                                      for n in NEEDS}
    summary["solved"] = len({c["key"] for c in solved_now} & reachable)
    return {
        "job_id": snapshot.get("job_id"), "lane": snapshot.get("lane"), "juice_shop": snapshot.get("juice_shop_version"),
        "challenges": len(after), "disabled_in_docker": len(disabled),
        "mapped_challenges": len(mapped), "reachable": summary,
        "leads": len(snapshot.get("leads") or []), "evidence": len(snapshot.get("evidence") or []),
        "items_marked": sum(1 for i in snapshot.get("items") or [] if i.get("state") != "open"),
        "identified": identified, "uncertain": uncertain, "rejected": rejected,
        "identified_outside_reachable": sorted(ident_keys - reachable),
        "solved_during_run": [{"key": c["key"], "name": c["name"], "category": c["category"],
                               "identified": c["key"] in ident_keys} for c in solved_now],
        "solved_before_run": [c["key"] for c in solved_before],
        "review_not_matched": sorted(k for k in review if k not in found),
        "categories": dict(sorted(categories.items())),
    }


def union(scores: list[dict], reach: dict | None = None) -> dict:
    """Several runs (the lanes of one run) taken together: each challenge once."""
    reach = load_reach() if reach is None else reach
    reachable = {k for k, r in reach.items() if r["reach"] == "yes"}
    ident, unc, solved = {}, {}, {}
    for s in scores:
        for r in s["identified"]:
            ident.setdefault(r["key"], r)
        for r in s["uncertain"]:
            unc.setdefault(r["key"], r)
        for c in s["solved_during_run"]:
            solved.setdefault(c["key"], c)
    for k in ident:
        unc.pop(k, None)
    summary = reachable_summary(reach)
    summary["identified"] = len(set(ident) & reachable)
    summary["identified_by_needs"] = {n: sum(1 for k in set(ident) & reachable if reach[k]["needs"] == n)
                                      for n in NEEDS}
    summary["solved"] = len(set(solved) & reachable)
    return {"jobs": [s["job_id"] for s in scores], "reachable": summary,
            "identified": sorted(ident), "uncertain": sorted(unc), "solved_during_runs": sorted(solved),
            "solved_not_identified": sorted(set(solved) - set(ident)),
            "identified_outside_reachable": sorted(set(ident) - reachable)}


def pct(n: int, d: int) -> str:
    return f"{n} of {d} ({100 * n / d:.0f}%)" if d else f"{n} of 0"


def markdown(s: dict) -> str:
    lane = s.get("lane") or {}
    rs = s["reachable"]
    nr = rs["not_reachable"]
    out = [f"### Juice Shop scoring (job {s['job_id']}, lane `{lane.get('role', '?')}`, Juice Shop "
           f"{s.get('juice_shop') or '?'})", "",
           "Identified: a lead or evidence entry of the run names the challenge's issue by an indicator of "
           "`tools/juiceshop/challenge_map.tsv` (firm counted, uncertain listed for review). Solved: Juice "
           "Shop's own flag, set during the run. Both are counted against the challenges this lab can reach "
           "(`tools/juiceshop/reachable.tsv`). A read-only agent can identify far more than it can solve.", "",
           "| | |", "|---|---|",
           f"| Challenges | {s['challenges']} ({s['disabled_in_docker']} disabled in Docker by Juice Shop's safety "
           f"mode; {s['mapped_challenges']} have an indicator in the table) |",
           f"| Reachable in this lab | {rs['total']} of {s['challenges'] - s['disabled_in_docker']} enabled: "
           f"{rs['needs']['read']} read, {rs['needs']['write']} write, {rs['needs']['account']} account; "
           f"{rs['browser_only']} solved only in a browser (not reachable: {nr['no-llm']} LLM, {nr['no-chain']} "
           f"blockchain, {nr['no-internet']} internet only, {nr['no-front']} refused by the front) |",
           f"| Run's leads and evidence | {s['leads']} lead(s), {s['evidence']} evidence entr"
           f"{'y' if s['evidence'] == 1 else 'ies'}, {s['items_marked']} item(s) marked |",
           f"| Identified (counted) | {len(s['identified'])} |",
           f"| Identified of the reachable | {pct(rs['identified'], rs['total'])}: read "
           f"{rs['identified_by_needs']['read']}/{rs['needs']['read']}, write {rs['identified_by_needs']['write']}/"
           f"{rs['needs']['write']}, account {rs['identified_by_needs']['account']}/{rs['needs']['account']} |",
           f"| Uncertain (for review, not counted) | {len(s['uncertain'])} |",
           f"| Solved during the run (Juice Shop's flags) | {len(s['solved_during_run'])} |"]
    if s["solved_before_run"]:
        out.append(f"| Solved before the run (not counted) | {len(s['solved_before_run'])} |")
    if s["rejected"]:
        out.append(f"| Rejected by the review | {len(s['rejected'])} |")
    if s["identified_outside_reachable"]:
        out.append(f"| Identified outside the reachable set | {', '.join(s['identified_outside_reachable'])} |")
    out += ["", "| Category | Challenges (enabled, reachable) | Identified | Uncertain | Solved during the run |",
            "|---|---|---|---|---|"]
    for cat, c in s["categories"].items():
        out.append(f"| {cat} | {c['challenges']} ({c['enabled']}, {c['reachable']}) | {c['identified']} | "
                   f"{c['uncertain']} | {c['solved']} |")
    tot = {k: sum(c[k] for c in s["categories"].values()) for k in ("challenges", "enabled", "reachable",
                                                                     "identified", "uncertain", "solved")}
    out.append(f"| **Total** | {tot['challenges']} ({tot['enabled']}, {tot['reachable']}) | {tot['identified']} | "
               f"{tot['uncertain']} | {tot['solved']} |")

    def hit_line(h):
        why = {"absent": " (says it is absent)", "speculative": " (only supposed)",
               "not obtained": " (listed or refused, not obtained)"}.get(h["reason"], "")
        if h["reason"].startswith("counted once"):
            why = f" ({h['reason']})"
        return f"{h['where']}: \"{h['text']}\"{why}"
    for title, rows in (("Identified", s["identified"]), ("Uncertain, for review", s["uncertain"]),
                        ("Rejected by the review", s["rejected"])):
        if not rows:
            continue
        out += ["", f"{title}:", "", "| Challenge | Category | Match | Found in |", "|---|---|---|---|"]
        for r in rows:
            how = r["confidence"] + (f", {r['review']}" if r["review"] else "")
            hits = sorted(r["hits"], key=lambda h: h["confidence"] != r["confidence"])
            found = "<br>".join(hit_line(h).replace("|", "\\|") for h in hits[:3])
            out.append(f"| {r['name']} (`{r['key']}`) | {r['category']} | {how} | {found} |")
    if s["solved_during_run"]:
        out += ["", "Solved during the run: " + ", ".join(
            f"{c['name']} ({c['category']}{', identified' if c['identified'] else ', not identified'})"
            for c in s["solved_during_run"]) + "."]
    if s["review_not_matched"]:
        out += ["", "Review decisions for challenges this run did not match: " + ", ".join(s["review_not_matched"])]
    return "\n".join(out) + "\n"


def markdown_union(u: dict) -> str:
    rs = u["reachable"]
    return "\n".join([
        f"### Juice Shop scoring, union of jobs {', '.join(str(j) for j in u['jobs'])}", "",
        "| | |", "|---|---|",
        f"| Identified of the reachable | {pct(rs['identified'], rs['total'])}: read "
        f"{rs['identified_by_needs']['read']}/{rs['needs']['read']}, write {rs['identified_by_needs']['write']}/"
        f"{rs['needs']['write']}, account {rs['identified_by_needs']['account']}/{rs['needs']['account']} |",
        f"| Identified | {', '.join(u['identified']) or 'none'} |",
        f"| Uncertain, not identified by any run | {', '.join(u['uncertain']) or 'none'} |",
        f"| Solved during the runs (Juice Shop's flags) | {', '.join(u['solved_during_runs']) or 'none'} |",
        f"| Solved but not identified | {', '.join(u['solved_not_identified']) or 'none'} |",
    ]) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("snapshot", nargs="+")
    ap.add_argument("--review")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--map", default=str(MAP))
    ap.add_argument("--reach", default=str(REACH))
    args = ap.parse_args(argv)
    try:
        review = json.loads(Path(args.review).read_text()) if args.review else None
        rows, reach = load_map(args.map), load_reach(args.reach)
        scores = [score(json.loads(Path(f).read_text()), rows, review, reach) for f in args.snapshot]
    except (OSError, ValueError, Failed) as e:
        print(f"STOPPED: {e}", file=sys.stderr)
        return 1
    if len(scores) == 1:
        print(json.dumps(scores[0], indent=2) if args.json else markdown(scores[0]), end="\n" if args.json else "")
        return 0
    u = union(scores, reach)
    if args.json:
        print(json.dumps({"runs": scores, "union": u}, indent=2))
    else:
        print("\n".join(markdown(s) for s in scores) + "\n" + markdown_union(u), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
