"""Hunt executors: who works a lane, and what they may see and write.

A lane is worked by an executor. Every executor gets the same lane context and
writes through the same ledger functions, so an agent can never do more than a
person working through the API.

Read side (lane_context):
  the lane's checklist items, the engagement's scope rules, rate limit and
  research identification, plus the recon output for the lane's host:
  observations, endpoints and leads. Endpoints are ranked by signal (surface.py), not
  listed alphabetically: junk is dropped, identifiers are collapsed, and a single-page
  app's client routes are listed on their own. Leads come first by kind and severity.
  recon.origins is the scheme, host and port the probe module saw answering (empty
  when no probe ran), so an agent does not spend requests finding out. An item carries
  its pack's hint, when the pack gives one: the usual checks for that test.
  known_paths (D-059) lists the paths already seen answering on the lane's host, as
  "METHOD /path status [source]": imported traffic first, then evidence, then what recon
  requested itself (crawl, content discovery) and the ranked endpoints do not show. Paths
  only (no query, no fragment), identifiers collapsed, redacted when the engagement redacts,
  at most KNOWN_PATHS; none once the engagement's content was deleted.

Write side (what an executor may do):
  - append evidence to the lane (ledger.append_evidence; hash-chained),
  - mark an item done (only with evidence) or N/A (only with a reason),
  - record a lead for another lane.
  An executor never issues a receipt. Only a person closes a lane, signing the
  receipt with their name after reviewing the evidence (D-018).

Executors
  manual  a person, through the UI or API (always available)
  agent   a Claude agent (agentloop + agenttools). The API key lives in the gateway only,
          which adds it to the agent's Claude API calls (D-042, docs/WORKER_API.md); the API
          learns that agents are enabled from ATTACKLEDGER_AGENTS_ENABLED=1, which
          docker-compose sets when ANTHROPIC_API_KEY is set.
"""
import os
from dataclasses import dataclass
from urllib.parse import urlsplit

from sqlalchemy import select

from . import approvals, gates, packs, redact, surface, targets, testaccounts
from .models import Endpoint, Evidence, InboxEntry, Lane, Lead, Observation

# Endpoints read per host to rank; a host with more (a large archive) is ranked on the
# first ones by id and the context says so.
RANK_SCAN = 20_000
_SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}
# Leads a tester reads first: what recon saw on the target before what it inferred.
_LEAD_KIND = {"secret": 0, "nuclei": 0, "listing": 1, "robots": 1, "security-txt": 1, "sourcemap": 1,
              "graphql": 2, "agent": 2, "parameter": 3, "param-class": 4, "dork": 5}


def _lead_order(l: Lead, role: str) -> tuple:
    routed = (l.detail or {}).get("lane") == role
    return (_LEAD_KIND.get(l.kind, 3) - (2 if routed else 0), _SEVERITY.get(l.severity or "", 5), l.id)


def origins(observations: list[dict], host: str) -> list[dict]:
    """The origins of `host` a probe saw answering, from its observations (worker.parse_probe):
    one entry per scheme://host:port, the most recent probe first, with the status it got."""
    out: dict[str, dict] = {}
    for data in observations:
        if not isinstance(data, dict) or not data.get("live") or not isinstance(data.get("url"), str):
            continue
        try:
            u = urlsplit(data["url"])
            port = u.port or {"http": 80, "https": 443}.get(u.scheme)
        except ValueError:
            continue
        if u.scheme not in ("http", "https") or u.hostname != host or port is None:
            continue
        out.setdefault(f"{u.scheme}://{u.hostname}:{port}", {"status": data.get("status_code")})
    return [{"origin": o, **v} for o, v in out.items()]


# Known paths (D-059): at most this many go to the agent, read from at most KNOWN_SCAN rows of
# each source (the most recent first).
KNOWN_PATHS = 40
KNOWN_SCAN = 5_000
KNOWN_PATH_CHARS = 120
_DEFAULT_PORT = {"http": 80, "https": 443}
# Files that say little about what a host routes: they go after everything else.
_STATIC = {"css", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "woff", "woff2", "ttf", "eot", "otf", "map",
           "mp4", "webm", "mp3"}
_SOURCE_ORDER = {"import": 0, "evidence": 1, "recon": 2}


def _status_rank(statuses: set) -> int:
    """What a status says about a path: answered (2xx, 3xx), exists but gated or failing (401,
    405, 5xx), unknown, refused (other 4xx: a catch-all answers these too), not there (404, 410)."""
    def one(s):
        if 200 <= s < 300:
            return 0
        if 300 <= s < 400:
            return 1
        if s in (401, 405) or s >= 500:
            return 2
        return 5 if s in (404, 410) else 4
    return min((one(s) for s in statuses), default=3)


def _known_path(url: str, host: str, rep: redact.Report | None) -> str | None:
    """The path of `url` on `host` as the agent is given it: no query or fragment, identifiers
    collapsed (surface.shape), redacted when rep is given; the origin is kept only when its port
    is not the scheme's default. None for another host or a URL that does not parse."""
    if not isinstance(url, str) or not url:
        return None
    try:
        u = urlsplit(url)
        port = u.port
    except ValueError:
        return None
    if u.scheme not in _DEFAULT_PORT or (u.hostname or "").rstrip(".") != host:
        return None
    path = surface.shape(u.path or "/")
    if rep is not None:
        path = redact.text(path, rep, personal=True)
    path = "".join(c for c in path if 32 <= ord(c) != 127)
    if len(path) > KNOWN_PATH_CHARS:
        path = path[:KNOWN_PATH_CHARS - 3] + "..."
    if port is not None and port != _DEFAULT_PORT[u.scheme]:
        path = f"{u.scheme}://{host}:{port}{path}"
    return path


def known_paths(session, eng, host: str, recon_eps=(), shown=frozenset(), cap: int = KNOWN_PATHS) -> dict:
    """The paths already seen answering on `host` in this engagement, most informative first,
    for an agent that would otherwise guess them (D-059). Sources: imported traffic
    (InboxEntry: method, path, status), evidence attached to any lane (its URI: the path only),
    and recon endpoints a tool requested itself (a crawl, or content discovery with its status)
    whose shape is not among the ranked endpoints already shown (`shown`). Deduplicated by
    method and path; ordered by what the status says (answered first, 404 last), then source
    (import, evidence, recon), signal (surface.score) and how often it was seen; static files
    last. Nothing once the engagement's content was deleted: evidence URIs outlive the deletion
    by design (the chain commits to them), the rest is blank or gone."""
    if eng.content_deleted_at is not None:
        return {"total": 0, "paths": []}
    rep = redact.Report() if redact.enabled(eng) else None
    seen: dict[tuple, dict] = {}
    by_path: dict[str, tuple] = {}

    def add(method, url, status, source):
        path = _known_path(url, host, rep)
        if path is None:
            return
        method = (method or "").upper()[:10] or None
        # Evidence names no method: it joins the first row with its path, if there is one.
        key = (method, path) if method else by_path.get(path, (None, path))
        by_path.setdefault(path, key)
        row = seen.setdefault(key, {"statuses": set(), "sources": {}, "url": url})
        if isinstance(status, int) and 100 <= status <= 999:
            row["statuses"].add(status)
        row["sources"][source] = row["sources"].get(source, 0) + 1

    for e in session.scalars(select(InboxEntry).where(InboxEntry.engagement_id == eng.id, InboxEntry.host == host,
                                                      InboxEntry.url != "")
                             .order_by(InboxEntry.id.desc()).limit(KNOWN_SCAN)):
        add(e.method, e.url, e.status, "import")
    for uri in session.scalars(select(Evidence.uri).where(Evidence.engagement_id == eng.id,
                                                          Evidence.uri.like(f"http%://{host}%"))
                               .order_by(Evidence.id.desc()).limit(KNOWN_SCAN)):
        add(None, uri, None, "evidence")
    for e in recon_eps:
        sources = (e.source or "").split(",")
        st = next((surface.status_of(s) for s in sources if surface.status_of(s)), None)
        if (st is None and "katana" not in sources) or e.is_js or surface.is_junk(e.url) or surface.route_of(e.url):
            continue                # archives (gau, wayback) say a path once existed, not that it answers
        if surface.shape(e.url) in shown:
            continue
        add("GET", e.url, st, "recon")

    def order(item):
        (method, path), row = item
        static = surface.extension(path) in _STATIC
        src = min(_SOURCE_ORDER[s] for s in row["sources"])
        return (static, _status_rank(row["statuses"]), src, -surface.score(row["url"])[0],
                -sum(row["sources"].values()), path, method or "")

    out = []
    for (method, path), row in sorted(seen.items(), key=order)[:cap]:
        statuses = "/".join(str(s) for s in sorted(row["statuses"])[:3])
        sources = ",".join(s + (f" x{n}" if n > 1 else "")
                           for s, n in sorted(row["sources"].items(), key=lambda kv: _SOURCE_ORDER[kv[0]]))
        out.append(" ".join(x for x in (method, path, statuses, f"[{sources}]") if x))
    return {"total": len(seen), "paths": out}


@dataclass(frozen=True)
class Executor:
    key: str
    title: str
    summary: str

    def available(self) -> tuple[bool, str]:
        return True, ""


class _Agent(Executor):
    def available(self) -> tuple[bool, str]:
        if os.environ.get("ATTACKLEDGER_AGENTS_ENABLED") != "1":
            return False, "Set ANTHROPIC_API_KEY (in .env, for the gateway) to enable agents."
        return True, ""


EXECUTORS: dict[str, Executor] = {
    "manual": Executor("manual", "Manual", "You work the checklist and attach evidence yourself."),
    "agent": _Agent("agent", "Claude agent", "A Claude agent works the checklist within the lane's rules "
                                              "and attaches evidence; you review and close the lane."),
}


def as_dict(e: Executor) -> dict:
    ok, why = e.available()
    return {"key": e.key, "title": e.title, "summary": e.summary, "available": ok, "unavailable_reason": why}


def lane_context(session, lane: Lane, limit: int = 200) -> dict:
    """Everything an executor may read for this lane. Nothing outside the lane's host."""
    asset, eng = lane.asset, lane.asset.engagement
    pack = packs.get_pack(eng.pack_id)
    lane_def = pack.lane(lane.role) if lane.role in pack.lane_index else None
    host = asset.host

    obs = session.scalars(select(Observation).where(Observation.engagement_id == eng.id,
                                                    Observation.host == host)
                          .order_by(Observation.id.desc()).limit(limit)).all()
    eps = session.scalars(select(Endpoint).where(Endpoint.engagement_id == eng.id, Endpoint.host == host)
                          .order_by(Endpoint.id).limit(RANK_SCAN)).all()
    lds = sorted(session.scalars(select(Lead).where(Lead.engagement_id == eng.id, Lead.host == host)).all(),
                 key=lambda l: _lead_order(l, lane.role))
    lead_rows = [{"kind": l.kind, "title": l.title, "bucket": l.bucket, "severity": l.severity,
                  "source_url": l.source_url, "detail": l.detail} for l in lds]
    ranked = surface.rank_endpoints([{"url": e.url, "source": e.source, "js": e.is_js} for e in eps],
                                    lead_rows, lane.role, limit=limit)
    triage_row = next((r for r in targets.ranked(session, eng) if r["host"] == host), None)
    hints = {i.id: i.hint for i in lane_def.items if i.hint} if lane_def else {}
    return {
        "lane": {"id": lane.id, "role": lane.role, "name": lane_def.name if lane_def else lane.role,
                 "status": gates.lane_status(lane).value, "executor": lane.executor},
        "host": host,
        "rules": {"scope_include": eng.scope_include, "scope_exclude": eng.scope_exclude,
                  "rate_limit_rps": eng.rate_limit_rps,
                  "research_header": eng.research_header, "research_user_agent": eng.research_user_agent,
                  "authorized": eng.authorized_at is not None, "policy_url": eng.policy_url},
        # Labels and roles only (D-040): the gateway adds an account's session, the agent never sees it.
        "test_accounts": testaccounts.for_context(session, eng, host),
        "writes": {"allowed": bool(eng.allow_writes), "approval_minutes": approvals.APPROVAL_MINUTES,
                   "note": ("writes are proposed with propose_write and wait for a person's approval; a DELETE "
                            "also needs their confirmation") if eng.allow_writes else
                           "this engagement allows read-only requests only"},
        # Paths already seen answering on the host (D-059), so an agent need not guess them.
        "known_paths": known_paths(session, eng, host, eps, {e["shape"] for e in ranked["endpoints"]}),
        "items": [{"idx": i.idx, "key": i.item_key, "text": i.text, "state": i.state.value,
                   "controls": i.controls, **({"hint": hints[i.item_key]} if i.item_key in hints else {})}
                  for i in lane.items],
        "recon": {
            "triage": ({k: triage_row[k] for k in ("score", "signals", "golden")} if triage_row else None),
            "origins": origins([o.data for o in obs], host),
            "observations": [o.data for o in obs],
            "endpoints": [{"url": e["url"], "source": e["source"], "js": e["js"], "shape": e["shape"],
                           "count": e["count"], "signals": e["signals"]} for e in ranked["endpoints"]],
            "spa_routes": ranked["routes"],
            "endpoint_summary": {
                "recorded": ranked["total"], "distinct_shapes": ranked["shapes"],
                "junk_dropped": ranked["junk_dropped"], "not_shown": ranked["omitted"],
                "spa_routes": ranked["routes_total"], "ranked_on_first": RANK_SCAN if len(eps) >= RANK_SCAN else None,
                "order": "by signal: API paths, lead targets, sensitive names, status, files; junk dropped"},
            "leads": lead_rows[:max(limit, 50)],
            "leads_total": len(lead_rows),
        },
    }
