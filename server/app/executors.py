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

from sqlalchemy import select

from . import approvals, gates, packs, surface, targets, testaccounts
from .models import Endpoint, Lane, Lead, Observation

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
        "items": [{"idx": i.idx, "key": i.item_key, "text": i.text, "state": i.state.value,
                   "controls": i.controls} for i in lane.items],
        "recon": {
            "triage": ({k: triage_row[k] for k in ("score", "signals", "golden")} if triage_row else None),
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
