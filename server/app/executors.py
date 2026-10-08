"""Hunt executors: who works a lane, and what they may see and write.

A lane is worked by an executor. Every executor gets the same lane context and
writes through the same ledger functions, so an agent can never do more than a
person working through the API.

Read side (lane_context):
  the lane's checklist items, the engagement's scope rules, rate limit and
  research identification, plus the recon output for the lane's host:
  observations, endpoints and leads.

Write side (what an executor may do):
  - append evidence to the lane (ledger.append_evidence; hash-chained),
  - mark an item done (only with evidence) or N/A (only with a reason),
  - record a lead for another lane.
  An executor never issues a receipt. Only a person closes a lane, signing the
  receipt with their name after reviewing the evidence (D-018).

Executors
  manual  a person, through the UI or API (always available)
  agent   a Claude agent (agentloop + agenttools). The API key lives in the worker only;
          the API learns that agents are enabled from ATTACKLEDGER_AGENTS_ENABLED=1,
          which docker-compose sets when ANTHROPIC_API_KEY is set.
"""
import os
from dataclasses import dataclass

from sqlalchemy import select

from . import gates, packs
from .models import Endpoint, Lane, Lead, Observation


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
            return False, "Set ANTHROPIC_API_KEY (in .env, for the worker) to enable agents."
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
                          .order_by(Endpoint.url).limit(limit)).all()
    lds = session.scalars(select(Lead).where(Lead.engagement_id == eng.id, Lead.host == host)).all()
    return {
        "lane": {"id": lane.id, "role": lane.role, "name": lane_def.name if lane_def else lane.role,
                 "status": gates.lane_status(lane).value, "executor": lane.executor},
        "host": host,
        "rules": {"scope_include": eng.scope_include, "scope_exclude": eng.scope_exclude,
                  "rate_limit_rps": eng.rate_limit_rps,
                  "research_header": eng.research_header, "research_user_agent": eng.research_user_agent,
                  "authorized": eng.authorized_at is not None, "policy_url": eng.policy_url},
        "items": [{"idx": i.idx, "key": i.item_key, "text": i.text, "state": i.state.value,
                   "controls": i.controls} for i in lane.items],
        "recon": {
            "observations": [o.data for o in obs],
            "endpoints": [{"url": e.url, "source": e.source, "js": e.is_js} for e in eps],
            "leads": [{"kind": l.kind, "title": l.title, "bucket": l.bucket, "severity": l.severity,
                       "source_url": l.source_url, "detail": l.detail} for l in lds],
        },
    }
