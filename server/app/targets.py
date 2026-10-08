"""Default targets for each module, computed from what earlier steps produced.

Used by the API when a job is queued without explicit targets, and by the worker
for deferred jobs (a pipeline run), whose targets are resolved only when the step
runs and the steps before it have finished.
"""
from collections.abc import Callable

from sqlalchemy import select

from . import jobgates, modules, scope, triage, urls
from .models import Endpoint, Engagement, Observation

# Hints when a module has nothing to run on, keyed by kind.
NO_TARGET_HINT = {
    "crawl": "run 'Find live web servers' first",
    "jsanalyze": "crawl golden hosts or collect archived URLs first",
}


def probes_by_host(session, eng_id: int) -> dict[str, list[dict]]:
    rows = session.scalars(select(Observation).where(Observation.engagement_id == eng_id)
                           .order_by(Observation.id.desc())).all()
    latest_job: dict[str, int] = {}
    out: dict[str, list[dict]] = {}
    for o in rows:
        if not o.data.get("live"):
            continue
        # Keep only the newest probe run per host (all its ports).
        if latest_job.setdefault(o.host, o.job_id) != o.job_id:
            continue
        out.setdefault(o.host, []).append(o.data)
    return out


def ranked(session, eng: Engagement) -> list[dict]:
    probes = {h: p for h, p in probes_by_host(session, eng.id).items()
              if scope.in_scope(h, eng.scope_include, eng.scope_exclude)}
    rows = triage.rank(probes)
    for r in rows:
        r["urls"] = sorted({p["url"] for p in probes[r["host"]] if p.get("url")})
    return rows


def golden_urls(session, eng: Engagement) -> list[str]:
    rows = ranked(session, eng)
    golden = [r for r in rows if r["golden"]] or rows
    return sorted({u for r in golden for u in r["urls"]})


def in_scope_endpoints(session, eng: Engagement, js: bool | None = None) -> list[str]:
    stmt = select(Endpoint.url).where(Endpoint.engagement_id == eng.id)
    if js is not None:
        stmt = stmt.where(Endpoint.is_js.is_(js))
    return [u for u in session.scalars(stmt).all()
            if scope.in_scope(urls.host_of(u) or "", eng.scope_include, eng.scope_exclude)]


def by_host_score(session, eng: Engagement, items: list[str]) -> list[str]:
    """Highest-scoring hosts first, so per-run caps spend themselves where it matters."""
    score = {r["host"]: r["score"] for r in ranked(session, eng)}
    return sorted(items, key=lambda u: (-score.get(urls.host_of(u) or "", -1), u))


def _jsanalyze(session, eng):
    return by_host_score(session, eng, in_scope_endpoints(session, eng, js=True))


def live_urls(session, eng: Engagement) -> list[str]:
    """Every live web service, highest-scoring hosts first."""
    return [u for r in ranked(session, eng) for u in r["urls"]]


SELECTORS: dict[str, Callable] = {
    "crawl": golden_urls,
    "jsanalyze": _jsanalyze,
    "nuclei": live_urls,
}


def default_targets(session, eng: Engagement, m: modules.Module) -> list[str]:
    if m.kind in SELECTORS:
        return SELECTORS[m.kind](session, eng)
    if m.input == "roots":
        return sorted(jobgates.roots(eng))
    if m.input == "hosts":
        return sorted(a.host for a in eng.assets if a.in_scope)
    return []
