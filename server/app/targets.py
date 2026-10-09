"""Default targets for each module, computed from what earlier steps produced.

Used by the API when a job is queued without explicit targets, and by the worker
for deferred jobs (a pipeline run), whose targets are resolved only when the step
runs and the steps before it have finished.
"""
from collections.abc import Callable

from sqlalchemy import or_, select

from . import jobgates, modules, scope, surface, triage, urls
from .models import Endpoint, Engagement, Observation

# Hints when a module has nothing to run on, keyed by kind.
NO_TARGET_HINT = {
    "crawl": "run 'Find live web servers' first",
    "jsanalyze": "crawl golden hosts or collect archived URLs first",
}

NEEDS_WILDCARD = "needs a wildcard in scope, such as *.example.com"
# Why a pipeline step found nothing to work on when it started, keyed by input, then kind.
SKIP_REASON = {
    "roots": NEEDS_WILDCARD,
    "hosts": "no in-scope hosts: add an exact scope entry or a host, or a wildcard for 'Find subdomains'",
    "urls": "earlier steps found no URLs to work on",
    "crawl": "no live web servers from 'Find live web servers'",
    "wellknown": "no live web servers from 'Find live web servers'",
    "content": "no live web servers from 'Find live web servers'",
    "nuclei": "no live web servers from 'Find live web servers'",
    "jsanalyze": "no JavaScript files from the crawl or the archived URLs",
    "params": "no dynamic endpoints from the crawl, the archived URLs or content discovery",
    "paramclass": "no URLs with parameters from the earlier steps",
}


def skip_reason(m: modules.Module) -> str:
    return SKIP_REASON.get(m.kind) or SKIP_REASON[m.input]


def cannot_apply(eng: Engagement, m: modules.Module) -> str | None:
    """Why a pipeline step can never have targets with this scope, known before anything runs."""
    roots = jobgates.roots(eng)
    if m.input == "roots" and not roots:
        return NEEDS_WILDCARD
    if m.input == "hosts" and not roots and not any(a.in_scope for a in eng.assets):
        return SKIP_REASON["hosts"]
    return None


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


def api_shapes_by_host(session, eng: Engagement, hosts) -> dict[str, int]:
    """How many distinct API-like path shapes recon recorded per host (triage's API signal).
    Only URLs that look like an API are read, so a large archive costs one filtered query."""
    if not hosts:
        return {}
    like = or_(*(Endpoint.url.like(f"%/{p}/%") for p in ("api", "rest", "graphql", "gql", "rpc", "odata"))
               , Endpoint.url.like("%/v_/%"), Endpoint.url.like("%/v__/%"))
    rows = session.execute(select(Endpoint.host, Endpoint.url).where(
        Endpoint.engagement_id == eng.id, Endpoint.host.in_(list(hosts)), Endpoint.is_js.is_(False), like)).all()
    by_host: dict[str, list[str]] = {}
    for h, u in rows:
        by_host.setdefault(h, []).append(u)
    return {h: len(surface.api_shapes(us)) for h, us in by_host.items()}


def ranked(session, eng: Engagement) -> list[dict]:
    probes = {h: p for h, p in probes_by_host(session, eng.id).items()
              if scope.in_scope(h, eng.scope_include, eng.scope_exclude)}
    rows = triage.rank(probes, api_shapes=api_shapes_by_host(session, eng, probes))
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


def _param_lead_urls(session, eng: Engagement) -> set[str]:
    from .models import Lead
    return {l.source_url for l in session.scalars(select(Lead).where(Lead.engagement_id == eng.id,
                                                                     Lead.kind == "parameter"))
            if scope.in_scope(urls.host_of(l.source_url) or "", eng.scope_include, eng.scope_exclude)}


DYNAMIC_EXT = {"php", "asp", "aspx", "jsp", "jspx", "do", "action", "cgi", "pl", "cfm"}


def dynamic_endpoints(session, eng: Engagement) -> list[str]:
    """Endpoints that take input: a query string, a script extension or an API path.
    One URL per path (query values do not matter to parameter discovery)."""
    picked: dict[str, str] = {}
    for u in in_scope_endpoints(session, eng, js=False):
        base = u.split("?", 1)[0]
        if "#" in u or urls.extension(urls.urlsplit(u).path) in urls.STATIC:
            continue      # a client-side route or a recorded file: nothing a server takes input on
        if "?" in u or urls.extension(urls.urlsplit(u).path) in DYNAMIC_EXT or "/api/" in base:
            picked.setdefault(base, base)
    return by_host_score(session, eng, sorted(picked.values()))


SELECTORS: dict[str, Callable] = {
    "crawl": golden_urls,
    "jsanalyze": _jsanalyze,
    "nuclei": live_urls,
    "wellknown": live_urls,
    "content": golden_urls,
    "params": dynamic_endpoints,
    "paramclass": lambda session, eng: sorted({u for u in in_scope_endpoints(session, eng, js=False) if "?" in u}
                                              | _param_lead_urls(session, eng)),
}


def default_targets(session, eng: Engagement, m: modules.Module) -> list[str]:
    if m.kind in SELECTORS:
        return SELECTORS[m.kind](session, eng)
    if m.input == "roots":
        return sorted(jobgates.roots(eng))
    if m.input == "hosts":
        return sorted(a.host for a in eng.assets if a.in_scope)
    return []
