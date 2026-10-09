"""Gates every recon job passes, derived from the module registry.

The API applies them when a job is created. The worker applies them again when
the job runs, because the engagement can change in between (scope narrowed, a
module switched off, authorization missing).
"""
from . import modules, scope, urls
from .models import Engagement


class GateError(Exception):
    pass


def check_engagement(eng: Engagement, kind: str) -> modules.Module:
    m = modules.get(kind)
    if m is None:
        raise GateError(f"unknown job kind: {kind}")
    if eng.authorized_at is None:
        raise GateError("record your authorization for this program before running jobs")
    if not eng.scope_include:
        raise GateError("define the program scope before running jobs")
    if m.opt_in and kind not in (eng.enabled_modules or []):
        raise GateError(f"{m.title.lower()} is off for this engagement; enable it only if the "
                        f"program policy allows it")
    if eng.rate_limit_rps < m.min_rps:
        raise GateError(f"{m.title.lower()} needs a rate limit of at least {m.min_rps} per second to stay "
                        f"within it; this engagement allows {eng.rate_limit_rps}")
    if m.needs_identification and not (eng.research_header or eng.research_user_agent):
        raise GateError("set the research header or user agent the program requires "
                        "before sending traffic to its hosts")
    return m


def roots(eng: Engagement) -> set[str]:
    return {p[2:] for p in eng.scope_include if p.startswith("*.")}


def split_targets(eng: Engagement, m: modules.Module, targets: list[str]) -> tuple[list[str], list[str]]:
    """(allowed, refused) for this module's input type."""
    inc, exc = eng.scope_include, eng.scope_exclude
    if m.input == "roots":
        ok = roots(eng)
        test = lambda t: t in ok  # noqa: E731
    elif m.input == "urls":
        test = lambda t: scope.in_scope(urls.host_of(t) or "", inc, exc)  # noqa: E731
    else:
        test = lambda t: scope.in_scope(t, inc, exc)  # noqa: E731
    allowed = [t for t in targets if test(t)]
    refused = [t for t in targets if not test(t)]
    return allowed, refused


def normalize_targets(m: modules.Module, targets: list[str]) -> list[str]:
    cleaned = [t.strip() for t in targets if t and t.strip()]
    return cleaned if m.input == "urls" else [t.lower() for t in cleaned]
