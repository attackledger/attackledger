"""Every HTTP route of the API, as a request is matched and authorized: method, path, route.

The tests that check every route (each has a permission rule, none reaches another
organization, the worker's routes) walk this, not `app.routes` directly. FastAPI up to 0.136
copied an included router's routes into `app.routes`; from 0.137 `app.routes` holds one entry
per included router (`fastapi.routing._IncludedRouter`) and its routes are reached through
that entry's `effective_route_contexts()`, with the include's prefix already applied to their
path. A walk that kept only the `APIRoute` entries of `app.routes` saw none of the included
routers' routes on the newer versions and still passed, so this one refuses any entry it does
not recognise, and test_routes.py checks it against the OpenAPI schema and each router.
"""
from typing import NamedTuple

from fastapi.routing import APIRoute


class Endpoint(NamedTuple):
    method: str
    path: str           # the full path template, prefixes included: what authz.RULES is keyed by
    route: APIRoute     # the route that handles it (for an included router, its own APIRoute)


def endpoints(app) -> list[Endpoint]:
    """Every (method, path) the app answers, HEAD and OPTIONS included if a route declares them."""
    out: list[Endpoint] = []
    for r in app.router.routes:
        if isinstance(r, APIRoute):
            out.extend(Endpoint(m, r.path, r) for m in sorted(r.methods))
        elif callable(getattr(r, "effective_route_contexts", None)):    # an included router, 0.137+
            for ctx in r.effective_route_contexts():                   # nested includes too
                orig = ctx.original_route
                if not isinstance(orig, APIRoute):
                    raise AssertionError(f"an included router holds a {type(orig).__name__}, which "
                                         f"routewalk does not know how to walk: {orig!r}")
                if not ctx.path:
                    raise AssertionError(f"no effective path for an included route: {orig.path}")
                out.extend(Endpoint(m, ctx.path, orig) for m in sorted(ctx.methods or orig.methods))
        else:
            raise AssertionError(f"app.routes holds a {type(r).__name__}, which routewalk does not "
                                 f"know how to walk (a FastAPI change?): {r!r}")
    return out
