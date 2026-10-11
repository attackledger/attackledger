"""The route walk the permission and organization tests depend on (routewalk.py) misses no
route, whatever FastAPI version keeps included routers in app.routes, and authz looks up the
rule of the route that actually answers."""
import os
import re
import sys
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite://")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

import routewalk
import testdb
from app import approvals, authz, db, gatewayapi, testaccounts, workerapi
from app.main import app

MAIN = Path(__file__).resolve().parents[1] / "app" / "main.py"
HTTP = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
# Served, but not in the schema: the schema itself and its page (main.py), both in authz.RULES.
NOT_IN_SCHEMA = {("GET", "/openapi.json"), ("GET", "/docs")}


def served() -> list[tuple[str, str]]:
    return [(m, p) for m, p, _ in routewalk.endpoints(app) if m not in ("HEAD", "OPTIONS")]


def test_the_walk_lists_each_route_once():
    eps = served()
    assert len(eps) == len(set(eps))


def test_the_walk_matches_the_openapi_schema():
    """FastAPI builds the schema with its own walk of the routers: the two must agree, route
    for route, apart from the two routes that keep themselves out of it."""
    schema = {(m.upper(), p) for p, ops in app.openapi()["paths"].items() for m in ops if m in HTTP}
    walked = set(served())
    assert walked - schema == NOT_IN_SCHEMA
    assert schema - walked == set()
    assert {(m, p) for m, p, r in routewalk.endpoints(app) if not r.include_in_schema} == NOT_IN_SCHEMA


def test_the_walk_reaches_every_included_router():
    """Each router main.py includes, route for route. The includes take no prefix: authz.authorize
    looks the rule up by request.scope["route"].path, which for an included route is the path
    its own router declared, so a prefix would make it miss the rule (and refuse everyone but
    owners) until RULES and authorize learn about it."""
    src = MAIN.read_text()
    includes = re.findall(r"app\.include_router\(([^)]*)\)", src)
    assert includes == ["gatewayapi.router", "workerapi.router", "testaccounts.router", "approvals.router"]
    walked = set(served())
    for module in (gatewayapi, workerapi, testaccounts, approvals):
        own = {(m, r.path) for r in module.router.routes for m in r.methods if m not in ("HEAD", "OPTIONS")}
        assert own, module.__name__
        assert own <= walked, (module.__name__, sorted(own - walked))
    # And the app's own routes: the walk is more than the included routers.
    assert ("GET", "/health") in walked and ("POST", "/engagements") in walked


class _RecordingRules(dict):
    """authz.RULES as authorize sees it, but each lookup is recorded and then stops the request
    (HTTP 418) before anything else of authorize, or any handler, runs."""
    def __init__(self, rules):
        super().__init__(rules)
        self.looked: list[tuple[str, str]] = []

    def get(self, key, default=None):
        self.looked.append(key)
        raise HTTPException(418, "looked up")


@pytest.fixture()
def client(monkeypatch):
    eng = testdb.memory_engine()
    db.Base.metadata.create_all(eng)
    Session = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)

    def _session():
        s = Session()
        try:
            yield s
        finally:
            s.close()
    app.dependency_overrides[db.get_session] = _session
    try:
        with TestClient(app) as c:
            yield c
    finally:
        app.dependency_overrides.clear()


def test_authorize_finds_the_rule_of_every_route(client, monkeypatch):
    """A request to each route, its path parameters filled in: authorize runs for it (418, from
    the recording table) and looks up exactly that route's (method, path), which has a rule."""
    rec = _RecordingRules(authz.RULES)
    monkeypatch.setattr(authz, "RULES", rec)
    wrong = []
    for method, path in sorted(served()):
        url = re.sub(r"\{\w+\}", "1", path)
        rec.looked.clear()
        r = client.request(method, url)
        if r.status_code != 418 or rec.looked != [(method, path)]:
            wrong.append((method, path, r.status_code, rec.looked[:]))
    assert wrong == []
    assert set(served()) == set(dict(rec))           # and each of them is in the real table
