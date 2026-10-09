"""First run on a production install (ATTACKLEDGER_REQUIRE_SIGN_IN=1): the API is closed to
everyone until the first owner is created on the server, so whoever reaches it first over
the network cannot make themselves owner."""
import os
import sys
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite://")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest

from app import auth, people
from test_keytrust import PW, env  # noqa: F401  (env is a fixture)

OWNER = {"email": "owner@lab.test", "name": "Olive Owner", "password": PW, "is_owner": True}


@pytest.fixture()
def prod(env, monkeypatch):        # noqa: F811
    monkeypatch.setenv("ATTACKLEDGER_REQUIRE_SIGN_IN", "1")
    return env


def test_health_says_setup_and_nothing_else_is_open(prod):
    c, _ = prod
    h = c.get("/health").json()
    assert h["mode"] == "setup" and h["auth_required"] is True
    for method, path in [("GET", "/engagements"), ("GET", "/people"), ("GET", "/auth/me")]:
        r = c.request(method, path)
        assert r.status_code == 401 and "python -m app.people create --owner" in r.json()["detail"]


def test_nobody_can_become_the_first_owner_over_the_api(prod):
    c, Session = prod
    assert c.post("/people", json=OWNER).status_code == 401
    assert c.post("/engagements", json={"name": "Grab"}).status_code == 401
    assert c.post("/auth/login", json={}).status_code == 422
    assert c.post("/auth/login", json={"token": "anything"}).status_code == 422
    assert c.post("/auth/login", json={"email": OWNER["email"], "password": PW}).status_code == 422
    with Session() as s:
        assert not auth.people_exist(s)


def test_the_server_cli_creates_the_first_owner_who_then_signs_in(prod, monkeypatch):
    c, _ = prod
    monkeypatch.setenv("ATTACKLEDGER_NEW_PASSWORD", PW)
    assert people.main(["create", "--email", OWNER["email"], "--name", OWNER["name"]]) == 2   # must be --owner
    assert people.main(["create", "--email", OWNER["email"], "--name", OWNER["name"], "--owner"]) == 0
    assert c.get("/health").json()["mode"] == "people"
    assert c.get("/engagements").status_code == 401                       # not signed in
    assert c.post("/auth/login", json={"email": OWNER["email"], "password": PW}).status_code == 200
    assert c.post("/engagements", json={"name": "First"}).status_code == 201


def test_the_token_still_works_when_set(prod, monkeypatch):
    c, _ = prod
    monkeypatch.setenv("ATTACKLEDGER_API_TOKEN", "s3cret-token")
    assert c.get("/health").json()["mode"] == "token"
    assert c.get("/engagements").status_code == 401
    assert c.get("/engagements", headers={"Authorization": "Bearer s3cret-token"}).status_code == 200


@pytest.mark.parametrize("value,closed", [("1", True), ("true", True), ("ture", True), ("yes", True),
                                          ("", False), ("0", False), ("false", False), ("off", False)])
def test_unknown_values_fail_closed(env, monkeypatch, value, closed):   # noqa: F811
    c, _ = env
    monkeypatch.setenv("ATTACKLEDGER_REQUIRE_SIGN_IN", value)
    assert c.get("/health").json()["mode"] == ("setup" if closed else "open")
    assert c.get("/engagements").status_code == (401 if closed else 200)


def test_the_api_documentation_needs_sign_in_in_production(prod, monkeypatch):
    """/docs and /openapi.json list every route and parameter; in production they answer only
    to a signed-in caller, like the rest of the API."""
    c, _ = prod
    for path in ("/openapi.json", "/docs"):
        r = c.get(path)
        assert r.status_code == 401 and "python -m app.people create --owner" in r.json()["detail"]
    assert c.get("/redoc").status_code == 404           # served nowhere any more
    monkeypatch.setenv("ATTACKLEDGER_NEW_PASSWORD", PW)
    assert people.main(["create", "--email", OWNER["email"], "--name", OWNER["name"], "--owner"]) == 0
    assert c.get("/openapi.json").status_code == 401    # people exist: still sign in first
    assert c.post("/auth/login", json={"email": OWNER["email"], "password": PW}).status_code == 200
    spec = c.get("/openapi.json")
    assert spec.status_code == 200 and "/engagements/{eng_id}/inbox/map" in spec.json()["paths"]
    docs = c.get("/docs")
    assert docs.status_code == 200 and "openapi.json" in docs.text


def test_open_local_use_keeps_the_documentation_open(env):
    c, _ = env
    assert c.get("/openapi.json").status_code == 200 and c.get("/docs").status_code == 200
