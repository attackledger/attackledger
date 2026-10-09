"""People, sessions, roles and separation of duties."""
import hashlib
import os
import sys
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite://")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import auth, authz, db
from app.main import app

PW = "correct horse battery"   # test passwords for this suite only


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.delenv("ATTACKLEDGER_API_TOKEN", raising=False)
    auth._failures.clear()
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    db.Base.metadata.create_all(eng)
    Session = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)

    def _session():
        s = Session()
        try:
            yield s
        finally:
            s.close()
    app.dependency_overrides[db.get_session] = _session
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def h(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()


def person(c, email, name, owner=False):
    r = c.post("/people", json={"email": email, "name": name, "password": PW, "is_owner": owner})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def sign_in(c, email, password=PW):
    c.cookies.clear()
    return c.post("/auth/login", json={"email": email, "password": password})


def setup_team(c):
    """Open mode: create the owner and three people, an engagement and a lane."""
    owner = person(c, "owner@lab.test", "Olive Owner", owner=True)   # open mode: anyone local may
    assert sign_in(c, "owner@lab.test").status_code == 200            # from now on, people sign in
    ids = {n: person(c, f"{n}@lab.test", n.title()) for n in ("tess", "rita", "vic", "out")}
    e = c.post("/engagements", json={"name": "Team"}).json()["id"]
    c.put(f"/engagements/{e}/members", json={"members": [
        {"user_id": ids["tess"], "roles": ["tester"]},
        {"user_id": ids["rita"], "roles": ["tester", "reviewer"]},
        {"user_id": ids["vic"], "roles": ["viewer"]},
    ]})
    a = c.post(f"/engagements/{e}/assets", json={"host": "shop.lab.test"}).json()["id"]
    lane = c.post("/lanes", json={"asset_id": a, "role": "recon"}).json()
    return owner, ids, e, a, lane


def resolve_all(c, lane):
    for it in lane["items"]:
        c.patch(f"/lanes/{lane['id']}/items/{it['idx']}", json={"state": "na", "na_reason": "lab"})


# ---- the permission table ------------------------------------------------------

def test_every_route_has_a_permission_rule():
    missing = []
    for r in app.routes:
        if isinstance(r, APIRoute) and r.path not in authz.DOC_ROUTES:
            for m in r.methods - {"HEAD", "OPTIONS"}:
                if (m, r.path) not in authz.RULES:
                    missing.append(f"{m} {r.path}")
    assert missing == []
    stale = [k for k in authz.RULES if not any(isinstance(r, APIRoute) and r.path == k[1] and k[0] in r.methods
                                               for r in app.routes)]
    assert stale == []


def test_principal_never_defaults_to_owner():
    from starlette.requests import Request
    with pytest.raises(Exception):
        authz.current(Request({"type": "http", "headers": [], "state": {}}))


# ---- modes and sign-in -------------------------------------------------------------

def test_modes_open_token_people(client, monkeypatch):
    assert client.get("/health").json() == {"ok": True, "auth_required": False, "mode": "open", "timestamps": False}
    monkeypatch.setenv("ATTACKLEDGER_API_TOKEN", "tok-123")
    assert client.get("/health").json()["mode"] == "token"
    assert client.get("/engagements").status_code == 401
    hdr = {"authorization": "Bearer tok-123"}
    # The first person must be an owner; weak passwords are refused.
    assert client.post("/people", headers=hdr, json={"email": "a@lab.test", "name": "A", "password": PW}).status_code == 422
    assert client.post("/people", headers=hdr, json={"email": "a@lab.test", "name": "A", "password": "short",
                                                     "is_owner": True}).status_code == 422
    assert client.post("/people", headers=hdr, json={"email": "a@lab.test", "name": "A", "password": PW,
                                                     "is_owner": True}).status_code == 201
    assert client.get("/health").json()["mode"] == "people"
    # The token still works for automation, as an owner.
    assert client.get("/engagements", headers=hdr).status_code == 200


def test_sign_in_sessions_lockout_and_disabled(client):
    person(client, "owner@lab.test", "Olive Owner", owner=True)
    assert client.get("/engagements").status_code == 401                # people mode: sign in first
    assert sign_in(client, "owner@lab.test", "wrong password!!").status_code == 401
    assert sign_in(client, "nobody@lab.test").status_code == 401         # same answer for unknown emails
    r = sign_in(client, "OWNER@lab.test ")
    assert r.status_code == 200 and r.json()["name"] == "Olive Owner"
    assert "httponly" in r.headers["set-cookie"].lower() and "samesite=strict" in r.headers["set-cookie"].lower()
    me = client.get("/auth/me").json()
    assert me["kind"] == "person" and me["is_owner"] is True
    # Only the hash of the session value is stored.
    value = client.cookies.get(auth.COOKIE)
    from app.models import UserSession
    s = next(app.dependency_overrides[db.get_session]())
    stored = [u.token_sha256 for u in s.query(UserSession)]
    assert value not in stored and h(value) in stored
    client.post("/auth/logout")
    assert client.get("/engagements").status_code == 401
    client.cookies.set(auth.COOKIE, value)                                # a signed-out session is dead
    assert client.get("/engagements").status_code == 401
    for _ in range(auth.LOCKOUT_FAILURES):
        sign_in(client, "owner@lab.test", "wrong password!!")
    assert sign_in(client, "owner@lab.test").status_code == 429           # locked even with the right one


def test_last_owner_is_protected_and_disabled_people_cannot_sign_in(client):
    o = person(client, "owner@lab.test", "Olive Owner", owner=True)
    assert client.post("/people", json={"email": "x@lab.test", "name": "X", "password": PW}).status_code == 401
    sign_in(client, "owner@lab.test")
    t = person(client, "tess@lab.test", "Tess")
    assert client.patch(f"/people/{o}", json={"disabled": True}).status_code == 422
    assert client.patch(f"/people/{o}", json={"is_owner": False}).status_code == 422
    assert client.patch(f"/people/{t}", json={"disabled": True}).status_code == 200
    assert sign_in(client, "tess@lab.test").status_code == 401


# ---- roles -------------------------------------------------------------------------

def test_roles_decide_what_each_person_can_do(client):
    _, ids, e, a, lane = setup_team(client)
    L = lane["id"]

    sign_in(client, "out@lab.test")                                      # not on the engagement
    assert client.get("/engagements").json() == []
    assert client.get(f"/engagements/{e}/coverage").status_code == 404   # not even confirmed to exist
    assert client.get(f"/lanes/{L}").status_code == 404

    sign_in(client, "vic@lab.test")                                      # viewer: reads only
    assert [x["id"] for x in client.get("/engagements").json()] == [e]
    assert client.get(f"/lanes/{L}").status_code == 200
    assert client.get(f"/engagements/{e}/report").status_code == 200
    assert client.post(f"/lanes/{L}/attach", json={"item_idx": 1, "kind": "note", "text": "x"}).status_code == 403
    assert client.post("/lanes", json={"asset_id": a, "role": "mapper"}).status_code == 403
    assert client.put(f"/engagements/{e}/scope", json={"include": ["*.lab.test"]}).status_code == 403

    sign_in(client, "tess@lab.test")                                     # tester: works, cannot sign
    r = client.post(f"/lanes/{L}/attach", json={"item_idx": 1, "kind": "note", "text": "checked robots.txt"})
    assert r.status_code == 201 and r.json()["evidence"][-1]["created_by"] == ids["tess"]
    resolve_all(client, client.get(f"/lanes/{L}").json())
    assert client.post(f"/lanes/{L}/close", json={"reviewed": True}).status_code == 403
    assert client.get("/people").status_code == 403                      # people are managed by owners
    assert client.post("/engagements", json={"name": "x"}).status_code == 403

    sign_in(client, "rita@lab.test")                                     # reviewer: signs as herself
    r = client.post(f"/lanes/{L}/close", json={"reviewed": True, "closed_by": "Someone Else"})
    assert r.status_code == 200
    assert r.json()["receipt"] and client.get(f"/lanes/{L}").json()["receipt"]["closed_by"] == "Rita"
    assert client.get(f"/lanes/{L}").json()["receipt"]["closed_by_user"] == ids["rita"]


def test_separation_of_duties(client, monkeypatch):
    _, ids, e, a, lane = setup_team(client)
    L = lane["id"]
    client.patch(f"/engagements/{e}", json={"separation_of_duties": True})
    sign_in(client, "rita@lab.test")                                     # tester and reviewer
    client.post(f"/lanes/{L}/attach", json={"item_idx": 1, "kind": "note", "text": "my own test"})
    resolve_all(client, client.get(f"/lanes/{L}").json())
    r = client.post(f"/lanes/{L}/close", json={"reviewed": True})
    assert r.status_code == 422 and "someone else" in r.json()["detail"]
    # Another reviewer may sign it.
    sign_in(client, "owner@lab.test")
    client.put(f"/engagements/{e}/members", json={"members": [
        {"user_id": ids["rita"], "roles": ["tester", "reviewer"]},
        {"user_id": ids["vic"], "roles": ["viewer", "reviewer"]}]})
    # The operator token has no identity, so it cannot sign while separation is on.
    monkeypatch.setenv("ATTACKLEDGER_API_TOKEN", "tok-123")
    client.cookies.clear()
    r = client.post(f"/lanes/{L}/close", headers={"authorization": "Bearer tok-123"}, json={"reviewed": True,
                                                                                         "closed_by": "Bot"})
    assert r.status_code == 422 and "sign in as a person" in r.json()["detail"]
    sign_in(client, "vic@lab.test")
    assert client.post(f"/lanes/{L}/close", json={"reviewed": True}).status_code == 200


def test_member_roles_are_validated(client):
    _, ids, e, _, _ = setup_team(client)
    r = client.put(f"/engagements/{e}/members", json={"members": [{"user_id": ids["tess"], "roles": ["admin"]}]})
    assert r.status_code == 422
    r = client.put(f"/engagements/{e}/members", json={"members": [{"user_id": 9999, "roles": ["viewer"]}]})
    assert r.status_code == 422
