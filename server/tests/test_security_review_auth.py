"""Regression tests from the security review of authentication, authorization and tenant
isolation (docs/security-review/AUTH.md). Each test names the finding it closes."""
import base64
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app import auth, blobs, vault
from app.models import Lane
from test_agent import api  # noqa: F401  (fixture)
from test_encryption import delete, engagement, v1_row
from test_people import client, person, sign_in  # noqa: F401  (fixture)


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _people(api, monkeypatch):
    monkeypatch.delenv("ATTACKLEDGER_API_TOKEN", raising=False)
    auth._failures.clear()
    person(api, "owner@lab.test", "Olive Owner", owner=True)     # open mode: the first owner
    assert sign_in(api, "owner@lab.test").status_code == 200


# ---- AUTH-1: a cited hash opened another engagement's pre-encryption blob ----------------------

def test_auth1_citing_a_hash_does_not_open_another_engagements_plaintext_blob(api, monkeypatch):
    """A tester on engagement X cites the hash of a plaintext blob (stored before encryption,
    cited by v1 evidence of engagement Y only). The citation must not open Y's bytes for X, must
    not copy them into X's encrypted store, and must not keep them alive after Y's deletion."""
    _people(api, monkeypatch)
    y, y_lane = engagement(api, "victim")
    x, x_lane = engagement(api, "attacker")
    secret = b"pre-encryption note of the victim engagement: admin password reset link"
    blobs.put(secret)                                                   # the old plaintext store
    with api.Session() as s:
        v1_row(s, s.get(Lane, y_lane["id"]), "old note", sha(secret))
    tess = person(api, "tess@lab.test", "Tess Tester")
    assert api.put(f"/engagements/{x}/members",
                   json={"members": [{"user_id": tess, "roles": ["tester"]}]}).status_code == 200

    sign_in(api, "tess@lab.test")
    assert api.get(f"/blobs/{sha(secret)}").status_code == 404        # control: not hers to read
    r = api.post(f"/lanes/{x_lane['id']}/evidence",
                 json={"item_idx": 1, "kind": "note", "sha256": sha(secret), "summary": "cited"})
    assert r.status_code == 201, r.text
    r = api.get(f"/blobs/{sha(secret)}")
    assert r.status_code == 404 and secret not in r.content

    sign_in(api, "owner@lab.test")                                     # Y's own evidence still opens it
    assert api.get(f"/blobs/{sha(secret)}").content == secret

    with api.Session() as s:                                           # encrypting copies it to Y only
        res = vault.encrypt_existing(s)
    assert res == {"encrypted": 1, "already_encrypted": 0, "plaintext_removed": 1}
    assert blobs.get(sha(secret), engagement_id=y) == secret
    assert not blobs.encrypted_path(sha(secret), x).exists()

    blobs.put(secret)                                                  # again, as before encryption
    blobs.encrypted_path(sha(secret), y).unlink()
    res = delete(api, y, "victim")                                     # X's citation does not keep it
    assert res["removed"]["plaintext_blobs_removed"] == 1
    assert not blobs.plain_path(sha(secret)).exists()
    sign_in(api, "tess@lab.test")
    assert api.get(f"/blobs/{sha(secret)}").status_code == 404


# ---- AUTH-2: requests a page of another site sends ----------------------------------------------

def _key(api) -> dict:
    pub = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    r = api.post("/auth/keys", json={"algorithm": "Ed25519", "public_key": base64.b64encode(pub).decode()})
    assert r.status_code == 201, r.text
    return r.json()


def test_auth2_a_page_of_another_site_cannot_change_anything(api, monkeypatch):
    """SameSite=Strict keeps the cookie from cross-site requests, but a sibling subdomain is the
    same site, and routes without a JSON body (revoking a key, cancelling a job, deleting a test
    account, an import's raw body) need no preflight. The browser says where a request came from."""
    _people(api, monkeypatch)
    for headers in ({"Sec-Fetch-Site": "same-site", "Origin": "https://evil.lab.test"},
                    {"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"},
                    {"Origin": "https://evil.lab.test"},                # a browser without Fetch Metadata
                    {"Origin": "null"}):
        key = _key(api)
        r = api.post(f"/auth/keys/{key['id']}/revoke", headers=headers)
        assert r.status_code == 403, (headers, r.text)
        assert not next(k for k in api.get("/auth/keys").json() if k["id"] == key["id"])["revoked"]
        e = api.post("/engagements", json={"name": "made from elsewhere"}, headers=headers)
        assert e.status_code == 403
    assert all(x["name"] != "made from elsewhere" for x in api.get("/engagements").json())
    # The app itself, and clients that are not browsers, are not affected.
    for headers in ({"Sec-Fetch-Site": "same-origin", "Origin": "http://testserver"},
                    {"Origin": "http://testserver"}, {}):
        key = _key(api)
        r = api.post(f"/auth/keys/{key['id']}/revoke", headers=headers)
        assert r.status_code == 200 and r.json()["revoked"], (headers, r.text)
    # Reading is not refused: a page of another site cannot read the answer (no CORS).
    assert api.get("/auth/keys", headers={"Sec-Fetch-Site": "same-site"}).status_code == 200


def test_auth2_open_mode_refuses_another_sites_page_too(api, monkeypatch):
    """Open mode answers anyone on the machine; a web page the operator visits is not anyone."""
    monkeypatch.delenv("ATTACKLEDGER_API_TOKEN", raising=False)
    r = api.post("/engagements", json={"name": "lab"}, headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403
    assert api.post("/engagements", json={"name": "lab"}).status_code == 201


# ---- AUTH-3: separation of duties did not count who imported the evidence ------------------------

def test_auth3_whoever_imported_a_lanes_evidence_cannot_sign_it(client):  # noqa: F811
    """With separation of duties on, the person who supplied evidence cannot sign its receipt:
    for agent and recon runs the person who started them counts, not only who attached. An import
    is the same: the person who uploaded the export supplied the exchanges, whoever mapped them."""
    import test_import as ti
    ids, e, a = ti.team(client)
    client.put(f"/engagements/{e}/members", json={"members": [
        {"user_id": ids["tess"], "roles": ["tester"]},
        {"user_id": ids["rita"], "roles": ["tester", "reviewer"]}]})
    assert client.patch(f"/engagements/{e}", json={"separation_of_duties": True}).status_code == 200
    athn = ti.lane(client, a, "athn")

    sign_in(client, "rita@lab.test")                       # Rita uploads the export ...
    assert ti.upload(client, e, ti.HAR).status_code == 201
    sign_in(client, "tess@lab.test")                       # ... Tess maps it and resolves the lane
    login = ti.by_url(client, e, "/rest/user/login")
    r = client.post(f"/engagements/{e}/inbox/map", json={
        "entry_ids": [login["id"]], "targets": [{"lane_id": athn["id"], "item_idx": 1}], "mark_done": True})
    assert r.status_code == 200, r.text
    for it in client.get(f"/lanes/{athn['id']}").json()["items"]:
        if it["state"] == "open":
            client.patch(f"/lanes/{athn['id']}/items/{it['idx']}", json={"state": "na", "na_reason": "lab"})

    sign_in(client, "rita@lab.test")
    view = client.get(f"/lanes/{athn['id']}").json()
    assert view["can_sign"]["ok"] is False and "imported" in view["can_sign"]["reason"]
    r = client.post(f"/lanes/{athn['id']}/close", json={"reviewed": True})
    assert r.status_code == 422 and "imported" in r.json()["detail"]

    sign_in(client, "owner@lab.test")                      # someone who did neither signs it
    r = client.post(f"/lanes/{athn['id']}/close", json={"reviewed": True})
    assert r.status_code == 200, r.text


# ---- AUTH-4: a non-ASCII bearer token or cookie gave a 500 ---------------------------------------

def test_auth4_non_ascii_tokens_and_cookies_are_refused_with_401(api, monkeypatch):
    """hmac.compare_digest raises TypeError on a str with a non-ASCII character. Starlette decodes
    headers as Latin-1, so a request could make the API answer 500 instead of 401."""
    monkeypatch.setenv("ATTACKLEDGER_API_TOKEN", "operator-token-for-tests-0001")
    monkeypatch.setenv("ATTACKLEDGER_WORKER_TOKEN", "worker-token-for-tests-00001")
    monkeypatch.setenv("ATTACKLEDGER_GATEWAY_TOKEN", "gateway-token-for-tests-0001")
    other = b"caf\xc3\xa9-\xe2\x82\xac"                               # UTF-8 bytes; read back as Latin-1
    for path, headers in (("/engagements", {"authorization": b"Bearer " + other}),
                          ("/engagements", {"cookie": b"al_session=" + other}),
                          ("/worker/ping", {"authorization": b"Bearer " + other}),
                          ("/gateway/dns-scopes", {"authorization": b"Bearer " + other})):
        r = api.get(path, headers=headers)
        assert r.status_code == 401, (path, r.status_code, r.text)
    r = api.post("/auth/login", json={"token": "café €"})
    assert r.status_code == 401
    # Control: the right token still opens them.
    assert api.get("/engagements", headers={"authorization": "Bearer operator-token-for-tests-0001"}).status_code == 200


# ---- AUTH-7: a malformed signed payload gave a 500 -----------------------------------------------

def test_auth7_a_payload_with_fields_of_the_wrong_type_is_refused_with_422(monkeypatch):
    """A payload in canonical form whose fields have other types (a time without a zone, a list for
    the chain position, a string id) raised inside the checks."""
    import json as _json

    import test_signing as ts
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app import db
    from app.main import app
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
    try:
        with TestClient(app, raise_server_exceptions=False) as c:
            e, lane, ids = ts.setup(c)
            ts.sign_in(c, "rita@lab.test")
            k = ts.register(c)

            def changed(**change):
                def mutate(payload):
                    p = _json.loads(payload)
                    for path, value in change.items():
                        node = p
                        *parents, last = path.split("__")
                        for n in parents:
                            node = node[n]
                        node[last] = value
                    return _json.dumps(p, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                return mutate
            for change in ({"issued_at": "2026-10-10T10:00:00"}, {"chain__seq": [1]}, {"chain__seq": "1"},
                           {"lane__id": str(lane)}, {"signer__name": 7}, {"issued_at": "yesterday"}):
                r = ts.signed_close(c, lane, k, changed(**change))
                assert r.status_code == 422 and "malformed" in r.json()["detail"], (change, r.status_code, r.text)
            assert ts.signed_close(c, lane, k).status_code == 200             # control: the real payload signs
    finally:
        app.dependency_overrides.clear()


# ---- AUTH-6: a token-mode cookie was a fixed HMAC of the token -----------------------------------

TOKEN = "operator-token-for-tests-0006"


def _token_sign_in(api) -> str:
    api.cookies.clear()
    r = api.post("/auth/login", json={"token": TOKEN})
    assert r.status_code == 200, r.text
    return api.cookies.get(auth.COOKIE)


def _with_cookie(api, value):
    """/engagements with this cookie only, as a browser holding a copy of it would ask."""
    api.cookies.clear()
    api.cookies.set(auth.COOKIE, value)
    return api.get("/engagements")


def test_auth6_signing_out_revokes_a_copied_token_mode_cookie(api, monkeypatch):
    """The cookie was HMAC(token, constant): signing out deleted it in the browser only, and a
    copy of it worked until the token changed."""
    monkeypatch.setenv("ATTACKLEDGER_API_TOKEN", TOKEN)
    value = _token_sign_in(api)
    assert _with_cookie(api, value).status_code == 200                 # control: the session works
    api.cookies.set(auth.COOKIE, value)
    assert api.post("/auth/logout").status_code == 200
    assert _with_cookie(api, value).status_code == 401                 # the copy is dead too
    # The bearer path (scripts, the worker's tools, the gateway) is unchanged.
    assert api.get("/engagements", headers={"authorization": f"Bearer {TOKEN}"}).status_code == 200


def test_auth6_token_mode_sessions_are_random_and_stored_as_hashes(api, monkeypatch):
    import hmac as _hmac

    from app.models import UserSession
    monkeypatch.setenv("ATTACKLEDGER_API_TOKEN", TOKEN)
    one, two = _token_sign_in(api), _token_sign_in(api)
    assert one != two and TOKEN not in one + two
    old = _hmac.new(TOKEN.encode(), b"attackledger-session-v1", hashlib.sha256).hexdigest()
    assert _with_cookie(api, old).status_code == 401                   # the old derived cookie is refused
    with api.Session() as s:
        rows = s.query(UserSession).all()
        stored = {r.token_sha256 for r in rows}
        assert stored == {sha(one.encode()), sha(two.encode())}
        assert all(r.user_id is None and TOKEN not in (r.token_binding or "") for r in rows)
    api.cookies.set(auth.COOKIE, one)                                  # signing out ends that one only
    api.post("/auth/logout")
    assert _with_cookie(api, one).status_code == 401 and _with_cookie(api, two).status_code == 200


def test_auth6_token_mode_sessions_expire_like_people_sessions(api, monkeypatch):
    from datetime import datetime, timedelta, timezone

    from app.models import UserSession
    monkeypatch.setenv("ATTACKLEDGER_API_TOKEN", TOKEN)
    value = _token_sign_in(api)
    with api.Session() as s:
        row = s.query(UserSession).one()
        assert abs((auth._aware(row.expires_at) - auth._aware(row.created_at))
                   - timedelta(hours=auth.SESSION_HOURS)) < timedelta(seconds=5)
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        s.commit()
    assert _with_cookie(api, value).status_code == 401


def test_auth6_changing_the_api_token_ends_every_token_session(api, monkeypatch):
    """A session belongs to the token it was opened with. Once the API starts with another token
    (auth.end_stale_token_sessions runs at start-up, and at every token sign-in), the sessions of
    the old one are deleted, so changing the token back does not bring them back."""
    from app.models import UserSession
    monkeypatch.setenv("ATTACKLEDGER_API_TOKEN", TOKEN)
    value = _token_sign_in(api)
    monkeypatch.setenv("ATTACKLEDGER_API_TOKEN", TOKEN + "-new")
    assert _with_cookie(api, value).status_code == 401                 # bound to the old token
    with api.Session() as s:
        assert auth.end_stale_token_sessions(s) == 1
        assert s.query(UserSession).count() == 0
    monkeypatch.setenv("ATTACKLEDGER_API_TOKEN", TOKEN)
    assert _with_cookie(api, value).status_code == 401                 # gone for good


def test_auth6_token_sessions_work_and_end_in_people_mode_too(api, monkeypatch):
    """With people, the token still signs a browser in as the operator (automation, recovery)."""
    _people(api, monkeypatch)
    monkeypatch.setenv("ATTACKLEDGER_API_TOKEN", TOKEN)
    value = _token_sign_in(api)
    assert api.get("/auth/me").json()["kind"] == "token"
    assert _with_cookie(api, value).status_code == 200
    api.cookies.set(auth.COOKIE, value)
    api.post("/auth/logout")
    assert _with_cookie(api, value).status_code == 401
    monkeypatch.delenv("ATTACKLEDGER_API_TOKEN")
    assert sign_in(api, "owner@lab.test").status_code == 200           # control: people still sign in

