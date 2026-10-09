"""Organizations (D-042, docs/ORGANIZATIONS.md): every record belongs to one, and a caller sees
their own organization only.

The core test walks every route in authz.RULES as a member and as an owner of another
organization, with that organization's real ids: every one answers 404, exactly as an id that
was never used does, shows nothing of the other organization, and changes none of its rows. A
positive control proves the ids are real (the owning organization reaches them). Body and
query parameters that name ids are walked the same way. The worker and gateway channels, the
chains, sign-in and the single-organization install are tested after it.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect as sa_inspect, select, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import orgfill
from harness import ROOT
from orgfill import PW, bearer, sign_in

from app import auditlog, auth, authz, db, keylog, orgs, orgscope, people
from app.main import app
from app.models import (AuditEntry, Engagement, GatewayRequest, Job, KeyLogEntry, Membership, Organization,
                        OrgOwned, User)

T1, T2 = "cnryonex", "cnrytwoy"           # tags: org 1's names, hosts and texts carry T1
W1, G1 = "worker-token-of-the-deployment-0000", "gateway-token-of-the-deployment-000"
W2, G2 = "worker-token-of-org-two-000000000000", "gateway-token-of-org-two-0000000000"
NEVER = 987654                             # an id no table uses


def _engine():
    """SQLite in memory; or, with ATTACKLEDGER_TEST_PG_EMPTY_URL, a Postgres database these
    tests may empty (the claim's SKIP LOCKED and the chains' advisory locks run there)."""
    url = os.environ.get("ATTACKLEDGER_TEST_PG_EMPTY_URL")
    if url:
        eng = create_engine(url)
        db.Base.metadata.drop_all(eng)
    else:
        eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    db.Base.metadata.create_all(eng)
    return eng


@pytest.fixture()
def orgs2(monkeypatch):
    """Two organizations, each filled through the API: org 1 is the default one (the
    deployment's tokens), org 2 was made on the server with tokens of its own."""
    monkeypatch.delenv("ATTACKLEDGER_API_TOKEN", raising=False)
    monkeypatch.setenv("ATTACKLEDGER_WORKER_TOKEN", W1)
    monkeypatch.setenv("ATTACKLEDGER_GATEWAY_TOKEN", G1)
    auth._failures.clear()
    eng = _engine()
    Session = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)

    def _session():
        s = Session()
        try:
            yield s
        finally:
            s.close()
    app.dependency_overrides[db.get_session] = _session
    monkeypatch.setattr(people, "SessionLocal", Session)
    with TestClient(app) as c1:
        orgfill._ok(c1.post("/people", json={"email": f"owner-{T1}@example.com", "name": f"Olive {T1}",
                                             "password": PW, "is_owner": True}))
        sign_in(c1, f"owner-{T1}@example.com")
        one = orgfill.fill(c1, tag=T1, owner_email=f"owner-{T1}@example.com", worker_token=W1, gateway_token=G1)
        with Session() as s:                # what python -m app.orgs does
            org = Organization(name="Org two", worker_token_sha256=hashlib.sha256(W2.encode()).hexdigest(),
                               gateway_token_sha256=hashlib.sha256(G2.encode()).hexdigest())
            s.add(org)
            s.commit()
            two_id = org.id
        monkeypatch.setenv("ATTACKLEDGER_NEW_PASSWORD", PW)
        assert people.main(["create", "--org", str(two_id), "--owner", "--email", f"owner-{T2}@example.com",
                            "--name", f"Olive {T2}"]) == 0
        c2 = TestClient(app)
        sign_in(c2, f"owner-{T2}@example.com")
        two = orgfill.fill(c2, tag=T2, owner_email=f"owner-{T2}@example.com", worker_token=W2, gateway_token=G2)
        m2 = TestClient(app)                # a member of org 2: tester and reviewer on its engagement
        sign_in(m2, two["reviewer_email"])
        sign_in(c1, f"owner-{T1}@example.com")
        yield {"c1": c1, "c2": c2, "m2": m2, "one": one, "two": two, "Session": Session, "two_id": two_id}
    app.dependency_overrides.clear()


# ---- the walk -------------------------------------------------------------------------------

# What each path parameter names, from what orgfill made. idx and part name no row.
def path_values(ids: dict) -> dict:
    return {"eng_id": ids["eng"], "lane_id": ids["lane"], "job_id": ids["recon_job"], "user_id": ids["reviewer"],
            "key_id": ids["key"], "entry_id": ids["entry"], "account_id": ids["account"], "pid": ids["proposal"],
            "digest": ids["note_digest"], "idx": 1, "part": "request"}


ROW_PARAMS = {"eng_id", "lane_id", "job_id", "user_id", "key_id", "entry_id", "account_id", "pid", "digest"}
NOT_A_ROW = {"idx", "part", "name"}         # an item's index, a part's name, a timestamp root's file name
CHANNELS = ("public", "gateway", "worker", "job")   # tested in their own tests below


def body_for(method: str, path: str, ids: dict):
    """A body each route accepts, so validation never answers before the route does; the ids
    in it are the given organization's (see the body-id test)."""
    return {
        ("POST", "/auth/keys"): {"algorithm": "Ed25519", "public_key": "AAAA"},
        ("POST", "/auth/password"): {"current_password": "not the password", "new_password": "x" * 14},
        ("POST", "/engagements"): {"name": "a new engagement"},
        ("PATCH", "/engagements/{eng_id}"): {"separation_of_duties": False},
        ("PUT", "/engagements/{eng_id}/scope"): {"include": ["*.example.org"]},
        ("POST", "/engagements/{eng_id}/attest"): {"operator": "x", "policy_url": "https://example.com/p", "confirm": True},
        ("POST", "/engagements/{eng_id}/scope/import"): {"csv": "identifier,asset_type\n"},
        ("PUT", "/engagements/{eng_id}/members"): {"members": []},
        ("POST", "/people"): {"email": "new@example.com", "name": "New", "password": PW},
        ("PATCH", "/people/{user_id}"): {"name": "Renamed"},
        ("POST", "/engagements/{eng_id}/content/delete"): {"confirm_name": "nope"},
        ("POST", "/engagements/{eng_id}/assets"): {"host": f"new.{ids['tag']}.example.com"},
        ("POST", "/engagements/{eng_id}/jobs"): {"kind": "resolve", "targets": []},
        ("POST", "/engagements/{eng_id}/pipeline"): {"kinds": ["resolve"]},
        ("POST", "/lanes"): {"asset_id": ids["asset"], "role": "authz"},
        ("PATCH", "/lanes/{lane_id}"): {"executor": "manual"},
        ("POST", "/lanes/{lane_id}/evidence"): {"kind": "note", "sha256": "0" * 64, "summary": "s"},
        ("POST", "/lanes/{lane_id}/attach"): {"item_idx": 1, "kind": "note", "text": "t"},
        ("PATCH", "/lanes/{lane_id}/items/{idx}"): {"state": "open"},
        ("POST", "/lanes/{lane_id}/agent-runs"): {"driver": "d"},
        ("POST", "/engagements/{eng_id}/inbox/map"): {"entry_ids": [ids["entry2"]],
                                                      "targets": [{"lane_id": ids["lane2"], "item_idx": 1}]},
        ("POST", "/engagements/{eng_id}/inbox/dismiss"): {"entry_ids": [ids["entry"]]},
        ("POST", "/engagements/{eng_id}/inbox/restore"): {"entry_ids": [ids["entry2"]]},
        ("POST", "/engagements/{eng_id}/test-accounts"): {"label": "Z", "role": "r", "hosts": [ids["host"]],
                                                          "kind": "cookie", "value": "a=b"},
        ("PUT", "/engagements/{eng_id}/test-accounts/{account_id}"): {"role": "other"},
        ("POST", "/engagements/{eng_id}/approvals/{pid}/approve"): {"request_sha256": "0" * 64},
        ("POST", "/engagements/{eng_id}/approvals/{pid}/confirm-delete"): {"request_sha256": "0" * 64,
                                                                           "confirm_path": "/"},
        ("POST", "/engagements/{eng_id}/approvals/{pid}/reject"): {"note": "no"},
        ("POST", "/lanes/{lane_id}/close"): {"reviewed": True},
    }.get((method, path))


def call(c, method, path, values, body=None, raw=None, params=None):
    url = re.sub(r"\{(\w+)\}", lambda m: str(values[m.group(1)]), path)
    if raw is not None:
        return c.request(method, url, content=raw, params=params,
                         headers={"content-type": "application/octet-stream"})
    return c.request(method, url, json=body, params=params)


def _norm(r, *ids) -> tuple:
    """Status and body with the ids replaced, to compare an answer for another organization's
    id with the answer for an id that was never used."""
    body = r.text
    for i in ids:
        body = re.sub(rf"\b{re.escape(str(i))}\b", "ID", body)
    return r.status_code, body


def routes() -> list[tuple[str, str, str]]:
    out = []
    for r in app.routes:
        if isinstance(r, APIRoute):
            for m in sorted(r.methods):
                perm = authz.RULES[(m, r.path)][0]
                out.append((m, r.path, perm))
    assert {(m, p) for m, p, _ in out} == set(authz.RULES)        # the walk covers the whole table
    return out


def snapshot(Session, org: int) -> str:
    """Every row of one organization, direct and through its parents, as one hash."""
    h = hashlib.sha256()
    through = {"checklist_items": "SELECT c.* FROM checklist_items c JOIN lanes l ON l.id = c.lane_id "
                                  "WHERE l.organization_id = :o ORDER BY c.id",
               "receipts": "SELECT r.* FROM receipts r JOIN lanes l ON l.id = r.lane_id "
                           "WHERE l.organization_id = :o ORDER BY r.id",
               "agent_exchanges": "SELECT x.* FROM agent_exchanges x JOIN jobs j ON j.id = x.job_id "
                                  "WHERE j.organization_id = :o ORDER BY x.id",
               "signing_keys": "SELECT k.* FROM signing_keys k JOIN users u ON u.id = k.user_id "
                               "WHERE u.organization_id = :o ORDER BY k.id",
               "user_sessions": "SELECT us.id, us.user_id FROM user_sessions us JOIN users u ON u.id = us.user_id "
                                "WHERE u.organization_id = :o ORDER BY us.id"}
    with Session() as s:
        for t in sorted(db.Base.metadata.tables):
            if t == "organizations":
                q = "SELECT * FROM organizations WHERE id = :o"
            elif t in through:
                q = through[t]
            else:
                assert "organization_id" in db.Base.metadata.tables[t].c, t
                q = f"SELECT * FROM {t} WHERE organization_id = :o ORDER BY id"
            for row in s.execute(text(q), {"o": org}):
                h.update(repr((t, tuple(row))).encode())
    return h.hexdigest()


def test_every_table_is_owned_directly_or_through_a_parent():
    for t, table in db.Base.metadata.tables.items():
        cls = next(m.class_ for m in db.Base.registry.mappers if m.local_table is table)
        if cls is Organization:
            continue
        assert issubclass(cls, OrgOwned) != (cls in orgscope.THROUGH), t
        if cls in orgscope.THROUGH:            # its parent is owned, and the column names it
            fk = orgscope.THROUGH[cls]
            assert any(fk == k and issubclass(p, OrgOwned) for k, _, p in orgscope._parents(cls)), t


def test_no_route_reaches_another_organization(orgs2):
    """The walk: every route, another organization's ids, as its owner and as a member."""
    c1, c2, m2, one, two, Session = (orgs2[k] for k in ("c1", "c2", "m2", "one", "two", "Session"))
    foreign, own, never = path_values(one), path_values(two), {k: NEVER for k in ROW_PARAMS}
    never.update(idx=1, part="request", digest="f" * 64)
    before = snapshot(Session, 1)
    walked, skipped = 0, []
    for method, path, perm in routes():
        names = set(re.findall(r"\{(\w+)\}", path))
        if perm in CHANNELS:
            skipped.append((method, path))
            continue
        if not names & ROW_PARAMS:
            continue                               # nothing to point at: the list checks below
        raw = b"not an export" if path == "/engagements/{eng_id}/imports" else None
        for who in (c2, m2):
            # 1. every id the other organization's, 2. the first one ours and the rest theirs.
            mixes = [foreign]
            rest = [n for n in names & ROW_PARAMS if n not in ("eng_id", "lane_id")]
            if rest and names & {"eng_id", "lane_id"}:
                mixes.append({**own, **{n: foreign[n] for n in rest}})
            for values in mixes:
                body = body_for(method, path, two)
                r = call(who, method, path, values, body=body, raw=raw)
                assert r.status_code == 404, (method, path, values, r.status_code, r.text)
                assert T1 not in r.text, (method, path, r.text)
                gone = {**values, **{n: never[n] for n in names & ROW_PARAMS if values[n] == foreign[n]}}
                r0 = call(who, method, path, gone, body=body, raw=raw)
                ids = [foreign[n] for n in names & ROW_PARAMS] + [never[n] for n in names & ROW_PARAMS]
                assert _norm(r, *ids) == _norm(r0, *ids), (method, path, r.text, r0.text)
                walked += 1
    assert snapshot(Session, 1) == before          # nothing of org 1 changed
    assert sorted(skipped) == sorted((m, p) for (m, p), (perm, _) in authz.RULES.items() if perm in CHANNELS)
    assert walked >= 2 * 50

    # Positive control: the same ids are real; their organization reaches every one of them
    # (a body that does not validate stops a write before the route runs; 404 never comes).
    for method, path, perm in routes():
        names = set(re.findall(r"\{(\w+)\}", path))
        if perm in CHANNELS or not names & ROW_PARAMS:
            continue
        who = c1
        if path.startswith("/auth/keys/"):
            who = TestClient(app)
            sign_in(who, one["reviewer_email"])        # a key is its owner's only
        body, raw = ([], None) if method != "GET" else (None, None)
        if path == "/engagements/{eng_id}/imports":
            body, raw = None, b"not an export"
        if method in ("POST",) and body_for(method, path, one) is None and raw is None:
            body = None                                 # routes without a body
        r = call(who, method, path, foreign, body=body, raw=raw,
                 params={"key": one["key_fingerprint"]} if path.endswith("receipt-payload") else None)
        assert r.status_code != 404, (method, path, r.status_code, r.text)


def test_lists_and_counts_show_only_your_organization(orgs2):
    c2, m2, two, one = orgs2["c2"], orgs2["m2"], orgs2["two"], orgs2["one"]
    own = path_values(two)
    for method, path, perm in routes():
        if perm in CHANNELS or method != "GET":
            continue
        for who in (c2, m2):
            values = {**own, "name": "x"}
            params = {"key": two["key_fingerprint"]} if path.endswith("receipt-payload") else None
            r = call(who, method, path, values, params=params)
            assert r.status_code < 500, (path, r.text)
            assert T1 not in r.text and one["host"] not in r.text, (method, path, r.text[:500])
    # The counts are org 2's own: its chain, its people, its engagements.
    audit = c2.get("/audit").json()
    with orgs2["Session"]() as s:
        n2 = s.scalar(select(text("count(*)")).select_from(AuditEntry).where(AuditEntry.organization_id == 2))
        n1 = s.scalar(select(text("count(*)")).select_from(AuditEntry).where(AuditEntry.organization_id == 1))
    assert audit["chain"]["intact"] and audit["chain"]["head"]["seq"] == n2 == len(audit["entries"]) and n1 > 0
    assert {p["email"] for p in c2.get("/people").json()} == {f"owner-{T2}@example.com", two["reviewer_email"],
                                                              two["viewer_email"]}
    assert [e["id"] for e in c2.get("/engagements").json()] == [two["eng"]]
    assert c2.get("/auth/keys").json() == [] and len(m2.get("/auth/keys").json()) == 1


def test_ids_in_bodies_and_queries_answer_as_if_never_used(orgs2):
    """The handler-side ids: in a body or a query, another organization's id gets the answer a
    never-used id gets."""
    c2, m2, one, two, Session = (orgs2[k] for k in ("c2", "m2", "one", "two", "Session"))
    before = snapshot(Session, 1)
    e, lane, entry = two["eng"], two["lane"], two["entry2"]
    cases = [
        ("POST", "/lanes", lambda x: {"json": {"asset_id": x, "role": "authz"}}, "asset"),
        ("PUT", f"/engagements/{e}/members", lambda x: {"json": {"members": [{"user_id": x, "roles": ["viewer"]}]}},
         "reviewer"),
        ("POST", f"/lanes/{lane}/attach", lambda x: {"json": {"item_idx": 1, "kind": "run", "job_id": x}}, "recon_job"),
        ("POST", f"/engagements/{e}/inbox/map",
         lambda x: {"json": {"entry_ids": [x], "targets": [{"lane_id": two["lane2"], "item_idx": 1}]}}, "entry"),
        ("POST", f"/engagements/{e}/inbox/map",
         lambda x: {"json": {"entry_ids": [entry], "targets": [{"lane_id": x, "item_idx": 1}]}}, "lane2"),
        ("POST", f"/engagements/{e}/inbox/dismiss", lambda x: {"json": {"entry_ids": [x]}}, "entry"),
        ("POST", f"/engagements/{e}/inbox/restore", lambda x: {"json": {"entry_ids": [x]}}, "entry2"),
        ("GET", f"/engagements/{e}/inbox", lambda x: {"params": {"batch": x}}, "batch"),
        ("GET", f"/engagements/{e}/gateway-log", lambda x: {"params": {"job_id": x}}, "agent_job"),
        ("GET", f"/lanes/{lane}/receipt-payload", lambda x: {"params": {"key": x}}, "key_fingerprint"),
        ("POST", f"/lanes/{two['lane2']}/close",
         lambda x: {"json": {"reviewed": True, "payload": "{}", "signature": "AA==", "key_fingerprint": x}},
         "key_fingerprint"),
    ]
    for who in (c2, m2):
        for method, url, make, key in cases:
            theirs = one[key]
            never = "e" * 64 if key == "key_fingerprint" else NEVER
            r, r0 = who.request(method, url, **make(theirs)), who.request(method, url, **make(never))
            assert _norm(r, theirs, never) == _norm(r0, theirs, never), (url, key, r.text, r0.text)
            assert T1 not in r.text and r.status_code != 200 or method == "GET", (url, r.text)
    assert snapshot(Session, 1) == before


def test_names_and_emails_are_per_organization(orgs2):
    """No oracle: org 2 can use org 1's engagement name and a person's email."""
    c2, one = orgs2["c2"], orgs2["one"]
    assert c2.post("/engagements", json={"name": f"Engagement {T1}"}).status_code == 201
    assert c2.post("/engagements", json={"name": f"Engagement {T1}"}).status_code == 409    # within org 2: taken
    r = c2.post("/people", json={"email": one["reviewer_email"], "name": "Another Rita", "password": PW + "2"})
    assert r.status_code == 201
    # Both accounts sign in, each into its own organization: the password decides.
    a, b = TestClient(app), TestClient(app)
    sign_in(a, one["reviewer_email"])
    sign_in(b, one["reviewer_email"], PW + "2")
    assert a.get("/auth/me").json()["user_id"] == one["reviewer"]
    assert b.get("/auth/me").json()["user_id"] == r.json()["id"]
    assert [x["id"] for x in b.get("/engagements").json()] == []
    assert a.post("/auth/login", json={"email": one["reviewer_email"], "password": "wrong password!"}).status_code == 401


def test_a_row_that_would_join_two_organizations_is_refused(orgs2):
    one, two, Session = orgs2["one"], orgs2["two"], orgs2["Session"]
    with Session() as s:                                   # even the operator's session refuses it
        s.add(Membership(engagement_id=two["eng"], user_id=one["viewer"], roles=["viewer"]))
        with pytest.raises(orgscope.TenancyError, match="different organizations"):
            s.flush()
    with Session() as s:
        orgscope.scope(s, 2)
        assert s.get(Engagement, one["eng"]) is None and s.get(User, one["viewer"]) is None
        s.add(Engagement(name="x", organization_id=1))     # written for org 1 from org 2's request
        with pytest.raises(orgscope.TenancyError):
            s.flush()
    with Session() as s:
        orgscope.scope(s, 2)
        job = s.get(Job, two["recon_job"])
        job.engagement_id = one["eng"]                     # moving a row to another organization's parent
        with pytest.raises(orgscope.TenancyError):
            s.flush()
    with Session() as s:
        orgscope.pend(s)                                   # a request before its caller is known
        with pytest.raises(orgscope.TenancyError, match="before the caller"):
            s.scalars(select(Engagement)).all()


# ---- the worker and the gateway ----------------------------------------------------------------

def test_a_worker_claims_only_its_organizations_jobs(orgs2):
    c1, c2, one, two = orgs2["c1"], orgs2["c2"], orgs2["one"], orgs2["two"]
    j2 = orgfill._ok(c2.post(f"/engagements/{two['eng']}/jobs", json={"kind": "resolve", "targets": [two["host"]]}))
    assert c1.post("/worker/claim", json={}, headers=bearer(W1)).json() == {"job": None}     # not the default org's
    spec = c1.post("/worker/claim", json={}, headers=bearer(W2)).json()["job"]
    assert spec["id"] == j2["id"] and spec["organization_id"] == orgs2["two_id"]
    j1 = orgfill._ok(c1.post(f"/engagements/{one['eng']}/jobs", json={"kind": "resolve", "targets": [one["host"]]}))
    assert c1.post("/worker/claim", json={}, headers=bearer(W2)).json() == {"job": None}
    spec1 = c1.post("/worker/claim", json={}, headers=bearer(W1)).json()["job"]
    assert spec1["id"] == j1["id"] and spec1["organization_id"] == 1
    # A job token opens its own job only, whichever organization it is in.
    assert c1.post(f"/worker/jobs/{j1['id']}/log", json={"lines": ["x"]}, headers=bearer(spec["token"])).status_code == 401
    assert c1.post(f"/worker/jobs/{j2['id']}/log", json={"lines": ["x"]}, headers=bearer(spec["token"])).status_code == 200
    # An outside driver's run is claimed by id, by its own organization's worker only.
    assert c1.post("/worker/claim", json={"job_id": one["agent_job"]}, headers=bearer(W2)).json() == {"job": None}
    for tok in ("", "wrong-token", G2):
        assert c1.post("/worker/claim", json={}, headers=bearer(tok)).status_code == 401


def test_results_written_by_a_job_belong_to_its_organization(orgs2):
    c1, two, Session = orgs2["c1"], orgs2["two"], orgs2["Session"]
    j = orgfill._ok(orgs2["c2"].post(f"/engagements/{two['eng']}/jobs", json={"kind": "resolve",
                                                                            "targets": [two["host"]]}))
    spec = c1.post("/worker/claim", json={}, headers=bearer(W2)).json()["job"]
    assert spec["id"] == j["id"]
    orgfill._ok(c1.post(f"/worker/jobs/{j['id']}/results", headers=bearer(spec["token"]),
                        json={"observations": [{"host": f"new.{T2}.example.com", "data": {"a": ["192.0.2.1"]}}]}))
    with Session() as s:
        rows = s.execute(text("SELECT organization_id FROM observations WHERE job_id = :j"), {"j": j["id"]}).all()
        assets = s.execute(text("SELECT organization_id FROM assets WHERE host = :h"),
                           {"h": f"new.{T2}.example.com"}).all()
    assert rows == [(orgs2["two_id"],)] and assets == [(orgs2["two_id"],)]


def test_a_gateway_answers_for_its_organization_only(orgs2):
    c1, one, two, Session = orgs2["c1"], orgs2["one"], orgs2["two"], orgs2["Session"]
    sess = {"job_id": one["agent_job"], "secret": one["agent_gateway_secret"]}
    ok = c1.post("/gateway/session", json=sess, headers=bearer(G1))
    assert ok.status_code == 200 and ok.json()["organization_id"] == 1                # positive control
    r = c1.post("/gateway/session", json=sess, headers=bearer(G2))
    r0 = c1.post("/gateway/session", json={**sess, "job_id": NEVER}, headers=bearer(G2))
    assert r.status_code == 404 and _norm(r, one["agent_job"], NEVER) == _norm(r0, one["agent_job"], NEVER)
    for route, extra in (("/gateway/account", {"label": "A", "host": one["host"]}),
                         ("/gateway/approval", {"approval_id": one["proposal"], "method": "POST",
                                                "url": f"https://{one['host']}/api/basket", "body_sha256": "0" * 64})):
        assert c1.post(route, json={**sess, **extra}, headers=bearer(G2)).status_code == 404
    mine = c1.post("/gateway/session", json={"job_id": two["agent_job"], "secret": two["agent_gateway_secret"]},
                   headers=bearer(G2))
    assert mine.status_code == 200 and mine.json()["organization_id"] == orgs2["two_id"]
    assert [d["engagement_id"] for d in c1.get("/gateway/dns-scopes", headers=bearer(G2)).json()] == [two["eng"]]
    assert [d["engagement_id"] for d in c1.get("/gateway/dns-scopes", headers=bearer(G1)).json()] == [one["eng"]]
    # Log rows that name another organization's engagement or job keep neither, and stay its own.
    before = snapshot(Session, 1)
    orgfill._ok(c1.post("/gateway/log", headers=bearer(G2), json={"rows": [
        {"at": "2026-10-10T00:00:00+00:00", "engagement_id": one["eng"], "job_id": one["agent_job"], "tool": "x",
         "kind": "target", "method": "GET", "url": "https://x.example.org/", "verdict": "refused",
         "approval_id": one["proposal"]}]}))
    assert snapshot(Session, 1) == before
    with Session() as s:
        row = s.scalars(select(GatewayRequest).order_by(GatewayRequest.id.desc())).first()
        assert (row.organization_id, row.engagement_id, row.job_id) == (orgs2["two_id"], None, None)


def test_without_any_token_the_channels_stay_closed(orgs2, monkeypatch):
    c1, Session = orgs2["c1"], orgs2["Session"]
    monkeypatch.delenv("ATTACKLEDGER_WORKER_TOKEN")
    monkeypatch.delenv("ATTACKLEDGER_GATEWAY_TOKEN")
    assert c1.get("/worker/ping", headers=bearer(W1)).status_code == 401              # the file token is gone
    assert c1.get("/worker/ping", headers=bearer(W2)).status_code == 200              # org 2's still opens
    with Session() as s:
        s.execute(text("UPDATE organizations SET worker_token_sha256 = NULL, gateway_token_sha256 = NULL"))
        s.commit()
    assert c1.get("/worker/ping", headers=bearer(W2)).status_code == 503
    assert c1.get("/gateway/dns-scopes", headers=bearer(G2)).status_code == 503


# ---- chains and reports ----------------------------------------------------------------------

def verify(report: dict, tmp_path: Path) -> str:
    p = tmp_path / f"r{hashlib.sha256(json.dumps(report).encode()).hexdigest()[:8]}.json"
    p.write_text(json.dumps(report))
    r = subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "verify_report.py"), str(p)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    return r.stdout


def test_each_organization_has_its_own_chains_and_reports_verify(orgs2, tmp_path):
    c1, c2, one, two, Session = (orgs2[k] for k in ("c1", "c2", "one", "two", "Session"))
    with Session() as s:
        for model in (AuditEntry, KeyLogEntry):
            for org in (1, orgs2["two_id"]):
                rows = s.scalars(select(model).where(model.organization_id == org).order_by(model.seq)).all()
                assert [e.seq for e in rows] == list(range(1, len(rows) + 1)) and rows[0].prev_hash == "0" * 64
        assert auditlog.verify(s) == [] and keylog.verify(s) == []             # every chain, by the operator
        assert auditlog.verify(s, 2) == [] and keylog.verify(s, 1) == []
    r1, r2 = c1.get(f"/engagements/{one['eng']}/report").json(), c2.get(f"/engagements/{two['eng']}/report").json()
    assert "Verified." in verify(r1, tmp_path) and "Verified." in verify(r2, tmp_path)
    assert T1 not in json.dumps(r2) and T2 not in json.dumps(r1)
    for log in ("audit_log", "key_log"):
        h1, h2 = {l["entry_hash"] for l in r1[log]["links"]}, {l["entry_hash"] for l in r2[log]["links"]}
        assert not h1 & h2 and r1[log]["head"] != r2[log]["head"]
    # Tampering in one organization's chain breaks that chain only.
    with Session() as s:
        e = s.scalars(select(AuditEntry).where(AuditEntry.organization_id == 1).order_by(AuditEntry.seq)).first()
        e.actor_name = "someone else"
        s.commit()
        assert auditlog.verify(s, 1) and auditlog.verify(s, 2) == []
        assert all(p.startswith("organization 1: ") for p in auditlog.verify(s))


def test_the_command_line_lists_each_organizations_chain(orgs2, capsys):
    assert people.main(["audit-log"]) == 0 and people.main(["key-log"]) == 0
    out = capsys.readouterr().out
    assert "org 1 " in out and f"org {orgs2['two_id']} " in out and out.count("chain: intact") == 2
    assert people.main(["set-password", "--email", orgs2["one"]["reviewer_email"]]) == 0      # one account: no --org


def test_the_orgs_command(orgs2, monkeypatch, capsys):
    monkeypatch.setattr("app.db.SessionLocal", orgs2["Session"])
    assert orgs.main(["create", "--name", "Org three"]) == 0
    assert orgs.main(["create", "--name", "Org three"]) == 1
    assert orgs.main(["worker-token", "--org", "Org three"]) == 0
    token = capsys.readouterr().out.strip().splitlines()[-1]
    assert orgs.main(["list"]) == 0
    listed = capsys.readouterr().out
    assert "Default organization  (default)" in listed and "Org three  (own worker token)" in listed
    r = orgs2["c1"].get("/worker/ping", headers=bearer(token))
    assert r.status_code == 200
    with orgs2["Session"]() as s:
        assert s.scalar(select(Organization.worker_token_sha256).where(Organization.name == "Org three")) \
            == hashlib.sha256(token.encode()).hexdigest()


# ---- one organization: exactly as before -----------------------------------------------------

def test_one_organization_shows_nothing_new(stack_one):
    c = stack_one
    me = c.get("/auth/me").json()
    assert "organization" not in me and set(me) == {"kind", "user_id", "name", "is_owner", "mode", "roles"}


def test_two_organizations_show_their_name(orgs2):
    assert orgs2["c2"].get("/auth/me").json()["organization"] == {"id": orgs2["two_id"], "name": "Org two"}
    assert orgs2["c1"].get("/auth/me").json()["organization"]["name"] == "Default organization"


@pytest.fixture()
def stack_one(monkeypatch):
    monkeypatch.delenv("ATTACKLEDGER_API_TOKEN", raising=False)
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
        with Session() as s:
            assert [o.name for o in s.scalars(select(Organization))] == ["Default organization"]
        yield c
    app.dependency_overrides.clear()


def test_every_tenant_table_has_the_column_in_the_database():
    eng = create_engine("sqlite://")
    db.Base.metadata.create_all(eng)
    insp = sa_inspect(eng)
    direct = {m.local_table.name for m in db.Base.registry.mappers if issubclass(m.class_, OrgOwned)}
    assert len(direct) == 17
    for t in direct:
        assert "organization_id" in {c["name"] for c in insp.get_columns(t)}, t
