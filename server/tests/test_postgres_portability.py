"""What once differed between SQLite and Postgres, and now behaves the same on both.

The suite runs on SQLite by default and on Postgres with ATTACKLEDGER_TEST_PG
(tools/test_postgres.sh). Each test here passes on both; on Postgres, before its fix, it failed:

  - times: a session in another zone than UTC stored aware times in its local time;
  - NUL: Postgres text cannot hold U+0000, so a NUL gave a 500 after part of the work, and on
    the gateway's channel it stopped the request log, and then the traffic, for good;
  - integers: Postgres INTEGER is 32 bits; a gateway log row with a count past 2 GiB did the same
    (the counts are BIGINT since migration 0025);
  - lengths: a column's length is enforced by Postgres only;
  - LIKE ignores case on SQLite only.
"""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import testdb
from sqlalchemy import select, text
from sqlalchemy.orm import sessionmaker

from harness import stack  # noqa: F401  (fixture)

from app import db, gatewayapi, importers, targets
from app.models import Endpoint, Engagement, GatewayRequest, Job, Organization, iso_utc

GATEWAY_TOKEN = "gateway-token-for-tests-000000000"


# ---- times -------------------------------------------------------------------------------------

def test_times_are_stored_in_utc_whatever_zone_the_database_session_is_in(monkeypatch):
    """PGTZ (or the server's TimeZone) set to a zone 3.5 hours from UTC: an aware time written
    and read back is the same instant. Before, it came back 3.5 hours later, so an approval and
    a session expired late and a receipt's issue time no longer matched its signed payload."""
    monkeypatch.setenv("PGTZ", "Asia/Tehran")
    eng = testdb.memory_engine()
    db.Base.metadata.create_all(eng)
    Session = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
    at = datetime(2026, 10, 10, 12, 0, 0, 123456, tzinfo=timezone.utc)
    with Session() as s:
        s.add(Organization(name="zones", created_at=at))
        s.commit()
    with Session() as s:
        stored = s.scalar(select(Organization.created_at).where(Organization.name == "zones"))
        assert iso_utc(stored) == "2026-10-10T12:00:00.123456+00:00"
        if testdb.on_postgres():
            assert s.scalar(text("SHOW TIME ZONE")) == "UTC"


# ---- NUL characters ----------------------------------------------------------------------------

def test_a_nul_from_a_person_is_refused_before_anything_is_stored(stack):
    r = stack.api.post("/engagements", json={"name": "lab\x00"})
    assert r.status_code == 422 and "NUL" in r.json()["detail"]
    with stack.Session() as s:
        assert s.scalars(select(Engagement)).all() == []
    assert stack.api.post("/engagements", json={"name": "lab"}).status_code == 201        # control
    e = stack.api.get("/engagements").json()[0]["id"]
    assert stack.api.get(f"/engagements/{e}/gateway-log?verdict=%00").status_code == 400
    assert stack.api.get(f"/engagements/{e}/gateway-log?verdict=refused").status_code == 200
    # A JSON string that only spells a backslash and "u0000" is ordinary text.
    assert stack.api.post("/engagements", json={"name": "lab \\u0000"}).status_code == 201


def _log_row(eng: int, job: int, **change) -> dict:
    return {"at": "2026-10-10T12:00:00+00:00", "engagement_id": eng, "job_id": job, "tool": "httpx",
            "kind": "target", "method": "GET", "url": "https://app.example.com/", "host": "app.example.com",
            "port": 443, "status": 200, "verdict": "allowed", **change}


def test_the_gateway_log_takes_every_row_it_is_sent(stack, monkeypatch):
    """A NUL in a URL (an agent can be steered to ask for one), or a response larger than 2 GiB
    (a target can send one): the API refused the batch on Postgres, the gateway kept it and sent
    it again, and nothing it logged after that row was ever written."""
    monkeypatch.setenv("ATTACKLEDGER_GATEWAY_TOKEN", GATEWAY_TOKEN)
    e = stack.engagement()
    job = stack.queue(e, "probe", ["app.example.com"])
    rows = [_log_row(e, job), _log_row(e, job, url="https://app.example.com/\x00admin", reason="cut\x00off"),
            _log_row(e, job, url="https://app.example.com/big", bytes_received=3_000_000_000,
                     duration_ms=2**40, port=70_000, status=10_000, approval_id=2**40),
            _log_row(e, job, url="https://app.example.com/huge", bytes_sent=2**70, bytes_received=2**62,
                     duration_ms=-5)]
    r = stack.api.post("/gateway/log", json={"rows": rows}, headers={"authorization": f"Bearer {GATEWAY_TOKEN}"})
    assert r.status_code == 200 and r.json() == {"written": 4, "unlogged": []}
    with stack.Session() as s:
        got = {g.url: g for g in s.scalars(select(GatewayRequest))}
    assert set(got) == {"https://app.example.com/", "https://app.example.com/�admin", "https://app.example.com/big",
                        "https://app.example.com/huge"}
    assert got["https://app.example.com/�admin"].reason == "cut�off"
    # Counts and durations are BIGINT (migration 0025): kept exactly, up to 2**63 - 1.
    big, huge = got["https://app.example.com/big"], got["https://app.example.com/huge"]
    assert big.bytes_received == 3_000_000_000 and big.duration_ms == 2**40
    assert huge.bytes_sent == gatewayapi.INT8_MAX == 2**63 - 1 and huge.bytes_received == 2**62
    assert huge.duration_ms is None
    assert big.port is None and big.status is None and big.approval_id is None
    assert got["https://app.example.com/"].port == 443 and got["https://app.example.com/"].status == 200


def test_the_worker_channel_keeps_a_nul_from_tool_output(stack):
    e = stack.engagement()
    stack.queue(e, "resolve", ["a.example.com"])
    job = stack.claim()
    job.log("tool said \x00 here")
    with stack.Session() as s:
        assert "tool said � here" in s.get(Job, job.id).log


def test_an_import_row_with_a_nul_in_its_url_is_unreadable_and_the_rest_import():
    data = (Path(__file__).parent / "data" / "import" / "sample.har").read_bytes()
    _, before = importers.parse(data)                  # the sample's own unreadable rows stay so
    har = json.loads(data)
    har["log"]["entries"][0]["request"]["url"] = "https://shop.example.com/\x00"
    har["log"]["entries"][1]["comment"] = "seen\x00twice"
    adapter, parsed = importers.parse(json.dumps(har).encode())
    assert adapter.id == "har" and [row for row, _ in parsed.unreadable] == [1] + [row for row, _ in before.unreadable]
    assert len(parsed.entries) == len(before.entries) - 1
    assert parsed.entries[0].row == 2 and parsed.entries[0].label == "seen\ufffdtwice"


# ---- lengths -----------------------------------------------------------------------------------

def test_an_evidence_uri_longer_than_its_column_is_refused(stack):
    e = stack.engagement()
    lane = stack.lane(e, "app.example.com")
    body = {"item_idx": 1, "kind": "note", "sha256": hashlib.sha256(b"x").hexdigest(), "summary": "s"}
    assert stack.api.post(f"/lanes/{lane}/evidence", json={**body, "uri": "u" * 1001}).status_code == 422
    # Redaction can make it longer than it was sent (a marker for "abc"): refused too, never cut.
    head = "https://app.example.com/?token=abc&q="
    r = stack.api.post(f"/lanes/{lane}/evidence", json={**body, "uri": head + "a" * (1000 - len(head))})
    assert r.status_code == 422 and "once redacted" in r.json()["detail"]
    assert stack.api.post(f"/lanes/{lane}/evidence", json={**body, "uri": "u" * 1000}).status_code == 201


# ---- LIKE ------------------------------------------------------------------------------------

def _endpoints(stack, e, urls_):
    job = stack.queue(e, "crawl", ["app.example.com"])
    with stack.Session() as s:
        for u in urls_:
            s.add(Endpoint(engagement_id=e, job_id=job, host="app.example.com", url=u,
                           url_sha256=hashlib.sha256(u.encode()).hexdigest(), source="katana"))
        s.commit()


def test_url_search_ignores_case_and_takes_wildcards_literally(stack):
    e = stack.engagement()
    _endpoints(stack, e, ["https://app.example.com/Admin/users", "https://app.example.com/a_b",
                          "https://app.example.com/axb", "https://app.example.com/100%"])

    def found(q):
        return sorted(i["url"].rsplit("/", 1)[-1] for i in stack.api.get(f"/engagements/{e}/endpoints",
                                                                          params={"q": q}).json()["items"])
    assert found("admin") == found("ADMIN") == ["users"]
    assert found("a_b") == ["a_b"]                  # "_" is not "any character"
    assert found("0%") == ["100%"]


def test_api_paths_count_for_triage_whatever_their_case(stack):
    e = stack.engagement()
    _endpoints(stack, e, ["https://app.example.com/API/v1/users", "https://app.example.com/Rest/orders/1",
                          "https://app.example.com/about"])
    with stack.Session() as s:
        shapes = targets.api_shapes_by_host(s, s.get(Engagement, e), ["app.example.com"])
    assert shapes == {"app.example.com": 2}
