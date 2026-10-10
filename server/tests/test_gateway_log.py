"""The gateway's request log when the API cannot store a row (gatewaylog.py, docs/GATEWAY.md).

The gateway keeps every row it has not written and refuses all traffic once 5,000 wait. A row
the API refuses therefore used to stop the log for good, and then the traffic: the gateway sent
the same batch again and again. Now:

  - the API writes every row it can and answers, by index, the rows it cannot store, storing a
    placeholder (verdict "unlogged") in each one's place;
  - the gateway sets such a row aside in its quarantine file (bounded, holding what the log row
    holds and nothing more), and, when the API refuses a whole batch with a 400, 413 or 422 (a
    body limit), halves it until the row is alone, then logs the placeholder itself;
  - every other failure (no answer, 5xx, a wrong token) keeps the rows queued, as before: the
    gateway still fails closed.
"""
import asyncio
import json
import os
import threading

import pytest
from sqlalchemy import select

from harness import stack  # noqa: F401  (fixture)
from test_gateway import SECRET, FakeApi, Stack as GatewayStack

from app import gateway, gatewaylog
from app.models import GatewayRequest

GATEWAY_TOKEN = "gateway-token-for-tests-000000000"


def row(eng=None, job=None, **change) -> dict:
    return {"at": "2026-10-10T12:00:00+00:00", "engagement_id": eng, "job_id": job, "tool": "httpx",
            "kind": "target", "method": "GET", "url": "https://app.example.com/", "host": "app.example.com",
            "port": 443, "status": 200, "verdict": "allowed", **change}


def post(stack, rows):
    return stack.api.post("/gateway/log", json={"rows": rows}, headers={"authorization": f"Bearer {GATEWAY_TOKEN}"})


# ---- the API: every row it can, a placeholder for each it cannot -------------------------------

def test_the_api_stores_every_row_it_can_and_a_placeholder_for_each_it_cannot(stack, monkeypatch):
    """Before, one such row made the API refuse the batch (422, or an exception for a time that
    has no UTC form), and the gateway sent it again for ever."""
    monkeypatch.setenv("ATTACKLEDGER_GATEWAY_TOKEN", GATEWAY_TOKEN)
    e = stack.engagement()
    job = stack.queue(e, "probe", ["app.example.com"])
    rows = [row(e, job, url="https://app.example.com/ok"),
            row(e, job, verdict="maybe", url="https://app.example.com/secret-path"),
            row(e, job, tool="t" * 40, verdict="refused", status=403),
            "not a row",
            row(e, job, at="0001-01-01T00:00:00+01:00"),
            row(e, job, url="https://app.example.com/also-ok", verdict="failed")]
    r = post(stack, rows)
    assert r.status_code == 200
    out = r.json()
    assert out["written"] == 2 and [u["index"] for u in out["unlogged"]] == [1, 2, 3, 4]
    reasons = [u["reason"] for u in out["unlogged"]]
    assert "verdict" in reasons[0] and "tool" in reasons[1] and "at:" in reasons[3]
    assert all("secret-path" not in x for x in reasons)
    with stack.Session() as s:
        got = s.scalars(select(GatewayRequest).order_by(GatewayRequest.id)).all()
    assert [g.verdict for g in got] == ["allowed", "unlogged", "unlogged", "unlogged", "unlogged", "failed"]
    holders = [g for g in got if g.verdict == "unlogged"]
    assert all(g.url == "" for g in holders)                      # never what was refused
    assert [g.engagement_id for g in holders] == [e, e, None, e] and holders[0].job_id == job
    assert holders[1].tool == "t" * 32 and "the request was refused" in holders[1].reason
    assert holders[0].host == "app.example.com" and "quarantine" in holders[0].reason
    log = stack.api.get(f"/engagements/{e}/gateway-log").json()
    assert log["by_verdict"] == {"allowed": 1, "failed": 1, "unlogged": 3}
    assert {x["url"] for x in log["rows"] if x["verdict"] != "unlogged"} == {
        "https://app.example.com/ok", "https://app.example.com/also-ok"}


def test_a_lone_surrogate_is_kept_as_the_replacement_character(stack, monkeypatch):
    """JSON can spell a lone surrogate; UTF-8, and so the database driver, cannot hold one."""
    monkeypatch.setenv("ATTACKLEDGER_GATEWAY_TOKEN", GATEWAY_TOKEN)
    e = stack.engagement()
    body = json.dumps({"rows": [row(e, url="https://app.example.com/\udc80x", reason="r\ud800")]})
    assert "\\udc80" in body
    r = stack.api.post("/gateway/log", content=body, headers={"authorization": f"Bearer {GATEWAY_TOKEN}",
                                                              "content-type": "application/json"})
    assert r.status_code == 200 and r.json() == {"written": 1, "unlogged": []}
    with stack.Session() as s:
        g = s.scalars(select(GatewayRequest)).one()
    assert g.url == "https://app.example.com/�x" and g.reason == "r�"


# ---- the gateway -------------------------------------------------------------------------------

class RefusingApi(FakeApi):
    """An API that refuses, with `status`, every batch holding a row whose URL contains `poison`
    (as the API did before it answered per row, or a body limit in front of it would), or answers
    per row."""

    def __init__(self, status=422, per_row=False, poison="POISON"):
        super().__init__()
        self.status, self.per_row, self.poison, self.batches = status, per_row, poison, []

    async def post_log(self, rows):
        self.batches.append(len(rows))
        bad = [i for i, r in enumerate(rows) if self.poison in r["url"]]
        if bad and not self.per_row:
            return self.status, {"detail": [{"loc": ["body", "rows", bad[0], "url"], "msg": "refused here",
                                             "input": "the value itself"}]}
        self.logged += [gatewaylog.placeholder(r, "x") if i in bad else r for i, r in enumerate(rows)]
        return 200, {"written": len(rows) - len(bad), "unlogged": [{"index": i, "reason": "url: refused"} for i in bad]}


def gateway_with(api, tmp_path) -> gateway.Gateway:
    return gateway.Gateway(api, None, deny_hosts=(), networks=[], quarantine=str(tmp_path / "quarantine.jsonl"))


def logged(gw, n, poison=()):
    for i in range(n):
        gw.record(rules=None, tool="httpx", kind="target", method="GET",
                  url=f"http://app.example.com/{'POISON' if i in poison else 'ok'}/{i}", verdict="allowed",
                  engagement_id=1, job_id=2)


def drain(gw, limit=200) -> int:
    calls = 0
    while gw.log_rows and calls < limit:
        assert asyncio.run(gw.flush_log())
        calls += 1
    assert not gw.log_rows
    return calls


def set_aside(tmp_path) -> list[dict]:
    p = tmp_path / "quarantine.jsonl"
    return [json.loads(line) for line in p.read_text().splitlines()] if p.exists() else []


def test_rows_the_api_answers_as_not_stored_are_set_aside(tmp_path):
    api = RefusingApi(per_row=True)
    gw = gateway_with(api, tmp_path)
    logged(gw, 5, poison={1, 3})
    assert asyncio.run(gw.flush_log()) and gw.log_rows == []
    kept = set_aside(tmp_path)
    assert [k["row"]["url"] for k in kept] == ["http://app.example.com/POISON/1", "http://app.example.com/POISON/3"]
    assert all("placeholder" in k["why"] for k in kept) and gw.quarantined == 2 and gw.quarantine_lost == 0
    assert oct(os.stat(tmp_path / "quarantine.jsonl").st_mode & 0o777) == "0o600"
    assert api.batches == [5]                     # the API made the placeholders: nothing more is sent


@pytest.mark.parametrize("status", [400, 413, 422])
def test_a_whole_batch_refused_is_halved_until_the_row_is_found(tmp_path, monkeypatch, status):
    monkeypatch.setattr(gateway, "LOG_BATCH", 64)
    api = RefusingApi(status=status)
    gw = gateway_with(api, tmp_path)
    logged(gw, 150, poison={37, 120})
    calls = drain(gw)
    assert calls <= 30
    urls = [r["url"] for r in api.logged]
    assert [u for u in urls if u] == [f"http://app.example.com/ok/{i}" for i in range(150) if i not in (37, 120)]
    holders = [r for r in api.logged if r["verdict"] == gatewaylog.UNLOGGED]
    assert len(holders) == 2 and all(h["engagement_id"] == 1 and h["job_id"] == 2 and h["url"] == "" for h in holders)
    assert f"refused it with {status} (url: refused here)" in holders[0]["reason"]
    assert all("the value itself" not in h["reason"] for h in holders)
    assert [k["row"]["url"] for k in set_aside(tmp_path)] == [
        "http://app.example.com/POISON/37", "http://app.example.com/POISON/120"]
    assert gw.log_batch == 64


@pytest.mark.parametrize("status", [0, 500, 502, 503, 401, 403, 404, 429])
def test_other_failures_keep_the_rows_and_the_gateway_fails_closed(tmp_path, monkeypatch, status):
    """No answer, a 5xx or a refusal that is not about the rows: nothing is set aside, every
    row waits, and with LOG_BACKLOG rows waiting traffic is refused."""
    monkeypatch.setattr(gateway, "LOG_BACKLOG", 4)
    api = RefusingApi(status=status, poison="")       # every batch is refused
    gw = gateway_with(api, tmp_path)
    logged(gw, 4)
    for _ in range(3):
        assert asyncio.run(gw.flush_log()) is False
    assert len(gw.log_rows) == 4 and gw.log_full() and set_aside(tmp_path) == [] and api.logged == []
    assert api.batches == [4, 4, 4]


def test_a_row_is_not_set_aside_when_the_api_refuses_its_placeholder_too(tmp_path, monkeypatch):
    """Then the API, not the row, is the problem (it would refuse anything): the row waits."""
    monkeypatch.setattr(gateway, "LOG_BACKLOG", 1)
    api = RefusingApi(status=422, poison="")
    gw = gateway_with(api, tmp_path)
    logged(gw, 1)
    assert asyncio.run(gw.flush_log()) is False and asyncio.run(gw.flush_log()) is False
    assert len(gw.log_rows) == 1 and gw.log_full() and set_aside(tmp_path) == [] and gw.quarantined == 0
    assert api.batches == [1, 1, 1, 1]            # the row, then its placeholder, each time


def test_the_quarantine_file_is_bounded_and_rows_past_it_are_still_counted(tmp_path, monkeypatch):
    monkeypatch.setattr(gateway, "QUARANTINE_MAX_BYTES", 700)
    api = RefusingApi(per_row=True)
    gw = gateway_with(api, tmp_path)
    logged(gw, 4, poison={0, 1, 2, 3})
    assert asyncio.run(gw.flush_log()) and gw.log_rows == []
    assert 1 <= len(set_aside(tmp_path)) < 4 and os.path.getsize(tmp_path / "quarantine.jsonl") <= 700
    assert gw.quarantined == 4 and gw.quarantine_lost == 4 - len(set_aside(tmp_path))
    assert len(api.logged) == 4                   # the placeholders are in the log all the same


def test_without_a_quarantine_file_the_row_is_counted_and_the_log_moves_on(tmp_path):
    api = RefusingApi(per_row=True)
    gw = gateway.Gateway(api, None, deny_hosts=(), networks=[])
    logged(gw, 2, poison={0})
    assert asyncio.run(gw.flush_log()) and gw.log_rows == [] and gw.quarantine_lost == 1


def test_the_quarantine_file_holds_what_the_log_row_holds_and_no_secret(tmp_path):
    """Through the real proxy: the engagement redacts, so the URL's token is a marker in the row,
    and the file holds that row as it was logged; a test account's label, never its session."""
    s = GatewayStack(tmp_path)
    try:
        api = RefusingApi(per_row=True, poison="access_token")
        api.add(1)
        s.gw.api, s.gw.quarantine_path = api, str(tmp_path / "quarantine.jsonl")
        assert s.get("http://app.example.com/cb?access_token=tok-0123456789abcdef")[0] == 200
        assert s.get("http://app.example.com/me?access_token=tok-0123456789abcdef",
                     headers={"X-AttackLedger-As": "A"})[0] == 403          # a probe job sends as no account
        s.rows(2)
        assert s.run(s.gw.flush_log())
    finally:
        s.close()
    text = (tmp_path / "quarantine.jsonl").read_text()
    kept = set_aside(tmp_path)
    assert len(kept) == 2 and "tok-0123456789abcdef" not in text
    assert kept[0]["row"]["url"].startswith("http://app.example.com/cb?access_token=") and kept[1]["row"]["account"] == "A"
    assert set(kept[0]["row"]) == set(gatewaylog.placeholder({}, "").keys())     # the log row's fields, nothing more


class Bridge:
    """gateway.Api, but calling the API in this process with the gateway token."""

    def __init__(self, client):
        self.c, self.lock = client, threading.Lock()

    def _call(self, method, path, body=None):
        with self.lock:
            r = self.c.request(method, path, json=body, headers={"authorization": f"Bearer {GATEWAY_TOKEN}"})
        return r.status_code, (r.json() if r.content else {})

    async def session(self, job_id, secret):
        return await asyncio.to_thread(self._call, "POST", "/gateway/session", {"job_id": job_id, "secret": secret})

    async def post_log(self, rows):
        return await asyncio.to_thread(self._call, "POST", "/gateway/log", {"rows": rows})


def test_a_long_test_account_label_no_longer_stops_the_log(stack, tmp_path, monkeypatch):
    """A tool in the worker sent X-AttackLedger-As with a label longer than the log's 16
    characters: the gateway logged the refusal with the whole label, the API refused the batch
    (422) and the gateway sent it again for ever; with 5,000 such rows all traffic stopped. The
    gateway now logs the label as the column holds it."""
    monkeypatch.setenv("ATTACKLEDGER_GATEWAY_TOKEN", GATEWAY_TOKEN)
    e = stack.engagement(include=("*.example.com", "example.com"))
    stack.queue(e, "probe", ["app.example.com"])
    job = stack.claim()
    s = GatewayStack(tmp_path)
    try:
        s.gw.api, s.gw.quarantine_path = Bridge(stack.api), str(tmp_path / "quarantine.jsonl")
        label = "L" * 40
        status, _, text = s.get("http://app.example.com/", headers={"X-AttackLedger-As": label},
                                auth=s.auth(job=job.id, secret=job.gateway_secret))
        assert status == 403 and b"test account" in text
        assert s.get("http://app.example.com/after", auth=s.auth(job=job.id, secret=job.gateway_secret))[0] == 200
        s.rows(2)
        assert s.run(s.gw.flush_log()) and s.gw.log_rows == []
    finally:
        s.close()
    assert set_aside(tmp_path) == []
    with stack.Session() as ss:
        got = ss.scalars(select(GatewayRequest).order_by(GatewayRequest.id)).all()
    assert [(g.verdict, g.account) for g in got] == [("refused", "L" * 16), ("allowed", None)]
    assert SECRET not in json.dumps([g.reason for g in got])
