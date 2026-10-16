"""The depth floor of an agent run (D-061): min_requests.

A finish below the floor is declined, with a tool result (not an error), at most twice while turns
and budget remain; the third ends the run, which records that it ended below the floor. With no
room left the floor does not apply. min_requests 0 is today's behavior, byte for byte.
Scripted fake model and transport, as in test_agent: no network, no Anthropic API."""
import json
from types import SimpleNamespace

import pytest

from app import agentloop, agenttools
from test_agent import (HOST, FakeClient, FakeTransport, agent_job, api, api_lane, blob_dir,  # noqa: F401
                        make_lane, reply, session, tool_use, toolbox)
from harness import load_worker, stack  # noqa: F401

FINISH = {"summary": "All items marked."}


def finish(n, summary="All items marked."):
    return reply(tool_use(f"f{n}", "finish", {"summary": summary}))


def get_call(n, path="/"):
    return reply(tool_use(f"g{n}", "http_request", {"method": "GET", "url": f"https://{HOST}{path}", "headers": []}))


def remote(min_requests=0, max_requests=10):
    ctx = {"host": HOST, "rules": {"scope_include": ["*.lab.test"], "scope_exclude": [], "rate_limit_rps": 5,
                                   "research_header": "X-Bug-Bounty: lab"}}
    return agenttools.RemoteToolbox(SimpleNamespace(), ctx, transport=FakeTransport(),
                                    max_requests=max_requests, min_requests=min_requests)


# ---- both toolboxes ---------------------------------------------------------------------------

@pytest.fixture(params=["local", "remote"])
def make_tb(request, session):
    made = []

    def make(min_requests=0, max_requests=10):
        if request.param == "remote":
            return remote(min_requests, max_requests)
        made.append(1)
        lane, job = make_lane(session, host=f"h{len(made)}.lab.test")
        return toolbox(session, lane, job, max_requests=max_requests, min_requests=min_requests)
    return make


def test_no_floor_finishes_at_once(make_tb):
    tb = make_tb(0)
    assert tb.call("finish", FINISH) == ('{"finished": true}', False)
    assert tb.finished == "All items marked." and tb.floor_refusals == 0


def test_finish_below_the_floor_is_declined_twice_then_ends(make_tb):
    tb = make_tb(5)
    tb.requests = 2
    for n, more in ((1, "declined 1 more time"), (2, "next finish ends the run")):
        text, is_error = tb.call("finish", FINISH)
        out = json.loads(text)
        assert is_error is False and out["finished"] is False and tb.finished is None
        assert out["depth_floor"] == {"min_requests": 5, "requests": 2} and tb.floor_refusals == n
        msg = out["message"]
        assert "used 2" in msg and "known_paths" in msg and "spa_routes" in msg and "JavaScript bundles" in msg
        assert "read-only" in msg and "no brute force" in msg and "not mean the host is exhausted" in msg
        assert more in msg
    assert json.loads(tb.call("finish", {"summary": "Still done."})[0]) == {"finished": True}
    assert tb.finished == "Still done." and tb.floor_refusals == 2 and tb.offered == "All items marked."


def test_the_floor_does_not_apply_without_room(make_tb):
    tb = make_tb(5)
    tb.room = lambda: False                      # last turn, or too little cost or tokens left
    assert json.loads(tb.call("finish", FINISH)[0]) == {"finished": True} and tb.floor_refusals == 0
    tb = make_tb(5, max_requests=5)
    tb.requests = 5                              # the request budget is used: the floor is met anyway
    assert json.loads(tb.call("finish", FINISH)[0]) == {"finished": True}
    tb = make_tb(5)
    tb.requests = 5                              # at the floor
    assert json.loads(tb.call("finish", FINISH)[0]) == {"finished": True}


def test_a_finish_without_a_summary_is_still_an_error(make_tb):
    tb = make_tb(5)
    text, is_error = tb.call("finish", {"summary": ""})
    assert is_error and tb.floor_refusals == 0


@pytest.mark.parametrize("min_requests,max_requests", [(11, 10), (-1, 10), (True, 10), ("3", 10)])
def test_a_floor_over_the_request_budget_is_refused(session, min_requests, max_requests):
    lane, job = make_lane(session)
    with pytest.raises(ValueError, match="min_requests"):
        toolbox(session, lane, job, max_requests=max_requests, min_requests=min_requests)
    with pytest.raises(ValueError, match="min_requests"):
        remote(min_requests, max_requests)


# ---- the loop ---------------------------------------------------------------------------------

def run(session, script, lane_job=None, **kw):
    lane, job = lane_job or make_lane(session)
    client, lines = FakeClient(script), []
    res = agentloop.run(session, lane, job.id, client, transport=FakeTransport(), sleep=lambda s: None,
                        log=lines.append, **kw)
    return res, client, lines


def test_min_requests_zero_is_todays_run_byte_for_byte(session):
    lane_job = make_lane(session)
    a, ca, _ = run(session, [get_call(1), finish(2)], lane_job)
    b, cb, lines = run(session, [get_call(1), finish(2)], lane_job, min_requests=0)
    assert ca.requests == cb.requests and ca.requests[0]["system"] == agentloop.SYSTEM
    assert "depth floor" not in json.dumps(cb.requests, default=str)
    assert a.as_dict() == b.as_dict() and "depth_floor" not in b.as_dict() and "below_depth_floor" not in b.as_dict()
    assert not any("depth floor" in line for line in lines)


def test_the_loop_declines_twice_and_records_a_run_below_the_floor(session):
    res, client, lines = run(session, [finish(1), finish(2), finish(3, "Done, really.")], min_requests=4)
    assert res.status == "finished" and res.turns == 3 and res.requests == 0
    assert res.below_depth_floor is True
    assert res.depth_floor == {"min_requests": 4, "requests": 0, "refusals": 2,
                               "reason": "the agent finished after the floor declined 2 times"}
    assert res.summary.startswith("Below the depth floor: 0 of 4 requests") and res.summary.endswith("Done, really.")
    d = res.as_dict()
    assert d["below_depth_floor"] is True and d["depth_floor"]["refusals"] == 2
    # The floor's instruction is in the first message only; the system prompt is the same as without it.
    first = client.requests[0]
    assert first["system"] == agentloop.SYSTEM
    assert "depth floor of 4 requests" in first["messages"][0]["content"]
    assert "stub until you have read the script or page" in first["messages"][0]["content"]
    for n in (1, 2):                 # the declines went back as plain results, not errors
        result = client.requests[n]["messages"][-1]["content"][0]
        assert "is_error" not in result and json.loads(result["content"])["finished"] is False
    assert sum("finish declined by the depth floor" in line for line in lines) == 2
    assert any(line.startswith("below the depth floor: 0 of 4") for line in lines)


def test_a_run_that_reaches_the_floor_is_not_flagged(session):
    res, _, lines = run(session, [finish(1), get_call(2), get_call(3, "/robots.txt"), finish(4)], min_requests=2)
    assert res.status == "finished" and res.requests == 2 and res.below_depth_floor is False
    assert res.depth_floor == {"min_requests": 2, "requests": 2, "refusals": 1}
    assert res.summary == "All items marked."
    assert any("depth floor reached: 2 of 2 requests" in line for line in lines)


def test_the_floor_does_not_hold_a_run_on_its_last_turn(session):
    res, client, _ = run(session, [finish(1)], min_requests=5, max_turns=1)
    assert res.status == "finished" and len(client.requests) == 1 and res.below_depth_floor is True
    assert res.depth_floor["refusals"] == 0 and "no turns or budget" in res.depth_floor["reason"]


def test_the_floor_does_not_hold_a_run_whose_budget_cannot_pay_for_another_call(session):
    # $0.60 for the first call on Opus leaves $0.40 of $1.00; the next prompt alone could cost more.
    res, client, _ = run(session, [reply(tool_use("f1", "finish", FINISH), usage=(100_000, 10_000))],
                         min_requests=5, max_cost_usd=1.0)
    assert res.status == "finished" and len(client.requests) == 1 and res.depth_floor["refusals"] == 0
    assert res.below_depth_floor is True and res.cost_usd <= 1.0


def test_the_floor_does_not_hold_a_run_at_the_token_ceiling(session):
    res, client, _ = run(session, [reply(tool_use("f1", "finish", FINISH), usage=(40_000, 0))],
                         model="claude-haiku-5-5", min_requests=5, env={"ATTACKLEDGER_AGENT_MAX_TOKENS": "50000"})
    assert res.status == "finished" and len(client.requests) == 1 and res.depth_floor["refusals"] == 0


def test_a_declined_run_that_then_hits_a_limit_keeps_the_agents_finish(session):
    lead = reply(tool_use("l1", "record_lead", {"title": "x", "detail": "d", "severity": "", "url": ""}))
    res, _, _ = run(session, [finish(1), lead], min_requests=5, max_turns=2)
    assert res.status == "finished" and res.summary.endswith("All items marked.")
    assert "told to continue to the depth floor" in res.detail and "turn limit" in res.detail
    assert res.below_depth_floor is True and res.depth_floor["refusals"] == 1
    assert "after the agent asked to finish" in res.depth_floor["reason"]

    res, _, _ = run(session, [finish(1), reply(SimpleNamespace(type="text", text="ok"), stop="end_turn")],
                    make_lane(session, host="api.lab.test"), min_requests=5)
    assert res.status == "finished" and res.summary.endswith("All items marked.")


def test_a_run_stopped_without_asking_to_finish_stays_partial(session):
    lead = reply(tool_use("l1", "record_lead", {"title": "x", "detail": "d", "severity": "", "url": ""}))
    res, _, _ = run(session, [lead], min_requests=5, max_turns=1)
    assert res.status == "turn_limit" and res.summary.startswith("Partial run")
    assert res.below_depth_floor is True and res.depth_floor["reason"] == "the run stopped (turn limit)"


# ---- the API and the worker -------------------------------------------------------------------

def ready_lane(api, monkeypatch):
    monkeypatch.setenv("ATTACKLEDGER_AGENTS_ENABLED", "1")
    e, lane = api_lane(api)
    api.patch(f"/lanes/{lane}", json={"executor": "agent"})
    api.put(f"/engagements/{e}/scope", json={"include": ["*.lab.test"], "research_header": "X-Bug-Bounty: lab"})
    api.post(f"/engagements/{e}/attest", json={"operator": "op", "policy_url": "https://lab.test/policy",
                                               "confirm": True})
    return lane


def test_the_api_validates_and_keeps_the_floor_in_the_limits(api, monkeypatch):
    lane = ready_lane(api, monkeypatch)
    r = api.post(f"/lanes/{lane}/agent-runs", json={"max_requests": 20, "min_requests": 21})
    assert r.status_code == 422 and "min_requests" in r.json()["detail"]
    assert api.post(f"/lanes/{lane}/agent-runs", json={"min_requests": -1}).status_code == 422
    r = api.post(f"/lanes/{lane}/agent-runs", json={"min_requests": 3, "driver": "someone"})
    assert r.status_code == 422 and "outside driver" in r.json()["detail"]
    r = api.post(f"/lanes/{lane}/agent-runs", json={"max_requests": 20, "min_requests": 20})
    assert r.status_code == 201
    assert r.json()["result"]["limits"] == {"max_turns": 15, "max_requests": 20, "max_cost_usd": 0.5,
                                            "min_requests": 20}
    api.post(f"/jobs/{r.json()['id']}/cancel")
    r = api.post(f"/lanes/{lane}/agent-runs", json={"min_requests": 0})
    assert r.status_code == 201 and "min_requests" not in r.json()["result"]["limits"]


def test_worker_run_below_the_floor_is_done_flagged_and_logged(stack):
    worker = load_worker()
    job, _ = agent_job(stack, max_requests=5, min_requests=3)
    out = worker.execute(job, client=FakeClient([finish(1), finish(2), finish(3)]))
    j = stack.job(job.id)
    assert out["status"] == "done" and j.result["status"] == "finished"
    assert j.result["limits"] == {"max_requests": 5, "min_requests": 3}
    assert j.result["below_depth_floor"] is True
    assert j.result["depth_floor"]["min_requests"] == 3 and j.result["depth_floor"]["refusals"] == 2
    assert j.result["summary"].startswith("Below the depth floor: 0 of 3 requests")
    assert "depth floor: 3 requests" in j.log and "finish declined by the depth floor" in j.log
    assert "BELOW THE DEPTH FLOOR: 0 of 3 requests" in j.log


def test_worker_run_without_a_floor_records_no_floor(stack):
    worker = load_worker()
    job, _ = agent_job(stack, max_requests=5)
    assert worker.execute(job, client=FakeClient([finish(1)]))["status"] == "done"
    j = stack.job(job.id)
    assert "depth_floor" not in j.result and "below_depth_floor" not in j.result and "depth floor" not in j.log


def test_worker_fails_a_floor_over_the_budget_before_any_call(stack):
    worker = load_worker()
    job, _ = agent_job(stack, max_requests=5, min_requests=6)     # only through a hand-made job
    client = FakeClient([finish(1)])
    assert worker.execute(job, client=client)["status"] == "failed"
    assert client.requests == [] and "min_requests" in stack.job(job.id).log


# ---- tools/agent_live.py ----------------------------------------------------------------------

def test_agent_live_passes_the_floor_and_shows_it_in_the_section_and_the_numbers():
    from test_agent_live import lab_line, load_live, row, run_data
    live = load_live()
    rows = [row("http://shop.lab.test/")]
    m = run_data(live, [lab_line("/")], rows)
    assert m["min_requests"] == 0 and m["depth_floor"] is None and m["below_depth_floor"] is False
    text = live.section(m, dry=False, today="d", project="p", prices="x")
    assert "max_cost_usd 0.5, min_requests 0 (no depth floor)" in text and "depth floor reached" not in text

    m["limits"] = {**m["limits"], "min_requests": 40}
    m["depth_floor"] = {"min_requests": 40, "requests": 12, "refusals": 2,
                        "reason": "the agent finished after the floor declined 2 times"}
    m["below_depth_floor"] = True
    text = live.section(m, dry=False, today="d", project="p", prices="x")
    assert "max_cost_usd 0.5, min_requests 40 |" in text
    assert ("**below the depth floor**: 12 of 40 requests (the agent finished after the floor declined 2 times)"
            in text)
    m["depth_floor"], m["below_depth_floor"] = {"min_requests": 40, "requests": 41, "refusals": 1}, False
    assert "depth floor of 40 reached, finish declined 1 time(s)" in live.section(m, dry=False, today="d",
                                                                                   project="p", prices="x")


def test_agent_live_has_a_min_requests_flag_that_defaults_to_no_floor(monkeypatch):
    from test_agent_live import load_live
    live = load_live()
    seen = {}

    def fake_run(stack, args):
        seen["min_requests"] = args.min_requests
    monkeypatch.setattr(live, "run", fake_run)
    monkeypatch.setattr(live, "Stack", lambda args: None)
    assert live.main(["run"]) == 0 and seen["min_requests"] == 0
    assert live.main(["run", "--min-requests", "40"]) == 0 and seen["min_requests"] == 40
    src = (live.ROOT / "tools" / "agent_live.py").read_text()
    assert '"min_requests": args.min_requests' in src       # sent with the run's limits
