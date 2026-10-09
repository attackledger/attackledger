#!/usr/bin/env python3
"""Drive an agent run step by step from outside the worker, through the same Toolbox gates.

For runs where the model is not called through the Messages API, for example a Claude
session working a lane while no API key is available. Every call goes through
agenttools.Toolbox: lane host and scope only, read-only methods, research identification,
no redirects, rate limit, request budget, no tool that closes a lane. State between calls
(exchange ids, request count, pacing) is kept in a state file.

Run inside the worker container (it has the database and the lab network):

  docker exec -i <worker> python - start LANE_ID "DRIVER" < tools/agent_bridge.py
  docker exec -i <worker> python - context            < tools/agent_bridge.py
  docker exec -i <worker> python - call TOOL 'JSON'   < tools/agent_bridge.py
  docker exec -i <worker> python - end                < tools/agent_bridge.py

DRIVER names who made the decisions, and is recorded on the run.
"""
import json
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, "/srv")
from app import agenttools, executors  # noqa: E402
from app.db import SessionLocal  # noqa: E402
from app.models import Job, JobStatus, Lane  # noqa: E402

STATE = "/tmp/agent_bridge_state.json"


def load() -> dict:
    with open(STATE) as f:
        return json.load(f)


def save(state: dict) -> None:
    with open(STATE, "w") as f:
        json.dump(state, f)


def log(session, job: Job, line: str) -> None:
    job.log = (job.log + line + "\n")[-20000:]
    session.commit()


def toolbox(session, lane: Lane, state: dict) -> agenttools.Toolbox:
    tb = agenttools.Toolbox(session, lane, state["job_id"], clock=time.time,
                            max_requests=state["limits"]["max_requests"])
    tb.exchanges = state["exchanges"]
    tb.requests = state["requests"]
    tb.body_shown = state["body_shown"]
    tb._last_sent = state["last_sent"]
    for k in ("evidence_added", "items_marked", "leads_added"):
        setattr(tb, k, state[k])
    return tb


def main(argv: list[str]) -> None:
    cmd = argv[0]
    with SessionLocal() as s:
        if cmd == "start":
            lane = s.get(Lane, int(argv[1]))
            driver = argv[2]
            lane.executor = "agent"
            agenttools.check_lane(lane)
            limits = {"max_turns": None, "max_requests": 30}
            job = Job(engagement_id=lane.asset.engagement_id, kind="agent", lane_id=lane.id,
                      targets=[lane.asset.host], status=JobStatus.running,
                      started_at=datetime.now(timezone.utc), result={"limits": limits})
            s.add(job)
            s.commit()
            log(s, job, f"agent run driven by {driver} through the agent tools (no Messages API call)")
            save({"job_id": job.id, "lane_id": lane.id, "driver": driver, "limits": limits, "exchanges": {},
                  "requests": 0, "body_shown": 0, "last_sent": None, "calls": 0,
                  "evidence_added": 0, "items_marked": 0, "leads_added": 0, "summary": None})
            print(json.dumps({"job_id": job.id}))
        elif cmd == "context":
            state = load()
            print(json.dumps(executors.lane_context(s, s.get(Lane, state["lane_id"]), limit=50), default=str))
        elif cmd == "call":
            state = load()
            lane, job = s.get(Lane, state["lane_id"]), s.get(Job, state["job_id"])
            name, args = argv[1], json.loads(argv[2])
            try:
                tb = toolbox(s, lane, state)
            except agenttools.RunRefused as e:
                # Every item already decided: only finishing is left.
                if name == "finish" and isinstance(args, dict) and str(args.get("summary", "")).strip():
                    state["summary"] = str(args["summary"]).strip()[:8000]
                    state["calls"] += 1
                    save(state)
                    log(s, job, f"call {state['calls']}: finish ok")
                    print(json.dumps({"finished": True}))
                    return
                print(f"ERROR: {e}")
                return
            text, is_error = tb.call(name, args)
            s.commit()
            state.update(exchanges=tb.exchanges, requests=tb.requests, body_shown=tb.body_shown,
                         last_sent=tb._last_sent, calls=state["calls"] + 1, evidence_added=tb.evidence_added,
                         items_marked=tb.items_marked, leads_added=tb.leads_added)
            if tb.finished is not None:
                state["summary"] = tb.finished
            save(state)
            log(s, job, f"call {state['calls']}: {name} {'refused: ' + text[:300] if is_error else 'ok'}")
            print(text if not is_error else f"ERROR: {text}")
        elif cmd == "end":
            state = load()
            job = s.get(Job, state["job_id"])
            finished = state["summary"] is not None
            job.result = {
                "limits": state["limits"], "status": "finished" if finished else "ended",
                "model": state["driver"], "turns": None, "tool_calls": state["calls"], "requests": state["requests"],
                "evidence_added": state["evidence_added"], "items_marked": state["items_marked"],
                "leads_added": state["leads_added"], "summary": state["summary"] or "",
                "detail": (f"Driven by {state['driver']} through the same five gated tools, because no "
                           "API key was available yet. Token use was not measured."),
            }
            job.result_count = state["evidence_added"]
            job.targets_done = 1 if finished else 0
            job.status = JobStatus.done if finished else JobStatus.partial
            job.finished_at = datetime.now(timezone.utc)
            s.commit()
            log(s, job, f"agent {job.result['status']}: {state['calls']} call(s), {state['requests']} request(s), "
                        f"{state['evidence_added']} evidence, {state['items_marked']} item(s) marked")
            print(json.dumps(job.result))
        else:
            sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
