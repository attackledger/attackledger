#!/usr/bin/env python3
"""Drive an agent run step by step from outside the worker's loop, through the same tools.

For runs where the model is not called through the Messages API, for example a Claude
session working a lane while no API key is available (D-031). Every call goes through the
agent's tools as a worker run does (agenttools.RemoteToolbox, D-042): lane host and scope
only, read-only methods, research identification, no redirects, rate limit, request budget,
no tool that closes a lane. The requests leave through the gateway; the exchanges, evidence,
item marks and leads are checked and written by the API. State between calls (the job's
token, request count, pacing) is kept in a state file.

1. A person queues the run on the lane, naming the driver (it needs the tester role):

     curl -X POST .../api/lanes/LANE_ID/agent-runs -H 'content-type: application/json' \\
          -d '{"driver": "Claude Opus 5.5 in Claude Code", "max_requests": 30}'

   The worker's own loop never takes such a run.

2. Inside the worker container (it has the worker token and the gateway, the only route to
   the lab), claim it and work it:

     docker exec -i <worker> python - start JOB_ID          < tools/agent_bridge.py
     docker exec -i <worker> python - context               < tools/agent_bridge.py
     docker exec -i <worker> python - call TOOL 'JSON'      < tools/agent_bridge.py
     docker exec -i <worker> python - end                   < tools/agent_bridge.py
"""
import json
import os
import sys
import time

sys.path.insert(0, "/srv")
from app import agenttools, egress, workerclient  # noqa: E402

STATE = "/tmp/agent_bridge_state.json"


def load() -> dict:
    with open(STATE) as f:
        return json.load(f)


def save(state: dict) -> None:
    # It holds the run's job token and gateway credential: readable by the worker user only.
    with os.fdopen(os.open(STATE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        json.dump(state, f)


def channel(state: dict) -> workerclient.JobChannel:
    return workerclient.JobChannel(workerclient.Client(), state["spec"])


def toolbox(job: workerclient.JobChannel, state: dict) -> agenttools.RemoteToolbox:
    # Through the traffic gateway with the run's own credential, like the worker's agent runs.
    gw = egress.Egress(job.id, job.gateway_secret).check()
    tb = agenttools.RemoteToolbox(job, state["spec"]["context"], clock=time.time,
                                  max_requests=state["spec"]["limits"].get("max_requests") or 30,
                                  transport=agenttools.urllib_transport(gw))
    for k in ("requests", "body_shown", "evidence_added", "items_marked", "leads_added"):
        setattr(tb, k, state[k])
    tb._last_sent = state["last_sent"]
    return tb


def main(argv: list[str]) -> None:
    cmd = argv[0] if argv else ""
    if cmd == "start":
        spec = workerclient.Worker.from_env().claim(int(argv[1]))
        if spec is None:
            sys.exit(f"job {argv[1]} is not a queued run for an outside driver (or its gates refused it; "
                     "see the job's log)")
        state = {"spec": spec, "requests": 0, "body_shown": 0, "last_sent": None, "calls": 0,
                 "evidence_added": 0, "items_marked": 0, "leads_added": 0, "summary": None}
        save(state)
        channel(state).log(f"agent run driven by {spec['driver']} through the agent tools (no Messages API call)")
        print(json.dumps({"job_id": spec["id"], "lane_id": spec["lane_id"], "limits": spec["limits"]}))
    elif cmd == "context":
        print(json.dumps(load()["spec"]["context"], default=str))
    elif cmd == "call":
        state = load()
        job = channel(state)
        name, args = argv[1], json.loads(argv[2])
        tb = toolbox(job, state)
        text, is_error = tb.call(name, args)
        state.update(requests=tb.requests, body_shown=tb.body_shown, last_sent=tb._last_sent,
                     calls=state["calls"] + 1, evidence_added=tb.evidence_added, items_marked=tb.items_marked,
                     leads_added=tb.leads_added)
        if tb.finished is not None:
            state["summary"] = tb.finished
        save(state)
        job.log(f"call {state['calls']}: {name} {'refused: ' + text[:300] if is_error else 'ok'}")
        print(text if not is_error else f"ERROR: {text}")
    elif cmd == "end":
        state = load()
        job = channel(state)
        finished = state["summary"] is not None
        driver = state["spec"]["driver"]
        result = {
            "status": "finished" if finished else "ended", "model": driver, "turns": None,
            "tool_calls": state["calls"], "requests": state["requests"],
            "evidence_added": state["evidence_added"], "items_marked": state["items_marked"],
            "leads_added": state["leads_added"], "summary": state["summary"] or "",
            "detail": (f"Driven by {driver} through the same five gated tools, because no "
                       "API key was available yet. Token use was not measured."),
        }
        job.log(f"agent {result['status']}: {state['calls']} call(s), {state['requests']} request(s), "
                f"{state['evidence_added']} evidence, {state['items_marked']} item(s) marked")
        out = job.finish(agent=result, result_count=state["evidence_added"])
        os.unlink(STATE)
        print(json.dumps({**result, "job_status": out["status"]}))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
