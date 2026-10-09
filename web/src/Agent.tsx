import { useCallback, useEffect, useState } from "react";
import { api, type ExecutorInfo, type Job, type LaneDetail } from "./api";
import { JobLog } from "./Recon";

const OUTCOME: Record<string, string> = {
  finished: "Finished",
  ended: "Stopped without finishing",
  turn_limit: "Reached the turn limit",
  cancelled: "Cancelled",
  timed_out: "Reached the time limit",
  refused: "The model declined",
};

function plural(n: number, one: string, many = `${one}s`) {
  return `${n} ${n === 1 ? one : many}`;
}

/** Who works the lane, and the agent's runs when it is the Claude agent. */
export function Executor({ lane, onLaneChanged }: { lane: LaneDetail; onLaneChanged: (l: LaneDetail) => void }) {
  const [executors, setExecutors] = useState<ExecutorInfo[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.executors().then(setExecutors).catch(() => {});
  }, []);

  async function choose(key: string) {
    try {
      onLaneChanged(await api.setExecutor(lane.id, key));
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  const agent = executors.find((e) => e.key === "agent");
  return (
    <section className="executor" aria-labelledby="executor-title">
      <h3 id="executor-title">Who works this lane</h3>
      <div className="executor-choice" role="radiogroup" aria-label="Executor">
        {executors.map((e) => (
          <label key={e.key} className={`executor-option${lane.executor === e.key ? " on" : ""}`}>
            <input type="radio" name={`executor-${lane.id}`} checked={lane.executor === e.key}
                   disabled={!e.available || lane.status === "closed"} onChange={() => choose(e.key)} />
            <span>
              <strong>{e.title}</strong>
              <span className="hint">{e.available ? e.summary : e.unavailable_reason}</span>
            </span>
          </label>
        ))}
      </div>
      {error && <p className="field-error" role="alert">{error}</p>}
      {lane.executor === "agent" && agent?.available && <AgentRuns lane={lane} onLaneChanged={onLaneChanged} />}
    </section>
  );
}

function AgentRuns({ lane, onLaneChanged }: { lane: LaneDetail; onLaneChanged: (l: LaneDetail) => void }) {
  const [runs, setRuns] = useState<Job[]>([]);
  const [turns, setTurns] = useState(40);
  const [requests, setRequests] = useState(200);
  const [openLog, setOpenLog] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    const list = await api.agentRuns(lane.id).catch(() => null);
    if (list) setRuns(list);
    return list;
  }, [lane.id]);

  const active = runs.some((r) => r.status === "queued" || r.status === "running");
  useEffect(() => {
    load();
  }, [load]);
  useEffect(() => {
    if (!active) return;
    // While a run is active, follow it; when it ends, reload the lane to show its evidence.
    const t = setInterval(async () => {
      const list = await load();
      if (list && !list.some((r) => r.status === "queued" || r.status === "running")) {
        api.lane(lane.id).then(onLaneChanged).catch(() => {});
      }
    }, 2500);
    return () => clearInterval(t);
  }, [active, load, lane.id, onLaneChanged]);

  async function start() {
    try {
      await api.startAgentRun(lane.id, turns, requests);
      setError(null);
      await load();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <div className="agent-runs">
      {lane.status !== "closed" && (
        <div className="agent-start">
          <label>
            Turns
            <input type="number" min={1} max={100} value={turns} onChange={(e) => setTurns(Number(e.target.value))} />
          </label>
          <label>
            Requests
            <input type="number" min={1} max={1000} value={requests}
                   onChange={(e) => setRequests(Number(e.target.value))} />
          </label>
          <button className="btn" disabled={active} onClick={start}>Start agent run</button>
        </div>
      )}
      <p className="hint">
        Read-only requests to {lane.host}, with your research identification and rate limit. The agent attaches
        evidence and marks items; you review it and sign the receipt.
      </p>
      {error && <p className="field-error" role="alert">{error}</p>}
      {runs.length > 0 && (
        <ul className="jobs">
          {runs.map((j) => {
            const r = j.result ?? {};
            const failure = j.status === "failed"
              ? j.log?.split("\n").reverse().find((l) => l.startsWith("error: "))?.slice(7)
              : undefined;
            return (
              <li key={j.id} className="job">
                <div className="job-row">
                  <span className={`chip ${j.status}`}>{j.status}</span>
                  <span className="job-kind">{r.status ? OUTCOME[r.status] ?? r.status : "Agent run"}</span>
                  {r.turns !== undefined && (
                    <span className="muted">
                      {plural(r.turns, "turn")}, {plural(r.requests ?? 0, "request")},{" "}
                      {plural(r.evidence_added ?? 0, "evidence entry", "evidence entries")},{" "}
                      {plural(r.items_marked ?? 0, "item")} marked
                      {r.cost_usd_estimate !== undefined && `, about $${r.cost_usd_estimate.toFixed(2)}`}
                      {r.model && ` on ${r.model}`}
                    </span>
                  )}
                  <span className="job-actions">
                    {(j.status === "queued" || j.status === "running") && (
                      <button className="btn ghost small" onClick={async () => { await api.cancelJob(j.id); load(); }}>
                        Cancel
                      </button>
                    )}
                    <button className="btn ghost small" aria-expanded={openLog === j.id}
                            onClick={() => setOpenLog(openLog === j.id ? null : j.id)}>
                      {openLog === j.id ? "Hide log" : "Show log"}
                    </button>
                  </span>
                </div>
                {r.summary && <p className="agent-summary">{r.summary}</p>}
                {r.detail && <p className="muted">{r.detail}</p>}
                {failure && <p className="field-error">{failure}</p>}
                {openLog === j.id && <JobLog jobId={j.id} live={j.status === "running" || j.status === "queued"} />}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
