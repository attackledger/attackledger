import { FormEvent, useCallback, useEffect, useState } from "react";
import { api, Job, ObservationRow, Scope } from "./api";

const STEPS = [
  {
    kind: "subdomains",
    title: "Find subdomains",
    body: "Queries passive sources for names under each wildcard in scope. Sends nothing to the target.",
  },
  {
    kind: "resolve",
    title: "Resolve hosts",
    body: "Looks up A, AAAA and CNAME records for in-scope hosts. DNS only.",
  },
  {
    kind: "probe",
    title: "Find live web servers",
    body: "Requests each in-scope host once, with your research identification, and records status, title and stack.",
  },
] as const;

function lines(v: string) {
  return v.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
}

export function Recon({ engId, onAssetsChanged }: { engId: number; onAssetsChanged: () => void }) {
  const [scope, setScope] = useState<Scope | null>(null);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [obs, setObs] = useState<ObservationRow[]>([]);
  const [openLog, setOpenLog] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const [s, j, o] = await Promise.all([api.scope(engId), api.jobs(engId), api.observations(engId)]);
    setScope(s);
    setJobs(j);
    setObs(o);
  }, [engId]);

  useEffect(() => {
    setScope(null);
    refresh().catch((e) => setError(e.message));
  }, [refresh]);

  const active = jobs.some((j) => j.status === "queued" || j.status === "running");
  useEffect(() => {
    if (!active) return;
    const t = setInterval(() => {
      refresh().then(onAssetsChanged).catch(() => {});
    }, 2000);
    return () => clearInterval(t);
  }, [active, refresh, onAssetsChanged]);

  if (!scope) return <p className="muted">{error ?? "Loading recon…"}</p>;

  const authorized = !!scope.authorized_at;
  const hasScope = scope.include.length > 0;
  const identified = !!(scope.research_header || scope.research_user_agent);

  function blocker(kind: string): string | null {
    if (!hasScope) return "Define the scope first";
    if (!authorized) return "Record your authorization first";
    if (kind === "subdomains" && !scope!.include.some((p) => p.startsWith("*.")))
      return "Needs a wildcard rule such as *.example.com";
    if (kind === "probe" && !identified) return "Set the research header or user agent first";
    return null;
  }

  async function run(kind: string) {
    setError(null);
    try {
      await api.runJob(engId, kind);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <div className="recon">
      <RulesOfEngagement engId={engId} scope={scope} onSaved={(s) => { setScope(s); onAssetsChanged(); }} />

      <section aria-labelledby="pipeline-title" className="panel">
        <h3 id="pipeline-title" className="panel-title">Recon pipeline</h3>
        <ol className="steps">
          {STEPS.map((s) => {
            const why = blocker(s.kind);
            const last = jobs.find((j) => j.kind === s.kind);
            return (
              <li key={s.kind} className="step">
                <div className="step-text">
                  <h4>{s.title}</h4>
                  <p>{s.body}</p>
                  {last && (
                    <p className={`step-last ${last.status}`}>
                      Last run: {last.status}
                      {last.status === "done" && `, ${last.result_count} in-scope ${last.result_count === 1 ? "result" : "results"}`}
                    </p>
                  )}
                </div>
                <div className="step-action">
                  <button className="btn" disabled={!!why} onClick={() => run(s.kind)}>
                    Run
                  </button>
                  {why && <span className="step-why">{why}</span>}
                </div>
              </li>
            );
          })}
        </ol>
        {error && <p className="field-error" role="alert">{error}</p>}
      </section>

      <section aria-labelledby="hosts-title" className="panel">
        <div className="panel-head">
          <h3 id="hosts-title" className="panel-title">Discovered hosts</h3>
          <span className="muted">{obs.length} in scope</span>
        </div>
        {obs.length === 0 ? (
          <p className="muted">Run a step above. Only hosts that match your scope rules are kept.</p>
        ) : (
          <div className="sheet">
            <table className="obs">
              <thead>
                <tr>
                  <th scope="col">Host</th>
                  <th scope="col">Status</th>
                  <th scope="col">Title</th>
                  <th scope="col">Stack</th>
                  <th scope="col">Addresses</th>
                </tr>
              </thead>
              <tbody>
                {obs.map((o) => (
                  <tr key={o.host}>
                    <th scope="row">{o.url ? <a href={o.url} target="_blank" rel="noreferrer noopener">{o.host}</a> : o.host}</th>
                    <td>{o.status_code ? <span className={`code c${String(o.status_code)[0]}`}>{o.status_code}</span> : <span className="muted">—</span>}</td>
                    <td className="clip" title={o.title}>{o.title ?? ""}</td>
                    <td>{(o.tech ?? []).slice(0, 4).map((t) => <span key={t} className="tag">{t}</span>)}</td>
                    <td className="clip">{[...(o.a ?? []), ...(o.cname ?? [])].join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section aria-labelledby="jobs-title" className="panel">
        <h3 id="jobs-title" className="panel-title">Runs</h3>
        {jobs.length === 0 ? (
          <p className="muted">No runs yet.</p>
        ) : (
          <ul className="jobs">
            {jobs.map((j) => (
              <li key={j.id} className="job">
                <div className="job-row">
                  <span className={`chip ${j.status}`}>{j.status}</span>
                  <span className="job-kind">{STEPS.find((s) => s.kind === j.kind)?.title ?? j.kind}</span>
                  <span className="muted">{j.targets.length} target{j.targets.length === 1 ? "" : "s"}</span>
                  <span className="muted job-time">{new Date(j.created_at).toLocaleTimeString()}</span>
                  <span className="job-actions">
                    {(j.status === "queued" || j.status === "running") && (
                      <button className="btn ghost small" onClick={async () => { await api.cancelJob(j.id); refresh(); }}>
                        Cancel
                      </button>
                    )}
                    <button
                      className="btn ghost small"
                      aria-expanded={openLog === j.id}
                      onClick={() => setOpenLog(openLog === j.id ? null : j.id)}
                    >
                      {openLog === j.id ? "Hide log" : "Show log"}
                    </button>
                  </span>
                </div>
                {openLog === j.id && <JobLog jobId={j.id} live={j.status === "running" || j.status === "queued"} />}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

function JobLog({ jobId, live }: { jobId: number; live: boolean }) {
  const [job, setJob] = useState<Job | null>(null);
  useEffect(() => {
    let stop = false;
    const load = () => api.job(jobId).then((j) => !stop && setJob(j)).catch(() => {});
    load();
    const t = live ? setInterval(load, 1500) : undefined;
    return () => { stop = true; if (t) clearInterval(t); };
  }, [jobId, live]);
  if (!job) return null;
  return (
    <div className="log">
      <pre>{job.log || "Waiting for the worker…"}</pre>
      {job.output_sha256 && <p className="muted">Output SHA-256 <code>{job.output_sha256}</code></p>}
    </div>
  );
}

function RulesOfEngagement({ engId, scope, onSaved }: { engId: number; scope: Scope; onSaved: (s: Scope) => void }) {
  const [include, setInclude] = useState(scope.include.join("\n"));
  const [exclude, setExclude] = useState(scope.exclude.join("\n"));
  const [rps, setRps] = useState(scope.rate_limit_rps);
  const [header, setHeader] = useState(scope.research_header ?? "");
  const [ua, setUa] = useState(scope.research_user_agent ?? "");
  const [operator, setOperator] = useState(scope.authorized_by ?? "");
  const [policy, setPolicy] = useState(scope.policy_url ?? "");
  const [confirm, setConfirm] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);

  async function save(ev: FormEvent) {
    ev.preventDefault();
    setError(null);
    setSaved(null);
    try {
      let s = await api.saveScope(engId, {
        include: lines(include), exclude: lines(exclude), rate_limit_rps: rps,
        research_header: header.trim() || null, research_user_agent: ua.trim() || null,
      });
      if (confirm) s = await api.attest(engId, operator, policy);
      setConfirm(false);
      setSaved("Rules saved.");
      onSaved(s);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <section aria-labelledby="roe-title" className="panel">
      <div className="panel-head">
        <h3 id="roe-title" className="panel-title">Rules of engagement</h3>
        {scope.authorized_at ? (
          <span className="auth ok">Authorized by {scope.authorized_by}, {new Date(scope.authorized_at).toLocaleDateString()}</span>
        ) : (
          <span className="auth bad">Not authorized yet. Nothing will run.</span>
        )}
      </div>
      <form className="roe" onSubmit={save}>
        <div className="roe-grid">
          <label>
            In scope
            <textarea rows={4} value={include} onChange={(e) => setInclude(e.target.value)} placeholder={"*.example.com\nexample.com"} />
            <span className="hint">One per line. *.example.com covers subdomains only, so list the apex separately.</span>
          </label>
          <label>
            Out of scope
            <textarea rows={4} value={exclude} onChange={(e) => setExclude(e.target.value)} placeholder="status.example.com" />
            <span className="hint">Exclusions always win.</span>
          </label>
          <label>
            Research header
            <input value={header} onChange={(e) => setHeader(e.target.value)} placeholder="X-Bug-Bounty: your-handle" />
            <span className="hint">Sent on every request to the target, exactly as the program asks.</span>
          </label>
          <label>
            Research user agent
            <input value={ua} onChange={(e) => setUa(e.target.value)} placeholder="Mozilla/5.0 (compatible; your-handle)" />
            <span className="hint">Set this too if the program requires it; otherwise tools send their own.</span>
          </label>
          <label className="narrow">
            Requests per second
            <input type="number" min={1} max={50} value={rps} onChange={(e) => setRps(Number(e.target.value))} />
          </label>
        </div>

        <fieldset className="attest">
          <legend>Authorization</legend>
          <div className="roe-grid">
            <label>
              Program policy URL
              <input value={policy} onChange={(e) => setPolicy(e.target.value)} placeholder="https://hackerone.com/example" />
            </label>
            <label>
              Your name or handle
              <input value={operator} onChange={(e) => setOperator(e.target.value)} />
            </label>
          </div>
          <label className="check">
            <input type="checkbox" checked={confirm} onChange={(e) => setConfirm(e.target.checked)} />
            I am authorized to test this program and will follow its policy.
          </label>
        </fieldset>

        {error && <p className="field-error" role="alert">{error}</p>}
        {saved && <p className="saved" role="status">{saved}</p>}
        <button type="submit" className="btn">Save rules</button>
      </form>
    </section>
  );
}
