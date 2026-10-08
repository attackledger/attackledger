import { FormEvent, useCallback, useEffect, useState } from "react";
import { api, EndpointRow, Job, Lead, ReconModule, Scope, ScopeImport, TriageReport } from "./api";


const TRAFFIC_LABEL = { passive: "Passive", dns: "DNS only", target: "Sends traffic" } as const;

const SIGNAL_HINT: Record<string, string> = {
  AUTH: "401, or 403 that is not a WAF page",
  TITLE: "Title looks like a login, admin or console page",
  APPTECH: "Application technology beyond CDN or edge noise",
  ODDPORT: "Web service on a port other than 80/443",
  KEYWORD: "Host name contains a high-value keyword",
  "200": "Answers 200",
  WAF: "Looks like a WAF or bot challenge",
};

function lines(v: string) {
  return v.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
}

export function Recon({ engId, onAssetsChanged }: { engId: number; onAssetsChanged: () => void }) {
  const [scope, setScope] = useState<Scope | null>(null);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [triage, setTriage] = useState<TriageReport | null>(null);
  const [mods, setMods] = useState<ReconModule[]>([]);
  const [pipeMsg, setPipeMsg] = useState<string | null>(null);   // all hooks before any early return
  useEffect(() => { api.modules().then(setMods).catch(() => {}); }, []);
  const [openLog, setOpenLog] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const [s, j, t] = await Promise.all([api.scope(engId), api.jobs(engId), api.triage(engId)]);
    setScope(s);
    setJobs(j);
    setTriage(t);
  }, [engId]);

  useEffect(() => {
    setScope(null);
    refresh().catch((e) => setError(e.message));
  }, [refresh]);

  const active = jobs.some((j) => j.status === "queued" || j.status === "running");
  useEffect(() => {
    if (!active) return;
    const t = setInterval(() => { refresh().then(onAssetsChanged).catch(() => {}); }, 2000);
    return () => clearInterval(t);
  }, [active, refresh, onAssetsChanged]);

  if (!scope) return <p className="muted">{error ?? "Loading recon…"}</p>;

  const authorized = !!scope.authorized_at;
  const hasScope = scope.include.length > 0;
  const identified = !!(scope.research_header || scope.research_user_agent);
  const hasWildcard = scope.include.some((p) => p.startsWith("*."));
  const liveHosts = triage?.hosts.length ?? 0;

  function blocker(kind: string): string | null {
    if (!hasScope) return "Define the scope first";
    if (!authorized) return "Record your authorization first";
    const m = mods.find((x) => x.kind === kind);
    if (!m) return "Unknown module";
    if (m.input === "roots" && !hasWildcard) return "Needs a wildcard rule such as *.example.com";
    if (m.opt_in && !scope!.enabled_modules.includes(kind)) return "Off in the rules: enable it only if the program allows it";
    if (m.needs_identification && !identified) return "Set the research header or user agent first";
    if (kind === "crawl" && liveHosts === 0) return "Find live web servers first";
    return null;
  }

  async function runAll() {
    setError(null);
    setPipeMsg(null);
    try {
      const r = await api.runPipeline(engId);
      setPipeMsg(`Queued ${r.queued.length} step${r.queued.length === 1 ? "" : "s"}` +
        (r.skipped.length ? `; skipped ${r.skipped.map((s) => mods.find((m) => m.kind === s.kind)?.title ?? s.kind).join(", ")}` : "") +
        ". Each step picks its targets when it starts.");
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    }
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
      <RulesOfEngagement engId={engId} scope={scope} mods={mods} onSaved={(s) => { setScope(s); onAssetsChanged(); }} />

      <section aria-labelledby="pipeline-title" className="panel">
        <div className="panel-head">
          <h3 id="pipeline-title" className="panel-title">Recon pipeline</h3>
          <button className="btn" disabled={!authorized || !hasScope || active} onClick={runAll}
                  title="Queue every step that passes its gates, in order">
            {active ? "Running…" : "Run pipeline"}
          </button>
        </div>
        {pipeMsg && <p className="saved" role="status">{pipeMsg}</p>}
        <ol className="steps">
          {mods.map((s) => {
            const why = blocker(s.kind);
            const last = jobs.find((j) => j.kind === s.kind);
            const busy = last && (last.status === "queued" || last.status === "running");
            return (
              <li key={s.kind} className="step">
                <div className="step-text">
                  <h4>
                    {s.title} <span className={`traffic ${s.traffic}`}>{TRAFFIC_LABEL[s.traffic]}</span>
                    {s.opt_in && <span className="traffic optin">Opt-in</span>}
                  </h4>
                  <p>{s.summary}</p>
                  {last && (
                    <p className={`step-last ${last.status}`}>
                      Last run: {last.status}
                      {last.status === "done" && `, ${last.result_count} ${last.result_count === 1 ? "result" : "results"}`}
                      {last.status === "partial" && `: stopped early (time or per-run limit), ${last.remaining} target${last.remaining === 1 ? "" : "s"} not run yet`}
                    </p>
                  )}
                </div>
                <div className="step-action">
                  <button className="btn" disabled={!!why || !!busy} onClick={() => run(s.kind)}>
                    {busy ? "Running…" : "Run"}
                  </button>
                  {why && <span className="step-why">{why}</span>}
                </div>
              </li>
            );
          })}
        </ol>
        {error && <p className="field-error" role="alert">{error}</p>}
      </section>

      {triage && <GoldenTargets report={triage} />}
      <Leads engId={engId} version={jobs.filter((j) => j.status === "done").length} />
      <Endpoints engId={engId} version={jobs.length} />

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
                  <span className="job-kind">{mods.find((s) => s.kind === j.kind)?.title ?? j.kind}</span>
                  <span className="muted">
                    {j.status === "partial" || (j.status === "cancelled" && j.remaining)
                      ? `${j.targets_done} of ${j.targets.length} targets run`
                      : `${j.targets.length} target${j.targets.length === 1 ? "" : "s"}`}
                  </span>
                  <span className="muted job-time">{new Date(j.created_at).toLocaleTimeString()}</span>
                  <span className="job-actions">
                    {j.remaining > 0 && (j.status === "partial" || j.status === "cancelled") && (
                      <button className="btn small" onClick={async () => {
                        try { await api.resumeJob(j.id); await refresh(); } catch (e) { setError((e as Error).message); }
                      }}>
                        Run remaining {j.remaining}
                      </button>
                    )}
                    {(j.status === "queued" || j.status === "running") && (
                      <button className="btn ghost small" onClick={async () => { await api.cancelJob(j.id); refresh(); }}>
                        Cancel
                      </button>
                    )}
                    <button className="btn ghost small" aria-expanded={openLog === j.id}
                            onClick={() => setOpenLog(openLog === j.id ? null : j.id)}>
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

function GoldenTargets({ report }: { report: TriageReport }) {
  const golden = report.hosts.filter((h) => h.golden).length;
  return (
    <section aria-labelledby="golden-title" className="panel">
      <div className="panel-head">
        <h3 id="golden-title" className="panel-title">Golden targets</h3>
        <span className="muted">{golden} of {report.hosts.length} live hosts score {report.golden_min_score} or more</span>
      </div>
      {report.hosts.length === 0 ? (
        <p className="muted">Run “Find live web servers”. Each host is scored from what it answers, highest first.</p>
      ) : (
        <div className="sheet">
          <table className="obs triage">
            <thead>
              <tr>
                <th scope="col">Score</th>
                <th scope="col">Host</th>
                <th scope="col">Signals</th>
                <th scope="col">Status</th>
                <th scope="col">Ports</th>
                <th scope="col">Title</th>
                <th scope="col">Stack</th>
                <th scope="col">Endpoints</th>
                <th scope="col">Leads</th>
              </tr>
            </thead>
            <tbody>
              {report.hosts.map((h) => (
                <tr key={h.host} className={h.golden ? "golden" : undefined}>
                  <td><span className="score">{h.score}</span></td>
                  <th scope="row">
                    {h.urls[0] ? <a href={h.urls[0]} target="_blank" rel="noreferrer noopener">{h.host}</a> : h.host}
                  </th>
                  <td>{h.signals.map((s) => <span key={s} className={`sig sig-${s}`} title={SIGNAL_HINT[s]}>{s}</span>)}</td>
                  <td>{h.statuses.map((c) => <span key={c} className={`code c${c[0]}`}>{c} </span>)}</td>
                  <td>{h.ports.join(", ")}</td>
                  <td className="clip" title={h.titles.join(" / ")}>{h.titles[0] ?? ""}</td>
                  <td>{h.tech.slice(0, 3).map((t) => <span key={t} className="tag">{t}</span>)}</td>
                  <td>{h.endpoints ? `${h.endpoints}${h.js ? ` (${h.js} JS)` : ""}` : <span className="muted">—</span>}</td>
                  <td>{h.leads ? <strong>{h.leads}</strong> : <span className="muted">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

const LEAD_KIND: Record<string, string> = { secret: "Secret candidate", graphql: "GraphQL operation", sourcemap: "Sourcemap", nuclei: "Scanner finding", parameter: "Hidden parameters", "param-class": "Parameter pattern", dork: "Manual check" };

function Leads({ engId, version }: { engId: number; version: number }) {
  const [rows, setRows] = useState<Lead[]>([]);
  const [open, setOpen] = useState<number | null>(null);
  useEffect(() => { api.leads(engId).then(setRows).catch(() => {}); }, [engId, version]);
  const real = rows.filter((l) => l.kind === "secret" && l.bucket === "real").length;

  return (
    <section aria-labelledby="leads-title" className="panel">
      <div className="panel-head">
        <h3 id="leads-title" className="panel-title">Leads</h3>
        <span className="muted">
          {rows.length} total{real ? `, ${real} secret ${real === 1 ? "candidate" : "candidates"} to review` : ""}
        </span>
      </div>
      {rows.length === 0 ? (
        <p className="muted">Analyse JavaScript to collect leads. They are what the hunt lanes start from.</p>
      ) : (
        <>
          <p className="disclaimer">
            Secret candidates are shown masked and have not been tested. Do not use them. Confirm the owner, check
            the program policy, and report.
          </p>
          <ul className="leads">
            {rows.map((l) => (
              <li key={l.id} className={`lead ${l.kind} ${l.bucket}`}>
                <div className="lead-row">
                  <span className="lead-kind">{LEAD_KIND[l.kind] ?? l.kind}</span>
                  <span className="lead-title">
                    {l.title}
                    {l.detail.preview && <code className="lead-preview">{l.detail.preview}</code>}
                  </span>
                  <span className="lead-badge">
                    {(l.bucket === "real" || l.kind === "nuclei") && l.severity && <span className="sev">{l.severity}</span>}
                    {l.bucket === "public" && <span className="muted">Public by design</span>}
                  </span>
                  <button className="btn ghost small" aria-expanded={open === l.id}
                          onClick={() => setOpen(open === l.id ? null : l.id)}>
                    {open === l.id ? "Hide" : "Details"}
                  </button>
                </div>
                {open === l.id && (
                  <dl className="lead-detail">
                    <div><dt>Host</dt><dd>{l.host}</dd></div>
                    <div><dt>Found in</dt><dd><a href={l.source_url} target="_blank" rel="noreferrer noopener">{l.source_url}</a></dd></div>
                    {l.detail.value_sha256 && <div><dt>Value SHA-256</dt><dd><code>{l.detail.value_sha256}</code></dd></div>}
                    {l.detail.map_url && <div><dt>Map</dt><dd>{l.detail.map_url}</dd></div>}
                    {l.detail.template && <div><dt>Template</dt><dd><code>{l.detail.template}</code> ({l.detail.pass} pass)</dd></div>}
                    {l.detail.matched_at && <div><dt>Matched at</dt><dd>{l.detail.matched_at}</dd></div>}
                    {l.detail.sources && l.detail.sources.length > 0 && (
                      <div><dt>Sources</dt><dd className="lead-sources">{l.detail.sources.join("\n")}</dd></div>
                    )}
                  </dl>
                )}
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}

function Endpoints({ engId, version }: { engId: number; version: number }) {
  const [rows, setRows] = useState<EndpointRow[]>([]);
  const [total, setTotal] = useState(0);
  const [jsOnly, setJsOnly] = useState(false);
  const [q, setQ] = useState("");
  const [offset, setOffset] = useState(0);

  useEffect(() => {
    const t = setTimeout(() => {
      api.endpoints(engId, { js: jsOnly ? true : undefined, q: q.trim() || undefined, offset })
        .then((r) => { setRows(r.items); setTotal(r.total); })
        .catch(() => {});
    }, 200);
    return () => clearTimeout(t);
  }, [engId, jsOnly, q, offset, version]);

  return (
    <section aria-labelledby="ep-title" className="panel">
      <div className="panel-head">
        <h3 id="ep-title" className="panel-title">Endpoints</h3>
        <span className="muted">{total} in scope</span>
      </div>
      <div className="ep-filters">
        <input aria-label="Filter endpoints" placeholder="Filter by text, e.g. /api/" value={q}
               onChange={(e) => { setQ(e.target.value); setOffset(0); }} />
        <label className="check">
          <input type="checkbox" checked={jsOnly} onChange={(e) => { setJsOnly(e.target.checked); setOffset(0); }} />
          JavaScript only
        </label>
      </div>
      {rows.length === 0 ? (
        <p className="muted">Crawl golden hosts or collect archived URLs. Static files and duplicate parameter shapes are dropped.</p>
      ) : (
        <>
          <ul className="ep-list">
            {rows.map((e) => (
              <li key={e.url}>
                <span className={`ep-src ${e.js ? "js" : ""}`}>{e.js ? "JS" : e.source}</span>
                <a href={e.url} target="_blank" rel="noreferrer noopener" className="ep-url">{e.url}</a>
              </li>
            ))}
          </ul>
          {total > 100 && (
            <div className="pager">
              <button className="btn ghost small" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 100))}>Previous</button>
              <span className="muted">{offset + 1}–{Math.min(offset + 100, total)} of {total}</span>
              <button className="btn ghost small" disabled={offset + 100 >= total} onClick={() => setOffset(offset + 100)}>Next</button>
            </div>
          )}
        </>
      )}
    </section>
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

function RulesOfEngagement({ engId, scope, mods, onSaved }: {
  engId: number; scope: Scope; mods: ReconModule[]; onSaved: (s: Scope) => void;
}) {
  const [include, setInclude] = useState(scope.include.join("\n"));
  const [exclude, setExclude] = useState(scope.exclude.join("\n"));
  const [rps, setRps] = useState(scope.rate_limit_rps);
  const [header, setHeader] = useState(scope.research_header ?? "");
  const [ua, setUa] = useState(scope.research_user_agent ?? "");
  const [enabled, setEnabled] = useState<string[]>(scope.enabled_modules);
  const [depth, setDepth] = useState(scope.crawl_depth);
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
        enabled_modules: enabled, crawl_depth: depth,
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
            <span className="hint">A hard ceiling for every step that sends traffic, port scanning included. Use the program's limit.</span>
          </label>
          <label className="narrow">
            Crawl depth
            <input type="number" min={1} max={5} value={depth} onChange={(e) => setDepth(Number(e.target.value))} />
          </label>
        </div>
        {mods.some((m) => m.opt_in) && (
          <fieldset className="optins">
            <legend>Modules the program allows</legend>
            {mods.filter((m) => m.opt_in).map((m) => (
              <label key={m.kind} className="check optin-row">
                <input type="checkbox" checked={enabled.includes(m.kind)}
                       onChange={(e) => setEnabled(e.target.checked ? [...enabled, m.kind] : enabled.filter((k) => k !== m.kind))} />
                <span><strong>{m.title}</strong>{m.caution && <span className="hint"> {m.caution}</span>}</span>
              </label>
            ))}
          </fieldset>
        )}

        <ScopeImporter engId={engId} onApplied={async () => {
          const s = await api.scope(engId);
          setInclude(s.include.join("\n"));
          setExclude(s.exclude.join("\n"));
          onSaved(s);
        }} />

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


function ScopeImporter({ engId, onApplied }: { engId: number; onApplied: () => void }) {
  const [csv, setCsv] = useState<string | null>(null);
  const [preview, setPreview] = useState<ScopeImport | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function load(file: File | undefined) {
    setError(null);
    setPreview(null);
    if (!file) return;
    const text = await file.text();
    setCsv(text);
    try { setPreview(await api.importScope(engId, text, false)); } catch (e) { setError((e as Error).message); }
  }

  async function apply() {
    if (!csv) return;
    try {
      await api.importScope(engId, csv, true);
      setPreview(null);
      setCsv(null);
      onApplied();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <div className="importer">
      <label className="check">
        <span>Import a HackerOne scope CSV</span>
        <input type="file" accept=".csv,text/csv" onChange={(e) => load(e.target.files?.[0])} />
      </label>
      <span className="hint">Assets not eligible for submission become exclusions, so a wildcard cannot cover them.</span>
      {error && <p className="field-error">{error}</p>}
      {preview && (
        <div className="import-preview">
          <p>
            <strong>{preview.include.length}</strong> in scope, <strong>{preview.exclude.length}</strong> excluded
            {preview.not_imported.length > 0 && <>, {preview.not_imported.length} not imported (not web assets)</>}
            {preview.invalid.length > 0 && <>, {preview.invalid.length} invalid</>}.
          </p>
          {preview.exclude.length > 0 && <p className="hint">Excluded: {preview.exclude.join(", ")}</p>}
          {preview.not_imported.length > 0 && (
            <p className="hint">Not imported: {preview.not_imported.map((x) => `${x.identifier} (${x.type})`).join(", ")}</p>
          )}
          <button type="button" className="btn small" onClick={apply}>Add to the rules</button>
        </div>
      )}
    </div>
  );
}
