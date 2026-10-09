import { FormEvent, useCallback, useEffect, useState } from "react";
import { api, EndpointRow, Job, Lead, ObservationRow, ReconModule, ReconPhase, ReconSummary, Scope, ScopeImport,
         TriageReport } from "./api";
import { AddHost } from "./AddHost";
import { latestLine, secondsSince, shownStatus, skipReason, STATUS_WORD } from "./jobs";
import { duration, plural, termsFor, type Terms } from "./words";


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

/** "Added shop.example.com as a host." for the hosts the server made from exact scope entries. */
function addedText(hosts: string[] | undefined): string {
  if (!hosts?.length) return "";
  const shown = hosts.slice(0, 5).join(", ") + (hosts.length > 5 ? ` and ${hosts.length - 5} more` : "");
  return ` Added ${shown} as ${hosts.length === 1 ? "a host" : "hosts"}.`;
}

function lines(v: string) {
  return v.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
}

type ResultTab = "golden" | "hosts" | "urls" | "leads" | "runs";

// Which results view shows what a module produced.
const RESULT_TAB: Record<string, ResultTab> = {
  subdomains: "hosts", resolve: "hosts", ports: "hosts", probe: "hosts",
  crawl: "urls", archive: "urls", content: "urls",
  jsanalyze: "leads", params: "leads", paramclass: "leads", nuclei: "leads", dorks: "leads",
};

function ago(iso: string | null) {
  if (!iso) return "";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return new Date(iso).toLocaleDateString();
}

export function Recon({ engId, onAssetsChanged, canManage = true, canRun = true, hostsInScope, engagementType }: {
  engId: number; onAssetsChanged: () => void; canManage?: boolean; canRun?: boolean;   // owner; tester
  hostsInScope: number;
  engagementType?: string;   // bug_bounty, pentest or internal: the words for who sets the rules
}) {
  const terms = termsFor(engagementType);
  const [scope, setScope] = useState<Scope | null>(null);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [triage, setTriage] = useState<TriageReport | null>(null);
  const [summary, setSummary] = useState<ReconSummary | null>(null);
  const [mods, setMods] = useState<ReconModule[]>([]);
  const [phases, setPhases] = useState<ReconPhase[]>([]);
  const [pipeMsg, setPipeMsg] = useState<string | null>(null);   // all hooks before any early return
  const [pipeSkipped, setPipeSkipped] = useState<{ kind: string; reason: string }[]>([]);
  const [rulesMsg, setRulesMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [tab, setTab] = useState<ResultTab>("golden");
  const [only, setOnly] = useState<string | null>(null);         // results filtered to one module
  useEffect(() => {
    api.modules().then(setMods).catch(() => {});
    api.phases().then(setPhases).catch(() => {});
  }, []);

  const refresh = useCallback(async () => {
    const [s, j, t, sum] = await Promise.all([api.scope(engId), api.jobs(engId), api.triage(engId),
                                              api.reconSummary(engId)]);
    setScope(s);
    setJobs(j);
    setTriage(t);
    setSummary(sum);
  }, [engId]);

  useEffect(() => {
    setScope(null);
    setRulesMsg(null);
    setPipeMsg(null);
    setPipeSkipped([]);
    setEditing(false);
    setOnly(null);
    setTab("golden");
    refresh().catch((e) => setError(e.message));
  }, [refresh]);

  const active = jobs.some((j) => j.status === "queued" || j.status === "running");
  useEffect(() => {
    if (!active) return;
    const t = setInterval(() => { refresh().then(onAssetsChanged).catch(() => {}); }, 2000);
    return () => clearInterval(t);
  }, [active, refresh, onAssetsChanged]);

  // The step that is running now (the worker runs one at a time): follow its log while it runs.
  const running = jobs.find((j) => j.status === "running") ?? null;
  const runningId = running?.id ?? null;
  const [runLog, setRunLog] = useState<{ id: number; log: string } | null>(null);
  useEffect(() => {
    if (runningId == null) return;
    let stop = false;
    const load = () => api.job(runningId).then((j) => { if (!stop) setRunLog({ id: j.id, log: j.log ?? "" }); }).catch(() => {});
    load();
    const t = setInterval(load, 3000);
    return () => { stop = true; clearInterval(t); };
  }, [runningId]);
  const liveLine = running && runLog?.id === running.id ? latestLine(runLog.log) : null;

  if (!scope) return <p className="muted">{error ?? "Loading recon…"}</p>;

  const authorized = !!scope.authorized_at;
  const hasScope = scope.include.length > 0;
  const identified = !!(scope.research_header || scope.research_user_agent);
  const hasWildcard = scope.include.some((p) => p.startsWith("*."));
  const liveHosts = triage?.hosts.length ?? 0;
  const needsRules = !authorized || !hasScope || !identified;
  const noHosts = hostsInScope === 0;
  // With no host and no wildcard rule, no step has anything to work on.
  const nothingToDo = noHosts && !hasWildcard;
  const runAllWhy = !hasScope ? "Define the scope first."
    : !authorized ? "Record your authorization first."
    : nothingToDo ? "Nothing to work on yet: add a host, or a wildcard rule for recon to discover hosts under."
    : null;

  function blocker(kind: string): string | null {
    if (!hasScope) return "Define the scope first";
    if (!authorized) return "Record your authorization first";
    const m = mods.find((x) => x.kind === kind);
    if (!m) return "Unknown module";
    if (m.input === "roots" && !hasWildcard) return "Needs a wildcard rule such as *.example.com";
    if (m.input === "hosts" && noHosts && !hasWildcard) return "No in-scope hosts yet: add one first";
    if (m.opt_in && !scope!.enabled_modules.includes(kind)) return `Off in the rules: enable it only if ${terms.allows} it`;
    if (m.needs_identification && !identified) return "Set the research header or user agent first";
    if (scope!.rate_limit_rps < m.min_rps) return `Needs a rate limit of at least ${m.min_rps} per second to stay within it`;
    if (kind === "crawl" && liveHosts === 0) return "Find live web servers first";
    return null;
  }

  async function queue(kinds?: string[]) {
    setError(null);
    setPipeMsg(null);
    setPipeSkipped([]);
    try {
      const r = await api.runPipeline(engId, kinds);
      setPipeMsg(`Queued ${plural(r.queued.length, "step")}` +
        (r.skipped.length ? `; ${plural(r.skipped.length, "step")} cannot apply and ${r.skipped.length === 1 ? "was" : "were"} not queued` : "") +
        ". Steps run one at a time, in order; each picks its targets when it starts, from what the steps before it found.");
      setPipeSkipped(r.skipped);
      setTab("runs");
      setOnly(null);
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

  function showResults(kind: string) {
    setTab(RESULT_TAB[kind] ?? "runs");
    setOnly(RESULT_TAB[kind] === "hosts" ? null : kind);
    document.getElementById("results")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  const s = summary;
  const funnel: [string, number | undefined][] = [
    ["host names in scope", s?.hosts], ["resolve", s?.resolved], ["answer on the web", s?.live],
    ["golden", s?.golden], ["URLs", s?.urls], ["leads", s?.leads],
  ];
  const stat: Record<string, string> = s ? {
    subdomains: plural(s.hosts, "host name") + " in scope",
    live: `${plural(s.resolved, "host")} resolve, ${s.live.toLocaleString()} answer on the web, ${s.golden.toLocaleString()} golden`,
    urls: `${plural(s.urls, "URL")}, ${s.js.toLocaleString()} JavaScript`,
    js: plural((s.lead_kinds.secret ?? 0) + (s.lead_kinds.graphql ?? 0) + (s.lead_kinds.sourcemap ?? 0)
               + (s.lead_kinds.parameter ?? 0) + (s.lead_kinds["param-class"] ?? 0), "lead"),
    issues: plural(s.lead_kinds.nuclei ?? 0, "finding") + " to verify",
    manual: plural(s.lead_kinds.dork ?? 0, "query", "queries"),
  } : {};

  return (
    <div className="recon">
      <TargetBar scope={scope} mods={mods} editing={canManage && (editing || needsRules)}
                 canClose={canManage && !needsRules} onToggle={() => setEditing(!editing)} />
      {!canManage && needsRules && (
        <p className="notice-inline">The rules for this engagement are not complete yet (scope, research identification
          or authorization). An owner has to record them before anything runs.</p>
      )}
      {canManage && (editing || needsRules) && (
        <RulesOfEngagement engId={engId} scope={scope} mods={mods} terms={terms}
                           onSaved={(sc, msg, fold) => {
                             // Saved: once the rules are complete the form folds into the summary bar above,
                             // so the page leads with the work. An import keeps the form open for the rest.
                             setScope(sc); setRulesMsg(msg ?? null); if (fold) setEditing(false);
                             onAssetsChanged(); refresh().catch(() => {});
                           }} />
      )}
      {rulesMsg && !(canManage && (editing || needsRules)) && <p className="saved" role="status">{rulesMsg}</p>}

      {noHosts && (
        <section className="panel no-hosts" aria-labelledby="no-hosts-title">
          <h3 id="no-hosts-title" className="panel-title">No in-scope hosts yet</h3>
          <p>Recon works on the hosts in this engagement, and so does the ledger. There are three ways to get them:</p>
          <ul>
            <li>
              <strong>Add a host here.</strong> It gets a row in the ledger straight away.
            </li>
            <li>
              <strong>Exact entries in the scope rules</strong>, such as <code>shop.example.com</code>, become hosts
              when the rules are saved.
            </li>
            <li>
              <strong>Wildcard rules</strong>, such as <code>*.example.com</code>, are not hosts themselves: the
              subdomain step discovers the hosts under them.{" "}
              {hasWildcard ? "This engagement has one, so running the steps will look for hosts."
                           : "This engagement has none yet."}
            </li>
          </ul>
          {canRun ? <AddHost engId={engId} onAdded={() => { onAssetsChanged(); refresh().catch(() => {}); }}
                             id="recon-new-host" className="inline-form" />
                  : <p className="muted">A tester or an owner on this engagement adds hosts.</p>}
        </section>
      )}

      <section aria-labelledby="workflow-title" className="panel workflow">
        <div className="panel-head">
          <h3 id="workflow-title" className="panel-title">Recon workflow</h3>
          {canRun ? (
            <div className="run-all">
              <button id="run-all" className="btn" disabled={!!runAllWhy || active} onClick={() => queue()}
                      aria-describedby="run-all-why">
                {running ? "Running…" : active ? "Queued…" : "Run all steps"}
              </button>
              <span id="run-all-why" className="step-why">
                {active ? "Wait for the queued steps to finish."
                  : runAllWhy ?? "Queues every step that passes its gates. They run one at a time, in order."}
              </span>
            </div>
          ) : active && <span className="chip running">Running</span>}
        </div>
        {pipeMsg && <p className="saved" role="status">{pipeMsg}</p>}
        {pipeSkipped.length > 0 && (
          <ul className="pipe-skipped" aria-label="Steps not queued">
            {pipeSkipped.map((x) => (
              <li key={x.kind}><strong>{mods.find((m) => m.kind === x.kind)?.title ?? x.kind}</strong>: {x.reason}</li>
            ))}
          </ul>
        )}
        {error && <p className="field-error" role="alert">{error}</p>}
        {active && <QueueStatus jobs={jobs} mods={mods} liveLine={liveLine} />}

        <ol className="funnel" aria-label="How the surface narrows">
          {funnel.map(([label, n]) => (
            <li key={label}><span className="funnel-n">{n === undefined ? "–" : n.toLocaleString()}</span>{label}</li>
          ))}
        </ol>

        <ol className="phases">
          {phases.map((p, i) => {
            const runnable = p.kinds.filter((k) => !blocker(k));
            return (
              <li key={p.key} className="phase">
                <div className="phase-head">
                  <span className="phase-n" aria-hidden="true">{i + 1}</span>
                  <div className="phase-text">
                    <h4>{p.title}</h4>
                    <p>{p.summary}</p>
                    {stat[p.key] && <p className="phase-stat">{stat[p.key]}</p>}
                  </div>
                  {canRun && (
                    <button className="btn ghost small" disabled={active || runnable.length === 0}
                            onClick={() => queue(runnable)}
                            title={runnable.length ? `Queue ${runnable.length} of ${p.kinds.length} tools in this step` : "Nothing in this step can run yet"}>
                      Run step
                    </button>
                  )}
                </div>
                <details className="phase-help">
                  <summary>How this step works</summary>
                  <p>{p.help}</p>
                  <dl>
                    {p.kinds.map((k) => mods.find((m) => m.kind === k)).filter((m): m is ReconModule => !!m).map((m) => (
                      <div key={m.kind}><dt>{m.title}</dt><dd>{m.summary}</dd></div>
                    ))}
                  </dl>
                </details>
                <ul className="tools">
                  {p.kinds.map((k) => mods.find((m) => m.kind === k)).filter((m): m is ReconModule => !!m).map((m) => (
                    <ToolCard key={m.kind} m={m} last={jobs.find((j) => j.kind === m.kind)} why={blocker(m.kind)} canRun={canRun}
                              jobs={jobs} liveLine={liveLine}
                              onRun={() => run(m.kind)} onResults={() => showResults(m.kind)} />
                  ))}
                </ul>
              </li>
            );
          })}
        </ol>
      </section>

      <section id="results" aria-label="Recon results" className="panel results">
        <div className="rtabs" role="tablist" aria-label="Results">
          {([["golden", "Golden targets"], ["hosts", "Hosts"], ["urls", "URLs"], ["leads", "Leads"], ["runs", "Runs"]] as const).map(([k, label]) => (
            <button key={k} role="tab" aria-selected={tab === k} className={`rtab${tab === k ? " on" : ""}`}
                    onClick={() => { setTab(k); setOnly(null); }}>
              {label}
              {k === "leads" && s ? <span className="tab-n">{s.leads}</span> : null}
              {k === "urls" && s ? <span className="tab-n">{s.urls}</span> : null}
              {k === "runs" && active ? <span className="tab-n live">Running</span> : null}
            </button>
          ))}
        </div>
        {only && (
          <p className="only">
            Showing only what <strong>{mods.find((m) => m.kind === only)?.title ?? only}</strong> found.{" "}
            <button className="linklike" onClick={() => setOnly(null)}>Show everything</button>
          </p>
        )}
        {tab === "golden" && triage && <GoldenTargets report={triage} />}
        {tab === "hosts" && <Hosts engId={engId} version={jobs.length} />}
        {tab === "urls" && <Endpoints engId={engId} version={jobs.length} module={only ?? undefined} />}
        {tab === "leads" && <Leads engId={engId} terms={terms} version={jobs.filter((j) => shownStatus(j) === "done" || j.status === "partial").length}
                                   module={only ?? undefined} />}
        {tab === "runs" && <Runs jobs={jobs} mods={mods} refresh={refresh} onError={setError} canRun={canRun} liveLine={liveLine} />}
      </section>
    </div>
  );
}

function TargetBar({ scope, mods, editing, canClose, onToggle }: {
  scope: Scope; mods: ReconModule[]; editing: boolean; canClose: boolean; onToggle: () => void;
}) {
  const optIns = mods.filter((m) => m.opt_in);
  const enabled = optIns.filter((m) => scope.enabled_modules.includes(m.kind));
  const shown = scope.include.slice(0, 3);
  return (
    <section className="target-bar" aria-label="Target and rules">
      <dl>
        <div>
          <dt>Scope</dt>
          <dd>
            {scope.include.length === 0 ? <span className="bad">No scope yet</span> : (
              <>
                {shown.map((p) => <code key={p}>{p}</code>)}
                {scope.include.length > 3 && <span className="muted"> and {scope.include.length - 3} more</span>}
                {scope.exclude.length > 0 && <span className="muted">, {scope.exclude.length} excluded</span>}
              </>
            )}
          </dd>
        </div>
        <div>
          <dt>Rate limit</dt>
          <dd>{scope.rate_limit_rps} per second</dd>
        </div>
        <div>
          <dt>Identification</dt>
          <dd>{scope.research_header ? <code>{scope.research_header}</code>
               : scope.research_user_agent ? "User agent set" : <span className="bad">Not set</span>}</dd>
        </div>
        <div>
          <dt>Allowed extras</dt>
          <dd>{enabled.length ? enabled.map((m) => m.title).join(", ") : <span className="muted">None</span>}</dd>
        </div>
        <div>
          <dt>Evidence</dt>
          <dd>{scope.redact_evidence === false ? <span className="bad">Stored unredacted (lab)</span>
               : "Credentials redacted before storage"}</dd>
        </div>
        <div>
          <dt>Authorization</dt>
          <dd>{scope.authorized_at
            ? <span className="ok">{scope.authorized_by}, {new Date(scope.authorized_at).toLocaleDateString()}</span>
            : <span className="bad">Not recorded. Nothing will run.</span>}</dd>
        </div>
      </dl>
      {canClose && (
        <button className="btn ghost small" aria-expanded={editing} onClick={onToggle}>
          {editing ? "Close rules" : "Edit rules"}
        </button>
      )}
    </section>
  );
}

function ToolCard({ m, last, why, canRun, jobs, liveLine, onRun, onResults }: {
  m: ReconModule; last?: Job; why: string | null; canRun: boolean; jobs: Job[]; liveLine: string | null;
  onRun: () => void; onResults: () => void;
}) {
  const [log, setLog] = useState(false);
  const busy = !!last && (last.status === "queued" || last.status === "running");
  const st = last ? shownStatus(last) : null;
  return (
    <li className={`tool${why ? " blocked" : ""}`}>
      <div className="tool-name">
        <h5 title={m.summary}>{m.title}</h5>
        <p className="tool-uses">{m.tools.join(", ")}</p>
      </div>
      <span className="tool-badges">
        <span className={`traffic ${m.traffic}`}>{TRAFFIC_LABEL[m.traffic]}</span>
        {m.opt_in && <span className="traffic optin">Opt-in</span>}
      </span>
      <p className="tool-last">
        {last ? (
          <>
            <StatusChip job={last} />{" "}
            {st === "done" && plural(last.result_count, "result")}
            {st === "partial" && `${last.remaining} not run yet`}
            {st !== "running" && st !== "queued" &&
              <span className="muted"> {ago(last.finished_at ?? last.started_at ?? last.created_at)}</span>}
            {st === "skipped" && <SkipReason job={last} />}
            {(st === "running" || st === "queued") && <JobProgress job={last} jobs={jobs} liveLine={liveLine} />}
          </>
        ) : <span className="muted">Not run yet</span>}
        {why && canRun && <span className="tool-why">{why}</span>}
      </p>
      <div className="tool-actions">
        {canRun && <button className="btn small" disabled={!!why || busy} onClick={onRun}>{last?.status === "running" ? "Running…" : busy ? "Queued" : "Run"}</button>}
        <button className="btn ghost small" onClick={onResults}>Results</button>
        {last && (
          <button className="btn ghost small" aria-expanded={log} onClick={() => setLog(!log)}>
            {log ? "Hide log" : "Log"}
          </button>
        )}
      </div>
      {log && last && <JobLog jobId={last.id} live={busy} />}
    </li>
  );
}

function Runs({ jobs, mods, refresh, onError, canRun, liveLine }: {
  jobs: Job[]; mods: ReconModule[]; refresh: () => Promise<void>; onError: (m: string) => void; canRun: boolean;
  liveLine: string | null;
}) {
  const [openLog, setOpenLog] = useState<number | null>(null);
  if (jobs.length === 0) return <p className="muted">{canRun ? "No runs yet. Run a step above, or every step at once." : "No runs yet."}</p>;
  return (
    <ul className="jobs">
      {jobs.map((j) => (
        <li key={j.id} className="job">
          <div className="job-row">
            <StatusChip job={j} />
            <span className="job-kind">{j.kind === "agent" ? "Claude agent" : mods.find((s) => s.kind === j.kind)?.title ?? j.kind}</span>
            <span className="muted">
              {j.status === "partial" || (j.status === "cancelled" && j.remaining)
                ? `${j.targets_done} of ${plural(j.targets.length, "target")} run`
                : shownStatus(j) === "skipped" ? "nothing to work on"
                : j.deferred && j.targets.length === 0 ? "targets picked when it starts"
                : shownStatus(j) === "done" ? `${plural(j.targets.length, "target")}, ${plural(j.result_count, "result")}`
                : plural(j.targets.length, "target")}
            </span>
            <span className="muted job-time">{new Date(j.created_at).toLocaleTimeString()}</span>
            <span className="job-actions">
              {canRun && j.remaining > 0 && (j.status === "partial" || j.status === "cancelled") && (
                <button className="btn small" onClick={async () => {
                  try { await api.resumeJob(j.id); await refresh(); } catch (e) { onError((e as Error).message); }
                }}>
                  Run remaining {j.remaining}
                </button>
              )}
              {canRun && (j.status === "queued" || j.status === "running") && (
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
          {shownStatus(j) === "skipped" && <p className="job-note"><SkipReason job={j} /></p>}
          {(j.status === "running" || j.status === "queued") && (
            <p className="job-note"><JobProgress job={j} jobs={jobs} liveLine={liveLine} /></p>
          )}
          {openLog === j.id && <JobLog jobId={j.id} live={j.status === "running" || j.status === "queued"} />}
        </li>
      ))}
    </ul>
  );
}

/** The queue at a glance while anything runs: what runs now, how long it has run, what waits behind it. */
function QueueStatus({ jobs, mods, liveLine }: { jobs: Job[]; mods: ReconModule[]; liveLine: string | null }) {
  const title = (j: Job) => (j.kind === "agent" ? "Claude agent" : mods.find((m) => m.kind === j.kind)?.title ?? j.kind);
  const running = jobs.find((j) => j.status === "running");
  const waiting = jobs.filter((j) => j.status === "queued").sort((a, b) => a.id - b.id);
  return (
    <div className="queue">
      <p className="queue-now">
        {running ? <>Now running: <strong>{title(running)}</strong></> : "Waiting for the worker to pick up the next step."}
      </p>
      {running && <p className="queue-progress"><JobProgress job={running} jobs={jobs} liveLine={liveLine} /></p>}
      {waiting.length > 0 && (
        <p className="queue-next">
          Then, in order: {waiting.map(title).join(", ")}.
        </p>
      )}
      <p className="hint">
        Steps run one at a time, so a slow step such as content discovery holds the ones after it. Content discovery
        sends at most the rate limit per second; on a large host that can take many minutes.
      </p>
    </div>
  );
}

export function StatusChip({ job }: { job: Job }) {
  const st = shownStatus(job);
  return <span className={`chip ${st}`}>{STATUS_WORD[st] ?? st}</span>;
}

/** Why a skipped step did not run. The list of jobs carries no log, so it is read from the job when needed. */
export function SkipReason({ job }: { job: Job }) {
  const [fetched, setFetched] = useState<string | null>(null);
  const known = skipReason(job);
  useEffect(() => {
    if (known) return;
    let stop = false;
    api.job(job.id).then((j) => { if (!stop) setFetched(skipReason(j)); }).catch(() => {});
    return () => { stop = true; };
  }, [job.id, known]);
  const why = known ?? fetched;
  return <span className="skip-why">{why ? `Not run: ${why}` : "Not run: it had nothing to work on."}</span>;
}

/** Where a queued or running step is: elapsed time, targets finished, the worker's latest line. */
export function JobProgress({ job, jobs, liveLine }: { job: Job; jobs: Job[]; liveLine: string | null }) {
  if (job.status === "queued") {
    const ahead = jobs.filter((j) => (j.status === "queued" && j.id < job.id) || j.status === "running").length;
    return (
      <span className="progress">
        {ahead ? `Waiting: ${plural(ahead, "step")} ahead of it. Steps run one at a time.` : "Starting…"}
      </span>
    );
  }
  const elapsed = secondsSince(job.started_at);
  const total = job.targets.length;
  const done = job.targets_done;
  // Only a pace the run has shown: targets are counted in finished batches, so no estimate before the first.
  const left = elapsed != null && done > 0 && done < total ? (elapsed / done) * (total - done) : null;
  return (
    <span className="progress" aria-live="off">
      <span>
        Running{elapsed != null && <> for {duration(elapsed)}</>}
        {total > 0 && <>, {done} of {plural(total, "target")} finished</>}
        {left != null && <>; about {left < 60 ? "a minute" : duration(Math.round(left / 60) * 60)} left at this pace</>}.
      </span>
      {liveLine && <span className="progress-line" title={liveLine}>{liveLine}</span>}
    </span>
  );
}

function Hosts({ engId, version }: { engId: number; version: number }) {
  const [rows, setRows] = useState<ObservationRow[]>([]);
  const [q, setQ] = useState("");
  const [liveOnly, setLiveOnly] = useState(false);
  useEffect(() => { api.observations(engId).then(setRows).catch(() => {}); }, [engId, version]);
  const shown = rows.filter((r) => (!liveOnly || r.live) && (!q || r.host.includes(q.trim().toLowerCase())));
  return (
    <div>
      <div className="ep-filters">
        <input aria-label="Filter hosts" placeholder="Filter by host name" value={q} onChange={(e) => setQ(e.target.value)} />
        <label className="check">
          <input type="checkbox" checked={liveOnly} onChange={(e) => setLiveOnly(e.target.checked)} />
          Live web servers only
        </label>
        <span className="muted">{plural(shown.length, "host")}</span>
      </div>
      {shown.length === 0 ? (
        <p className="muted">{rows.length ? "No host matches the filter." : "Find subdomains to fill this list."}</p>
      ) : (
        <div className="sheet">
          <table className="obs">
            <thead>
              <tr>
                <th scope="col">Host</th>
                <th scope="col">Addresses</th>
                <th scope="col">CNAME</th>
                <th scope="col">Web</th>
                <th scope="col">Title</th>
                <th scope="col">Stack</th>
              </tr>
            </thead>
            <tbody>
              {shown.slice(0, 500).map((r) => (
                <tr key={r.host}>
                  <th scope="row">{r.url ? <a href={r.url} target="_blank" rel="noreferrer noopener">{r.host}</a> : r.host}</th>
                  <td className="clip" title={(r.a ?? []).join(", ")}>{(r.a ?? []).slice(0, 2).join(", ") || <span className="muted">–</span>}</td>
                  <td className="clip" title={(r.cname ?? []).join(", ")}>{(r.cname ?? [])[0] ?? <span className="muted">–</span>}</td>
                  <td>{r.status_code ? <span className={`code c${String(r.status_code)[0]}`}>{r.status_code}</span> : <span className="muted">–</span>}</td>
                  <td className="clip" title={r.title}>{r.title ?? ""}</td>
                  <td>{(r.tech ?? []).slice(0, 3).map((t) => <span key={t} className="tag">{t}</span>)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {shown.length > 500 && <p className="muted">Showing the first 500 of {shown.length}. Filter to narrow down.</p>}
        </div>
      )}
    </div>
  );
}

function GoldenTargets({ report }: { report: TriageReport }) {
  const golden = report.hosts.filter((h) => h.golden).length;
  return (
    <div role="tabpanel" className="tabpanel">
      <div className="tabpanel-head">
        <span className="muted">
          {golden} of {plural(report.hosts.length, "live host")} {golden === 1 ? "scores" : "score"} {report.golden_min_score} or more
        </span>
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
    </div>
  );
}

const LEAD_KIND: Record<string, string> = { secret: "Secret candidate", graphql: "GraphQL operation", sourcemap: "Sourcemap", nuclei: "Scanner finding", parameter: "Hidden parameters", "param-class": "Parameter pattern", dork: "Manual check" };

function Leads({ engId, version, module, terms }: { engId: number; version: number; module?: string; terms: Terms }) {
  const [rows, setRows] = useState<Lead[]>([]);
  const [open, setOpen] = useState<number | null>(null);
  useEffect(() => { api.leads(engId, module).then(setRows).catch(() => {}); }, [engId, version, module]);
  const real = rows.filter((l) => l.kind === "secret" && l.bucket === "real").length;

  return (
    <div role="tabpanel" className="tabpanel">
      <div className="tabpanel-head">
        <span className="muted">
          {plural(rows.length, "lead")}{real ? `, ${plural(real, "secret candidate")} to review` : ""}
        </span>
      </div>
      {rows.length === 0 ? (
        <p className="muted">Analyse JavaScript to collect leads. They are what the hunt lanes start from.</p>
      ) : (
        <>
          <p className="disclaimer">
            Secret candidates are shown masked and have not been tested. Do not use them. Confirm the owner, {terms.leadsCheck},
            and report.
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
    </div>
  );
}

function Endpoints({ engId, version, module }: { engId: number; version: number; module?: string }) {
  const [rows, setRows] = useState<EndpointRow[]>([]);
  const [total, setTotal] = useState(0);
  const [jsOnly, setJsOnly] = useState(false);
  const [q, setQ] = useState("");
  const [offset, setOffset] = useState(0);

  useEffect(() => {
    const t = setTimeout(() => {
      api.endpoints(engId, { js: jsOnly ? true : undefined, q: q.trim() || undefined, offset, module })
        .then((r) => { setRows(r.items); setTotal(r.total); })
        .catch(() => {});
    }, 200);
    return () => clearTimeout(t);
  }, [engId, jsOnly, q, offset, version, module]);

  return (
    <div role="tabpanel" className="tabpanel">
      <div className="tabpanel-head">
        <span className="muted">{plural(total, "URL")} in scope</span>
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
    </div>
  );
}

export function JobLog({ jobId, live }: { jobId: number; live: boolean }) {
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
      <pre tabIndex={0} aria-label={`Log of run ${jobId}`}>{job.log || "Waiting for the worker…"}</pre>
      {job.output_sha256 && <p className="muted">Output SHA-256 <code>{job.output_sha256}</code></p>}
    </div>
  );
}

function RulesOfEngagement({ engId, scope, mods, terms, onSaved }: {
  engId: number; scope: Scope; mods: ReconModule[]; terms: Terms; onSaved: (s: Scope, message?: string, fold?: boolean) => void;
}) {
  const [include, setInclude] = useState(scope.include.join("\n"));
  const [exclude, setExclude] = useState(scope.exclude.join("\n"));
  const [rps, setRps] = useState(scope.rate_limit_rps);
  const [header, setHeader] = useState(scope.research_header ?? "");
  const [ua, setUa] = useState(scope.research_user_agent ?? "");
  const [enabled, setEnabled] = useState<string[]>(scope.enabled_modules);
  const [depth, setDepth] = useState(scope.crawl_depth);
  const [redactOn, setRedactOn] = useState(scope.redact_evidence !== false);
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
      const added = s.hosts_added;
      if (redactOn !== (scope.redact_evidence !== false)) {
        const r = await api.updateEngagement(engId, { redact_evidence: redactOn });
        s = { ...s, redact_evidence: r.redact_evidence };
      }
      if (confirm) s = await api.attest(engId, operator, policy);
      setConfirm(false);
      const msg = `Rules saved.${addedText(added)}`;
      setSaved(msg);
      onSaved(s, msg, true);
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
            <textarea id="roe-include" rows={4} value={include} onChange={(e) => setInclude(e.target.value)} placeholder={"*.example.com\nexample.com"} />
            <span className="hint">One per line. *.example.com covers subdomains only, so list the apex separately.</span>
          </label>
          <label>
            Out of scope
            <textarea rows={4} value={exclude} onChange={(e) => setExclude(e.target.value)} placeholder="status.example.com" />
            <span className="hint">Exclusions always win.</span>
          </label>
          <label>
            Research header
            <input value={header} onChange={(e) => setHeader(e.target.value)} placeholder={terms.headerPlaceholder} />
            <span className="hint">Sent on every request to the target, exactly as {terms.asks}.</span>
          </label>
          <label>
            Research user agent
            <input value={ua} onChange={(e) => setUa(e.target.value)} placeholder="Mozilla/5.0 (compatible; your-handle)" />
            <span className="hint">Set this too if {terms.requires} it; otherwise tools send their own.</span>
          </label>
          <label className="narrow">
            Requests per second
            <input type="number" min={1} max={50} value={rps} onChange={(e) => setRps(Number(e.target.value))} />
            <span className="hint">A hard ceiling for every step that sends traffic, port scanning included. Use the limit in {terms.rulesBy}.</span>
          </label>
          <label className="narrow">
            Crawl depth
            <input type="number" min={1} max={5} value={depth} onChange={(e) => setDepth(Number(e.target.value))} />
          </label>
        </div>
        {mods.some((m) => m.opt_in) && (
          <fieldset className="optins">
            <legend>Modules {terms.allows}</legend>
            {mods.filter((m) => m.opt_in).map((m) => (
              <label key={m.kind} className="check optin-row">
                <input type="checkbox" checked={enabled.includes(m.kind)}
                       onChange={(e) => setEnabled(e.target.checked ? [...enabled, m.kind] : enabled.filter((k) => k !== m.kind))} />
                <span><strong>{m.title}</strong>{m.caution && <span className="hint"> {m.caution}</span>}</span>
              </label>
            ))}
          </fieldset>
        )}

        <fieldset className="optins">
          <legend>Evidence redaction</legend>
          <label className="check optin-row">
            <input type="checkbox" checked={redactOn} onChange={(e) => setRedactOn(e.target.checked)} />
            <span><strong>Redact sensitive values before evidence is stored</strong>
              <span className="hint"> Cookies, Authorization and API-key headers, tokens, keys and passwords in URLs
                and bodies, JWTs and private keys, and email addresses and card numbers in responses and files, are
                replaced by a marker such as [redacted:sha256:1a2b3c4d5e6f]. The same value always gets the same
                marker. Evidence can never be removed from the ledger, so keep this on for client work. Turn it off
                only for a lab: evidence is then stored as captured, and each entry says so. Other personal data
                (names, addresses, phone numbers) and binary files are not redacted.</span></span>
          </label>
        </fieldset>

        <ScopeImporter engId={engId} label={terms.scopeImport} onApplied={async (added) => {
          const s = await api.scope(engId);
          setInclude(s.include.join("\n"));
          setExclude(s.exclude.join("\n"));
          const msg = `Scope imported into the rules.${addedText(added)}`;
          setSaved(msg);
          onSaved(s, msg);
        }} />

        <fieldset className="attest">
          <legend>Authorization</legend>
          <div className="roe-grid">
            <label>
              {terms.policyLabel}
              <input value={policy} onChange={(e) => setPolicy(e.target.value)} placeholder={terms.policyPlaceholder} />
            </label>
            <label>
              Your name or handle
              <input id="roe-operator" value={operator} onChange={(e) => setOperator(e.target.value)} />
            </label>
          </div>
          <label className="check">
            <input type="checkbox" checked={confirm} onChange={(e) => setConfirm(e.target.checked)} />
            {terms.attest}
          </label>
        </fieldset>

        {error && <p className="field-error" role="alert">{error}</p>}
        {saved && <p className="saved" role="status">{saved}</p>}
        <button type="submit" className="btn">Save rules</button>
      </form>
    </section>
  );
}


function ScopeImporter({ engId, label, onApplied }: { engId: number; label: string; onApplied: (hostsAdded?: string[]) => void }) {
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
      const r = await api.importScope(engId, csv, true);
      setPreview(null);
      setCsv(null);
      onApplied(r.hosts_added);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <div className="importer">
      <label className="check">
        <span>{label}</span>
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
