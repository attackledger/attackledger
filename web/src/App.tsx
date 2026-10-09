import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError, Cell, Coverage, CoverageRow, EngagementSummary, Job, LaneContext, LaneDetail, LaneItem, Me,
         PackSummary, type EvidenceEntry } from "./api";
import { focusWhenReady, nextStep, SetupData, SetupGuide, SetupStep, setupComplete, setupSteps } from "./Setup";
import { AddHost } from "./AddHost";
import { plural } from "./words";
import { People, Team } from "./People";
import { Retention, deletedText } from "./Retention";
import { Account } from "./Account";
import { Executor } from "./Agent";
import { BulkNotApplicable, ItemWork, RedactionNote } from "./LaneWork";
import { DEMO, demoUrl } from "./demo";
import { ensureKey, localKey, sign, type LocalKey } from "./signing";
import { Controls } from "./Controls";
import { Recon } from "./Recon";
import { Report } from "./Report";
import { Verify } from "./Verify";
import { History } from "./History";
import { Import } from "./Import";
import { can, readOnly, rolesOn } from "./access";
import { ThemeToggle } from "./theme";

const TYPE_NAMES: Record<string, string> = {
  bug_bounty: "Bug bounty",
  pentest: "Pentest",
  internal: "Internal assessment",
};

type Tab = "recon" | "import" | "ledger" | "controls" | "report" | "verify" | "history" | "team";
const TAB_NAMES: Record<Tab, string> = {
  recon: "Recon", import: "Import", ledger: "Ledger", controls: "Controls", report: "Report", verify: "Verify", history: "History", team: "Team",
};

/** Who the caller is on an engagement, for the tab it opens on and the order of the tabs. */
type Home = "owner" | "worker" | "viewer" | "unknown";
function homeOf(me: Me | null, engId: number): Home {
  if (DEMO || !me) return "unknown";
  if (me.is_owner) return "owner";
  return readOnly(me, engId) ? "viewer" : "worker";
}

// Readers (clients, auditors) come for the report and its proof; the work tabs follow.
// Import has no demo data, so the demo leaves it out.
const VIEWER_TABS: Tab[] = ["report", "verify", "history", "ledger", "controls", "recon", ...(DEMO ? [] : ["import" as const])];
const WORK_TABS: Tab[] = ["recon", ...(DEMO ? [] : ["import" as const]), "ledger", "controls", "report", "verify", "history"];

type LoginMode = "token" | "people" | "setup";

export function App() {
  // Null while signed in. Signing out sets it in place, without reloading the page: a reload left a
  // moment in which what a person typed went to the page being replaced and was lost (and the form
  // could first show the token field until the server said how it signs in).
  const [login, setLogin] = useState<{ mode?: LoginMode; signedOut?: boolean } | null>(null);
  useEffect(() => {
    // Every refused request sends this; only the first one changes anything, so the form never remounts.
    const on = () => setLogin((l) => l ?? {});
    window.addEventListener("attackledger:auth-required", on);
    return () => window.removeEventListener("attackledger:auth-required", on);
  }, []);
  if (login) return <Login known={login.mode} signedOut={login.signedOut} onDone={() => window.location.reload()} />;
  return <Workspace onSignedOut={(mode) => setLogin({ mode, signedOut: true })} />;
}

function Login({ known, signedOut, onDone }: { known?: LoginMode; signedOut?: boolean; onDone: () => void }) {
  const [token, setToken] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mode, setMode] = useState<LoginMode | null>(known ?? null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (known) return;   // just signed out: the server's mode is already known
    api.health().then((h) => setMode(h.mode === "people" || h.mode === "setup" ? h.mode : "token"))
      .catch(() => setMode("token"));
  }, [known]);
  async function submit(ev: FormEvent) {
    ev.preventDefault();
    try {
      if (mode === "people") await api.loginPerson(email, password);
      else await api.login(token);
      onDone();
    } catch (e) {
      setError((e as Error).message);
    }
  }
  if (mode === null) {
    // No fields until the form is known, so nothing typed lands in a form that is then replaced.
    return (
      <main className="login">
        <div className="panel login-card">
          <div className="brand"><StampGlyph /><h1 className="wordmark">AttackLedger</h1></div>
          <p className="muted" role="status">Checking how this server signs people in…</p>
        </div>
      </main>
    );
  }
  if (mode === "setup") {
    // Production installs refuse everyone until the first owner exists (ATTACKLEDGER_REQUIRE_SIGN_IN).
    return (
      <main className="login">
        <div className="panel login-card">
          <div className="brand"><StampGlyph /><h1 className="wordmark">AttackLedger</h1></div>
          <p>Nobody can sign in yet.</p>
          <p className="muted">
            Whoever installed this server creates the first owner there, then signs in here:
          </p>
          <pre className="cmd" tabIndex={0} aria-label="Command">docker compose exec api python -m app.people create --owner --email you@example.com --name "Your Name"</pre>
          <button type="button" className="btn primary" onClick={() => window.location.reload()}>I have done this</button>
        </div>
      </main>
    );
  }
  if (mode === "people") {
    return (
      <main className="login">
        <form className="panel login-card" onSubmit={submit}>
          <div className="brand"><StampGlyph /><h1 className="wordmark">AttackLedger</h1></div>
          {signedOut && <p className="muted" role="status">You have signed out.</p>}
          <label className="sign-name">
            Email
            <input id="login-email" type="email" autoComplete="username" value={email}
                   onChange={(e) => setEmail(e.target.value)} autoFocus />
          </label>
          <label className="sign-name">
            Password
            <input id="login-password" type="password" autoComplete="current-password" value={password}
                   onChange={(e) => setPassword(e.target.value)} />
          </label>
          {error && <p className="field-error">{error}</p>}
          <button className="btn primary" disabled={!email || !password}>Sign in</button>
        </form>
      </main>
    );
  }
  return (
    <main className="login">
      <form className="panel login-card" onSubmit={submit}>
        <div className="brand"><StampGlyph /><h1 className="wordmark">AttackLedger</h1></div>
        {signedOut && <p className="muted" role="status">You have signed out.</p>}
        <p className="muted">This ledger requires the operator token.</p>
        <label className="sign-name">
          API token
          <input type="password" autoComplete="current-password" value={token} onChange={(e) => setToken(e.target.value)} autoFocus />
        </label>
        {error && <p className="field-error">{error}</p>}
        <button className="btn primary" disabled={!token}>Sign in</button>
      </form>
    </main>
  );
}

function Workspace({ onSignedOut }: { onSignedOut: (mode: LoginMode) => void }) {
  const [engagements, setEngagements] = useState<EngagementSummary[] | null>(null);
  const [current, setCurrent] = useState<number | null>(null);
  const [coverage, setCoverage] = useState<Coverage | null>(null);
  const [laneId, setLaneId] = useState<number | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("recon");
  const [me, setMe] = useState<Me | null>(null);
  const [meKnown, setMeKnown] = useState(DEMO);
  const [page, setPage] = useState<"work" | "people">("work");
  const [menuOpen, setMenuOpen] = useState(false);   // narrow screens: the engagement list folds away
  useEffect(() => {
    if (!DEMO) api.me().then(setMe).catch(() => {}).finally(() => setMeKnown(true));
  }, []);
  const owner = can(me, null, "team");   // People page and Team tab

  // The engagement whose opening tab is still to be chosen (by role, and for owners by setup).
  // Set only when a person opens an engagement, so a tab chosen on purpose is never overridden.
  const [chooseFor, setChooseFor] = useState<number | null>(null);
  const currentRef = useRef<number | null>(null);
  currentRef.current = current;
  const openEngagement = useCallback((id: number) => {
    setCurrent(id);
    setLaneId(null);
    setPage("work");
    setMenuOpen(false);
    setChooseFor(id);
  }, []);

  const loadEngagements = useCallback(async () => {
    try {
      const list = await api.engagements();
      setEngagements(list);
      if (currentRef.current == null && list[0]) {
        setCurrent(list[0].id);
        setChooseFor(list[0].id);
      }
    } catch (e) {
      setNotice(`Can't reach the ledger API. Start it with "docker compose up", then reload. (${(e as Error).message})`);
      setEngagements([]);
    }
  }, []);

  const [coverageFor, setCoverageFor] = useState<number | null>(null);
  const loadCoverage = useCallback(async () => {
    if (current == null) return setCoverage(null);
    const c = await api.coverage(current);
    setCoverage(c);
    setCoverageFor(current);
  }, [current]);

  useEffect(() => { loadEngagements(); }, [loadEngagements]);
  useEffect(() => { loadCoverage().catch((e) => setNotice(e.message)); }, [loadCoverage]);

  // Hosts were added (by hand, by saving scope rules, or by recon): the ledger and the sidebar's host counts both follow.
  const hostsChanged = useCallback(async () => {
    await Promise.all([loadCoverage().catch((e) => setNotice((e as Error).message)), loadEngagements()]);
  }, [loadCoverage, loadEngagements]);

  // The guided first run reads the engagement's scope and runs; it follows every change to the ledger.
  const [setup, setSetup] = useState<SetupData | null>(null);
  const setsUp = current != null && !DEMO && (can(me, current, "rules") || can(me, current, "work"));
  useEffect(() => {
    if (current == null || !setsUp || coverageFor !== current) return setSetup(null);
    let live = true;
    // The team step is for owners when people sign in: only they can read who holds which role.
    const team = me?.mode === "people" && can(me, current, "team")
      ? Promise.all([api.people(), api.members(current)])
          .then(([ps, ms]) => ({ others: ps.filter((p) => !p.disabled && !p.is_owner).length, members: ms }))
          .catch(() => null)
      : Promise.resolve(null);
    const type = engagements?.find((e) => e.id === current)?.engagement_type;
    Promise.all([api.scope(current), api.jobs(current), api.imports(current).catch(() => []), team])
      .then(([scope, jobs, imports, t]) => {
        if (live) setSetup({ engId: current, scope, jobs, imports: imports.length, team: t, engagementType: type });
      })
      .catch(() => {});
    return () => { live = false; };
  }, [current, coverage, coverageFor, setsUp, me, engagements]);
  const steps = useMemo(
    () => (setup && coverage && setup.engId === current && coverageFor === current ? setupSteps(setup, coverage) : null),
    [setup, coverage, current, coverageFor]);

  // Choose the opening tab once what it depends on is known.
  useEffect(() => {
    if (chooseFor == null || chooseFor !== current) return;
    if (!meKnown) return;
    const home = homeOf(me, chooseFor);
    if (home === "viewer") setTab("report");
    else if (home === "worker") setTab("ledger");
    else if (home === "owner") {
      if (!steps) return;   // wait for the setup state
      const next = nextStep(steps);
      if (next) setTab(next.tab);   // otherwise the tab stays as it was
    }
    setChooseFor(null);
  }, [chooseFor, current, me, meKnown, steps]);

  function goToStep(st: SetupStep) {
    setTab(st.tab);
    setLaneId(null);
    focusWhenReady(st.focus);
  }

  const home = current != null ? homeOf(me, current) : "unknown";
  const tabs: Tab[] = [...(home === "viewer" ? VIEWER_TABS : WORK_TABS), ...(owner ? ["team" as const] : [])];
  const currentName = engagements?.find((e) => e.id === current)?.name;
  const currentType = engagements?.find((e) => e.id === current)?.engagement_type;
  // With nothing to pick yet, the list is the only thing to show.
  const menuShown = menuOpen || !engagements || engagements.length === 0;

  async function openCell(assetId: number, role: string, cell: Cell) {
    setNotice(null);
    if (cell.lane_id) return setLaneId(cell.lane_id);
    try {
      const lane = await api.openLane(assetId, role);
      await loadCoverage();
      setLaneId(lane.id);
    } catch (e) {
      setNotice((e as Error).message);
    }
  }

  return (
    <div className="shell">
      <aside className={`index${menuShown ? "" : " folded"}`}>
        <div className="index-top">
          <div className="brand">
            <StampGlyph />
            <div>
              <h1 className="wordmark">AttackLedger</h1>
              <p className="tagline">Nothing counts as tested until it has a receipt.</p>
            </div>
          </div>
          <button type="button" className="btn ghost small menu-toggle" aria-expanded={menuShown}
                  aria-controls="index-panel" onClick={() => setMenuOpen(!menuShown)}>
            {menuShown ? "Hide engagements" : <>Engagements<span className="sr-only">, current: {currentName ?? "none"}</span></>}
          </button>
        </div>

        <div id="index-panel" className="index-panel">
        <nav aria-labelledby="eng-heading" className="index-nav">
          <h2 id="eng-heading" className="index-heading">Engagements</h2>
          {engagements && engagements.length > 0 && (
            <ul className="engagement-list">
              {engagements.map((e) => (
                <li key={e.id}>
                  <button
                    className="engagement"
                    aria-current={e.id === current ? "page" : undefined}
                    onClick={() => openEngagement(e.id)}
                  >
                    <span className="engagement-name">
                      {e.name}
                      <span className="engagement-type">{TYPE_NAMES[e.engagement_type] ?? e.engagement_type}</span>
                    </span>
                    <span className="count">{plural(e.assets, "host")}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
          {can(me, null, "create") && (
            <NewEngagement onCreated={async (id) => { await loadEngagements(); openEngagement(id); }} />
          )}
        </nav>

        <div className="index-foot">
          {me && me.mode !== "open" && (
            <div className="whoami">
              <span>Signed in as <strong>{me.name}</strong></span>
              <button className="link-button" onClick={async () => {
                try { await api.logout(); } catch (e) { return setNotice((e as Error).message); }
                onSignedOut(me.mode === "people" ? "people" : "token");
              }}>
                Sign out
              </button>
              <Account me={me} />
            </div>
          )}
          {owner && (
            <button className={`btn ghost small${page === "people" ? " on" : ""}`}
                    onClick={() => setPage(page === "people" ? "work" : "people")}>
              {page === "people" ? "Back to engagements" : "People"}
            </button>
          )}
          <ThemeToggle />
        </div>
        </div>
      </aside>

      <main className="ledger">
        {DEMO && (
          <p className="demo-banner">
            Read-only demo with fictional hosts. The recon data comes from a real run against a local lab; buttons that
            change or run something are switched off. <a href="../">About AttackLedger</a>
          </p>
        )}
        {DEMO && engagements && engagements.length > 0 && (
          <DemoGuide engagements={engagements} go={(engId, t, lane) => {
            setCurrent(engId);
            setTab(t);
            setLaneId(lane ?? null);
          }} />
        )}
        {notice && (
          <p className="notice" role="alert">
            {notice}
            <button className="link-button" onClick={() => setNotice(null)}>Dismiss</button>
          </p>
        )}
        {engagements && engagements.length === 0 && !notice && page === "work" && (
          <section className="empty">
            <h2>Start your first engagement</h2>
            <p>
              Name it after the client or the program you're testing, then add the hosts that are in scope.
              Each host gets a row and each role a column. A cell closes only when every checklist
              item has evidence or a written reason.
            </p>
          </section>
        )}
        {page === "people" && owner && <People mode={me?.mode ?? "open"} />}
        {coverage && current != null && page === "work" && (
          <>
            <header className="eng-head">
              <h2 className="eng-title">{coverage.engagement}</h2>
              <div className="tabs" role="tablist" aria-label="Engagement views">
                {tabs.map((t) => (
                  <button
                    key={t}
                    role="tab"
                    id={`tab-${t}`}
                    aria-selected={tab === t}
                    aria-controls={`panel-${t}`}
                    className="tab"
                    onClick={() => setTab(t)}
                  >
                    {TAB_NAMES[t]}
                    {t === "ledger" && (
                      <span className="tab-count">{coverage.closed_cells}/{coverage.total_cells}</span>
                    )}
                  </button>
                ))}
              </div>
            </header>
            {readOnly(me, current) && (
              <p className="readonly-note" role="note">
                You can read this engagement{rolesOn(me, current).length ? ` (${rolesOn(me, current).join(", ")})` : ""}:
                its coverage, evidence and reports, and verify its receipts. Changes are made by its testers, reviewers and owners.
              </p>
            )}
            {steps && !setupComplete(steps) && (tab === "recon" || tab === "ledger" || tab === "import" || tab === "team") && (
              <SetupGuide steps={steps} canDo={(who) => can(me, current, who)} onGo={goToStep} />
            )}
            <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
              {tab === "recon" && <Recon engId={current} onAssetsChanged={hostsChanged} canManage={can(me, current, "rules")}
                                         canRun={can(me, current, "work")} engagementType={currentType}
                                         hostsInScope={coverage.assets.filter((a) => a.in_scope).length} />}
              {tab === "ledger" && (
                <Matrix coverage={coverage} engId={current} onOpen={openCell} onAdded={hostsChanged}
                        canWork={can(me, current, "work")} />
              )}
              {tab === "import" && <Import engId={current} canWork={can(me, current, "work")} onMapped={() => { loadCoverage().catch(() => undefined); }} />}
              {tab === "controls" && <Controls engId={current} pack={coverage.pack.name} />}
              {tab === "report" && <Report engId={current} />}
              {tab === "verify" && <Verify engId={current} />}
              {tab === "history" && <History engId={current} />}
              {tab === "team" && owner && (
                <>
                  <Team engId={current} separation={!!coverage.separation_of_duties}
                        signatures={!!coverage.require_signatures} onChanged={hostsChanged} />
                  <Retention engId={current} onChanged={hostsChanged} />
                </>
              )}
            </div>
          </>
        )}
      </main>

      {laneId != null && (
        <Folio laneId={laneId} me={me} onClose={() => setLaneId(null)} onChanged={loadCoverage} />
      )}
    </div>
  );
}

function StampGlyph() {
  return (
    <svg className="glyph" viewBox="0 0 40 40" aria-hidden="true">
      <rect x="4" y="4" width="32" height="32" rx="4" fill="none" stroke="currentColor" strokeWidth="2.5" />
      <rect x="8" y="8" width="24" height="24" rx="2" fill="none" stroke="currentColor" strokeWidth="1.2" />
      <path d="M13 20.5l4.5 4.5L27 15" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/** Demo only: where to look, in order, with buttons that take you there. */
function DemoGuide({ engagements, go }: {
  engagements: EngagementSummary[]; go: (engId: number, tab: Tab, laneId?: number) => void;
}) {
  const [open, setOpen] = useState(() => {
    try { return localStorage.getItem("attackledger-demo-guide") !== "hidden"; } catch { return true; }
  });
  const [receipted, setReceipted] = useState<{ engId: number; laneId: number } | null>(null);
  const [agentLane, setAgentLane] = useState<{ engId: number; laneId: number } | null>(null);
  useEffect(() => {
    // The engagement with the most receipted lanes shows the ledger, the receipt and the report best.
    Promise.all(engagements.map((e) => api.coverage(e.id).then((c) => ({ e, c })))).then((rows) => {
      const best = rows.sort((a, b) => b.c.closed_cells - a.c.closed_cells)[0];
      const lane = best?.c.assets.flatMap((a) => Object.values(a.roles)).find((cell) => cell.status === "closed");
      if (best && lane?.lane_id) setReceipted({ engId: best.e.id, laneId: lane.lane_id });
      // A lane worked by the Claude agent, if the demo has one.
      const cells = rows.flatMap(({ e, c }) => c.assets.flatMap((a) => Object.values(a.roles))
        .filter((cell) => cell.lane_id).map((cell) => ({ engId: e.id, laneId: cell.lane_id as number })));
      Promise.all(cells.map((x) => api.lane(x.laneId).then((l) => ({ ...x, agent: l.executor === "agent" }))))
        .then((ls) => { const hit = ls.find((x) => x.agent); if (hit) setAgentLane({ engId: hit.engId, laneId: hit.laneId }); })
        .catch(() => {});
    }).catch(() => {});
  }, [engagements]);

  function toggle() {
    setOpen(!open);
    try { localStorage.setItem("attackledger-demo-guide", open ? "hidden" : "shown"); } catch { /* ignore */ }
  }

  const lab = engagements[0];
  const steps: { title: string; text: string; action?: () => void }[] = [
    { title: "Recon, step by step", action: () => go(lab.id, "recon"),
      text: `${lab.name} ran the full pipeline against a local lab. Each step lists its tools, its last run and what it found.` },
    { title: "Golden targets", action: () => { go(lab.id, "recon"); setTimeout(() => document.getElementById("results")?.scrollIntoView({ behavior: "smooth" }), 300); },
      text: "Every live host is scored from what it answers. The highest scores are where testing starts." },
    { title: "The coverage ledger", action: receipted ? () => go(receipted.engId, "ledger") : undefined,
      text: "One row per host, one column per lane. A cell is receipted only when every item has evidence or a reason; a change afterwards makes it void." },
    ...(agentLane ? [{ title: "A Claude agent run", action: () => go(agentLane.engId, "ledger", agentLane.laneId),
      text: "Claude worked a recon lane through the same gated tools: its requests, the evidence it attached, and what it left open for a person." }] : []),
    { title: "A receipted lane", action: receipted ? () => go(receipted.engId, "ledger", receipted.laneId) : undefined,
      text: "The checklist, the hash-chained evidence behind each item and the reviewer's signature." },
    { title: "The report", action: receipted ? () => go(receipted.engId, "report") : undefined,
      text: "Coverage mapped to controls, with everything needed to verify it offline using only Python." },
  ];

  return (
    <section className="demo-guide" aria-labelledby="demo-guide-title">
      <div className="demo-guide-head">
        <h2 id="demo-guide-title">Start here</h2>
        <button className="btn ghost small" aria-expanded={open} onClick={toggle}>{open ? "Hide" : "Show"}</button>
      </div>
      {open && (
        <ol>
          {steps.map((st) => (
            <li key={st.title}>
              <div>
                <h3>{st.title}</h3>
                <p>{st.text}</p>
              </div>
              {st.action && <button className="btn small" onClick={st.action}>Show me</button>}
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

/** The methodology a new engagement of this type starts with: the first pack written for the type. */
function packFor(packs: PackSummary[], type: string): string {
  return (packs.find((p) => p.engagement_types.includes(type)) ?? packs[0])?.id ?? "";
}

function NewEngagement({ onCreated }: { onCreated: (id: number) => void }) {
  const [name, setName] = useState("");
  const [packs, setPacks] = useState<PackSummary[]>([]);
  const [type, setType] = useState("pentest");   // the first users are pentest and audit teams (D-028)
  const [packId, setPackId] = useState("");
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    api.packs().then((ps) => { setPacks(ps); setPackId((cur) => cur || packFor(ps, "pentest")); }).catch(() => {});
  }, []);
  function chooseType(t: string) {
    setType(t);
    setPackId(packFor(packs, t));
  }
  async function submit(ev: FormEvent) {
    ev.preventDefault();
    if (!name.trim()) return;
    try {
      const { id } = await api.createEngagement(name.trim(), packId || packFor(packs, type), type);
      setName("");
      setError(null);
      onCreated(id);
    } catch (e) {
      setError((e as Error).message);
    }
  }
  return (
    <form className="inline-form" onSubmit={submit}>
      <label htmlFor="new-eng">New engagement</label>
      <div className="field-row">
        <input id="new-eng" value={name} onChange={(e) => setName(e.target.value)}
               placeholder={type === "bug_bounty" ? "Program name" : "Client or system name"} />
      </div>
      <label htmlFor="new-type" className="sub-label">Type</label>
      <div className="field-row">
        <select id="new-type" value={type} onChange={(e) => chooseType(e.target.value)}>
          {Object.entries(TYPE_NAMES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
      </div>
      <label htmlFor="new-pack" className="sub-label">Methodology</label>
      <div className="field-row">
        <select id="new-pack" value={packId} onChange={(e) => setPackId(e.target.value)}>
          {packs.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
        <button type="submit" className="btn">Create</button>
      </div>
      {error && <p className="field-error">{error}</p>}
    </form>
  );
}

function isGapRow(row: CoverageRow) {
  return row.in_scope && Object.values(row.roles).some((c) => c.status !== "closed");
}

function Matrix({ coverage, engId, onOpen, onAdded, canWork }: {
  coverage: Coverage;
  engId: number;
  onOpen: (assetId: number, role: string, cell: Cell) => void;
  onAdded: () => void;
  canWork: boolean;   // testers open lanes and add hosts
}) {
  const [gapsOnly, setGapsOnly] = useState(false);
  // Deleted content can never be reviewed again, so no lane here can get a new receipt.
  const deleted = coverage.content_deleted ?? null;
  const opens = canWork && !deleted;

  const rows = gapsOnly ? coverage.assets.filter(isGapRow) : coverage.assets;

  const totals = useMemo(() => {
    const inScopeRows = coverage.assets.filter((r) => r.in_scope);
    return coverage.roles.map((r) => ({
      role: r,
      closed: inScopeRows.filter((row) => row.roles[r].status === "closed").length,
      total: inScopeRows.length,
    }));
  }, [coverage]);

  const laneName = (k: string) => coverage.lanes.find((l) => l.key === k)?.name ?? k;
  const blockers = (row: CoverageRow, k: string) =>
    (coverage.lanes.find((l) => l.key === k)?.needs ?? []).filter((n) => row.roles[n]?.status !== "closed");

  const pct = coverage.total_cells ? Math.round((coverage.closed_cells / coverage.total_cells) * 100) : 0;

  return (
    <section aria-labelledby="ledger-title">
      <header className="ledger-head">
        <div>
          <h3 id="ledger-title" className="sr-only">Coverage ledger</h3>
          <p className="tally">
            {coverage.closed_cells} of {plural(coverage.total_cells, "in-scope cell")} receipted ({pct}%)
          </p>
        </div>
        <label className="switch">
          <input type="checkbox" checked={gapsOnly} onChange={(e) => setGapsOnly(e.target.checked)} />
          <span>Only hosts with gaps</span>
        </label>
      </header>

      {deleted && (
        <p className="notice-inline" role="note">
          {deletedText(deleted)} {LOCKED_TEXT} New lanes cannot be opened.
        </p>
      )}

      {coverage.assets.length === 0 ? (
        <p className="empty-row">{opens ? "Add a host below to open its row in the ledger." : "No hosts in this engagement yet."}</p>
      ) : (
        <div className="sheet" role="region" aria-label="Coverage table, hosts by lane" tabIndex={0}>
          <table style={{ minWidth: `${12 + coverage.roles.length * 7.5}rem` }}>
            <colgroup>
              <col style={{ width: "12rem" }} />
              {coverage.roles.map((r) => <col key={r} />)}
            </colgroup>
            <thead>
              <tr>
                <th scope="col" className="host-col">Host</th>
                {coverage.roles.map((r) => (
                  <th scope="col" key={r}>{laneName(r)}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 && (
                <tr>
                  <td className="all-clear" colSpan={coverage.roles.length + 1}>
                    Every in-scope host is fully receipted.
                  </td>
                </tr>
              )}
              {rows.map((row) => (
                <tr key={row.asset_id} className={row.in_scope ? undefined : "out-of-scope"}>
                  <th scope="row" className="host-col">
                    <span className="host-name" title={row.host}>{row.host}</span>
                    {!row.in_scope && <span className="scope-note">Out of scope</span>}
                  </th>
                  {coverage.roles.map((r) => (
                    <td key={r}>
                      <CellMark
                        cell={row.roles[r]}
                        disabled={!row.in_scope}
                        label={`${laneName(r)} on ${row.host}`}
                        lockedBy={blockers(row, r).map(laneName)}
                        canOpen={opens}
                        onClick={() => onOpen(row.asset_id, r, row.roles[r])}
                      />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
            <tfoot>
              <tr>
                <th scope="row" className="host-col">Totals</th>
                {totals.map((t) => (
                  <td key={t.role} className={t.closed === t.total && t.total > 0 ? "total done" : "total"}>
                    {t.closed}<span className="of">/{t.total}</span>
                  </td>
                ))}
              </tr>
            </tfoot>
          </table>
        </div>
      )}

      <Legend />

      {opens && <AddHost engId={engId} onAdded={onAdded} />}
    </section>
  );
}

function Legend() {
  return (
    <dl className="legend" aria-label="What the marks mean">
      <div><dt><span className="stamp mini"><span className="stamp-word">Receipted</span></span></dt><dd>Every item proven</dd></div>
      <div><dt><span className="stamp mini void"><span className="stamp-word">Void</span></span></dt><dd>Changed after its receipt</dd></div>
      <div><dt><span className="mark-open">In progress</span></dt><dd>Opened, not receipted; shows how many items are open</dd></div>
      <div><dt><span className="mark-unopened">Not opened</span></dt><dd>Not tested yet</dd></div>
      <div><dt><span className="mark-locked">Needs …</span></dt><dd>Receipt the lane it depends on first</dd></div>
    </dl>
  );
}

function CellMark({ cell, label, lockedBy, disabled, canOpen, onClick }: {
  cell: Cell; label: string; lockedBy: string[]; disabled: boolean; canOpen: boolean; onClick: () => void;
}) {
  // Table cells take their names from the row and column headers, so plain text, not aria-label on a span.
  if (disabled) return <span className="cell-blank"><span className="sr-only">Out of scope</span></span>;
  switch (cell.status) {
    case "closed":
      return (
        <button className="cell stamp" onClick={onClick} aria-label={`${label}: receipted ${cell.receipt}`}>
          <span className="stamp-word">Receipted</span>
          <span className="stamp-hash">{cell.receipt}</span>
        </button>
      );
    case "stale":
      return (
        <button className="cell stamp void" onClick={onClick} aria-label={`${label}: void, the receipt no longer matches the ledger`}>
          <span className="stamp-word">Void</span>
          <span className="stamp-hash">{cell.receipt}</span>
        </button>
      );
    case "open":
      return (
        <button className="cell open" onClick={onClick}
                aria-label={`${label}: in progress, ${plural(cell.unresolved ?? 0, "item")} open`}>
          <span className="cell-word">In progress</span>
          <span className="cell-sub">
            {cell.unresolved ? <><span className="open-count">{cell.unresolved}</span> open</> : "ready to sign"}
          </span>
        </button>
      );
    default:
      if (lockedBy.length)
        return (
          <span className="cell locked" title={`Receipt ${lockedBy.join(", ")} on this host first`}>
            Needs {lockedBy.length === 1 ? lockedBy[0].toLowerCase() : `${lockedBy.length} lanes`}
          </span>
        );
      if (!canOpen) return <span className="cell plain">Not opened</span>;
      return (
        <button className="cell unopened" onClick={onClick} aria-label={`${label}: not opened. Open this lane`}>
          <span className="cell-word">Not opened</span>
          <span className="cell-sub">Open lane</span>
        </button>
      );
  }
}

// Why nothing on a lane can change once its engagement's content is deleted (D-043).
const LOCKED_TEXT = "Nobody can review evidence that can no longer be read, so its lanes can never be receipted again.";

const ITEM_MARK: Record<string, string> = { done: "✓", na: "—", open: "○", evidence: "◐" };

interface Problem { idx: number; why: string }

const WAITING = "has evidence, not marked done";

/** Open items whose evidence is attached and that only wait to be marked done: the server's count
 *  when it sends one, otherwise counted from the lane. */
function waitingDone(lane: LaneDetail): number {
  if (typeof lane.waiting_done === "number") return lane.waiting_done;
  const withEvidence = new Set(lane.evidence.map((e) => e.item_idx));
  return lane.items.filter((i) => i.state === "open" && withEvidence.has(i.idx)).length;
}

/** "3 items still need evidence or a reason, and 2 have evidence waiting to be marked done." */
function progressText(needs: number, waiting: number): string {
  const need = needs > 0 ? `${plural(needs, "item")} still ${needs === 1 ? "needs" : "need"} evidence or a reason` : "";
  const wait = waiting > 0 ? `${needs > 0 ? "" : `${plural(waiting, "item")} `}${waiting === 1 ? "has" : "have"} evidence waiting to be marked done` : "";
  if (need && wait) return `${need}, and ${waiting} ${wait}.`;
  return `${need || wait}.`;
}

/** What still keeps a lane from closing, worked out from the lane as it is now (the server's gate, mirrored). */
function problemsOf(lane: LaneDetail): Problem[] {
  const withEvidence = new Set(lane.evidence.map((e) => e.item_idx).filter((x): x is number => x != null));
  const out: Problem[] = [];
  for (const i of lane.items) {
    if (i.state === "open") out.push({ idx: i.idx, why: withEvidence.has(i.idx) ? WAITING : "still open" });
    else if (i.state === "done" && !withEvidence.has(i.idx)) out.push({ idx: i.idx, why: "marked done without evidence" });
    else if (i.state === "na" && !(i.na_reason ?? "").trim()) out.push({ idx: i.idx, why: "not applicable without a reason" });
  }
  return out;
}

function itemCounts(lane: LaneDetail) {
  const ev = (i: LaneItem) => lane.evidence.some((e) => e.item_idx === i.idx);
  return {
    done: lane.items.filter((i) => i.state === "done").length,
    evidence: lane.items.filter((i) => i.state === "open" && ev(i)).length,
    na: lane.items.filter((i) => i.state === "na").length,
    open: lane.items.filter((i) => i.state === "open" && !ev(i)).length,
  };
}

function isAgent(e: EvidenceEntry): boolean {
  return e.source === "agent" || (e.summary ?? "").startsWith("[agent] ");
}

function goToItem(laneId: number, idx: number) {
  const el = document.getElementById(`lane-${laneId}-item-${idx}`);
  el?.scrollIntoView({ behavior: "smooth", block: "center" });
  el?.focus({ preventScroll: true });
}

function Folio({ laneId, me, onClose, onChanged }: {
  laneId: number; me: Me | null; onClose: () => void; onChanged: () => void;
}) {
  const [lane, setLane] = useState<LaneDetail | null>(null);
  const [ctx, setCtx] = useState<LaneContext | null>(null);
  const [runs, setRuns] = useState<Job[]>([]);
  const [raw, setRaw] = useState<{ title: string; text: string } | null>(null);   // demo: evidence bytes shown in place
  const [titles, setTitles] = useState<Record<string, string>>({});
  useEffect(() => {
    api.modules().then((ms) => setTitles(Object.fromEntries(ms.map((m) => [m.kind, m.title])))).catch(() => {});
  }, []);
  const [error, setError] = useState<string | null>(null);
  const [refused, setRefused] = useState(false);   // the last close was refused by the gate
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    setLane(null);
    setCtx(null);
    setError(null);
    setRefused(false);
    api.lane(laneId).then(setLane).catch((e) => setError(e.message));
    api.laneContext(laneId).then(setCtx).catch(() => {});
    api.lane(laneId)
      .then((l) => api.jobs(l.engagement_id))
      .then((js) => setRuns(js.filter((j) => (j.status === "done" || j.status === "partial") && j.output_sha256)))
      .catch(() => {});
  }, [laneId]);

  useEffect(() => {
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const [signer, setSigner] = useState(() => {
    try { return localStorage.getItem("attackledger-signer") ?? ""; } catch { return ""; }
  });
  const [reviewed, setReviewed] = useState(false);

  const [key, setKey] = useState<LocalKey | null>(null);
  // Whether signing here uses a key already registered to this person, or creates and registers one.
  const [keyReady, setKeyReady] = useState<boolean | null>(null);
  useEffect(() => {
    if (me?.kind !== "person" || !me.user_id) return;
    let live = true;
    Promise.all([localKey(me.user_id), api.keys().catch(() => null)]).then(([k, registered]) => {
      if (!live) return;
      const usable = !!k && !!registered?.some((r) => r.fingerprint === k.fingerprint && !r.revoked);
      setKey(usable ? k : null);
      setKeyReady(registered ? usable : null);
    });
    return () => { live = false; };
  }, [me]);

  async function close() {
    try {
      if (me?.kind === "person" && me.user_id) {
        // Sign in this browser: the private key never leaves it (D-027).
        const k = await ensureKey(me.user_id);
        setKey(k);
        setKeyReady(true);
        const { payload } = await api.receiptPayload(laneId, k.fingerprint);
        setLane(await api.closeLaneSigned(laneId, payload, await sign(k, payload), k.fingerprint));
        setReviewed(false);
        setError(null);
        setRefused(false);
        onChanged();
        return;
      }
      try { localStorage.setItem("attackledger-signer", signer.trim()); } catch { /* ignore */ }
      setLane(await api.closeLane(laneId, signer.trim(), reviewed));
      setReviewed(false);
      setError(null);
      setRefused(false);
      onChanged();
    } catch (e) {
      const d = e instanceof ApiError ? e.detail as { unresolved?: string[] } | null : null;
      if (d && Array.isArray(d.unresolved)) {
        // Shown from the lane itself below, so the list follows as items are resolved.
        setRefused(true);
        setError(null);
        api.lane(laneId).then(setLane).catch(() => {});
      } else {
        setError((e as Error).message);
      }
    }
  }

  const laneChanged = useCallback((l: LaneDetail) => {
    setLane(l);
    setError(null);
    onChanged();
  }, [onChanged]);

  const locked = lane?.content_deleted ?? null;   // deleted content: nothing here can be receipted again
  const canWork = !!lane && can(me, lane.engagement_id, "work") && !locked;
  const canSign = !!lane && can(me, lane.engagement_id, "sign");

  const counts = lane && itemCounts(lane);
  const problems = lane ? problemsOf(lane) : [];
  const waiting = lane ? waitingDone(lane) : 0;
  const needs = Math.max(0, problems.length - problems.filter((p) => p.why === WAITING).length);

  return (
    <>
      <div className="scrim" onClick={onClose} aria-hidden="true" />
      <div className="folio" role="dialog" aria-modal="true" aria-labelledby="folio-title">
        <div className="folio-head">
          <div>
            <h2 id="folio-title" className="folio-title">{lane ? lane.role_name : "Lane"}</h2>
            {lane && <p className="folio-host">{lane.host}</p>}
          </div>
          <button ref={closeRef} className="btn ghost" onClick={onClose}>Close</button>
        </div>

        {!lane ? (
          <p className="folio-body">{error ?? "Loading lane…"}</p>
        ) : (
          <div className="folio-body">
            <StatusLine lane={lane} needs={needs} waiting={waiting} />
            <p className="worked-by">
              Worked <strong>{lane.executor === "agent" ? "by a Claude agent" : "manually"}</strong>
              {ctx && (
                <span className="muted">
                  {" "}· recon for {ctx.host}: {ctx.recon.endpoints.length} endpoints, {ctx.recon.leads.length} leads,{" "}
                  {ctx.recon.observations.length} observations
                </span>
              )}
            </p>
            {counts && (
              <dl className="counts" aria-label={`Checklist, ${plural(lane.items.length, "item")}`}>
                <div className="c-done"><dt>Done</dt><dd>{counts.done}</dd></div>
                <div className="c-ev"><dt>Evidence attached, not marked done</dt><dd>{counts.evidence}</dd></div>
                <div className="c-na"><dt>Not applicable</dt><dd>{counts.na}</dd></div>
                <div className="c-open"><dt>Open, no evidence</dt><dd>{counts.open}</dd></div>
              </dl>
            )}

            <h3>Checklist</h3>
            {locked && (
              <p className="notice-inline" role="note">
                {deletedText(locked)} {LOCKED_TEXT} Items cannot be changed, and the lane cannot be signed.
              </p>
            )}
            {lane.executor === "manual" && canWork && lane.status !== "closed" && (
              <BulkNotApplicable lane={lane} onChanged={laneChanged} />
            )}
            <ol className="items">
              {lane.items.map((i) => {
                const ev = lane.evidence.filter((e) => e.item_idx === i.idx);
                const mark = i.state === "open" && ev.length ? "evidence" : i.state;
                return (
                  <li key={i.idx} id={`lane-${lane.id}-item-${i.idx}`} tabIndex={-1}
                      className={`item ${i.state}${mark === "evidence" ? " has-evidence" : ""}`}>
                    <span className="item-mark" aria-hidden="true">{ITEM_MARK[mark]}</span>
                    <span className="item-idx">{i.idx}</span>
                    <span className="item-text">
                      <span className="item-key">{i.key}</span>
                      {i.text}
                    </span>
                    <span className="item-state">
                      {i.state === "done" && (ev.length ? `Done, ${plural(ev.length, "evidence entry", "evidence entries")}`
                                                         : "Marked done, but no evidence is attached")}
                      {i.state === "na" && `Not applicable: ${i.na_reason}`}
                      {i.state === "open" && (ev.length
                        ? `Open: ${plural(ev.length, "evidence entry", "evidence entries")} attached, not marked done yet`
                        : "Open")}
                    </span>
                    {i.controls.length > 0 && (
                      <span className="item-controls">
                        {i.controls.map((c) => <span key={c} className="tag">{c}</span>)}
                      </span>
                    )}
                    {lane.executor === "manual" && canWork && (
                      <ItemWork lane={lane} item={i} runs={runs} titles={titles} onChanged={laneChanged} />
                    )}
                  </li>
                );
              })}
            </ol>

            <h3>Evidence</h3>
            {lane.content_deleted && (
              <p className="notice-inline" role="status">
                {deletedText(lane.content_deleted)} Its hashes, receipts and history remain, so reports still verify.
              </p>
            )}
            {lane.evidence.length === 0 ? (
              <p className="muted">No evidence recorded yet. Agents and the API add entries as they test.</p>
            ) : (
              <ul className="evidence">
                {lane.evidence.map((e) => (
                  <li key={e.id}>
                    <span className="ev-kind">{e.uri?.startsWith("job:") ? "Recon run" : e.kind.charAt(0).toUpperCase() + e.kind.slice(1)}</span>
                    <span className="ev-summary">
                      {e.summary ?? (
                        <span className="ev-deleted">
                          {e.content === "deleted" && lane.content_deleted ? deletedText(lane.content_deleted)
                            : "Content unavailable: the stored summary does not open."}
                        </span>
                      )}
                      {e.item_idx != null && <span className="ev-item">Item {e.item_idx}</span>}
                      <RedactionNote r={e.redaction} />
                    </span>
                    <span className="ev-ref">
                      <code className="ev-hash" title={e.sha256}>{e.sha256.slice(0, 10)}</code>
                      {!DEMO && !lane.content_deleted && (isAgent(e) || e.uri?.startsWith("file:") || (e.kind === "note" && !e.uri)) && (
                        <a href={`/api/blobs/${e.sha256}`} target="_blank" rel="noopener noreferrer">View raw</a>
                      )}
                      {DEMO && isAgent(e) && (
                        <button className="linklike" onClick={() => {
                          fetch(demoUrl(`blobs/${e.sha256}`)).then((r) => (r.ok ? r.text() : Promise.reject()))
                            .then((t) => setRaw({ title: e.summary ?? "", text: t }))
                            .catch(() => setError("The raw evidence is not in the demo data."));
                        }}>View raw</button>
                      )}
                    </span>
                  </li>
                ))}
              </ul>
            )}

            <Executor lane={lane} canWork={canWork} onLaneChanged={laneChanged} />
          </div>
        )}
        {raw && (
          <div className="raw-viewer" role="dialog" aria-modal="true" aria-label="Raw evidence">
            <div className="report-viewer-bar">
              <span>{raw.title}</span>
              <button className="btn ghost small" onClick={() => setRaw(null)}>Close</button>
            </div>
            <pre tabIndex={0} aria-label="Raw evidence bytes">{raw.text}</pre>
          </div>
        )}

        {lane && (
          <div className="folio-foot">
            {error && <p className="field-error" role="alert">{error}</p>}
            {refused && lane.status !== "closed" && (problems.length > 0 ? (
              <div className="refusal" role="alert">
                <p>
                  <strong>Not closed.</strong> {progressText(needs, waiting)} The list follows your changes.
                </p>
                <ul className="refusal-items">
                  {problems.map((pr) => (
                    <li key={pr.idx}>
                      <button className="linklike" onClick={() => goToItem(lane.id, pr.idx)}>Item {pr.idx}</button>{" "}
                      {pr.why}
                    </li>
                  ))}
                </ul>
              </div>
            ) : (
              <p className="saved" role="status">Every item now has evidence or a reason. Sign and close again.</p>
            ))}
            {lane.status === "closed" ? (
              <p className="muted">
                Receipt signed by {lane.receipt!.closed_by ?? "an unknown reviewer"}
                {lane.receipt!.closed_by_email && <> ({lane.receipt!.closed_by_email})</>},{" "}
                {new Date(lane.receipt!.created_at).toLocaleString()}
                {lane.receipt!.signed
                  ? <>, with key <code title={lane.receipt!.key_fingerprint ?? ""}>{(lane.receipt!.key_fingerprint ?? "").slice(0, 16)}</code> ({lane.receipt!.algorithm})</>
                  : " (a name, not a cryptographic signature)"}.
                {lane.receipt!.timestamp && (
                  <> Timestamped {new Date(lane.receipt!.timestamp.time).toLocaleString()}
                    {lane.receipt!.timestamp.tsa && <> by {tsaHost(lane.receipt!.timestamp.tsa)}</>}.</>
                )}
                {!lane.receipt!.timestamp && lane.receipt!.timestamp_error && (
                  <> Not timestamped: {lane.receipt!.timestamp_error}.{" "}
                    {canSign && (
                      <button className="linklike" onClick={async () => {
                        try { setLane(await api.timestampReceipt(laneId)); setError(null); onChanged(); }
                        catch (e) { setError((e as Error).message); }
                      }}>Timestamp now</button>
                    )}
                  </>
                )}
              </p>
            ) : locked ? (
              <p className="muted">{lane.status === "stale" ? "The receipt is void. " : "Not receipted. "}
                This lane cannot be signed: {LOCKED_TEXT.charAt(0).toLowerCase() + LOCKED_TEXT.slice(1)}</p>
            ) : !canSign ? (
              <p className="muted">
                {lane.status === "stale" ? "The receipt is void. " : "Not receipted yet. "}
                A reviewer on this engagement signs and closes the lane once every item has evidence or a reason.
              </p>
            ) : (
              <div className="sign">
                {me?.kind === "person" ? (
                  <>
                    <p className="muted">
                      You sign as <strong>{me.name}</strong>
                      {key ? <> with your key <code title={key.fingerprint}>{key.fingerprint.slice(0, 16)}</code> ({key.algorithm})</>
                           : keyReady === false ? " with a new key made in this browser; it never leaves it"
                           : ". A signing key is created in this browser the first time you sign; it never leaves it"}.
                    </p>
                    {keyReady === false && (
                      <p className="notice-inline" id={`new-key-${lane.id}`}>
                        This browser has no signing key for you yet. Signing will create one and register it; it will be
                        listed in the key log, and you'll see a notice at your next sign-in.
                      </p>
                    )}
                  </>
                ) : (
                  <label className="sign-name">
                    Your name, as it appears on the receipt
                    <input value={signer} onChange={(e) => setSigner(e.target.value)} placeholder="Full name" />
                  </label>
                )}
                <label className="check">
                  <input type="checkbox" checked={reviewed} onChange={(e) => setReviewed(e.target.checked)} />
                  I reviewed this lane's evidence. Only a person closes a lane.
                </label>
                <button className="btn primary" disabled={(me?.kind !== "person" && !signer.trim()) || !reviewed} onClick={close}
                        aria-describedby={keyReady === false ? `new-key-${lane.id}` : undefined}>
                  {keyReady === false ? "Create a key, sign and close lane" : "Sign and close lane"}
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </>
  );
}

function tsaHost(url: string): string {
  try { return new URL(url).host; } catch { return url; }
}

function StatusLine({ lane, needs, waiting }: { lane: LaneDetail; needs: number; waiting: number }) {
  if (lane.status === "closed" && lane.receipt)
    return (
      <p className="status ok">
        Receipted. Manifest <code>{lane.receipt.sha256.slice(0, 16)}</code>
      </p>
    );
  if (lane.status === "stale")
    return <p className="status bad">The ledger changed after the receipt was issued. Review the new entries and close again.</p>;
  if (needs === 0 && waiting === 0)
    return <p className="status ready">In progress. Every item has evidence or a reason; a reviewer can sign and close the lane.</p>;
  return <p className="status bad">In progress. {progressText(needs, waiting)}</p>;
}
