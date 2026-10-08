import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, Cell, Coverage, CoverageRow, EngagementSummary, LaneDetail, PackSummary } from "./api";
import { Controls } from "./Controls";
import { Recon } from "./Recon";
import { ThemeToggle } from "./theme";

const TYPE_NAMES: Record<string, string> = {
  bug_bounty: "Bug bounty",
  pentest: "Pentest",
  internal: "Internal assessment",
};

type Tab = "recon" | "ledger" | "controls";
const TAB_NAMES: Record<Tab, string> = { recon: "Recon", ledger: "Ledger", controls: "Controls" };

export function App() {
  const [engagements, setEngagements] = useState<EngagementSummary[] | null>(null);
  const [current, setCurrent] = useState<number | null>(null);
  const [coverage, setCoverage] = useState<Coverage | null>(null);
  const [laneId, setLaneId] = useState<number | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("recon");

  const loadEngagements = useCallback(async () => {
    try {
      const list = await api.engagements();
      setEngagements(list);
      setCurrent((c) => c ?? list[0]?.id ?? null);
    } catch (e) {
      setNotice(`Can't reach the ledger API. Start it with "docker compose up", then reload. (${(e as Error).message})`);
      setEngagements([]);
    }
  }, []);

  const loadCoverage = useCallback(async () => {
    if (current == null) return setCoverage(null);
    setCoverage(await api.coverage(current));
  }, [current]);

  useEffect(() => { loadEngagements(); }, [loadEngagements]);
  useEffect(() => { loadCoverage().catch((e) => setNotice(e.message)); }, [loadCoverage]);

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
      <aside className="index">
        <div className="brand">
          <StampGlyph />
          <div>
            <h1 className="wordmark">AttackLedger</h1>
            <p className="tagline">Nothing counts as tested until it has a receipt.</p>
          </div>
        </div>

        <nav aria-labelledby="eng-heading" className="index-nav">
          <h2 id="eng-heading" className="index-heading">Engagements</h2>
          {engagements && engagements.length > 0 && (
            <ul className="engagement-list">
              {engagements.map((e) => (
                <li key={e.id}>
                  <button
                    className="engagement"
                    aria-current={e.id === current ? "page" : undefined}
                    onClick={() => { setCurrent(e.id); setLaneId(null); }}
                  >
                    <span className="engagement-name">
                      {e.name}
                      <span className="engagement-type">{TYPE_NAMES[e.engagement_type] ?? e.engagement_type}</span>
                    </span>
                    <span className="count">{e.assets} {e.assets === 1 ? "host" : "hosts"}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
          <NewEngagement onCreated={async (id) => { await loadEngagements(); setCurrent(id); }} />
        </nav>

        <div className="index-foot">
          <ThemeToggle />
        </div>
      </aside>

      <main className="ledger">
        {notice && (
          <p className="notice" role="alert">
            {notice}
            <button className="link-button" onClick={() => setNotice(null)}>Dismiss</button>
          </p>
        )}
        {engagements && engagements.length === 0 && !notice && (
          <section className="empty">
            <h2>Start your first engagement</h2>
            <p>
              Name it after the program you're testing, then add the hosts that are in scope.
              Each host gets a row and each role a column. A cell closes only when every checklist
              item has evidence or a written reason.
            </p>
          </section>
        )}
        {coverage && current != null && (
          <>
            <header className="eng-head">
              <h2 className="eng-title">{coverage.engagement}</h2>
              <div className="tabs" role="tablist" aria-label="Engagement views">
                {(["recon", "ledger", "controls"] as const).map((t) => (
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
            <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
              {tab === "recon" && <Recon engId={current} onAssetsChanged={loadCoverage} />}
              {tab === "ledger" && (
                <Matrix coverage={coverage} engId={current} onOpen={openCell} onAdded={loadCoverage} />
              )}
              {tab === "controls" && <Controls engId={current} pack={coverage.pack.name} />}
            </div>
          </>
        )}
      </main>

      {laneId != null && (
        <Folio laneId={laneId} onClose={() => setLaneId(null)} onChanged={loadCoverage} />
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

function NewEngagement({ onCreated }: { onCreated: (id: number) => void }) {
  const [name, setName] = useState("");
  const [packs, setPacks] = useState<PackSummary[]>([]);
  const [packId, setPackId] = useState("bug-bounty");
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { api.packs().then(setPacks).catch(() => {}); }, []);
  async function submit(ev: FormEvent) {
    ev.preventDefault();
    if (!name.trim()) return;
    try {
      const { id } = await api.createEngagement(name.trim(), packId);
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
        <input id="new-eng" value={name} onChange={(e) => setName(e.target.value)} placeholder="Program or client name" />
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

function Matrix({ coverage, engId, onOpen, onAdded }: {
  coverage: Coverage;
  engId: number;
  onOpen: (assetId: number, role: string, cell: Cell) => void;
  onAdded: () => void;
}) {
  const [host, setHost] = useState("");
  const [inScope, setInScope] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [gapsOnly, setGapsOnly] = useState(false);

  const rows = gapsOnly ? coverage.assets.filter(isGapRow) : coverage.assets;

  const totals = useMemo(() => {
    const inScopeRows = coverage.assets.filter((r) => r.in_scope);
    return coverage.roles.map((r) => ({
      role: r,
      closed: inScopeRows.filter((row) => row.roles[r].status === "closed").length,
      total: inScopeRows.length,
    }));
  }, [coverage]);

  async function add(ev: FormEvent) {
    ev.preventDefault();
    if (!host.trim()) return;
    try {
      await api.addAsset(engId, host.trim(), inScope);
      setHost("");
      setError(null);
      onAdded();
    } catch (e) {
      setError((e as Error).message);
    }
  }

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
            {coverage.closed_cells} of {coverage.total_cells} in-scope cells receipted ({pct}%)
          </p>
        </div>
        <label className="switch">
          <input type="checkbox" checked={gapsOnly} onChange={(e) => setGapsOnly(e.target.checked)} />
          <span>Only hosts with gaps</span>
        </label>
      </header>

      {coverage.assets.length === 0 ? (
        <p className="empty-row">Add a host below to open its row in the ledger.</p>
      ) : (
        <div className="sheet" role="region" aria-label="Coverage ledger" tabIndex={0}>
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

      <form className="inline-form add-host" onSubmit={add}>
        <label htmlFor="new-host">Add a host</label>
        <div className="field-row">
          <input id="new-host" value={host} onChange={(e) => setHost(e.target.value)} placeholder="app.example.com" />
          <label className="check">
            <input type="checkbox" checked={inScope} onChange={(e) => setInScope(e.target.checked)} />
            In scope
          </label>
          <button type="submit" className="btn">Add host</button>
        </div>
        {error && <p className="field-error">{error}</p>}
      </form>
    </section>
  );
}

function Legend() {
  return (
    <dl className="legend" aria-label="What the marks mean">
      <div><dt><span className="stamp mini"><span className="stamp-word">RECEIPTED</span></span></dt><dd>Every item proven</dd></div>
      <div><dt><span className="stamp mini void"><span className="stamp-word">VOID</span></span></dt><dd>Changed after its receipt</dd></div>
      <div><dt><span className="mark-open">3 open</span></dt><dd>In progress</dd></div>
      <div><dt><span className="mark-locked">Needs …</span></dt><dd>Receipt the lane it depends on first</dd></div>
    </dl>
  );
}

function CellMark({ cell, label, lockedBy, disabled, onClick }: {
  cell: Cell; label: string; lockedBy: string[]; disabled: boolean; onClick: () => void;
}) {
  if (disabled) return <span className="cell-blank" aria-label={`${label}: out of scope`} />;
  switch (cell.status) {
    case "closed":
      return (
        <button className="cell stamp" onClick={onClick} aria-label={`${label}: receipted ${cell.receipt}`}>
          <span className="stamp-word">RECEIPTED</span>
          <span className="stamp-hash">{cell.receipt}</span>
        </button>
      );
    case "stale":
      return (
        <button className="cell stamp void" onClick={onClick} aria-label={`${label}: receipt no longer matches the ledger`}>
          <span className="stamp-word">VOID</span>
          <span className="stamp-hash">{cell.receipt}</span>
        </button>
      );
    case "open":
      return (
        <button className="cell open" onClick={onClick} aria-label={`${label}: ${cell.unresolved} items open`}>
          <span className="open-count">{cell.unresolved}</span> open
        </button>
      );
    default:
      if (lockedBy.length)
        return (
          <span className="cell locked" title={`Receipt ${lockedBy.join(", ")} on this host first`}>
            Needs {lockedBy.length === 1 ? lockedBy[0].toLowerCase() : `${lockedBy.length} lanes`}
          </span>
        );
      return (
        <button className="cell unopened" onClick={onClick} aria-label={`Open ${label}`}>
          Open
        </button>
      );
  }
}

const ITEM_MARK: Record<string, string> = { done: "✓", na: "—", open: "○" };

function Folio({ laneId, onClose, onChanged }: { laneId: number; onClose: () => void; onChanged: () => void }) {
  const [lane, setLane] = useState<LaneDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    setLane(null);
    setError(null);
    api.lane(laneId).then(setLane).catch((e) => setError(e.message));
  }, [laneId]);

  useEffect(() => {
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  async function close() {
    try {
      setLane(await api.closeLane(laneId));
      setError(null);
      onChanged();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  const counts = lane && {
    done: lane.items.filter((i) => i.state === "done").length,
    na: lane.items.filter((i) => i.state === "na").length,
    open: lane.items.filter((i) => i.state === "open").length,
  };

  return (
    <>
      <div className="scrim" onClick={onClose} aria-hidden="true" />
      <aside className="folio" role="dialog" aria-modal="true" aria-labelledby="folio-title">
        <header className="folio-head">
          <div>
            <h2 id="folio-title" className="folio-title">{lane ? lane.role_name : "Lane"}</h2>
            {lane && <p className="folio-host">{lane.host}</p>}
          </div>
          <button ref={closeRef} className="btn ghost" onClick={onClose}>Close</button>
        </header>

        {!lane ? (
          <p className="folio-body">{error ?? "Loading lane…"}</p>
        ) : (
          <div className="folio-body">
            <StatusLine lane={lane} />
            {counts && (
              <p className="counts">
                <span className="c-done">{counts.done} with evidence</span>
                <span className="c-na">{counts.na} not applicable</span>
                <span className="c-open">{counts.open} open</span>
              </p>
            )}

            <h3>Checklist</h3>
            <ol className="items">
              {lane.items.map((i) => {
                const ev = lane.evidence.filter((e) => e.item_idx === i.idx);
                return (
                  <li key={i.idx} className={`item ${i.state}`}>
                    <span className="item-mark" aria-hidden="true">{ITEM_MARK[i.state]}</span>
                    <span className="item-idx">{i.idx}</span>
                    <span className="item-text">
                      <span className="item-key">{i.key}</span>
                      {i.text}
                    </span>
                    <span className="item-state">
                      {i.state === "done" && `${ev.length} evidence ${ev.length === 1 ? "entry" : "entries"}`}
                      {i.state === "na" && `Not applicable: ${i.na_reason}`}
                      {i.state === "open" && "Open"}
                    </span>
                    {i.controls.length > 0 && (
                      <span className="item-controls">
                        {i.controls.map((c) => <span key={c} className="tag">{c}</span>)}
                      </span>
                    )}
                  </li>
                );
              })}
            </ol>

            <h3>Evidence</h3>
            {lane.evidence.length === 0 ? (
              <p className="muted">No evidence recorded yet. Agents and the API add entries as they test.</p>
            ) : (
              <ul className="evidence">
                {lane.evidence.map((e) => (
                  <li key={e.id}>
                    <span className="ev-kind">{e.kind}</span>
                    <span className="ev-summary">
                      {e.summary}
                      {e.item_idx != null && <span className="ev-item">Item {e.item_idx}</span>}
                    </span>
                    <code className="ev-hash" title={e.sha256}>{e.sha256.slice(0, 10)}</code>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        {lane && (
          <footer className="folio-foot">
            {error && <p className="field-error" role="alert">{error}</p>}
            {lane.status === "closed" ? (
              <p className="muted">Receipt issued {new Date(lane.receipt!.created_at).toLocaleString()}</p>
            ) : (
              <button className="btn primary" onClick={close}>Close lane and issue receipt</button>
            )}
          </footer>
        )}
      </aside>
    </>
  );
}

function StatusLine({ lane }: { lane: LaneDetail }) {
  if (lane.status === "closed" && lane.receipt)
    return (
      <p className="status ok">
        Receipted. Manifest <code>{lane.receipt.sha256.slice(0, 16)}</code>
      </p>
    );
  if (lane.status === "stale")
    return <p className="status bad">The ledger changed after the receipt was issued. Review the new entries and close again.</p>;
  const open = lane.items.filter((i) => i.state === "open").length;
  return <p className="status bad">{open} of {lane.items.length} items still open.</p>;
}
