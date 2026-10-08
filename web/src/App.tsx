import { FormEvent, useCallback, useEffect, useState } from "react";
import { api, Cell, Coverage, EngagementSummary, LaneDetail } from "./api";

const ROLE_NAMES: Record<string, string> = {
  recon: "Recon",
  mapper: "Model",
  authz: "Access control",
  authflow: "Auth & sessions",
  logic: "Business logic",
  injection: "Input handling",
  mobile: "Mobile",
};

const NEEDS_MODEL = new Set(["authz", "authflow", "logic", "injection"]);

export function App() {
  const [engagements, setEngagements] = useState<EngagementSummary[] | null>(null);
  const [current, setCurrent] = useState<number | null>(null);
  const [coverage, setCoverage] = useState<Coverage | null>(null);
  const [laneId, setLaneId] = useState<number | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

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
        <h1 className="wordmark">AttackLedger</h1>
        <p className="tagline">Nothing counts as tested until it has a receipt.</p>
        <nav aria-label="Engagements">
          <h2 className="index-heading">Engagements</h2>
          <ul className="engagement-list">
            {engagements?.map((e) => (
              <li key={e.id}>
                <button
                  className="engagement"
                  aria-current={e.id === current ? "page" : undefined}
                  onClick={() => { setCurrent(e.id); setLaneId(null); }}
                >
                  <span>{e.name}</span>
                  <span className="count">{e.assets} {e.assets === 1 ? "host" : "hosts"}</span>
                </button>
              </li>
            ))}
          </ul>
          <NewEngagement onCreated={async (id) => { await loadEngagements(); setCurrent(id); }} />
        </nav>
      </aside>

      <main className="ledger">
        {notice && <p className="notice" role="alert">{notice}</p>}
        {engagements && engagements.length === 0 && !notice && (
          <section className="empty">
            <h2>Start your first engagement</h2>
            <p>
              Name it after the program you're testing, then add the hosts that are in scope.
              Each host gets a row; each role gets a column. A cell closes only when every checklist
              item has evidence or a written reason.
            </p>
          </section>
        )}
        {coverage && current != null && (
          <Matrix coverage={coverage} engId={current} onOpen={openCell} onAdded={loadCoverage} />
        )}
      </main>

      {laneId != null && (
        <Folio laneId={laneId} onClose={() => setLaneId(null)} onChanged={loadCoverage} />
      )}
    </div>
  );
}

function NewEngagement({ onCreated }: { onCreated: (id: number) => void }) {
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  async function submit(ev: FormEvent) {
    ev.preventDefault();
    if (!name.trim()) return;
    try {
      const { id } = await api.createEngagement(name.trim());
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
        <input id="new-eng" value={name} onChange={(e) => setName(e.target.value)} placeholder="Program name" />
        <button type="submit">Create</button>
      </div>
      {error && <p className="field-error">{error}</p>}
    </form>
  );
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

  return (
    <section aria-labelledby="ledger-title">
      <header className="ledger-head">
        <h2 id="ledger-title">{coverage.engagement}</h2>
        <p className="tally">
          <strong>{coverage.closed_cells}</strong> of {coverage.total_cells} in-scope cells receipted
        </p>
      </header>

      {coverage.assets.length === 0 ? (
        <p className="empty-row">Add a host below to open its row in the ledger.</p>
      ) : (
        <div className="sheet" role="region" aria-label="Coverage ledger" tabIndex={0}>
          <table>
            <thead>
              <tr>
                <th scope="col" className="host-col">Host</th>
                {coverage.roles.map((r) => (
                  <th scope="col" key={r}>{ROLE_NAMES[r] ?? r}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {coverage.assets.map((row) => (
                <tr key={row.asset_id} className={row.in_scope ? undefined : "out-of-scope"}>
                  <th scope="row" className="host-col">
                    {row.host}
                    {!row.in_scope && <span className="scope-note">out of scope</span>}
                  </th>
                  {coverage.roles.map((r) => (
                    <td key={r}>
                      <CellMark
                        cell={row.roles[r]}
                        disabled={!row.in_scope}
                        label={`${ROLE_NAMES[r]} on ${row.host}`}
                        locked={NEEDS_MODEL.has(r) && row.roles.mapper?.status !== "closed"}
                        onClick={() => onOpen(row.asset_id, r, row.roles[r])}
                      />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <form className="inline-form add-host" onSubmit={add}>
        <label htmlFor="new-host">Add a host</label>
        <div className="field-row">
          <input id="new-host" value={host} onChange={(e) => setHost(e.target.value)} placeholder="app.example.com" />
          <label className="check">
            <input type="checkbox" checked={inScope} onChange={(e) => setInScope(e.target.checked)} />
            In scope
          </label>
          <button type="submit">Add host</button>
        </div>
        {error && <p className="field-error">{error}</p>}
      </form>
    </section>
  );
}

function CellMark({ cell, label, locked, disabled, onClick }: {
  cell: Cell; label: string; locked: boolean; disabled: boolean; onClick: () => void;
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
      if (locked)
        return (
          <span className="cell locked" title="Receipt the Model lane on this host first">
            Needs model
          </span>
        );
      return (
        <button className="cell unopened" onClick={onClick} aria-label={`Open ${label}`}>
          Open
        </button>
      );
  }
}

function Folio({ laneId, onClose, onChanged }: { laneId: number; onClose: () => void; onChanged: () => void }) {
  const [lane, setLane] = useState<LaneDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLane(null);
    api.lane(laneId).then(setLane).catch((e) => setError(e.message));
  }, [laneId]);

  useEffect(() => {
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

  return (
    <aside className="folio" aria-label="Lane detail">
      <button className="folio-close" onClick={onClose} aria-label="Close lane detail">Close</button>
      {!lane ? (
        <p>{error ?? "Loading lane…"}</p>
      ) : (
        <>
          <h2 className="folio-title">{ROLE_NAMES[lane.role] ?? lane.role}</h2>
          <p className="folio-host">{lane.host}</p>
          <StatusLine lane={lane} />

          <h3>Checklist</h3>
          <ol className="items">
            {lane.items.map((i) => {
              const ev = lane.evidence.filter((e) => e.item_idx === i.idx);
              return (
                <li key={i.idx} className={`item ${i.state}`}>
                  <span className="item-text">{i.text}</span>
                  <span className="item-state">
                    {i.state === "done" && `${ev.length} evidence`}
                    {i.state === "na" && `N/A: ${i.na_reason}`}
                    {i.state === "open" && "open"}
                  </span>
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
                  <span className="ev-summary">{e.summary}</span>
                  <code className="ev-hash">{e.sha256.slice(0, 12)}</code>
                </li>
              ))}
            </ul>
          )}

          {error && <p className="field-error" role="alert">{error}</p>}
          {lane.status !== "closed" && (
            <button className="primary" onClick={close}>Close lane and issue receipt</button>
          )}
        </>
      )}
    </aside>
  );
}

function StatusLine({ lane }: { lane: LaneDetail }) {
  if (lane.status === "closed" && lane.receipt)
    return <p className="status ok">Receipted. Manifest {lane.receipt.sha256.slice(0, 16)}</p>;
  if (lane.status === "stale")
    return <p className="status bad">The ledger changed after the receipt was issued. Review and close again.</p>;
  const open = lane.items.filter((i) => i.state === "open").length;
  return <p className="status bad">{open} of {lane.items.length} items still open.</p>;
}
