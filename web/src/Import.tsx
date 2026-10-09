import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import {
  api, ApiError, type AlreadyImported, type ImportBatch, type ImportFormats, type InboxEntry, type InboxEntryDetail,
  type InboxFilter, type InboxPage, type MapTarget, type RefusedRow,
} from "./api";
import { DEMO, demoInboxRaw } from "./demo";
import { plural } from "./words";

// Evidence import (D-029). A tester uploads an export from Burp, Caido or a browser; its
// in-scope entries wait here, redacted, until a person maps each one to checklist items.
// Nothing reaches the ledger without that step. Reviewers and viewers can read the inbox and
// the files, dismissed entries included, to judge whether coverage is complete.

const STATES = [
  { key: "new", label: "To map" },
  { key: "mapped", label: "Mapped" },
  { key: "dismissed", label: "Dismissed" },
  { key: "", label: "All" },
] as const;

const STATUS = [
  { key: "", label: "Any status" }, { key: "2xx", label: "2xx" }, { key: "3xx", label: "3xx" },
  { key: "4xx", label: "4xx" }, { key: "5xx", label: "5xx" }, { key: "none", label: "No response" },
];

function when(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { timeZoneName: "short" });
}

function size(n: number): string {
  if (n < 1000) return `${n} B`;
  if (n < 1_000_000) return `${(n / 1000).toFixed(1)} kB`;
  return `${(n / 1_000_000).toFixed(1)} MB`;
}

function code(status: number | null) {
  if (status == null) return <span className="muted">none</span>;
  return <span className={`code c${String(status)[0]}`}>{status}</span>;
}

function BatchSummary({ b }: { b: ImportBatch }) {
  return (
    <>
      {plural(b.accepted, "entry", "entries")} added to the inbox, {b.out_of_scope} refused as out of scope,{" "}
      {plural(b.duplicates, "duplicate")} and {b.unreadable} unreadable, from {plural(b.rows, "row")}.
    </>
  );
}

function Refused({ rows, total }: { rows: RefusedRow[]; total: number }) {
  const groups = useMemo(() => {
    const out: { reason: string; host: string; rows: number[]; detail: string | null }[] = [];
    for (const r of rows) {
      const g = out.find((x) => x.reason === r.reason && x.host === (r.host ?? "") && x.detail === r.detail);
      if (g) g.rows.push(r.row);
      else out.push({ reason: r.reason, host: r.host ?? "", rows: [r.row], detail: r.detail });
    }
    return out;
  }, [rows]);
  if (!rows.length) return null;
  const label = { out_of_scope: "Out of scope", duplicate: "Already in the inbox", unreadable: "Unreadable" } as const;
  return (
    <details className="import-refused">
      <summary>Rows not imported ({total})</summary>
      <p className="hint">
        Out-of-scope rows are listed by row number and host only. Nothing else about them was stored.
      </p>
      <ul>
        {groups.map((g) => (
          <li key={`${g.reason}-${g.host}-${g.detail}`}>
            <strong>{label[g.reason as keyof typeof label] ?? g.reason}</strong>
            {g.host && <> · {g.host}</>}
            {g.detail && <> · {g.detail}</>}
            <span className="hint"> · {g.rows.length === 1 ? "row" : "rows"} {g.rows.slice(0, 30).join(", ")}
              {g.rows.length > 30 ? ` and ${g.rows.length - 30} more` : ""}</span>
          </li>
        ))}
      </ul>
      {total > rows.length && <p className="hint">The first {rows.length} are listed.</p>}
    </details>
  );
}

function Upload({ engId, formats, onDone }: {
  engId: number; formats: ImportFormats | null; onDone: (b: ImportBatch) => void;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [format, setFormat] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [repeat, setRepeat] = useState<AlreadyImported | null>(null);   // the same file was imported before
  const limit = formats?.limits.file_bytes ?? 50_000_000;

  async function send(form: HTMLFormElement, reimport: boolean) {
    if (!file) return setError("Choose a file to import.");
    if (file.size > limit) return setError(`Files are limited to ${size(limit)}. Export fewer items.`);
    setBusy(true);
    setError(null);
    setRepeat(null);
    try {
      onDone(await api.importFile(engId, file, format || null, reimport));
      setFile(null);
      form.reset();
    } catch (e) {
      const d = e instanceof ApiError ? (e.detail as AlreadyImported | null) : null;
      if (e instanceof ApiError && e.status === 409 && d?.error === "already_imported") setRepeat(d);
      else setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="work-form import-upload" aria-describedby="import-help"
          onSubmit={(ev) => { ev.preventDefault(); void send(ev.currentTarget, false); }}>
      <label>
        Export file
        <input type="file" accept=".har,.json,.xml"
               onChange={(e) => { setFile(e.target.files?.[0] ?? null); setRepeat(null); }} />
      </label>
      <label>
        Format
        <select value={format} onChange={(e) => setFormat(e.target.value)}>
          <option value="">Detect from the file</option>
          {formats?.formats.map((f) => <option key={f.id} value={f.id}>{f.title}</option>)}
        </select>
      </label>
      <p className="hint" id="import-help">
        {formats ? formats.formats.map((f) => `${f.title}: ${f.summary}`).join(" ") : ""} Up to {size(limit)} and{" "}
        {(formats?.limits.entries ?? 5000).toLocaleString()} entries per file. Rows for hosts outside the scope are
        refused and not stored; cookies, tokens, keys and passwords are redacted before anything is stored.
      </p>
      {error && <p className="field-error" role="alert">{error}</p>}
      {repeat && (
        <div className="field-error" role="alert">
          <p>
            This file was already imported on {when(repeat.earlier.created_at)} by {repeat.earlier.created_by_name}
            {repeat.earlier.filename ? ` (as ${repeat.earlier.filename})` : ""}. Importing it again adds nothing new:
            its rows already in the inbox count as duplicates.
          </p>
          <div className="work-buttons">
            <button type="button" className="btn ghost small" disabled={busy}
                    onClick={(ev) => { const f = ev.currentTarget.form; if (f) void send(f, true); }}>
              Import it again
            </button>
            <button type="button" className="btn ghost small" onClick={() => setRepeat(null)}>Keep the earlier import</button>
          </div>
        </div>
      )}
      <div className="work-buttons">
        <button type="submit" className="btn" disabled={busy || !file || !!repeat}>{busy ? "Importing…" : "Import"}</button>
      </div>
    </form>
  );
}

function EntryPanel({ engId, id, canWork, selectedSameHost, rules, onChanged, onClose }: {
  engId: number; id: number; canWork: boolean; selectedSameHost: number[];
  rules: ImportFormats["suggestion_rules"]; onChanged: () => void; onClose: () => void;
}) {
  const [e, setE] = useState<InboxEntryDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [chosen, setChosen] = useState<string[]>([]);       // "role:idx": one lane per role on a host
  const [extra, setExtra] = useState("");
  const [note, setNote] = useState("");
  const [also, setAlso] = useState(false);
  // Off by default: one imported exchange is often part of a test, and "done" says the test was
  // performed. The lane counts items that have evidence and still wait to be marked done.
  const [markDone, setMarkDone] = useState(false);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<string | null>(null);

  const load = useCallback(() => {
    api.inboxEntry(engId, id).then(setE).catch((x) => setError((x as Error).message));
  }, [engId, id]);
  useEffect(() => {
    setE(null); setChosen([]); setNote(""); setDone(null); setError(null); setAlso(false); setMarkDone(false);
    load();
  }, [load]);

  if (!e) return <section className="panel" aria-live="polite"><p className="muted">{error ?? "Loading the entry…"}</p></section>;

  const usable = e.targets.filter((t) => t.opened || t.can_open);
  const items = e.targets.flatMap((t) => t.items.map((i) => ({ ...i, role: t.role, opened: t.opened })));
  const split = (k: string) => { const at = k.lastIndexOf(":"); return { role: k.slice(0, at), idx: Number(k.slice(at + 1)) }; };
  const name = (k: string) => {
    const { role, idx } = split(k);
    const i = items.find((x) => x.role === role && x.idx === idx);
    return i ? `${i.key} ${i.text}${i.opened ? "" : " (opens the lane)"}` : k;
  };
  const roleOf = (laneId: number) => e.targets.find((t) => t.lane_id === laneId)?.role ?? String(laneId);
  const mapped = new Set(e.mappings.map((m) => `${roleOf(m.lane_id)}:${m.item_idx}`));
  const toggle = (k: string) => setChosen((c) => (c.includes(k) ? c.filter((x) => x !== k) : [...c, k]));
  const others = selectedSameHost.filter((x) => x !== e.id);
  const raw = (part: string) => DEMO ? demoInboxRaw(engId, e.id, part) : `/api/engagements/${engId}/inbox/${e.id}/raw/${part}`;

  async function run(fn: () => Promise<string>) {
    setBusy(true);
    setError(null);
    try {
      setDone(await fn());
      onChanged();
      load();
    } catch (x) {
      setError((x as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const map = (ev: FormEvent) => {
    ev.preventDefault();
    const targets: MapTarget[] = chosen.map((k) => {
      const { role, idx } = split(k);
      const lane = e.targets.find((t) => t.role === role)?.lane_id;
      return lane != null ? { lane_id: lane, item_idx: idx } : { role, item_idx: idx };   // by role: the lane opens
    });
    void run(async () => {
      const r = await api.mapEntries(engId, [e.id, ...(also ? others : [])], targets, note, markDone);
      setChosen([]);
      setNote("");
      const lanes = r.opened.filter((x) => x.startsWith("lane ")).length;
      const said = [
        r.evidence_added.length
          ? `Added ${plural(r.evidence_added.length, "evidence entry", "evidence entries")} to the ledger.`
          : "Already mapped to these items; nothing was added.",
        r.opened.some((x) => x.startsWith("host ")) ? `Added ${e.host} to the ledger.` : "",
        lanes ? `Opened ${plural(lanes, "lane")}.` : "",
        r.marked_done.length ? `Marked ${plural(r.marked_done.length, "item")} done.`
          : markDone ? "" : "The items stay open until someone marks them done.",
      ];
      return said.filter(Boolean).join(" ");
    });
  };

  return (
    <section className="panel import-entry" aria-labelledby="entry-title">
      <div className="panel-head">
        <h3 id="entry-title" className="panel-title">
          <span className="sr-only">Entry {e.id}: </span>{e.method} {code(e.status)}
        </h3>
        <button type="button" className="btn ghost small" onClick={onClose}>Close entry</button>
      </div>
      <p className="import-url">{e.url}</p>
      <dl className="import-facts">
        <div><dt>From</dt><dd>{e.format}, row {e.row}{e.tool_id ? `, id ${e.tool_id}` : ""}</dd></div>
        {e.tool_time && <div><dt>Recorded</dt><dd>{e.tool_time}</dd></div>}
        {e.label && <div><dt>Label</dt><dd>{e.label}</dd></div>}
        <div><dt>Stored</dt><dd>
          request {e.request_sha256 ? size(e.request_bytes) : "not in the export"}, response{" "}
          {e.response_sha256 ? size(e.response_bytes) : "not in the export"}
        </dd></div>
        {e.redaction && (
          <div><dt>Redacted</dt><dd>
            {e.redaction.redacted ? `${plural(e.redaction.redacted, "value")}: ${e.redaction.kinds.join(", ")}` : "nothing found"}
            {e.redaction.not_redacted.length > 0 && `; not redacted: ${e.redaction.not_redacted.join(", ")}`}
          </dd></div>
        )}
        {e.notes.length > 0 && <div><dt>Notes</dt><dd>{e.notes.join("; ")}</dd></div>}
      </dl>
      <p className="item-actions">
        {e.request_sha256 && <a className="btn ghost small" href={raw("request")} target="_blank" rel="noopener noreferrer">View request</a>}
        {e.response_sha256 && <a className="btn ghost small" href={raw("response")} target="_blank" rel="noopener noreferrer">View response</a>}
        <a className="btn ghost small" href={raw("record")} target="_blank" rel="noopener noreferrer">View record</a>
      </p>

      {e.mappings.length > 0 && (
        <>
          <h4 className="sub-label">In the ledger</h4>
          <ul className="import-mapped">
            {e.mappings.map((m) => (
              <li key={m.evidence_id}>{name(`${m.lane_id}:${m.item_idx}`)} <span className="hint">· by {m.by_name}, {when(m.at)}</span></li>
            ))}
          </ul>
        </>
      )}

      {e.state === "dismissed" && e.dismissed && (
        <div className="import-dismissed">
          <p>
            Dismissed by {e.dismissed.by_name ?? "someone"} on {when(e.dismissed.at)}
            {e.dismissed.reason ? `: ${e.dismissed.reason.replace(/[.!?]+$/, "")}` : ""}. The dismissal is in the change history.
          </p>
          {canWork && (
            <button type="button" className="btn ghost small" disabled={busy}
                    onClick={() => run(async () => { await api.restoreEntries(engId, [e.id]); return "Restored to the inbox."; })}>
              Restore
            </button>
          )}
        </div>
      )}

      {canWork && e.state !== "dismissed" && (
        usable.length === 0 ? (
          <p className="hint">
            No lane can be opened on {e.host}{e.targets[0]?.why_not ? `: ${e.targets[0].why_not}` : ""}.
          </p>
        ) : (
          <form className="work-form" onSubmit={map}>
            <fieldset className="import-pick">
              <legend>Map to checklist items</legend>
              {e.suggestions.length > 0 ? (
                <ul className="import-suggestions">
                  {e.suggestions.map((s) => {
                    const k = `${s.role}:${s.item_idx}`;
                    const sid = `sug-${e.id}-${k.replace(":", "-")}`;
                    return (
                      <li key={k}>
                        <label className="check">
                          <input type="checkbox" checked={chosen.includes(k)} disabled={mapped.has(k)}
                                 onChange={() => toggle(k)} aria-describedby={sid} />
                          <span>
                            <strong>{s.key}</strong> {s.text}{mapped.has(k) ? " (already mapped)" : ""}
                            {!s.opened && " (opens the lane)"}
                          </span>
                        </label>
                        <span className="hint import-why" id={sid}>Suggested: {s.why.join("; ")}.</span>
                      </li>
                    );
                  })}
                </ul>
              ) : <p className="hint">No suggestion for this entry. Choose items below.</p>}
              <label>
                Another item
                <select value={extra} onChange={(ev) => {
                  const k = ev.target.value;
                  if (k && !chosen.includes(k)) setChosen([...chosen, k]);
                  setExtra("");
                }}>
                  <option value="">Choose an item on {e.host}…</option>
                  {e.targets.map((t) => (
                    <optgroup key={t.role} disabled={!t.opened && !t.can_open}
                              label={t.opened ? t.name : t.can_open ? `${t.name} (opens the lane)` : `${t.name} (${t.why_not})`}>
                      {t.items.map((i) => {
                        const k = `${t.role}:${i.idx}`;
                        return <option key={k} value={k} disabled={mapped.has(k)}>{i.key} {i.text}</option>;
                      })}
                    </optgroup>
                  ))}
                </select>
              </label>
              {chosen.filter((k) => !e.suggestions.some((s) => `${s.role}:${s.item_idx}` === k)).length > 0 && (
                <ul className="import-chosen" aria-label="Other chosen items">
                  {chosen.filter((k) => !e.suggestions.some((s) => `${s.role}:${s.item_idx}` === k)).map((k) => (
                    <li key={k}>{name(k)} <button type="button" className="linklike" onClick={() => toggle(k)}>
                      Remove<span className="sr-only"> {name(k)}</span></button></li>
                  ))}
                </ul>
              )}
              {!e.asset && <p className="hint">{e.host} is in the scope rules but not in the ledger yet; mapping adds it.</p>}
            </fieldset>
            <label className="check">
              <input type="checkbox" checked={markDone} onChange={(ev) => setMarkDone(ev.target.checked)}
                     aria-describedby={`done-help-${e.id}`} />
              Mark these items done
            </label>
            <p className="hint" id={`done-help-${e.id}`}>
              Done means the item's test was performed. Leave this off if this request is only part of it; the lane shows
              the items that have evidence and are waiting to be marked done.
            </p>
            <label>
              Note (optional, goes into the evidence summary)
              <textarea rows={2} maxLength={2000} value={note} onChange={(ev) => setNote(ev.target.value)} />
            </label>
            {others.length > 0 && (
              <label className="check">
                <input type="checkbox" checked={also} onChange={(ev) => setAlso(ev.target.checked)} />
                Also map the {plural(others.length, "other selected entry", "other selected entries")} on {e.host}
              </label>
            )}
            <details className="import-rules">
              <summary>How suggestions are made</summary>
              <p className="hint">
                Each rule looks at one thing about the entry (a word in its path, a parameter name, the method, the
                status or a response header) and points at items on this host whose text uses one of its words. A word
                of the path that also appears in an item's text counts too. Suggestions are a starting point; you decide.
              </p>
              <ul className="hint">
                {rules.map((r) => <li key={r.id}>{r.title}: items that mention {r.words.join(", ")}</li>)}
              </ul>
            </details>
            <div className="work-buttons">
              <button type="submit" className="btn" disabled={busy || chosen.length === 0}>
                Add to the ledger{chosen.length ? ` (${plural(chosen.length, "item")})` : ""}
              </button>
            </div>
          </form>
        )
      )}
      {canWork && e.state === "new" && (
        <form className="inline-form import-dismiss" onSubmit={(ev) => {
          ev.preventDefault();
          void run(async () => { await api.dismissEntries(engId, [e.id], reason); setReason(""); return "Dismissed."; });
        }}>
          <label className="sr-only" htmlFor={`dismiss-${e.id}`}>Reason for dismissing</label>
          <input id={`dismiss-${e.id}`} placeholder="Reason for dismissing (optional)" value={reason} maxLength={500}
                 onChange={(ev) => setReason(ev.target.value)} />
          <button type="submit" className="btn ghost small" disabled={busy}>Dismiss</button>
        </form>
      )}
      {done && <p className="status ok" role="status">{done}</p>}
      {error && <p className="field-error" role="alert">{error}</p>}
    </section>
  );
}

export function Import({ engId, canWork, onMapped }: { engId: number; canWork: boolean; onMapped: () => void }) {
  const [formats, setFormats] = useState<ImportFormats | null>(null);
  const [batches, setBatches] = useState<ImportBatch[] | null>(null);
  const [last, setLast] = useState<ImportBatch | null>(null);
  const [filter, setFilter] = useState<InboxFilter>({ state: "new" });
  const [page, setPage] = useState<InboxPage | null>(null);
  const [selected, setSelected] = useState<number[]>([]);
  const [openId, setOpenId] = useState<number | null>(null);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { api.importFormats().then(setFormats).catch(() => undefined); }, []);
  const loadBatches = useCallback(() => {
    api.imports(engId).then(setBatches).catch((e) => setError((e as Error).message));
  }, [engId]);
  const loadPage = useCallback(() => {
    api.inbox(engId, filter).then(setPage).catch((e) => setError((e as Error).message));
  }, [engId, filter]);
  useEffect(() => { setLast(null); setOpenId(null); setSelected([]); loadBatches(); }, [loadBatches]);
  useEffect(() => { loadPage(); }, [loadPage]);

  const set = (patch: InboxFilter) => { setSelected([]); setFilter((f) => ({ ...f, offset: 0, ...patch })); };
  const entries = page?.entries ?? [];
  const byId = (id: number) => entries.find((x) => x.id === id);
  const openHost = openId != null ? byId(openId)?.host : undefined;
  const sameHost = selected.filter((id) => byId(id)?.host === openHost);
  const allShown = entries.length > 0 && entries.every((x) => selected.includes(x.id));

  async function dismissSelected(ev: FormEvent) {
    ev.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.dismissEntries(engId, selected, reason);
      setSelected([]);
      setReason("");
      loadPage();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="recon import">
      <section className="panel" aria-labelledby="import-title">
        <h3 id="import-title" className="panel-title">Import evidence</h3>
        <p className="report-lede">
          Bring in what you captured in Burp, Caido or a browser. Each in-scope request waits in the inbox below until a
          person maps it to checklist items; nothing reaches the ledger before that.
        </p>
        {canWork
          ? <Upload engId={engId} formats={formats} onDone={(b) => {
              setLast(b); loadBatches(); setOpenId(null); set({ state: "new", batch: b.id });
            }} />
          : <p className="hint">
              Testers import files and map their entries. You can read every entry, including the ones not mapped yet
              and the dismissed ones with their reasons, to judge whether coverage is complete.
            </p>}
        {last && (
          <div className="import-result" role="status">
            <p className="status ok">Imported {last.filename ?? "the file"} ({last.format_title}): <BatchSummary b={last} /></p>
            <Refused rows={last.refused} total={last.out_of_scope + last.duplicates + last.unreadable} />
          </div>
        )}
      </section>

      <section className="panel" aria-labelledby="inbox-title">
        <div className="panel-head">
          <h3 id="inbox-title" className="panel-title">Inbox</h3>
          {page && (
            <p className="hint">
              {plural(page.counts.new, "entry", "entries")} to map, {page.counts.mapped} mapped, {page.counts.dismissed} dismissed
            </p>
          )}
        </div>
        <div className="import-filters" role="group" aria-label="Filter the inbox">
          <label>Show
            <select value={filter.state ?? ""} onChange={(e) => set({ state: e.target.value })}>
              {STATES.map((s) => <option key={s.key} value={s.key}>{s.label}</option>)}
            </select>
          </label>
          <label>Host
            <select value={filter.host ?? ""} onChange={(e) => set({ host: e.target.value })}>
              <option value="">Every host</option>
              {page?.hosts.map((h) => <option key={h} value={h}>{h}</option>)}
            </select>
          </label>
          <label>Status
            <select value={filter.status ?? ""} onChange={(e) => set({ status: e.target.value })}>
              {STATUS.map((s) => <option key={s.key} value={s.key}>{s.label}</option>)}
            </select>
          </label>
          <label>File
            <select value={filter.batch ?? ""} onChange={(e) => set({ batch: e.target.value ? Number(e.target.value) : undefined })}>
              <option value="">Every file</option>
              {batches?.map((b) => <option key={b.id} value={b.id}>{b.filename ?? `import ${b.id}`} ({when(b.created_at)})</option>)}
            </select>
          </label>
          <label>URL contains
            <input type="search" value={filter.q ?? ""} onChange={(e) => set({ q: e.target.value })} />
          </label>
        </div>
        {error && <p className="field-error" role="alert">{error}</p>}
        {!page ? <p className="muted">Loading the inbox…</p> : entries.length === 0 ? (
          <p className="muted">
            {page.counts.new + page.counts.mapped + page.counts.dismissed === 0
              ? "Nothing imported yet."
              : "No entry matches these filters."}
          </p>
        ) : (
          <>
            <div className="history-wrap" role="region" aria-label="Inbox entries" tabIndex={0}>
              <table className="ctl import-table">
                <thead>
                  <tr>
                    {canWork && (
                      <th scope="col">
                        <input type="checkbox" aria-label="Select every entry shown" checked={allShown}
                               onChange={() => setSelected(allShown ? [] : entries.map((x) => x.id))} />
                      </th>
                    )}
                    <th scope="col">Request</th><th scope="col">Status</th><th scope="col">From</th><th scope="col">State</th>
                  </tr>
                </thead>
                <tbody>
                  {entries.map((x: InboxEntry) => (
                    <tr key={x.id} aria-current={openId === x.id ? "true" : undefined}>
                      {canWork && (
                        <td>
                          <input type="checkbox" aria-label={`Select ${x.method} ${x.url}`} checked={selected.includes(x.id)}
                                 onChange={() => setSelected((s) => (s.includes(x.id) ? s.filter((i) => i !== x.id) : [...s, x.id]))} />
                        </td>
                      )}
                      <td className="import-req">
                        <button type="button" className="linklike" onClick={() => setOpenId(x.id)}>
                          <span className="job-kind">{x.method}</span> {x.url}
                        </button>
                        {x.label && <span className="hint"> · {x.label}</span>}
                      </td>
                      <td>{code(x.status)}</td>
                      <td className="history-time">{x.format}, row {x.row}</td>
                      <td>
                        <span className={`chip ${x.state === "mapped" ? "done" : x.state === "dismissed" ? "skipped" : "queued"}`}>
                          {x.state === "new" ? "to map" : x.state}
                        </span>
                        {x.mappings.length > 0 && <span className="hint"> {x.mappings.map((m) => m.item_key).join(", ")}</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="import-pager">
              <span className="hint">
                {page.offset + 1}–{page.offset + entries.length} of {page.total}
              </span>
              <button type="button" className="btn ghost small" disabled={page.offset === 0}
                      onClick={() => setFilter((f) => ({ ...f, offset: Math.max(0, (f.offset ?? 0) - page.limit) }))}>Previous</button>
              <button type="button" className="btn ghost small" disabled={page.offset + entries.length >= page.total}
                      onClick={() => setFilter((f) => ({ ...f, offset: (f.offset ?? 0) + page.limit }))}>Next</button>
            </div>
            {canWork && selected.length > 0 && (
              <form className="inline-form import-dismiss" onSubmit={dismissSelected}>
                <span>{plural(selected.length, "entry", "entries")} selected.</span>
                <label className="sr-only" htmlFor="dismiss-selected">Reason for dismissing the selected entries</label>
                <input id="dismiss-selected" placeholder="Reason (optional)" value={reason} maxLength={500}
                       onChange={(e) => setReason(e.target.value)} />
                <button type="submit" className="btn ghost small" disabled={busy}>Dismiss selected</button>
              </form>
            )}
          </>
        )}
      </section>

      {openId != null && (
        <EntryPanel engId={engId} id={openId} canWork={canWork} selectedSameHost={sameHost}
                    rules={formats?.suggestion_rules ?? []} onClose={() => setOpenId(null)}
                    onChanged={() => { loadPage(); onMapped(); }} />
      )}

      <section className="panel" aria-labelledby="files-title">
        <h3 id="files-title" className="panel-title">Imported files</h3>
        {!batches ? <p className="muted">Loading…</p> : batches.length === 0 ? <p className="muted">No file imported yet.</p> : (
          <ul className="jobs">
            {batches.map((b) => (
              <li key={b.id} className="job">
                <div className="job-row">
                  <span className="job-kind">{b.filename ?? `Import ${b.id}`}</span>
                  <span>{b.format_title}{b.creator ? ` · ${b.creator}` : ""}</span>
                  <span className="job-time">{when(b.created_at)}</span>
                  <span>by {b.created_by_name}</span>
                  {b.repeat_of != null && <span className="hint">same file as import {b.repeat_of}</span>}
                </div>
                <p className="job-note"><BatchSummary b={b} /> <span className="hint">File SHA-256 {b.file_sha256.slice(0, 16)}…, {size(b.file_bytes)}.</span></p>
                <Refused rows={b.refused} total={b.out_of_scope + b.duplicates + b.unreadable} />
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
