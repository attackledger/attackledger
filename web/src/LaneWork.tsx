import { FormEvent, useState } from "react";
import { api, type Job, type LaneDetail, type LaneItem, type Redaction } from "./api";
import { plural } from "./words";
import { getDraft, useDraft } from "./drafts";
import { localTime } from "./display";

type Mode = null | "evidence" | "na";
type Source = "note" | "file" | "run";

const MAX_FILE = 5_000_000;

function toBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result).split(",", 2)[1] ?? "");
    r.onerror = () => reject(new Error("The file could not be read."));
    r.readAsDataURL(file);
  });
}

/** What a person can do on one checklist item: attach evidence, mark it done or N/A, reopen it. */
export function ItemWork({ lane, item, runs, titles, onChanged }: {
  lane: LaneDetail; item: LaneItem; runs: Job[]; titles: Record<string, string>; onChanged: (l: LaneDetail) => void;
}) {
  // Unsent text is kept as a draft (drafts.ts): after an expired session, a reload or a shared link
  // the form opens again with it.
  const at = `${lane.id}:${item.idx}`;
  const [mode, setMode] = useState<Mode>(() => (getDraft(`note:${at}`) || getDraft(`summary:${at}`) ? "evidence"
    : getDraft(`na:${at}`) ? "na" : null));
  const [source, setSource] = useState<Source>(() => (getDraft(`summary:${at}`) && !getDraft(`note:${at}`) ? "file" : "note"));
  const [text, setText, clearText] = useDraft(`note:${at}`);
  const [file, setFile] = useState<File | null>(null);
  const [jobId, setJobId] = useState<number | "">("");
  const [summary, setSummary, clearSummary] = useDraft(`summary:${at}`);
  const [reason, setReason, clearReason] = useDraft(`na:${at}`);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // A change waiting for the person to accept that it voids the lane's receipt.
  const [pending, setPending] = useState<{ what: string; run: () => Promise<unknown> } | null>(null);

  const evidence = lane.evidence.filter((e) => e.item_idx === item.idx).length;
  const receipted = lane.status === "closed";
  const id = `item-${lane.id}-${item.idx}`;

  /** On a receipted lane any change voids the receipt the client sees, so it is asked first. */
  function guarded(what: string, run: () => Promise<unknown>) {
    setError(null);
    if (receipted) setPending({ what, run });
    else void run();
  }

  async function act(fn: () => Promise<LaneDetail>) {
    setBusy(true);
    setError(null);
    try {
      onChanged(await fn());
      return true;
    } catch (e) {
      setError((e as Error).message);
      return false;
    } finally {
      setBusy(false);
    }
  }

  function attach(ev: FormEvent) {
    ev.preventDefault();
    guarded("Attach evidence", doAttach);
  }

  async function doAttach() {
    const ok = await act(async () => {
      if (source === "note") return api.attach(lane.id, { item_idx: item.idx, kind: "note", text });
      if (source === "file") {
        if (!file) throw new Error("Choose a file to attach.");
        if (file.size > MAX_FILE) throw new Error("Files are limited to 5 MB.");
        return api.attach(lane.id, { item_idx: item.idx, kind: "file", filename: file.name,
                                     content_b64: await toBase64(file), summary });
      }
      if (jobId === "") throw new Error("Choose a recon run.");
      return api.attach(lane.id, { item_idx: item.idx, kind: "run", job_id: jobId, summary });
    });
    if (ok) {
      clearText(); setFile(null); setJobId(""); clearSummary(); setMode(null);
    }
  }

  function markNa(ev: FormEvent) {
    ev.preventDefault();
    guarded("Mark not applicable", doMarkNa);
  }

  async function doMarkNa() {
    if (await act(() => api.updateItem(lane.id, item.idx, "na", reason.trim()))) {
      clearReason(); setMode(null);
    }
  }

  return (
    <div className="item-work">
      <div className="item-actions">
        <button type="button" className="btn ghost small" aria-expanded={mode === "evidence"}
                onClick={() => setMode(mode === "evidence" ? null : "evidence")}>Add evidence</button>
        {item.state !== "done" && (
          <button type="button" className="btn ghost small" disabled={busy || evidence === 0}
                  title={evidence === 0 ? "Attach evidence to this item first" : undefined}
                  onClick={() => guarded("Mark done", () => act(() => api.updateItem(lane.id, item.idx, "done")))}>Mark done</button>
        )}
        {item.state !== "na" && (
          <button type="button" className="btn ghost small" aria-expanded={mode === "na"}
                  onClick={() => setMode(mode === "na" ? null : "na")}>Not applicable</button>
        )}
        {item.state !== "open" && (
          <button type="button" className="btn ghost small" disabled={busy}
                  onClick={() => guarded("Reopen", () => act(() => api.updateItem(lane.id, item.idx, "open")))}>Reopen</button>
        )}
      </div>
      {receipted && mode && !pending && (
        <p className="hint">This lane has a receipt. Any change voids it, so you will be asked before anything is saved.</p>
      )}
      {pending && (
        <div className="confirm void-confirm" role="group" aria-labelledby={`${id}-void`}>
          <p id={`${id}-void`}>
            <strong>This lane has a {lane.receipt?.signed ? "signed receipt" : "receipt"}.</strong> Changing an item voids
            it, and the client will see the receipt as void until a reviewer signs again.
          </p>
          <div className="work-buttons">
            <button type="button" className="btn small" disabled={busy} autoFocus
                    onClick={() => { const p = pending; setPending(null); void p.run(); }}>
              {pending.what} and void the receipt
            </button>
            <button type="button" className="btn ghost small" onClick={() => setPending(null)}>Keep the receipt</button>
          </div>
        </div>
      )}

      {mode === "evidence" && (
        <form className="work-form" onSubmit={attach}>
          <fieldset className="work-source">
            <legend>Evidence for item {item.idx}</legend>
            {(["note", "file", "run"] as const).map((s) => (
              <label key={s} className="check">
                <input type="radio" name={`${id}-source`} checked={source === s} onChange={() => setSource(s)} />
                {s === "note" ? "Note" : s === "file" ? "File" : "Recon run"}
              </label>
            ))}
          </fieldset>
          {source === "note" && (
            <label>
              What you tested and what you saw
              <textarea id={`${id}-note`} rows={3} value={text} onChange={(e) => setText(e.target.value)}
                        placeholder="GET /admin/ answers 401 with and without the session cookie." />
            </label>
          )}
          {source === "file" && (
            <label>
              File (screenshot, request and response export, tool output), up to 5 MB
              <input id={`${id}-file`} type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
            </label>
          )}
          {source === "run" && (
            <label>
              Recon run
              <select id={`${id}-run`} value={jobId} onChange={(e) => setJobId(e.target.value ? Number(e.target.value) : "")}>
                <option value="">Choose a finished run</option>
                {runs.map((j) => (
                  <option key={j.id} value={j.id}>
                    {titles[j.kind] ?? j.kind}, job {j.id}, {plural(j.result_count, "result")}, {localTime(j.created_at)}
                  </option>
                ))}
              </select>
              {runs.length === 0 && <span className="hint">No finished runs with recorded output yet.</span>}
            </label>
          )}
          {source !== "note" && (
            <label>
              What it shows, in a sentence
              <input id={`${id}-summary`} value={summary} onChange={(e) => setSummary(e.target.value)} />
            </label>
          )}
          <p className="hint">
            {source === "run"
              ? "The run's output hash goes into the chain."
              : "AttackLedger hashes it, keeps the bytes, and links the entry to the rest of the chain."}
          </p>
          <div className="work-buttons">
            <button type="submit" className="btn small" disabled={busy}>Attach evidence</button>
            <button type="button" className="btn ghost small" onClick={() => setMode(null)}>Cancel</button>
          </div>
        </form>
      )}

      {mode === "na" && (
        <form className="work-form" onSubmit={markNa}>
          <label>
            Why this does not apply to {lane.host}
            <input id={`${id}-reason`} value={reason} onChange={(e) => setReason(e.target.value)}
                   placeholder="The host has no login, so session tests do not apply." />
          </label>
          <div className="work-buttons">
            <button type="submit" className="btn small" disabled={busy || !reason.trim()}>Mark not applicable</button>
            <button type="button" className="btn ghost small" onClick={() => setMode(null)}>Cancel</button>
          </div>
        </form>
      )}
      {error && <p className="field-error" role="alert">{error}</p>}
    </div>
  );
}

function listIdx(idx: number[]): string {
  if (idx.length <= 1) return idx.join("");
  return `${idx.slice(0, -1).join(", ")} and ${idx[idx.length - 1]}`;
}

/** Mark every open item that has no evidence not applicable, with one reason. Each item goes through the
 *  same per-item request as marking it by hand, so the server checks every change. */
/** What was taken out of an evidence entry's stored bytes before they were hashed (D-038). */
export function RedactionNote({ r }: { r?: Redaction | null }) {
  if (!r || (r.redacted === 0 && r.not_redacted.length === 0)) return null;
  const off = r.not_redacted.some((w) => w.startsWith("redaction is off"));
  return (
    <span className={`ev-redaction${off || r.not_redacted.length ? " warn" : ""}`}>
      {r.redacted > 0 && `${plural(r.redacted, "value")} redacted before storage: ${r.kinds.join(", ")}`}
      {r.redacted > 0 && r.not_redacted.length > 0 && ". "}
      {off ? "Stored as captured: redaction is off for this engagement"
        : r.not_redacted.length > 0 && `Not redacted: ${r.not_redacted.join(", ")}`}
    </span>
  );
}

export function BulkNotApplicable({ lane, onChanged }: { lane: LaneDetail; onChanged: (l: LaneDetail) => void }) {
  const [step, setStep] = useState<"idle" | "reason" | "confirm">(() => (getDraft(`bulk-na:${lane.id}`) ? "reason" : "idle"));
  const [reason, setReason, clearReason] = useDraft(`bulk-na:${lane.id}`);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const withEvidence = new Set(lane.evidence.map((e) => e.item_idx).filter((x): x is number => x != null));
  const targets = lane.items.filter((i) => i.state === "open" && !withEvidence.has(i.idx)).map((i) => i.idx);
  const kept = lane.items.filter((i) => i.state === "open" && withEvidence.has(i.idx)).length;
  const id = `bulk-na-${lane.id}`;

  if (targets.length === 0 && step === "idle" && !progress && !error) return null;

  async function apply() {
    const list = [...targets];
    const why = reason.trim();
    setBusy(true);
    setError(null);
    setProgress(null);
    let last: LaneDetail | null = null;
    let n = 0;
    for (const idx of list) {
      try {
        last = await api.updateItem(lane.id, idx, "na", why);
        n += 1;
        setProgress(`Marked ${n} of ${list.length}…`);
      } catch (e) {
        setError(`Marked ${n} of ${plural(list.length, "item")}; stopped at item ${idx}: ${(e as Error).message}`);
        break;
      }
    }
    setBusy(false);
    if (last) onChanged(last);
    if (n === list.length) {
      setProgress(`Marked ${plural(n, "item")} not applicable.`);
      clearReason();
    } else {
      setProgress(null);
    }
    setStep("idle");
  }

  return (
    <div className="bulk-na">
      {step === "idle" && targets.length > 0 && (
        <button type="button" className="btn ghost small"
                onClick={() => { setStep("reason"); setProgress(null); setError(null); }}>
          Mark the {plural(targets.length, "open item")} not applicable…
        </button>
      )}
      {step !== "idle" && (
        <form className="work-form" onSubmit={(ev: FormEvent) => { ev.preventDefault(); if (reason.trim()) setStep("confirm"); }}>
          <label htmlFor={`${id}-reason`}>
            Why these items do not apply to {lane.host}
          </label>
          <input id={`${id}-reason`} value={reason} disabled={step === "confirm" || busy} autoFocus
                 onChange={(e) => setReason(e.target.value)}
                 placeholder="The host serves static files only: no login, no forms, no API." />
          <p className="hint">
            Applies to {targets.length === 1 ? "item" : "items"} {listIdx(targets)}: every open item without evidence.
            {kept > 0 && ` ${plural(kept, "open item")} with evidence attached ${kept === 1 ? "is" : "are"} left for you to mark done.`}
            {" "}Each gets the same reason, recorded on the item like a reason written by hand.
          </p>
          {step === "reason" ? (
            <div className="work-buttons">
              <button type="submit" className="btn small" disabled={!reason.trim()}>Review</button>
              <button type="button" className="btn ghost small" onClick={() => setStep("idle")}>Cancel</button>
            </div>
          ) : (
            <div className="confirm" role="group" aria-label="Confirm">
              <p>
                Mark {plural(targets.length, "item")} not applicable with this reason? A reviewer sees the reason on
                each item and in the report.
              </p>
              <div className="work-buttons">
                <button type="button" className="btn small" disabled={busy} onClick={apply} autoFocus>
                  {busy ? "Marking…" : `Mark ${plural(targets.length, "item")} not applicable`}
                </button>
                <button type="button" className="btn ghost small" disabled={busy} onClick={() => setStep("reason")}>Back</button>
              </div>
            </div>
          )}
        </form>
      )}
      {progress && <p className="saved" role="status">{progress}</p>}
      {error && <p className="field-error" role="alert">{error}</p>}
    </div>
  );
}
