import { useEffect, useState } from "react";
import { api, type ContentDeleted, type ContentStatus } from "./api";
import { plural } from "./words";

// Retention and deleting an engagement's content (D-043). Owners only, on the Team tab. The
// content is encrypted with a key per engagement; deleting the key makes the raw evidence and
// the summaries unreadable, while hashes, receipts and the history stay, so reports still verify.

function day(iso: string): string {
  return iso.slice(0, 10);
}

/** "Deleted on 2026-10-09 by Olive Owner (owner@example.com)": one sentence for every view. */
export function deletedText(d: ContentDeleted): string {
  return `Content deleted on ${day(d.at)} by ${d.by}.`;
}

function today(): string {
  return new Date().toISOString().slice(0, 10);
}

export function Retention({ engId, onChanged }: { engId: number; onChanged: () => void }) {
  const [st, setSt] = useState<ContentStatus | null>(null);
  const [until, setUntil] = useState("");
  const [confirming, setConfirming] = useState(false);
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);

  useEffect(() => {
    setSt(null);
    setConfirming(false);
    setTyped("");
    setError(null);
    setSaved(null);
    api.contentStatus(engId).then((s) => {
      setSt(s);
      setUntil(s.retain_until ?? "");
    }).catch((e) => setError((e as Error).message));
  }, [engId]);

  async function saveDate(value: string | null) {
    setError(null);
    setSaved(null);
    try {
      const r = await api.updateEngagement(engId, { retain_until: value });
      setSt((s) => (s ? { ...s, retain_until: r.retain_until } : s));
      setUntil(r.retain_until ?? "");
      setSaved(r.retain_until ? `The content is kept until ${r.retain_until}, then deleted.` : "No retention date.");
      onChanged();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function remove() {
    if (!st) return;
    setBusy(true);
    setError(null);
    try {
      setSt(await api.deleteContent(engId, typed));
      setConfirming(false);
      onChanged();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (!st) {
    return (
      <section className="panel retention" aria-labelledby="retention-title">
        <h3 id="retention-title" className="panel-title">Data and retention</h3>
        <p className="muted">{error ?? "Loading…"}</p>
      </section>
    );
  }

  const deleted = st.content_deleted;
  return (
    <section className="panel retention" aria-labelledby="retention-title">
      <h3 id="retention-title" className="panel-title">Data and retention</h3>
      {deleted ? (
        <>
          <p className="notice-inline" role="status">{deletedText(deleted)}</p>
          <p className="muted">The key, the raw evidence, the evidence summaries and the recon results can no longer be
            read. Hashes, receipts, signatures, timestamps and the change history of its
            {" "}{plural(st.evidence_entries, "evidence entry", "evidence entries")} remain, so reports built now still verify.
            {st.v1_summaries > 0 && ` ${plural(st.v1_summaries, "summary", "summaries")} recorded before chain record v2
            ${st.v1_summaries === 1 ? "remains" : "remain"}, because the chain covers their text.`}</p>
        </>
      ) : (
        <>
          <p className="muted">Evidence is encrypted with a key for this engagement
            {st.encryption.master_key === "development" && " (under the public development master key: for a local trial only)"}.
            Deleting the key makes the raw evidence and the summaries unreadable. Hashes, receipts and the change history
            stay, so reports still verify.</p>
          <form className="work-form retention-date" onSubmit={(e) => { e.preventDefault(); void saveDate(until || null); }}>
            <label htmlFor={`retain-${engId}`}>Keep the content until (UTC)</label>
            <div className="retention-row">
              <input id={`retain-${engId}`} type="date" min={today()} value={until} onChange={(e) => setUntil(e.target.value)} />
              <button type="submit" className="btn small" disabled={(until || null) === st.retain_until}>Save date</button>
              {st.retain_until && (
                <button type="button" className="btn ghost small" onClick={() => void saveDate(null)}>Remove date</button>
              )}
            </div>
            <span className="hint">
              {st.retain_until
                ? `The worker deletes the content after ${st.retain_until}.`
                : "No date: the content is kept until an owner deletes it."}
            </span>
          </form>

          {!confirming ? (
            <button type="button" className="btn ghost small danger" onClick={() => { setConfirming(true); setTyped(""); }}>
              Delete this engagement's data
            </button>
          ) : (
            <div className="confirm danger-zone" role="group" aria-labelledby="delete-title">
              <p id="delete-title"><strong>Delete this engagement's data now? This cannot be undone.</strong></p>
              <p>Deleted: the engagement's key, its raw evidence,
                {" "}{plural(st.encrypted_summaries, "evidence summary", "evidence summaries")},
                {" "}{plural(st.observations, "recon observation")}, {plural(st.endpoints, "URL")},
                {" "}{plural(st.leads, "lead")} and the job logs. No new evidence or runs afterwards.</p>
              <p>Kept: hosts, lanes, items, hashes, receipts, signatures, timestamps and the change history
                {st.v1_summaries > 0 && `, and ${plural(st.v1_summaries, "summary", "summaries")} recorded before chain record v2`}.
                Reports built afterwards still verify.</p>
              <label htmlFor={`confirm-${engId}`}>Type the engagement's name, <strong>{st.engagement}</strong>, to confirm</label>
              <input id={`confirm-${engId}`} value={typed} autoComplete="off" onChange={(e) => setTyped(e.target.value)} />
              <div className="retention-row">
                <button type="button" className="btn small danger" disabled={busy || typed !== st.engagement}
                        onClick={() => void remove()}>Delete permanently</button>
                <button type="button" className="btn ghost small" onClick={() => setConfirming(false)}>Cancel</button>
              </div>
            </div>
          )}
        </>
      )}
      {error && <p className="field-error" role="alert">{error}</p>}
      {saved && <p className="saved" role="status">{saved}</p>}
    </section>
  );
}
