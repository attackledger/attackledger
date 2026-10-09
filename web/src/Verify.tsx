import { useEffect, useState } from "react";
import { DEMO, demoUrl } from "./demo";
import { OfflineVerifier, VERIFY_PAGE } from "./OfflineVerifier";
import { Fingerprint, When } from "./display";
import { reportFilename } from "./Report";
import { cliText, decodeFile, ed25519Native, pageWording, selfTest, verifyReport, type CheckResult, type Outcome } from "./verify_report";

// The same module as the public verifier page (attackledger.com/verify): a port of
// tools/verify_report.py that makes every one of its checks, compared with it line for line by
// tools/verifier_equivalence/.

interface Lane {
  lane_id: number;
  host: string;
  name: string;
  status: string;
  receipt: {
    manifest_sha256: string;
    closed_by: string | null;
    closed_by_email?: string | null;
    issued_at?: string;
    signature?: { algorithm: string; key_fingerprint: string; payload: string } | null;
    timestamp?: { time: string; tsa?: string | null } | null;
  } | null;
}

const BADGE: Record<CheckResult["verdict"], { cls: string; label: string }> = {
  PASS: { cls: "ok", label: "Passed" }, FAIL: { cls: "bad", label: "Failed" }, SKIP: { cls: "plain", label: "Skipped" },
};


function tsaHost(url: string | null | undefined): string | null {
  if (!url) return null;
  try { return new URL(url).host; } catch { return url; }
}

function signerOf(lane: Lane): { name: string | null; email: string | null } {
  try {
    const p = JSON.parse(lane.receipt?.signature?.payload ?? "null") as { signer?: { name?: string; email?: string } } | null;
    if (p?.signer) return { name: p.signer.name ?? null, email: p.signer.email ?? null };
  } catch { /* the verifier reports an unreadable payload */ }
  return { name: lane.receipt?.closed_by ?? null, email: lane.receipt?.closed_by_email ?? null };
}

/** A client's or auditor's check of the report: every check verify_report.py makes, in the browser. */
export function Verify({ engId }: { engId: number }) {
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [lanes, setLanes] = useState<Lane[]>([]);
  const [edNative, setEdNative] = useState<boolean | null>(null);
  const [self, setSelf] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Same origin and no Content-Disposition, so the download takes the name given here: the name the server
  // gives a downloaded report (attackledger-<name>-<id>.json), which the offline command then uses as it is.
  const json = DEMO ? demoUrl(`reports/${engId}.json`) : `/api/engagements/${engId}/report`;
  const [file, setFile] = useState("report.json");

  useEffect(() => {
    let live = true;
    setOutcome(null);
    setSelf(null);
    setError(null);
    (async () => {
      if (!globalThis.crypto?.subtle) {
        throw new Error("This page is not served over HTTPS, so the browser offers no WebCrypto to check the report. "
                        + "Use the offline verifier below.");
      }
      // The report as served, byte for byte: its hashes are over the exact text.
      const res = await fetch(json);
      if (!res.ok) throw new Error(res.status === 403 ? "Your role on this engagement does not allow this." : `The report could not be loaded (${res.status}).`);
      const text = decodeFile(new Uint8Array(await res.arrayBuffer()));
      let name = "report.json";
      try {
        const eng = (JSON.parse(text) as { engagement?: { name?: string } }).engagement;
        if (typeof eng?.name === "string") name = reportFilename(eng.name, engId, "json");
      } catch { /* the verifier reports an unreadable report */ }
      const o = await verifyReport(text, name);
      if (!live) return;
      setFile(name);
      setOutcome(o);
      try {
        setLanes((JSON.parse(text) as { lanes: Lane[] }).lanes.filter((l) => l.receipt && l.status === "closed"));
      } catch {
        setLanes([]);
      }
      setEdNative(await ed25519Native());
      if (o.results.find((c) => c.name === "Receipt signatures")?.verdict === "PASS") {
        const ok = await selfTest(text, name).catch(() => false);
        if (live) setSelf(ok);
      }
    })().catch((e) => live && setError((e as Error).message));
    return () => { live = false; };
  }, [engId, json]);

  const failed = outcome?.results.filter((c) => c.verdict === "FAIL") ?? [];

  return (
    <div className="report verify">
      <section className="panel report-hero" aria-labelledby="verify-title">
        <div>
          <h3 id="verify-title" className="panel-title">Verify the report</h3>
          <p className="report-lede">
            This checks the report in your browser exactly as the offline verifier does: the body hash, the evidence
            chain, every receipt against its items and evidence, signatures, the key log, the change history and the
            timestamps, with the same verdicts. A client can run the same check without this app at{" "}
            <a href={VERIFY_PAGE} target="_blank" rel="noopener noreferrer">attackledger.com/verify</a>: download the
            report JSON and drop it there. Nothing is uploaded.
          </p>
          {outcome && (
            <p className={`status ${outcome.status === "verified" ? "ok" : "bad"}`} role="status">
              {outcome.status === "verified" ? "Verified: no check failed."
                : outcome.status === "failed" ? `Verification failed: ${failed.map((c) => c.name).join(", ")}.`
                : `The report could not be checked: ${outcome.message}`}
            </p>
          )}
          {error && <p className="field-error" role="alert">{error}</p>}
          {!outcome && !error && <p className="muted">Checking the report…</p>}
        </div>
        <div className="report-actions">
          <a className="btn" href={json} download={file}>Download report JSON</a>
        </div>
      </section>

      {outcome && outcome.results.length > 0 && (
        <section className="panel" aria-labelledby="checks-title">
          <h3 id="checks-title" className="panel-title">Checks</h3>
          <ul className="verify-list">
            {outcome.results.map((c) => {
              const notes = outcome.notes.filter((n) => n.check === c.name);
              return (
                <li key={c.name} className={`verify-item ${BADGE[c.verdict].cls}`}>
                  <div className="verify-head">
                    <strong>{c.name}</strong>
                    <span className={`verify-outcome ${BADGE[c.verdict].cls}`} aria-label={BADGE[c.verdict].label}>{c.verdict}</span>
                  </div>
                  {c.skip && <p className="hint">Skipped: {c.skip}. There was nothing for this check to check.</p>}
                  {c.problems.length > 0 && <ul className="verify-problems bad">{c.problems.map((p) => <li key={p}>{pageWording(p)}</li>)}</ul>}
                  {notes.length > 0 && <ul className="verify-problems">{notes.map((n) => <li key={n.text}>{n.text}</li>)}</ul>}
                </li>
              );
            })}
          </ul>
          {self !== null && (
            <p className="hint">
              {self
                ? "Self-test: a copy of this report with one changed signature byte fails the signature check here, as it should."
                : "Self-test failed: a tampered copy did not fail. Do not rely on this page; use the offline verifier."}
            </p>
          )}
          {edNative === false && (
            <p className="hint">This browser has no Ed25519 in WebCrypto, so Ed25519 signatures are checked with the verifier's own code.</p>
          )}
          <details className="verify-cli">
            <summary>The result as verify_report.py prints it</summary>
            <pre className="cmd" tabIndex={0} aria-label="Verifier output">{cliText(outcome)}</pre>
          </details>
        </section>
      )}

      {lanes.length > 0 && outcome && (
        <section className="panel" aria-labelledby="receipts-title">
          <h3 id="receipts-title" className="panel-title">Receipts</h3>
          <ul className="verify-list">
            {lanes.map((l) => <ReceiptRow key={l.lane_id} lane={l} outcome={outcome} />)}
          </ul>
        </section>
      )}

      <section className="panel" aria-labelledby="offline-title">
        <h3 id="offline-title" className="panel-title">The same check, offline</h3>
        <OfflineVerifier file={file} saved />
        <p className="muted">
          A signature proves the key holder signed; to tie a key to a person, compare its fingerprint with the one the
          signer gives you.
        </p>
      </section>
    </div>
  );
}

function ReceiptRow({ lane, outcome }: { lane: Lane; outcome: Outcome }) {
  const rc = lane.receipt!;
  const sig = rc.signature;
  const label = `${lane.host} / ${lane.name}: `;
  const mine = outcome.results.flatMap((c) => c.problems).filter((p) => p.startsWith(label)).map((p) => p.slice(label.length));
  const word = mine.length ? { cls: "bad", mark: "✕", text: "Fails a check" }
    : sig ? { cls: "ok", mark: "✓", text: "Signature verifies" } : { cls: "plain", mark: "—", text: "Name only, not signed" };
  const signer = signerOf(lane);
  return (
    <li className={`verify-item ${word.cls}`}>
      <div className="verify-head">
        <span className="verify-lane">
          <strong>{lane.host}</strong>
          <span className="muted"> · {lane.name}</span>
        </span>
        <span className={`verify-outcome ${word.cls}`}>
          <span aria-hidden="true">{word.mark}</span> {word.text}
        </span>
      </div>
      <dl className="facts verify-facts">
        <div>
          <dt>Signer</dt>
          <dd>
            {signer.name ?? "Unknown"}{signer.email && <> ({signer.email})</>}
            {!sig && " (a name, not a cryptographic signature)"}
          </dd>
        </div>
        {sig && <div><dt>Algorithm</dt><dd>{sig.algorithm}</dd></div>}
        {sig && <div><dt>Key fingerprint</dt><dd><Fingerprint fp={sig.key_fingerprint} full /></dd></div>}
        <div><dt>Manifest</dt><dd><code>{rc.manifest_sha256}</code></dd></div>
        <div><dt>Issued</dt><dd><When iso={rc.issued_at} /></dd></div>
        <div>
          <dt>Timestamp</dt>
          <dd>
            {rc.timestamp
              ? <><When iso={rc.timestamp.time} />{tsaHost(rc.timestamp.tsa) && <> by {tsaHost(rc.timestamp.tsa)}</>}</>
              : <span className="muted">None</span>}
          </dd>
        </div>
      </dl>
      {mine.length > 0 && <ul className="verify-problems bad">{mine.map((p) => <li key={p}>{pageWording(p)}</li>)}</ul>}
    </li>
  );
}
