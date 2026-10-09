import { useEffect, useState } from "react";
import { api } from "./api";
import { DEMO, demoUrl } from "./demo";
import { checkReport, ed25519Supported, tamperCheck, type Outcome, type ReceiptCheck, type ReportForVerify } from "./receipts";

const OUTCOME: Record<Outcome, { word: string; mark: string; cls: string }> = {
  pass: { word: "Signature verifies", mark: "✓", cls: "ok" },
  fail: { word: "Signature fails", mark: "✕", cls: "bad" },
  unsigned: { word: "Name only, not signed", mark: "—", cls: "plain" },
  unsupported: { word: "Not checked in this browser", mark: "?", cls: "plain" },
};

// Downloaded side by side (the demo and the site) the root is passed explicitly; in the repository
// tools/verify_report.py loads tools/tsa-roots/ by itself.
const COMMAND = DEMO ? "python3 verify_report.py report.json --tsa-root digicert-trusted-root-g4.pem"
                     : "python3 tools/verify_report.py report.json";

function tsaHost(url: string | null | undefined): string | null {
  if (!url) return null;
  try { return new URL(url).host; } catch { return url; }
}

function when(iso: string | null | undefined): string {
  if (!iso) return "unknown";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { timeZoneName: "short" });
}

/** A client's or auditor's check of the receipts: who signed, with which key, and whether it verifies. */
export function Verify({ engId }: { engId: number }) {
  const [report, setReport] = useState<ReportForVerify | null>(null);
  const [checks, setChecks] = useState<ReceiptCheck[] | null>(null);
  const [edOk, setEdOk] = useState<boolean | null>(null);
  const [selfTest, setSelfTest] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    setReport(null);
    setChecks(null);
    setSelfTest(null);
    setError(null);
    api.report<ReportForVerify>(engId).then(async (r) => {
      if (!live) return;
      setReport(r);
      if (!globalThis.crypto?.subtle) {
        setError("This page is not served over HTTPS, so the browser offers no WebCrypto to check signatures. "
                 + "Use the offline verifier below.");
        return;
      }
      const [cs, ed] = await Promise.all([checkReport(r), ed25519Supported()]);
      if (!live) return;
      setChecks(cs);
      setEdOk(ed);
      const first = cs.find((c) => c.outcome === "pass");
      if (first) tamperCheck(r, first).then((ok) => live && setSelfTest(ok)).catch(() => live && setSelfTest(false));
    }).catch((e) => live && setError((e as Error).message));
    return () => { live = false; };
  }, [engId]);

  // Same origin and no Content-Disposition, so the download is saved as report.json, the name the command uses.
  const json = DEMO ? demoUrl(`reports/${engId}.json`) : `/api/engagements/${engId}/report`;
  const signed = checks?.filter((c) => c.outcome !== "unsigned") ?? [];
  const passed = checks?.filter((c) => c.outcome === "pass").length ?? 0;
  const failed = checks?.filter((c) => c.outcome === "fail").length ?? 0;
  const voids = report?.lanes.filter((l) => l.status === "stale").length ?? 0;

  return (
    <div className="report verify">
      <section className="panel report-hero" aria-labelledby="verify-title">
        <div>
          <h3 id="verify-title" className="panel-title">Verify the receipts</h3>
          <p className="report-lede">
            Each receipted lane is signed by its reviewer with a key that only they hold. This page checks every
            signature in your browser against the public key carried in the report. It is a quick look: the offline
            verifier is the authoritative check.
          </p>
          {checks && (
            <p className={`status ${failed ? "bad" : "ok"}`} role="status">
              {checks.length === 0
                ? "No lane is receipted yet, so there is nothing to verify."
                : <>
                    {passed} of {signed.length} {signed.length === 1 ? "signature verifies" : "signatures verify"}
                    {failed > 0 && <>, {failed} {failed === 1 ? "fails" : "fail"}</>}
                    {checks.length > signed.length && <>; {checks.length - signed.length} of {checks.length} receipts carry a name only</>}.
                    {voids > 0 && <> {voids} {voids === 1 ? "receipt is" : "receipts are"} void and not counted.</>}
                  </>}
            </p>
          )}
          {edOk === false && (
            <p className="notice-inline">
              This browser cannot check Ed25519 signatures: its WebCrypto has no Ed25519. ECDSA P-256 signatures are
              still checked here; run the offline verifier for the rest.
            </p>
          )}
          {error && <p className="field-error" role="alert">{error}</p>}
          {!report && !error && <p className="muted">Loading the report…</p>}
        </div>
        <div className="report-actions">
          <a className="btn" href={json} download="report.json">Download report JSON</a>
          {DEMO && <a className="btn ghost" href="../verify_report.py" download>Download verify_report.py</a>}
          {DEMO && <a className="btn ghost" href="../digicert-trusted-root-g4.pem" download>Download DigiCert root</a>}
        </div>
      </section>

      {checks && checks.length > 0 && (
        <section className="panel" aria-labelledby="receipts-title">
          <h3 id="receipts-title" className="panel-title">Receipts</h3>
          <ul className="verify-list">
            {checks.map((c) => <ReceiptRow key={c.lane.lane_id} c={c} />)}
          </ul>
          {selfTest !== null && (
            <p className="hint">
              {selfTest
                ? "Self-test: a copy of a receipt with one changed signature byte, and one with another manifest, both fail here, as they should."
                : "Self-test failed: a tampered copy of a receipt did not fail. Do not rely on this page; use the offline verifier."}
            </p>
          )}
        </section>
      )}

      <section className="panel" aria-labelledby="offline-title">
        <h3 id="offline-title" className="panel-title">The authoritative check, offline</h3>
        <p className="muted">
          <code>verify_report.py</code> ({DEMO ? "download it above" : <>in the AttackLedger repository, <code>tools/verify_report.py</code>, with the
          DigiCert root in <code>tools/tsa-roots/</code></>}) needs only Python and no AttackLedger install. It rebuilds every receipt from
          its items and evidence, walks the evidence chain, recomputes the report body hash, checks each signature and
          checks each RFC 3161 timestamp token, including the timestamp authority's certificate chain up to the root
          you trust. {DEMO ? <>Save the report JSON as <code>report.json</code> next to the script and the root, and run:</>
                           : <>Save the report JSON as <code>report.json</code> in the repository folder and run:</>}
        </p>
        <pre className="cmd">{COMMAND}</pre>
        <p className="muted">
          Timestamp tokens, the key log and the change history are not checked in the browser. A signature proves the
          key holder signed; to tie a key to a person, compare its fingerprint with the one the signer gives you.
        </p>
      </section>
    </div>
  );
}

function ReceiptRow({ c }: { c: ReceiptCheck }) {
  const rc = c.lane.receipt!;
  const sig = rc.signature;
  const o = OUTCOME[c.outcome];
  const fp = c.fingerprint ?? sig?.key_fingerprint ?? null;
  return (
    <li className={`verify-item ${o.cls}`}>
      <div className="verify-head">
        <span className="verify-lane">
          <strong>{c.lane.host}</strong>
          <span className="muted"> · {c.lane.name}</span>
        </span>
        <span className={`verify-outcome ${o.cls}`}>
          <span aria-hidden="true">{o.mark}</span> {o.word}
        </span>
      </div>
      <dl className="facts verify-facts">
        <div>
          <dt>Signer</dt>
          <dd>
            {c.signer ?? rc.closed_by ?? "Unknown"}
            {(c.signerEmail ?? rc.closed_by_email) && <> ({c.signerEmail ?? rc.closed_by_email})</>}
            {!sig && " (a name, not a cryptographic signature)"}
          </dd>
        </div>
        {sig && <div><dt>Algorithm</dt><dd>{sig.algorithm}</dd></div>}
        {fp && <div><dt>Key fingerprint</dt><dd><code>{fp}</code></dd></div>}
        <div><dt>Manifest</dt><dd><code>{rc.manifest_sha256}</code></dd></div>
        <div><dt>Issued</dt><dd>{when(rc.issued_at)}</dd></div>
        <div>
          <dt>Timestamp</dt>
          <dd>
            {rc.timestamp
              ? <>Present: {when(rc.timestamp.time)}{tsaHost(rc.timestamp.tsa) && <> by {tsaHost(rc.timestamp.tsa)}</>}.
                  <span className="hint"> The token is checked by verify_report.py, not here.</span></>
              : <span className="muted">None</span>}
          </dd>
        </div>
      </dl>
      {c.problems.length > 0 && (
        <ul className={c.outcome === "fail" ? "verify-problems bad" : "verify-problems"}>
          {c.problems.map((p) => <li key={p}>{p}</li>)}
        </ul>
      )}
    </li>
  );
}
