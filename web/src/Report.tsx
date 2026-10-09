import { useEffect, useState } from "react";
import { api } from "./api";
import { DEMO, demoUrl } from "./demo";
import { plural } from "./words";

interface ReportSummary {
  generated_at: string;
  engagement: { name: string; authorized_by: string | null; authorized_at: string | null };
  summary: {
    hosts_in_scope: number;
    lanes_per_host: number;
    lanes_possible: number;
    lanes_opened: number;
    lanes_receipted: number;
    lanes_stale: number;
    evidence_entries: number;
    chain_head: string;
  };
  integrity: { body_sha256: string };
}

export function Report({ engId }: { engId: number }) {
  const [r, setR] = useState<ReportSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [printable, setPrintable] = useState<string | null>(null);   // demo: the report shown in place

  useEffect(() => {
    setR(null);
    api.report<ReportSummary>(engId)
      .then(setR)
      .catch((e) => setError(e.message));
  }, [engId]);

  if (!r) return <p className="muted">{error ?? "Building report…"}</p>;
  const s = r.summary;
  const base = `/api/engagements/${engId}`;
  // The demo ships each report as a static file next to the app.
  const links = DEMO
    ? { html: demoUrl(`reports/${engId}.html`), htmlDl: demoUrl(`reports/${engId}.html`), json: demoUrl(`reports/${engId}.json`) }
    : { html: `${base}/report.html`, htmlDl: `${base}/report.html?download=true`, json: `${base}/report?download=true` };

  return (
    <div className="report">
      {printable && (
        <div className="report-viewer" role="dialog" aria-modal="true" aria-label="Printable report">
          <div className="report-viewer-bar">
            <span>Printable report, as delivered</span>
            <button className="btn ghost small" onClick={() => setPrintable(null)}>Close</button>
          </div>
          {/* The report is a self-contained HTML file; shown inert, scripts off. */}
          <iframe title="Printable report" sandbox="" srcDoc={printable} />
        </div>
      )}
      <section className="panel report-hero">
        <div>
          <h3 className="panel-title">Coverage report</h3>
          <p className="report-lede">
            <strong>{s.lanes_receipted}</strong> of {plural(s.lanes_possible, "possible lane")}{" "}
            {s.lanes_receipted === 1 ? "is" : "are"} receipted across {plural(s.hosts_in_scope, "in-scope host")}.{" "}
            {plural(s.lanes_opened - s.lanes_receipted, "more is", "more are")} in progress or void, and{" "}
            {plural(s.lanes_possible - s.lanes_opened, "is", "are")} not opened, so{" "}
            {s.lanes_possible - s.lanes_opened === 1 ? "it counts" : "they count"} as untested.
          </p>
          {!r.engagement.authorized_at && (
            <p className="status bad">No authorization is recorded for this engagement. The report says so.</p>
          )}
        </div>
        <div className="report-actions">
          {DEMO ? (
            <button className="btn" onClick={() => {
              fetch(links.html).then((res) => res.text()).then(setPrintable).catch(() => setError("The report could not be loaded."));
            }}>Open printable report</button>
          ) : (
            <a className="btn" href={links.html} target="_blank" rel="noopener">Open printable report</a>
          )}
          <a className="btn ghost" href={links.htmlDl} download>Download HTML</a>
          <a className="btn ghost" href={links.json} download>Download JSON</a>
        </div>
      </section>

      <section className="panel">
        <h3 className="panel-title">What the report proves</h3>
        <dl className="facts">
          <div><dt>Evidence entries</dt><dd>{s.evidence_entries}, each linked to the one before it</dd></div>
          <div><dt>Chain head</dt><dd><code>{s.chain_head}</code></dd></div>
          <div><dt>Report body hash</dt><dd><code>{r.integrity.body_sha256}</code></dd></div>
          <div><dt>Void receipts</dt><dd>{s.lanes_stale}</dd></div>
        </dl>
        <p className="muted">
          Anyone can check a downloaded report without AttackLedger installed. The verifier rebuilds every receipt
          from its items and evidence, walks the evidence chain and recomputes the body hash:
        </p>
        <pre className="cmd">python3 tools/verify_report.py attackledger-report.html</pre>
        <p className="muted">The hashes change every time the report is generated, because it includes the generation time.</p>
      </section>
    </div>
  );
}
