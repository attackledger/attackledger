import { useEffect, useState } from "react";

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

function plural(n: number, one: string, many: string) {
  return `${n} ${n === 1 ? one : many}`;
}

export function Report({ engId }: { engId: number }) {
  const [r, setR] = useState<ReportSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setR(null);
    fetch(`/api/engagements/${engId}/report`)
      .then((res) => (res.ok ? res.json() : Promise.reject(new Error(`Request failed (${res.status})`))))
      .then(setR)
      .catch((e) => setError(e.message));
  }, [engId]);

  if (!r) return <p className="muted">{error ?? "Building report…"}</p>;
  const s = r.summary;
  const base = `/api/engagements/${engId}`;

  return (
    <div className="report">
      <section className="panel report-hero">
        <div>
          <h3 className="panel-title">Coverage report</h3>
          <p className="report-lede">
            <strong>{s.lanes_receipted}</strong> of {s.lanes_possible} possible lanes are receipted across{" "}
            {s.hosts_in_scope} in-scope {s.hosts_in_scope === 1 ? "host" : "hosts"}.{" "}
            {plural(s.lanes_opened - s.lanes_receipted, "more is", "more are")} open or void, and{" "}
            {plural(s.lanes_possible - s.lanes_opened, "was", "were")} never opened, so{" "}
            {s.lanes_possible - s.lanes_opened === 1 ? "it counts" : "they count"} as untested.
          </p>
          {!r.engagement.authorized_at && (
            <p className="status bad">No authorization is recorded for this engagement. The report says so.</p>
          )}
        </div>
        <div className="report-actions">
          <a className="btn" href={`${base}/report.html`} target="_blank" rel="noopener">Open printable report</a>
          <a className="btn ghost" href={`${base}/report.html?download=true`}>Download HTML</a>
          <a className="btn ghost" href={`${base}/report?download=true`}>Download JSON</a>
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
