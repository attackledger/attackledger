import { useEffect, useState } from "react";
import { api, ControlRow, ControlsReport } from "./api";

const STATUS_TEXT: Record<ControlRow["status"], string> = {
  evidenced: "Evidenced",
  partial: "Partial",
  none: "No evidence",
};

export function Controls({ engId, pack }: { engId: number; pack: string }) {
  const [report, setReport] = useState<ControlsReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setReport(null);
    api.controls(engId).then(setReport).catch((e) => setError(e.message));
  }, [engId]);

  if (!report) return <p className="muted">{error ?? "Loading controls…"}</p>;

  const groups = new Map<string, ControlRow[]>();
  for (const c of report.controls) {
    const list = groups.get(c.framework_name) ?? [];
    list.push(c);
    groups.set(c.framework_name, list);
  }
  const evidenced = report.controls.filter((c) => c.status === "evidenced").length;

  return (
    <div className="controls">
      <p className="controls-intro">
        Which controls the receipted tests in this engagement produce evidence for, using the{" "}
        <strong>{pack}</strong> methodology across {report.hosts_in_scope} in-scope{" "}
        {report.hosts_in_scope === 1 ? "host" : "hosts"}. {evidenced} of {report.controls.length} controls are
        fully evidenced.
      </p>
      <p className="disclaimer">{report.disclaimer} Check each mapping against the current standard.</p>

      {report.hosts_in_scope === 0 && (
        <p className="muted">Add in-scope hosts first. Control evidence is counted per host.</p>
      )}

      {[...groups.entries()].map(([fw, rows]) => (
        <section key={fw} className="panel" aria-labelledby={`fw-${rows[0].framework}`}>
          <h3 id={`fw-${rows[0].framework}`} className="panel-title">{fw}</h3>
          <table className="ctl">
            <thead>
              <tr>
                <th scope="col">Control</th>
                <th scope="col">Evidence from</th>
                <th scope="col" className="ctl-progress-col">Receipted items</th>
                <th scope="col">Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((c) => {
                const pct = c.required ? Math.round((c.evidenced / c.required) * 100) : 0;
                return (
                  <tr key={c.id}>
                    <th scope="row">
                      <span className="ctl-id">{c.id}</span>
                      <span className="ctl-text">{c.text}</span>
                    </th>
                    <td className="ctl-lanes">{c.lanes.join(", ")}</td>
                    <td>
                      <div className="bar" role="img" aria-label={`${c.evidenced} of ${c.required} receipted`}>
                        <span style={{ width: `${pct}%` }} />
                      </div>
                      <span className="bar-label">{c.evidenced}/{c.required}</span>
                    </td>
                    <td><span className={`ctl-status ${c.status}`}>{STATUS_TEXT[c.status]}</span></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </section>
      ))}
    </div>
  );
}
