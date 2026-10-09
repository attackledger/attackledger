import { useEffect, useState } from "react";
import { api, ControlRow, ControlsReport } from "./api";
import { plural } from "./words";

// Same words as the report (report.py _CONTROL_STATUS). "Partial" is avoided here because
// it is also an evidence strength.
const STATUS_TEXT: Record<ControlRow["status"], string> = {
  evidenced: "All mapped items receipted",
  resolved: "Resolved, partly not applicable",
  not_applicable: "Not applicable",
  partial: "Some mapped items receipted",
  none: "No mapped item receipted",
};

const STRENGTH_TEXT: Record<ControlRow["strength"], string> = {
  full: "Full evidence",
  partial: "Partial evidence",
  supporting: "Supporting evidence",
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
        <strong>{pack}</strong> methodology across {plural(report.hosts_in_scope, "in-scope host")}.{" "}
        {evidenced} of {plural(report.controls.length, "control")} {evidenced === 1 ? "has" : "have"} every mapped item receipted. Each mapping says how strong the evidence is; a test result alone never shows that a control is met. Items marked not applicable are counted apart and never as evidence.
      </p>
      <p className="disclaimer">{report.disclaimer} Check each mapping against the current standard.</p>

      {report.hosts_in_scope === 0 && (
        <p className="muted">Add in-scope hosts first. Control evidence is counted per host.</p>
      )}

      {[...groups.entries()].map(([fw, rows]) => (
        <section key={fw} className="panel" aria-labelledby={`fw-${rows[0].framework}`}>
          <h3 id={`fw-${rows[0].framework}`} className="panel-title">{fw}</h3>
          {/* On a phone the table fits by wrapping; anything still wider scrolls here, never the page. */}
          <div className="ctl-scroll" role="region" aria-label={`${fw}: controls table`} tabIndex={0}>
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
                const na = c.not_applicable ?? 0;
                return (
                  <tr key={c.id}>
                    <th scope="row">
                      <span className="ctl-id">{c.id}</span>
                      <span className="ctl-text">{c.text}</span>
                      {c.strength && <span className={`ctl-strength ${c.strength}`}>{STRENGTH_TEXT[c.strength]}</span>}
                      {c.note && <span className="ctl-note">{c.note}</span>}
                    </th>
                    <td className="ctl-lanes">{c.lanes.join(", ")}</td>
                    <td>
                      <div className="bar" role="img"
                           aria-label={`${c.evidenced} of ${c.required} with evidence${na ? `, ${na} not applicable` : ""}`}>
                        <span style={{ width: `${pct}%` }} />
                      </div>
                      <span className="bar-label">{c.evidenced}/{c.required}{na > 0 && `, ${na} N/A`}</span>
                    </td>
                    <td><span className={`ctl-status ${c.status}`}>{STATUS_TEXT[c.status]}</span></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          </div>
        </section>
      ))}
    </div>
  );
}
