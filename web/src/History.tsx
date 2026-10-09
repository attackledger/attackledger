import { useEffect, useMemo, useState } from "react";
import { api, type AuditEntry, type AuditLog } from "./api";
import { plural } from "./words";

// The engagement's administrative history from the server's audit log (D-037): scope and
// rules, authorization, settings, roles, and changes to the accounts of its people. Every
// role can read it. The wording comes from the server, the same as in the report.

type Group = "all" | "scope" | "roles" | "settings" | "authorization" | "people";

const GROUPS: { key: Group; label: string }[] = [
  { key: "all", label: "Everything" },
  { key: "scope", label: "Scope and rules" },
  { key: "roles", label: "Roles" },
  { key: "settings", label: "Settings" },
  { key: "authorization", label: "Authorization" },
  { key: "people", label: "People" },
];

function groupOf(action: string): Group {
  if (action === "scope.updated") return "scope";
  if (action === "members.updated") return "roles";
  if (action === "engagement.settings" || action === "engagement.created") return "settings";
  if (action === "engagement.authorized") return "authorization";
  return "people";
}

function when(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { timeZoneName: "short" });
}

export function History({ engId }: { engId: number }) {
  const [log, setLog] = useState<AuditLog | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [group, setGroup] = useState<Group>("all");

  useEffect(() => {
    let live = true;
    setLog(null);
    setError(null);
    api.audit(engId).then((l) => live && setLog(l)).catch((e) => live && setError((e as Error).message));
    return () => { live = false; };
  }, [engId]);

  // Newest first: the question is usually "what changed lately".
  const rows = useMemo<AuditEntry[]>(
    () => (log?.entries ?? []).filter((e) => group === "all" || groupOf(e.action) === group).reverse(),
    [log, group],
  );

  if (!log) return <p className="muted">{error ?? "Loading the history…"}</p>;

  return (
    <div className="report history">
      <section className="panel" aria-labelledby="history-title">
        <h3 id="history-title" className="panel-title">Change history</h3>
        <p className="report-lede">
          Every change to this engagement's scope and rules, authorization, settings and roles, and to the accounts of
          the people who work on it, with who made it and when. Each entry is chained by hash to the one before it, and
          reports carry these entries so a reader can check them offline.
        </p>
        <p className={`status ${log.chain.intact ? "ok" : "bad"}`} role="status">
          {log.chain.intact
            ? `The audit log is intact: ${plural(log.chain.head.seq, "entry", "entries")}, every one linked to the one before it.`
            : "The audit log is broken: an entry was changed, removed or reordered. Ask the operator; reports made now will fail verification."}
        </p>
        {!log.chain.intact && (
          <ul className="verify-problems bad">{log.chain.problems.map((p) => <li key={p}>{p}</li>)}</ul>
        )}
        <label className="history-filter">
          Show{" "}
          <select value={group} onChange={(e) => setGroup(e.target.value as Group)}>
            {GROUPS.map((g) => <option key={g.key} value={g.key}>{g.label}</option>)}
          </select>
        </label>
        {rows.length === 0
          ? <p className="muted">Nothing of this kind was recorded.</p>
          : (
            <div className="history-wrap" role="region" aria-label="Change history table" tabIndex={0}>
              <table className="ctl">
                <thead>
                  <tr><th scope="col">When</th><th scope="col">By</th><th scope="col">Change</th></tr>
                </thead>
                <tbody>
                  {rows.map((e) => (
                    <tr key={e.seq}>
                      <td className="history-time">{when(e.at)}<span className="hint"> #{e.seq}</span></td>
                      <td>{e.actor_label}</td>
                      <td>{e.text}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        <p className="hint">
          Entries by "recorded when the audit log was added" show the state at that time; who set it earlier is not
          known. Passwords are never recorded, only that one was set.
        </p>
      </section>
    </div>
  );
}
