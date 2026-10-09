import { FormEvent, useCallback, useEffect, useState } from "react";
import { api, type ApprovalQueue, type TestAccount, type WriteProposal } from "./api";
import { plural } from "./words";

// Test accounts (D-040) and the approval queue for writes (D-041), for testers and owners.
// A person signs in to each account on the target and pastes what it gave them; the API stores it
// encrypted and never shows it again: only a fingerprint and when it was added and last used. The
// gateway adds it to an agent's requests "as" that account. Writes an agent proposes wait here
// until a person reads the full request and approves or rejects it; a DELETE needs a second step.

const KIND_TEXT: Record<TestAccount["kind"], string> = {
  cookie: "Cookie header",
  bearer: "Bearer token",
  headers: "Headers",
};

const KIND_HELP: Record<TestAccount["kind"], string> = {
  cookie: "The value of the Cookie header after signing in, for example sid=…; csrftoken=…",
  bearer: "The token only; it is sent as Authorization: Bearer <token>.",
  headers: "One Name: value per line, for example an API key header and a CSRF header.",
};

function when(iso: string | null): string {
  return iso ? `${iso.slice(0, 16).replace("T", " ")} UTC` : "never";
}

function MaterialField({ id, kind, value, onChange }: { id: string; kind: TestAccount["kind"]; value: string;
                                                         onChange: (v: string) => void }) {
  return (
    <div className="field">
      <label htmlFor={id}>Session material</label>
      {kind === "headers" ? (
        <textarea id={id} rows={3} value={value} spellCheck={false} autoComplete="off"
                  onChange={(e) => onChange(e.target.value)} aria-describedby={`${id}-help`} />
      ) : (
        <input id={id} type="password" value={value} autoComplete="off" spellCheck={false}
               onChange={(e) => onChange(e.target.value)} aria-describedby={`${id}-help`} />
      )}
      <span id={`${id}-help`} className="hint">{KIND_HELP[kind]} Stored encrypted; it is never shown again.</span>
    </div>
  );
}

function HostChoice({ id, hosts, chosen, onChange }: { id: string; hosts: string[]; chosen: string[];
                                                       onChange: (h: string[]) => void }) {
  return (
    <fieldset className="field host-choice" aria-describedby={`${id}-help`}>
      <legend>Hosts it is for</legend>
      {hosts.length === 0 && <span className="hint">Add in-scope hosts to the ledger first.</span>}
      {hosts.map((h) => (
        <label key={h} className="check">
          <input type="checkbox" checked={chosen.includes(h)}
                 onChange={() => onChange(chosen.includes(h) ? chosen.filter((x) => x !== h) : [...chosen, h])} />
          {h}
        </label>
      ))}
      <span id={`${id}-help`} className="hint">The gateway adds the session only to requests for these hosts.</span>
    </fieldset>
  );
}

export function TestAccounts({ engId, canWork, hosts }: { engId: number; canWork: boolean; hosts: string[] }) {
  const [rows, setRows] = useState<TestAccount[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);
  const [label, setLabel] = useState("");
  const [role, setRole] = useState("");
  const [chosen, setChosen] = useState<string[]>([]);
  const [kind, setKind] = useState<TestAccount["kind"]>("cookie");
  const [value, setValue] = useState("");
  const [editing, setEditing] = useState<number | null>(null);
  const [deleting, setDeleting] = useState<number | null>(null);

  const load = useCallback(() => {
    api.testAccounts(engId).then(setRows).catch((e) => setError((e as Error).message));
  }, [engId]);
  useEffect(() => { setRows(null); setError(null); setSaved(null); load(); }, [load]);
  useEffect(() => { if (hosts.length === 1) setChosen(hosts); }, [hosts]);

  async function add(ev: FormEvent) {
    ev.preventDefault();
    setError(null);
    setSaved(null);
    try {
      const a = await api.addTestAccount(engId, { label: label.trim(), role: role.trim(), hosts: chosen, kind, value });
      setValue("");
      setLabel("");
      setRole("");
      setSaved(`Test account ${a.label} added. Its session material is stored encrypted and is not shown again.`);
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function remove(a: TestAccount) {
    setError(null);
    setSaved(null);
    try {
      await api.deleteTestAccount(engId, a.id);
      setDeleting(null);
      setSaved(`Test account ${a.label} deleted.`);
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <section className="panel accounts" aria-labelledby="accounts-title">
      <h3 id="accounts-title" className="panel-title">Test accounts</h3>
      <p className="muted">Create each account on the target and sign in to it yourself, then paste what the sign-in
        gave you. An agent asks for a request "as A"; the gateway adds A's session. The agent, the worker, the logs and
        the evidence never see it.</p>
      {rows === null && !error && <p className="muted" role="status">Loading…</p>}
      {rows && rows.length === 0 && <p className="muted">No test accounts yet.</p>}
      {rows && rows.length > 0 && (
        <ul className="account-list">
          {rows.map((a) => (
            <li key={a.id} className="account-card">
              <div className="account-head">
                <strong className="account-label">{a.label}</strong>
                <span>{a.role}</span>
                <span className="muted">{KIND_TEXT[a.kind]}</span>
              </div>
              <dl className="account-facts">
                <dt>Hosts</dt><dd>{a.hosts.join(", ")}</dd>
                <dt>Sets</dt><dd>{a.header_names.join(", ")}</dd>
                <dt>Fingerprint</dt><dd><code>{a.fingerprint}</code></dd>
                <dt>Added</dt><dd>{when(a.created_at)}{a.created_by ? ` by ${a.created_by}` : ""}</dd>
                {a.replaced_at && <><dt>Replaced</dt><dd>{when(a.replaced_at)}</dd></>}
                <dt>Last used</dt><dd>{when(a.last_used_at)}</dd>
              </dl>
              {canWork && editing !== a.id && deleting !== a.id && (
                <div className="retention-row">
                  <button type="button" className="btn ghost small" onClick={() => { setEditing(a.id); setDeleting(null); }}>
                    Replace<span className="sr-only"> test account {a.label}</span>
                  </button>
                  <button type="button" className="btn ghost small danger" onClick={() => { setDeleting(a.id); setEditing(null); }}>
                    Delete<span className="sr-only"> test account {a.label}</span>
                  </button>
                </div>
              )}
              {deleting === a.id && (
                <div className="confirm danger-zone" role="group" aria-label={`Delete test account ${a.label}`}>
                  <p>Delete test account {a.label}? Agents can no longer send requests as it.</p>
                  <div className="retention-row">
                    <button type="button" className="btn small danger" onClick={() => void remove(a)}>Delete</button>
                    <button type="button" className="btn ghost small" onClick={() => setDeleting(null)}>Cancel</button>
                  </div>
                </div>
              )}
              {editing === a.id && (
                <ReplaceForm engId={engId} account={a} hosts={hosts}
                             onDone={(msg) => { setEditing(null); if (msg) { setSaved(msg); load(); } }}
                             onError={setError} />
              )}
            </li>
          ))}
        </ul>
      )}
      {canWork && (
        <form className="account-form" onSubmit={add} aria-labelledby="add-account-title">
          <h4 id="add-account-title" className="sub-title">Add a test account</h4>
          <div className="account-grid">
            <div className="field">
              <label htmlFor={`acc-label-${engId}`}>Label</label>
              <input id={`acc-label-${engId}`} value={label} maxLength={16} placeholder="A" autoComplete="off"
                     onChange={(e) => setLabel(e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor={`acc-role-${engId}`}>Role in the application</label>
              <input id={`acc-role-${engId}`} value={role} maxLength={100} placeholder="customer" autoComplete="off"
                     onChange={(e) => setRole(e.target.value)} />
            </div>
          </div>
          <HostChoice id={`acc-hosts-${engId}`} hosts={hosts} chosen={chosen} onChange={setChosen} />
          <fieldset className="field kind-choice">
            <legend>What you are pasting</legend>
            {(Object.keys(KIND_TEXT) as TestAccount["kind"][]).map((k) => (
              <label key={k} className="check">
                <input type="radio" name={`acc-kind-${engId}`} checked={kind === k} onChange={() => setKind(k)} />
                {KIND_TEXT[k]}
              </label>
            ))}
          </fieldset>
          <MaterialField id={`acc-value-${engId}`} kind={kind} value={value} onChange={setValue} />
          <button type="submit" className="btn" disabled={!label.trim() || !role.trim() || !value.trim() || chosen.length === 0}>
            Add test account
          </button>
        </form>
      )}
      {error && <p className="field-error" role="alert">{error}</p>}
      {saved && <p className="saved" role="status">{saved}</p>}
    </section>
  );
}

function ReplaceForm({ engId, account, hosts, onDone, onError }: {
  engId: number; account: TestAccount; hosts: string[]; onDone: (msg: string | null) => void; onError: (e: string) => void;
}) {
  const [kind, setKind] = useState<TestAccount["kind"]>(account.kind);
  const [value, setValue] = useState("");
  const [role, setRole] = useState(account.role);
  const [chosen, setChosen] = useState<string[]>(account.hosts);
  const id = `replace-${account.id}`;
  async function save(ev: FormEvent) {
    ev.preventDefault();
    try {
      await api.replaceTestAccount(engId, account.id, {
        role, hosts: chosen, ...(value.trim() ? { kind, value } : {}),
      });
      onDone(`Test account ${account.label} saved.`);
    } catch (e) {
      onError((e as Error).message);
    }
  }
  return (
    <form className="account-form confirm" onSubmit={save} aria-label={`Replace test account ${account.label}`}>
      <div className="field">
        <label htmlFor={`${id}-role`}>Role in the application</label>
        <input id={`${id}-role`} value={role} maxLength={100} onChange={(e) => setRole(e.target.value)} />
      </div>
      <HostChoice id={`${id}-hosts`} hosts={Array.from(new Set([...hosts, ...account.hosts]))} chosen={chosen}
                  onChange={setChosen} />
      <fieldset className="field kind-choice">
        <legend>New session material (leave empty to keep the current one)</legend>
        {(Object.keys(KIND_TEXT) as TestAccount["kind"][]).map((k) => (
          <label key={k} className="check">
            <input type="radio" name={`${id}-kind`} checked={kind === k} onChange={() => setKind(k)} />
            {KIND_TEXT[k]}
          </label>
        ))}
      </fieldset>
      <MaterialField id={`${id}-value`} kind={kind} value={value} onChange={setValue} />
      <div className="retention-row">
        <button type="submit" className="btn small" disabled={!role.trim() || chosen.length === 0}>Save</button>
        <button type="button" className="btn ghost small" onClick={() => onDone(null)}>Cancel</button>
      </div>
    </form>
  );
}

// ---- approvals -------------------------------------------------------------------------------

const STATUS_TEXT: Record<WriteProposal["status"], string> = {
  pending: "Waiting for approval",
  confirming: "Approved, waiting for the DELETE confirmation",
  approved: "Approved, not sent yet",
  rejected: "Rejected",
  sent: "Sent once",
  failed: "Approved, but not sent",
  expired: "Expired",
};

export function Approvals({ engId, canRules, onCount }: { engId: number; canRules: boolean; onCount: (n: number) => void }) {
  const [q, setQ] = useState<ApprovalQueue | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(() => {
    api.approvals(engId).then((r) => { setQ(r); onCount(r.waiting); }).catch((e) => setError((e as Error).message));
  }, [engId, onCount]);
  useEffect(() => {
    setQ(null);
    setError(null);
    load();
    const t = window.setInterval(load, 10000);
    return () => window.clearInterval(t);
  }, [load]);

  async function toggle(on: boolean) {
    setError(null);
    try {
      await api.setAllowWrites(engId, on);
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  const open = q?.items.filter((p) => p.status === "pending" || p.status === "confirming" || p.status === "approved") ?? [];
  const done = q?.items.filter((p) => !open.includes(p)) ?? [];
  return (
    <section className="panel approvals" aria-labelledby="approvals-title">
      <h3 id="approvals-title" className="panel-title">Writes waiting for approval</h3>
      {q && (
        <p className="muted">
          {q.allow_writes
            ? `Agents may propose POST, PUT, PATCH and DELETE requests. Nothing is sent until a tester approves that exact
               request; an approval expires after ${plural(q.approval_minutes, "minute")} and is used once.`
            : "Writes are off for this engagement: agents send read-only requests only, and nothing can be proposed."}
          {q.separation_of_duties && " Separation of duties is on: whoever started an agent run cannot approve its writes."}
        </p>
      )}
      {q && canRules && (
        <label className="check">
          <input type="checkbox" checked={q.allow_writes} onChange={(e) => void toggle(e.target.checked)} />
          Allow agents to propose writes (each one waits for a person's approval)
        </label>
      )}
      {!q && !error && <p className="muted" role="status">Loading…</p>}
      {q && open.length === 0 && <p className="muted">Nothing is waiting.</p>}
      {open.length > 0 && (
        <ul className="write-list">
          {open.map((p) => <WriteCard key={p.id} engId={engId} p={p} onChanged={load} onError={setError} />)}
        </ul>
      )}
      {done.length > 0 && (
        <>
          <h4 className="sub-title">Decided</h4>
          <ul className="write-list decided">
            {done.map((p) => (
              <li key={p.id} className="write-card">
                <p className="write-line"><span className={`method m-${p.method.toLowerCase()}`}>{p.method}</span>
                  <code className="write-url">{p.url || "(content deleted)"}</code></p>
                <p className="hint">
                  {STATUS_TEXT[p.status]}{p.response_status != null ? `: status ${p.response_status}` : ""}
                  {p.account ? `, as test account ${p.account}` : ""}
                  {p.decided_by ? `. ${p.status === "rejected" ? "Rejected" : "Approved"} by ${p.decided_by}, ${when(p.decided_at)}` : ""}
                  {p.note ? `: ${p.note}` : ""}
                </p>
              </li>
            ))}
          </ul>
        </>
      )}
      {error && <p className="field-error" role="alert">{error}</p>}
    </section>
  );
}

function WriteCard({ engId, p, onChanged, onError }: { engId: number; p: WriteProposal; onChanged: () => void;
                                                        onError: (e: string) => void }) {
  const [note, setNote] = useState("");
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const id = `write-${p.id}`;
  async function act(fn: () => Promise<unknown>) {
    setBusy(true);
    try {
      await fn();
      setNote("");
      setTyped("");
      onChanged();
    } catch (e) {
      onError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const r = p.request;
  return (
    <li className="write-card" aria-labelledby={`${id}-title`}>
      <p id={`${id}-title`} className="write-line">
        <span className={`method m-${p.method.toLowerCase()}`}>{p.method}</span>
        <code className="write-url">{r?.url ?? p.url}</code>
      </p>
      <dl className="account-facts">
        <dt>Status</dt><dd>{STATUS_TEXT[p.status]}{p.expires_at ? `; the approval expires ${when(p.expires_at)}` : ""}</dd>
        <dt>As</dt><dd>{p.account ? `test account ${p.account}` : "no test account"}</dd>
        <dt>Checklist</dt><dd>{p.lane_role ?? "lane"} on {p.host}{p.item_idx != null ? `, item ${p.item_idx}` : ""}</dd>
        <dt>Proposed by</dt><dd>{p.proposed_by}, {when(p.created_at)}</dd>
        <dt>Reason</dt><dd>{p.reason}</dd>
        <dt>Request SHA-256</dt><dd><code>{p.request_sha256.slice(0, 16)}…</code></dd>
      </dl>
      {r && (
        <details className="write-request" open>
          <summary>Full request ({plural(r.body_bytes, "byte")} of body)</summary>
          <pre className="cmd" tabIndex={0} aria-label={`Request of write ${p.id}`}>
            {`${r.method} ${r.url}\n${r.headers.map(([k, v]) => `${k}: ${v}`).join("\n")}${r.headers.length ? "\n" : ""}`}
            {r.account ? `[the gateway adds test account ${r.account}'s session here]\n` : ""}
            {r.body ? `\n${r.body}` : ""}
          </pre>
        </details>
      )}
      {!p.job_running && <p className="hint">The agent run that proposed it has ended; it can no longer be sent.</p>}
      {p.status === "pending" && p.job_running && (
        <div className="write-decide">
          <div className="field">
            <label htmlFor={`${id}-note`}>Note (required to reject)</label>
            <input id={`${id}-note`} value={note} maxLength={2000} autoComplete="off" onChange={(e) => setNote(e.target.value)} />
          </div>
          <div className="retention-row">
            <button type="button" className="btn small" disabled={busy}
                    onClick={() => void act(() => api.approveWrite(engId, p.id, p.request_sha256, note))}>
              {p.method === "DELETE" ? "Approve, then confirm" : "Approve and send once"}
              <span className="sr-only"> write {p.id}</span>
            </button>
            <button type="button" className="btn ghost small danger" disabled={busy || !note.trim()}
                    onClick={() => void act(() => api.rejectWrite(engId, p.id, note))}>
              Reject<span className="sr-only"> write {p.id}</span>
            </button>
          </div>
        </div>
      )}
      {p.status === "confirming" && p.job_running && (
        <div className="confirm danger-zone" role="group" aria-labelledby={`${id}-confirm-title`}>
          <p id={`${id}-confirm-title`}><strong>Confirm this DELETE. It changes the target and cannot be undone here.</strong></p>
          <label htmlFor={`${id}-path`}>Type the path, <code>{p.confirm_path}</code>, to confirm</label>
          <input id={`${id}-path`} value={typed} autoComplete="off" spellCheck={false} onChange={(e) => setTyped(e.target.value)} />
          <div className="retention-row">
            <button type="button" className="btn small danger" disabled={busy || typed !== p.confirm_path}
                    onClick={() => void act(() => api.confirmDelete(engId, p.id, p.request_sha256, typed))}>
              Confirm DELETE
            </button>
            <button type="button" className="btn ghost small" disabled={busy || !note.trim()}
                    onClick={() => void act(() => api.rejectWrite(engId, p.id, note))}>Reject instead</button>
          </div>
          <div className="field">
            <label htmlFor={`${id}-note2`}>Note (required to reject)</label>
            <input id={`${id}-note2`} value={note} maxLength={2000} autoComplete="off" onChange={(e) => setNote(e.target.value)} />
          </div>
        </div>
      )}
      {p.status === "approved" && <p className="hint">The agent's run sends it the next time it checks its writes.</p>}
    </li>
  );
}
