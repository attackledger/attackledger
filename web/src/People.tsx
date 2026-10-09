import { FormEvent, useCallback, useEffect, useState } from "react";
import { api, type Member, type Person } from "./api";

const ROLE_HELP: Record<string, string> = {
  viewer: "reads coverage, evidence and reports",
  tester: "runs recon, works lanes, attaches evidence",
  reviewer: "signs receipts",
};

/** Owners only: who can sign in. */
export function People({ mode }: { mode: "open" | "token" | "people" }) {
  const [people, setPeople] = useState<Person[]>([]);
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [owner, setOwner] = useState(mode !== "people");
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);

  const load = useCallback(() => api.people().then(setPeople).catch((e) => setError(e.message)), []);
  useEffect(() => { load(); }, [load]);

  async function add(ev: FormEvent) {
    ev.preventDefault();
    setError(null);
    setSaved(null);
    try {
      const p = await api.createPerson({ email, name, password, is_owner: owner });
      setSaved(`Added ${p.name}. Give them their password in person or through your password manager.`);
      setEmail(""); setName(""); setPassword(""); setOwner(false);
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function change(p: Person, body: Partial<Person>) {
    setError(null);
    try { await api.updatePerson(p.id, body); load(); } catch (e) { setError((e as Error).message); }
  }

  return (
    <div className="people">
      <section className="panel" aria-labelledby="people-title">
        <h3 id="people-title" className="panel-title">People</h3>
        <p className="muted">Everyone who can sign in. Roles are given per engagement, on its Team tab.
          Owners manage people and engagements and can do everything.</p>
        {mode !== "people" && (
          <p className="notice-inline">
            Nobody has an account yet, so {mode === "open" ? "this ledger is open to anyone who can reach it" : "the operator token is the only way in"}.
            Add the first person as an owner: from then on, everyone signs in with email and password
            {mode === "token" ? " (the token keeps working for automation)" : ""}.
          </p>
        )}
        <ul className="people-list">
          {people.map((p) => (
            <li key={p.id} className={p.disabled ? "off" : undefined}>
              <span className="people-name"><strong>{p.name}</strong><span className="muted">{p.email}</span></span>
              <span className="people-tags">
                {p.is_owner && <span className="tag">Owner</span>}
                {p.disabled && <span className="tag">Disabled</span>}
              </span>
              <span className="people-actions">
                <button className="btn ghost small" onClick={() => change(p, { is_owner: !p.is_owner })}>
                  {p.is_owner ? "Remove owner" : "Make owner"}
                </button>
                <button className="btn ghost small" onClick={() => change(p, { disabled: !p.disabled })}>
                  {p.disabled ? "Enable" : "Disable"}
                </button>
              </span>
            </li>
          ))}
        </ul>
        {error && <p className="field-error" role="alert">{error}</p>}
      </section>

      <section className="panel" aria-labelledby="add-person-title">
        <h3 id="add-person-title" className="panel-title">Add a person</h3>
        <form className="person-form" onSubmit={add}>
          <label>Name<input id="person-name" value={name} onChange={(e) => setName(e.target.value)} /></label>
          <label>Email<input id="person-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} /></label>
          <label>
            First password
            <input id="person-password" type="password" autoComplete="new-password" value={password}
                   onChange={(e) => setPassword(e.target.value)} />
            <span className="hint">At least 12 characters.</span>
          </label>
          <label className="check">
            <input type="checkbox" checked={owner} onChange={(e) => setOwner(e.target.checked)} />
            Owner
          </label>
          <button className="btn" disabled={!email || !name || !password}>Add person</button>
          {saved && <p className="saved" role="status">{saved}</p>}
        </form>
      </section>
    </div>
  );
}

/** Owners only: who works on this engagement, in which roles, and whether duties are separated. */
export function Team({ engId, separation, onChanged }: { engId: number; separation: boolean; onChanged: () => void }) {
  const [people, setPeople] = useState<Person[]>([]);
  const [roles, setRoles] = useState<Record<number, string[]>>({});
  const [sod, setSod] = useState(separation);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);

  useEffect(() => {
    setSod(separation);
    Promise.all([api.people(), api.members(engId)]).then(([ps, ms]) => {
      setPeople(ps.filter((p) => !p.disabled));
      setRoles(Object.fromEntries(ms.map((m: Member) => [m.user_id, m.roles])));
    }).catch((e) => setError(e.message));
  }, [engId, separation]);

  function toggle(uid: number, role: string) {
    const cur = roles[uid] ?? [];
    setRoles({ ...roles, [uid]: cur.includes(role) ? cur.filter((r) => r !== role) : [...cur, role] });
  }

  async function save() {
    setError(null);
    setSaved(null);
    try {
      await api.setMembers(engId, Object.entries(roles).map(([uid, rs]) => ({ user_id: Number(uid), roles: rs })));
      if (sod !== separation) await api.updateEngagement(engId, { separation_of_duties: sod });
      setSaved("Team saved.");
      onChanged();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  const others = people.filter((p) => !p.is_owner);
  return (
    <section className="panel team" aria-labelledby="team-title">
      <h3 id="team-title" className="panel-title">Team</h3>
      <p className="muted">Owners can do everything on every engagement. Everyone else sees only the engagements
        they have a role on.</p>
      {others.length === 0 ? (
        <p className="muted">Nobody else can sign in yet. Add people on the People page first.</p>
      ) : (
        <div className="sheet">
          <table className="obs team-table">
            <thead>
              <tr>
                <th scope="col">Person</th>
                {Object.keys(ROLE_HELP).map((r) => <th key={r} scope="col" title={ROLE_HELP[r]}>{r[0].toUpperCase() + r.slice(1)}</th>)}
              </tr>
            </thead>
            <tbody>
              {others.map((p) => (
                <tr key={p.id}>
                  <th scope="row">{p.name}<span className="muted"> {p.email}</span></th>
                  {Object.keys(ROLE_HELP).map((r) => (
                    <td key={r}>
                      <input type="checkbox" aria-label={`${p.name}: ${r}`} checked={(roles[p.id] ?? []).includes(r)}
                             onChange={() => toggle(p.id, r)} />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="hint">{Object.entries(ROLE_HELP).map(([r, t]) => `${r[0].toUpperCase() + r.slice(1)} ${t}`).join(". ")}.</p>
      <label className="check">
        <input type="checkbox" checked={sod} onChange={(e) => setSod(e.target.checked)} />
        Separation of duties: whoever attached a lane's evidence cannot sign its receipt
      </label>
      {error && <p className="field-error" role="alert">{error}</p>}
      {saved && <p className="saved" role="status">{saved}</p>}
      <button className="btn" onClick={save}>Save team</button>
    </section>
  );
}
