// The signed-in person's own account (D-036): key changes since their previous sign-in,
// their signing keys, and changing their password. Opens by itself when a key was
// registered or revoked for them that this browser did not make, because only they can
// tell whether it was them, and once per sign-in while they still use a password someone
// else set (a new account, or a reset on the server), asking them to choose their own.

import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { api, type KeyNotice, type Me, type SigningKeyView } from "./api";
import { localKey } from "./signing";
import "./Account.css";

const VIA: Record<string, string> = {
  own_session: "from your own session",
  assigned_password: "from a session signed in with a password someone else set",
  operator_cli: "by the operator on the server",
  backfill: "before the key log existed",
};

function when(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().slice(0, 16).replace("T", " ") + " UTC";
}

function short(fp: string): string {
  return `${fp.slice(0, 4)} ${fp.slice(4, 8)} ${fp.slice(8, 12)} ${fp.slice(12, 16)}…`;
}

function seenKey(me: Me): string {
  return `attackledger-key-notice:${me.user_id}:${me.key_notice?.since ?? "first"}:${me.key_notice?.events.length ?? 0}`;
}

// The previous sign-in time changes with every sign-in, so a skipped prompt comes back at the next one.
function skippedKey(me: Me): string {
  return `attackledger-password-prompt:${me.user_id}:${me.key_notice?.since ?? "first"}`;
}

export function Account({ me }: { me: Me | null }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [mine, setMine] = useState<string | null>(null);       // the key held in this browser
  const [notice, setNotice] = useState<KeyNotice | null>(null);
  const [keys, setKeys] = useState<SigningKeyView[]>([]);
  const [chosen, setChosen] = useState(me?.password_chosen ?? true);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);
  const [prompted, setPrompted] = useState(false);   // opened to ask for a password of their own
  const currentRef = useRef<HTMLInputElement>(null);

  const loadKeys = useCallback(() => api.keys().then(setKeys).catch((e) => setError(e.message)), []);

  useEffect(() => {
    if (!me || me.kind !== "person" || me.user_id == null) return;
    setChosen(me.password_chosen ?? true);
    localKey(me.user_id).then((k) => {
      const fp = k?.fingerprint ?? null;
      setMine(fp);
      const others = (me.key_notice?.events ?? []).filter((e) => e.key_fingerprint !== fp);
      setNotice(others.length ? { since: me.key_notice!.since, events: others } : null);
      let seen = false;
      let skipped = false;
      try {
        seen = sessionStorage.getItem(seenKey(me)) === "1";
        skipped = sessionStorage.getItem(skippedKey(me)) === "1";
      } catch { /* storage blocked */ }
      const askPassword = me.password_chosen === false && !skipped;
      setPrompted(askPassword);
      if ((others.length && !seen) || askPassword) open();
    });
  }, [me]);

  // Opened to ask for a password: start in its first field, once the section is in place.
  useEffect(() => { if (prompted && dialog.current?.open) currentRef.current?.focus(); }, [prompted]);

  function open() {
    setError(null);
    setSaved(null);
    loadKeys();
    if (!dialog.current?.open) dialog.current?.showModal();
  }

  function close() {
    try {
      if (me) sessionStorage.setItem(seenKey(me), "1");
      if (me && !chosen) sessionStorage.setItem(skippedKey(me), "1");   // closing is skipping, until the next sign-in
    } catch { /* storage blocked */ }
    setPrompted(false);
    dialog.current?.close();
  }

  async function revoke(id: number) {
    setError(null);
    try {
      await api.revokeKey(id);
      await loadKeys();
      setNotice((n) => n && { ...n, events: n.events.map((e) => e.key_id === id ? { ...e, key_revoked: true } : e) });
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function change(ev: FormEvent) {
    ev.preventDefault();
    setError(null);
    setSaved(null);
    if (next !== again) return setError("The new passwords do not match.");
    try {
      await api.changePassword(current, next);
      setCurrent(""); setNext(""); setAgain("");
      setChosen(true);
      setSaved("Password changed. You stay signed in here and are signed out everywhere else.");
    } catch (e) {
      setError((e as Error).message);
    }
  }

  if (!me || me.kind !== "person") return null;
  const password = (
    <section aria-labelledby="password-title">
      <h3 id="password-title">{!chosen ? "Choose your own password" : "Change your password"}</h3>
      {!chosen && (
        <p className="notice-inline">You still sign in with a password someone else set, when your account was made
          or reset. Choose your own, so that only you can sign in as you. Until you do, keys you register are
          recorded in the key log as registered on a password someone else set.</p>
      )}
      <form className="person-form" onSubmit={change}>
        <label>Current password
          <input ref={currentRef} type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} />
          {!chosen && <span className="hint">The one you were given.</span>}
        </label>
        <label>New password
          <input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />
          <span className="hint">At least 12 characters. Changing it signs you out on every other device.</span>
        </label>
        <label>New password again
          <input type="password" autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} />
        </label>
        <div className="work-buttons">
          <button className="btn" disabled={!current || !next || !again}>{!chosen ? "Save my password" : "Change password"}</button>
          {prompted && !chosen && <button type="button" className="btn ghost" onClick={close}>Skip for now</button>}
        </div>
      </form>
    </section>
  );
  const active = (id: number | null) => id != null && keys.some((k) => k.id === id && !k.revoked);

  return (
    <>
      <button className="link-button" onClick={open}>Your account</button>
      <dialog ref={dialog} className="account" aria-labelledby="account-title" onCancel={close}>
        <div className="account-head">
          <h2 id="account-title" className="panel-title">Your account</h2>
          <button className="btn ghost small" onClick={close}>Close</button>
        </div>
        {prompted && password}

        {notice && (
          <section className="key-notice" aria-labelledby="key-notice-title">
            <h3 id="key-notice-title">
              {notice.since ? `Key changes since your last sign-in (${when(notice.since)})` : "Key changes on your account"}
            </h3>
            <ul>
              {notice.events.map((e, i) => (
                <li key={i}>
                  <span>
                    <strong>{e.event === "registered" ? "New signing key" : "Key revoked"}</strong>{" "}
                    <code title={e.key_fingerprint}>{short(e.key_fingerprint)}</code>{" "}
                    <span className="muted">{e.algorithm}, {when(e.at)}, {VIA[e.via] ?? e.via}</span>
                  </span>
                  {e.event === "registered" && active(e.key_id) && (
                    <button className="btn ghost small" onClick={() => revoke(e.key_id!)}>Revoke</button>
                  )}
                  {e.event === "registered" && e.key_revoked && !active(e.key_id) && <span className="tag">Revoked</span>}
                </li>
              ))}
            </ul>
            <p>If this wasn't you, tell an owner and revoke it. A revoked key signs nothing new; receipts it
              already signed keep showing which key signed them and when it was registered.</p>
          </section>
        )}

        <section aria-labelledby="keys-title">
          <h3 id="keys-title">Your signing keys</h3>
          {keys.length === 0 ? (
            <p className="muted">None yet. A key is made in your browser the first time you sign a receipt.</p>
          ) : (
            <ul className="key-list">
              {keys.map((k) => (
                <li key={k.id} className={k.revoked ? "off" : undefined}>
                  <span>
                    <code title={k.fingerprint}>{short(k.fingerprint)}</code>{" "}
                    <span className="muted">{k.algorithm}, registered {when(k.created_at)}</span>
                    {k.fingerprint === mine && <span className="tag">This browser</span>}
                    {k.revoked && <span className="tag">Revoked</span>}
                  </span>
                  {!k.revoked && <button className="btn ghost small" onClick={() => revoke(k.id)}>Revoke</button>}
                </li>
              ))}
            </ul>
          )}
        </section>

        {!prompted && password}
        {error && <p className="field-error" role="alert">{error}</p>}
        {saved && <p className="saved" role="status">{saved}</p>}
      </dialog>
    </>
  );
}
