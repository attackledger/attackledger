// Unsent text a person typed (an evidence note, a not-applicable reason, an import note), kept
// until it is sent, so that a session that expires mid-sentence loses nothing: the sign-in form
// comes and goes, and the field comes back with what was in it.
//
// Kept in memory, and in sessionStorage (this tab only, gone when it closes) so a reload keeps it
// too. Storage can be blocked or throw; then memory alone keeps it. Text that looks like a
// credential (a cookie, an Authorization header, a token, a password) stays in memory only:
// nothing secret is ever written to storage. Signing out, or a different person signing in on
// this tab, clears every draft.

import { useCallback, useEffect, useState } from "react";

// Keys used: note:<lane>:<item>, summary:<lane>:<item>, na:<lane>:<item>, bulk-na:<lane>,
// import-note:<engagement>:<entry>.
const PREFIX = "attackledger-draft:";
const OWNER = "attackledger-draft-owner";
const mem = new Map<string, string>();

// A credential pasted in (a header, a JWT, "password=...", a JSON field or a header such as
// "access_token": "..." or X-Api-Key: ..., a private key, an AWS key id, a URL with a password, a
// provider's prefixed token), not a sentence such as
// "a wrong password: 401": after a colon, only a value of eight or more characters counts.
const SECRETISH = new RegExp([
  /authorization\s*:|bearer\s+[\w.~+/-]{8,}|(^|\s)(set-)?cookie\s*:|eyJ[\w-]{8,}\./.source,
  /(api[_-]?key|passw(or)?d|secret|token|session(id)?)\s*=\s*\S/.source,
  /(api[_-]?key|passw(or)?d|secret|token|session(id)?|subscription[_-]?key|functions[_-]?key)[\w-]*["']?\s*:\s*["']?[^\s"',]{8,}/.source,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b/.source,
  // A URL with a user name and password before its host, and tokens a provider marks with a
  // prefix: GitHub, GitLab, Slack, Stripe, Google, npm, Anthropic and OpenAI (web e2e tests, WE-4).
  /\b[a-z][a-z0-9+.-]*:\/\/[^\s/?#@:]*:[^\s/?#@]+@/.source,
  /\b(gh[pousr]_[a-z0-9]{20,}|github_pat_\w{20,}|glpat-[\w-]{20,}|xox[abeoprs]-[\w-]{10,}|[rs]k_live_\w{16,})/.source,
  /\b(AIza[\w-]{30,}|npm_[a-z0-9]{30,}|sk-(ant-|proj-)?[\w-]{20,})/.source,
].join("|"), "i");

function storage(): Storage | null {
  try { return window.sessionStorage; } catch { return null; }
}

export function getDraft(key: string): string {
  if (mem.has(key)) return mem.get(key)!;
  try {
    const v = storage()?.getItem(PREFIX + key);
    if (v) { mem.set(key, v); return v; }
  } catch { /* storage blocked */ }
  return "";
}

export function setDraft(key: string, value: string) {
  if (!value) return clearDraft(key);
  mem.set(key, value);
  try {
    if (SECRETISH.test(value)) storage()?.removeItem(PREFIX + key);
    else storage()?.setItem(PREFIX + key, value);
  } catch { /* storage blocked or full: memory keeps it */ }
}

export function clearDraft(key: string) {
  mem.delete(key);
  try { storage()?.removeItem(PREFIX + key); } catch { /* storage blocked */ }
}

function storedKeys(): string[] {
  const s = storage();
  if (!s) return [];
  try {
    return Array.from({ length: s.length }, (_, i) => s.key(i) ?? "").filter((k) => k.startsWith(PREFIX));
  } catch { return []; }
}

export function hasDrafts(): boolean {
  return mem.size > 0 || storedKeys().length > 0;
}

export function clearAllDrafts() {
  mem.clear();
  try { const s = storage(); for (const k of storedKeys()) s?.removeItem(k); } catch { /* storage blocked */ }
}

/** Drafts belong to whoever typed them: a different person signing in on this tab starts clean. */
let memOwner: string | null = null;
export function claimDrafts(owner: string) {
  if (memOwner != null && memOwner !== owner) clearAllDrafts();
  memOwner = owner;
  try {
    const s = storage();
    const was = s?.getItem(OWNER);
    if (was != null && was !== owner) clearAllDrafts();
    s?.setItem(OWNER, owner);
  } catch { /* storage blocked: memory drafts are this page's own */ }
}

/** A text field's value, kept as a draft under `key` until it is cleared. */
export function useDraft(key: string): [string, (v: string) => void, () => void] {
  const [value, setValue] = useState(() => getDraft(key));
  useEffect(() => { setValue(getDraft(key)); }, [key]);
  const set = useCallback((v: string) => { setValue(v); setDraft(key, v); }, [key]);
  const clear = useCallback(() => { setValue(""); clearDraft(key); }, [key]);
  return [value, set, clear];
}
