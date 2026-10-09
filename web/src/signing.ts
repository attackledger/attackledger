// The reviewer's signing key (D-027). Created in this browser with WebCrypto as a
// non-extractable key and kept in IndexedDB: the private key never leaves the browser,
// and the server only ever sees the public key. Ed25519 where the browser supports it,
// otherwise ECDSA P-256 with SHA-256.

import { api } from "./api";

export type Algorithm = "Ed25519" | "ECDSA-P256";

export interface LocalKey {
  userId: number;
  algorithm: Algorithm;
  fingerprint: string;
  keyPair: CryptoKeyPair;
}

const DB = "attackledger-keys";
const STORE = "keys";

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE, { keyPath: "userId" });
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(new Error("This browser cannot store a signing key (IndexedDB is unavailable)."));
  });
}

async function load(userId: number): Promise<LocalKey | null> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const req = db.transaction(STORE).objectStore(STORE).get(userId);
    req.onsuccess = () => resolve((req.result as LocalKey) ?? null);
    req.onerror = () => reject(req.error);
  });
}

async function save(key: LocalKey): Promise<void> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

function b64(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

async function generate(): Promise<{ algorithm: Algorithm; keyPair: CryptoKeyPair }> {
  if (!window.isSecureContext || !crypto.subtle) {
    throw new Error("Signing needs a secure page (HTTPS or localhost).");
  }
  try {
    const keyPair = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]) as CryptoKeyPair;
    return { algorithm: "Ed25519", keyPair };
  } catch {
    const keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
    return { algorithm: "ECDSA-P256", keyPair };
  }
}

/** This person's key in this browser, registered with the server; created on first use. */
export async function ensureKey(userId: number): Promise<LocalKey> {
  const existing = await load(userId);
  const registered = await api.keys();
  if (existing && registered.some((k) => k.fingerprint === existing.fingerprint && !k.revoked)) return existing;
  const { algorithm, keyPair } = existing && !registered.some((k) => k.fingerprint === existing.fingerprint)
    ? { algorithm: existing.algorithm, keyPair: existing.keyPair }   // known here, not on this server yet
    : await generate();                                             // none, or revoked: make a new one
  const spki = b64(await crypto.subtle.exportKey("spki", keyPair.publicKey));
  let fingerprint: string;
  try {
    fingerprint = (await api.addKey(algorithm, spki)).fingerprint;
  } catch (e) {
    if (!(e as Error).message.includes("already registered")) throw e;
    fingerprint = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",
      Uint8Array.from(atob(spki), (c) => c.charCodeAt(0))))).map((x) => x.toString(16).padStart(2, "0")).join("");
  }
  const key = { userId, algorithm, fingerprint, keyPair };
  await save(key);
  return key;
}

export async function localKey(userId: number): Promise<LocalKey | null> {
  try { return await load(userId); } catch { return null; }
}

/** Sign the exact payload text the server issued, the way the server verifies it. */
export async function sign(key: LocalKey, payload: string): Promise<string> {
  const data = new TextEncoder().encode(payload);
  const params = key.algorithm === "Ed25519" ? { name: "Ed25519" } : { name: "ECDSA", hash: "SHA-256" };
  return b64(await crypto.subtle.sign(params, key.keyPair.privateKey, data));
}
