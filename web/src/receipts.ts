// In-browser check of a report's receipt signatures, following the same rules as
// tools/verify_report.py check_signatures. It is a convenience: the offline verifier is
// the authoritative check (it also rebuilds each manifest, walks the evidence chain,
// recomputes the body hash and checks RFC 3161 timestamp tokens, which this does not).

export interface ReportSignature {
  algorithm: string;
  public_key: string;        // base64 SPKI DER
  key_fingerprint: string;   // hex SHA-256 of the SPKI DER bytes
  payload: string;           // the exact text that was signed
  value: string;             // base64 signature (Ed25519 64 bytes, or ECDSA P-256 raw r||s)
}

export interface ReportReceipt {
  manifest_sha256: string;
  closed_by: string | null;
  issued_at?: string;
  signature?: ReportSignature | null;
  timestamp?: { time: string; tsa?: string | null; token?: string } | null;
}

export interface ReportLane {
  lane_id: number;
  host: string;
  role: string;
  name: string;
  status: string;
  receipt: ReportReceipt | null;
}

export interface ReportForVerify {
  format: string;
  generated_at: string;
  engagement: { name: string };
  lanes: ReportLane[];
  evidence: { seq: number; chain_hash: string }[];
}

export type Outcome = "pass" | "fail" | "unsigned" | "unsupported";

export interface ReceiptCheck {
  lane: ReportLane;
  outcome: Outcome;
  problems: string[];         // why it failed, or why it could not be checked
  signer: string | null;      // the name inside the signed payload
  fingerprint: string | null; // the fingerprint computed from the public key
}

const GENESIS = "0".repeat(64);

// SubjectPublicKeyInfo DER prefixes, as in verify_report.py.
const SPKI_PREFIX: Record<string, string> = {
  "Ed25519": "302a300506032b6570032100",
  "ECDSA-P256": "3059301306072a8648ce3d020106082a8648ce3d030107034200",
};

function unb64(s: string): Uint8Array {
  if (typeof s !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4 !== 0) {
    throw new Error("not base64");
  }
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

function hex(buf: ArrayBuffer | Uint8Array): string {
  return Array.from(buf instanceof Uint8Array ? buf : new Uint8Array(buf))
    .map((x) => x.toString(16).padStart(2, "0")).join("");
}

let ed25519: Promise<boolean> | null = null;

/** Whether this browser's WebCrypto can verify Ed25519 signatures. */
export function ed25519Supported(): Promise<boolean> {
  ed25519 ??= (async () => {
    if (!globalThis.crypto?.subtle) return false;
    try {
      await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
      return true;
    } catch {
      return false;
    }
  })();
  return ed25519;
}

/** Verify one signature over the exact payload bytes. Throws "unsupported" if WebCrypto lacks the algorithm. */
export async function verifySignature(algorithm: string, spki: Uint8Array, payload: string,
                                      signature: Uint8Array): Promise<boolean> {
  const prefix = SPKI_PREFIX[algorithm];
  if (!prefix || !hex(spki).startsWith(prefix)) return false;
  if (signature.length !== 64) return false;
  const data = new TextEncoder().encode(payload);
  if (algorithm === "Ed25519") {
    if (!(await ed25519Supported())) throw new Error("unsupported");
    const key = await crypto.subtle.importKey("spki", spki, { name: "Ed25519" }, false, ["verify"]);
    return crypto.subtle.verify({ name: "Ed25519" }, key, signature, data);
  }
  const key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, data);
}

/** Check one receipted lane's signature the way verify_report.py does. */
export async function checkReceipt(lane: ReportLane, chain: Map<number, string>): Promise<ReceiptCheck> {
  const rc = lane.receipt!;
  const sig = rc.signature;
  if (!sig) return { lane, outcome: "unsigned", problems: [], signer: null, fingerprint: null };

  const problems: string[] = [];
  let spki: Uint8Array, value: Uint8Array;
  let payload: {
    format?: string; manifest_sha256?: string; key_fingerprint?: string;
    lane?: { id?: number }; signer?: { name?: string }; chain?: { seq?: number; head?: string };
  };
  try {
    spki = unb64(sig.public_key);
    value = unb64(sig.value);
    payload = JSON.parse(sig.payload);
    if (!payload || typeof payload !== "object") throw new Error("payload");
  } catch {
    return { lane, outcome: "fail", problems: ["The signature fields cannot be read."], signer: null, fingerprint: null };
  }

  const fingerprint = hex(await crypto.subtle.digest("SHA-256", spki));
  if (fingerprint !== sig.key_fingerprint) problems.push("The public key does not match its fingerprint.");

  let unsupported = false;
  try {
    if (!(await verifySignature(sig.algorithm, spki, sig.payload, value))) {
      problems.push("The signature does not verify with the public key in the report.");
    }
  } catch (e) {
    if ((e as Error).message === "unsupported") unsupported = true;
    else problems.push("The public key cannot be used to verify.");
  }
  if (payload.format !== "attackledger-receipt-v2") problems.push("The signed payload has an unknown format.");
  if (payload.manifest_sha256 !== rc.manifest_sha256) problems.push("The signature covers a different manifest.");
  if (payload.lane?.id !== lane.lane_id) problems.push("The signature names another lane.");
  if (payload.key_fingerprint !== sig.key_fingerprint) problems.push("The signed payload names another key.");
  const c = payload.chain ?? {};
  const genesis = c.seq === 0 && c.head === GENESIS;
  if (!genesis && (c.seq === undefined || chain.get(c.seq) !== c.head)) {
    problems.push("The signed evidence chain head is not in this report.");
  }

  const signer = payload.signer?.name ?? null;
  if (problems.length) return { lane, outcome: "fail", problems, signer, fingerprint };
  if (unsupported) {
    return { lane, outcome: "unsupported", signer, fingerprint,
             problems: ["This browser cannot check Ed25519 signatures (its WebCrypto has no Ed25519). Use verify_report.py."] };
  }
  return { lane, outcome: "pass", problems: [], signer, fingerprint };
}

/** Every receipted lane in the report, checked. */
export async function checkReport(r: ReportForVerify): Promise<ReceiptCheck[]> {
  const chain = new Map(r.evidence.map((e) => [e.seq, e.chain_hash]));
  const lanes = r.lanes.filter((l) => l.status === "closed" && l.receipt);
  return Promise.all(lanes.map((l) => checkReceipt(l, chain)));
}

/** Change one character of a base64 signature, keeping it valid base64 (for the tamper check). */
export function tamper(b64: string): string {
  const i = Math.min(10, b64.length - 3);
  return b64.slice(0, i) + (b64[i] === "A" ? "B" : "A") + b64.slice(i + 1);
}

/** A self-test: a copy of a passing receipt with one changed signature byte, or another lane id, must fail. */
export async function tamperCheck(r: ReportForVerify, passing: ReceiptCheck): Promise<boolean> {
  const chain = new Map(r.evidence.map((e) => [e.seq, e.chain_hash]));
  const rc = passing.lane.receipt!;
  const badSig: ReportLane = { ...passing.lane, receipt: { ...rc, signature: { ...rc.signature!, value: tamper(rc.signature!.value) } } };
  const badPayload: ReportLane = { ...passing.lane, receipt: { ...rc, signature: { ...rc.signature!,
    payload: rc.signature!.payload.replace(rc.manifest_sha256, rc.manifest_sha256.replace(/^./, (ch) => (ch === "0" ? "1" : "0"))) } } };
  const [a, b] = await Promise.all([checkReceipt(badSig, chain), checkReceipt(badPayload, chain)]);
  return a.outcome === "fail" && b.outcome === "fail";
}
