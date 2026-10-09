// Verify an AttackLedger report in the browser: a port of tools/verify_report.py.
//
// The Python script is the reference. This module makes the same checks in the same order,
// with the same messages, so that the public verifier page (attackledger.com/verify) and the
// app's Verify tab give the verdicts the offline verifier gives. tools/verifier_equivalence/
// runs both on a table of reports and compares every line of output.
//
// Two things make a faithful port harder than it looks, and both are handled here:
//   - Hashes are taken over Python's json.dumps output, so numbers must survive the round
//     trip as Python sees them (5 and 5.0 are different text). Reports are parsed with a
//     JSON reader that keeps ints and floats apart, and serialized the way Python does.
//   - Python raises on a missing key or a wrong type, and the script catches some of those
//     errors and not others. The helpers below (at, getk, pyEq, ...) raise the same error
//     kinds, so a malformed report fails, or cannot be checked, where the script's would.
//
// Cryptography is WebCrypto: SHA-2, ECDSA P-256 and P-384, RSA PKCS #1 v1.5, and Ed25519
// where the browser has it. Where it does not (browsers before Chrome 137, Firefox 129 or
// Safari 17), Ed25519 falls back to a port of the script's own RFC 8032 code, below.
// Nothing here makes a network request.

import { TSA_ROOTS } from "./tsa_roots";

export const GENESIS = "0".repeat(64);
const FORMATS = ["attackledger-report/1", "attackledger-report/2"];
const CHAIN_FIELDS = ["seq", "lane_id", "host", "role", "item_id", "kind", "sha256", "uri", "summary"];
// Evidence chain record v2: the summary is replaced by its hash, so the content can be
// deleted with its engagement key while the chain still verifies (D-043).
const CHAIN_FIELDS_V2 = ["v", "seq", "lane_id", "host", "role", "item_id", "kind", "sha256", "uri", "summary_sha256",
                         "source"];
const KEY_LOG_FIELDS = ["seq", "user_id", "user_name", "key_fingerprint", "algorithm", "event", "at", "via"];
const AUDIT_FIELDS = ["seq", "at", "actor", "action", "engagement_id", "subject_id", "change"];
const PAYLOAD_FORMATS = ["attackledger-receipt-v2", "attackledger-receipt-v3"];
const KEY_VIA: Record<string, string> = {
  own_session: "from their own session",
  assigned_password: "from a session signed in with a password someone else set",
  operator_cli: "by the operator on the server",
  backfill: "before the key log existed (recorded when it was added)",
};

// ---- Python semantics ----------------------------------------------------------------

type Kind = "KeyError" | "TypeError" | "ValueError" | "IndexError" | "AttributeError";

/** An error the Python script would raise, by kind, so the same ones are caught. */
export class PyError extends Error {
  kind: Kind;
  constructor(kind: Kind, message: string) {
    super(`${kind}: ${message}`);
    this.kind = kind;
  }
}

function raise(kind: Kind, message: string): never {
  throw new PyError(kind, message);
}

function caught(e: unknown, ...kinds: Kind[]): PyError {
  if (e instanceof PyError && kinds.includes(e.kind)) return e;
  throw e;
}

/** A JSON number with a fraction or exponent: Python reads it as a float, not an int. */
export class PyFloat {
  value: number;
  constructor(value: number) {
    this.value = value;
  }
}

type Dict = Record<string, unknown>;

function dict(): Dict {
  return Object.create(null) as Dict;
}

function isDict(x: unknown): x is Dict {
  return typeof x === "object" && x !== null && !Array.isArray(x) && !(x instanceof PyFloat)
    && !(x instanceof Uint8Array);
}

function own(d: Dict, k: string): boolean {
  return Object.prototype.hasOwnProperty.call(d, k);
}

function typeName(x: unknown): string {
  if (x === null || x === undefined) return "NoneType";
  if (typeof x === "boolean") return "bool";
  if (typeof x === "number" || typeof x === "bigint") return "int";
  if (x instanceof PyFloat) return "float";
  if (typeof x === "string") return "str";
  if (Array.isArray(x)) return "list";
  if (x instanceof Uint8Array) return "bytes";
  return "dict";
}

function truthy(x: unknown): boolean {
  if (x === null || x === undefined) return false;
  if (typeof x === "boolean") return x;
  if (typeof x === "number") return x !== 0;
  if (typeof x === "bigint") return x !== 0n;
  if (typeof x === "string") return x.length > 0;
  if (x instanceof PyFloat) return x.value !== 0;
  if (Array.isArray(x)) return x.length > 0;
  if (x instanceof Uint8Array) return x.length > 0;
  return Object.keys(x as Dict).length > 0;
}

function numeric(x: unknown): number | bigint | undefined {
  if (typeof x === "boolean") return x ? 1 : 0;
  if (typeof x === "number" || typeof x === "bigint") return x;
  if (x instanceof PyFloat) return x.value;
  return undefined;
}

function numEq(a: number | bigint, b: number | bigint): boolean {
  if (typeof a === "number" && typeof b === "number") return a === b;
  const [big, other] = typeof a === "bigint" ? [a, b] : [b as bigint, a];
  if (typeof other === "bigint") return big === other;
  return Number.isInteger(other) && BigInt(other) === big;
}

function numLt(a: number | bigint, b: number | bigint): boolean {
  if (typeof a === "number" && typeof b === "number") return a < b;
  if (typeof a === "bigint" && typeof b === "bigint") return a < b;
  // One side is an int beyond 2**53, compared exactly: x < n iff floor(x) < n, and n < x iff n < ceil(x).
  if (typeof a === "number") {
    if (Number.isNaN(a)) return false;
    return Number.isFinite(a) ? BigInt(Math.floor(a)) < (b as bigint) : a < 0;
  }
  const f = b as number;
  if (Number.isNaN(f)) return false;
  return Number.isFinite(f) ? a < BigInt(Math.ceil(f)) : f > 0;
}

/** Python's ==. */
export function pyEq(a: unknown, b: unknown): boolean {
  const na = numeric(a), nb = numeric(b);
  if (na !== undefined || nb !== undefined) return na !== undefined && nb !== undefined && numEq(na, nb);
  if (a === null || a === undefined) return b === null || b === undefined;
  if (typeof a === "string") return a === b;
  if (Array.isArray(a)) return Array.isArray(b) && a.length === b.length && a.every((x, i) => pyEq(x, b[i]));
  if (a instanceof Uint8Array) return b instanceof Uint8Array && bytesEq(a, b);
  if (isDict(a)) {
    if (!isDict(b)) return false;
    const ka = Object.keys(a), kb = Object.keys(b);
    return ka.length === kb.length && ka.every((k) => own(b, k) && pyEq(a[k], b[k]));
  }
  return false;
}

/** The key Python's dict and set would file x under; lists and dicts cannot be keys. */
function pyKey(x: unknown): string {
  if (x === null || x === undefined) return "N";
  if (typeof x === "string") return "s" + x;
  const n = numeric(x);
  if (n !== undefined) {
    if (typeof n === "bigint") return "n" + n.toString();
    if (Number.isInteger(n)) return "n" + BigInt(n).toString();
    return "f" + String(n);
  }
  return raise("TypeError", `unhashable type: '${typeName(x)}'`);
}

/** A Python dict keyed by report values. */
class PyMap<V> {
  private m = new Map<string, V>();
  set(k: unknown, v: V): void { this.m.set(pyKey(k), v); }
  get(k: unknown): V | undefined { return this.m.get(pyKey(k)); }
  has(k: unknown): boolean { return this.m.has(pyKey(k)); }
}

/** o[k] for a string key. */
function at(o: unknown, k: string): unknown {
  if (isDict(o)) return own(o, k) ? o[k] : raise("KeyError", `'${k}'`);
  if (Array.isArray(o)) return raise("TypeError", "list indices must be integers or slices, not str");
  if (typeof o === "string") return raise("TypeError", "string indices must be integers, not 'str'");
  return raise("TypeError", `'${typeName(o)}' object is not subscriptable`);
}

/** o.get(k, d). */
function getk(o: unknown, k: string, d: unknown = null): unknown {
  if (!isDict(o)) return raise("AttributeError", `'${typeName(o)}' object has no attribute 'get'`);
  return own(o, k) ? o[k] : d;
}

/** a or b. */
function or<T>(a: unknown, b: T): unknown {
  return truthy(a) ? a : b;
}

function iter(x: unknown): unknown[] {
  if (Array.isArray(x)) return x;
  if (typeof x === "string") return Array.from(x);
  if (isDict(x)) return Object.keys(x);
  return raise("TypeError", `'${typeName(x)}' object is not iterable`);
}

/** item in container. */
function pyIn(item: unknown, container: unknown): boolean {
  if (isDict(container)) {
    pyKey(item);
    return typeof item === "string" && own(container, item);
  }
  if (Array.isArray(container)) return container.some((x) => pyEq(item, x));
  if (typeof container === "string") {
    if (typeof item !== "string") return raise("TypeError", "'in <string>' requires string as left operand");
    return container.includes(item);
  }
  return raise("TypeError", `argument of type '${typeName(container)}' is not iterable`);
}

function floatRepr(x: number): string {
  if (Number.isNaN(x)) return "nan";
  if (x === Infinity) return "inf";
  if (x === -Infinity) return "-inf";
  if (x === 0) return Object.is(x, -0) ? "-0.0" : "0.0";
  // The shortest digits that round-trip, as both languages choose them, laid out as Python's repr.
  const sign = x < 0 ? "-" : "";
  const s = String(Math.abs(x));
  let digits: string, exp: number;
  const m = s.match(/^(\d+)(?:\.(\d+))?e([+-]\d+)$/);
  if (m) {
    digits = m[1] + (m[2] ?? "");
    exp = Number(m[3]) + m[1].length - 1;
  } else {
    const [ip, fp = ""] = s.split(".");
    if (ip !== "0") {
      digits = ip + fp;
      exp = ip.length - 1;
    } else {
      const lead = fp.match(/^0*/)![0].length;
      digits = fp.slice(lead);
      exp = -lead - 1;
    }
  }
  digits = digits.replace(/0+$/, "") || "0";
  if (exp >= -4 && exp < 16) {
    if (exp >= 0) {
      const ip = digits.length > exp + 1 ? digits.slice(0, exp + 1) : digits.padEnd(exp + 1, "0");
      return `${sign}${ip}.${digits.slice(exp + 1) || "0"}`;
    }
    return `${sign}0.${"0".repeat(-exp - 1)}${digits}`;
  }
  const mant = digits.length > 1 ? `${digits[0]}.${digits.slice(1)}` : digits;
  return `${sign}${mant}e${exp < 0 ? "-" : "+"}${String(Math.abs(exp)).padStart(2, "0")}`;
}

function strRepr(s: string): string {
  const q = s.includes("'") && !s.includes('"') ? '"' : "'";
  let out = q;
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if (ch === "\\") out += "\\\\";
    else if (ch === q) out += "\\" + q;
    else if (ch === "\t") out += "\\t";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (c < 0x20 || c === 0x7f) out += "\\x" + c.toString(16).padStart(2, "0");
    else if (ch !== " " && /[\p{C}\p{Z}]/u.test(ch)) {
      out += c <= 0xff ? "\\x" + c.toString(16).padStart(2, "0")
        : c <= 0xffff ? "\\u" + c.toString(16).padStart(4, "0") : "\\U" + c.toString(16).padStart(8, "0");
    } else out += ch;
  }
  return out + q;
}

function pyRepr(x: unknown): string {
  if (typeof x === "string") return strRepr(x);
  if (Array.isArray(x)) return "[" + x.map(pyRepr).join(", ") + "]";
  if (isDict(x)) return "{" + Object.keys(x).map((k) => `${strRepr(k)}: ${pyRepr(x[k])}`).join(", ") + "}";
  return pyStr(x);
}

/** str(x), which is also what an f-string shows. */
export function pyStr(x: unknown): string {
  if (x === null || x === undefined) return "None";
  if (x === true) return "True";
  if (x === false) return "False";
  if (typeof x === "number") return String(x === 0 ? 0 : x);
  if (typeof x === "bigint") return x.toString();
  if (x instanceof PyFloat) return floatRepr(x.value);
  if (typeof x === "string") return x;
  return pyRepr(x);
}

function intAdd(a: number | bigint, b: number | bigint): number | bigint {
  const s = BigInt(a) + BigInt(b);
  return s >= BigInt(Number.MIN_SAFE_INTEGER) && s <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(s) : s;
}

/** a + b. */
function pyAdd(a: unknown, b: unknown): unknown {
  if (typeof a === "string" && typeof b === "string") return a + b;
  const na = numeric(a), nb = numeric(b);
  if (na !== undefined && nb !== undefined) {
    if (a instanceof PyFloat || b instanceof PyFloat) return new PyFloat(Number(na) + Number(nb));
    return intAdd(na, nb);
  }
  if (Array.isArray(a) && Array.isArray(b)) return [...a, ...b];
  return raise("TypeError", `unsupported operand type(s) for +: '${typeName(a)}' and '${typeName(b)}'`);
}

function codePointLt(a: string, b: string): boolean {
  const x = Array.from(a), y = Array.from(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const cx = x[i].codePointAt(0)!, cy = y[i].codePointAt(0)!;
    if (cx !== cy) return cx < cy;
  }
  return x.length < y.length;
}

/** a < b. */
function pyLt(a: unknown, b: unknown): boolean {
  const na = numeric(a), nb = numeric(b);
  if (na !== undefined && nb !== undefined) return numLt(na, nb);
  if (typeof a === "string" && typeof b === "string") return codePointLt(a, b);
  if (Array.isArray(a) && Array.isArray(b)) {
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      if (!pyEq(a[i], b[i])) return pyLt(a[i], b[i]);
    }
    return a.length < b.length;
  }
  return raise("TypeError", `'<' not supported between instances of '${typeName(a)}' and '${typeName(b)}'`);
}

/** sorted(xs, key=key): keys are computed first, then a stable sort that uses only <. */
function sortedBy<T>(xs: T[], key: (x: T) => unknown): T[] {
  const keyed = xs.map((x) => ({ x, k: key(x) }));
  keyed.sort((p, q) => (pyLt(p.k, q.k) ? -1 : pyLt(q.k, p.k) ? 1 : 0));
  return keyed.map((p) => p.x);
}

// str.strip(): Python's whitespace, which is not quite JavaScript's.
const PY_SPACE = "\t\n\x0b\x0c\r\x1c\x1d\x1e\x1f \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007" +
                 "\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000";

function strip(x: unknown): string {
  if (typeof x !== "string") return raise("AttributeError", `'${typeName(x)}' object has no attribute 'strip'`);
  let i = 0, j = x.length;
  while (i < j && PY_SPACE.includes(x[i])) i++;
  while (j > i && PY_SPACE.includes(x[j - 1])) j--;
  return x.slice(i, j);
}

function join(sep: string, xs: unknown): string {
  return iter(xs).map((x) => (typeof x === "string" ? x : raise("TypeError", "sequence item: expected str instance"))).join(sep);
}

/** s[:n] for a string. */
function head(s: unknown, n: number): string {
  if (typeof s === "string") return Array.from(s).slice(0, n).join("");
  if (Array.isArray(s)) return pyRepr(s.slice(0, n));
  return raise("TypeError", `'${typeName(s)}' object is not subscriptable`);
}

function plural(n: number, one: string, many: string): string {
  return n === 1 ? one : many;
}

// ---- JSON as Python reads and writes it ----------------------------------------------------

/** json.loads: ints stay ints (beyond 2**53 as BigInt), floats are PyFloat, NaN and Infinity are read. */
export function pyLoads(text: string): unknown {
  if (text.startsWith("\ufeff")) raise("ValueError", "Unexpected UTF-8 BOM (decode using utf-8-sig)");
  let i = 0;
  const fail = (what: string): never => raise("ValueError", `${what}: char ${i}`);
  const ws = () => { while (i < text.length && " \t\n\r".includes(text[i])) i++; };
  const num = /-?(?:0|[1-9]\d*)(\.\d+)?([eE][-+]?\d+)?/y;

  function str(): string {
    i++;                                                    // the opening quote
    let out = "";
    for (;;) {
      if (i >= text.length) fail("Unterminated string starting at");
      const c = text[i];
      if (c === '"') { i++; return out; }
      if (c < " ") fail("Invalid control character at");
      if (c !== "\\") { out += c; i++; continue; }
      const e = text[i + 1];
      if (e === undefined) fail("Unterminated string starting at");
      const simple: Record<string, string> = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
      if (e in simple) { out += simple[e]; i += 2; continue; }
      if (e !== "u") fail("Invalid \\escape");
      const hex = text.slice(i + 2, i + 6);
      if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail("Invalid \\uXXXX escape");
      out += String.fromCharCode(parseInt(hex, 16));         // UTF-16 code units: pairs join by themselves
      i += 6;
    }
  }

  function value(depth: number): unknown {
    if (depth > 990) throw new Error("the report is nested too deeply to read");
    ws();
    const c = text[i];
    if (c === "{") {
      i++;
      const o = dict();
      ws();
      if (text[i] === "}") { i++; return o; }
      for (;;) {
        ws();
        if (text[i] !== '"') fail("Expecting property name enclosed in double quotes");
        const k = str();
        ws();
        if (text[i] !== ":") fail("Expecting ':' delimiter");
        i++;
        o[k] = value(depth + 1);
        ws();
        if (text[i] === "}") { i++; return o; }
        if (text[i] !== ",") fail("Expecting ',' delimiter");
        i++;
      }
    }
    if (c === "[") {
      i++;
      const a: unknown[] = [];
      ws();
      if (text[i] === "]") { i++; return a; }
      for (;;) {
        a.push(value(depth + 1));
        ws();
        if (text[i] === "]") { i++; return a; }
        if (text[i] !== ",") fail("Expecting ',' delimiter");
        i++;
      }
    }
    if (c === '"') return str();
    for (const [word, v] of [["null", null], ["true", true], ["false", false], ["NaN", new PyFloat(NaN)],
                             ["Infinity", new PyFloat(Infinity)], ["-Infinity", new PyFloat(-Infinity)]] as const) {
      if (text.startsWith(word, i)) { i += word.length; return v; }
    }
    num.lastIndex = i;
    const m = num.exec(text);
    if (!m) return fail("Expecting value");
    i += m[0].length;
    if (m[1] === undefined && m[2] === undefined) {
      if (m[0].replace("-", "").length > 4300) raise("ValueError", "Exceeds the limit (4300 digits) for integer string conversion");
      const n = BigInt(m[0]);
      return n >= BigInt(Number.MIN_SAFE_INTEGER) && n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : n;
    }
    return new PyFloat(Number(m[0]));
  }

  const v = value(0);
  ws();
  if (i !== text.length) fail("Extra data");
  return v;
}

function jsonStr(s: string, ascii: boolean): string {
  let out = '"';
  for (let k = 0; k < s.length; k++) {
    const c = s.charCodeAt(k);
    const ch = s[k];
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\f") out += "\\f";
    else if (c < 0x20 || (ascii && c > 0x7e)) out += "\\u" + c.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

/** json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=ascii). */
export function canonical(obj: unknown, ascii = false): string {
  if (obj === null || obj === undefined) return "null";
  if (obj === true) return "true";
  if (obj === false) return "false";
  if (typeof obj === "number") return String(obj === 0 ? 0 : obj);
  if (typeof obj === "bigint") return obj.toString();
  if (obj instanceof PyFloat) {
    const v = obj.value;
    return Number.isNaN(v) ? "NaN" : v === Infinity ? "Infinity" : v === -Infinity ? "-Infinity" : floatRepr(v);
  }
  if (typeof obj === "string") return jsonStr(obj, ascii);
  if (Array.isArray(obj)) return "[" + obj.map((x) => canonical(x, ascii)).join(",") + "]";
  if (isDict(obj)) {
    const keys = Object.keys(obj).sort((a, b) => (codePointLt(a, b) ? -1 : codePointLt(b, a) ? 1 : 0));
    return "{" + keys.map((k) => jsonStr(k, ascii) + ":" + canonical(obj[k], ascii)).join(",") + "}";
  }
  return raise("TypeError", `Object of type ${typeName(obj)} is not JSON serializable`);
}

// ---- hashes and bytes --------------------------------------------------------------------

type Hash = "SHA-256" | "SHA-384" | "SHA-512";

function subtle(): SubtleCrypto {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new Error("this browser offers no WebCrypto here (the page must be served over HTTPS)");
  return s;
}

async function digest(alg: Hash, data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().digest(alg, data));
}

function hex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

function fromHex(s: string): Uint8Array {
  return Uint8Array.from(s.match(/../g) ?? [], (x) => parseInt(x, 16));
}

/** text.encode(): UTF-8, and a lone surrogate cannot be encoded. */
function encode(text: unknown): Uint8Array {
  if (typeof text !== "string") return raise("AttributeError", `'${typeName(text)}' object has no attribute 'encode'`);
  if (/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(text)) {
    return raise("ValueError", "'utf-8' codec can't encode a surrogate");
  }
  return new TextEncoder().encode(text);
}

async function sha(text: unknown): Promise<string> {
  return hex(await digest("SHA-256", encode(text)));
}

function bytesEq(a: Uint8Array | null, b: Uint8Array | null): boolean {
  if (a === null || b === null) return a === b;
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function b64bytes(s: string): Uint8Array {
  const data = s.replace(/=+$/, "");
  const out: number[] = [];
  let acc = 0, bits = 0;
  for (const ch of data) {
    acc = (acc << 6) | B64.indexOf(ch);
    bits += 6;
    if (bits >= 8) { bits -= 8; out.push((acc >> bits) & 0xff); }
  }
  return Uint8Array.from(out);
}

function b64Shape(s: string): boolean {
  const pads = s.length - s.replace(/=+$/, "").length, data = s.length - pads;
  return (data % 4 === 0 && pads === 0) || (data % 4 === 2 && pads === 2) || (data % 4 === 3 && pads === 1);
}

/** base64.b64decode(s, validate=True). */
function b64decode(s: unknown): Uint8Array {
  if (typeof s !== "string") return raise("TypeError", `argument should be a bytes-like object or ASCII string, not '${typeName(s)}'`);
  if (/[^\x00-\x7f]/.test(s)) return raise("ValueError", "string argument should contain only ASCII characters");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return raise("ValueError", "Only base64 data is allowed");
  if (!b64Shape(s)) return raise("ValueError", "Incorrect padding");
  return b64bytes(s);
}

/** base64.b64decode(s) without validate, as for a PEM block: other characters are dropped. */
function b64decodeLoose(s: string): Uint8Array {
  const kept = s.replace(/[^A-Za-z0-9+/=]/g, "");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(kept) || !b64Shape(kept)) return raise("ValueError", "Incorrect padding");
  return b64bytes(kept);
}

function b64encode(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i += 3) {
    const n = (b[i] << 16) | ((b[i + 1] ?? 0) << 8) | (b[i + 2] ?? 0);
    s += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + (i + 1 < b.length ? B64[(n >> 6) & 63] : "=") + (i + 2 < b.length ? B64[n & 63] : "=");
  }
  return s;
}

function bigFrom(b: Uint8Array): bigint {
  return b.length ? BigInt("0x" + hex(b)) : 0n;
}

function bigTo(n: bigint, size: number): Uint8Array | null {
  const h = n.toString(16);
  if (h.length > size * 2) return null;
  return fromHex(h.padStart(size * 2, "0"));
}

// ---- times, as datetime has them ---------------------------------------------------------

/** An aware datetime: microseconds since the epoch in UTC, and the UTC offset in seconds. */
interface Time {
  us: bigint;
  off: number;
}

const DAY_US = 86_400_000_000n;

function daysFromCivil(y: number, m: number, d: number): number {
  y -= m <= 2 ? 1 : 0;
  const era = Math.floor(y / 400);
  const yoe = y - era * 400;
  const doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return era * 146097 + doe - 719468;
}

function daysIn(y: number, m: number): number {
  return [31, (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0 ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1];
}

function makeTime(y: number, mo: number, d: number, h: number, mi: number, s: number, us: number, off: number): Time {
  if (!(y >= 1 && y <= 9999)) raise("ValueError", `year ${y} is out of range`);
  if (!(mo >= 1 && mo <= 12)) raise("ValueError", "month must be in 1..12");
  if (!(d >= 1 && d <= daysIn(y, mo))) raise("ValueError", "day is out of range for month");
  if (!(h >= 0 && h <= 23)) raise("ValueError", "hour must be in 0..23");
  if (!(mi >= 0 && mi <= 59)) raise("ValueError", "minute must be in 0..59");
  if (!(s >= 0 && s <= 59)) raise("ValueError", "second must be in 0..59");
  const wall = BigInt(daysFromCivil(y, mo, d)) * DAY_US + BigInt(((h * 60 + mi) * 60 + s)) * 1_000_000n + BigInt(us);
  return { us: wall - BigInt(Math.round(off * 1e6)), off };
}

function fraction(f: string | undefined): number {
  return f ? Number((f + "000000").slice(0, 6)) : 0;
}

/** datetime.fromisoformat for the forms reports use (Python 3.11+ reads a few more, such as week dates). */
function fromIso(text: unknown): Time & { naive: boolean } {
  if (typeof text !== "string") return raise("TypeError", "fromisoformat: argument must be str");
  const tz = "(Z|[+-]\\d{2}(?::?\\d{2}(?::?\\d{2}(?:\\.\\d{1,6})?)?)?)?";
  const time = `(\\d{2})(?::?(\\d{2})(?::?(\\d{2})(?:[.,](\\d+))?)?)?${tz}`;
  const m = text.match(new RegExp(`^(\\d{4})-(\\d{2})-(\\d{2})(?:[\\s\\S]${time})?$`))
    ?? text.match(new RegExp(`^(\\d{4})(\\d{2})(\\d{2})(?:T${time})?$`));
  if (!m) return raise("ValueError", `Invalid isoformat string: ${strRepr(text)}`);
  const [, y, mo, d, h = "0", mi = "0", s = "0", f, z] = m;
  let off = 0;
  if (z && z !== "Z") {
    const zm = z.match(/^([+-])(\d{2}):?(\d{2})?:?(\d{2})?(?:\.(\d{1,6}))?$/)!;
    off = (Number(zm[2]) * 3600 + Number(zm[3] ?? 0) * 60 + Number(zm[4] ?? 0) + fraction(zm[5]) / 1e6) * (zm[1] === "-" ? -1 : 1);
    if (Math.abs(off) >= 86400) raise("ValueError", "offset must be a timedelta strictly between -timedelta(hours=24) and timedelta(hours=24)");
  }
  const t = makeTime(+y, +mo, +d, +h, +mi, +s, fraction(f), off);
  return { ...t, naive: z === undefined };
}

/** _utc: naive times are UTC; whole_seconds drops the microseconds. */
function utc(text: unknown, wholeSeconds = false): Time {
  const t = fromIso(text);
  if (!wholeSeconds) return { us: t.us, off: t.off };
  const offUs = BigInt(Math.round(t.off * 1e6));
  const wall = t.us + offUs;
  const micro = ((wall % 1_000_000n) + 1_000_000n) % 1_000_000n;
  return { us: t.us - micro, off: t.off };
}

function parts(t: Time) {
  const wall = t.us + BigInt(Math.round(t.off * 1e6));
  const days = wall >= 0n ? wall / DAY_US : -((-wall + DAY_US - 1n) / DAY_US);
  const rest = wall - days * DAY_US;
  const date = new Date(Number(days) * 86_400_000);
  const sec = Number(rest / 1_000_000n);
  return { y: date.getUTCFullYear(), mo: date.getUTCMonth() + 1, d: date.getUTCDate(),
           h: Math.floor(sec / 3600), mi: Math.floor(sec / 60) % 60, s: sec % 60, us: Number(rest % 1_000_000n) };
}

const p2 = (n: number) => String(n).padStart(2, "0");

/** strftime("%Y-%m-%d %H:%M UTC"), on the time as written (reports write UTC). */
function stamp(t: Time): string {
  const p = parts(t);
  return `${String(p.y).padStart(4, "0")}-${p2(p.mo)}-${p2(p.d)} ${p2(p.h)}:${p2(p.mi)} UTC`;
}

function isoformat(t: Time): string {
  const p = parts(t);
  let s = `${String(p.y).padStart(4, "0")}-${p2(p.mo)}-${p2(p.d)}T${p2(p.h)}:${p2(p.mi)}:${p2(p.s)}`;
  if (p.us) s += "." + String(p.us).padStart(6, "0");
  const sign = t.off < 0 ? "-" : "+";
  const a = Math.abs(t.off), whole = Math.floor(a);
  s += `${sign}${p2(Math.floor(whole / 3600))}:${p2(Math.floor(whole / 60) % 60)}`;
  if (whole % 60 || a !== whole) s += ":" + p2(whole % 60);
  if (a !== whole) s += "." + String(Math.round((a - whole) * 1e6)).padStart(6, "0");
  return s;
}

// ---- 1-3: body, chain, receipts ---------------------------------------------------------

type Problems = string[];
type Notes = string[];

async function checkBody(r: Dict): Promise<Problems> {
  const body = dict();
  for (const k of Object.keys(r)) if (k !== "integrity") body[k] = r[k];
  const want = getk(getk(r, "integrity", dict()), "body_sha256");
  const got = await sha(canonical(body));
  return pyEq(got, want) ? [] : [`report body hash mismatch (recorded ${pyStr(want)}, computed ${got})`];
}

async function checkChain(r: Dict): Promise<[Problems, Notes]> {
  const problems: Problems = [], notes: Notes = [];
  let prev = getk(getk(r, "integrity", dict()), "chain_genesis", GENESIS);
  if (!pyEq(prev, GENESIS)) problems.push("unexpected chain genesis value");
  let removed = 0, n = 0;
  for (const e of iter(at(r, "evidence"))) {
    n += 1;
    const seq = pyStr(at(e, "seq"));
    if (!pyEq(at(e, "seq"), n)) problems.push(`evidence #${seq}: out of sequence (expected #${n})`);
    if (!pyEq(at(e, "prev_hash"), prev)) problems.push(`evidence #${seq}: does not link to the previous entry`);
    const v = getk(e, "v");
    if (v !== null && !pyEq(v, 2)) {
      problems.push(`evidence #${seq}: unknown record version ${pyStr(v)}`);
    } else {
      const rec = dict();
      for (const k of v === null ? CHAIN_FIELDS : CHAIN_FIELDS_V2) rec[k] = at(e, k);
      if (!pyEq(await sha(pyAdd(at(e, "prev_hash"), canonical(rec))), at(e, "chain_hash"))) {
        problems.push(`evidence #${seq}: content does not match its chain hash`);
      }
      if (v !== null) {
        const summary = getk(e, "summary");
        if (summary === null) removed += 1;
        else if (!pyEq(await sha(summary), at(e, "summary_sha256"))) {
          problems.push(`evidence #${seq}: its summary does not match the summary hash in the chain`);
        }
      }
    }
    prev = at(e, "chain_hash");
  }
  const head = at(at(r, "summary"), "chain_head");
  if (!pyEq(head, prev)) problems.push("summary chain head does not match the last evidence entry");
  if (removed) {
    notes.push(`${removed} evidence ${plural(removed, "entry has", "entries have")} no content in this report (removed under the `
               + "retention policy); the chain still verifies over the hashes");
  }
  return [problems, notes];
}

function manifest(lane: unknown, evidence: unknown): Dict {
  // Mirrors the ledger's receipt manifest: items in order, the lane's evidence by id.
  const evs = sortedBy(iter(evidence).filter((e) => pyEq(at(e, "lane_id"), at(lane, "lane_id"))), (e) => at(e, "id"));
  const m = dict();
  m.lane = at(lane, "lane_id");
  m.role = at(lane, "role");
  m.host = at(lane, "host");
  m.items = sortedBy(iter(at(lane, "items")), (i) => at(i, "idx")).map((i) => {
    const o = dict();
    o.idx = at(i, "idx"); o.key = at(i, "key"); o.state = at(i, "state"); o.na_reason = at(i, "na_reason");
    return o;
  });
  m.evidence = evs.map((e) => {
    const o = dict();
    o.id = at(e, "id"); o.item = at(e, "item_id"); o.kind = at(e, "kind"); o.sha256 = at(e, "sha256");
    return o;
  });
  return m;
}

function label(lane: unknown): string {
  return `${pyStr(at(lane, "host"))} / ${pyStr(at(lane, "name"))}`;
}

async function checkReceipts(r: Dict): Promise<[Problems, Notes]> {
  const problems: Problems = [], notes: Notes = [];
  for (const lane of iter(at(r, "lanes"))) {
    const name = label(lane);
    const evs = iter(at(r, "evidence")).filter((e) => pyEq(at(e, "lane_id"), at(lane, "lane_id")));
    if (!pyEq(sortedBy(evs.map((e) => at(e, "id")), (x) => x), sortedBy(iter(at(lane, "evidence_ids")), (x) => x))) {
      problems.push(`${name}: evidence list does not match the ledger`);
    }
    const proven = new PyMap<true>();
    for (const e of evs) if (at(e, "item_id") !== null) proven.set(at(e, "item_id"), true);
    for (const i of iter(at(lane, "items"))) {
      if (pyEq(at(i, "state"), "done") && !proven.has(at(i, "item_id"))) {
        problems.push(`${name}: item ${pyStr(at(i, "key"))} is marked done without evidence`);
      }
      if (pyEq(at(i, "state"), "na") && !strip(or(at(i, "na_reason"), ""))) {
        problems.push(`${name}: item ${pyStr(at(i, "key"))} is N/A without a reason`);
      }
    }
    const rc = at(lane, "receipt");
    if (pyEq(at(lane, "status"), "closed")) {
      if (!truthy(rc)) {
        problems.push(`${name}: reported as receipted but has no receipt`);
        continue;
      }
      // The ledger hashes the manifest with ASCII-escaped JSON.
      const got = await sha(canonical(manifest(lane, at(r, "evidence")), true));
      if (!pyEq(got, at(rc, "manifest_sha256"))) problems.push(`${name}: receipt does not match its items and evidence`);
      if (iter(at(lane, "items")).some((i) => pyEq(at(i, "state"), "open"))) {
        problems.push(`${name}: reported as receipted with open items`);
      }
      if (!strip(or(getk(rc, "closed_by"), ""))) {
        notes.push(`${name}: receipt has no signer (issued before signatures were required)`);
      }
    } else if (pyEq(at(lane, "status"), "stale")) {
      notes.push(`${name}: receipt is void (the ledger changed after it was issued)`);
    }
  }
  return [problems, notes];
}

// ---- signatures ---------------------------------------------------------------------------

interface Curve {
  name: "P-256" | "P-384";
  p: bigint;
  a: bigint;
  b: bigint;
  n: bigint;
}

const P256: Curve = {
  name: "P-256",
  p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
  a: 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffcn,
  b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
  n: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
};

const P384: Curve = {
  name: "P-384",
  p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffffn,
  a: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffcn,
  b: 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aefn,
  n: 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973n,
};

function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r < 0n ? r + m : r;
}

function modpow(b: bigint, e: bigint, m: bigint): bigint {
  let r = 1n;
  b = mod(b, m);
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}

function bitLength(n: bigint): number {
  return n === 0n ? 0 : n.toString(2).length;
}

/** ECDSA over curve c (SEC 1, 4.1.4), given the message and (r, s). The script's checks on the
 * point and on r and s come first, then WebCrypto checks the signature itself. */
async function ecdsaVerify(c: Curve, point: Uint8Array, hash: Hash, message: Uint8Array, r: bigint, s: bigint): Promise<boolean> {
  const size = (bitLength(c.p) + 7) >> 3;
  if (point.length !== 1 + 2 * size || point[0] !== 4) return false;
  const x = bigFrom(point.subarray(1, 1 + size)), y = bigFrom(point.subarray(1 + size));
  if (!(x < c.p && y < c.p && mod(y * y - x * x * x - c.a * x - c.b, c.p) === 0n)) return false;
  if (!(1n <= r && r < c.n && 1n <= s && s < c.n)) return false;
  const rs = concat(bigTo(r, size)!, bigTo(s, size)!);
  try {
    const key = await subtle().importKey("raw", point, { name: "ECDSA", namedCurve: c.name }, false, ["verify"]);
    return await subtle().verify({ name: "ECDSA", hash }, key, rs, message);
  } catch {
    return false;
  }
}

async function p256Verify(point: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
  if (signature.length !== 64) return false;
  return ecdsaVerify(P256, point, "SHA-256", message, bigFrom(signature.subarray(0, 32)), bigFrom(signature.subarray(32)));
}

// Ed25519, RFC 8032: the script's own code, used only where WebCrypto has no Ed25519.
const ED_P = 2n ** 255n - 19n;
const ED_Q = 2n ** 252n + 27742317777372353535851937790883648493n;
const ED_D = mod(-121665n * modpow(121666n, ED_P - 2n, ED_P), ED_P);
const ED_I = modpow(2n, (ED_P - 1n) / 4n, ED_P);
type EdPoint = [bigint, bigint, bigint, bigint];

function edAdd(P: EdPoint, Q: EdPoint): EdPoint {
  const [x1, y1, z1, t1] = P, [x2, y2, z2, t2] = Q;
  const a = mod((y1 - x1) * (y2 - x2), ED_P), b = mod((y1 + x1) * (y2 + x2), ED_P);
  const c = mod(t1 * 2n * ED_D * t2, ED_P), d = mod(z1 * 2n * z2, ED_P);
  const e = b - a, f = d - c, g = d + c, h = b + a;
  return [mod(e * f, ED_P), mod(g * h, ED_P), mod(f * g, ED_P), mod(e * h, ED_P)];
}

function edMul(s: bigint, P: EdPoint): EdPoint {
  let Q: EdPoint = [0n, 1n, 1n, 0n];
  while (s > 0n) {
    if (s & 1n) Q = edAdd(Q, P);
    P = edAdd(P, P);
    s >>= 1n;
  }
  return Q;
}

function edEqual(P: EdPoint, Q: EdPoint): boolean {
  return mod(P[0] * Q[2] - Q[0] * P[2], ED_P) === 0n && mod(P[1] * Q[2] - Q[1] * P[2], ED_P) === 0n;
}

function littleEndian(b: Uint8Array): bigint {
  return bigFrom(Uint8Array.from(b).reverse());
}

function edDecompress(b: Uint8Array): EdPoint | null {
  if (b.length !== 32) return null;
  let y = littleEndian(b);
  const sign = y >> 255n;
  y &= (1n << 255n) - 1n;
  if (y >= ED_P) return null;
  const x2 = mod((y * y - 1n) * modpow(ED_D * y * y + 1n, ED_P - 2n, ED_P), ED_P);
  let x: bigint;
  if (x2 === 0n) {
    if (sign) return null;
    x = 0n;
  } else {
    x = modpow(x2, (ED_P + 3n) / 8n, ED_P);
    if (mod(x * x - x2, ED_P) !== 0n) x = mod(x * ED_I, ED_P);
    if (mod(x * x - x2, ED_P) !== 0n) return null;
    if ((x & 1n) !== sign) x = ED_P - x;
  }
  return [x, y, 1n, mod(x * y, ED_P)];
}

/** Whether 8P is the neutral point (the eight points of small order). */
function edSmallOrder(P: EdPoint): boolean {
  const P8 = edAdd(edAdd(edAdd(P, P), edAdd(P, P)), edAdd(edAdd(P, P), edAdd(P, P)));
  return P8[0] === 0n && P8[1] === P8[2];
}

const ED_G = edDecompress(fromHex("5866666666666666666666666666666666666666666666666666666666666666"))!;

/** How Ed25519 is checked: "auto" uses WebCrypto where the browser has it. */
export type Ed25519Mode = "auto" | "webcrypto" | "fallback";

let edNative: Promise<boolean> | null = null;

/** Whether this browser's WebCrypto verifies Ed25519 (checked on RFC 8032, test 1). */
export function ed25519Native(): Promise<boolean> {
  edNative ??= (async () => {
    try {
      const pub = fromHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
      const sig = fromHex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                          + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
      const key = await subtle().importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
      return await subtle().verify({ name: "Ed25519" }, key, sig, new Uint8Array(0));
    } catch {
      return false;
    }
  })();
  return edNative;
}

async function ed25519Verify(pub: Uint8Array, message: Uint8Array, signature: Uint8Array, mode: Ed25519Mode): Promise<boolean> {
  if (signature.length !== 64) return false;
  const A = edDecompress(pub), R = edDecompress(signature.subarray(0, 32));
  if (A === null || R === null) return false;
  const s = littleEndian(signature.subarray(32));
  if (s >= ED_Q) return false;
  // WebCrypto engines disagree on keys and R points of small order (OpenSSL refuses them; the
  // script's equation accepts some), so those are always left to the script's own code.
  if (!edSmallOrder(A) && !edSmallOrder(R) && (mode === "webcrypto" || (mode === "auto" && (await ed25519Native())))) {
    try {
      const key = await subtle().importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
      return await subtle().verify({ name: "Ed25519" }, key, signature, message);
    } catch {
      return false;
    }
  }
  const h = mod(littleEndian(await digest("SHA-512", concat(signature.subarray(0, 32), pub, message))), ED_Q);
  return edEqual(edMul(s, ED_G), edAdd(R, edMul(h, A)));
}

// SubjectPublicKeyInfo prefixes (DER) for the two key types.
const SPKI: Record<string, Uint8Array> = {
  "Ed25519": fromHex("302a300506032b6570032100"),
  "ECDSA-P256": fromHex("3059301306072a8648ce3d020106082a8648ce3d030107034200"),
};

async function verifySignature(algorithm: unknown, spki: Uint8Array, message: Uint8Array, signature: Uint8Array,
                               mode: Ed25519Mode): Promise<boolean> {
  pyKey(algorithm);
  const prefix = typeof algorithm === "string" && own(SPKI, algorithm) ? SPKI[algorithm] : null;
  if (prefix === null || !bytesEq(spki.subarray(0, prefix.length), prefix) || spki.length < prefix.length) return false;
  const raw = spki.subarray(prefix.length);
  return algorithm === "Ed25519" ? ed25519Verify(raw, message, signature, mode) : p256Verify(raw, message, signature);
}

function receiptsWord(n: number): string {
  return `${n} receipt` + (n === 1 ? "" : "s");
}

function closedLanes(r: Dict): unknown[] {
  return iter(at(r, "lanes")).filter((l) => truthy(at(l, "receipt")) && pyEq(at(l, "status"), "closed"));
}

function countReceipts(r: Dict, field: string): [number, number] {
  const rcs = closedLanes(r).map((l) => at(l, "receipt"));
  return [rcs.filter((rc) => truthy(getk(rc, field))).length, rcs.length];
}

function signerText(s: unknown): string {
  // A payload's signer as "Name (email)"; v2 payloads have no email.
  const d = isDict(s) ? s : dict();
  return truthy(getk(d, "email")) ? `${pyStr(getk(d, "name"))} (${pyStr(at(d, "email"))})` : pyStr(getk(d, "name"));
}

function loadsStr(x: unknown): unknown {
  if (typeof x !== "string") return raise("TypeError", `the JSON object must be str, bytes or bytearray, not ${typeName(x)}`);
  return pyLoads(x);
}

async function checkSignatures(r: Dict, require: boolean, mode: Ed25519Mode): Promise<[Problems, Notes]> {
  const problems: Problems = [], notes: Notes = [];
  let signed = 0, receipted = 0;
  const chain = new PyMap<unknown>();
  for (const e of iter(at(r, "evidence"))) chain.set(at(e, "seq"), at(e, "chain_hash"));
  for (const lane of iter(at(r, "lanes"))) {
    const rc = at(lane, "receipt");
    if (!truthy(rc) || !pyEq(at(lane, "status"), "closed")) continue;
    receipted += 1;
    const sig = getk(rc, "signature");
    const name = label(lane);
    if (!truthy(sig)) {
      if (require) problems.push(`${name}: the receipt is not signed`);
      continue;
    }
    signed += 1;
    let spki: Uint8Array, value: Uint8Array, payload: unknown;
    try {
      spki = b64decode(at(sig, "public_key"));
      value = b64decode(at(sig, "value"));
      payload = loadsStr(at(sig, "payload"));
    } catch (e) {
      caught(e, "ValueError", "KeyError", "TypeError");
      problems.push(`${name}: signature fields cannot be read`);
      continue;
    }
    if (!pyEq(hex(await digest("SHA-256", spki)), getk(sig, "key_fingerprint"))) {
      problems.push(`${name}: the public key does not match its fingerprint`);
    }
    if (!(await verifySignature(getk(sig, "algorithm", ""), spki, encode(at(sig, "payload")), value, mode))) {
      problems.push(`${name}: the signature does not verify`);
    }
    if (!pyIn(getk(payload, "format"), PAYLOAD_FORMATS)) problems.push(`${name}: unknown signed payload format`);
    else if (!pyEq(at(payload, "format"), PAYLOAD_FORMATS[0])
             && typeof getk(or(getk(payload, "signer"), dict()), "email") !== "string") {
      problems.push(`${name}: the signed payload does not name the signer's email`);
    }
    if (!pyEq(getk(payload, "manifest_sha256"), at(rc, "manifest_sha256"))) {
      problems.push(`${name}: the signature covers a different manifest`);
    }
    if (!pyEq(getk(or(getk(payload, "lane"), dict()), "id"), at(lane, "lane_id"))) {
      problems.push(`${name}: the signature names another lane`);
    }
    if (!pyEq(getk(payload, "key_fingerprint"), getk(sig, "key_fingerprint"))) {
      problems.push(`${name}: the signed payload names another key`);
    }
    const c = or(getk(payload, "chain"), dict());
    if (!(pyEq(getk(c, "seq"), 0) && pyEq(getk(c, "head"), GENESIS)) && !pyEq(chain.get(getk(c, "seq")) ?? null, getk(c, "head"))) {
      problems.push(`${name}: the signed evidence chain head is not in this report`);
    }
    if (!problems.length) {
      notes.push(`${name}: signed by ${signerText(getk(payload, "signer"))} with key `
                 + `${head(getk(sig, "key_fingerprint", ""), 16)} (${pyStr(getk(sig, "algorithm"))})`);
    }
  }
  if (receipted && signed < receipted) {
    notes.push(`${receipted - signed} of ${receiptsWord(receipted)} ${receipted - signed === 1 ? "is" : "are"} not signed (a name only)`);
  }
  return [problems, notes];
}

// ---- the key log and the audit log ------------------------------------------------------------

type Rec = [Time, unknown];

/** The links and records of a hash-chained log in a report (the key log, the audit log). Returns
 * the problems and the records in chain order, or null for the records when the links cannot be read. */
async function checkLog(log: unknown, what: string, fields: string[]): Promise<[Problems, Rec[] | null]> {
  const problems: Problems = [];
  if (!pyEq(getk(log, "genesis"), GENESIS)) problems.push(`unexpected ${what} genesis value`);
  const links = iter(or(getk(log, "links"), []));
  let prev: unknown = null;
  for (let n = 0; n < links.length; n++) {
    const ln = links[n];
    let seq: unknown, ph: unknown, rsha: unknown, eh: unknown;
    try {
      [seq, ph, rsha, eh] = [at(ln, "seq"), at(ln, "prev_hash"), at(ln, "record_sha256"), at(ln, "entry_hash")];
    } catch (e) {
      caught(e, "KeyError", "TypeError");
      problems.push(`a ${what} link cannot be read`);
      return [problems, null];
    }
    if (n === 0 && pyEq(seq, 1) && !pyEq(ph, GENESIS)) problems.push(`${what} entry #1 does not start from the genesis value`);
    if (n > 0) {
      const expected = pyAdd(at(links[n - 1], "seq"), 1);
      if (!pyEq(seq, expected)) problems.push(`${what} entry #${pyStr(seq)}: out of sequence (expected #${pyStr(expected)})`);
    }
    if (n > 0 && !pyEq(ph, prev)) problems.push(`${what} entry #${pyStr(seq)}: does not link to the previous entry`);
    if (!pyEq(await sha(pyAdd(ph, rsha)), eh)) problems.push(`${what} entry #${pyStr(seq)}: does not match its chain hash`);
    prev = eh;
  }
  const headLink = or(getk(log, "head"), dict());
  if (links.length && (!pyEq(getk(headLink, "seq"), at(links[links.length - 1], "seq"))
                       || !pyEq(getk(headLink, "entry_hash"), at(links[links.length - 1], "entry_hash")))) {
    problems.push(`the ${what} head does not match its last link`);
  }
  const bySeq = new PyMap<unknown>();
  for (const ln of links) bySeq.set(at(ln, "seq"), ln);
  const records: Rec[] = [];
  let latest: Time | null = null;
  for (const e of sortedBy(iter(or(getk(log, "entries"), [])), (e) => or(getk(e, "seq"), 0))) {
    const ln = bySeq.get(getk(e, "seq"));
    if (ln === undefined) {
      problems.push(`${what} entry #${pyStr(getk(e, "seq"))} is not in the chain the report carries`);
    } else {
      const rec = dict();
      for (const k of fields) rec[k] = getk(e, k);
      if (!pyEq(await sha(canonical(rec)), at(ln, "record_sha256"))) {
        problems.push(`${what} entry #${pyStr(getk(e, "seq"))}: content does not match its record hash`);
      }
    }
    let t: Time;
    try {
      t = utc(at(e, "at"));
    } catch (err) {
      caught(err, "ValueError", "KeyError", "TypeError");
      problems.push(`${what} entry #${pyStr(getk(e, "seq"))}: its time cannot be read`);
      continue;
    }
    if (latest !== null && t.us < latest.us) {             // appended later, but dated earlier
      problems.push(`${what} entry #${pyStr(getk(e, "seq"))} is dated before an earlier entry`);
    }
    latest = latest === null || t.us > latest.us ? t : latest;
    records.push([t, e]);
  }
  return [problems, records];
}

async function checkKeyLog(r: Dict): Promise<[Problems, Notes]> {
  const notes: Notes = [];
  const signed = closedLanes(r).filter((l) => truthy(getk(at(l, "receipt"), "signature")));
  const log = getk(r, "key_log");
  if (log === null) {
    if (signed.length) {
      notes.push("this report has no key history (made before the key log); compare each signer's key "
                 + "fingerprint with the one they give you");
    }
    return [[], notes];
  }
  const [problems, records] = await checkLog(log, "key log", KEY_LOG_FIELDS);
  if (records === null) return [problems, notes];
  const history = new PyMap<unknown[]>();
  for (const [, e] of records) {
    const k = getk(e, "key_fingerprint");
    if (!history.has(k)) history.set(k, []);
    history.get(k)!.push(e);
  }
  const described = new PyMap<true>();
  for (const lane of signed) {
    const name = label(lane);
    const sig = at(at(lane, "receipt"), "signature");
    const fp = or(getk(sig, "key_fingerprint"), "");
    let issued: Time, signer: unknown;
    try {
      const payload = loadsStr(at(sig, "payload"));
      [issued, signer] = [utc(at(payload, "issued_at")), at(payload, "signer")];
    } catch (e) {
      caught(e, "ValueError", "KeyError", "TypeError");
      problems.push(`${name}: the signed payload cannot be read`);
      continue;
    }
    const events = history.get(fp) ?? [];
    const reg = events.find((e) => pyEq(getk(e, "event"), "registered"));
    const short = () => head(fp, 16);
    if (reg === undefined) {
      problems.push(`${name}: the key log has no registration for key ${short()}`);
      continue;
    }
    const mine: Problems = [];
    let revoked: unknown[];
    try {
      if (!pyEq(getk(reg, "user_id"), getk(signer, "id"))) {
        mine.push(`${name}: key ${short()} is registered to ${pyStr(getk(reg, "user_name"))}, not the signer`);
      }
      // A payload's issue time is in whole seconds; compare key log times the same way.
      if (utc(at(reg, "at"), true).us > issued.us) mine.push(`${name}: key ${short()} was registered after the receipt was issued`);
      revoked = events.filter((e) => pyEq(getk(e, "event"), "revoked"));
      for (const e of revoked) {
        if (pyLt(at(e, "seq"), at(reg, "seq"))) mine.push(`${name}: key ${short()} was revoked before it was registered`);
        if (utc(at(e, "at"), true).us < issued.us) mine.push(`${name}: key ${short()} was revoked before the receipt was issued`);
      }
    } catch (e) {
      caught(e, "ValueError", "KeyError", "TypeError", "AttributeError");
      mine.push(`${name}: the key log entries for key ${short()} cannot be read`);
      revoked = [];
    }
    problems.push(...mine);
    if (!mine.length && !described.has(fp)) {
      described.set(fp, true);
      const when = stamp(utc(at(reg, "at")));
      const later = revoked.length ? `; revoked ${stamp(utc(at(revoked[0], "at")))}, after it signed` : "";
      const via = getk(reg, "via");
      notes.push(`${signerText(signer)} signed with key ${short()}, registered ${when} `
                 + `${typeof via === "string" && own(KEY_VIA, via) ? KEY_VIA[via] : (pyKey(via), "in a way this verifier does not know")}${later}`);
    }
  }
  return [problems, notes];
}

const ACTORS: Record<string, string> = {
  token: "the operator token", cli: "the operator on the server", open: "open mode", backfill: "the audit log backfill",
};

function actorText(a: unknown): string {
  const d = isDict(a) ? a : dict();
  if (pyEq(getk(d, "kind"), "person")) {
    return truthy(getk(d, "email")) ? `${pyStr(getk(d, "name"))} (${pyStr(getk(d, "email"))})` : pyStr(getk(d, "name"));
  }
  const kind = getk(d, "kind");
  pyKey(kind);
  return typeof kind === "string" && own(ACTORS, kind) ? ACTORS[kind] : pyStr(kind);
}

function scopeText(s: unknown): string {
  const words = (v: unknown) => (truthy(v) ? join(", ", v) : "none");
  const out = [`in scope ${words(getk(s, "include"))}`, `out of scope ${words(getk(s, "exclude"))}`,
               `${pyStr(getk(s, "rate_limit_rps"))} requests per second`];
  if (truthy(getk(s, "research_header"))) out.push(`header ${pyStr(at(s, "research_header"))}`);
  if (truthy(getk(s, "research_user_agent"))) out.push(`user agent ${pyStr(at(s, "research_user_agent"))}`);
  if (truthy(getk(s, "enabled_modules"))) out.push(`opt-in modules ${words(at(s, "enabled_modules"))}`);
  return out.join("; ");
}

interface State {
  scope: Rec | null;
  roles: PyMap<unknown>;
  since: PyMap<Rec>;
  people: PyMap<Dict>;
}

function update(target: Dict, src: unknown): void {
  if (!isDict(src)) raise("TypeError", `'${typeName(src)}' object is not a mapping`);
  for (const k of Object.keys(src)) target[k] = src[k];
}

/** Scope, roles and people as the log has them at a time: entries at or before it. */
function stateAt(records: Rec[], engId: unknown, when: Time): State {
  const st: State = { scope: null, roles: new PyMap(), since: new PyMap(), people: new PyMap() };
  for (const rec of records) {
    const [t, e] = rec;
    if (t.us > when.us) break;
    const action = getk(e, "action"), ch = or(getk(e, "change"), dict());
    const after = getk(ch, "after");
    if (pyEq(getk(e, "engagement_id"), engId) && pyEq(action, "scope.updated")) {
      st.scope = rec;
    } else if (pyEq(getk(e, "engagement_id"), engId) && pyEq(action, "members.updated")) {
      const roles = new PyMap<unknown>();
      const order: unknown[] = [];
      for (const m of iter(or(after, []))) {
        const uid = at(m, "user_id");
        if (!roles.has(uid)) order.push(uid);
        roles.set(uid, or(getk(m, "roles"), []));
      }
      for (const uid of order) {                           // since when each person has held "reviewer"
        if (pyIn("reviewer", roles.get(uid)) && !pyIn("reviewer", st.roles.get(uid) ?? [])) st.since.set(uid, rec);
      }
      st.roles = roles;
    } else if (["person.created", "person.renamed", "person.owner", "person.disabled", "person.enabled"].some((a) => pyEq(action, a))) {
      const sid = getk(e, "subject_id");
      if (!st.people.has(sid)) st.people.set(sid, dict());
      update(st.people.get(sid)!, or(after, dict()));
    }
  }
  return st;
}

async function checkAuditLog(r: Dict): Promise<[Problems, Notes]> {
  const notes: Notes = [];
  const receipted = closedLanes(r);
  const log = getk(r, "audit_log");
  if (log === null) {
    if (receipted.length) {
      notes.push("this report has no change history (made before the audit log); who held the reviewer "
                 + "role and which scope was in force when each receipt was issued are not shown");
    }
    return [[], notes];
  }
  const [problems, records] = await checkLog(log, "audit log", AUDIT_FIELDS);
  if (records === null) return [problems, notes];
  const engId = at(at(r, "engagement"), "id");
  const start = records.find(([, e]) => pyEq(getk(e, "engagement_id"), engId))?.[0] ?? null;
  for (const lane of receipted) {
    const name = label(lane), rc = at(lane, "receipt");
    const sig = getk(rc, "signature");
    let uid: unknown, who: unknown, email: unknown, issued: Time;
    try {
      if (truthy(sig)) {
        const payload = loadsStr(at(sig, "payload"));
        [uid, who, email] = [at(at(payload, "signer"), "id"), at(at(payload, "signer"), "name"), getk(at(payload, "signer"), "email")];
      } else {
        [uid, who, email] = [getk(rc, "closed_by_user"), getk(rc, "closed_by"), getk(rc, "closed_by_email")];
      }
      issued = utc(at(rc, "issued_at"));
    } catch (e) {
      caught(e, "ValueError", "KeyError", "TypeError");
      problems.push(`${name}: the receipt's signer or issue time cannot be read`);
      continue;
    }
    if (start === null || issued.us < start.us) {
      notes.push(`${name}: issued before the audit log covered this engagement, so the roles and scope `
                 + "at that time are not recorded");
      continue;
    }
    const st = stateAt(records, engId, issued);
    const scope = st.scope
      ? `scope set ${stamp(st.scope[0])} by ${actorText(getk(st.scope[1], "actor"))}: `
        + scopeText(or(getk(or(getk(st.scope[1], "change"), dict()), "after"), dict()))
      : "no scope recorded";
    if (uid === null) {
      notes.push(`${name}: closed by "${pyStr(who)}" with the operator token or in open mode, so no account or `
                 + `role applies; ${scope}`);
      continue;
    }
    const person = st.people.get(uid) ?? null;
    const mine: Problems = [];
    if (person === null) {
      mine.push(`${name}: the audit log has no record of the signer ${pyStr(who)} (id ${pyStr(uid)})`);
    } else {
      if (!pyEq(getk(person, "name"), who)) {
        mine.push(`${name}: the receipt names the signer ${pyStr(who)}, but the audit log names them `
                  + `${pyStr(getk(person, "name"))} at that time`);
      }
      if (email !== null && !pyEq(getk(person, "email"), email)) {
        mine.push(`${name}: the receipt names the signer's email ${pyStr(email)}, but the audit log has `
                  + `${pyStr(getk(person, "email"))}`);
      }
      if (truthy(getk(person, "disabled"))) mine.push(`${name}: the signer's account was disabled when the receipt was issued`);
    }
    const held = pyIn("reviewer", st.roles.get(uid) ?? []);
    if (!held && !truthy(getk(person ?? dict(), "is_owner"))) {
      mine.push(`${name}: ${pyStr(who)} did not hold the reviewer role on this engagement when the receipt was `
                + "issued, and was not an owner");
    }
    problems.push(...mine);
    if (!mine.length) {
      const since = st.since.get(uid);
      const role = held && since
        ? `held the reviewer role, given ${stamp(since[0])} by ${actorText(getk(since[1], "actor"))}`
        : "was an owner, who may sign any receipt";
      const whoText = truthy(getk(person, "email")) ? `${pyStr(who)} (${pyStr(getk(person, "email"))})` : pyStr(who);
      notes.push(`${name}: issued ${stamp(issued)}; ${whoText} ${role}; ${scope}`);
    }
  }
  return [problems, notes];
}

// ---- RFC 3161 timestamps -----------------------------------------------------------------------
//
// A timestamp token is CMS SignedData over a TSTInfo. The TSTInfo names the hash of what was
// timestamped and the time; the signer is the timestamp authority, whose certificate must chain
// to a root the reader trusts. Only what these checks need is parsed.

const TS_STATEMENT = "attackledger-timestamp-v1";
const HASH: Record<string, Hash> = {
  "2.16.840.1.101.3.4.2.1": "SHA-256", "2.16.840.1.101.3.4.2.2": "SHA-384", "2.16.840.1.101.3.4.2.3": "SHA-512",
};
const RSA_WITH: Record<string, string> = {
  "1.2.840.113549.1.1.11": "2.16.840.1.101.3.4.2.1", "1.2.840.113549.1.1.12": "2.16.840.1.101.3.4.2.2",
  "1.2.840.113549.1.1.13": "2.16.840.1.101.3.4.2.3",
};
const ECDSA_WITH: Record<string, string> = {
  "1.2.840.10045.4.3.2": "2.16.840.1.101.3.4.2.1", "1.2.840.10045.4.3.3": "2.16.840.1.101.3.4.2.2",
  "1.2.840.10045.4.3.4": "2.16.840.1.101.3.4.2.3",
};
const RSA = "1.2.840.113549.1.1.1", EC = "1.2.840.10045.2.1";
const CURVES: Record<string, Curve> = { "1.2.840.10045.3.1.7": P256, "1.3.132.0.34": P384 };
const DIGEST_INFO_LEN: Record<string, number> = {
  "2.16.840.1.101.3.4.2.1": 19 + 32, "2.16.840.1.101.3.4.2.2": 19 + 48, "2.16.840.1.101.3.4.2.3": 19 + 64,
};
const TIME_STAMPING = "1.3.6.1.5.5.7.3.8";

function hashOf(oid: string | null): Hash | null {
  return oid !== null && own(HASH, oid) ? HASH[oid] : null;
}

/** One DER element: [tag, start, content start, end]. */
type Node = [number, number, number, number];

function byteAt(buf: Uint8Array, i: number): number {
  return i < buf.length ? buf[i] : raise("IndexError", "index out of range");
}

function der(buf: Uint8Array, pos: number): Node {
  const tag = byteAt(buf, pos);
  if ((tag & 0x1f) === 0x1f) raise("ValueError", "unsupported tag");
  let n = byteAt(buf, pos + 1), p = pos + 2;
  if (n & 0x80) {
    const k = n & 0x7f;
    if (!(k >= 1 && k <= 4)) raise("ValueError", "bad length");
    n = Number(bigFrom(buf.subarray(p, p + k)));
    p += k;
  }
  if (p + n > buf.length) raise("ValueError", "truncated");
  return [tag, pos, p, p + n];
}

function kids(buf: Uint8Array, node: Node): Node[] {
  const out: Node[] = [];
  let p = node[2];
  while (p < node[3]) {
    const k = der(buf, p);
    out.push(k);
    p = k[3];
  }
  return out;
}

function nth<T>(xs: T[], i: number): T {
  const j = i < 0 ? xs.length + i : i;
  return j >= 0 && j < xs.length ? xs[j] : raise("IndexError", "list index out of range");
}

function val(buf: Uint8Array, node: Node): Uint8Array {
  return buf.subarray(node[2], node[3]);
}

function whole(buf: Uint8Array, node: Node): Uint8Array {
  return buf.subarray(node[1], node[3]);
}

function oid(b: Uint8Array): string {
  const b0 = byteAt(b, 0);
  const first = Math.min(Math.floor(b0 / 40), 2);
  const out: string[] = [String(first), String(b0 - 40 * first)];
  let v = 0n;
  for (const c of b.subarray(1)) {
    v = (v << 7n) | BigInt(c & 0x7f);
    if (!(c & 0x80)) { out.push(v.toString()); v = 0n; }
  }
  return out.join(".");
}

function derTime(buf: Uint8Array, node: Node): Time {
  const raw = val(buf, node);
  if (raw.some((x) => x > 0x7f)) raise("ValueError", "'ascii' codec can't decode");
  let s = String.fromCharCode(...raw);
  if (!s.endsWith("Z")) raise("ValueError", "time not in UTC");
  if (node[0] === 0x17) {                                    // UTCTime, YYMMDDHHMMSSZ
    if (!/^\d\d/.test(s)) raise("ValueError", "invalid literal for int()");
    s = (Number(s.slice(0, 2)) >= 50 ? "19" : "20") + s;
  } else if (node[0] !== 0x18) raise("ValueError", "not a time");
  const m = s.slice(0, 14).match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/);
  if (!m) raise("ValueError", "time data does not match format '%Y%m%d%H%M%S'");
  const frac = s.slice(14, -1);
  let us = 0;
  if (frac) {
    const digits = (frac.replace(/^\.+/, "") + "000000").slice(0, 6);
    if (!/^\d{6}$/.test(digits)) raise("ValueError", "invalid literal for int()");
    us = Number(digits);
  }
  return makeTime(+m[1], +m[2], +m[3], +m[4], +m[5], +m[6], us, 0);
}

function alg(buf: Uint8Array, node: Node): string {
  return oid(val(buf, nth(kids(buf, node), 0)));
}

function nameCn(name: Uint8Array): string {
  // The common name in an X.509 Name, for messages.
  try {
    for (const rdn of kids(name, der(name, 0))) {
      for (const atv of kids(name, rdn)) {
        const k = kids(name, atv);
        if (oid(val(name, nth(k, 0))) === "2.5.4.3") return new TextDecoder("utf-8").decode(val(name, nth(k, 1)));
      }
    }
  } catch (e) {
    caught(e, "ValueError", "IndexError");
  }
  return "(no common name)";
}

interface Cert {
  der: Uint8Array;
  tbs: Uint8Array;
  sigAlg: string;
  sig: Uint8Array;
  serial: bigint;
  issuer: Uint8Array;
  subject: Uint8Array;
  spki: Uint8Array;
  notBefore: Time;
  notAfter: Time;
  eku: string[] | null;
  ca: boolean;
  ski: Uint8Array | null;
  name: string;
}

function signedInt(b: Uint8Array): bigint {
  const n = bigFrom(b);
  return b.length && b[0] & 0x80 ? n - (1n << BigInt(8 * b.length)) : n;
}

function exactly<T>(xs: T[], n: number): T[] {
  if (xs.length !== n) raise("ValueError", `expected ${n} values to unpack, got ${xs.length}`);
  return xs;
}

export function parseCert(bytes: Uint8Array): Cert {
  const c = der(bytes, 0);
  const [tbs, sigAlg, sig] = exactly(kids(bytes, c), 3);
  const t = kids(bytes, tbs);
  const i = nth(t, 0)[0] === 0xa0 ? 1 : 0;
  const [nb, na] = exactly(kids(bytes, nth(t, i + 3)), 2).map((x) => derTime(bytes, x));
  const out: Cert = {
    der: bytes, tbs: whole(bytes, tbs), sigAlg: alg(bytes, sigAlg), sig: val(bytes, sig).subarray(1),
    serial: signedInt(val(bytes, nth(t, i))), issuer: whole(bytes, nth(t, i + 2)), subject: whole(bytes, nth(t, i + 4)),
    spki: whole(bytes, nth(t, i + 5)), notBefore: nb, notAfter: na, eku: null, ca: false, ski: null, name: "",
  };
  for (const extWrap of t.slice(i + 6).filter((x) => x[0] === 0xa3)) {
    for (const ext of kids(bytes, nth(kids(bytes, extWrap), 0))) {
      const k = kids(bytes, ext);
      const id = oid(val(bytes, nth(k, 0))), value = val(bytes, nth(k, -1));
      if (id === "2.5.29.37") {
        out.eku = kids(value, der(value, 0)).map((x) => oid(val(value, x)));
      } else if (id === "2.5.29.19") {
        const bc = kids(value, der(value, 0));
        out.ca = bc.length > 0 && bc[0][0] === 0x01 && !bytesEq(val(value, bc[0]), Uint8Array.of(0));
      } else if (id === "2.5.29.14") {
        out.ski = val(value, der(value, 0));
      }
    }
  }
  out.name = nameCn(out.subject);
  return out;
}

function b64url(b: Uint8Array): string {
  return b64encode(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Check an X.509 or CMS signature: RSA PKCS #1 v1.5 or ECDSA, with SHA-2. */
async function verifyWithKey(spki: Uint8Array, sigAlg: string, digestAlg: string | null, message: Uint8Array,
                             sig: Uint8Array): Promise<boolean> {
  const k = kids(spki, der(spki, 0));
  const a = kids(spki, nth(k, 0));
  const keyType = oid(val(spki, nth(a, 0)));
  const keyBits = val(spki, nth(k, 1)).subarray(1);
  if (own(RSA_WITH, sigAlg)) {
    digestAlg = RSA_WITH[sigAlg];
    sigAlg = RSA;
  } else if (own(ECDSA_WITH, sigAlg)) {
    digestAlg = ECDSA_WITH[sigAlg];
    sigAlg = EC;
  }
  const hash = hashOf(digestAlg);
  if (hash === null || sigAlg !== keyType) return false;
  if (keyType === RSA) {
    const nk = kids(keyBits, der(keyBits, 0));
    if (nk.length < 2) raise("ValueError", "not enough values to unpack");
    const n = bigFrom(val(keyBits, nk[0])), e = bigFrom(val(keyBits, nk[1]));
    const size = (bitLength(n) + 7) >> 3;
    if (sig.length !== size || size < DIGEST_INFO_LEN[digestAlg!] + 11) return false;
    try {
      const key = await subtle().importKey("jwk", { kty: "RSA", n: b64url(bigTo(n, size)!), e: b64url(bigTo(e, (bitLength(e) + 7) >> 3)!), ext: true },
                                           { name: "RSASSA-PKCS1-v1_5", hash }, false, ["verify"]);
      return await subtle().verify({ name: "RSASSA-PKCS1-v1_5" }, key, sig, message);
    } catch {
      return false;
    }
  }
  if (keyType === EC) {
    const curveOid = a.length > 1 ? oid(val(spki, a[1])) : null;
    const curve = curveOid !== null && own(CURVES, curveOid) ? CURVES[curveOid] : null;
    if (curve === null) return false;
    const rs = kids(sig, der(sig, 0));
    if (rs.length < 2) raise("ValueError", "not enough values to unpack");
    return ecdsaVerify(curve, keyBits, hash, message, bigFrom(val(sig, rs[0])), bigFrom(val(sig, rs[1])));
  }
  return false;
}

interface Token {
  imprintAlg: string;
  imprint: Uint8Array;
  time: Time;
  certs: Cert[];
  match: { issuer: Uint8Array; serial: bigint } | { ski: Uint8Array };
  digestAlg: string;
  sigAlg: string;
  sig: Uint8Array;
  signedAttrs: Uint8Array;
  econtent: Uint8Array;
  contentType: string | null;
  messageDigest: Uint8Array | null;
}

/** The TSTInfo fields, the signer's signed attributes and the certificates in a token. */
function readToken(token: Uint8Array): Token {
  const ci = kids(token, der(token, 0));
  if (oid(val(token, nth(ci, 0))) !== "1.2.840.113549.1.7.2") raise("ValueError", "not CMS signed data");
  const sd = kids(token, nth(kids(token, nth(ci, 1)), 0));
  const encap = kids(token, nth(sd, 2));
  if (oid(val(token, nth(encap, 0))) !== "1.2.840.113549.1.9.16.1.4") raise("ValueError", "not a timestamp");
  const econtent = val(token, nth(kids(token, nth(encap, 1)), 0));
  let certs: Cert[] = [], signers: Node[] | null = null;
  for (const part of sd.slice(3)) {
    if (part[0] === 0xa0) certs = kids(token, part).map((x) => parseCert(whole(token, x)));
    else if (part[0] === 0x31) signers = kids(token, part);
  }
  if (!signers || signers.length !== 1) raise("ValueError", "a timestamp has exactly one signer");
  const si = kids(token, signers[0]);
  const sid = nth(si, 1), digestAlg = alg(token, nth(si, 2));
  const attrsNode = nth(si, 3)[0] === 0xa0 ? si[3] : null;
  if (attrsNode === null) raise("ValueError", "the signer has no signed attributes");
  const sigAlg = alg(token, nth(si, 4)), sig = val(token, nth(si, 5));
  const attrs = new Map<string, Node[]>();
  for (const at of kids(token, attrsNode)) {
    const k = kids(token, at);
    attrs.set(oid(val(token, nth(k, 0))), kids(token, nth(k, 1)));
  }
  const f = kids(econtent, der(econtent, 0));
  const imprint = kids(econtent, nth(f, 2));
  const signedAttrs = concat(Uint8Array.of(0x31), whole(token, attrsNode).subarray(1));
  let match: Token["match"];
  if (sid[0] === 0x30) {
    const iss = kids(token, sid);
    match = { issuer: whole(token, nth(iss, 0)), serial: signedInt(val(token, nth(iss, 1))) };
  } else {
    match = { ski: val(token, sid) };
  }
  const ct = attrs.get("1.2.840.113549.1.9.3") ?? [];
  const md = attrs.get("1.2.840.113549.1.9.4") ?? [];
  return {
    imprintAlg: alg(econtent, nth(imprint, 0)), imprint: val(econtent, nth(imprint, 1)), time: derTime(econtent, nth(f, 4)),
    certs, match, digestAlg, sigAlg, sig, signedAttrs, econtent,
    contentType: ct.length ? oid(val(token, ct[0])) : null, messageDigest: md.length ? val(token, md[0]) : null,
  };
}

/** load_roots: every certificate in each PEM text. */
export function loadRoots(files: { name: string; text: string }[]): Cert[] {
  const roots: Cert[] = [];
  for (const f of files) {
    const blocks = [...f.text.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g)].map((m) => m[1]);
    if (!blocks.length) throw new Unusable(`no certificate found in ${f.name}`);
    roots.push(...blocks.map((b) => parseCert(b64decodeLoose(b.split(/\s+/).join("")))));
  }
  return roots;
}

/** Check the TSA's signature and its certificate chain at the token's time. */
async function tokenProblems(t: Token, roots: Cert[]): Promise<[Problems, string]> {
  if (t.contentType !== "1.2.840.113549.1.9.16.1.4") return [["the signed attributes do not name a timestamp"], ""];
  const h = hashOf(t.digestAlg);
  if (h === null || !bytesEq(t.messageDigest, await digest(h, t.econtent))) {
    return [["the timestamp's content does not match what the authority signed"], ""];
  }
  const m = t.match;
  const signer = t.certs.find((c) => ("ski" in m && bytesEq(c.ski, m.ski))
                                     || ("issuer" in m && bytesEq(c.issuer, m.issuer) && c.serial === m.serial));
  if (signer === undefined) return [["the token does not include the authority's certificate"], ""];
  if (!(await verifyWithKey(signer.spki, t.sigAlg, t.digestAlg, t.signedAttrs, t.sig))) {
    return [["the authority's signature does not verify"], signer.name];
  }
  if (!signer.eku || !signer.eku.includes(TIME_STAMPING)) return [[`${signer.name} is not a timestamping certificate`], signer.name];
  const problems: Problems = [];
  let cur = signer;
  const when = t.time;
  for (let n = 0; n < 8; n++) {
    if (!(cur.notBefore.us <= when.us && when.us <= cur.notAfter.us)) problems.push(`${cur.name} was not valid at the token's time`);
    if (roots.some((r) => bytesEq(r.subject, cur.subject) && bytesEq(r.spki, cur.spki))) return [problems, signer.name];
    let issuer: Cert | undefined;
    for (const c of [...roots, ...t.certs]) {
      if (bytesEq(c.subject, cur.issuer) && c !== cur && (await verifyWithKey(c.spki, cur.sigAlg, null, cur.tbs, cur.sig))) {
        issuer = c;
        break;
      }
    }
    if (issuer === undefined) {
      if (bytesEq(cur.issuer, cur.subject)) {
        problems.push(`it chains to ${cur.name}, which you have not trusted (pass --tsa-root FILE if you trust it)`);
      } else {
        problems.push(`the certificate that issued ${cur.name} is not in the token and no root you `
                      + "trusted issued it (pass --tsa-root FILE with the authority's root)");
      }
      return [problems, signer.name];
    }
    if (!issuer.ca) problems.push(`${issuer.name} is not a certificate authority`);
    cur = issuer;
  }
  return [[...problems, "the certificate chain is too long"], signer.name];
}

async function checkTimestamps(r: Dict, roots: Cert[]): Promise<[Problems, Notes]> {
  const problems: Problems = [], notes: Notes = [];
  let stamped = 0, receipted = 0;
  for (const lane of iter(at(r, "lanes"))) {
    const rc = at(lane, "receipt");
    if (!truthy(rc) || !pyEq(at(lane, "status"), "closed")) continue;
    receipted += 1;
    const ts = getk(rc, "timestamp");
    if (!truthy(ts)) continue;
    stamped += 1;
    const name = label(lane);
    let t: Token;
    try {
      t = readToken(b64decode(at(ts, "token")));
    } catch (e) {
      caught(e, "ValueError", "IndexError", "KeyError", "TypeError");
      problems.push(`${name}: the timestamp token cannot be read`);
      continue;
    }
    const statement = `${TS_STATEMENT}\n${pyStr(at(rc, "manifest_sha256"))}\n${pyStr(or(getk(or(getk(rc, "signature"), dict()), "value"), ""))}\n`;
    const mine: Problems = [];
    const h = hashOf(t.imprintAlg);
    if (h === null || !bytesEq(await digest(h, encode(statement)), t.imprint)) mine.push(`${name}: the timestamp covers a different receipt`);
    const [found, tsa] = await tokenProblems(t, roots);
    mine.push(...found.map((p) => `${name}: ${p}`));
    let shown: Time | null;
    try {
      shown = utc(or(getk(ts, "time"), ""));
    } catch (e) {
      caught(e, "ValueError");
      shown = null;
    }
    if (shown === null || shown.us !== t.time.us) mine.push(`${name}: the time shown in the report is not the token's time`);
    problems.push(...mine);
    if (!mine.length) notes.push(`${name}: timestamped ${isoformat(t.time)} by ${tsa}`);
  }
  if (receipted && stamped < receipted) {
    notes.push(`${receipted - stamped} of ${receiptsWord(receipted)} ${receipted - stamped === 1 ? "is" : "are"} not timestamped`);
  }
  return [problems, notes];
}

// ---- the whole report -----------------------------------------------------------------------

/** The report or its inputs cannot be used (the script exits with a message). */
export class Unusable extends Error {}

export type Verdict = "PASS" | "FAIL" | "SKIP";

export interface CheckResult {
  name: string;
  verdict: Verdict;
  problems: string[];
  skip: string | null;          // why there was nothing to check
}

export interface Note {
  check: string;                // the check that wrote it
  text: string;
}

export interface Outcome {
  /** verified: no check failed; failed: one did; unusable: the format or a file cannot be used;
   * error: the report is malformed in a way the script would stop on. */
  status: "verified" | "failed" | "unusable" | "error";
  title: string[];              // the two heading lines
  results: CheckResult[];
  notes: Note[];
  message: string | null;       // for unusable and error
  exitCode: 0 | 1 | 2;
}

export interface VerifyOptions {
  /** Extra trusted roots (PEM text), as with --tsa-root. The pinned roots are always trusted. */
  roots?: { name: string; text: string }[];
  requireSignatures?: boolean;
  ed25519?: Ed25519Mode;
}

const EMBED = /<script type="application\/json" id="attackledger-report">([\s\S]*?)<\/script>/;

/** A file's bytes as the script reads them: strict UTF-8, with a byte order mark kept (so it fails). */
export function decodeFile(bytes: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new Unusable("the file is not UTF-8 text");
  }
}

/** load(): the report from a JSON file, or the one embedded in an HTML report. */
export function readReport(text: string, fileName: string): unknown {
  text = text.replace(/\r\n?/g, "\n");                     // as Python's text mode reads it
  if (/\.html?$/.test(fileName)) {
    const m = text.match(EMBED);
    if (!m) throw new Unusable("no embedded report found in the HTML file");
    text = m[1];
  }
  return pyLoads(text);
}

function failure(status: "unusable" | "error", message: string, exitCode: 1 | 2): Outcome {
  return { status, title: [], results: [], notes: [], message, exitCode };
}

/** Run every check, as `verify_report.py FILE [--tsa-root ...] [--require-signatures]` does. */
export async function verifyReport(text: string, fileName: string, opts: VerifyOptions = {}): Promise<Outcome> {
  let roots: Cert[];
  try {
    roots = loadRoots([...(opts.roots ?? []), ...TSA_ROOTS]);
  } catch (e) {
    if (e instanceof Unusable) return failure("error", e.message, 1);
    return failure("error", `a trusted root cannot be read: ${(e as Error).message}`, 1);
  }
  let r: unknown;
  try {
    r = readReport(text, fileName);
  } catch (e) {
    if (e instanceof Unusable) return failure("error", e.message, 1);
    return failure("error", `the file is not a report that can be read: ${(e as Error).message}`, 1);
  }
  try {
    return await verifyParsed(r, roots, opts);
  } catch (e) {
    return failure("error", `the report cannot be checked: ${(e as Error).message}`, 1);
  }
}

async function verifyParsed(r: unknown, roots: Cert[], opts: VerifyOptions): Promise<Outcome> {
  const format = getk(r, "format");
  if (!pyIn(format, FORMATS)) return failure("unusable", `unsupported report format: ${pyStr(format)}`, 2);
  const report = r as Dict;
  const require = !!opts.requireSignatures, mode = opts.ed25519 ?? "auto";

  // (name, problems, skip): a check with a skip reason found nothing to check.
  const results: [string, Problems, string | null][] = [];
  const notes: Note[] = [];
  const add = (check: string, more: Notes) => notes.push(...more.map((text) => ({ check, text })));
  results.push(["Report body hash", await checkBody(report), null]);
  const [chainProblems, chainNotes] = await checkChain(report);
  results.push(["Evidence chain", chainProblems, null]);
  add("Evidence chain", chainNotes);
  const [receiptProblems, receiptNotes] = await checkReceipts(report);
  results.push(["Lane receipts", receiptProblems, null]);
  add("Lane receipts", receiptNotes);
  if (!pyEq(at(report, "format"), "attackledger-report/1")) {
    for (const [name, field] of [["Receipt signatures", "signature"], ["Receipt timestamps", "timestamp"]] as const) {
      const [problems, more] = field === "signature" ? await checkSignatures(report, require, mode)
                                                      : await checkTimestamps(report, roots);
      const [have, receipted] = countReceipts(report, field);
      const done = field === "signature" ? "signed" : "timestamped";
      const skip = have ? null : receipted ? `0 of ${receiptsWord(receipted)} ${done}` : "no receipts";
      results.push([name, problems, skip]);
      add(name, more);
      if (field === "signature") {
        const [keyProblems, keyNotes] = await checkKeyLog(report);
        if (own(report, "key_log")) results.push(["Signing key history", keyProblems, null]);
        add("Signing key history", keyNotes);
        const [auditProblems, auditNotes] = await checkAuditLog(report);
        if (own(report, "audit_log")) results.push(["Change history", auditProblems, null]);
        add("Change history", auditNotes);
      }
    }
  } else if (require) {
    results.push(["Receipt signatures", ["this report format carries no signatures"], null]);
  }

  const eng = at(report, "engagement"), s = at(report, "summary");
  const lanes = at(s, "lanes_receipted"), entries = at(s, "evidence_entries");
  const title = [
    `AttackLedger report: ${pyStr(at(eng, "name"))} (${pyStr(at(at(eng, "pack"), "name"))} ${pyStr(at(at(eng, "pack"), "version"))})`,
    `${pyStr(lanes)} receipted lane${pyEq(lanes, 1) ? "" : "s"}, ${pyStr(entries)} evidence entr${pyEq(entries, 1) ? "y" : "ies"}`,
  ];
  const checks: CheckResult[] = results.map(([name, problems, skip]) => ({
    name, problems, skip: skip && !problems.length ? skip : null,
    verdict: skip && !problems.length ? "SKIP" : problems.length ? "FAIL" : "PASS",
  }));
  const ok = checks.every((c) => c.verdict !== "FAIL");
  return { status: ok ? "verified" : "failed", title, results: checks, notes, message: null, exitCode: ok ? 0 : 1 };
}

/** The verifier's output, line for line as verify_report.py prints it. */
export function cliText(o: Outcome): string {
  if (o.status === "unusable") return `${o.message}\n`;
  if (o.status === "error") return "";
  const out = [o.title[0], `  ${o.title[1]}`, ""];
  for (const c of o.results) {
    if (c.verdict === "SKIP") { out.push(`  SKIP  ${c.name} (${c.skip})`); continue; }
    out.push(`  ${c.verdict}  ${c.name}`);
    for (const p of c.problems) out.push(`        - ${p}`);
  }
  for (const n of o.notes) out.push(`  NOTE  ${n.text}`);
  out.push("", o.status === "verified" ? "Verified." : "Verification FAILED.");
  return out.join("\n") + "\n";
}

/** A message as a page shows it: the command line's --tsa-root hints become the page's own. */
export function pageWording(text: string): string {
  return text.replace("(pass --tsa-root FILE if you trust it)", "(add its root certificate under Trusted roots if you trust it)")
    .replace("(pass --tsa-root FILE with the authority's root)", "(add the authority's root certificate under Trusted roots)");
}

/** A self-test: a copy of the report with one signature byte changed must fail the signature check. */
export async function selfTest(text: string, fileName: string, opts: VerifyOptions = {}): Promise<boolean | null> {
  const r = readReport(text, fileName);
  const lane = isDict(r) && Array.isArray(r.lanes)
    ? r.lanes.find((l) => isDict(l) && l.status === "closed" && isDict(l.receipt) && isDict(l.receipt.signature)
                          && typeof l.receipt.signature.value === "string")
    : undefined;
  if (!lane) return null;
  const sig = ((lane as Dict).receipt as Dict).signature as Dict;
  const value = sig.value as string;
  const bytes = b64decode(value);
  bytes[0] ^= 1;
  sig.value = b64encode(bytes);
  const o = await verifyParsed(r, loadRoots([...(opts.roots ?? []), ...TSA_ROOTS]), opts);
  return o.results.find((c) => c.name === "Receipt signatures")?.verdict === "FAIL";
}

/** The building blocks, for tools/verifier_equivalence/ to compare one by one with the script's. */
export const internals = {
  canonical, pyLoads, floatRepr, b64decode, verifyWithKey, verifySignature,
  utcIso: (text: unknown) => isoformat(utc(text)),
  ed25519: (pub: Uint8Array, message: Uint8Array, signature: Uint8Array, mode: Ed25519Mode) =>
    ed25519Verify(pub, message, signature, mode),
};
