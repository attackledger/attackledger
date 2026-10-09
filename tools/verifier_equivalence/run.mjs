// Run tools/verify_report.py and the browser verifier (web/src/verify_report.ts, bundled by
// run.sh) on every report in cases.json, and on the building blocks one by one (signatures,
// JSON, times, base64), and compare. Every check must give the same verdict and the same
// output, line for line. Ed25519 is checked both ways the browser can: with WebCrypto and with
// the module's own fallback.
//
// Usage (through run.sh): node run.mjs BUNDLE [--python verify_report.py] [--markdown FILE]
import { spawnSync } from "node:child_process";
import { constants, createHash, generateKeyPairSync, privateEncrypt, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "../..");
const argv = process.argv.slice(2);
const v = await import(pathToFileURL(path.resolve(argv[0])).href);
const opt = (name, fallback) => (argv.includes(name) ? argv[argv.indexOf(name) + 1] : fallback);
const python = path.resolve(opt("--python", path.join(repo, "tools/verify_report.py")));
const markdown = opt("--markdown", null);
const pythonHasV2 = readFileSync(python, "utf8").includes("summary_sha256");
const CHECKS = { "Report body hash": "B", "Evidence chain": "C", "Lane receipts": "R", "Receipt signatures": "S",
                 "Signing key history": "K", "Change history": "H", "Receipt timestamps": "T" };
const MODES = ["webcrypto", "fallback"];

function fromCli(stdout, code) {
  const verdicts = Object.fromEntries(Object.values(CHECKS).map((k) => [k, "-"]));
  for (const line of stdout.split("\n")) {
    const m = line.match(/^ {2}(PASS|FAIL|SKIP) {2}(.+?)(?: \(.*\))?$/);
    if (m && CHECKS[m[2]]) verdicts[CHECKS[m[2]]] = m[1];
  }
  const status = code === 0 ? "verified" : code === 2 ? "unusable"
    : stdout.includes("\nVerification FAILED.\n") ? "failed" : "error";
  return { status, verdicts, text: stdout };
}

function fromModule(o) {
  const verdicts = Object.fromEntries(Object.values(CHECKS).map((k) => [k, "-"]));
  for (const c of o.results) verdicts[CHECKS[c.name]] = c.verdict;
  return { status: o.status, verdicts, text: v.cliText(o) };
}

function runPython(c) {
  const roots = (c.roots ?? []).flatMap((r) => ["--tsa-root", path.join(here, "fixtures", r)]);
  const p = spawnSync("python3", ["-I", python, c.file, ...roots, ...(c.require ? ["--require-signatures"] : [])],
                      { cwd: repo, encoding: "utf8" });
  return fromCli(p.stdout, p.status);
}

async function runModule(c, mode) {
  const roots = (c.roots ?? []).map((r) => ({ name: path.join(here, "fixtures", r),
                                              text: readFileSync(path.join(here, "fixtures", r), "utf8") }));
  const bytes = new Uint8Array(readFileSync(path.join(repo, c.file)));
  let text;
  try {
    text = v.decodeFile(bytes);
  } catch {
    return { status: "error", verdicts: {}, text: "" };
  }
  return fromModule(await v.verifyReport(text, c.file, { roots, requireSignatures: !!c.require, ed25519: mode }));
}

function firstDiff(a, b) {
  const x = a.split("\n"), y = b.split("\n");
  const i = x.findIndex((line, n) => line !== y[n]);
  return i < 0 ? x.length : i + 1;
}

// ---- whole reports ----------------------------------------------------------------------

const { cases } = JSON.parse(readFileSync(path.join(here, "cases.json"), "utf8"));
const rows = [];
let failures = 0, pending = 0;
for (const c of cases) {
  const py = runPython(c);
  const js = {};
  for (const mode of MODES) js[mode] = await runModule(c, mode);
  const deferred = c.v2 && !pythonHasV2;
  const problems = [];
  for (const mode of MODES) {
    if (js[mode].status !== py.status) problems.push(`${mode}: status ${js[mode].status}, Python ${py.status}`);
    for (const k of Object.values(CHECKS)) {
      if (js[mode].verdicts[k] !== py.verdicts[k]) problems.push(`${mode}: ${k} ${js[mode].verdicts[k]}, Python ${py.verdicts[k]}`);
    }
    if (js[mode].text !== py.text) problems.push(`${mode}: output differs from line ${firstDiff(js[mode].text, py.text)}`);
  }
  const want = c.expect ?? {};
  const unmet = Object.entries(want).filter(([k, x]) => (k === "status" ? js.webcrypto.status : js.webcrypto.verdicts[k]) !== x)
    .map(([k, x]) => `expected ${k} ${x}`);
  if (!deferred) unmet.push(...Object.entries(want).filter(([k, x]) => (k === "status" ? py.status : py.verdicts[k]) !== x)
    .map(([k, x]) => `Python: expected ${k} ${x}`));
  if (unmet.length) failures += 1;
  if (problems.length && !deferred) failures += 1;
  if (deferred) pending += 1;
  rows.push({ c, py, js, problems, unmet, deferred });
}

const cell = (r, k) => {
  const a = r.py.verdicts[k], b = r.js.webcrypto.verdicts[k], f = r.js.fallback.verdicts[k];
  if (r.deferred) return b === f ? b : `${b}/${f}`;
  return a === b && b === f ? a : `py ${a}, js ${b}/${f}`;
};
const lines = [
  "| # | Report | B | C | R | S | K | H | T | Result | Same verdicts and output |",
  "|---|---|---|---|---|---|---|---|---|---|---|",
];
rows.forEach((r, i) => {
  const flags = [r.c.roots?.length ? `+${r.c.roots.join(", ")}` : "", r.c.require ? "--require-signatures" : ""].filter(Boolean).join(" ");
  const same = r.deferred ? `pending: verify_report.py has no v2 yet (Python says ${r.py.status})`
    : r.problems.length ? `NO: ${r.problems.join("; ")}` : "yes";
  const result = { verified: "Verified", failed: "FAILED", unusable: "unusable (exit 2)", error: "cannot be checked" }[r.js.webcrypto.status];
  lines.push(`| ${i + 1} | ${r.c.name}${flags ? ` (${flags})` : ""} | ${Object.values(CHECKS).map((k) => cell(r, k)).join(" | ")} | `
             + `${result}${r.unmet.length ? ` (UNEXPECTED: ${r.unmet.join(", ")})` : ""} | ${same} |`);
});

// ---- building blocks ----------------------------------------------------------------------

const b64 = (b) => Buffer.from(b).toString("base64");
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const N256 = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const big = (b) => BigInt("0x" + Buffer.from(b).toString("hex"));
const be = (n, size) => Buffer.from(n.toString(16).padStart(size * 2, "0"), "hex");
const le = (n, size) => Buffer.from(be(n, size)).reverse();

const vectors = { ed25519: [], p256: [], withkey: [], json: [], iso: [], b64: [] };
const msg = Buffer.from("attackledger-receipt payload, ünïcödé ✓");
{
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url");
  const sig = sign(null, msg, privateKey);
  const s = BigInt("0x" + Buffer.from(sig.subarray(32)).reverse().toString("hex"));
  const flip = (b, i) => { const c = Buffer.from(b); c[i] ^= 1; return c; };
  const identity = Buffer.concat([Buffer.from([1]), Buffer.alloc(31)]);
  vectors.ed25519.push(
    ["valid", pub, msg, sig], ["other message", pub, Buffer.from("other"), sig], ["R changed", pub, msg, flip(sig, 3)],
    ["S changed", pub, msg, flip(sig, 40)], ["s + L (non-canonical s)", pub, msg, Buffer.concat([sig.subarray(0, 32), le(s + L, 32)])],
    ["key y >= p", Buffer.from("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "hex"), msg, sig],
    ["key x = 0 with the sign bit", Buffer.concat([Buffer.from([1]), Buffer.alloc(30), Buffer.from([0x80])]), msg, sig],
    ["small-order key and R, s = 0", identity, msg, Buffer.concat([identity, Buffer.alloc(32)])],
    ["RFC 8032 test 1", Buffer.from("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "hex"), Buffer.alloc(0),
     Buffer.from("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", "hex")],
    ["short signature", pub, msg, sig.subarray(0, 63)], ["short key", pub.subarray(0, 31), msg, sig],
  );
  vectors.ed25519.push(...torsionVectors());
}

/** Keys and R points with a torsion part (T of order 2 added). A cofactorless verifier, like the
 * script, accepts the first and refuses the other two; a cofactored one accepts all three. */
function torsionVectors() {
  const P = 2n ** 255n - 19n;
  const md = (a) => ((a % P) + P) % P;
  const pw = (b, e) => { let r = 1n; b = md(b); for (; e > 0n; e >>= 1n) { if (e & 1n) r = r * b % P; b = b * b % P; } return r; };
  const D = md(-121665n * pw(121666n, P - 2n));
  const add = ([x1, y1, z1, t1], [x2, y2, z2, t2]) => {
    const a = md((y1 - x1) * (y2 - x2)), b = md((y1 + x1) * (y2 + x2)), c = md(t1 * 2n * D * t2), d = md(z1 * 2n * z2);
    const e = b - a, f = d - c, g = d + c, h = b + a;
    return [md(e * f), md(g * h), md(f * g), md(e * h)];
  };
  const mul = (s, Q) => { let R = [0n, 1n, 1n, 0n]; for (; s > 0n; s >>= 1n) { if (s & 1n) R = add(R, Q); Q = add(Q, Q); } return R; };
  const enc = ([x, y, z]) => { const zi = pw(z, P - 2n), ax = md(x * zi), ay = md(y * zi); return le(ay | ((ax & 1n) << 255n), 32); };
  const gy = md(4n * pw(5n, P - 2n));
  const gx2 = md((gy * gy - 1n) * pw(D * gy * gy + 1n, P - 2n));
  let gx = pw(gx2, (P + 3n) / 8n);
  if (md(gx * gx - gx2) !== 0n) gx = md(gx * pw(2n, (P - 1n) / 4n));
  if (gx & 1n) gx = P - gx;
  const G = [gx, gy, 1n, md(gx * gy)];
  const T2 = [0n, P - 1n, 1n, 0n];                                   // (0, -1), of order 2
  const scalar = (b) => BigInt("0x" + Buffer.from(b).reverse().toString("hex"));
  const hash = (...parts) => scalar(createHash("sha512").update(Buffer.concat(parts)).digest()) % L;
  const a = 123456789123456789123456789n % L, A = mul(a, G), A2 = add(A, T2);
  const out = [];
  for (const [name, key, rTorsion, wantEven] of [["key with a torsion part, h even", A2, false, true],
                                                 ["key with a torsion part, h odd", A2, false, false],
                                                 ["R with a torsion part", A, true, null]]) {
    for (let r = 1000n; ; r++) {
      let R = mul(r, G);
      if (rTorsion) R = add(R, T2);
      const h = hash(enc(R), enc(key), msg);
      if (wantEven !== null && (h % 2n === 0n) !== wantEven) continue;
      out.push([name, enc(key), msg, Buffer.concat([enc(R), le((r + h * a) % L, 32)])]);
      break;
    }
  }
  return out;
}
{
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const spki = publicKey.export({ format: "der", type: "spki" });
  const sig = sign("sha256", msg, { key: privateKey, dsaEncoding: "ieee-p1363" });
  const r = big(sig.subarray(0, 32)), s = big(sig.subarray(32));
  const offCurve = Buffer.from(spki); offCurve[offCurve.length - 1] ^= 1;
  vectors.p256.push(
    ["valid", spki, msg, sig], ["other message", spki, Buffer.from("other"), sig],
    ["high s (n - s)", spki, msg, Buffer.concat([be(r, 32), be(N256 - s, 32)])],
    ["r = 0", spki, msg, Buffer.concat([Buffer.alloc(32), be(s, 32)])], ["s = n", spki, msg, Buffer.concat([be(r, 32), be(N256, 32)])],
    ["point off the curve", offCurve, msg, sig], ["DER signature", spki, msg, sign("sha256", msg, privateKey)],
  );
}
{
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const spki = publicKey.export({ format: "der", type: "spki" });
  const digestInfo = "3031300d060960864801650304020105000420";
  const raw = (em) => privateEncrypt({ key: privateKey, padding: constants.RSA_NO_PADDING }, em);
  const block = (type, fill, t) => Buffer.concat([Buffer.from([0, type]), Buffer.alloc(256 - t.length - 3, fill), Buffer.from([0]), t]);
  const h = createHash("sha256").update(msg).digest();
  const t = Buffer.concat([Buffer.from(digestInfo, "hex"), h]);
  const noNull = Buffer.concat([Buffer.from("302f300b0609608648016503040201" + "0420", "hex"), h]);
  const RSA256 = "1.2.840.113549.1.1.11";
  vectors.withkey.push(
    ["RSA valid", spki, RSA256, null, msg, sign("sha256", msg, privateKey)],
    ["RSA other message", spki, RSA256, null, Buffer.from("other"), sign("sha256", msg, privateKey)],
    ["RSA sha384WithRSA", spki, "1.2.840.113549.1.1.12", null, msg, sign("sha384", msg, privateKey)],
    ["RSA rsaEncryption + SHA-256 (as CMS has it)", spki, "1.2.840.113549.1.1.1", "2.16.840.1.101.3.4.2.1", msg, sign("sha256", msg, privateKey)],
    ["RSA block type 2", spki, RSA256, null, msg, raw(block(2, 0x11, t))],
    ["RSA garbage before the digest", spki, RSA256, null, msg,
     raw(Buffer.concat([Buffer.from([0, 1]), Buffer.alloc(8, 0xff), Buffer.from([0]), Buffer.alloc(256 - t.length - 11, 0x42), t]))],
    ["RSA DigestInfo without NULL", spki, RSA256, null, msg, raw(block(1, 0xff, noNull))],
    ["RSA hand-made valid block", spki, RSA256, null, msg, raw(block(1, 0xff, t))],
    ["RSA signature one byte short", spki, RSA256, null, msg, sign("sha256", msg, privateKey).subarray(1)],
  );
  for (const [curve, size, hashName, sigAlg] of [["P-384", 48, "sha384", "1.2.840.10045.4.3.3"], ["P-384", 48, "sha256", "1.2.840.10045.4.3.2"],
                                                 ["P-256", 32, "sha512", "1.2.840.10045.4.3.4"]]) {
    const k = generateKeyPairSync("ec", { namedCurve: curve });
    const ecSpki = k.publicKey.export({ format: "der", type: "spki" });
    const der = sign(hashName, msg, { key: k.privateKey, dsaEncoding: "der" });
    vectors.withkey.push([`${curve} ${hashName} valid`, ecSpki, sigAlg, null, msg, der],
                         [`${curve} ${hashName} other message`, ecSpki, sigAlg, null, Buffer.from("other"), der],
                         [`${curve} ${hashName} truncated DER signature`, ecSpki, sigAlg, null, msg, der.subarray(0, 6)]);
    if (curve === "P-384") vectors.withkey.push([`${curve} key, RSA algorithm`, ecSpki, RSA256, null, msg, der]);
    void size;
  }
}
vectors.json.push(
  '{"a":1,"b":1.0,"c":-0.0,"d":5e-324,"e":1e16,"f":1e22,"g":0.1,"h":123456789.0,"i":1e-7,"j":0.0001}',
  '{"big":12345678901234567890123,"neg":-1180591620717411303424,"safe":9007199254740993}',
  '{"inf":1e400,"nan":NaN,"minf":-Infinity}', '[1.5e300, 2.5E-10, 1E5, 100.0, 0.5, 3.141592653589793]',
  '{"z":"ünïcödé ✓ 😀","a":"\\u2028 \\u0000 \\u001f \\u007f \\" \\\\ \\/ \\b\\f\\n\\r\\t","é":1,"e":2,"😀":3,"\\uffff":4}',
  '{"lone":"\\ud800","pair":"\\ud83d\\ude00"}', '{"dup":1,"dup":2}', '  [ ]  ', '{"a":01}', '[1,]', '"\x01"', '{"__proto__":{"x":1}}',
  '\ufeff{}', '{"a":true,"b":false,"c":null}', '1' + '0'.repeat(4400),
);
vectors.iso.push("2026-10-09T15:26:05.342124+00:00", "2026-10-09T15:26:05+00:00", "2026-10-09T15:26:05Z", "2026-10-09 15:26:05",
                 "2026-10-09", "2026-10-09T15", "2026-10-09T15:26", "2026-10-09T15:26:05.1", "2026-10-09T15:26:05.1234567",
                 "2026-10-09T15:26:05,5", "20261009T152605", "2026-10-09T15:26:05+0530", "2026-10-09T15:26:05+05",
                 "2026-10-09T15:26:05-05:30", "2026-10-09T24:00:00", "2026-02-29T00:00:00", "2024-02-29T00:00:00",
                 "9999-12-31T23:59:59.999999+00:00", "0001-01-01T00:00:00-01:00", " 2026-10-09", "", "nonsense");
vectors.b64.push("QUJD", "QUJD=", "QQ", "QQ=", "QQ==", "QR==", "Q", "QUJDRA==", "QUJDRA===", "", "=", "QU JD", "QUJD\n", "ü", "-_8=");

const PY = `
import base64, importlib.util, json, sys
spec = importlib.util.spec_from_file_location("vr", sys.argv[1]); vr = importlib.util.module_from_spec(spec); spec.loader.exec_module(vr)
d, b, out = json.load(sys.stdin), base64.b64decode, {}
def safe(f):
    try: return f()
    except Exception: return "error"
out["ed25519"] = [safe(lambda: vr.ed25519_verify(b(p), b(m), b(s))) for _, p, m, s in d["ed25519"]]
out["p256"] = [safe(lambda: vr.verify_signature("ECDSA-P256", b(k), b(m), b(s))) for _, k, m, s in d["p256"]]
out["withkey"] = [safe(lambda: vr.verify_with_key(b(k), a, g, b(m), b(s))) for _, k, a, g, m, s in d["withkey"]]
out["json"] = [safe(lambda: vr.canonical(json.loads(t)) + "\\n" + json.dumps(json.loads(t), sort_keys=True, separators=(",", ":"))) for t in d["json"]]
out["iso"] = [safe(lambda: vr._utc(t).isoformat()) for t in d["iso"]]
out["b64"] = [safe(lambda: base64.b64encode(base64.b64decode(t, validate=True)).decode()) for t in d["b64"]]
json.dump(out, sys.stdout)
`;
const enc = (x) => (Buffer.isBuffer(x) || x instanceof Uint8Array ? b64(x) : x);
const p = spawnSync("python3", ["-I", "-c", PY, python], { input: JSON.stringify(Object.fromEntries(
  Object.entries(vectors).map(([k, xs]) => [k, xs.map((x) => (Array.isArray(x) ? x.map(enc) : x))]))), encoding: "utf8" });
if (p.status !== 0) throw new Error(p.stderr);
const pyOut = JSON.parse(p.stdout);
const I = v.internals;
const safe = async (f) => { try { return await f(); } catch { return "error"; } };
const u8 = (x) => new Uint8Array(x);
const jsOut = {
  ed25519: Object.fromEntries(await Promise.all(MODES.map(async (mode) => [mode, await Promise.all(vectors.ed25519.map(
    ([, pub, m, s]) => safe(() => I.ed25519(u8(pub), u8(m), u8(s), mode))))]))),
  p256: await Promise.all(vectors.p256.map(([, k, m, s]) => safe(() => I.verifySignature("ECDSA-P256", u8(k), u8(m), u8(s), "auto")))),
  withkey: await Promise.all(vectors.withkey.map(([, k, a, g, m, s]) => safe(() => I.verifyWithKey(u8(k), a, g, u8(m), u8(s))))),
  json: vectors.json.map((t) => { try { const x = I.pyLoads(t); return I.canonical(x) + "\n" + I.canonical(x, true); } catch { return "error"; } }),
  iso: vectors.iso.map((t) => { try { return I.utcIso(t); } catch { return "error"; } }),
  b64: vectors.b64.map((t) => { try { return b64(I.b64decode(t)); } catch { return "error"; } }),
};
const prim = [];
const compare = (group, names, js, mode = "") => names.forEach((name, i) => {
  const same = JSON.stringify(js[i]) === JSON.stringify(pyOut[group][i]);
  if (!same) failures += 1;
  prim.push(`| ${group}${mode ? ` (${mode})` : ""} | ${name} | ${String(pyOut[group][i]).split("\n")[0].slice(0, 60)} | ${same ? "yes" : `NO (js: ${String(js[i]).slice(0, 60)})`} |`);
});
for (const mode of MODES) compare("ed25519", vectors.ed25519.map((x) => x[0]), jsOut.ed25519[mode], mode);
compare("p256", vectors.p256.map((x) => x[0]), jsOut.p256);
compare("withkey", vectors.withkey.map((x) => x[0]), jsOut.withkey);
compare("json", vectors.json.map((t) => "`" + t.slice(0, 50).replace(/\|/g, "\\|").replace(/\n/g, " ") + (t.length > 50 ? "…" : "") + "`"), jsOut.json);
compare("iso", vectors.iso.map((t) => `\`${t}\``), jsOut.iso);
compare("b64", vectors.b64.map((t) => `\`${JSON.stringify(t)}\``), jsOut.b64);

const report = [
  `Reference: ${path.relative(repo, python) || python}${pythonHasV2 ? "" : " (no evidence chain record v2 yet)"}. `
  + `Browser module: web/src/verify_report.ts, Ed25519 with WebCrypto and with its fallback. `
  + `Columns: B body hash, C evidence chain, R lane receipts, S signatures, K key log, H change history, T timestamps; - not shown.`,
  "", ...lines, "", "| Building block | Case | Python | Same in the module |", "|---|---|---|---|", ...prim, "",
  `${rows.length} reports, ${prim.length} building-block cases; ${failures} differences or unmet expectations`
  + (pending ? `; ${pending} v2 reports pending a verify_report.py with v2.` : "."),
].join("\n");
console.log(report);
if (markdown) writeFileSync(markdown, report + "\n");
process.exit(failures ? 1 : 0);
