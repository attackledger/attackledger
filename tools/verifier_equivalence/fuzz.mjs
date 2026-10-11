// Seeded random-mutation mode of the equivalence tests (docs/security-review/FUZZING.md):
//
//   tools/verifier_equivalence/run.sh --fuzz 2000 [--seed 7] [--keep DIR] [--jobs 8]
//
// Each mutant is one of the reports in cases.json with one to three mutations: byte flips,
// inserted and deleted spans, JSON values changed (type, number format, one character or one
// unit off), keys deleted, duplicated or reordered, strings rewritten with \u escapes, values
// wrapped or nested hundreds of levels deep. verify_report.py and the browser module (both
// Ed25519 modes) run on every mutant with the case's options; they must give the same status,
// verdicts and output, and the script must never stop with a traceback. Mutations that do not
// change what the JSON means (key order, escapes) must also leave the output as it was for the
// unmutated report. The same seed always makes the same mutants. Exit code 0: no difference.
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

// Runs verify_report.py's main() on many files in one process and reports, per file, the exit
// code and output the command line would have given, and whether it stopped with an exception.
const PY_BATCH = `
import contextlib, importlib.util, io, json, sys
spec = importlib.util.spec_from_file_location("vr", sys.argv[1]); vr = importlib.util.module_from_spec(spec); spec.loader.exec_module(vr)
sys.setrecursionlimit(1000)
out = []
for job in json.load(sys.stdin):
    buf, crash = io.StringIO(), None
    with contextlib.redirect_stdout(buf):
        try:
            code = vr.main(["verify_report.py", job["file"], *job["args"]])
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
            if not isinstance(e.code, int) and e.code is not None:
                crash = "SystemExit: " + str(e.code)
        except BaseException as e:
            code, crash = 1, type(e).__name__ + ": " + str(e)[:300]
    out.append({"code": code, "stdout": buf.getvalue(), "crash": crash})
json.dump(out, sys.stdout)
`;

function prng(seed) {                       // mulberry32
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return { next, int: (n) => Math.floor(next() * n), pick: (xs) => xs[Math.floor(next() * xs.length)] };
}

// ---- a JSON tree that keeps every scalar exactly as written ------------------------------------

function parseRaw(text) {
  let i = 0;
  const ws = () => { while (i < text.length && " \t\n\r".includes(text[i])) i++; };
  function value() {
    ws();
    const c = text[i];
    if (c === "{" || c === "[") {
      const obj = c === "{";
      i++;
      const node = obj ? { t: "obj", pairs: [] } : { t: "arr", items: [] };
      ws();
      if (text[i] === (obj ? "}" : "]")) { i++; return node; }
      for (;;) {
        if (obj) {
          ws();
          const k = scalar();
          ws();
          if (text[i] !== ":") throw new Error("bad JSON");
          i++;
          node.pairs.push([k, value()]);
        } else node.items.push(value());
        ws();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === (obj ? "}" : "]")) { i++; return node; }
        throw new Error("bad JSON");
      }
    }
    return { t: "raw", text: scalar() };
  }
  function scalar() {
    const start = i;
    if (text[i] === '"') {
      i++;
      while (i < text.length && text[i] !== '"') i += text[i] === "\\" ? 2 : 1;
      i++;
    } else {
      while (i < text.length && !",:]} \t\n\r".includes(text[i])) i++;
    }
    if (i === start || i > text.length) throw new Error("bad JSON");
    return text.slice(start, i);
  }
  const v = value();
  ws();
  if (i !== text.length) throw new Error("bad JSON");
  return v;
}

const emit = (n) => n.t === "raw" ? n.text
  : n.t === "obj" ? "{" + n.pairs.map(([k, v]) => `${k}: ${emit(v)}`).join(", ") + "}"
  : "[" + n.items.map(emit).join(", ") + "]";

function nodes(n, out = [], parent = null, key = null) {
  out.push({ n, parent, key });
  if (n.t === "obj") n.pairs.forEach(([, v], i) => nodes(v, out, n, i));
  if (n.t === "arr") n.items.forEach((v, i) => nodes(v, out, n, i));
  return out;
}

function put(parent, key, value) {
  if (parent.t === "obj") parent.pairs[key][1] = value;
  else parent.items[key] = value;
}

const raw = (text) => ({ t: "raw", text });
const NUMBERS = ["0", "-0", "1", "-1", "1.0", "1e0", "1E2", "0.1", "1e-7", "5e-324", "1e16", "1e400", "-1e400", "NaN",
                 "Infinity", "-Infinity", "9007199254740993", "123456789012345678901234567890", "1" + "0".repeat(4400), "2", "24"];
const STRINGS = ['""', '"x"', '"\\u0000"', '"\\ud800"', '"\\ud83d\\ude00"', '"\u00e9"', '"\\u2028"', '"</script>"',
                 '"\\u001b[2J"', '"attackledger-report/1"', '"attackledger-report/2"', '"closed"', '"done"', '"na"',
                 '"Ed25519"', '"ECDSA-P256"', '"2026-10-09T15:26:05+00:00"', '"2026-10-09"', '"' + "0".repeat(64) + '"',
                 '"QUJD"', '"=="', '"' + "a".repeat(5000) + '"'];
const OTHER = ["true", "false", "null", "[]", "{}"];

function nudge(r, text) {
  if (/^-?\d+$/.test(text)) return String(BigInt(text) + (r.next() < 0.5 ? 1n : -1n));
  if (/^-?\d/.test(text)) return r.pick([text + "0", text.replace(/\d(?=\D*$)/, (d) => String((+d + 1) % 10)), text.toUpperCase()]);
  if (!text.startsWith('"') || text.length < 3) return r.pick(OTHER);
  const body = text.slice(1, -1);
  if (/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d/.test(body)) {           // a time, one second off
    const s = (+body.slice(17, 19) + 1) % 60;
    return `"${body.slice(0, 17)}${String(s).padStart(2, "0")}${body.slice(19)}"`;
  }
  const at = r.int(body.length);
  if (body[at] === "\\") return text;
  const c = body[at];
  const swap = /[0-9a-f]/.test(c) ? "0123456789abcdef"[("0123456789abcdef".indexOf(c) + 1) % 16]
    : /[A-Za-z0-9+/]/.test(c) ? (c === "A" ? "B" : "A") : "x";
  return `"${body.slice(0, at)}${swap}${body.slice(at + 1)}"`;
}

/** The same JSON string with some characters (and every one that must be) written as \u escapes. */
function escaped(r, text) {
  let s;
  try { s = JSON.parse(text); } catch { return text; }
  if (typeof s !== "string") return text;
  const hex = (u) => "\\u" + (r.next() < 0.5 ? u.toString(16).padStart(4, "0") : u.toString(16).padStart(4, "0").toUpperCase());
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const u = s.charCodeAt(i), lead = u >= 0xd800 && u < 0xdc00, next = s.charCodeAt(i + 1);
    if (lead && next >= 0xdc00 && next < 0xe000) {          // a pair: both escaped, or both as they are
      out += r.next() < 0.4 ? hex(u) + hex(next) : s[i] + s[i + 1];
      i++;
    } else if ((u >= 0xd800 && u < 0xe000) || u < 0x20 || u === 0x22 || u === 0x5c || r.next() < 0.4) out += hex(u);
    else out += s[i];
  }
  return '"' + out + '"';
}

// Each operation says whether it keeps the meaning of the JSON (key order, escapes).
const TREE_OPS = [
  ["value", false, (r, ctx) => ctx.parent && put(ctx.parent, ctx.key, raw(r.pick([...NUMBERS, ...STRINGS, ...OTHER])))],
  ["nudge", false, (r, ctx) => ctx.n.t === "raw" && ctx.parent && put(ctx.parent, ctx.key, raw(nudge(r, ctx.n.text)))],
  ["nudge", false, (r, ctx) => ctx.n.t === "raw" && ctx.parent && put(ctx.parent, ctx.key, raw(nudge(r, ctx.n.text)))],
  ["type", false, (r, ctx) => ctx.n.t === "raw" && ctx.parent && put(ctx.parent, ctx.key, raw(
    ctx.n.text.startsWith('"') ? (/^"-?\d+"$/.test(ctx.n.text) ? ctx.n.text.slice(1, -1) : "0") : JSON.stringify(ctx.n.text)))],
  ["delete key", false, (r, ctx) => ctx.n.t === "obj" && ctx.n.pairs.length && ctx.n.pairs.splice(r.int(ctx.n.pairs.length), 1)],
  ["duplicate key", false, (r, ctx) => {
    if (ctx.n.t !== "obj" || !ctx.n.pairs.length) return false;
    const [k, v] = ctx.n.pairs[r.int(ctx.n.pairs.length)];
    ctx.n.pairs.splice(r.int(ctx.n.pairs.length + 1), 0, [k, r.next() < 0.5 ? v : raw(r.pick([...NUMBERS, ...STRINGS]))]);
    return true;
  }],
  ["reorder keys", true, (r, ctx) => {
    if (ctx.n.t !== "obj" || ctx.n.pairs.length < 2) return false;
    const keys = ctx.n.pairs.map(([k]) => k);
    if (new Set(keys).size !== keys.length) return false;
    for (let i = ctx.n.pairs.length - 1; i > 0; i--) {
      const j = r.int(i + 1);
      [ctx.n.pairs[i], ctx.n.pairs[j]] = [ctx.n.pairs[j], ctx.n.pairs[i]];
    }
    return true;
  }],
  ["escape", true, (r, ctx) => {
    if (ctx.n.t === "raw" && ctx.n.text.startsWith('"') && ctx.parent) { put(ctx.parent, ctx.key, raw(escaped(r, ctx.n.text))); return true; }
    if (ctx.n.t === "obj" && ctx.n.pairs.length) { const p = ctx.n.pairs[r.int(ctx.n.pairs.length)]; p[0] = escaped(r, p[0]); return true; }
    return false;
  }],
  ["array", false, (r, ctx) => {
    if (ctx.n.t !== "arr" || !ctx.n.items.length) return false;
    const i = r.int(ctx.n.items.length), j = r.int(ctx.n.items.length);
    const op = r.int(3);
    if (op === 0) ctx.n.items.splice(i, 1);
    else if (op === 1) ctx.n.items.splice(j, 0, ctx.n.items[i]);
    else [ctx.n.items[i], ctx.n.items[j]] = [ctx.n.items[j], ctx.n.items[i]];
    return true;
  }],
  ["wrap", false, (r, ctx) => ctx.parent && put(ctx.parent, ctx.key, r.next() < 0.5 ? { t: "arr", items: [ctx.n] }
    : { t: "obj", pairs: [['"value"', ctx.n]] })],
  ["deep", false, (r, ctx) => {
    if (!ctx.parent) return false;
    const depth = r.pick([400, 600, 985, 990, 995, 1000, 1100, 3000]);
    put(ctx.parent, ctx.key, raw("[".repeat(depth) + "]".repeat(depth)));
    return true;
  }],
];
const BYTE_TOKENS = ["\x00", "\ufeff", "\\", '"', ",", "]", "}", "{", "[", ":", "\\u", "\r", "\r\n", "1e400", "NaN",
                     "</script>", '<script type="application/json" id="attackledger-report">', "\u2028"]
  .map((t) => Buffer.from(t, "utf8")).concat([Buffer.from([0xed, 0xa0, 0x80]), Buffer.from([0xff]), Buffer.from([0xc3])]);

function byteOp(r, b) {
  const i = r.int(b.length + 1);
  switch (r.int(4)) {
    case 0: return Buffer.concat([b.subarray(0, i), r.pick(BYTE_TOKENS), b.subarray(i)]);
    case 1: return Buffer.concat([b.subarray(0, i), b.subarray(i + 1 + r.int(64))]);
    case 2: { const span = b.subarray(i, i + 1 + r.int(200)); return Buffer.concat([b.subarray(0, i), span, span, b.subarray(i)]); }
    default: {
      const c = Buffer.from(b);
      if (c.length) c[Math.min(i, c.length - 1)] ^= 1 << r.int(8);
      return c;
    }
  }
}

const EMBED = /(<script type="application\/json" id="attackledger-report">)([\s\S]*?)(<\/script>)/;
const utf8 = (b) => { try { return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(b); } catch { return null; } };

/** A mutant of one report file: [bytes, operations, whether every operation keeps the meaning]. */
function mutant(r, file) {
  let bytes = readFileSync(file);
  const html = /\.html?$/.test(file);
  const ops = [];
  let same = true;
  for (let k = 0, rounds = 1 + r.int(3); k < rounds; k++) {
    const text = utf8(bytes);
    const m = html && text !== null ? text.match(EMBED) : null;
    const json = html ? (m ? m[2] : null) : text;
    let tree = null;
    try { tree = json !== null ? parseRaw(json) : null; } catch { tree = null; }
    let done = false;
    let all = null;
    try { all = tree ? nodes(tree) : null; } catch { all = null; }      // nested too deep to walk: bytes only
    if (all && r.next() < 0.75) {
      for (let tries = 0; tries < 20 && !done; tries++) {
        const [name, keeps, f] = r.pick(TREE_OPS);
        if (f(r, r.pick(all)) !== false) {
          ops.push(name);
          same &&= keeps;
          done = true;
        }
      }
      if (done) {
        const body = emit(tree);
        bytes = Buffer.from(html ? text.replace(EMBED, (_, a, _b, c) => a + body + c) : body, "utf8");
      }
    }
    if (!done) {
      bytes = byteOp(r, bytes);
      ops.push("bytes");
      same = false;
    }
  }
  return [bytes, ops, same];
}

function runPythonBatch(python, jobs, parallel) {
  const chunks = Array.from({ length: parallel }, (_, k) => jobs.filter((_, i) => i % parallel === k));
  return Promise.all(chunks.map((chunk) => new Promise((resolve, reject) => {
    if (!chunk.length) return resolve([]);
    const p = spawn("python3", ["-I", "-c", PY_BATCH, python], { stdio: ["pipe", "pipe", "pipe"] });
    let out = "", err = "";
    p.stdout.on("data", (d) => { out += d; });
    p.stderr.on("data", (d) => { err += d; });
    p.on("close", (code) => (code === 0 ? resolve(JSON.parse(out)) : reject(new Error(err.slice(-2000)))));
    p.stdin.end(JSON.stringify(chunk));
  }))).then((parts) => jobs.map((_, i) => parts[i % parallel][Math.floor(i / parallel)]));
}

export async function fuzz({ v, python, here, repo, cases, count, seed, keep, parallel, fromCli, fromModule }) {
  const r = prng(seed);
  const dir = mkdtempSync(path.join(os.tmpdir(), "al-verifier-fuzz-"));
  const flags = (c) => [...(c.roots ?? []).flatMap((x) => ["--tsa-root", path.join(here, "fixtures", x)]),
                        ...(c.require ? ["--require-signatures"] : []), ...(c.history ? ["--require-history"] : [])];
  const roots = (c) => (c.roots ?? []).map((x) => ({ name: path.join(here, "fixtures", x), text: readFileSync(path.join(here, "fixtures", x), "utf8") }));
  const runJs = async (c, file, mode) => {
    let text;
    try {
      text = v.decodeFile(new Uint8Array(readFileSync(file)));
    } catch (e) {                     // as the page shows a file it cannot decode
      return fromModule({ status: "error", title: [], results: [], notes: [], message: e.message, exitCode: 2 });
    }
    return fromModule(await v.verifyReport(text, file, { roots: roots(c), requireSignatures: !!c.require, requireHistory: !!c.history, ed25519: mode }));
  };
  try {
    // The unmutated reports first: what a meaning-preserving mutant must still print.
    const baseline = new Map();
    for (const c of cases) if (!baseline.has(c.name)) baseline.set(c.name, await runJs(c, path.join(repo, c.file), "webcrypto"));
    const mutants = [];
    for (let k = 0; k < count; k++) {
      const c = cases[r.int(cases.length)];
      const [bytes, ops, same] = mutant(r, path.join(repo, c.file));
      const file = path.join(dir, `m${k}${path.extname(c.file)}`);
      writeFileSync(file, bytes);
      mutants.push({ k, c, file, ops, same });
    }
    const py = await runPythonBatch(python, mutants.map((m) => ({ file: m.file, args: flags(m.c) })), parallel);
    const problems = [];
    let crashes = 0, meaning = 0;
    const statuses = {};
    for (const m of mutants) {
      const p = py[m.k];
      const pyResult = fromCli(p.stdout, p.code);
      statuses[pyResult.status] = (statuses[pyResult.status] ?? 0) + 1;
      const why = [];
      if (p.crash) { crashes += 1; why.push(`verify_report.py stopped: ${p.crash}`); }
      for (const mode of ["webcrypto", "fallback"]) {
        const js = await runJs(m.c, m.file, mode);
        if (js.status !== pyResult.status) why.push(`${mode}: status ${js.status}, Python ${pyResult.status}`);
        for (const key of Object.keys(pyResult.verdicts)) {
          if (js.verdicts[key] !== pyResult.verdicts[key]) why.push(`${mode}: ${key} ${js.verdicts[key]}, Python ${pyResult.verdicts[key]}`);
        }
        if (js.text !== pyResult.text) why.push(`${mode}: output differs`);
        if (mode === "webcrypto" && m.same) {
          meaning += 1;
          const base = baseline.get(m.c.name);
          if (js.text !== base.text || js.status !== base.status) why.push("a mutation that keeps the meaning changed the output");
        }
      }
      if (why.length) problems.push({ ...m, why: [...new Set(why)], py: p });
    }
    const lines = [`Fuzz: seed ${seed}, ${count} mutants of ${new Set(cases.map((c) => c.file)).size} reports `
                   + `(${meaning} keep the meaning). Python: ${Object.entries(statuses).map(([s, n]) => `${n} ${s}`).join(", ")}; `
                   + `${crashes} stopped with an exception. ${problems.length} mutants with a difference.`];
    for (const p of problems.slice(0, 40)) lines.push(`  m${p.k}: ${p.c.name} [${p.ops.join(", ")}]: ${p.why.join("; ")}`);
    if (keep && problems.length) {
      mkdirSync(keep, { recursive: true });
      for (const p of problems) {
        writeFileSync(path.join(keep, path.basename(p.file)), readFileSync(p.file));
        writeFileSync(path.join(keep, path.basename(p.file) + ".txt"),
                      JSON.stringify({ case: p.c, ops: p.ops, why: p.why, python: p.py }, null, 2));
      }
      lines.push(`Kept ${problems.length} mutants in ${keep}.`);
    }
    console.log(lines.join("\n"));
    return problems.length ? 1 : 0;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
