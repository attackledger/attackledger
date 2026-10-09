// The public verifier page (site/verify.html, built by tools/build_verify.sh). It reads a report
// the person chooses, runs verify_report.ts on it, and shows the result the way the command
// line does. It builds every element with the DOM API (never innerHTML), so it runs under the
// page's Trusted Types policy, and it makes no network request: the page's CSP forbids them.

import { cliText, decodeFile, ed25519Native, loadRoots, pageWording, selfTest, verifyReport, type Outcome } from "./verify_report";
import { TSA_ROOTS } from "./tsa_roots";

// What each check means, in the words of the report's own "How to verify" section.
const EXPLAIN: [string, string][] = [
  ["Report body hash", "The report has not been edited since it was generated: its SHA-256 matches the recorded value."],
  ["Evidence chain", "Every evidence entry links to the one before it, from the genesis value to the chain head: none was "
    + "removed, reordered or changed. Where a summary was deleted with its engagement's key, the chain is still checked "
    + "over the hash it commits to."],
  ["Lane receipts", "For every receipted lane, a manifest rebuilt from the report's own items and evidence has the receipt's "
    + "hash, every item marked done has evidence, and every not-applicable item has a reason."],
  ["Receipt signatures", "Each signed receipt verifies with the public key in the report, the key matches its fingerprint, and "
    + "the signed text names this lane, this manifest and a chain head in the report."],
  ["Signing key history", "Each signing key's entries in the key log hash correctly and link into the log in order, and the key "
    + "was registered to the signer before the receipt was issued and not revoked before it."],
  ["Change history", "The audit log entries hash correctly and link into the log in order. For each receipt, the signer held "
    + "the reviewer role (or was an owner) and had the name in the receipt when it was issued."],
  ["Receipt timestamps", "Each RFC 3161 timestamp covers this receipt's manifest hash and signature, the authority's signature "
    + "verifies, and its certificate chain reaches a root you trust and was valid at the token's time."],
];
const MEANS = new Map(EXPLAIN);

type Root = { name: string; text: string; fingerprint: string; subject: string };

const state: { file: { name: string; bytes: Uint8Array } | null; roots: Root[]; running: number } = {
  file: null, roots: [], running: 0,
};

function $(id: string): HTMLElement {
  return document.getElementById(id)!;
}

function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls?: string | null, ...kids: (Node | string | null)[]): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  for (const k of kids) if (k !== null) e.append(k);
  return e;
}

async function sha256(bytes: Uint8Array): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), (b) => b.toString(16).padStart(2, "0")).join("");
}

function pemBytes(text: string): Uint8Array {
  const b = text.match(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/)?.[1].replace(/[^A-Za-z0-9+/]/g, "") ?? "";
  return Uint8Array.from(atob(b), (c) => c.charCodeAt(0));
}

async function describeRoot(name: string, text: string): Promise<Root> {
  const [cert] = loadRoots([{ name, text }]);        // throws on a file with no readable certificate
  const fp = (await sha256(pemBytes(text))).toUpperCase();
  return { name, text, fingerprint: fp.match(/../g)!.join(":"), subject: cert.name };
}

function size(n: number): string {
  return n < 1024 ? `${n} bytes` : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KiB` : `${(n / 1024 / 1024).toFixed(1)} MiB`;
}

// ---- the trusted roots --------------------------------------------------------------------

async function showRoots(): Promise<void> {
  const pinned = await Promise.all(TSA_ROOTS.map((r) => describeRoot(r.name, r.text)));
  const list = $("roots");
  list.replaceChildren();
  for (const r of pinned) {
    list.append(el("li", null, el("span", null, el("strong", null, r.subject), " (pinned)", el("span", "fp", `SHA-256 ${r.fingerprint}`))));
  }
  state.roots.forEach((r, i) => {
    const remove = el("button", "btn small", "Remove");
    remove.type = "button";
    remove.setAttribute("aria-label", `Remove ${r.subject}`);
    remove.addEventListener("click", () => {
      state.roots.splice(i, 1);
      void showRoots().then(rerun);
    });
    list.append(el("li", null, el("span", null, el("strong", null, r.subject), ` (from ${r.name})`,
                                  el("span", "fp", `SHA-256 ${r.fingerprint}`)), remove));
  });
}

async function addRoot(file: File): Promise<void> {
  const error = $("root-error");
  error.textContent = "";
  try {
    const text = decodeFile(new Uint8Array(await file.arrayBuffer()));
    state.roots.push(await describeRoot(file.name, text));
  } catch {
    error.textContent = `${file.name} has no certificate this page can read. Choose a PEM file (BEGIN CERTIFICATE).`;
    return;
  }
  await showRoots();
  await rerun();
}

// ---- checking ----------------------------------------------------------------------------

const WORD = { verified: "Verified", failed: "Failed", unusable: "Not a report", error: "Not checked" } as const;

async function check(name: string, bytes: Uint8Array): Promise<void> {
  state.file = { name, bytes };
  await rerun();
  $("result-title").focus();
}

async function rerun(): Promise<void> {
  if (!state.file) return;
  const { name, bytes } = state.file;
  const run = ++state.running;
  const status = $("status"), result = $("result");
  status.textContent = `Checking ${name}…`;
  result.setAttribute("aria-busy", "true");
  if (!globalThis.crypto?.subtle) {
    status.textContent = "This browser offers no WebCrypto on this page, so it cannot check the report. Open the page over HTTPS, or use verify_report.py.";
    result.replaceChildren();
    return;
  }
  const opts = { roots: state.roots.map((r) => ({ name: r.name, text: r.text })), requireSignatures: ($("require") as HTMLInputElement).checked };
  let o: Outcome;
  try {
    o = await verifyReport(decodeFile(bytes), name, opts);
  } catch (e) {
    o = { status: "error", title: [], results: [], notes: [], message: (e as Error).message, exitCode: 1 };
  }
  const digest = await sha256(bytes);
  if (run !== state.running) return;                       // a newer check started meanwhile
  render(o, name, bytes.length, digest);
  result.removeAttribute("aria-busy");
  const failed = o.results.filter((c) => c.verdict === "FAIL").map((c) => c.name);
  status.textContent = o.status === "verified" ? `${name}: verified. No check failed.`
    : o.status === "failed" ? `${name}: verification failed. ${failed.length} ${failed.length === 1 ? "check" : "checks"} failed: ${failed.join(", ")}.`
    : `${name}: not checked. ${o.message ?? ""}`;
  if (o.status !== "unusable" && o.status !== "error" && o.results.find((c) => c.name === "Receipt signatures")?.verdict === "PASS") {
    const ok = await selfTest(decodeFile(bytes), name, opts).catch(() => false);
    if (run === state.running && ok !== null) {
      result.append(el("p", "selftest", ok
        ? "Self-test: a copy of this report with one signature byte changed fails the signature check here, as it should."
        : "Self-test failed: a copy with a changed signature did not fail. Do not rely on this page; use verify_report.py."));
    }
  }
}

function render(o: Outcome, name: string, bytes: number, digest: string): void {
  const result = $("result");
  const tone = o.status === "verified" ? "ok" : o.status === "failed" ? "bad" : "plain";
  const head = el("div", `verdict ${tone}`,
    el("span", "verdict-stamp", WORD[o.status]),
    el("div", "verdict-text",
       el("p", "what", o.title[0]?.replace(/^AttackLedger report: /, "") ?? name),
       el("p", "meta", o.title[1] ?? (o.message ? pageWording(o.message) : "")),
       el("p", "meta", `${name}, ${size(bytes)}, SHA-256 `, el("code", null, digest))));
  const parts: Node[] = [head];

  if (o.results.length) {
    const list = el("ul", "checks");
    for (const c of o.results) {
      const body = el("div", null, el("p", "check-name", c.name), el("p", "check-what", MEANS.get(c.name) ?? ""));
      if (c.verdict === "SKIP") body.append(el("p", "check-what", `Skipped: ${c.skip}. There was nothing for this check to check.`));
      if (c.problems.length) body.append(el("ul", "problems", ...c.problems.map((p) => el("li", null, pageWording(p)))));
      const notes = o.notes.filter((n) => n.check === c.name);
      if (notes.length) body.append(el("ul", "notes", ...notes.map((n) => el("li", null, n.text))));
      const badge = el("span", `badge ${c.verdict.toLowerCase()}`, c.verdict);
      badge.setAttribute("aria-label", { PASS: "Passed", FAIL: "Failed", SKIP: "Skipped" }[c.verdict]);
      list.append(el("li", null, badge, body));
    }
    parts.push(list);
    const orphans = o.notes.filter((n) => !o.results.some((c) => c.name === n.check));
    if (orphans.length) parts.push(el("ul", "notes", ...orphans.map((n) => el("li", null, n.text))));
  }

  const text = cliText(o);
  if (text) {
    const copy = el("button", "btn small", "Copy the result as text");
    copy.type = "button";
    copy.addEventListener("click", () => {
      navigator.clipboard.writeText(text).then(() => { copy.textContent = "Copied"; },
                                               () => { copy.textContent = "Copy failed: select the text below"; });
    });
    const pre = el("pre", null, text);
    pre.tabIndex = 0;
    pre.setAttribute("aria-label", "The result as verify_report.py prints it");
    parts.push(el("div", "after", copy),
               el("details", "cli", el("summary", null, "The result as verify_report.py prints it"), pre));
  }
  result.replaceChildren(...parts);
}

// ---- wiring ------------------------------------------------------------------------------

function pick(input: HTMLInputElement, use: (f: File) => void): void {
  input.addEventListener("change", () => {
    const f = input.files?.[0];
    if (f) use(f);
    input.value = "";                                       // the same file can be chosen again
  });
}

async function readFile(f: File): Promise<void> {
  await check(f.name, new Uint8Array(await f.arrayBuffer()));
}

function init(): void {
  $("explain").replaceChildren(...EXPLAIN.map(([n, m]) => el("li", null, el("strong", null, n), m)));
  pick($("report-file") as HTMLInputElement, (f) => void readFile(f));
  pick($("root-file") as HTMLInputElement, (f) => void addRoot(f));
  $("require").addEventListener("change", () => void rerun());
  $("paste-check").addEventListener("click", () => {
    const text = ($("paste-text") as HTMLTextAreaElement).value;
    if (!text.trim()) return;
    // A pasted HTML report is read like a .html file, anything else like a .json one.
    void check(text.trimStart().startsWith("<") ? "pasted report.html" : "pasted report.json", new TextEncoder().encode(text));
  });

  const drop = $("drop");
  let depth = 0;
  drop.addEventListener("dragenter", (e) => { e.preventDefault(); depth++; drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => { if (--depth <= 0) { depth = 0; drop.classList.remove("over"); } });
  drop.addEventListener("dragover", (e) => { e.preventDefault(); if (e.dataTransfer) e.dataTransfer.dropEffect = "copy"; });
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    depth = 0;
    drop.classList.remove("over");
    const f = e.dataTransfer?.files?.[0];
    if (f) void readFile(f);
  });
  // A file dropped anywhere else on the page would make the browser open it; take it here instead.
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("drop", (e) => {
    e.preventDefault();
    const f = e.dataTransfer?.files?.[0];
    if (f) void readFile(f);
  });

  void showRoots();
  void ed25519Native().then((native) => {
    $("support").append(" ", el("strong", null, native
      ? "This browser checks Ed25519 with its own WebCrypto."
      : "This browser has no Ed25519 in WebCrypto, so this page uses the verifier's own code for it."));
  });
}

init();
