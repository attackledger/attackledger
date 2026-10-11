// Shared by the site phase's specs (tests/site/): the built site, the outside requests its policy
// allows, and the reference verifier (verify_report.py, the copy the site serves).
import { execFileSync } from "node:child_process";
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { BrowserContext, Page } from "@playwright/test";
import { expect, SITE, test } from "./lib";

/** Where tests/pages-server.mjs built the site (tools/build_pages.sh). */
export const OUT = process.env.E2E_PAGES_OUT ?? "/tmp/pages";

/** The hosts the site's policy lets a page load from besides its own origin (Google Fonts). */
const ALLOWED_HOSTS = new Set(["fonts.googleapis.com", "fonts.gstatic.com"]);

/** One of the demo's own font files, served as if from fonts.gstatic.com. */
function fontFile(): Buffer {
  const dir = path.join(OUT, "demo/assets");
  const name = readdirSync(dir).find((f) => /^atkinson-hyperlegible-latin-400-normal-.*\.woff2$/.test(f));
  if (!name) throw new Error("no font in the built demo");
  return readFileSync(path.join(dir, name));
}

/** A stylesheet as Google Fonts answers one: an @font-face whose file is on fonts.gstatic.com. */
const FONT_CSS = `@font-face { font-family: "Atkinson Hyperlegible"; font-style: normal; font-weight: 400; font-display: swap;
  src: url(https://fonts.gstatic.com/s/atkinsonhyperlegible/v1/e2e-400.woff2) format("woff2"); }
@font-face { font-family: "Zilla Slab"; font-style: normal; font-weight: 700; font-display: swap;
  src: url(https://fonts.gstatic.com/s/zillaslab/v1/e2e-700.woff2) format("woff2"); }`;

export interface Outside { allowed: string[]; refused: string[] }

/** The test network has no route out. Every request a page makes to another origin is caught
 *  here: one to Google Fonts (which the policy allows) is answered as Google would, with CORS;
 *  any other is refused and recorded, and fails the test. A request the policy blocks never gets
 *  this far: the guard sees it as a violation. */
export async function offline(context: BrowserContext): Promise<Outside> {
  const seen: Outside = { allowed: [], refused: [] };
  const font = fontFile();
  await context.route((url) => url.origin !== SITE, async (route) => {
    const u = new URL(route.request().url());
    if (!ALLOWED_HOSTS.has(u.host) || u.protocol !== "https:") {
      seen.refused.push(u.href);
      await route.abort("blockedbyclient");
      return;
    }
    seen.allowed.push(u.href);
    const css = u.host === "fonts.googleapis.com";
    await route.fulfill({ status: 200, contentType: css ? "text/css; charset=utf-8" : "font/woff2",
                          headers: { "access-control-allow-origin": "*" }, body: css ? FONT_CSS : font });
  });
  return seen;
}

/** The test, with every outside request caught (offline); none but Google Fonts is allowed. */
export const siteTest = test.extend<{ outside: Outside }>({
  outside: [async ({ context, guard }, use) => {
    // WebKit reports a <link rel="preconnect"> it could not open as a console error. A preconnect
    // is a bare connection, not a request Playwright can answer, and the test network has no DNS
    // for the outside: only the two Google Fonts hosts the pages name, and only this message.
    guard.allowConsole(/^Failed to preconnect to https:\/\/fonts\.(googleapis|gstatic)\.com\/\. Error: /);
    const seen = await offline(context);
    await use(seen);
    expect(seen.refused, "requests to origins the site does not use").toEqual([]);
    for (const u of seen.allowed) expect(ALLOWED_HOSTS.has(new URL(u).host), u).toBe(true);
  }, { auto: true }],
});

// ---- the reference verifier -----------------------------------------------------------------

export type Verdict = [name: string, verdict: "PASS" | "FAIL" | "SKIP"];

export interface Reference { verdicts: Verdict[]; failed: string[]; verified: boolean; facts: string[]; output: string }

export interface Mode { label: string; flags: string[]; signatures: boolean; history: boolean }
export const MODES: Mode[] = [
  { label: "normal", flags: [], signatures: false, history: false },
  { label: "--require-history", flags: ["--require-history"], signatures: false, history: true },
  { label: "--require-signatures --require-history", flags: ["--require-signatures", "--require-history"], signatures: true, history: true },
];

/** What verify_report.py (the copy the site serves, with the root the site serves) says of a file. */
export function reference(file: string, flags: string[]): Reference {
  let output: string;
  try {
    output = execFileSync("python3", ["-I", path.join(OUT, "verify_report.py"), file,
                                       "--tsa-root", path.join(OUT, "digicert-trusted-root-g4.pem"), ...flags],
                          { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (e) {
    const err = e as { stdout?: string; status?: number };
    if (err.status !== 1 || !err.stdout) throw e;           // 1: verification failed; else it could not run
    output = err.stdout;
  }
  const verdicts = [...output.matchAll(/^ {2}(PASS|FAIL|SKIP) {2}(.+?)(?: \(.*\))?$/gm)].map((m) => [m[2], m[1]] as Verdict);
  const facts: string[] = [];
  const at = output.indexOf("What the verified JSON in this HTML report says");
  if (at >= 0) for (const line of output.slice(at).split("\n").slice(1)) { if (/^ {2}\S/.test(line)) facts.push(line.trim()); else if (facts.length) break; }
  return { verdicts, failed: verdicts.filter(([, v]) => v === "FAIL").map(([n]) => n), verified: /^Verified\.$/m.test(output), facts, output };
}

/** Writes a file into the test's output folder (the runner's /tmp) and gives its path. */
export function scratch(name: string, body: string | Buffer): string {
  const p = test.info().outputPath(name.replace(/[^\w.-]/g, "_").slice(-100));
  mkdirSync(path.dirname(p), { recursive: true });
  writeFileSync(p, body);
  return p;
}

// ---- the public verifier page -----------------------------------------------------------------

export async function setModes(page: Page, mode: Mode): Promise<void> {
  await page.locator("#require").setChecked(mode.signatures);
  await page.locator("#require-history").setChecked(mode.history);
}

/** What the page says once it has checked a file: its status line and every check's verdict. */
export async function pageVerdicts(page: Page): Promise<Verdict[]> {
  return page.locator("#result ul.checks > li").evaluateAll((lis) => lis.map((li) => [
    li.querySelector(".check-name")?.textContent ?? "", li.querySelector(".badge")?.textContent ?? "",
  ] as [string, string])) as Promise<Verdict[]>;
}

/** The status line the page shows for a reference result. */
export function statusFor(name: string, ref: Reference): string {
  if (ref.verified) return `${name}: verified. No check failed.`;
  const n = ref.failed.length;
  return `${name}: verification failed. ${n} ${n === 1 ? "check" : "checks"} failed: ${ref.failed.join(", ")}.`;
}

let checks = 0;

/** Loads a file into the page, in a mode, and checks that it gives the reference verifier's verdicts.
 *  Each check gets a file name of its own ("3 name"), so the status line the test waits for is
 *  this check's, never the one before it. Gives the reference's result, and the name shown. */
export async function checkLikeReference(page: Page, file: string, body: string | Buffer, mode: Mode): Promise<Reference> {
  const name = `${++checks} ${file}`;
  const ref = reference(scratch(file, body), mode.flags);
  expect(ref.verdicts.length, `verify_report.py gave no verdicts:\n${ref.output}`).toBeGreaterThan(0);
  await setModes(page, mode);
  await page.locator("#report-file").setInputFiles({ name, mimeType: name.endsWith(".html") ? "text/html" : "application/json",
                                                     buffer: Buffer.isBuffer(body) ? body : Buffer.from(body) });
  await expect(page.locator("#status"), `${name}, ${mode.label}`).toHaveText(statusFor(name, ref));
  expect(await pageVerdicts(page), `${name}, ${mode.label}`).toEqual(ref.verdicts);
  return ref;
}
