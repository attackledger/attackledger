// Shared by every spec: the addresses, the hostile strings, an API client, and the guard
// fixture that watches every page a test opens.
import { createHash } from "node:crypto";
import { expect, test as base, type BrowserContext, type Page, type Response } from "@playwright/test";

export const APP = "http://localhost:18180";
/** The API as the runner reaches it without a browser (seeding, checks): straight to the web container. */
export const API = "http://web/api";
/** The worker's routes, as the gateway's relay reaches them: on the API's control-network alias. They
 *  are refused through the web app (TM-1), and answer only on that address (authz.machine_channel). */
export const WORKER_API = "http://api-control:8000";
export const SIBLING = "http://localhost:18181";   // same site as the app, another origin
export const OTHER_SITE = "http://127.0.0.1:18181";  // another site
export const VERIFY_PAGE = "http://localhost:18182/verify.html";
/** The public site, as Cloudflare Pages serves it (the site phase, tests/pages-server.mjs). */
export const SITE = "http://localhost:18183";

export const TOKEN = need("E2E_API_TOKEN");
export const WORKER_TOKEN = process.env.E2E_WORKER_TOKEN ?? "";

function need(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is not set; run the suite with tools/test_e2e.sh`);
  return v;
}

// ---- hostile content ------------------------------------------------------------------------
// Every element a payload could create carries data-e2exss, and every script it could run calls
// window.__xss(...), which the guard turns into a test failure. The marker "e2exss" also lets a
// test find where the text was rendered.
const X = (id: string) => `__xss('${id}')`;
export const P = {
  img: (id: string) => `<img src=x onerror="${X(id)}" data-e2exss>`,
  svg: (id: string) => `"><svg onload="${X(id)}" data-e2exss><rect width=9 height=9 /></svg>`,
  script: (id: string) => `</script><script data-e2exss>${X(id)}</script>`,
  iframe: (id: string) => `<iframe srcdoc="<script>parent.${X(id)}</script>" data-e2exss></iframe>`,
  css: () => `<style data-e2exss>*{background:red!important}</style><div style="position:fixed;inset:0" data-e2exss></div>`,
  js: (id: string) => `javascript:${X(id)}//`,
  // A right-to-left override that is never closed, then a right-to-left isolate that is not
  // either: the classic "exe.txt" spoof, and Hebrew letters.
  rtl: "\u202Eexe.txt e2exss-rtl \u2067\u05D0\u05D1\u05D2",
  long: (id: string) => `e2exss-long-${id}-${"W".repeat(3000)}`,
};

/** One hostile string with every kind of payload, for free-text fields with room for it. */
export function hostile(id: string): string {
  return `e2exss ${id} ${P.img(id)} ${P.svg(id)} ${P.script(id)} ${P.iframe(id)} ${P.css()} ${P.js(id)} ${P.rtl}`;
}

/** Hostile and short (labels with a length limit). */
export function hostileShort(id: string): string {
  return `<img src=x onerror=${X(id)}>`.slice(0, 200);
}

// Names the seed gives things, so specs can find them.
export const NAMES = {
  hostileEng: `E2E ${P.img("eng-name")}${P.rtl}`,
  cleanEng: "E2E clean report",
  unicodeEng: "Müşteri portalı عربي 東京",
  signedEng: "E2E signed",
  scope: "*.xss.test",
  app: "app.xss.test",
  api: "api.xss.test",
};

// ---- people (the people phase) --------------------------------------------------------------------
// The owner's first password is the one tools/test_e2e.sh gave the server; every other password is
// derived from it, so each run has new ones and none is written anywhere.
const ownerFirst = process.env.E2E_OWNER_PASSWORD ?? "";
const derive = (label: string) => createHash("sha256").update(`${ownerFirst}:${label}`).digest("hex").slice(0, 32);

export const OWNER = { email: process.env.E2E_OWNER_EMAIL ?? "owner@e2e.test", name: "E2E Owner",
                       firstPassword: ownerFirst, password: derive("owner") };
const someone = (key: string, name: string) => ({ email: `${key}@e2e.test`, name, firstPassword: derive(`${key}-first`), password: derive(key) });
export const PEOPLE = {
  reader: someone("reader", `<img src=x onerror=__xss('person-name') data-e2exss> Reader`),
  tester: someone("tester", "E2E Tester"),
  reviewer: someone("reviewer", "E2E Reviewer"),
  attacker: someone("attacker", "E2E Attacker"),       // has no role anywhere
};
/** A password for a person a test creates, from its label. */
export const passwordFor = (label: string) => derive(label);

// ---- the API, as the operator token -----------------------------------------------------------
export class Api {
  constructor(private headers: Record<string, string> = { authorization: `Bearer ${TOKEN}` }, private base = API) {}

  async call<T = any>(method: string, path: string, body?: unknown, extra: Record<string, string> = {}): Promise<T> {
    const isBytes = body instanceof Uint8Array;
    const res = await fetch(this.base + path, {
      method,
      headers: { ...this.headers, ...(body !== undefined ? { "content-type": isBytes ? "application/octet-stream" : "application/json" } : {}), ...extra },
      body: body === undefined ? undefined : isBytes ? body : JSON.stringify(body),
    });
    const text = await res.text();
    if (!res.ok) throw new ApiError(method, path, res.status, text);
    return (text ? JSON.parse(text) : null) as T;
  }

  /** The status and text, for calls that are expected to be refused. */
  async raw(method: string, path: string, body?: unknown): Promise<{ status: number; text: string }> {
    const res = await fetch(this.base + path, {
      method, headers: { ...this.headers, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: res.status, text: await res.text() };
  }

  engagementId = async (name: string): Promise<number> => {
    const list = await this.call<{ id: number; name: string }[]>("GET", "/engagements");
    const e = list.find((x) => x.name === name);
    if (!e) throw new Error(`no engagement named ${JSON.stringify(name.slice(0, 40))}`);
    return e.id;
  };
}

export class ApiError extends Error {
  constructor(public method: string, public path: string, public status: number, public text: string) {
    super(`${method} ${path} -> ${status}: ${text.slice(0, 400)}`);
  }
}

export const api = new Api();

/** The API as a person: signs in and sends the session cookie. */
export async function person(email: string, password: string): Promise<Api> {
  const res = await fetch(`${API}/auth/login`, { method: "POST", headers: { "content-type": "application/json" },
                                                 body: JSON.stringify({ email, password }) });
  if (!res.ok) throw new ApiError("POST", "/auth/login", res.status, await res.text());
  const cookie = (res.headers.get("set-cookie") ?? "").split(";")[0];
  return new Api({ cookie });
}

/** Waits until the API answers through the web container (it may still be starting). */
export async function waitForApi(): Promise<void> {
  const until = Date.now() + 120_000;
  for (;;) {
    try {
      const r = await fetch(`${API}/health`);
      if (r.ok) return;
    } catch { /* not up yet */ }
    if (Date.now() > until) throw new Error("the API did not answer within 2 minutes");
    await new Promise((r) => setTimeout(r, 1000));
  }
}

// ---- signing in -------------------------------------------------------------------------------

/** A browser session for the operator token (D-056), set in the context through the API. */
export async function signInToken(context: BrowserContext): Promise<void> {
  const r = await context.request.post(`${APP}/api/auth/login`, { data: { token: TOKEN } });
  expect(r.status(), await r.text()).toBe(200);
}

export async function signInPerson(context: BrowserContext, email: string, password: string): Promise<void> {
  const r = await context.request.post(`${APP}/api/auth/login`, { data: { email, password } });
  expect(r.status(), await r.text()).toBe(200);
}

/** Closes the account dialog if it opened by itself (a password to choose, a key notice). */
export async function dismissAccount(page: Page): Promise<void> {
  const dialog = page.locator("dialog.account[open]");
  if (await dialog.isVisible()) await dialog.getByRole("button", { name: /^(Close|Skip for now)$/ }).first().click();
}

/** Opens an engagement (by name) on a tab, and waits for the tab panel. */
export async function openTab(page: Page, engId: number, tab: string): Promise<void> {
  // A load that hangs says which requests it waits for (a diagnostic for a slow test machine).
  const timer = setTimeout(() => console.log(`[e2e] ${page.url()} still loading after 20 s; in flight:`,
    inFlight(page)), 20_000);
  await page.goto(`${APP}/#/e/${engId}/${tab}`).finally(() => clearTimeout(timer));
  await expect(page.getByRole("tab", { name: new RegExp(`^${tabLabel(tab)}`) })).toHaveAttribute("aria-selected", "true");
}

export function tabLabel(tab: string): string {
  return ({ recon: "Recon", import: "Import", ledger: "Ledger", controls: "Controls", report: "Report", verify: "Verify",
            history: "History", accounts: "Test accounts", approvals: "Approvals", team: "Team" } as Record<string, string>)[tab] ?? tab;
}

// ---- the guard --------------------------------------------------------------------------------
// Attached to every test: it watches every page and tab the test's browser context opens, and
// fails the test on a CSP violation (the securitypolicyviolation event or a console report), a
// script run by injected content (__xss), any dialog, an uncaught page error or a console error
// that the test did not expect, and on a document served without the headers it must have.

export interface Guard {
  csp: string[];
  xss: string[];
  dialogs: string[];
  errors: string[];
  documents: { url: string; status: number }[];
  /** Console errors matching this are expected in this test (a refused request, for example). */
  allowConsole(re: RegExp): void;
}

const APP_CSP = [
  "default-src 'none'", "script-src 'self' 'sha256-", "style-src 'self'", "connect-src 'self'", "base-uri 'none'",
  "form-action 'self'", "frame-ancestors 'none'", "object-src 'none'",
];

export function checkDocumentHeaders(r: Response): string[] {
  const url = new URL(r.url());
  if (url.origin === SITE) return checkSiteHeaders(r);
  const h = r.headers();
  const bad: string[] = [];
  // A header the API and nginx both set arrives twice, joined with a comma; browsers read the
  // first value (Fetch, "determine nosniff"), so each copy must say the same.
  const want = (name: string, value: string) => {
    const got = (h[name] ?? "").split(",").map((v) => v.trim().toLowerCase());
    if (!got.every((v) => v === value.toLowerCase())) bad.push(`${url.pathname}: ${name} is ${JSON.stringify(h[name] ?? null)}, not ${value}`);
  };
  if (url.origin !== APP) return bad;               // the test's own pages
  const csp = h["content-security-policy"] ?? "";
  want("x-content-type-options", "nosniff");
  if (url.pathname.startsWith("/api/")) {
    // The API's HTML pages (the printable report, the docs) carry the API's own policy; raw
    // evidence is text under a sandbox; JSON opened in a tab is not rendered as a page.
    const type = (h["content-type"] ?? "").toLowerCase();
    if (!/^(text\/html|text\/plain|application\/json)/.test(type)) bad.push(`${url.pathname}: served as ${type}`);
    if (type.startsWith("text/") && !csp.includes("default-src 'none'")) bad.push(`${url.pathname}: no default-src 'none' in ${JSON.stringify(csp)}`);
    if (type.startsWith("text/plain") && !/\bsandbox\b/.test(csp)) bad.push(`${url.pathname}: raw text without a CSP sandbox`);
    if (/script-src[^;]*'unsafe-inline'/.test(csp) || /script-src[^;]*'unsafe-eval'/.test(csp)) bad.push(`${url.pathname}: unsafe script-src`);
    want("x-frame-options", "DENY");
  } else {
    for (const part of APP_CSP) if (!csp.includes(part)) bad.push(`${url.pathname}: CSP lacks ${part}: ${csp}`);
    if (/'unsafe-(inline|eval)'/.test(csp)) bad.push(`${url.pathname}: CSP allows unsafe script or style`);
    want("x-frame-options", "DENY");
    want("referrer-policy", "no-referrer");
    want("cross-origin-opener-policy", "same-origin");
  }
  return bad;
}

/** The site's documents (attackledger.com): the headers tools/build_pages.sh writes into _headers,
 *  as Cloudflare Pages applies them. Every path has the site's policy; /verify has the verifier
 *  page's own as well (two policies, both enforced), which allows no connection at all. */
export function checkSiteHeaders(r: Response): string[] {
  const url = new URL(r.url());
  if (r.status() >= 300 && r.status() < 400) return [];      // a redirect: no document
  const h = r.headers();
  const bad: string[] = [];
  const where = url.pathname;
  const want = (name: string, ok: (v: string) => boolean, what: string) => {
    if (!ok(h[name] ?? "")) bad.push(`${where}: ${name} is ${JSON.stringify(h[name] ?? null)}, not ${what}`);
  };
  const policies = (h["content-security-policy"] ?? "").split(",").map((p) => p.trim()).filter(Boolean);
  if (!policies.length) bad.push(`${where}: no Content-Security-Policy`);
  const directive = (p: string, name: string) => p.split(";").map((d) => d.trim()).find((d) => d.split(/\s+/)[0] === name);
  for (const p of policies) {
    const script = directive(p, "script-src") ?? directive(p, "default-src") ?? "";
    if (/'unsafe-(inline|eval)'|\*|https?:|data:/.test(script.replace(/^\S+/, ""))) bad.push(`${where}: script-src allows more than this origin and hashes: ${script}`);
  }
  for (const d of ["object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'"]) {
    if (!policies.some((p) => p.includes(d))) bad.push(`${where}: no policy has ${d}`);
  }
  if (!policies.some((p) => /form-action '(none|self)'/.test(p))) bad.push(`${where}: no policy limits form-action`);
  if (where === "/verify") {
    const own = policies.find((p) => p.includes("default-src 'none'"));
    for (const d of ["connect-src 'none'", "require-trusted-types-for 'script'", "trusted-types 'none'"]) {
      if (!own?.includes(d)) bad.push(`${where}: the verifier's policy lacks ${d}`);
    }
  }
  want("x-content-type-options", (v) => v === "nosniff", "nosniff");
  want("referrer-policy", (v) => v === "strict-origin-when-cross-origin" || v === "no-referrer", "strict-origin-when-cross-origin");
  want("cross-origin-opener-policy", (v) => v === "same-origin", "same-origin");
  want("permissions-policy", (v) => ["camera=()", "microphone=()", "geolocation=()"].every((x) => v.includes(x)), "camera, microphone and geolocation off");
  want("strict-transport-security", (v) => Number(/max-age=(\d+)/.exec(v)?.[1] ?? 0) >= 31536000, "max-age of a year or more");
  return bad;
}

/** The browser refusing Playwright's own helper script in a sandboxed document (raw evidence, served
 *  with CSP sandbox): the sandbox at work, not an error of the app. */
function harness(page: Page, text: string): boolean {
  return new URL(page.url()).pathname.startsWith("/api/")
    && /because the document's frame is sandboxed and the 'allow-scripts' permission is not set/.test(text);
}

/** Firefox itself asks for /favicon.ico for a document that names no icon (raw evidence, served as
 *  text under default-src 'none'), and reports the refusal as the page's violation. Its source is
 *  the browser's own FaviconLoader, not the page; anything the page loads is still counted. */
function browserFavicon(text: string): boolean {
  return /favicon\.ico/.test(text) && /(FaviconLoader|at resource:)/.test(text);
}

/** WebKit styles a document it shows as text (text/plain, JSON) with a stylesheet of its own, and
 *  reports that stylesheet as refused under default-src 'none', for any text at all (measured with a
 *  two-word text/plain page). Not counted on such a document, and only there: an HTML page that
 *  says the same has had a style injected. */
const webkitTextStyle = (text: string) =>
  text === "Refused to apply a stylesheet because its hash, its nonce, or 'unsafe-inline' appears in neither the style-src directive nor the default-src directive of the Content Security Policy.";

/** WebKit reports a cross-origin fetch it refuses as an uncaught error, even when the page catches
 *  the rejection (the CSRF pages do). Counted as a console error, which a test can expect. */
const webkitRefusedFetch = (message: string) => /^Fetch API cannot load .* due to access control checks\.$/.test(message);

export const test = base.extend<{ guard: Guard }>({
  guard: [async ({ context }, use) => {
    const allowed: RegExp[] = [];
    const g: Guard = { csp: [], xss: [], dialogs: [], errors: [], documents: [], allowConsole: (re) => allowed.push(re) };
    const headerProblems: string[] = [];
    const docType = new WeakMap<Page, string>();     // the type of each page's own document
    const failed: string[] = [];
    await context.exposeBinding("__e2eReport", ({ page }, kind: string, detail: string) => {
      const where = page?.url() ?? "?";
      if (kind === "csp" && browserFavicon(detail)) return;
      if (kind === "csp") g.csp.push(`${where}: ${detail}`);
      else if (kind === "xss") g.xss.push(`${where}: ${detail}`);
    });
    await context.addInitScript(() => {
      const report = (kind: string, detail: string) => (window as unknown as { __e2eReport: (k: string, d: string) => void }).__e2eReport(kind, detail);
      document.addEventListener("securitypolicyviolation", (e) => {
        report("csp", `${e.effectiveDirective} blocked ${e.blockedURI || "(inline)"} at ${e.sourceFile}:${e.lineNumber} sample=${e.sample}`);
      }, true);
      (window as unknown as { __xss: (id: string) => void }).__xss = (id: string) => report("xss", String(id));
    });
    const watch = (page: Page) => {
      trackRequests(page);
      page.on("console", (m) => {
        const text = m.text();
        if (browserFavicon(text)) return;
        if (webkitTextStyle(text) && !/^text\/html/.test(docType.get(page) ?? "")) return;
        if (/Content[- ]Security[- ]Policy|CSP/i.test(text)) g.csp.push(`${page.url()}: console: ${text}`);
        else if (m.type() === "error" && !allowed.some((re) => re.test(text)) && !harness(page, text)) g.errors.push(`${page.url()}: ${text}`);
      });
      page.on("pageerror", (e) => {
        // WebKit's text arrives split at its first colon, as name "Fetch API cannot load http" and
        // the rest of the URL and sentence as the message.
        const text = e.name && e.name !== "Error" ? `${e.name}:${e.message}` : e.message;
        if (webkitRefusedFetch(text) && allowed.some((re) => re.test(text))) return;
        g.errors.push(`${page.url()}: uncaught ${e.name}: ${e.message}`);
      });
      // The console says only "Failed to load resource"; which one is here.
      page.on("response", (r) => { if (r.status() >= 400) failed.push(`${r.status()} ${r.request().method()} ${r.url()}`); });
      page.on("dialog", (d) => { g.dialogs.push(`${d.type()}: ${d.message()}`); void d.dismiss().catch(() => undefined); });
      page.on("response", (r) => {
        if (r.request().resourceType() !== "document") return;
        if (r.frame() === page.mainFrame()) docType.set(page, r.headers()["content-type"] ?? "");
        g.documents.push({ url: r.url(), status: r.status() });
        headerProblems.push(...checkDocumentHeaders(r));
      });
    };
    context.pages().forEach(watch);
    context.on("page", watch);
    await use(g);
    expect(g.xss, "a script from injected content ran").toEqual([]);
    expect(g.csp, "Content-Security-Policy violations").toEqual([]);
    expect(g.dialogs, "dialogs opened").toEqual([]);
    expect(g.errors, `console errors or uncaught exceptions (responses over 400: ${failed.join("; ") || "none"})`).toEqual([]);
    expect(headerProblems, "documents served without their security headers").toEqual([]);
  }, { auto: true }],
});

export { expect };

// Requests in flight per page, so a test can wait until a view has loaded what it shows.
// Each request is counted until it finishes or fails, by the request itself (two requests for the
// same URL are two requests).
const traffic = new WeakMap<Page, { pending: Map<import("@playwright/test").Request, string>; last: number }>();
/** The URLs of the requests a page has in flight. */
export const inFlight = (page: Page): string[] => [...(traffic.get(page)?.pending.values() ?? [])];
function trackRequests(page: Page): void {
  const t = { pending: new Map<import("@playwright/test").Request, string>(), last: Date.now() };
  traffic.set(page, t);
  page.on("request", (r) => { t.pending.set(r, r.url()); t.last = Date.now(); });
  const done = (r: import("@playwright/test").Request) => { t.pending.delete(r); t.last = Date.now(); };
  page.on("requestfinished", done);
  page.on("requestfailed", done);
  // WebKit under Playwright 1.63 never reports the end of a document request whose URL has a
  // fragment (every app route: /#/e/3/ledger), measured: the request stays in flight forever.
  // Once the page has loaded, its documents have arrived.
  page.on("load", () => {
    for (const r of [...t.pending.keys()]) if (r.isNavigationRequest() && r.resourceType() === "document") done(r);
  });
}

/** Waits until the page has had no request in flight for `ms` (the app's 10-second polls aside). */
export async function quiet(page: Page, ms = 400): Promise<void> {
  const t = traffic.get(page);
  if (!t) return page.waitForLoadState("networkidle");
  const until = Date.now() + 15_000;
  while (Date.now() < until) {
    if (t.pending.size === 0 && Date.now() - t.last >= ms) return;
    await page.waitForTimeout(50);
  }
  throw new Error(`requests still in flight on ${page.url()}: ${inFlight(page).join(", ")}`);
}

/** Whether the text of an element reads left to right on screen: its first letter left of its
 *  last. A bidi override left open in text before it would show it reversed. */
export async function readsLeftToRight(page: Page, selector: string): Promise<boolean[]> {
  return page.locator(selector).evaluateAll((els) => els.map((el) => {
    const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
    const node = walker.nextNode() as Text | null;
    if (!node || node.data.trim().length < 2) return true;
    const text = node.data;
    const first = text.search(/\S/), last = text.length - 1 - [...text].reverse().join("").search(/\S/);
    const rect = (i: number) => { const r = document.createRange(); r.setStart(node, i); r.setEnd(node, i + 1); return r.getBoundingClientRect(); };
    return rect(first).left < rect(last).left;
  }));
}

/** Elements a payload would have created, and javascript: links, anywhere in the page. */
export async function injected(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll("[data-e2exss]"))) out.push(`element <${el.tagName.toLowerCase()}>`);
    for (const el of Array.from(document.querySelectorAll("a[href], area[href], iframe[src], form[action]"))) {
      const v = (el.getAttribute("href") ?? el.getAttribute("src") ?? el.getAttribute("action") ?? "").replace(/[\u0000- ]/g, "");
      if (/^(javascript|vbscript|data):/i.test(v)) out.push(`<${el.tagName.toLowerCase()}> with ${v.slice(0, 60)}`);
    }
    for (const el of Array.from(document.querySelectorAll("*"))) {
      for (const a of Array.from(el.attributes)) if (/^on/i.test(a.name)) out.push(`<${el.tagName.toLowerCase()}> with ${a.name}`);
    }
    return out;
  });
}
