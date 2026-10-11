// Shared by every spec: the addresses, the hostile strings, an API client, and the guard
// fixture that watches every page a test opens.
import { expect, test as base, type BrowserContext, type Page, type Response } from "@playwright/test";

export const APP = "http://localhost:18180";
/** The API as the runner reaches it without a browser (seeding, checks): straight to the web container. */
export const API = "http://web/api";
export const SIBLING = "http://localhost:18181";   // same site as the app, another origin
export const OTHER_SITE = "http://127.0.0.1:18181";  // another site
export const VERIFY_PAGE = "http://localhost:18182/verify.html";

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
  svg: (id: string) => `"><svg onload="${X(id)}" data-e2exss><circle r=9 /></svg>`,
  script: (id: string) => `</script><script data-e2exss>${X(id)}</script>`,
  iframe: (id: string) => `<iframe srcdoc="<script>parent.${X(id)}</script>" data-e2exss></iframe>`,
  css: () => `<style data-e2exss>*{background:red!important}</style><div style="position:fixed;inset:0" data-e2exss></div>`,
  js: (id: string) => `javascript:${X(id)}//`,
  rtl: "‮exe.txt‬ e2exss-rtl ⁧אבג",
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
  scope: "*.xss.test",
  app: "app.xss.test",
  api: "api.xss.test",
};

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

/** Opens an engagement (by name) on a tab, and waits for the tab panel. */
export async function openTab(page: Page, engId: number, tab: string): Promise<void> {
  // A load that hangs says which requests it waits for (a diagnostic for a slow test machine).
  const timer = setTimeout(() => console.log(`[e2e] ${page.url()} still loading after 20 s; in flight:`,
    [...((page as unknown as { __pending?: Set<string> }).__pending ?? [])]), 20_000);
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
  const h = r.headers();
  const bad: string[] = [];
  const want = (name: string, value: string) => {
    if ((h[name] ?? "").toLowerCase() !== value.toLowerCase()) bad.push(`${url.pathname}: ${name} is ${JSON.stringify(h[name] ?? null)}, not ${value}`);
  };
  if (url.origin !== APP) return bad;               // the test's own pages
  const csp = h["content-security-policy"] ?? "";
  want("x-content-type-options", "nosniff");
  if (url.pathname.startsWith("/api/")) {
    // The API's documents (the printable report, raw evidence, the docs) carry the API's own policy.
    if (!csp.includes("default-src 'none'")) bad.push(`${url.pathname}: no default-src 'none' in ${JSON.stringify(csp)}`);
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

export const test = base.extend<{ guard: Guard }>({
  guard: [async ({ context }, use) => {
    const allowed: RegExp[] = [];
    const g: Guard = { csp: [], xss: [], dialogs: [], errors: [], documents: [], allowConsole: (re) => allowed.push(re) };
    const headerProblems: string[] = [];
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
        if (/Content[- ]Security[- ]Policy|CSP/i.test(text)) g.csp.push(`${page.url()}: console: ${text}`);
        else if (m.type() === "error" && !allowed.some((re) => re.test(text)) && !harness(page, text)) g.errors.push(`${page.url()}: ${text}`);
      });
      page.on("pageerror", (e) => g.errors.push(`${page.url()}: uncaught ${e.name}: ${e.message}`));
      page.on("dialog", (d) => { g.dialogs.push(`${d.type()}: ${d.message()}`); void d.dismiss().catch(() => undefined); });
      page.on("response", (r) => {
        if (r.request().resourceType() !== "document") return;
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
    expect(g.errors, "console errors or uncaught exceptions").toEqual([]);
    expect(headerProblems, "documents served without their security headers").toEqual([]);
  }, { auto: true }],
});

export { expect };

// Requests in flight per page, so a test can wait until a view has loaded what it shows.
const traffic = new WeakMap<Page, { inflight: number; last: number }>();
function trackRequests(page: Page): void {
  const t = { inflight: 0, last: Date.now() };
  traffic.set(page, t);
  const pending = new Set<string>();
  page.on("request", (r) => { t.inflight++; t.last = Date.now(); pending.add(r.url()); });
  const done = (r: import("@playwright/test").Request) => { pending.delete(r.url()); t.inflight = Math.max(0, t.inflight - 1); t.last = Date.now(); };
  (page as unknown as { __pending: Set<string> }).__pending = pending;
  page.on("requestfinished", done);
  page.on("requestfailed", done);
}

/** Waits until the page has had no request in flight for `ms` (the app's 10-second polls aside). */
export async function quiet(page: Page, ms = 400): Promise<void> {
  const t = traffic.get(page);
  if (!t) return page.waitForLoadState("networkidle");
  const until = Date.now() + 15_000;
  while (Date.now() < until) {
    if (t.inflight === 0 && Date.now() - t.last >= ms) return;
    await page.waitForTimeout(50);
  }
  throw new Error(`requests still in flight on ${page.url()}`);
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
