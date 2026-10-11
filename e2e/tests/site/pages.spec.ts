// The public site (attackledger.com), built by tools/build_pages.sh and served with its _headers as
// Cloudflare Pages applies them (tests/pages-server.mjs). Every page a visitor can reach from the
// home page, the not-found page, and the read-only demo with every tab of every engagement and
// every lane, in both themes, under the guard (lib.ts): no CSP violation, no console error, every
// document with its headers; and no request to any origin but the site's own and Google Fonts
// (site-lib.ts, offline).
import { readFileSync } from "node:fs";
import path from "node:path";
import type { APIRequestContext, Page } from "@playwright/test";
import { checkSiteHeaders, expect, quiet, SITE } from "../lib";
import { OUT, siteTest as test } from "../site-lib";

/** Every same-origin page reachable from the home page by links, with where each was linked from. */
async function crawl(request: APIRequestContext): Promise<Map<string, string>> {
  const pages = new Map<string, string>([["/", "start"]]);
  const queue = ["/"];
  while (queue.length) {
    const at = queue.shift()!;
    const res = await request.get(SITE + at);
    expect(res.status(), `${at} (linked from ${pages.get(at)})`).toBeLessThan(400);
    const final = new URL(res.url()).pathname;
    if (!(res.headers()["content-type"] ?? "").startsWith("text/html")) continue;
    for (const m of (await res.text()).matchAll(/<a\b[^>]*\bhref="([^"]*)"/g)) {
      const href = m[1].replace(/&amp;/g, "&");
      if (href.startsWith("#")) continue;
      const u = new URL(href, SITE + final);
      if (u.origin !== SITE) {
        expect(u.protocol, `${href} on ${final}`).toMatch(/^(https|mailto):$/);
        continue;
      }
      if (!pages.has(u.pathname)) { pages.set(u.pathname, final); queue.push(u.pathname); }
    }
  }
  return pages;
}

const demoData = JSON.parse(readFileSync(path.join(OUT, "demo/demo-data.json"), "utf8")) as { get: Record<string, unknown> };
const ENGAGEMENTS = (demoData.get["/engagements"] as { id: number; name: string }[]);
const LANES = Object.entries(demoData.get).filter(([k]) => /^\/lanes\/\d+$/.test(k))
  .map(([, v]) => v as { id: number; engagement_id: number; host: string; name?: string; role: string });

const mainTabs = (page: Page) => page.getByRole("tablist", { name: "Engagement views" }).getByRole("tab");

async function demoTabs(page: Page, engId: number): Promise<string[]> {
  await page.goto(`${SITE}/demo/#/e/${engId}`);
  const tabs = mainTabs(page);
  await expect(tabs.first()).toBeVisible();
  await quiet(page);
  return tabs.allTextContents();
}

for (const theme of ["light", "dark"] as const) {
  test.describe(`${theme} theme`, () => {
    test.use({ colorScheme: theme });

    test("every page linked from the home page, and the not-found page", async ({ page, request, guard }) => {
      const pages = await crawl(request);
      // The pages a visitor reaches: the home page, the security policy, the verifier, the sample
      // report, the demo; the downloads (JSON, the script, the root, security.txt) are not pages.
      for (const p of ["/", "/security", "/verify", "/sample-report.html", "/sample-report.json", "/demo/", "/verify_report.py",
                       "/digicert-trusted-root-g4.pem", "/.well-known/security.txt"]) {
        expect([...pages.keys()], p).toContain(p);
      }
      for (const p of [...pages.keys(), "/demo/reports/1.html", "/demo/reports/2.html", "/demo/reports/3.html", "/demo/reports/4.html"]) {
        const res = await page.goto(SITE + p);
        expect(res?.status(), p).toBeLessThan(400);
        await quiet(page);
        await expect(page.locator("body"), p).not.toBeEmpty();
      }
      // An unknown path: the site's own not-found page, with status 404 and the same headers.
      guard.allowConsole(/status of 404/);
      const res = await page.goto(`${SITE}/no/such/page`);
      expect(res?.status()).toBe(404);
      await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
      await quiet(page);
      expect(guard.documents.filter((d) => d.status === 404).map((d) => new URL(d.url).pathname)).toEqual(["/no/such/page"]);
      // The guard checked the headers of each of these documents as it saw them.
      expect(guard.documents.map((d) => new URL(d.url).pathname))
        .toEqual(expect.arrayContaining(["/", "/security", "/verify", "/sample-report", "/demo/", "/demo/reports/3"]));
    });

    test("the demo: every tab of every engagement, and every lane", async ({ page, context }) => {
      test.setTimeout(240_000);
      await context.addInitScript((t) => { try { localStorage.setItem("attackledger-theme", t); } catch { /* blocked */ } }, theme);
      expect(ENGAGEMENTS.length).toBeGreaterThanOrEqual(4);
      for (const e of ENGAGEMENTS) {
        const tabs = await demoTabs(page, e.id);
        expect(tabs.length, e.name).toBeGreaterThanOrEqual(5);
        for (let i = 0; i < tabs.length; i++) {
          const tab = mainTabs(page).nth(i);
          await tab.click();
          await expect(tab).toHaveAttribute("aria-selected", "true");
          await quiet(page);
          await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
        }
      }
      for (const lane of LANES) {
        await page.goto(`${SITE}/demo/#/e/${lane.engagement_id}/ledger/lane/${lane.id}`);
        await expect(page.getByRole("dialog").or(page.locator(".folio")).first(), `lane ${lane.id}`).toBeVisible();
        await quiet(page);
        // Raw evidence the demo has: fetched from the site (connect-src 'self') and shown as text.
        const raw = page.getByRole("button", { name: /^View raw/ });
        if (await raw.count()) {
          await raw.first().click();
          await expect(page.getByRole("dialog", { name: "Raw evidence" })).toBeVisible();
          await expect(page.getByLabel("Raw evidence bytes")).not.toBeEmpty();
          await page.getByRole("dialog", { name: "Raw evidence" }).getByRole("button", { name: "Close" }).click();
        }
      }
      // A change is refused in the demo, and nothing is sent: everything stayed on the site.
      const sent = await page.evaluate(() => performance.getEntriesByType("resource").map((r) => r.name));
      for (const url of sent) expect(new URL(url).origin, url).toBe(SITE);
    });
  });
}

test("downloads and files are served as what they are, and the configuration is not served", async ({ request }) => {
  const type = async (p: string) => (await request.get(SITE + p, { maxRedirects: 0 })).headers()["content-type"] ?? "";
  expect(await type("/sample-report.json")).toMatch(/^application\/json/);
  for (const p of ["/verify_report.py", "/digicert-trusted-root-g4.pem", "/.well-known/security.txt"]) {
    expect(await type(p), p).toBe("text/plain; charset=utf-8");
  }
  for (const p of ["/_headers", "/_redirects"]) expect((await request.get(SITE + p)).status(), p).toBe(404);
  // Pages' routing, which the links rely on: /x.html moves to /x, and /x serves it.
  const moved = await request.get(`${SITE}/sample-report.html`, { maxRedirects: 0 });
  expect(moved.status()).toBe(308);
  expect(moved.headers().location).toBe("/sample-report");
  // The verifier page's script and the published copy of verify_report.py are the files in the
  // checkout: what a visitor gets is what the repository holds.
  expect(await (await request.get(`${SITE}/verify_report.py`)).text())
    .toBe(readFileSync("/repo/site/verify_report.py", "utf8"));
  expect(await (await request.get(`${SITE}/verify`)).text()).toBe(readFileSync("/repo/site/verify.html", "utf8"));
});

test("the header check fails a document without the site's headers (a control)", async ({ request }) => {
  const served = await request.get(`${SITE}/verify`);
  const as = (path: string, headers: Record<string, string>) =>
    checkSiteHeaders({ url: () => SITE + path, status: () => 200, headers: () => headers } as never);
  expect(as("/verify", served.headers())).toEqual([]);
  // Without the verifier's own policy, /verify fails: only the site's (which allows connections).
  const siteOnly = { ...served.headers(), "content-security-policy": served.headers()["content-security-policy"].split(",")[0] };
  expect(as("/verify", siteOnly).join("\n")).toContain("the verifier's policy lacks connect-src 'none'");
  expect(as("/", {}).length).toBeGreaterThanOrEqual(6);
  const unsafe = { ...served.headers(), "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'" };
  expect(as("/", unsafe).join("\n")).toContain("script-src allows more than this origin and hashes");
});
