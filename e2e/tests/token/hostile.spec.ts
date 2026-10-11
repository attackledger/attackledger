// Hostile content renders as text: names, notes, reasons, imports, recon results, findings, test
// accounts and write proposals full of markup, javascript: URLs, CSS, RTL overrides and very long
// strings (seed.ts). Every view of the hostile engagement is opened with the CSP in force (the
// guard fails on any violation, since an injected element would try to run or load something),
// and again with the CSP switched off in the browser, so that the app's own escaping is tested
// on its own: no injected element, no javascript: link, no script run.
import type { Page } from "@playwright/test";
import { api, APP, expect, injected, NAMES, openTab, quiet, signInToken, test } from "../lib";

const TABS = ["recon", "import", "ledger", "controls", "report", "verify", "history", "accounts", "approvals"];

async function settle(page: Page): Promise<void> {
  await quiet(page);
  await expect(page.getByText(/Loading…|Checking the report…|Building report…/)).toHaveCount(0);
}

async function expectClean(page: Page, where: string): Promise<void> {
  expect(await injected(page), `${where}: elements or links made from hostile content`).toEqual([]);
}

/** Clicks the expanders of a view (Details buttons, closed <details>) so their content renders too. */
async function expandAll(page: Page): Promise<void> {
  for (const b of await page.getByRole("button", { name: /^Details$/ }).all()) if (await b.isVisible()) await b.click();
  await page.evaluate(() => document.querySelectorAll("details").forEach((d) => { d.open = true; }));
}

/** Opens one of the recon result views and waits until its rows are there. */
async function showResults(page: Page, name: string): Promise<void> {
  const results = page.locator("#results");
  await results.getByRole("tab", { name: new RegExp(`^${name}`) }).click();
  const rows = { "Golden targets": "tbody tr", Hosts: "tbody tr", URLs: ".ep-list li", Leads: ".leads li", Runs: "li, tr" }[name]!;
  await expect(results.locator(rows).first()).toBeVisible();
  await settle(page);
  await expandAll(page);
}

for (const csp of ["with the CSP", "with the CSP switched off"] as const) {
  test.describe(`hostile content renders as text, ${csp}`, () => {
    test.use({ bypassCSP: csp !== "with the CSP" });
    let engId: number;
    test.beforeAll(async () => { engId = await api.engagementId(NAMES.hostileEng); });
    test.beforeEach(async ({ context }) => { await signInToken(context); });

    test("every tab", async ({ page }) => {
      for (const tab of TABS) {
        await openTab(page, engId, tab);
        await settle(page);
        await expandAll(page);
        await expectClean(page, tab);
      }
      // The engagement's name is shown as typed, markup and all.
      await expect(page.locator(".eng-title")).toContainText("<img src=x onerror=");
      await expect(page.locator(".engagement-name", { hasText: "E2E <img src=x onerror=" })).toHaveCount(1);
    });

    test("recon results: hosts, golden targets, URLs, leads and findings", async ({ page }) => {
      await openTab(page, engId, "recon");
      const results = page.locator("#results");
      for (const name of ["Golden targets", "Hosts", "URLs", "Leads", "Runs"]) {
        await showResults(page, name);
        await expectClean(page, `recon ${name}`);
      }
      await results.getByRole("tab", { name: /^Leads/ }).click();
      await expect(results.getByText("e2exss finding-title", { exact: false })).toBeVisible();
      // Links to recon URLs go to http(s) addresses only.
      for (const a of await page.locator("#results a[href]").all()) {
        expect(await a.getAttribute("href")).toMatch(/^https?:\/\//);
      }
    });

    test("recon URLs that are not http(s) are shown as text, not links", async ({ page }) => {
      // The API refuses such URLs now (seed.ts checks it); rows stored before, or a server that
      // sends one anyway, must still not become a javascript: link.
      const bad = (id: string) => `javascript:__xss('${id}')//`;
      await page.route("**/api/engagements/*/observations*", async (route) => {
        const rows = await (await route.fetch()).json() as { url?: string }[];
        await route.fulfill({ json: rows.map((r) => ({ ...r, url: bad("observation-url") })) });
      });
      await page.route("**/api/engagements/*/triage*", async (route) => {
        const t = await (await route.fetch()).json() as { hosts: { urls: string[] }[] };
        await route.fulfill({ json: { ...t, hosts: t.hosts.map((h) => ({ ...h, urls: [bad("triage-url")] })) } });
      });
      await page.route("**/api/engagements/*/leads*", async (route) => {
        const rows = await (await route.fetch()).json() as { source_url: string }[];
        await route.fulfill({ json: rows.map((r) => ({ ...r, source_url: bad("lead-url") })) });
      });
      await page.route("**/api/engagements/*/endpoints*", async (route) => {
        const r = await (await route.fetch()).json() as { items: { url: string }[] };
        await route.fulfill({ json: { ...r, items: r.items.map((e, i) => ({ ...e, url: `${bad("endpoint-url")}${i}` })) } });
      });
      await openTab(page, engId, "recon");
      const results = page.locator("#results");
      for (const name of ["Golden targets", "Hosts", "URLs", "Leads"]) {
        await showResults(page, name);
        await expectClean(page, `recon ${name}`);
        if (name === "Golden targets" || name === "Hosts") {
          // The host is listed, as text rather than as a link to the URL.
          await expect(results.getByRole("rowheader", { name: NAMES.app, exact: true })).toBeVisible();
          await expect(results.getByRole("link", { name: NAMES.app })).toHaveCount(0);
        } else {
          // The URL is shown as it was sent, as text.
          await expect(results.getByText(/^javascript:__xss\('(endpoint|lead)-url'\)/).first()).toBeVisible();
        }
      }
    });

    test("a lane's evidence, N/A reasons and receipt", async ({ page }) => {
      const cov = await api.call<{ assets: { host: string; roles: Record<string, { lane_id?: number }> }[] }>(
        "GET", `/engagements/${engId}/coverage`);
      const row = cov.assets.find((a) => a.host === NAMES.app)!;
      for (const role of ["recon", "mapper"]) {
        await page.goto(`${APP}/#/e/${engId}/ledger/lane/${row.roles[role].lane_id}`);
        await expect(page.locator(".folio, [aria-label*='lane' i]").first()).toBeVisible();
        await settle(page);
        await expandAll(page);
        await expectClean(page, `lane ${role}`);
      }
      await page.goto(`${APP}/#/e/${engId}/ledger/lane/${row.roles.recon.lane_id}`);
      await expect(page.getByText("e2exss summary-1", { exact: false }).first()).toBeVisible();
    });

    test("raw evidence opens as inert text", async ({ page, context }) => {
      const cov = await api.call<{ assets: { host: string; roles: Record<string, { lane_id?: number }> }[] }>(
        "GET", `/engagements/${engId}/coverage`);
      const lane = cov.assets.find((a) => a.host === NAMES.app)!.roles.mapper.lane_id;
      await page.goto(`${APP}/#/e/${engId}/ledger/lane/${lane}`);
      const links = page.getByRole("link", { name: /^View raw/ });
      await expect(links.first()).toBeVisible();
      for (const link of await links.all()) {
        const [raw] = await Promise.all([context.waitForEvent("page"), link.click()]);
        await raw.waitForLoadState();
        expect(new URL(raw.url()).pathname).toMatch(/^\/api\/blobs\/[0-9a-f]{64}$/);
        await expectClean(raw, "raw evidence");
        await raw.close();
      }
    });

    test("an imported entry and its raw parts", async ({ page, context }) => {
      const inbox = await api.call<{ entries: { id: number; url: string }[] }>("GET", `/engagements/${engId}/inbox?limit=50`);
      expect(inbox.entries.length).toBeGreaterThan(0);
      for (const e of inbox.entries) {
        await page.goto(`${APP}/#/e/${engId}/import/entry/${e.id}`);
        await expect(page.locator(".import-entry")).toBeVisible();
        await settle(page);
        await expectClean(page, `import entry ${e.id}`);
      }
      const first = inbox.entries.find((e) => e.url.includes("search"))!;
      await page.goto(`${APP}/#/e/${engId}/import/entry/${first.id}`);
      await expect(page.locator(".import-url")).toContainText("<script>__xss('har-url')</script>");
      for (const name of ["View request", "View response", "View record"]) {
        const [raw] = await Promise.all([context.waitForEvent("page"), page.getByRole("link", { name }).click()]);
        await raw.waitForLoadState();
        await expectClean(raw, name);
        await raw.close();
      }
    });

    test("the printable report", async ({ page, context }) => {
      await openTab(page, engId, "report");
      const [report] = await Promise.all([context.waitForEvent("page"),
                                          page.getByRole("link", { name: "Open printable report" }).click()]);
      await report.waitForLoadState();
      await expect(report.locator("body")).toContainText("<img src=x onerror=");
      await expectClean(report, "printable report");
      await report.close();
    });
  });
}
