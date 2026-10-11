// Accessibility of the public site: axe-core (WCAG 2.2 A and AA rules) on every page, the
// not-found page, the verifier page with a result shown, and every tab of the demo's richest
// engagement and one of its lanes, in the light and the dark theme. No serious or critical
// violation is allowed.
import { readFileSync } from "node:fs";
import path from "node:path";
import AxeBuilder from "@axe-core/playwright";
import type { Page } from "@playwright/test";
import { expect, quiet, SITE } from "../lib";
import { OUT, siteTest as test } from "../site-lib";

async function axe(page: Page, where: string): Promise<string[]> {
  await quiet(page);
  // The page as a visitor sees it once it has settled: after its stamps have been pressed (an
  // entry animation that starts faint), not in the middle of one.
  await page.evaluate(() => Promise.race([Promise.all(document.getAnimations().map((a) => a.finished.catch(() => undefined))),
                                          new Promise((r) => setTimeout(r, 3000))]));
  // No preload: axe would fetch the cross-origin Google Fonts stylesheet itself (to read media
  // queries), which the site's connect-src rightly refuses; that request is axe's, not the page's.
  const r = await new AxeBuilder({ page }).options({ preload: false })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
  return r.violations
    .filter((v) => v.impact === "serious" || v.impact === "critical")
    .map((v) => `${where}: ${v.id} (${v.impact}) ${v.help}: ${v.nodes.slice(0, 3).map((n) => n.target.join(" ")).join(", ")}`);
}

const PAGES = ["/", "/security", "/verify", "/sample-report", "/demo/reports/1", "/demo/reports/2", "/demo/reports/4", "/no/such/page"];

for (const theme of ["light", "dark"] as const) {
  test.describe(`${theme} theme`, () => {
    test.use({ colorScheme: theme });

    test("every page of the site", async ({ page, guard }) => {
      guard.allowConsole(/status of 404/);           // /no/such/page: the not-found page, answered 404
      const problems: string[] = [];
      for (const p of PAGES) {
        await page.goto(SITE + p);
        problems.push(...await axe(page, p));
      }
      // The verifier with a result on the page: a report that verifies, as HTML (with its facts).
      await page.goto(`${SITE}/verify`);
      await page.locator("#report-file").setInputFiles({ name: "sample-report.html", mimeType: "text/html",
                                                         buffer: readFileSync(path.join(OUT, "sample-report.html")) });
      await expect(page.locator("#status")).toHaveText("sample-report.html: verified. No check failed.");
      await expect(page.locator(".selftest")).toBeVisible();
      problems.push(...await axe(page, "/verify with a result"));
      expect(problems).toEqual([]);
    });

    test("the demo: every tab and a lane", async ({ page, context }) => {
      test.setTimeout(120_000);
      await context.addInitScript((t) => { try { localStorage.setItem("attackledger-theme", t); } catch { /* blocked */ } }, theme);
      const problems: string[] = [];
      await page.goto(`${SITE}/demo/`);
      await expect(page.locator(".demo-banner")).toBeVisible();
      problems.push(...await axe(page, "/demo/"));
      await page.goto(`${SITE}/demo/#/e/3`);
      const tabs = page.getByRole("tablist", { name: "Engagement views" }).getByRole("tab");
      await expect(tabs.first()).toBeVisible();
      for (let i = 0; i < await tabs.count(); i++) {
        await tabs.nth(i).click();
        await expect(tabs.nth(i)).toHaveAttribute("aria-selected", "true");
        problems.push(...await axe(page, `demo tab ${await tabs.nth(i).textContent()}`));
      }
      await page.goto(`${SITE}/demo/#/e/3/ledger/lane/7`);
      await expect(page.getByRole("dialog").or(page.locator(".folio")).first()).toBeVisible();
      problems.push(...await axe(page, "demo lane 7"));
      expect(problems).toEqual([]);
    });
  });
}
