// Accessibility smoke test: axe-core (WCAG 2.2 A and AA rules) on the sign-in form, each main tab,
// an open lane, the People page and the public verifier page, in the light and the dark theme.
// No serious or critical violation is allowed.
import AxeBuilder from "@axe-core/playwright";
import type { Page } from "@playwright/test";
import { api, APP, expect, NAMES, openTab, quiet, signInToken, test, VERIFY_PAGE } from "../lib";

const TABS = ["recon", "import", "ledger", "controls", "report", "verify", "history", "accounts", "approvals", "team"];

async function axe(page: Page, where: string): Promise<string[]> {
  await quiet(page);
  const r = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
  return r.violations
    .filter((v) => v.impact === "serious" || v.impact === "critical")
    .map((v) => `${where}: ${v.id} (${v.impact}) ${v.help}: ${v.nodes.slice(0, 3).map((n) => n.target.join(" ")).join(", ")}`);
}

for (const theme of ["light", "dark"] as const) {
  test.describe(`${theme} theme`, () => {
    test.use({ colorScheme: theme });
    test.beforeEach(async ({ context }) => {
      await context.addInitScript((t) => { try { localStorage.setItem("attackledger-theme", t); } catch { /* blocked */ } }, theme);
    });

    test("sign-in form", async ({ page, guard }) => {
      guard.allowConsole(/status of 401/);
      await page.goto(APP);
      await expect(page.getByLabel("API token")).toBeVisible();
      expect(await axe(page, "sign-in")).toEqual([]);
    });

    test("every main tab, a lane and the People page", async ({ page, context }) => {
      test.setTimeout(180_000);
      await signInToken(context);
      const problems: string[] = [];
      for (const name of [NAMES.cleanEng, NAMES.hostileEng]) {
        const engId = await api.engagementId(name);
        for (const tab of TABS) {
          await openTab(page, engId, tab);
          problems.push(...await axe(page, `${name.slice(0, 16)} ${tab}`));
        }
      }
      const engId = await api.engagementId(NAMES.cleanEng);
      const cov = await api.call<{ assets: { roles: Record<string, { lane_id?: number }> }[] }>("GET", `/engagements/${engId}/coverage`);
      for (const role of ["recon", "mapper"]) {
        await page.goto(`${APP}/#/e/${engId}/ledger/lane/${cov.assets[0].roles[role].lane_id}`);
        await expect(page.getByRole("dialog").or(page.locator(".folio")).first()).toBeVisible();
        problems.push(...await axe(page, `lane ${role}`));
      }
      await page.goto(`${APP}/#/people`);
      await expect(page.getByRole("heading", { name: "People" })).toBeVisible();
      problems.push(...await axe(page, "people"));
      expect(problems).toEqual([]);
    });

    test("the printable report of each engagement", async ({ page, context }) => {
      // The server's own HTML report (server/app/report.py), as the app opens it and as it is
      // downloaded and published (site/sample-report.html). Its own colours: one look for both themes.
      await signInToken(context);
      const problems: string[] = [];
      for (const name of [NAMES.cleanEng, NAMES.hostileEng, NAMES.unicodeEng]) {
        const engId = await api.engagementId(name);
        await page.goto(`${APP}/api/engagements/${engId}/report.html`);
        await expect(page.locator("h1")).toBeVisible();
        problems.push(...await axe(page, `report.html of ${name.slice(0, 16)}`));
      }
      expect(problems).toEqual([]);
    });

    test("the public verifier page", async ({ page }) => {
      await page.goto(VERIFY_PAGE);
      expect(await axe(page, "verify.html")).toEqual([]);
    });
  });
}
