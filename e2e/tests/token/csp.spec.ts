// The CSP holds on every page and tab: the guard (lib.ts) fails a test on any violation, from the
// securitypolicyviolation event or a console report, and checks the headers of every document.
// Here every tab of every engagement is opened in both themes, with the pages the API serves.
import { api, APP, expect, NAMES, openTab, quiet, signInToken, test } from "../lib";

const TABS = ["recon", "import", "ledger", "controls", "report", "verify", "history", "accounts", "approvals", "team"];

for (const theme of ["light", "dark"] as const) {
  test(`every tab of every engagement, ${theme} theme`, async ({ page, context }) => {
    await context.addInitScript((t) => { try { localStorage.setItem("attackledger-theme", t); } catch { /* blocked */ } }, theme);
    await signInToken(context);
    const engagements = await api.call<{ id: number; name: string }[]>("GET", "/engagements");
    expect(engagements.length).toBeGreaterThanOrEqual(3);
    for (const e of engagements) {
      for (const tab of TABS) {
        await openTab(page, e.id, tab);
        await quiet(page);
        await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
      }
    }
    await page.goto(`${APP}/#/people`);
    await expect(page.getByRole("heading", { name: "People" })).toBeVisible();
    await quiet(page);
  });
}

test("documents the app and the API serve carry their headers", async ({ page, context }) => {
  await signInToken(context);
  const engId = await api.engagementId(NAMES.cleanEng);
  // The app's index under several paths (nginx answers unknown paths with it), a link to an
  // engagement that does not exist, and the API's own pages.
  for (const path of ["/", "/index.html", "/no/such/page", `/#/e/999999/ledger`,
                      `/api/engagements/${engId}/report.html`, "/api/docs", "/api/verifier"]) {
    const res = await page.goto(`${APP}${path}`);
    expect(res, path).not.toBeNull();
    expect(res!.status(), path).toBeLessThan(400);
    await quiet(page);
  }
  await expect(page.locator("body")).not.toBeEmpty();
  // The bundle and the stylesheet: from this origin, as the policy says, and not sniffable.
  await page.goto(APP);
  const assets = await page.evaluate(() => performance.getEntriesByType("resource").map((r) => r.name));
  expect(assets.length).toBeGreaterThan(0);
  for (const url of assets) expect(new URL(url).origin, url).toBe(APP);
});
