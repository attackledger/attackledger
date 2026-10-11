// Drafts belong to whoever typed them (D-053): when a session ends and someone else signs in on the
// same tab, they must not get the first person's unsent notes; the same person signing back in gets
// them back. This must hold in a tab that was opened while already signed in (a second tab, a
// reload), not only in one where the person typed their password.
import type { Page } from "@playwright/test";
import { api, APP, dismissAccount, expect, NAMES, PEOPLE, signInPerson, test } from "../lib";

const NOTE = "Half-written: the export endpoint answers 200 without a session, check it with the tester account";

async function drafts(page: Page): Promise<string[]> {
  return page.evaluate(() => Object.keys(sessionStorage).filter((k) => k.startsWith("attackledger-draft:")).map((k) => sessionStorage.getItem(k) ?? ""));
}

async function signInOnForm(page: Page, who: { email: string; password: string }) {
  await page.getByLabel("Email").fill(who.email);
  await page.getByLabel("Password").fill(who.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.locator(".whoami")).toBeVisible();
  await dismissAccount(page);
}

for (const next of ["someone else", "the same person"] as const) {
  test(`a session ends in a tab opened while signed in, then ${next} signs in`, async ({ page, context, guard }) => {
    guard.allowConsole(/status of 401/);
    const engId = await api.engagementId(NAMES.cleanEng);
    const cov = await api.call<{ assets: { roles: Record<string, { lane_id?: number }> }[] }>("GET", `/engagements/${engId}/coverage`);
    const lane = cov.assets[0].roles.mapper.lane_id!;
    // The tester's session comes from elsewhere (as in a second tab): this tab never saw a sign-in form.
    await signInPerson(context, PEOPLE.tester.email, PEOPLE.tester.password);
    await page.goto(`${APP}/#/e/${engId}/ledger/lane/${lane}`);
    await dismissAccount(page);
    await page.locator(".item-work").nth(2).getByRole("button", { name: "Add evidence" }).click();
    await page.locator(`#item-${lane}-3-note`).fill(NOTE);
    await expect.poll(() => drafts(page)).toEqual([NOTE]);

    // The session ends (it expired, or was ended elsewhere); the app asks to sign in again.
    await context.request.post(`${APP}/api/auth/logout`);
    await page.reload();
    await expect(page.getByLabel("Email")).toBeVisible();

    await signInOnForm(page, next === "someone else" ? PEOPLE.reviewer : PEOPLE.tester);
    if (next === "someone else") {
      expect(await drafts(page), "the tester's unsent note, kept for the reviewer").toEqual([]);
    } else {
      expect(await drafts(page)).toEqual([NOTE]);
      await page.goto(`${APP}/#/e/${engId}/ledger/lane/${lane}`);
      await expect(page.locator(`#item-${lane}-3-note`)).toHaveValue(NOTE);
      await page.locator(`#item-${lane}-3-note`).fill("");
    }
  });
}
