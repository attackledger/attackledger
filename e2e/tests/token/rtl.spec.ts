// Bidi controls in text from people and tools (an engagement name, a note, a recon title) must not
// reorder what the app writes after them: a right-to-left override left open in a name would make
// the engagement's type read backwards next to it ("ytnuob guB") if both were in one line of
// inline text. The app's layout keeps each in its own box; a control in plain markup shows that the
// check sees a reversal where there is one.
import { api, APP, expect, NAMES, openTab, readsLeftToRight, signInToken, test } from "../lib";

test("an open right-to-left override does not reverse the text after it", async ({ page, context }) => {
  await signInToken(context);
  const engId = await api.engagementId(NAMES.hostileEng);
  await openTab(page, engId, "ledger");
  const entry = page.locator(".engagement", { hasText: "E2E <img" });
  await expect(entry).toBeVisible();
  // The control: the same text in plain inline markup does read backwards, so the check sees it.
  await page.evaluate(() => {
    const p = document.createElement("p");
    p.id = "e2e-bidi-control";
    p.append("\u202Eexe.txt ");
    const s = document.createElement("span");
    s.textContent = "Bug bounty";
    p.append(s);
    document.body.append(p);
  });
  expect(await readsLeftToRight(page, "#e2e-bidi-control span")).toEqual([false]);
  await page.evaluate(() => document.getElementById("e2e-bidi-control")?.remove());
  expect(await readsLeftToRight(page, '.engagement[aria-current="page"] .engagement-type')).toEqual([true]);
  expect(await readsLeftToRight(page, '.engagement[aria-current="page"] .count')).toEqual([true]);

  const cov = await api.call<{ assets: { host: string; roles: Record<string, { lane_id?: number }> }[] }>("GET", `/engagements/${engId}/coverage`);
  const lane = cov.assets.find((a) => a.host === NAMES.app)!.roles.recon.lane_id;
  await page.goto(`${APP}/#/e/${engId}/ledger/lane/${lane}`);
  await expect(page.locator(".ev-item").first()).toBeVisible();
  const items = await readsLeftToRight(page, ".ev-item");
  expect(items.length).toBeGreaterThan(3);
  expect(items.every(Boolean), "evidence item labels after a hostile summary").toBe(true);

  await openTab(page, engId, "recon");
  await page.locator("#results").getByRole("tab", { name: /^Leads/ }).click();
  await expect(page.locator(".lead-preview").first()).toBeVisible();
  expect((await readsLeftToRight(page, ".lead-kind")).every(Boolean)).toBe(true);
});
