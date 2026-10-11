// Drafts (D-053, EV-8): unsent text is kept in sessionStorage so that a reload or an expired session
// loses nothing, but text that looks like a credential stays in memory only. Each sample is typed
// (key by key) or pasted into a lane's evidence note and its N/A reason; the tab's storage must then
// hold no draft with it, and ordinary prose must still be kept across a reload.
import type { Page } from "@playwright/test";
import { api, APP, expect, NAMES, signInToken, test } from "../lib";

// Made-up credentials in the forms a tester pastes into a note. None is real. The ones with a
// provider's prefix are put together at run time, so that no secret scanner reads this file as
// holding a real key (and goes to ask the provider whether it works).
const j = (...parts: string[]) => parts.join("");
const CREDENTIALS = [
  "Authorization: Bearer e2eFAKEtoken0123456789",
  "Proxy-Authorization: Basic ZTJlOmZha2VwYXNzd29yZA==",
  "Cookie: session=e2efake0123456789abcdef",
  "set-cookie: sid=e2efake0123456789; HttpOnly",
  '{"access_token": "e2efake0123456789abcdef"}',
  "X-Api-Key: e2efake0123456789",
  "Ocp-Apim-Subscription-Key: e2efake0123456789abcdef",
  "password: e2eFakePassw0rd",
  "the reset link is https://app.clean.test/reset?token=e2efake0123456789",
  j("-----BEGIN OPENSSH ", "PRIVATE KEY-----"),
  j("AKIA", "E2EFAKE000000000"),
  j("eyJhbGciOiJIUzI1NiJ9", ".eyJzdWIiOiJlMmUifQ.e2efakesignature"),
  // A URL with a user name and password in it, and tokens with well-known prefixes.
  j("logged in at https://admin:e2eFakePassw0rd", "@app.clean.test/login"),
  j("gh", "p_e2eFAKE0123456789abcdefghijABCDEFGH"),
  j("github", "_pat_11E2EFAKE0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGH"),
  j("gl", "pat-e2eFAKE0123456789abcd"),
  j("xo", "xb-000000000000-0000000000000-e2eFAKE0123456789abcd"),
  j("sk", "_live_e2eFAKE0123456789abcdefgh"),
  j("AI", "zaE2EFAKE0123456789abcdefghijklmnopqr"),
];
const PROSE = ["A wrong password: 401", "The login form answers 200 for any user name, then shows the form again."];

async function drafts(page: Page): Promise<Record<string, string>> {
  return page.evaluate(() => {
    const out: Record<string, string> = {};
    for (let i = 0; i < sessionStorage.length; i++) {
      const k = sessionStorage.key(i)!;
      if (k.startsWith("attackledger-draft:")) out[k] = sessionStorage.getItem(k) ?? "";
    }
    return out;
  });
}

test.describe("drafts never keep a credential in storage", () => {
  let url: string;
  let laneId: number;
  test.beforeAll(async () => {
    const engId = await api.engagementId(NAMES.cleanEng);
    const cov = await api.call<{ assets: { roles: Record<string, { lane_id?: number }> }[] }>("GET", `/engagements/${engId}/coverage`);
    laneId = cov.assets[0].roles.mapper.lane_id!;
    url = `${APP}/#/e/${engId}/ledger/lane/${laneId}`;
  });
  test.beforeEach(async ({ context }) => { await signInToken(context); });

  async function noteField(page: Page, idx = 1) {
    const item = page.locator(".item-work").nth(idx - 1);
    const note = page.locator(`#item-${laneId}-${idx}-note`);
    if (!(await note.isVisible())) await item.getByRole("button", { name: "Add evidence" }).click();
    return note;
  }

  for (const how of ["pasted", "typed"] as const) {
    test(`a credential ${how} into a note or a reason stays out of sessionStorage`, async ({ page }) => {
      await page.goto(url);
      const note = await noteField(page);
      const reasonButton = page.locator(".item-work").nth(1).getByRole("button", { name: "Not applicable" });
      await reasonButton.click();
      const reason = page.locator(`#item-${laneId}-2-reason`);
      const leaked: string[] = [];
      for (const secret of CREDENTIALS) {
        for (const field of [note, reason]) {
          await field.fill("");
          if (how === "pasted") await field.fill(`Seen on the target: ${secret}`);
          else await field.pressSequentially(`Seen: ${secret}`, { delay: 0 });
          const stored = Object.values(await drafts(page)).join("\n");
          if (stored.includes(secret.slice(-12))) leaked.push(`${secret} (${how})`);
        }
      }
      expect(leaked, "credentials written to sessionStorage").toEqual([]);
      // In memory the text is still in the field: nothing the person typed is lost while the tab is open.
      await expect(note).toHaveValue(new RegExp(CREDENTIALS[CREDENTIALS.length - 1].slice(-12)));
      await note.fill("");
      await reason.fill("");
    });
  }

  test("prose is kept across a reload, and a credential is not", async ({ page }) => {
    await page.goto(url);
    const note = await noteField(page);
    await note.fill(PROSE[1]);
    const second = await noteField(page, 2);
    await second.fill(`${PROSE[0]} ${CREDENTIALS[0]}`);
    expect(Object.values(await drafts(page))).toEqual([PROSE[1]]);
    await page.reload();
    await expect(page.locator(`#item-${laneId}-1-note`)).toHaveValue(PROSE[1]);
    await expect(page.locator(`#item-${laneId}-2-note`)).toHaveCount(0);
    await page.locator(`#item-${laneId}-1-note`).fill("");
    expect(await drafts(page)).toEqual({});
  });

  test("signing out clears every draft", async ({ page }) => {
    await page.goto(url);
    const note = await noteField(page);
    await note.fill(PROSE[1]);
    expect(Object.keys(await drafts(page)).length).toBe(1);
    await page.goto(url.replace(/\/lane\/\d+$/, ""));      // the lane panel covers the sidebar
    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page.getByText("You have signed out.")).toBeVisible();
    expect(await drafts(page)).toEqual({});
  });
});
