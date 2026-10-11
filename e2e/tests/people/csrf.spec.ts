// Login CSRF (AUTH-2) in people mode: a page of another origin posts the attacker's own email and
// password to the sign-in, to put the victim's browser in the attacker's account (where what the
// victim then records would be the attacker's to read). Refused; the victim stays who they were.
import { APP, expect, OTHER_SITE, PEOPLE, SIBLING, signInPerson, test } from "../lib";

for (const [label, origin] of [["a sibling on the same site", SIBLING], ["another site", OTHER_SITE]] as const) {
  test(`a sign-in posted from ${label} is refused`, async ({ page, context, guard }) => {
    guard.allowConsole(/status of 403|Failed to load resource/);
    await signInPerson(context, PEOPLE.reader.email, PEOPLE.reader.password);
    const q = new URLSearchParams({ email: PEOPLE.attacker.email, password: PEOPLE.attacker.password });
    const [res] = await Promise.all([
      page.waitForResponse((r) => r.url() === `${APP}/api/auth/login`),
      page.goto(`${origin}/form-login.html?${q}`),
    ]);
    expect(res.status()).toBe(403);
    const me = await context.request.get(`${APP}/api/auth/me`);
    expect(me.status()).toBe(200);
    expect((await me.json()).name).toBe(PEOPLE.reader.name);
  });
}

test("the control: the attacker's credentials do sign in from the app itself", async ({ page, context, guard }) => {
  guard.allowConsole(/status of 401/);
  await page.goto(APP);
  await page.getByLabel("Email").fill(PEOPLE.attacker.email);
  await page.getByLabel("Password").fill(PEOPLE.attacker.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.locator(".whoami")).toContainText("Signed in as E2E Attacker");
  expect((await (await context.request.get(`${APP}/api/auth/me`)).json()).name).toBe(PEOPLE.attacker.name);
});
