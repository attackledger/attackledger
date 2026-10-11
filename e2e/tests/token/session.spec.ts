// Signing in with the operator token, and out (D-056): the browser gets a session cookie, not the
// token; signing out ends that session on the server, so the cookie stops working even where a
// copy of it was kept.
import { APP, expect, test, TOKEN } from "../lib";

test("token sign-in and sign-out; the cookie stops working after sign-out", async ({ page, context, browser, guard }) => {
  guard.allowConsole(/status of 401/);           // the app asks who is signed in before anyone is
  await page.goto(APP);
  await expect(page.getByText("This ledger requires the operator token.")).toBeVisible();

  // A wrong token: refused, and no session.
  await page.getByLabel("API token").fill(`${TOKEN}x`);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.locator(".field-error")).toHaveText("wrong token");
  expect(await context.cookies()).toEqual([]);

  await page.getByLabel("API token").fill(TOKEN);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.locator(".whoami")).toContainText("Signed in as operator token");

  const cookies = await context.cookies();
  expect(cookies.map((c) => c.name)).toEqual(["al_session"]);
  const session = cookies[0];
  expect(session.httpOnly).toBe(true);
  expect(session.sameSite).toBe("Strict");
  expect(session.path).toBe("/");
  expect(session.value).not.toContain(TOKEN);     // a session of its own, not the token
  // Scripts on the page cannot read it.
  expect(await page.evaluate(() => document.cookie)).not.toContain("al_session");

  // A copy of the cookie, kept elsewhere (another browser profile, a stolen copy), works now...
  const elsewhere = await browser.newContext();
  await elsewhere.addCookies([{ name: session.name, value: session.value, domain: "localhost", path: "/" }]);
  expect((await elsewhere.request.get(`${APP}/api/engagements`)).status()).toBe(200);

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByText("You have signed out.")).toBeVisible();
  expect(await context.cookies()).toEqual([]);

  // ...and not after sign-out: the server ended the session, not only this browser's cookie.
  const after = await elsewhere.request.get(`${APP}/api/engagements`);
  expect(after.status()).toBe(401);
  await elsewhere.close();

  // The form is ready to sign in again, and nothing of the workspace is shown.
  await expect(page.getByLabel("API token")).toBeVisible();
  await expect(page.locator(".engagement-list")).toHaveCount(0);
});

test("the operator token is never stored by the browser", async ({ page, context, guard }) => {
  guard.allowConsole(/status of 401/);
  await page.goto(APP);
  await page.getByLabel("API token").fill(TOKEN);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.locator(".whoami")).toContainText("Signed in as operator token");
  const stored = await page.evaluate(() => JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }));
  expect(stored).not.toContain(TOKEN);
  const state = JSON.stringify(await context.storageState());
  expect(state).not.toContain(TOKEN);
});
