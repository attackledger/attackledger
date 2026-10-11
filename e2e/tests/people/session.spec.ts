// People mode: the owner the server created signs in with email and password, and out; the session
// ends on the server. An owner adds a person on the People page, as docs/INSTALL.md section 10
// says, and the person chooses their own password at the first sign-in.
import { api, APP, dismissAccount, expect, injected, OWNER, passwordFor, person, signInPerson, test } from "../lib";

test("the owner signs in and out; a copy of the cookie stops working", async ({ page, context, browser, guard }) => {
  guard.allowConsole(/status of 40[13]/);
  await page.goto(APP);
  await expect(page.getByLabel("Email")).toBeVisible();
  await page.getByLabel("Email").fill(OWNER.email);
  await page.getByLabel("Password").fill(`${OWNER.password}x`);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.locator(".field-error")).toHaveText("wrong email or password");
  expect(await context.cookies()).toEqual([]);

  await page.getByLabel("Password").fill(OWNER.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.locator(".whoami")).toContainText("Signed in as E2E Owner");
  await dismissAccount(page);
  const [session] = await context.cookies();
  expect(session.httpOnly && session.sameSite === "Strict").toBe(true);

  const elsewhere = await browser.newContext();
  await elsewhere.addCookies([{ name: session.name, value: session.value, domain: "localhost", path: "/" }]);
  expect((await elsewhere.request.get(`${APP}/api/auth/me`)).status()).toBe(200);
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByText("You have signed out.")).toBeVisible();
  await expect(page.getByLabel("Email")).toBeVisible();
  expect((await elsewhere.request.get(`${APP}/api/auth/me`)).status()).toBe(401);
  await elsewhere.close();
});

test("an owner adds a person; they choose their own password at the first sign-in", async ({ page, context, browser, browserName }) => {
  await signInPerson(context, OWNER.email, OWNER.password);
  await page.goto(`${APP}/#/people`);
  await dismissAccount(page);
  const email = `added-${browserName}@e2e.test`;
  const first = passwordFor(`${email}-first`);
  const own = passwordFor(email);
  const name = `<svg onload=__xss('added-person') data-e2exss> Added ${browserName}`;
  await page.locator("#person-name").fill(name);
  await page.locator("#person-email").fill(email);
  await page.locator("#person-password").fill(first);
  await page.getByRole("button", { name: "Add person" }).click();
  await expect(page.getByRole("listitem").filter({ hasText: email })).toBeVisible();
  await expect(page.getByText(name).first()).toBeVisible();
  expect(await injected(page)).toEqual([]);

  // The new person, in a browser of their own: asked at once to choose a password.
  const theirs = await browser.newContext();
  const them = await theirs.newPage();
  await them.goto(APP);
  await them.getByLabel("Email").fill(email);
  await them.getByLabel("Password").fill(first);
  await them.getByRole("button", { name: "Sign in" }).click();
  const dialog = them.locator("dialog.account[open]");
  await expect(dialog.getByRole("heading", { name: "Choose your own password" })).toBeVisible();
  await dialog.getByLabel("Current password").fill(first);
  await dialog.getByLabel("New password", { exact: true }).fill(own);
  await dialog.getByLabel("New password again").fill(own);
  await dialog.getByRole("button", { name: "Save my password" }).click();
  await expect(dialog.getByText("Password changed.")).toBeVisible();
  await theirs.close();
  // The first password no longer opens the account; their own does.
  await expect(person(email, first)).rejects.toThrow(/401/);
  await person(email, own);
});

test("the operator token still works for automation in people mode", async () => {
  const list = await api.call<{ name: string }[]>("GET", "/engagements");
  expect(list.length).toBeGreaterThan(0);
});
