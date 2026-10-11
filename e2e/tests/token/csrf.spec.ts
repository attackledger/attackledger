// CSRF and same-site requests (AUTH-2): a signed-in browser opens pages of another origin that
// post forms and send scripted requests to the API. A sibling on the same site
// (http://localhost:18181) gets the SameSite=Strict cookie; another site (http://127.0.0.1:18181)
// does not. Every change they try must be refused, and the victim's session must survive.
import type { BrowserContext, Page } from "@playwright/test";
import { api, APP, expect, OTHER_SITE, SIBLING, signInToken, test, TOKEN } from "../lib";

async function csrfEngagements(): Promise<string[]> {
  return (await api.call<{ name: string }[]>("GET", "/engagements")).map((e) => e.name).filter((n) => n.startsWith("csrf-"));
}

async function stillSignedIn(context: BrowserContext): Promise<void> {
  expect((await context.request.get(`${APP}/api/engagements`)).status(), "the victim's session still works").toBe(200);
}

/** Opens a page that posts a form at once, and returns the API's answer to it. */
async function formPost(page: Page, url: string, apiPath: string): Promise<{ status: number; body: string }> {
  const [res] = await Promise.all([
    page.waitForResponse((r) => r.url() === `${APP}/api${apiPath}` && r.request().method() === "POST"),
    page.goto(url),
  ]);
  return { status: res.status(), body: await res.text() };
}

for (const [label, origin] of [["a sibling on the same site", SIBLING], ["another site", OTHER_SITE]] as const) {
  test(`changes sent from ${label} are refused`, async ({ page, context, browserName, guard }) => {
    guard.allowConsole(/status of 40[13]|Failed to load resource|CORS|Cross-Origin Request Blocked|Cross-Origin-Resource-Policy|NetworkError|due to access control checks|Preflight response is not successful|is not allowed by Access-Control-Allow-Origin/i);
    await signInToken(context);
    const tag = `csrf-${browserName}-${origin === SIBLING ? "sibling" : "site"}`;

    const create = await formPost(page, `${origin}/form-create.html?name=${tag}-form`, "/engagements");
    expect(create.status, create.body).toBe(403);
    expect(create.body).toContain("a page of another site sent this request");

    // Scripted: simple no-cors requests reach the API and are refused there (the page cannot read
    // the answer: no CORS header, and Cross-Origin-Resource-Policy); a JSON request needs a CORS
    // preflight the API never grants, so it is not sent at all.
    const answers: string[] = [];
    page.on("response", (r) => { if (r.url().startsWith(`${APP}/api/`)) answers.push(`${r.request().method()} ${new URL(r.url()).pathname} ${r.status()}`); });
    // Chromium reports an answer that Cross-Origin-Resource-Policy hides as a failed request: it
    // was sent and answered all the same.
    page.on("requestfailed", (r) => {
      if (r.url().startsWith(`${APP}/api/`)) answers.push(`${r.method()} ${new URL(r.url()).pathname} ${r.failure()?.errorText}`);
    });
    await page.goto(`${origin}/fetch.html?name=${tag}`);
    await expect(page.locator("#out")).not.toBeEmpty();
    const out = JSON.parse(await page.locator("#out").textContent() ?? "{}") as Record<string, string>;
    expect(out["cors json"]).toMatch(/^error:TypeError/);
    expect(out["cors read"]).toMatch(/^error:TypeError/);
    for (const k of ["no-cors text/plain", "no-cors form", "no-cors logout"]) expect(out[k]).toMatch(/^(error:TypeError|sent:opaque:0)$/);
    // Each no-cors POST was answered 403 (Firefox shows the answer, Chromium and WebKit only that
    // CORP hid it); none was accepted.
    const refused = (path: string) => answers.filter((a) => a === `POST ${path} 403` || a.startsWith(`POST ${path} net::ERR_BLOCKED_BY_RESPONSE`)
      || (a.startsWith(`POST ${path} Cancelled load to `) && a.endsWith("because it violates the resource's Cross-Origin-Resource-Policy response header.")));
    expect(refused("/api/engagements"), answers.join("; ")).toHaveLength(2);
    expect(refused("/api/auth/logout"), answers.join("; ")).toHaveLength(1);
    expect(answers.filter((a) => /^POST .* [23]\d\d$/.test(a))).toEqual([]);

    const logout = await formPost(page, `${origin}/form-logout.html`, "/auth/logout");
    expect(logout.status).toBe(403);
    const login = await formPost(page, `${origin}/form-login.html?token=${encodeURIComponent(TOKEN)}`, "/auth/login");
    expect(login.status).toBe(403);
    expect(login.body).not.toContain('"ok":true');

    expect(await csrfEngagements(), "engagements created by another origin").toEqual([]);
    await stillSignedIn(context);
  });
}

test("the same requests from the app itself are accepted (the control)", async ({ page, context, browserName }) => {
  await signInToken(context);
  await page.goto(APP);
  const name = `control-${browserName}-${Date.now()}`;
  const status = await page.evaluate(async (n) => (await fetch("/api/engagements", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: n }) })).status, name);
  expect(status).toBe(201);
  expect((await api.call<{ name: string }[]>("GET", "/engagements")).some((e) => e.name === name)).toBe(true);
});
