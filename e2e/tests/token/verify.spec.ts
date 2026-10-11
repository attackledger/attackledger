// The verifier, in the app (Verify tab) and on the public page (site/verify.html, served as a
// static file): a report as the server exports it verifies, a tampered copy fails, and "require
// the complete history" (--require-history) fails a report without its seal that passes without it.
import type { Page } from "@playwright/test";
import { api, expect, injected, NAMES, openTab, signInToken, test, VERIFY_PAGE } from "../lib";

type Report = { engagement: { name: string }; integrity: { seal?: unknown; body_sha256: string }; lanes: unknown[] };

async function reportOf(engId: number): Promise<string> {
  const r = await fetch(`http://web/api/engagements/${engId}/report`, { headers: { authorization: `Bearer ${process.env.E2E_API_TOKEN}` } });
  expect(r.status).toBe(200);
  return r.text();
}

/** The same report with its body changed after export (the name a reader would see). */
function tampered(text: string): string {
  const r = JSON.parse(text) as Report;
  r.engagement.name += " (edited)";
  return JSON.stringify(r);
}

/** The same report without its seal: as a server before the seal (D-055), or one that left it out. */
function unsealed(text: string): string {
  const r = JSON.parse(text) as Report;
  expect(r.integrity.seal, "the server seals every report it exports").toBeTruthy();
  delete r.integrity.seal;
  return JSON.stringify(r);
}

test.describe("the in-app Verify tab", () => {
  let engId: number;
  test.beforeAll(async () => { engId = await api.engagementId(NAMES.cleanEng); });
  test.beforeEach(async ({ context }) => { await signInToken(context); });

  const status = (page: Page) => page.getByRole("status").filter({ hasText: /Verified|Verification failed|could not be checked/ });
  const strict = (page: Page) => page.getByRole("checkbox", { name: /Require the complete history/ });

  test("verifies the report the server exports; the complete history needs signed receipts", async ({ page }) => {
    await openTab(page, engId, "verify");
    await expect(status(page)).toHaveText("Verified: no check failed.");
    // Its receipt was closed with the operator token, a name only: nothing binds the history to it.
    await strict(page).check();
    await expect(status(page)).toHaveText("Verification failed: Change history.");
    await expect(page.getByRole("listitem").filter({ hasText: /^www\.clean\.test \/ Recon: the receipt is not signed, so nothing binds its change history/ })).toBeVisible();
  });

  test("fails a report changed on its way to the browser", async ({ page }) => {
    await page.route(`**/api/engagements/${engId}/report`, async (route) => {
      await route.fulfill({ body: tampered(await (await route.fetch()).text()), contentType: "application/json" });
    });
    await openTab(page, engId, "verify");
    await expect(status(page)).toHaveText("Verification failed: Report body hash, Report seal.");
  });

  test("a report without its seal passes, and fails when the complete history is required", async ({ page }) => {
    await page.route(`**/api/engagements/${engId}/report`, async (route) => {
      await route.fulfill({ body: unsealed(await (await route.fetch()).text()), contentType: "application/json" });
    });
    await openTab(page, engId, "verify");
    await expect(status(page)).toHaveText("Verified: no check failed.");
    await strict(page).check();
    await expect(status(page)).toHaveText("Verification failed: Change history, Report seal.");
    await expect(page.getByRole("listitem").filter({ hasText: /^this report is not sealed, which --require-history requires$/ })).toBeVisible();
    await strict(page).uncheck();
    await expect(status(page)).toHaveText("Verified: no check failed.");
  });

  test("the hostile engagement's report verifies and its names render as text", async ({ page }) => {
    const hostile = await api.engagementId(NAMES.hostileEng);
    await openTab(page, hostile, "verify");
    // Its receipt is void: the recon run's evidence came after it (seed.ts). The verifier says so.
    await expect(status(page)).toHaveText("Verified: no check failed.");
    await expect(page.getByRole("listitem").filter({ hasText: `${NAMES.app} / Recon: receipt is void` }).last()).toBeVisible();
    expect(await injected(page)).toEqual([]);
  });
});

test.describe("the public verifier page", () => {
  let good: string;
  test.beforeAll(async () => { good = await reportOf(await api.engagementId(NAMES.cleanEng)); });

  async function check(page: Page, name: string, text: string): Promise<void> {
    await page.locator("#report-file").setInputFiles({ name, mimeType: "application/json", buffer: Buffer.from(text) });
  }

  test("verifies a good report, fails a tampered one, and requires the history when asked", async ({ page }) => {
    await page.goto(VERIFY_PAGE);
    // A static page with its own policy in a meta tag: nothing but its inline script and style.
    const csp = await page.locator('meta[http-equiv="Content-Security-Policy"]').getAttribute("content");
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("connect-src 'none'");
    const status = page.locator("#status");
    const strict = page.locator("#require-history");

    await check(page, "good.json", good);
    await expect(status).toHaveText("good.json: verified. No check failed.");
    await strict.check();
    await expect(status).toHaveText("good.json: verification failed. 1 check failed: Change history.");
    await strict.uncheck();
    await expect(status).toHaveText("good.json: verified. No check failed.");

    await check(page, "tampered.json", tampered(good));
    await expect(status).toHaveText("tampered.json: verification failed. 2 checks failed: Report body hash, Report seal.");

    await check(page, "unsealed.json", unsealed(good));
    await expect(status).toHaveText("unsealed.json: verified. No check failed.");
    await strict.check();
    await expect(status).toHaveText("unsealed.json: verification failed. 2 checks failed: Change history, Report seal.");
  });

  test("the hostile engagement's HTML report verifies, and what its JSON says is shown as text", async ({ page }) => {
    const id = await api.engagementId(NAMES.hostileEng);
    const r = await fetch(`http://web/api/engagements/${id}/report.html`, { headers: { authorization: `Bearer ${process.env.E2E_API_TOKEN}` } });
    expect(r.status).toBe(200);
    await page.goto(VERIFY_PAGE);
    await check(page, "hostile.html", await r.text());
    await expect(page.locator("#status")).toHaveText("hostile.html: verified. No check failed.");
    // The facts list (what the verified JSON says): the hostile name as typed, nothing made from it.
    await expect(page.locator("#result .facts li").first()).toContainText(`Engagement: ${NAMES.hostileEng} (id ${id})`);
    expect(await injected(page)).toEqual([]);
  });

  test("a hostile report renders its names as text", async ({ page }) => {
    const hostile = await reportOf(await api.engagementId(NAMES.hostileEng));
    await page.goto(VERIFY_PAGE);
    await check(page, "<img src=x onerror=__xss('file-name')>.json", hostile);
    await expect(page.locator("#status")).toContainText(/verified|verification failed/);
    expect(await page.locator("#result [data-e2exss], #result img, #result svg, #result script").count()).toBe(0);
  });
});
