// Roles hide what a person cannot do, and the server refuses it anyway: a reader (viewer) sees the
// report first and has no way to change, sign or approve anything; a tester works but does not
// sign; a reviewer signs, with a key made in the browser, and the signed report then verifies with
// the complete history required, and fails without its seal.
import type { Page } from "@playwright/test";
import { api, APP, dismissAccount, expect, injected, NAMES, openTab, PEOPLE, person, signInPerson, test } from "../lib";

type Coverage = { assets: { host: string; roles: Record<string, { lane_id?: number }> }[] };
const laneOf = async (engId: number, role: string, host?: string) => {
  const cov = await api.call<Coverage>("GET", `/engagements/${engId}/coverage`);
  return (host ? cov.assets.find((a) => a.host === host)! : cov.assets[0]).roles[role].lane_id!;
};

async function tabNames(page: Page): Promise<string[]> {
  return (await page.getByRole("tab").filter({ has: page.locator("xpath=self::button[@id]") }).allInnerTexts())
    .map((t) => t.replace(/\d+\/\d+$/, "").trim());
}

test("a reader sees the report first, reads everything, and can change, sign or approve nothing", async ({ page, context, guard }) => {
  guard.allowConsole(/status of 40[34]/);
  await signInPerson(context, PEOPLE.reader.email, PEOPLE.reader.password);
  const clean = await api.engagementId(NAMES.cleanEng);
  await page.goto(`${APP}/#/e/${clean}`);
  await dismissAccount(page);
  await expect(page.getByRole("tab", { name: "Report" })).toHaveAttribute("aria-selected", "true");
  expect(await tabNames(page)).toEqual(["Report", "Verify", "History", "Ledger", "Controls", "Recon", "Import"]);
  await expect(page.locator(".readonly-note")).toContainText("You can read this engagement (viewer)");
  // The reader's own name is hostile, and shows as text.
  await expect(page.locator(".whoami")).toContainText("<img src=x onerror=__xss('person-name') data-e2exss> Reader");
  expect(await injected(page)).toEqual([]);
  await expect(page.locator("#new-eng")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "People" })).toHaveCount(0);

  // A lane: no evidence, item or signing controls.
  await page.goto(`${APP}/#/e/${clean}/ledger/lane/${await laneOf(clean, "mapper")}`);
  await expect(page.locator(".folio")).toBeVisible();
  await expect(page.getByText("A reviewer on this engagement signs and closes the lane")).toBeVisible();
  for (const name of ["Add evidence", "Not applicable", "Mark done", /Sign and close lane/]) {
    await expect(page.getByRole("button", { name })).toHaveCount(0);
  }
  // A link to the Team tab, or to tabs for testers, opens the report instead.
  for (const tab of ["team", "accounts", "approvals"]) {
    await page.goto(`${APP}/#/e/${clean}/${tab}`);
    await expect(page.getByRole("tab", { name: "Report" })).toHaveAttribute("aria-selected", "true");
  }

  // And the server refuses the same things when asked directly with the reader's session.
  const reader = await person(PEOPLE.reader.email, PEOPLE.reader.password);
  const hostile = await api.engagementId(NAMES.hostileEng);
  const pid = (await api.call<{ items: { id: number }[] }>("GET", `/engagements/${hostile}/approvals`)).items[0].id;
  const refused = [
    await reader.raw("POST", `/lanes/${await laneOf(clean, "mapper")}/close`, { reviewed: true }),
    await reader.raw("POST", `/lanes/${await laneOf(clean, "mapper")}/attach`, { item_idx: 1, kind: "note", text: "x" }),
    await reader.raw("POST", `/engagements/${hostile}/approvals/${pid}/approve`, {}),
    await reader.raw("POST", `/engagements/${hostile}/approvals/${pid}/reject`, { note: "x" }),
    await reader.raw("PUT", `/engagements/${clean}/scope`, { include: ["*.evil.test"] }),
    await reader.raw("PUT", `/engagements/${clean}/members`, { members: [] }),
    await reader.raw("POST", "/engagements", { name: "made by a reader" }),
  ];
  expect(refused.map((r) => r.status)).toEqual([403, 403, 403, 403, 403, 403, 403]);
  // The proposal was neither approved nor rejected.
  const after = await api.call<{ items: { id: number; status: string }[] }>("GET", `/engagements/${hostile}/approvals`);
  expect(["pending", "expired"]).toContain(after.items.find((p) => p.id === pid)!.status);
});

test("a tester works a lane but is not offered the signature, and cannot sign", async ({ page, context }) => {
  await signInPerson(context, PEOPLE.tester.email, PEOPLE.tester.password);
  const clean = await api.engagementId(NAMES.cleanEng);
  const lane = await laneOf(clean, "mapper");
  await page.goto(`${APP}/#/e/${clean}/ledger/lane/${lane}`);
  await dismissAccount(page);
  await expect(page.getByRole("button", { name: "Add evidence" }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: /Sign and close lane/ })).toHaveCount(0);
  await expect(page.getByText("A reviewer on this engagement signs and closes the lane")).toBeVisible();
  const tester = await person(PEOPLE.tester.email, PEOPLE.tester.password);
  expect((await tester.raw("POST", `/lanes/${lane}/close`, { reviewed: true })).status).toBe(403);
});

test("a reviewer signs with a key made in the browser; the report then verifies in full", async ({ page, context, browserName }) => {
  await signInPerson(context, PEOPLE.reviewer.email, PEOPLE.reviewer.password);
  const engId = await api.engagementId(`${NAMES.signedEng} ${browserName}`);
  const lane = await laneOf(engId, "recon");
  await page.goto(`${APP}/#/e/${engId}/ledger/lane/${lane}`);
  await dismissAccount(page);
  await expect(page.getByText("You sign as E2E Reviewer")).toBeVisible();
  await page.getByRole("checkbox", { name: /I reviewed this lane's evidence/ }).check();
  await page.getByRole("button", { name: /sign and close lane/i }).click();
  await expect(page.getByText(/Receipt signed by E2E Reviewer \(reviewer@e2e\.test\), .* with key/)).toBeVisible();
  // The server holds the public key only.
  const keys = await (await person(PEOPLE.reviewer.email, PEOPLE.reviewer.password)).call<{ fingerprint: string }[]>("GET", "/auth/keys");
  expect(keys.length).toBeGreaterThan(0);

  await page.keyboard.press("Escape");
  await openTab(page, engId, "verify");
  const status = page.getByRole("status").filter({ hasText: /Verified|Verification failed/ });
  const strict = page.getByRole("checkbox", { name: /Require the complete history/ });
  await expect(status).toHaveText("Verified: no check failed.");
  await strict.check();
  await expect(status).toHaveText("Verified: no check failed.");
  await expect(page.getByText(/^Self-test: a copy of this report with one changed signature byte fails the signature check here/)).toBeVisible();

  // The same report without its seal fails once the complete history is required, and not before.
  await page.route(`**/api/engagements/${engId}/report`, async (route) => {
    const r = JSON.parse(await (await route.fetch()).text()) as { integrity: { seal?: unknown } };
    delete r.integrity.seal;
    await route.fulfill({ body: JSON.stringify(r), contentType: "application/json" });
  });
  await page.reload();
  await expect(strict).not.toBeChecked();
  await expect(status).toHaveText("Verified: no check failed.");
  await strict.check();
  await expect(status).toHaveText("Verification failed: Report seal.");
});
