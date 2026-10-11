// Report downloads (WE-1): an engagement named in Turkish, Arabic and Japanese downloads its HTML
// and JSON report under the name the app shows, where the API answered 500 before.
import { api, expect, NAMES, openTab, signInToken, test } from "../lib";

test("the report of an engagement named outside Latin-1 downloads as HTML and JSON", async ({ page, context }) => {
  await signInToken(context);
  const engId = await api.engagementId(NAMES.unicodeEng);
  await openTab(page, engId, "report");
  const slug = "müşteri-portalı-عربي-東京";
  for (const [link, ext] of [["Download HTML", "html"], ["Download JSON", "json"]] as const) {
    const [download] = await Promise.all([page.waitForEvent("download"), page.getByRole("link", { name: link }).click()]);
    expect(await download.failure()).toBeNull();
    expect(download.suggestedFilename()).toBe(`attackledger-${slug}-${engId}.${ext}`);
    const body = await (await import("node:fs/promises")).readFile(await download.path());
    expect(body.length).toBeGreaterThan(1000);
    if (ext === "json") expect(JSON.parse(body.toString("utf8")).engagement.name).toBe(NAMES.unicodeEng);
  }
  // The Verify tab offers the same name for its download, and the offline command uses it.
  await openTab(page, engId, "verify");
  await expect(page.getByRole("link", { name: "Download report JSON" })).toHaveAttribute("download", `attackledger-${slug}-${engId}.json`);
});
