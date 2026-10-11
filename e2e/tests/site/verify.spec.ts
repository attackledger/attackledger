// The public verifier page at /verify, as the site serves it (its meta policy and the _headers ones):
// the sample report and every demo report, as JSON and as HTML, in each mode, give exactly the
// verdicts of verify_report.py (the copy the site serves, run here in the runner); tampered copies
// fail as it says; hostile report content is shown as text and runs nothing; an HTML report whose
// visible text was edited verifies (the checks cover its JSON) and shows what that JSON says.
import { readFileSync } from "node:fs";
import path from "node:path";
import { expect, hostile, injected, SITE } from "../lib";
import { checkLikeReference, MODES, OUT, siteTest as test } from "../site-lib";

type Dict = Record<string, any>;
const REPORTS = ["sample-report", "demo/reports/1", "demo/reports/2", "demo/reports/3", "demo/reports/4"];
const read = (rel: string) => readFileSync(path.join(OUT, rel), "utf8");
const fileName = (rel: string, ext: string) => `${rel.replace(/\//g, "-")}.${ext}`;

const EMBED = /(<script type="application\/json" id="attackledger-report">)([\s\S]*?)(<\/script>)/;
/** JSON as the server embeds it in an HTML report: nothing in it can end the script element. */
const embed = (r: unknown) => JSON.stringify(r).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026");

/** Changes the text an HTML report shows, outside its embedded JSON. */
function editVisible(html: string, edit: (outside: string) => string): string {
  const m = EMBED.exec(html)!;
  return edit(html.slice(0, m.index)) + m[0] + edit(html.slice(m.index + m[0].length));
}

// ---- tampering -------------------------------------------------------------------------------

const TAMPERS: Record<string, (r: Dict) => boolean> = {
  // One bit of the first receipt signature.
  "a flipped signature byte": (r) => {
    const sig = (r.lanes as Dict[]).find((l) => l.receipt?.signature?.value)?.receipt.signature;
    if (!sig) return false;
    const bytes = Buffer.from(sig.value, "base64");
    bytes[7] ^= 0x01;
    sig.value = bytes.toString("base64");
    return true;
  },
  // A lane reported closed that is open, or the first lane's status changed.
  "an edited lane status": (r) => {
    const lanes = r.lanes as Dict[];
    if (!lanes.length) return false;
    const open = lanes.find((l) => l.status === "open");
    if (open) open.status = "closed";
    else lanes[0].status = "open";
    return true;
  },
  // An entry left out of the change history.
  "a dropped audit entry": (r) => {
    const entries = r.audit_log?.entries as Dict[] | undefined;
    if (!entries?.length) return false;
    entries.splice(Math.floor(entries.length / 2), 1);
    return true;
  },
};

test.beforeEach(async ({ page }) => {
  const res = await page.goto(`${SITE}/verify`);
  expect(res?.status()).toBe(200);
  await expect(page.locator("#roots li").first()).toBeVisible();
});

for (const rel of REPORTS) {
  test(`${rel}: JSON and HTML give verify_report.py's verdicts in every mode`, async ({ page }) => {
    test.setTimeout(180_000);
    for (const [ext, body] of [["json", read(`${rel}.json`)], ["html", read(`${rel}.html`)]] as const) {
      for (const mode of MODES) {
        const ref = await checkLikeReference(page, fileName(rel, ext), body, mode);
        expect(ref.verified, `${rel}.${ext}, ${mode.label}: the published reports verify\n${ref.output}`).toBe(true);
        // The page's own self-test, when there are signatures to test.
        if (ref.verdicts.some(([n, v]) => n === "Receipt signatures" && v === "PASS")) {
          await expect(page.locator(".selftest")).toHaveText(/^Self-test: .* fails the signature check here, as it should\.$/);
        }
        // An HTML report says what its JSON says, as verify_report.py prints it.
        const facts = page.locator("#result .facts li");
        if (ext === "html") await expect(facts).toHaveText(ref.facts);
        else await expect(facts).toHaveCount(0);
      }
    }
  });

  test(`${rel}: tampered copies fail, as verify_report.py says`, async ({ page }) => {
    test.setTimeout(180_000);
    const original = JSON.parse(read(`${rel}.json`)) as Dict;
    // The control: the same report written out again unchanged still verifies.
    const control = await checkLikeReference(page, fileName(rel, "copy.json"), JSON.stringify(original), MODES[0]);
    expect(control.verified).toBe(true);
    let tried = 0;
    for (const [what, tamper] of Object.entries(TAMPERS)) {
      const r = structuredClone(original);
      if (!tamper(r)) continue;                     // nothing of the kind in this report
      tried++;
      for (const mode of MODES.slice(0, 2)) {
        const ref = await checkLikeReference(page, fileName(rel, `${what.replace(/\W+/g, "-")}.json`), JSON.stringify(r), mode);
        expect(ref.verified, `${rel} with ${what}, ${mode.label}`).toBe(false);
        expect(ref.failed.length).toBeGreaterThan(0);
        await expect(page.locator("#result .verdict.bad")).toBeVisible();
      }
      // The same tampered report in an HTML report fails the same way.
      const html = read(`${rel}.html`).replace(EMBED, (_m, a, _b, c) => a + embed(r) + c);
      const ref = await checkLikeReference(page, fileName(rel, `${what.replace(/\W+/g, "-")}.html`), html, MODES[0]);
      expect(ref.verified).toBe(false);
      await expect(page.locator("#result .facts")).toHaveCount(0);
    }
    expect(tried, "tampers that apply to this report").toBeGreaterThanOrEqual(rel === "demo/reports/2" ? 2 : 3);
  });
}

test("an HTML report with edited visible text verifies, and shows what its JSON says", async ({ page }) => {
  const html = editVisible(read("sample-report.html"), (s) => s.replace(/Client web app/g, "Edited by e2e").replace(/\bclosed\b/g, "edited"));
  expect(html).toContain("<h1>Edited by e2e</h1>");
  const ref = await checkLikeReference(page, "edited.html", html, MODES[1]);
  expect(ref.verified).toBe(true);
  const facts = page.locator("#result section.facts");
  await expect(facts.getByRole("heading", { name: "What the verified report says" })).toBeVisible();
  await expect(facts.locator("li")).toHaveText(ref.facts);
  await expect(facts.locator("li").first()).toHaveText(/^Engagement: Client web app \(id 3\)/);
  await expect(facts).not.toContainText("Edited by e2e");
});

/** The sample report with a hostile string in every name and text a page shows. */
function hostileReport(): Dict {
  const r = JSON.parse(read("sample-report.json")) as Dict;
  r.engagement.name = hostile("v-eng");
  r.engagement.authorized_by = hostile("v-auth");
  r.hosts[0].host = hostile("v-host");
  (r.lanes as Dict[]).forEach((l, i) => {
    l.name = hostile(`v-lane-${i}`);
    if (i === 0) l.host = hostile("v-lane-host");
    if (l.receipt) l.receipt.closed_by = hostile(`v-closed-${i}`);
    (l.items as Dict[]).forEach((it, j) => { it.text = hostile(`v-item-${i}-${j}`); if (j % 2) it.na_reason = hostile(`v-na-${i}-${j}`); });
  });
  (r.evidence as Dict[]).forEach((e, k) => { e.summary = hostile(`v-ev-${k}`); });
  for (const e of (r.audit_log?.entries ?? []) as Dict[]) e.actor.name = hostile("v-actor");
  return r;
}

for (const csp of ["with", "without"] as const) {
  test.describe(`hostile report content, ${csp} the CSP`, () => {
    test.use({ bypassCSP: csp === "without" });

    test("fails verification and is shown as text", async ({ page }) => {
      const r = hostileReport();
      for (const [name, body] of [[`<img src=x onerror=__xss('v-file') data-e2exss>\u202Eexe.json`, JSON.stringify(r)],
                                  ["hostile.html", read("sample-report.html").replace(EMBED, (_m, a, _b, c) => a + embed(r) + c)]]) {
        const ref = await checkLikeReference(page, name, body, MODES[0]);
        expect(ref.verified).toBe(false);
        await expect(page.locator("#result .what")).toContainText("e2exss v-eng");
        await expect(page.locator("#result")).toContainText("e2exss v-lane-0");
        expect(await injected(page)).toEqual([]);
      }
    });

    test("an HTML report whose page is hostile verifies, and its markup is never rendered", async ({ page }) => {
      const html = editVisible(read("sample-report.html"), (s) => s.replace("<h1>Client web app</h1>", `<h1>${hostile("v-h1")}</h1>`));
      const ref = await checkLikeReference(page, "hostile-page.html", html, MODES[0]);
      expect(ref.verified).toBe(true);
      await expect(page.locator("#result .facts li").first()).toHaveText(/^Engagement: Client web app/);
      expect(await injected(page)).toEqual([]);
    });
  });
}
