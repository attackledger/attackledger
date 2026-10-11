// Run by tools/test_e2e.sh inside the runner container (e2e/Dockerfile), never on the host.
// E2E_PHASE picks the tests: "site" (the public site, built with tools/build_pages.sh and served
// as Cloudflare Pages would; no stack needed), "token" (operator token, hostile content, CSP,
// verifier, drafts, accessibility) or "people" (after the first owner is created on the server).
import { defineConfig, devices } from "@playwright/test";

const phase = ({ site: "site", people: "people" } as Record<string, string>)[process.env.E2E_PHASE ?? ""] ?? "token";

const report = process.env.E2E_REPORT;

export default defineConfig({
  testDir: `./tests/${phase}`,
  globalSetup: phase === "site" ? undefined : phase === "token" ? "./tests/seed.ts" : "./tests/people-setup.ts",
  // tools/test_e2e.sh sets E2E_REPORT when the caller asks for a report (E2E_REPORT_DIR): the
  // HTML report and the traces of failed tests are kept there. Otherwise they go to /tmp, which
  // is emptied with the container.
  outputDir: report ? `${report}/results` : "/tmp/test-results",
  // Every run must pass as it is: no retries hide a flaky test.
  retries: 0,
  workers: 2,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: report ? [["list"], ["html", { outputFolder: `${report}/html`, open: "never" }]] : [["list"]],
  forbidOnly: true,
  use: {
    baseURL: "http://localhost:18180",
    trace: "retain-on-failure",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    // Firefox under Playwright 1.63 loses about one navigation in ten from a new tab to a page sent
    // with Cross-Origin-Opener-Policy (the browsing-context switch it makes): the page loads, the
    // test never hears of it. Firefox's COOP handling is off here for that reason only; the guard
    // still checks that every document is sent with COOP, and Chromium enforces it.
    { name: "firefox", use: { ...devices["Desktop Firefox"],
                              launchOptions: { firefoxUserPrefs: { "browser.tabs.remote.useCrossOriginOpenerPolicy": false } } } },
    // The WebKit build in the same image (Playwright's WebKit for Linux, the engine of Safari).
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],
  webServer: phase === "site" ? {
    command: "node tests/pages-server.mjs",
    url: "http://127.0.0.1:18183/",
    reuseExistingServer: false,
    stdout: "ignore",
    stderr: "pipe",
  } : {
    command: "node tests/servers.mjs",
    url: "http://127.0.0.1:18181/health",
    reuseExistingServer: false,
    stdout: "ignore",
    stderr: "pipe",
  },
});
