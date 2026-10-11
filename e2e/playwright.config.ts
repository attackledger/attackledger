// Run by tools/test_e2e.sh inside the runner container (e2e/Dockerfile), never on the host.
// E2E_PHASE picks the tests: "token" (operator token, hostile content, CSP, verifier, drafts,
// accessibility) or "people" (after the first owner is created on the server).
import { defineConfig, devices } from "@playwright/test";

const phase = process.env.E2E_PHASE === "people" ? "people" : "token";

export default defineConfig({
  testDir: `./tests/${phase}`,
  globalSetup: phase === "token" ? "./tests/seed.ts" : "./tests/people-setup.ts",
  outputDir: "/tmp/test-results",
  // Every run must pass as it is: no retries hide a flaky test.
  retries: 0,
  workers: 2,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: [["list"]],
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
  ],
  webServer: {
    command: "node tests/servers.mjs",
    url: "http://127.0.0.1:18181/health",
    reuseExistingServer: false,
    stdout: "ignore",
    stderr: "pipe",
  },
});
