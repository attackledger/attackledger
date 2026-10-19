# The browser test runner (tools/test_e2e.sh). Playwright's own image, pinned by the digest of
# its multi-arch index (docs/SUPPLY_CHAIN.md); the tag says what the digest was when it was
# pinned. It has Node and the Chromium and Firefox builds of this Playwright version, so nothing
# is installed on the host and no browser is downloaded at test time.
# mcr.microsoft.com/playwright:v1.63.0-noble (Ubuntu 24.04), pinned 2026-10-11.
FROM mcr.microsoft.com/playwright:v1.64.1-noble@sha256:7852dc5a7d72f5fe458a597d690f6c42fbc8e9e26ddfa95f8e6ef552558d9bbf
WORKDIR /e2e
COPY package.json package-lock.json ./
# Exactly the lockfile, each package checked against its SHA-512 there; no install scripts
# (the browsers are already in the image, matching @playwright/test 1.63.0).
RUN npm ci --no-audit --no-fund --ignore-scripts
COPY playwright.config.ts ./
COPY tests ./tests
# The image's unprivileged user. Test output goes to /tmp, which is emptied with the container.
USER pwuser
ENV HOME=/tmp
