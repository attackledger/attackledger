# Dependabot pull requests, 2026-10-11

What each of the 14 open Dependabot pull requests changes, whether it follows the two-week rule
(`docs/SUPPLY_CHAIN.md`, "Which version"), and what happened when it was applied to `main`
(`4ddfe16`) and tested here. Nothing was merged, closed, commented on or pushed: every test ran on
a local scratch branch or a copy of the tree, and the images were built under their own tags,
which were then removed.

The two-week cutoff for today is **2026-09-27**: a release published after that is too young,
unless only it fixes a known advisory. Release dates are from PyPI, the npm registry, Docker Hub
and the GitHub releases of each project. Advisories are from the GitHub advisory database:
**none of these pull requests fixes an advisory** that affects a version `main` pins today
(`main` already has cryptography 50.0.0, starlette 1.7.0, Vite 8.3.1, esbuild 0.28.2).

## Verdicts

| PR | Title (short) | Verdict | Reason |
|---|---|---|---|
| #25 | python group: uvicorn, SQLAlchemy, psycopg, pydantic, PyYAML | **MERGE AFTER RE-LOCK** | Dependabot's lock leaves out uvicorn and psycopg, so CI fails (`test_locks_hash_every_package_and_match_their_input`). Re-locked, both suites pass. |
| #24 | dev-tooling: ESLint 10.11.0, eslint-plugin-react-hooks 7.1.1 | **MERGE** | Every check passes, the lint still catches a hooks violation, and the built app is byte-identical to `main`'s. |
| #23 | npm-production: React 19.3.0, react-dom, @types, @fontsource 5.3.0 | **MERGE** | A React major. Every check and the browser suite pass (102 tests), and the CSP-relevant output is unchanged. |
| #21 | actions: checkout, setup-python, setup-node | **MERGE AFTER FIXING THE COMMENTS** | These are three major bumps to **v7**, but the pin comments still say `v4.4.0` / `v5.6.0`. The commits check out. |
| #13 | alembic 1.14.0 → 1.20.0 | **DO NOT MERGE as is** (the bump itself is good) | The PR conflicts: it edits the old unhashed `requirements.txt`. Recreate it, or apply it by hand after #25. Add `path_separator = os` to `alembic.ini`. |
| #9 | cryptography 43.0.3 → 50.0.2 | **WAIT** until **2026-10-14** | 50.0.2 was released 2026-09-30. `main` is on 50.0.0, which has no advisory. The PR also conflicts. The forecast test passed. |
| #8 | fastapi 0.115.6 → 0.142.2 | **DO NOT MERGE** (close) | Conflicts. Too young (OK only from 2026-10-14). Adds `opentelemetry-api`, and 0.142.x sets up OpenTelemetry exporters from `OTEL_*` automatically (0.143.0 made this opt-in). Skip 0.142.x. |
| #11 | sqlalchemy 2.0.36 → 2.1.3 | **CLOSE AS SUPERSEDED** by #25 | #25 takes SQLAlchemy 2.1.1. 2.1.3 is too young (OK from 2026-10-16), and the PR conflicts. |
| #10 | dev-tooling (6 updates, old base) | **CLOSE AS SUPERSEDED** by #24 and `main` | Vite 8 and plugin-react 6 are already on `main`. TypeScript 7.0.2 cannot install next to typescript-eslint 8.71.1 (CI: `ERESOLVE`). Conflicts. |
| #15 | react-dom 19.3.0 alone | **CLOSE AS SUPERSEDED** by #23 | Fails `npm ci` on its own (`ERESOLVE`, @types/react 18 vs @types/react-dom 19). Conflicts. |
| #19 | react 19.3.0 alone | **CLOSE AS SUPERSEDED** by #23 | Fails `npm ci` on its own (`ERESOLVE`, react 19 vs react-dom 18). |
| #22 | web image nginx 1.30 → 1.31 | **DO NOT MERGE** (a decision) | 1.31 is nginx's mainline branch, and the project chose stable (`web/Dockerfile`). It brings no security fix or OS package that 1.30.5 lacks. It works if you do want mainline. |
| #20 | compose nginx 1.30 → 1.31 (lab, lab proxy) | **DO NOT MERGE** (a decision) | Same as #22. CI fails as is: the `nginx:1.30-alpine@*` lines in `tools/scan_ignore.txt` no longer match any image, and the scan finds 4 fixable HIGH findings it no longer accepts. |
| #5 | web nginx 1.27 → 1.31 (old, unpinned) | **CLOSE AS SUPERSEDED** by #22 | `main` already moved to a digest-pinned 1.30.5. Conflicts, and uses a tag with no digest. |

The eight older pull requests (#5 to #19, opened 2026-10-09) predate the lock, the grouping and the
cooldown. All but #19 conflict with `main`: GitHub reports them `CONFLICTING`, and #19 fails CI.
Suggested order: #24, #23, #21 (after the comment fix), #25 (after the re-lock), then alembic.
Then close #5, #8, #10, #11, #15 and #19. Either leave #9 open until 2026-10-14 or close it and let
the weekly python group bring cryptography in. Decide #20 and #22 together.

## Python

### #25: python group (MERGE AFTER RE-LOCK)

| Package | From | To | Released | Age today |
|---|---|---|---|---|
| uvicorn[standard] | 0.32.1 | 0.54.0 | 2026-09-25 | 16 days |
| SQLAlchemy | 2.0.36 | 2.1.1 | 2026-09-25 | 16 days |
| psycopg[binary] | 3.2.3 | 3.3.6 | 2026-09-18 | 23 days |
| pydantic | 2.10.3 | 2.13.5 | 2026-08-28 | 44 days |
| PyYAML | 6.0.2 | 6.0.3 | 2025-09-25 | over a year |

**What is wrong with the pull request as is:** Dependabot changed `server/requirements.in` and
rewrote the lock itself. The lock it wrote has **no `uvicorn` and no `psycopg` line**. It also
rewrote every `# via -r server/requirements.in` as `# via -r requirements.in`. CI fails on both
`server` and `postgres` with
`server/requirements.txt is not locked from requirements.in: uvicorn` (`assert None == '0.54.0'`).

**Re-lock** (what was run here; resolving takes about 6 minutes):

```sh
gh pr checkout 25
git checkout origin/main -- server/requirements.txt   # start from the good lock, not Dependabot's
tools/lock_requirements.sh server/requirements.in
git diff server/requirements.txt                       # expect exactly the changes below
git commit -am "Re-lock server/requirements.txt" && git push
```

What the re-lock changes in `server/requirements.txt`, from `main`'s lock:

- removed: **greenlet 3.5.6**. SQLAlchemy 2.1 no longer depends on it; it is needed only for
  asyncio, and `server/app` has no `sqlalchemy.ext.asyncio` / `AsyncSession`;
- psycopg and psycopg-binary 3.2.3 → 3.3.6;
- pydantic 2.10.3 → 2.13.5, with pydantic-core 2.27.1 → 2.46.5 (2026-08-28);
- PyYAML 6.0.2 → 6.0.3; SQLAlchemy 2.0.36 → 2.1.1; uvicorn 0.32.1 → 0.54.0;
- nothing else: every other package and hash is unchanged. 1,171 hashes in total, and the header
  line is the script's.

**Tests** (an API image built from the re-locked tree as `attackledger-api:deps-eval`; the suite
run in it as a non-root user, the worktree mounted):

- SQLite: **1248 passed, 1 skipped** (4 min 14 s);
- `tools/test_postgres.sh` with that image: **1248 passed, 1 skipped**, then the migration-0022
  upgrade **2 passed**, `[pg] PASS`;
- `pip-audit` (the hashed `tools/ci/requirements-audit.txt`, pip-audit 2.10.1) on the image with
  #25, alembic 1.20.0 and cryptography 50.0.2 installed: **no known vulnerabilities**.

Not rebuilt here: the worker image. It installs the same lock on the same Python base, and the
API image's build shows that every package has a wheel for Linux and Python 3.12.

**Things to know:**

- **SQLAlchemy 2.1 is a new minor, and 2.1.1 has regressions that 2.1.2 to 2.1.4 fix.** One of
  them is relevant here. Up to 2.1.3, iterating a `Result` directly (or `Result.scalars()`)
  creates reference cycles, so the cursor is freed by the cyclic GC instead of at once (fixed in
  2.1.4). The app does this, for example in `server/app/auth.py:251,266`
  (`for row in session.scalars(...)`). The suites pass on both databases, so this costs resources
  and does not change results. The other 2.1.x regressions concern things the app does not use:
  `selectinload` on many-to-many, `MappedAsDataclass`, `aggregate_strings`, asyncpg. 2.1.4
  (2026-10-07) can be taken from **2026-10-21**. If you would rather not run 2.1.1 for ten days,
  put `sqlalchemy==2.0.54` (2026-09-15) in the `.in` file instead before re-locking. That
  variant was not tested here.
- uvicorn 0.53 adds `::1` to the default `FORWARDED_ALLOW_IPS`. Production passes
  `--forwarded-allow-ips "*"` explicitly (`deploy/compose.prod.yml`), so it is unaffected. Since
  0.50 the default WebSocket implementation is websockets-sansio, and the API serves no
  WebSockets.
- Pushing the re-lock to the branch stops Dependabot from rebasing it (`docs/SUPPLY_CHAIN.md`).

### #13: alembic 1.14.0 → 1.20.0 (DO NOT MERGE as is; the update is good)

Alembic 1.20.0 was released 2026-09-11 (30 days ago), and the only requirement it adds is
`SQLAlchemy>=2.0`. The pull request is from before the lock existed: it edits a
`server/requirements.txt` without hashes and conflicts with `main`. Alembic is not in #25,
presumably because this single-package pull request was already open.

Applying it on top of the re-locked #25 changes **one line of the lock** (alembic 1.14.0 →
1.20.0, new hashes); Mako and the rest stay as they are. Tests, with #25 applied:
SQLite **1248 passed, 1 skipped**; Postgres **1248 passed, 1 skipped**, upgrade **2 passed**,
`[pg] PASS`.

It adds **385 `DeprecationWarning`s** to the suite: "No path_separator found in configuration;
falling back to legacy splitting on spaces, commas, and colons for prepend_sys_path". One line in
`server/alembic.ini` removes them (checked here on `test_auditlog.py`, `test_agent.py` and
`test_auth.py`: 72 passed, no warnings). Without it, a `%(here)s` path that contains a space or
a colon would be split.

```ini
[alembic]
script_location = %(here)s/migrations
prepend_sys_path = %(here)s
path_separator = os
```

To take it (after #25 is merged): comment `@dependabot recreate` on #13 and re-lock as for #25.
Or close #13 and make the change by hand:

```sh
git switch -c alembic-1.20 origin/main
sed -i '' 's/^alembic==1.14.0$/alembic==1.20.0/' server/requirements.in
# and add "path_separator = os" under [alembic] in server/alembic.ini
tools/lock_requirements.sh server/requirements.in
git diff server/requirements.txt          # expect only the alembic lines
```

### #9: cryptography 43.0.3 → 50.0.2 (WAIT until 2026-10-14)

`main` is already on 50.0.0 (2026-07-31), which fixes every cryptography advisory published
(GHSA-g6cj-pr64-35w5, the PKCS#7 Bleichenbacher oracle, was the last). 50.0.1 (2026-08-25) and
50.0.2 (2026-09-30) only rebuild the wheels against newer OpenSSL (4.0.2, then 4.0.3) and update
PyO3. No advisory names them. 50.0.2 can be taken from **2026-10-14**, and 50.0.1 now if you want
the OpenSSL refresh sooner. The pull request conflicts with `main` (old lock), so recreate it or
make the change by hand, as for #13.

Forecast test (#25 + alembic 1.20.0 + cryptography 50.0.2, re-locked; the lock changes only the
cryptography lines; the image reports `OpenSSL 4.0.3 29 Sep 2026`): SQLite **1248 passed,
1 skipped**; Postgres **1248 passed, 1 skipped**, upgrade **2 passed**, `[pg] PASS`.

### #8: fastapi 0.115.6 → 0.142.2 (DO NOT MERGE)

- It conflicts (old lock), and `main` is already on 0.141.1.
- 0.142.2 was released 2026-09-30, so it is too young (OK only from 2026-10-14).
- **0.142.0 added "native OpenTelemetry support"**: a new runtime dependency,
  `opentelemetry-api>=1.44.0`, and **automatic exporter setup from `OTEL_*` environment
  variables, on by default**. 0.143.0 (2026-10-08) made it opt-in as a breaking change
  ("Require opt-in for automatic OpenTelemetry exporter setup"). For a product whose point is
  that nothing leaves except through the gateway, skip the whole 0.142 series.
- Next step: from **2026-10-22** evaluate 0.143.0. That is a decision about the new
  `opentelemetry-api` dependency (the `.in` file's comment already notes it), plus checking that
  nothing sets `FASTAPI_OTEL_AUTO_CONFIGURE`.

### #11: sqlalchemy 2.0.36 → 2.1.3 (CLOSE AS SUPERSEDED by #25)

#25 takes SQLAlchemy 2.1.1, the newest release old enough. 2.1.3 was released 2026-10-02 (OK only
from 2026-10-16), and 2.1.4 (2026-10-07) already supersedes it. The pull request conflicts with
`main`.

## npm (web)

All of these were checked in the Node image `web/Dockerfile` pins (Node 24.21.0), each on a copy
of `main` with the pull request's diff applied:
`npm ci --ignore-scripts && npx tsc --noEmit && npm run lint && npm run build`, then
`npm audit --package-lock-only`.

| | npm ci | tsc | lint | build | npm audit | app bundle |
|---|---|---|---|---|---|---|
| `main` | ok | ok | ok | ok | 0 | `index-CUQ-3DcK.js` 392.91 kB (gzip 120.14 kB) |
| #23 | ok | ok | ok | ok | 0 | `index-LaVvctwU.js` 472.05 kB (gzip 143.11 kB) |
| #24 | ok | ok | ok | ok | 0 | `index-CUQ-3DcK.js`: identical to `main` |

### #23: npm-production (MERGE)

react and react-dom 18.3.1 → 19.3.0, @types/react 18.3.12 → 19.3.0, @types/react-dom 18.3.1 →
19.3.0 (all released 2026-09-09, 32 days ago), scheduler 0.28.0 (the same day), and
@fontsource/atkinson-hyperlegible and @fontsource/zilla-slab 5.1.0 → 5.3.0 (2026-07-19). All seven
new lock entries are older than 14 days.

- React 19 is a major. The app already uses `createRoot`, and none of the APIs React 19 removed
  appear in `web/src`: `ReactDOM.render`, `findDOMNode`, `propTypes`, `defaultProps`, string refs,
  legacy context. No component renders a `<title>`, `<meta>`, `<link>`, `<style>` or `<script>`,
  which React 19 would hoist into the head. `tsc` passes with the 19 types.
- `dist/index.html` is identical apart from the asset hashes, and the built file set is the same
  (18 assets). The Content-Security-Policy therefore needs no change.
- **Browser suite** (`tools/test_e2e.sh`, run as compose project `al-deps-eval` instead of
  `al-e2e` so that no other run's stack was touched; the API built from `main`): phase token
  **80 passed**, phase people **22 passed**, `[e2e] PASS`, in Chromium and Firefox.
- The app bundle grows by 79 kB (23 kB gzipped).

### #24: dev-tooling (MERGE)

ESLint ^9.15.0 (locked 9.39.5, which npm now marks deprecated and unsupported) → ^10.11.0
(2026-09-18), and eslint-plugin-react-hooks ^5.0.0 → ^7.1.1 (2026-04-17). The lock gains 62 entries
(Babel, which react-hooks 7 now uses, zod, cacheable and others) and loses 36. All 62 were
published before 2026-09-27. typescript-eslint 8.71.1 declares support for ESLint 10.

- `npm run lint` passes. A positive control was added: a scratch component with a conditional
  `useState` is reported as a `react-hooks/rules-of-hooks` error under ESLint 10.11.0, so the lint
  still works after the major bump.
- Development only: the built app is byte-identical to `main`'s, so the browser suite was not
  rerun for it. esbuild is unchanged, so `site/verify.html` is unaffected.
- #23 and #24 both change `web/package-lock.json`. Merge one, let Dependabot rebase the other,
  and merge it after CI.

### #10, #15, #19 (CLOSE AS SUPERSEDED)

- **#10** comes from before the Vite 8 move. Its Vite (8.3.3), @vitejs/plugin-react (6.1.2) and
  ESLint (10.12.0) versions are all younger than 14 days; #24 and `main` cover the rest. Its
  **TypeScript 7.0.2 cannot be installed**: typescript-eslint 8.71.1 requires
  `typescript >=4.8.4 <6.1.0`, and CI fails with `ERESOLVE` (`While resolving:
  typescript-eslint@8.71.1, Found: typescript@7.0.2`). TypeScript 7 (the native compiler) is a
  decision of its own and waits for typescript-eslint to support it.
- **#15** (react-dom alone) and **#19** (react alone): each fails `npm ci` with `ERESOLVE`, because
  react and react-dom, or their types, must move together. #23 moves them together.

## GitHub Actions: #21 (MERGE AFTER FIXING THE COMMENTS)

Dependabot moved each SHA but **not the comment next to it**. It most likely could not parse the
`# v4.4.0 (tag v4)` format. The pull request really does this:

| Action | Old pin | New SHA | Real version | Comment in the PR |
|---|---|---|---|---|
| actions/checkout | v4.4.0 `11d5960a` | `3d3c42e5aac5ba805825da76410c181273ba90b1` | **v7.0.1** (= tag v7), 2026-07-20 | `# v4.4.0 (tag v4)` |
| actions/setup-python | v5.6.0 `a26af69b` | `5fda3b95a4ea91299a34e894583c3862153e4b97` | **v7.0.0** (= tag v7), 2026-07-20 | `# v5.6.0 (tag v5)` |
| actions/setup-node | v4.4.0 `49933ea5` | `820762786026740c76f36085b0efc47a31fe5020` | **v7.0.0** (tag v7 is now 7.1.0, from 2026-10-08), 2026-07-14 | `# v4.4.0 (tag v4)` |

How each commit was checked: through the GitHub API, each SHA is a commit in the action's own
repository with a verified signature. It is exactly what that release tag points at. The v4 and
v5 tags still point at the old pins, so these are not tag moves. `test_supply_chain.py` did not
catch the wrong comments because it only checks that a comment matching `# v\d` exists. A test
that compares the comment with the tag would have.

What the majors change, and why none of it breaks these workflows:

- v5 and v6 run on Node 24, which needs runner 2.327.1 or later. The jobs run on GitHub-hosted
  `ubuntu-24.04`, so that holds.
- checkout v6 keeps credentials in a separate file. Every checkout here sets
  `persist-credentials: false`.
- checkout v7 refuses to check out a fork's pull request under `pull_request_target` or
  `workflow_run`. Only `cla.yml` uses `pull_request_target`, and it has no checkout.
- setup-python v7 removed the `pip-install` input and EOL Pythons. The workflows use only
  `python-version: "3.12"`.
- setup-node v5 caches automatically when `package.json` has a `packageManager` field.
  `web/package.json` has none, so nothing is cached. setup-node v7 removes the dummy
  `NODE_AUTH_TOKEN`. The workflows use only `node-version: "24"`.

Tests: CI on #21 passed every job (server, postgres, verifier, web, workflows, CLA).
`tools/lint_workflows.sh` (actionlint and shellcheck) passes both on the pull request and after
the comment fix below.

```sh
gh pr checkout 21
sed -i '' \
  -e 's|3d3c42e5aac5ba805825da76410c181273ba90b1 # v4.4.0 (tag v4)|3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1 (tag v7)|' \
  -e 's|5fda3b95a4ea91299a34e894583c3862153e4b97 # v5.6.0 (tag v5)|5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0 (tag v7)|' \
  -e 's|820762786026740c76f36085b0efc47a31fe5020 # v4.4.0 (tag v4)|820762786026740c76f36085b0efc47a31fe5020 # v7.0.0 (tag v7.0.0)|' \
  .github/workflows/tests.yml .github/workflows/security.yml
grep -h -o 'uses: actions/[a-z-]*@[0-9a-f]* # .*' .github/workflows/*.yml | sort | uniq -c
#   9 checkout ... # v7.0.1 (tag v7) · 3 setup-node ... # v7.0.0 (tag v7.0.0) · 3 setup-python ... # v7.0.0 (tag v7)
tools/lint_workflows.sh
git commit -am "Actions: the pin comments name v7" && git push
```

## Base images: nginx (#22, #20, #5)

nginx's odd minors are its mainline branch and its even minors are stable. `web/Dockerfile`
says "nginx:1.30.5-alpine (the stable branch…)". Measured:

| | `nginx:1.30-alpine` (the pin) | `nginx:1.31-alpine` (#20, #22) |
|---|---|---|
| Digest | `0985e772…` (= `stable-alpine`) | `df221db8…` (= `mainline-alpine`) |
| nginx | 1.30.5 | 1.31.6 |
| Built | 2026-09-26 | 2026-09-26 (15 days: inside the rule) |
| Alpine | 3.24.2 | 3.24.2 |
| zlib, pcre2, libexpat, tiff, libssl3, libcrypto3 | 1.3.2-r0, 10.48-r0, 2.8.4-r0, 4.7.1-r0, 3.5.8-r0, 3.5.8-r0 | the same |
| Last security fix | CVE-2026-90439 (HTTP/3), in 1.30.5 | the same fix, in 1.31.6 |

The move therefore gains no security fix and no newer OS package. It brings mainline's new
features (control API, predicate locations, `ngx_http_json_module`) and leaves the stable branch
the project chose. **DO NOT MERGE #22 and #20 unless you decide to follow mainline.** If you
do decide that:

- **#22 alone works**. The web image `attackledger-web:deps-eval` built from it reports nginx
  1.31.6, `nginx -t` passes, `tools/scan_images.sh` finds **0 HIGH or CRITICAL** (the six apk
  floors in `web/Dockerfile` are still needed, because the 1.31 base has the same old packages),
  and the browser suite on it passes: **80 + 22 passed**, `[e2e] PASS`. Update the comment above
  the `FROM` line (version, branch, date).
- **#20 cannot be merged on its own**. CI fails `test_scan_ignore_entries_name_a_reason_and_an_end`:
  `no published image matches: CVE-2026-85091 nginx:1.30-alpine@* zlib ...`. Scanning
  `nginx:1.31-alpine@sha256:df221db8…` gives `[scan] 4 HIGH/CRITICAL with a fix, 0 accepted`
  (zlib CVE-2026-85091, pcre2 CVE-2026-103111, libexpat CVE-2026-93990, tiff CVE-2026-4775), so
  the script exits 1. The 1.30 pin, with the current ignore list, gives `0 with a fix, 4 accepted`.
  The four `nginx:1.30-alpine@*` lines in `tools/scan_ignore.txt` would have to become
  `nginx:1.31-alpine@*`, and the comments above both `image:` lines would need updating.
  Merge #20 together with #22.
- To keep the stable branch and stop these weekly pull requests, add an `ignore` for nginx minor
  versions to the `docker` and `docker-compose` entries of `.github/dependabot.yml`. A new stable
  minor (1.32) would then be moved by hand with `tools/refresh_pins.sh`, which already covers
  every pin.

**#5** (1.27-alpine → 1.31-alpine, no digest, from before the pins) is superseded by #22, and
`main` already left 1.27 for a pinned 1.30.5. It conflicts with `main`.

## How it was tested, and what was cleaned up

- Python: the scratch branches `deps-eval/pr25` (#25 re-locked), `deps-eval/pr13` (+ alembic
  1.20.0) and `deps-eval/pr9` (+ cryptography 50.0.2), each re-locked with
  `tools/lock_requirements.sh server/requirements.in`. For each: an API image built as
  `attackledger-api:deps-eval`, the suite run in it on SQLite (`--network none`, non-root), then
  `ATTACKLEDGER_TEST_IMAGE=attackledger-api:deps-eval tools/test_postgres.sh`.
- npm: copies of `main` with each pull request's diff, checked in the pinned `node:24-alpine`.
  Browser suite: the scratch branches `deps-eval/pr23` and `deps-eval/pr22`, with
  `tools/test_e2e.sh` run as compose project `al-deps-eval`.
- nginx: `attackledger-web:deps-eval` built from #22, `tools/scan_images.sh` on it and on both
  nginx base images.
- Actions: `tools/lint_workflows.sh` on a copy with #21, before and after the comment fix.
- The first SQLite run of #25 failed `test_every_lock_is_made_by_the_lock_script_and_tested`,
  because the tree copies sat inside the worktree, and the test found their `.in` files. They
  were moved out and both suites were rerun on a clean tree. The numbers above come from that
  rerun.
- Network: GitHub API (GET), PyPI, the npm registry, Docker Hub and Grype's database only.
  No traffic to any target.
- Afterwards: the scratch branches deleted; the `attackledger-*:deps-eval` and `al-deps-eval-*`
  images and the pulled `nginx:1.31-alpine` image removed; the `al-deps-eval` project's
  containers, networks and volumes removed by the script; no `server/attackledger.db`,
  `__pycache__` or temporary files left. The user's `attackledger-*` containers, networks,
  volumes and images were not touched.
