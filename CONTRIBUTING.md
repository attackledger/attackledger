# Contributing to AttackLedger

Thank you for your interest. Issues and pull requests are welcome.

## Before you open a pull request

- **Sign the CLA once.** AttackLedger is published under the AGPL-3.0 and also offered under
  a commercial licence, so every contribution needs the [Contributor License
  Agreement](CLA.md). On your first pull request, a bot posts a comment. Reply with the
  sentence it gives you. You keep the copyright in your work. A pull request can't be
  merged until every commit author has signed.
- **Security issues go privately** to murat@attackledger.com or through GitHub's [private
  reporting](https://github.com/attackledger/attackledger/security/advisories/new), not in
  issues or pull requests. See [SECURITY.md](SECURITY.md).
- **No real targets.** Never include real target names, findings, captured traffic,
  credentials or personal data in code, tests or fixtures. Use `example.com`, `*.test`
  hosts or the bundled lab.
- **Keep the guarantees.** The gateway's scope, method, rate and identification checks, the
  evidence chain, and the rule that only a person signs a receipt are what the product
  stands on. Changes that weaken them won't be merged. Changes that make them stronger
  are very welcome.

## Working on the code

- Read `README.md` (quick start) and `docs/TARGET_ARCHITECTURE.md`.
- **Server tests:** `cd server && python -m pytest -q tests`. The CI runs them as a non-root
  user, so please do the same.
- **Server tests on Postgres:** `tools/test_postgres.sh` (below).
- **Web:** `cd web && npm ci --ignore-scripts && npx tsc --noEmit && npm run lint && npm run build`.
- **Verifier changes:** a change to `tools/verify_report.py` needs the same change in
  `web/src/verify_report.ts`, and a case in `tools/verifier_equivalence/cases.json`
  (D-046).
- **Decisions:** record one that changes direction, scope, licensing or security behaviour
  in `docs/DECISIONS.md`, and add a line to `CHANGELOG.md`.
- **Plain English** in user-facing text: short sentences, sentence case, and say what
  happens.

## What the CI runs

Every push and pull request runs `.github/workflows/tests.yml`. Each job is a command you can
run yourself first:

| Job | Runs | On your machine |
|---|---|---|
| `server` | the server suite on SQLite, with the fuzz tests at their default, seeded size | `cd server && python -m pytest -q tests` |
| `postgres` | the same suite on Postgres 16 and the migration-0022 upgrade check | `tools/test_postgres.sh` |
| `verifier` | the browser verifier against `tools/verify_report.py`, then 500 seeded mutants | `tools/verifier_equivalence/run.sh`, then `--fuzz 500 --seed 20261010` |
| `web` | type check, lint, build | `cd web && npm ci --ignore-scripts && npx tsc --noEmit && npm run lint && npm run build` |
| `e2e` | the browser tests: the public site as Cloudflare Pages serves it, then the web app on its own stack, in Chromium, Firefox and WebKit (Playwright's report is uploaded when a test fails) | `tools/test_e2e.sh` (Docker; `docs/security-review/WEB_E2E.md`) |
| `workflows` | actionlint and shellcheck on the workflows | `tools/lint_workflows.sh` (Docker) |

The jobs have a read-only token and no secrets, so a pull request from a fork runs them all.
`server/tests/test_supply_chain.py` keeps it that way: actions pinned by commit, read-only
permissions, no `pull_request_target` outside the CLA workflow.

A second workflow, `.github/workflows/security.yml`, runs weekly and on demand (not on pull
requests): the image scan, the base-image pin report, `pip-audit`, `npm audit` and the SBOM
(`docs/SUPPLY_CHAIN.md`, "The weekly security workflow"). Dependabot opens grouped update pull
requests weekly; a Python one needs a re-lock before it can pass (same document, "Dependabot").

## Testing on Postgres

Production runs on Postgres 16; `python -m pytest` runs on SQLite, which forgives things Postgres
does not. `tools/test_postgres.sh` runs the whole server suite on a throwaway Postgres in one
command (Docker, the API image and the Postgres image `docker-compose.yml` pins by digest, which
it pulls if missing; it removes what it started).
Each test gets new, empty databases, and the server is in a time zone other than UTC. It then
upgrades a database that the 0.7.1 code filled (migration 0022 with data).

Run it before a pull request that touches:

- the models or a migration;
- a query: ordering, `LIKE`, JSON columns, locks, a conditional update, anything two requests or
  workers can do at once (the race tests in `tests/test_security_review_auth.py`);
- times (stored without a zone, read as UTC);
- text or numbers stored from a request, a tool or an import: column lengths, NUL characters
  and 32-bit integers are enforced by Postgres only.

`tools/test_postgres.sh tests/test_ledger.py` runs only those tests. Against a Postgres of your
own, set `ATTACKLEDGER_TEST_PG` to a URL whose role may create databases
(`postgresql+psycopg://user@host/postgres`, the password in `PGPASSWORD`) and run pytest as usual;
the tests create and drop `al_test_*` databases there.

## Browser tests

`tools/test_e2e.sh` runs the public site and the web app in Chromium, Firefox and WebKit with
Playwright (`docs/security-review/WEB_E2E.md`). It needs only Docker: it builds this tree's API and
web images and a runner from Playwright's pinned image (`e2e/Dockerfile`), checks the site (built by
`tools/build_pages.sh` inside the runner and served with its `_headers` as Cloudflare Pages would),
starts its own stack as compose project `al-e2e` with no port on the host, fills it with hostile
content, runs the app's suite twice over (with the operator token, then with people signed in), and
removes the project's containers, networks and volumes. About MINUTES minutes once the images are built.

```sh
tools/test_e2e.sh               # everything
tools/test_e2e.sh -g verifier   # only tests whose name matches; arguments go to playwright test
tools/test_e2e.sh --keep        # leave the stack up to look at it; tools/test_e2e.sh --down removes it
```

Run it before a pull request that touches the web app, nginx's headers, sign-in, sessions or roles,
the verifiers, or the site (`site/`, `tools/build_pages.sh`). A new view goes into
`e2e/tests/token/hostile.spec.ts` and `csp.spec.ts`, a new site page into `e2e/tests/site/`; every
test runs under the guard in `e2e/tests/lib.ts`, which fails on any CSP violation, script run by
injected content, dialog or unexpected console error. The tests use made-up credentials only, made
at run time, and reach nothing outside the test network.

## AI-assisted contributions

Contributions written with an AI assistant are fine. You are still the one confirming
section 4 of the CLA, so read and test what you submit. Keep any `Co-Authored-By` trailer
your tool adds (D-011).
