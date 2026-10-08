# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org/);
before 1.0, minor versions may change the data model.

## [0.3.2] - 2026-10-08

### Fixed
- **A run stopped at the time limit no longer shows as `done`.** It is now
  `partial`, and the remaining targets are listed exactly. Targets run in batches
  (`WORKER_CHUNK_SIZE`, default 20), and a batch counts only once it finished.
- The time limit is enforced by a watchdog, so a tool that prints nothing (such as a
  slow port scan) is still stopped on time.
- **Run remaining** starts a new run for the targets a partial or cancelled run did
  not reach, and every gate is checked again. Cancelling a queued run keeps all of
  its targets resumable.
- Migration `0004` adds the `partial` status, `targets_done` and `remaining_targets`.

## [0.3.1] - 2026-10-08

### Security
- **Port scanning now honours the engagement rate limit.** naabu ran at ten times
  the requests-per-second value, carried over from the original pipeline. The
  value is now a hard ceiling for every step that sends traffic, a test checks this
  for every tool, and the shipped `recon/run_pipeline.sh` was corrected the same way.

### Added
- **JavaScript analysis (module 8)**, ported from the original `js_analyze.py` and
  `secret_triage.py`. It covers endpoints (LinkFinder regex, own host only), GraphQL
  operations, sourcemaps (fetched only when in scope) and secret candidates in REAL,
  PUBLIC and NOISE buckets, with REAL checked first. Secrets are stored masked and
  hashed and are never tested.
- **Leads.** A new `leads` table (migration `0003`), an API endpoint and a UI panel.
  Hosts in Golden targets show their lead count.

### Fixed
- JS fetch failures were swallowed. They are now logged with their reason, and a
  run that fetches nothing fails.
- Protocol-relative URLs in JS could resolve to another host.
- `recon/secret_triage.py` referenced a bucket name left over from translation.

## [0.3.0] - 2026-10-08

### Added
- **Recon pipeline modelled on the author's own process.**
  - Multi-source subdomain discovery (subfinder `-all`, assetfinder, crt.sh), filtered
    to scope before resolution.
  - Port scanning (naabu top 100, connect scan). Off by default, enabled per engagement.
  - Richer probing per open port, with CDN and CNAME data.
  - **Golden-target scoring**, ported from the original pipeline.
  - Crawling of golden hosts with katana. It stays on the same host and never
    follows logout, delete or revoke paths.
  - Archived URLs from gau and waybackurls.
  - Endpoint store with uro-style clean-up and JavaScript flagging.
- UI: a six-step pipeline with traffic labels, a Golden targets table, and an
  Endpoints browser with search and a JS-only filter.
- Migration `0002`: the endpoints table plus `allow_port_scan` and `crawl_depth`.

### Changed
- DNS resolution runs in two passes (A/AAAA, then CNAME). Some resolvers made dnsx
  drop hosts without a CNAME when all three were requested together.
- A pre-migration database is stamped at head, and only when its schema matches
  the models.

### Fixed
- A job whose tool fails without producing anything is now `failed` instead of `done`.

## [0.2.0] - 2026-10-08

### Added
- **Database migrations (Alembic).** The API migrates at startup and the worker
  waits for the latest revision. Databases created before migrations are stamped
  only when their schema matches the models; otherwise startup is refused.
- Tests cover a fresh migrate, downgrade followed by upgrade, stamping a
  pre-migration database, refusing one that has drifted, and drift between the
  models and the migrations.
- `docs/DECISIONS.md`: a decision record of who proposed and who decided each
  product choice.

### Fixed
- The downgrade now removes the Postgres enum types, so downgrading and then
  upgrading works.

## [0.1.0] - 2026-10-08

First tracked release.

### Added
- **Evidence ledger.** Engagements, assets and lanes (host × methodology lane) with
  checklist items. Evidence is append-only and hash-chained per engagement.
- **Fail-closed gates.** An item is done only with evidence, and N/A needs a reason.
  A lane closes with a receipt (manifest hash), and any later change voids the receipt.
  A lane opens only when the lanes it depends on are receipted.
- **Methodology packs.** `bug-bounty` (7 lanes) and `web-pentest-wstg` (97 OWASP WSTG
  tests), with indicative mapping to PCI DSS v4.0, ISO/IEC 27001:2022 and DORA controls.
- **Recon engine.** A worker runs subfinder, dnsx and httpx. Jobs are refused without
  a scope, a recorded authorization and, for target traffic, the research header or
  user agent. Scope is re-checked on every target and every result.
- **Audit report.** JSON and printable HTML. `tools/verify_report.py` verifies it
  offline (body hash, evidence chain, receipts).
- **Web UI.** Recon, Ledger, Controls and Report views, with dark mode.
- **Release gate.** `tools/release_gate.sh` blocks publishing private target names,
  open-finding fingerprints, personal paths and secrets.

### Known limitations
- Reports are not signed. Verification proves internal consistency, not authorship.
- No authentication on the API. Bind to localhost only (the default).
