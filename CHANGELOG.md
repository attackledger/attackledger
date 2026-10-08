# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org/);
before 1.0, minor versions may change the data model.

## [Unreleased]

### Added
- **Run pipeline.** One action queues every step that passes its gates, in registry
  order, and reports the skipped ones with their reasons. Each step resolves its
  targets when it starts, from what the earlier steps produced (deferred jobs,
  migration `0008`). Default target selection moved to `targets.py`, shared by the
  API and the worker.
- `docs/ROADMAP.md`.

- **M7 nuclei module (opt-in)**, pinned to nuclei v3.11.1 and nuclei-templates v10.4.9.
  It mirrors the original pipeline: takeover checks on every live service; exposures,
  misconfigurations and stack-tagged templates on one representative per cluster; and
  exposed panels, vulnerabilities and CVEs on golden hosts, all at medium severity and
  up. It never runs dos, fuzz, intrusive, brute-force, default-login,
  credential-stuffing or token-spray templates.
- **Templates excluded by content** at image build (834 of them): raw/unsafe requests,
  hard-coded out-of-band hosts and digest authentication. Measured against a raw
  socket logger, the full scan sent 8,899 of 8,899 requests with the research
  identification. Without the exclusions, 3 template classes dropped it or called
  third parties. nuclei runs with `-ni -dr` and refuses to run if the exclusion list
  is missing.
- Pinned, SHA-256-verified downloads for feroxbuster v2.13.1, nuclei-templates and
  the SecLists `common.txt` wordlist. Arjun 2.2.7 is installed in the worker for
  upcoming modules.

- **M3 content discovery (opt-in).** feroxbuster runs on golden hosts, up to 10 per
  run, one URL and one scan at a time, with the common.txt wordlist. Hosts that answer
  every path the same way are skipped after a baseline check, which carries the
  research identification. It never follows redirects or extracted links and never
  requests logout or delete paths. Measured: 9,504 requests, all identified, with
  a peak of exactly the 20/s limit.

- **M5 parameter discovery (opt-in).** Arjun 2.2.7 runs on dynamic endpoints (query
  strings, script extensions, API paths), up to 20 per run, highest-scoring hosts
  first. Each endpoint's accepted parameters are recorded as a lead. It runs isolated
  from the worker's own dependencies, with one thread and a fixed delay.
  Measured: 1,332 requests, all identified, with a peak of exactly the 10/s limit. With
  several threads, `--rate-limit` alone reached 17/s.

### Fixed
- Names that answer NOERROR with no records were counted as resolved, and subdomain
  discovery could add them as assets. Only an A or AAAA record now counts.

## [0.4.1] - 2026-10-08

### Changed
- **Only a person issues receipts (D-018).** Closing a lane requires the signer's
  name and a review confirmation. The signer is stored on the receipt (migration
  `0007`), shown in the lane and in the report, and the verifier notes unsigned
  receipts.

### Fixed
- JavaScript analysis no longer drops files beyond 250 silently. The registry's
  `max_targets` caps a run, the overflow is listed as remaining, and the run is
  `partial` and resumable. Files from the highest-scoring hosts go first.
- An all-whitespace signer name is rejected.

## [0.4.0] - 2026-10-08

Architecture release: the shape every later module and the hunt agents plug into.

### Added
- **Module registry** (`modules.py`): each recon job kind is defined once, with its
  input type, traffic class, HTTP flag, opt-in flag and outputs. API gates, worker
  dispatch and UI steps are derived from it (`GET /modules`), and the worker refuses
  to start if its runners and the registry disagree.
- **Shared job gates** (`jobgates.py`), applied when a job is queued and again when
  it runs.
- **Opt-in modules per engagement** (`enabled_modules`, migration `0005`). This
  replaces `allow_port_scan`, and existing settings carry over.
- **Hunt executors** (`executors.py`, migration `0006`). A lane has an executor,
  manual or agent; the agent arrives in v0.4.x/v0.5. `GET /lanes/{id}/context` returns
  what an executor may read, limited to the lane's host.
- `docs/ARCHITECTURE.md`: layers, contracts and invariants.

### Changed
- Research identification is required for modules that send **HTTP**. Port
  scanning is target traffic but carries no headers; it is gated by opt-in instead.

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
