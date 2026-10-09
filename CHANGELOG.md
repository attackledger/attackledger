# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org/);
before 1.0, minor versions may change the data model.

## [Unreleased] - 0.6.0

Hunt agents: a Claude agent can work a lane within the lane's rules. Not yet run
against the live API (no key was available); tested with a scripted model and the
local lab.

### Added
- **Agent runs** (`POST /lanes/{id}/agent-runs`): a job of kind `agent` on one lane,
  with turn and request limits, cancel, partial status and a token cost estimate.
  Migration `0009` adds `jobs.lane_id` and `jobs.result`.
- **Gated agent tools** (`agenttools.py`): `http_request`, `add_evidence`,
  `mark_item`, `record_lead`, `finish`. Lane host and scope only, read-only methods
  (D-024), identification always sent, no redirects, rate-limited, budgeted. No
  tool can close a lane.
- **Agent loop** (`agentloop.py`) on the Messages API with `claude-opus-5-5`,
  adaptive thinking, prompt caching and server-side refusal fallback (D-025).
- **Blob store** for raw evidence, shared by API and worker, and `GET /blobs/{sha256}`
  (sandboxed plain text, only for hashes that evidence cites).
- **UI:** choose the lane's executor, start and follow agent runs, see why a run
  failed, and open the raw exchange behind each agent evidence entry.
- **Agent model setting** `ATTACKLEDGER_AGENT_MODEL` on the worker: `claude-opus-5-5`
  (default), `claude-sonnet-5-5` or `claude-haiku-5-5` for a cheaper first test. Unknown
  models are refused. The cost estimate uses the chosen model's price; Haiku requests
  no server-side fallback (it has none). The model is shown on each run.
- **People, roles and separation of duties** (D-032). Sign in with email and password;
  per-engagement roles (viewer, tester, reviewer) and owners; a People page and a Team
  tab for owners; every route checked against one permission table; non-members do not
  see an engagement at all. Separation of duties is a per-engagement switch: the person
  who attached a lane's evidence cannot sign its receipt. Evidence, jobs and receipts
  record who made them. The first owner is added from the People page (open or token
  mode) or with `python -m app.people create --owner`. Migration `0010`.
- **Signed receipts** (D-033). A reviewer's browser creates a non-extractable Ed25519
  key (ECDSA P-256 where Ed25519 is missing) and signs each receipt; the server stores
  only the public key and checks every signature against the lane's current manifest.
  Report format `attackledger-report/2` carries payload, signature and public key;
  `verify_report.py` checks them offline with the standard library and still reads
  format 1. An engagement can require signatures. Migration `0011`.
- **RFC 3161 timestamps** (D-034). With `ATTACKLEDGER_TSA_URL` set, each receipt's
  manifest hash and signature are timestamped (only a hash is sent). If the authority
  cannot be reached the close still succeeds and can be timestamped later. The verifier
  checks the token, the authority's signature and its certificate chain to a root you
  trust (`tools/tsa-roots/` or `--tsa-root`). Docker Compose uses DigiCert's public
  service by default and its root is pinned; `ATTACKLEDGER_TSA_URL=off` turns it off.
  Migration `0012`.
- `ATTACKLEDGER_COOKIE_SECURE` is now passed to the API by Docker Compose (it was
  documented but not forwarded).
- **A real Claude agent run in the demo.** With no API key yet, Claude Opus worked the
  Lab recon lane from Claude Code through `tools/agent_bridge.py`, which runs every call
  through the same gated tools inside the worker (D-031). 23 requests (22 reached the lab,
  all with the research header and user agent; peak 2/s), 10 items done, 2 N/A, 5 left open
  with reasons, 8 leads, no receipt. The demo shows the run, its log and the raw exchanges,
  and says how it was driven and that token use was not measured.
- **"Start here" guide in the demo:** five steps (recon steps, golden targets, the coverage
  ledger, a receipted lane, the report), each with a button that opens the right view.
- **Work a lane from the lane panel.** On a manually worked lane, each item now has Add
  evidence (a note, a file up to 5 MB, or a finished recon run), Mark done, Not applicable
  (with a reason) and Reopen. `POST /lanes/{id}/attach` hashes notes and files on the
  server and keeps the bytes in the blob store, so "View raw" opens them; a recon run
  contributes its output hash. Changing a receipted lane warns that the receipt goes void.
- **Read-only demo** (`site/demo/`): the real web app built with `VITE_DEMO=1`. Reads come
  from a snapshot exported by `tools/export_demo.py`, every change is refused with a
  message, and reports are static files. `tools/build_demo.sh` builds it from a demo stack
  with fictional data; the Lab recon data comes from a real pipeline run against the lab.
- **Recon screen reorganised into six steps** (D-026), like ars0n-framework-v2:
  a target bar with the rules, a funnel from host names to leads, numbered steps with
  "Run step" and "How this step works", one card per tool (tools used, last run,
  results, log), and results in tabs: golden targets, hosts, URLs, leads and runs. A
  card's Results button opens what that module found. New API: `GET /recon/phases`,
  `GET /engagements/{id}/recon/summary`, and a `module` filter on endpoints and leads.
  The pipeline order now matches the steps: content discovery runs before JavaScript
  analysis, and nuclei before the dork list.
- **Small runs by default, with a cost limit.** Defaults are 15 turns, 30 requests and an
  estimated $0.50; the run stops at whichever comes first (cost is checked after each
  turn, so a run can go over by at most one turn). The model sees at most 4,000
  characters of each response and 40,000 per run, because every tool result is sent
  again on each later turn; the full response is always kept as evidence. The first
  message carries at most 50 recon rows of each kind.
- **Interrupted jobs are recovered.** At startup the worker marks every job left
  `running` as failed with a reason; between jobs it does the same for any run past the
  time limit plus `WORKER_STALE_GRACE` (default 10 min). Results from finished batches
  and an agent's evidence are kept. One worker per database is assumed.
- Lab: `/go` redirects to an `.invalid` host, to check that tools never follow it.
- 44 tests for the agent layer, including the gates, a scripted end-to-end run and
  the API. Positive controls: removing the host check, the pacing, the reserved
  headers or the identification precedence each makes a test fail.

### Fixed
- **Content discovery went over low rate limits.** feroxbuster's wildcard detection and
  its two start requests are not rate-limited: at a limit of 2/s the first second carried
  9 requests. It now runs with `--dont-filter` (the baseline check does that job) at the
  limit minus 2, and needs a limit of at least 3/s (a new `min_rps` gate in the registry,
  shown in the UI). Measured on the lab: peak 3/s at a limit of 3, 18/s at 20. The 0.5.0
  note "peak of exactly the 20/s limit" was true only at that limit.

### Verified on the lab
- Real transport: 5 of 5 requests carried the research header and user agent; a 302
  came back with its Location and was not followed; 2 rps gave 0.51 s spacing.
- End to end through the worker on Postgres: evidence chained and verified offline
  by `tools/verify_report.py`; a request to `example.com` was refused and never sent;
  the lane stayed unreceipted.

## [0.5.0] - 2026-10-09

Recon completed: every module of the original pipeline that can run safely, plus
the pipeline runner, scope import and API authentication.

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

- **M6 parameter routing** (computed, no traffic). Parameters from URLs and Arjun are
  sorted into gf-style classes (ssrf, redirect, idor, sqli, lfi, xss, rce), and each
  becomes a lead that names the hunt lane testing it.
- **M10 dork checklist** (computed, no traffic). For each wildcard root it writes the
  original dork.sh queries as click-ready manual checks.

- **HackerOne scope CSV import**, with a preview before apply. Assets not eligible
  for submission become **exclusions**, so a wildcard cannot cover them; the original
  csv_to_scope.py skipped them. Non-web assets (apps, CIDRs) are listed, not imported.

- **API authentication.** Set `ATTACKLEDGER_API_TOKEN` to require a token on every
  route except `/health` and login. The token works as a bearer header or as an
  HttpOnly, SameSite=Strict session cookie that holds an HMAC of the token, never the
  token itself, and is compared in constant time. The UI shows a sign-in screen when
  needed. `/health` reports whether auth is on.
- ESLint with `react-hooks/rules-of-hooks` in CI.

### Fixed
- The Recon view crashed after the Run pipeline button was added: a hook was declared
  after an early return. The new lint rule catches this class of bug.
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
