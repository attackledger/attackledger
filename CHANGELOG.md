# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org/);
before 1.0, minor versions may change the data model.

## [Unreleased]

### Added
- **Organizations** (D-042, migration 0022). Every record belongs to one. The migration
  makes a default organization and moves every existing row into it; a self-hosted
  install is unchanged.
  - **Scoping:** every API query is scoped to the caller's organization in one place
    (`orgscope.py`). Another organization's ids answer 404, like ids never used.
  - **Logs:** the key log and the audit log are one chain per organization. The default
    organization's chain is the old one, so existing reports still verify.
  - **Tokens:** worker and gateway tokens belong to an organization.
  - **Commands:** `python -m app.orgs` (list, create, tokens) and
    `python -m app.people … --org`.
  - **Behaviour change:** non-owners get 404, not 403, on owner routes for what they
    cannot see.
- **Test accounts** (D-040, migration 0021). Testers add sessions they signed in to
  themselves: a cookie, a bearer token or headers.
  - They are stored encrypted and never shown again.
  - The gateway adds them to an agent's requests "as A", for that account's hosts only,
    and scrubs responses before they reach the worker.
  - Evidence names the account.
- **Writes with a person's approval** (D-041), off by default. Agents propose POST, PUT,
  PATCH or DELETE, and a tester approves the exact request.
  - An approval is hash-bound, expires after 15 minutes and is used once.
  - A DELETE needs its path typed.
  - The gateway sends the write once, and it becomes evidence and audit entries.
  - New Test accounts and Approvals tabs.

### Fixed
- **Gateway log noise:** ProjectDiscovery tools run with `-duc`, so there are no update
  calls in the request log, and the gateway answers katana's Burp check itself.
- **Gateway log:** `bytes_sent` is now recorded.

## [0.7.1] - 2026-10-10

Fixes from the second design-partner review of 0.7.0.

### Changed
- **A voided receipt stays void** (D-052). Any change to a receipted lane voids its receipt
  until it is signed again, even if the lane is changed back. The audit log records it as
  `lane.receipt_voided`, and the report and change history show why.
- **Strict Content-Security-Policy on the web app**, plus the usual security headers in
  nginx and Caddy.
- **API docs** (`/docs`): a script-free page built from the OpenAPI schema. It loads
  nothing from another origin.
- **Wording**: gate and step messages use client, statement of work and rules of
  engagement wording on pentest and internal engagements.

### Added
- **Confirmation before mapping onto a receipted lane**: the API returns 409 unless
  `confirm_void`.
- **`can_sign` in the lane view**: it says before signing whether this person can sign,
  and why not.
- **The deletion screen** says what stays: each evidence URL with its host, path and
  query, plus receipts, signatures and logs. A proposal for a chain record that would not
  keep query strings is in `docs/PROPOSAL_URI_PRIVACY.md`.
- **The import route** documents its raw body in OpenAPI, and refuses multipart uploads
  with an example.
- **`caido_pull --upload`** finds the API under the site's address.
- **Docs**:
  - a Mac trial section in INSTALL;
  - what content deletion keeps;
  - what counts as a duplicate import;
  - the Verify tab as it is;
  - `.env.example` matches where each key goes.

- **Web**:
  - Links to an engagement, tab, lane and import entry (`#/e/3/ledger/lane/12`), with
    Back and Forward, reload, and "Copy link" on the lane panel. They work in the demo
    too (D-053).
  - An expired session says so, keeps unsent notes and reasons, and returns you to where
    you were.
  - Import marks items on receipted lanes "(voids receipt)" and asks before voiding them.
  - An engagement whose content was deleted shows a banner on every tab and disables
    import, runs and mapping.
  - Lane evidence is shown in chain order, with View raw for imported entries.
  - Cells show "Signed after …", and people who cannot sign see why.
  - Times are local, with UTC on hover. Fingerprints have one format. The offline
    command uses the report's real file name.

### Fixed
- **Controls**: the status when only not-applicable items are resolved.
- **Recon**: the per-step lead counts.
- **Mapping**: a clearer error for an item number that doesn't exist.

## [0.7.0] - 2026-10-09

The MVP for a design partner (docs/MVP.md). It covers:
- a traffic gateway for all target traffic, and a worker with no route to the internet
  or the database;
- encryption at rest with retention;
- evidence import from HAR, Burp and Caido;
- a public in-browser verifier;
- a tested install with backup and restore.

Version 0.6.0 was never released on its own; its changes, which first brought hunt agents
(a Claude agent can work a lane within the lane's rules), are included here. The agent loop
on the Messages API has still not run against the live API (no key was available). It is
tested with a scripted model and the local lab, and was driven from Claude Code for the
demo (D-031).

### Added
- **Caido pull** (`tools/caido_pull.py`, D-035). It reads HTTP history from your own Caido's
  GraphQL API, with an HTTPQL filter and a time window, and writes a Caido JSON export. The
  export can be redacted locally and uploaded to an engagement as you. The Caido token
  never leaves your machine.
- **Traffic gateway** (D-039, docs/GATEWAY.md). The worker has no route to the internet.
  Every recon tool and the agent go through one gateway. The gateway:
  - enforces scope, GET/HEAD/OPTIONS only, a rate ceiling shared by all tools, and the
    identification;
  - answers DNS only for in-scope names;
  - makes the port probes (naabu removed);
  - logs every request (`GET /engagements/{id}/gateway-log`).

  Benchmark through it: 0 non-GET, peak 20/s at a limit of 20. Migration `0019`.
- **Public verifier page** (`/verify`, D-042, D-046). Drop a report on
  attackledger.com/verify and every `verify_report.py` check runs in the browser, with
  the same verdicts and messages. Nothing is uploaded: `connect-src 'none'`, everything
  inline, Trusted Types.
- **The Verify tab checks everything**: the chain, receipts, signatures, key log, change
  history and RFC 3161 timestamps. It uses the same module as the public page
  (`web/src/verify_report.ts`, replacing `receipts.ts`).
- **Equivalence tests** (`tools/verifier_equivalence/run.sh`): 67 reports and 107
  building-block cases compared line for line with `verify_report.py`; 0 differences.
- **Install and operations**:
  - `docs/INSTALL.md`, tested end to end from the document.
  - A production override with Caddy HTTPS (`deploy/`).
  - `tools/backup.sh` and `tools/restore.sh`. The backup has a checksummed manifest.
    Restore refuses a damaged backup, an unknown migration, the wrong master key, or a
    non-empty install without `--force`.
- **Setup mode** (D-045): `ATTACKLEDGER_REQUIRE_SIGN_IN=1` closes the API until the
  first owner is created on the server.
- **Evidence import** (D-029): HAR 1.2, Burp Suite XML and Caido JSON files become inbox
  entries on a new Import tab.
  - Out-of-scope rows are refused and listed by row and host.
  - Credentials are redacted and raw bytes encrypted before storage, and entries are
    deduplicated by content.
  - A person maps each entry to checklist items, with explained suggestions. Each mapping
    is evidence with source `import:<tool>`.
  - Imports and dismissals are in the change history. Migration `0018`.
- **Encryption at rest** (D-043): evidence blobs and summaries are encrypted with a key
  per engagement, wrapped by a deployment master key (`ATTACKLEDGER_MASTER_KEY_FILE` or
  `ATTACKLEDGER_MASTER_KEY`; `ATTACKLEDGER_DEV_KEY=1` for trials). The API and worker
  refuse to start without one. Migration `0017`.
- **Retention**: owners set a "keep until" date, which the worker executes, or delete an
  engagement's data now with a typed-name confirmation. Both go into the audit log.
  Reports built afterwards still verify, with summaries marked unavailable.
- **Evidence chain record v2** commits to `summary_sha256` and `source` (manual, recon,
  agent, `import:<tool>`). v1 rows and old reports verify as before.
- `python -m app.vault`: generate, status, encrypt-existing, rotate-master,
  delete-content.
- **Guided first run**: the five setup steps from scope to first lane, each step's
  status computed from the engagement itself.
- **Role-based home**: each engagement opens on a tab chosen by role: Report for
  viewers, Ledger for testers and reviewers, the next setup step for owners.
- **Accessibility**: WCAG 2.2 AA contrast in both themes (axe: 0 violations on every
  app screen), small labels one size larger, focus ring on checklist items, and
  focusable logs, commands and tables. On phones and tablets nothing scrolls
  sideways and the sidebar folds into a compact header.
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
- **Audit log** (D-037). Scope and rules, authorization, settings, roles and people changes
  are recorded in a hash-chained audit log, shown in a History tab and a "Change history"
  report section and checked by `verify_report.py` (who held the reviewer role and which
  scope was in force when each receipt was issued). `GET /engagements/{id}/audit`,
  `GET /audit`, `python -m app.people audit-log`. Receipt payload v3 names the signer's
  email. Migration `0016`.
- **Evidence redaction** (D-038). Cookies, Authorization headers, tokens, keys, JWTs, emails
  and card numbers are replaced by a hash marker before evidence is stored; each entry says
  what was redacted. Per-engagement setting, on by default. Migration `0015`.
- **Key trust** (D-036). Owners can no longer set other people's passwords; people change
  their own (`POST /auth/password`) and an operator resets on the server
  (`python -m app.people set-password`, `revoke-key`, `key-log`). Key registrations and
  revocations go into a hash-chained key log (migration `0014`); people see key changes at
  sign-in in a "Your account" dialog; reports carry each signing key's history and
  `verify_report.py` checks it.
- **Fixes from a fresh-install trial.**
  - Exact scope entries become hosts when the rules are saved (`hosts_added` in the
    response); wildcards stay rules. Recon says when there are no hosts and lets you add
    one in place.
  - Steps with nothing to work on end `skipped` with a reason instead of `done`, and
    Run all steps no longer queues steps that cannot apply (migration `0013`).
  - Running steps show elapsed time, targets finished and the latest log line; queued
    steps show their place in the queue.
  - The verifier prints SKIP, not PASS, when no receipt is signed or timestamped;
    `--require-signatures` fails unsigned reports.
  - A clear message for a non-HTTPS policy URL; report evidence labels and counted nouns
    read correctly; the sidebar host count stays current.
  - Lane panel: honest item counts, a refused close lists what is still unresolved as it
    changes, and open items can be marked not applicable in bulk with one reason.
  - The Ledger and the report use the same words: Not opened, In progress, Receipted, Void.
  - README: first steps, API docs, database password, requirements and status.
- **Security policy** at `/security`, `/.well-known/security.txt` (RFC 9116) and `SECURITY.md`:
  scope, testing rules, how to report to murat@attackledger.com, 90-day coordinated
  disclosure and safe harbor (no bounty).
- **Client-facing HTML report.** Cover, a summary for the client with what the report
  does and does not prove, scope and authorization, a hosts × lanes coverage matrix,
  per-lane receipts (hash, signer, key, timestamp, void state) and step-by-step
  verification with the pinned DigiCert root; prints cleanly to A4 PDF. The JSON report
  adds `engagement.pack.lanes`, `engagement.separation_of_duties` and
  `engagement.require_signatures` (additive; format unchanged).
- **Role-aware web app and a Verify tab.** Viewers get a read-only app, and each role
  sees only the actions the server accepts (tester works, reviewer signs, owner manages);
  one helper (`web/src/access.ts`) mirrors `authz.RULES`. The Verify tab checks each
  receipt's signature in the browser (WebCrypto Ed25519 or ECDSA P-256) by the verifier's
  rules, offers the report JSON, and points to `verify_report.py` for the full check.
- **RFC 3161 timestamps** (D-034). With `ATTACKLEDGER_TSA_URL` set, each receipt's
  manifest hash and signature are timestamped (only a hash is sent). If the authority
  cannot be reached the close still succeeds and can be timestamped later. The verifier
  checks the token, the authority's signature and its certificate chain to a root you
  trust (`tools/tsa-roots/` or `--tsa-root`). Docker Compose uses DigiCert's public
  service by default and its root is pinned; `ATTACKLEDGER_TSA_URL=off` turns it off.
  Migration `0012`.
- **Demo and sample report signed and timestamped.** `tools/demo_sign.py` has a demo
  reviewer sign every closed demo lane (a script stands in for the browser key) and
  DigiCert timestamps each receipt; the sample report verifies with all five checks and the
  site ships DigiCert's root for `--tsa-root`. The HTML report shows each receipt's key
  and timestamp.
- Times from the API and in reports now carry their UTC offset; the browser showed UTC
  times from Postgres as local time.
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

### Changed
- **Demo**:
  - "Client web app" shows the Import tab. It has a HAR and a Burp export made from the
    lab (out-of-scope and duplicate rows refused), WSTG mappings with suggestions, a
    dismissed entry with its reason, and redacted requests and responses.
  - "Client web app" has a retention date, shown on the History tab.
  - "Client portal 2025" shows deleted content and a report that still verifies.
  - Lanes are worked in parallel next to a receipted Information gathering lane.
- **The worker no longer touches the database** (D-042, docs/WORKER_API.md, migration
  0020). It has no database credentials, database network, master key, blob store or
  Anthropic key.
  - It claims jobs and writes through `/worker/*` API routes, relayed by the gateway, with
    a token scoped to one job.
  - What a job writes is limited by its kind. Scope, redaction, deduplication,
    encryption and the evidence chain are applied in the API.
  - The Claude API key is set on the gateway, which adds it to agent calls.
  - Retention and marking interrupted jobs run in the API.
  - `tools/agent_bridge.py`: a person queues the run with a `driver`, and the bridge
    claims it.
  - The benchmark through the gateway is unchanged.
- **Contributions need a CLA** (D-051). See `CLA.md` and `CONTRIBUTING.md`. A bot asks each
  new contributor to sign once.
- **Control mappings reviewed** (D-050, docs/CONTROLS.md). They were checked against PCI
  DSS v4.0.1, ISO/IEC 27001:2022 Annex A and DORA, with the TLPT RTS (EU) 2025/1190.
  - Each mapping states its evidence strength: partial or supporting; none is full. The
    Controls view and the audit report show the strength and say a qualified assessor has
    not reviewed the mappings.
  - Removed mappings that overstated: PCI 11.3.2 (ASV scan), PCI 6.4.1 (superseded by
    6.4.2) and DORA Article 26 (TLPT). A bug bounty is now only supporting evidence for
    PCI 11.4.3.
  - Added ISO A.8.8, A.8.3, A.5.17 and A.8.2, and DORA Articles 24, 25 and 9, where lanes
    produce the evidence.
- **Recon for single-page apps** (D-049). Juice Shop recall went from 5 to 15 of 32
  in-reach items through the gateway, with 0 writes and a peak of 20 at a limit of 20.
  - A new step, Read well-known files, records robots.txt, security.txt and directory
    listings.
  - Content discovery filters a catch-all page by its fingerprint instead of skipping the
    host.
  - JavaScript analysis records single-page app routes and relative links.
  - Triage counts an API surface (+2).
  - Static files under paths such as uploads or backup, plus archives and sourcemaps, are
    kept as endpoints and never fetched.
- **Agents get a ranked lane context** and a reading view of responses: text and links
  for HTML, routes and endpoints for large JS files. `view: "raw"` gives the body as
  received.
- **The repository is public** (D-048) at https://github.com/attackledger/attackledger,
  after a full-history scan. Secret scanning with push protection, private vulnerability
  reporting and CodeQL are on.

### Changed (design-partner review, 2026-10-09)
- **Lanes are worked in parallel** (D-047): a lane opens at once, and it can be signed only
  after the lanes it needs are receipted (pack `needs_gate`; the bug bounty pack keeps
  gating the opening).
- **Mapping** can open a lane and, optionally, mark the items done ("Mark these items
  done", off by default). Lanes count items with evidence that wait to be marked done.
- **Import privacy**: the import audit entry holds counts only, never refused host names
  or the file name.
- **Re-importing** the same file needs an explicit choice.
- **API docs** (`/docs`, `/openapi.json`) need sign-in whenever the API does; `/redoc` is
  removed.
- **Add a host** says why a host was stored out of scope.
- **Verifier downloads**: the verifier script and TSA roots download from the API. The
  report's "How to verify" points to attackledger.com first. Reviewers see the host's
  inbox counts when signing.
- **Docs**: a tester guide (`docs/TESTER_GUIDE.md`). INSTALL now covers per-OS trust
  steps for Caddy's internal CA, a plain-HTTP trial over an SSH tunnel, keeping the CA
  through a restore, and practising against the lab with `--profile lab` (new
  `lab-proxy`, for capturing a browser HAR).

- **Web**:
  - A change to an item on a receipted lane asks first, and says the client will see the
    receipt as void.
  - An engagement whose content was deleted offers no lane or item changes and says why,
    and the API refuses them (409).
  - Setup: recon or an import completes the evidence step, and there is a Team step.
  - Pentest and internal engagements use client, statement of work and rules of
    engagement wording, and the methodology defaults by type.
  - Before a browser's first signature, the reviewer is told a new key will be
    registered.
  - People whose password someone else set are asked to choose their own at sign-in; they
    can skip.
  - Report and Verify point to attackledger.com/verify first, then to this server's
    verifier with its SHA-256.
  - The tab bar is sticky, the lane panel draws above the ledger, and the Controls table
    fits on phones.

### Fixed
- **Web**: a dismissal reason no longer shows a double full stop, and an out-of-scope host
  no longer widens the ledger page at 390 px.
- **The release gate refused every git worktree**: a worktree's `.git` is a file holding an
  absolute path, which the personal-path check matched. It is now skipped like the `.git`
  directory; nothing committed is skipped.
- **Sign-in right after Sign out was lost**: signing out reloaded the page, so input typed
  at once was dropped. It now switches to the sign-in form in place.
- **Content-Length after redaction**: a stored message whose body was redacted kept its
  original Content-Length.
- **Evidence imports over 1 MB were refused** by the web container's nginx (default body
  limit). It is now 60 MB in nginx and Caddy.
- **nuclei could send writes and burst over the limit** (measured by the Juice Shop
  benchmark: 24 POST, 1 DELETE, 1 DEBUG; 40 requests in one second at a limit of 20).
  nuclei now runs only templates that provably send GET, HEAD or OPTIONS requests
  (`nucleisafe.py`, 6,551 of 13,786 excluded; the worker refuses to scan otherwise), takes
  one token per tick with no retries, and needs a limit of at least 2/s. Re-run: 0
  non-GET of 5,511 requests, nuclei peak 19 at 20.
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
