# Decision record

This file records the product and design decisions behind AttackLedger: who
decided, what was considered, and why. It is kept honestly. Where an idea was
proposed by an AI assistant (Claude, via Claude Code), the entry says so, and it
names the person who made the decision.

Owner and decision maker: **Murat Kabak**.

## Origin of the material

The methodology in this repository predates the code. It comes from Murat Kabak's
hands-on bug-bounty work, which he has done since 2022. Between August and
October 2026 he wrote that experience down as a private, agent-driven practice. The
written form included:

- the **role pipeline**: recon, mapper, authz, authflow, logic, injection and mobile,
  one role per host lane, with the application model as a hard gate,
- the **per-role checklists** that the lane gate enforces,
- the **fail-closed closure rule**: "done" is a computed state backed by a receipt,
  never a claim, implemented as `close_gate` / `is_closed`,
- the **lane gate and delete guard** hooks for AI agents, and coverage auditing
  against the full inventory,
- the **finding-validator** step before any report is filed.

In October 2026 this material was translated to English, generalized and stripped
of all engagement data to form `methodology/`, `roles/`, `checklists/`, `agents/`,
`skills/`, `gates/`, `hooks/`, `lanes/` and `recon/`. The application code (ledger
API, worker, web UI, report and verifier) was written with Claude Code, following
the decisions below.

## Decisions

Each entry has an id and a date and records the decision, its context, the
options considered and who decided.

### D-001 · Build a framework from the existing methodology (2026-10-08)
- **Decision:** Turn the private bug-bounty methodology into a general,
  target-independent framework rather than publishing notes.
- **Context:** Murat wanted a product that also serves his career goal
  (information-systems audit, CISA) and could support an application to a startup program.
- **Decided by:** Murat Kabak. The initiative and the requirement that it be
  "a framework, not target-specific" came from him.

### D-002 · Name: AttackLedger (2026-10-08)
- **Decision:** The product is called AttackLedger, at attackledger.com.
- **Options considered:** FailClosed, Lanegate, Huntline and Proofline (proposed by
  Claude); Hackbot.ai and Hackbot.si (proposed by Murat; both taken and generic);
  RedAttest, AttackLedger, RedAssure and ProofStrike (proposed by Claude after Murat
  asked for a name covering **both audit and offensive security**); HunterLedger
  (proposed by Murat).
- **Decided by:** Murat Kabak, who set the audit-plus-offense criterion and chose
  AttackLedger over HunterLedger.

### D-003 · Publish methodology only, never engagement data (2026-10-08)
- **Decision:** Ship roles, checklists and gates. Never ship target names,
  findings, briefs, reports, ledgers or the history of the private repository. A
  release gate blocks private target names, personal paths and secrets, and
  denylists outside the repository hold the sensitive patterns.
- **Amendment (same day):** An anonymized "field lesson" can still reveal an open
  or unreported finding. Murat rejected that risk outright. Lessons that describe a
  specific vulnerability, endpoint, parameter or chain are therefore deleted, not
  generalized. The gate also checks a second denylist of fingerprints from open reports.
- **Decided by:** Murat Kabak. Claude proposed the original scrub plan; the
  stricter amendment is Murat's.

### D-004 · License: AGPL-3.0 with a commercial option (2026-10-08)
- **Decision:** Dual license. The open-source edition is AGPL-3.0, and a
  commercial license is available on request. Contributors sign a CLA.
- **Options considered:** MIT, which Claude initially proposed; GPL-3.0; AGPL-3.0.
- **Context:** Murat asked whether MIT would close off revenue and stated that
  paid use should stay possible.
- **Decided by:** Murat Kabak.

### D-005 · Holistic recon + hunt, operated from the UI (2026-10-08)
- **Decision:** The UI runs the work, not just tracks it: recon jobs, results,
  and later hunt agents, comparable to ars0n-framework but covering hunting as well
  as recon.
- **Context:** After the first UI, Murat said it felt like a tracking app, not a
  framework.
- **Decided by:** Murat Kabak.

### D-006 · Docker-first (2026-10-08)
- **Decision:** All services run under Docker Compose from the start.
- **Options considered:** Starting on the host with SQLite and adding Docker later,
  which Claude proposed.
- **Decided by:** Murat Kabak.

### D-007 · Positioning: an evidence system for offensive security (2026-10-08)
- **Decision:** AttackLedger's claim is "prove what was tested". Recon and
  hunting produce evidence; the output is receipted coverage, control mapping and a
  verifiable report. Bug bounty is the first pack; pentest firms, internal teams and
  auditors are the paying audience.
- **Context:** Murat noted the product was drifting toward "another bug bounty
  tool" and asked for direction.
- **Proposed by:** Claude. **Decided by:** Murat Kabak, who approved the direction
  ("good idea, continue").

### D-008 · Research identification is required before target traffic (2026-10-08)
- **Decision:** A job that sends traffic to a target is refused unless the
  engagement carries the research header and/or user agent the program requires.
  The API and the worker each check this independently, and CR/LF is rejected.
- **Context:** The earlier private pipeline always sent this identification; the
  new engine had no field for it.
- **Decided by:** Murat Kabak, who required it to be added ("this part is important").

### D-009 · Visual identity: the ledger (2026-10-08)
- **Decision:** The light theme looks like columnar ledger paper, and the dark
  theme like a bottle-green cloth binding. Closed lanes carry a RECEIPTED rubber
  stamp and stale receipts a VOID stamp.
- **Proposed by:** Claude, using the `frontend-design` guidance. **Decided by:**
  Murat Kabak, who approved the design and asked for it to be made more
  professional and to have a dark mode.

### D-010 · Repository, versioning and ownership (2026-10-08)
- **Decision:** Private repository under the `attackledger` organization, with
  semantic versions starting at v0.1.0, a changelog and a pre-push release gate.
  Murat's personal profile names him as founder.
- **Decided by:** Murat Kabak. He asked for a private repository with versioning
  and wanted it to be clear that the application is his.
- **Changed 2026-10-09: the repository is public** (D-048).

### D-011 · AI assistance is disclosed (2026-10-08)
- **Decision:** Commits written with Claude keep their `Co-Authored-By` trailer.
  This file records which ideas came from the assistant.
- **Context:** Copyright protection for AI-generated material is unsettled in
  several jurisdictions. Human authorship lies in the methodology, the decisions,
  and the selection, review and arrangement of the code. Disclosure keeps that claim
  credible. Legal advice is to be sought before selling commercial licenses.
- **Decided by:** Murat Kabak.

### D-012 · Ship the product first; migrations before features (2026-10-08)
- **Decision:** Postpone the trademark filing and finish the product first. Release
  order: v0.2 database migrations, v0.3 hunt agents, v0.4 live site and public
  repository.
- **Proposed by:** Claude (the release order). **Decided by:** Murat Kabak, who
  put the product before the trademark ("ship the product first").

### D-013 · Recon mirrors the author's own pipeline (2026-10-08)
- **Decision:** The recon engine reproduces the stages of Murat's
  `run_pipeline.sh`: multi-source discovery with ownership filtering, ports and
  probing, golden-target scoring with the original weights, keyword list and
  boring-tech list, and crawl plus archive URLs with uro-style clean-up. It does
  not aim for parity with ars0n-framework.
- **Context:** Murat judged the first recon engine too thin and asked that it
  reflect his own pipeline.
- **Proposed by:** Claude, on two points: the split into batches (discovery,
  triage and endpoints first; JS analysis, content discovery, parameters and
  nuclei later, each as an explicit opt-in) and applying the crawl
  "never follow logout/delete" filter to every crawl, not only authenticated ones.
  **Decided by:** Murat Kabak.

### D-014 · One rate limit, no multipliers (2026-10-08)
- **Decision:** The engagement's requests-per-second value is a hard ceiling for
  every step that sends traffic, port scanning included. The ×10 port-scan
  multiplier inherited from the original pipeline is removed.
- **Context:** Some programs cap total traffic, for example 5 requests per second.
  A hidden multiplier would break that rule without the operator noticing.
- **Decided by:** Murat Kabak, who asked for the fix. Claude chose a single
  ceiling over a separate port-scan field, so the limit lives in one place.

### D-015 · Secrets are evidence, not inventory (2026-10-08)
- **Decision:** Secret candidates found in recon are stored as a masked preview, a
  SHA-256 and their location, never in full, and AttackLedger never tests them.
- **Proposed by:** Claude, extending the "do not use the key, only report it" rule in
  Murat's secret triage notes. **Decided by:** Murat Kabak.

### D-016 · An interrupted run is never "done" (2026-10-08)
- **Decision:** A run that hits the time limit is `partial` and lists exactly which
  targets were not run. Targets run in batches so the list is exact rather than
  estimated, and the operator can run the remainder.
- **Context:** With the rate limit enforced, port scanning a large program takes
  longer than the 30-minute limit. Marking such a run "done" would overstate coverage.
- **Decided by:** Murat Kabak, who asked for the fix. Claude proposed batching and
  the watchdog.

### D-017 · Architecture before more modules (2026-10-08)
- **Decision:** Before finishing recon, introduce a module registry (one definition
  per job kind, from which gates, worker dispatch and UI derive) and a hunt executor
  contract (shared lane context and write paths for people and agents), documented in
  `docs/ARCHITECTURE.md`.
- **Context:** Adding a module touched five places, and missing one of them was a
  real risk. Hunt agents would have multiplied that.
- **Decided by:** Murat Kabak ("let's set up an architecture first, then fill it in").
  Claude proposed the registry and the executor contract.

### D-018 · Only a person issues receipts (2026-10-08)
- **Decision:** Executors, agents included, may attach evidence and mark items, but
  only a person closes a lane. Closing requires the signer's name and an explicit
  "I reviewed this lane's evidence". The signer is stored on the receipt and shown in
  the report.
- **Why:** A receipt is the claim "this was tested". A human signature on it is what
  makes the coverage statement credible to an auditor.
- **Alternative considered:** agents close lanes, with a human review step before
  the report.
- **Limit:** until the API has user accounts, the signature is an attestation, not
  an authenticated identity.
- **Proposed by:** Claude. **Decided by:** Murat Kabak (option A, "only a person closes").

### D-019 · Per-run caps never drop work silently (2026-10-08)
- **Decision:** A module may declare `max_targets` in the registry (JavaScript
  analysis: 250, as in the original js_analyze.py). Targets beyond it are recorded
  as remaining and the run is `partial`, resumable with *Run remaining*. JS files are
  taken from the highest-scoring hosts first instead of alphabetically.
- **Decided by:** Murat Kabak, who asked for it after the architecture work.

### D-020 · What nuclei may never run (2026-10-08, made autonomously, reviewed 2026-10-09)
- **Decision:** On top of the tag exclusions, AttackLedger excludes nuclei templates
  by **content** at build time: raw/unsafe requests, hard-coded out-of-band hosts
  (oast.*, interact.sh) and interactsh URLs, and digest authentication. Templates for
  default logins, credential stuffing, token spraying and fuzzing are never selected.
  The original pipeline's DAST pass is not ported.
- **Evidence:** a scan against a raw socket logger showed that unsafe templates and the
  digest-auth template sent requests without the research header, and that static OOB
  hosts could make a vulnerable target call a third party. After the exclusions,
  8,899 of 8,899 requests carried the identification.
- **Also found:** the original pipeline's golden pass (Mac copy) used `-t http/cve/`,
  which matches 2 templates; the directory is `http/cves/` (4,345). Fixed there on
  2026-10-09 at Murat's request. The VPS copy's golden pass has no CVE templates at all.
- **Made by:** Claude, overnight under Murat's standing permission ("you may do
  everything"). **Review (2026-10-09):** Murat asked Claude to review the autonomous decisions; re-checked against the current code, tests and lab measurements, and kept.
- **Correction (2026-10-09):** tag and grep exclusions missed writes. The Juice Shop
  benchmark measured 24 POST, 1 DELETE and 1 DEBUG request from nuclei
  (`nacos-create-user` is tagged `instrusive`). Exclusion is now an allowlist by content
  (`nucleisafe.py`): a template runs only if every request it can send is provably GET,
  HEAD or OPTIONS with no body. The list is built with the image and re-checked before the
  first scan; 6,551 of 13,786 templates are excluded. `-rl 20` let 40 requests into one
  second; nuclei now takes one token per tick (`-rl 1 -rld`), with no retries. Re-run: 0
  non-GET requests out of 5,511, nuclei peak 19 at a limit of 20.

### D-021 · Content discovery without recursion (2026-10-08, made autonomously, reviewed 2026-10-09)
- **Decision:** feroxbuster runs at depth 1, one URL per process with a pause between
  them, instead of depth 2 with recursion.
- **Evidence:** feroxbuster's rate limit is per scan, and each recursed directory starts
  a new scan with a full budget. At the hand-over the total reached 29/s against a
  20/s limit. One scan per process stayed at the limit, with a peak of exactly 20/s
  over 9,504 requests.
- **Trade-off:** subdirectories are not explored automatically. A follow-up run can
  target discovered directories.
- **Also found in the original pipeline:** `--scan-limit 3` lets three per-directory
  budgets run at once. (An earlier version of this entry also said its baseline probes
  were sent without the research header. That was wrong: both copies send it.)
- **Correction, 2026-10-09:** the 20/s peak was measured at a limit of 20 only. At lower
  limits, feroxbuster went over: its wildcard detection and two start requests are not
  rate-limited (measured on the lab: 9 requests in the first second at a limit of 2).
  Content discovery now runs with `--dont-filter` (the baseline check already does that
  job) and a ferox rate of the limit minus 2, and needs a limit of at least 3/s.
  Measured: peak 3/s at a limit of 3, 18/s at a limit of 20. The original pipeline got
  the same fix, plus a second depth-1 pass over the directories the first pass finds;
  AttackLedger does not have that second pass yet (roadmap).
- **Made by:** Claude, overnight. **Review (2026-10-09):** Murat asked Claude to review the autonomous decisions; re-checked against the current code, tests and lab measurements, and kept.

### D-022 · Operator-token authentication now, user accounts later (2026-10-09, made autonomously, reviewed 2026-10-09)
- **Decision:** A single operator token (`ATTACKLEDGER_API_TOKEN`) guards the API as a
  bearer header or an HMAC session cookie (HttpOnly, SameSite=Strict). It stays off by
  default for local use, and `/health` says when it is off.
- **Why now:** it is the minimum before the API leaves localhost (VPS, demo). Real
  multi-user accounts remain on the roadmap, and with them authenticated receipt signers.
  The public demo is static, so no API is exposed by it.
- **Made by:** Claude, overnight. **Review (2026-10-09):** Murat asked Claude to review the autonomous decisions; re-checked against the current code, tests and lab measurements, and kept.

### D-023 · Scope import turns ineligible assets into exclusions (2026-10-09, made autonomously, reviewed 2026-10-09)
- **Decision:** In a HackerOne CSV, an asset with `eligible_for_submission=false` becomes
  an exclude rule. The original csv_to_scope.py skipped it, which leaves it covered by a
  wildcard.
- **Made by:** Claude, overnight. **Review (2026-10-09):** Murat asked Claude to review the autonomous decisions; re-checked against the current code, tests and lab measurements, and kept.

### D-024 · Agents send read-only requests only, for now (2026-10-09, made autonomously, reviewed 2026-10-09)
- **Decision:** In v0.6 the agent's HTTP tool allows GET, HEAD and OPTIONS. POST, PUT,
  PATCH and DELETE are refused before anything is sent.
- **Why:** a state-changing request on a live program can create, modify or delete
  real data. The recon side of AttackLedger never writes either. Writes need a
  separate, reviewed design: per-engagement opt-in, the operator's own test accounts
  and a per-request preview or allow-list.
- **Cost:** most authorization, logic and injection checks need writes, so in these
  lanes the agent will leave items open and say why. That is intended.
- **Made by:** Claude, overnight. **Review (2026-10-09):** Murat asked Claude to review the autonomous decisions; re-checked against the current code, tests and lab measurements, and kept.
- **Correction (2026-10-09):** "the recon side never writes" was not true for nuclei
  until 2026-10-09 (measured, see D-020). It is now enforced by template content, and the
  traffic gateway (D-039) will refuse writes for every tool.

### D-025 · Agent loop on the Messages API, not the Agent SDK (2026-10-09, made autonomously, reviewed 2026-10-09)
- **Decision:** The agent executor is a manual tool-use loop over the Messages API
  (`anthropic` Python SDK 1.12.1), instead of the Claude Agent SDK named in the roadmap.
- **Why:** the Agent SDK brings built-in file, shell and web tools. Here the agent must
  have exactly five gated tools and nothing else. A manual loop also lets the worker
  stop between turns (cancel, time limit) and commit evidence after every turn.
- **Settings:** `claude-opus-5-5` by default (`ATTACKLEDGER_AGENT_MODEL` also allows
  Sonnet 5.5 and Haiku 5.5), adaptive thinking at effort `high`, top-level prompt caching,
  and server-side refusal fallback (`fallbacks: "default"`; none on Haiku). Runs stop at
  turn, request and estimated-cost limits (defaults 15, 30, $0.50). Since 2026-10-12 the cost
  is bounded before each call (the next call's worst case must fit in what is left) and the
  worker caps every run (`ATTACKLEDGER_AGENT_MAX_USD` $1.00, `_MAX_TURNS` 30, `_MAX_TOKENS`
  2,000,000). The conversation is
  append-only. A refusal stops the run and fails the job.
- **Not yet tested against the live API:** no API key was available. The loop is
  tested with a scripted fake model (shape-compatible responses) and the real
  transport against the local lab. The first live run should be on the lab.
- **Security work and classifiers:** offensive-security prompts can trigger the cyber
  safety classifier. Murat is enrolled in Anthropic's Cyber Verification Program; the API
  key must belong to the enrolled organization. Other users can apply to the program.
- **Made by:** Claude, overnight. **Review (2026-10-09):** Murat asked Claude to review the autonomous decisions; re-checked against the current code, tests and lab measurements, and kept.

### D-026 · Recon shown as six phases, like ars0n (2026-10-09, requested by Murat)
- **Request:** Murat asked for the recon screen to be organised the way ars0n-framework-v2
  is: a target at the top, numbered workflow steps with tool cards, and a decision point.
- **Decision:** `modules.PHASES` groups the modules into six steps: find subdomains;
  resolve and find live web servers; collect URLs; JavaScript and parameters; known
  issues; manual checks. The registry order now follows the phases, which moves content
  discovery before JavaScript analysis (the JS files it finds are analysed too) and
  nuclei before the dork list. A test fails if a module has no phase or the orders differ.
- **UI:** a target bar with the rules (the form opens on demand, or by itself when
  something required is missing), a funnel of counts from host names to leads, the
  steps with "Run step" and "How this step works", tool cards with Run, Results and Log,
  and results in tabs, with golden targets as the decision point.
- **Not copied from ars0n:** company and ASN workflows, brute-force DNS and automatic
  rounds of re-probing; they are not in the original pipeline either.

### D-027 · Receipts are signed by a person and timestamped (2026-10-09, decided by Murat)
- **Decision:** each receipt is signed with a key that only the reviewer holds (created in
  their browser, never sent to the server) and timestamped by an RFC 3161 authority. The
  report carries the public keys and tokens, and verifies offline.
- **Why:** a hash in the tester's own database can be recomputed by anyone with access to
  it. A client or auditor needs proof that does not depend on trusting the tester, the
  server or its administrator.
- **Considered:** storing receipt hashes in a hosted ledger (trust moves to our service),
  keeping the local chain only (weakest).
- **Proposed by:** Claude. **Decided by:** Murat Kabak.

### D-028 · First users: pentest teams and auditors (2026-10-09, decided by Murat)
- **Decision:** the architecture is shaped around pentest teams who must prove coverage to a
  client, and the auditors who read that proof. Bug bounty stays supported.
- **Consequences:** roles (tester, reviewer, viewer) and separation of duties; a
  client-facing report; the WSTG pack and control mappings are first-class.
- **Considered:** bug bounty hunters first (more users, less revenue), both equally (no focus).
- **Proposed by:** Claude. **Decided by:** Murat Kabak.

### D-029 · Importing evidence from other tools is part of the core (2026-10-09, decided by Murat)
- **Decision:** an adapter interface turns tool output into inbox entries; a person maps
  them to checklist items before anything reaches the ledger. Evidence records their
  source. Caido is the first adapter.
- **Why:** pentest teams already work in Caido, Burp and scanners; proof has to come from
  where the work happens.
- **Proposed by:** Claude. **Decided by:** Murat Kabak.
- **Built 2026-10-09 as file import only, for the MVP** (docs/IMPORT.md, migration 0018).
  It covers HAR 1.2, Burp Suite XML and Caido JSON exports; Caido's API pull stays
  deferred (D-035).
  - **Adapters** are pure parsers with size limits, and XML goes through defusedxml.
  - **Mapped evidence** commits to an import record that names the hashes of the
    redacted request and response.
  - **Deleting an engagement's content** also wipes its inbox.
  - **Caido's layout** follows Caido's documented sample and should be checked against a
    real export.

### D-030 · Deployment model: open (2026-10-09)
- **Status:** not decided. Options: self-hosted only; self-hosted testing with a hosted
  service that stores, timestamps and verifies (no target traffic from our side); fully
  hosted. The architecture keeps workers separable so that every option stays possible.
- **Decided by:** Murat Kabak, later.
- **Update 2026-10-09:** decided in D-042 (self-hosted, with a public verifier page).

### D-031 · The demo's agent run is driven from Claude Code, through the same tools (2026-10-09, requested by Murat)
- **Decision:** until an API key is available, the demo's agent run is made by Claude Opus
  working in Claude Code. It acts only through `tools/agent_bridge.py`, which runs each call
  through `agenttools.Toolbox` inside the worker: the same five tools and the same gates
  (lane host, scope, read-only methods, research identification, no redirects, rate limit,
  request budget, no tool that closes a lane). The lab is reachable only inside the Docker
  network, so the model cannot reach it any other way.
- **Disclosure:** the run records who drove it, and the demo shows that it did not go
  through the Messages API and that token use was not measured. The evidence, the requests
  and the decisions are real; the API executor (D-025) runs the same tools.
- **Proposed by:** Murat ("make the keyless demo with an Opus agent"). **Built by:** Claude.

### D-032 · People, roles and separation of duties (2026-10-09, step 1 of the target architecture)
- **Decision:** people sign in with email and password; roles are given per engagement
  (viewer reads, tester works, reviewer signs) and owners do everything. One table in
  `authz.py` names the permission of every route; a route without an entry is closed to
  everyone but owners, and a test fails if any route lacks one.
- **Compatibility:** with no people and no token the API stays open for local use (as
  before); with only `ATTACKLEDGER_API_TOKEN` it works as before; once the first person
  exists, everyone signs in, and the token keeps working as an owner for automation.
- **Security choices:** scrypt password hashes (standard library); session cookies hold a
  random value and only its SHA-256 is stored; HttpOnly, SameSite=Strict, Secure when
  `ATTACKLEDGER_COOKIE_SECURE=1`; failed sign-ins locked per email and address after 5
  in 15 minutes; unknown emails cost the same time as wrong passwords; a non-member gets
  404, not 403, so engagements are not confirmed to exist; the last active owner cannot
  be disabled or demoted. Passwords for the CLI come from the terminal or an environment
  variable, never from an argument.
- **Separation of duties:** an engagement setting. When on, whoever attached a lane's
  evidence (recorded per entry, and for recon and agent runs, the person who started
  them) cannot sign its receipt, and the operator token cannot sign at all.
- **Receipts:** a signed-in reviewer signs under their account name, linked to their id.
  This is still not a cryptographic signature: that is step 2 (D-027).
- **Proposed and built by:** Claude, at Murat's request ("complete what is missing").

### D-033 · Signed receipts (2026-10-09, step 2a of the target architecture)
- **Decision:** a reviewer closes a lane by signing the receipt with a key held only in
  their browser. WebCrypto creates it as non-extractable and keeps it in IndexedDB:
  Ed25519 where the browser supports it, otherwise ECDSA P-256 with SHA-256. The server
  stores only the public key, registered to the person (`signing_keys`, migration `0011`).
- **What is signed:** canonical JSON (`attackledger-receipt-v2`) issued by the server
  for one lane and one key: engagement, lane, manifest hash, chain head, signer, key
  fingerprint and issue time. The server accepts it only in canonical form, only if it
  still matches the lane's current manifest and chain head, and only within 10 minutes
  of issue; then it checks the signature.
- **Report format 2:** each signed receipt carries the payload, the signature and the
  public key. `verify_report.py` checks them offline with its own Ed25519 (RFC 8032)
  and P-256 code (standard library only), and checks that the payload names the same
  manifest, lane and key as the receipt and a chain head the report contains. Format 1
  reports still verify.
- **Engagement switch:** *require signatures* refuses unsigned closes. Without it, a close
  with only a name is still allowed and labelled as not a cryptographic signature.
- **Lost or replaced keys:** a key can be revoked and a new one registered. Old
  signatures stay valid, because the report carries the key that made them.
- **What non-extractable does not give (note, 2026-10-11, TM-4):** the key cannot be copied
  out of the browser, but any code served on the app's origin can have the browser sign with
  it, and the browser does not show what is signed. A dishonest operator or a tampered web image
  could get a signature on a payload the reviewer did not see. The signature proves the key
  signed that payload, not that the reviewer read it (`VERIFIER.md`, "What a signature does not
  prove"; THREAT_MODEL.md T3.5).
- **Not yet:** timestamps (step 2b). Until then the signed issue time is the server's
  clock, not an independent one.
- **Verified:** tests for the RFC 8032 vector, cross-checks against `cryptography`,
  refusals and tampering (manifest, payload, key, age); a browser close on the local lab
  signed with Ed25519, the verifier passed it and failed it after one name was changed.
- **Proposed and built by:** Claude, at Murat's request (D-027).

### D-034 · RFC 3161 timestamps on receipts (2026-10-09, step 2b of the target architecture)
- **Decision:** when a lane closes, the server asks a timestamp authority (TSA) to
  timestamp `attackledger-timestamp-v1`, the receipt's manifest hash and its signature
  (one line each). Only the SHA-256 of that text leaves the deployment. The token goes on
  the receipt and into the report (format 2, optional field). Migration `0012`.
- **Which TSA:** set by the operator (`ATTACKLEDGER_TSA_URL`). Docker Compose defaults to
  DigiCert's public service (`http://timestamp.digicert.com`, approved by Murat), and the
  verifier pins its root, DigiCert Trusted Root G4 (taken from the macOS root store and
  matched against DigiCert's download). `off` sends nothing and skips timestamps. A real
  DigiCert token is kept as a test fixture and verifies offline.
- **Server checks:** the reply must answer this request (same hash, same nonce, status
  granted). The server does not decide whether to trust the TSA; the reader does.
- **Unreachable TSA:** the close still succeeds; the receipt records why it has no
  timestamp, and `POST /lanes/{id}/receipt/timestamp` (reviewer) tries again. A later
  timestamp shows the later time; it never claims the close time.
- **Verifier:** parses the CMS token itself (standard library only) and checks that it
  covers this receipt, that the TSA's signature verifies (RSA PKCS #1 v1.5, ECDSA P-256 or
  P-384, SHA-2), that the signing certificate is for timestamping, and that the chain
  reaches a root the reader trusts and was valid at the token's time. Trusted roots are
  PEM files in `tools/tsa-roots/` or given with `--tsa-root`. A root carried inside the
  token is not trusted by being there. An untrusted chain fails the check.
- **Verified:** tests against OpenSSL's own TSA (`openssl ts -reply`) for RSA and EC
  chains with an intermediate; OpenSSL's `ts -verify` agrees with the verifier; bad
  chains (issuer not a CA, certificate not yet valid, no timestamping purpose, a token
  carrying its own root) and tampering are refused; each of 15 checks was broken on purpose
  and a test failed each time. A browser close against a local TSA was timestamped and
  verified.
- **Proposed and built by:** Claude, at Murat's request (D-027).

### D-035 · Tool integrations wait until after the first release (2026-10-09, decided by Murat)
- **Decision:** evidence import (D-029) and other integrations with outside tools (Caido,
  Burp, nuclei) move to the later section of the roadmap. When they come, each is an
  optional integration that an operator turns on at setup with their own credentials;
  no one's token is ever part of the code, the demo or a report.
- **Why:** they are complex, the first release does not need them, and an integration
  must never carry the author's own credentials.
- **Proposed by:** Murat Kabak. **Decided by:** Murat Kabak.
- **Caido API pull, built 2026-10-09** (`tools/caido_pull.py`, docs/IMPORT.md). It runs on
  the tester's machine, not on the server, and the server holds no tool token.
  - **The token** is read from the environment or a file only, and is sent only to the
    Caido address given.
  - **The tool** uses no proxy and follows no redirect.
  - **Schema:** pinned to Caido's public schema v0.58.3; it fails closed on any other
    shape.
  - **Not supported:** personal access tokens, because exchanging them would need Caido's
    cloud flow.
  - **Testing:** checked against Caido's public schema only, not a live instance.
  - **Made by:** Claude, under Murat's overnight permission.

### D-036 · Key trust: no password setting for others, and a key log (2026-10-09)
- **Problem:** an owner could set another person's password through the API, sign in as
  them, register a key and sign receipts in their name; the report would look valid.
- **Decision:** no one sets another person's password through the API. Owners set the
  first password only; people change their own (`POST /auth/password`, current password
  required, other sessions end); an operator resets on the server
  (`python -m app.people set-password`). Every key registration and revocation is appended
  to a hash-chained key log (migration `0014`; existing keys backfilled), recording how it
  happened (own session, a session on a password someone else set, operator CLI). People
  see key changes since their last sign-in and can revoke them. Reports carry each signing
  key's history, and the verifier checks it.
- **Boundary:** anyone with shell or database access is still the root of trust. They
  cannot forge a signature with someone's key; a key they register leaves an entry, shows
  in the person's notice and in every report it signs. For high assurance, compare key
  fingerprints out of band. Not yet covered: an owner renaming an account to look like
  someone else, and checking the key log in the browser's Verify tab.
- **Proposed and built by:** Claude, at Murat's request (from a product critique).

### D-037 · Audit log of administrative changes; receipts name the signer's email (2026-10-09)
- **Problem:** an owner could rename an account to look like a reviewer and sign with their
  own key; scope, roles and settings changes left no tamper-evident record, so an auditor
  could not see the scope in force or who held the reviewer role when a receipt was issued.
- **Decision:** a hash-chained, append-only audit log (migration `0016`, backfilled) records
  scope and rules, authorization, settings (including evidence redaction), roles and people
  events, never passwords, in the same transaction as each change. Reports carry the
  engagement's entries and its people's; the verifier fails a receipt whose signer lacked
  the reviewer role (and was not an owner) or had another name or email, and notes the
  scope in force. Receipt payload `attackledger-receipt-v3` adds the signer's email; v2
  receipts verify as before. A History tab shows the log in plain language.
- **Boundary:** whoever has database access is still the root of trust; rewriting the log
  breaks the head that reports already carry. Not yet: the role check uses the close time,
  and a report could omit an entry unnoticed. (Since the 2026-10-10 security review the close
  time must lie within the window the server allows after the signed payload's issue time, so it
  can no longer be moved freely; see docs/security-review/EVIDENCE.md. Since D-054 a receipt
  signed as payload v4 commits to the entries up to its signing, so leaving one of those out
  fails, and `--require-history` fails a report without the logs.)
- **Proposed and built by:** Claude, at Murat's request (from the product critique).

### D-038 · Raw evidence is redacted before it is stored (2026-10-09)
- **Problem:** captured traffic holds live credentials and personal data, and the ledger can
  never delete what it stored.
- **Decision:** cookies, Authorization headers, tokens, keys, JWTs, private keys, email
  addresses and Luhn-valid card numbers are replaced by `[redacted:sha256:<12 hex>]` before
  anything enters the blob store or the recon tables; the agent sees the redacted exchange
  too. Each evidence entry records how many values of which kinds were redacted. On by
  default; an owner may turn it off for a lab, which the audit log records (migration
  `0015`).
- **Boundary:** pattern- and name-based, not general personal-data detection; binary and
  compressed bodies are stored as is and noted; evidence stored before this change is untouched.
- **Proposed and built by:** Claude, at Murat's request.

### D-039 · All target traffic goes through a gateway (2026-10-09, decided by Murat)
- **Problem:** each tool enforced the rules with its own flags; a Juice Shop benchmark found
  nuclei sending POST and DELETE requests and bursting above the rate limit.
- **Decision:** the worker has no direct route to the internet. Every request from recon
  tools and agents goes through a separate gateway container that enforces, in one place,
  the engagement's rate ceiling (across all tools and workers), the allowed methods, the
  scope (host allowlist, exclusions win), the identification header and user agent, and the
  redirect policy, and logs every request. A misconfigured tool cannot exceed the rules.
- **Open design points:** HTTPS needs the gateway to terminate TLS for method and header
  checks (a gateway CA trusted only inside the worker); DNS resolution and port scanning go
  through the gateway's resolver and a rate-limited tunnel, or are refused.
- **Proposed by:** Claude. **Decided by:** Murat Kabak.
- **Built 2026-10-09** (docs/GATEWAY.md, migration 0019).
  - **Proxy:** its own asyncio/h11 proxy rather than mitmproxy. There is nothing to
    switch off, certificate checks are per destination, and it adds no dependencies.
  - **Credentials and rules:** each job gets its own credentials, which the API checks.
    The API holds the rules; the gateway has no database access (D-042).
  - **Rate ceiling:** a token bucket whose tokens return 1.05 s after use.
  - **DNS:** answered only for in-scope names of running jobs.
  - **Outside services:** an allowlist of passive sources, GET only and not counted
    against the rate; the Claude API for agent runs only.
  - **Ports:** the gateway makes the port probes instead of naabu.
  - **Failure:** fails closed. Hooks are in place for D-040 and D-041.
  - **Benchmark through it:** 0 non-GET of 5,507 requests, peak 20 at a limit of 20 for
    every tool.
  - **Not yet:** the worker still reads the database directly.
  - **Built by:** Claude.

### D-040 · Agents use test accounts through the gateway, never the credentials (2026-10-09, decided by Murat)
- **Decision:** an operator adds test accounts (A, B, ...) to an engagement; they are stored
  encrypted (D-043). An agent asks for a request "as A"; the gateway adds A's session
  cookie or token. The agent's context, the logs and the evidence never contain the raw
  credential (redaction, D-038, stays on). Creating accounts and signing in are always done
  by a person; the evidence records which test account each request used.
- **Why:** most of the value in the benchmark (and authorization testing such as BOLA)
  needs signed-in sessions; keeping credentials at the gateway keeps them out of the model
  and the ledger.
- **Proposed by:** Claude. **Decided by:** Murat Kabak.
- **Built 2026-10-10** (docs/APPROVALS.md, GATEWAY.md decision 9, migration 0021). The
  account is chosen per request, with a header the gateway removes, not per job, so one
  run can compare accounts. The session leaves the API only to the gateway, and only:
  - for a running agent job;
  - for the hosts named for that account;
  - while redaction is on.

  The gateway scrubs responses before they reach the worker. Recon stays
  unauthenticated. Built by Claude.

### D-041 · Writes only with a person's approval (2026-10-09, decided by Murat; amends D-024)
- **Decision:** agents may propose POST, PUT, PATCH or DELETE requests. Each one waits in an
  approval queue; a person sees the full request and approves or rejects it; the gateway
  sends it only after approval. DELETE needs its own explicit confirmation. An engagement
  rule (off by default) decides whether writes may be proposed at all. Every approval,
  rejection and sent write is recorded in the audit log and as evidence. Recon tools stay
  read-only by construction (nuclei templates are classified and non-GET ones excluded).
- **Proposed by:** Claude. **Decided by:** Murat Kabak.
- **Built 2026-10-10:**
  - **Who approves:** testers and owners. Viewers and reviewers can't, so reviewing stays
    separate from changing the target. Separation of duties applies: whoever started the
    run can't approve its writes.
  - **What an approval covers:** it binds the request's SHA-256, expires after 15 minutes,
    and the gateway uses it once, sending the approved headers.
  - **DELETE:** the approver types the URL's path in a second call.
  - **Left out:** a UI route for a person's own writes. Testers use their own tools and
    import the exchanges.
  - Built by Claude.

### D-042 · Deployment: self-hosted, with a public verifier page (2026-10-09, decided by Murat; closes D-030)
- **Decision:** AttackLedger runs only on the customer's own servers; test data never
  leaves them. The one hosted part is a verification page on attackledger.com: an auditor
  drops a report file in, the checks run in the browser, and nothing is uploaded. We hold
  no customer data.
- **Why:** banks and audit firms are the target readers (D-028 and the business
  answers of 2026-10-09); a hosted service would put their test data with us and needs
  operations a 5-10 hour week cannot carry.
- **Proposed by:** Claude. **Decided by:** Murat Kabak.
- **Keeping a hosted service possible (asked by Murat):** a later SaaS, most likely a hybrid
  in which the web app and ledger are hosted while the worker and gateway stay in the
  customer's network, stays possible if two rules hold from now on: every record belongs to
  an organization (add the organization id to the data model before more tables depend on
  a single tenant), and the worker talks to the API over an authenticated channel instead
  of reading the database directly (design it with the gateway, D-039). Per-engagement
  encryption keys (D-043) already fit per-customer isolation. Backups, monitoring, data
  processing agreements, a security certification and billing are operational work that
  starts only when a hosted service is chosen.
- **The worker channel was built 2026-10-09** (docs/WORKER_API.md, migration 0020). The
  worker has no database credentials, database network, master key, blob store or
  Anthropic key.
  - **Channel:** the worker reaches `/worker/*` on the API only through the gateway's
    relay, not over a network shared with the API. A shared network would make the
    worker an owner in open mode, and production's forwarded-header trust rules out a
    check on the source address. The relay also fits the hybrid SaaS case.
  - **Credentials:** a worker token kept in a volume shared only with the API, which can
    only claim jobs. Each claimed job gets its own token, separate from the gateway secret
    its tools use.
  - **Gates:** the API runs them at claim time. What each job kind may write is a table
    (`WRITES`).
  - **Encryption:** the API encrypts and stores blobs.
  - **Anthropic key:** it moved to the gateway, which adds it to agent calls (the pattern
    D-040 plans for test accounts).
  - **Background work:** retention and the stale-job sweep run in the API.
  - **Benchmark:** unchanged through the channel: 13,344 GET, peak 20 at 20, the same
    endpoints, leads and recall.
  - **Made by:** Claude, autonomously, under Murat's overnight permission.
- **Organization id on every record, built 2026-10-10** (docs/ORGANIZATIONS.md,
  migration 0022).
  - **Scoping:** one session-level filter (`orgscope.py`) scopes every query. New rows
    take their parents' organization, and rows that would span organizations are refused.
    17 tables carry the column and 5 are owned through a parent. Another organization's
    ids answer 404, exactly like ids never used.
  - **Logs:** the key log and the audit log are one chain per organization, with
    unchanged records. The default organization keeps the deployment's chain, so earlier
    reports verify.
  - **Tokens:** worker and gateway tokens are per organization; job tokens are unchanged.
  - **Encryption:** engagement keys are unchanged. A per-organization key-encryption key
    is designed, not built.
  - **Not built:** a UI for organizations and a role above owner. Organizations are made
    on the server (`python -m app.orgs`).
  - **Verified:**
    - a walk of every route in `authz.RULES` as another organization: every answer is a
      404 identical to a never-used id, nothing changes, and a positive control shows the
      ids are real;
    - migration tests with API-filled data on SQLite and Postgres.
  - **Made by:** Claude.

### D-043 · Evidence and test accounts encrypted, with retention by key deletion (2026-10-09, decided by Murat)
- **Decision:** raw evidence and test-account credentials are encrypted with a key per
  engagement (wrapped by a deployment master key). Each engagement has a retention period
  after it closes (default one year, configurable). When it ends, the engagement key is
  destroyed: the content becomes unreadable, while hashes, receipts and reports stay valid.
  The deletion is recorded in the audit log, and the verifier reports "content removed
  under the retention policy" instead of failing.
- **Why:** the chain commits to hashes, not content, so content can go without breaking
  it; clients and KVKK/GDPR expect a retention limit.
- **Proposed by:** Claude. **Decided by:** Murat Kabak.
- **Built 2026-10-09** (docs/ENCRYPTION.md, migration 0017). Details settled while
  building, proposed and built by Claude:
  - **Wrapped key location.** It is kept in the engagement's blob folder, not the
    database, so the database and the blob volume must be backed up together.
  - **Older rows.** Rows from before chain record v2 keep their plaintext summary,
    because the v1 chain covers the text.
  - **Recon results and job logs** are deleted rather than encrypted.
  - **Evidence URIs and N/A reasons** stay, because the chain and receipts commit to them.
  - **Retention** is an explicit date until engagements have a close event, so the
    one-year default is not built yet.
  - **Old backups** become unreadable only after the master key is rotated.

### D-044 · How AttackLedger is offered (2026-10-09, decided by Murat)
- **Decision:** the whole product is open source (AGPL-3.0); organisations that cannot use
  AGPL buy a commercial licence. Revenue, when it comes, from four lines: commercial
  licences, installation and support, reviewed control packs by subscription, and training
  and advice. First 2-3 design partners use it free in return for feedback and a case
  study; prices are set after them. The move from portfolio project to side business is
  triggered by a design partner using it on real work and saying they would pay.
- **Details:** docs/BUSINESS.md.
- **Proposed by:** Claude, from Murat's answers. **Decided by:** Murat Kabak.

### D-045 · Production installs never run open (2026-10-09, made autonomously)
- **Decision:** with `ATTACKLEDGER_REQUIRE_SIGN_IN=1`, which `deploy/compose.prod.yml`
  sets, an install with no people and no token refuses everything until the first owner
  is created on the server (`python -m app.people create --owner`). Unknown values count
  as on.
- **Why:** before this, an install with no people was open, so whoever reached it first
  over the network could make themselves owner. Creating the owner on the server also
  removes the need for a shared operator token to bootstrap.
- **Made by:** Claude, for MVP item 6, under Murat's overnight permission. **Approved** by Murat Kabak on 2026-10-09 as part of a general approval of the overnight work ("bunları da hallet, iznim var"), not item by item.

### D-046 · The browser verifier is a port of verify_report.py (2026-10-09, made autonomously)
- **Decision:** the browser verifier is a line-for-line port of `verify_report.py`, not a
  reimplementation.
  - It reads JSON as Python does and uses WebCrypto for the cryptography.
  - Where the browser lacks Ed25519, it falls back to the script's own Ed25519 code.
    Small-order points always use that code.
  - The public page is one self-contained file under `default-src 'none';
    connect-src 'none'` and Trusted Types, set in a meta tag and in the header.
  - Any change to `verify_report.py` needs the same change in `web/src/verify_report.ts`
    and a case in `tools/verifier_equivalence/cases.json`, and `run.sh` must report 0
    differences.
- **Why:** an auditor must get the same answer from the page as from the script; two
  independent implementations would drift.
- **Made by:** Claude, for MVP item 5, under Murat's overnight permission. **Approved** by Murat Kabak on 2026-10-09 as part of a general approval of the overnight work ("bunları da hallet, iznim var"), not item by item.

### D-047 · Lane dependencies gate the receipt, not the opening (2026-10-09, made autonomously)
- **Decision:**
  - A lane that depends on another lane (every WSTG lane on *Information gathering*) can
    be opened, worked and mapped to at once.
  - The dependency must be receipted before the dependent lane is signed.
  - A pack may keep opening gated with `needs_gate: open`. The bug bounty pack does,
    because its later lanes start from the application model.
- **Why:** pentest teams test categories in parallel; the design-partner review could not
  map an `/admin/` request to Authentication because that lane was locked.
- **Also:** the verifier downloads from the API are for signed-in people. The independent
  copy for clients is on attackledger.com.
- **Made by:** Claude, from the MVP review, under Murat's overnight permission. **Approved** by Murat Kabak on 2026-10-09 as part of a general approval of the overnight work ("bunları da hallet, iznim var"), not item by item.

### D-048 · The repository is public (2026-10-09, decided by Murat)
- **Decision:** github.com/attackledger/attackledger is public under the AGPL-3.0. It went
  public after a scan of the full history (152 commits) found nothing to remove:
  - **Both denylists:** no target names. The one hit is four random letters inside a
    base64 signature in an old demo build, the same false positive as before.
  - **Personal paths:** none; only a fake test URL and a container path.
  - **trufflehog over the history:** only a fake test URL in `test_redact.py`.
  - **Other identifiers:** no VPS address. Notification tokens and HackerOne credentials
    appear as setting names only.
- **Also turned on:** secret scanning with push protection, private vulnerability
  reporting, CodeQL default setup, Dependabot alerts and security updates.
- **Why:** D-044 (everything open source) and the portfolio goal; the public verifier
  page and the reports point readers to the source.
- **Decided by:** Murat Kabak (2026-10-09, "bunları da hallet, iznim var"). Scanned and
  published by Claude.

### D-049 · Recon reads what a host publishes about itself (2026-10-09, made autonomously)
- **Decision:**
  - Recon reads robots.txt and security.txt by default. Fetching the directories robots.txt
    names counts as crawling, not brute force, so it is not opt-in. It is capped at 13 GETs
    per service.
  - Content discovery stays opt-in. It still skips hosts that answer every path with the
    same error or redirect.
  - What an agent is shown of a response is a derived reading view. Evidence always stores
    the full redacted exchange, and the view never shows more than that.
  - Triage scores only observed signals. An API surface counts as application evidence,
    like the existing technology signal.
- **Evidence:** the Juice Shop benchmark through the gateway, before and after:
  - in-reach recall went from 5 to 15 of 32;
  - requests went from 5,511 to 13,352;
  - every request was GET, HEAD or OPTIONS, with a peak of 20 at a limit of 20.
- **Made by:** Claude, from the benchmark gaps, under Murat's overnight permission.

### D-050 · Every control mapping states its strength (2026-10-09, made autonomously)
- **Decision:**
  - Every control mapping states its strength (full, partial or supporting), with one
    strength per control per pack. A bare id means supporting.
  - A mapping that overstates is removed, not kept with a caveat.
  - The catalog records who reviewed it, when and against which sources. The Controls view
    and the report show that statement.
  - Until a QSA, ISO lead auditor or DORA TLPT authority reviews them, the packs say so.
- **Why:** the readers are bank IT auditors and Big4 IT audit teams. The first review found
  mappings that would not be accepted as evidence: an ASV scan, a superseded WAF
  requirement, and TLPT.
- **Considered:**
  - Strength per control in the catalog. Rejected: the same control differs between a
    pentest and a bug bounty.
  - Strength per item, with mixed strengths in a row. Rejected: a row must state a single
    claim.
- **Made by:** Claude, under Murat's permission ("bunları da hallet").

### D-051 · Contributions need a CLA (2026-10-09, decided by Murat)
- **Decision:** every commit author of a pull request signs `CLA.md` once before it can
  be merged.
  - The CLA is a licence grant, not a copyright transfer. Contributors keep their
    copyright and grant a broad copyright and patent licence that allows the work to be
    licensed under the AGPL and commercially.
  - Signing happens through CLA Assistant Lite, a GitHub Action pinned by commit. It
    stores signatures in this repository on the unprotected branch `cla-signatures`, so no
    third-party service or extra token is involved.
- **Why:** dual licensing (D-044) needs the right to license every line both ways. The
  repository became public on 2026-10-09 (D-048).
- **Note:** the text was drafted by Claude from the common structure of individual CLAs.
  It has not been reviewed by a lawyer. Have it reviewed before the first commercial
  licence is sold.
- **Proposed by:** a side note in the session. **Decided by:** Murat Kabak ("bunu yapalım").

### D-052 · A voided receipt stays void (2026-10-10, made autonomously)
- **Decision:**
  - Any change to a receipted lane voids its receipt. The audit log records it as
    `lane.receipt_voided`, naming the receipt and the cause.
  - Restoring the earlier state does not bring the old receipt back. Only a new signature
    closes the lane.
- **Why:** audit evidence must show the gap. If the receipt became valid again whenever
  the manifest matched, nothing would show that the lane had changed in between.
- **Considered:** keeping the receipt valid when the manifest matches again (rejected for
  that reason).
- **Made by:** Claude, from the second design-partner review, under Murat's overnight
  permission.

### D-053 · The web app keeps its place in a hash route (2026-10-10, made autonomously)
- **Decision:**
  - The app keeps its place in a hash route (`#/e/<id>/<tab>/lane/<n>`), not History API
    paths. It works unchanged behind nginx's SPA fallback and under `/demo/` on a static
    host, and nothing after `#` reaches the server.
  - Unsent text is kept in memory and in `sessionStorage` for the tab. Text that looks
    like a credential is never kept there.
  - Drafts are cleared on sign-out, or when another person signs in.
- **Made by:** Claude, from the second design-partner review, under Murat's overnight
  permission.

### D-054 · Receipts bind evidence to items and sign the history they were issued against (2026-10-10, made autonomously)
- **Problem** (security review open items O-1 and O-2, docs/security-review/EVIDENCE.md):
  - A receipt's manifest named items by position, key, state and reason, and evidence by the
    database id of its item. The item's own id was in no manifest, so in a signed report the
    item ids of two items marked done could be swapped and every check still passed.
  - A report could leave out audit or key log entries, or both logs, and get only a NOTE
    (D-037). Dropping the `lane.receipt_voided` entry then hid a void (EV-1).
- **Decision:**
  - **Manifest version 2.** Each item also names its database `id` and its `text`, and the
    manifest carries `"v": 2`. New receipts use it. A receipt made with version 1 keeps its
    hash. The server and both verifiers accept either. The version is inside what is hashed,
    so one cannot pass for the other. The verifier adds a NOTE for version 1: it does not cover
    which item a piece of evidence supports.
  - **Why the id and the text.** Evidence already names its item by `item_id`, in the
    evidence chain and in the manifest. Naming the same id on the item ties the two
    together, and both are in every report. The position (`idx`) alone cannot do that.
    The text is fixed when the lane opens, so it never voids a receipt, and binding it covers
    the wording the report shows for each item. A hash of the text was not used: it proves no
    more than the text itself.
  - **Receipt payload v4.** It adds `history`, which records the audit log head (`seq`,
    `head`) when the payload was issued. It also counts the entries up to that head that are
    this engagement's or person events of the signer (`entries`), with the SHA-256 of their
    sequence numbers as canonical JSON (`sha256`). The key log head (`seq`, `head`) is
    recorded too. The server issues v4 only and checks every field at close. Both verifiers fail a
    report whose logs do not reach those heads, have another entry there, or lack a counted
    entry, in normal mode too: that would contradict what was signed. v2 and v3 receipts verify as
    before.
  - **Why those entries.** They are exactly the ones the verifier reads to judge a receipt:
    scope, roles and voids of the engagement, and the signer's name, email, owner flag and
    account state. The verifier can rebuild the set from the report alone. Committing to the
    head alone would not be enough. A left-out entry still looks like a link of another
    engagement, because links carry hashes only.
  - **`--require-history`**, and a checkbox on the /verify page (off by default). The report
    must carry both logs. Every receipt must be signed as v4, and must have been issued while the
    audit log covered the engagement. Otherwise the check fails.
- **What strict mode cannot prove:** the history after the newest signed head. A void is
  recorded after the receipt it voids, so only a later v4 signature (on any lane of the
  engagement) commits to it. A void made after the last signature can still be left out. The
  verifier then says, in strict mode, up to which entry the history is bound. Closing that gap
  would need a party that signs at report time, such as a server key or a timestamp of
  the report. Neither exists today (D-036 keeps trust in the reviewers' keys). (Closed by D-055:
  the server seals each report it exports, and strict mode requires the seal.) The role
  check still uses the close time, which can be up to 15 minutes after the signed head.
- **Considered:** a tag per audit link naming its engagement, salted so that other
  engagements stay unreadable. It would show every left-out entry, the later ones too, but
  it changes the audit chain's construction, needs a migration and a salt per engagement,
  and still says nothing about entries after the report was made. Rejected for now.
- **Made by:** Claude, from the security review's open items, at Murat's request to close them.

### D-055 · The server seals every report it exports (2026-10-10, made autonomously)
- **Problem** (security review O-2, the part D-054 left open, docs/security-review/EVIDENCE.md):
  a void, or any audit or key log entry, recorded after the newest receipt signature could be
  left out of a report, with the lane shown as receipted, and `--require-history` still passed.
  Nothing was signed at report time.
- **Decision:**
  - **An instance seal key.** Each deployment has one Ed25519 key, made on first use and kept
    in the blob store wrapped by the master key, like a data key (`vault.seal_key`; startup
    check and `rotate-master` cover it). Its public key is registered once in each
    organization's key log as an entry that names no person (`via: instance`, migration `0024`
    makes `key_log.user_id` optional), before the first receipt payload the server issues there,
    so later receipt signatures cover the registration.
  - **The seal.** When a report is exported (JSON, HTML, the app's Verify tab), the server signs
    `attackledger-seal-v1`: the engagement, the report body hash, the heads (seq and entry hash)
    of the audit log and the key log the report carries, the key and the time. It goes in
    `integrity.seal`, outside the body hash. The report's key history includes the seal key.
  - **A timestamp of the seal** from the configured authority, when timestamps are on, over
    `attackledger-seal-timestamp-v1`, the body hash and the seal's signature. The seal's time then
    cannot be backdated. If the authority does not answer, the report is still sealed, without a
    timestamp.
  - **Verifiers.** Both check the seal the same way (*Report seal*): signature, key and
    fingerprint, body hash, engagement, the logs ending at the sealed heads, the key's
    registration as the instance's, the time and the timestamp. `--require-history`, the /verify
    checkbox and the Verify tab's option also require a valid seal. Reports without a seal keep
    verifying in normal mode, with a NOTE. A NOTE says whether a receipt signature covers the
    seal key's registration.
- **What it proves and what it does not:** the seal is the server's statement that the report and
  its history were complete up to those heads at that time. It does not make the server
  trustworthy: whoever holds the seal key can seal a different report, and a seal key no receipt
  signature covers is tied to the server only by its fingerprint, which the reader compares out
  of band (docs/VERIFIER.md). Trust in the review stays with the reviewers' keys (D-036).
- **Considered:**
  - A timestamp of the report alone, with no server key. It proves when, not who: anyone can
    timestamp an edited report. Rejected as the only mechanism, kept as part of the seal.
  - Asking a reviewer to sign every export. It would bind the history to a person, but exports
    happen without a reviewer present (a client download, the Verify tab), and a reviewer's
    browser key cannot sign server-side. Rejected.
  - Binding the seal key's fingerprint into the receipt payload (a payload v5). Registering the
    key in the key log before the first payload gives the same binding for new receipts without a
    new payload format. Rejected for now.
  - Keeping the key in the database. The blob store already holds the wrapped data keys and is
    covered by the same checks and rotation; a database row would need its own. Rejected.
- **Made by:** Claude, from the security review's remaining O-2 gap, at Murat's request to close it.

### D-056 · A browser signed in with the token gets a real session (2026-10-10, made autonomously)
- **Problem** (security review AUTH-6, docs/security-review/AUTH.md): in token mode the cookie
  was `HMAC(token, constant)`. Signing out deleted it in the browser only; a copy of it, from a
  shared machine, a proxy log or a backup of a browser profile, opened the API as an owner until
  the token changed. Nothing on the server could end it.
- **Decision:**
  - Signing in with the operator token gives the browser a session like a person's: a random
    cookie value, of which only the SHA-256 is stored in `user_sessions`, ending on sign-out or
    after 12 hours (`SESSION_HOURS`). The row names nobody (`user_id` empty, migration 0023).
  - Each token session is bound to the token it was opened with (`token_binding`, a scrypt hash
    of the token, so a database leak makes guessing a weak token no easier than a password). It
    opens nothing while the API runs with another token, and the API deletes the sessions of any
    other token when it starts, and at each token sign-in. Changing the token therefore ends them
    for good; changing it back does not bring them back.
  - The bearer token is unchanged: scripts, the worker and the gateway send it in the header and
    hold no session. A token session still works in people mode, as the token does.
  - The old derived cookie is no longer accepted, so a browser signed in with the token signs in
    once more after the upgrade.
- **Considered:** keeping the derived cookie and adding a revocation list (it still could not
  end a copy without state, so it is the same table with a worse key); a session table of its own
  for the token (two lookups, two expiry rules to keep the same; rejected for one table with one
  rule).
- **Number:** D-055 was left free for a decision being written in parallel on another branch.
- **Made by:** Claude, from the security review (third pass, branch `sec3-sessions`).

### D-057 · An agent is told where the host answers and how a test is usually done (2026-10-14, made autonomously)
- **Problem** (the first live runs on the lab, docs/BENCHMARK.md, 2026-10-14): every run spent
  1 to 5 requests of its budget on `https://` URLs of a host that answers on HTTP only, and kept
  trying after the first failure; the configuration lane closed "old backup and unreferenced
  files" without requesting version-control metadata; no run looked for hidden parameters. The
  agent was told neither which origins recon had seen answering nor how a checklist item is
  usually tested, while every item carried its ISO, PCI and DORA control ids, paid for on every
  turn and of no use for testing.
- **Decision:**
  - The lane context has `recon.origins`: each scheme://host:port the probe module saw answering,
    with its status (from the probe's observations; empty when no probe ran). The system prompt
    says to use them, and when there are none to find out with one request each whether http or
    https answers before spending more.
  - The agent's tools remember an origin that fails to connect (the gateway's "could not connect
    to") before it has answered in the run, and refuse further requests to it without counting
    them. An origin that answered once is never blocked, so a passing failure costs one request.
  - A pack item may carry a `hint` (plain text, at most 400 characters): how the test is usually
    done. The lane context gives it to the agent on that item only, so it costs tokens only on
    lanes that have it. The WSTG pack has hints on six items (INFO-03, INFO-05, INFO-06, CONF-03,
    CONF-04, CONF-05). Hints are general methodology: a test checks that none names a path the
    bundled lab serves or a parameter it reads.
  - The model's copy of the lane context leaves out the items' control mappings
    (`agentloop.agent_view`); the context the API returns is unchanged.
- **Cost:** the system prompt grows by 269 bytes (about 65 tokens) on every lane. The first
  message shrinks on every WSTG lane, hints included, because the control ids go: by 207 bytes
  (errh) to 2,341 bytes (inpv), and by 535 and 564 bytes on info and conf, which carry hints.
- **Considered:** per-lane methodology text in the system prompt (paid on every lane, and the
  prompt would grow with each pack); naming exact version-control files or candidate parameter
  names in the hints (the lab plants some of them, so the benchmark would measure the hint, not
  the agent; the model knows the standard files of a .git directory); retrying
  a failed origin once more for timeouts (rejected: a timeout costs the connect timeout each time,
  and an origin that has answered is never blocked anyway).
- **Made by:** Claude, at Murat's request after the live runs (branch `agent-brief`).

### D-058 · The audit log commits to a salted hash of its free text, so deletion reaches it (2026-10-14, decided by Murat)
- **Problem** (docs/security-review/RETENTION.md, the open item of the security review): the
  audit log is hash-chained (D-037), so deleting an engagement's content (D-043) could not remove
  the free text its entries held: notes on approved and rejected writes, the path typed to confirm
  a DELETE, test accounts' roles, hosts and header names, dismissal reasons, the tool named in an
  imported file. Everything else that held them was deleted or blanked.
- **Decision** (Murat chose a new record version; Claude chose the construction):
  - **Audit record v2.** An entry whose change carries one of those fields
    (`auditlog.TEXT_FIELDS`, by action and place, such as `after.note`) is written as v2: the
    field leaves the change, and the record, which the chain hashes, gets `"v": 2` and
    `text_sha256: {path: sha256(canonical({"field": path, "salt": salt, "value": value}))}`.
    The salt and the value are kept in `audit_log.texts`, outside the hashed bytes. Reports carry
    them with the entry (`texts`), the History tab and the report's history put them back in the
    sentence, and both verifiers check each one against its hash.
  - **Deletion** sets `texts` to NULL for the engagement's entries. The records, the links, the
    heads, the receipts that sign them (v4) and the seal stay as they were, so reports made before
    and after the deletion verify, also with `--require-history`. The verifiers say in a NOTE how
    many texts are unavailable and why; the History tab and the report show `[deleted]` in their
    place. An entry written after the deletion keeps its hash and no text. The append-only
    triggers (TM-5) let `texts` become NULL and nothing else (migration 0028).
  - **An entry with no such text stays v1.** Its record would be the same change either way, so
    reports made only of such entries still verify with verifiers from before this decision, and
    0028 can still be downgraded while no v2 entry exists.
  - **Old entries are not rewritten.** Entries written before 0028 are v1 and keep their text in
    the record, which the chain covers: deleting the content leaves it, the deletion screen counts
    those entries, and the deletion's own entry records how many there were.
- **Why a random salt per field, and not a keyed hash (HMAC) with a per-engagement key that
  deletion destroys:** a role such as `admin`, a path or a short note can be guessed from a plain
  hash; 128 random bits per field make that impossible once the salt is gone. To check a text, a
  verifier needs its salt, which travels with that one text only. With an HMAC the verifier would
  need the engagement's key: every exported report would carry it, and with it anyone holding
  that report could test guesses against every later entry of the engagement once its text was
  deleted. The salt also needs no key store, no rotation and nothing beyond SHA-256 in the browser
  verifier, and binding the field's name into the hash keeps a text from being shown under
  another field.
- **What an auditor can still verify after a deletion:** that the history is complete and
  unaltered (every record and link), who did what and when, the method, host, account label and
  request hash of every write, the decision and that a DELETE was confirmed, a test account's
  label, kind and fingerprint, and which fields held text. **What is lost:** the text itself: the
  note, the typed path, the role, hosts and header names, the dismissal reason, the import tool.
  A report exported before the deletion still holds them, as it holds the evidence summaries.
- **Not reached:** backups made before the deletion, Postgres dead rows and WAL (RETENTION.md):
  the texts are plaintext in the database, like the rows they describe (`write_proposals`,
  `test_accounts`), which deletion removes the same way. Encrypting them under the engagement key
  would help only if those rows were encrypted too.
- **Compatibility:** a verifier from before this decision fails a report that has a v2 entry
  (the record hash does not match), rather than passing it; `tools/verify_report.py` and the
  browser verifier from this version read both. The report format stays `attackledger-report/2`.
- **Considered:** an HMAC keyed per engagement (above); encrypting the texts with the
  engagement's data key and committing to a plain hash, as chain record v2 does for evidence
  summaries (a plain hash of a short value can be guessed); rewriting old entries to v2 (it would
  change records that signatures and seals already cover, so reports already issued would fail);
  making every new entry v2 (older verifiers would fail every new report, with nothing gained for
  entries without text).
- **Proposed by:** Claude (the security review's open item). **Decided by:** Murat Kabak (a new
  record version). Built on branch `audit-fieldhash`.

### D-059 · An agent is given the host's known paths, and never probes an action with GET (2026-10-14, made autonomously)
- **Problem** (a real engagement, 2026-10-14): an agent lane started on a host with no recon. The
  host serves one path prefix only and answers the same 403 to everything else. The agent guessed
  common paths (`/`, `/login`, `/robots.txt`, `/.well-known/openid-configuration`), got the same 403
  each time, concluded that the edge blocked the research client, and finished with nothing
  tested, while an import in the engagement held over a hundred real requests showing the
  working paths. The lane context gave the agent recon output only, and the prompt said nothing
  about a uniform 4xx. Separately, a lab run sent GET to a password-change form's target to see
  whether it answered, and then reported that the user's password might have changed.
- **Decision:**
  - The lane context has `known_paths` (`executors.known_paths`): `{"total": N, "paths": [...]}`,
    each path a line `METHOD /path status [source xN]`, for the lane's host only. Sources:
    imported traffic (inbox entries: method, path, status), the URIs of evidence attached to any
    lane of the engagement (the path only; it joins a row with the same path), and recon endpoints
    a tool requested itself (a crawl, or content discovery with its status) that are not already
    among the ranked endpoints shown. Archive URLs (gau, wayback), JavaScript files and junk are
    left out: they say a path once existed or looked like one, not that it answers.
  - Deduplicated by method and path shape (`surface.shape`: identifiers collapsed, so
    `/items/1` and `/items/2` are one row with a count). Query strings and fragments are never
    given. When the engagement redacts (the default), each path also goes through
    `redact.text` with the personal-data rules (an email in a path becomes a marker); the stored
    URLs were redacted already. A port other than the scheme's default keeps its origin.
  - Ordered by what the status says (2xx, 3xx, then 401/405/5xx, unknown, other 4xx, 404/410
    last: a catch-all answers 403 to anything), then source (import, evidence, recon), signal
    (`surface.score`) and count; static files (styles, images, fonts) last. At most 40 shown
    (`KNOWN_PATHS`), read from at most 5,000 rows of each source, the most recent first.
  - Nothing once the engagement's content was deleted: evidence URIs outlive the deletion by
    design (the chain commits to them, RETENTION.md), so the function returns nothing rather than
    relying on the other sources being blank.
  - The system prompt gets two lines. One: when guessed paths all get the same 4xx body, suspect a
    path allowlist or catch-all, not a block on the researcher; use `known_paths` and name the
    reachable paths in the summary. Two (asked for during the work, after the lab run above): never GET or HEAD a form's target or
    a URL naming an action (password or email change, delete, transfer) to probe it, since a badly
    built endpoint may act on GET; treat it as a write needing approval and read the page leading
    to it instead; a logout link the application serves as a GET may be followed to test session
    termination.
- **Cost:** the system prompt grows by 535 bytes on every lane and turn (about 135 tokens:
  214 bytes for the known-paths line, 321 for the GET rule). The first message grows by 40 bytes
  when nothing is known (`{"total": 0, "paths": []}`), and by about 2.4 KB (about 600 tokens)
  at the cap: measured on a lane with 117 imported requests over 59 path shapes, 40 shown. The
  first message is cached, so later turns read it at the cache rate.
- **Considered:** the gateway's request log as a fourth source (it holds every earlier request to
  the host, recon tools' misses included, and a failed run's guesses: mostly noise, and recon's
  findings are in the endpoints already); giving exact identifiers instead of shapes (an object
  id from someone's traffic is personal data more often than it helps; the agent sees `{id}`);
  repeating recon endpoints already ranked (paid twice); a structured object per path (more bytes
  per row than a line); known paths from other engagements of the same program (the
  context never reaches outside its engagement and host). The GET rule is in the prompt only:
  the tools cannot tell an action URL from a page, and refusing GET by path words would block
  reads of the pages that lead to them.
- **Made by:** Claude, after the runs above (branch `agent-known-paths`).

### D-060 · OWASP Juice Shop as a second lab target (2026-10-16, decided by Murat)
- **Problem:** the agent runs are measured on one practice target, a static nginx shop
  (`lab/nginx.conf`) with 31 issues planted for the WSTG lanes. Twelve lanes have been run on it,
  and the latest runs found 25 of the 31. A target this small says little about how an agent
  does on a real application: a few hundred routes, a single-page front end, an API, a database.
- **Decision:**
  - The `lab` profile gets OWASP Juice Shop, `bkimminich/juice-shop:v20.2.0` (released
    2026-08-10, the newest release at least two weeks old), pinned by its multi-arch index digest
    `sha256:8739101a…5193526b`. It starts only when named
    (`docker compose --profile lab up -d juiceshop-front`).
  - Juice Shop listens on 3000 on a network of its own (`juiceshop`, internal, no host address)
    that only a small nginx front shares. The front (`lab/juiceshop.conf`) is on the lab network as
    `juice.lab.test`, port 80. The front is there for three reasons: Juice Shop writes its access
    log to a file inside its container, and the run's measurement needs the target's own count of
    requests and research headers in the shop's format; port 80 keeps the gateway, the pre-flight
    check and the agents' URLs the same for both targets; and the gateway never shares a network
    with the vulnerable application itself. The front changes nothing in a request. No port is
    published, and the lab proxy for browsers does not forward to it.
  - Hardening as for every service, except the read-only root filesystem: Juice Shop rewrites
    its own files at every start and its challenges write by design. The writes stay in the
    container's layer, which a recreate discards (a fresh shop, no challenge solved). The test of
    hardening names it as the one exception. The image is pinned, not scanned or put in the SBOM:
    it is vulnerable on purpose and runs nothing of AttackLedger's.
  - `tools/agent_live.py --target juiceshop` (the shop stays the default): its own engagement,
    `Agent live run (Juice Shop)`, scope `juice.lab.test` only, authorized, the same research
    header; a lane per role, all signed out (Juice Shop's accounts are its challenges). The agents
    stay read-only unless the D-041 approval flow is used; nothing is approved automatically.
    Pre-flight also checks Juice Shop and reads its challenge list from inside the stack (the
    front's container asks Juice Shop directly: neither through the gateway nor in the front's
    log). A run starts on a fresh shop, reads the list before and after, and writes a snapshot.
  - `tools/juiceshop_score.py` scores the snapshot offline. **Identified**: a lead or evidence
    entry names a challenge by an indicator in `tools/juiceshop/challenge_map.tsv`, a table a
    person can review; firm indicators count, uncertain ones (and matches in an entry with a
    negation) are listed for a reviewer to confirm or reject. **Solved**: Juice Shop's own flag
    went from unsolved to solved during the run. The two are never added: a read-only agent can
    identify far more than it can solve, and the method text says so.
- **Cost:** about 520 MB of image and up to 1 GB of memory while it runs. The indicator table
  covers 74 of 116 challenges and must be checked against the challenge list when the pin moves
  (the scorer stops if a key or name no longer matches).
- **Considered:** Juice Shop listening on port 80 itself (`PORT=80`; simpler, but no access log
  in the run's format, so the independent count and the header check would be lost); putting
  Juice Shop on the lab network with the front (the gateway could then reach port 3000 directly);
  a read-only root filesystem with volumes over the folders it writes (volumes would keep state
  between recreates); fuzzy text matching of leads to challenge descriptions (it would overclaim);
  reading the solved flags through the gateway (they would count as the run's requests); signing
  in with Juice Shop's built-in accounts for the signed-in lanes (that solves challenges by itself);
  DVWA or WebGoat (fewer API routes, no machine-readable solved state).
- **Proposed by:** Claude. **Decided by:** Murat Kabak, who chose this option on 2026-10-16. Built
  on branch `feat/lab-juiceshop`.

## Adding entries

Add a new `D-0NN` entry whenever a decision changes direction, scope, licensing or
security behavior. Record who proposed the idea, who decided and what else was
considered. Keep the entries factual.
