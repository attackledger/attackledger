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
  turn, request and estimated-cost limits (defaults 15, 30, $0.50). The conversation is
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
  and a report could omit an entry unnoticed.
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

### D-041 · Writes only with a person's approval (2026-10-09, decided by Murat; amends D-024)
- **Decision:** agents may propose POST, PUT, PATCH or DELETE requests. Each one waits in an
  approval queue; a person sees the full request and approves or rejects it; the gateway
  sends it only after approval. DELETE needs its own explicit confirmation. An engagement
  rule (off by default) decides whether writes may be proposed at all. Every approval,
  rejection and sent write is recorded in the audit log and as evidence. Recon tools stay
  read-only by construction (nuclei templates are classified and non-GET ones excluded).
- **Proposed by:** Claude. **Decided by:** Murat Kabak.

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
- **Made by:** Claude, for MVP item 6, under Murat's overnight permission. To be reviewed.

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
- **Made by:** Claude, for MVP item 5, under Murat's overnight permission. To be reviewed.

## Adding entries

Add a new `D-0NN` entry whenever a decision changes direction, scope, licensing or
security behavior. Record who proposed the idea, who decided and what else was
considered. Keep the entries factual.
