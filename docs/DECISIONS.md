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

### D-030 · Deployment model: open (2026-10-09)
- **Status:** not decided. Options: self-hosted only; self-hosted testing with a hosted
  service that stores, timestamps and verifies (no target traffic from our side); fully
  hosted. The architecture keeps workers separable so that every option stays possible.
- **Decided by:** Murat Kabak, later.

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

## Adding entries

Add a new `D-0NN` entry whenever a decision changes direction, scope, licensing or
security behavior. Record who proposed the idea, who decided and what else was
considered. Keep the entries factual.
