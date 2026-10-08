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

### D-018 · Who issues receipts (2026-10-08) — PROPOSED, awaiting decision
- **Proposal:** Executors, agents included, may attach evidence and mark items, but
  only a person closes a lane and issues its receipt.
- **Why proposed:** A receipt is the claim "this was tested"; keeping a human
  signature on it is what makes the coverage statement credible to an auditor.
- **Alternative:** Let agents close lanes, with a mandatory human review step before
  the report.
- **Proposed by:** Claude. **Decision:** pending, Murat Kabak.

## Adding entries

Add a new `D-0NN` entry whenever a decision changes direction, scope, licensing or
security behavior. Record who proposed the idea, who decided and what else was
considered. Keep the entries factual.
