---
name: hunt-orchestrate
description: Playbook for ORCHESTRATING a bug bounty hunt — the orchestrator does not hunt, sub-agents do. ROLE PIPELINE (lane = host x role: recon/mapper/authz/authflow/logic/injection/mobile), agent brief template (11 items, starting with the FULL text of methodology/AGENT_EXECUTION_PROMPT.md + the roles/ROLE_<role>.md addendum), deep-scan queue, model selection (session usage above 70% -> Sonnet), report triage (a verdict without evidence is sent back), pushing (pivot after 2 attempts), resource requests and close-out. Load it when moving to the hunt after recon is done, when spawning a new agent, when triaging an agent report, or when the operator says "hunt", "keep hunting", "playbook", "open an agent". Source files: methodology/ORCHESTRATOR_PLAYBOOK.md (this playbook) + methodology/AGENT_EXECUTION_PROMPT.md (the execution prompt given to agents).
---

# HUNT — ORCHESTRATOR PLAYBOOK (the orchestrating model's own job)

The agents do the hunting. I pick the target, split the lanes, write the brief, triage the report,
update the board and push the agents deeper. **I do not run hunting myself** — only short,
decisive single measurements: verifying an agent report, a control test, a scope check.

The execution prompt given to agents: `methodology/AGENT_EXECUTION_PROMPT.md` (FULL TEXT, never shortened).

**ORCHESTRATOR MEASUREMENT LIMIT — AT MOST 3 REQUESTS.** One question, one answer. **If you are about to
send a 4th request, that is a LANE**: stop, write a brief, open an agent. If a measurement decides whether a
lane OPENS, it is mine; the CONTENT of the lane belongs to the agent. A variation battery (a different TLS version,
a different vantage point, a different host) is ALWAYS content. Field lesson: starting as "a single control
test" I sent 15+ requests, and the operator cut me off mid-turn.

---

## 0 · Deep-scan queue (the former "Recon 2" block — moved here)

I choose the targets; the operator does not hand out hosts. Following board priority, build a queue from hosts
that have not been deep-scanned yet and are genuinely live. When building the queue, four rules:

- Remove the ones already deep-scanned — look at the **output FILE**, not a marker (a killed run may have
  left a marker behind: that is how a `PASS3_DONE` marker was once written falsely)
- Verify every host against the OOS list ONE BY ONE — if the pipeline is not given a scope file it skips the
  scope diff and assumes "everything is in scope"
- Take the rate from the program's policy; the pipeline default (50/s) is too aggressive for most programs
- If there is no auth, pass `REQUIRE_AUTH=0` and WRITE DOWN THE DECISION (which module was skipped)

The run mechanics and output triage are in phase B of `methodology/AGENT_EXECUTION_PROMPT.md` — that is the single source,
not repeated here. Each host starts in the background, is not waited on, and I move to the next. When the queue
finishes, ONE summary: what came out on which host, which is worth hunting.

**Queue vs. Hunt B:** the queue = hosts nobody is hunting (multi-host, mine); Hunt B = a host under hunt
(single host, in the agent, with two measurement gates). Both write to the same `DEEP-SCAN-INVENTORY`
document, so any overlap is visible.

## 0b · PIPELINE + AGENT — POLICY-GATED SEQUENTIAL FLOW (standard)

**Measured (comparing two programs):** the two methods are strong in DIFFERENT places, so the right model is
SEQUENCING, not comparison:
- **The pipeline (`recon/run_pipeline.sh`)** wins at scale: subdomain/port scanning, nuclei's thousands of signature
  templates, wayback/gau historical URL mining, bulk JS-secret grep.
  Weak: no judgment (cannot filter noise), cannot carry a session (cookies cannot be transferred safely),
  does not understand policy nuance.
- **The recon agent (skill-based)** wins at judgment: applies positive controls, catches confounds,
  tests authenticated, reads the policy and stops accordingly. Weak: scale/speed — cannot repeat by hand
  the volume the pipeline produces.

**Rule — BEFORE every new recon lane is opened, in order:**

1. **Look in the policy for an automation ban** (phrases such as "automated scanner", "vulnerability scanner",
   "mass scanning", "high-volume enumeration", "excessive API use").
   - **IF NOT:** the pipeline runs FIRST at FULL capacity (nuclei + feroxbuster included).
   - **IF YES:** drop the pipeline to **passive-only** mode: `CONTENT_DISCOVERY=0` (feroxbuster's
     wordlist counts as "high-volume enumeration") · cut it off BEFORE it reaches the nuclei module (7/11)
     (set up a background watcher: kill the process as soon as "Nuclei scan" appears in the log) ·
     `PARAM_MINING=0`. The remaining passive modules (subdomain/DNS, TLS/cert, wayback/gau,
     JS-secret grep, tech-detect) are ALWAYS safe; run them even when there is an automation ban.
2. **VERIFY the Katana crawl scope.** `-jc` (JS-endpoint parsing) could write out-of-scope third-party
   domains into the list too (field incident: unrelated government and cloud-provider domains were
   discovered). In v14.7 and later the script derives a `KATANA_SCOPE_REGEX` from `SCOPE_FILE` and locks it
   with `-cs` — this is automatic now, but if an old copy of the script is in use
   (`.bak_*` files), assume this protection is ABSENT and check the output by hand.
3. **The pipeline's output becomes the agent's INPUT, not a PARALLEL repeat.** When the pipeline finishes
   (or completes its passive modules), write the produced file paths (subdomain list, tech
   stack, JS/endpoint inventory) into the agent brief as "AVAILABLE" — the agent does not discover from
   scratch; it triages this inventory and does the REAL testing (authenticated, with positive controls).
4. **Exception — parallel run for comparison:** if the operator explicitly says "run both, compare",
   the two may run in parallel — but that is an EXCEPTION, not the default flow. Default: sequential +
   combine-as-input.

## 0c · REUSE THE SAME-ROLE AGENT — do not close and reopen (standard)

Operator instruction (paraphrased): *when a finished agent has the same kind of task in the queue on
another host, it should continue with that. If the authz job is done and another authz job is queued,
do not close the agent and open a new one — continue on top of it.*

**Reason — measured:** the most expensive part of every new spawn is STEP 0 (reading
AGENT_EXECUTION_PROMPT.md + ROLE_<role>.md + policy.md, ~15-20k tokens; +50k more before the `tools:"*"` fix).
An agent continuing in the same ROLE already carries these files in its context — no need to make it read them again.

**Rule:** when a role agent (e.g. authz) finishes a host and hands back, and ANOTHER HOST OF THE SAME
ROLE is waiting in the QUEUE:
1. **Do NOT make a new `Agent` call.** Instead send the new brief with `SendMessage` to THAT AGENT'S id (the `from=` in the
   hand-back message).
2. State EXPLICITLY in the message: **"NEW HOST, do NOT CARRY OVER the previous host's ID/object/scope assumptions"** —
   it does NOT need to re-read the core files (`AGENT_EXECUTION_PROMPT.md`/`ROLE_<role>.md`)
   (already in context), but it must open the NEW brief file and read the NEW host's APP_MODEL/policy/CLASS_MATRIX
   rows — these are host-specific and are not skipped.
3. Caveat: this applies ONLY to the same ROLE (authz->authz, recon->recon). A different role is NOT
   continued with the same agent (agent definitions carry a role-specific system prompt, and ROLE_<role>.md changes).
4. The cap (see "Running cap" below) does NOT change — a resumed agent still counts as "1 active". Use
   `ListAgents` to track which IDs last ran in which role.
5. Even a fully COMPLETED agent can be woken with SendMessage (the tool's own behavior:
   "resumes it with full context"). If a role has MORE THAN ONE old agent (e.g. authz ran twice), resume the
   LATEST completed one — it has the freshest context.

**When a FRESH spawn remains:** if no agent has run for that role this session (first time), or there is no
OTHER job of that role in the queue (opening a different role needs a fresh spawn, since the role changes
the agent) — OR while the only agent in that role is still busy (working on another host) and a second parallel
agent of the same role is needed to fill the cap (a fresh spawn does NOT violate REUSE here, because the busy
agent is already doing other work — the reuse rule applies only to an IDLE/COMPLETED agent).

**Extension (operator): "if an agent that is not closed but not working does not burn tokens, never close the
agent you opened. Send work to it as it arrives."**
- A completed (COMPLETED) agent is **PARKED**, not closed/deleted — idling burns no extra tokens (verified
  behavior: it consumes context/tokens only when woken with SendMessage).
- When a new job enters the queue in that agent's ROLE (e.g. mapper finished, then another host became ready for
  APP_MODEL), **FIRST look at a parked same-role agent** — a fresh spawn ONLY if that role never ran or
  all existing same-role agent(s) are busy.
- Practical result: as the session progresses, 1 parked agent per ROLE accumulates (recon/mapper/authz/
  authflow/logic/injection/mobile) — none of them are closed; they are woken with SendMessage as needed.
  An agent that shows "completed" in `ListAgents` output is not ARCHIVED, just idle; the next same-role
  brief is tried on IT first.

**Clarification (operator): "if there are 7 agent types, 7 agents can be open — if the open ones burn no tokens
while idle."**
- **The CAP applies ONLY to the number of agents WORKING at the same time (running).** The number of parked
  (completed, not working) agents DOES NOT COUNT toward the cap.
- Since there are 7 roles, the PARKED pool can theoretically grow to 7 (1 parked agent per role) — this is
  NORMAL and expected, not a cap violation.
- When counting with `ListAgents`: count "running" against the cap, do NOT count "completed" (parked) —
  they already burn no tokens, they are only RESERVED for the next same-role job.

**Observation — reuse does NOT reset context, it CARRIES it (measured):** waking an agent with `SendMessage`
saves re-reading STEP 0 (~15-20k) but ALL of that agent's previous context (every earlier host/lane it finished)
rides into the new turn automatically. Measurement: a recon agent finished a host at 192,176 tokens (task
notification); 17 seconds after a SendMessage to the same agent for another host, the panel showed 200.8k — so
the new turn ADDED only ~8.6k, and the remaining 192k was CARRIED context. Consequence: as reuse chains
(recon->recon->recon...) context GROWS CUMULATIVELY, and the processing cost of every turn rises with it.

**Rule — 400,000 TOTAL-TOKEN CEILING (compact-equivalent):** when an agent's
`subagent_tokens` (the cumulative value in the latest task notification) **EXCEEDS 400k**, that agent is
NO LONGER REUSED. The next job for that role is opened with a FRESH `Agent()` call (ACCEPT paying the STEP 0
cost again — the cost of carrying a bloated context on every turn is far higher than STEP 0's one-time
~15-20k). The old (400k+) agent is not deleted/closed, it only LEAVES THE REUSE POOL — parking is still
free, but it is not woken.
Rationale for the threshold: a full host lane is around ~150-230k (measured examples: mapper 179k, authz
229k, recon 192k) — 400k allows carrying ~2 lanes, collecting the STEP 0 saving, and prevents the context
from bloating disproportionately on the 3rd lane.

**Running cap — operator delegation.** The parked-pool model above made a tight RUNNING cap needlessly
restrictive — parked agents are free; the bottleneck is only the number of agents working at the same time.
The operator delegated choosing this number to the orchestrator. **Default value: 3** (the operator can change it
at any time; it has moved between 2 and 5 depending on triage quality and rate-limit budget). If the cap is
exceeded (running > cap) DO NOT open a new lane. The operator can change it again; I never go above the stated
value on my own initiative. Rationale: (a) the rate limit is a self-imposed per-host ceiling (≤5/s), not a
program-wide shared budget — as long as the hosts differ, the agent count does not split that budget,
(b) hosts × 7 roles is a wide enough work pool that several concurrent lanes prevent lost work without
lowering triage quality, (c) raising the cap is consistent with a "push harder" instruction. **It is not
fixed** — the operator can change it at any time, and the orchestrator can propose a different number with a
rationale (lower if triage quality drops, higher if work piles up).

## 1 · Lane splitting — the ROLE PIPELINE

**Lane = (host × ROLE).** Roles are split, not surfaces. 7 roles, definitions in `roles/ROLE_<role>.md`,
the skill partition in the `role` column of `methodology/SKILL_MAP.md`:

| role | checklist sections owned | one sentence |
|---|---|---|
| `recon`     | 3 Info Gathering · 4 Config Mgmt · 5 Secure Transmission · 12 Cryptography | external surface + configuration inventory |
| `mapper`    | — (produces: `APP_MODEL_<HOST>.md`) | roles · objects · flows · state machine |
| `authz`     | 8 Authorization | IDOR/BOLA/BFLA, matrix-driven |
| `authflow`  | 6 Authentication · 7 Session Management | SSO/OAuth/session/ATO chains |
| `logic`     | 10 DoS · 11 Business Logic · 14 Card Payment | business logic, race, state skipping |
| `injection` | 9 Data Validation · 13 File Uploads · 15 HTML5 | **lowest priority** — scanner territory |
| `mobile`    | — (produces: `MOBILE_SURFACE_<package>.md`) | APK/IPA corpus — **offline**, needs no session |

13/13 sections are owned. No unowned section, no doubly-owned section.

**Order (per host):** `recon → mapper → authz → authflow → logic → injection`.
`mobile` is independent of the order — being offline it does not wait for a session and produces work when things are blocked.

**Concurrency — sequential model:**
- **A SINGLE role** is active on a host at a time. Roles wait their turn in that host's queue, and concurrent lanes
  are always on **DIFFERENT hosts** (per-host rate limiting prevents host sharing).
- Warning: the number of concurrent lanes is NOT a fixed 2 — see §0c "Running cap" for the current value and
  rationale. What does not change: the cap applies only to RUNNING agents (working at the same time); parked/
  completed agents are not counted (§0c).
- Model: sub-agents are **Sonnet**; `model: "sonnet"` is written EXPLICITLY at every spawn.

**Spawn call — NAMING IS MANDATORY:**
```
subagent_type: "<role>-agent"         # recon|mapper|authz|authflow|logic|injection|mobile
description:   "<role> · <host>"      # the name shown on the panel, e.g. "authflow · sso.example.com"
model:         "sonnet"
```
The 7 roles are REGISTERED agent types (generated from `agents/<role>-agent.md`). The definitions are thin
wrappers and do not copy the role text — the single source is `roles/ROLE_<role>.md`, the generator is
`lanes/gen_agents.py`. When you change a role file, RUN gen_agents.py.
**DO NOT open a hunting lane with `general-purpose`** — it shows up nameless on the panel and the gates in
the role definition do not engage. If the role type is not in the registry, **first run
`python3 lanes/gen_agents.py`**; a new type may not appear in the same session, in which case make the lane
WAIT, do not fall back to `general-purpose`. `lanes/open_lane.py` already prints the correct spawn line.

**HARD GATE:** an `authz` / `authflow` / `logic` / `injection` lane is not opened for a host until
the FILE `APP_MODEL_<HOST>.md` EXISTS for it. If it does not, `mapper` runs first.
Reason: "matrix-driven authz" is only possible if the roles × objects Cartesian product is written down;
until this model was produced as an artifact, authz was free browsing.
**Size cap:** `APP_MODEL_<HOST>.md` ≤ 30 KB (~400 lines). Measured: at 40 KB the agent startup cost is
20638 tokens, which exceeds the 20k ceiling. If it overflows, the raw endpoint list goes to
`ENDPOINTS_<HOST>.tsv`. `lanes/agent_budget.py <brief.md>` is already mandatory before every spawn — it is caught there.

**The `report` role was REMOVED** (we already have a validator). The load is on ME — if the validator says
FILE, I write the report text, but I RUN three things myself before handoff:
  a) **Trigger-word scan** — search the body for `takeover` · `informative` · `duplicate` ·
     `self-xss`; keep the substance, drop the word (platform auto-triage gates fire on these).
  b) **Evidence hygiene** (`claude-bughunter:evidence-hygiene`) — cookie redaction, PII masking,
     HAR cleanup, ≥1 screenshot.
  c) **CVSS 4.0 VECTOR** — a vector, not a label. I do not change the validator's vector, and I do not
     WRITE the "if the lock is opened" vector today (that is the inflation pattern that produces N/As).
The operator does the submission; I verify via the API.

Every lane gets a WRITTEN boundary: which host, which ROLE, what NOT to touch (= another role's slice).

## 2 · Brief template (same order at every spawn)

1. **AGENT_EXECUTION_PROMPT.md — full text, at the very top.** No shortening, no summary.
   Reason: that block exists to prevent giving up early; if trimmed, the agent returns with
   "I looked, found nothing".
2. **ROLE: `<role>` + the FULL TEXT of `roles/ROLE_<role>.md`.** This addendum layers on top of the core;
   in a conflict, the role addendum wins ONLY for its own slice. Ask for a separate
   attestation for the role addendum too (the file's `wc -l` output + the literal text of a DIFFERENT line).
3. TARGET: a single host + the lane boundary (= the role's checklist slice; do not enter another role's slice)
4. **PATH to `APP_MODEL_<HOST>.md`** — MANDATORY for `authz`/`authflow`/`logic`/`injection`.
   If the file is missing the lane is NOT OPENED; mapper runs first. (`recon` and `mapper` are exempt from this item.)
5. MANDATORY HEADER + rate + policy prohibitions (copy from the program; a rule, not a reminder)
6. CLOSED ITEMS: what has been closed WITH EVIDENCE on this host (so it is not repeated) — the board
   document + `rejected_candidates.md` item numbers
7. PITFALLS (measured in this program): 986b = a geo-blocked host is LIVE · trailing slash
   gives two forms · separate a 404 by its body · a prefix root is not the verdict for the subtree ·
   marker ≠ completion · a declared corpus beats a wordlist
8. TOOL/RESOURCE STATUS: the tool inventory and the "resources that can be requested from the operator" list are now
   inside `AGENT_EXECUTION_PROMPT.md` (every agent gets it automatically). In the brief write only the **CURRENTLY
   AVAILABLE / NOT AVAILABLE** status — it varies per program. Example: AVAILABLE → mailbox · Caido · Chrome extension · VPS.  NOT AVAILABLE → accounts gated behind identity verification · invite-only portal credentials.  REQUESTABLE → an additional test account · VPN/region-specific egress · eSIM number · funding the account · one-time method permission for a specific endpoint.
9. HANDOFF: report format + the obligation to write to disk/board (written in the agent prompt).
   **The role-slice matrix is MANDATORY** — per row `section | item | VERDICT | #bypass techniques |
   evidence ref`, and the cells are entered into `engagements/<program>/CLASS_MATRIX.tsv`.
   A report without the matrix is SENT BACK at triage.
10. **CLASS SKILLS — write them NAME BY NAME on the FIRST line of the brief, do not say "load if available".**
   Source: the **rows of `methodology/SKILL_MAP.md` that belong to the lane's ROLE**. Do not open another role's row.
   Put the names of whichever skills the lane needs in the brief ("FIRST ACTION: `cat methodology/AGENT_EXECUTION_PROMPT.md`,
   SECOND ACTION: LOAD the skills `claude-bughunter:hunt-cache-poison` and `hunt-host-header`").
   Measured: of 58 installed `hunt-*` skills, 2 had ever been called in their lifetime; the reason was that their names
   did not appear in the briefs. Also, a RUNNING agent does not use one unless told later via SendMessage.
   Typical candidates by stack signal: `hunt-grpc` (Envoy grpc_json_transcoder + `:set`-suffixed routes) ·
   `hunt-shadow-api` (hunting undeclared routes) · `hunt-cache-poison` (CDN/cache stacks; needs no auth and no
   state change ⇒ fits restrictive programs, rarely tested) · `hunt-mfa-bypass` / `hunt-ato` /
   `hunt-forgot-password` (challenge/respond, password_reset, mfa/recovery) · `hunt-oauth`
   (oauth2/token, sso_login, redirect_uri_allowed) · `hunt-nextjs` (SSR brand apps) ·
   `hunt-llm-ai` (LLM gateways).
11. MODEL NOTE (if Sonnet): "verify every measurement with a control test, do not rely on a single observation"

## 3 · Model selection

The operator's **Current session** indicator: **above 70% → new agents are Sonnet**,
below → Opus. I cannot read this indicator; the operator's report is authoritative. A running
agent's model does not change; on `fork`, the override is ignored.

## 4 · Triage (when a report arrives)

- Is there a request behind the verdict? If not, send it back — an item whose "request it rests on" is empty
  is untested.
- In a "clean/PASS" claim, is there a NAME for the protection? If not, convert it to an unclear item and return it to phase F.
- If an agent said BLOCKED: were 2 alternative angles tried? If not, send it back.
- Finding candidate: if there is no validator verdict, report text is NOT WRITTEN. The agent calls the validator itself;
  if it has not, ask it to. **Low entry threshold, high exit threshold:** every
  candidate with a proven root cause goes to the validator (even if impact cannot be shown, tagged "BORDERLINE"); the FILE
  decision, however, must pass the impact + policy-exclusion check. An agent saying "no impact, did not pursue" means
  the agent is doing the validator's job — send it back.
- **If the role-slice matrix is missing the report is SENT BACK** — "I looked" is not a handoff; it must come line by line:
  which item of which checklist section got which verdict.
- The STEP 0 attestation + the ROLE ADDENDUM attestation are VERIFIED: against the file with `wc -l` and `sed -n '<N>p'`.
  (A lane fabricated its attestation once; every brief asks for a DIFFERENT and FILLED line number.)
- If an agent's measurement contradicts my record: do not accept the agent as right immediately;
  I verify with a single control test. (Both agents and I have been wrong before.)

## 5 · Pushing

- If 2 real attempts fail, PIVOT — do not hit the same wall a third time, record the hole,
  move to the next item.
- If an agent says "waiting", push with `SendMessage`: report the interim result + work in parallel.
- If an agent tries to spawn its own sub-agent, stop it; the single exception is `finding-validator`.

## 5b · Resource requests

The operator can provide the following on request (all optional, may not arrive):
VPN/region-specific IP · login · extra credentials · a 2nd account · manual Caido crawl · Chrome extension ·
session · loading money into an account · bitcoin · SMS verification with an eSIM · mailbox (existing).

If an item is stalled for lack of a resource, DO NOT write `BLOCKED` — record it as "waiting on operator action: <exactly what>",
relay it in ONE line, and continue the hunt on the remaining surface. The request must be concrete: which account type,
which country egress, how much funding, which portal invite, which number.

## 6 · Close-out

When a lane finishes: are the board documents current, was `rejected_candidates.md` appended,
is DEEP-SCAN-INVENTORY marked? Then `coverage-auditor` (coverage, not finding quality),
then the engagement status + leads to carry over go into the engagement notes.

**Extra role close-out condition:** in `engagements/<program>/CLASS_MATRIX.tsv`, the cells of the sections
that role owns must be WRITTEN on THAT HOST's row. An empty cell = the role is not closed.
Value set: `PASS | FINDING | N/A | BLOCKED | UNVERIFIED | -`.
Behind every cell that says `PASS` there are ≥3 named bypass techniques + a positive control.
A path missed because of a 429 is `UNVERIFIED`, NOT `PASS`.

When the host's whole role queue finishes: all 13 sections of that host's row must be filled — this is the
single answer surface for "what was done on this host".

Note: "done" is a computed state, not a claim. The close gate (`gates/close_gate.sh`, `gates/is_closed.sh`)
fails closed: without a receipt, the engagement is OPEN.

## ESCALATE FIRST — A REPORT IS THE LAST RESORT (STANDING)

> *"When you find a hole, first try to escalate it. Try to progress. Force it.
> If it doesn't work, we report."*

**Writing a report is NOT the first reflex.** When a lane brings back a finding, the FIRST question as
orchestrator is not "shall I write the report text" but **"how far does this go"**.

The payoff difference is 10-50x: written up as first seen -> Low/informative/duplicate ·
escalated until it reaches data -> High/Critical.

### What the orchestrator does when a lane brings back a finding
1. Look in the handoff for **which rungs of the ladder were tried**. If none, **do not write the report** —
   give the same lane or a new gap-filling lane an ESCALATION task.
2. The ladder (the full text is in the agent prompt):
   go deeper in the same class (extract the sample space COMPLETELY; 4/10 is not "most") · go one layer down ·
   chain (read `CROSS_LANE_LEADS.md`) · same root cause on another host ·
   variant surfaces · **DEMONSTRATE the impact** (not "it is reachable" but "here is the data I reached").
3. If there IS progress, the report WAITS. If there is NO progress and ≥3 techniques of different CLASSES were tried,
   ONLY THEN `finding-validator` + report.

"Force it" does not mean breaking the rules: state-changing calls · DoS/rate-limit ·
messages to real people · out-of-scope hosts = not escalation, a violation.

Process rule: do not draft a report while a defense layer remains only partly measured — measure the whole remaining layer first.

## AGENT CAP — for the RUNNING count; the value can change (history + current value in §0c)

> The cap on concurrent lanes was tightened and relaxed by the operator over time; the operator later delegated
> the choice of the RUNNING cap to the orchestrator. **THE CURRENT VALUE AND RATIONALE: §0c "Running cap".** This
> block is now only HISTORY — the mechanical rules below still apply; substitute the CURRENT value wherever a number appears.

- The number of concurrent **HUNTING LANES (RUNNING)** does not exceed the cap — the value is in §0c, not fixed.
- When one finishes, open a new one immediately or wake a parked same-role agent, **do not ask** — but I do not
  raise the cap on my own initiative, I only apply the operator's delegated decision / propose with a rationale.
- A `finding-validator` called inside a lane is THAT LANE's work and is not counted as a separate lane —
  but still confirm with `ListAgents` that the number "running" does not exceed the cap. PARKED/completed
  agents are NOT counted (§0c).
- **Write `open lanes: N/<current cap>` in every report.** COUNT with `ListAgents` BEFORE spawning.

## TRY THE SAME BUG EVERYWHERE — A PATTERN, NOT A SINGLE FINDING (STANDING)

> *"When you find a hole, try it on other endpoints too. There is probably a hole there as well."*

When a lane brings back a finding, the orchestrator's SECOND question (the first is "how far does it escalate") is:
**"where else does this same pattern exist?"**

What was found is not an EVENT but a PATTERN. What produces the pattern is not a single endpoint: the same
framework · the same gateway rule · the same build config · the same team · the same template. If it was
forgotten in one, it was probably forgotten in others.

### What the orchestrator does
1. Look in the handoff for a **spread table** (endpoint | probe | bytes | OPEN/CLOSED). If missing, do not write the report —
   give the same lane or a new lane a LATERAL SPREAD task.
2. Have the sibling surface COUNTED from the INVENTORY, not GUESSED: `ENDPOINTS_<host>.tsv` · APK corpus ·
   sourcemaps · the same 404 signature · the same upstream decorator · the same naming pattern (`*/graphql` etc.).
3. For every new host, **RE-CHECK the scope** (`lanes/open_lane.py` step 1).

### REPORTING NUANCE — I must know this on the agent's behalf
N endpoints with the same root cause ⇒ **ONE report + an N-asset table**, NOT N separate reports.
Typical policy: *"Root cause duplicates (i.e. same issue across multiple hosts or endpoints) will be
considered duplicates when the underlying component/mechanism is the same."*
Submitting them separately produces duplicates and lowers Signal.
