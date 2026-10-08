# TASKS given to hunting agents
> Every hunting agent receives TWO layers. Layer 1 is fixed (the same for everyone), Layer 2 is lane-specific.

---
# LAYER 1 — `methodology/AGENT_EXECUTION_PROMPT.md` (FULL TEXT, never trimmed)
Measured result when it is trimmed: the agent tries to spawn its own sub-agent and returns with
"I looked, found nothing". That is why a summary is never substituted.

## Operating rules (violation = the run stops)
- **Mandatory header** on every request, anonymous requests included. Not a single request without the header.
- **Forbidden, no exceptions:** DoS/stress · brute force · token/UUID/ID **enumeration** · state-changing calls (money, messages, create/delete/modify records) ·
  out-of-scope hosts (deny-wins: if `x.y.z` is OOS then `*.x.y.z` is OOS) · **subdomain takeover claims** ·
  opening a report on the platform / sending email · writing a cookie-token value into chat.
- **429 / WAF challenge → the host is LEFT.** No slowing down and continuing either.
- **Control test:** before interpreting a denial (401/403), re-try a known-good endpoint.
  A dead session mimics an authz finding perfectly. Any authz verdict without a control is **VOID**.
- **No idle waiting:** while a scan runs in the background, move to a parallel item and report the interim result.
- **Do not run agents to divide work.** The single exception is `finding-validator`.

## Task order — A through I, flows automatically, no approval is asked

| phase | task | gate / output |
|---|---|---|
| **A · Pre-check** | 6 items: scope · header · rate · session · 2nd account · GraphQL present/absent | all 6 as a table; if one is missing **STOP** |
| **B · Deep scan** | ferox + parameter mining + crawl + nuclei + JS, in the background | **Gate 1:** does the baseline discriminate with 3 made-up paths? If not, do NOT run. **Gate 2:** is it already running? (double pass FORBIDDEN) |
| **C · Main hunt** | `webapp-checklist` — 123 items, 13 sections. No moving to another category before one finishes | an interim table per category: item/verdict/evidence. The class skill is loaded **by name** |
| **D · Coverage audit** | ALL 123 items in a single table: `# / item / verdict / **the request it rests on**` | an item with an empty request column is **untested**, its verdict is reset |
| **E · Close the unclear** | give every warning-marked item a verdict NOW. If you cannot decide: which single piece of information is missing, which request would bring it | the unclear count must be **0** |
| **F · Bypass enforcement** | for every PASS: (1) **NAME** the protection (2) **≥2 bypasses** specific to that mechanism | if you cannot name it, it is not PASS but unclear. Failing is not the problem, **not having tried** is the problem |
| **G · Axis variation** | the same items on 4 axes: **method · content-type · auth state · user-agent** | COMPARE the responses — the difference itself may be a finding |
| **H · Client artifact mining** | every JS: beautify → API path · fetch/axios · hardcoded URL · token ref · hidden parameter · WS · S3 · sourcemap. **In a mobile lane, the APK too** (`mobile_recon.sh`) | `JS_ENDPOINTS.md` + if a secret was found, the **`secret_triage.py` output** |
| **I · Final gate** | 6 questions + if there is a finding candidate, the order: **(a0) read the policy OOS list YOURSELF** → (a) the N/A anti-pattern checklist → (b) **`finding-validator`** → (c) report text | do NOT open on the platform, do NOT send email — the text is handed to the orchestrator |

## Handoff (a report alone is not enough — it is lost when the session closes)
- `rejected_candidates.md` → **APPEND-ONLY**, never rewritten
- Tier board (db) → **pin** `if_version`, add new fields (`note_*`), **do not delete** existing ones
- The `state` vocabulary is **FIXED**: only `deep` / `probe` / `revisit`. Do not invent other values
- The report has 6 headings: what was closed and with what · tested with evidence / unclear remaining / unopened categories ·
  validator verdict · BLOCKED items · **what is left next (the top 3 most valuable)** · files written

---
# LAYER 2 — the brief the orchestrator writes (lane-specific, 8 sections)
The order is fixed:

1. **STEP 0 attestation** — read `AGENT_EXECUTION_PROMPT.md` in full + quote **a DIFFERENT and FILLED
   line number in every brief**. (A lane once fabricated the attestation; it is verified against the file.)
2. **TARGET + LANE BOUNDARY** — a single host, which prefix/surface, **what NOT to touch**
3. **MANDATORY HEADER + rate + policy prohibitions** — copied from the program, a rule not a reminder
4. **CLOSED ITEMS** — what has been closed WITH EVIDENCE on this host (so it is not repeated)
5. **MEASURED PITFALLS** — this program's body-signature table, filter order, trailing slash,
   "a prefix root is not the verdict for the subtree", `curl 000` ≠ dead
6. **TOOLS** — recon VPS paths, Caido, Chrome MCP (a fetch inside `javascript_tool` carries headers),
   vantage-point warning
7. **SKILL line** — **at least one skill BY NAME** from `SKILL_MAP.md` + its **artifact** is requested in the handoff
8. **HANDOFF format** + the obligation to write to the board **periodically** (do not wait for the lane to end)

## The orchestrator's own rules
- Two agents are never put on the same host. Lane = (host x phase set) or (host x surface)
- The FIRST step of writing a brief is **precheck**: the host document + file dates.
  (A stale "live lead" was caught in exactly this way.)
- **On every program with mobile assets, `secret_gate.py <handle>`** — before opening a lane, 30 seconds.
  Does the policy pay for credentials, how many assets are `eligible_for_bounty`, what is the operational rule?
  **GO / TIMEBOX / SKIP.** This is an ORCHESTRATOR gate and is not delegated to the agent — the agent is not asked to interpret the
  policy and say "not worth it"; the decision is made BEFORE the brief is written.
- Agent budget: startup context ceiling **20k tokens**
- Triage: if there is no request behind a verdict, **send it back** · if it says "PASS", is there a **name** for the protection ·
  if it says BLOCKED, were **≥3 techniques** tried · if there is a finding candidate, is there a **validator verdict**
- If an agent's measurement contradicts my record, **do NOT accept it as correct immediately** — I verify it with a single control test

---
# CREDENTIAL / SECRET — WHERE IT FITS
Full flow: `methodology/SECRET_HUNT_FLOW.md` (5 phases). **Not all of it** goes into an agent brief — it is split:

| phase | who does it | when |
|---|---|---|
| **0 · Payment gate** (`secret_gate.py`) | **ORCHESTRATOR** | before the lane is opened, once per program |
| **1 · Corpus** (APK/JS/repo) | agent | if the brief provides the package name + the correct `MOBILE_MAX_PKGS` |
| **2 · Scan** (`trufflehog --only-verified`) | agent | on the Phase 1 output |
| **3 · Triage** (`secret_triage.py`) | agent | **EVERY time it thinks it has found a secret** — embedded in phase H, not conditional |
| **4 · Validation limit** | agent | if the policy says `stop and report`, the key is NOT USED |

**Why Phase 0 is not given to the agent:** the agent is not asked to read the policy and say "not worth it on this program" —
that decision determines whether the lane opens at all, so it belongs to the orchestrator. The agent only **executes**.
**Why Phase 3 is unconditional:** phase H was already extracting token references and there was no classification guide;
hundreds of false positives were born in exactly this gap. It is now inside H.

---
# CONTEXT BUDGET — in every brief

**Startup cost was measured:** `AGENT_EXECUTION_PROMPT.md` alone is about **7.9k tokens**; the brief is ~1.2-1.5k.
Total ~10k. Ceiling 20k. **`lanes/agent_budget.py <brief.md>` runs BEFORE every spawn** — in one session it was
skipped for five spawns in a row and the numbers were assumed instead of measured.

**The real risk is not startup but A SINGLE LARGE TOOL OUTPUT.** Every brief will contain:

- **When reading the board (`ArtifactData`), do NOT call `list`/`query` without `out_dir`** — a collection can hold
  hundreds of documents, some 30-40 KB; a single call can drop ~200k tokens.
  - One document: `get` + `doc_id`. Multiple: **`out_dir`** → write to a file, read with `head`/`grep`.
- **Do not `cat` a large file.** `wc -l` + `grep -n` + `sed -n 'A,Bp'`.
  Typical trap sizes: a React-Native `index.android.bundle` of 17 MB · a `dex_strings_clean.txt`
  of 1.5M lines · corpus tsv files of ~1,000 lines · some board documents of 39 KB.
- **Do not read the whole tree of jadx output** — go targeted with **`--single-class`**.

Note: on every tool turn the WHOLE conversation is re-sent to the model. So the cost is not independent but
**context x number of turns**. If an agent with 15k context takes 5-6 turns a minute the counter shows 90k and this
is NORMAL. The real waste is a single dump call that balloons the context all at once.
