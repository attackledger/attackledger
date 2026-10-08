# BRIEF — <program> · <host> · ROLE: <role>
# Template: methodology/ORCHESTRATOR_PLAYBOOK.md §2 (11 items). The model is EXPLICITLY "sonnet" at spawn.
# BEFORE spawn: precheck (host document + `ls -la targets/<host>/` DATES)
#               + `python3 lanes/agent_budget.py <this brief>` PASS
#               + no other role is running on this host; the 2nd agent is on a DIFFERENT host

## STEP 0 — read and attest (these first, then a single request)
1. cat methodology/AGENT_EXECUTION_PROMPT.md
2. cat roles/ROLE_<role>.md
3. cat engagements/<program>/APP_MODEL_<host>.md
4. sed -n '<A>,<B>p' engagements/<program>/policy.md
5. grep -n "<host>" engagements/<program>/CLASS_MATRIX.tsv

ATTESTATION (the two are SEPARATE; fabrication gets caught):
  - AGENT_EXECUTION_PROMPT.md: `wc -l` + the LITERAL text of line <N1>
  - ROLE_<role>.md:            `wc -l` + the LITERAL text of line <N2>

## 3 · TARGET
Host: <host>  ·  ROLE: <role>  ·  Slice: checklist sections <...>
DO NOT TOUCH: sections of other roles (<...>) — those roles run in their own lanes.

## 4 · APP_MODEL
<path>  (if missing, THIS LANE IS NOT OPENED — mapper runs first. recon/mapper are exempt from this item.)

## 5 · MANDATORY HEADER + rate + prohibitions
Header: <ALL of the program's MANDATORY headers, verbatim from the policy>   — not a SINGLE request without headers.
WRITE ALL OF THEM. Some programs require TWO headers (for example a bug-bounty marker header
   plus a test-account-email header); a brief that lists only one forces the agent to patch it
   from the core text. Source: the policy.md 'Submission Requirements' section. A fail-closed
   header helper on the recon host is recommended.
Rate:   <from the policy>/min, INCLUDING DEBUGGING.
Prohibitions: DoS/flood (damage caused by SPEED) · state-changing calls ·
        If you are going to write a prohibition, put `policy.md line N` next to it. With no reference there is NO restriction.
        Enumeration is NOT forbidden in most programs — do not invent it, VERIFY it from the policy.
        out-of-scope hosts · if you see 429/WAF, LEAVE the host.

## 6 · CLOSED ITEMS
<CLOSED_INDEX.md item numbers + board document>  — do not repeat them.

## 7 · PITFALLS (MEASURED in this program)
986b = a geo-blocked host is LIVE · trailing slash gives two forms · separate a 404 by its BODY ·
a prefix root is not the verdict for the subtree · marker != completion · a declared corpus beats a wordlist
<+ program-specific>

## 8 · TOOL / RESOURCE STATUS
ALL TOOLS ARE YOURS, DO NOT ASK PERMISSION: Caido MCP · Claude in Chrome MCP · recon VPS ·
Region-specific egress: do NOT assume it is available. If the brief says "region-specific egress
  is available", it is WRONG unless you first VERIFY YOUR OWN egress with `curl -s https://ipinfo.io/json`.
  If it is not the region you need, do NOT count it as a tool; say so in your report. · WebSearch/WebFetch.
"The tool was missing / permission was needed" is NOT A VALID REASON — if one path is blocked, try ANOTHER TOOL.
AVAILABLE: <...>   NOT AVAILABLE: <...>   REQUESTABLE: <...>

## 9 · HANDOFF
0) TEMP FILES: write raw output from curl -D/-o and similar to the scratchpad or to engagements/<program>/evidence/ — do NOT write into the working directory. Delete temp files when the job is done.
a) ROLE-SLICE MATRIX — per row:
   section | item | PASS|FINDING|N/A|BLOCKED|UNVERIFIED | #bypass techniques | evidence ref
b) APPEND CLASS_MATRIX.tsv rows MANUALLY in the existing LONG format
   (host<TAB>section<TAB>item<TAB>verdict<TAB>n_tech<TAB>evidence<TAB>lane<TAB>date).
   Do NOT use `class_matrix.py set` — it converts the file to wide format and WIPES all history.
c) A SEPARATE artifact file for every skill in SKILL_MAP that belongs to this ROLE
d) If there is a finding candidate, YOU invoke `finding-validator` (the single exception)
e0) ODD/UNEXPECTED observations — WRITE EVERYTHING you think "this is weird" about during the lane to CROSS_LANE_LEADS.md:
   duplicate/hidden pages (example: a 2nd forgot-password page with no inputs), unexpected redirects,
   inconsistent behavior. WRITE it even if it does not turn into a finding — a human/cold-retry converts it into impact.
e) LANE CHECKLIST (briefs/LANE_CHECKLIST_<role>_<host>.md) — tick as the work progresses.
   Every box is either `- [x]` (work written to disk) or `- [~] N/A: <reason>`. If an unticked `- [ ]`
   remains, the SubagentStop lane-gate hook sends you BACK; you cannot say "done".
A report without the matrix is SENT BACK.

## 10 · SKILLS (rows with role=<role> in methodology/SKILL_MAP.md)
SECOND ACTION: LOAD the skills `<skill-1>` and `<skill-2>` and PRODUCE their outputs.
Do not open another role's skills.

## 11 · MODEL NOTE (Sonnet)
Verify every measurement with a control test; do not rely on a single observation.
A 401/403 is invalid until re-tested with a canary.

THREE GATES BEFORE SAYING "DONE" (an item does NOT close unless all are YES):
  a) techniques from 3 DIFFERENT CLASSES (3 variants of the same technique do NOT COUNT) — by class name
  b) 3 DIFFERENT TOOLS/PATHS (curl -> Caido -> Chrome -> VPS -> region-specific egress)
  c) POSITIVE CONTROL (verify the discriminator on a known-positive example)
If any is NO, the item is `UNVERIFIED`, NOT "clean/absent/BLOCKED".
For EVERY item you close, WRITE how many classes and which tools were tried.
