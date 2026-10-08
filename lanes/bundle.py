#!/usr/bin/env python3
"""bundle.py -- collects ALL the text given to hunt agents into one .md file.

Agents do NOT read this file (they receive the parts separately); it is for HUMANS:
to review everything in one place and see what is and is not written down.

Usage: python3 lanes/bundle.py > AGENTS_BUNDLE.md
"""
import io, os, datetime

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root
ROLES = ["recon", "mapper", "authz", "authflow", "logic", "injection", "mobile"]
CORE = "methodology/AGENT_EXECUTION_PROMPT.md"
SKILL_MAP = "methodology/SKILL_MAP.md"
BRIEF = "roles/BRIEF_TEMPLATE.md"


def read(p):
    return io.open(os.path.join(BASE, p), encoding="utf-8").read().rstrip()


def lines(p):
    return len(read(p).split("\n"))


out = []
w = out.append
today = datetime.date.today().isoformat()

w("# The COMPLETE text given to hunt agents")
w("")
w("> Generated: `python3 lanes/bundle.py > AGENTS_BUNDLE.md` | %s" % today)
w("> This file is for HUMANS. Agents receive the parts separately:")
w("> core FULL TEXT + their own role addendum + brief. This bundle is not given to them.")
w("")
w("## What an agent receives, in what order")
w("")
w("```")
w("1. %s   core, FULL TEXT, no trimming   %3d lines" % (CORE, lines(CORE)))
w("2. roles/ROLE_<role>.md           role addendum, layers ON TOP of the core    %3d-%d lines"
  % (min(lines("roles/ROLE_%s.md" % r) for r in ROLES),
     max(lines("roles/ROLE_%s.md" % r) for r in ROLES)))
w("3. brief                         target + scope + attestation line numbers")
w("   template: %s                                   %3d lines" % (BRIEF, lines(BRIEF)))
w("")
w("Opening-cost ceiling: 20 000 tokens -- measured with agent_budget.py before every spawn.")
w("Spawn: subagent_type=\"<role>-agent\" | description=\"<role> - <target>\" | model=\"sonnet\"")
w("Concurrent agent ceiling: 2, on different targets. NO exceptions.")
w("```")
w("")
w("## Role -> checklist slice -> handoff")
w("")
w("| role | webapp-checklist sections | handoff |")
w("|---|---|---|")
w("| `recon` | 3 InfoGath, 4 ConfigMgmt, 5 SecTransmit, 12 Crypto | matrix slice + 5 skill artifacts |")
w("| `mapper` | - | `APP_MODEL_<host>.md` (roles, objects, flows, state machine), 30 KB cap |")
w("| `authz` | 8 Authorization | authz matrix (object x role), every cell a real request |")
w("| `authflow` | 6 Authentication, 7 Session | matrix slice + chain note |")
w("| `logic` | 10 DoS, 11 BizLogic, 14 CardPay | transition matrix (unauthorized state transitions) |")
w("| `injection` | 9 DataValid, 13 FileUpload, 15 HTML5 | sink matrix (sink x class x context) |")
w("| `mobile` | - | `MOBILE_SURFACE_<package>.md` + web DIFF |")
w("")
w("13/13 sections have exactly one owner. Audit: `python3 lanes/check_partition.py`")
w("")
w("---")
w("")
w("# PART 1 -- CORE (goes to every role VERBATIM)")
w("")
w("`%s` -- %d lines" % (CORE, lines(CORE)))
w("")
w("```text")
w(read(CORE))
w("```")
w("")
w("---")
w("")
w("# PART 2 -- ROLE ADDENDA")
w("")
for r in ROLES:
    p = "roles/ROLE_%s.md" % r
    w("## `%s` -- %d lines" % (r, lines(p)))
    w("")
    w("`%s`" % p)
    w("")
    w("```text")
    w(read(p))
    w("```")
    w("")
w("---")
w("")
w("# PART 3 -- BRIEF TEMPLATE")
w("")
w("`%s` -- %d lines." % (BRIEF, lines(BRIEF)))
w("For every lane, `lanes/open_lane.py <program> <target> <role>` generates from it and runs the gates.")
w("")
w("```text")
w(read(BRIEF))
w("```")
w("")
w("---")
w("")
w("# PART 4 -- SKILL MAP (role -> required skill -> artifact)")
w("")
w(read(SKILL_MAP))
w("")
w("---")
w("")
w("# PART 5 -- TOOLS")
w("")
w("| tool | what it does |")
w("|---|---|")
w("| `lanes/open_lane.py <prog> <target> <role>` | opens a lane: scope, precheck, APP_MODEL gate, overlap, attestation pick, brief, budget |")
w("| `lanes/check_partition.py` | does each of the 13 sections have exactly one owner; does each role get >= 1 skill row |")
w("| `lanes/class_matrix.py` | `init` / `set` / `show` / `gaps` / `next` -- coverage ledger and queue |")
w("| `board/board_gen.py` | generates the three lists of the board from the real inventory (never hand-written) |")
w("| `lanes/gen_agents.py` | generates `~/.claude/agents/<role>-agent.md` from the role files |")
w("| `lanes/bundle.py` | this file |")
w("| `lanes/agent_budget.py <brief.md>` | opening cost, 20k ceiling |")
w("")
print("\n".join(out))
