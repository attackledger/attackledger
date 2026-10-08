# AttackLedger

**Evidence-first, fail-closed orchestration for AI-assisted offensive security.**

AttackLedger is a methodology and tooling framework for running bug-bounty and
penetration-testing engagements with a team of AI agents (built on Claude Code),
where every claim about coverage has to be backed by a recorded artifact.

The core rule is borrowed from audit practice:

> **A control without evidence is a control that was not performed.**
> In AttackLedger, "done" is a *computed* state, never a statement. If the
> receipt is missing, the work is open.

## Why

AI agents are fast, and they are also prone to *completion bias*. They declare
a host "fully tested" after a partial pass, call a surface "exhausted" when it
was rate-limited, or report "no findings" when they could not see the response.
AttackLedger turns those failure modes into gates:

| Failure mode | Gate |
|---|---|
| "Done" asserted without proof | `gates/close_gate.sh` / `gates/is_closed.sh`: closure is derived from receipts and fails closed |
| Hosts silently dropped between recon and testing | `gates/coverage_audit.sh` + the `coverage-auditor` agent diff the full inventory against what was actually tested |
| Agent stops with unchecked items | `hooks/lane_gate.sh` (SubagentStop hook) sends the agent back while any `- [ ]` remains in its lane checklist |
| Destructive requests slipping through | `hooks/delete_guard.sh` (PreToolUse hook) requires explicit approval for DELETE-class actions |
| Weak findings reaching a report | the `finding-validator` agent re-verifies impact cold, before anything is filed |

## How it works

An engagement is split into **lanes**, where a lane is one host combined with one role.
Each role has a mandate, a checklist and a hard entry condition:

```
recon ──► mapper ──► authz ─┐
                    authflow ├──► finding-validator ──► report
                    logic   ─┤
                    injection┘
          mobile (offline, parallel)
```

- **recon** measures the external surface (live hosts, tech, TLS and headers, leaks).
- **mapper** builds the application model (roles × objects × flows × state machine). The `authz`, `authflow`, `logic` and `injection` lanes **cannot open** until this model exists.
- **authz** works from the matrix: IDOR / BOLA / BFLA tests derived from roles × objects.
- **authflow** covers authentication, sessions, SSO/OAuth and account recovery.
- **logic** covers business logic, race conditions and state-machine bypasses.
- **injection** covers input validation, uploads and client-side sinks.
- **mobile** extracts the APK/IPA surface offline.

An orchestrator, which itself does not hunt, opens lanes, briefs agents
from templates, caps concurrency and triages what comes back. A finding without
evidence is returned to its agent.

## Repository layout

| Path | Contents |
|---|---|
| `methodology/` | Orchestrator playbook, agent execution prompt, secret-hunt flow, skill map |
| `roles/` | One mandate per role, plus the agent brief template |
| `checklists/` | Per-role lane checklists (what the lane gate enforces) |
| `agents/` | Claude Code sub-agent definitions |
| `skills/` | Claude Code skills: `hunt-orchestrate`, `webapp-checklist` (OWASP WSTG-based) |
| `gates/` | Closure, coverage and nightly audit scripts |
| `hooks/` | Claude Code hooks (lane gate, delete guard) |
| `lanes/` | Lane opening, partition checks, class matrix, agent context budget |
| `recon/` | Recon pipeline and helpers |
| `board/` | Tier board generator (attack-surface priority board) |
| `tools/` | Release gate used to keep this repository clean |

## Requirements

- [Claude Code](https://claude.com/claude-code)
- Optional: [Caido](https://caido.io) together with [caido-mcp-server](https://github.com/c0tton-fluff/caido-mcp-server)
- Recon tooling: the usual ProjectDiscovery stack (subfinder, dnsx, httpx, katana, nuclei), plus ffuf/feroxbuster, jq and Python 3

<!-- CONFIG: environment variables — filled in after the code pass -->

## Rules of engagement

AttackLedger is for **authorized testing only**: programs whose scope you are
in, or systems you own or have written permission to test. The framework
assumes and enforces:

- Scope is read live from the program policy. An explicit deny always wins.
- No denial-of-service and no flooding.
- Agents never create accounts or enter passwords. A human handles identities.
- Destructive (DELETE-class) actions need explicit human approval.

## Status

`v0.1`: initial public release of the methodology, roles, gates and recon
pipeline. Expect rough edges.

## Author

Murat Kabak · contact: murat@attackledger.com

## License

MIT. See `LICENSE`.
