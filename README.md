# AttackLedger

**Prove what was tested.** An evidence system for offensive security.

AttackLedger runs recon and testing engagements (bug bounty, penetration tests,
internal assessments) and records every test as evidence in a tamper-evident
ledger. Coverage is a computed result backed by receipts. It can be mapped to the
controls auditors ask about, such as PCI DSS 11.4, ISO 27001 A.8.8 and DORA
testing requirements.

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

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the layers, the contracts for
adding a recon module or a hunt executor, and the invariants. The decisions behind
them are in [`docs/DECISIONS.md`](docs/DECISIONS.md).

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

## Quick start

```bash
docker compose up -d --build        # api, worker, web, postgres, local lab target
python3 tools/seed_demo.py          # optional demo engagements
open http://localhost:8080
```

All ports bind to `127.0.0.1`. To require a token (do this before exposing the API
anywhere else), set `ATTACKLEDGER_API_TOKEN` in a `.env` file next to `docker-compose.yml`. The `lab` service is a local practice target that
answers as `shop.lab.test` inside the compose network.

## Methodology packs and controls

Lanes and checklist items come from **packs** (`packs/*.yaml`), not code:

| Pack | Lanes | Use |
|---|---|---|
| `bug-bounty` | recon, model, access control, auth & sessions, business logic, input handling, mobile | Bug bounty programs |
| `web-pentest-wstg` | one per OWASP WSTG category (97 tests) | Scoped pentests, internal assessments |

Each item maps to controls in `packs/controls.yaml` (PCI DSS v4.0, ISO/IEC
27001:2022 Annex A, EU DORA). The **Controls** view shows, per control, how many
mapped items on in-scope hosts are backed by receipted evidence. These mappings
are indicative and do not amount to a compliance determination.

Packs fail closed. A pack that references an unknown control, has a dependency
cycle or contains a lane without items will not load, and the API will not start.

## Audit report

Every engagement exports a coverage report (**Report** tab, or
`GET /engagements/{id}/report` and `/report.html`). It contains the scope,
the recorded authorization, every lane and item, the evidence, the recon runs
and the control mapping. It is also verifiable offline:

```bash
python3 tools/verify_report.py attackledger-report.html
```

The verifier uses only the Python standard library and shares no code with
AttackLedger. It performs three checks:

1. **Body hash.** The report body matches its recorded SHA-256.
2. **Evidence chain.** Each evidence entry is linked to the previous one
   (`chain_hash = sha256(prev_hash + record)`). Editing, deleting or
   reordering an entry breaks the chain.
3. **Receipts.** Every lane reported as receipted is checked against a manifest
   rebuilt from the report's own items and evidence. This means that rewriting
   the whole chain and the body hash is still detected.

The HTML report is served with `default-src 'none'`. No script runs in it and
nothing is fetched. All evidence text is escaped.

## Recon engine

The pipeline follows the author's own recon process and runs in the `worker`
container. Steps:

| Step | Tools | Traffic |
|---|---|---|
| Find subdomains | subfinder (all sources), assetfinder, crt.sh, then DNS | passive + DNS |
| Resolve hosts | dnsx (A/AAAA, then CNAME) | DNS |
| Scan ports | naabu top 100, connect scan, port 25 skipped | target, **opt-in per engagement** |
| Find live web servers | httpx: status, title, stack, CDN, per open port | target |
| Golden targets | scoring: AUTH +4, TITLE +4, APPTECH +2, ODDPORT/KEYWORD/200 +1 | computed |
| Crawl golden hosts | katana: same host only, JS parsing, logout/delete paths never followed | target |
| Collect archived URLs | gau, waybackurls | passive |
| Analyse JavaScript | endpoints, GraphQL operations, sourcemaps, secret candidates (REAL / PUBLIC / NOISE) | target |
| Discover content | feroxbuster on golden hosts, one scan at a time, baseline check, no recursion | target, **opt-in** |
| Discover hidden parameters | Arjun on dynamic endpoints, one thread, fixed delay | target, **opt-in** |
| Route parameters | gf-style classes → the hunt lane that tests them | none (computed) |
| Dork checklist | click-ready Google dorks per root (manual) | none (computed) |
| Scan for known issues | nuclei: takeovers (all hosts), exposures/misconfig/stack templates (one per cluster), panels/vulns/CVEs (golden) | target, **opt-in** |

The engagement's *requests per second* value is a hard ceiling for every step that
sends traffic, port scanning included. There is no multiplier.

Secret candidates are stored **masked and hashed**, never in full, and are never
tested against any service. JS fetches follow no redirects.

Crawl and archive output is cleaned in the same way as `uro`: static files are
dropped and URLs that differ only in parameter values are collapsed. Only
in-scope URLs are kept. A job whose tool fails without producing anything is
marked failed, not done. A job stopped at the time limit (`WORKER_JOB_TIMEOUT`, default 30 min) is
marked **partial**, lists the targets it did not reach and can be resumed with
*Run remaining*.

A job is refused unless the engagement has:

1. a scope (`*.example.com` covers subdomains only; exclusions always win),
2. a recorded authorization (operator, policy URL, explicit confirmation),
3. for jobs that send traffic to the target, the **research header and/or
   user agent** the program requires.

The worker re-checks scope on every target and on every host a tool reports.
Redirects are not followed.

## Hunt agents (v0.6, preview)

A lane can be worked by a Claude agent. Put `ANTHROPIC_API_KEY=...` in `.env` (it is
passed to the worker only), set the lane's executor to *Claude agent* and start a run
from the lane. The agent:

- sends **read-only** requests (GET, HEAD, OPTIONS) to the lane's host only, with the
  research identification, no redirects and within the rate limit;
- attaches the exchanges it made as evidence (each one viewable as raw bytes), marks
  items done or N/A, and records leads;
- **cannot close the lane.** You review the evidence and sign the receipt.

`ATTACKLEDGER_AGENT_MODEL` picks the model: `claude-opus-5-5` (default),
`claude-sonnet-5-5` (half the price) or `claude-haiku-5-5` (much cheaper, weaker for
this work). Set a monthly spend limit in the Anthropic Console before the first run.

Runs stop at the first limit they reach: turns (default 15), requests (30), an estimated
cost (default $0.50, checked after each turn) and the worker time limit. The model sees
only the first 4,000 characters of each response, and 40,000 per run; the full response
is kept as evidence. The loop has not yet run against the live API: try it on the lab first.

## People and roles

With no accounts, the API is open on localhost (or guarded by `ATTACKLEDGER_API_TOKEN`).
Add the first owner on the People page, or from the command line:

```bash
docker compose exec -it api python -m app.people create --email you@example.com --name "Your Name" --owner
```

From then on everyone signs in with email and password. Owners add people and give them
roles per engagement on its Team tab: **viewer** (reads coverage, evidence and reports),
**tester** (runs recon, works lanes, attaches evidence) and **reviewer** (signs receipts).
Turn on *separation of duties* there to stop anyone signing a lane they attached
evidence to. Behind HTTPS, set `ATTACKLEDGER_COOKIE_SECURE=1`.

A reviewer's first close creates a signing key in their browser; the private key never
leaves it. Each receipt is then signed, and the report carries the signature and the
public key, so `tools/verify_report.py` checks who signed what without trusting the
server. Turn on *require signatures* on the Team tab to refuse unsigned closes.
Signing needs HTTPS or localhost.

The HTML report (`/engagements/{id}/report.html`) is written for clients and auditors: open
it in a browser and print to PDF, or check it offline with `python3 tools/verify_report.py report.html`.

Clients and auditors sign in as viewers: they read coverage, evidence and reports, and
the Verify tab checks every receipt's signature in their browser. The authoritative check
is `python3 tools/verify_report.py report.json` (it loads the timestamp roots in `tools/tsa-roots/`).

Receipts are also timestamped by an RFC 3161 timestamp authority: DigiCert's public
service by default (`ATTACKLEDGER_TSA_URL`). Only a SHA-256 hash is sent, once per
closed lane; set `ATTACKLEDGER_TSA_URL=off` to send nothing. The report carries each
token, and the verifier checks it against the roots in `tools/tsa-roots/` (DigiCert's
is included) or any you pass:

```bash
python3 tools/verify_report.py report.json --tsa-root authority-root.pem
```

## Database migrations

The API applies Alembic migrations at startup. The worker waits until the database
reaches the latest revision. A database created before v0.2 is stamped at the
first revision only if its schema matches the models exactly. If it does not,
the API refuses to start and leaves the data alone.

```bash
# after changing server/app/models.py
cd server && DATABASE_URL=... alembic revision --autogenerate -m "describe the change"
```

A test fails if a model change ships without its migration.

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

AttackLedger is dual-licensed:

- **Open source:** [GNU AGPL-3.0](LICENSE). It is free to use, modify and self-host. If you
  offer a modified version to others over a network (for example as a hosted
  service), you must publish your source under the same license.
- **Commercial:** for embedding AttackLedger in a proprietary product or offering
  it as a service without the AGPL obligations, contact murat@attackledger.com.

Copyright (C) 2026 Murat Kabak.

## Contributing

Contributions are welcome. To keep dual licensing possible, contributors are
asked to sign a Contributor License Agreement (CLA) before a pull request is
merged.
