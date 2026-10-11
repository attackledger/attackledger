# AttackLedger security review, October 2026

These reports cover an internal, white-box security review of AttackLedger: the API, the traffic
gateway, the tool worker, the verifiers, the web app and how it is built and deployed. It ran
from 10 to 11 October 2026, on the code after release 0.8.0 (`c3557a5`).

**Who did it.** The author ran the review with AI agents (Claude). Each part was reviewed by one
agent, and a second agent, which had written none of the fixes, then tried to get around each fix
(`RECHECK.md`). **No independent third party has tested AttackLedger.** Read these reports as the
author's own testing, written down so that anyone can repeat it, not as an external pentest
report or an attestation.

**How.** Each suspected issue was first proven with a test that failed, then fixed, and the test
was kept as a regression test. Traffic went only to localhost, local stubs and the bundled lab,
apart from package registries, the timestamp authority, and the passive-source queries one lab
run made (`SUPPLY_CHAIN.md`). The server suite went from 758 to 1,050 tests, and it now also runs
on Postgres 16 (`tools/test_postgres.sh`), as production does. The Python and browser verifiers
give identical results on 134 reports and on 2,600 random mutants (`tools/verifier_equivalence/run.sh`).

## Reports

| Report | Covers | Found |
|---|---|---|
| [GATEWAY.md](GATEWAY.md) | Scope enforcement, the Claude API path, rate limits, test-account sessions, Docker networks, the worker channel, the request log | 1 High, 3 Medium, 7 Low |
| [EVIDENCE.md](EVIDENCE.md) | Both verifiers, receipts, the report format, the report seal, encryption, imports, redaction, the web app | 6 Medium, 5 Low |
| [AUTH.md](AUTH.md) | Sign-in, sessions, roles, organization isolation, approvals, single-use steps, Postgres-only behaviour | 3 Low, 4 Info fixed, 3 races fixed |
| [RECHECK.md](RECHECK.md) | An adversarial second pass over every fix above | 4 bypasses (2 Medium), 1 new Low |
| [RETENTION.md](RETENTION.md) | Whether deleting an engagement's content reaches every store | 3 Medium, 4 Low |
| [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md) | Container privileges, image and package pinning, known advisories, SBOM | 2 Medium, 3 Low |
| [FUZZING.md](FUZZING.md) | Property-based and mutation fuzzing of the importers, redaction, scope and URL parsing, page and bundle parsers, and both verifiers | 6 Medium, 12 Low, 1 Info |
| [WEB_E2E.md](WEB_E2E.md) | The web app in Chromium and Firefox (Playwright): hostile content in every view, the CSP and headers, sessions, roles, CSRF, both verifiers, drafts, accessibility | 5 Low, 1 Info |

Severities are the reviewers' own and describe impact in AttackLedger's threat model, mainly a
compromised or misled tool or agent in the worker and a malicious page in the operator's browser.

### The findings that mattered most

- **GW-1 (High): an agent could make Anthropic's servers fetch any URL.** The gateway sent an
  agent's Claude API call without reading it, so server tools, the MCP connector and URL sources
  reached hosts outside the scope, the rate limit and the request log. The gateway now sends only
  what the agent loop sends.
- **EV-1, EV-2, O-2 (Medium): a voided receipt could still look receipted.** Unsigned report
  fields could be edited so the verifiers missed a void. Receipts now sign the history they rely
  on, and every exported report is sealed by the instance's key (D-055); `--require-history`
  fails reports whose history is incomplete.
- **GW-8 (Medium): the worker could reach services on the Docker host.** The internal networks
  now give the host no address, and the gateway refuses its own networks.
- **AUTH-2 and its recheck (Medium): another site's page could change things.** This worked
  through a sibling subdomain, and in open mode through DNS rebinding.
- **Postgres-only (security):** times were stored in the database session's zone, which kept
  approvals usable for hours on a non-UTC server, and one bad log row could stop the gateway's
  log and then all its traffic (also GW-11).
- **FZ-4 (Medium): an exclude rule could silently match nothing.** A rule with a line end before
  its last dot was stored broken, so the host it was meant to exclude under a wildcard stayed in
  scope for the gateway. Fuzzing also found five inputs that took quadratic time and could stall an
  import or a recon run (FZ-6, FZ-11 to FZ-13).
- **RET-2, RET-3 (Medium): content deletion missed running jobs and job targets.** The backup
  documentation also overstated what master-key rotation does (RET-7).

## Still open

Each report lists its own open items. The main ones:

- **The seal proves what the server stated, not that the server is honest.** Whoever holds the
  instance key can seal a different report (VERIFIER.md).
- **The gateway can reach the host's addresses on networks it is not on,** such as the host's
  LAN. INSTALL §6 suggests a host firewall rule, which has not been tested.
- **The audit log keeps some free text that content deletion cannot remove** without breaking
  its hash chain: approval notes, the typed DELETE path, and test-account roles and hosts.
- **Content deletion does not reach backups made before it,** Postgres WAL and dead rows, or
  container logs (RETENTION.md).
- **OS packages are not version-pinned, and nothing scans them.** Images and tags are not signed.
  Pin refreshes are manual (`tools/refresh_pins.sh`).

## Reporting a vulnerability

See [SECURITY.md](../../SECURITY.md).
