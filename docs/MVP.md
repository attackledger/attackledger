# MVP: ready for a design partner

Status: agreed 2026-10-09. The MVP is the version a design partner (BUSINESS.md, stage 2)
can install on their own server and use on a real engagement.

## Who and how

A pentest team or a bank's audit team runs the test with the tools they already use
(Burp, Caido, browsers, scanners). AttackLedger holds the engagement's rules, imports
their evidence, records coverage per checklist item, has a reviewer sign each lane and
gives the client a report anyone can verify. Recon and the Claude agent are available
inside the gateway's limits, but the MVP does not depend on them.

## In scope

| # | Work | Decision | Done when |
|---|---|---|---|
| 1 | nuclei read-only and rate ceiling | D-020, D-024 | benchmark: 0 non-GET requests, peak at or under the limit |
| 2 | Traffic gateway | D-039 | the worker has no route to the internet; every recon tool and the agent go through the gateway, which enforces scope, methods, rate and identification and logs each request; the benchmark passes through it |
| 3 | Encryption and retention | D-043 | evidence and captured traffic are encrypted at rest with a key per engagement; deleting an engagement's key makes its content unreadable while its chain and receipts still verify |
| 4 | Evidence import | D-029 | a HAR file, a Burp XML export and a Caido JSON export become inbox entries; out-of-scope rows are refused and listed; secrets are redacted; a person maps entries to items; the chain records the source |
| 5 | Public verifier page | D-042 | attackledger.com/verify checks a report in the browser without uploading it, with the same verdicts as `verify_report.py` on the sample report |
| 6 | Install and operations | D-042 | a written install on a fresh Linux server with TLS, first owner, keys, backup and restore, and upgrade; tested end to end from the document |

## Not in the MVP

- Test accounts with credentials injected at the gateway, and the approval queue for
  writes (D-040, D-041). Built after the MVP, on 2026-10-10.
- Recon improvements from the benchmark (SPA routes, authenticated recon, agent context).
- A live agent run on the Messages API; it needs an API key on the operator's side.
- Organization id on every record and the worker talking to the API (D-042). Built after the
  MVP, on 2026-10-09/10.
- Caido's local API (token-based pull). File import covers the MVP.

## Release

When all six are done: the full test suite passes as a non-root user, the benchmark is
re-run through the gateway, the demo and site are rebuilt, the README and landing page
claims match what was measured, and the version is tagged 0.7.0.
