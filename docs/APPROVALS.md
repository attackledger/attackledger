# Test accounts and writes with a person's approval (D-040, D-041)

Status: built 2026-10-09, migration `0021`. Code: `server/app/testaccounts.py`,
`server/app/approvals.py`, the gateway's side in `server/app/gateway.py` (`GATEWAY.md`, decision
9), the agent's side in `server/app/agenttools.py`, the UI in `web/src/Accounts.tsx`. This page
records the design and the choices made while building it.

## Test accounts (D-040)

### What is stored

| Field | Where | Shown |
|---|---|---|
| Label (A, B, ...), role in the application, hosts it is for, kind | `test_accounts` | yes |
| The header names it sets (`Cookie`, `Authorization`, `X-Api-Key`) | `test_accounts.header_names` | yes |
| The session material, as `[name, value]` pairs | `material_enc`, sealed with the engagement key (`vault.seal_secret`, AES-256-GCM, the purpose and the hash as associated data) | never |
| SHA-256 of the material | `fingerprint` | the first 16 hex digits |
| Added, by whom; replaced; last used | `created_at`, `created_by`, `replaced_at`, `last_used_at` | yes |

- **Kinds.** A cookie header value becomes `Cookie: <value>`; a bearer token
  `Authorization: Bearer <token>`; header lines are taken as they are. Refused: line breaks,
  names the connection, the proxy or AttackLedger sets (`Host`, `Content-Length`, `Proxy-*`,
  `X-AttackLedger-*`, `User-Agent`), the engagement's identification header, duplicates, more than
  10 headers, more than 8,000 characters.
- **Hosts.** Each must be an in-scope host name (no wildcard). The gateway checks the scope again
  on every request, so a host taken out of scope stops getting the session at once.
- **Redaction on.** An account cannot be added, and the gateway refuses to use one, while the
  engagement's evidence redaction (D-038) is off: the scrubbing of responses relies on it.
- **Never returned.** No route returns the material. The one way out of the API is
  `POST /gateway/account`, for the gateway token, for a running agent job's credential, for a host
  named for the account (`GATEWAY.md`, decision 9).
- **Audit.** `account.added`, `account.replaced`, `account.deleted`, with the label, role, hosts,
  kind, header names and fingerprint, never a value.
- **Content deletion** (D-043) deletes the rows; the sealed values were unreadable already, since
  the key goes.

### Who

Testers and owners add, replace and delete accounts (the work is theirs: they signed in to
them). Anyone on the engagement can list them: labels, roles and fingerprints are not secrets,
and a reviewer needs them to read evidence that says "as test account B".

### The agent's view

The lane context lists `test_accounts: [{label, role, usable_on_this_host}]` and nothing else.
`http_request` and `propose_write` take `as_account`. The tool adds `X-AttackLedger-As`; the
agent cannot set that header or any other `X-AttackLedger-*` header itself. The recorded exchange
names the account (`request.as_account`), and so does every evidence summary built from it.

## Writes (D-041)

### The rule

`engagements.allow_writes`, off by default, changed by an owner (`PATCH /engagements/{id}`), audited
as `engagement.writes`. Off: `http_request` refuses every write as before and the write tools are
not offered to the model; `propose_write` called anyway is refused; the gateway refuses a write
without an approval, whatever the rule.

### The life of a write

```
agent: propose_write ──► pending ──approve──► approved ──(the run's write_status)──► gateway uses it ──► sent
                            │       (DELETE) ─► confirming ──typed path──┘                      └─► failed
                            ├──reject──► rejected            approved, not used in 15 min ──► expired
                            └──the run ends──► expired
```

- **Proposal.** Method (POST, PUT, PATCH, DELETE), URL on the lane's host and in scope, the
  agent's headers (none AttackLedger sets, no method override), a text body up to 1 MB (none for a
  DELETE), the test account, the checklist item and a reason. Stored sealed with the engagement
  key; `request_sha256` is the SHA-256 of its canonical form (method, URL, headers in order, body,
  account). At most 20 undecided per run. The list shows the URL and reason redacted.
- **Approval** (`POST .../approvals/{id}/approve`) names the `request_sha256` the person read; a
  different one is refused, so what is approved is what was displayed. The approval expires
  `ATTACKLEDGER_APPROVAL_MINUTES` (default 15) after it is given.
- **DELETE** needs a second, separate call, `POST .../approvals/{id}/confirm-delete`, by the person
  who approved it, with the URL's path typed exactly. Until then it is `confirming` and cannot be
  sent. The path rather than the word DELETE: it makes the person read which resource goes.
- **Rejection** needs a note; the agent reads it.
- **Sending.** The run's `write_status` tool asks the API; for an approved write it gets the request
  back and sends it through the gateway with `X-AttackLedger-Approval`. The gateway asks the API to
  use the approval, which checks the method, URL, body and account against the sealed request and
  marks it sent, in one transaction, before anything is sent: a changed body or URL is refused and
  the approval stays unused; a second use is refused. The gateway sends the approved headers, not
  the worker's.
- **Recording.** The exchange (with the request body) is stored like any other, redacted and
  encrypted, and becomes evidence on the proposal's item, source `agent`, with a summary that says
  who approved it and when, the request hash, the DELETE confirmation and the agent's reason. The
  gateway's log row carries the approval id; it gives the response status even if the worker never
  reports the exchange.
- **Audit.** `write.approved`, `write.delete_confirmed`, `write.rejected` by the person;
  `write.sent` by the traffic gateway (a new actor kind, `gateway`), each with the proposal id,
  method, host, account and request hash, never the body.

### Who approves

The tester role, or an owner. Viewers and reviewers cannot see the queue or decide: approving a
write changes the target, which is the tester's work under the rules of engagement, and keeping
it apart from reviewing keeps the reviewer independent of what was done to the target. With
separation of duties on, whoever started the agent run cannot approve its writes, and the operator
token cannot approve at all, as for receipts.

### The loop does not stall

`propose_write` returns at once with a proposal id. The agent goes on with other items and calls
`write_status` later, which reports `pending`, `rejected: <note>`, `expired`, or
`approved and sent: status 200` with the exchange id. `wait_seconds` (up to 120) lets it wait for a
decision when nothing else is left, polling the API every 5 seconds; each poll is also the job's
heartbeat. A run that ends leaves its undecided writes `expired`.

### A person's own writes

Not built, on purpose. A tester who wants to send a write sends it from their own tool (Burp,
Caido, a browser), under their own control, and imports the exchange as evidence (D-029). A UI
route that sends writes on a person's behalf would add a second way to change the target that is
not tied to a run, its limits and its log, for something the tester's own tools already do.

## Measured

- Tests (`server/tests/test_test_accounts.py`, 29 tests, 39 cases): the real gateway between the worker's tools and
  a recording upstream, with the real API behind it. Each refusal (rule off, unapproved, changed
  body or URL or account, expired, used twice, DELETE without its confirmation, wrong host, recon
  job, redaction off, viewer, reviewer, separation of duties, content deletion) was broken on
  purpose once and a test failed each time (15 mutations, all caught; two were first caught only by
  the API's layer, so tests of the gateway's own layer were added).
- A scan of everything stored and shown after a run (every table, every blob file, the decrypted
  evidence, the report, the audit log, the gateway log, the lane context, the tool results) for the
  raw session values, their base64 and the cookie header: none.
- Lab (Juice Shop, `docs/BENCHMARK.md` stack, lab only): two throwaway users registered on the lab
  container, added as A and B (bearer). As A, A's basket 200; as B, A's basket 200 (Juice Shop's
  known BOLA); no account, 401. A POST (one item into A's basket) and a DELETE (that item)
  proposed, approved in the UI, the DELETE confirmed by typing its path, each sent once: the
  counting proxy in front of Juice Shop saw exactly one POST and one DELETE, the basket was empty
  again afterwards. Neither token appeared in the database dump, the logs of the API, gateway,
  worker and web, the blob volume, the decrypted evidence, the API's responses, the worker's files,
  process environments and the bridge's state file; the scan found both in the session file it was
  given as a positive control.

## Not done

- Checking a recorded exchange against the gateway's log row before it becomes evidence.
- Test accounts for recon tools (authenticated crawling): recon stays unauthenticated.
- Refreshing an expired session: a person signs in again and replaces it.
- An absolute expiry for a pending proposal: it lives as long as its run.
