# Security review: does deleting an engagement's content reach everything?

Date: 2026-10-11. Branch `sec4-retention`, from `e81074e`. White-box review of our own code, on
localhost only: the server test suite in the API image (SQLite) and `tools/test_postgres.sh`
(Postgres 16). No traffic went to any external host.

The promise under review (D-043, `docs/ENCRYPTION.md`): when an owner deletes an engagement's
content, or its retention date passes, the engagement's sensitive content can no longer be read
anywhere AttackLedger keeps it, while the evidence chain, receipts and reports still verify.
"Content" here is what the testing captured or found: raw exchanges, notes, files, summaries,
URLs with their paths and query strings, recon output, test account material, proposed requests,
logs, free text quoting any of these. What a report verifies (hashes, hosts, receipts, the audit
log) is kept on purpose and listed separately below.

Severity uses the scale of the earlier reports. **Medium**: the promise is defeated in a common
situation. **Low**: it needs an unusual install, timing or data, or only an operator can read
what is left.

## Findings

| ID | Severity | Finding | Fix | Regression test (`server/tests/test_retention.py`) |
|---|---|---|---|---|
| RET-1 | Low | The gateway's quarantine file keeps a deleted engagement's request log rows (known since GW-11) | `827b56c` | `test_deleting_content_leaves_nothing_readable_in_any_store`, `test_a_row_set_aside_while_the_gateway_asks_is_kept`, `test_the_gateway_keeps_its_quarantine_file_when_the_api_does_not_answer`, `test_the_api_names_only_deleted_engagements_and_their_jobs` |
| RET-2 | Medium | A run going on at the deletion keeps writing: log lines, its error, the agent's summary; its exchanges' URLs stay until it ends | `827b56c` | `test_deleting_content_leaves_nothing_readable_in_any_store`, `test_what_deletion_keeps_of_the_jobs_and_the_request_log` |
| RET-3 | Medium | Job targets keep the URLs recon found (paths, query strings), and agent runs their outcome text | `827b56c` | both above |
| RET-4 | Low | The request log's reasons quote the request and the target's reply, and are kept; one quotes an approved write's URL unredacted | `827b56c`, and the next commit for rows naming only a job | both above, `test_the_gateway_redacts_a_reason_that_quotes_the_request` |
| RET-5 | Low | On a SQLite built without `SECURE_DELETE` (macOS's Python), deleted rows stay readable in the database file | `827b56c` | `test_the_sqlite_database_overwrites_what_it_deletes` |
| RET-6 | Low | Plaintext blobs from before encryption that no evidence cites (a v0.6 agent run's exchanges) are never removed | `827b56c` | `test_encrypt_existing_removes_plaintext_blobs_no_evidence_cites` |
| RET-7 | Medium | The docs say rotating the master key makes a deletion final in old backups; the database half of a backup is not encrypted | `827b56c` (docs) | `test_the_deletion_screen_and_the_backup_tools_say_that_backups_are_not_reached` |

Each of the 9 tests fails on `4e2c6f4` (checked by running the file against an export of that
tree: 9 failed) and passes after `827b56c`. On Postgres they pass too (the SQLite one is skipped).
The worker's pipe deadlock, found in the same pass, is in `CHANGELOG.md` under Fixed (`4e2c6f4`,
two tests in `test_worker.py`).

## Every store, and what deletion does to it

"After" is the state once `vault.delete_content` has run (and, for the quarantine file, the
gateway's next purge, within a minute). **Gone** means no readable copy is left: deleted,
blanked, or encrypted under the engagement key, which is deleted (crypto-shredded).

### Database

| Store | Content in it | Before this review | After |
|---|---|---|---|
| `evidence.summary_enc` (chain v2) | evidence summaries | ciphertext nulled, key deleted | gone |
| `evidence.summary` (chain v1, before 0017) | summaries | kept | **kept by design**: the v1 chain hash covers the text |
| `evidence.uri` | the URL of an exchange, a file name | kept | **kept by design**: chain v1 and v2 commit to it (the deletion screen says so) |
| `evidence.redaction` | counts per kind of what was redacted | kept | kept: no values |
| `observations`, `endpoints`, `leads` | recon output: titles, technologies, URLs, secrets found, lead details | deleted | gone |
| `jobs.log` | tool output, errors, agent turns | replaced by a note | gone, **and a running job's later lines are not kept** (RET-2) |
| `jobs.result` | agent `summary`, `detail`; limits, counts, usage | `summary` removed | `summary` and `detail` removed (RET-3); counts stay |
| `jobs.targets`, `jobs.remaining_targets` | hosts, or URLs from `endpoints` (params, paramclass, jsanalyze, crawl, content, nuclei) | **kept** | reduced to their hosts (RET-3) |
| `jobs` status of a queued or running job | | **kept running** | cancelled (RET-2) |
| `agent_exchanges` | URL, method, status of each request a running agent sent | deleted only when the run ended | deleted with the content (RET-2) |
| `gateway_requests.url` | every URL a tool or agent requested | blanked (EV-6), also for later rows | gone |
| `gateway_requests.reason` | why a request was refused or failed: quotes the request (an approved write's URL, unredacted), the target's malformed reply | **kept** | blanked, also for later rows and for rows that name only one of its jobs; redacted when written (RET-4) |
| `gateway_requests` method, host, port, status, verdict, bytes, account label | | kept | **kept by design**: the record of what was sent |
| `inbox_entries` | URL, label, tool id and time, facts, dismissal reason | blanked (`inbox.wipe`) | gone; host, method, status, hashes stay |
| `import_batches` | file name, creator, refused rows | blanked | gone; counts and the file's hash stay |
| `test_accounts` | session material (sealed), role, hosts | deleted | gone |
| `write_proposals` | sealed request (headers, body), URL, agent's reason, decision note | waiting ones deleted; the others blanked | gone, and an approved write's later outcome no longer writes a reason into the note (RET-4) |
| `checklist_items.na_reason` | why an item is not applicable | kept | **kept by design**: receipts commit to it |
| `receipts` | signed payloads, manifests (hashes, item ids and texts) | kept | **kept by design** |
| `audit_log.change` | before/after of settings, scope, members; test account labels; write methods, hosts and request hashes | kept | **kept by design**: hash-chained, it cannot change, and it is what the history proves |
| `audit_log.texts` (audit record v2, since 0028) | notes on approved/rejected writes and dismissal reasons (redacted); the path typed to confirm a DELETE; test account roles, hosts, header names; import tool names | (kept in `change` before D-058) | **blanked** (follow-up below): the record commits to a salted hash of each, which stays |
| `audit_log.change` of entries written before 0028 (audit record v1) | the same free text, in the record | kept | **kept by design**: the v1 chain hash covers the text; the deletion screen and the deletion's own entry count these entries |
| `engagements`, `assets`, `lanes` | name, scope, policy URL, research header, hosts | kept | **kept by design**: what the report is about |
| `key_log`, `users`, `memberships`, sessions | people and keys | kept | not engagement content |
| Free pages of the SQLite file | bytes of deleted rows and of replaced values | **kept on builds without `SECURE_DELETE`** | overwritten: the engine turns `secure_delete` on (RET-5) |
| Postgres dead rows and WAL | the old row versions | kept until `VACUUM` reuses the space, and in the WAL until recycled | **not reached**, see below |

### Files

| Store | Content in it | Before | After |
|---|---|---|---|
| Blob store, `<blobs>/e/<id>/` | raw evidence, imported requests and responses, agent exchanges, all AES-256-GCM under the engagement key | key and every blob deleted, tombstone written | gone |
| Blob store, flat `<blobs>/<dd>/<sha>` (before 0017), cited by this engagement's v1 evidence only | plaintext evidence | deleted | gone |
| The same, cited by another live engagement's v1 evidence too | | kept | kept: it is that engagement's evidence |
| The same, cited by no evidence (a v0.6 agent run stored every exchange; only those it added as evidence are cited) | plaintext exchanges | **kept for good**: nothing names their engagement | `encrypt-existing` (without `--engagement`) removes them, `status` counts them (RET-6) |
| Blob store temporary files `.<sha>.<pid>.tmp` | a blob being written | in the engagement's folder: deleted with it | the same; the flat store is no longer written |
| Gateway quarantine file `/data/gateway/log-quarantine.jsonl` | request log rows the API refused: URLs and reasons (redacted) | **kept** | the gateway removes the deleted engagements' rows, by engagement or by job, within a minute or at its next start (RET-1) |
| Worker temporary files | `arjun`'s output for the URL being scanned (a `TemporaryDirectory`, removed after each URL); a file naming the gateway's resolver | removed as the job goes | the same. A worker killed during an `arjun` scan leaves that one file in the container's `/tmp` until the container is recreated |
| Tools' own state under the worker's `HOME` | update checks off (`-duc`), `feroxbuster --no-state`; no resume files | none found | the same |

### Memory

| Store | Before | After |
|---|---|---|
| The gateway's queue of unwritten log rows | written later with the URL blanked (EV-6), reason kept | URL and reason blanked |
| The gateway's caches: job rules (2 s), test account headers (2 s), DNS scopes (3 s) | expire within seconds; the API refuses a deleted engagement's accounts and a cancelled job's credential | the same, and the job is cancelled at once |
| A running worker's run (queued rows, the tool's output) | sent to the API and stored | refused (`results`, `agent/exchange`: 409) or answered and not kept (`log`, `finish`) |

## Follow-up, 2026-10-14: the audit log's free text (D-058)

Branch `audit-fieldhash`, from `c2d4d06`. The open item above, "a later record version could commit
to hashes of the free-text fields", was decided by the owner and built:

- **Audit record v2.** An entry whose change carries free text (`auditlog.TEXT_FIELDS`: `after.note`
  of `write.approved` and `write.rejected`, `after.path` of `write.delete_confirmed`, `role`, `hosts`
  and `header_names` of the `account.*` entries, `after.reason` of `import.dismissed`,
  `after.creator` of `import.batch`) commits to `sha256(canonical({field, salt, value}))` per field,
  with a random 128-bit salt, instead of the text. The salt and the text are in `audit_log.texts`,
  outside the hashed bytes; deleting the content sets it to NULL, and the append-only trigger lets
  nothing else change. An entry without free text stays v1.
- **Tests** (`server/tests/test_audit_texts.py`, `test_retention.py`). The canary test now also puts
  the canary into every one of those fields, for both engagements, checks that the audit log holds
  both before the deletion (the positive control), and after it searches every table, the SQLite
  file's raw bytes and the History view: the deleted engagement's canary is nowhere, the other's is
  still there. With the blanking turned off, it fails. Reports made before and after the deletion
  verify with `--require-history`, the seal included; the History tab shows `[deleted]`; the
  verifiers catch an edited text, a changed salt, a text moved to another field, texts given on a v1
  entry, and a v2 entry passed off as v1. The equivalence corpus has 19 more cases (`audit-v2*`).
- **What remains.** Entries written before 0028 are v1 and keep their text: their chain hash covers
  it, and rewriting them would break every receipt and seal over them. The deletion screen says how
  many there are. The texts are plaintext in the database, like `write_proposals` and
  `test_accounts`, so backups made before a deletion and Postgres's dead rows and WAL keep them, as
  below.

## What deletion cannot reach

These are outside what the API can delete. The docs now say so where an owner or an operator
reads them (the deletion screen, `INSTALL.md`, `ENCRYPTION.md`, `tools/backup.sh`,
`tools/restore.sh`).

- **Backups made before the deletion** (RET-7). `blobs.tar.gz` holds the engagement's wrapped
  key and its encrypted evidence: rotating the master key and destroying the old one makes them
  unreadable. `postgres.dump` is not encrypted: it holds in plaintext the recon results, job logs
  and targets, request log URLs and reasons, imported URLs and labels, proposed writes' URLs and
  reasons. Rotation does nothing to it; only deleting the backup does. Restoring a backup made
  before a deletion brings the content back, and the engagement shows no deletion: delete it
  again after the restore. The gateway's volumes are not in the backups.
- **Postgres's files.** A deleted or updated row stays in its table's file as a dead row until
  `VACUUM` reuses the space (autovacuum does so eventually, without zeroing it), and in the WAL
  until the segment is recycled after checkpoints, or for good in a WAL archive. `VACUUM FULL`
  on the tables rewrites them (it locks them meanwhile). A dump made after the deletion holds none
  of it. Not automated: `VACUUM FULL` blocks the API.
- **Disks.** Deleted files and rewritten pages stay on the disk's free blocks until reused (on an
  SSD, also in remapped blocks). Full-disk encryption is the answer there.
- **Container logs.** Docker keeps each container's output (`compose.prod.yml` rotates it at
  10 MB). uvicorn's access log has every API request line, with query strings (an endpoint search
  term, for example); the gateway prints an error message that can quote a target's reply
  (`connection ended by an error`). No request URL is printed on purpose.
- **Browsers and copies people made**: exported reports, downloaded blobs, drafts in a browser's
  `sessionStorage` (EV-8 keeps credentials out of them).
- **The Claude API.** An agent run sends the lane's context and the exchanges' bodies to
  Anthropic's Messages API through the gateway; AttackLedger stores no transcript, and what the
  API keeps is under Anthropic's retention terms.
- **Quarantine rows that name no engagement and no job**: a request with no valid job
  credential. They cannot be attributed to an engagement and stay until an operator removes them.

## Details

### RET-1: the gateway's quarantine file (Low)

- **What:** GW-11 set rows the API could not store aside in the gateway's private volume, and
  said that deleting an engagement's content does not blank them. The rows hold redacted URLs
  and reasons. Only an operator with access to the gateway's volume reads the file.
- **Choice:** purge in place, asked for by the gateway. The API cannot reach the file (it does not
  mount the gateway's volume, by design), and there is no channel from the API to the gateway:
  the gateway is always the caller. Encrypting the rows under the engagement's key would shred them
  with the key, also in copies, but the gateway holds no engagement key (D-042), would need one per
  engagement it logs for, and the file exists for an operator to read with `cat`. The gateway's
  volumes are not backed up, so a purge in place leaves no copy behind.
- **Fix:** `POST /gateway/content-deleted` (gateway token only) takes engagement and job ids and
  answers those whose engagement's content was deleted. The gateway asks about the ids its file
  holds at start and every minute, then, with no await in between (set-aside runs on the same event
  loop), reads the file again and replaces it atomically (mode 0600) without those rows and without
  lines that are not a whole row. Without an answer nothing is removed. A row is now always written
  on a line of its own, so a line cut short by a crash no longer swallows the next row.

### RET-2: a run going on at the deletion (Medium)

- **What:** deletion replaced the job logs and left running jobs running. The worker kept
  appending log lines (`POST /worker/jobs/{id}/log`: tool output, errors with URLs), its finish
  added `error: ...`, and an agent run's finish stored its `summary` again. The gateway still took
  its traffic. Its `agent_exchanges` (the URL of every request) stayed until the run ended. Measured
  with the canary test on `4e2c6f4`: the job's log held two new lines with the canary after the
  deletion.
- **Fix:** deletion cancels the engagement's queued and running jobs (the worker stops the tool at
  its next heartbeat; the gateway refuses the credential within its 2 s cache) and deletes their
  exchanges. For a job whose engagement's content is deleted, `log` is answered and not stored, and
  `finish` stores no lines and no agent summary or detail.

### RET-3: job targets and outcome text (Medium)

- **What:** the parameter, JavaScript, crawl, content and nuclei steps take their targets from
  `endpoints`: full URLs with paths and query strings. Deletion removed the endpoints and kept the
  same URLs in `jobs.targets` and `jobs.remaining_targets`, listed by `GET /engagements/{id}/jobs`.
  An agent run's `detail` (its outcome in a sentence, which can quote an error) stayed too.
- **Fix:** targets become their hosts, in order, once; `summary` and `detail` are removed.

### RET-4: the request log's reasons (Low)

- **What:** EV-6 blanked the URLs and kept the reasons as policy text. Some reasons quote the
  request or the target: an approved write that differs from the approval is refused with
  `write not sent: the request is not the approved one: POST <url> differs` (the URL as the agent
  sent it, not redacted even when the URL column was), and an upstream error with the target's
  malformed reply. An approved write's outcome also copied the reason into the proposal's note.
- **Fix:** deletion blanks reasons with URLs, also for rows that arrive later, for rows the API
  kept without their engagement but with one of its jobs (a placeholder whose engagement id was not
  valid), and in the outcome written to a proposal. The gateway redacts a row's reason as it
  redacts its URL.

### RET-5: SQLite's free pages (Low)

- **What:** SQLite leaves a deleted row's bytes in the file's free pages, and an updated value's
  old bytes in its page, until something overwrites them, unless `secure_delete` is on. Debian's
  SQLite (the Docker image) is built with it on; Python 3.13 on macOS (SQLite 3.49.1) is not, and
  a source install runs on SQLite by default. A copy of the database file then showed deleted
  content.
- **Fix:** `db.make_engine` turns `secure_delete` on for every SQLite connection. The test opens
  its connections with it off, as such a build does, and searches the file's bytes.

### RET-6: uncited plaintext blobs from v0.6 (Low)

- **What:** before 0017 the agent stored every exchange it sent in the flat plaintext store
  (`git show e1ef070:server/app/agenttools.py`, `blobs.put(...)` without an engagement), and only
  those it added as evidence are cited by v1 evidence. Deletion removes the plaintext blobs only its
  engagement's v1 evidence cites, and `encrypt-existing` copies cited ones only. The others are read
  by nothing (AUTH-1) and stayed for good.
- **Fix:** `encrypt-existing` run over every engagement removes the plaintext blobs no v1 evidence
  cites; `status` counts them. A run limited with `--engagement` leaves them.

### RET-7: backups (Medium, documentation)

- **What:** `INSTALL.md` said: "To make a deletion final in the backups too, either keep backups no
  longer than your retention policy allows, or rotate the master key after the deletion and destroy
  the old one", and `ENCRYPTION.md` the same. Rotation covers the blob store's encrypted part only;
  the dump's plaintext rows survive it. Neither `tools/backup.sh` nor the deletion screen said that
  deletion does not reach backups, nor `tools/restore.sh` that a restore brings deleted content back.
- **Fix:** the four places say it, and the deletion screen's "what stays" list has a line on backups.

## Verification

- `server/tests/test_retention.py::test_deleting_content_leaves_nothing_readable_in_any_store`
  seeds a canary (letters only, so redaction leaves it and every encoding spells it the same) into
  every store above for one engagement, and another canary for a second engagement, then deletes
  the first's content, lets its running job log, fail and send a log row, and runs the gateway's
  purge. It searches every row of every table, the SQLite file's raw bytes with its journals, every
  file of the blob store and the quarantine file, and eight API views. Before the deletion both
  canaries are found in the tables, the raw file, the blob store (the plaintext blob; the rest is
  encrypted) and the quarantine file; after it the first is found nowhere, the second everywhere it
  was (the positive control).
- The reply a target sends is quoted by h11's errors (`illegal status line: b'...'`,
  `illegal header line: ...`), which the gateway puts in the reason (`<host> sent no valid
  response: ...`): checked in the h11 the image ships.
- SQLite: 929 passed, 1 skipped (the baseline was 918 passed, 1 skipped). Postgres:
  `tools/test_postgres.sh` PASS (929 passed, 1 skipped, and the migration-0022 upgrade check).
  `tools/release_gate.sh` PASS.
