# Encryption at rest and retention (D-043)

Status: built on branch `feat/encryption`, migration `0018`. This page records the design
choices; the code is `server/app/vault.py`, `server/app/blobs.py` and `server/app/ledger.py`.

## What is encrypted

| Content | Where | At rest | When the engagement's key is deleted |
|---|---|---|---|
| Raw evidence: HTTP exchanges, notes, attached files | blob store | AES-256-GCM, engagement key | key, blobs and the engagement's folder are deleted |
| Evidence summary (chain v2 rows) | `evidence.summary_enc` | AES-256-GCM, engagement key | ciphertext set to null; `summary_sha256` stays |
| Evidence summary (chain v1 rows, written before 0018) | `evidence.summary` | plaintext | **kept**: the v1 chain hash covers the text itself, so removing it would make the chain unverifiable; reports issued before already carry it |
| Recon results: observations, endpoints, leads | their tables | plaintext | **deleted** |
| Job logs, an agent run's closing summary | `jobs.log`, `jobs.result.summary` | plaintext | **replaced** by a deletion note |
| Evidence URI (`evidence.uri`) | evidence row | plaintext | kept: the chain record (v1 and v2) commits to it |
| Item N/A reasons | checklist items | plaintext | kept: the receipt manifest commits to them |
| Hosts, lane roles, hashes, receipts, signatures, timestamps, key log, audit log | | plaintext | kept: they are what a report verifies |

Why recon results are not encrypted at rest: they are filtered and searched in SQL (host,
URL substring, lead kind), the recon view lists them in bulk, and they are recon metadata
rather than captured exchanges; redaction (D-038) already applies to them. They are not part
of any chain or receipt, so retention can simply delete them. Encrypting them is possible
later without a format change.

Why the URI stays: the chain record v2 is a shared contract (`uri` plaintext). Agent URIs
are redacted before storage (D-038). A later record version could commit to `uri_sha256`
instead; that is not in the MVP.

## Keys

- **Master key.** One per deployment, 256 bits. Read from `ATTACKLEDGER_MASTER_KEY_FILE`
  (a file holding the key as base64 or 64 hex digits), or, when that is not set, from
  `ATTACKLEDGER_MASTER_KEY`. If the file variable is set but the file cannot be read or is
  not a 256-bit key, startup fails: it never falls back to the other variable.
  `python -m app.vault generate` prints a new one.
- **Development key.** `ATTACKLEDGER_DEV_KEY=1` uses a built-in key whose value is public
  (it is in the source code). It is for tests, local trials and the demo, and gives no
  confidentiality. A configured master key wins over it. `/health` says which is in use.
- **Fail closed.** With no master key and no `ATTACKLEDGER_DEV_KEY=1`, the API and the
  worker refuse to start, and so do the CLI commands that need a key.
- **Engagement data key.** Random 256 bits per engagement, created the first time the
  engagement stores encrypted content. It is stored wrapped (AES-256-GCM under the master
  key, the engagement id as associated data, so a key file copied to another engagement
  does not open) in the blob store, at `<blobs>/e/<engagement id>/key.json`, next to the
  blobs it protects. The file names the master key's id (a hash of the key, not the key).
- **Why in the blob store and not the database.** The blob store's interface
  (`put/get(..., engagement_id=)`) has no database session, and the API and the worker
  share the folder. Keeping the key there means the store needs nothing else to encrypt or
  decrypt, and deleting one engagement's folder deletes its key and blobs together without
  touching any other engagement. Consequence for backups: the database and the blob store
  must be backed up together (they always had to be; the evidence is in the blob store).
- **One user for the blob store.** The API and the worker both run as uid 10001, because
  each reads the keys and writes into the engagement folders the other made. A blob volume
  from an earlier version holds folders made by the API as root; give it to that user once
  when upgrading: `docker compose run --rm --user 0 --no-deps api chown -R 10001 /data/blobs`.
- **Startup checks.** The API and the worker check that they can write to the blob store,
  that every key file was wrapped by the configured master key, and the API checks that every engagement with encrypted
  summaries still has its key file (unless its content was deleted). Either failing stops
  startup with the fix in the message, so a wrong key or an unmounted volume never looks
  like deleted content.

### Rotating the master key

1. Generate the new key and keep the old one: `python -m app.vault generate > new.key`.
2. Stop the worker. Point the API's configuration at the new key.
3. Re-wrap every data key: `python -m app.vault rotate-master --old-key-file old.key`
   (or `--old-dev-key` when moving off the development key). It re-encrypts each
   `key.json` under the new master key; the content itself is not re-encrypted, because
   only the data keys depend on the master key. It is safe to run again: files already
   under the new key are skipped, files under neither key are reported and fail the command.
4. Start the API and the worker with the new key. Destroy the old key once backups made
   with it are no longer needed.

Rotation is also what finishes a deletion in old backups: a backup of the blob store still
holds the wrapped key of an engagement deleted since. Without the master key it was
wrapped with, that copy is useless, so after deleting content that must not survive in
backups, rotate the master key and destroy the old one.

## Blobs

- `blobs.put(data, engagement_id=N)` returns the sha256 of the **plaintext** (the digest
  the chain commits to, unchanged in meaning) and stores
  `b"ALE1" + nonce(12) + AES-GCM(data)` at `<blobs>/e/N/<dd>/<digest>`, with the
  engagement id and the digest as associated data: a file moved to another name or another
  engagement does not decrypt.
- `blobs.get(digest, engagement_id=N)` decrypts and checks the sha256 again; a wrong key,
  a tampered file or a mismatch returns `None`. For an engagement whose content was
  deleted it returns `None`; `put` raises `ContentDeleted`.
- Without `engagement_id`, both behave as before 0018 (plaintext, `<blobs>/<dd>/<digest>`).
- `get(..., engagement_id=N)` falls back to that plaintext location for blobs written
  before 0018, so old evidence opens as before.

## Existing data

Rule: **new content is always encrypted; content stored before 0018 stays as it was until
an explicit command encrypts it.**

- Old evidence rows stay chain v1, with their plaintext summary (see the table above).
- Old blobs stay plaintext in the flat store until
  `python -m app.vault encrypt-existing [--engagement N]` copies each blob that an
  engagement's evidence cites into that engagement's encrypted folder, checks it, and
  removes the plaintext copy once every engagement that cites it has its own encrypted copy.
  It can be run again; it reports what it did.
- `python -m app.vault status` lists, per engagement, encrypted and plaintext blobs,
  encrypted and plaintext (v1) summaries, and whether the content was deleted.
- Deleting an engagement's content also deletes plaintext blobs that only that engagement
  cites.
- Old reports verify as before: their entries carry no `v` and are checked as v1.

## Retention and deletion

- **Delete now.** An owner opens the engagement's Settings, chooses "Delete this
  engagement's data", sees what will be deleted and what stays, and confirms by typing the
  engagement's name. The API (`POST /engagements/{id}/content/delete`) refuses unless
  `confirm_name` equals the name exactly. It cannot be undone.
- **Delete after a date.** An owner sets "Keep the content until" (a UTC date,
  `PATCH /engagements/{id}` with `retain_until`). The worker checks once a minute and
  deletes the content of every engagement whose date has passed (the day after it). No date
  means the content is kept until someone deletes it. The decision's default of one year
  after an engagement closes needs an engagement close event, which does not exist yet; a
  date is the MVP.
- **What deletion does**, in this order: in one database transaction it records who and
  when (`content_deleted_at`, `content_deleted_by`, `content_deleted_reason`), nulls the
  v2 summary ciphertexts, deletes recon results, replaces job logs, and appends an audit
  log entry (`engagement.content_deleted`, by the person or by "the retention policy");
  then it writes a tombstone in the engagement's folder, deletes the key file and every
  blob in the folder, and deletes plaintext blobs only this engagement cites. If the
  process stops between the two steps, the worker finishes the file step on its next pass.
- **Afterwards** the engagement takes no new evidence, jobs or agent runs, and no new
  receipts, because nobody can review evidence that can no longer be read (refused with a
  message, not an error). Receipts issued before stay valid. Its lanes, items, receipts, hashes and audit history stay; every
  evidence entry shows "Content deleted on <date> by <who>". `GET /blobs/{sha}` answers
  410 with the same sentence. Nothing answers 500.
- **Retention date changes** are audit log entries (`engagement.retention`).
- **CLI.** `python -m app.vault delete-content --engagement N` does the same as the owner
  action, recorded as "the operator on the server", for an operator (for example when a
  key file was lost and the API refuses to start).

## Evidence chain record v2

Rows written before 0018 keep the v1 record (nine fields, no `v`). New rows:

```
{"v": 2, "seq", "lane_id", "host", "role", "item_id", "kind", "sha256", "uri",
 "summary_sha256": sha256(summary utf-8) hex,
 "source": "manual" | "recon" | "agent" | "import:<tool>"}
chain_hash = sha256(prev_hash + canonical(record))
```

`canonical` is JSON with sorted keys, no spaces, `ensure_ascii=False`, as for v1. A v1 and a
v2 row can follow each other in one chain. A v2 row cannot be turned into a v1 row, or the
other way round, because `v` and the summary hash are inside the hashed record.

Sources at the existing call sites: `POST /lanes/{id}/evidence` and `POST /lanes/{id}/attach`
(note, file or a recon run a person attaches): `manual`; the worker's recon run evidence:
`recon`; the agent's `add_evidence` tool: `agent`. The evidence import uses `import:<tool>`.

### In the report

Each v1 evidence entry is unchanged. Each v2 entry is:

```
{"id", "v": 2, "seq", "lane_id", "host", "role", "item_id", "kind", "sha256", "uri",
 "summary_sha256", "source", "summary": "<text>" | null,
 "created_at", "prev_hash", "chain_hash"}
```

`summary` is null when the engagement's content was deleted (or, rarely, when the stored
ciphertext no longer opens). The report's `engagement` object gains:

```
"retain_until": "YYYY-MM-DD" | null,
"content_deleted": {"at": "<ISO 8601>", "by": "<name (email)> | the retention policy",
                    "reason": "owner" | "retention" | "operator"} | null
```

The report format stays `attackledger-report/2`; readers that ignore unknown keys read it.

### What the verifier does

- Rebuilds the v1 record for entries without `v`, the v2 record for `v: 2`, and fails any
  other `v`.
- For a v2 entry with a summary, fails the chain check if `sha256(summary)` is not
  `summary_sha256`.
- For a v2 entry whose summary is null, still checks the chain and adds a NOTE:
  "N evidence entries: content unavailable (key deleted on <date> by <who>)".
- Receipt payload formats are unchanged; manifests never contained summaries.
