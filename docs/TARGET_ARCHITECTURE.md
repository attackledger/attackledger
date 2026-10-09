# Target architecture

Status: agreed direction, 2026-10-09 (D-027 to D-030). Nothing here is built yet unless it
says so. `ARCHITECTURE.md` describes what runs today.

## What the product is for

AttackLedger proves what a security test covered. The first users are **pentest teams**
who must show a client what was tested, and the **auditors** who read that proof
(D-028). Bug bounty work stays supported; it is not what the architecture is shaped around.

That focus sets three requirements:

1. A receipt must be trustworthy to someone who does not trust the tester or the tool.
2. Evidence must be able to come from the tools testers already use, not only from
   AttackLedger itself.
3. Different people do different things: someone tests, someone else signs, a client or
   auditor only reads.

## Layers

```
 Interfaces     Web UI · API · CLI (import, verify) · agent tools
                                  │
 Core           Rules ─► Recon ─► Surface ─► Lanes ─► Ledger ─► Receipts ─► Reports
                                              ▲          ▲         │
                                              │          │         ├─ signatures (per person)
                                  Import inbox┘          │         └─ timestamps (RFC 3161)
                                  (adapters: Caido, Burp, nuclei, ...)
                                                         │
 Executors      manual · Claude agent · import           │
                                                         │
 Identity       organization · people · roles · signing keys
                                  │
 Runtime        API · workers · Postgres · blob store · timestamp client
```

Extension points, each a registry with a fail-closed loader, as modules and packs are today:

| Extension | Today | Adds |
|---|---|---|
| Recon modules | `modules.py` | a tool that discovers surface |
| Methodology packs | `packs/*.yaml` | lanes and checklist items |
| Control catalogs | `controls.yaml` | a framework's controls |
| Executors | manual, agent | a way to work a lane |
| Import adapters | (new) | a tool whose output becomes evidence |
| Report formats | JSON, HTML | a client-facing output |

## Domain model

```
Organization ─┬─ Person (roles, signing public keys)
              └─ Engagement (client, statement of work or program policy, test window,
                   │         scope rules, rate limit, identification, authorization)
                   ├─ Asset ─ Lane (pack lane) ─ Item ─┐
                   ├─ Recon jobs ─ Surface (hosts, URLs, leads)
                   ├─ Import batches ─ Inbox entries ──┤ accepted into
                   └─ Ledger: Evidence ◄───────────────┘
                          └─ Receipt (manifest hash, signature, timestamp token)
```

**Roles** (an engagement can grant each one per person):

| Role | Can |
|---|---|
| Owner | manage the organization, people and engagements |
| Tester | run recon, work lanes, attach and import evidence |
| Reviewer | sign receipts (close lanes) |
| Viewer (client, auditor) | read the coverage, evidence and reports; verify them |

**Separation of duties** is a per-engagement setting: when it is on, the person who
attached a lane's evidence cannot sign its receipt. Auditors look for this.

## Trust model (D-027)

Today a receipt is a hash of the lane's manifest, written into the tester's own database.
Anyone with database access could rewrite history and recompute it. The target makes each
receipt verifiable without trusting the database, the server or the tester:

1. **Evidence chain** (built). Every entry links to the previous one by hash.
2. **Signed receipts.** The reviewer signs `{manifest hash, lane, engagement, signer id,
   signed at}` with a key that only they hold.
   - The private key is created in the reviewer's browser (WebCrypto, non-extractable,
     Ed25519 where supported, otherwise ECDSA P-256) and never reaches the server. The
     server stores only the public key, registered to the person. Nobody who runs or
     administers the server can forge a signature made with someone's key.
   - A lost key is replaced by registering a new one; signatures made with the old key
     stay valid, because the report carries the public key that made them.
   - **Key registration is the weak point, so it is logged (D-036).** Whoever could sign
     in as a person could register a new key in their name and sign with it. Through the
     application, nobody sets another person's password: an owner sets only the first one
     when adding someone, the person changes it with their current password, and a
     forgotten one is reset on the server. Whoever has shell or database access to the
     server is still the root of trust and could reset a password, sign in and register
     a key. What they cannot do is make that silent:
     - every key registration and revocation is an entry in an append-only, hash-chained
       key log, recording the person, the fingerprint, the time and how it happened
       (the person's own session, a session with a password someone else set, or the
       operator on the server);
     - the person sees keys registered or revoked for them since their previous sign-in,
       and can revoke one they did not make;
     - every report carries the key log entries of each key that signed it, with the chain
       links up to the head, and `verify_report.py` checks that each key was registered to
       its signer before the receipt was issued and not revoked before it. Hiding or
       backdating a key means rewriting or reordering the log, and every report already
       issued carries the log's head at the time, so comparing them shows it.
   - For high assurance, the reader compares each signer's key fingerprint with the one
     the signer gives them through a channel they trust. That check does not depend on
     the server at all.
   - **Administrative changes are logged too (D-037).** Scope and rules, authorization,
     engagement settings, roles and people (added, renamed, owner, disabled, password set
     or reset, never the password) are entries in a second hash-chained log, written in
     the same transaction as the change. Reports carry their engagement's entries and the
     person events of its signers and members; the verifier says which scope was in force
     when each receipt was issued and fails a receipt whose signer did not hold the
     reviewer role (and was not an owner) then, or had another name. The signed payload
     (`attackledger-receipt-v3`) names the signer's email as well as their name, so
     renaming an account to look like someone else does not make their signature.
3. **Timestamps.** Each signature is sent, as a hash only, to an RFC 3161 timestamp
   authority. The token proves the receipt existed at that time and was not changed
   afterwards. The authority is configurable; no evidence content leaves the deployment.
4. **Self-verifying report.** The report bundles the chain, receipts, signatures, public
   keys and timestamp tokens. `verify_report.py` checks all of them offline, including the
   timestamp authority's certificate chain.

What it does not prove: that the tests themselves were good. It proves what was recorded,
by whom, and when, and that nothing changed afterwards.

## Evidence import (D-029; deferred, D-035)

Deferred until after the first release. The design below stands; notes from a first look
at Caido's formats are at the end of this section.

Testers already work in Caido, Burp and scanners. Import lets their output become evidence
without changing how they work.

```
export or API ─► adapter ─► scope check ─► dedupe ─► inbox ─► person maps to items ─► ledger
                  (parse)    (out of scope   (content   (per          (with suggestions)   (source:
                              rows refused   hash)      engagement)                         import:caido)
                              and listed)
```

- **Adapter contract.** An adapter turns one export (or one API pull) into entries:
  host, URL, method, status, raw request and response bytes, the tool's own id and time,
  and the tool's label (finding name, template id). Adapters only parse; they never send
  traffic.
- **Scope check.** Entries for hosts outside the engagement's rules are refused and
  listed, never stored.
- **Inbox.** Imported entries wait in the engagement's inbox. A person maps each to a
  checklist item (or several), with suggestions from simple rules such as a nuclei
  template tag or a Caido finding class. Nothing reaches the ledger without that step.
- **Provenance.** Evidence gains a `source` field: `manual`, `recon`, `agent` or
  `import:<tool>`, committed in the chain. This is a change to the chain record, so the
  chain format gets a version and the verifier reads both versions.
- **Caido first.** It is the tool Murat uses. Two ways in, to be confirmed against
  Caido's current export format and API before building: an export file, or a pull through
  Caido's local API with the user's own token.

**Setup, not code.** Integrations are configured by each operator when they install
AttackLedger: their own tool URL and token, kept only in their deployment's settings,
read by the worker, and never written to the ledger, reports or logs. Importing an
export file needs no token at all, so that path comes first.

**Caido notes** (public docs and schema, 2026-10-09; recheck before building):
- HTTP history exports as JSON or CSV from the UI (Export, then the Exports page) or through
  the GraphQL API (`startExportRequestsTask`, then `dataExport` for a download link). JSON
  rows carry `host`, `port`, `is_tls`, `method`, `path`, `query`, `created_at` (epoch ms),
  `raw` (base64) and a `response` with `status_code` and its own `raw`. Raw bytes are only
  present if the export includes them.
- Findings export as JSON; the exact layout was not confirmed from public sources.
- The local API is GraphQL at the instance address with `Authorization: Bearer <token>`;
  Caido says its schema may change between releases.
- Captured traffic holds cookies and Authorization headers. They must be redacted or
  flagged before anything enters an append-only ledger.

## Deployment (D-042: self-hosted, with a public verifier page)

AttackLedger runs on the customer's own servers; the only hosted part is a verification
page on attackledger.com that checks a report in the browser without uploading it. What
keeps this possible:

- The worker, which sends traffic to targets, is separate from the API and the ledger.
  A deployment can run workers only inside the customer's network.
- The ledger and the verifier do not depend on the worker. A future hosted service could
  store and timestamp receipts and serve reports without ever sending traffic to a target.
- Multiple workers need a shared rate limiter per engagement before they run in parallel.

## Order of work

1. **Identity and roles.** People, roles, sign-in. Signatures need an identity first.
   Built 2026-10-09 (D-032).
2. **Signed and timestamped receipts.** Browser keys, timestamp client, chain and report
   format version 2, verifier update.
   Signatures built 2026-10-09 (D-033); timestamps built 2026-10-09 (D-034).
3. **Client and auditor views.** A client-facing report and a read-only viewer role.
   Built 2026-10-09: the HTML report for clients, a role-aware web app and a Verify tab.
4. **Deployment decision.** Decided 2026-10-09 (D-042).
5. **Traffic gateway** (D-039): the worker loses direct egress; one gateway enforces rate,
   methods, scope and identification for every tool and agent, and logs every request.
6. **Test accounts and approved writes** (D-040, D-041): credential injection at the
   gateway; an approval queue for agent-proposed writes.
7. **Encryption and retention** (D-043): per-engagement keys, retention by key deletion.
8. **Public verifier page** (D-042) on attackledger.com.
9. **Keep SaaS possible** (D-042): an organization id on every record; the worker reaches
   the API over an authenticated channel, not the database.

Later (D-035): the import inbox and adapters for Caido, Burp and nuclei. Each is an
optional integration that an operator turns on at setup with their own credentials.

Agent work continues alongside under D-024 (amended by D-041) and D-025.
