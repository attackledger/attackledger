# Organizations: every record belongs to one (D-042)

Status: built 2026-10-10, migration `0022`. This is the "keep SaaS possible" half of D-042
that was still open; the other half, the worker talking to the API instead of the database,
is in `WORKER_API.md`.

A self-hosted install is one organization. It is made by the migration, it needs no setting,
and nothing in the app shows it. Everything below matters only for a hosted service later,
where one deployment would hold several customers.

## The rule

Every tenant-owned row belongs to exactly one organization, and every API request sees one
organization's rows only: its caller's. Another organization's engagement, lane, job,
person, key, import entry, test account, proposed write or blob does not exist for the
caller. The API answers 404, with the same body as for an id that was never used, never 403.

## Design

### Scoped in one place, not per route

`server/app/orgscope.py` does it for the whole application, on the SQLAlchemy session:

- **The filter.** A session carries its organization in `session.info`. While it does, every
  ORM `SELECT`, `UPDATE` and `DELETE` gets `organization_id = <the session's>` for every table
  owned directly, wherever the table appears: `session.get`, lists, counts, joins,
  subqueries, bulk updates and deletes (`with_loader_criteria`, added in `do_orm_execute`).
  A route cannot forget the filter, because no route writes it.
- **New and changed rows.** Before each flush, every new row takes its organization from its
  parents (each foreign key to a tenant-owned row) and the session. A row whose parents belong
  to two organizations, or to another one than the session's, is refused (`TenancyError`),
  also in the operator's own sessions, and so is changing a row's parent to another
  organization's. No row ever points across organizations.
- **Three states.** No organization: the operator's sessions (command line, the API's
  maintenance thread, migrations, tests), not filtered. *Pending*: a request whose caller is
  not known yet; any query raises. An id: a request for that organization.
- **Who sets it.** `authz.authorize`, the dependency every route runs first, marks the session
  pending, finds the caller and scopes the session to the caller's organization:

  | Caller | Organization |
  |---|---|
  | A person (session cookie) | their own (`users.organization_id`) |
  | The operator token, open mode | the default organization |
  | The worker token | the deployment's token file: the default organization; a token from `python -m app.orgs worker-token`: that organization |
  | A job token | the job's |
  | The gateway token | as the worker token, with `gateway-token` |

  Sign-in and sign-out run before the caller is known, so they read explicitly without the
  filter (`orgscope.unscoped`): sign-in to find the account by its email, sign-out to find the
  session by its cookie's hash. After sign-in the session is scoped to the account's
  organization. Three other places ask a question of the whole deployment, and say so:
  whether anyone has an account yet (it decides the sign-in mode), which plaintext blobs
  another engagement still cites before one is deleted (the plaintext store is shared), and
  the number of organizations (below).
- **404, not 403.** `authz._engagements` now looks the engagement up through the scoped
  session too (before, it trusted the id in the path), so another organization's engagement is
  "not found" before any route runs, for owners as well. The permission table is unchanged; on
  owner-only routes a non-owner gets 404 for an engagement they have no role on or a person
  not in their organization, and 403 only for what they can see.

### Owned directly or through a parent

Seventeen tables carry `organization_id` (`models.OrgOwned`), five reach it through a parent
(`orgscope.THROUGH`), and a test fails if a table is in neither list.

| Table | Owned | Why |
|---|---|---|
| `organizations` | (the owner) | |
| `engagements` | directly | the root of almost everything; listed and named by id. Names are unique per organization |
| `users` | directly | people belong to one organization; listed by owners, named by id. Emails are unique per organization |
| `memberships` | directly | they join a person and an engagement, which must be of the same organization; the column makes the check and the filter one rule |
| `assets` | directly | named by id in a request body (`POST /lanes`), so a lookup must be filtered |
| `lanes` | directly | named by id in paths; `authz` resolves them before the route runs |
| `checklist_items` | through `lanes` | only ever reached as `lane.items`, by index; never listed alone |
| `evidence` | directly | its hash is looked up across engagements (`GET /blobs/{digest}`); without the column the lookup would find another organization's evidence |
| `receipts` | through `lanes` | reached as `lane.receipts`; the history and reports reach them by lane |
| `jobs` | directly | named by id in paths and bodies; the worker's claim takes "the oldest queued job", which must be its organization's |
| `observations`, `endpoints`, `leads` | directly | recon results: listed per engagement, and the worker writes them; the column keeps a hosted service's largest tables filterable without joins |
| `agent_exchanges` | through `jobs` | read and written only through one running job's own token; deleted when the job ends |
| `test_accounts`, `write_proposals` | directly | named by id in paths (`account_id`, `pid`) |
| `import_batches`, `inbox_entries` | directly | named by id in paths, bodies and the `batch` filter |
| `gateway_requests` | directly | a refused request may have no engagement or job at all; it still belongs to the gateway's organization |
| `signing_keys` | through `users` | a person's own keys; the fingerprint stays unique in the deployment (below), so the receipt check finds exactly one key |
| `user_sessions` | through `users` | found by the cookie's hash before the organization is known; that lookup is what decides it |
| `key_log`, `audit_log` | directly | one hash chain per organization, keyed `(organization_id, seq)` |

Through-parent tables get the same parent check on every new row, so a lane's item, a job's
exchange or a person's key can never be another organization's.

### The key log and the audit log: one chain per organization

Each organization has its own key log and audit log, each from the same genesis value with
its own head, keyed `(organization_id, seq)`; appends lock per organization
(`pg_advisory_xact_lock(7036 or 7037, organization)`).

- **Why per organization.** A report carries the chain links from its first entry to the
  head. With one chain for the deployment, every report would carry other customers' heads and
  sequence numbers, and so how much they did and when. Per organization, a report shows only
  its own organization's chain. (The suggestion in the task; built so.)
- **The records do not change.** No organization field enters a record, so nothing is
  versioned, and the verifiers did not change. The default organization's chain is the
  deployment's chain as it was, with the same sequence numbers and hashes: reports issued
  before 0022 still verify, and new entries continue them (the migration test checks both).
  Which organization a chain belongs to is where it is kept, not what it says, as an
  engagement's evidence chain does not name its engagement in each record.
- **Considered:** one global chain with an organization field (leaks heads, and changes every
  record); a genesis value derived from the organization (a reader has no independent source
  for it, it would change both verifiers, and the default organization's chain could not
  have it). Rejected.
- `auditlog.verify` and `keylog.verify` check the session's organization, or, for the
  operator, every organization's chain in turn; `python -m app.people audit-log` and `key-log`
  list and check each.

### Reports and the verifiers

The report format is unchanged (`attackledger-report/2`). `keylog.for_report` and
`auditlog.for_report` take the engagement's organization explicitly, so a report built from
an unscoped session (the command line) still carries one organization's chain only.
`tools/verifier_equivalence/cases.json` has four new cases, made by `make_org_fixtures.py`: the
report issued at 0021, the same engagement's report after 0022, a second organization's
report, and that report with the default organization's audit head put in (fails *Change
history* in both verifiers). `run.sh`: 72 reports, 107 building-block cases, 0 differences.

### Names, emails and sign-in

- Engagement names and emails are unique per organization, so creating one does not reveal
  that another organization uses the same name or email.
- An email may therefore have an account in two organizations. Sign-in checks the password
  against every account with that email (all of them, so the time does not say which
  matched) and signs in the one whose password matches. Two accounts with the same email and
  the same password sign in to the older one; a hosted service would add an organization to
  the sign-in form or per-organization addresses.
- Signing key fingerprints stay unique for the deployment. Registering a public key that is
  registered already answers 409 whoever's it is; a public key is in every report it signed,
  so this reveals nothing a reader of that report does not have.

### Blobs and encryption keys

- Engagement keys (D-043) are already per engagement, under the engagement's id, which is
  unique in the deployment. Nothing changed.
- Plaintext blobs predate encryption (0018) and organizations, so they are the default
  organization's. Evidence names its hash as the caller gives it, so another organization's
  evidence citing the same hash would have read them; `blobs.get(..., plaintext=False)` is now
  used for engagements of other organizations.
- **The master key, later (not built).** Today one deployment master key wraps every
  engagement key. Per organization, each organization would get its own key-encryption key,
  wrapped by the master key (or held in that customer's KMS); engagement keys would be wrapped
  by their organization's key, and the wrap's associated data would name the organization as
  well as the engagement. Destroying an organization's key would then make all its content
  unreadable at once, and rotation could be done per customer. `vault.py`'s key file already
  records which master key wrapped it, so a per-organization key id fits the same field.

### The web app

Nothing new while the deployment has one organization. With more than one, `/auth/me` adds
`organization: {id, name}` and the app shows "Signed in as … of …". (That one fact, that the
deployment has more than one organization, is the only thing a caller learns about the
others.) Owners administer their own organization; there is no role above them and no screen
for organizations.

### On the server

```sh
docker compose exec api python -m app.orgs list
docker compose exec api python -m app.orgs create --name "Example Bank"
docker compose exec -it api python -m app.people create --org "Example Bank" --owner --email you@example.com --name "Your Name"
docker compose exec api python -m app.orgs worker-token --org "Example Bank"    # printed once
docker compose exec api python -m app.orgs gateway-token --org "Example Bank"
```

`--org` takes an id or the exact name; without it, `people create` uses the default
organization, and `set-password` and `revoke-key` ask for it only when the email has an
account in more than one.

## Upgrading (migration 0022)

- **Up.** Creates `organizations` with the default organization, adds `organization_id` to
  the seventeen tables, fills it with the default organization's id, makes it `NOT NULL` with
  a foreign key and an index, and turns the four deployment-wide unique constraints into
  per-organization ones. On SQLite, thirteen tables get the column in place with the default
  organization's id as the column default (SQLite cannot add a `NOT NULL` foreign key column
  otherwise; the application always sets the value), and the four tables whose unique
  constraint changes are rebuilt. Constraint names are Postgres's own (`<table>_<columns>_key`,
  `_fkey`) on both.
- **Down.** Restores 0021 exactly, and refuses while there is more than one organization,
  whose names, emails and chain positions could then collide.
- **Measured.** Postgres 16 (Colima on a Mac), 1,000,000 gateway log rows and 500,000
  endpoints on top of the fixture: 7.6 seconds for the upgrade.
- **Tested with data, both databases** (`tests/test_org_migration.py`). The fixture is a
  database at 0021 filled through the 0.7.1 API by `tests/orgfill.py` (people, roles, scope,
  an engagement with every kind of evidence, a signed receipt, recon results, an import, a test
  account, an agent run with an exchange and a proposed write, gateway log rows: every table
  has rows), with the report that API issued. The test upgrades it and checks: one
  organization; every row in it; no row lost; the chains byte for byte as they were and
  intact; the old report verifies and its heads are in the upgraded chains; the owner signs
  in and sees the same engagement; a new change continues the audit chain from the old head; a
  new report verifies with the same evidence chain; downgrade is refused with two
  organizations, then restores the 0021 schema and data; upgrading again works. On Postgres:

  ```sh
  # a database at 0021: the code before this change, filled by the same script
  DATABASE_URL=postgresql+psycopg://... python tests/data/org-migration/make_fixture.py OUT
  # then, with this change
  ATTACKLEDGER_TEST_PG_URL=postgresql+psycopg://... ATTACKLEDGER_TEST_PG_FIXTURE=OUT \
    python -m pytest tests/test_org_migration.py
  ```

  A fresh Postgres database also migrated to 0022 with no difference from the models, down to
  the base and up again.

## Tests (`tests/test_organizations.py`)

Two organizations are filled through the API with the same script; organization 1's names,
hosts and texts carry a marker. They run on SQLite, and on Postgres with
`ATTACKLEDGER_TEST_PG_EMPTY_URL` set to a database they may empty (all 16 pass on both).

- **The walk.** Every route in `authz.RULES` (the test fails if the table and the routes
  differ), called by organization 2's owner and by a member with every role, with organization
  1's real ids in the path, and with organization 2's own engagement or lane and organization
  1's ids for the rest. Every call answers 404, shows no marker, and answers exactly as the
  same call with never-used ids (status and body). Organization 1's rows, direct and through
  parents, are hashed before and after: nothing changed. Then, as the positive control, the
  same ids reach every route for organization 1 (a body that does not validate stops writes
  before they run). The gateway, worker, job and public routes are the only ones left out, by
  name, and have their own tests.
- **Ids in bodies and queries** (an asset in `POST /lanes`, a person in the members list, a
  job attached as a run, inbox entries and lanes in map, dismiss and restore, the `batch` and
  `job_id` filters, a key fingerprint for a receipt): the same answer as a never-used id.
- **Lists and counts.** Every `GET` route with organization 2's own ids shows no marker; the
  audit log's head is organization 2's own count; people, engagements and keys are its own.
- **Rows that would join two organizations** are refused, also in the operator's session;
  a query before the caller is known raises.
- **Worker and gateway.** Each worker token claims only its organization's jobs (also an
  outside driver's run by id), the claim carries `organization_id`, job tokens open their own
  job only, results land in the job's organization; a gateway token gets 404 for another
  organization's job credential (also for test accounts and approvals), its own DNS scopes,
  and log rows naming another organization's engagement or job keep neither and stay its own.
  Without any token the channels answer 503.
- **Chains.** Each organization's key log and audit log start at 1 from the genesis value and
  verify; reports from both verify with `verify_report.py`, carry nothing of the other and
  share no link; tampering breaks only that organization's chain.
- **One organization** shows nothing new (`/auth/me` has exactly the fields it had); names and
  emails are per organization, and the same email signs in to the account whose password
  matches.

Mutations checked by hand: with the filter off, six tests fail; with the old `authz` lookup
(trusting the engagement id), the walk fails; with the worker token mapped to the wrong
organization, the fixture cannot even be filled.

## What a hosted service would still need

- **Public ids.** Ids are deployment-wide sequences, so an organization can infer from the gaps
  roughly how many engagements, lanes or jobs other organizations made. Reports and signed
  payloads carry these ids, so changing them means a new payload and report version: random
  public ids, or numbering per organization.
- **Sign-in per organization:** an organization in the sign-in form or per-organization
  addresses; failed sign-ins are counted per email and address for the whole deployment, so
  one customer could slow another's sign-in by failing on their email.
- **Per-organization encryption keys** (above), and per-organization retention and deletion of
  a whole organization.
- **Database-level isolation as a second layer:** Postgres row-level security on
  `organization_id`, with the session setting it per request, would hold even for a raw query.
  Today the guarantee is the ORM's: there is no raw SQL on tenant tables in the application.
- **Several workers per organization, TLS between gateway and API, quotas per organization**
  (rate ceilings are per engagement), and the operational work D-042 lists: backups per
  customer, monitoring, data processing agreements, certification, billing.
- **Health and mode** (`/health`) describe the deployment, not the organization.

## Deliberately not built

- Any UI for organizations, and any role above an owner: organizations are made on the
  server only (`python -m app.orgs`).
- A per-organization master key (design above).
- Moving or merging rows between organizations, and deleting an organization.
- Changes to the report format or the verifiers: none were needed.
