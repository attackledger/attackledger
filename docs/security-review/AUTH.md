# Security review: authentication, sessions, authorization and tenant isolation

Date: 2026-10-10. Branch `sec-review-auth`, from `c3557a5` (0.8.0 plus ops fixes).
Method: a white-box reading of the code, then a failing pytest (FastAPI `TestClient`, SQLite) for
each suspected issue. A fix was made only when the test failed first. Every fix keeps its test as a
regression test in `server/tests/test_security_review_auth.py`. No live stack was used and no
traffic left the machine.

Test suite: 758 passed and 1 skipped before; 762 passed and 1 skipped after (4 new tests).

## Findings

| ID | Severity | Finding | Fix commit | Regression test |
|---|---|---|---|---|
| AUTH-1 | Low | A cited hash opened another engagement's pre-encryption blob, and kept it after that engagement's content was deleted | `ec778ee` | `test_auth1_citing_a_hash_does_not_open_another_engagements_plaintext_blob` |
| AUTH-2 | Low | Changes sent by a page of another origin were accepted: a sibling subdomain (same site) with the session cookie, or any web page in open mode | `0859dbc` | `test_auth2_a_page_of_another_site_cannot_change_anything`, `test_auth2_open_mode_refuses_another_sites_page_too` |
| AUTH-3 | Low | Separation of duties ignored who imported a lane's evidence | `cff4cc8` | `test_auth3_whoever_imported_a_lanes_evidence_cannot_sign_it` |
| AUTH-4 | Info | `hmac.compare_digest` raises on non-ASCII bearer tokens and cookies (500, not a bypass) | not fixed | none |
| AUTH-5 | Info | On SQLite, using an approval does not lock the row | not fixed (Postgres locks it) | none |
| AUTH-6 | Info | The token-mode cookie is a fixed HMAC of the token, so signing out does not revoke it | not fixed (by design) | none |
| AUTH-7 | Info | A malformed signed payload gives a 500 instead of a 422 | not fixed | none |

No Critical, High or Medium issue was found. Organization isolation (D-042) held everywhere I
looked; the details are under "Checked and sound".

### AUTH-1 (Low): a cited hash opened another engagement's pre-encryption blob

**What.** `POST /lanes/{id}/evidence` records any SHA-256 the caller gives, without bytes.
`GET /blobs/{digest}` serves the bytes of a hash that evidence on a readable engagement cites. It
first tries the engagement's own encrypted copy, and then, for the default organization, the shared
plaintext store from before encryption (`_plaintext_ok`). So a tester on engagement X could cite the
hash of a plaintext blob that only engagement Y's old (chain v1) evidence cites, and read Y's bytes
without any role on Y. There were two more effects:

- `python -m app.vault encrypt-existing` copied the blob into X's encrypted store.
- Deleting Y's content, by an owner or by retention (D-043), kept the plaintext blob, because X
  "still cited" it. The bytes stayed readable through X after Y's deletion.

**Preconditions.** The tester role on some engagement in the default organization; plaintext blobs
from before migration 0017 still in the store (an install upgraded from before encryption that has
not run `encrypt-existing`, or a blob still shared with another engagement); and the blob's SHA-256.
A tester without access to Y has no ordinary way to learn the hash, which is why this is Low and
not higher. Other organizations were already blocked from the plaintext store.

**Reproduction** (the test does exactly this): store `blobs.put(secret)` and a v1 evidence row on
Y citing it. As Tess (tester on X only), `GET /blobs/<sha>` gives 404. Then
`POST /lanes/<X lane>/evidence {"sha256": "<sha>", "kind": "note", ...}` gives 201, and
`GET /blobs/<sha>` gives 200 with Y's bytes.

**Fix.** Only chain v1 evidence, written before encryption (the same commit, `2fc50f1`, introduced
both v2 rows and encrypted blobs), ever pointed at a plaintext blob. The fallback in `get_blob` and
`get_inbox_raw` now needs a v1 row of that engagement citing the hash. `vault.encrypt_existing` and
the deletion step (`vault._legacy`) count v1 rows only. Newer evidence that cites a hash cannot open,
copy or keep another engagement's blob. One existing test,
`test_agent.py::test_blobs_are_served_only_when_evidence_refers_to_them`, relied on the vulnerable
path itself: it stored a plaintext blob and cited it with new evidence. It now stores the blob under
the engagement's key, as every blob is stored today, and keeps every assertion it had.
`docs/ENCRYPTION.md` says so.

### AUTH-2 (Low): changes sent by a page of another origin were accepted

**What.** The session cookie is `SameSite=Strict`, which keeps it off cross-site requests, and
routes with a JSON body need a CORS preflight that the API never grants. Two gaps remained:

- **A sibling subdomain is the same site.** If AttackLedger is `attackledger.bank.example`, a page
  on any `*.bank.example` (another team's app, or one with an XSS) gets the cookie on a plain form
  POST. Routes without a JSON body accept such a POST: `POST /auth/keys/{id}/revoke` (it revokes the
  victim's signing key and writes a key-log entry "via own session"), `POST /jobs/{id}/cancel`,
  `POST /engagements/{id}/test-accounts/{aid}/delete`, `POST /lanes/{id}/receipt/timestamp`, and
  `POST /engagements/{id}/imports`, which reads the raw body whatever its content type, so a
  `text/plain` form plants an attacker's export in the inbox under the victim's name.
- **Open mode.** The API acts as the local operator for anyone who can reach it. A web page that the
  operator visits can send the same form POSTs to `http://localhost:8000` (no cookie is needed).

**Reproduction.** Signed in, `POST /auth/keys/<id>/revoke` with `Sec-Fetch-Site: same-site` and
`Origin: https://evil.lab.test` returned 200 and revoked the key.

**Fix.** `authz.authorize`, which every route runs first, now refuses POST, PUT, PATCH and DELETE
when the browser says the request came from another origin (`auth.from_another_site`):
`Sec-Fetch-Site` other than `same-origin` or `none`, or, for browsers without Fetch Metadata, an
`Origin` whose host is not the request's `Host` (`null` included). Host names are compared without
ports, so the dev setup (nginx's `$host` drops the port) works. The web app's own requests are
same-origin. Clients that are not browsers (the worker, the gateway relay, the CLI tools, scripts
with the token) send neither header and are not affected. Reads are not refused: a page of another
origin cannot read the answers (no CORS).

### AUTH-3 (Low): separation of duties ignored who imported a lane's evidence

**What.** With separation of duties on, whoever supplied a lane's evidence must not sign its
receipt. For recon and agent runs the person who started the run counts (`created_by` on the
evidence). Imported evidence (D-029) recorded only the person who mapped it. A person with the
tester and reviewer roles could upload an export, have a colleague map its entries to a lane, and
then sign that lane's receipt over evidence they supplied.

**Reproduction.** SoD on. Rita (tester and reviewer) uploads `sample.har`; Tess (tester) maps the
login entry to the authentication lane and resolves it; Rita's `POST /lanes/<id>/close` returned 200.

**Fix.** `_sign_refusal`, which serves both the close route and `can_sign`, also refuses the
uploader of an import batch whose entries are evidence on the lane (`_imported_by`, through the
entries' `mappings`). `docs/TESTER_GUIDE.md` says so.

### Info

- **AUTH-4.** `auth._principal` compares the bearer header and the token-mode cookie with
  `hmac.compare_digest` on `str`. That raises `TypeError` for non-ASCII characters (Starlette decodes
  headers as Latin-1), so such a request gets a 500. The same applies to `orgs.channel_org` for
  worker and gateway tokens. It fails closed, with no bypass. Comparing the UTF-8 bytes would turn
  it into a 401.
- **AUTH-5.** `approvals.consume` locks the proposal (`SELECT ... FOR UPDATE`) on Postgres only. On
  SQLite, two concurrent uses could both read `approved`. Production runs Postgres (both compose
  files), where the second use waits and then sees `sent`. SQLite is used by the tests only.
- **AUTH-6.** In token mode, the cookie is `HMAC(token, "attackledger-session-v1")`. Signing out
  deletes it in the browser, but a copied cookie works until the token changes. This is by design
  (no sessions without people). People mode uses random sessions stored as hashes.
- **AUTH-7.** `_check_signed` assumes the payload's field types: a naive `issued_at` or a
  non-integer `chain.seq` raises (500) before the canonical-form check has a chance to refuse it.
  It needs the signer's own session and key, so it rejects nothing it should accept.
- Design notes, not defects: separation of duties covers evidence, not N/A decisions (a person can
  mark every item N/A and sign); sign-in lockout is per email and address, kept in memory (a
  restart clears it); in a multi-organization deployment, sign-in time grows with the number of
  accounts that share an email (ORGANIZATIONS.md already lists per-organization sign-in as future
  work); `auth.OPEN_PATHS` is unused.

## Scope covered

Files read in full: `server/app/auth.py`, `authz.py`, `orgscope.py`, `orgs.py`, `approvals.py`,
`testaccounts.py`, `gatewayapi.py`, `signing.py`, `ledger.py`, `blobs.py`, `keylog.py`,
`auditlog.py` (append, chains, reading), `gates.py` (manifest, void), and the routes of `main.py`.
Read in part: `people.py` (CLI create, set-password), `vault.py` (deletion, legacy blobs,
`encrypt_existing`), `workerapi.py` (job tokens, toolbox, agent calls, recon evidence),
`agenttools.py` (mark_item, add_evidence, record_sent, record_write), `gateway.py` (request flow,
header policy, approval and account use), `inbox.py` (mapping), `report.py` (queries),
`deploy/compose.prod.yml`, `deploy/Caddyfile`, `web/nginx.conf`, `web/src/api.ts` (request
headers). Docs: ARCHITECTURE ("Authentication and permissions", invariants), DECISIONS D-032 to
D-053, ORGANIZATIONS, APPROVALS.

Routes checked by name: `/auth/login`, `/auth/logout`, `/auth/me`, `/auth/password`, `/auth/keys`
(GET, POST), `/auth/keys/{key_id}/revoke`, `/people` (GET, POST), `/people/{user_id}`,
`/engagements/{eng_id}/members` (GET, PUT), `PATCH /engagements/{eng_id}`, `/blobs/{digest}`,
`/lanes` (POST), `/lanes/{lane_id}/evidence`, `/attach`, `/items/{idx}`, `/close`,
`/receipt-payload`, `/receipt/timestamp`, `/agent-runs`, `/jobs/{job_id}/cancel`, `/resume`,
`/engagements/{eng_id}/audit`, `/audit`, `/engagements/{eng_id}/inbox/*` (list, entry, raw, map,
dismiss, restore), `/engagements/{eng_id}/imports`, the four test-account routes, the four approval
routes, the five `/gateway/*` routes, `/worker/claim` and the job-token routes, and the verifier
downloads.

## Checked and sound

- **Permission table.** Every route has a rule (the existing test enforces it). An unknown route is
  owner-only. `HEAD` is not routed (405). Path ids that are not integers give 404 before any handler runs. For an object the caller
  cannot see, the answer is 404 with the same body as an id that was never used. 403 comes only for
  what they can see.
- **Setup mode (D-045).** With `ATTACKLEDGER_REQUIRE_SIGN_IN` on and no people or token, every
  route except `/health` answers 401, `/auth/login` answers 422, and `POST /people` cannot make the
  first owner. Unknown values count as on. The first owner comes from the CLI. In open mode the first
  person must be an owner.
- **Sessions.** The value is random (32 bytes); only its SHA-256 is stored; expiry is checked on
  every request; the cookie is HttpOnly, SameSite=Strict, and Secure behind HTTPS. A changed
  password ends the other sessions, a disabled person's sessions end at once, and a demotion or a
  role removal takes effect on the next request (the principal is rebuilt each time). Session
  fixation is not possible, because the server chooses the value. Lockout after five failures, and
  unknown emails cost one scrypt. In production, Caddy overwrites `X-Forwarded-For`, so the address
  that uvicorn trusts (`--forwarded-allow-ips *`, leftmost entry in 0.32) is the client's.
- **People.** No API route sets another person's password (D-036); the last active owner cannot be
  disabled or demoted; members must be people of the caller's organization.
- **Organizations (D-042).** The filter is added in `do_orm_execute` for every ORM select, update
  and delete, including subqueries, joins and bulk statements. The routes and helpers use no raw
  SQL on tenant tables; the only `text()` is the advisory lock. The through-parent tables
  (`signing_keys`, `user_sessions`, `receipts`, `checklist_items`, `agent_exchanges`) are reached
  only through a scoped parent or with an ownership check (`revoke_key`, `_key_of`). The
  identity-map risk (a `session.get` returning a row loaded unscoped earlier) is handled: sign-in
  expunges the other organizations' candidates, and the other unscoped loads (`_job_caller`, the
  principal, `orgscope.owner` for audit and key-log appends) load only the caller's own
  organization's rows, or raise `TenancyError` before a cross-organization row is used. Worker,
  gateway and job tokens are each bound to one organization, and `/gateway/log` drops ids of
  another organization. Reports take the chains of the engagement's organization. The background
  passes (sweep, retention) run as the operator and act by engagement id.
- **Cross-engagement ids in one organization.** Asset in `POST /lanes`, the job in `attach` (kind
  run), lanes and entries in `inbox/map`, dismiss and restore, the proposal in the approval routes,
  the account in the test-account routes, and the gateway log's `job_id` filter: each is checked
  against the engagement in the path. Blobs are read only through engagements the caller can read
  (AUTH-1 was the one gap).
- **Approved writes (D-041).** An approval binds `request_sha256` (method, URL, headers in order,
  body, account), and the person must name the hash they read. When the approval is used, the
  method, normalized URL, body hash and account must match; the gateway then sends the approved
  headers, not the worker's, and checks them again (method overrides, upgrades). The approval
  expires 15 minutes after it is given and is used once (row lock on Postgres; AUTH-5 for SQLite). A
  DELETE stays `confirming` until the same approver types the exact path. Only testers and owners
  decide; with SoD on, the run's starter and the operator token cannot. An approval is accepted only
  from the job that proposed it, and only while it runs and the engagement allows writes.
- **Test accounts (D-040).** No route returns the material. Viewers and reviewers see labels and
  fingerprints only. The gateway gets the material only with a running agent job's secret, for that
  job's engagement, for a host named for the account, in scope, with redaction on. A person cannot
  call `/gateway/*` (gateway token only), cannot set `X-AttackLedger-*` through the agent's tools,
  and cannot start an agent run without the tester role.
- **Signing and receipts (D-033, D-052).** Only the reviewer role (or an owner) gets a payload,
  closes a lane or timestamps a receipt. A signed close checks the signer's own unrevoked key, the
  canonical payload, the lane, manifest, chain head, signer id, name and email, and an age of at
  most 10 minutes. A void is an audit-log entry and stays void (`is_voided` reads the log); every
  person-facing route that changes a lane, and recon results, call `record_change` or `void_receipt`. The agent's tools never change a closed lane:
  `check_lane` refuses on every call, and `mark_item` only moves open items. Nothing un-voids a
  receipt.
- **CSRF on JSON routes.** Before AUTH-2, too, these were safe: FastAPI parses the body as JSON only
  for a JSON content type, which a cross-origin form cannot send, and the API grants no preflight.
