# Threat model

This document says what AttackLedger protects, from whom, where the trust boundaries are, which
control in the code addresses each threat, which test shows it, and what risk is left. It is
written for an IT auditor (a bank's internal audit, an external IT audit team) who wants to judge
whether a coverage report from AttackLedger can be relied on, and for a deployer who has to know
what the product does not do for them.

Status: written on 2026-10-11 against the code after commit `d589443`; section 8's gaps TM-1,
TM-3 and TM-5 were closed afterwards (commits `bef9636`, `02082a9`, `260fcd8`, `f30a4fd` and `a1e25ff`), TM-2,
TM-4 and TM-6 are documented. It brings together what is
spread over the design documents ([ARCHITECTURE.md](ARCHITECTURE.md), [GATEWAY.md](GATEWAY.md), [WORKER_API.md](WORKER_API.md),
[ENCRYPTION.md](ENCRYPTION.md), [VERIFIER.md](VERIFIER.md), [APPROVALS.md](APPROVALS.md), [ORGANIZATIONS.md](ORGANIZATIONS.md), [DECISIONS.md](DECISIONS.md)) and the
internal security review (`security-review/`). Every control it names was found in the code or in
a test; nothing here was re-tested for this document. Like the review, it is the author's own
work, done with AI agents (Claude). **No independent third party has tested AttackLedger.**

Contents:

1. [What AttackLedger is, in one paragraph](#1-what-attackledger-is-in-one-paragraph)
2. [System and trust boundaries](#2-system-and-trust-boundaries)
3. [Assets](#3-assets)
4. [Actors](#4-actors)
5. [Threats by boundary](#5-threats-by-boundary)
6. [What the signatures and the seal prove against a dishonest operator](#6-what-the-signatures-and-the-seal-prove-against-a-dishonest-operator)
7. [Out of scope and accepted residual risk](#7-out-of-scope-and-accepted-residual-risk)
8. [Gaps noted while writing this model](#8-gaps-noted-while-writing-this-model)
9. [Assumptions: what the deployer must do](#9-assumptions-what-the-deployer-must-do)
10. [How to use this document as an auditor](#10-how-to-use-this-document-as-an-auditor)

## 1. What AttackLedger is, in one paragraph

AttackLedger records a security test as it happens and turns the record into a report that shows
what the test covered. Testers, recon tools and Claude agents produce evidence; the evidence is
stored append-only in a hash chain per engagement; a reviewer closes each lane (a host and a test
area) by signing a receipt over the lane's items and evidence with a key held in their browser; and
the exported report carries everything a reader needs to check the receipts, the chain and the
change history offline. All traffic to targets leaves through one gateway that enforces the
engagement's scope, read-only methods, rate ceiling and research identification, and logs every
request. It runs self-hosted, on the customer's or the tester's own server (D-042).

The central claim an auditor relies on is: **a receipted lane in a report that verifies was
reviewed and signed by the named person, over exactly the items and evidence the report shows,
under the scope and roles the change history shows, and nothing in it changed afterwards.** Most
of this document is about where that claim can fail.

## 2. System and trust boundaries

```
  PEOPLE'S BROWSERS                       THE INSTALLATION (one Docker host)
  ─────────────────                       ──────────────────────────────────────────────────────────
  testers, reviewers, owners
  a reviewer's signing key  ──[B2] HTTPS──► caddy ──► web (nginx) ──► api ──[B4]──► db (Postgres)
  (in that browser only)                    (TLS)     (app, /api/)     │    └─[B4]─► blob store (encrypted)
        ▲                                                              │             master key file (read-only)
        │ [B3] other sites' pages                                      │             seal key (wrapped)
        │      in the same browser                                     ├──[B9]──► timestamp authority (a hash only)
                                                                       │
                                                                 [B6]  control network:
                                                                       │ /gateway/* and relayed /worker/*
                                                                       │ (answered there only: TM-1)
                                                                       │
                                           worker ──[B5] internal ──► gateway ──[B7]──► targets (scope only)
                                           recon tools,  network      CA key,   ──[B8]──► passive sources (GET only)
                                           agent loop                 gateway           api.anthropic.com
                                           (no database, no keys,     token,            (the gateway adds the key)
                                            no route out)             Anthropic key

  OPERATORS [B10]  a shell on the host, or membership of the docker group: root of trust over all of the above
  BACKUPS   [B11]  a database dump and a blob archive (tools/backup.sh), kept apart from the master key
  BUILDS    [B12]  base images, packages, the repository and its CI; the public site on Cloudflare Pages

  CUSTOMER'S AUDITOR ◄──[B1] the report file, over any channel── exported by the api
     checks it with tools/verify_report.py (offline, Python standard library) or
     attackledger.com/verify (runs in the browser, uploads nothing)
```

Networks and who is on them are in [INSTALL.md](INSTALL.md) section 6; the gateway's own diagram is in
[GATEWAY.md](GATEWAY.md), the worker's channel in [WORKER_API.md](WORKER_API.md).

| Boundary | Between | What crosses it | Trust on each side |
|---|---|---|---|
| B1 | The installation and the customer's auditor | The exported report (JSON, or HTML with the JSON embedded), by email, a portal, a USB stick: any channel | The channel and anyone who handles the file are untrusted. The verifier trusts only the report's signatures, the key fingerprints the reader got out of band, and the timestamp roots the reader chooses |
| B2 | People's browsers and the API, through Caddy (TLS) and nginx | Sign-in, session cookies, every person's request; the app's code and the reports | The network is untrusted; Caddy terminates TLS. The API trusts no request until `authz.authorize` has named the caller |
| B3 | Other origins in the same browser and the app's origin | Forms, scripts, DNS rebinding, framing | Every other origin is hostile, sibling subdomains of the same site included |
| B4 | The API and its stores | Rows in Postgres, encrypted files in the blob store, the master key file, the report seal key | Only the API holds the database credentials, the master key and the blob volume. Whoever can read them directly is an operator (B10) |
| B5 | The worker and the gateway | Every request a recon tool or agent sends, DNS questions, port probes, and the worker's calls to the API (relayed) | **The worker is untrusted**: any tool in it may be buggy, compromised or misled, and tools run as the worker's user. It has no database, no keys and no route except to the gateway |
| B6 | The gateway and the API | Job credentials, rules, test-account headers, approvals, the request log | Each side authenticates the other's calls with tokens (gateway token, worker token, job token). One Docker network, no TLS |
| B7 | The gateway and targets | Read-only requests in scope, approved writes, the targets' answers | **Targets are untrusted**: any response may be hostile, oversized, slow, malformed, or contain instructions for an agent |
| B8 | The gateway and third-party services | Agent calls to the Claude API (with the deployment's API key), passive recon queries | Anthropic and the passive sources are third parties: they see what is sent to them. Upstream certificates are verified |
| B9 | The API and the timestamp authority | The SHA-256 of a receipt or seal statement, and a signed token back | The authority is trusted only as far as the reader trusts its root certificate |
| B10 | Operators and the installation | Shell, Docker, the database, the key files | Root of trust. The product can make an operator's changes visible, not impossible |
| B11 | The installation and its backups | Database dump, blob archive | Backups leave the host and outlive deletions |
| B12 | Upstream projects and the installation | Images, packages, tools, the code itself; the public verifier page | Pinned and checked where possible; trust ends at the git checkout |

Organizations (tenants) are a boundary inside one deployment (`ORGANIZATIONS.md`). A self-hosted
install has one, so this matters only for a hosted service; it is covered under B2.

## 3. Assets

| Asset | Where it lives | Why it matters | Main protection |
|---|---|---|---|
| Evidence and its integrity | `evidence` rows (hash chain per engagement), raw exchanges, notes and files in the blob store | The basis of every receipt | Append-only chain (`ledger.append_evidence`, `ledger.verify_chain`); AES-256-GCM per engagement (`vault.py`, `blobs.py`); redaction before storage (`redact.py`, D-038) |
| Receipts and signatures | `receipts` rows, in every report | The reviewer's statement that a lane was reviewed | Signed in the reviewer's browser (Ed25519 or ECDSA P-256, D-033); checked by the server (`main._check_signed`) and by both verifiers; manifest v2 and payload v4 (D-054) |
| Report seal | `integrity.seal` of every exported report; the key in `<blobs>/instance/seal-key.json` | The server's statement that the report and its history are complete up to the sealed heads | Ed25519 key wrapped by the master key (`vault.seal_key`, `seal.py`, D-055) |
| Audit log and key log | `audit_log`, `key_log` (one hash chain each per organization) | Who held which role, the scope in force, voids, key registrations | Hash chains (`auditlog.verify`, `keylog.verify`); payload v4 and the seal bind their heads into reports |
| Timestamps | Tokens on receipts and seals | That a receipt or a report existed at a time the server could not backdate | RFC 3161 (`timestamps.py`, D-034); checked offline against roots the reader trusts |
| Master key | A file on the host (`/etc/attackledger/master.key` by default), mounted read-only into the API only | Opens every engagement key and the seal key | Kept out of `.env`, the worker and the backups; API refuses to start without it (`vault.master_key`, `vault.check_store`) |
| Engagement data keys | `<blobs>/e/<id>/key.json`, wrapped by the master key | Open one engagement's content; deleting one shreds that content | AES-256-GCM wrap with the engagement id as associated data (`ENCRYPTION.md`) |
| Test-account sessions | `test_accounts.material_enc` (sealed with the engagement key); in the gateway's memory for 2 seconds | Live sessions in the customer's application | Never returned by any route; injected and scrubbed by the gateway only (D-040, `APPROVALS.md`) |
| Anthropic API key | `ANTHROPIC_API_KEY` on the gateway service only | Costs money; identifies the deployment to Anthropic | Not in the worker; added by the gateway to agent calls only (D-042) |
| Scope and rules | `engagements` (scope include/exclude, rate, identification, authorization, settings) | What may be touched, how fast, and how the traffic is identified | Fail-closed scope matching (`scope.in_scope`); enforced at the gateway; every change an audit entry |
| People's credentials and sessions | `users` (scrypt hashes), `user_sessions` (SHA-256 of the cookie), `signing_keys` (public keys) | Access, and the identity behind each signature | `auth.py`, D-032, D-036, D-056 |
| Machine tokens | Gateway token and worker token in volumes shared with the API only; job tokens and gateway secrets (stored as SHA-256) | Open the machine channels | 256-bit values, compared as bytes (`auth.same_secret`); job tokens valid only while their job runs |
| Gateway CA key | The gateway's private volume | Lets the gateway read HTTPS traffic of the tools | Mounted by the gateway only; the worker gets the public certificate |
| Reports | Exported files, wherever the tester sends them | What the auditor reads | Self-contained and verifiable offline; the HTML report allows no script |
| The request log | `gateway_requests`, written by the gateway | The independent record of what was sent to targets | Written by the gateway, not the worker; the gateway refuses traffic when the log cannot be written |

## 4. Actors

| Actor | Legitimate capability | As a threat, assumed able to | Trust |
|---|---|---|---|
| **Customer's auditor** | Reads reports and verifies them | Receive a report that someone between the tester and them edited | Trusted; works over an untrusted channel |
| **Tester** | Adds evidence, marks items, runs recon and agents, adds test accounts, approves writes (role `tester`) | Record evidence that is not genuine, mark items done or N/A without doing the work, sign their own lanes if separation of duties is off | Trusted for their own work; the reviewer is the check on it |
| **Reviewer (signer)** | Closes lanes by signing receipts (role `reviewer`) | Sign without reviewing; sign evidence they supplied | Trusted to review; separation of duties checks the second |
| **Owner** | Everything in the organization: people, roles, scope, settings, deletion | Grant themselves or a friend the reviewer role, switch off redaction, signatures or separation of duties, delete content, rename accounts | Trusted, but every such change is an audit entry the report carries |
| **Operator with shell access** | Runs the host, Docker, backups, the server commands (`python -m app.people`, `app.vault`, `app.orgs`) | Read the master key and the database, rewrite rows, register keys, reset passwords, seal any report | Root of trust (D-036, D-037). Changes can be made visible, not prevented |
| **Compromised or prompt-injected tool or agent in the worker** | Send requests for its job | Send anything the worker can, read everything the worker holds (its token, its running jobs' tokens and gateway secrets) | Untrusted (`GATEWAY.md`, `WORKER_API.md` threat models) |
| **Malicious target** | Answers requests | Send hostile, oversized, slow or malformed responses, reflect sessions, embed instructions for an agent, resolve its names to internal addresses | Untrusted |
| **Malicious web page in a person's browser** | None | Send forms and scripts to the app's origin, rebind DNS, frame the app, run on a sibling subdomain | Untrusted |
| **Someone with a copy of a backup** | None | Read every byte of the database dump and the blob archive | Untrusted; may also obtain the master key separately |
| **Dishonest instance operator** | Runs the server that produces the report | Everything an operator can, with the aim of making a report say more than happened | Section 6 says what the seal and signatures still prove |
| **Supply-chain attacker** | None | Publish a malicious image, package, tool release or template; change the public verifier page | Untrusted; pins and hashes limit what a build takes |

## 5. Threats by boundary

Each table lists threats in STRIDE terms (**S**poofing, **T**ampering, **R**epudiation,
**I**nformation disclosure, **D**enial of service, **E**levation of privilege), the controls with
the code and the test that shows them, the review findings that tested them (`security-review/`),
and the risk that is left. Test files are in `server/tests/` unless the path says otherwise.

### B1. The report and the customer's auditor

| ID | STRIDE | Threat | Controls (code; test) | Review | Residual risk |
|---|---|---|---|---|---|
| T1.1 | T | Someone edits a report (a lane's status, an item, the summary counts) and recomputes the body hash | Receipts are signed over the lane's manifest and chain head; both verifiers rebuild every manifest and check every signature (`tools/verify_report.py` `check_receipts`, `check_signatures`; `web/src/verify_report.ts`); manifest v2 binds each evidence entry to its item (`gates.manifest`); summary counts are recounted. `test_security_evidence.py::test_ev1_a_voided_receipt_cannot_be_reported_as_receipted`, `test_ev4_the_summary_counts_must_be_the_reports_own`, `test_security_verifier.py::test_o1_swapped_item_ids_fail_under_manifest_v2`, `test_report.py::test_rewriting_the_whole_chain_still_breaks_the_receipt` | EV-1, EV-4, O-1 | The body hash alone is self-consistency: anyone can recompute it. Trust rests on the reviewers' key fingerprints, compared out of band. Unsigned receipts verify with a NOTE unless `--require-signatures` is given |
| T1.2 | T, R | A void, a role change or a scope change is left out of the report's history so a voided receipt looks valid | Receipt payload v4 signs the audit and key log heads and the set of entries it relies on (D-054); the server seals every export over the body hash and both heads (`seal.seal`, D-055); a void is matched to its receipt by lane, manifest and signed time (`_voids` in `verify_report.py`, `voidsReceipt` in the browser). `test_security_verifier.py::test_o2_a_void_after_the_newest_signature_is_caught_by_the_seal`, `test_o2_require_history`, `test_report_seal.py::test_a_report_with_an_entry_left_out_fails_the_seal_in_every_mode`, `test_security_recheck.py::test_ev1_a_void_is_not_hidden_by_moving_the_receipts_issue_time` | EV-1, EV-2, O-2, RECHECK EV-1 | In normal mode a report without a seal (as made before D-055) verifies with a NOTE; only `--require-history` (the /verify checkbox) fails it. After the newest receipt signature, the history is bound by the server's key only (section 6) |
| T1.3 | S | A lane signed in one engagement is presented in a report about another | The verifier compares the signed engagement id with the report's. `test_security_evidence.py::test_ev3_a_receipt_signed_for_another_engagement_fails` | EV-3 | A different engagement name is only a NOTE (renames are allowed) |
| T1.4 | S | A forger seals an edited report with their own key and appends that key to the key log | The verifier says whether a receipt signature covers the seal key's registration; the seal fails when the key log does not register it as the instance's before the sealed head. `test_report_seal.py::test_a_seal_from_another_instance_key_fails` | O-2 | When no receipt was signed after the key was registered, only the fingerprint ties the seal key to the tester's server: the reader must compare it with the one the tester gives (VERIFIER.md) |
| T1.5 | T | The visible text of an HTML report is edited and its embedded JSON left alone | Both verifiers say that only the embedded JSON was checked and print what it says, for the reader to compare. `test_security_evidence.py::test_ev5_html_reports_say_that_only_the_embedded_json_is_checked`, `test_security_verifier.py::test_o3_a_verified_html_report_is_followed_by_its_facts` | EV-5, O-3 | The page's text is not verified; the reader compares it with the facts list or uses the JSON |
| T1.6 | T | A receipt or a report is backdated, or the server's clock is wrong | RFC 3161 timestamps on receipts and seals from the configured authority; the verifiers check the token, the authority's signature and its chain to a root the reader trusts (`timestamps.py`; `check_timestamps`). `test_timestamps.py::test_token_verifies_offline_and_tampering_is_caught`, `test_chain_rules`, `test_report_seal.py::test_the_seal_is_timestamped_when_a_tsa_is_set` | (D-034) | With timestamps off, or when the authority did not answer, times are the server's clock (the receipt says it has no timestamp). Which authority to trust is the reader's choice |
| T1.7 | S | A report makes the command-line verifier print a fake `Verified.` (terminal controls), or crashes it | Every printed value is escaped (`shown`); a malformed report exits with code 2, "cannot be checked". `test_security_recheck.py::test_the_verifier_prints_report_text_with_terminal_controls_escaped`, `test_security_fuzz.py::test_fz16_the_verifier_never_stops_with_a_traceback`; 2,600 random mutants with no difference between the two verifiers | RC-1, FZ-16 to FZ-19 | None known; the exit code, not the printed text, is the machine-readable verdict |
| T1.8 | I | The browser verifier sends the report somewhere | The page's policy is `default-src 'none'; connect-src 'none'` with Trusted Types, in a meta tag and in the header (VERIFIER.md). `e2e/tests/site/verify.spec.ts`, `e2e/tests/site/pages.spec.ts` | WE (site phase) | The page is served by attackledger.com (Cloudflare Pages, built from the repository): whoever controls that site could serve another page. A saved copy keeps its policy; `tools/verify_report.py` from a checkout needs no site at all |
| T1.9 | T | The two verifiers disagree, so a report passes on one and fails on the other | The browser verifier is a port of the script, kept equal by `tools/verifier_equivalence/run.sh` (134 reports, 107 building blocks, 0 differences) and its seeded fuzzing in the CI | FZ-16 to FZ-19 | None known |
| T1.10 | T | A genuine but old report (sealed before a void) is presented as the current one | Not prevented: it is a valid report of its time | O-2 (VERIFIER.md) | The reader checks `sealed_at` or the seal's timestamp against when they expect the report to have been made |

### B2. Browsers, Caddy, nginx and the API

| ID | STRIDE | Threat | Controls (code; test) | Review | Residual risk |
|---|---|---|---|---|---|
| T2.1 | S | Guessing a person's password | scrypt hashes, at least 12 characters (`auth.py`); 5 failures in 15 minutes lock that email from that address (`auth.LOCKOUT_FAILURES`); unknown emails cost one scrypt. `test_people.py::test_sign_in_sessions_lockout_and_disabled` | AUTH (checked and sound) | **No second factor** (TM-2): a password alone opens an account; a reviewer's signature still needs their browser's key. Putting AttackLedger behind the organisation's SSO or VPN is left to the deployer (section 9). The lockout is kept in memory and a restart clears it (AUTH, Info) |
| T2.2 | S | Stealing or replaying a session | A random 32-byte cookie, only its SHA-256 stored; `HttpOnly`, `SameSite=Strict`, `Secure` in production (`ATTACKLEDGER_COOKIE_SECURE=1` in `deploy/compose.prod.yml`); ended after 30 minutes without use (`ATTACKLEDGER_SESSION_IDLE_MINUTES`, `auth.session_over`; the web app's own polls carry `X-AttackLedger-Background` and do not count) and 12 hours after sign-in whatever its use (`auth.SESSION_HOURS`); and by sign-out, a password change or reset, or disabling the person; a token session is bound to the token and dies when it changes (D-056). `test_security_review_auth.py::test_auth6_signing_out_revokes_a_copied_token_mode_cookie`, `test_keytrust.py::test_disabling_a_person_ends_their_sessions`, `test_session_idle.py`, `e2e/tests/people/session.spec.ts` | AUTH-6, TM-3 (fixed) | A copied cookie that is used works until the 12 hours end. The idle limit relies on the web app to mark its own background requests; a client that never marks them keeps its session in use (it holds the cookie anyway). The last use is written at most once a minute, so a session can end up to a minute early |
| T2.3 | E | Calling a route without the right role | One permission table for every route (`authz.RULES`, `authz.authorize`); a route without an entry is owner-only; non-members get 404. `test_people.py::test_every_route_has_a_permission_rule`, `test_principal_never_defaults_to_owner`, `e2e/tests/people/roles.spec.ts` | AUTH (permission table sound) | None known |
| T2.4 | E | Becoming the first owner of a fresh production install over the network | Setup mode: with `ATTACKLEDGER_REQUIRE_SIGN_IN=1` (production) nothing opens until the first owner is made on the server (`auth.require_sign_in`, D-045). `test_setup_mode.py::test_nobody_can_become_the_first_owner_over_the_api`, `test_unknown_values_fail_closed` | AUTH (setup mode sound) | The development compose file runs open on localhost; it is not for real work |
| T2.5 | S, E | An owner takes over a reviewer's identity to sign in their name | No one sets another person's password through the API (D-036); every key registration is in the key log, shown to the person at their next sign-in; the verifier fails a receipt whose signer lacked the reviewer role or had another name or email (D-037). `test_keytrust.py::test_owners_cannot_set_someone_elses_password`, `test_notice_lists_key_changes_since_the_previous_sign_in`, `test_key_log_chains_every_registration_and_revocation` | AUTH (people sound) | An owner can still create an account and give it the reviewer role; that is in the audit log the report carries. The reader compares signers' key fingerprints out of band |
| T2.6 | T, E | A person signs a lane whose evidence they supplied | Separation of duties, an engagement setting: whoever attached, imported or started the run behind a lane's evidence cannot sign it, and the operator token cannot sign at all (`main._sign_refusal`). `test_people.py::test_separation_of_duties`, `test_security_review_auth.py::test_auth3_whoever_imported_a_lanes_evidence_cannot_sign_it` | AUTH-3 | **Off by default** (`models.py`); the report states whether it was on, and the verifier does not re-check it. It covers evidence, not N/A decisions |
| T2.7 | I | Reading another engagement's or another organization's data | Every query is filtered by organization in one place (`orgscope.py`); engagements are resolved through the filtered session (`authz._engagements`); a blob opens only for a hash the engagement's own evidence cites. `test_organizations.py::test_no_route_reaches_another_organization`, `test_ids_in_bodies_and_queries_answer_as_if_never_used`, `test_security_review_auth.py::test_auth1_citing_a_hash_does_not_open_another_engagements_plaintext_blob` | AUTH-1, AUTH (organizations sound) | Isolation is the ORM's, not the database's (no row-level security); ids are deployment-wide sequences (`ORGANIZATIONS.md`, "What a hosted service would still need") |
| T2.8 | T | Hostile content (from a target, an import or a compromised worker) runs as script in a person's session | React renders text as text; the app's policy allows only its own origin and one hashed inline script (`web/nginx.conf`); raw evidence is served as `text/plain` under `default-src 'none'; sandbox`; the HTML report escapes every value and allows no script; recon URLs are linked only when http(s). `test_web_headers.py::test_the_app_policy_allows_only_this_origin_and_hashed_inline_code`, `test_security_web_e2e.py::test_we2_a_probe_url_must_be_an_http_url_of_the_host_it_probed`, `e2e/tests/token/hostile.spec.ts`, `e2e/tests/token/csp.spec.ts` | WE-2, EVIDENCE (web sound) | None known in the views tested (Chromium, Firefox, WebKit) |
| T2.9 | I | Credentials left in the browser's storage | Unsent drafts that look like credentials are never written to `sessionStorage`, and drafts are cleared when another person signs in (`web/src/drafts.ts`, `SECRETISH`, D-053). `e2e/tests/token/drafts.spec.ts`, `e2e/tests/people/drafts.spec.ts` | EV-8, WE-4, WE-6 | A heuristic: some key formats are not recognised, and a credential typed key by key is kept until it is recognisable |
| T2.10 | I | Eavesdropping on people's traffic | Caddy terminates TLS (Let's Encrypt or the organisation's certificate) and sends HSTS (`deploy/Caddyfile`). `test_web_headers.py::test_the_caddyfile_sends_the_same_values_and_no_policy_of_its_own` | (INSTALL §5) | Certificates and the TLS private key are the deployer's to manage. Option D (plain HTTP over an SSH tunnel) is for trials only |
| T2.11 | D | Malformed input makes routes fail (500) or stall | NUL and lone surrogates refused before the database (`nulguard.py`); body limits; quadratic parsers made linear. `test_security_fuzz2.py::test_fz31_a_lone_surrogate_in_a_persons_json_is_a_422_not_a_500` and the FZ tests | FZ-5, FZ-14, FZ-31 to FZ-34 | There is no general request rate limit on the API besides the sign-in lockout; denial of service by a signed-in person is not addressed |
| T2.12 | S | A leaked gateway or worker token is used from outside | Tokens are 256 bits, compared as bytes (`auth.same_secret`, `orgs.channel_org`); without a configured token the machine routes answer 503. `test_security_review_auth.py::test_auth4_non_ascii_tokens_and_cookies_are_refused_with_401`, `test_worker_api.py::test_worker_routes_need_the_worker_token` | AUTH-4, TM-1 (fixed) | Fixed (TM-1): nginx refuses `/api/gateway/` and `/api/worker/` in every spelling (`web/nginx.conf`), and the API answers the machine routes only on its address on the control network, by the connection's local address, not a forwarded one (`authz.machine_channel`, `ATTACKLEDGER_CONTROL_LISTEN=api-control`); elsewhere they are 404 before any token is read. `test_machine_routes.py`, `test_web_headers.py::test_nginx_refuses_the_machine_routes_in_every_spelling`, `e2e/tests/token/machine.spec.ts`. A leaked token is then usable only from the control network, which only the gateway is on. Without `ATTACKLEDGER_CONTROL_LISTEN` (outside Compose) the token alone guards them |

### B3. Other origins in a person's browser

| ID | STRIDE | Threat | Controls (code; test) | Review | Residual risk |
|---|---|---|---|---|---|
| T3.1 | T, E | A form or script on another site, or on a sibling subdomain of the same site, changes something in the victim's session (CSRF) | `SameSite=Strict` cookies; every POST, PUT, PATCH and DELETE that a browser says came from another origin is refused (`auth.from_another_site`, in `authz.authorize`); JSON routes need a preflight the API never grants. `test_security_review_auth.py::test_auth2_a_page_of_another_site_cannot_change_anything`, `e2e/tests/token/csrf.spec.ts`, `e2e/tests/people/csrf.spec.ts` | AUTH-2 | A browser that sends neither Fetch Metadata nor `Origin` is not covered; every current browser sends them |
| T3.2 | E | DNS rebinding reaches an install running in open mode on the operator's machine | Open mode answers only requests whose `Host` names the machine locally (`auth.local_request`). `test_security_recheck.py::test_auth2_open_mode_answers_only_local_names` | AUTH-2 (recheck) | Open mode exists for local trials; production refuses it (T2.4) |
| T3.3 | T | The app is framed and the person tricked into clicking (clickjacking) | `frame-ancestors 'none'`, `X-Frame-Options: DENY` (`web/nginx.conf`, `deploy/Caddyfile`). `e2e/tests/token/csp.spec.ts` (the guard checks every document's headers) | WE (headers sound) | None known |
| T3.4 | I | Another origin reads the API's answers | No CORS; `Cross-Origin-Resource-Policy: same-origin` and `Cross-Origin-Opener-Policy: same-origin` | WE (sound) | None known |
| T3.5 | S | A script uses the reviewer's signing key to sign something they did not review | The key is created non-extractable and kept in the browser's storage for the app's origin (`web/src/signing.ts`); only script of that origin can use it, and the policy above admits no other script; the server accepts a signature only over a payload it issued for that lane in the last 10 minutes (`main._check_signed`) | (D-033) | **Code that the installation serves can use the key**: a dishonest operator or a tampered web image could make the browser sign without the reviewer seeing it (TM-4, documented in `VERIFIER.md` and D-033). A malicious browser extension is out of scope (`SECURITY.md`) |

### B4. The API and its stores

| ID | STRIDE | Threat | Controls (code; test) | Review | Residual risk |
|---|---|---|---|---|---|
| T4.1 | I | A copy of the blob volume or the disk is read | Raw evidence, summaries and test-account material are AES-256-GCM under a key per engagement, wrapped by the master key, with associated data binding each to its engagement and hash (`vault.py`, `blobs.py`, D-043). `test_encryption.py::test_wrong_engagement_key_is_refused`, `test_tampered_ciphertext_is_refused` | EVIDENCE (encryption sound) | Recon results, URLs, job logs, evidence URIs, N/A reasons and the audit log's free text (kept outside its hashed records since D-058) are plaintext in the database (`ENCRYPTION.md`, "What is encrypted"). Full-disk encryption is the deployer's |
| T4.2 | T | Someone with database access edits or deletes evidence or history | Evidence, audit log and key log are hash chains; a receipt binds the chain head; reports carry the heads, so a rewrite after a report was sent breaks that report's heads (`ledger.verify_chain`, `auditlog.verify`, `keylog.verify`). `test_report.py::test_deleting_evidence_breaks_the_chain`, `test_rewriting_the_whole_chain_still_breaks_the_receipt`, `test_auditlog.py::test_chain_detects_edits_deletions_and_reordering`; `python -m app.people audit-log` and `key-log` check the chains on the server | (D-036, D-037), TM-5 (fixed) | Since TM-5 the database refuses it too: triggers on `evidence`, `receipts`, `gateway_requests`, `audit_log` and `key_log` refuse every `DELETE` and `TRUNCATE` and every `UPDATE` but the three the product makes (migration 0026, `app/appendonly.py`; `test_appendonly.py` on SQLite and Postgres). **A database superuser can drop the triggers**, and the API connects as one (the role the Postgres image makes from `POSTGRES_USER`); so can anyone who can write the SQLite file. The triggers stop mistakes and SQL sent through the application; the chains remain the proof. A rewrite before any report left the server is detectable only by the signatures and timestamps it would break |
| T4.3 | I | The master key leaks | A file mounted read-only into the API only, never in `.env`, the worker or the backups; startup fails if it is missing or wrong, with no fallback; the public development key is reported by `/health` (`vault.master_key`, `vault.check_store`). `test_encryption.py` | (D-043) | A plain file on the host: anyone with root reads it. No HSM or KMS. Rotation (`vault.rotate_master`) re-wraps keys, it does not re-encrypt content |
| T4.4 | T | A blob is replaced on disk | `blobs.get` checks the SHA-256 again, and GCM's tag fails on any change. `test_agent.py::test_blob_store_rejects_tampered_bytes` | | None known |
| T4.5 | I | Content survives its deletion | `vault.delete_content` deletes keys and blobs, blanks or deletes every database store that holds content, cancels running jobs, and the gateway purges its quarantine file. `test_retention.py::test_deleting_content_leaves_nothing_readable_in_any_store`, `test_the_sqlite_database_overwrites_what_it_deletes`, `test_security_evidence.py::test_ev6_deleting_content_removes_the_traffic_log_urls` | EV-6, RET-1 to RET-7 | **Deletion does not reach** backups made before it, Postgres's dead rows and write-ahead log, container logs, browsers and copies people made, or what the Claude API received. It keeps by design evidence URIs, and the free text of audit entries written before migration 0028 (later entries' text is blanked, D-058, `test_audit_texts.py`) (`security-review/RETENTION.md`) |
| T4.6 | T | Two requests race so a single-use step happens twice (an approval used twice, a job claimed by two workers) | Each such step is one conditional UPDATE from the status that was read (`approvals.move`, `workerapi.claim`); this holds on SQLite and Postgres. `test_security_review_auth.py::test_auth5_two_concurrent_uses_of_one_approval_send_it_once`, `test_two_workers_claiming_at_once_never_take_the_same_job` | AUTH-5 | None known |
| T4.7 | T | Behaviour differs on Postgres (production) from SQLite (most tests) | The whole suite also runs on Postgres 16 in a non-UTC time zone (`tools/test_postgres.sh`, CI job `postgres`). `test_postgres_portability.py` | AUTH (Postgres-only items) | None known |

### B5. The worker and the gateway (a compromised or misled tool or agent)

The question here is the one `GATEWAY.md` and `WORKER_API.md` ask: what can a tool inside the
worker do, if it is buggy, compromised or prompt-injected? Tools run as the worker's user, so the
answer covers the whole worker process.

| ID | STRIDE | Threat | Controls (code; test) | Review | Residual risk |
|---|---|---|---|---|---|
| T5.1 | E | Traffic to a host outside the engagement's scope | The worker has no route but the gateway and no external DNS; the gateway checks every request, tunnel, DNS question and probe against the scope (`gateway.Policy`, `scope.in_scope`: unknown is out, exclusions win, a wildcard does not cover its apex); job targets must be one line (`jobgates.one_line`). `test_gateway.py::test_out_of_scope_hosts_are_refused_and_nothing_is_sent`, `test_scope.py::test_wildcard_does_not_cover_apex`, `test_security_fuzz.py::test_fz4_an_exclude_rule_with_a_line_end_still_excludes`, `test_worker.py::test_every_tool_is_pointed_at_the_gateway`, `test_security_gateway.py::test_gw7_a_target_cannot_carry_a_second_line_to_the_tools` | GW-7, FZ-3, FZ-4, FZ-35 | The gateway answers DNS for in-scope names of any engagement with a running job |
| T5.2 | T | A write method, a body, a method override, a protocol upgrade or a smuggled request reaches a target | GET, HEAD and OPTIONS only, with no body, unless a person approved that exact request; overrides, `Upgrade` and other protocols refused; every request parsed by h11 and written out again (`gateway.Policy.check`). `test_gateway.py::test_write_and_unusual_methods_are_refused`, `test_method_parameter_naming_a_write_is_refused`, `test_test_accounts.py::test_an_unapproved_write_is_never_sent` | GW (smuggling sound), FZ-20, FZ-21, FZ-36, FZ-37 | None known |
| T5.3 | D | Traffic over the engagement's rate ceiling | One limiter per engagement for every tool, job and worker, for requests and for connections (`gateway.Limiter`, `Gateway.connect_limiter`). `test_gateway.py::test_rate_ceiling_holds_for_concurrent_clients_and_jobs`, `test_security_gateway.py::test_gw2_connections_to_targets_are_paced_like_requests`, `test_security_recheck.py::test_gw2_port_probes_and_requests_together_open_at_most_rate_connections`, `test_worker.py::test_no_step_exceeds_the_engagement_rate_limit` | GW-2 | One gateway per deployment; several gateways would each apply the ceiling |
| T5.4 | S | Target traffic without the research identification, or with a forged one | The gateway removes any header of the same name and adds the engagement's; an engagement without one gets no target traffic. `test_gateway.py::test_target_traffic_needs_identification`, `test_allowed_request_carries_only_the_engagements_identification` | GW (sound) | None known |
| T5.5 | R | A request leaves without a row in the request log | The gateway, not the worker, writes the log; it refuses all traffic while 5,000 rows wait; a row the API cannot store becomes a placeholder (`gatewaylog.placeholder`); every connection that sent anything has one row. `test_gateway.py::test_a_full_request_log_stops_all_traffic`, `test_gateway_log.py::test_the_api_stores_every_row_it_can_and_a_placeholder_for_each_it_cannot`, `test_security_fuzz3.py::test_fz38_a_tunnel_without_a_request_has_one_row` | GW-11, FZ-38 to FZ-40 | None known for the gateway's own traffic. The log records what was sent, not whether the worker's evidence matches it (T5.11) |
| T5.6 | E | The worker reaches the database, a key, a blob, or a person's route | No network with the database; no database URL, master key, blob volume or Anthropic key in the worker; the relay forwards only `GET`/`POST` to `^/worker/...` (`gateway.CONTROL_PATH`) and only two headers; each job token opens its own job only while it runs, and writes only what its kind may write (`workerapi.WRITES`). `test_gateway.py::test_the_control_port_relays_nothing_else`, `test_worker_api.py::test_a_job_token_opens_only_its_own_job`, `test_writes_are_limited_by_the_job_kind`, `test_the_worker_cannot_write_receipts_or_change_scope_or_rules`, `test_rows_out_of_scope_are_refused_and_never_stored` | GW-9 | None known |
| T5.7 | E | The worker reaches the Docker host, the deployment's own containers or a cloud metadata service | The gateway refuses loopback, link-local, metadata addresses outside link-local (`gateway.METADATA_ADDRESSES`), the deployment's containers by every alias (`gateway.DENY_HOSTS`), the subnets of its own networks except the lab's (`gateway.interface_networks`), and IPv6 forms that embed a refused IPv4 address (`gateway.embedded_ipv4`); it connects to the address it checked. The internal networks give the host no address. `test_security_gateway.py::test_gw5_metadata_addresses_outside_link_local_are_refused`, `test_gw6_every_address_of_the_deployments_containers_is_refused`, `test_gw8_the_gateways_own_networks_are_refused_except_the_labs`, `test_gw8_the_docker_host_has_no_address_on_the_worker_and_gateway_internal_networks`, `test_security_recheck.py::test_gw8_addresses_that_embed_a_refused_ipv4_address_are_refused` | GW-5, GW-6, GW-8, RECHECK GW-5/GW-8 | **The gateway can reach the host's addresses on networks it is not on** (another bridge, `docker0`, the host's LAN address) if an in-scope name resolves to one. INSTALL §6 suggests a host firewall rule; it has not been measured. With IPv6 enabled on the Docker networks, the worker could reach the host's IPv6 address directly |
| T5.8 | I | A tool or agent obtains a test account's session | The session is never in the worker: the gateway adds it per request and scrubs every value of it from the response, decoded and in common encodings, before the worker sees it; compressed bodies are decoded first or withheld (`gateway.scrub_response`, `gateway.account_values`). `test_test_accounts.py::test_a_request_as_a_has_as_session_and_the_worker_never_sees_it`, `test_the_raw_credentials_appear_nowhere_that_is_stored_or_shown`, `test_security_gateway.py::test_gw3_a_compressed_response_is_scrubbed_too`, `test_gw4_a_reflected_session_is_scrubbed_in_its_decoded_and_escaped_forms` | GW-3, GW-4, GW-10 | A session reflected in another form (base64, part of the value) is not scrubbed |
| T5.9 | I | A tool takes the Anthropic key | The key is on the gateway only, added to agent calls after any client key is removed. `test_agent.py::test_worker_has_no_anthropic_key_and_the_gateway_adds_it` | GW (secrets sound) | None known |
| T5.10 | I | A compromised worker exfiltrates what it holds (lane context, recon output) | No route out; agent calls to the Claude API may carry only the agent loop's own keys and custom tools (T8.1) | GW-1 | Two documented channels remain: data in URLs of GET requests to the fixed list of passive sources, and in DNS questions for in-scope names. Both are logged |
| T5.11 | T | A compromised worker records wrong content inside its own jobs (fabricated observations or exchanges) | Rows carry the job's and engagement's ids and nothing the worker chose; scope and redaction run again in the API; agent evidence can cite only exchanges the API stored for this run; agent evidence is marked `[agent]`. `test_agent.py::test_evidence_cites_only_this_runs_exchanges_and_is_chained`, `test_worker_api.py::test_agent_exchanges_are_checked_again_by_the_api` | (WORKER_API.md) | The API cannot know what a target really answered. The gateway's request log is the independent record of what was sent, but **a recorded exchange is not checked against the gateway's log row** before it becomes evidence (`GATEWAY.md`, "Not done here") |
| T5.12 | E | The worker claims and runs other queued jobs with its worker token | Each job it claims is held to its own engagement's rules and its kind's capability; gates run again at claim time (`jobgates.check_engagement`) | (WORKER_API.md) | A compromised worker is the worker for every job it takes; it can also fail its jobs or hold them until the heartbeat timeout |
| T5.13 | E | A prompt-injected agent acts on instructions in target content | Target content is framed as untrusted data in the prompt and every tool result (`agentloop.py`); the agent's tools reach the lane's host only, read-only, within a request budget; it cannot close a lane or issue a receipt; writes need a person's approval of that exact request, used once, within 15 minutes, and a DELETE a second confirmation by typing its path (`agenttools.Toolbox`, `approvals.py`, D-041). `test_agent.py::test_target_content_is_framed_as_data`, `test_no_tool_can_close_a_lane_or_issue_a_receipt`, `test_requests_off_the_lane_host_are_refused_and_never_sent`, `test_request_budget_is_enforced`, `test_test_accounts.py::test_an_approval_binds_the_exact_request`, `test_a_delete_needs_its_second_confirmation`, `test_an_approval_expires` | GW-10, AUTH-5 | An injected agent can still mark items done with weak evidence or N/A with a plausible reason, record misleading leads, and propose writes with persuasive reasons. **The reviewer is the control**: agent work is labelled, and only a person signs |

### B6. The gateway and the API

| ID | STRIDE | Threat | Controls (code; test) | Review | Residual risk |
|---|---|---|---|---|---|
| T6.1 | S | Something other than the gateway calls `/gateway/*` (rules, test-account headers, approvals, log) | The gateway token, one per organization, in a volume only the gateway and the API mount; job credentials checked per call, answered only for a running job (`gatewayapi._running_job`); test-account headers only for a running agent job and a host named for the account. `test_test_accounts.py::test_the_account_route_answers_the_gateway_only_for_agent_jobs_and_named_hosts`, `test_organizations.py::test_a_gateway_answers_for_its_organization_only` | AUTH (gateway routes), AUTH-4, TM-1 (fixed) | Since TM-1 the routes answer only on the control network (T2.12). Gateway and API talk plain HTTP on that Docker network (`WORKER_API.md`, "Not done here") |
| T6.2 | E, T | The gateway itself is compromised (it parses every hostile response) | It holds no database credentials and no engagement key; it runs hardened (no capabilities, read-only root, its own user: SC-1); requests and responses go through h11 0.16; its TLS, HTTP and DNS handling were fuzzed; the API checks an approval's method, URL, body and account again before marking it sent (`approvals.consume`) | SC-1, FZ-20 to FZ-22, FZ-35 to FZ-40 | **The gateway is trusted** for scope, rate and the log. A compromised gateway could send anything anywhere, write false log rows, use the Anthropic key and the test-account sessions of running agent jobs, and read the HTTPS traffic it terminates: see "A compromised gateway" below (TM-6) |

#### A compromised gateway (TM-6)

The gateway parses every response a target sends (HTTP through h11, TLS, DNS), so a parser bug
there is the most likely way in from outside. `GATEWAY.md` and `WORKER_API.md` model a
compromised worker; this is what follows if the gateway itself runs an attacker's code.

What it holds:

| Held | Where | What it opens |
|---|---|---|
| The CA's private key | `gateway-private` volume, the gateway only | Certificates the worker's tools trust, for any host. People's browsers do not trust this CA |
| The gateway token | `gateway-control` volume, shared with the API | The `/gateway/*` routes for its organization: job credentials checked (`session`), test-account headers for running agent jobs on named hosts (`account`), the exact approved write of a running job (`approval`), the DNS scopes of running jobs (`dns-scopes`), request-log rows (`log`), and purge notices (`content-deleted`) |
| The Anthropic API key | its environment | The Claude API, billed to the deployer |
| In memory, while jobs run | | Each job's gateway secret, the test-account sessions it adds to agent requests, the approved writes' bodies, and every request and response of the tools and agents in clear (it terminates their TLS) |
| On the worker's relay | | The worker token and each job's token as they pass through |

What it does not hold: the database credentials, the master key, any engagement key, the blob
store, the report seal key, reviewers' keys, people's passwords or sessions, or the operator token.
The routes its token opens write only request-log rows and an approval's outcome; none writes
evidence, receipts, the audit log or the key log.

What it could do:

- Send any traffic anywhere it can route (it is on the default network): out of scope, write
  methods, above the rate ceiling, without or with a forged research identification. Scope,
  methods, rate and identification are its own checks (T5.1 to T5.4).
- Leave rows out of the request log, or write false ones for its organization's engagements and
  jobs: the log is its statement, and the API checks only each row's form (T5.5).
- Alter what targets answered before the worker sees it, so tool and agent evidence records a
  different answer; or send a write that differs from the one a person approved and report the
  approved one as sent. The API cannot see what really went over the wire (T5.11).
- Use the test-account sessions of running agent jobs beyond the approved requests, and the
  Anthropic key for anything.
- Act as the worker, with the tokens it relays: claim queued jobs of its organization and write
  their results within each job kind's limits (T5.12).
- Try the API's other routes from the control network: they need a person's session or the
  operator token, which it does not have, and the sign-in lockout applies to its address.

What still holds, or detects it:

- Reports still verify or fail on their own: the evidence and history chains, reviewers'
  signatures, timestamps and the seal are made without the gateway, and it can change none of
  them. A reviewer still has to sign over evidence it may have falsified (section 6: the ledger
  proves what was recorded, not that a target answered so).
- The targets' own logs are the record it does not control: with the research identification,
  the customer can compare what reached its servers with the report's request log. Traffic that
  is not in the log, or rows with no traffic behind them, show there.
- The Anthropic console shows the key's use; rotating the key, the gateway token (delete the
  `gateway-control` file and restart) and the CA (`GATEWAY.md`, "Operations") ends what it held.
- Its container has no capabilities, a read-only root and its own user (SC-1), no database
  network, and no volume but its own and the token's: a compromise stays in the gateway unless
  it escapes the container (T12.3).

Not done: running the parsers in a separate, unprivileged process from the one that holds the
keys; comparing an agent's recorded exchanges with the gateway's log rows (`GATEWAY.md`, "Not
done here"); signing log rows with a key the gateway does not hold. Until then **the gateway is
trusted** for scope, rate, identification and the request log.

### B7. The gateway and targets (a malicious target)

| ID | STRIDE | Threat | Controls (code; test) | Review | Residual risk |
|---|---|---|---|---|---|
| T7.1 | D | A target holds connections open (endless `100 Continue`, a head a line at a time) or sends a malformed reply | A response head has 90 seconds in all and at most 32 informational answers (`gateway.HEAD_TIMEOUT`); a scrubbed body 300 seconds and 20 MB (`gateway.MAX_SCRUBBED_BODY`); malformed replies are refused by h11 and logged. `test_security_fuzz2.py::test_fz22_a_target_that_never_ends_its_head_is_a_failed_row_in_bounded_time`, `test_fz22_a_test_accounts_response_body_is_read_in_bounded_time` | FZ-22 | None known |
| T7.2 | I | Secrets in captured traffic (cookies, tokens, passwords in forms, XML, GraphQL, SAML) reach append-only evidence | Redaction before anything is stored, and before the model sees it (`redact.http_message`, `redact.SECRET_NAMES`, D-038); the evidence summary, which the chain commits to, counts what was redacted. `test_redact.py`, `test_security_evidence.py::test_ev7_cloud_api_key_headers_are_redacted`, `test_security_fuzz2.py::test_fz23_secrets_in_xml_and_html_are_redacted`, `test_security_fuzz3.py::test_fz41_a_saml_assertion_in_other_xml_is_replaced_whole`, `test_fz42_positional_xmlrpc_credentials_are_replaced` | EV-7, FZ-6 to FZ-10, FZ-15, FZ-23 to FZ-27, FZ-41 to FZ-44 | Pattern- and name-based, not general personal-data detection; binary and compressed bodies are stored as they are; `redact.py` lists the forms it does not cover. An owner can switch redaction off for a lab (audited) |
| T7.3 | D | A hostile page or bundle stalls an import, a recon step or an agent turn (catastrophic regular expressions) | Every text parser was fuzzed for linear time on pumped input. `test_security_fuzz.py::test_fz6_spaces_inside_an_authorization_value_are_linear`, `test_fz11_unclosed_comments_scripts_and_titles_are_linear` and the other FZ tests | FZ-6, FZ-11 to FZ-13 | Python's `HTMLParser` was not fuzzed beyond the public functions |
| T7.4 | E | A hostile response exploits a recon tool in the worker | The tool is in the worker's sandbox (no route but the gateway, no keys, no capabilities, read-only root) and behind the gateway's checks | SC-12 | **The worker's Go tools have known advisories with fixes** (35 HIGH or CRITICAL rows), not yet moved; the likely effect is a crashed or hung tool within its job (`security-review/SUPPLY_CHAIN.md`) |
| T7.5 | T, I | A network attacker between the gateway and a target reads or changes traffic | None for targets: the gateway does not verify target certificates, as the tools did not (they record hosts with odd certificates) | (GATEWAY.md) | Accepted by design. Passive sources and the Claude API are verified |
| T7.6 | E | An in-scope name resolves to an internal address of the customer's network | The gateway resolves the name itself, refuses the address classes in T5.7, and connects to the address it checked, so a DNS answer cannot change between check and use. `test_security_gateway.py::test_gw8_the_gateways_own_networks_are_refused_except_the_labs` | GW (rebinding sound) | Other private addresses are allowed on purpose: an internal pentest needs them. The scope decides |

Hostile content shown to people is under T2.8; hostile reports shown by the verifier under T1.7.

### B8. The gateway and third-party services

| ID | STRIDE | Threat | Controls (code; test) | Review | Residual risk |
|---|---|---|---|---|---|
| T8.1 | E, I | An agent call makes Anthropic's servers fetch or connect to other hosts (server tools, the MCP connector, URL sources), outside the scope, the rate and the log | The gateway parses the body strictly and sends it only with the agent loop's own keys (`gateway.SERVICE_BODY_KEYS`), custom tools only and no URL source (`gateway.Policy.check_service_body`). `test_security_gateway.py::test_gw1_claude_api_calls_cannot_make_anthropic_fetch_for_the_worker`, `test_gw1_the_agents_own_calls_are_still_sent`, `test_security_recheck.py` (`test_gw1_held_*`, 17 bodies) | GW-1 (High) | Relies on Anthropic's parser reading JSON keys case-sensitively, as it does (RECHECK) |
| T8.2 | I | What the Claude API receives | Only agent runs send anything; they send the lane's context and the redacted exchanges; AttackLedger stores no transcript | RETENTION | Anthropic sees that data and keeps it under its own terms; content deletion cannot reach it. Agents are off unless `ANTHROPIC_API_KEY` is set |
| T8.3 | I | Passive sources learn about the engagement | Only passive jobs reach them, GET/HEAD/OPTIONS only, without the research identification, at most 10 per second per host, logged (`gateway.PASSIVE_HOSTS`) | (GATEWAY.md) | Each source learns which domains were looked up |
| T8.4 | S | A third party is impersonated to the gateway | Upstream certificates are verified for passive sources and the Claude API | GW (sound) | None known |

### B9. The API and the timestamp authority

| ID | STRIDE | Threat | Controls (code; test) | Review | Residual risk |
|---|---|---|---|---|---|
| T9.1 | I | The authority learns what was tested | Only the SHA-256 of a fixed statement (manifest hash and signature, or body hash and seal) is sent (`timestamps.py`, `seal.statement`) | (D-034) | The authority learns when receipts are closed |
| T9.2 | T, S | A forged or replayed timestamp | The server checks that the reply answers its request (hash and nonce); the verifiers check the token's signature and chain to a root the reader trusts. `test_timestamps.py::test_server_refuses_replies_for_other_requests`, `test_token_verifies_offline_and_tampering_is_caught` | (D-034) | The default authority is reached over plain HTTP (`http://timestamp.digicert.com`): a network attacker can block timestamps, not forge them. A close without a timestamp still succeeds and says so |

### B10. Operators with shell access

| ID | STRIDE | Threat | Controls (code; test) | Review | Residual risk |
|---|---|---|---|---|---|
| T10.1 | T, S, R, I, E | An operator reads the master key and the database, rewrites rows, registers a key for someone, resets a password, or seals any report | Visibility, not prevention: a key registered by the operator is a key-log entry saying so and is shown to the person at their next sign-in; a password reset ends the person's sessions and is an audit entry; a rewrite breaks the heads of reports already sent and the signatures over them; reviewers' private keys are never on the server, so their signatures cannot be forged. `test_keytrust.py::test_operator_reset_and_revoke_on_the_server`, `test_auditlog.py::test_password_events_and_the_operator_cli` | (D-036, D-037, D-055) | **Whoever runs the server is the root of trust** for anything not covered by a reviewer's signature or a timestamp. Membership of the `docker` group is root on the host (INSTALL §13) |

### B11. Backups

| ID | STRIDE | Threat | Controls (code; test) | Review | Residual risk |
|---|---|---|---|---|---|
| T11.1 | I | Someone with a copy of a backup reads it | The blob archive is encrypted (engagement keys wrapped by the master key, which is not in the backup); passwords and sessions are hashes; the backup folder is created with `umask 077` (`tools/backup.sh`). `test_retention.py::test_the_deletion_screen_and_the_backup_tools_say_that_backups_are_not_reached` | RET-7 | **The database dump is plaintext**: recon results, URLs, job logs, the request log, imported entries, the audit log and the scope. `tools/backup.sh` does not encrypt it; storing backups securely is the deployer's. A backup together with the master key opens every engagement and the seal key, so its holder could seal reports in the instance's name |
| T11.2 | T | Restoring an old backup brings deleted content back | Documented in `tools/restore.sh`, `INSTALL.md` §7 and §14 and the deletion screen | RET-7 | The engagement then shows no deletion; it must be deleted again |

### B12. Supply chain and the public site

| ID | STRIDE | Threat | Controls (code; test) | Review | Residual risk |
|---|---|---|---|---|---|
| T12.1 | T, E | A compromised base image, package, tool or action enters a build | Every image by multi-arch digest; Python packages by hash (`--require-hashes`, wheels only except Arjun's two hash-pinned source packages); npm by lockfile without install scripts; Go modules against `go.sum` and the checksum database; tool downloads by recorded SHA-256; GitHub Actions by commit. `test_supply_chain.py::test_images_are_pinned_by_digest`, `test_dockerfile_base_images_are_pinned_by_digest`, `test_every_pip_install_is_hash_pinned`, `test_locks_hash_every_package_and_match_their_input`, `test_web_build_installs_the_lockfile_without_scripts`, `test_github_actions_are_pinned_by_commit` | SC-2, SC-3, SC-5, SC-6 | **OS packages are not version-pinned** (signed indexes, but drift between builds). Images and git tags are not signed and no build provenance is published. Some downloads are checked against hashes recorded at pin time, not publishers' signatures. Arjun is built from source packages whose `setup.py` runs at build time |
| T12.2 | E | A vulnerable dependency is exploited | `pip-audit`, `npm audit`, an OS and Go-binary image scan (`tools/scan_images.sh`) and an SBOM (`tools/sbom.sh`), run weekly by `.github/workflows/security.yml`; Dependabot. `test_supply_chain.py::test_image_scan_reads_go_binaries_and_fails_on_expired_entries` | SC-4, SC-10 to SC-12 | Known open rows: the worker's Go tools (T7.4) and Caddy's, accepted until 2026-11-11. The workflows had not yet run on GitHub when the review was written. Pin refreshes are manual (`tools/refresh_pins.sh`) |
| T12.3 | E | A container escape or lateral move after a compromise | Every container: no capabilities (Caddy keeps one), `no-new-privileges`, read-only root, a non-root user (Caddy excepted), memory and process limits, `noexec` temporary filesystems. `test_supply_chain.py::test_every_service_is_hardened` | SC-1 | Docker's default seccomp profile only; no AppArmor profile of our own; no user-namespace remapping unless the operator enables it |
| T12.4 | T | The public verifier page is changed | One self-contained file under a strict policy, built by `tools/build_verify.sh`; `tools/build_pages.sh` refuses a page whose hashes do not match its policy; the site tests compare it byte for byte with `site/` | WE (site phase) | Trust in the site is trust in the repository and in the Cloudflare and GitHub accounts behind it (T1.8) |

## 6. What the signatures and the seal prove against a dishonest operator

A report is produced by the server of whoever ran the test. An auditor may need to know what a
report still proves if that party is not honest. In short: **the reviewers' signatures are the
evidence of the review; the seal is only the server's statement** (D-036, D-037, D-055,
`VERIFIER.md`).

| A valid report proves | Provided that |
|---|---|
| Each signed receipt was signed by the holder of that key, over exactly that lane's items, N/A reasons and evidence hashes, and the evidence chain up to its head | The reader compared the signer's key fingerprint with one obtained out of band (from the reviewer, not from the report) |
| The signer held the reviewer role (or was an owner) and had that name and email, by the history up to the signed head; no entry the signature relies on was left out (payload v4) | The receipt is payload v4 (`--require-history` fails older ones) |
| The receipt existed by the token's time and cannot be backdated | It carries a timestamp from an authority whose root the reader trusts |
| The report, its audit log and key log were complete up to the sealed heads when the server exported it | The seal key is the tester's server's: a receipt signature covers its registration (the verifier says so), or the reader compared its fingerprint out of band |

| A valid report does not prove | Why |
|---|---|
| That the server is honest | Whoever holds the seal key (the operator, or anyone with the master key and the blob store) can seal a report built from an edited database, or one made before a void |
| That the evidence is genuine | The ledger proves what was recorded, when and by whom, not that a target really answered that way. Manual evidence is the tester's word; tool and agent evidence is the worker's, and the gateway's log is not compared with it (T5.11) |
| That the test was complete | Coverage is what the pack's items say and what people marked; a lane marked N/A has a reason, not a test |
| That the reviewer actually reviewed | A signature is a statement. Separation of duties (if on) only stops a person signing their own evidence |
| That nothing happened after the newest signature | After the newest receipt signature, the history is bound by the seal alone |
| That this is the latest report | A report sealed before a void is a valid report of its time (T1.10) |
| That the browser signed only what the reviewer saw | The code that uses the reviewer's key is served by the installation (T3.5, TM-4, `VERIFIER.md`) |

## 7. Out of scope and accepted residual risk

Out of scope by design:

- **Dishonest operators**, beyond what section 6 makes visible. The product does not try to protect
  against the server's operator; it keeps reviewers' signatures independent of them.
- **Denial of service** by people with an account, and volume attacks on the installation.
  `SECURITY.md` also excludes them from testing.
- **Compromised devices and browser extensions** of the people using AttackLedger.
- **Third-party services**: Anthropic, the passive sources, the timestamp authority, Cloudflare,
  GitHub. What they receive is listed under B8 and B9.
- **Whether a test was good.** AttackLedger proves what was recorded and signed, not the quality
  of the testing.

Accepted residual risks (each is described in the table named):

- The seal proves what the server stated, not that the server is honest (T1.4, section 6).
- The gateway can reach the host's addresses on networks it is not on, such as the host's LAN;
  the suggested firewall rule is untested (T5.7).
- Content deletion does not reach old backups, Postgres's dead rows and write-ahead log,
  container logs, browsers and copies, or what the Claude API received; evidence URIs and the
  free text of audit entries written before migration 0028 are kept by design (T4.5, T8.2, T11.1).
- The database dump in a backup is not encrypted (T11.1).
- The gateway does not verify target certificates (T7.5).
- A compromised worker can still send read-only traffic within its engagements' scope, use the
  passive-source and DNS channels, and record wrong content inside its own jobs (T5.10 to T5.12).
- A prompt-injected agent can mislead within its lane; the reviewer is the control (T5.13).
- Redaction is pattern-based (T7.2).
- OS packages are unpinned, images and tags unsigned, and the worker's Go tools carry known
  advisories (T12.1, T12.2, T7.4).
- Tenant isolation is the ORM's, without database row-level security (T2.7).
- People sign in with a password alone; there is no second factor (T2.1, TM-2). Deployers who
  need one put AttackLedger behind their organisation's SSO or VPN.
- Code served on the installation's origin can use a reviewer's signing key (T3.5, TM-4).
- The gateway is trusted for scope, rate, identification and the request log; a compromised
  gateway is described under B6 (T6.2, TM-6).
- The append-only triggers stop changes sent through the application, not a database
  superuser; the hash chains remain the proof (T4.2, TM-5).
- **No independent third-party test** has been made. The security review was the author's, with
  AI agents (`security-review/README.md`).

## 8. Gaps noted while writing this model

Writing this model meant looking for a control behind every threat. These are the places where an
auditor might expect one and the code had none, or where the residual risk was not stated in the
other documents. Three were fixed in the code, each with tests that failed before the fix; the
other three are documented, and one of them (TM-2) is the deployer's decision.

| ID | Gap | Where seen | Status |
|---|---|---|---|
| TM-1 | The machine routes (`/gateway/*`, `/worker/*`, including `/worker/jobs/{id}/*`) were reachable through the public HTTPS front end: `web/nginx.conf` forwarded all of `/api/` to the API, and `authz.authorize` checked only the token, not where the call came from. A leaked gateway token would have let someone outside write request-log rows and read the DNS scopes of running engagements; a leaked worker token, claim queued jobs with their specifications | `web/nginx.conf` (`location /api/`), `authz.RULES` | **Fixed** (`bef9636`, `02082a9`). nginx refuses `/api/gateway/` and `/api/worker/` with the API's own 404, in every spelling (case, `//`, `%67`, `%2F`, dot segments), by a regular-expression location matched on the normalized path. The API answers the gateway, worker and job routes only on its control-network address (`ATTACKLEDGER_CONTROL_LISTEN=api-control`), judged by the connection's local address, which the kernel sets, never by `X-Forwarded-For`, which uvicorn trusts in production; the gateway calls the API by that alias. Tests: `test_machine_routes.py`, `test_web_headers.py` (the nginx variants), `e2e/tests/token/machine.spec.ts`. On a stack copy, every spelling through nginx and every call on the API's default-network address answered 404, while the worker claimed and ran a lab probe through the gateway's relay and the gateway wrote its log |
| TM-2 | No second sign-in factor for people (TOTP, WebAuthn or SSO). A password alone opens an owner's or a reviewer's account; the reviewer's signature still needs their browser key | `auth.py` | **Documented; the deployer's decision.** AttackLedger has no second factor. `INSTALL.md` (sections 10 and 13) and section 9 here say so, and suggest putting AttackLedger behind the organisation's SSO (an authenticating proxy) or VPN, so that the password is the second step and not the only one |
| TM-3 | Sessions had a 12-hour absolute lifetime and no idle timeout | `auth.SESSION_HOURS` | **Fixed** (`f30a4fd`, `a1e25ff`). Every session, a person's or the token's, ends after `ATTACKLEDGER_SESSION_IDLE_MINUTES` (default 30) without use, and 12 hours after sign-in in any case. The last use (`user_sessions.last_seen_at`, migration 0027) is written at most once a minute; requests the web app sends on its own while nobody has used the page for a minute carry `X-AttackLedger-Background` and do not count, so a page left open is signed out too. The web app shows "Your session expired" and keeps unsent drafts. Tests: `test_session_idle.py` (a fake clock), `e2e/tests/people/session.spec.ts`. On a stack copy with a one-minute limit, a session polled only in the background ended after the minute, and one used every 22 seconds stayed open once the write interval was scaled to the limit (`a1e25ff`, found there) |
| TM-4 | The reviewer's key is non-extractable, but any code the installation serves on its origin can use it. A dishonest operator or a tampered web image could have the browser sign a payload the reviewer did not see. `DECISIONS.md` (D-033) and `VERIFIER.md` did not say this | `web/src/signing.ts`, D-033 | **Documented** in `VERIFIER.md` ("What a signature does not prove") and D-033, and in T3.5 and section 6 here. A longer-term option is to show the reviewer the signed payload's facts before signing, and to let reviewers check the web image they are served |
| TM-5 | Append-only was enforced by the application only. The API connects as the role the Postgres image creates from `POSTGRES_USER`, a superuser, and no trigger, rule or grant stopped an `UPDATE` or `DELETE` on `evidence`, `receipts`, `audit_log` or `key_log` | `docker-compose.yml`, `deploy/compose.prod.yml`, `server/migrations/` | **Fixed** (`260fcd8`). Migration 0026 adds triggers, on Postgres and SQLite, to `evidence`, `receipts`, `gateway_requests`, `audit_log` and `key_log`: every `DELETE` (and `TRUNCATE`) is refused, and every `UPDATE` except the three changes the product makes (an evidence row's `summary_enc` set to NULL and a request-log row's `url` and `reason` set to `''` when the engagement's content is deleted; a receipt's four timestamp columns while it has no timestamp token). Tests: `test_appendonly.py` on a database made from the models and one migrated to head, on both backends; content deletion, retention, a later timestamp and a backup restored with `tools/restore.sh` work on a Postgres stack copy. **A database superuser can still drop the triggers**, so the hash chains remain the proof. A separate database role for the API without the right to alter these tables is the next step |
| TM-6 | The design documents modelled a compromised worker but not a compromised gateway, which parses every hostile response and holds the CA key, the Anthropic key and the gateway token, and sees test-account sessions and approved writes in clear (T6.2) | `GATEWAY.md` "Threat model" | **Documented** under B6, "A compromised gateway": what it holds, what it could do, and what still holds or detects it |

## 9. Assumptions: what the deployer must do

The controls above hold only if the installation is set up as [INSTALL.md](INSTALL.md) says. In particular:

| Assumption | Why it matters | Where |
|---|---|---|
| Use the production compose file (`deploy/compose.prod.yml`, set through `COMPOSE_FILE` in `.env`) | It turns on setup mode (`ATTACKLEDGER_REQUIRE_SIGN_IN=1`), secure cookies, the published ports through Caddy only, and turns off the development key | INSTALL §4, §8 |
| Put AttackLedger behind the organisation's SSO (an authenticating proxy in front of Caddy) or VPN if a password alone is not enough for its policy | There is no second sign-in factor (TM-2) | INSTALL §10, §13 |
| Keep `ATTACKLEDGER_CONTROL_LISTEN` and the gateway's `ATTACKLEDGER_API_URL` as `docker-compose.yml` sets them | The machine routes answer only on the control network (TM-1) | `docker-compose.yml`, [WORKER_API.md](WORKER_API.md) |
| HTTPS with a real certificate (option A or B) for real work; protect the TLS private key | Session cookies and signing keys depend on a secure page; option D is for trials | INSTALL §5 |
| Create the master key as INSTALL §7 says, readable only by the API's user, **kept apart from the backups**, and copied to a vault or safe; rotate it when someone who had it leaves | It opens every engagement's content and the seal key | INSTALL §7, §13, [ENCRYPTION.md](ENCRYPTION.md) |
| Back up the database and the blob store together, store the backups securely (the dump is plaintext), and keep them no longer than the retention you promise; delete content again after restoring an older backup | Deletion does not reach backups | INSTALL §14, [security-review/RETENTION.md](security-review/RETENTION.md) |
| Add the host firewall rule of INSTALL §6 if the host runs services on all interfaces; keep IPv6 off on the Docker networks | The gateway can otherwise reach the host's other addresses | INSTALL §6, T5.7 |
| Give shell access and membership of the `docker` group only to administrators | Either is root over the keys and the database | INSTALL §13, T10.1 |
| Create the first owner on the server; leave the operator token empty unless scripts need it | The token acts as an owner (it cannot sign) | INSTALL §4, §9 |
| For audit-grade engagements, turn on *require signatures* and *separation of duties*, keep evidence redaction on, and keep a timestamp authority configured | *Require signatures* and *separation of duties* are off by default (redaction is on); without a timestamp authority, times are the server's | `models.py`, D-032, D-033, D-034, D-038 |
| Give reviewers' key fingerprints and the seal key's fingerprint to the report's readers by a channel other than the report | Every signature check is only as good as the fingerprint the reader compares | [VERIFIER.md](VERIFIER.md), INSTALL §11 |
| Use full-disk encryption on the host | Deleted files and Postgres pages stay on disk until overwritten | [security-review/RETENTION.md](security-review/RETENTION.md) |
| Refresh pinned images and packages (`tools/refresh_pins.sh`), rebuild, and watch the weekly security workflow | Pins do not pick up security fixes by themselves | [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md) |
| Read `docker compose logs` as sensitive | uvicorn's access log has request lines with query strings; the gateway's errors can quote a target | INSTALL §16, [security-review/RETENTION.md](security-review/RETENTION.md) |

## 10. How to use this document as an auditor

**To judge a report you received:**

1. Verify it yourself: `python3 tools/verify_report.py report.json --require-history`, from a
   checkout of the AttackLedger repository (standard library only, no network), or drop it on
   `attackledger.com/verify` with *Require the full change history* ticked. Use
   `--require-signatures` too if every receipt should be signed. Exit code 0 is a pass, 1 a failed
   check, 2 a report that cannot be checked.
2. Compare the reviewers' key fingerprints and the seal key's fingerprint (Integrity section) with
   values the tester gave you by another channel (T1.1, T1.4).
3. Check that `sealed_at`, or the seal's timestamp, is when you expect the report to have been
   made (T1.10), and which timestamp authority's root you are trusting (T1.6).
4. For an HTML report, compare the page with the list the verifier prints of what the verified
   JSON says (T1.5).
5. Read the report's engagement settings (separation of duties, signatures required, redaction)
   and the change history for the roles and scope in force (T2.6).
6. Read section 6 for what a passing report does not prove.

**To review the product:**

| Question | Where to look |
|---|---|
| What runs and how it fits together | [ARCHITECTURE.md](ARCHITECTURE.md) (and its "Invariants worth keeping"), this document's section 2 |
| How traffic is held to the scope | [GATEWAY.md](GATEWAY.md), [security-review/GATEWAY.md](security-review/GATEWAY.md); code `server/app/gateway.py`, `server/app/scope.py` |
| What the worker can and cannot do | [WORKER_API.md](WORKER_API.md); code `server/app/workerapi.py` |
| How evidence, receipts and reports are built and checked | [VERIFIER.md](VERIFIER.md), [ENCRYPTION.md](ENCRYPTION.md) (chain record v2), [security-review/EVIDENCE.md](security-review/EVIDENCE.md); code `server/app/ledger.py`, `gates.py`, `seal.py`, `tools/verify_report.py` |
| Who may do what | [ARCHITECTURE.md](ARCHITECTURE.md) "Authentication and permissions", [security-review/AUTH.md](security-review/AUTH.md); code `server/app/authz.py` (`RULES`), `auth.py` |
| Writes and test accounts | [APPROVALS.md](APPROVALS.md) |
| Encryption, retention and deletion | [ENCRYPTION.md](ENCRYPTION.md), [security-review/RETENTION.md](security-review/RETENTION.md) |
| Tenants | [ORGANIZATIONS.md](ORGANIZATIONS.md) |
| Why each decision was taken | [DECISIONS.md](DECISIONS.md) (D-0xx numbers are cited throughout) |
| Containers and dependencies | [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md), [security-review/SUPPLY_CHAIN.md](security-review/SUPPLY_CHAIN.md) |
| Parsers of hostile input | [security-review/FUZZING.md](security-review/FUZZING.md) |
| The web app in real browsers | `security-review/WEB_E2E.md` |
| Which findings were fixed, and how a second reviewer tried to bypass the fixes | [security-review/README.md](security-review/README.md), [security-review/RECHECK.md](security-review/RECHECK.md) |
| Control mappings (WSTG, ISO, PCI and others) | [CONTROLS.md](CONTROLS.md) |
| How to report a vulnerability | [SECURITY.md](../SECURITY.md) |

**To reproduce the tests** (from a checkout; each finding ID in the review has a named regression
test that failed before its fix):

| What | Command | Needs |
|---|---|---|
| The server suite on SQLite, including the fuzz tests at their seeded default size | `cd server && python -m pytest -q tests` | Python 3.12 and the hash-pinned `server/requirements.txt` (pytest included), or the API image |
| The same suite on Postgres 16 in a non-UTC time zone, then the migration-0022 upgrade check | `tools/test_postgres.sh` | Docker and the API image; starts and removes its own Postgres |
| The browser verifier against `verify_report.py`, report by report and building block by building block | `cd web && npm ci --ignore-scripts && cd .. && tools/verifier_equivalence/run.sh` (add `--fuzz 500 --seed 20261010` for random mutants) | Python 3 and Node 20 or later |
| The web app and the public site in Chromium, Firefox and WebKit, with hostile content, headers, sessions, roles and CSRF | `tools/test_e2e.sh` | Docker only; runs on its own network with no route out and removes what it started |
| One finding's regression tests | for example `cd server && python -m pytest -q tests/test_security_gateway.py -k gw8` | as the suite |
| Longer fuzzing runs | `ATTACKLEDGER_FUZZ_ITERATIONS=5000 ATTACKLEDGER_FUZZ_SEED=7 python -m pytest -q tests/test_fuzz.py` (and `test_fuzz2.py`, `test_fuzz3.py`) | as the suite |
| The containers' hardening and pins | `cd server && python -m pytest -q tests/test_supply_chain.py`; `tools/scan_images.sh`; `tools/sbom.sh` | Docker for the scan and the SBOM |
| The chains on a running installation | `docker compose exec -T api python -m app.people audit-log \| tail -n 1` and `key-log` (each ends with `chain: intact`) | Shell on the server |

The CI workflow `.github/workflows/tests.yml` runs the first four on every push and pull request (`CONTRIBUTING.md`, "What the CI runs"). [security-review/SUPPLY_CHAIN.md](security-review/SUPPLY_CHAIN.md) notes that the workflows had not yet run on GitHub when it was written.
