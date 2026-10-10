# Security review: evidence integrity, encryption, imports, reports and the web front end

Date: 2026-10-10. Branch `sec-review-evidence`, from `c3557a5`. White-box review of our own
code, run on localhost only: the server test suite in the API image, the two verifiers, and
the web bundle under Node. No traffic went to any external host.

Severity uses this scale. **High**: an attacker gets data or a verdict they should not, with
no special position. **Medium**: a verdict or a promise of the product can be defeated by
someone who handles a report or the data, with little effort. **Low**: a gap that needs an
unusual input or position, or that defence in depth already covers.

## Findings

| ID | Severity | Finding | Fix | Regression test |
|---|---|---|---|---|
| EV-1 | Medium | A voided receipt can be reported as receipted and still verify | `d46f16b` | `test_ev1_a_voided_receipt_cannot_be_reported_as_receipted` |
| EV-2 | Medium | The receipt's issue time is not bound to the signed one; moving it skips the reviewer-role check | `d46f16b` | `test_ev2_the_receipt_issue_time_must_match_the_signed_payload` |
| EV-3 | Low | The signed engagement is not compared with the report's engagement | `d46f16b` | `test_ev3_a_receipt_signed_for_another_engagement_fails` |
| EV-4 | Low | The counts printed at the top of the verifier's output are not checked | `d46f16b` | `test_ev4_the_summary_counts_must_be_the_reports_own` |
| EV-5 | Medium | An HTML report whose visible text was edited still verifies, and nothing says so | `d46f16b` (partial: a NOTE) | `test_ev5_html_reports_say_that_only_the_embedded_json_is_checked` |
| EV-6 | Medium | Deleting an engagement's content leaves every requested URL in the traffic log | `0ec997f` | `test_ev6_deleting_content_removes_the_traffic_log_urls` |
| EV-7 | Low | Azure API Management and Azure Functions key headers are stored unredacted | `f2e71e1` | `test_ev7_cloud_api_key_headers_are_redacted` |
| EV-8 | Low | Unsent drafts holding a credential in common forms are written to `sessionStorage` | `fd398cd` | reproduction below (the web app has no test runner) |
| O-1 | Low | The receipt manifest does not bind evidence to its item: two done items' ids can be swapped | `0e1f9d5` | `test_o1_swapped_item_ids_fail_under_manifest_v2`, `test_o1_new_receipts_are_over_a_manifest_that_names_each_item`, `test_o1_manifest_v1_receipts_still_close_and_verify_with_a_note` |
| O-2 | Medium | Audit and key log entries, or both logs, can be left out of a report; dropping a void entry defeats EV-1 | `0e1f9d5` (bounded: see below) | `test_o2_payload_v4_signs_the_history_heads_and_the_server_checks_them`, `test_o2_an_audit_entry_the_signature_covers_cannot_be_left_out`, `test_o2_require_history`, `test_o2_a_void_left_out_is_caught_by_any_later_signature`, `test_o2_a_void_after_the_newest_signature_is_named_as_not_covered` |
| O-3 | Medium | An HTML report's text is not verified, and the reader is not shown what was (EV-5) | `0e1f9d5` | `test_o3_a_verified_html_report_is_followed_by_its_facts` |

The EV regression tests are in `server/tests/test_security_evidence.py`. Each of them fails on
`c3557a5` (checked by running the file against a copy of that tree: 7 failed) and passes
after the fixes. EV-1 to EV-5 also have cases in `tools/verifier_equivalence/cases.json`.
The O-1 to O-3 tests are in `server/tests/test_security_verifier.py`. All 9 fail on `c7a0c25`
(checked the same way) and pass on `0e1f9d5`. They have 25 cases in `cases.json`, the
fixtures `v4-*` and `v1-item-ids-swapped`.

### The verifier threat model (EV-1 to EV-5)

A report's body hash is not a signature: anyone who edits a report can recompute it. What
protects a report is the reviewers' signatures, read against key fingerprints the reader got
out of band (D-036). A signed payload covers the engagement id and name, the lane, the
manifest hash, the evidence chain head, the signer, the key and the issue time. Everything
else in the report is repeated unsigned. The findings below are places where an unsigned copy
could contradict what was signed, or claim more than was checked, and the verifier still
printed `Verified.`

### EV-1: a voided receipt reported as receipted (Medium)

- **Where:** `tools/verify_report.py` `check_receipts`, `check_audit_log`; the same in
  `web/src/verify_report.ts`.
- **What:** D-052 keeps a receipt void for good, even when the lane is changed back so its
  manifest matches the receipt again. The report says so only through the lane's `status`
  (`stale`), which is not signed, and through a `lane.receipt_voided` entry in the audit log.
  The verifier never read the void entries. Setting `status` to `closed` (and the summary
  count up by one) and recomputing the body hash gave a report in which the voided receipt
  passed every check.
- **Reproduction:** close a lane, reopen an item and mark it done again (the lane is void,
  the manifest matches), export the report, set the lane's status to `closed`, add one to
  `summary.lanes_receipted`, recompute `integrity.body_sha256`. Before the fix: `Verified.`
- **Fix:** for every lane reported as receipted, the change-history check looks for a
  `lane.receipt_voided` entry of this engagement that names the same lane, manifest hash and
  issue time (the entry's receipt id is the server's and is not in a report). If there is
  one, it fails: "reported as receipted, but the change history records that this receipt
  was voided <time>". A later receipt with the same manifest has another issue time and is
  not affected.
- **Remaining:** a forger who also drops the void entry is caught only when a receipt signed
  after the void commits to it (O-2, D-054).
- **Recheck:** the match on the exact issue time was bypassed by moving the receipt's unsigned
  issue time by a second, inside the window EV-2 allows, with the void entry kept (so O-2's
  count held too). A void now also names a signed receipt when its issue time is in that window
  around the signed one and it came after the payload (`RECHECK.md`, EV-1).

### EV-2: the receipt's issue time is not the signed one (Medium)

- **Where:** `check_audit_log` used `receipt.issued_at`, which is not signed, to decide which
  roles, names and scope applied. The signed time is `payload.issued_at`.
- **What:** moving `issued_at` to any time changed the result of the role check. Moved before
  the first audit entry of the engagement, the check became a NOTE ("issued before the audit
  log covered this engagement"), so a signer who did not hold the reviewer role passed.
- **Reproduction:** `test_ev2_...` rewrites the audit log so the signer was only a tester
  (the verifier fails), then moves `issued_at` 30 days back: before the fix, `Verified.`
- **Fix:** the signature check fails a receipt whose `issued_at` is not between one minute
  before and 15 minutes after its payload's `issued_at`. The server accepts a payload up to
  ten minutes old (and one minute ahead) and then waits for the timestamp authority, so every
  genuine receipt is inside that window; the role check still uses the close time, as D-037
  says. D-037 now notes the window.

### EV-3: the signed engagement is not compared (Low)

- **Where:** `check_signatures`.
- **What:** the payload names the engagement (`id`, `name`); the verifier compared the lane,
  the manifest, the key and the chain head, but not the engagement. A lane signed in one
  engagement could be presented in a report that names another one (another id, name, scope
  and authorization) and still verify. The manifest's host limits this, which is why it is Low.
- **Fix:** the signature check fails when the payload's engagement id is not the report's.
  A different name is a NOTE ("signed when the engagement was named ..."), because the server
  allows a rename after signing.

### EV-4: the counts at the top of the output are not checked (Low)

- **Where:** `main` prints `summary.lanes_receipted` and `summary.evidence_entries` from the
  report, unchecked.
- **What:** a report claiming "12 receipted lanes" with two closed lanes printed that line
  and then `Verified.`
- **Fix:** the receipts check counts receipted lanes on in-scope hosts, as `report.build`
  does, and the chain check counts evidence entries; a summary that disagrees fails.

### EV-5: an HTML report's visible text is not covered (Medium, fixed in part)

- **Where:** `load` / `readReport` read only the JSON embedded in an HTML report.
- **What:** the HTML report is the client-facing document, and its "How to verify" section
  says to drop the HTML or the JSON on the verifier. Editing the page's text (a finding, a
  scope line, a name) and leaving the embedded JSON alone gives an HTML file that verifies.
- **Fix:** for an HTML file, both verifiers add a NOTE (shown with the body hash check on the
  Verify page) that only the embedded JSON was checked, not the text the page displays. The
  "How to verify" texts now say that the body hash can be recomputed by anyone and should be
  compared with the value the tester gave.
- **Remaining:** the page's text is still not verified. The verifier cannot re-render the
  page (it must stay independent of the server's code). Since O-3 it shows what the verified
  JSON says, so the reader can compare.

### EV-6: deleted content leaves the traffic log's URLs (Medium)

- **Where:** `vault.delete_content`; `gateway_requests` (`GatewayRequest`), read by
  `GET /engagements/{id}/gateway-log`.
- **What:** deleting an engagement's data removed recon URLs, inbox URLs and proposed writes'
  URLs, and the deletion screen said "Recon results: observations, URLs and leads" go. The
  gateway log kept every URL the tools and agents requested, paths and query strings
  included, readable by every role on the engagement.
- **Fix:** the deletion blanks `url` in the engagement's gateway rows, in the same
  transaction, and keeps method, host, port, status, verdict, reason and byte counts (what
  the log proves about scope and rate). Rows the gateway sends after the deletion are stored
  without a URL. The deletion screen, the `removed` counts (`gateway_urls`) and
  `docs/ENCRYPTION.md` say so.

### EV-7: cloud API key headers stored unredacted (Low)

- **Where:** `redact.SECRET_NAMES` / `SECRET_PARTS`.
- **What:** `Ocp-Apim-Subscription-Key` (Azure API Management), `X-Functions-Key` (Azure
  Functions) and `X-Master-Key` matched no secret name or part, so an imported exchange or an
  agent's evidence kept them as captured, in the blob store and in the client report's raw
  evidence.
- **Fix:** new name parts `subscriptionkey`, `functionskey`, `masterkey`; the copy in
  `tools/caido_pull.py` matches (its test compares the two). `access_key` was not added: it
  normalizes to `accesskey`, the HTML attribute on many pages.

### EV-8: drafts holding a credential written to sessionStorage (Low)

- **Where:** `web/src/drafts.ts`, `SECRETISH` (D-053).
- **What:** D-053 says text that looks like a credential is never written to storage. The
  check missed a JSON field (`"access_token": "..."`), a key header (`X-Api-Key: ...`,
  `Ocp-Apim-Subscription-Key: ...`), `password: ...`, a PEM private key and an AWS key id.
- **Fix:** those forms are caught too. After a colon only a value of eight characters or more
  counts, so sentences such as "a wrong password: 401" are still kept across a reload.
- **Reproduction** (no test runner in `web/package.json`): bundle `web/src/drafts.ts` with
  `web/node_modules/.bin/esbuild --bundle --format=esm --platform=node`, give `globalThis.window`
  a Map-backed `sessionStorage`, call `setDraft("k", value)` and check the storage. Before the
  fix all six credential samples were stored; after it none is, and both prose samples are.

### O-1: the manifest did not bind evidence to its item (Low)

- **Where:** `gates.manifest`, and `manifest` in both verifiers.
- **What:** a manifest listed items by `idx`, `key`, `state` and `na_reason`, and evidence by
  `id`, `item` (the item's database id), `kind` and `sha256`. The item's database id was not in the
  manifest. So in a signed report the `item_id` of two items marked done could be swapped. Each
  piece of evidence then seemed to support the other item, and every check passed.
- **Fix:** manifest version 2 (D-054). Each item also names its `id` and its `text`, and the
  manifest carries `"v": 2`. New receipts use it. The server's `lane_status` and both verifiers
  accept a version 1 hash for receipts made before. The verifiers add a NOTE that such a receipt
  does not bind evidence to items. The version is inside the hashed text, so neither can pass for
  the other.
- **Remaining:** receipts issued before this change keep version 1 and its limit. The NOTE names them.

### O-2: history entries could be left out of a report (Medium, bounded)

- **Where:** `check_key_log` and `check_audit_log` in both verifiers. The signed payload.
- **What:** links are hashes only, so a left-out audit entry of this engagement looked like
  another engagement's. Dropping `key_log` or `audit_log` gave only a NOTE (D-037). A forger
  could also drop the `lane.receipt_voided` entry and get past EV-1.
- **Fix:** receipt payload v4 (D-054) signs `history`. That is the audit log head when the payload
  was issued, the number of audit entries up to it that are the engagement's or person events of
  the signer, the SHA-256 of their sequence numbers, and the key log head. The server checks every
  field at close. In every mode, both verifiers fail a report whose logs stop before the signed
  head, differ there, or leave out a counted entry. `--require-history`, and *Require the full
  change history* on /verify, also fail missing logs, receipts that commit to no history
  (unsigned, v2, v3) and format 1. In that mode a NOTE says up to which entry signatures bind the history.
- **Remaining, by design of the chain:** nothing signed after the newest receipt commits to
  later entries. A void made after the last signature can still be left out with the lane
  shown as receipted, in strict mode too. That case is a fixture and a test, and strict mode's
  NOTE says so. Closing it would need a signature at report time (no such signer exists; D-036).
  `docs/VERIFIER.md` says what strict mode proves and what it does not.

### O-3: what was verified in an HTML report was not shown (Medium)

- **Fix:** after an HTML report verifies, `verify_report.py` prints what its embedded JSON
  says, and /verify shows the same list under the result. The list gives the engagement, its
  authorization and scope, the hosts and lanes, each receipted lane with its items, signer and
  dates, void receipts, the evidence count and chain head, and when the report was made. The
  page builds it with the DOM API under its CSP and Trusted Types, and has no new inline script.
  The rebuilt page's hashes are in its meta CSP, and `tools/build_pages.sh` accepts them. The HTML
  report's "How to verify" mentions the list and `--require-history`.

## Open items (not fixed)

- **By design, noted:** a report whose signatures were removed verifies with a NOTE unless
  `--require-signatures` is given; the body hash is self-consistency only (see EV-5's wording
  change). History after the newest signed head is not bound (O-2).

## What was checked and found sound

**Imports** (`server/app/importers/__init__.py`, `burp.py`, `har.py`, `caido.py`;
`server/app/inbox.py` `import_file`, `content_hash`, `wipe`).
- Burp XML through `defusedxml.iterparse` with `forbid_entities` and `forbid_external`:
  internal and external entities, parameter entities, billion laughs refused; an external DTD
  is never fetched; nesting over 32 refused; items released as read (existing tests in
  `test_import.py` cover each case).
- Size: 50 MB per file and 5,000 entries checked before parsing rows; `b64` decodes at most
  the kept prefix, so a huge base64 field costs only what is stored; HAR headers capped at 500
  and form params at 1,000; JSON recursion and huge integers refused with a message.
- HAR rebuild (`message`) replaces CR and LF inside names and values, so one field cannot
  become two headers.
- Scope: the host checked is `urlsplit(url).hostname` of the same URL that is stored, through
  `scope.normalize_host` and `scope.in_scope` (non-ASCII, IP literals with brackets and
  malformed hosts refused as unreadable). A hand-made URL such as `https://a.test\@b.test/`
  is read as host `b.test` here while a browser reads `a.test`; only a file written by hand
  produces that, and the tester controls their own file anyway, so it was left.
- Dedupe hashes method, redacted URL, status and the redacted bytes' hashes (plus the tool id
  without bytes); entries are never overwritten, only counted as duplicates.
- Redaction (`redact.http_message`, `_header_line`, `header_value`, `text`): every header line
  goes through the header rules whatever its name, then the text rules; Cookie and Set-Cookie
  values, Authorization schemes, JSON keys, query and form parameters, JWTs, bearer tokens,
  PEM keys and the recon credential formats are masked; Content-Length is corrected. Gaps
  outside EV-7 need unusual input (an obsolete folded header line, a cookie without a name,
  a JSON key written with `\u` escapes) and were left.

**Ledger, receipts and the verifiers** (`ledger.py` `canonical`, `evidence_record`,
`append_evidence`, `verify_chain`; `gates.py` `manifest`, `manifest_hash`, `lane_status`,
`void_receipt`; `signing.py`; `main.py` `_check_signed`, `receipt_payload`, `close_lane`;
`report.py` `build`, `render_html`; `timestamps.py`; `keylog.py` and `auditlog.py`
`for_report`; `tools/verify_report.py` and `web/src/verify_report.ts`, every check).
- Chain v1/v2: `v` and `summary_sha256` are inside the hashed record, so a row cannot be
  turned into the other version; `v` other than absent or 2 fails (`1` and `3` are existing
  fixtures).
- A receipt's chain head binds every entry up to that sequence number; the manifest binds the
  lane's evidence ids, kinds and hashes. Evidence after the newest signed head is bound by
  nothing, which is inherent and visible in the report.
- The server accepts only canonical payloads, checks lane, host, role, manifest, signer,
  email, key, chain head and age, then the signature. The verifiers' Ed25519 (RFC 8032, with
  `s < L`), P-256 and P-384 ECDSA (point on curve, `1 <= r, s < n`) and RSA PKCS #1 v1.5
  (exact encoding compared, no lenient parsing) were read line by line.
- RFC 3161: the server checks hash and nonce; the verifiers check the statement (manifest
  hash and signature value), the signed attributes' message digest, the signer's
  timestamping EKU, the chain to a trusted root with validity at the token's time.
- JSON: the TypeScript reader keeps ints and floats apart, builds objects with no prototype
  (`Object.create(null)`, so `__proto__` is an ordinary key), refuses lone surrogates the way
  Python's encoder does, takes the last of duplicate keys as Python does, and stops at depth
  990. Canonical output (sorted by code point, `ensure_ascii` for the manifest) matches;
  `tools/verifier_equivalence/run.sh` reports 80 reports and 107 building blocks with no
  difference.
- The HTML report escapes every value (`_e`), escapes `<`, `>` and `&` in the embedded JSON,
  and is served with a CSP that allows no script; raw evidence is served as `text/plain` with
  `default-src 'none'; sandbox` and `nosniff`.

**Encryption** (`vault.py`, `blobs.py`).
- AES-256-GCM with a fresh random 96-bit nonce for every seal; the number of seals per key is
  far below the random-nonce bound.
- Associated data binds a wrapped data key to its engagement, a blob to its engagement and
  hash, a summary to its engagement and hash, and a secret to its engagement, purpose and
  hash: ciphertext moved to another engagement, name or row does not open (existing tests
  `test_wrong_engagement_key_is_refused`, `test_tampered_ciphertext_is_refused`).
- Blob paths: digests are checked as 64 hex digits before use, engagement ids pass through
  `int()`, attached file names are reduced to their last part and used only in the URI.
- A new key file is created with `O_EXCL` and mode 0600; the master key is never logged and
  `/health` names only its kind. A wrong master key or a missing key file stops startup.
- Deletion writes the tombstone first, then removes the key and every blob, and removes
  plaintext blobs only this engagement cites. Plaintext blobs written before 0018 can be read
  through another default-organization engagement whose evidence names the same hash; that
  needs the hash, is limited to the default organization (`_plaintext_ok`) and is the
  documented migration path, so it was left.

**Web** (`web/src/` all `href` and `src` uses, `Report.tsx`, `Verify.tsx`, `verify_page.ts`,
`drafts.ts`; `web/nginx.conf`).
- No `dangerouslySetInnerHTML` or `innerHTML`; the public verifier builds the DOM by hand under
  Trusted Types and a CSP with `connect-src 'none'`.
- Links built from recon and agent data (`Recon.tsx`): endpoint rows are kept only as in-scope
  http(s) URLs (`urls.clean`, `urls.host_of`), leads only when their source URL's host is in
  scope (`workerapi._where`; a `javascript:` URL has no host that passes), the agent's URLs
  through `check_url` (http and https only), and probe observations name the URL the probe
  built. The app's CSP (`script-src 'self'` and one hash) also blocks `javascript:` URLs. No
  change.
- nginx: the app's CSP allows only its own origin; `/api/` responses carry `nosniff`,
  `X-Frame-Options: DENY` and the API's own CSP on the HTML it serves.

## Verification

- O-1 to O-3 (`0e1f9d5`): server 799 passed, 1 skipped (790 and 1 before; the 9 new tests).
  `run.sh`: 105 reports, 107 building blocks, 0 differences (80 before). `tsc --noEmit` passes.
  `site/verify.html` was rebuilt with `tools/build_verify.sh`, and `tools/build_pages.sh`
  accepts its hashes. `site/verify_report.py` is a copy of `tools/verify_report.py`. The sample
  and demo reports still verify, with the manifest version 1 NOTE. With `--require-history`
  they fail, because they were signed as payload v3, except the demo export without receipts.
- Server: 765 passed, 1 skipped (758 and 1 before; the 7 new tests).
- `tools/verifier_equivalence/run.sh`: 80 reports, 107 building-block cases, 0 differences
  or unmet expectations (72 before; 8 new cases). One existing fixture,
  `lane-status-stale.json`, now also lowers the summary count, as the server would.
- `cd web && npx tsc --noEmit`: passes. `site/verify.html` rebuilt with `tools/build_verify.sh`;
  `site/verify_report.py` is again a copy of `tools/verify_report.py`. The published sample
  and demo reports still verify.
