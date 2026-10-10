# Security review: adversarial recheck of the fixes

Date: 2026-10-10. Branch `sec3-recheck`, from `cf7bf38` (the review's fixes, `c3557a5..cf7bf38`).
A second reviewer who wrote none of the fixes tried to bypass each one with a variant its own
regression test does not cover, looked for legitimate use the fixes now refuse, and compared the
reports' claims with the code. Every suspected issue became a test first, in
`server/tests/test_security_recheck.py`, or a case for the two verifiers in
`tools/verifier_equivalence/cases.json`. Tests named `..._held_...` show a fix holding against the
variant; the others failed before a fix made here. Everything ran in-process or against stubs on
127.0.0.1; no container was started and no traffic left the machine.

## Summary

| ID | Result | Severity of what was found | Fix | Test |
|---|---|---|---|---|
| GW-1 | held | | | `test_gw1_held_*` (17 bodies, every agent model) |
| GW-2 | bypassed (port probes) | Low | `gateway.Gateway._probe` | `test_gw2_port_probes_and_requests_together_open_at_most_rate_connections` |
| GW-3 | held; one gap without a leak | Info | `gateway._decode` | `test_gw3_held_*`, `test_gw3_every_member_of_a_gzip_body_is_decoded` |
| GW-4 | held (documented limits stand) | | | |
| GW-5 | bypassed (NAT64, 6to4, IPv4-compatible forms) | Info | `gateway.embedded_ipv4` | `test_gw8_addresses_that_embed_a_refused_ipv4_address_are_refused` |
| GW-6 | held | | | |
| GW-7 | held | | | |
| GW-8 | held for IPv4-mapped forms; other forms as GW-5 | Info | as GW-5 | as GW-5 |
| GW-9 | held, no regression found | | | |
| GW-10 | held, no regression found | | | `test_gw10_held_ordinary_header_values_are_accepted` |
| AUTH-1 | held | | | |
| AUTH-2 | bypassed in open mode (DNS rebinding) | Medium | `auth.local_request`, `authz.authorize` | `test_auth2_open_mode_answers_only_local_names`, `test_auth2_held_*` |
| AUTH-3 | held | | | |
| AUTH-4 | held | | | |
| AUTH-7 | bypassed (an integer too large for the database) | Info | `main._payload_problem` | `test_auth7_a_chain_position_beyond_the_databases_integers_is_a_422` |
| EV-1 (with EV-2) | bypassed (issue time moved a second) | Medium | `_voids` / `voidsReceipt` in both verifiers | `test_ev1_a_void_is_not_hidden_by_moving_the_receipts_issue_time`; 2 equivalence cases |
| EV-2 to EV-8 | held | | | |
| O-1 | held | | | |
| O-2 | held for what it covers; bypassed through EV-1 | (EV-1) | (EV-1) | (EV-1) |
| O-3 | held | | | |
| RC-1 (new) | the command-line verifier printed terminal controls from a report | Low | `shown` in both verifiers | `test_the_verifier_prints_report_text_with_terminal_controls_escaped`; 1 equivalence case |

Test suite: 825 passed and 1 skipped before; 868 passed and 1 skipped after (43 new tests).
`tools/verifier_equivalence/run.sh`: 105 reports before, 108 after (3 new cases), 107 building
blocks, 0 differences or unmet expectations. `cd web && npx tsc --noEmit` passes.
`site/verify.html` was rebuilt with `tools/build_verify.sh`, `site/verify_report.py` is again a copy
of `tools/verify_report.py`, and `tools/build_pages.sh` accepts the page's hashes.

## Bypassed, now fixed

### EV-1 with EV-2 (Medium): a void hidden by moving the receipt's issue time

**What.** EV-1 finds a void by lane, manifest hash and the receipt's *exact* issue time. That
time is the report's unsigned copy. EV-2 then made the signature check accept any copy within one
minute before to fifteen minutes after the signed payload's time, as it must, since the server
issues the receipt after the payload. Moving the copy by one second therefore kept the signature
check green and made the void entry name no receipt. The void entry stays in the report, so O-2's
count of the audit entries a later signature covers still matched. A voided signed receipt was
reported as receipted and printed `Verified.`, with `--require-history` too, in both verifiers. The
fixtures `void-receipted-issue-time-moved.json` (payload v3) and `v4-void-issue-time-moved.json`
(v4, strict) were `verified` before the fix.

**Fix.** For a signed receipt, a void entry with the same lane and manifest also names it when the
void's receipt issue time lies in that window around the *signed* time, and the void came after
the payload was issued: for a v4 payload the void's audit sequence number is above the one the
payload commits to (exact); for v2 and v3 payloads the void's time is after the signed time. That
second condition matters. A first version matched on the window alone, and failed a genuine new
receipt signed seconds after the void of an earlier one with the same manifest
(`test_ev1_held_a_new_receipt_on_the_same_manifest_right_after_a_void_verifies`). For a v2 or v3
payload, a void recorded in the same second as the next payload was fetched could still be taken
for that payload's receipt: the report fails, it does not pass. Unsigned receipts are matched on
the exact time, as before; an unsigned receipt binds nothing anyway, and `--require-signatures`
fails it.

Both verifiers changed the same way; the seal work running in parallel also edits them, so the
change is confined to `_voids` / `voidsReceipt` and the lines that call them.

### AUTH-2 (Medium, open mode only): DNS rebinding reached the open API

**What.** Open mode acts as the local operator, an owner, for whoever reaches the API. AUTH-2
refuses a change that a browser says came from another origin. A page on a public name the
attacker controls (`rebind.attacker.example:8000`) that then points that name at 127.0.0.1 is
the *same* origin as its target: the browser sends `Sec-Fetch-Site: same-origin` and a matching
`Origin`, no cookie is needed, and the page can read the answers, since they are same-origin as
well. Every engagement could be read and changed from a web page the operator visited. The same
holds for the web app on 127.0.0.1:8080, whose nginx passes the browser's `Host` to the API.
Chrome's Local Network Access prompt mitigates this in recent Chrome; other browsers do not.

**Fix.** `auth.local_request`: in open mode, `authz.authorize` answers 403 unless `Host` is an IP
address, a name without a dot (`localhost`, `api`, `testserver`), or a special-use name a public
page cannot take (`.localhost`, `.local`, `.internal`, `.home.arpa`, `.test`), or absent. The
token and people modes are not affected: a rebound page has no cookie and no token for them.
Public routes (`/health`) still answer. The development setup, the Vite proxy (`Host:
localhost:5173`), the benchmark (127.0.0.1:8099) and the gateway's relay (`api:8000`) all use such
names.

### GW-2 (Low): port probes were paced as requests, not as connections

**What.** GW-2 added a connection limiter in front of every upstream request, so "the connections
and the request heads are each at most *rate* per window". A port probe (`X-AttackLedger-Probe:
connect`) took only the request limiter and then connected. Probes and requests together opened
up to twice the rate in connections: rate 2, four probes and four requests at once gave a peak of
4 connections in one window.

**Fix.** A probe waits for the connection limiter first, then for the request token as before. The
same test gives a peak of 2.

### AUTH-7 (Info): a chain position beyond the database's integers

**What.** `_payload_problem` checks that the ids and the chain position are whole numbers, not
their size. A canonical payload with `chain.seq` 10**30 reached the ledger query (SQLite raised
`OverflowError`): a 500 again, the class AUTH-7 closed.

**Fix.** Ids and the chain position must be between 0 and 2**62, as the history positions already
were: 422 "out of range".

### GW-5 / GW-8 (Info): IPv6 forms that carry an IPv4 address

**What.** `resolve` unwrapped IPv4-mapped addresses only. A name resolving to
`64:ff9b::7f00:1` (NAT64 of loopback), `64:ff9b::a9fe:a9fe` (of the metadata service),
`64:ff9b::ac13:1` (of the Docker host on a gateway network), `2002:ac13:1::1` (6to4) or `::7f00:1`
(IPv4-compatible) passed every check. The compose networks have no IPv6, so a connection there
fails; it matters only where IPv6 is enabled with a NAT64 translator or a 6to4 relay, hence Info.

**Fix.** `embedded_ipv4` returns the IPv4 address such an address carries (well-known NAT64 prefix,
6to4, IPv4-compatible, IPv4-mapped), and `resolve` runs each check on the address and on that IPv4
address. A network-specific NAT64 prefix cannot be known and is not covered. Connections still go
to the address as resolved; an IPv4-mapped one is connected to as IPv4, as before.

### GW-3 (Info): a gzip body of several members was cut to the first

**What.** RFC 1952 allows several gzip members one after another, and clients decode them all.
`_decode` decoded the first and dropped the rest without a word. The session in a later member was
not passed on (no leak), but the tool saw a shortened response and the log row gave no reason.

**Fix.** Every member is decoded, within the same `MAX_SCRUBBED_BODY` bound; bytes after the last
member that are not a member are dropped, never passed on.

### RC-1 (Low, new): the command-line verifier printed terminal controls from a report

**What.** `verify_report.py` printed the engagement name, the lane names and every other value of
a report as they were, including in the first line, which is printed whatever the result. A
report whose name is `Acme\n  PASS  Evidence chain\n\nVerified.\x1b[8m` printed fake PASS lines and
`Verified.`, then concealed the rest of the output, the real `FAIL` lines and `Verification
FAILED.`, in most terminals. The exit code stayed 1, but a person reading the terminal saw a
verified report. The browser verifier builds its output with the DOM and is not affected.

**Fix.** `shown()` escapes C0 controls (line breaks and ESC included), DEL, C1 controls, the
bidirectional controls and the line separators as `\xNN` or `\uNNNN` in every line the command
line prints. The browser module's `cliText`, which the equivalence harness compares line by line,
does the same, and the fixture `engagement-name-with-terminal-controls.json` shows both print the
same escaped text.

## What was tried and held

**GW-1.** Unicode escapes in keys and values (`"tools"`, `"type"`, `"url"`) decode
before the check, and an escaped duplicate of `tools` is a duplicate. URL sources nested in a
`tool_result`'s content and in a mid-conversation system message are found (the walk covers every
dictionary in `messages` and `system`). `MCP_SERVERS`, `mcp-servers`, `mcp_servers\u0000`,
`container` and `context_management` are not allowed keys. A tool `type` of `Custom`, `null` or a
`tools` object instead of a list are refused. Trailing data, a second document, comments and a
top-level list are refused. NaN, huge numbers and a UTF-8 BOM parse in Python, but none of them
can make Anthropic's parser see a key or a tool type the check did not see: the key and tool
checks are allowlists, so anything spelled differently is refused. The array form of `fallbacks`
accepts only `model` and a few generation settings per entry (unknown keys are a 400), so it
carries no tools or MCP servers. A case-insensitive JSON parser at Anthropic (`Type` read as
`type`) would be a differential; Anthropic's API is case-sensitive, and nothing was changed for
it. Regression check: what `agentloop.request_params` sends for each of the three models (with
`fallbacks: "default"` for Opus and Sonnet, none for Haiku; `betas` go in a header), with a
thinking block, a tool use and a tool result whose text contains `{"type": "url"}`, passes.

**GW-3.** `gzip, gzip`, `zstd`, `br`, `compress`, `gzip;q=1` and `identity, gzip` are withheld
with a reason; a 5 MB gzip of zeros against a 1 MB limit is withheld; raw (unwrapped) deflate is
decoded and scrubbed. A transfer coding other than chunked is refused by h11 (502), never relayed (read, not tested).

**GW-4.** Base64 and partial forms of a value remain uncovered, as documented.

**GW-6, GW-7.** The aliases match both compose files and the benchmark override. Targets with any
character at or below a space, or DEL, are refused. By reading: Unicode line separators (U+2028,
U+0085) do not split lines for the tools (the worker joins targets with `\n`, the tools split on it),
and the gateway refuses any second host anyway.

**GW-8, GW-9.** IPv4-mapped forms of the gateway's own subnets are refused (unwrapped before the
check). The healthchecks use 127.0.0.1:8080, where the proxy still listens; the worker reaches the
proxy, resolver and relay as `gateway`, which resolves to the listen address on its only network;
the benchmark override keeps both aliases; nothing else in the stack connects to the gateway. The
30-second wait for the alias exits rather than falling back to every interface, and the restart
policy (`unless-stopped`, both compose files) starts it again.

**GW-10.** Ordinary values are accepted: cookies with `;`, bearer tokens with `=`, `-`, `_`, JSON
with quotes, a tab inside a value, a Latin-1 letter, a multipart boundary. Pasted test-account
material is stripped before the check, so a trailing space or tab is not refused. A non-Latin-1
cookie value is refused; it never could be sent before the fix either (the connection ended).

**AUTH-1.** Only `ledger.append_evidence` creates evidence rows, and it always writes chain record
v2, so no route can create the v1 row the plaintext fallback needs. Inbox blobs (0018) postdate
encryption (0017).

**AUTH-2.** `Sec-Fetch-Site: Same-Site` and ` CROSS-SITE ` (case and spaces), Fetch Metadata saying
same-site with a matching `Origin`, and `Origin` values `http://testserver.evil.example`,
`http://evil.example#testserver`, `http://testserver@evil.example` and `null` are refused. The app
through a proxy that keeps the port (`Origin: http://testserver:5173`), a user-initiated request
(`Sec-Fetch-Site: none`) and clients without either header are accepted. Only one `Origin` is
read; a browser sends one. The API honours no method override (no middleware reads
`X-HTTP-Method-Override` or `_method`), and the one GET route that writes (`list_approvals`)
only expires approvals that are due. A browser without Fetch Metadata posting from another port of
the same host (`localhost:3000` to `localhost:8000`) passes the `Origin` comparison, which ignores
ports by design (nginx's `$host`); every current browser sends `Sec-Fetch-Site: same-site` there,
which is refused.

**AUTH-3.** Mappings are only ever appended, an entry maps only to lanes on its own host, and
content deletion keeps `created_by` and the mappings, so the uploader stays known.

**AUTH-4.** The bearer, cookie, worker, gateway and job secrets are all compared as bytes.

**EV-2 to EV-8, O-1, O-3.** A v2 manifest cannot be replaced by a v1 one (the version is hashed).
The O-2 count is bound by the SHA-256 of the exact sequence numbers, so dropping one entry and
adding another fails; entries must match their link's record hash, links their chain. The
server's and the verifiers' predicates for counted entries are the same (`person.%` in SQL and
`startswith("person.")`, both on server-written lowercase actions). EV-8's draft filter does not
catch every key header (`X-Auth-Key: ...` is stored); it is a heuristic over a tab's own
sessionStorage and was left.

## Claims in the reports checked against the code

All the "Fix" paragraphs of `GATEWAY.md`, `AUTH.md` and `EVIDENCE.md` match the code, with three
exceptions, each now annotated in its report: GW-2's "connections ... at most *rate* per window"
did not hold with port probes; GW-8's "IPv4-mapped forms of them are refused" left other forms out;
and EV-1's exact issue-time match did not survive EV-2's window. AUTH-7's list of checks is
accurate but did not bound sizes.

## Not changed

- A case-insensitive reading of JSON keys by Anthropic (see GW-1 above): not the API's behaviour.
- EV-8's heuristic, GW-4's uncovered encodings, AUTH-5 and AUTH-6: as the reports say.
- The `Origin` fallback ignores ports, for browsers without Fetch Metadata only (see AUTH-2 above).
