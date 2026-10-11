# Security review: fuzzing the parsers of hostile input

Date: 2026-10-10 to 11. Branch `sec4-fuzz`, from `ce5042e`, merged with `main` before the last run.
An AI agent (Claude) wrote property-based and mutation fuzzers for every part of AttackLedger that
reads input it does not control, ran them, minimised each failure by hand, kept it as a
deterministic test, and fixed the code. Everything ran in-process or in a throwaway API container
on this machine; no traffic left it apart from npm (`npm ci` for the verifier build).

## How it works

No third-party fuzzer is needed. The API image has no `hypothesis`, and the default test run must
stay offline and fast, so `server/tests/fuzzing.py` is a small seeded mutation fuzzer with the
standard library: byte flips, inserted tokens (`1e400`, `\ud800`, `]]>`, a 5,000-digit number, a
70 KB run), deleted, duplicated and spliced spans, and a JSON tree mutator that keeps duplicate
keys and exact number text (values of another type or format, keys deleted, duplicated or
reordered, values wrapped, `\u` escapes). Every test takes its own generator from one seed, so a
failure is reproduced by running the test again. `time_limit` uses `SIGALRM`, which interrupts a
regular expression match in Python 3.12, so a catastrophic backtrack fails a test instead of
hanging it.

```sh
# default: part of the normal suite, about 20 s
python -m pytest -q tests/test_fuzz.py tests/test_security_fuzz.py
# a long run
ATTACKLEDGER_FUZZ_ITERATIONS=5000 ATTACKLEDGER_FUZZ_SEED=7 python -m pytest -q tests/test_fuzz.py
# the verifiers: random mutants of every report in cases.json
bash tools/verifier_equivalence/run.sh --fuzz 2000 [--seed 7] [--keep DIR] [--jobs 8]
```

Also: `ATTACKLEDGER_FUZZ_SIZE` (characters in a pumped input, default 40,000) and
`ATTACKLEDGER_FUZZ_BUDGET` (seconds, default 2).

## Targets and properties

| Target | Property (`server/tests/test_fuzz.py` unless named) | Inputs per default run |
|---|---|---|
| Importers (HAR, Burp XML, Caido JSON) | Only `ImportRefused` (or a listed unreadable row), within 5 s; every entry has a valid URL, method, status, bounded parts, no NUL | 150 mutants per format, each with and without the format named |
| The inbox, end to end through the API | Every accepted row's host is in scope by `scope.py`; its stored, redacted URL still names that host; the entry opens (no 500); every `out_of_scope` row is out of scope | 12 files of 25 generated rows |
| Redaction | No secret placed in an Authorization or Proxy-Authorization value, Cookie, Set-Cookie, secret header, query, form, multipart field, JSON key (escaped or not), HAR-style header or JWT survives `http_message`; `http_message` and `text` are idempotent; random message mutations never raise | 1,500 placements, 1,500 mutations |
| Scope and URLs (differential) | The gateway (`split_authority` + `in_scope`), the inbox (`http_url` + `normalize_host`) and recon (`urls.host_of`) never read a URL as in scope on another host than a browser (WHATWG) contacts, and never disagree on the host | 3,000 URLs from a grammar (case, trailing dots, line ends, IDN and punycode, `\`, `@`, ports, IPv6) |
| Host and rule normalisation | `normalize_host` and `normalize_pattern` are idempotent, ASCII, lower case; `in_scope` ignores case, a trailing dot and spaces; an exclude rule, however written, excludes its host | 3,000 + 2,000 |
| Text parsers (20: redaction, JS analysis, page text, surface, URL clean-up, scope CSV) | Pumped input: a unit repeated to 10,000 and to 40,000 characters may take up to 8 times as long, not 16 (linear, not quadratic), and under 2 s; binary and odd text never raises | every one of 87 tokens alone and followed by `y`, plus 20 random combinations; 25 binary inputs |
| Scope CSV | Only `ValueError`; every stored rule is normalised | 1,500 |
| Both verifiers (`tools/verifier_equivalence/fuzz.mjs`) | Same status, verdicts and output from `verify_report.py` and the browser module (both Ed25519 modes); the script never stops with a traceback; a mutation that keeps the JSON's meaning (key order, escapes) leaves the output as it was | as many mutants as asked |

Verifier mutants: byte flips and inserted or deleted spans; a JSON value changed (pool of numbers
such as `-0`, `1e400`, `NaN`, 5,000-digit integers; strings such as `\u0000`, `\ud800`,
`</script>`, terminal escapes), nudged (one hex character, one second, an integer plus or minus
one) or of another type; keys deleted, duplicated or reordered; strings re-escaped; arrays
shortened, duplicated or swapped; values wrapped or nested 400 to 3,000 levels deep. HTML reports
are mutated inside their embedded JSON or as bytes.

Runs made: the default suite; the verifier fuzz with seed 20261010 (2,000 mutants) and seed 7
(600); before the fixes, 40 and 300 mutants found FZ-16, FZ-17 and FZ-19. After the fixes:
2,600 mutants (68 + 22 meaning-preserving), 0 differences, 0 tracebacks.

## Findings

Severity is in AttackLedger's threat model (a hostile target page, bundle or export, a misled
tool or agent). "Found by" says whether random fuzzing found it or a probe written while building
the fuzzer did; each has a regression test in `server/tests/test_security_fuzz.py` (FZ-*) that
failed before its fix, and the verifier ones also have equivalence cases (`fuzz-*.json`, made by
`tools/verifier_equivalence/make_fuzz_fixtures.py`). Fixes FZ-1 to FZ-15 are in `f462fad`; FZ-16
to FZ-19 in `e174d9b`.

| ID | Severity | Where | What | Found by | Fix |
|---|---|---|---|---|---|
| FZ-1 | Low | `importers.status` | A status of `1e400` (JSON infinity) raised `OverflowError`: the import answered 500 and nothing was imported; `200.5` was silently read as 200 | probe | Not a whole number: one unreadable row |
| FZ-2 | Low | `redact._fix_content_length` | A Content-Length of more than 4,300 digits raised `ValueError` (Python's integer string limit) when the body was redacted: import 500 | probe | At most 18 digits are read; a longer value is left as written |
| FZ-3 | Low | `importers.http_url`, `urls.host_of` | `https://other.example\@shop.example.com/` goes to `other.example` in a browser, but Python reads `shop.example.com`: an export's out-of-scope request was imported as in scope (recon stored it under the in-scope host). The gateway already refused it | URL differential | A backslash before the path is refused (one unreadable row) |
| FZ-4 | Medium | `scope.normalize_host`, `normalize_pattern` | `$` also matches before a final line end. `"admin.example.com\n."` (from the scope API or a quoted CSV cell) was stored as `admin.example.com\n`, which matches nothing: as an exclude under a wildcard, the excluded host was in scope for the gateway. Also `"*.x.com\t."` kept its tab | normalisation idempotence | `fullmatch`; trailing dots and spaces in any order are removed; a pattern is `*.` plus the normalised host |
| FZ-5 | Low | API (`main._invalid_request`), `redact.marker` | A lone surrogate in a JSON string (`"\ud800"`, which Python's JSON reader accepts) made every JSON route answer 500: FastAPI's 422 echoes the input and cannot encode it. `redact.marker` raised on one too | binary fuzz of redaction; API probe | The 422 is written as ASCII JSON; the marker hashes the value with `surrogatepass` when it is not from undecodable bytes |
| FZ-6 | Medium | `redact.header_value` (Authorization, Proxy-Authorization) | `(\S.*?)(\s*)$` was quadratic in a run of spaces inside the value: 1 MB took about 40 minutes. It runs on every header line of an imported request and response, and on "Name: value" lines in any redacted body, so a target page or response could stall an import or an agent run | pumped input | The value's trailing space is split off first; the match is linear |
| FZ-7 | Low | `inbox.import_file` (URL redaction) | The stored URL went through all the text rules: a host label shaped like an AWS key id, a Slack token or a JWT was replaced, and a password in `user:pw@` became a marker with brackets, which `urlsplit` refuses ("Invalid IPv6 URL"). The entry then answered 500 | inbox property | `redact.url`: the host is kept as the scope check read it; the password's marker is percent-encoded |
| FZ-8 | Low | `redact._header_line` | A head line that only contains a colon (`password=a:b`) was read as header `password=a` with value `b`: `a` was kept. Redacting it twice changed it again (a marker has colons) | idempotence | A line whose name is not an RFC 9110 token is redacted as text |
| FZ-9 | Low | `redact._cookie_values` | A cookie without a name (`Cookie: secret`, `Set-Cookie: secret; Path=/`, `=secret`) was stored unredacted | review while writing placements | Every piece without `=` is replaced too |
| FZ-10 | Low | `redact._json` | A JSON key written with escapes (`"token"`) was not recognised as secret, nor a HAR header name with one | placements | Keys are decoded before their name is checked |
| FZ-11 | Medium | `pagetext` (`strip_html`, `view`, `title_of`, `directory_listing`) | `<!--.*?-->`, the script-block expression and `<title...>(.*?)</title>` read to the end of the page again for every unclosed opening: 1 MB of `<!--` took about 10 minutes of an agent's turn | pumped input | One forward search each (`_strip_comments`, `_drop_blocks`), same results on well-formed pages |
| FZ-12 | Medium | `jsanalysis.PUBLIC_BY_DESIGN` (Google OAuth client id) | `\d+-...` restarted at every digit of a run: a 5 MB bundle of digits would take hours of the recon worker | pumped input | `(?<!\d)\d+-...`, the same matches |
| FZ-13 | Medium | `jsanalysis.spa_routes` | Every unclosed `children:[` read up to 400,000 characters, the parent search and the span test were quadratic: a bundle of nothing but `{path:'a',component:X,children:[` took hours | pumped input | `bisect` for the parent, a sweep for the spans, at most 4,000,000 characters read for children arrays and 50,000 route candidates per bundle |
| FZ-14 | Low | `scopeimport.parse` | One `https://[x/` row refused the whole CSV ("Invalid IPv6 URL"); a lone CR or a field over csv's limit raised `csv.Error`: the API answered 500 | CSV fuzz | One invalid row; csv errors are a 422 with a message; the CSV is read with `newline=""` |
| FZ-15 | Medium | `redact.text` | A multipart/form-data field with a secret name (`name="password"`) was stored unredacted, so a password posted as multipart reached append-only evidence | placements | `_multipart`: the first line of a non-file field with a secret name is replaced, and Content-Length follows |
| FZ-16 | Low | `tools/verify_report.py` | A malformed report (a missing key, a value of another type, a file that is not UTF-8 or not JSON) stopped the script with a traceback and exit code 1, which is the code for "a check failed"; the documented code is 2. 18 of the first 40 mutants | verifier fuzz | `main` prints one line, `the report cannot be checked: <why>`, and returns 2; output is printed only once the checks are over. The browser module says the same (status `error`, exit code 2) |
| FZ-17 | Low | both verifiers | JSON nested 990 to 1,000 levels: the browser module refused it at 990, Python read or refused it depending on its version and stack. The verdicts differed | verifier fuzz | Both refuse nesting over 500 levels before reading, the same way |
| FZ-18 | Info | both verifiers' `shown` | A lone surrogate in text the script prints raised `UnicodeEncodeError` on output | verifier fuzz | Escaped as `\ud800` by both (in a report it now also stops the body hash, so both say it cannot be checked) |
| FZ-19 | Low | `verify_report.manifest` | An item without `item_id` or `text` stopped the script; the browser module read them as missing and failed the check | verifier fuzz | The script reads them as missing too |

## What held

- The adapters never raised anything but `ImportRefused` on mutated files apart from FZ-1, and
  `defusedxml` refused every entity the mutations produced.
- Redaction kept no placed secret in headers, queries, forms, JSON or JWTs apart from FZ-8, FZ-9,
  FZ-10 and FZ-15, and every marker survived a second pass.
- The gateway never read another host than a browser would; it already refused backslashes,
  credentials and malformed ports. With FZ-3 and FZ-4 fixed, the three readers agree on every
  generated URL.
- Python and the browser verifier gave the same output on all 2,600 mutants after the fixes,
  including the 90 whose meaning was unchanged, which printed exactly what the original printed.
- Other `$`-anchored validators were checked by hand: `testaccounts`, `blobs`, `ledger` and
  `packs` strip their input first or never accept a line end, and Pydantic's patterns match the
  whole string.

## Not covered

- `jsanalysis` and `pagetext` were fuzzed through their public functions; Python's `HTMLParser`
  itself held on every pumped input, but was not fuzzed beyond that.
- The gateway's own HTTP parsing (h11) and the gateway log are another review's subject
  (`GATEWAY.md`, and the parallel log work). After FZ-5, a lone surrogate in a gateway or worker
  JSON body is a 422 instead of a 500; how the gateway handles a refused log batch was not changed
  here.
- Redaction of XML bodies (`<password>...</password>`) and of multi-line multipart values is not
  done; `redact.py` lists what it does not do.
- The inbox mapping, the report builder and the web app were not fuzzed.
- The verifier fuzz does not regenerate signatures, so mutations of signed content test the
  failure paths, not a valid signature over altered content (`make_fixtures.py` covers those).

## Counts

Server suite (SQLite): 954 passed and 1 skipped on `main` before; 1,050 passed and 1 skipped
after (`test_fuzz.py`, `test_security_fuzz.py`). `tools/verifier_equivalence/run.sh`: 126 reports
before, 134 after (8 new `fuzz-*` cases), 107 building blocks, 0 differences.
`site/verify.html` was rebuilt with `tools/build_verify.sh`, `site/verify_report.py` is again a
copy of `tools/verify_report.py`, and `tools/build_pages.sh` accepts the page's hashes.

# Second pass

Date: 2026-10-11. Branch `sec5-fuzz2`, from `33f1144`. The same agent setup and harness
(`server/tests/fuzzing.py`), aimed at what the first pass listed as not covered: redaction of XML,
multipart, form and GraphQL bodies; the gateway's own HTTP parsing; the gateway log ingestion; the
inbox mapping and the report builder. Everything ran in-process or in a throwaway API container;
the gateway tests use the in-process gateway of `test_gateway.py` on 127.0.0.1 in front of local
stub upstreams. No traffic left the machine.

```sh
python -m pytest -q tests/test_fuzz2.py tests/test_security_fuzz2.py      # about 25 s
ATTACKLEDGER_FUZZ_ITERATIONS=1000 ATTACKLEDGER_FUZZ_SEED=7 python -m pytest -q tests/test_fuzz2.py -k gateway
```

## Targets and properties (`server/tests/test_fuzz2.py`)

| Target | Property | Inputs per default run |
|---|---|---|
| Gateway, requests from a tool | Mutated request heads and bodies (absolute form, HEAD, OPTIONS, approved writes chunked and not, CONNECT and probes, pipelined requests; tokens such as `\xb9`, `[`, `//`, obs-fold, chunk sizes, `Upgrade`, overrides): the handler never ends by an error, every input holding a whole head leaves a row, nothing reaches the upstream without an `allowed` row, all within 15 s | 120 |
| Gateway, responses from a target | Mutated responses (1xx floods, 101, `Transfer-Encoding: gzip`, both lengths, trailers, obs-fold, latin-1, NUL): one row per request, verdict `allowed` or `failed`, within 15 s | 120 |
| Gateway resolver | Mutated DNS queries: `dns_answer` never raises; every packet it forwards asks, label for label (read by an independent parser), a name in scope | 3,000 |
| Gateway log, `POST /gateway/log` | Batches of 1 to 30 random rows (each field of another type, size or character, missing, NaN, `1e400`, huge integers, lone surrogates, NUL; whole rows mutated or not objects): always 200, one stored row per row, a placeholder (verdict `unlogged`, no URL) for each refused one; `gatewaylog.placeholder` of anything passes the API's own row check; the gateway reads an answer of any shape | 25 batches; 2,000; 2,000 |
| Redaction of bodies | A secret with a secret name in random XML (elements, CDATA, attributes, XML-RPC members, plists, `<input>`/`<meta>`/`<add>` pairs, SOAP and HTML wrappers), multipart (one and several lines, quoted or not), form (percent-encoded names, values with `; , ) ' # " < >`) and GraphQL (JSON, raw, URL-encoded GET) documents: it never survives `text` or `http_message`, a second pass changes nothing; the same documents with a name that is not secret come back unchanged; 30 pumped tokens (alone, followed by `y`, and 25 random combinations) are linear, as in the first pass | 400 and 200 per format |
| Inbox mapping and the report | Random histories through the API (hosts, lanes, notes and files with random text, item states and N/A reasons, receipts, HAR imports with random entries, mapping onto items by lane or by role, dismiss and restore): no request answers 5xx; the JSON and HTML reports build and both verify with `tools/verify_report.py` (exit 0); the HTML is the JSON rendered; the same state gives the same bytes, with the clock fixed; at least one mapping, receipt and import succeeded | 8 histories |

Runs made, besides the default suite: seeds 1 to 5 (gateway, 500 to 800 inputs each), 1 and 2
(redaction, 3,000 per format), 1 to 7 (report, 40 to 80 histories), and seed 7 at 1,000 gateway
inputs, 5,000 redaction placements and 300 histories after the fixes, with no failure.

## Findings

Severity in AttackLedger's threat model, as in the first pass. Each has a regression test in
`server/tests/test_security_fuzz2.py` (FZ-*) that failed before its fix; "found by" says whether
a fuzzer of `test_fuzz2.py` found it or a probe written while building one did.

| ID | Severity | Where | What | Found by | Fix |
|---|---|---|---|---|---|
| FZ-20 | Low | `gateway._request`, `split_authority`, `credential` | A request whose checks raised anything but `Refused` was dropped: no answer, no row in the request log (only a line on stderr). `http://[shop/` (urlsplit: Invalid IPv6 URL), a path such as `//[x/` in the `_method` check, a port or an approval number in superscript digits (`"²".isdigit()` is True, `int("²")` raises), a Proxy-Authorization value that is not ASCII (`b64decode` raises `ValueError`, not `binascii.Error`). Nothing was forwarded | probe; request fuzz (credential) | ASCII digits only; the query read without urlsplit; `ValueError` is a 407; anything else that stops a check is a refusal and a row (500 and verdict `failed` for a bug) |
| FZ-21 | Low | `gateway._serve` | A request head h11 refuses (a non-ASCII target, a bad Content-Length, a line that is not a header, a head over the limit), and a body it refuses (an approved write's bad chunk), closed the connection without an answer or a row | probe | h11's status (400 or 431) is sent and a row without the URL is logged; inside a tunnel it names the job and the host; body errors are refusals (FZ-20's path) |
| FZ-22 | Medium | `gateway._forward`, `_scrubbed` | A target answering with endless `100 Continue`, a response head sent a line at a time, or (as a test account) a body sent a byte at a time held the gateway's connection, and the tool's, for as long as it liked: only the time between two reads was bounded (60 s). No row was written until it ended, and a scanner hitting such a host kept opening connections the gateway never closed | probe | The response head has 90 s in all (`HEAD_TIMEOUT`) and at most 32 informational answers; a request head 90 s; a scrubbed body 300 s |
| FZ-23 | Medium | `redact.text` (`_xml`) | Secrets in XML and HTML were stored: `<wsse:Password>` and `<wsse:BinarySecurityToken>` (SOAP WS-Security), `<password>` in CDATA, `<apiKey>`, XML-RPC `<name>password</name><value>`, plist `<key>password</key><string>`, `.NET <add key="DbPassword" value=...>`, `<input name="csrf_token" value=...>`, `<meta name="csrf-token" content=...>`, and `password = "..."` with spaces around `=`. Only `name="value"` attributes were read | placements | One forward scan of opening tags: the text of a leaf element with a secret name (`<Code>` and `<Key>` excepted: S3 errors and object names), secret attributes, the value after a secret XML-RPC name or plist key, `value`/`content` of a tag whose `name`, `key` or `property` is secret |
| FZ-24 | Low | `redact.SECRET_NAMES` | `SAMLResponse` and `SAMLart` were stored as they were: a signed SAML response logs its bearer in until it expires, and holds their identity | placements | Both are secret names (and in the Caido tool's copy) |
| FZ-25 | Low | `redact._multipart` | Only the first line of a multipart field was redacted, and only with a quoted name: the rest of a multi-line secret (`private_key`), or a field written `name=password`, was stored | placements | The value runs to the part's boundary (the `--` line that opened it, searched forward once and remembered when missing); unquoted names count |
| FZ-26 | Low | `redact._kv`, `url`, `http_message` | A form value stopped at `; , ) ' # " <` (the text rules end a value there, as code and prose do), so the rest of a password a client sent unencoded was kept; a percent-encoded name (`pass%77ord`) was not recognised | placements | `redact.params`: in a URL's query, the request line's query and a form body (by its Content-Type), each secret value whole up to the next `&`; names decoded first. The Caido tool's vendored rules do the same for the request line; the equivalence test covers it |
| FZ-27 | Medium | `redact.text` (`_graphql`) | A secret GraphQL argument written in the query was stored: `login(password: "...")` in a JSON body, a GraphQL body, or URL-encoded in a GET query. Variables were already redacted (they are JSON) | placements | String arguments with a secret name in all three spellings; `$name: Type` (a definition) and `code` are not values |
| FZ-28 | Low | `nulguard` | On the machine channels, a JSON body with a NUL was rewritten with `ensure_ascii=False`, which cannot encode a lone surrogate: a batch with both was a 500, which the gateway sends again for ever (and its traffic then stops) | log fuzz | Written with escapes |
| FZ-29 | Info | `gatewaylog.placeholder` | A placeholder repeating a lone surrogate (a reason, a tool name) failed the API's own row check, so it was not valid by construction | log fuzz | Surrogates become U+FFFD |
| FZ-30 | Info | `gateway._unlogged`, `_detail`, `flush_forever` | An answer of another shape to a log batch (`unlogged` not a list, `loc` not a list: a proxy in front of the API) raised `TypeError` in the task that sends the log, which then stopped for good | log fuzz | Any shape is read; the task prints an error and tries again |
| FZ-31 | Low | `nulguard` (every JSON route) | A lone surrogate in a person's JSON (`"\ud800"`, or the bytes `ED A0 80`, both of which Python's reader accepts) reached the database driver, which cannot encode it: a 500 on every route that stores text. FZ-5 had made the 422 printable; a valid request still failed | report fuzz (an N/A reason) | Refused with a 422 like a NUL; on the machine channels replaced with U+FFFD |
| FZ-32 | Low | `nulguard._is_json` | A body without a Content-Type was not checked, but FastAPI reads it as JSON: a NUL reached the database (a 500 on Postgres) | review while fixing FZ-31 | Checked as JSON |
| FZ-33 | Low | `GET /engagements/{id}/inbox` | A status filter of `²` or 5,000 digits passed `isdigit()` and raised in `int()` or the database driver: a 500 | probe while writing the inbox fuzz | ASCII and at most three digits; otherwise the usual 422 |
| FZ-34 | Low | `importers.har`, `importers.text`, `message` | A lone surrogate in a HAR (body text, a header, the comment, the creator, the status text) made the import a 500: `surrogateescape` takes `\udc80` to `\udcff` only, and text fields kept it for the database to refuse | report fuzz | U+FFFD, as for NUL; a URL with one is one unreadable row |
| FZ-35 | Low | `gateway.parse_question` | DNS labels may hold dots. Joined with dots, the question for the labels `x`, `shop.example`, `com` was checked as `x.shop.example.com`, in scope of `*.shop.example.com`, and the packet forwarded asked a name that is not under `shop.example.com`. Such a name is not delegated anywhere a target or an attacker controls, so it was not a way out, but the name checked was not the name forwarded | resolver fuzz | Dots and backslashes in a label are escaped as DNS writes them (the scope check then refuses the name) |

## What held

- h11 refused every malformed head and chunk the fuzzers produced (chunk sizes over 20 hex
  digits, a Content-Length that is not digits, NUL and lone CR in headers, 101 without an upgrade,
  `Transfer-Encoding: gzip`), and re-framed every body it passed on: a request with both
  Content-Length and chunked was refused as a read-only request with a body, a response with both
  was sent on chunked, trailers were dropped, obs-fold was joined into one line. Nothing reached an
  upstream without an `allowed` row.
- The API's per-row log check held: no random row made it refuse a batch, and every refused row
  had a placeholder without its URL, apart from FZ-28 (a batch-level rewrite before the check). A
  body Python cannot read at all (a number of more than 4,300 digits) is a 400 for the batch, which
  the gateway halves until the row is alone, as designed.
- The report always built and verified, JSON and HTML, from every random history, and was the
  same bytes for the same state: no set or dictionary order leaks into it.
- The new redaction rules stayed linear on every pumped input, and idempotent; the first pass's
  placement and pumped tests still pass on them.

## Still not covered

- XML-RPC parameters known only by their position (`wp.getUsersBlogs(username, password)`), a
  SAML assertion held inside other XML, unquoted HTML attribute values, and JSON values under a
  secret key that are objects are still not redacted (`redact.py` lists them).
- The gateway's TLS layer (handshakes, ALPN, the CA's leaf certificates for odd names) was not
  fuzzed; only plain HTTP and requests inside an established tunnel were. HTTP/2 is not spoken.
- A partial request head that times out leaves no row (the client stopped, nothing was read to
  check); a CONNECT tunnel that never carries a request has no row of its own.
- The report fuzz drives the API with one person and the WSTG pack; signed receipts, the timestamp
  authority, separation of duties and content deletion were not part of its histories, and
  byte-stability was checked within one process with the clock fixed, not across processes.
- The verifiers were not changed in this pass, so the equivalence run was not repeated (134
  reports, 0 differences, from the first pass). The web app is the subject of the end-to-end tests.

## Counts

Server suite (SQLite): 1,050 passed and 1 skipped before; 1,154 passed and 1 skipped after
(`test_fuzz2.py`, `test_security_fuzz2.py`, and one more case in `test_caido_pull.py` and
`test_security_fuzz.py`). Postgres (`tools/test_postgres.sh`): 1,154 passed and 1 skipped, and the
migration-0022 upgrade check passes. One run of the whole suite on a loaded machine failed the
first pass's linearity check for `pagetext.view` (code this pass did not change; 8 times plus
50 ms is a tight margin under load); it passed alone and in the next full runs.

# Third pass

Date: 2026-10-11. Branch `sec6-fuzz3`, from `5f89ee7`. The same agent setup and harness
(`server/tests/fuzzing.py`), aimed at what the second pass listed as still not covered: the
gateway's TLS layer, request heads that never end and tunnels that never carry a request,
XML-RPC parameters known only by their position, SAML assertions inside other XML, unquoted
HTML attribute values, JSON objects and arrays under a secret key, and a report fuzz with
signed receipts, voids, content deletion and the seal, checked across processes. Everything ran
in-process or in a throwaway API container; the gateway tests use the in-process gateway of
`test_gateway.py` on 127.0.0.1 and Python's `ssl` with the gateway's own CA, in front of local
stub upstreams. No traffic left the machine.

```sh
python -m pytest -q tests/test_fuzz3.py tests/test_security_fuzz3.py      # about 40 s
ATTACKLEDGER_FUZZ_ITERATIONS=400 ATTACKLEDGER_FUZZ_SEED=7 python -m pytest -q tests/test_fuzz3.py -k tls
```

ClientHellos come from `server/tests/tlsfuzz.py`: a real ClientHello from Python's `ssl`
(MemoryBIO, nothing sent), with its server name and ALPN extensions replaced by any bytes.

## Targets and properties (`server/tests/test_fuzz3.py`)

| Target | Property | Inputs per default run |
|---|---|---|
| Gateway TLS, raw ClientHellos | After CONNECT, a ClientHello with any server name (the CONNECT host in other cases, an IP literal, `[::1]`, empty, 64-character labels, 255, 256 and 4,000 bytes, not ASCII, Latin-1, a NUL, CRLF and a header, `*.`, another host, none) and any ALPN list (`h2` only, empty, three 255-byte names, `h3`, `http/1.0`), TLS 1.3 and 1.2, byte-mutated or not, followed by an alert, the hello again or a token, then closed or left idle: no crash, exactly one row for the connection (the tunnel's own, `refused` or `failed`, naming the job and host), nothing sent upstream, never an answer in HTTP, within 15 s | 60 |
| Gateway TLS, whole handshakes | Python's `ssl`, verifying with the gateway CA or not, with server names of every kind (none, case, final dot, another host, an excluded host, an IP, a 63-character label) and ALPN lists, then nothing, a request (inside the tunnel's rules or not: HTTP/2 preface, absolute form, another `Host`, a write) or a mutated one, closed with or without `close_notify`: one row when the tunnel carried no request, never a tunnel row besides a request's; nothing upstream without an `allowed` row; nothing at all for another server name; only `http/1.1` or no protocol negotiated | 40 |
| Request heads cut anywhere | Any non-empty part of a plain, CONNECT or in-tunnel head (mutated or not), then closed or left idle until the head timeout: exactly one row (400 or 408), the tool answered, nothing upstream | 40 |
| The second pass's request fuzz, strengthened | Every input that sent anything now leaves a row, tunnels included (it allowed none for a tunnel that carried no request) | 120 |
| Redaction of the new forms | A value placed in a positional XML-RPC parameter (WordPress, Blogger, MetaWeblog and Movable Type calls, login-named methods; `<string>`, bare and `<base64>` values; alone or in `system.multicall` among other calls), a SAML assertion or encrypted assertion inside SOAP, WS-Security, an artifact response or WS-Trust (prefixes `saml:`, `saml2:`, `ns2:`, none, with the namespace on the element or not), a SAML response in base64 under a name that is not secret (form, JSON, raw, wrapped at 76), an HTML attribute quoted or not in any order and case, `data-*` attributes, a JSON object or array 1 to 4 levels deep under a secret key (escaped keys too): it never survives `text` or `http_message`, a second pass changes nothing, JSON stays JSON with the same keys; the same documents without a secret name, method or SAML namespace come back unchanged; 29 pumped tokens (alone, followed by `y`, and 25 random combinations) are linear | 400 and 200 per format |
| The report | Random histories (the second pass's operations, plus closes signed with Ed25519 and ECDSA P-256 keys by a reviewer, an owner and a tester who is refused, unsigned closes, voids by a reopened item or new evidence, keys revoked after signing, the signer renamed (random text), given another email, disabled and enabled again, roles changed, the content deleted): no request answers 5xx; the JSON and HTML reports build, are the JSON rendered, and verify with `tools/verify_report.py`; in strict mode (`--require-history`) they verify exactly when every receipt in force is signed, and otherwise fail for that reason; then two other Python processes with other hash seeds (`PYTHONHASHSEED` 1 and 4242), reading the same database with the clock fixed, write the same bytes for every engagement | 5 histories |

Runs made, besides the default suite: seeds 1 to 3 at 400 inputs per TLS and head test, seeds 1
to 3 and 9 to 11 at 3,000 redaction placements per format, seeds 1 to 6 at 30 report histories,
and 600 inputs of the strengthened request fuzz, after the fixes, with no failure. While the
SAML rule was being written, the placement fuzzer found that an `<AssertionIDRef>` inside an
assertion (its close tag starts like the assertion's) made the rule skip the assertion, and that
an assertion in another's `<Advice>` ended the outer one's replacement early; both are in the
regression tests.

## Findings

Severity in AttackLedger's threat model, as in the first two passes. Each has a regression test
in `server/tests/test_security_fuzz3.py` (FZ-*) that failed before its fix; "found by" says
whether a fuzzer of `test_fuzz3.py` found it, a probe written while building one did, or it was
on the second pass's list.

| ID | Severity | Where | What | Found by | Fix |
|---|---|---|---|---|---|
| FZ-36 | Low | `gateway._connect` | A CONNECT with a body (`Content-Length`, chunked, cut off) was closed with no answer and no row; one followed by bytes before the `200` was answered `200` and then closed, with no row | probe while writing the TLS fuzzer | Both are a `400` and a `CONNECT` row (`refused`); a body that never arrives is a `408` |
| FZ-37 | Low | `gateway._connect` (`StreamWriter.start_tls`) | Bytes the client sent after CONNECT, before the `200` came back, stayed in the stream's buffer, and the tunnel read them as its first request, as if they had come through TLS: a plain `GET` was sent to the target and its answer went back inside TLS. Every check still applied (scope, `Host`, the credential), so nothing out of scope was reachable, but "every tunnel is TLS" did not hold | probe (an API answer that takes 300 ms, as in a deployment) | The buffer is checked with no await between the check and the handshake's start, which stops reading; such a tunnel is refused and logged |
| FZ-38 | Low | `gateway._serve`, `_connect` | No row for a connection that ended before a whole request: a tunnel whose TLS handshake failed (plain HTTP, garbage, a client that does not trust the CA, no handshake), a tunnel closed or idle after its handshake (a TLS scanner), and a request head that stopped arriving (plain or in a tunnel). A tool that only made handshakes, or failed every one, did not appear in the request log | on the second pass's list | One row per connection: the tunnel's own (`CONNECT`, the job and host, why), or a `408` for a head cut off; nothing for a connection that sent nothing (the healthcheck's) or a keep-alive one idle after its request |
| FZ-39 | Info | `gateway.CA.server_context`, `_connect` | The TLS server name (SNI) was not read: a client that does not check the certificate could make its handshake for another name than it had CONNECTed to. The certificate was the CONNECT host's and every request had to name that host in `Host`, so nothing reached another host | probe while writing the TLS fuzzer | The name is kept by an SNI callback and must be the CONNECT host's when sent; otherwise the tunnel is refused, with the name in the row. Non-ASCII names, which Python refuses before the callback with a traceback on stderr, are one line (`gateway.quiet_unraisable`, installed in `main`) |
| FZ-40 | Info | `gateway._request` | Inside a tunnel, a refusal made before the credential was looked up (a target that is not a path, a `Host` of another host, an HTTP/2 preface from a client offering only `h2`) logged a row with no job and no engagement, so the engagement's log did not show it | probe while writing the TLS fuzzer (ALPN `h2`) | The tunnel's job and engagement are in every row it leaves; `PRI * HTTP/2.0` is told that the gateway speaks HTTP/1.1 only |
| FZ-41 | Medium | `redact` (`_xml`, `SECRET_NAMES`, `_formats`) | A SAML assertion inside other XML (WS-Security, an artifact response, ECP) kept its subject and attributes, and an encrypted assertion was kept whole: a service provider decrypts and accepts it as it is, so it logged its subject in until it expired. A SAML response in base64 under another name than `SAMLResponse` (OAuth's SAML bearer grant `assertion=`, WS-Federation's `wresult`, a JSON field) was stored as it was | on the second pass's list; placements | `<Assertion>`, `<EncryptedAssertion>` and `<Artifact>` are replaced whole when the XML is SAML's (a `saml` prefix or SAML's namespace in the document), an assertion in another's `<Advice>` included; a base64 run starting like XML is decoded (its first 6,000 characters) and replaced when it names SAML's namespace; `assertion`, `wresult` and `credentials` are secret names (a JSON `assertion` is WebAuthn's and is not) |
| FZ-42 | Medium | `redact` (`_xmlrpc`) | XML-RPC parameters known only by their position were stored: `wp.getUsersBlogs(username, password)`, the WordPress brute-force target, and every WordPress, Blogger, MetaWeblog and Movable Type call, which all take a password that way, in `system.multicall` too | on the second pass's list; placements | In a call of those APIs, or of a method named for a login (`login`, `auth`, `token`, `session`, `password`, ...), every string parameter is replaced: a parameter's own value and each value directly in an array (multicall's params); numbers, booleans and struct members with names that are not secret stay |
| FZ-43 | Low | `redact._xml_attrs` | HTML attribute values without quotes were not read: `<input type=hidden name=csrf_token value=...>`, `<meta name=csrf-token content=...>`, `<INPUT VALUE=... NAME=password>`; nor `data-*` attributes named by what follows (`data-pwd`) | on the second pass's list; placements (`data-*`) | Unquoted values as HTML ends them (a `/` that closes the tag is kept); `data-` is ignored for the name |
| FZ-44 | Low | `redact._json` | A JSON object or a nested array under a secret key was kept: `"credentials": {...}` (only its own secret keys went), `"token": {"value": ...}`, `"session": {"id": ...}`, `"password": [["..."]]` | on the second pass's list; placements | Every string and number inside it is replaced, keys kept, the JSON still valid; its end is found by counting brackets outside strings (at most 1,000,000 characters on); one cut off is replaced to where the search stopped |

## What held

- OpenSSL refused every malformed ClientHello the fuzzer made, and every overlong or NUL-holding
  server name, before the gateway's code ran; Python refused names that are not ASCII. An empty
  name passes OpenSSL and is refused by the gateway, as not the CONNECT host's. The CA issued a leaf for every name the scope allows, including 1,931-character names
  of 63-character labels and IP literals, in about a millisecond. No ALPN list made the gateway
  negotiate anything but `http/1.1`.
- Nothing reached an upstream from a tunnel whose server name was another host, whose handshake
  failed, or whose request was refused; the `Host` check held on every request inside a tunnel.
- The report built, verified and verified strictly from every random history with signed
  receipts, voids, revoked keys, renamed, re-emailed and disabled signers, changed roles and
  deleted content, and strict mode failed exactly the reports with an unsigned receipt in force.
  Two processes with other hash seeds wrote the same bytes as the first for every engagement:
  no set, dictionary or hash order leaks into a report, and the seal (Ed25519, deterministic) is
  the same for the same body and time.
- The new redaction rules are linear on every pumped input and idempotent, and the first and
  second passes' placement, plain and pumped tests still pass on them. Measured on 2 MB bodies:
  JSON with a secret object in each record at 2.2 MB/s (4.6 before), an XML-RPC call of 40,000
  parameters at 3 MB/s, HTML at 3.7 MB/s.

## Still not covered

- Redaction: an XML element with a secret name that holds other elements (other than a SAML
  assertion), JavaScript object literals (unquoted keys), XML-RPC calls of other APIs that take
  a password by position, and a deflated SAML message under another name than `SAMLResponse`.
  `redact.py` lists these.
- The gateway still speaks HTTP/1.1 only; HTTP/2 and HTTP/3 are refused, not fuzzed. The upstream
  side of TLS (what a target's handshake can do to the gateway's client) was not fuzzed.
- The report fuzz drives the API with one organization and the WSTG pack, and no timestamp
  authority; timestamps on receipts and seals are covered by `test_timestamps.py` and
  `test_report_seal.py`, not by random histories.
- The verifiers were not changed in this pass, so the equivalence run was not repeated (134
  reports, 0 differences, from the first pass). The web app is the subject of the end-to-end tests.

## Counts

Server suite (SQLite): 1,159 passed and 1 skipped before; 1,222 passed and 1 skipped after
(`test_fuzz3.py`, `test_security_fuzz3.py`, and more cases in `test_caido_pull.py`'s check of the
vendored rules). Postgres (`tools/test_postgres.sh`): 1,222 passed and 1 skipped, and the
migration-0022 upgrade check passes; the report fuzz's other processes read the same Postgres
database there. The second pass's request fuzz holds the stronger property (a row for every
connection that sent anything). The verifiers did not change: 134 reports, 0 differences, as
before.
