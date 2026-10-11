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
