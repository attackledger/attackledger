# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org/);
before 1.0, minor versions may change the data model.

## [Unreleased]

Tested on a real server: a fresh Ubuntu 22.04 VPS (Docker 29.1, Compose 2.40), with the
production file, loopback-only option D and the lab profile. Lab recon ran through the
gateway (22 requests, all GET or DNS). The worker could not reach the internet, the
database or the API. Backup, wiping every volume and restoring without `--force` kept the
evidence chain identical, and the encrypted note stayed readable.

### Security
From an internal security review of the whole product, in three parts, and a second pass that
closed the first's recommendations; each report lists what was checked, every finding with its
reproduction, and what was found sound (`docs/security-review/`). Every fix has a regression test
that failed before it.

Gateway and worker isolation (`GATEWAY.md`):
- **An agent job could make Anthropic's servers fetch any URL** (GW-1). The gateway forwarded
  any `/v1/messages` body, so server tools (web fetch, web search), the MCP connector and URL
  image or document sources reached hosts outside the scope, the rate ceiling and the request
  log. The body is now parsed strictly and sent only with the agent's own keys and tools.
- **Connections to targets were not paced** (GW-2). The rate token was taken after the TCP
  connection and TLS handshake, so concurrency opened connections at any rate. Connections now
  wait for a token of their own.
- **A compressed response leaked a test account's session** (GW-3). A target that compressed
  despite `Accept-Encoding: identity` passed the scrub and the redaction. The body is now
  decoded before it is scrubbed, or withheld.
- **A reflected session in another encoding was not scrubbed** (GW-4): URL-decoded (phpinfo's
  `$_COOKIE`), URL-encoded, HTML-escaped or with JSON-escaped slashes.
- **Cloud metadata services outside link-local were reachable** (GW-5): Alibaba Cloud, AWS over
  IPv6, Azure's WireServer and Oracle Cloud Classic addresses are now refused.
- **One address of the API was not refused** (GW-6). Docker resolves a service name to one
  network only; the API, on two networks with the gateway, now has an alias per network in the
  deny list (and the production API trusts `X-Forwarded-For` from any peer).
- **A job target could carry a second target line to the tools** (GW-7): the URL parser drops
  newlines, the tools do not. Targets with whitespace or control characters are refused.
- **The Docker host was reachable** (GW-8, second pass). Through the gateway, an in-scope name
  resolving to the host's bridge address (172.x.0.1) or anywhere in the gateway's own networks
  reached host services and the stack; and the worker, alone on the internal network, reached a
  service the host ran there directly (measured on Docker 29.5). The gateway now refuses the
  subnets of its own interfaces except the lab's (`ATTACKLEDGER_GATEWAY_TARGET_NETWORKS`, set to
  the gateway's alias `gateway-lab`), and the internal networks give the host no address
  (`inhibit_ipv4`). Real internal targets stay allowed: those subnets are routed to Docker, never
  to a customer's network. On upgrade, Compose recreates the internal networks.
- **The gateway listened on every network it is on** (GW-9, second pass). The proxy, the
  resolver and the worker's relay now answer on the worker's network only
  (`ATTACKLEDGER_GATEWAY_LISTEN=gateway-internal`), the proxy also on loopback for the healthcheck.
- **A header with a line break ended an approved write without a log row** (GW-10, second pass).
  Test-account and approved-write headers were checked only when the gateway wrote them, after
  the approval was used. They are now refused where they come in (422 for test accounts, a tool
  error for the agent, no approval of such a request), and the gateway logs a refusal instead of
  dropping the connection.
- **One request log row the API refused stopped the gateway's log, and then all traffic** (GW-11,
  third pass). The gateway sends an unwritten batch again until the API takes it, and refuses every
  request once 5,000 rows wait; the API refused the whole batch for one bad row. Any tool in the
  worker could do it: an `X-AttackLedger-As` label longer than 16 characters was logged whole, and
  the API refused it (422). The label is now logged as the column holds it, and one row can no
  longer hold the log up: the API writes every row it can and answers, per row, the ones it cannot
  store, storing in each one's place a placeholder (verdict `unlogged`, no URL, and why), so the log
  still counts the traffic it could not record. The gateway sets such rows aside in a bounded
  quarantine file in its private volume (`/data/gateway/log-quarantine.jsonl`, holding only what
  the log row holds); a batch refused whole with 400, 413 or 422 is halved until the row is found.
  An API or database that is down, a 5xx or a wrong token keep the rows queued, and the gateway
  still fails closed. A lone surrogate in a row (a 422, then a 500, for the whole batch) is kept
  as U+FFFD, and a time with no UTC form is a placeholder.

Evidence, encryption, imports and the web app (`EVIDENCE.md`); both verifiers changed the same way:
- **The verifier missed a voided receipt reported as receipted** (EV-1). Setting a void lane's
  unsigned status back to `closed` hid the void (D-052). The change history check now fails a
  receipt that an audit entry records as voided.
- **A receipt's issue time could be moved** (EV-2). The role check read the unsigned time, and
  moving it before the audit log began skipped the check. It must now lie within the window
  the server allows after the signed payload's issue time.
- **The signed engagement was not compared with the report's** (EV-3). Another engagement id
  fails; a rename since signing is a NOTE.
- **The counts the verifier prints were not checked** (EV-4). Receipted lanes and evidence
  entries in the summary must be the report's own.
- **An HTML report with edited page text still verified** (EV-5). The verifier now says that
  only the embedded JSON is checked, and "How to verify" says the body hash can be recomputed
  by anyone.
- **Deleting an engagement's content left its traffic log URLs** (EV-6). The gateway log's
  URLs are now blanked; method, host, status and verdict stay.
- **Azure key headers were stored unredacted** (EV-7): `Ocp-Apim-Subscription-Key`,
  `X-Functions-Key` and `X-Master-Key`, also as parameters and JSON keys.
- **Drafts with a credential reached sessionStorage** (EV-8) when written as a JSON field, a key
  header, `password: ...`, a private key or an AWS key id.
- **Evidence could be moved to another item in a signed report** (O-1). The manifest did not
  name the items' ids. Manifest version 2 names each item's id and text (D-054). Older receipts
  still verify, with a NOTE.
- **History entries could be left out of a report** (O-2). Receipt payload v4 signs the audit
  log and key log heads, and the count and hash of the engagement's and signer's audit entries up
  to them. The server checks them, and a report that leaves one of them out fails. The new
  `--require-history` option (a checkbox on /verify) also fails a report without the logs, or
  with receipts signed before v4.
- **A void made after the last receipt signature could still be left out** (O-2, the rest).
  The server now seals every report it exports (D-055): its own Ed25519 key, wrapped by the
  master key and registered in each organization's key log, signs the report body hash and the
  heads of the audit log and the key log, and the seal is timestamped when a timestamp authority
  is set. Both verifiers check it (*Report seal*); `--require-history`, the /verify checkbox and
  the Verify tab option require it. Reports made before seals verify as before, with a NOTE.
  The seal is the server's statement, not a reviewer's: what it does and does not prove is in
  `docs/VERIFIER.md`. Migration `0024` lets a key log entry name no person. The sample report and
  the demo were rebuilt in the current format (manifest v2, payload v4, sealed).
- **A verified HTML report did not show what was verified** (O-3). Both verifiers now list what
  its embedded JSON says (engagement, scope, lanes, signers, dates, counts) to compare with the page.
- **Deleting an engagement's content now reaches every place it is kept** (RET-1 to RET-7, an
  audit of every store, `docs/security-review/RETENTION.md`). A new test seeds a unique string into
  every store, deletes the content and searches every table row, the SQLite file's bytes, the blob
  store and the gateway's quarantine file; a second engagement's string is the control. Left behind
  before, now removed:
  - the gateway's quarantine file kept the deleted engagement's request log rows (RET-1). The
    gateway now asks the API at start and every minute (`POST /gateway/content-deleted`) and
    removes their rows;
  - a run going on at the deletion kept running and writing: log lines, its error, the agent's
    summary; its exchanges' URLs stayed until it ended (RET-2). Deletion cancels the engagement's
    queued and running jobs, deletes their exchanges, and keeps nothing they report afterwards;
  - job targets kept the URLs recon found, with paths and query strings, and agent runs their
    outcome text (RET-3). Targets are reduced to their hosts, the text is removed;
  - the request log's reasons quote the request (an approved write's URL, unredacted) and the
    target's malformed reply (RET-4). They are blanked with the URLs, also for rows that arrive
    later, and the gateway redacts them as it redacts URLs;
  - on a SQLite built without `SECURE_DELETE` (the one in macOS's Python), deleted rows stayed
    readable in the database file (RET-5). Every SQLite connection now turns `secure_delete` on;
  - plaintext blobs from before encryption that no evidence cites (a v0.6 agent run stored every
    exchange) were never removed (RET-6). `encrypt-existing` removes them, `status` counts them;
  - the docs said that rotating the master key makes a deletion final in old backups (RET-7). It
    does for their encrypted half only: the database dump in a backup is plaintext. The install
    guide, `ENCRYPTION.md`, `tools/backup.sh`, `tools/restore.sh` and the deletion screen now say
    that deletion does not reach backups made before it, and that restoring one brings the content
    back.

Authentication, authorization and organization isolation (`AUTH.md`):
- **A cited hash opened another engagement's blob from before encryption** (AUTH-1, Low).
  A tester could cite the SHA-256 of another engagement's plaintext blob as evidence and read
  it. `encrypt-existing` then copied it, and deleting the other engagement's content kept it.
  Only an engagement's own chain v1 evidence now opens, copies or keeps a plaintext blob.
- **Changes sent by a page of another origin are refused** (AUTH-2, Low). A sibling subdomain
  is the same site and got the SameSite=Strict cookie, and in open mode any web page could post
  to the local API. Routes without a JSON body (revoking a key, cancelling a job, deleting a
  test account, an import) took such posts. POST, PUT, PATCH and DELETE are now refused when
  `Sec-Fetch-Site` or `Origin` says another origin sent them.
- **Separation of duties counts who imported the evidence** (AUTH-3, Low). The person who
  uploaded an export could sign the receipt of a lane holding its entries, if someone else
  mapped them. They are now refused, as the starter of a recon or agent run is.
- **A non-ASCII bearer token or cookie gave a 500** (AUTH-4, Info, second pass); so did one for the
  worker or gateway channel, and an operator token with one at `/auth/login`. Tokens are compared
  as bytes now: 401.
- **A malformed signed payload gave a 500** (AUTH-7, Info, second pass): a time without a zone, a
  list as the chain position. A string chain position was even accepted. The field types are
  checked first: 422.
- **Signing out did not revoke a browser signed in with the operator token** (AUTH-6, Info, third
  pass). The cookie was a fixed HMAC of the token, so a copy of it worked until the token changed.
  Signing in with the token now creates a random session stored as a hash, like a person's: it
  ends on sign-out or after 12 hours, and when the API starts with another token (D-056,
  migration 0023). Bearer tokens (scripts, the worker, the gateway) are unchanged.
- **An approval could be used twice on SQLite** (AUTH-5, Info, third pass). Its single use relied on
  a row lock taken on Postgres only. Using it, approving, confirming a DELETE, rejecting and
  expiring are now conditional updates from the status that was read, on every database: of two
  uses one succeeds, a rejection racing the gateway no longer overwrites a sent write, and an
  approval racing a rejection no longer makes the rejected write sendable.
- **Two workers could claim the same job on SQLite** (third pass). The job ran twice and the
  second claim replaced the first one's job token and gateway secret. Claiming is a conditional
  update from `queued` now; the worker that loses takes the next job.

A second, adversarial pass over those fixes (`RECHECK.md`) found four bypasses and one new issue:
- **A voided signed receipt could still verify as receipted** (EV-1 with EV-2, Medium). The void
  was matched on the receipt's exact issue time, which a report repeats unsigned and EV-2 lets
  differ from the signed time by up to 15 minutes: moving it a second hid the void, in strict mode
  too. Both verifiers now match a void in that window around the signed time, if it came after
  the payload.
- **Open mode could be reached by DNS rebinding** (AUTH-2, Medium). A page whose public name was
  pointed at 127.0.0.1 sent same-origin requests and read the answers. Open mode now answers only
  requests that name the machine by an IP address, a name without a dot or a special-use name.
- **The command-line verifier printed terminal controls from a report** (RC-1, Low): a name could
  print a fake `Verified.` and conceal the real result. Such characters are now printed escaped.
- **Port probes beside requests opened up to twice the rate in connections** (GW-2, Low). Probes
  now wait for the connection limiter too.
- Info: NAT64, 6to4 and IPv4-compatible forms of refused addresses are refused too (GW-5, GW-8);
  every member of a multi-member gzip response is decoded (GW-3, it was cut short, without a leak);
  a signed payload's ids out of the database's range are a 422, not a 500 (AUTH-7).

On Postgres, as production runs (the suite had run on SQLite only; `tools/test_postgres.sh`):
- **Approvals and sessions expired late, or early, on a database session not in UTC.** Times are
  stored without a zone and read back as UTC, but Postgres stored a timezone-aware time in the
  session's local time (the server's `TimeZone`, or `PGTZ`). At +03:30 an approved write stayed
  usable for three and a half hours after its 5 minutes, an expired browser session still signed
  in, and a signed receipt's stored issue time no longer matched its signed payload, so its
  report failed verification (24 tests failed with the server in such a zone; the 0.7.1 code's own
  report failed `verify_report.py`). Every connection now sets its time zone to UTC. The Compose
  stack's database is in UTC, so it was not affected.
- **One row could stop the gateway's request log for good, and then its traffic.** A NUL character
  in a logged URL or reason (an agent can be steered to request one), or a response of more than
  2 GiB (a target can send one: the byte count overflowed Postgres's 32-bit `INTEGER`), made the
  API refuse the whole log batch with a 500. The gateway keeps an unwritten batch and sends it
  again, so nothing it logged after that row was written, and once 5,000 rows waited it refused
  all traffic (it fails closed). The API now writes every row: a NUL becomes U+FFFD, counts past
  the column's range are kept as its maximum, and ports, statuses and ids outside theirs as none.
  A NUL in a tool's output did the same to a job's log and results on the worker's channel; it is
  kept as U+FFFD there too.

Containers and dependencies (`SUPPLY_CHAIN.md`):
- **Every container ran with Docker's default capabilities and a writable root filesystem**
  (SC-1), and Postgres, nginx and Caddy as root. Every service now has `no-new-privileges`, no
  capability (Caddy keeps `NET_BIND_SERVICE`, which its binary needs to run), a read-only root
  filesystem with sized `noexec` tmpfs folders, a non-root user (Postgres 70, nginx 101) and
  memory and process limits, in the development file too. The gateway's port 53 and nginx's port
  80 are bound through `net.ipv4.ip_unprivileged_port_start=0`, not a capability.
- **Base images were unpinned, and four no longer got fixes** (SC-2): nginx 1.27 and Caddy 2.8.4,
  which face clients, Node 20 and Go 1.23 (which compiled seven recon tools). Every image is now
  pinned by its multi-arch digest, on nginx 1.30.5, Caddy 2.11.4, Node 24.21.0 and Go 1.26.9.
- **Python dependencies were pinned at the top only** (SC-3): 34 of the 46 installed packages
  were whatever PyPI had on the day of the build, unchecked. `server/requirements.txt` is now a
  lock with every package hashed (`server/requirements.in` is what people edit;
  `tools/lock_requirements.sh` makes the lock), installed with `pip --require-hashes --no-deps
  --only-binary :all:`. Arjun's source packages are built with a hash-pinned setuptools (SC-5).
- **Known advisories in the API's packages** (SC-4), none found reachable in a way that mattered
  here: cryptography 43.0.3 → 50.0.0, starlette 0.41.3 → 1.6.0 (FastAPI 0.115.6 → 0.136.3),
  pip 25.0.1 → 26.2.1, pytest 8.3.4 → 9.1.1. `pip-audit` now finds none in either image.
- **The web build ran npm install scripts** (SC-6). It now uses `npm ci --ignore-scripts`; the
  production dependencies have no advisory, and the development tools were upgraded (Vite
  5.4.21, ESLint 9.39.5, typescript-eslint 8.71.1), leaving two dev-server-only advisories that
  need Vite 6.
- **SBOM**: `tools/sbom.sh` writes a CycloneDX SBOM per image (OS packages, Python, the Go
  modules of each recon tool, npm), from the built images (SC-7, `docs/SUPPLY_CHAIN.md`).
- `tools/backup.sh`, `tools/restore.sh` and the pre-encryption upgrade step run their root steps
  as one-off containers with only the capabilities they need (SC-8), so they keep working without
  the default ones (measured: without them, root could not read the engagement keys and every
  backup failed). The lab proxy's nginx configuration is now a file, `deploy/lab-proxy.conf`:
  Compose cannot write inline content into a read-only container (SC-9).
- **FastAPI 0.136.3 → 0.141.1, starlette 1.6.0 → 1.7.0.** FastAPI 0.137+ no longer lists an
  included router's routes in `app.routes`, so the tests that check every route (each has a
  permission rule, none reaches another organization, the worker's routes) would have seen none
  of the gateway, worker, test-account and approval routes. They now walk included routers
  (`server/tests/routewalk.py`), checked against the OpenAPI schema and each router, and a new
  test sends a request to every route and checks that `authz.authorize` runs and finds that
  route's own rule.
- **Vite 5.4.21 → 8.3.1** (@vitejs/plugin-react 4.3.4 → 6.1.1, esbuild 0.28.2 as a development
  dependency of its own): the two development-server advisories left (SC-6) are gone, `npm audit`
  finds none. The built app has the same files and the same inline script, so the
  Content-Security-Policy is unchanged; the verifier page builds byte-identical.
- **GitHub Actions are pinned by commit SHA**, with the tag in a comment; a test fails on any
  `uses:` that is not.
- **`tools/refresh_pins.sh`** shows, for every digest-pinned base image, the digest its tag points
  at today (`--write` moves the stale ones). `docs/SUPPLY_CHAIN.md` suggests running it monthly
  and whenever an advisory names a base image.

### Upgrade note
The internal Docker networks changed (the host gets no address on them). Upgrade with
`docker compose down` (without `-v`) before `docker compose up -d --wait`: a plain `up -d` left the
database without a name on its recreated network, and the API failed to start (INSTALL §15).

A browser signed in with the operator token is signed out once by the upgrade: the old token-mode
cookie is no longer accepted (AUTH-6). Sign in with the token again. People's sessions, and
scripts that send the token as a bearer header, are not affected. Migration 0023 runs when the API
starts.

On a Postgres server whose `TimeZone` is not UTC (not the Compose stack's), times written before
this upgrade stay shifted by that zone's offset; new ones are stored in UTC.

Migration 0025 (run when the API starts) changes three columns of `gateway_requests` to BIGINT. On
Postgres that rewrites the table under a lock: with a large request log the API takes longer to
start, and the gateway queues its rows (failing closed past 5,000) until it is up. Counts recorded
before as 2,147,483,647 stay so. Rows the gateway sets aside are in `/data/gateway/log-quarantine.jsonl`
in the `gateway-private` volume; a backup of the database does not include them.

Containers and dependencies (`docs/security-review/SUPPLY_CHAIN.md`): `docker compose build`
pulls the new base images by digest, and `docker compose down` then `docker compose up -d --wait`
(see above) recreates every container with the new limits; volumes and data are kept. Postgres now runs as uid 70 from the start: a
data volume made by an earlier release is already owned by it. Caddy reads
`deploy/certs/key.pem` as root without `DAC_OVERRIDE`: keep the key owned by root (INSTALL §5
copies it as root), or Caddy cannot read it. The web container's memory limit is 512 MB (was
256 MB): uploads wait in a memory-backed tmpfs. Scripts of your own that `docker compose exec
--user 0` into a container and expect root's usual powers (reading other users' files, chown) now
need a one-off `docker compose run --cap-add ...` instead, as `tools/backup.sh` does. The web app is built
for Vite 8's default browsers (Chrome and Edge 111, Firefox 114, Safari 16.4 or later; before:
Chrome 87, Firefox 78, Safari 14).

### Fixed
- **The gateway log's byte counts and durations are 64-bit** (migration `0025`, BIGINT on
  Postgres). They were 32-bit `INTEGER`, so a response past 2 GiB, which a target decides, was
  recorded as 2,147,483,647 bytes; the exact count is kept now, up to 2^63 - 1. A negative duration
  is recorded as unknown.
- **A NUL character in a request gave a 500 on Postgres**, after part of the work, where SQLite
  stored it. Now on every database: in the path or query 400, in a person's JSON 422 with nothing
  stored; in an import, a row whose URL holds one is listed as unreadable, and other fields keep
  it as U+FFFD (`app/nulguard.py`, `importers.text`).
- **An evidence URI longer than 1,000 characters gave a 500 on Postgres** (the column's length is
  enforced there only). It is refused with 422, also when redaction makes it longer.
- **URL search and triage's API signal depended on the database.** `LIKE` ignores case on SQLite
  and not on Postgres: `/API/v1/...` paths counted for triage on SQLite only, and the endpoint and
  inbox searches matched case on Postgres. Both now ignore case everywhere, and the endpoint search
  takes `%` and `_` literally.
- **A flaky worker test.** `test_worker.py`'s gateway test compared two separate DNS lookups of
  `gateway.invalid`; a resolver that answered inconsistently made them differ. The tests now
  answer `.invalid` names themselves (RFC 6761: they never resolve).
- **The same worker test was still flaky, and the cause was the worker.** The worker wrote a
  tool's input to its stdin and closed it; a tool that had already ended without reading it (the
  test runs `env`; a real tool refusing a flag does the same) made that a `BrokenPipeError` that
  ended the job with the worker's error instead of the tool's exit code and stderr. Whether `env`
  finished first was timing: with three suites at once it failed in 4 of 9 runs. A broken pipe to a
  tool is now the tool's outcome; a new test sends more input than a pipe holds to a tool that
  quits, so it fails every time without the fix.
- **A tool that answers as it reads could hang its job.** The worker wrote all of a tool's input
  before reading any of its output, so a tool that writes while it reads (`dnsx`, `httpx` and
  `katana` answer target by target) filled its output pipe, about 64 KiB, and waited for the worker,
  which still waited to finish writing. The time limit's timer started only after the write, so the
  job stayed running until someone cancelled it. stderr had the same wait: read only after stdout
  ended, more than a pipe of warnings before the output stopped the tool until the time limit. The
  input is now written and stderr read by threads while stdout is read, the timer starts with the
  tool, and a broken pipe is still the tool's outcome. Two new tests (`cat` echoing 50,000 lines,
  a tool writing 460 KB of warnings first) hung or timed out before the fix.
- **`tools/backup.sh` and `tools/restore.sh` swallowed the rest of a script.** Run from a
  pipe or a heredoc (for example `ssh host 'bash -s' < steps.sh`), `docker compose exec`
  read the caller's stdin, so nothing after the backup ran. Docker calls no longer read
  stdin; the two restore steps fed a file are the only exceptions.
- **Restore refused a freshly wiped install.** Since migration 0022 every new install holds
  the default organization, and restore counted that row as data and asked for `--force`.
- **The web image had no favicons**: `web/Dockerfile` did not copy `web/public`, so a
  self-hosted install answered `/favicon.svg` with the app's HTML. Found by capturing the
  local app through Caido.

### Changed
- **The server tests run on Postgres too**: `tools/test_postgres.sh` starts a throwaway Postgres
  16 and runs the whole suite on it, each test on new databases (`ATTACKLEDGER_TEST_PG`,
  `server/tests/testdb.py`), then upgrades a database the 0.7.1 code filled (CONTRIBUTING.md).
  The race tests prove one winner there as well, and migrations 0001 to 0023 run from empty.
- **Recon workflow, redesigned** (ideas from the ars0n framework; no code taken).
  - A summary line ("6 steps, 13 tools; 13 done, last finished …") and one clear Run all
    button.
  - While steps run, one progress bar shows which tool runs now and for how long. It stays
    under 100% until the last step finishes.
  - The found counts are large, with log-scale bars.
  - Steps are a timeline: numbered nodes turn into a check when every tool of the step has
    finished.
  - Tool cards sit in a grid, each led by its result count, with Run, Results and Log in
    the same place on every card.

## [0.8.0] - 2026-10-10

Test accounts and approved writes for agents, and organizations on every record.

### Added
- **Organizations** (D-042, migration 0022). Every record belongs to one. The migration
  makes a default organization and moves every existing row into it; a self-hosted
  install is unchanged.
  - **Scoping:** every API query is scoped to the caller's organization in one place
    (`orgscope.py`). Another organization's ids answer 404, like ids never used.
  - **Logs:** the key log and the audit log are one chain per organization. The default
    organization's chain is the old one, so existing reports still verify.
  - **Tokens:** worker and gateway tokens belong to an organization.
  - **Commands:** `python -m app.orgs` (list, create, tokens) and
    `python -m app.people … --org`.
  - **Behaviour change:** non-owners get 404, not 403, on owner routes for what they
    cannot see.
- **Test accounts** (D-040, migration 0021). Testers add sessions they signed in to
  themselves: a cookie, a bearer token or headers.
  - They are stored encrypted and never shown again.
  - The gateway adds them to an agent's requests "as A", for that account's hosts only,
    and scrubs responses before they reach the worker.
  - Evidence names the account.
- **Writes with a person's approval** (D-041), off by default. Agents propose POST, PUT,
  PATCH or DELETE, and a tester approves the exact request.
  - An approval is hash-bound, expires after 15 minutes and is used once.
  - A DELETE needs its path typed.
  - The gateway sends the write once, and it becomes evidence and audit entries.
  - New Test accounts and Approvals tabs.

### Fixed
- **Gateway log noise:** ProjectDiscovery tools run with `-duc`, so there are no update
  calls in the request log, and the gateway answers katana's Burp check itself.
- **Gateway log:** `bytes_sent` is now recorded.

## [0.7.1] - 2026-10-10

Fixes from the second design-partner review of 0.7.0.

### Changed
- **A voided receipt stays void** (D-052). Any change to a receipted lane voids its receipt
  until it is signed again, even if the lane is changed back. The audit log records it as
  `lane.receipt_voided`, and the report and change history show why.
- **Strict Content-Security-Policy on the web app**, plus the usual security headers in
  nginx and Caddy.
- **API docs** (`/docs`): a script-free page built from the OpenAPI schema. It loads
  nothing from another origin.
- **Wording**: gate and step messages use client, statement of work and rules of
  engagement wording on pentest and internal engagements.

### Added
- **Confirmation before mapping onto a receipted lane**: the API returns 409 unless
  `confirm_void`.
- **`can_sign` in the lane view**: it says before signing whether this person can sign,
  and why not.
- **The deletion screen** says what stays: each evidence URL with its host, path and
  query, plus receipts, signatures and logs. A proposal for a chain record that would not
  keep query strings is in `docs/PROPOSAL_URI_PRIVACY.md`.
- **The import route** documents its raw body in OpenAPI, and refuses multipart uploads
  with an example.
- **`caido_pull --upload`** finds the API under the site's address.
- **Docs**:
  - a Mac trial section in INSTALL;
  - what content deletion keeps;
  - what counts as a duplicate import;
  - the Verify tab as it is;
  - `.env.example` matches where each key goes.

- **Web**:
  - Links to an engagement, tab, lane and import entry (`#/e/3/ledger/lane/12`), with
    Back and Forward, reload, and "Copy link" on the lane panel. They work in the demo
    too (D-053).
  - An expired session says so, keeps unsent notes and reasons, and returns you to where
    you were.
  - Import marks items on receipted lanes "(voids receipt)" and asks before voiding them.
  - An engagement whose content was deleted shows a banner on every tab and disables
    import, runs and mapping.
  - Lane evidence is shown in chain order, with View raw for imported entries.
  - Cells show "Signed after …", and people who cannot sign see why.
  - Times are local, with UTC on hover. Fingerprints have one format. The offline
    command uses the report's real file name.

### Fixed
- **Controls**: the status when only not-applicable items are resolved.
- **Recon**: the per-step lead counts.
- **Mapping**: a clearer error for an item number that doesn't exist.

## [0.7.0] - 2026-10-09

The MVP for a design partner (docs/MVP.md). It covers:
- a traffic gateway for all target traffic, and a worker with no route to the internet
  or the database;
- encryption at rest with retention;
- evidence import from HAR, Burp and Caido;
- a public in-browser verifier;
- a tested install with backup and restore.

Version 0.6.0 was never released on its own; its changes, which first brought hunt agents
(a Claude agent can work a lane within the lane's rules), are included here. The agent loop
on the Messages API has still not run against the live API (no key was available). It is
tested with a scripted model and the local lab, and was driven from Claude Code for the
demo (D-031).

### Added
- **Caido pull** (`tools/caido_pull.py`, D-035). It reads HTTP history from your own Caido's
  GraphQL API, with an HTTPQL filter and a time window, and writes a Caido JSON export. The
  export can be redacted locally and uploaded to an engagement as you. The Caido token
  never leaves your machine.
- **Traffic gateway** (D-039, docs/GATEWAY.md). The worker has no route to the internet.
  Every recon tool and the agent go through one gateway. The gateway:
  - enforces scope, GET/HEAD/OPTIONS only, a rate ceiling shared by all tools, and the
    identification;
  - answers DNS only for in-scope names;
  - makes the port probes (naabu removed);
  - logs every request (`GET /engagements/{id}/gateway-log`).

  Benchmark through it: 0 non-GET, peak 20/s at a limit of 20. Migration `0019`.
- **Public verifier page** (`/verify`, D-042, D-046). Drop a report on
  attackledger.com/verify and every `verify_report.py` check runs in the browser, with
  the same verdicts and messages. Nothing is uploaded: `connect-src 'none'`, everything
  inline, Trusted Types.
- **The Verify tab checks everything**: the chain, receipts, signatures, key log, change
  history and RFC 3161 timestamps. It uses the same module as the public page
  (`web/src/verify_report.ts`, replacing `receipts.ts`).
- **Equivalence tests** (`tools/verifier_equivalence/run.sh`): 67 reports and 107
  building-block cases compared line for line with `verify_report.py`; 0 differences.
- **Install and operations**:
  - `docs/INSTALL.md`, tested end to end from the document.
  - A production override with Caddy HTTPS (`deploy/`).
  - `tools/backup.sh` and `tools/restore.sh`. The backup has a checksummed manifest.
    Restore refuses a damaged backup, an unknown migration, the wrong master key, or a
    non-empty install without `--force`.
- **Setup mode** (D-045): `ATTACKLEDGER_REQUIRE_SIGN_IN=1` closes the API until the
  first owner is created on the server.
- **Evidence import** (D-029): HAR 1.2, Burp Suite XML and Caido JSON files become inbox
  entries on a new Import tab.
  - Out-of-scope rows are refused and listed by row and host.
  - Credentials are redacted and raw bytes encrypted before storage, and entries are
    deduplicated by content.
  - A person maps each entry to checklist items, with explained suggestions. Each mapping
    is evidence with source `import:<tool>`.
  - Imports and dismissals are in the change history. Migration `0018`.
- **Encryption at rest** (D-043): evidence blobs and summaries are encrypted with a key
  per engagement, wrapped by a deployment master key (`ATTACKLEDGER_MASTER_KEY_FILE` or
  `ATTACKLEDGER_MASTER_KEY`; `ATTACKLEDGER_DEV_KEY=1` for trials). The API and worker
  refuse to start without one. Migration `0017`.
- **Retention**: owners set a "keep until" date, which the worker executes, or delete an
  engagement's data now with a typed-name confirmation. Both go into the audit log.
  Reports built afterwards still verify, with summaries marked unavailable.
- **Evidence chain record v2** commits to `summary_sha256` and `source` (manual, recon,
  agent, `import:<tool>`). v1 rows and old reports verify as before.
- `python -m app.vault`: generate, status, encrypt-existing, rotate-master,
  delete-content.
- **Guided first run**: the five setup steps from scope to first lane, each step's
  status computed from the engagement itself.
- **Role-based home**: each engagement opens on a tab chosen by role: Report for
  viewers, Ledger for testers and reviewers, the next setup step for owners.
- **Accessibility**: WCAG 2.2 AA contrast in both themes (axe: 0 violations on every
  app screen), small labels one size larger, focus ring on checklist items, and
  focusable logs, commands and tables. On phones and tablets nothing scrolls
  sideways and the sidebar folds into a compact header.
- **Agent runs** (`POST /lanes/{id}/agent-runs`): a job of kind `agent` on one lane,
  with turn and request limits, cancel, partial status and a token cost estimate.
  Migration `0009` adds `jobs.lane_id` and `jobs.result`.
- **Gated agent tools** (`agenttools.py`): `http_request`, `add_evidence`,
  `mark_item`, `record_lead`, `finish`. Lane host and scope only, read-only methods
  (D-024), identification always sent, no redirects, rate-limited, budgeted. No
  tool can close a lane.
- **Agent loop** (`agentloop.py`) on the Messages API with `claude-opus-5-5`,
  adaptive thinking, prompt caching and server-side refusal fallback (D-025).
- **Blob store** for raw evidence, shared by API and worker, and `GET /blobs/{sha256}`
  (sandboxed plain text, only for hashes that evidence cites).
- **UI:** choose the lane's executor, start and follow agent runs, see why a run
  failed, and open the raw exchange behind each agent evidence entry.
- **Agent model setting** `ATTACKLEDGER_AGENT_MODEL` on the worker: `claude-opus-5-5`
  (default), `claude-sonnet-5-5` or `claude-haiku-5-5` for a cheaper first test. Unknown
  models are refused. The cost estimate uses the chosen model's price; Haiku requests
  no server-side fallback (it has none). The model is shown on each run.
- **People, roles and separation of duties** (D-032). Sign in with email and password;
  per-engagement roles (viewer, tester, reviewer) and owners; a People page and a Team
  tab for owners; every route checked against one permission table; non-members do not
  see an engagement at all. Separation of duties is a per-engagement switch: the person
  who attached a lane's evidence cannot sign its receipt. Evidence, jobs and receipts
  record who made them. The first owner is added from the People page (open or token
  mode) or with `python -m app.people create --owner`. Migration `0010`.
- **Signed receipts** (D-033). A reviewer's browser creates a non-extractable Ed25519
  key (ECDSA P-256 where Ed25519 is missing) and signs each receipt; the server stores
  only the public key and checks every signature against the lane's current manifest.
  Report format `attackledger-report/2` carries payload, signature and public key;
  `verify_report.py` checks them offline with the standard library and still reads
  format 1. An engagement can require signatures. Migration `0011`.
- **Audit log** (D-037). Scope and rules, authorization, settings, roles and people changes
  are recorded in a hash-chained audit log, shown in a History tab and a "Change history"
  report section and checked by `verify_report.py` (who held the reviewer role and which
  scope was in force when each receipt was issued). `GET /engagements/{id}/audit`,
  `GET /audit`, `python -m app.people audit-log`. Receipt payload v3 names the signer's
  email. Migration `0016`.
- **Evidence redaction** (D-038). Cookies, Authorization headers, tokens, keys, JWTs, emails
  and card numbers are replaced by a hash marker before evidence is stored; each entry says
  what was redacted. Per-engagement setting, on by default. Migration `0015`.
- **Key trust** (D-036). Owners can no longer set other people's passwords; people change
  their own (`POST /auth/password`) and an operator resets on the server
  (`python -m app.people set-password`, `revoke-key`, `key-log`). Key registrations and
  revocations go into a hash-chained key log (migration `0014`); people see key changes at
  sign-in in a "Your account" dialog; reports carry each signing key's history and
  `verify_report.py` checks it.
- **Fixes from a fresh-install trial.**
  - Exact scope entries become hosts when the rules are saved (`hosts_added` in the
    response); wildcards stay rules. Recon says when there are no hosts and lets you add
    one in place.
  - Steps with nothing to work on end `skipped` with a reason instead of `done`, and
    Run all steps no longer queues steps that cannot apply (migration `0013`).
  - Running steps show elapsed time, targets finished and the latest log line; queued
    steps show their place in the queue.
  - The verifier prints SKIP, not PASS, when no receipt is signed or timestamped;
    `--require-signatures` fails unsigned reports.
  - A clear message for a non-HTTPS policy URL; report evidence labels and counted nouns
    read correctly; the sidebar host count stays current.
  - Lane panel: honest item counts, a refused close lists what is still unresolved as it
    changes, and open items can be marked not applicable in bulk with one reason.
  - The Ledger and the report use the same words: Not opened, In progress, Receipted, Void.
  - README: first steps, API docs, database password, requirements and status.
- **Security policy** at `/security`, `/.well-known/security.txt` (RFC 9116) and `SECURITY.md`:
  scope, testing rules, how to report to murat@attackledger.com, 90-day coordinated
  disclosure and safe harbor (no bounty).
- **Client-facing HTML report.** Cover, a summary for the client with what the report
  does and does not prove, scope and authorization, a hosts × lanes coverage matrix,
  per-lane receipts (hash, signer, key, timestamp, void state) and step-by-step
  verification with the pinned DigiCert root; prints cleanly to A4 PDF. The JSON report
  adds `engagement.pack.lanes`, `engagement.separation_of_duties` and
  `engagement.require_signatures` (additive; format unchanged).
- **Role-aware web app and a Verify tab.** Viewers get a read-only app, and each role
  sees only the actions the server accepts (tester works, reviewer signs, owner manages);
  one helper (`web/src/access.ts`) mirrors `authz.RULES`. The Verify tab checks each
  receipt's signature in the browser (WebCrypto Ed25519 or ECDSA P-256) by the verifier's
  rules, offers the report JSON, and points to `verify_report.py` for the full check.
- **RFC 3161 timestamps** (D-034). With `ATTACKLEDGER_TSA_URL` set, each receipt's
  manifest hash and signature are timestamped (only a hash is sent). If the authority
  cannot be reached the close still succeeds and can be timestamped later. The verifier
  checks the token, the authority's signature and its certificate chain to a root you
  trust (`tools/tsa-roots/` or `--tsa-root`). Docker Compose uses DigiCert's public
  service by default and its root is pinned; `ATTACKLEDGER_TSA_URL=off` turns it off.
  Migration `0012`.
- **Demo and sample report signed and timestamped.** `tools/demo_sign.py` has a demo
  reviewer sign every closed demo lane (a script stands in for the browser key) and
  DigiCert timestamps each receipt; the sample report verifies with all five checks and the
  site ships DigiCert's root for `--tsa-root`. The HTML report shows each receipt's key
  and timestamp.
- Times from the API and in reports now carry their UTC offset; the browser showed UTC
  times from Postgres as local time.
- `ATTACKLEDGER_COOKIE_SECURE` is now passed to the API by Docker Compose (it was
  documented but not forwarded).
- **A real Claude agent run in the demo.** With no API key yet, Claude Opus worked the
  Lab recon lane from Claude Code through `tools/agent_bridge.py`, which runs every call
  through the same gated tools inside the worker (D-031). 23 requests (22 reached the lab,
  all with the research header and user agent; peak 2/s), 10 items done, 2 N/A, 5 left open
  with reasons, 8 leads, no receipt. The demo shows the run, its log and the raw exchanges,
  and says how it was driven and that token use was not measured.
- **"Start here" guide in the demo:** five steps (recon steps, golden targets, the coverage
  ledger, a receipted lane, the report), each with a button that opens the right view.
- **Work a lane from the lane panel.** On a manually worked lane, each item now has Add
  evidence (a note, a file up to 5 MB, or a finished recon run), Mark done, Not applicable
  (with a reason) and Reopen. `POST /lanes/{id}/attach` hashes notes and files on the
  server and keeps the bytes in the blob store, so "View raw" opens them; a recon run
  contributes its output hash. Changing a receipted lane warns that the receipt goes void.
- **Read-only demo** (`site/demo/`): the real web app built with `VITE_DEMO=1`. Reads come
  from a snapshot exported by `tools/export_demo.py`, every change is refused with a
  message, and reports are static files. `tools/build_demo.sh` builds it from a demo stack
  with fictional data; the Lab recon data comes from a real pipeline run against the lab.
- **Recon screen reorganised into six steps** (D-026), like ars0n-framework-v2:
  a target bar with the rules, a funnel from host names to leads, numbered steps with
  "Run step" and "How this step works", one card per tool (tools used, last run,
  results, log), and results in tabs: golden targets, hosts, URLs, leads and runs. A
  card's Results button opens what that module found. New API: `GET /recon/phases`,
  `GET /engagements/{id}/recon/summary`, and a `module` filter on endpoints and leads.
  The pipeline order now matches the steps: content discovery runs before JavaScript
  analysis, and nuclei before the dork list.
- **Small runs by default, with a cost limit.** Defaults are 15 turns, 30 requests and an
  estimated $0.50; the run stops at whichever comes first (cost is checked after each
  turn, so a run can go over by at most one turn). The model sees at most 4,000
  characters of each response and 40,000 per run, because every tool result is sent
  again on each later turn; the full response is always kept as evidence. The first
  message carries at most 50 recon rows of each kind.
- **Interrupted jobs are recovered.** At startup the worker marks every job left
  `running` as failed with a reason; between jobs it does the same for any run past the
  time limit plus `WORKER_STALE_GRACE` (default 10 min). Results from finished batches
  and an agent's evidence are kept. One worker per database is assumed.
- Lab: `/go` redirects to an `.invalid` host, to check that tools never follow it.
- 44 tests for the agent layer, including the gates, a scripted end-to-end run and
  the API. Positive controls: removing the host check, the pacing, the reserved
  headers or the identification precedence each makes a test fail.

### Changed
- **Demo**:
  - "Client web app" shows the Import tab. It has a HAR and a Burp export made from the
    lab (out-of-scope and duplicate rows refused), WSTG mappings with suggestions, a
    dismissed entry with its reason, and redacted requests and responses.
  - "Client web app" has a retention date, shown on the History tab.
  - "Client portal 2025" shows deleted content and a report that still verifies.
  - Lanes are worked in parallel next to a receipted Information gathering lane.
- **The worker no longer touches the database** (D-042, docs/WORKER_API.md, migration
  0020). It has no database credentials, database network, master key, blob store or
  Anthropic key.
  - It claims jobs and writes through `/worker/*` API routes, relayed by the gateway, with
    a token scoped to one job.
  - What a job writes is limited by its kind. Scope, redaction, deduplication,
    encryption and the evidence chain are applied in the API.
  - The Claude API key is set on the gateway, which adds it to agent calls.
  - Retention and marking interrupted jobs run in the API.
  - `tools/agent_bridge.py`: a person queues the run with a `driver`, and the bridge
    claims it.
  - The benchmark through the gateway is unchanged.
- **Contributions need a CLA** (D-051). See `CLA.md` and `CONTRIBUTING.md`. A bot asks each
  new contributor to sign once.
- **Control mappings reviewed** (D-050, docs/CONTROLS.md). They were checked against PCI
  DSS v4.0.1, ISO/IEC 27001:2022 Annex A and DORA, with the TLPT RTS (EU) 2025/1190.
  - Each mapping states its evidence strength: partial or supporting; none is full. The
    Controls view and the audit report show the strength and say a qualified assessor has
    not reviewed the mappings.
  - Removed mappings that overstated: PCI 11.3.2 (ASV scan), PCI 6.4.1 (superseded by
    6.4.2) and DORA Article 26 (TLPT). A bug bounty is now only supporting evidence for
    PCI 11.4.3.
  - Added ISO A.8.8, A.8.3, A.5.17 and A.8.2, and DORA Articles 24, 25 and 9, where lanes
    produce the evidence.
- **Recon for single-page apps** (D-049). Juice Shop recall went from 5 to 15 of 32
  in-reach items through the gateway, with 0 writes and a peak of 20 at a limit of 20.
  - A new step, Read well-known files, records robots.txt, security.txt and directory
    listings.
  - Content discovery filters a catch-all page by its fingerprint instead of skipping the
    host.
  - JavaScript analysis records single-page app routes and relative links.
  - Triage counts an API surface (+2).
  - Static files under paths such as uploads or backup, plus archives and sourcemaps, are
    kept as endpoints and never fetched.
- **Agents get a ranked lane context** and a reading view of responses: text and links
  for HTML, routes and endpoints for large JS files. `view: "raw"` gives the body as
  received.
- **The repository is public** (D-048) at https://github.com/attackledger/attackledger,
  after a full-history scan. Secret scanning with push protection, private vulnerability
  reporting and CodeQL are on.

### Changed (design-partner review, 2026-10-09)
- **Lanes are worked in parallel** (D-047): a lane opens at once, and it can be signed only
  after the lanes it needs are receipted (pack `needs_gate`; the bug bounty pack keeps
  gating the opening).
- **Mapping** can open a lane and, optionally, mark the items done ("Mark these items
  done", off by default). Lanes count items with evidence that wait to be marked done.
- **Import privacy**: the import audit entry holds counts only, never refused host names
  or the file name.
- **Re-importing** the same file needs an explicit choice.
- **API docs** (`/docs`, `/openapi.json`) need sign-in whenever the API does; `/redoc` is
  removed.
- **Add a host** says why a host was stored out of scope.
- **Verifier downloads**: the verifier script and TSA roots download from the API. The
  report's "How to verify" points to attackledger.com first. Reviewers see the host's
  inbox counts when signing.
- **Docs**: a tester guide (`docs/TESTER_GUIDE.md`). INSTALL now covers per-OS trust
  steps for Caddy's internal CA, a plain-HTTP trial over an SSH tunnel, keeping the CA
  through a restore, and practising against the lab with `--profile lab` (new
  `lab-proxy`, for capturing a browser HAR).

- **Web**:
  - A change to an item on a receipted lane asks first, and says the client will see the
    receipt as void.
  - An engagement whose content was deleted offers no lane or item changes and says why,
    and the API refuses them (409).
  - Setup: recon or an import completes the evidence step, and there is a Team step.
  - Pentest and internal engagements use client, statement of work and rules of
    engagement wording, and the methodology defaults by type.
  - Before a browser's first signature, the reviewer is told a new key will be
    registered.
  - People whose password someone else set are asked to choose their own at sign-in; they
    can skip.
  - Report and Verify point to attackledger.com/verify first, then to this server's
    verifier with its SHA-256.
  - The tab bar is sticky, the lane panel draws above the ledger, and the Controls table
    fits on phones.

### Fixed
- **Web**: a dismissal reason no longer shows a double full stop, and an out-of-scope host
  no longer widens the ledger page at 390 px.
- **The release gate refused every git worktree**: a worktree's `.git` is a file holding an
  absolute path, which the personal-path check matched. It is now skipped like the `.git`
  directory; nothing committed is skipped.
- **Sign-in right after Sign out was lost**: signing out reloaded the page, so input typed
  at once was dropped. It now switches to the sign-in form in place.
- **Content-Length after redaction**: a stored message whose body was redacted kept its
  original Content-Length.
- **Evidence imports over 1 MB were refused** by the web container's nginx (default body
  limit). It is now 60 MB in nginx and Caddy.
- **nuclei could send writes and burst over the limit** (measured by the Juice Shop
  benchmark: 24 POST, 1 DELETE, 1 DEBUG; 40 requests in one second at a limit of 20).
  nuclei now runs only templates that provably send GET, HEAD or OPTIONS requests
  (`nucleisafe.py`, 6,551 of 13,786 excluded; the worker refuses to scan otherwise), takes
  one token per tick with no retries, and needs a limit of at least 2/s. Re-run: 0
  non-GET of 5,511 requests, nuclei peak 19 at 20.
- **Content discovery went over low rate limits.** feroxbuster's wildcard detection and
  its two start requests are not rate-limited: at a limit of 2/s the first second carried
  9 requests. It now runs with `--dont-filter` (the baseline check does that job) at the
  limit minus 2, and needs a limit of at least 3/s (a new `min_rps` gate in the registry,
  shown in the UI). Measured on the lab: peak 3/s at a limit of 3, 18/s at 20. The 0.5.0
  note "peak of exactly the 20/s limit" was true only at that limit.

### Verified on the lab
- Real transport: 5 of 5 requests carried the research header and user agent; a 302
  came back with its Location and was not followed; 2 rps gave 0.51 s spacing.
- End to end through the worker on Postgres: evidence chained and verified offline
  by `tools/verify_report.py`; a request to `example.com` was refused and never sent;
  the lane stayed unreceipted.

## [0.5.0] - 2026-10-09

Recon completed: every module of the original pipeline that can run safely, plus
the pipeline runner, scope import and API authentication.

### Added
- **Run pipeline.** One action queues every step that passes its gates, in registry
  order, and reports the skipped ones with their reasons. Each step resolves its
  targets when it starts, from what the earlier steps produced (deferred jobs,
  migration `0008`). Default target selection moved to `targets.py`, shared by the
  API and the worker.
- `docs/ROADMAP.md`.

- **M7 nuclei module (opt-in)**, pinned to nuclei v3.11.1 and nuclei-templates v10.4.9.
  It mirrors the original pipeline: takeover checks on every live service; exposures,
  misconfigurations and stack-tagged templates on one representative per cluster; and
  exposed panels, vulnerabilities and CVEs on golden hosts, all at medium severity and
  up. It never runs dos, fuzz, intrusive, brute-force, default-login,
  credential-stuffing or token-spray templates.
- **Templates excluded by content** at image build (834 of them): raw/unsafe requests,
  hard-coded out-of-band hosts and digest authentication. Measured against a raw
  socket logger, the full scan sent 8,899 of 8,899 requests with the research
  identification. Without the exclusions, 3 template classes dropped it or called
  third parties. nuclei runs with `-ni -dr` and refuses to run if the exclusion list
  is missing.
- Pinned, SHA-256-verified downloads for feroxbuster v2.13.1, nuclei-templates and
  the SecLists `common.txt` wordlist. Arjun 2.2.7 is installed in the worker for
  upcoming modules.

- **M3 content discovery (opt-in).** feroxbuster runs on golden hosts, up to 10 per
  run, one URL and one scan at a time, with the common.txt wordlist. Hosts that answer
  every path the same way are skipped after a baseline check, which carries the
  research identification. It never follows redirects or extracted links and never
  requests logout or delete paths. Measured: 9,504 requests, all identified, with
  a peak of exactly the 20/s limit.

- **M5 parameter discovery (opt-in).** Arjun 2.2.7 runs on dynamic endpoints (query
  strings, script extensions, API paths), up to 20 per run, highest-scoring hosts
  first. Each endpoint's accepted parameters are recorded as a lead. It runs isolated
  from the worker's own dependencies, with one thread and a fixed delay.
  Measured: 1,332 requests, all identified, with a peak of exactly the 10/s limit. With
  several threads, `--rate-limit` alone reached 17/s.

- **M6 parameter routing** (computed, no traffic). Parameters from URLs and Arjun are
  sorted into gf-style classes (ssrf, redirect, idor, sqli, lfi, xss, rce), and each
  becomes a lead that names the hunt lane testing it.
- **M10 dork checklist** (computed, no traffic). For each wildcard root it writes the
  original dork.sh queries as click-ready manual checks.

- **HackerOne scope CSV import**, with a preview before apply. Assets not eligible
  for submission become **exclusions**, so a wildcard cannot cover them; the original
  csv_to_scope.py skipped them. Non-web assets (apps, CIDRs) are listed, not imported.

- **API authentication.** Set `ATTACKLEDGER_API_TOKEN` to require a token on every
  route except `/health` and login. The token works as a bearer header or as an
  HttpOnly, SameSite=Strict session cookie that holds an HMAC of the token, never the
  token itself, and is compared in constant time. The UI shows a sign-in screen when
  needed. `/health` reports whether auth is on.
- ESLint with `react-hooks/rules-of-hooks` in CI.

### Fixed
- The Recon view crashed after the Run pipeline button was added: a hook was declared
  after an early return. The new lint rule catches this class of bug.
- Names that answer NOERROR with no records were counted as resolved, and subdomain
  discovery could add them as assets. Only an A or AAAA record now counts.

## [0.4.1] - 2026-10-08

### Changed
- **Only a person issues receipts (D-018).** Closing a lane requires the signer's
  name and a review confirmation. The signer is stored on the receipt (migration
  `0007`), shown in the lane and in the report, and the verifier notes unsigned
  receipts.

### Fixed
- JavaScript analysis no longer drops files beyond 250 silently. The registry's
  `max_targets` caps a run, the overflow is listed as remaining, and the run is
  `partial` and resumable. Files from the highest-scoring hosts go first.
- An all-whitespace signer name is rejected.

## [0.4.0] - 2026-10-08

Architecture release: the shape every later module and the hunt agents plug into.

### Added
- **Module registry** (`modules.py`): each recon job kind is defined once, with its
  input type, traffic class, HTTP flag, opt-in flag and outputs. API gates, worker
  dispatch and UI steps are derived from it (`GET /modules`), and the worker refuses
  to start if its runners and the registry disagree.
- **Shared job gates** (`jobgates.py`), applied when a job is queued and again when
  it runs.
- **Opt-in modules per engagement** (`enabled_modules`, migration `0005`). This
  replaces `allow_port_scan`, and existing settings carry over.
- **Hunt executors** (`executors.py`, migration `0006`). A lane has an executor,
  manual or agent; the agent arrives in v0.4.x/v0.5. `GET /lanes/{id}/context` returns
  what an executor may read, limited to the lane's host.
- `docs/ARCHITECTURE.md`: layers, contracts and invariants.

### Changed
- Research identification is required for modules that send **HTTP**. Port
  scanning is target traffic but carries no headers; it is gated by opt-in instead.

## [0.3.2] - 2026-10-08

### Fixed
- **A run stopped at the time limit no longer shows as `done`.** It is now
  `partial`, and the remaining targets are listed exactly. Targets run in batches
  (`WORKER_CHUNK_SIZE`, default 20), and a batch counts only once it finished.
- The time limit is enforced by a watchdog, so a tool that prints nothing (such as a
  slow port scan) is still stopped on time.
- **Run remaining** starts a new run for the targets a partial or cancelled run did
  not reach, and every gate is checked again. Cancelling a queued run keeps all of
  its targets resumable.
- Migration `0004` adds the `partial` status, `targets_done` and `remaining_targets`.

## [0.3.1] - 2026-10-08

### Security
- **Port scanning now honours the engagement rate limit.** naabu ran at ten times
  the requests-per-second value, carried over from the original pipeline. The
  value is now a hard ceiling for every step that sends traffic, a test checks this
  for every tool, and the shipped `recon/run_pipeline.sh` was corrected the same way.

### Added
- **JavaScript analysis (module 8)**, ported from the original `js_analyze.py` and
  `secret_triage.py`. It covers endpoints (LinkFinder regex, own host only), GraphQL
  operations, sourcemaps (fetched only when in scope) and secret candidates in REAL,
  PUBLIC and NOISE buckets, with REAL checked first. Secrets are stored masked and
  hashed and are never tested.
- **Leads.** A new `leads` table (migration `0003`), an API endpoint and a UI panel.
  Hosts in Golden targets show their lead count.

### Fixed
- JS fetch failures were swallowed. They are now logged with their reason, and a
  run that fetches nothing fails.
- Protocol-relative URLs in JS could resolve to another host.
- `recon/secret_triage.py` referenced a bucket name left over from translation.

## [0.3.0] - 2026-10-08

### Added
- **Recon pipeline modelled on the author's own process.**
  - Multi-source subdomain discovery (subfinder `-all`, assetfinder, crt.sh), filtered
    to scope before resolution.
  - Port scanning (naabu top 100, connect scan). Off by default, enabled per engagement.
  - Richer probing per open port, with CDN and CNAME data.
  - **Golden-target scoring**, ported from the original pipeline.
  - Crawling of golden hosts with katana. It stays on the same host and never
    follows logout, delete or revoke paths.
  - Archived URLs from gau and waybackurls.
  - Endpoint store with uro-style clean-up and JavaScript flagging.
- UI: a six-step pipeline with traffic labels, a Golden targets table, and an
  Endpoints browser with search and a JS-only filter.
- Migration `0002`: the endpoints table plus `allow_port_scan` and `crawl_depth`.

### Changed
- DNS resolution runs in two passes (A/AAAA, then CNAME). Some resolvers made dnsx
  drop hosts without a CNAME when all three were requested together.
- A pre-migration database is stamped at head, and only when its schema matches
  the models.

### Fixed
- A job whose tool fails without producing anything is now `failed` instead of `done`.

## [0.2.0] - 2026-10-08

### Added
- **Database migrations (Alembic).** The API migrates at startup and the worker
  waits for the latest revision. Databases created before migrations are stamped
  only when their schema matches the models; otherwise startup is refused.
- Tests cover a fresh migrate, downgrade followed by upgrade, stamping a
  pre-migration database, refusing one that has drifted, and drift between the
  models and the migrations.
- `docs/DECISIONS.md`: a decision record of who proposed and who decided each
  product choice.

### Fixed
- The downgrade now removes the Postgres enum types, so downgrading and then
  upgrading works.

## [0.1.0] - 2026-10-08

First tracked release.

### Added
- **Evidence ledger.** Engagements, assets and lanes (host × methodology lane) with
  checklist items. Evidence is append-only and hash-chained per engagement.
- **Fail-closed gates.** An item is done only with evidence, and N/A needs a reason.
  A lane closes with a receipt (manifest hash), and any later change voids the receipt.
  A lane opens only when the lanes it depends on are receipted.
- **Methodology packs.** `bug-bounty` (7 lanes) and `web-pentest-wstg` (97 OWASP WSTG
  tests), with indicative mapping to PCI DSS v4.0, ISO/IEC 27001:2022 and DORA controls.
- **Recon engine.** A worker runs subfinder, dnsx and httpx. Jobs are refused without
  a scope, a recorded authorization and, for target traffic, the research header or
  user agent. Scope is re-checked on every target and every result.
- **Audit report.** JSON and printable HTML. `tools/verify_report.py` verifies it
  offline (body hash, evidence chain, receipts).
- **Web UI.** Recon, Ledger, Controls and Report views, with dark mode.
- **Release gate.** `tools/release_gate.sh` blocks publishing private target names,
  open-finding fingerprints, personal paths and secrets.

### Known limitations
- Reports are not signed. Verification proves internal consistency, not authorship.
- No authentication on the API. Bind to localhost only (the default).
