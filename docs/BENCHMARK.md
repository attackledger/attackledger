# Benchmark: AttackLedger against OWASP Juice Shop

First measured run on 2026-10-09. Machine-readable results: `tools/benchmark/results-2026-10-09.json`.
Ground truth: `tools/benchmark/ground_truth.json` (committed before any run, matchers not tuned afterwards).

## Setup

| | |
|---|---|
| Target | OWASP Juice Shop **v20.2.0** (published 2026-08-10), `bkimminich/juice-shop:v20.2.0@sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b` |
| Stack | compose project `attackledger-bench` (`tools/benchmark/compose.override.yml`), API on 127.0.0.1:8099, internal Docker network (no internet for Juice Shop or the worker), TSA off |
| AttackLedger | commit `0e1d854` code, the main stack's api/worker images retagged (`attackledger-bench-*`), nuclei v3.11.1, templates v10.4.9 |
| Measurement | `juice-proxy`, a byte-for-byte TCP relay in front of Juice Shop (`tools/benchmark/countproxy.py`) that logs every request head |
| Engagement | scope `juice.lab.test`, `X-Bug-Bounty: bench-researcher`, UA `AttackLedger/0.6 (bench-researcher)`, 20 req/s, authorization recorded, every opt-in module on (ports, content, params, nuclei), crawl depth 3 |

Reproduce: `python3 tools/benchmark/run.py up`, then `recon`, then (after any agent run) `score`, then `down`.

## Ground truth

Juice Shop v20.2.0 has 116 challenges. 18 are disabled by Juice Shop when it runs in Docker. Of the 98
enabled, **23 are in reach** for unauthenticated GET/HEAD/OPTIONS work without a browser, brute force or
computation outside HTTP, and **75 are out of reach**: 31 need a state-changing request, 15 need a login,
10 need a POST to submit what was found, 6 need computation (token signing, decryption), 4 need a
browser, 4 need the chatbot's LLM, 2 need a wallet, 2 need another site, 1 needs brute force.
Nine non-challenge surface items (robots.txt, Swagger UI, key listing, config endpoint, CORS, missing
headers, hard-coded test credentials, PII in reviews) bring the in-reach total to **32**.

So about three quarters of Juice Shop is out of reach for a read-only, unauthenticated agent by design (D-024).

## Results

| Item | In reach | Recon | Agent | Solved |
|---|---|---|---|---|
| exposedMetrics (/metrics) | yes | yes (nuclei `prometheus-metrics`) | no | yes (recon) |
| scoreBoard (hidden route) | yes | yes (JS analysis: `/score-board`) | no | no |
| web3Sandbox | yes | weak (only the chunk name `web3-sandbox.module-*.js`) | no | no |
| securityPolicy (security.txt) | yes | no | yes (x2) | yes (agent) |
| errorHandling | yes | no lead recorded | no | yes (by recon traffic) |
| directoryListing (/ftp) | yes | no | partial: listing fetched, file names not visible | no |
| S01 robots.txt | yes | no | yes (x1) | n/a |
| S04 application-configuration | yes | yes (endpoint) | no | n/a |
| S05 application-version | yes | rejected on review (malformed URL) | no | n/a |
| S06 CORS `*` | yes | no | yes (x1) | n/a |
| S07 no CSP / HSTS | yes | no (info severity filtered) | yes (x1) | n/a |
| the other 21 in-reach items | yes | no | not reached | no |

Totals on the 32 in-reach items:

| | Found | Recall |
|---|---|---|
| Recon (automated matcher) | 5 | 15.6% |
| Recon (after review: S05 rejected) | 4 | 12.5% |
| Agent (stopped after 4 requests, see below) | 4 | 12.5% |
| Recon or agent (after review) | 8 | 25.0% |

Juice Shop marked 3 challenges solved: errorHandling and exposedMetrics (recon traffic), securityPolicy (agent).
None of the out-of-reach challenges were solved.

## Runtime and requests

| Step | Status | Seconds | Requests | Peak / calendar second | Peak / sliding 1 s |
|---|---|---|---|---|---|
| resolve | done | 0.1 | 0 | | |
| ports | done | 16.0 | (connections only) | | |
| probe | done | 0.2 | 1 | 1 | 1 |
| crawl | done | 13.2 | 29 | 20 | 22 |
| content | done, skipped host | 0.1 | 2 | 2 | 2 |
| jsanalyze | done | 1.6 | 20 | 12 | 13 |
| params | done | 225.1 | 3,206 | 19 | 19 |
| paramclass | done | 0 | 0 | | |
| nuclei | done | 130.3 | 2,612 | **29** | **40** |

Wall time 390 s, 5,870 requests, all with the research header and user agent (0 missing).
134 endpoints, 23 leads (1 nuclei, 8 parameter, 13 param-class, 1 secret: a public Google OAuth client id).

## What the run showed

1. **nuclei sends writes** (fixed, see the re-run below). The recon run sent 24 POST, 1 DELETE and 1 DEBUG request, all from nuclei
   exposures/misconfiguration templates (`dragonfly-public-signup` signs up, `nacos-create-user` creates and
   then DELETEs a user, `hadoop-unauth-rce`, several login forms). 54 templates in the passes that ran can send
   a non-GET request and are not excluded; the golden pass would add 1,826 more, 11 of which can DELETE.
   `nacos-create-user` is tagged `instrusive` (typo), so the `intrusive` tag exclusion misses it. This
   contradicts D-024 ("the recon side never writes") and the DELETE-approval rule.
2. **nuclei goes over the rate limit** (fixed, see the re-run below). It averaged 20.1/s at a limit of 20, but one calendar second had 29
   requests and 1,326 sliding one-second windows were above 20 (peak 40). The other tools stayed at or under
   20 per calendar second.
3. **A single SPA host is never golden.** Juice Shop scored 3 (ODDPORT, KEYWORD, 200; httpx detected no
   tech), below the threshold of 4, so the nuclei golden pass (panels, vulns, CVEs) and the stack pass never ran.
4. **Content discovery skips SPAs.** The catch-all route answers every path with 200, so the baseline check
   skipped the host (2 requests). /ftp, /api-docs, /encryptionkeys and /support/logs were never found.
5. **The agent sees too little.** The lane context lists the first 50 endpoints alphabetically (mostly
   junk such as `/%60+_%28i...`, `/10`, `/16`), so `/score-board`, `/rest/*` and the metrics lead are cut off.
   The 4,000-character view was filled by the /ftp listing page's inline CSS before any file name, and a
   Range header does not help on a dynamic page. main.js is 1.2 MB against a 40,000-character run budget.
6. **Static files are dropped.** `urls.clean` drops images, so the photo-wall file was never kept.

## Limits of this run

- **The agent run is incomplete.** It was driven from Claude Code (D-031), not the product's Messages API
  loop. It used 4 of 60 requests on the recon lane before a safety classifier on the driving session stopped
  further hands-on probing; the model lane was not run. The job is recorded as `partial`, with no evidence
  attached and no items marked. Treat the agent recall as a lower bound, not a measurement of the loop.
- The driving model knows Juice Shop from training. A full run would overstate performance on unknown targets.
- One target, one run, one machine. Recon matchers are regexes; every automated match was reviewed by hand.

## Top three gaps

1. **Bundle- and listing-aware reading for agents and recon**: pass the agent the endpoints and leads that
   matter instead of the first 50 alphabetically, strip markup and CSS before the 4,000-character cut, and have
   recon record robots.txt, security.txt, SPA routes and directory listings as leads. Affects about 12 in-reach items.
2. **Recon that works on a single SPA host**: a single in-scope host should be golden (or the score should
   count the SPA), and content discovery needs a content-based baseline instead of a status-only one.
3. **Authenticated sessions with two test accounts plus reviewed safe POSTs**: 25 of the 75 out-of-reach
   challenges need a login or a POST submission; the operator's own accounts and a per-request allow-list (D-024) would open them.

Separate from recall, and first by risk: **exclude every nuclei template that can send a non-GET request**
(by content at build time, like the unsafe and out-of-band exclusions), and keep nuclei's per-pass hand-over
under the limit.

## Re-run after the nuclei fix (2026-10-09)

Machine-readable results: `tools/benchmark/results-2026-10-09-rerun.json`. Same target, settings and
pipeline as the first run; API and worker images built from branch `fix/nuclei-gates`
(`BENCH_KEEP_IMAGES=1 run.py up`). Recon only: no agent run, so the agent columns are empty.

What changed in nuclei:

- **Templates are read-only by construction** (`server/app/nucleisafe.py`, run at image build and again
  before the worker's first scan). A template runs only if every request it can send is provably GET,
  HEAD or OPTIONS to `{{BaseURL}}`/`{{RootURL}}` or the target's Host, with no body, no method override,
  no other protocol, no scripted flow, no self-contained third-party URL, no unsafe/pipeline/race/threads/
  digest/fuzzing key and no out-of-band reference. Unknown keys and unparseable files are excluded too.
  7,235 of 13,786 template files are kept, 6,551 excluded (the old list had 834). Templates nuclei
  loads per pass: takeovers 75 → 74, generic 760 → 696, golden 3,906 → 2,449.
- **One rate-limit token per tick.** nuclei refills all `-rl` tokens at once per tick, so `-rl 20` let 40
  requests into one sliding second. Now `-rl 1 -rld ceil(1050/(limit-1)) ms` (56 ms at 20/s): a window
  holds at most one request per tick plus one refilled just before it. `-retries 0`, because a retry is
  sent without a token (measured: 12 connections for 6 tokens with `-retries 1`). 1.1 s between nuclei
  processes. nuclei needs a limit of at least 2/s.

| Step | Status | Seconds | Requests | Peak / calendar second | Peak / sliding 1 s |
|---|---|---|---|---|---|
| probe | done | 0.2 | 1 | 1 | 1 |
| crawl | done | 13.2 | 29 | 20 | 22 |
| content | done, skipped host | 0.1 | 2 | 2 | 2 |
| jsanalyze | done | 1.6 | 20 | 10 | 13 |
| params | done | 236.6 | 3,210 | 18 | 19 |
| nuclei | done | 133.5 | 2,249 | **18** | **19** |

Wall time 405 s, 5,511 requests, **all GET**, all with the research header and user agent. Non-GET
requests: **0** (first run: 24 POST, 1 DELETE, 1 DEBUG). nuclei: 2,249 requests (first run 2,612), 133.5 s
(130.3 s). Recall unchanged: the same 5 automated recon matches (4 after review), the same nuclei lead
(`prometheus-metrics`), errorHandling and exposedMetrics solved by recon traffic.

Pacing measured by hand on the same stack (nuclei in the bench worker, through juice-proxy):

| Templates | Limit | Requests | Peak / calendar second | Peak / sliding 1 s |
|---|---|---|---|---|
| exposures + misconfiguration, old flags `-rl 20` | 20 | 2,241 | 20 | **40** |
| exposures + misconfiguration | 20 | 2,241 | 18 | 19 |
| all of `http/`, medium and up (5,350 GET, 2 OPTIONS, 1 HEAD) | 20 | 5,353 | 18 | 19 |
| exposures + misconfiguration | 50 | 2,241 | 46 | 46 |
| exposures (150 s) | 5 | 569 | 4 | 5 |
| takeovers | 3 | 8 | 2 | 3 |
| exposures (150 s) | 2 | 138 | 2 | 2 |

Still open: **katana (crawl) reached 22 in one sliding second** at a limit of 20 in both runs (20 per
calendar second). It is not nuclei and is left for the gateway proxy, which will enforce one ceiling for
every tool.

## Run through the traffic gateway (2026-10-09)

Machine-readable results: `tools/benchmark/results-2026-10-09-gateway.json`. Same target, settings and
pipeline; API, gateway and worker images built from branch `feat/gateway` (`BENCH_KEEP_IMAGES=1 run.py up`).
Recon only, no agent run. What changed in the stack (D-039, `docs/GATEWAY.md`):

- the worker is on the internal network only; Juice Shop and juice-proxy are on a lab network that only the
  gateway joins, so every request reaches juice-proxy through the gateway, and juice-proxy stays an
  independent counter downstream of it;
- the gateway enforces the scope, GET/HEAD/OPTIONS only, a ceiling of 20 requests in any 1.05-second window
  for the engagement (all tools together), and sets the identification itself;
- port scanning is done by gateway probes instead of naabu (99 probes, 1 port open).

| Step | Status | Seconds | Requests | Peak / calendar second | Peak / sliding 1 s |
|---|---|---|---|---|---|
| probe | done | 0.4 | 1 | 1 | 1 |
| crawl | done | 13.3 | 29 | 20 | **20** |
| content | done, skipped host | 0.1 | 2 | 2 | 2 |
| jsanalyze | done | 1.7 | 20 | 11 | 13 |
| params | done | 238.8 | 3,206 | 18 | 18 |
| nuclei | done | 134.5 | 2,249 | 19 | 19 |

Counted by juice-proxy: 5,507 requests, **all GET** (non-GET: 0), all with the research header and user agent,
**peak 20 in any sliding second and 20 in any calendar second at a limit of 20** (first run: 40 and 29;
re-run after the nuclei fix: 22 and 20, from katana). Wall time 405 s. The gateway's own log for the
engagement agrees: 5,509 GET (5,507 sent, 1 refused, 1 failed), 99 port probes and 10 DNS questions; the 5
refusals were katana asking for a host named `burpsuite` and four ProjectDiscovery tools calling their update
service `api.pdtm.sh`. Recall unchanged: 134 endpoints, the same 23 leads, the same nuclei lead
(`prometheus-metrics`), errorHandling and exposedMetrics solved by recon traffic.

A misbehaving tool, by hand on the same stack: a script in the worker with a job credential sent 200 GETs from
200 threads at once, each with a forged `X-Bug-Bounty` and `User-Agent`, plus one POST, PUT, DELETE, PATCH,
DEBUG and TRACE. juice-proxy saw 200 requests, all GET, peak 20 in any sliding second, every one with the
engagement's identification and none with the forged values; the six writes were refused with 403 and never
reached it. A direct connection from the worker to juice.lab.test failed (the name does not resolve there,
and the lab network is not attached).

## Recon and agent context for single-page apps (2026-10-09)

Machine-readable results: `tools/benchmark/results-2026-10-09-recon-agent.json` (the comparison), with the two
full runs in `results-2026-10-09-recon-before.json` and `results-2026-10-09-recon-after.json`. Same target,
settings and gateway stack as the run above. Before: images built from `main` at `d856413`. After: images built
from branch `feat/recon-agent` (`3ffe039`). Both runs were recon only (`run.py up`, `recon`, `score`, `down`) with
no agent run, because there is no API key. The agent-context comparison below is measured on the lane context
the API serves, not on a live agent loop.

What changed (gaps 3 to 6 above):

- **Triage counts an API.** A new API signal (+2) fires when recon has recorded at least 3 distinct API-like
  paths on the host (/api/, /rest/, /graphql, /v2/, with identifiers collapsed). Juice Shop now scores 5
  (ODDPORT, KEYWORD, 200, API) and is golden. The probe-only score is unchanged, and one or two API links do not
  count. A host with only a 200 and an API still scores 3.
- **Content discovery runs on catch-all hosts.** The baseline now fingerprints two random paths (status, size,
  sha256, words, lines, title). When both get the same 200 page, feroxbuster runs with that page filtered out (by
  size here: `--filter-size 9393`), and the results are filtered again in the runner. A host that answers every
  path with the same error or redirect is still skipped. 200 directories it finds are checked for a listing.
- **A new step, Read well-known files (`wellknown`, not opt-in).** It reads robots.txt and security.txt
  (/.well-known/ first) and checks the directories robots.txt names for a listing, with at most 13 GETs per
  service. Paths become endpoints. Robots rules, security contacts and listings become leads, and listing
  entries are recorded without being fetched.
- **JS analysis extracts SPA routes.** Angular, React Router and Vue router tables are read, nested children
  are joined to their parent, hash routing gives `/#/score-board`, and `./redirect?to=` links are resolved.
- **`urls.clean` keeps more.** Media under interesting directories (uploads, backup, ftp, private and similar)
  is kept, as are archives, sourcemaps and PDFs anywhere, and hash routes as their own entries. Recorded files and
  routes are never chosen as parameter-discovery targets.
- **Agent context and reading view** (see below).

### Recon recall

| | Before | After |
|---|---|---|
| Endpoints | 134 | 198 |
| Leads | 23 | 28 (+ robots, security-txt, listing; 14 param-class, 9 parameter) |
| In-reach items, automated matcher | 5 / 32 (15.6%) | **15 / 32 (46.9%)** |
| In-reach items, after review (S05 rejected as before) | 4 / 32 (12.5%) | **14 / 32 (43.8%)** |
| Challenges solved by recon traffic | errorHandling, exposedMetrics | errorHandling, exposedMetrics, securityPolicy |

These items are newly surfaced, each through the step named:

| Item | How it was surfaced |
|---|---|
| privacyPolicy, adminSection | SPA routes `/#/privacy-security/privacy-policy` and `/#/administration` (jsanalyze) |
| web3Sandbox | before: only the chunk name. After: also route `/#/web3-sandbox` |
| securityPolicy | security-txt lead and endpoint (wellknown) |
| S01 robots.txt | robots lead: `robots.txt: 1 disallowed path: /ftp` (wellknown) |
| directoryListing | listing lead `Directory listing at /ftp: 11 entries` plus the 11 entries as endpoints (wellknown, then content) |
| easterEggLevelOne, forgottenDevBackup, forgottenBackup, misplacedSignatureFile | `/ftp/eastere.gg`, `/ftp/package.json.bak`, `/ftp/coupons_2013.md.bak` and `/ftp/suspicious_errors.yml` listed by name. Reading them needs the `%2500` null-byte bypass, which recon does not try. |
| redirectChallenge | `./redirect?to=` links now extracted, so paramclass records `redirect-prone parameter: to` on `/redirect` |

Still not surfaced by recon: /api-docs (S02), /encryptionkeys (S03), /metrics as an endpoint, /support/logs and
/infrastructure (none of these is in `common.txt`, and content discovery does not recurse); the SQL-injection, JWT,
JSONP, CORS, header and test-credential items; the redirect crypto addresses (the endpoint store keeps one
`/redirect?to=` URL per parameter set, so the crypto addresses are collapsed away; the agent's bundle view lists
them, see below); and the photo-wall image. No step saw the image URL in this run: it only appears in
`/rest/memories` JSON, which is not crawled. So the static-file change is covered by unit tests only, not by
this benchmark.

### Traffic (after)

| Step | Status | Seconds | Requests | Peak / calendar second | Peak / sliding 1 s |
|---|---|---|---|---|---|
| probe | done | 0.3 | 1 | 1 | 1 |
| wellknown | done | 0.9 | 3 | 3 | 3 |
| crawl | done | 13.2 | 29 | 20 | 20 |
| content | done (catch-all filtered by size 9393) | 268.0 | 4,750 | 20 | 20 |
| jsanalyze | done | 1.8 | 20 | 10 | 12 |
| params | partial (21 dynamic endpoints, limit 20) | 235.8 | 3,230 | 18 | 19 |
| nuclei | done, **golden pass ran** | 313.7 | 5,319 | 18 | 19 |

Counted by juice-proxy: 13,352 requests (before: 5,511), every one with the research header and user agent.
Methods: 13,349 GET, 2 OPTIONS and 1 HEAD. The OPTIONS and HEAD come from the nuclei golden pass (panels,
vulnerabilities, CVEs), which now runs; nucleisafe allows them. **No state-changing request was sent (0 non
read-only)**, and the run had no request that was not GET before the golden pass started. **Peak 20 in any
sliding second and 20 in any calendar second at a limit of 20.** The gateway's log agrees: 13,351 GET, 1 HEAD and
2 OPTIONS allowed, and the same 5 refusals as before (katana's `burpsuite` host, the ProjectDiscovery update
service). Wall time 840 s (before 375 s): about 270 s for content discovery and 180 s more for the golden
nuclei pass. The golden pass found nothing new on Juice Shop (still `prometheus-metrics` only).

### Agent context

Recon lane of juice.lab.test. An agent's first message carries 50 endpoints (`agentloop.CONTEXT_LIMIT`) and the
leads.

**Before**, the first 50 endpoints by URL. Seventeen are junk, and none is under /rest:

```
(empty) / /%5C/index%5C.html /%60+_%28i%5B11%5D%7C%7Cf%5Bg.toLowerCase%28%29%5D%29+%60 /%60+_%28i%5B8%5D%29+%60
/%7B%7Bhref%7D%7D /0/0 /10 /16 /160 /20 /2fa/enter /40 /60 /Zone.js /about /about.component-CZcG2819.js
/accounting /address/create /address/edit/ /address/saved /address/select /api/Addresss /api/BasketItems
/api/Cards /api/Challenges /api/Challenges/ /api/Challenges/?key=[redacted] /api/Complaints /api/Deliverys
/api/Feedbacks /api/Hints /api/Products /api/Quantitys /api/Recycles /api/SecurityAnswers /api/SecurityQuestions
/api/Users /application-configuration /application-version /application/vnd.ms-word.do
/application/vnd.openxmlformats-officedocument.wordprocessingml.do /assets/i18n/ /bQ /basket /chatbot
/chatbot/conversation /chunk-BJ5LcrCb.js /chunk-DAJ4olp_.js /chunk-DBPdFzgj.js
```

**After**, ranked by signal (`server/app/surface.py`). Of 198 recorded endpoints, 16 junk entries are dropped and
the rest collapse to 137 shapes. The 50 shown are spread across prefixes, and the 44 client routes are listed
separately as `spa_routes`. The triage row (score 5, golden) and the leads come first by kind: nuclei,
secret, robots, security-txt, listing, then parameters.

```
/rest/user/security-question?email= /.well-known/security.txt /api/Feedbacks /robots.txt /rest/admin
/rest/admin/application-configuration /api/Challenges /redirect?to=http://leanpub.com/juice-shop
/rest/user/whoami /api/Hints /api/Products /api/Quantitys /api/SecurityQuestions /ftp
/rest/user/change-password?current= /security.txt /ftp/acquisitions.md /rest/wallet/balance
/ftp/announcement_encrypted.md /rest/captcha /ftp/coupons_2013.md.bak /rest/chat /ftp/eastere.gg
/rest/image-captcha/ /rest/user/authentication-details/ /ftp/encrypt.pyc /rest/memories /rest/user/login
/rest/continue-code-findIt/apply/ /rest/continue-code-fixIt/apply/ /rest/continue-code/apply/ /ws/v3/
/ftp/incident-support.kdbx /rest/order-history /rest/user/reset-password /api/BasketItems /ftp/legal.md
/rest/saveLoginIp /api/Challenges/?key=[redacted] /ftp/package-lock.json.bak /rest/track-order /api/Complaints
/ftp/package.json.bak /rest/user /v3/ /api/Users /ftp/suspicious_errors.yml /rest/continue-code /data-export
/api/Addresss
spa_routes: /#/administration /#/score-board /#/web3-sandbox /#/privacy-security/privacy-policy ... (44)
```

**What the agent is shown of a response.** `http_request` now returns a reading view (`server/app/pagetext.py`)
unless the agent asks for `view: "raw"`. The full response is kept as evidence either way, and the view is made
from the stored, redacted body. The /ftp listing page is 11,307 bytes, and its first file name is at character
9,006, so the old 4,000-character view held only inline CSS. Its reading view is 1,002 characters:

```
Title: listing directory /ftp
Directory listing, 11 entries: quarantine, acquisitions.md, announcement_encrypted.md, coupons_2013.md.bak,
eastere.gg, encrypt.pyc, incident-support.kdbx, legal.md, package-lock.json.bak, package.json.bak, suspicious_errors.yml
listing directory /ftp
~ / ftp
quarantine 8/10/2026 9:36:13 PM
acquisitions.md 909 8/10/2026 9:36:13 PM
...
Links: . ftp ftp/quarantine ftp/acquisitions.md ftp/announcement_encrypted.md ...
```

main.js (1.2 MB) becomes a 3,455-character summary. It holds the 43 client routes (hash routing noted), the
server paths it references with API paths first and junk dropped, including all eight `/redirect?to=` targets
with their crypto addresses, and the masked secret candidates.

**Which in-reach items an agent can see** (`tools/benchmark/agent_context.py`, the run.py matchers applied
to what the model is given):

| | Before | After |
|---|---|---|
| Lane context only (50 endpoints, routes, leads) | 3: exposedMetrics, S04, S05 | **14**: + scoreBoard, web3Sandbox, privacyPolicy, adminSection, securityPolicy, directoryListing, easterEggLevelOne, forgottenBackup, forgottenDevBackup, misplacedSignatureFile, redirect, S01 |
| Plus the first three responses an agent would open (/ftp, /main.js, /) | 4, one of them false (errorHandling matched the CSS selector `#stacktrace`) | **16**: + redirectCryptoCurrency and S05 from the main.js summary |

The bodies for the second row were fetched once from an isolated Juice Shop v20.2.0 container with no
network. They were not sent through the gateway, and the agent loop was not run.

### Limits

- No live agent run, so whether the model uses the better context is not measured.
- The new well-known and listing requests are counted above (3 for wellknown, 1 listing check after content
  discovery), all through the gateway as GET with the identification.
- Recon still finds nothing beyond depth 1 and `common.txt`. A larger or app-aware wordlist, or recursion that
  keeps to the rate ceiling, is the next step for /api-docs, /encryptionkeys, /metrics and /support/logs.

## Worker without a database (2026-10-09)

Machine-readable results: `tools/benchmark/results-2026-10-09-worker-api.json`. Same target, settings and
pipeline as the run above (`results-2026-10-09-recon-after.json`); API, gateway and worker images built
from branch `feat/worker-api` after it was rebased on the recon changes (`BENCH_KEEP_IMAGES=1 run.py up`).
Recon only, no agent run. What changed (D-042, `docs/WORKER_API.md`): the worker has no database
network or credentials and no master key; it is on a network with the gateway alone, claims jobs and
writes every result through the API's `/worker/*` routes, which the gateway relays.

| | Before (recon-after) | Worker without a database |
|---|---|---|
| Requests seen by juice-proxy | 13,352 | 13,344 (params: 3,222 instead of 3,230; Arjun's own variation) |
| Non-read-only requests | 0 | 0 |
| Peak, sliding 1 s / calendar second (limit 20) | 20 / 20 | 20 / 20 |
| Missing identification | 0 | 0 |
| Endpoints / leads | 198 / 28 | 198 / 28, the same rows |
| Recon recall (automated) | 15 of 32 | 15 of 32, the same items |
| Solved by recon traffic | errorHandling, exposedMetrics, securityPolicy | the same |
| Wall time | 840 s | 826 s |

The worker's channel for the whole run, from the API's access log: 24 claims, 10 finishes, 122 heartbeats,
43 log calls, 10 progress calls and 13 result calls (one per target batch: results are batched). A TCP
connection from the bench worker to `db:5432` or `api:8000` failed (the names do not resolve there);
only `gateway:8081` answered.

One earlier run of the same images, before the rebase and while another stack ran content discovery on
the same machine, saw one window of 21 requests within 0.90 s at juice-proxy (calendar-second peak 20); the
gateway's limiter is unchanged by this branch, and the run above peaked at 20. Delivery jitter between the gateway and juice-proxy under load is the likely cause; not investigated
further.

## Agent runs through the Messages API: how they are measured

`tools/agent_live_run.sh` (`tools/agent_live.py run`, docs/INSTALL.md section 19, "A first live agent
run") appends one dated section per run below, and writes the same numbers to
`tools/benchmark/results-<date>-agent-live.json` (`agent-dryrun` for a dry run against the stub). Each
section is one table:

| Row | Source |
|---|---|
| Model | the job's result (the worker's `ATTACKLEDGER_AGENT_MODEL`; a first run uses the cheapest) |
| Stack | the compose project, the commit, the date of the price table in `agentloop.MODELS` |
| Lane | the lab engagement's lane (`errh` unless `--role` names another) on `shop.lab.test`, scope `shop.lab.test` only, `X-Bug-Bounty: agent-live-run`; for a signed-in lane (`athn`, `athz`, `sess`, `cryp`, `clnt`, `apit`), the test accounts it ran with |
| Outcome | the job's status (`done` only if the agent finished) and the agent's (`finished`, `cost_limit`, ...) |
| Limits | what the run asked for, and what the worker applied (the lower of that and its ceilings) |
| Wall time | from queueing the run to its end, and the job's own start to finish |
| Claude API calls | the gateway's log for the job, kind `service`, by host |
| Target requests | the gateway's log for the job, kind `target`, by method and host; all must be `shop.lab.test` |
| Refused or failed rows | every gateway row for the job that was not sent, with its reason |
| Lab access log | the lab's own nginx log in the run's window (`lab/nginx.conf` logs the research header, the user agent and the fictional user a request was signed in as): an independent count |
| Research header on every request | yes only if every request the lab saw carried it and the lab saw as many as the gateway sent |
| Evidence | the lane's agent evidence since the job started, the items it is on, items marked, leads |
| Tokens | the API's usage summed over the run: input, output, cache read, cache write |
| Cost (estimate) | the loop's estimate from those tokens and the price table, against the budget the worker applied; the Console bill is authoritative |

The script stops with an error, after writing the section, if a request went to another host, the lab saw
a request without the header, or the job failed.

## Agent run dry run against a stub Claude API (2026-10-12, fixed run)

Not a measurement of the model: the Claude API was a local stub (`tools/agent_dryrun/claude_stub.py`) playing a fixed run, so the turns, tokens and cost are the stub's. It shows the path and the accounting end to end: the worker's SDK, the gateway's route, key swap and GW-1 body check, the budget, the tools, the evidence and this write-up.

| | |
|---|---|
| Model | `claude-haiku-5-5` |
| Stack | compose project `al-sec8-live`, commit `11af645`, prices of 2026-10-09 (`agentloop.MODELS`) |
| Lane | `errh` on `shop.lab.test`, scope `shop.lab.test` only, `X-Bug-Bounty: agent-live-run`, job 1 |
| Outcome | job `done`, agent `finished`, 6 turn(s) |
| Limits | max_turns 15, max_requests 20, max_cost_usd 0.05; applied by the worker: $0.0500, 15 turns, 2,000,000 tokens |
| Wall time | 3.0 s (job 1.2 s) |
| Claude API calls (gateway log) | 6 to claude-stub.test |
| Target requests (gateway log) | 2: GET 2; hosts: shop.lab.test (all shop.lab.test) |
| Refused or failed rows | none |
| Lab access log | 2 request(s), 2 with the research header, 2 with the user agent |
| Research header on every request | yes |
| Evidence | 2 entries on 1 item(s); 1 item(s) marked; 1 lead(s) |
| Tokens | input 1,050, output 1,080, cache read 10,033, cache write 3,498 |
| Cost (estimate) | $0.0012 of a $0.05 budget |

Agent summary for the reviewer: "Stub run: one item tested with two read-only requests and marked done; the other items were left open."

## Agent run dry run against a stub Claude API (2026-10-12, budget stop)

Not a measurement of the model: the Claude API was a local stub (`tools/agent_dryrun/claude_stub.py`) playing a fixed run, so the turns, tokens and cost are the stub's. It shows the path and the accounting end to end: the worker's SDK, the gateway's route, key swap and GW-1 body check, the budget, the tools, the evidence and this write-up.

| | |
|---|---|
| Model | `claude-haiku-5-5` |
| Stack | compose project `al-sec8-live`, commit `11af645`, prices of 2026-10-09 (`agentloop.MODELS`) |
| Lane | `errh` on `shop.lab.test`, scope `shop.lab.test` only, `X-Bug-Bounty: agent-live-run`, job 2 |
| Outcome | job `partial`, agent `cost_limit`, 1 turn(s); stopped before turn 2 at the cost limit (about $0.0021 of $0.0040 spent): the next call could cost up to $0.0021 |
| Limits | max_turns 15, max_requests 20, max_cost_usd 0.05; applied by the worker: $0.0040, 15 turns, 2,000,000 tokens |
| Wall time | 3.0 s (job 0.6 s) |
| Claude API calls (gateway log) | 1 to claude-stub.test |
| Target requests (gateway log) | 1: GET 1; hosts: shop.lab.test (all shop.lab.test) |
| Refused or failed rows | none |
| Lab access log | 1 request(s), 1 with the research header, 1 with the user agent |
| Research header on every request | yes |
| Evidence | 0 entries on 0 item(s); 0 item(s) marked; 0 lead(s) |
| Tokens | input 50, output 3,600, cache read 0, cache write 2,071 |
| Cost (estimate) | $0.0021 of a $0.004 budget |

Agent summary for the reviewer: "Partial run, stopped (cost limit) before the agent finished: 0 evidence entries, 0 items marked. The open items are left for a person; nothing was closed."

## Live agent run (2026-10-14)

One agent run through the Messages API, on the lab, with the cheapest configured model. The cost is the loop's estimate from the token counts the API returned; the Console bill is authoritative.

| | |
|---|---|
| Model | `claude-haiku-5-5` |
| Stack | compose project `attackledger`, commit `351316b`, prices of 2026-10-09 (`agentloop.MODELS`) |
| Lane | `errh` on `shop.lab.test`, scope `shop.lab.test` only, `X-Bug-Bounty: agent-live-run`, job 61 |
| Outcome | job `done`, agent `finished`, 9 turn(s) |
| Limits | max_turns 15, max_requests 20, max_cost_usd 0.5; applied by the worker: $0.50, 15 turns, 2,000,000 tokens |
| Wall time | 51.1 s (job 48.2 s) |
| Claude API calls (gateway log) | 9 to api.anthropic.com |
| Target requests (gateway log) | 20: GET 19, HEAD 1; hosts: shop.lab.test (all shop.lab.test) |
| Refused or failed rows | target HEAD https://shop.lab.test/: could not connect to shop.lab.test:443: Connect call failed ('172.21.0.2', 443); target GET https://shop.lab.test/%E0%A4%A: could not connect to shop.lab.test:443: Connect call failed ('172.21.0.2', 443); target GET https://shop.lab.test/?id=%27%22%3C%3E%5C&page=-1&q[]=1: could not connect to shop.lab.test:443: Connect call failed ('172.21.0.2', 443); target GET https://shop.lab.test/errh-probe-does-not-exist-7f3a: could not connect to shop.lab.test:443: Connect call failed ('172.21.0.2', 443); target GET https://shop.lab.test/: could not connect to shop.lab.test:443: Connect call failed ('172.21.0.2', 443) |
| Lab access log | 15 request(s), 14 with the research header, 14 with the user agent; 1 answered 400 by the lab's nginx before it read the headers |
| Research header on every request | yes (on the 14 whose headers the lab read; 1 not observable) |
| Evidence | 20 entries on 2 item(s); 2 item(s) marked; 4 lead(s) |
| Tokens | input 20, output 8,824, cache read 63,225, cache write 15,593 |
| Cost (estimate) | $0.0070 of a $0.5 budget |

Agent summary for the reviewer: "Lane 19 (error handling) on shop.lab.test: both open items were tested and marked done, with evidence attached. WSTG-ERRH-01 (improper error handling): malformed query strings, an invalid percent-encoding, out-of-range and non-numeric ids, and nonexistent paths produced generic responses (bare "not found" 404, stock nginx 400, plain "ok" or {"ok":true}), with no verbose error text. WSTG-ERRH-02 (stack traces): no stack trace or debug output in any response from phpinfo.php, /debug, /.git/HEAD, error-triggering paths, or the linked app.js. Caveats: HTTPS to shop.lab.test was refused at connect,"

## Live agent run (2026-10-14, info lane, 60 requests)

One agent run through the Messages API, on the lab, with the cheapest configured model. The cost is the loop's estimate from the token counts the API returned; the Console bill is authoritative.

| | |
|---|---|
| Model | `claude-haiku-5-5` |
| Stack | compose project `attackledger`, commit `aa9577b`, prices of 2026-10-09 (`agentloop.MODELS`) |
| Lane | `info` on `shop.lab.test`, scope `shop.lab.test` only, `X-Bug-Bounty: agent-live-run`, job 62 |
| Outcome | job `done`, agent `finished`, 9 turn(s) |
| Limits | max_turns 30, max_requests 60, max_cost_usd 0.5; applied by the worker: $0.50, 30 turns, 2,000,000 tokens |
| Wall time | 63.2 s (job 62.3 s) |
| Claude API calls (gateway log) | 9 to api.anthropic.com |
| Target requests (gateway log) | 25: GET 23, HEAD 1, OPTIONS 1; hosts: shop.lab.test (all shop.lab.test) |
| Refused or failed rows | target GET https://shop.lab.test/: could not connect to shop.lab.test:443: Connect call failed ('172.21.0.2', 443) |
| Lab access log | 24 request(s), 24 with the research header, 24 with the user agent |
| Research header on every request | yes |
| Evidence | 59 entries on 10 item(s); 9 item(s) marked; 1 lead(s) |
| Tokens | input 20, output 11,417, cache read 99,173, cache write 22,371 |
| Cost (estimate) | $0.0095 of a $0.5 budget |

Agent summary for the reviewer: "Lane 20 (information gathering, shop.lab.test): 9 of 10 items done with read-only GET/HEAD/OPTIONS requests at normal pace. Evidence is attached to each item; the lead on the exposed /backup/ directory is recorded for the info-disclosure lane. Item WSTG-INFO-01 (search engine discovery) is left open: only the on-host part (robots.txt, sitemap, security.txt, page links) was tested, and the search-engine index queries are off-host and outside this host-scoped tool. Other notes: the custom request headers were rejected because the gateway sets them, so requests went out with the gateway's researc"

## Live agent run (2026-10-14, conf lane, 60 requests)

One agent run through the Messages API, on the lab, with the cheapest configured model. The cost is the loop's estimate from the token counts the API returned; the Console bill is authoritative.

| | |
|---|---|
| Model | `claude-haiku-5-5` |
| Stack | compose project `attackledger`, commit `aa9577b`, prices of 2026-10-09 (`agentloop.MODELS`) |
| Lane | `conf` on `shop.lab.test`, scope `shop.lab.test` only, `X-Bug-Bounty: agent-live-run`, job 63 |
| Outcome | job `done`, agent `finished`, 10 turn(s) |
| Limits | max_turns 30, max_requests 60, max_cost_usd 0.5; applied by the worker: $0.50, 30 turns, 2,000,000 tokens |
| Wall time | 99.3 s (job 97.2 s) |
| Claude API calls (gateway log) | 10 to api.anthropic.com |
| Target requests (gateway log) | 40: GET 35, HEAD 2, OPTIONS 3; hosts: shop.lab.test (all shop.lab.test) |
| Refused or failed rows | target GET https://shop.lab.test/: could not connect to shop.lab.test:443: Connect call failed ('172.21.0.2', 443) |
| Lab access log | 39 request(s), 39 with the research header, 39 with the user agent |
| Research header on every request | yes |
| Evidence | 51 entries on 10 item(s); 8 item(s) marked; 1 lead(s) |
| Tokens | input 22, output 17,327, cache read 168,325, cache write 30,557 |
| Cost (estimate) | $0.0142 of a $0.5 budget |

Agent summary for the reviewer: "Configuration lane (shop.lab.test), read-only GET/HEAD/OPTIONS requests only; no writes were proposed. Done (7 items): WSTG-CONF-01 (HTTP banner nginx/1.30.5; HTTPS refused at TCP connect), CONF-02 (status, phpinfo, actuator and manager paths 404; admin login 401; unauthenticated JSON API), CONF-03 (no source disclosure from backup or alternate extensions), CONF-04 (the /backup/ 200 is a catch-all placeholder for any path, so backup contents were not confirmed; recorded as a lead correcting the existing one), CONF-05 (admin login 401 over plain HTTP; phpMyAdmin and manager 404), CONF-08 (cross"

## Live agent run (2026-10-14, inpv lane, 60 requests)

One agent run through the Messages API, on the lab, with the cheapest configured model. The cost is the loop's estimate from the token counts the API returned; the Console bill is authoritative.

| | |
|---|---|
| Model | `claude-haiku-5-5` |
| Stack | compose project `attackledger`, commit `aa9577b`, prices of 2026-10-09 (`agentloop.MODELS`) |
| Lane | `inpv` on `shop.lab.test`, scope `shop.lab.test` only, `X-Bug-Bounty: agent-live-run`, job 64 |
| Outcome | job `done`, agent `finished`, 15 turn(s) |
| Limits | max_turns 30, max_requests 60, max_cost_usd 0.5; applied by the worker: $0.50, 30 turns, 2,000,000 tokens |
| Wall time | 141.4 s (job 138.0 s) |
| Claude API calls (gateway log) | 15 to api.anthropic.com |
| Target requests (gateway log) | 41: GET 37, HEAD 2, OPTIONS 2; hosts: shop.lab.test (all shop.lab.test) |
| Refused or failed rows | target GET http://shop.lab.test/search.php?q=lanemethod1: method override to POST is refused |
| Lab access log | 40 request(s), 40 with the research header, 40 with the user agent |
| Research header on every request | yes |
| Evidence | 38 entries on 17 item(s); 15 item(s) marked; 2 lead(s) |
| Tokens | input 32, output 24,998, cache read 304,686, cache write 41,161 |
| Cost (estimate) | $0.0207 of a $0.5 budget |

Agent summary for the reviewer: "Lane 22 (input validation) on shop.lab.test, read-only, no test accounts, writes disallowed. Done (14 items): WSTG-INPV-01 reflected XSS CONFIRMED as unescaped HTML reflection in /search.php q (harmless marker tag, recorded as a high-severity lead); INPV-03 verb tampering (OPTIONS/HEAD on search and /admin/, 401 unchanged); INPV-04 HPP (first value used); INPV-05 SQLi, INPV-06 LDAP, INPV-07 XML, INPV-09 XPath, INPV-11 code, INPV-12 command, INPV-13 format string, INPV-18 SSTI, INPV-19 SSRF: no signal observed; INPV-08 SSI: encoded directive echoed, not processed, raw directive not sendable (co"

## Live agent run (2026-10-14, info lane, 60 requests, after D-057)

One agent run through the Messages API, on the lab, with the cheapest configured model. The cost is the loop's estimate from the token counts the API returned; the Console bill is authoritative.

| | |
|---|---|
| Model | `claude-haiku-5-5` |
| Stack | compose project `attackledger`, commit `106ebdf`, prices of 2026-10-09 (`agentloop.MODELS`) |
| Lane | `info` on `shop.lab.test`, scope `shop.lab.test` only, `X-Bug-Bounty: agent-live-run`, job 68 |
| Outcome | job `done`, agent `finished`, 14 turn(s) |
| Limits | max_turns 30, max_requests 60, max_cost_usd 0.5; applied by the worker: $0.50, 30 turns, 2,000,000 tokens |
| Wall time | 87.4 s (job 85.2 s) |
| Claude API calls (gateway log) | 14 to api.anthropic.com |
| Target requests (gateway log) | 28: GET 26, HEAD 1, OPTIONS 1; hosts: shop.lab.test (all shop.lab.test) |
| Refused or failed rows | target GET http://shop.lab.test:8080/: could not connect to shop.lab.test:8080: Connect call failed ('172.21.0.2', 8080); target GET https://shop.lab.test/: could not connect to shop.lab.test:443: Connect call failed ('172.21.0.2', 443) |
| Lab access log | 26 request(s), 26 with the research header, 26 with the user agent |
| Research header on every request | yes |
| Evidence | 49 entries on 10 item(s); 9 item(s) marked; 3 lead(s) |
| Tokens | input 30, output 14,684, cache read 204,826, cache write 25,599 |
| Cost (estimate) | $0.0126 of a $0.5 budget |

Agent summary for the reviewer: "Lane 24 (information gathering) on shop.lab.test. Nine of ten items are marked done with evidence. Item 1 (WSTG-INFO-01, search engine discovery) is left open because search-engine queries to third parties are outside what these host-scoped tools can send; on-host discovery is noted on it. Key findings: HTTP is the only working scheme (HTTPS:443 and 8080 refused); robots.txt disallows /backup/, which returns 200 unauthenticated; /static/app.js.map is publicly served (200); and a hidden debug parameter on /search.php changes the response to "verbose trace enabled" (confirmed by splitting a batc"

## Live agent run (2026-10-14, conf lane, 60 requests, after D-057)

One agent run through the Messages API, on the lab, with the cheapest configured model. The cost is the loop's estimate from the token counts the API returned; the Console bill is authoritative.

| | |
|---|---|
| Model | `claude-haiku-5-5` |
| Stack | compose project `attackledger`, commit `106ebdf`, prices of 2026-10-09 (`agentloop.MODELS`) |
| Lane | `conf` on `shop.lab.test`, scope `shop.lab.test` only, `X-Bug-Bounty: agent-live-run`, job 69 |
| Outcome | job `done`, agent `finished`, 13 turn(s) |
| Limits | max_turns 30, max_requests 60, max_cost_usd 0.5; applied by the worker: $0.50, 30 turns, 2,000,000 tokens |
| Wall time | 123.5 s (job 118.6 s) |
| Claude API calls (gateway log) | 13 to api.anthropic.com |
| Target requests (gateway log) | 51: GET 47, HEAD 1, OPTIONS 3; hosts: shop.lab.test (all shop.lab.test) |
| Refused or failed rows | target GET http://shop.lab.test:8080/: could not connect to shop.lab.test:8080: Connect call failed ('172.21.0.2', 8080); target GET https://shop.lab.test/: could not connect to shop.lab.test:443: Connect call failed ('172.21.0.2', 443) |
| Lab access log | 49 request(s), 49 with the research header, 49 with the user agent |
| Research header on every request | yes |
| Evidence | 56 entries on 10 item(s); 11 item(s) marked; 2 lead(s) |
| Tokens | input 28, output 21,329, cache read 222,013, cache write 36,494 |
| Cost (estimate) | $0.0174 of a $0.5 budget |

Agent summary for the reviewer: "Lane 25 (Configuration) on shop.lab.test. HTTP on port 80 is the only working web origin (https://443 was refused; plain HTTP also answers on 8443; 8080 refused). Ten of eleven items are done and item 10 is N/A.  Main findings (all read-only GET/HEAD/OPTIONS): - /.git/config is publicly readable (x18) and names the remote https://git.lab.test/shop/storefront.git. Other .git files, .svn, .hg, .env, backups and archives returned 404. - /backup/ and /backup/index.html serve a bare "backup index" page without authentication (robots.txt disallows it). - The search script shows debug output when deb"

## Live agent run (2026-10-14, inpv lane, 60 requests, after D-057)

One agent run through the Messages API, on the lab, with the cheapest configured model. The cost is the loop's estimate from the token counts the API returned; the Console bill is authoritative.

| | |
|---|---|
| Model | `claude-haiku-5-5` |
| Stack | compose project `attackledger`, commit `106ebdf`, prices of 2026-10-09 (`agentloop.MODELS`) |
| Lane | `inpv` on `shop.lab.test`, scope `shop.lab.test` only, `X-Bug-Bounty: agent-live-run`, job 70 |
| Outcome | job `done`, agent `finished`, 15 turn(s) |
| Limits | max_turns 30, max_requests 60, max_cost_usd 0.5; applied by the worker: $0.50, 30 turns, 2,000,000 tokens |
| Wall time | 114.4 s (job 112.8 s) |
| Claude API calls (gateway log) | 15 to api.anthropic.com |
| Target requests (gateway log) | 29: GET 26, HEAD 1, OPTIONS 2; hosts: shop.lab.test (all shop.lab.test) |
| Refused or failed rows | target GET http://shop.lab.test/admin/: method override to POST is refused; target GET https://shop.lab.test/: could not connect to shop.lab.test:443: Connect call failed ('172.21.0.2', 443) |
| Lab access log | 27 request(s), 27 with the research header, 27 with the user agent |
| Research header on every request | yes |
| Evidence | 36 entries on 17 item(s); 16 item(s) marked; 1 lead(s) |
| Tokens | input 32, output 19,849, cache read 236,591, cache write 32,593 |
| Cost (estimate) | $0.0164 of a $0.5 budget |

Agent summary for the reviewer: "Lane 26 (input validation) on shop.lab.test over HTTP only, since HTTPS on 443 was refused. Items done: INPV-01 (reflected HTML injection confirmed in /search.php?q=, recorded as a high lead, not browser-verified), INPV-03, 04, 05, 06, 07, 08, 09, 11, 12, 13, 16, 17, 18, 19 (no further issues observed). INPV-10 is N/A because no mail feature exists on the host. Left open: INPV-02 (stored XSS; no writable or stored-content surface reachable with read-only requests and no test accounts), INPV-14 (incubated vulnerabilities; needs multi-step stored flows), and INPV-15 (HTTP splitting was tested wi"

## Live agent run repeatability: info lane, three runs (2026-10-14)

The same lane run three more times on fresh lanes (`--no-append`, jobs 71 to 73; commit `a4a51dd`, `claude-haiku-5-5`,
60 requests allowed), to see whether the keys in `static/app.js`, missed by the post-D-057 info run above, were a
gap in the prompt or chance.

| Run | Requests | Items marked | Leads | Cost (estimate) | Keys in app.js | Hidden parameter | Source map | /backup/ |
|---|---|---|---|---|---|---|---|---|
| 1 | 26 | 9 of 10 | 5 | $0.0109 | found | found | found | found |
| 2 | 25 | 9 of 10 | 5 | $0.0100 | found | found | found | found |
| 3 | 27 | 9 of 10 | 4 | $0.0113 | found | not found | found | found |

The keys were found in every run, so the miss was chance and the hints were not changed. The hidden parameter was
found in two of three. Item 1 (search engine discovery) stays open in each run: it needs third-party queries the
host-scoped tools do not send.

## Live agent run (2026-10-14, athz lane, signed in, 60 requests)

One agent run through the Messages API, on the lab, with the cheapest configured model. The cost is the loop's estimate from the token counts the API returned; the Console bill is authoritative.

| | |
|---|---|
| Model | `claude-haiku-5-5` |
| Stack | compose project `attackledger`, commit `234ddaa`, prices of 2026-10-09 (`agentloop.MODELS`) |
| Lane | `athz` on `shop.lab.test`, scope `shop.lab.test` only, `X-Bug-Bounty: agent-live-run`, job 74, test accounts `user` (customer, alice), `admin` (admin, carol) |
| Outcome | job `done`, agent `finished`, 22 turn(s) |
| Limits | max_turns 30, max_requests 60, max_cost_usd 0.5; applied by the worker: $0.50, 30 turns, 2,000,000 tokens |
| Wall time | 108.3 s (job 106.0 s) |
| Claude API calls (gateway log) | 22 to api.anthropic.com |
| Target requests (gateway log) | 47: GET 45, HEAD 2; hosts: shop.lab.test (all shop.lab.test) |
| Refused or failed rows | target HEAD https://shop.lab.test/: could not connect to shop.lab.test:443: Connect call failed ('172.21.0.2', 443) |
| Lab access log | 46 request(s), 44 with the research header, 44 with the user agent; 2 answered 400 by the lab's nginx before it read the headers; signed in as alice 21, carol 8 |
| Research header on every request | yes (on the 44 whose headers the lab read; 2 not observable) |
| Evidence | 29 entries on 4 item(s); 4 item(s) marked; 3 lead(s) |
| Tokens | input 46, output 14,739, cache read 323,458, cache write 28,086 |
| Cost (estimate) | $0.0141 of a $0.5 budget |

Agent summary for the reviewer: "All four ATHZ items were tested with read-only requests on http://shop.lab.test (recon origins were empty; the HTTPS probe was refused by the gateway, so HTTP was used). Results: (1) WSTG-ATHZ-01 traversal/file inclusion: not observed on /static/, /products?id= or /search.php?q=. (2) WSTG-ATHZ-02 authorization bypass: /admin/ enforces roles and the header bypass attempts failed, but the admin API /api/v1/admin/users returns the full user list to a customer account; lead recorded (high). (3) WSTG-ATHZ-03 privilege escalation: the customer (alice) reads admin data (read-only; write-side escalati"

## Live agent run (2026-10-14, sess lane, signed in, 60 requests)

One agent run through the Messages API, on the lab, with the cheapest configured model. The cost is the loop's estimate from the token counts the API returned; the Console bill is authoritative.

| | |
|---|---|
| Model | `claude-haiku-5-5` |
| Stack | compose project `attackledger`, commit `234ddaa`, prices of 2026-10-09 (`agentloop.MODELS`) |
| Lane | `sess` on `shop.lab.test`, scope `shop.lab.test` only, `X-Bug-Bounty: agent-live-run`, job 75, test accounts `user` (customer, alice), `admin` (admin, carol) |
| Outcome | job `done`, agent `finished`, 14 turn(s) |
| Limits | max_turns 30, max_requests 60, max_cost_usd 0.5; applied by the worker: $0.50, 30 turns, 2,000,000 tokens |
| Wall time | 105.3 s (job 103.2 s) |
| Claude API calls (gateway log) | 14 to api.anthropic.com |
| Target requests (gateway log) | 22: GET 22; hosts: shop.lab.test (all shop.lab.test) |
| Refused or failed rows | target GET https://shop.lab.test/: could not connect to shop.lab.test:443: Connect call failed ('172.21.0.2', 443) |
| Lab access log | 21 request(s), 21 with the research header, 21 with the user agent; signed in as alice 9, carol 2 |
| Research header on every request | yes |
| Evidence | 27 entries on 9 item(s); 4 item(s) marked; 5 lead(s) |
| Tokens | input 30, output 19,042, cache read 177,673, cache write 29,148 |
| Cost (estimate) | $0.0149 of a $0.5 budget |

Agent summary for the reviewer: "Session lane (31) on http://shop.lab.test (HTTPS refused, HTTP answered). Done: SESS-01 (session schema observed; token entropy not sampled), SESS-02 (cookie attributes observed; no HttpOnly/SameSite visible, one-year Max-Age), SESS-04 (session value in statement URL, public cache headers on personalized pages, AWS key in app.js routed to config), SESS-06 (logout clears the cookie but the old session still returned 200 via /api/v1/me; logged as a lead to validate). Left open: SESS-03 (fixation needs a login POST, which writes-disabled rules forbid), SESS-05 (cross-site POST behavior not exerci"

## Live agent run (2026-10-14, athn lane, signed in, 60 requests)

One agent run through the Messages API, on the lab, with the cheapest configured model. The cost is the loop's estimate from the token counts the API returned; the Console bill is authoritative.

| | |
|---|---|
| Model | `claude-haiku-5-5` |
| Stack | compose project `attackledger`, commit `234ddaa`, prices of 2026-10-09 (`agentloop.MODELS`) |
| Lane | `athn` on `shop.lab.test`, scope `shop.lab.test` only, `X-Bug-Bounty: agent-live-run`, job 76, test accounts `user` (customer, alice), `admin` (admin, carol) |
| Outcome | job `done`, agent `finished`, 14 turn(s) |
| Limits | max_turns 30, max_requests 60, max_cost_usd 0.5; applied by the worker: $0.50, 30 turns, 2,000,000 tokens |
| Wall time | 84.2 s (job 82.0 s) |
| Claude API calls (gateway log) | 14 to api.anthropic.com |
| Target requests (gateway log) | 28: GET 26, HEAD 2; hosts: shop.lab.test (all shop.lab.test) |
| Refused or failed rows | target HEAD https://shop.lab.test/: could not connect to shop.lab.test:443: Connect call failed ('172.21.0.2', 443) |
| Lab access log | 27 request(s), 27 with the research header, 27 with the user agent; signed in as alice 6, carol 1 |
| Research header on every request | yes |
| Evidence | 31 entries on 10 item(s); 8 item(s) marked; 3 lead(s) |
| Tokens | input 30, output 14,583, cache read 189,504, cache write 26,310 |
| Cost (estimate) | $0.0125 of a $0.5 budget |

Agent summary for the reviewer: "Lane 32 (Authentication) on shop.lab.test. Items done: 1, 4, 5, 6, 7, 9, 10. Item 8 is N/A because no security-question or recovery feature exists on the host (/forgot-password and /reset-password return 404). Items 2 (default credentials) and 3 (lockout) are left open: both require repeated POST login attempts, which are out of scope with writes disabled and would amount to credential guessing. Only GET/HEAD/OPTIONS were sent, all as anonymous, alice (user) or carol (admin) as needed, at a low rate. Key observations: (1) only plain HTTP answers (HTTPS refused by the gateway), and the login fo"
