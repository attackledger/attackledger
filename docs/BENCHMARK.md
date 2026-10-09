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
