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
