# Traffic gateway (D-039)

Status: built 2026-10-09 on branch `feat/gateway` (MVP item 2). This file is the design and
the record of the decisions taken while building it.

## What it is for

Before the gateway, every recon tool enforced the engagement's rules with its own flags. A
benchmark against Juice Shop found nuclei sending POST, DELETE and DEBUG requests and reaching
40 requests in one second at a limit of 20 (`BENCHMARK.md`). The nuclei fix (`nucleisafe.py`,
merged before this branch) closed that one tool; the gateway closes the class:

- the worker container has **no route to the internet**;
- every byte a recon tool or the agent sends towards a target, a passive source or the Claude
  API leaves through **one gateway container**;
- the gateway enforces, per engagement and in one place: the scope rules, read-only methods,
  the rate ceiling, and the research identification; and it logs every request, allowed or
  refused, with the reason.

The tools' own flags stay. They are the first layer (they keep a tool from even trying), the
gateway is the second (it makes trying useless). The nuclei template classifier and its pacing
(`-rl 1 -rld ceil(1050/(limit-1))ms`, just under the ceiling) are kept as they are.

## Architecture

```
                      internal network (internal: true, no route out)
  ┌─────────┐                                                     ┌──────────────┐
  │ worker  │── HTTP proxy, CONNECT (job-<id>.<tool>:<secret>) ──►│              │── egress network ──► targets
  │ tools,  │── DNS (A/AAAA/CNAME) ──────────────────────────────►│   gateway    │                      passive sources
  │ agent   │── port probes (CONNECT + X-AttackLedger-Probe) ────►│              │                      api.anthropic.com
  └────┬────┘                                                     │  - TLS CA    │── lab network ─────► lab targets
       │ database (today; D-042 moves this to the API)            │  - limiter   │   (internal: true)   (benchmark: countproxy
  ┌────▼────┐                                                     │  - log queue │                       → Juice Shop)
  │   db    │◄──── api ◄── /gateway/session, /gateway/log ────────┤              │
  └─────────┘   (rules, request log; gateway token)               └──────────────┘
```

| Part | Where | What it does |
|---|---|---|
| Proxy | `server/app/gateway.py`, port 8080 | HTTP/1.1 forward proxy. Plain `http://` requests in absolute form; `https://` through CONNECT, always TLS-terminated with a deployment CA. Every request is parsed (h11), checked, re-serialized and sent on a new upstream connection |
| CA | `/data/gateway` (private volume), `/data/gateway-public/ca.pem` | Created on first start (EC P-256, 5 years). Leaf certificates per host, in memory and in a private temporary folder. Only the worker mounts the public certificate |
| DNS | same process, UDP 53 | Answers A, AAAA and CNAME questions for names in scope of an engagement that has a running job; refuses everything else |
| Rules | `GET`/`POST /gateway/*` on the API | The gateway asks the API who a job credential belongs to and what that engagement's rules are; it holds no database credentials |
| Request log | table `gateway_requests` (migration `0017`) | One row per request, probe and DNS question, allowed or refused, with the reason. Read with `GET /engagements/{id}/gateway-log` |
| Worker client | `server/app/egress.py` | Builds each job's credential, the proxy URL and environment per tool, the urllib opener, the resolver address and the port prober |

## Decisions

### 1. Our own asyncio proxy on h11, not mitmproxy

mitmproxy (MIT) would work, but most of what it does would have to be switched off and kept
off: its raw-TCP fallback for tunnels it cannot classify, WebSockets, HTTP/2 and HTTP/3,
transparent, upstream and reverse modes, `ignore_hosts` passthrough, its own DNS mode. It is
also a new dependency tree of about thirty packages including a native Rust module, and its
upstream certificate check is one global switch, while the gateway needs it on for passive
sources and the Claude API and off for targets (tools ran with `-k` before, and still record
hosts with odd certificates).

The gateway is about 900 lines on two libraries that are already installed: **h11 0.16.0**
(the strict HTTP/1.1 state machine under httpx; 0.16 has the chunked-encoding fix,
CVE-2025-43859) and **cryptography** for the CA. It runs from the API image, so the CI test run
covers it. It is simpler because there is nothing to switch off:

- it speaks HTTP/1.1 only and offers only `http/1.1` in ALPN;
- it never relays raw bytes. Every request is parsed and written out again by h11, so a
  malformed or smuggled request cannot reach a target; a tunnel that does not start a TLS
  handshake with the gateway's certificate is closed;
- one upstream connection per request (`Connection: close`), opened only after the request
  has passed every check, to an address resolved and checked by the gateway itself.

### 2. Job identity: proxy credentials per job

- When the worker claims a job it creates a 256-bit secret and stores only its SHA-256
  (`jobs.gateway_secret_sha256`). The secret lives in the worker's memory and in the
  environment and arguments of that job's tool processes, never in the job log (masked).
- Every tool authenticates as `job-<id>.<tool>:<secret>` (HTTP Basic proxy authentication).
  The tool name is self-declared and only used for attribution in the log.
- The gateway asks the API (`POST /gateway/session`) whether the credential is valid. The
  API answers only while the job is **running**, the secret matches, the engagement is
  authorized and has scope rules. The answer is cached for 2 seconds, so a cancelled or
  finished job, or a changed rule, takes effect within 2 seconds.
- A credential carries exactly one engagement's rules: there is no way to name another
  engagement, and another job's secret is not in the database.
- A job may only use the egress its module declares (`modules.py`): `passive` modules reach
  passive sources only, `target` modules reach the engagement's scope only, agent runs reach
  the scope and the Claude API.

Checked against every tool the modules run:

| Module | Tool | How it reaches the gateway |
|---|---|---|
| subdomains | subfinder, assetfinder, crt.sh fetch | `-proxy` / environment / urllib proxy handler; passive allowlist |
| resolve, subdomains | dnsx | `-r <gateway>:53` (DNS, below) |
| ports | was naabu | gateway port probes (decision 6) |
| probe | httpx | `-http-proxy`, `-r <gateway>:53` for its address lookups |
| crawl | katana | `-proxy`, `-r` |
| archive | gau, waybackurls | `--proxy` / environment; passive allowlist |
| content | feroxbuster | `--proxy` (and the baseline check through urllib) |
| jsanalyze | AttackLedger fetcher (urllib) | explicit proxy handler |
| params | Arjun (requests) | `HTTP(S)_PROXY` environment |
| nuclei | nuclei | `-p`, `-pi` (its internal requests too), `-r <file>` |
| agent | `agenttools` urllib transport, `anthropic` client | explicit proxy handler / `DefaultHttpxClient(proxy=…, verify=CA)` |
| paramclass, dorks | none (computed) | no egress |

Each tool also gets `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` (both cases) and
`SSL_CERT_FILE` pointing at the gateway CA, and nothing else from the worker's environment
(no `DATABASE_URL`, no `ANTHROPIC_API_KEY`). Whether a tool honours the proxy is not taken
on trust: the worker has no other route, so a tool that ignores it fails.

### 3. Rules come from the API, not the database

The gateway is the one container that talks to the internet and parses what targets send, so
it holds no database credentials. It gets rules and writes its log through three API routes
(`authz.py` permission `gateway`), authenticated with a gateway token that only the gateway
and the API can read (a file the gateway creates in a volume shared with the API, or
`ATTACKLEDGER_GATEWAY_TOKEN`):

| Route | Answers |
|---|---|
| `POST /gateway/session` | `{job_id, secret}` → the job's engagement, module traffic class and rules (scope, rate, identification, redaction), or why not |
| `GET /gateway/dns-scopes` | scope rules and rate of every engagement with a running job (for DNS) |
| `POST /gateway/log` | a batch of request-log rows |

With D-042 in mind: in a later hybrid service the API and ledger may be hosted while the
worker and gateway stay in the customer's network. The gateway already talks only to the API,
over an authenticated channel, so it needs no change then. The worker still reads the database
today; moving it to the API is D-042's other half, and it is what closes the gap named in the
threat model below.

### 4. DNS and passive sources

- **Docker** (29.5.2 measured) does not forward external DNS questions for containers that
  are only on internal networks, and the worker's `dns` is set to an unroutable address
  (192.0.2.1, TEST-NET-1) in case an older engine would. Container names still resolve.
- **The gateway resolver** answers only A, AAAA and CNAME questions for names that are in
  scope of an engagement with a running job, paced at that engagement's rate, and logs each
  question (`DNS`, tool `dns`). Everything else gets REFUSED. It forwards to the gateway's own
  resolver. UDP only: a truncated answer is passed back truncated.
- **Passive sources** are an allowlist of hosts (`gateway.PASSIVE_HOSTS`, extended with
  `ATTACKLEDGER_GATEWAY_PASSIVE_HOSTS`), taken from the hosts compiled into subfinder,
  assetfinder, gau and waybackurls. They are reachable only from jobs of a passive module,
  only on port 443, only with GET, HEAD or OPTIONS and no body, with the upstream certificate
  verified, without the research identification (it is not target traffic and would name the
  researcher to a third party), paced at 10 requests per second per host, logged with kind
  `passive`, and **not** counted against the engagement's ceiling. A host that is also in the
  engagement's scope is treated as a target.
- **The Claude API** (`api.anthropic.com`, or `ATTACKLEDGER_GATEWAY_SERVICE_HOSTS`) is a
  service host: agent jobs only, `POST /v1/messages` and `/v1/messages/count_tokens` only,
  upstream certificate verified, logged with kind `service`, not counted. Headers and bodies
  are never logged.

### 5. Rate ceiling

One limiter per engagement in the gateway process, shared by every tool, job and worker. It
is a token bucket with *rate* tokens in which each token comes back 1.05 seconds after it was
spent, so no 1.05-second window (and therefore no 1-second window, with 50 ms for network
jitter) holds more than *rate* requests. A plain refilling bucket with burst *B* lets *B* +
*rate* requests into one second; this is the form that makes "peak at or under the limit"
hold. The token is taken after the upstream connection is open and just before the request
head is written. Waiting requests queue in order; one that would wait more than 30 seconds
is refused with 429. Port probes take a token too (D-014). DNS questions have their own
limiter per engagement at the same rate.

One gateway per deployment. Several gateways would each enforce the ceiling separately; a
shared limiter comes with them, if ever.

### 6. Port scanning: gateway probes instead of naabu

naabu resolves names itself and connects to addresses, so its connections cannot be checked
against host-name scope; through a SOCKS proxy it would also need a raw TCP relay, which is
the side door the gateway exists to close. The `ports` module now asks the gateway: a
`CONNECT host:port` with the header `X-AttackLedger-Probe: connect`. The gateway checks scope,
refuses port 25, takes a rate token, opens a TCP connection, answers 200 (open), 502 with
the reason (closed, timed out) or 403, and closes it. No byte is relayed. Same top 100 ports as
before (nmap's list, port 25 skipped). naabu and libpcap are no longer in the worker image.

### 7. Methods and requests

Allowed to targets: GET, HEAD, OPTIONS, with no body (no `Content-Length` above 0, no
`Transfer-Encoding`). Refused: every other method (POST, PUT, PATCH, DELETE, TRACE, DEBUG,
PROPFIND, ...), method override headers (`X-HTTP-Method-Override` and the like) and `_method=`
parameters naming another method, `Upgrade` (WebSocket, h2c), `https://` in absolute form (it
must use CONNECT), a `Host` that differs from the CONNECT target, credentials in the URL, and
port 25. The identification is always set by the gateway: any header of the same name sent by
the tool is removed first, then the engagement's research header and user agent are added. An
engagement without either gets no target traffic at all (D-008). Hop-by-hop headers and
`Proxy-Authorization` are never forwarded. Redirects are never followed by the gateway; a tool
that follows one sends a new request, which is checked like any other.

Addresses: the gateway resolves the host itself, refuses loopback, link-local (cloud metadata),
multicast and unspecified addresses and the deployment's own containers
(`ATTACKLEDGER_GATEWAY_DENY_HOSTS`, default `db,api,web,worker,gateway`), and connects to the
address it checked, so a DNS answer cannot change between check and use. Private addresses are
allowed: an internal pentest needs them, and the lab is one.

Refusals are answered with status 403 (policy), 407 (credential), 429 (rate wait), 502
(upstream failed) or 503 (gateway cannot check or log), the header `X-AttackLedger-Gateway:
refused` and the reason as plain text. The agent's tool and the worker's fetcher report the
reason instead of a target status.

### 8. Fail closed

Nothing is sent when:

- the gateway is down: the worker has no other route (and it refuses to start a job that
  sends traffic when no gateway is configured or its CA is missing);
- the credential is missing, malformed or wrong, the job is not running, or the API cannot be
  reached (503);
- the gateway token is missing on either side (the API answers 503, the gateway refuses);
- the request log cannot be written: more than 5,000 unsent rows and every new request is
  refused until the API takes them;
- the engagement has no identification (target traffic), no scope, or no authorization.

### 9. Hooks for D-040 and D-041

`gateway.Policy` has two methods that do nothing yet:

- `inject_credentials(rules, headers)` (D-040): where a test account's session cookie or token
  will be added to an allowed request, after the tool's own headers and before the request is
  logged (the log never holds header values).
- `approved_write(rules, method, url, body_sha256)` (D-041): asked for every request whose
  method is not read-only. It returns nothing today, so every write is refused with
  "writes need a person's approval (D-041), which is not built yet". When the approval queue
  exists, it will return the approval that matches this exact request, and the gateway will
  send it once.

## Threat model

The question: what can a tool inside the worker do, if it is buggy (nuclei sending a POST) or
malicious (a compromised binary or template)?

**It cannot:**

- reach the internet, a target, or a passive source except through the gateway (no route; no
  external DNS);
- send a write method, a body, a WebSocket or any non-HTTP protocol to a target;
- reach a host outside its engagement's scope, port 25, or the deployment's own containers
  through the gateway;
- go over the engagement's rate ceiling, whatever its concurrency (requests queue or are refused);
- send target traffic without the engagement's identification, or with a forged one;
- use a finished or cancelled job's credential, or name another engagement in its credential;
- send a request the log does not record (the gateway refuses when the log is not being written);
- read the CA private key or the gateway token (not mounted in the worker).

**It still can:**

- send read-only requests to in-scope hosts within the ceiling. Those are the job.
- put data into URLs of GET requests to the passive sources (an exfiltration channel to a
  fixed list of public services) and into DNS questions for in-scope names. Both are logged.
- resolve in-scope names of another engagement while that engagement has a running job.
- **read and write the database**, because the worker still connects to it directly. With
  write access it could change an engagement's rules or another job's credential hash, or, in
  open mode, call the API as an owner. This is today's trust boundary and the reason for
  D-042's second half: once the worker talks to the API instead of the database, a malicious
  tool in the worker is held to its own job.

The gateway itself does not verify target certificates (as the tools did not), so on the path
between the gateway and a target a network attacker could read or change traffic. It verifies
passive sources and the Claude API.

## Operations

- `docker compose up` creates the CA, the gateway token and the volumes on first start. To
  rotate the CA, remove the `gateway-private` and `gateway-public` volumes and restart.
- Settings (gateway): `ATTACKLEDGER_API_URL` (default `http://api:8000`),
  `ATTACKLEDGER_GATEWAY_TOKEN` or `ATTACKLEDGER_GATEWAY_TOKEN_FILE`,
  `ATTACKLEDGER_GATEWAY_PASSIVE_HOSTS`, `ATTACKLEDGER_GATEWAY_SERVICE_HOSTS`,
  `ATTACKLEDGER_GATEWAY_DENY_HOSTS`. Worker: `ATTACKLEDGER_GATEWAY` (proxy address),
  `ATTACKLEDGER_GATEWAY_DNS`, `ATTACKLEDGER_GATEWAY_CA`.
- The request log: `GET /engagements/{id}/gateway-log` (any role on the engagement), with
  totals by verdict, kind and method and the latest rows.

## Not done here

- HTTP/2 to targets and to clients (everything is HTTP/1.1), DNS over TCP, and keep-alive to
  targets (a new connection per request).
- Credential injection and the approval queue (D-040, D-041): hooks only.
- A UI view of the request log (API only).
- The worker still uses the database directly (D-042).
