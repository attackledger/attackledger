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
                      internal network (internal: true: the worker and the gateway, nothing else)
  ┌─────────┐                                                     ┌──────────────┐
  │ worker  │── HTTP proxy, CONNECT (job-<id>.<tool>:<secret>) ──►│              │── egress network ──► targets
  │ tools,  │── DNS (A/AAAA/CNAME) ──────────────────────────────►│   gateway    │                      passive sources
  │ agent   │── port probes (CONNECT + X-AttackLedger-Probe) ────►│              │                      api.anthropic.com
  │         │── control port 8081: /worker/* only (D-042) ───────►│  - TLS CA    │                      (the gateway adds the key)
  └─────────┘                                                     │  - limiter   │── lab network ─────► lab targets
  ┌─────────┐   database network       control network            │  - log queue │   (internal: true)   (benchmark: countproxy
  │   db    │◄──────────────── api ◄── /gateway/*, relayed ───────┤  - relay     │                       → Juice Shop)
  └─────────┘                          /worker/* (tokens)         └──────────────┘
```

| Part | Where | What it does |
|---|---|---|
| Proxy | `server/app/gateway.py`, port 8080, on the worker's network only (and loopback, for the healthcheck) | HTTP/1.1 forward proxy. Plain `http://` requests in absolute form; `https://` through CONNECT, always TLS-terminated with a deployment CA. Every request is parsed (h11), checked, re-serialized and sent on a new upstream connection |
| CA | `/data/gateway` (private volume), `/data/gateway-public/ca.pem` | Created on first start (EC P-256, 5 years). Leaf certificates per host, in memory and in a private temporary folder. Only the worker mounts the public certificate |
| DNS | same process, UDP 53, on the worker's network only | Answers A, AAAA and CNAME questions for names in scope of an engagement that has a running job; refuses everything else |
| Rules | `GET`/`POST /gateway/*` on the API | The gateway asks the API who a job credential belongs to and what that engagement's rules are; it holds no database credentials |
| Request log | table `gateway_requests` (migrations `0019`, `0025`) | One row per request, probe and DNS question, allowed or refused, with the reason; a placeholder (`unlogged`) for a row the API could not store (decision 10). Read with `GET /engagements/{id}/gateway-log` |
| Worker client | `server/app/egress.py` | Builds each job's credential, the proxy URL and environment per tool, the urllib opener, the resolver address and the port prober |
| Control relay | same process, port 8081, on the worker's network only | Forwards the worker's `GET`/`POST /worker/*` calls to the API, with only `Authorization` and `Content-Type`; refuses every other path (D-042, `WORKER_API.md`) |

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

- When the worker claims a job, the API creates a 256-bit secret and stores only its SHA-256
  (`jobs.gateway_secret_sha256`; before D-042's worker half the worker made it). The secret
  lives in the worker's memory and in the environment and arguments of that job's tool
  processes, never in the job log (masked). It is not the job's API token, which tools never get.
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
| wellknown | AttackLedger fetcher (urllib) | explicit proxy handler |
| crawl | katana | `-proxy`, `-r` |
| archive | gau, waybackurls | `--proxy` / environment; passive allowlist |
| content | feroxbuster | `--proxy` (and the baseline and listing checks through urllib) |
| jsanalyze | AttackLedger fetcher (urllib) | explicit proxy handler |
| params | Arjun (requests) | `HTTP(S)_PROXY` environment |
| nuclei | nuclei | `-p`, `-pi` (its internal requests too), `-r <file>` |
| agent | `agenttools` urllib transport, `anthropic` client | explicit proxy handler / `DefaultHttpxClient(proxy=…, verify=CA)` |
| paramclass, dorks | none (computed) | no egress |

Each tool also gets `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` (both cases) and
`SSL_CERT_FILE` pointing at the gateway CA, and nothing else from the worker's environment
(which no longer holds a database URL or an API key anyway, D-042). Whether a tool honours the proxy is not taken
on trust: the worker has no other route, so a tool that ignores it fails.

### 3. Rules come from the API, not the database

The gateway is the one container that talks to the internet and parses what targets send, so
it holds no database credentials. It gets rules and writes its log through three API routes
(`authz.py` permission `gateway`), authenticated with a gateway token that only the gateway
and the API can read (a file the gateway creates in a volume shared with the API, or
`ATTACKLEDGER_GATEWAY_TOKEN`). The token belongs to one organization: this one to the default
organization; another organization's gateway gets its own from `python -m app.orgs
gateway-token`, and sees only that organization's jobs, scopes and log (`ORGANIZATIONS.md`):

| Route | Answers |
|---|---|
| `POST /gateway/session` | `{job_id, secret}` → the job's engagement, module traffic class and rules (scope, rate, identification, redaction), or why not |
| `GET /gateway/dns-scopes` | scope rules and rate of every engagement with a running job (for DNS) |
| `POST /gateway/log` | a batch of request-log rows |

With D-042 in mind: in a later hybrid service the API and ledger may be hosted while the
worker and gateway stay in the customer's network. The gateway talks only to the API, over an
authenticated channel, so it needs no change then. Since 2026-10-09 the worker does too
(`WORKER_API.md`): it has no database, and its calls to the API go through the gateway's relay.

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
  only on port 443 (HTTPS) or 80 (HTTP: waybackurls asks the web archive over plain HTTP),
  only with GET, HEAD or OPTIONS and no body, with the upstream certificate verified, without the research identification (it is not target traffic and would name the
  researcher to a third party), paced at 10 requests per second per host, logged with kind
  `passive`, and **not** counted against the engagement's ceiling. A host that is also in the
  engagement's scope is treated as a target.
- **The Claude API** (`api.anthropic.com`, or `ATTACKLEDGER_GATEWAY_SERVICE_HOSTS`) is a
  service host: agent jobs only, `POST /v1/messages` and `/v1/messages/count_tokens` only,
  upstream certificate verified, logged with kind `service`, not counted. Headers and bodies
  are never logged. The API key is the gateway's (`ANTHROPIC_API_KEY` on the gateway): it is
  added as `x-api-key` after any `x-api-key` or `Authorization` the client sent is removed, and
  without it these calls are refused with 503. The worker holds no key (D-042).
  The body is read and parsed strictly (a key given twice is refused) and sent only if it carries
  the keys an agent run sends (`gateway.SERVICE_BODY_KEYS`), custom tools only and no `url`
  source in its messages or system prompt: server tools (web fetch, web search, code execution),
  the MCP connector and URL image or document sources would make Anthropic's servers reach hosts
  the gateway never checks (security review GW-1, `docs/security-review/GATEWAY.md`).

### 5. Rate ceiling

One limiter per engagement in the gateway process, shared by every tool, job and worker. It
is a token bucket with *rate* tokens in which each token comes back 1.05 seconds after it was
spent, so no 1.05-second window (and therefore no 1-second window, with 50 ms for network
jitter) holds more than *rate* requests. A plain refilling bucket with burst *B* lets *B* +
*rate* requests into one second; this is the form that makes "peak at or under the limit"
hold. The token is taken after the upstream connection is open and just before the request
head is written. Waiting requests queue in order; one that would wait more than 30 seconds
is refused with 429. The upstream connection itself waits first for a token of a second
limiter per engagement at the same rate (per host for passive sources), so connections and TLS
handshakes are paced too, and a request refused for the rate has not connected (security review
GW-2). Port probes take a token too (D-014). DNS questions have their own limiter per engagement
at the same rate.

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
`Transfer-Encoding`), and a write a person approved (decision 9). Refused: every other method
(POST, PUT, PATCH, DELETE without an approval; TRACE, DEBUG, PROPFIND, ... always), method override headers (`X-HTTP-Method-Override` and the like) and `_method=`
parameters naming another method (a method name only: Arjun and scanners send `_method` with
numbers and payloads, which no framework reads as a method), `Upgrade` (WebSocket, h2c), `https://` in absolute form (it
must use CONNECT), a `Host` that differs from the CONNECT target, credentials in the URL, and
port 25. The identification is always set by the gateway: any header of the same name sent by
the tool is removed first, then the engagement's research header and user agent are added. An
engagement without either gets no target traffic at all (D-008). Hop-by-hop headers and
`Proxy-Authorization` are never forwarded. Redirects are never followed by the gateway; a tool
that follows one sends a new request, which is checked like any other.

Addresses: the gateway resolves the host itself, refuses loopback, link-local (cloud metadata),
multicast and unspecified addresses, the cloud metadata services outside link-local
(`gateway.METADATA_ADDRESSES`: Alibaba Cloud, AWS over IPv6, Azure's WireServer, Oracle Cloud
Classic) and the deployment's own containers (`ATTACKLEDGER_GATEWAY_DENY_HOSTS`, default
`gateway.DENY_HOSTS`: `db,api,api-control,api-default,web,worker,gateway,gateway-internal,gateway-lab,caddy,lab-proxy,...`),
and every address in the subnets of the gateway's own networks but the lab's (security review
GW-8), and connects to the address it checked, so a DNS answer cannot change between check and use.
The Docker host has an address on each bridge network the gateway is on (172.x.0.1 on `default`),
and the deployment's containers are there too; a real internal target never is, because a
destination inside the subnet of one of the gateway's interfaces is routed to Docker, not to a
customer's network. The gateway reads those subnets from `/proc/net/route` and `/proc/net/if_inet6`
every minute; `ATTACKLEDGER_GATEWAY_TARGET_NETWORKS` names the networks that hold targets
(`gateway-lab`, the gateway's own alias on the lab network; an address or a subnet works too, for
a gateway on a customer's LAN). The internal networks give the host no address at all
(`com.docker.network.bridge.inhibit_ipv4`), so the worker cannot reach the host either.
Docker answers a service name with its address on one shared network only, so a container the
gateway shares two networks with has a network alias for each in the compose files, and the
aliases are in the list (security review GW-6; a test checks the compose files). Other private addresses
are allowed: an internal pentest needs them.

Refusals are answered with status 403 (policy), 400 (a request or header it cannot write), 407
(credential), 429 (rate wait) or 503 (gateway cannot check or log), the header `X-AttackLedger-Gateway: refused` and the reason as
plain text. When the target itself cannot be reached (does not resolve, connection refused,
TLS failure, no response), a scanner gets what the target would have given it: a closed
connection, never a 502 it could record as the target's answer (measured: httpx recorded a
gateway 502 as a live HTTPS service before this). AttackLedger's own clients (the agent's
tool, the worker's fetcher) send `X-AttackLedger-Errors: respond` and get a 502 with the
reason instead; the header is never forwarded. Each request is logged as `allowed`,
`refused` (a rule) or `failed` (the target could not be reached).

Tools get the gateway as an address (`http://job-…@172.x.x.x:8080`), not as the name
`gateway`: httpx and katana resolve the proxy's name with the resolver they are given, which
is the gateway's, and it answers in-scope names only.

### 8. Fail closed

Nothing is sent when:

- the gateway is down: the worker has no other route (and it refuses to start a job that
  sends traffic when no gateway is configured or its CA is missing);
- the credential is missing, malformed or wrong, the job is not running, or the API cannot be
  reached (503);
- the gateway token is missing on either side (the API answers 503, the gateway refuses);
- the request log cannot be written: more than 5,000 unsent rows and every new request is
  refused until the API takes them. A row the API refuses as such does not hold the log up: it
  is set aside and a placeholder takes its place (decision 10); a failure of the API itself does;
- the engagement has no identification (target traffic), no scope, or no authorization.

### 9. Test accounts and approved writes (D-040, D-041)

Built 2026-10-09 (migration `0021`); the approval design is `APPROVALS.md`. Both are for agent
runs only (traffic class `agent`): a recon tool that asks for either is refused, so recon stays
unauthenticated and read-only by construction.

**As a test account.** An agent run asks with the request header `X-AttackLedger-As: <label>`,
which its tool sets (`agenttools`, `as_account`), never the model, and which the gateway removes.
A per-job parameter was the alternative; a header lets one run compare two accounts (A reads B's
object) request by request. The gateway then:

- refuses unless the engagement's evidence redaction is on (D-038);
- asks the API, `POST /gateway/account` with the job's credential, the label and the host. The
  API answers only for a running agent job, only for a host named for that account and in scope,
  and only while the engagement's content exists. The answer (the account's headers) is cached
  for 2 seconds, so a replaced or deleted account takes effect within 2 seconds. The worker never
  holds it: it is not in the claim, the lane context, the worker's channel or any job token;
- replaces any header of the same name the tool sent (a tool's own `Cookie` never reaches the
  target alongside the account's) and sends `Accept-Encoding: identity`. A target that compresses
  anyway has its gzip or deflate body decoded before the scrub; a body in another encoding is
  withheld (security review GW-3);
- reads the response whole (up to 20 MB) and scrubs it before it goes back: every value the
  account's headers carry (whole values, each cookie value, a bearer token, each also
  URL-decoded, URL-encoded, HTML-escaped and with JSON-escaped slashes: GW-4) becomes a redaction
  marker wherever it appears, and cookies, tokens and other credentials are redacted
  (`redact.header_value`, `redact.data`), so a target that echoes the session or rotates it
  (`Set-Cookie`) does not hand it to the worker. Measured in the lab with Juice Shop's 743-character
  tokens and with an upstream that echoes them in plain text;
- logs the request with the label (`gateway_requests.account`), never a header value.

**Headers from people and the API.** A test account's headers and an approved request's are
checked where they come in (`gateway.header_problem`: a header name is a token; a value has no
control character, nothing outside Latin-1, no space at either end), and again by the gateway: a
test account with such a header is refused when its headers arrive, before an approval is used;
an approved request with one is a `refused` row with its approval id; and every request head is
built by h11 before anything is connected, so a header it would not write is a refusal in the log,
never a connection ended by an error (security review GW-10). No message repeats a value.

**Approved writes.** A write is sent only with the header `X-AttackLedger-Approval: <id>`, from an
agent job, to a target, as POST, PUT, PATCH or DELETE. The gateway reads the body (up to 1 MB),
fetches the account if one is named, then, last, asks the API to use the approval
(`POST /gateway/approval`: job credential, id, method, URL, body SHA-256, account). The API checks
that it is this job's, approved, not expired and not used, that the method, URL (normalised: case,
default port, no fragment), body and account are the approved ones, marks it sent and writes the
`write.sent` audit entry in one transaction. From then on it is used, whether or not the target
answers. The gateway sends the approved request itself: the approved headers, not the tool's, then
the identification and the account, under the same scope, address, rate and logging rules as
every request. The log row carries the approval id; the API takes the response status from it
(or marks the write failed with the reason).

**Requests the gateway answers itself.** katana, given `-proxy`, first asks its proxy whether it
is Burp Suite (`GET http://burpsuite/`, from ProjectDiscovery's proxy helper; katana has no flag to
skip it, and ignores the proxy environment, so it needs `-proxy`). The gateway answers it with a
404 from a job's credential, sends nothing and logs nothing: it is the tool talking to its proxy,
not a request towards anyone. Every other request to that name is refused as out of scope.

### 10. The request log: rows the API cannot store (2026-10-10)

The gateway queues every row and sends the oldest 500 to `POST /gateway/log` every half second.
A batch that is not written stays queued and is sent again, and with 5,000 rows waiting the
gateway refuses all traffic (decision 8). Before this, one row the API refused (a test-account
label longer than its 16 characters, sent by any tool in the worker: security review GW-11) made
the API refuse the whole batch, so the log stopped for good and, once 5,000 rows waited, every
engagement's traffic with it. Now a row the API definitively refuses is taken out of the queue
without leaving the log silent:

- **The API answers per row.** It writes every row it can and answers
  `{"written": n, "unlogged": [{"index": i, "reason": "<field>: <why>"}]}`. In place of each row it
  cannot store it stores a placeholder (`app/gatewaylog.py`): verdict `unlogged`, the engagement,
  job, tool, kind, method, host, test-account label and approval id the row named where they are
  valid, **no URL** (whatever was refused may be in it), no counts, and why it was not stored. The
  engagement's log (`GET /engagements/{id}/gateway-log`) therefore shows, in `by_verdict.unlogged`,
  how many requests it could not record. A placeholder does not report an approved write's outcome:
  that write stays `sent` without a response status. Values the database cannot hold but the API
  can keep are kept instead (a NUL or a lone surrogate becomes U+FFFD; counts past BIGINT are its
  maximum; a port, status or id out of range is none).
- **The gateway sets the row aside** in its quarantine file (`ATTACKLEDGER_GATEWAY_QUARANTINE`,
  default `/data/gateway/log-quarantine.jsonl`, the gateway's private volume, mode 0600): one JSON
  line per row, `{"set_aside_at", "why", "row"}`. The row is what the API was sent, so the file holds
  nothing the log does not: URLs and reasons redacted as in the log, test accounts by label, never a header
  value, a body or a secret. It is bounded (`gateway.QUARANTINE_MAX_BYTES`, 16 MiB): past that a
  row is only counted (the gateway prints how many were not kept), and its placeholder is in the
  log all the same. A row cut short (the gateway stopped mid-write) cannot swallow the next one:
  a row is written on a line of its own.
- **Deleting an engagement's content reaches the file** (2026-10-11, security review RETENTION.md,
  RET-1). The API cannot reach the gateway's private volume, so the gateway asks: at start and every
  minute (`QUARANTINE_PURGE_SECONDS`) it sends the engagement and job ids its file holds to
  `POST /gateway/content-deleted` (gateway token), which answers those whose engagement's content
  was deleted, and the gateway rewrites the file without their rows (and without lines that are not
  a whole row), atomically, mode 0600. A row that names neither an engagement nor a job (a request
  with no valid job credential) cannot be attributed and stays. Without an answer nothing is
  removed and the next pass asks again; a gateway that was down at the deletion purges at its next
  start. Encrypting the rows under the engagement's key instead would shred them with the key, also
  in copies, but the gateway holds no engagement key by design (D-042) and the file is for an
  operator to read with `cat`; the gateway's volumes are not in the backups (`tools/backup.sh`),
  so purging in place leaves no copy behind.
- **A whole batch refused with 400, 413 or 422** (a body limit in front of the API, or a row that
  breaks the request itself) is halved until the row the API refuses is alone. Before that row is
  set aside, the gateway sends its placeholder by itself: only if the API takes it is the row the
  problem; if the API refuses the placeholder too, the row stays queued, as for any other failure.
  (An API older than the gateway, which knows no `unlogged` verdict, refuses the placeholder: the
  log then stops at that row as it did before. The gateway and the API run from the same image.) Measured in the tests: 150 rows with 2 such rows, 64 per batch,
  are written in at most 30 calls, in order.
- **Every other failure keeps the rows queued and is retried**, as before: no answer, a 5xx, 401,
  403, 404 or 429. The gateway still fails closed when the API or the database is down, its token
  is wrong, or the database refuses a row (a 5xx: nothing in the API's checks predicted it, and
  resending after a fix writes it).

The byte counts and the duration are 64-bit since migration `0025` (they were 32-bit INTEGER on
Postgres, where a response past 2 GiB did not fit; the API had kept such counts as 2^31 - 1).

## Threat model

The question: what can a tool inside the worker do, if it is buggy (nuclei sending a POST) or
malicious (a compromised binary or template)? Tools run as the worker's user, so the answer
covers the whole worker process too.

**It cannot:**

- reach the internet, a target, or a passive source except through the gateway (no route; no
  external DNS);
- send a write method or a body to a target unless a person approved that exact request, for
  an agent run, and only once (decision 9); or a WebSocket or any non-HTTP protocol at all;
- get a test account's session: the gateway adds it, and scrubs it from the response;
- reach a host outside its engagement's scope, port 25, or the deployment's own containers
  through the gateway, or the Docker host on any network the gateway or the worker is on (the
  worker's network gives the host no address; the gateway refuses its own networks' subnets but
  the lab's);
- go over the engagement's rate ceiling, whatever its concurrency (requests queue or are refused);
- send target traffic without the engagement's identification, or with a forged one;
- use a finished or cancelled job's credential, or name another engagement in its credential;
- send a request the log does not record (the gateway refuses when the log is not being written;
  a row the API cannot store is a placeholder in the log and is kept in the gateway's quarantine file
  until the engagement's content is deleted);
- read the CA private key or the gateway token (not mounted in the worker);
- **connect to the database** (it is on no network with it and has no credentials), or read the
  master key, an engagement key, a blob or the Anthropic API key (none is in the worker);
- call any API route but `/worker/*` (the relay forwards nothing else), or, with a job's token,
  touch another job or engagement, write rows its job kind does not write, write evidence of
  another source, close a lane, or change scope, rules or people (`WORKER_API.md`).

**It still can:**

- send read-only requests to in-scope hosts within the ceiling. Those are the job.
- put data into URLs of GET requests to the passive sources (an exfiltration channel to a
  fixed list of public services) and into DNS questions for in-scope names. Both are logged.
- resolve in-scope names of another engagement while that engagement has a running job.
- reach, through the gateway and within its scope, the Docker host's addresses on networks the
  gateway is not on (another project's bridge, `docker0`, the host's LAN address), if a scope
  name resolves to one: the gateway cannot know them from its container. A host firewall rule
  closes it (`docs/INSTALL.md`, section 6).
- claim queued jobs with the worker token and run them as the worker would, each held to its
  own engagement's rules and its kind's capability, and write wrong content inside the jobs it
  runs (the API cannot know what a target answered; the gateway's log, written by the gateway,
  is the independent record of what was sent).

The gateway itself does not verify target certificates (as the tools did not), so on the path
between the gateway and a target a network attacker could read or change traffic. It verifies
passive sources and the Claude API.

## Operations

- `docker compose up` creates the CA, the gateway token and the volumes on first start. To
  rotate the CA, remove the `gateway-private` and `gateway-public` volumes and restart.
- Settings (gateway): `ATTACKLEDGER_API_URL` (default `http://api:8000`),
  `ATTACKLEDGER_GATEWAY_TOKEN` or `ATTACKLEDGER_GATEWAY_TOKEN_FILE`,
  `ATTACKLEDGER_GATEWAY_PASSIVE_HOSTS`, `ATTACKLEDGER_GATEWAY_SERVICE_HOSTS`,
  `ATTACKLEDGER_GATEWAY_DENY_HOSTS`, `ATTACKLEDGER_GATEWAY_CONTROL_PORT` (default 8081, 0 turns
  the relay off), `ANTHROPIC_API_KEY`, `ATTACKLEDGER_GATEWAY_LISTEN` (names or addresses to listen
  on; the compose files set `gateway-internal`, the gateway's alias on the worker's network; a name
  that is not one of the container's addresses within 30 seconds stops the gateway; empty: every
  interface) and `ATTACKLEDGER_GATEWAY_TARGET_NETWORKS` (names, addresses or subnets marking the
  gateway's networks that hold targets; the compose files set `gateway-lab`; empty: none of its own
  networks is a target), `ATTACKLEDGER_GATEWAY_QUARANTINE` (the file for request log rows the API
  refused, default `/data/gateway/log-quarantine.jsonl`). Worker: `ATTACKLEDGER_GATEWAY` (proxy address),
  `ATTACKLEDGER_GATEWAY_DNS`, `ATTACKLEDGER_GATEWAY_CA`, `ATTACKLEDGER_WORKER_API` (default
  `http://gateway:8081`).
- The request log: `GET /engagements/{id}/gateway-log` (any role on the engagement), with
  totals by verdict, kind and method and the latest rows. `unlogged` rows are placeholders for
  rows the API could not store (decision 10); the rows themselves are in the gateway's quarantine
  file (`docker compose exec gateway cat /data/gateway/log-quarantine.jsonl`), and the gateway's
  output says each time one is set aside. `bytes_sent` is the request as the
  gateway wrote it upstream, head and body (it was always 0 before 2026-10-09); each row names the
  test account (`account`) and the approval (`approval_id`) it used, if any.
- Tools never check for updates: every ProjectDiscovery tool (subfinder, dnsx, httpx, katana,
  nuclei) runs with `-duc` (`egress.tool_flags`). Without it each asks `api.pdtm.sh` (nuclei also
  `api.github.com`) on every start, which the log showed as refused, out-of-scope CONNECTs
  (measured: 14 for one run of each, none with `-duc`). Their cloud features need
  `PDCP_API_KEY`, which no tool's environment carries.

## Not done here

- HTTP/2 to targets and to clients (everything is HTTP/1.1), DNS over TCP, and keep-alive to
  targets (a new connection per request).
- ~~Credential injection and the approval queue (D-040, D-041): hooks only.~~ Built 2026-10-09
  (decision 9, `APPROVALS.md`).
- Checking a recorded exchange against the gateway's own log row before it becomes evidence.
- A UI view of the request log (API only).
- ~~The worker still uses the database directly (D-042).~~ Done 2026-10-09: `WORKER_API.md`.
