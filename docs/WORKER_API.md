# Worker API: the worker talks to the API, not the database (D-042)

Status: designed and built 2026-10-09 ("Keep SaaS possible", step 9
of `TARGET_ARCHITECTURE.md`, the worker half). This file is the design and the record of the
decisions taken while building it. `GATEWAY.md` named the gap this closes: the worker could read
and write the whole database, so a malicious tool inside it was held to nothing.

## What changes

Before, the worker held `DATABASE_URL`, the encryption master key, the blob volume and the
Anthropic API key, and ran every gate itself. Now:

- the worker has **no database credentials, no database network, no master key, no blob
  volume and no Anthropic key**. Its container is on one network, with the gateway only;
- it claims jobs, reads what a job needs, writes results, evidence and logs and reports status
  through **`/worker/*` routes on the API**, relayed by the gateway;
- every write is checked by the API against a **per-job capability**: the job kind decides what
  it may write, and a job token opens only its own job, only while it runs;
- the API keeps every gate it had: scope, redaction, the evidence chain (`append_evidence` with
  the right `source`), encryption (`blobs.put(..., engagement_id=)`), receipts only by people,
  the audit log and retention (which moves from the worker into the API).

```
  ┌──────────────── internal (internal: true) ───────────────┐
  │ ┌─────────┐   proxy 8080, DNS 53 (D-039)   ┌───────────┐  │       ┌──── control (internal) ───┐
  │ │ worker  │ ─────────────────────────────► │           │ ─┼──────►│  api  /gateway/*          │
  │ │ tools,  │   control 8081: /worker/* only │  gateway  │ ─┼──────►│       /worker/*  (relayed)│
  │ │ agent   │ ─────────────────────────────► │           │  │       └──────┬────────────────────┘
  │ └─────────┘                                └─────┬─────┘  │              │ database (internal)
  └──────────────────────────────────────────────────┼────────┘        ┌─────▼────┐
                                     egress, lab ──► targets            │    db    │
                                                     passive sources    └──────────┘
                                                     api.anthropic.com (the gateway adds the key)
```

## Decisions

### 1. The channel goes through the gateway

The worker reaches the API through a relay in the gateway (port 8081), not on a network shared
with the API.

- **Why not a network shared with the API.** One API process serves people and the worker, so a
  worker that can reach it can also call the people's routes. With no people and no token (open
  mode, local trials) that would make it an owner. A source-address check cannot be trusted
  behind the production proxy settings (`--forwarded-allow-ips *`), and a second API container
  for the worker adds another holder of the master key.
- **With the relay** the worker's network holds the gateway and nothing else. The relay forwards
  only `GET` and `POST` to paths matching `^/worker/[a-z0-9/_-]*$`, with only `Authorization` and
  `Content-Type`, bodies up to 16 MB, never to `/gateway/*` or a person's route. It
  authenticates nothing itself: the API checks every token.
- **It fits a hybrid service (D-042).** If the API is hosted later while the worker and gateway
  stay in the customer's network, the worker still has one way out, the gateway, for target
  traffic and for its channel. Nothing else needs a route.

### 2. Worker identity: a worker token

- The worker creates a 256-bit token on first start in the volume `worker-control`, which only
  the worker and the API mount (the API read-only), as the gateway does with `gateway-control`.
  `ATTACKLEDGER_WORKER_TOKEN` (on both) replaces the file.
- The token does two things: **claim a queued job** (`POST /worker/claim`) and **ping**
  (`GET /worker/ping`, the worker's health check). Nothing else.
- Without a token on the API the worker routes answer 503 (fail closed).

### 3. Job claiming: atomic, and the API runs the gates

`POST /worker/claim` takes the oldest queued job in one transaction (`SELECT ... FOR UPDATE SKIP
LOCKED` on Postgres; SQLite has one writer), marks it running and, before answering:

- checks the engagement again (`jobgates.check_engagement`; for agent runs the lane, its executor
  and `agenttools.check_lane`). A job that fails is marked failed with the reason;
- resolves a deferred pipeline step's targets from what earlier steps stored, and marks it
  skipped, with the reason, when there are none;
- splits the targets against the current scope and applies the module's `max_targets`. All the
  run targets and the overflow are stored as `remaining_targets` at once, so a job is never
  "done" with targets left, even if the worker dies: progress removes finished batches;
- issues two secrets and stores only their SHA-256: the **job token** (for the API) and the
  **gateway secret** (for the job's tools, D-039). They are different so that a tool, which gets
  the gateway secret in its arguments, does not get the job token;
- returns the job's specification: kind, run targets, the engagement's rules (scope, rate,
  identification, crawl depth, enabled modules), and the inputs that kind reads (below).

An agent run that a person queued for an outside driver (`driver`, D-031) is skipped by the
normal claim; `tools/agent_bridge.py` claims it by id.

### 4. Per-job capability

A job token opens only its own job (`/worker/jobs/{id}/...` with the matching id), and only
while the job is running and not finished. Every route also refreshes the job's heartbeat.

| Every job | |
|---|---|
| `POST heartbeat` | the job's status: `running`, or `cancelled` (the worker stops) |
| `POST log` | lines appended to the job's log (masked by the worker, capped by the API) |
| `POST progress` | targets of a finished batch; only targets the job still has |
| `POST finish` | the outcome; the API decides the status, writes the recon run's evidence and ends the token |

What a job may **write** (`POST results`, `agent/*`) is set by its kind, in one table in
`workerapi.py` (`WRITES`), which a test checks against the module registry:

| Kind | Writes |
|---|---|
| subdomains, resolve | observations: `sources`, `a`, `aaaa`, `cname` |
| ports | observations: `open_ports` |
| probe | observations: the probe fields (`url`, `port`, `scheme`, `status_code`, `title`, `tech`, `webserver`, `cdn`, `location`, `live`) |
| wellknown | endpoints; leads of kind `robots`, `security-txt`, `listing` |
| crawl, archive | endpoints |
| content | endpoints; leads of kind `listing` |
| jsanalyze | endpoints; leads of kind `graphql`, `secret`, `sourcemap` |
| nuclei | leads of kind `nuclei` |
| params | leads of kind `parameter` |
| paramclass | leads of kind `param-class` |
| dorks | leads of kind `dork` |
| agent | exchanges (up to the run's request budget, the lane's host only); evidence (`source="agent"`), item marks and leads (kind `agent`) through the agent's three ledger tools |

Every host and URL is checked against the engagement's current scope (refused rows are counted,
never stored). Redaction (D-038) runs in the API, before storage, whatever the worker sent.
Endpoints and leads are deduplicated by the API. Rows carry the job's id, the engagement's id
and nothing the worker chose.

What a job may **read** is what its claim returned, and nothing more: there is no read route.

| Kind | Inputs in the claim |
|---|---|
| probe | the latest open ports per host |
| nuclei | the plan: cluster representatives, stack tags per URL, URLs on golden hosts |
| paramclass | the hidden parameters found by `params` |
| agent | the lane context (`executors.lane_context`, items, rules, recon for the lane's host only), the run's limits |

A job token can never: read or write another job or engagement, read a blob, write evidence of
another `source`, close a lane or sign a receipt (no route exists), change scope, rules,
authorization, members or settings, or call a person's route (the relay does not forward them).

### 5. Blobs: the API encrypts, the worker has no key

Only agent runs store blobs (their HTTP exchanges and notes). The worker sends the exchange
(request line and headers, response status, headers and body) to
`POST /worker/jobs/{id}/agent/exchange`; the API checks it (read-only method, the lane's host,
in scope, the request budget, the identification rebuilt from the engagement), redacts it,
stores it with `blobs.put(..., engagement_id=)` and answers with the exchange id and the
redacted view the model may see. So the master key, the engagement keys and the blob volume
stay with the API. A write-only blob path for the worker would still need the engagement key
to encrypt, which is the thing that must not be there.

Exchange ids map to blob hashes in the table `agent_exchanges` (migration `0020`), for running
agent jobs only: the rows are deleted when the job ends. `add_evidence` cites exchange ids, so the
worker cannot make evidence point at a hash it did not get from the API for this run.

### 6. Agent runs: the Anthropic key moves to the gateway

The key was in the worker's environment. Tools run as the same user as the worker process, so
a compromised tool could read it from `/proc`. Now the gateway holds it (`ANTHROPIC_API_KEY` on
the `gateway` service) and adds `x-api-key` to the Claude API calls of agent jobs, after removing
any `x-api-key` or `Authorization` the client sent; without a key it refuses them (503). The
worker's client sends a placeholder. This is the same pattern D-040 plans for test accounts:
credentials are added at the gateway, never held where untrusted code runs.

- Considered: keeping it in the worker. Simpler, but it leaves the worker container holding a
  secret with a cost attached, which any tool could take.
- The gateway already sees these calls in clear (it terminates TLS to check the route), so it
  learns nothing new; its logs never hold header values.
- The model loop, its limits and the cost estimate stay in the worker, unchanged (D-025). The
  ledger tools (`add_evidence`, `mark_item`, `record_lead`) run in the API through
  `POST /worker/jobs/{id}/agent/call`, with the same `agenttools.Toolbox` code and gates as
  before, re-checked on each call (lane not closed, engagement authorized, content not
  deleted). `http_request` is checked twice: in the worker before sending (first layer), and in
  the API when the exchange is recorded.

### 7. Retention and stale jobs run in the API

A maintenance thread in the API (`workerapi.maintenance`, started by the API's lifespan):

- every 60 seconds, `vault.apply_retention` (as the worker did), with the same audit entries;
- every 15 seconds, marks a running job whose heartbeat is older than 120 seconds failed
  (`interrupted`), and ends its tokens. The worker heartbeats every 15 seconds while a job runs,
  also while a tool prints nothing. The old start-up rule ("every running job is stale when a
  worker starts") is gone: it would let one worker's token end other workers' jobs. A restarted
  worker's jobs are marked within two minutes instead.

`ATTACKLEDGER_MAINTENANCE_SECONDS=0` turns the thread off (tests do; a second API process
should too, although both passes are safe to run twice).

### 8. Performance: batches

Recon writes many rows. The worker buffers observations, endpoints and leads and sends them in
one call per target batch (and whenever 2,000 rows are waiting), up to 5,000 per call; the API
writes each call in one transaction. Logs go one call per line (a job writes tens of lines),
heartbeats every 50 tool output lines and every 15 seconds. Measured on the lab (below).

### 9. Migration and upgrade

Migration `0020` adds `jobs.worker_token_sha256`, `jobs.heartbeat_at`, `jobs.driver` and the table
`agent_exchanges`. An existing install upgrades with the usual `docker compose up -d --build`:

- the new `worker-control` volume is created; the worker writes its token there on first start
  and the API reads it on each call (no restart order to follow);
- the database leaves the `internal` network; the worker no longer gets `DATABASE_URL`, the
  master key or the blob volume (remove them from your own overrides if you added them);
- move `ANTHROPIC_API_KEY` nowhere: it stays in `.env`, and the compose file now passes it to the
  gateway instead of the worker;
- a job that was running during the upgrade has no heartbeat and is marked interrupted within two
  minutes, as after any worker restart.

## Threat model, after

A buggy or malicious tool, or the whole worker process (tools run as the worker's user, so a tool
can read what the worker holds: the worker token and the tokens of its running jobs):

**It cannot:**

- connect to the database (no route; no credentials), read the master key, an engagement key or a
  blob, or the Anthropic key;
- reach the API except `/worker/*` through the relay;
- read anything but the specifications of the jobs it claims;
- write to another job or engagement, or to its own job after the job ended or was cancelled;
- write rows its job kind does not write, rows out of scope, unredacted rows (when redaction is
  on), evidence with a source other than its kind's, a receipt, scope or rules;
- change another job's credentials, or any person's data;
- everything in `GATEWAY.md`'s list (traffic is unchanged).

**It still can:**

- claim queued jobs with the worker token and run them as the worker would, each held to its own
  engagement's rules and its kind's capability. A compromised worker is the worker for every job
  it takes; that is the remaining trust, and it is per job;
- write wrong content inside its own job: the API cannot know what a target really answered. The
  gateway's request log, written by the gateway and not by the worker, is the independent record
  of what was sent;
- fail its own jobs, or hold them running until the heartbeat timeout.

## Not done here

- Workers in more than one place (several worker tokens, per-worker job ownership). One token per
  deployment, as one gateway.
- Checking an agent's exchange against the gateway's log before it becomes evidence.
- TLS between the gateway and the API (one Docker network today; a hosted API would need it).
