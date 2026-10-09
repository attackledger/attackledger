# Architecture

This file describes what runs today. Where the architecture is going: `TARGET_ARCHITECTURE.md`.

AttackLedger has one job: **prove what was tested**. Every part of the system
either produces evidence, gates who may produce it, or turns it into a
verifiable statement of coverage.

```
              ┌──────────────────── module registry (modules.py) ────────────────────┐
              │ kind · input (roots/hosts/urls) · traffic (passive/dns/target) · http │
              │ opt-in · after · produces · pipeline module                           │
              └───────────────────────────────────────────────────────────────────────┘
                 │ API gates            │ worker dispatch        │ UI pipeline steps
                 ▼ (jobgates.py)        ▼ (RUNNERS, checked)     ▼ (GET /modules)
   RECON  ──► Observation · Endpoint · Lead ──► lane context ──► HUNT (executor: manual | agent)
   jobs        (per host, in scope only)        (executors.py)          │
                                                                       ▼
   ENGAGEMENT ── pack (lanes × items × controls) ──► LEDGER: items · evidence (hash chain)
   scope · authorization · identification ·                         │
   rate limit · opt-in modules                                      ▼
                                                  receipt (manifest hash) ──► coverage ──► report
                                                                              controls      + offline verifier
```

## Layers

| Layer | Code | Responsibility |
|---|---|---|
| Engagement | `models.Engagement`, `scope.py` | Scope rules (fail-closed), authorization, research identification, a rate limit that caps every step, opt-in modules |
| Methodology | `packs.py`, `packs/*.yaml` | Lanes, items, lane dependencies and control mapping, all as data. Loading fails closed |
| Recon | `modules.py`, `jobgates.py`, `worker/worker.py` | Job kinds defined once in the registry, gated twice (when queued and when run), executed in batches with a watchdog |
| Recon output | `Observation`, `Endpoint`, `Lead` | Per-host facts, URLs and things worth a hunter's attention. Secrets are stored masked and hashed |
| Hunt | `executors.py` | Who works a lane, what they may read (the lane context) and what they may write |
| Ledger | `ledger.py`, `gates.py` | Append-only, hash-chained evidence. Item rules (done needs evidence, N/A needs a reason). Receipts and stale detection |
| Assurance | `report.py`, `tools/verify_report.py`, `/controls` | Coverage statement, control evidence and an offline-verifiable report |

## Contracts

### Adding a recon module

1. Add a `Module(...)` entry to `server/app/modules.py`. Set the input type and
   traffic class honestly. Set `http=True` if it sends HTTP, which makes the research
   identification mandatory. Set `opt_in=True` if programs commonly forbid it.
2. Add a runner `run_<kind>(run, targets) -> int` to `worker/worker.py` and register
   it in `RUNNERS`. The worker refuses to start while the registry and `RUNNERS`
   disagree.
3. Write only to `Observation`, `Endpoint` or `Lead`, and only for hosts that pass
   `scope.in_scope`.
4. Respect `engagement.rate_limit_rps` as a ceiling. A test fails if any tool is
   given more.

The API gates, the UI step, the opt-in switch and the traffic label all follow from
the registry entry.

### Gates a job passes (`jobgates.py`)

The API applies these when a job is queued. The worker applies them again when the
job runs.

1. The module exists.
2. Authorization is recorded.
3. A scope is defined.
4. If the module is opt-in, it is enabled for this engagement.
5. If the module sends HTTP, a research header or user agent is set.
6. Every target is in scope for the module's input type.

A run that stops at the time limit is `partial` and lists its remaining targets. It
is never `done`.

### Working a lane (`executors.py`)

- **Read:** `GET /lanes/{id}/context` returns the lane's items, the engagement rules
  and the recon output **for the lane's host only**.
- **Write:** evidence (hash-chained), items marked done (with evidence) or N/A (with
  a reason), and leads for other lanes.
- **Never:** issue a receipt or act outside the context's scope and rules.

The manual executor is a person using the UI or API. The agent executor uses
exactly the same write paths and gets no shortcut that a person does not have.

### Agent runs (v0.6)

An agent run is a job of kind `agent` tied to one lane (`jobs.lane_id`, migration
`0009`). The worker runs a manual tool-use loop over the Messages API
(`agentloop.py`, model `claude-opus-5-5`, adaptive thinking, server-side refusal
fallback). Every tool call goes through `agenttools.Toolbox`:

| Tool | Gate |
|---|---|
| `http_request` | Lane host only, inside the scope rules; GET, HEAD and OPTIONS only (D-024); research identification always sent and not overridable; no redirects; spaced to the rate limit; request budget per run |
| `add_evidence` | Cites exchanges from this run only (or a note); hash-chained; marked `[agent]` |
| `mark_item` | Open items only; done needs evidence on the item, N/A needs a reason |
| `record_lead` | Lane host only; deduplicated |
| `finish` | Ends the run with a summary for the reviewer |

There is no tool that closes a lane. Each exchange is stored in the content-addressed
blob store (`blobs.py`, volume shared by API and worker), so an evidence hash can be
opened and checked (`GET /blobs/{sha256}`, served as sandboxed plain text, only for
hashes that evidence cites). Before an exchange is stored, credentials and some personal
data are replaced by a hash marker (`redact.py`, D-038); the model sees the same redacted
exchange. Target content is framed as untrusted data in the
prompt and in every tool result. The gates are checked when the run is queued and
again when it starts. A run that ends without `finish`, at the turn limit or at the
time limit is `partial`, never `done`; a model refusal fails the job.

The Anthropic API key is set on the worker only. The API learns that agents are
enabled from `ATTACKLEDGER_AGENTS_ENABLED`, which compose derives from the key.

### Evidence and receipts

- Evidence is append-only and chained per engagement:
  `chain_hash = sha256(prev_hash + record)`.
- A receipt is the hash of a lane's manifest (items and evidence), **signed by the
  person who reviewed and closed the lane** (D-018). Any later change makes it stale
  (shown as VOID). Only people close lanes; executors cannot.
- With people signed in, the reviewer's browser signs the receipt with a key that never
  leaves it (Ed25519, or ECDSA P-256; D-033). The server checks the signature against the
  lane's current manifest and chain head and stores it with the public key. Without
  accounts, or when the engagement allows it, a close with only a name is accepted and
  marked as not a cryptographic signature.
- With `ATTACKLEDGER_TSA_URL` set, each receipt is also timestamped by that RFC 3161
  authority (D-034): only a hash of the manifest hash and signature is sent. The verifier
  checks the token and the authority's certificate chain against roots the reader trusts.
- The report embeds everything needed to rebuild every receipt and walk the chain
  offline, using only the Python standard library.

### Traffic gateway (D-039)

The worker has no route to the internet: it is on an internal network with the database,
the API and the gateway only. Every request a recon tool or an agent sends leaves through
the gateway (`gateway.py`), which enforces the engagement's scope, read-only methods, rate
ceiling (one limiter per engagement for every tool and worker) and identification, answers
DNS only for in-scope names, makes the port probes, and logs every request, allowed or
refused (`gateway_requests`, `GET /engagements/{id}/gateway-log`). Each job authenticates
with its own credential, valid while it runs; the gateway gets the rules from the API and
holds no database credentials. The tools' own flags stay as the first layer. Design,
decisions and threat model: `GATEWAY.md`.

### Computed modules

`paramclass` (M6) and `dorks` (M10) have traffic class `passive` and send no request at
all. They derive leads from what earlier modules stored. A lab test confirms that zero
requests reach the target.

### Authentication and permissions

Three modes (`auth.py`): open (no people, no token: localhost only), token
(`ATTACKLEDGER_API_TOKEN`) and people (email and password, sessions stored as hashes).
Every route passes `authz.authorize`, which looks the route up in one permission table:
public, signed in, owner, or a role on the route's engagement (viewer, tester,
reviewer). Routes without an entry are open to owners only, and a test checks that
every route has one. See D-032.

## Invariants worth keeping

- Unknown is out of scope. Exclusions win. A wildcard does not cover its apex.
- No tool runs on an engagement without recorded authorization.
- No HTTP leaves the worker without the research identification, and redirects are
  not followed. Nothing leaves the worker except through the gateway.
- The rate limit is a ceiling for every traffic-sending step.
- A failure that produced nothing is `failed`. A run cut short, by the time limit or
  by a module's `max_targets`, is `partial` and lists what it did not reach. Neither
  is ever shown as `done`.
- Only a person issues a receipt.
- Secrets are evidence, not inventory: masked, hashed and never tested.
- Raw evidence is redacted before it is stored (agent exchanges, notes, files, recon URLs
  and leads): `[redacted:sha256:<12 hex>]` replaces the value, and the evidence summary,
  which the chain commits to, says how many values of which kinds. An owner can turn this
  off per engagement for a lab; each entry then says it was stored as captured.
- Third-party scanners are trusted only after measurement. A raw socket logger checks
  that every request carries the research identification (nuclei: 8,899/8,899), and the
  target's log checks that the per-second peak stays at the limit (feroxbuster 20/20,
  Arjun 10/10).
