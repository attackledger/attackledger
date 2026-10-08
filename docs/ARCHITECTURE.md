# Architecture

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

The manual executor is a person using the UI or API. The agent executor (v0.4)
must use exactly the same write paths. It gets no shortcut that a person
does not have.

### Evidence and receipts

- Evidence is append-only and chained per engagement:
  `chain_hash = sha256(prev_hash + record)`.
- A receipt is the hash of a lane's manifest (items and evidence). Any later change
  makes it stale (shown as VOID).
- The report embeds everything needed to rebuild every receipt and walk the chain
  offline, using only the Python standard library.

## Invariants worth keeping

- Unknown is out of scope. Exclusions win. A wildcard does not cover its apex.
- No tool runs on an engagement without recorded authorization.
- No HTTP leaves the worker without the research identification, and redirects are
  not followed.
- The rate limit is a ceiling for every traffic-sending step.
- A failure that produced nothing is `failed`, and a run cut short is `partial`.
  Neither is ever shown as `done`.
- Secrets are evidence, not inventory: masked, hashed and never tested.
