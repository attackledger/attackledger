# Roadmap

Status as of 2026-10-09. The changelog records what shipped and the decision
record records why. This file lists what comes next.

## v0.5: finish recon (shipped in 0.5.0, apart from M9 and authenticated recon)

- [x] **M7 nuclei:** technology-matched templates plus takeover checks. Opt-in, with
      host clustering as in the original pipeline.
- [x] **M3 feroxbuster:** content discovery on golden hosts. Opt-in, with time and
      host caps.
- [x] **M5 arjun:** hidden-parameter discovery on a capped set of dynamic endpoints.
      Opt-in.
- [x] **M6 gf routing:** classify parameters (xss, ssrf, sqli, lfi, redirect, idor, …)
      into leads for the hunt lanes.
- [x] **M10 dork checklist:** the manual Google-dork list, generated per engagement.
- [x] **Run pipeline:** queue every applicable step in dependency order. Targets are
      resolved when each step runs.
- [x] **Scope import:** HackerOne scope CSV to include/exclude rules.
- [ ] **M9 cloud and infra:** cloud_enum and s3scanner (later).
- [ ] **Authenticated recon:** crawl with the operator's own test session (later).

## v0.6: hunt agents

- [x] Agent executor: a Messages API tool-use loop (D-025). It reads the lane context
      and writes only through the executor contract, never issuing a receipt (D-018).
- [x] Agent tools gated by lane host, scope, read-only methods (D-024), rate limit,
      request budget and research identification.
- [x] Agent runs as jobs, with a log, cancel, partial status and a token cost estimate.
- [x] Raw exchanges kept in a blob store and viewable from each evidence entry.
- [ ] **First live run on the lab** (needs an Anthropic API key in `.env`).
- [ ] A fuller review screen: side-by-side request and response, per-item diff.
- [ ] Write requests for agents: opt-in per engagement, own test accounts, preview.
- [x] Stale-job recovery: jobs left `running` by a worker crash are marked failed.
- [x] Agent model setting, so a first live test can run on a cheaper model.

## v0.7: ready to publish

- [x] Operator-token authentication (v0.5.0).
- [ ] Multi-user accounts, so that receipt signatures become authenticated identities.
- [ ] Live site at attackledger.com: landing page, docs and a read-only demo.
- [ ] Make the repository public after a fresh full-history scan, then pin it on the
      profile.
- [ ] Apply to the Claude startup program.
- [ ] CLA Assistant before the first outside contribution.

## Later and commercial

- [ ] Signed, timestamped reports (Ed25519 + RFC 3161).
- [ ] Compliance packs, with mappings reviewed against the current standards.
- [ ] Continuous monitoring: scheduled re-runs and a diff of new surface.
- [ ] Multiple workers, with a per-engagement global rate limit.
