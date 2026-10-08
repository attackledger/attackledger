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

- [ ] Agent executor (Claude Agent SDK). It reads `/lanes/{id}/context` and writes
      only through the executor contract, never issuing a receipt (D-018).
- [ ] Agent tools gated by scope, rate limit and research identification.
- [ ] Agent runs as jobs, with a log, cancel, partial status and token cost.
- [ ] A review screen for agent evidence before the human signs the lane.
- Needs an Anthropic Console API key.

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
