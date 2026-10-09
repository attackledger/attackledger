# Contributing to AttackLedger

Thank you for your interest. Issues and pull requests are welcome.

## Before you open a pull request

- **Sign the CLA once.** AttackLedger is published under the AGPL-3.0 and also offered under
  a commercial licence, so every contribution needs the [Contributor License
  Agreement](CLA.md). On your first pull request, a bot posts a comment. Reply with the
  sentence it gives you. You keep the copyright in your work. A pull request can't be
  merged until every commit author has signed.
- **Security issues go privately** to murat@attackledger.com or through GitHub's [private
  reporting](https://github.com/attackledger/attackledger/security/advisories/new), not in
  issues or pull requests. See [SECURITY.md](SECURITY.md).
- **No real targets.** Never include real target names, findings, captured traffic,
  credentials or personal data in code, tests or fixtures. Use `example.com`, `*.test`
  hosts or the bundled lab.
- **Keep the guarantees.** The gateway's scope, method, rate and identification checks, the
  evidence chain, and the rule that only a person signs a receipt are what the product
  stands on. Changes that weaken them won't be merged. Changes that make them stronger
  are very welcome.

## Working on the code

- Read `README.md` (quick start) and `docs/TARGET_ARCHITECTURE.md`.
- **Server tests:** `cd server && python -m pytest -q tests`. The CI runs them as a non-root
  user, so please do the same.
- **Web:** `cd web && npm ci && npm run lint && npm run build`.
- **Verifier changes:** a change to `tools/verify_report.py` needs the same change in
  `web/src/verify_report.ts`, and a case in `tools/verifier_equivalence/cases.json`
  (D-046).
- **Decisions:** record one that changes direction, scope, licensing or security behaviour
  in `docs/DECISIONS.md`, and add a line to `CHANGELOG.md`.
- **Plain English** in user-facing text: short sentences, sentence case, and say what
  happens.

## AI-assisted contributions

Contributions written with an AI assistant are fine. You are still the one confirming
section 4 of the CLA, so read and test what you submit. Keep any `Co-Authored-By` trailer
your tool adds (D-011).
