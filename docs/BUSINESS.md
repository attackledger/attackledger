# How AttackLedger is offered

Status: agreed 2026-10-09 (D-044). Product decisions are in DECISIONS.md; this page covers
what is offered, to whom, and how it may earn money.

## Position

AttackLedger is proof of what a security test covered, for the people who have to rely on
it: the client who paid for the test, the auditor who checks it, and the regulator behind
them. Findings tools say what was found; AttackLedger shows what was tested, by whom and
when, in a form anyone can check without trusting the tester.

## Readers it is built for

- Internal audit and IT audit teams at banks and other regulated firms.
- IT audit and technology risk teams at audit and consulting firms.
- Pentest firms that want to hand their clients verifiable coverage, and bug bounty hunters
  who want to track their own.

## What is offered

- **The software, open source** under the AGPL-3.0: the whole product, including the
  ledger, the verifier, recon, agents and reports. Anyone can read and check it.
- **A commercial licence** for organisations that cannot use AGPL software.
- **Installation and support** for deployments on the customer's own servers (D-042).
- **Reviewed control packs**: mappings from tests to controls (PCI DSS, ISO/IEC 27001,
  DORA and local banking rules), reviewed against the current text of each standard and
  kept current, by subscription. The code that reads them stays open.
- **Training and advice**: workshops for auditors on how to check what a penetration test
  covered, and advice for pentest teams on evidence and reporting.

Nothing is hosted for customers apart from the public verifier page (D-042); AttackLedger
holds no customer data.

## Stages

1. **Now: a portfolio project.** Make the product sound and measured, publish what it does
   and what it does not do, and talk to auditors. No sales.
2. **First users: 2-3 design partners.** A pentest firm or a bank audit team uses it on a
   real engagement at no cost, in return for regular feedback and, if they agree, a case
   study. Prices are set from what these partners value.
3. **A side business** begins when a design partner has used AttackLedger on real work and
   says they would pay for a licence or support. Until then, stage 1 and 2 rules apply.

## What counts as progress in stage 1

- The benchmark (docs/BENCHMARK.md) improves release by release, with the gates holding.
- The repository is public after a full-history scan.
- Articles that explain how to audit test coverage, in English with a Turkish summary.
- Conversations with auditors, and at least one design partner.

## Open

- Prices, licence terms and the support offer: after the first design partners.
- Trademark registration.
