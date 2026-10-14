# AttackLedger for auditors

**Proof of what a security test covered, that you check yourself.**

Status: October 2026, version 0.9.0 (a preview). Every statement below comes from the
documents listed under [Sources](#sources).

## The problem

A penetration test report says what was found. It rarely shows what was checked. An auditor
who relies on a test usually gets a list of findings and a methodology statement. There is no
record of which hosts were tested, which checks ran on each one, what the evidence was, or who
signed off.

"No findings" can mean the area was tested and was sound. It can also mean the area was never
reached. From the report alone, you cannot tell which.

AttackLedger follows an audit rule: a control without evidence is a control that was not
performed. A test area counts as done only when it has a receipt. If the receipt is missing,
the work is open.

## What an auditor gets

A report in JSON or HTML that you can verify yourself, offline, without trusting the tester's
tools. It contains:

- **The rules of the test.** The scope and the recorded authorization: who confirmed it, and
  the policy or statement of work that permits the test.
- **Coverage per host and lane.** A lane is one test area on one host, for example
  "authorization" on `app.example.com`. Each lane is a checklist from a methodology pack (OWASP
  WSTG, 97 tests, or a bug bounty pack). Every item shows its evidence, or the written reason it
  was marked not applicable. Items marked not applicable are shown apart and never counted as
  evidence.
- **Control mapping status.** Each checklist item names the controls it can give evidence for
  (PCI DSS v4.0.1, ISO/IEC 27001:2022 Annex A, EU DORA). The report shows, per control, how many
  mapped items on in-scope hosts are receipted, and how strong the mapping is ("partial" or
  "supporting"; none is "full").
- **Who signed what, and when.** A named reviewer signs each lane's receipt with a key held in
  their own browser. The receipt is timestamped by an RFC 3161 timestamp authority (DigiCert's
  public service by default), so it cannot be backdated. The report carries a hash-chained
  change history: who held the reviewer role, and which scope was in force, when each receipt
  was issued.
- **The evidence chain.** Every evidence entry is linked to the one before it. Editing,
  deleting or reordering an entry breaks the chain.

## How verification works, in 3 steps

1. **Run the verifier on the report.** `python3 verify_report.py report.json --require-history`
   uses only the Python standard library, needs no network and shares no code with the rest of
   AttackLedger. Or drop the report on `attackledger.com/verify`: the same checks run in your
   browser and nothing is uploaded. Add `--require-signatures` if every lane must be signed.
   Exit code 0 is a pass.
2. **Compare the key fingerprints.** Ask the tester, by a channel other than the report, for
   the reviewers' key fingerprints and the server's seal key fingerprint. Compare them with the
   report's Integrity section. A signature check is only as good as this comparison.
3. **Read what was verified.** Check that the seal time or its timestamp matches when you
   expected the report. Read the engagement settings (separation of duties, signatures
   required, redaction). For an HTML report, compare the page with the summary the verifier
   prints, because only the embedded data is checked, not the page text.

The verifier checks the report body hash, the evidence chain, each receipt against a manifest
rebuilt from the report's own items and evidence, each signature, each timestamp, the change
history and the server's seal.

## What it does not prove

- **That the operator is honest.** The server seals each report with its own key. Whoever runs
  the server can seal a report built from an edited database. The seal is the server's
  statement. The reviewers' signatures are the evidence of the review.
- **That the evidence is genuine.** The ledger proves what was recorded, when and by whom. It
  does not prove that a target really answered that way.
- **That the test was complete or good.** Coverage is what the checklist items say and what
  people marked. A lane marked not applicable has a reason, not a test.
- **That the reviewer really reviewed.** A signature is a statement. The reviewer's browser
  signs what the installation's code asks it to sign.
- **Compliance.** The control mappings are indicative. They were reviewed against public
  sources by an AI assistant (Claude) on 2026-10-09, not by a qualified assessor (QSA, ISO lead
  auditor or DORA TLPT authority). They are not a compliance determination. DORA threat-led
  penetration testing (TLPT) is deliberately not mapped.
- **Independent assurance of the tool.** No independent third party has tested AttackLedger.
  The security review was the author's own, done with AI agents.

## Status today

- **Version 0.9.0, a preview.** Before 1.0, versions may change the data model; migrations
  upgrade existing databases.
- **Self-hosted.** It runs on your own server. Test data never leaves it, and there is no
  telemetry.
- **Install tested** end to end on a fresh Ubuntu 22.04 server: backup, wiping every volume and
  restoring kept the evidence chain identical.
- **One real use, by its author:** 117 requests from a real vulnerability disclosure program,
  imported from Caido; 16 evidence entries mapped; 2 lanes signed in the reviewer's browser and
  timestamped; the report verified offline in strict mode.
- **Internal security review** of the whole product (10 to 11 October 2026), with a second,
  adversarial pass over every fix. The server test suite went from 758 to 1,289 tests. The
  Python and browser verifiers give identical results on 134 reports and 2,600 random mutants.
- **Works with the tools testers already use.** HAR, Burp Suite XML and Caido JSON exports are
  imported as evidence. Recon and a Claude agent are available inside the gateway's limits, but
  are optional. The agent has run against the real Claude API on the bundled lab only.
- **Known limits:** no second sign-in factor (put it behind your SSO or VPN); deleting an
  engagement's content does not reach backups made before it.
- **Who:** built by Murat Kabak, a security researcher in bug bounty programs since 2022. The
  idea dates from March 2025; the public release was October 2026. Self-funded, based in
  Turkey.

## What we ask of a design partner

We are looking for one internal or IT audit team, or one small pentest firm, to:

- install AttackLedger on their own server (we help);
- run one real, authorized test with it, with their usual tools;
- verify the report as an auditor would, and tell us what stopped them relying on it;
- join 2 to 3 feedback calls over about 6 weeks.

Details: [DESIGN_PARTNER.md](DESIGN_PARTNER.md). Contact: murat@attackledger.com.

To look first, with no install: the demo (`attackledger.com/demo/`), the sample report
(`attackledger.com/sample-report.html`) and the verifier page (`attackledger.com/verify`).

## Sources

[README](../../README.md) ·
[Verifier](../VERIFIER.md) ·
[Threat model §1, §6, §7, §10](../THREAT_MODEL.md) ·
[Control mappings](../CONTROLS.md) ·
[Security review](../security-review/README.md) ·
[How it is offered](../BUSINESS.md) ·
[MVP](../MVP.md) ·
[Install](../INSTALL.md) ·
[Changelog](../../CHANGELOG.md) ·
[Benchmark](../BENCHMARK.md)
