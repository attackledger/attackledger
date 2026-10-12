# Design partner programme

Status: October 2026. This page describes what we propose to a first design partner. It is an
outline for a conversation, not a contract or a legal offer. The terms would be agreed in
writing with each partner.

For what AttackLedger is and what it proves, read the [one-pager](ONE_PAGER.md) first.

## Who it is for

One or two teams that rely on, or produce, security test results:

- **An internal audit or IT audit team** at a bank or another regulated firm, or an IT audit
  and technology risk team at an audit firm. You want to check what a penetration test
  covered, not only what it found.
- **A small pentest firm** that wants to hand its clients proof of coverage: which hosts, which
  checks, what evidence, who signed off.

You need someone who is comfortable on a Linux server with Docker, and a test you are already
authorized to run.

## What you would do

1. **Install AttackLedger on your own server.** The [install guide](../INSTALL.md) covers a
   fresh Ubuntu server with HTTPS, the first owner, keys, backup and restore, and upgrades. The
   minimum server is 4 cores, 8 GB of memory and 60 GB of disk. We expect this to take an
   afternoon for someone used to Docker; the first image build alone takes 10 to 30 minutes.
   We can join a screen-share for it.
2. **Run one real, authorized test with it.** Keep your usual tools (Burp, Caido, browsers,
   scanners). Record the scope and the authorization, export your traffic as HAR, Burp XML or
   Caido JSON, import it, and map the entries to checklist items. A reviewer signs each lane.
   Recon and the Claude agent are optional; the core use does not depend on them.
3. **Verify the report as an auditor would.** Export the report, run the verifier on it, and
   note what you could and could not rely on.
4. **Join 2 to 3 feedback calls over about 6 weeks.** For example:

   | When | What |
   |---|---|
   | Week 0 | Intro call: your test, your questions, the install plan |
   | Week 1 | Install, with our help if you want it |
   | Weeks 2 to 4 | The test, and a mid-point call |
   | Week 6 | Closing call: what worked, what blocked you, what an auditor would still need |

An audit team that does not run tests itself can instead ask the tester it already works with
(an internal red team or an external provider) to run one engagement in AttackLedger, and then
verify the report it receives.

## Time it would take you

Our estimate, not a measurement. It depends on your server and the size of the test.

| Activity | Estimate |
|---|---|
| Install and first sign-in | About half a day |
| Extra work on the test (recording the rules, importing, mapping evidence, signing) | A few hours on top of the test itself |
| Verifying the report | Under an hour |
| Feedback calls | 2 to 3 calls of 30 to 45 minutes |

## What you would get

- **Free use.** The software is open source under the AGPL-3.0, so it costs nothing to use.
- **Direct influence on the roadmap.** What blocks you is what we build next.
- **Help with the install** and with your first engagement.
- **A commercial licence, free during the partnership,** if your organisation cannot use AGPL
  software. We would agree this in writing before you start.
- **A say in the control mappings.** The mappings to PCI DSS, ISO/IEC 27001 and DORA have not
  been reviewed by a qualified assessor. [CONTROLS.md](../CONTROLS.md) lists ten open questions
  for one. An auditor's view on them is very welcome.

In return we ask for honest feedback. A case study or a public reference only if you agree, and
nothing published about you without your written approval.

## What data stays with you

- **Everything.** AttackLedger is self-hosted on your server. Nothing is sent to AttackLedger,
  and it sends no telemetry. We do not need access to your server, your evidence or your target
  names. In feedback calls you decide what you show.
- Evidence is encrypted at rest with a key per engagement, wrapped by a master key you hold.
- What does leave your server, and only to third parties you can turn off or avoid:
  - a SHA-256 hash to a timestamp authority (DigiCert's public service by default) once per
    closed lane; set `ATTACKLEDGER_TSA_URL=off` to send nothing;
  - the agent's calls to Anthropic's API, only if you turn Claude agents on;
  - passive recon queries (certificate transparency, web archives), only if those steps run;
  - package downloads, at install and upgrade only.

The full list is in the [install guide](../INSTALL.md), section 1, "Network".

## FAQ

**Is the tool itself secure?**
It had an [internal security review](../security-review/README.md) of the whole product in
October 2026, with a second, adversarial pass over every fix, and a
[threat model](../THREAT_MODEL.md) written for IT auditors. Each finding has a regression test
that failed before its fix. **No independent third party has tested it.** Read the review as the
author's own testing, done with AI agents (Claude), not as an external pentest. The threat model
lists the accepted risks (section 7) and what the deployer must do (section 9). Two to know
first: there is no second sign-in factor, so put it behind your SSO or VPN; and content deletion
does not reach backups made before it.

**AGPL or commercial licence?**
Under the AGPL-3.0 you may use, change and self-host AttackLedger at no cost. If you offer a
modified version to others over a network, you must publish your source under the same
licence. A commercial licence is for organisations that cannot use AGPL software, or that want
to embed it or offer it as a service without those obligations. For the partnership we would
agree a commercial licence at no cost if you need one. This is not legal advice; ask your own
legal team.

**Is it production ready?**
Not yet, and we say so. It is version 0.8.0, a preview. Before 1.0, versions may change the data
model (migrations upgrade existing databases). The install has been tested end to end on a fresh
Ubuntu server, and the author has used it on one real engagement. The Claude agent has not yet
run against the live API. For a design partnership we suggest one engagement, run alongside your
usual report, not instead of it.

**Does it replace our pentest report?**
No. Findings tools and reports say what was found. AttackLedger adds a verifiable record of what
was tested, by whom and when.

**Does it make us compliant with PCI DSS, ISO 27001 or DORA?**
No. The mappings are indicative and none is "full": every control also needs things a test
result cannot show, such as a documented process, a frequency, tester independence and
remediation.

**Do we need AI, or an Anthropic account?**
No. Recon and the Claude agent are optional. The core use is importing your own evidence,
mapping it, signing lanes and exporting the report.

**What if the project stops?**
The code is open source, the installation and its data are on your server, and the verifier
uses only the Python standard library and shares no code with AttackLedger. A report you
received stays verifiable without us.

**Who is behind it?**
Murat Kabak, a security researcher in bug bounty programs since 2022. AttackLedger is
self-funded and based in Turkey. AttackLedger is not yet an incorporated company, so a partnership
agreement would be with him directly.

## Contact

murat@attackledger.com
