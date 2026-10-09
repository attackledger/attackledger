# Control mappings

Status: reviewed against public sources by Claude on 2026-10-10; not reviewed by a
qualified assessor (QSA, ISO lead auditor or DORA TLPT authority). The mappings are
indicative and are not a compliance determination.

The catalog is `packs/controls.yaml`; the mappings sit in `packs/web-pentest-wstg.yaml` and
`packs/bug-bounty.yaml`. The Controls tab and the audit report show, per control, how many
mapped items on in-scope hosts are receipted, the strength of the mapping, and the catalog's
note on when the mapping holds.

## Method

1. Each control id and title was checked against the current version of its standard,
   using the sources below. Titles are short paraphrases; the PCI DSS and ISO/IEC texts are
   copyrighted, so only numbers and short titles are kept.
2. Each mapping was judged by one question: would an assessor accept this receipted test
   result as evidence for this control, and how much of the control would it answer? A
   mapping that overstates is worse than a missing one, so doubtful mappings were removed
   or lowered to "supporting".
3. Gaps were added only where a lane really produces the evidence.
4. The conclusions are held as tests (`server/tests/test_packs.py`,
   `test_shipped_mappings_do_not_overstate`), so a later edit cannot quietly undo them.

## Sources

| Framework | Source | Version | Checked |
|---|---|---|---|
| PCI DSS | [PCI SSC document library](https://www.pcisecuritystandards.org/document_library/) | v4.0.1, June 2024 | 2026-10-09 |
| PCI DSS | [RFC instructions for the currently published PCI DSS v4.0.1](https://www.pcisecuritystandards.org/rfc_instructions_pci-dss-v4-0-1-june2026/) | June 2026 | 2026-10-09 |
| ISO/IEC 27001 | [ISO/IEC 27001:2022](https://www.iso.org/standard/27001), Annex A, with ISO/IEC 27002:2022 control names | 2022, Amd 1:2024 | 2026-10-09 |
| DORA | [Regulation (EU) 2022/2554](https://eur-lex.europa.eu/eli/reg/2022/2554/oj/eng), EUR-Lex | OJ L 333, 27.12.2022 | 2026-10-09 |
| DORA | [Commission Delegated Regulation (EU) 2025/1190](https://eur-lex.europa.eu/eli/reg_del/2025/1190/oj/eng), RTS on TLPT | OJ L 2025/1190, 18.6.2025, in force 8.7.2025 | 2026-10-09 |

What could and could not be read:

- **PCI DSS**: v4.0.1 is still the current version: the PCI SSC request for comments that ran
  from 3 June to 20 July 2026 is on "the currently-published version", v4.0.1, to decide
  whether to revise it. No later version was found. The standard itself sits behind the
  library's licence page and could not be fetched, so the requirement numbers, the 6.4.1 to
  6.4.2 change and the 6.3.1 guidance on bug bounties were confirmed from secondary sources
  (QSA and vendor summaries), not the official text.
- **ISO/IEC 27001**: iso.org refused automated access. The Annex A titles were checked against
  public control indexes and match the 27002:2022 names. Amd 1:2024 (climate action) changes
  clauses 4.1 and 4.2, not Annex A. No newer edition was found.
- **DORA**: Article titles and the list of tests in Article 25(1) were read from the EUR-Lex
  text. The RTS on TLPT is Delegated Regulation (EU) 2025/1190, adopted 13 February 2025. No
  consolidated text with amendments to Articles 24 to 27 was found.

## Strength scale

Every mapping names a strength. A control has one strength per pack, so each row of the
Controls tab states a single claim; a pack that maps one control at two strengths does not
load. A mapping written as a bare id (older or third-party packs) counts as "supporting".

| Strength | Meaning |
|---|---|
| full | The result alone answers the control's test; nothing else is needed. |
| partial | The result answers a defined part of the control's test; the rest needs other evidence. |
| supporting | The result is relevant and can corroborate other evidence; it does not answer the test. |

No shipped mapping is "full". Every control here also asks for things a test result cannot
show: a documented process, a frequency, tester independence, remediation.

A status such as "evidenced" means every mapped item on every in-scope host is receipted.
It says nothing about the control as a whole; read it together with the strength.

## Mappings after the review

Both packs: "test lanes" are every lane that tests the application (WSTG: all twelve
categories; bug bounty: recon, access control, auth & sessions, business logic, input
handling, mobile). The bug bounty model lane maps to no control.

| Control | Web pentest (WSTG) | Bug bounty | Note |
|---|---|---|---|
| PCI 4.2.1 PAN in transit | supporting: CONF-07, CRYP-01, CRYP-03 | supporting: RECON-04 | Only hosts that carry PAN |
| PCI 6.2.4 Common software attacks | supporting: athn, athz, sess, inpv, cryp, busl, clnt, apit | supporting: authz, authflow, logic, injection | 11.4.1 asks application tests to cover the 6.2.4 attack types |
| PCI 6.3.1 Vulnerabilities identified and managed | | supporting: test lanes | Guidance names bug bounties as one source |
| PCI 11.4.1 Pentest methodology | supporting: every lane | | Application layer only |
| PCI 11.4.3 External pentest | partial: every lane | supporting: test lanes | Application layer, from outside |
| ISO A.5.9 Inventory | supporting: info | supporting: recon | |
| ISO A.5.15 Access control | supporting: idnt, athz | supporting: authz | |
| ISO A.5.17 Authentication information | supporting: ATHN-02, 05, 07, 08, 09 | supporting: AUTHFLOW-11 | |
| ISO A.8.2 Privileged access rights | supporting: ATHZ-03 | | |
| ISO A.8.3 Information access restriction | partial: athz | partial: authz | |
| ISO A.8.5 Secure authentication | partial: athn, sess | partial: authflow | |
| ISO A.8.8 Technical vulnerabilities | partial: every lane | partial: test lanes | Identification only |
| ISO A.8.9 Configuration management | supporting: conf | supporting: RECON-03 | |
| ISO A.8.24 Use of cryptography | supporting: cryp, CONF-07, ATHN-01 | supporting: RECON-04, 05, AUTHFLOW-08 | |
| ISO A.8.28 Secure coding | supporting: inpv, errh, busl, clnt, apit | supporting: logic, injection, mobile | |
| ISO A.8.29 Security testing in development and acceptance | supporting: every lane | | Only as release acceptance |
| DORA Art. 8 Identification | supporting: info | supporting: recon | |
| DORA Art. 9 Protection and prevention | supporting: idnt, athn, athz, sess, cryp | supporting: authz, authflow | 9(4)(c) and (d) |
| DORA Art. 24 Testing requirements | supporting: every lane | supporting: test lanes | |
| DORA Art. 25 Testing of ICT tools and systems | partial: every lane | supporting: test lanes | Pentest and vulnerability assessment are listed tests |

## Changes and reasons

**Format** (backward compatible)

- A mapping is an id or `{id, strength}`; a bare id is "supporting". Unknown strengths, a
  mapping listed twice, and one control at two strengths in a pack stop the load.
- A catalog control is a title or `{title, note}`. The note says when the mapping holds.
- The catalog has a `reviewed` block (who, when, the statement, sources with URLs and
  versions) and a `strengths` block. The controls API returns `strength` and `note` on each
  row, and `reviewed` and `strengths` with the report; the review statement is appended to
  the existing `disclaimer`, which the Controls tab and the audit report already show.
- The audit report's control table gains an "Evidence strength" column and the notes, and
  its statuses now say what they count ("All mapped items receipted", "Some mapped items
  receipted", "No mapped item receipted"), since "Partial" is also a strength.
- Pack versions: bug-bounty 0.3, web-pentest-wstg 0.2. Lanes opened earlier keep the control
  tags they were opened with; the Controls tab always uses the current mappings.

**PCI DSS**

- Framework renamed from v4.0 to v4.0.1, the only version in force since v4.0 was retired at
  the end of 2024.
- **Removed 11.3.2** (bug bounty recon). 11.3.2 is the quarterly external scan by a PCI SSC
  Approved Scanning Vendor; bug bounty recon is not an ASV scan.
- **Removed 6.4.1** (input and client lanes). 6.4.1 is superseded by 6.4.2 from 31 March
  2025, which requires an automated technical solution in front of public-facing web
  applications (a WAF or similar). A penetration test is not that solution and does not
  evidence it.
- **Removed 11.4.4** from the catalog (it had no mapping). AttackLedger does not record the
  retest of a corrected finding as such. See open questions.
- **Lowered bug bounty 11.4.3** to supporting, and **removed bug bounty 11.4.1** (model
  lane). A bug bounty can add to, but does not replace, the penetration test 11.4 requires,
  and its method is not the entity's documented pentest methodology.
- **11.4.1 now comes from every WSTG lane**, not only information gathering: the method
  followed is shown by the whole method, and only for the application layer.
- **WSTG 11.4.3 marked partial**, with a note: application layer only, from outside the
  network; frequency, tester qualification and independence, and network-layer testing need
  other evidence.
- **6.2.4 marked supporting**: it is assessed mainly from procedures and developers.
- **Added 4.2.1** (supporting, TLS items only), for hosts that carry PAN.
- **Added 6.3.1** (supporting, bug bounty test lanes).

**ISO/IEC 27001:2022**

- **Added A.8.8** (partial) to every test lane. It was in the catalog but mapped by nothing,
  although identifying technical vulnerabilities is what a test does. Evaluating them and
  acting in time need other evidence.
- **Added A.8.3** (partial) to the authorization lanes: it is the control that access
  restriction is enforced; A.5.15, the access control rules, stays as supporting.
- **Added A.5.17 and A.8.2** (supporting) on the items that test them: password policy,
  default credentials, reset, security questions; privilege escalation.
- **Moved A.8.29** off the bug bounty mobile lane, where it did not fit (a bug bounty runs
  on production, not as acceptance testing), and onto the WSTG lanes as supporting, with a
  note that it holds only when the test is part of release acceptance.
- **Removed A.5.9 from the model lane**: an application model is not an asset inventory.
- Marked A.8.5 partial, and A.5.9, A.5.15, A.8.9, A.8.24, A.8.28 supporting.

**DORA**

- **Removed Article 26 (TLPT)** from the catalog. It had no mapping, but listing it implied
  AttackLedger could evidence it. TLPT under Articles 26 and 27 and RTS 2025/1190 is
  threat-intelligence-led, on live production, run by testers meeting Article 27, under a
  TLPT authority, and ends in an attestation; AttackLedger tests are none of that.
- **Added Article 25** (partial for WSTG, supporting for bug bounty) to the test lanes. It
  was in the catalog but mapped by nothing, although Article 25(1) names vulnerability
  assessments and penetration testing.
- **Added Article 24** (supporting) to the test lanes: the programme, its risk basis, tester
  independence (24(4)), remediation (24(5)) and yearly coverage of systems supporting
  critical or important functions (24(6)) need other evidence.
- **Added Article 9** (supporting) to the access, authentication and cryptography lanes.
- Article 8 kept as supporting, with the official title "Identification".

## Not mapped, on purpose

- **PCI 11.4.5 and 11.4.6** (segmentation testing): no lane tests segmentation.
- **PCI 11.4.2** (internal penetration testing): whether a test is internal depends on the
  engagement, not the lane. See open questions.
- **PCI 8.x** (authentication): Requirement 8 applies to non-consumer users (staff,
  administrators, third parties), not to cardholder accounts; most tested sign-in flows are
  consumer flows.
- **PCI 6.4.2, 6.4.3, 11.6.1** (WAF, payment page scripts, change detection): these are
  controls the entity runs; a test does not evidence them.
- **ISO A.8.34** (protection of information systems during audit testing): the evidence is
  AttackLedger's scope attestation, rate limits and agreed rules, not a lane.
- **DORA Articles 26 and 27, RTS 2025/1190**: see above.

## Open questions for a qualified assessor

1. **PCI 11.4.3 strength.** Is a receipted WSTG engagement on an in-scope host accepted as
   partial evidence for the application-layer part of the external pentest, or only as
   supporting?
2. **PCI 11.4.2.** Should an engagement of type "internal" map the WSTG lanes to 11.4.2
   instead of 11.4.3? That needs mappings that depend on the engagement type.
3. **PCI 11.4.4.** Would a retest lane, receipted after a fix, be accepted as evidence that
   exploitable findings were corrected and verified?
4. **PCI 4.2.1.** Is a TLS test result useful supporting evidence, given that the assessor
   also observes transmissions and examines configurations?
5. **PCI 6.3.1.** Does the assessor accept bug bounty results as one input to vulnerability
   identification for bespoke software, as the guidance suggests?
6. **ISO A.8.29.** Is a pre-release penetration test accepted as acceptance testing, or must
   it be part of the documented development process?
7. **ISO A.8.34.** Should the engagement's scope attestation and rate limits be shown as
   evidence for A.8.34?
8. **DORA Article 25 strength.** Partial for a scoped pentest of a system supporting a
   critical or important function, or supporting only?
9. **DORA RTS on ICT risk management** (Delegated Regulation (EU) 2024/1774, for example
   Article 10 on vulnerability and patch management): should mappings go to the RTS
   articles rather than, or as well as, DORA Article 9?
10. **Local banking rules.** Which national rules (for example a regulator's IT and
    penetration testing rules for banks) should have their own catalog?
