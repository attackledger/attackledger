# Security policy

How to report a security vulnerability in AttackLedger, what you may test, and what happens
after you report. The same policy is published at <https://attackledger.com/security>, and the
machine-readable contact is at <https://attackledger.com/.well-known/security.txt> (RFC 9116).

**Report a vulnerability to [murat@attackledger.com](mailto:murat@attackledger.com).**
Please do not report security issues in public GitHub issues or pull requests.

## About this project

AttackLedger is a small project run by one person, Murat Kabak. I read every report myself.
There is no bug bounty: I cannot pay for reports, but I will fix what you find, keep you
informed, and credit you if you want to be credited.

## In scope

- The website at `attackledger.com`, including the read-only demo at `/demo/` and the sample
  report.
- The AttackLedger application (API, web app and worker) and its source code, once the source
  is published. Test it on an installation you run yourself.
- The offline verifier, `verify_report.py`, and the report format it checks. For example, a
  report that was changed after signing but still verifies, or a receipt that verifies without
  a valid signature or timestamp.

## Out of scope

- Third-party services that AttackLedger uses or depends on, such as Cloudflare, GitHub,
  DigiCert's timestamp service and Google Fonts. Report issues in those to the vendor.
- Installations of AttackLedger that other people run. Only their owner can allow you to test
  them.
- Social engineering, phishing, or any attempt to get access through people.
- Denial of service, and anything that degrades the site for other visitors.
- Volume testing: high-rate automated scanning, brute force, or load and stress testing.
- Findings that need a compromised device, a malicious browser extension, or physical access.
- Scanner output or missing best-practice settings with no demonstrated security impact.

## Rules for testing

- Do not access, change or delete other people's data. Use only accounts, installations and
  data that are your own.
- Do not test third-party systems, even when they are connected to AttackLedger.
- If you come across someone else's data or a secret, stop, do not use it, do not keep a copy
  beyond what the report needs, and tell me.
- Keep request rates low. A proof of concept is enough; there is no need to show the full
  extent of an issue.
- Keep the details confidential until the issue is fixed or the disclosure date has passed.

## How to report

Email [murat@attackledger.com](mailto:murat@attackledger.com) in English or Turkish. Please
include:

- what is affected: the URL, or the version or commit of the application or verifier;
- the steps to reproduce it, with requests, responses or a short script where that helps;
- what an attacker could do with it, as you understand it;
- whether and how you would like to be credited.

There is no PGP key yet. If the details are too sensitive for plain email, send a short first
message and we will agree on another way to share them.

## What you can expect

- An acknowledgement within 3 working days.
- A first assessment within 10 working days: whether I can reproduce the issue and how I plan
  to fix it.
- Updates while the fix is in progress, and a note when it is released.
- Credit in the release notes if you want it.

## Coordinated disclosure

I ask for 90 days from your report before details are published, or less if the fix is
released sooner and we agree on a date. If a fix needs more time, I will explain why and ask;
you do not have to agree. Once the issue is fixed, I will publish a short advisory and credit
you if you want it.

## Safe harbor

If you make a good-faith effort to follow this policy, I consider your research authorized. I
will not take legal action against you or report you to law enforcement for it. If someone
else takes action against you over research that followed this policy, I will make it known
that it was authorized.

This covers AttackLedger's own site and software only. I cannot give permission on behalf of
Cloudflare, GitHub, DigiCert or anyone else who runs an installation. If you are unsure whether
something is allowed, ask first.
