---
name: webapp-checklist
description: Systematic OWASP web-app security checklist runner for an authenticated target you already have recon + a session for. Walks every non-recon section — Config Management, Secure Transmission, Authentication, Session Management, Authorization, Data Validation, DoS, Business Logic, Cryptography, File Uploads, Card Payment, HTML5 — as concrete tests against a live target (via Caido replay/batch + a proxied browser), records a pass/finding verdict per item, and hands back a coverage matrix. Use when the operator says "run the checklist", "go through every vuln class", "don't skip anything", or names this checklist; when you've finished recon on a bug-bounty target and want structured breadth before writing reports; or when picking up an engagement mid-way and need to know what's still untested. Based on the OWASP Web Security Testing Guide. Complements the `claude-bughunter:hunt-*` skills (this is breadth + tracking; they are depth per class) and `claude-bughunter:triage`/`report-writing` (verdict → report).
---

# webapp-checklist

Breadth-first, evidence-driven walk of the OWASP Web Application Security Testing checklist against
**one authenticated target you already hold recon + a session for.** Every item gets an explicit
verdict backed by a request/response, not a guess. Output is a coverage matrix the user can see at a
glance + a findings list feeding `claude-bughunter:triage` → `report-writing`.

This skill is the **map and the ledger**. When an item needs deep technique, hand off to the
matching `claude-bughunter:hunt-*` skill and bring the verdict back here.

## Preconditions (do not start without these)

1. **Scope confirmed** — run `claude-bughunter:scope` on every host you'll touch. Deny-wins.
2. **Recon done** — subdomains, live hosts, tech fingerprint, JS/endpoint inventory, GraphQL/OpenAPI
   schemas pulled. This skill does NOT do recon (sections 1–2 of the source list are skipped).
3. **A session** — a valid auth token / cookie for the target, ideally captured in Caido. Note its
   TTL; refresh from the proxied `/oauth/token` (or equivalent) response when it expires.
4. **Program rules loaded** — the engagement's own OOS list, test-plan header/UA, rate-limit ask.
   Honor them. If the user has explicitly told you to ignore a specific program prohibition, you may
   — but never touch OOS assets, and never run anything destructive without the user's ok.
5. **"No harm" default** — for any DELETE / overwrite / state-changing / email-sending test: probe
   with non-existent IDs and error-shape analysis first; only run the real mutation with the user's
   explicit go-ahead, and prefer testing A→B where B is a **second account you control**.

## Tooling

- **Caido** (`mcp__caido__*`) — `caido_send_request` for single probes, `caido_batch_send` (≤50
  parallel) for sweeps (BAC token swaps, param fuzz, header matrices), `caido_get_request` /
  `caido_export_curl` to pull captured traffic, `caido_list_requests` (httpql) to find endpoints.
  Project = the engagement's Caido project.
- **Proxied browser** (`mcp__claude-in-chrome__*`) — for anything that needs a real DOM: DOM-XSS,
  postMessage, clickjacking PoC, client-side validation, file-upload UI, business-logic flows the
  user walks while you analyze the traffic.
- **Local grep** over the downloaded JS bundles / sourcemaps — for entry points, hidden params,
  client-side secrets, GraphQL operation strings, hardcoded hosts.

## How to run

1. **Read `checklist.md`** (in this skill dir) — it has all ~130 non-recon items grouped by section,
   each with a concrete test recipe and a "finding when…" line.
2. **Build the target profile first** (from recon, don't re-scan): auth mechanism (JWT? cookie?
   OAuth/OIDC? which IdP?), API style (REST? GraphQL? both?), state-changing endpoints inventory,
   roles, file-upload surfaces, payment surface, third-party hosts.
3. **Walk section by section.** Batch where you can (one `caido_batch_send` covers a whole header /
   redirect / CORS matrix). For each item record: `PASS` (tested, secure) / `FINDING` (with the
   request + response) / `N/A` (feature absent — say why) / `BLOCKED` (can't test safely — say what's
   needed, e.g. 2nd account).
4. **Deep-dive on hits.** A `FINDING` or a strong smell → invoke the matching `claude-bughunter:hunt-*`
   skill for full technique + real-report shapes, then update the verdict here.
5. **Report the matrix** back to the user after each section (or in one block if they prefer),
   then push confirmed findings through `claude-bughunter:triage` before any report.

## Section → hunt-* handoff map

| Checklist section | Deep-dive skill(s) |
|---|---|
| Configuration Management | `hunt-source-leak`, `hunt-misc` |
| Secure Transmission | `hunt-tls-network` |
| Authentication | `hunt-auth-bypass`, `hunt-brute-force`, `hunt-forgot-password`, `hunt-mfa-bypass`, `hunt-captcha-bypass`, `hunt-oauth`, `hunt-saml`, `hunt-jwt-crypto` |
| Session Management | `hunt-session`, `hunt-csrf`, `hunt-clickjacking` |
| Authorization | `hunt-idor`, `hunt-auth-bypass`, `hunt-lfi` (path traversal), `hunt-shadow-api` |
| Data Validation | `hunt-xss`, `hunt-dom`, `hunt-html-injection`, `hunt-sqli`, `hunt-nosqli`, `hunt-xxe`, `hunt-ssti`, `hunt-ldap`, `hunt-rce`, `hunt-open-redirect`, `hunt-lfi`, `hunt-http-smuggling`, `hunt-api-misconfig` (HPP / mass-assignment / verb tampering), `hunt-cache-poison`, `hunt-host-header` |
| Denial of Service | `hunt-brute-force` (anti-automation only — respect program DoS ban) |
| Business Logic | `hunt-business-logic`, `hunt-race-condition`, `chain` |
| Cryptography | `hunt-jwt-crypto`, `hunt-tls-network` |
| File Uploads | `hunt-file-upload` |
| Card Payment | `hunt-business-logic`, `hunt-api-misconfig` |
| HTML5 | `hunt-cors`, `hunt-websocket`, `hunt-dom` (postMessage) |
| GraphQL-specific (target-dependent) | `hunt-graphql`, `hunt-fintech-graphql` |

## Coverage matrix template

```
# <target> — OWASP checklist coverage (<date>)
session: <token/cookie source, TTL>   |   scope-checked: <hosts>

## Configuration Management        [ n PASS / m FINDING / k N/A / j BLOCKED ]
- [PASS]    admin URLs / backup files ............ 404 across /admin,/backup,/.git,/.env,*.bak,*.old,*~
- [FINDING] sourcemaps exposed ................... GET /_next/**/ *.js.map → 200 w/ sourcesContent (Low, info-disc)
- [N/A]     Flash/Silverlight policy ............. no plugin content
...
```

Keep one block per section. Update verdicts in place as deep-dives resolve them.

## Notes

- **GraphQL targets:** the OWASP list predates GraphQL. Map each item onto it: introspection =
  "sensitive data in client-side / config disclosure"; field/operation authz = "missing / horizontal
  authz"; batching & alias amplification = "anti-automation / DoS"; input types = "mass assignment /
  auto-binding"; `node(id:)` / `xById` resolvers = "IDOR". Pull the schema from a captured request or
  the JS bundle since introspection is usually off.
- **Don't re-file the whole checklist as findings.** Most items are `PASS`. A `FINDING` still has to
  clear `claude-bughunter:triage`'s 7-Question Gate and the engagement's own N/A anti-patterns before
  it becomes a report.
- **Reusable across targets** — the skill is target-agnostic; only the profile in step 2 changes.
