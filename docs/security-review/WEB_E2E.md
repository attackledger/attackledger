# Security review: browser end-to-end tests of the web app and the public site

Date: 2026-10-11. Branch `sec5-webe2e`, from `33f1144`. An AI agent (Claude) wrote a Playwright
suite that runs the web app in Chromium and Firefox against its own copy of the stack, filled
with hostile content, and fixed what it found. Everything ran on this machine: the test stack and
the browsers are on a Docker network with no route out, and the only downloads were the
Playwright image and the npm packages in `e2e/package-lock.json`.

The server has had a large test suite since the start; the web app had none in a browser. Its
security rests on things that only a browser shows: that React renders hostile text as text, that
nginx's Content-Security-Policy holds on every view, that the session cookie behaves as D-056
says, that another site cannot act through the browser (AUTH-2), and that the verifier pages give
the same verdicts as `verify_report.py`.

**Second pass** (2026-10-11, branch `sec6-e2eci`, from `ff1b941`): the public site
(attackledger.com) as Cloudflare Pages serves it, WebKit in every phase, and an `e2e` job in the
CI (sections "The public site", "WebKit" and "In the CI" below; findings WE-7 to WE-9).

## How to run it

```sh
tools/test_e2e.sh            # build, the site, start, seed, the app's two phases, all three browsers, tear down
tools/test_e2e.sh --keep     # leave the stack running afterwards; tools/test_e2e.sh --down removes it
tools/test_e2e.sh -g drafts  # arguments go to `playwright test` (here: only tests named "drafts")
```

It needs Docker with Compose 2.24 or later, and nothing else on the host: no Node, no browser, no
Python. It takes about 7 minutes once the images are built (the first build of the API image,
the web image and the runner takes longer). Two optional variables: `E2E_PROJECT` names the compose
project (default `al-e2e`, to run beside another copy), and `E2E_REPORT_DIR` keeps Playwright's
HTML report and the traces of failed tests there, one folder per phase (the CI uses it).

What it does:

1. Builds this tree's API and web images and the runner image (`e2e/Dockerfile`: Playwright's own
   image, pinned by the digest of its multi-arch index, with `npm ci` of `e2e/package-lock.json`;
   Playwright 1.63.0 and axe-core 4.13.0, each the newest release at least two weeks old).
2. **Site phase** (below, "The public site"): needs no stack, and runs first.
3. Starts the database, the API and the web app as compose project `al-e2e`
   (`e2e/compose.e2e.yml` on top of `docker-compose.yml`): its own containers, networks and
   volumes, no gateway, worker or lab, the public development key, no timestamp authority, and no
   port published on the host. The runner and the web app share a network of their own,
   `al-e2e_browser`, which is internal (no route out) and gives the host no address.
4. Makes a random API token, worker token, database password and owner password for the run, in
   a private temporary file that is deleted at the end. None is printed. Variables from the
   caller's environment or an `.env` file do not reach the test stack.
5. **Token phase.** `e2e/tests/seed.ts` fills the empty stack through the API, as a tester, an
   owner and a worker would (below). Then the token specs run in Chromium, Firefox and WebKit.
6. Creates the first owner on the server exactly as `docs/INSTALL.md` section 9 says
   (`python -m app.people create --owner`, the password in `ATTACKLEDGER_NEW_PASSWORD`).
7. **People phase.** `e2e/tests/people-setup.ts` signs the owner in, has them choose their own
   password, adds a reader, a tester, a reviewer and an attacker with first passwords, has each
   choose their own, and gives them roles. Then the people specs run in all three browsers.
8. Removes the containers, networks and volumes of project `al-e2e`, and nothing else
   (`docker compose -p al-e2e down --volumes`). Its images stay, as a build cache.

Inside the runner, `e2e/tests/servers.mjs` forwards `127.0.0.1:18180` to the web container, so
the browsers open the app at `http://localhost:18180`: a secure context (WebCrypto, for the
verifier and for signing keys), served by the real nginx with its real headers. The same script
serves pages of other origins on port 18181 (as `http://localhost:18181`, a sibling on the same
site, and as `http://127.0.0.1:18181`, another site) and `site/verify.html` as a static file on
port 18182.

### The guard

Every test runs under a fixture (`e2e/tests/lib.ts`, `guard`) that watches every page and tab its
browser opens, popups and raw-evidence tabs included, and fails the test on:

- a `securitypolicyviolation` event, or a CSP report in the console;
- a call to `__xss(...)`, which every injected payload would make if it ran;
- any dialog (`alert`, `confirm`, `prompt`): the app opens none;
- an uncaught exception, or a console error the test did not declare as expected (a refused
  request in a CSRF test, the 401 before signing in);
- a document without its headers. The app's pages: the CSP with `default-src 'none'`,
  `script-src 'self'` and its one hash, no `unsafe-inline` or `unsafe-eval`, `frame-ancestors
  'none'`, `object-src 'none'`, `base-uri 'none'`, `form-action 'self'`; `X-Content-Type-Options:
  nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
  `Cross-Origin-Opener-Policy: same-origin`. The API's: HTML and text under `default-src 'none'`
  with no unsafe script source, raw text under a `sandbox`, nothing served as anything but HTML,
  text or JSON, `nosniff` and `DENY`.

These browser behaviours are not counted, and only these: Firefox asks for `/favicon.ico` for a
text document that names no icon and reports the refusal as the page's violation (its source is
the browser's FaviconLoader, not the page); the browsers refuse Playwright's own helper script in a
sandboxed raw-evidence tab; WebKit refuses its own stylesheet for a document it shows as text
(text/plain, JSON) under `default-src 'none'`, measured with a two-word text/plain page, and is
excused for it on such a document only; and WebKit reports a cross-origin fetch it refused as an
uncaught error even when the page caught it, which is counted as a console error (the CSRF tests
expect it, nothing else does).

## The public site

The site phase (`E2E_PHASE=site`, `e2e/tests/site/`) checks attackledger.com as visitors get it.
It needs no stack and runs first. Inside the runner, `e2e/tests/pages-server.mjs` runs
`tools/build_pages.sh` (the deploy build, unchanged) into the runner's own `/tmp`; the checkout is
mounted read-only, so nothing is written to `site/` or `dist/`. It then serves that folder on
`http://localhost:18183` the way Cloudflare Pages serves a deployment:

- `_headers` as Pages reads it: every rule whose pattern matches applies, in order, and a header
  two rules set is joined with `, `. So `/verify` gets the site's policy and the verifier page's
  own, two policies that are both enforced, as on Pages; `! Name` removes a header.
- Pages' routing: `/x` serves `x.html`, `/x.html` and `/x/index.html` redirect (308) to `/x` and
  `/x/`, an unknown path gets the nearest `404.html` with status 404, and `_headers` itself is not
  served.

A small server of its own rather than nginx with a configuration made from `_headers`, because
what has to match is Pages' merging and routing: nginx's `add_header` in an inner location
replaces the outer ones instead of adding to them, and its `try_files` and error pages route
differently. The server is about 150 lines of the runner's Node, so there is no further image to
pin. It does not do what Pages adds on its own (compression, caching headers, ETags, Cloudflare's
default headers) or `_redirects` (the site has none), and it refuses to start on an `_headers`
rule it cannot read, such as an absolute URL, rather than skip it.

The test network has no route out, and every request a site page makes to another origin is caught
(`e2e/tests/site-lib.ts`, `offline`): one to Google Fonts, which the policy allows, is answered as
Google would answer (a stylesheet whose fonts are on `fonts.gstatic.com`, with CORS; the font is one
of the demo's own files); any other is refused and fails the test. A request the policy blocks never
gets that far: the guard sees the violation. The guard checks every site document's headers: a
policy on every path with `object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'` and a
`form-action` limit, no script source beyond the origin and hashes; on `/verify` the verifier's own
policy with `default-src 'none'`, `connect-src 'none'` and Trusted Types; `nosniff`, the
referrer policy, COOP, the permissions policy and a year of HSTS. A control test feeds the check
documents without these and sees it fail.

| Spec | Checks |
|---|---|
| `site/pages.spec.ts` | Every page reachable by links from the home page (crawled; every link resolves, every outside link is https or mailto), the four demo HTML reports and an unknown path (status 404, the site's page), in both themes, under the guard. The demo: every tab of every engagement and every lane, raw evidence opened in each, both themes; everything it loads is from the site. The downloads are served as text or JSON, `/x.html` moves to `/x`, `_headers` is not served, and `/verify` and `/verify_report.py` are byte for byte the files in `site/`. |
| `site/verify.spec.ts` | The `/verify` page on `site/sample-report.json` and every `site/demo/reports/*.json`, and on each one's HTML report, in three modes (none, `--require-history`, and with `--require-signatures` too): the status line and every check's verdict are what `verify_report.py`, the copy the site serves, prints for the same file, run in the runner; the facts list of an HTML report is the one it prints; the self-test passes. Tampered copies (a flipped bit in a receipt signature, a lane's status edited, an audit entry dropped; as JSON and inside the HTML report) fail as `verify_report.py` says, after a control (the same report written out again) verifies. A report with hostile engagement, authorization, host, lane, item, N/A, signer, evidence and audit names, as JSON under a hostile file name and inside an HTML report, fails and is shown as text, with and without the CSP. An HTML report with edited visible text, and one whose visible page is hostile markup, verify and show "What the verified report says", which gives the JSON's facts and not the edited text. |
| `site/a11y.spec.ts` | axe-core, WCAG 2.2 A and AA, on every page (home, security, verifier, sample and demo reports, the not-found page), the verifier with a result, the demo's start, every tab of its richest engagement and a lane, in both themes: no serious or critical violation. |

## WebKit

The pinned image has Playwright's WebKit build (`webkit-2359`), so every phase runs in Chromium,
Firefox and WebKit. What WebKit needed, each measured in a probe before it went in:

- It never reports the end of a document request whose URL has a fragment (every route of the
  app, `/#/e/3/ledger`): the request stays in flight and `quiet()` waited for it until it failed.
  The request tracker (`lib.ts`) now ends a page's documents at its load event, and counts
  requests by request rather than by URL (two requests for one URL are two).
- It reports a `<link rel="preconnect">` it cannot open as a console error. The test network has
  no DNS for the outside; on the site only the two Google Fonts hosts the pages name, and only
  that message, are excused.
- Its plain-text stylesheet and its uncaught-error report of a refused fetch, as in "The guard".
- It reports a no-cors answer hidden by `Cross-Origin-Resource-Policy` as "Cancelled load ...
  because it violates the resource's Cross-Origin-Resource-Policy response header": the CSRF test
  counts that as the refused (and answered) request it is, as it does Chromium's
  `ERR_BLOCKED_BY_RESPONSE`.

Nothing in the app or the site needed a change for WebKit. AUTH-2 holds in it as in the others:
it sends `Sec-Fetch-Site`, and every cross-site change is refused.

## In the CI

`.github/workflows/tests.yml` has an `e2e` job (ubuntu-24.04, which has Docker and Compose):
`tools/test_e2e.sh`, with the job's read-only token, no secrets, a checkout that keeps no
credentials, and actions pinned by commit. When a test fails, Playwright's HTML report and the
failed tests' traces (`E2E_REPORT_DIR`) are uploaded as an artifact kept 7 days. The traces hold
the run's API and worker tokens in request headers; they were random for that run and died with
its stack. `test_supply_chain.py` checks that the workflow runs the command.

## What is tested

The hostile seed (`e2e/tests/seed.ts`) uses `*.xss.test` hosts. Each hostile string carries
`<img src=x onerror=...>`, `"><svg onload=...>`, `</script><script>...`, an `<iframe srcdoc>`, a
`<style>` and a full-page `<div style>`, a `javascript:` URL, a right-to-left override left open
with Hebrew after it, and some fields a 3,000 to 5,000 character string. Every element a payload
could create carries `data-e2exss`. It goes into:

- the engagement's name, the authorization's operator and policy URL query, the research user agent;
- evidence summaries and N/A reasons on every item of a lane, the name the lane's receipt was
  signed with, attached notes and an attached HTML file (name, body, summary) kept in the blob store;
- an import: a HAR whose entries have hostile URLs, paths, queries, headers, status texts, bodies,
  comments and creator, a `javascript:` URL and an out-of-scope one, under a hostile file name;
- a test account's role (its label is refused unless it is a short name);
- recon results posted as a worker would, with a worker token made for the run: probe titles,
  stacks, web servers, redirect locations and URLs (a `javascript:` URL among them); crawled
  URLs; secret, sourcemap and GraphQL leads (titles, previews, sources, map URLs); a scanner
  finding (title, severity, template, matched-at);
- a write proposal from an outside agent driver with a hostile driver name: URL, header, body and
  reason;
- in the people phase, people's names (a reader, and a person an owner adds on the People page).

The API refuses some of them, and the seed checks that it does: a `javascript:` policy URL, a
hostile host name, and (after WE-2) a probe URL that is not an http(s) URL of the probed host.

| Spec | Checks |
|---|---|
| `token/hostile.spec.ts` | Every tab of the hostile engagement, each recon view (golden targets, hosts, URLs, leads, runs, with every Details open), every lane, every imported entry and its raw request, response and record, raw evidence, and the printable report: no element made from a payload, no `on*` attribute, no `javascript:`, `vbscript:` or `data:` link or frame, and the names shown as typed. Once with the CSP and once with the CSP switched off in the browser (`bypassCSP`), so React's escaping is tested on its own. Recon URLs that are not http(s), sent by a server as an older row would be, are shown as text, never as links. |
| `token/csp.spec.ts` | Every tab of every engagement, and the People page, in the light and the dark theme, under the guard. The documents at `/`, `/index.html`, an unknown path, a link to an engagement that does not exist, the printable report, `/api/docs` and `/api/verifier`, with their headers; every script, style and font the page loads is from its own origin. |
| `token/session.spec.ts` | Token sign-in through the form; a wrong token is refused with no cookie; the cookie is `HttpOnly`, `SameSite=Strict`, not readable by scripts and not the token; a copy of it works in another browser until sign-out, and not after (D-056); the token is never in storage. |
| `token/csrf.spec.ts` | From a sibling on the same site (which gets the cookie) and from another site: a form post that creates an engagement, `no-cors` scripted posts (text and form), a JSON post (needs a preflight, never granted), a credentialed read, a form and a scripted sign-out, a sign-in with the token. Every change is answered 403 by the API, nothing is created, the answers are not readable, and the victim stays signed in. The control: the same request from the app is accepted. |
| `token/verify.spec.ts` | The Verify tab: the report as exported verifies; tampered on its way to the browser it fails (body hash and seal); without its seal it verifies, and fails once "Require the complete history" is ticked, and verifies again when it is unticked; the token-signed receipt fails the strict check as `verify_report.py --require-history` does. The public page `site/verify.html`, served statically with its meta CSP (`connect-src 'none'`, Trusted Types): the same report, tampered and unsealed copies, the same verdicts, a hostile report and file name rendered as text, and the hostile engagement's HTML report, which verifies and gives its hostile name in the facts list as text. |
| `token/report.spec.ts` | The report of an engagement named in Turkish, Arabic and Japanese downloads as HTML and JSON under the name the app shows (WE-1). |
| `token/drafts.spec.ts` | 19 made-up credentials (headers, cookies, JSON fields, key headers, a password, a reset token, a private key, an AWS key id, a JWT, a URL with a password, GitHub, GitLab, Slack, Stripe and Google tokens), pasted and typed key by key into a lane note and an N/A reason: none is in `sessionStorage` afterwards (EV-8, WE-4); prose is kept across a reload; signing out clears every draft. |
| `token/rtl.spec.ts` | An open right-to-left override in a name, a summary and a title does not reverse the text the app writes after it (the sidebar's type and host count, evidence item labels, lead kinds), measured from where each letter is drawn; a control in plain markup shows that the measure sees a reversal. |
| `token/a11y.spec.ts` | axe-core 4.13, WCAG 2.2 A and AA rules, on the sign-in form, every main tab of the clean and the hostile engagement, two lanes, the People page, the printable report of three engagements and the public verifier page, in both themes: no serious or critical violation. |
| `people/session.spec.ts` | The owner created on the server signs in with email and password; a wrong password is refused; sign-out ends the session on the server (a copy of the cookie stops working). An owner adds a person on the People page; at their first sign-in they are asked to choose their own password, and only that one works afterwards. The token still works for automation. |
| `people/roles.spec.ts` | A reader (viewer) opens on the report, has the reader's tabs only, sees the read-only note, no new-engagement form, no People page, no evidence, item or signing controls, and links to the Team, Test accounts and Approvals tabs fall back to the report; the API refuses the same reader closing a lane, attaching evidence, approving or rejecting a write proposal, changing scope or team, and creating an engagement (403). A tester works a lane but is not offered the signature, and the API refuses it. A reviewer signs with a key made in the browser; the signed report then verifies with the complete history required, its self-test passes, and without its seal it fails only that requirement. |
| `people/csrf.spec.ts` | Login CSRF: a sibling and another site post the attacker's own email and password to the sign-in, with a reader signed in; refused, and the browser is still the reader's. The control: the same credentials sign in from the app. |
| `people/drafts.spec.ts` | In a tab opened while already signed in, a tester's unsent note survives the end of the session for the tester, and is gone when someone else signs in on that tab (WE-6). |

Counts on the final run of the first pass: the token phase ran 80 tests (40 in each browser), the
people phase 22 (11 in each). On the final runs of the second pass: the site phase ran 75 (25 in each of the three browsers),
the token phase 129 (43 in each), the people phase 33 (11 in each), all passing, in
two runs in a row of `tools/test_e2e.sh`.

## Findings

Severity is in AttackLedger's threat model (a hostile target, tool, import or compromised worker;
a malicious page in the operator's browser). Each fix has the e2e test as its regression, and a
server test where the fix is on the server (`server/tests/test_security_web_e2e.py`, 12 tests,
all failing before the fix).

| ID | Severity | Finding | Fix | Regression tests |
|---|---|---|---|---|
| WE-1 | Low | A report download (HTML or JSON) for an engagement named outside Latin-1, such as "Müşteri" or any Arabic or Japanese name, answered 500: the name went into `Content-Disposition` as UTF-8, and a header is sent as Latin-1. | `filename=` has an ASCII copy of the name, and `filename*=UTF-8''...` the name as the app shows it (RFC 6266). | `test_we1_*`; `token/report.spec.ts` |
| WE-2 | Low | A probe result's `url` was stored as the worker sent it, and the Recon tab linked the host to it: a compromised worker could make it a `javascript:` URL in the operator's session. The app's CSP blocked it (no script ran in either browser), so the app itself did not. The same views linked lead sources and crawled URLs without checking the scheme. | The API refuses a probe observation whose `url` is not an http(s) URL of the probed host. The web app links recon URLs only when they are http(s) (`webHref`), and shows anything else as text. | `test_we2_*`; the seed's refusal check; `token/hostile.spec.ts` ("recon URLs that are not http(s)") |
| WE-3 | Info | A link to an engagement the person cannot open asked the API for that engagement's approval queue before the list showed it was not theirs (the API answered 404; nothing leaked). | The approval count is asked for listed engagements only, as coverage already was. | `token/csp.spec.ts` (the link to engagement 999999, under the guard; before the fix it failed in about one run in three, when the poll came before the list) |
| WE-4 | Low | Drafts (EV-8) kept a URL with a user name and password before its host and tokens with a provider's prefix (GitHub, GitLab, Slack, Stripe, Google) in `sessionStorage`. | `SECRETISH` also catches a URL with a password and the prefixes of GitHub, GitLab, Slack, Stripe, Google, npm, Anthropic and OpenAI tokens. | `token/drafts.spec.ts` |
| WE-5 | Low | The lane panel's signing area scrolls on a short screen but could not take the keyboard focus, so it could not be scrolled from the keyboard (axe `scrollable-region-focusable`, serious). | It is a labelled, focusable region, as the panel's body already was. | `token/a11y.spec.ts` |
| WE-6 | Low | Drafts are cleared when a different person signs in on the tab (D-053), but the tab learned whose drafts they were only from its sign-in form. In a tab opened while already signed in (a second tab, or a reload), a tester's unsent note was kept, after the session ended, for the next person to sign in there. | The workspace records whose drafts they are as soon as it knows who is signed in. | `people/drafts.spec.ts` |
| WE-7 | Low | The printable HTML report's tables scroll sideways when wider than the page (the hostile engagement's item table), but the scrolling area could not take the keyboard focus, so it could not be scrolled from the keyboard (axe `scrollable-region-focusable`, serious), in all three browsers. | Every table wrapper (`report.py`, `_scroller`) is a region with `tabindex="0"` and a label ("Coverage matrix", "Items: host · lane", ...). | `test_we7_*`; `token/a11y.spec.ts` ("the printable report") |
| WE-8 | Low | The HTML report's contents links were 23.25px apart (15px text at line height 1.55), under WCAG 2.5.8's 24px target size; axe flagged the published demo report with ten sections (`target-size`, serious). | Each contents row has 0.1rem of padding (26.45px apart). The published reports (`site/sample-report.html`, `site/demo/reports/*.html`) have the same one-line CSS change; their embedded JSON is untouched and still verifies with `verify_report.py --require-history`. | `test_we8_*`; `site/a11y.spec.ts` |
| WE-9 | Low | On the landing page, the sample `verify_report.py` output is the stamp green `#2e7d4f` on the code background `#e3ead8`, 4.1:1, under AA's 4.5:1 for small text (`color-contrast`, serious, light theme). | It uses the darker `--pass` green (`#25683f`) the verifier page already uses for the same purpose. | `site/a11y.spec.ts` |

### Checked and sound

- React renders every hostile string as text in both browsers, with the CSP switched off: no
  element, attribute or link came from any payload anywhere in the app. The printable report,
  raw evidence and imported parts are inert (the API's own policies; text under `sandbox`).
- The app's CSP has no violation on any view, in either theme, in either browser; every document
  has its headers; everything loads from the app's origin.
- Sessions: `HttpOnly`, `SameSite=Strict`, ended on the server at sign-out, in token and in
  people mode; the token is never stored by the browser.
- AUTH-2 holds in both browsers: Firefox and Chromium both send `Sec-Fetch-Site`, and every
  state-changing request from a sibling or another site, sign-in and sign-out included, is
  refused. Answers to credentialed reads from another origin are unreadable (no CORS, and
  `Cross-Origin-Resource-Policy: same-origin`).
- Roles: everything a reader, a tester or a reviewer is not offered, the API refuses too.
- Both verifiers give `verify_report.py`'s verdicts on good, tampered and unsealed reports, with
  and without `--require-history`, and on a report signed in the browser.
- No serious or critical accessibility violation on the views tested, in either theme.
- WebKit (second pass): React's escaping, the CSP on every view, sessions, CSRF and login CSRF,
  roles, both verifiers and drafts behave as in Chromium and Firefox; no app change was needed.
- The public site (second pass): no CSP violation on any page or any demo view in any of the three
  browsers or either theme; every document has the headers `_headers` gives it; no request leaves
  the site except to Google Fonts, which the policy allows; every link resolves. The public
  verifier gives `verify_report.py`'s exact verdicts, check by check, on every published report in
  three modes, fails every tampered copy as it does, and shows hostile report content as text with
  and without its CSP (the page builds its DOM with no HTML parsing, under Trusted Types).
- The published reports all verify, with `--require-history` and with `--require-signatures` too
  (report 2 has no receipts, so its signature and timestamp checks are skipped, on the page and
  in `verify_report.py` alike).

### Notes, not fixed

- On the API's paths, `X-Content-Type-Options: nosniff` is sent twice (by the API and by nginx).
  Browsers read the first value, so it is harmless; the guard accepts it only when every copy
  says `nosniff`.
- A credential typed key by key is in `sessionStorage` until enough of it is typed to be
  recognised (for example, the first seven characters after `password: `). This is inherent in
  recognising credentials by their form (D-053); a pasted one is never stored.
- Playwright 1.63's Firefox loses about one navigation in ten from a new tab to a page sent with
  `Cross-Origin-Opener-Policy` (the browsing-context switch): the page loads, the test never hears
  of it. Firefox runs with its COOP handling off for that reason only (`e2e/playwright.config.ts`);
  the guard still checks that every document is sent with COOP, and Chromium enforces it.
- axe runs on the site with its `preload` off: otherwise axe itself fetches the Google Fonts
  stylesheet with `XMLHttpRequest` (to read its media queries), which the site's `connect-src
  'self'` refuses, and the guard counted it as the page's violation. The tests also wait for a
  page's entry animations (the stamps are pressed in, starting faint) before measuring contrast.
- The headers and routing are those of a server written to behave as Pages does (above), not
  Pages itself; Cloudflare's own additions are not modelled.
- WE-7's change to the report's markup reaches the published reports at their next
  `tools/build_site.sh` (it needs the demo stack and DigiCert's timestamps); they are not wide
  enough to scroll, so they pass axe as they are.
- `E2E_REPORT_DIR` must be a directory Docker can mount: with Colima on macOS, one under the home
  directory (Colima does not mount `/tmp`).
- Not covered by this suite: the production Caddy front end (`deploy/`), Cloudflare Pages itself,
  and mobile layouts.
