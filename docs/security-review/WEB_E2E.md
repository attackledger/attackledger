# Security review: browser end-to-end tests of the web app

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

## How to run it

```sh
tools/test_e2e.sh            # build, start, seed, both phases in both browsers, tear down
tools/test_e2e.sh --keep     # leave the stack running afterwards; tools/test_e2e.sh --down removes it
tools/test_e2e.sh -g drafts  # arguments go to `playwright test` (here: only tests named "drafts")
```

It needs Docker with Compose 2.24 or later, and nothing else on the host: no Node, no browser.
It takes about 3 minutes once the images are built (the first build of the API image, the web
image and the runner takes longer).

What it does:

1. Builds this tree's API and web images and the runner image (`e2e/Dockerfile`: Playwright's own
   image, pinned by the digest of its multi-arch index, with `npm ci` of `e2e/package-lock.json`;
   Playwright 1.63.0 and axe-core 4.13.0, each the newest release at least two weeks old).
2. Starts the database, the API and the web app as compose project `al-e2e`
   (`e2e/compose.e2e.yml` on top of `docker-compose.yml`): its own containers, networks and
   volumes, no gateway, worker or lab, the public development key, no timestamp authority, and no
   port published on the host. The runner and the web app share a network of their own,
   `al-e2e_browser`, which is internal (no route out) and gives the host no address.
3. Makes a random API token, worker token, database password and owner password for the run, in
   a private temporary file that is deleted at the end. None is printed. Variables from the
   caller's environment or an `.env` file do not reach the test stack.
4. **Token phase.** `e2e/tests/seed.ts` fills the empty stack through the API, as a tester, an
   owner and a worker would (below). Then the token specs run in Chromium and Firefox.
5. Creates the first owner on the server exactly as `docs/INSTALL.md` section 9 says
   (`python -m app.people create --owner`, the password in `ATTACKLEDGER_NEW_PASSWORD`).
6. **People phase.** `e2e/tests/people-setup.ts` signs the owner in, has them choose their own
   password, adds a reader, a tester, a reviewer and an attacker with first passwords, has each
   choose their own, and gives them roles. Then the people specs run in both browsers.
7. Removes the containers, networks and volumes of project `al-e2e`, and nothing else
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

Two browser behaviours are not counted, and only these: Firefox asks for `/favicon.ico` for a
text document that names no icon and reports the refusal as the page's violation (its source is
the browser's FaviconLoader, not the page), and the browsers refuse Playwright's own helper script
in a sandboxed raw-evidence tab.

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
| `token/verify.spec.ts` | The Verify tab: the report as exported verifies; tampered on its way to the browser it fails (body hash and seal); without its seal it verifies, and fails once "Require the complete history" is ticked, and verifies again when it is unticked; the token-signed receipt fails the strict check as `verify_report.py --require-history` does. The public page `site/verify.html`, served statically with its meta CSP (`connect-src 'none'`, Trusted Types): the same report, tampered and unsealed copies, the same verdicts, and a hostile report and file name rendered as text. |
| `token/report.spec.ts` | The report of an engagement named in Turkish, Arabic and Japanese downloads as HTML and JSON under the name the app shows (WE-1). |
| `token/drafts.spec.ts` | 19 made-up credentials (headers, cookies, JSON fields, key headers, a password, a reset token, a private key, an AWS key id, a JWT, a URL with a password, GitHub, GitLab, Slack, Stripe and Google tokens), pasted and typed key by key into a lane note and an N/A reason: none is in `sessionStorage` afterwards (EV-8, WE-4); prose is kept across a reload; signing out clears every draft. |
| `token/rtl.spec.ts` | An open right-to-left override in a name, a summary and a title does not reverse the text the app writes after it (the sidebar's type and host count, evidence item labels, lead kinds), measured from where each letter is drawn; a control in plain markup shows that the measure sees a reversal. |
| `token/a11y.spec.ts` | axe-core 4.13, WCAG 2.2 A and AA rules, on the sign-in form, every main tab of the clean and the hostile engagement, two lanes, the People page and the public verifier page, in both themes: no serious or critical violation. |
| `people/session.spec.ts` | The owner created on the server signs in with email and password; a wrong password is refused; sign-out ends the session on the server (a copy of the cookie stops working). An owner adds a person on the People page; at their first sign-in they are asked to choose their own password, and only that one works afterwards. The token still works for automation. |
| `people/roles.spec.ts` | A reader (viewer) opens on the report, has the reader's tabs only, sees the read-only note, no new-engagement form, no People page, no evidence, item or signing controls, and links to the Team, Test accounts and Approvals tabs fall back to the report; the API refuses the same reader closing a lane, attaching evidence, approving or rejecting a write proposal, changing scope or team, and creating an engagement (403). A tester works a lane but is not offered the signature, and the API refuses it. A reviewer signs with a key made in the browser; the signed report then verifies with the complete history required, its self-test passes, and without its seal it fails only that requirement. |
| `people/csrf.spec.ts` | Login CSRF: a sibling and another site post the attacker's own email and password to the sign-in, with a reader signed in; refused, and the browser is still the reader's. The control: the same credentials sign in from the app. |
| `people/drafts.spec.ts` | In a tab opened while already signed in, a tester's unsent note survives the end of the session for the tester, and is gone when someone else signs in on that tab (WE-6). |

Counts on the final run: the token phase ran 80 tests (40 in each browser), the people phase 22
(11 in each), all passing, in two runs in a row of `tools/test_e2e.sh`.

## Findings

Severity is in AttackLedger's threat model (a hostile target, tool, import or compromised worker;
a malicious page in the operator's browser). Each fix has the e2e test as its regression, and a
server test where the fix is on the server (`server/tests/test_security_web_e2e.py`, 10 tests,
all failing before the fix).

| ID | Severity | Finding | Fix | Regression tests |
|---|---|---|---|---|
| WE-1 | Low | A report download (HTML or JSON) for an engagement named outside Latin-1, such as "Müşteri" or any Arabic or Japanese name, answered 500: the name went into `Content-Disposition` as UTF-8, and a header is sent as Latin-1. | `filename=` has an ASCII copy of the name, and `filename*=UTF-8''...` the name as the app shows it (RFC 6266). | `test_we1_*`; `token/report.spec.ts` |
| WE-2 | Low | A probe result's `url` was stored as the worker sent it, and the Recon tab linked the host to it: a compromised worker could make it a `javascript:` URL in the operator's session. The app's CSP blocked it (no script ran in either browser), so the app itself did not. The same views linked lead sources and crawled URLs without checking the scheme. | The API refuses a probe observation whose `url` is not an http(s) URL of the probed host. The web app links recon URLs only when they are http(s) (`webHref`), and shows anything else as text. | `test_we2_*`; the seed's refusal check; `token/hostile.spec.ts` ("recon URLs that are not http(s)") |
| WE-3 | Info | A link to an engagement the person cannot open asked the API for that engagement's approval queue before the list showed it was not theirs (the API answered 404; nothing leaked). | The approval count is asked for listed engagements only, as coverage already was. | `token/csp.spec.ts` (the link to engagement 999999, under the guard) |
| WE-4 | Low | Drafts (EV-8) kept a URL with a user name and password before its host and tokens with a provider's prefix (GitHub, GitLab, Slack, Stripe, Google) in `sessionStorage`. | `SECRETISH` also catches a URL with a password and the prefixes of GitHub, GitLab, Slack, Stripe, Google, npm, Anthropic and OpenAI tokens. | `token/drafts.spec.ts` |
| WE-5 | Low | The lane panel's signing area scrolls on a short screen but could not take the keyboard focus, so it could not be scrolled from the keyboard (axe `scrollable-region-focusable`, serious). | It is a labelled, focusable region, as the panel's body already was. | `token/a11y.spec.ts` |
| WE-6 | Low | Drafts are cleared when a different person signs in on the tab (D-053), but the tab learned whose drafts they were only from its sign-in form. In a tab opened while already signed in (a second tab, or a reload), a tester's unsent note was kept, after the session ended, for the next person to sign in there. | The workspace records whose drafts they are as soon as it knows who is signed in. | `people/drafts.spec.ts` |

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
- Not covered by this suite: the static demo (`site/demo/`, built with `VITE_DEMO=1`), the
  production Caddy front end (`deploy/`), WebKit, and mobile layouts.
