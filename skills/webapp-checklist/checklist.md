# OWASP Web App checklist — per-item test recipes

Non-recon sections only. Each item: **how to test** · **finding when**. Batch aggressively with
`caido_batch_send`. Hand deep technique to the mapped `claude-bughunter:hunt-*` skill.

Legend for verdicts: `PASS` (tested secure) · `FINDING` (+evidence) · `N/A` (feature absent) ·
`BLOCKED` (needs 2nd account / mailbox / user action).

---

## 3. Information Gathering (light — most is recon; do the app-specific bits)

- **Manually explore / spider hidden content** — walk every nav link + every JS-referenced route
  (`grep -oE '/[a-z0-9/_-]+' bundles`, Next.js `_buildManifest.js`, route manifests). List routes the
  UI never links.
- **robots.txt / sitemap.xml / .DS_Store / security.txt** — `GET` each on every host. *Finding when:*
  robots leaks sensitive paths; sitemap enumerates internal URLs; `.DS_Store` / `.git/` present.
- **Content by User-Agent** — replay a key page with `User-Agent: Googlebot`, mobile UA, empty UA.
  *Finding when:* auth bypass / different content / debug output for a crawler UA.
- **Fingerprint tech / versions / channels** — from headers (`Server`, `X-Powered-By`, `X-AspNet*`),
  cookie names, error pages, JS libs + pinned versions. Note web vs mobile-web vs mobile-app vs API.
- **Identify user roles / entry points / client-side code** — enumerate roles from the UI + token
  claims (`userType`, `role`, `scope`). Every form + every XHR/fetch = an entry point; inventory
  method + params + auth requirement.
- **Third-party hosted content** — list every external origin the app loads (script, iframe, img,
  fetch). *Finding when:* a dangling one (subdomain-takeover / abandoned CDN).
- **Debug parameters** — try `?debug=1`, `?test=1`, `?verbose=1`, `?trace=true`, `X-Debug: 1`,
  `?__debug`, GraphQL `?debug`. *Finding when:* stack traces / extra data / disabled auth.

## 4. Configuration Management

- **Admin / common URLs** — batch `GET` `/admin`, `/administrator`, `/manage`, `/console`,
  `/actuator`, `/actuator/env`, `/actuator/health`, `/api-docs`, `/swagger-ui`, `/openapi.json`,
  `/graphql` (GET), `/graphiql`, `/.env`, `/config`, `/status`, `/metrics`, `/debug`. *Finding when:*
  200 with data / an unauthenticated admin surface / an OpenAPI/Swagger describing internal routes.
- **Old / backup / unreferenced files** — for each discovered path try `.bak .old .orig .swp .save
  ~ .1 .zip .tar.gz .git/HEAD .svn/entries`. Also `*.js.map` for every bundle (**sourcemaps**).
  *Finding when:* source / config / backup retrievable.
- **HTTP methods + XST** — `OPTIONS` (read `Allow`), then `TRACE`, `PUT`, `DELETE`, `PATCH`,
  `CONNECT` on a representative path + on the API root. *Finding when:* `TRACE` enabled (XST); `PUT`
  writes; unexpected method reaches app logic.
- **File-extension handling** — request an app route with `.json .xml .config .bak .txt` appended,
  and a static asset as a script. *Finding when:* source disclosure / MIME confusion.
- **Security headers** — one `caido_send_request` per host, check: `Content-Security-Policy`
  (+`frame-ancestors`), `X-Frame-Options`, `Strict-Transport-Security`, `X-Content-Type-Options`,
  `Referrer-Policy`, `Permissions-Policy`, `Cache-Control` on authed responses. *Finding when:*
  missing CSP frame-ancestors / XFO (clickjacking), missing HSTS, `X-Content-Type-Options` absent on
  user-content, sensitive pages cacheable.
- **Policies (Flash/Silverlight/robots/crossdomain)** — `GET /crossdomain.xml`, `/clientaccesspolicy.xml`.
  *Finding when:* `<allow-access-from domain="*"/>`. Mostly `N/A` on modern stacks.
- **Non-prod data in prod (and vice-versa)** — look for `test`/`demo`/`staging` records, seeded
  users, `X-Environment` headers, prod creds in a `dev.` host. *Finding when:* real PII in a
  test/staging host, or test data leaking into prod responses.
- **Sensitive data in client-side code** — grep bundles + sourcemaps for `api[_-]?key|secret|token|
  password|bearer |aws_|AKIA|pk_live|sk_live|-----BEGIN|firebaseConfig|sentry.*dsn|https?://[^"]+\.
  internal`. Decode base64 blobs. *Finding when:* a **server-side** secret (not a publishable key)
  is present. Publishable Stripe / Mapbox / analytics keys are usually accepted-risk — check the
  program's OOS list.
  → `claude-bughunter:hunt-source-leak`

## 5. Secure Transmission

- **TLS version / ciphers / key length** — `nuclei -t ssl` or `testssl.sh` or `sslscan` per host
  (usually already in recon nuclei output). *Finding when:* TLS 1.0/1.1 enabled, RC3/3DES/EXPORT
  ciphers, <2048-bit RSA, expired/wrong-CN cert. (Often Low / dup / informative — check program.)
- **Creds / login form / session tokens over HTTPS only** — confirm no `http://` form action, no
  token in a non-secure cookie, HTTP→HTTPS redirect on every host.
- **HSTS** — `Strict-Transport-Security` present with a sane `max-age` (+`includeSubDomains`,
  ideally `preload`).
  → `claude-bughunter:hunt-tls-network`

## 6. Authentication

- **User enumeration** — compare responses (body, status, timing, headers) for: login with
  valid-user+wrong-pass vs unknown-user; password-reset for known vs unknown email; registration
  with existing email; any `verifyIdentity`/`checkEmail` endpoint. *Finding when:* a reliable
  distinguisher (different message / status / >X ms timing delta) leaks account existence — **weigh
  impact**: bare enumeration is often Low/informative; enumeration that also returns PII is higher.
- **Authentication bypass** — no-token request to authed endpoints; tampered JWT (see Crypto); force
  browsing to post-login routes; `x-client-name`/role header swap; SSO assertion replay; alternate
  auth endpoints (legacy `/xmlrpc`, `/api/v1/login`, mobile gateway) with weaker checks.
  → `claude-bughunter:hunt-auth-bypass`, `hunt-jwt-crypto`, `hunt-saml`, `hunt-oauth`
- **Brute-force protection** — ~10–15 rapid wrong attempts against login / OTP / reset-token /
  `verifyIdentity`. Note: hard lockout vs IP-throttle vs CAPTCHA-injection vs silent shadow-throttle.
  Try IP-rotation headers (`X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`) to bypass. *Finding when:*
  no throttle after N tries, or trivially bypassed. **Keep it to ~15 requests** — enough to prove
  presence/absence, not abusive.
  → `claude-bughunter:hunt-brute-force`
- **Password quality rules** — try to set `123456`, `password`, the username, a 1-char password
  (via reset or change). *Finding when:* trivially weak password accepted.
- **Remember-me** — inspect the persistent token: is it a raw credential? predictable? no expiry?
  still valid after server-side password change?
- **Autocomplete on password fields** — check `autocomplete="off"` / `new-password` on login &
  change-password inputs (in the rendered HTML). Low.
- **Password reset / recovery** — request a reset; inspect the email link (token length/entropy,
  expiry, single-use, tied to session?); **host-header injection** (`Host:`, `X-Forwarded-Host:`,
  `X-Forwarded-Server:` → does the link point at your host?); token in Referer to third parties;
  reset without invalidating existing sessions. *Blocked without mailbox access* — then test the
  request side only (does it accept an injected host without erroring? does it leak the token in the
  HTTP response?).
  → `claude-bughunter:hunt-forgot-password`
- **Password change** — requires current password? requires re-auth / step-up? invalidates other
  sessions? rate-limited? CSRF-protected?
- **CAPTCHA** — is it enforced server-side (remove the field, replay)? token single-use? bound to
  the action/session? accepted on a different endpoint? static/predictable values accepted?
  → `claude-bughunter:hunt-captcha-bypass`
- **MFA** — enrolled? enforced on every sensitive action or just login? bypass via: skip the step
  (force-browse past it), null/empty code, brute the 6-digit code (10^6 — rate-limited?), reuse an
  old code, downgrade to a weaker factor, remove the MFA requirement via a mass-assignment on the
  profile/enroll mutation, recovery-code brute.
  → `claude-bughunter:hunt-mfa-bypass`
- **Logout presence + effectiveness** — logout exists; after logout is the access token / refresh
  token / cookie actually dead server-side (replay a captured authed request post-logout)?
- **HTTP cache management** — authed responses: `Cache-Control: no-store` / `private`, `Pragma:
  no-cache`, no sensitive data in a cacheable response, no back-button data leak.
- **Default logins** — `admin/admin`, `test/test`, `guest/guest`, vendor defaults for any admin
  panel / device found in recon.
- **User-accessible auth history** — is there a "recent logins / sessions / devices" view; does it
  leak other users' data via IDOR; is it accurate.
- **Out-of-channel notification** — does a password change / new-device login / lockout send the
  user an email/SMS alert.
- **Consistent auth across SSO'd apps** — same identity across web / mobile / partner portals; a
  token minted for app A accepted by app B's API (audience confusion); one app with weaker MFA.

## 7. Session Management

- **Mechanism** — cookie? bearer JWT? token in URL (bad)? refresh-token flow? Document it.
- **Cookie flags** — every session/auth cookie: `HttpOnly`, `Secure`, `SameSite` (Lax/Strict),
  `__Host-`/`__Secure-` prefix. *Finding when:* session cookie missing `HttpOnly` or `Secure`, or
  `SameSite=None` without justification.
- **Cookie scope** — `Domain` not overly broad (not `.example.com` for a single-app cookie);
  `Path` scoped.
- **Cookie / token duration** — access-token TTL sane; refresh-token TTL + rotation; no
  "remember me forever".
- **Termination — max lifetime / idle timeout / logout** — session dies after an absolute max age;
  after N minutes idle; immediately on logout (server-side, not just cookie clear).
- **Multiple simultaneous sessions** — allowed? if so, does logging in elsewhere invalidate the
  first (or is that configurable / notified).
- **Token randomness** — session IDs / reset tokens / API keys: high entropy, no structure, not
  sequential, not time-derived. Collect ≥2 samples and eyeball / entropy-check.
- **New token on login / role change / logout** — session fixation test: set a session pre-login,
  authenticate, check the ID rotated.
- **Consistent session mgmt across shared-session apps** — as with auth.
- **Session puzzling** — can a session variable set by one endpoint (e.g. a pre-auth flow) be
  abused by another that trusts it for authz.
- **CSRF + clickjacking** — CSRF: does a state-changing request rely only on a cookie (no
  token / no `SameSite` / no origin check)? Try it cross-site (form-encoded / `text/plain` /
  simple GET). Clickjacking: `X-Frame-Options` / `CSP frame-ancestors` on every sensitive page;
  build a framing PoC if missing.
  → `claude-bughunter:hunt-session`, `hunt-csrf`, `hunt-clickjacking`

## 8. Authorization

- **Path traversal** — any param that names a file / path / key / template / report:
  `../`, `..%2f`, `....//`, `%2e%2e/`, absolute paths, null byte, UNC. Also object-storage keys
  (S3 key params) and download/export endpoints. *Finding when:* content outside the intended dir.
  Watch for a WAF that only blocks literal `../` — try encodings + non-traversal cross-tenant keys.
  → `claude-bughunter:hunt-lfi`
- **Bypassing authorization schema** — force-browse admin/other-role routes & API ops; HTTP verb
  swap on a protected endpoint (GET blocked, POST allowed?); `X-Original-URL` / `X-Rewrite-URL` /
  `X-Override-URL` path override; trailing-slash / case / `%2e` / `;` path tricks past a gateway ACL.
- **Vertical access control (privesc)** — as a low-priv user, call admin/staff/provider operations;
  swap `role`/`userType`/`scope` in the token or a header (`x-client-name: admin_portal`); mass-assign
  a privilege field (`isAdmin`, `role`, `verified`, `userType`) on a profile/register/update call.
  → `claude-bughunter:hunt-auth-bypass`, `hunt-api-misconfig`
- **Horizontal access control (IDOR / BOLA)** — for **every** object reference (path param, query
  param, JSON body field, GraphQL id/`memberId`/cursor, header-echoed id): swap it for another
  user's / a neighbouring / a guessed value. Test **read and write/export paths separately**. Base64-
  decode opaque tokens & cursors. Test bootstrap/handshake calls, not just the final data call.
  Negative control: a nonexistent-but-valid-shape ID → distinguish "not found" from "no permission".
  **Needs a 2nd account** to conclusively separate authz-enforced from just-not-found when the API
  returns a combined error. GraphQL: `node(id:)`, `nodes(ids:)`, aliased batch, `_by_pk`, every
  `xByY` / `xById` resolver, nested-field traversal that skips re-authz.
  → `claude-bughunter:hunt-idor` (+ `hunt-fintech-graphql` / `hunt-graphql` for GraphQL)
- **Missing authorization** — endpoints reachable with **no token at all** (batch every discovered
  API path unauthenticated); resolvers/routes that were never wired to the auth middleware; new/
  shadow API versions (`/v2/`, `/internal/`, `/beta/`) with weaker checks.
  → `claude-bughunter:hunt-shadow-api`

## 9. Data Validation

For every injection: identify the sink (search box, filter, sort param, filename, JSON blob stored
& re-rendered, template, redirect target, header value), send class-specific payloads, watch for
error-based / boolean / time-based / OOB (Collaborator) signal.

- **Reflected XSS** — payloads in every reflected param + header (UA, Referer, X-Forwarded-*).
  Break out of HTML text / attribute / JS string / URL contexts. Modern SPA: usually React auto-
  escapes → check `dangerouslySetInnerHTML`, `v-html`, `.innerHTML`, `href`/`src` sinks,
  `javascript:` URIs, unsanitised markdown (`marked`/`react-markdown`+`rehype-raw`).
- **Stored XSS** — any value that persists and re-renders elsewhere (profile name, comment, filename,
  support ticket, chatbot message, form response viewed by staff). Blind: plant a payload, note it
  as a blind-stored-XSS candidate if you can't see the render surface (e.g. internal staff tool).
- **DOM XSS** — sources (`location.*`, `document.referrer`, `postMessage`, `name`) → sinks
  (`eval`, `innerHTML`, `document.write`, `setTimeout(str)`, jQuery `$()`, `Function`). Grep bundles.
  → `claude-bughunter:hunt-xss`, `hunt-dom`
- **Cross-Site Flashing** — `N/A` unless Flash content exists.
- **HTML Injection** — unescaped user input in a non-JS context (email templates, PDF generation,
  CSV/spreadsheet export = formula injection `=cmd|...`, error messages).
  → `claude-bughunter:hunt-html-injection`
- **SQL Injection** — `'`, `"`, `')`, `--`, `/**/`, `' OR '1'='1`, time-based `;WAITFOR/SLEEP`,
  on every param incl. JSON values, ORDER BY / LIMIT, headers used in logging. Boolean & time & error.
  → `claude-bughunter:hunt-sqli`
- **LDAP Injection** — `*`, `)(`, `)(cn=*`, `*)(uid=*))(|(uid=*` on login / directory-search fields.
  → `claude-bughunter:hunt-ldap`
- **ORM Injection** — operator injection in query params that map to ORM filters (`[gt]`, `[ne]`,
  `[regex]`, `where[...]`), GraphQL `where:` args, Hasura `_by_pk`/`_ilike`. Overlaps NoSQLi.
- **XML Injection / XXE** — any endpoint accepting XML / SOAP / SAML / SVG / DOCX / XLSX / RSS.
  `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>`, OOB via `http://collab`, billion-laughs
  (careful — DoS). Try flipping `Content-Type: application/json` → `application/xml`.
  → `claude-bughunter:hunt-xxe`
- **SSI Injection** — `<!--#exec cmd="id"-->`, `<!--#include virtual="..."-->` in inputs reflected
  into `.shtml` / server-parsed pages. Mostly `N/A` modern.
- **XPath / XQuery Injection** — `' or '1'='1`, `']|//user/*|//foo['` on XML-backed search/login.
- **IMAP/SMTP Injection** — CRLF into name/subject/recipient fields of contact / invite / share
  features → header injection, extra recipients, SMTP command injection.
- **Code Injection** — `;id`, `` `id` ``, `${7*7}`, `#{7*7}`, `<%= 7*7 %>` in params that might hit
  `eval`/`exec`/deserialization. Overlaps SSTI + Command + Deserialization.
  → `claude-bughunter:hunt-rce`, `hunt-deserialization`
- **Expression Language / SSTI** — `${7*7}`, `{{7*7}}`, `#{7*7}`, `*{7*7}`, `@(7*7)`, `<%= 7*7 %>`;
  identify engine from the response, then escalate. Test error pages, email/PDF templates,
  filename/label fields, i18n params.
  → `claude-bughunter:hunt-ssti`
- **Command Injection** — `;id`, `|id`, `$(id)`, `&& id`, newline-injection, on params that reach
  shell (ping/lookup/convert/export/pdf/thumbnail features). Time-based + OOB.
- **Overflow (stack/heap/integer)** — very large / negative / boundary numbers on every numeric
  param (`limit=-1`, `limit=999999999`, `page=-1`, `qty=-1`, `amount=0.001`/`-1`, `id=0`,
  `2^31`, `2^63`). *Finding when:* negative-quantity price manipulation, integer-wrap auth/paging
  bypass, 500 that leaks a stack trace.
- **Format String** — `%s%s%s%n`, `{0}`, `%x` in inputs that hit a logger/formatter. Rare on web.
- **Incubated vulnerabilities** — a stored payload that only fires later in a different context
  (stored XSS in an admin report, log injection that lands in a log viewer, a poisoned cache entry).
- **HTTP Splitting / Smuggling** — CRLF (`%0d%0a`) into headers built from params (redirect `Location`,
  `Set-Cookie`, custom headers) → response splitting. Smuggling: CL.TE / TE.CL / TE.TE against the
  front-end/back-end pair (ALB/CloudFront/nginx). **Respect the program's DoS ban** — smuggling
  probes can degrade shared infra; keep to single controlled requests, no automation.
  → `claude-bughunter:hunt-http-smuggling`, `hunt-host-header`
- **HTTP Verb Tampering** — `HEAD`/`PUT`/`PATCH`/`DELETE`/arbitrary method on protected routes;
  `X-HTTP-Method-Override` / `_method` param to smuggle a method past an ACL.
- **Open Redirection** — every `redirect|url|next|return|returnTo|callback|dest|continue|image|file`
  param: `//evil.com`, `https://evil.com`, `https:evil.com`, `/\evil.com`, `https://trusted@evil.com`,
  `https://trusted.evil.com`, `https://trusted%2eevil.com`, path-relative `..`. Also OAuth
  `redirect_uri` (usually IdP-enforced exact match — confirm), and open-redirect→OAuth-token-theft
  chains.
  → `claude-bughunter:hunt-open-redirect`
- **Local / Remote File Inclusion** — `file|page|template|lang|include|path|doc` params:
  `../../etc/passwd`, `php://filter`, `data://`, `http://collab/x` (RFI). PHP-era mostly; also
  Node path joins, Java `getResourceAsStream`, template-path params.
  → `claude-bughunter:hunt-lfi`
- **Client-side vs server-side validation** — find a field with JS validation, bypass the JS
  (send the request directly), confirm the server re-validates. *Finding when:* server trusts the
  client (e.g. price, role, email-verified, max length, allowed values).
- **NoSQL Injection** — `{"$ne":null}`, `{"$gt":""}`, `{"$regex":"..."}`, `[$ne]=` in query string,
  operator injection in JSON bodies, GraphQL `where` args. Auth bypass + data extraction.
  → `claude-bughunter:hunt-nosqli`
- **HTTP Parameter Pollution** — duplicate params (`?id=self&id=victim`) in query & body & mixed;
  array vs scalar (`id[]=`); duplicate JSON keys; duplicate `operationName`. *Finding when:* a
  security decision uses one occurrence and the data layer uses another.
  → `claude-bughunter:hunt-api-misconfig`
- **Auto-binding / Mass Assignment** — add unexpected fields to create/update bodies:
  `{is_admin:true, role:"admin", verified:true, userId:<victim>, price:0, balance:999,
  emailVerified:true, mfaRequired:false}`. GraphQL: check if the input type is a strict allowlist
  (send a junk field — does it reject?). *Finding when:* server persists a field the UI never sends.
  → `claude-bughunter:hunt-api-misconfig`
- **NULL / Invalid Session Cookie** — request with cookie deleted / empty / malformed / another
  user's expired token. *Finding when:* 500 (unhandled), or fail-open (treated as a valid session /
  default user).

## 10. Denial of Service — **program usually bans DoS. Test only anti-automation, single requests.**

- **Anti-automation** — is there rate limiting / CAPTCHA on expensive endpoints (search, export,
  report gen, GraphQL, image processing, email send)? (Prove presence/absence with ≤15 requests.)
- **Account lockout** — does repeated failed login lock the account (and can an attacker weaponise
  that to lock out victims = a finding in itself)?
- **HTTP protocol DoS** — *do not run.* Note only: slowloris / large-header / decompression-bomb
  surface (e.g. an endpoint accepting gzip'd bodies with no size cap).
- **SQL wildcard DoS** — a search param that allows `%` / `_` / expensive `LIKE` with no limit —
  note it, don't hammer it.

## 11. Business Logic

- **Feature misuse** — every workflow: can a step be skipped, repeated, run out of order, run after
  it should be closed? (checkout without payment, submit after deadline, re-use a one-time link,
  approve your own request).
- **Lack of non-repudiation** — actions with no audit trail; ability to act as another user with no
  attribution; editable history.
- **Trust relationships** — the app trusts a client-supplied value it shouldn't: price, tax,
  currency, quantity, discount, tenant id, "email verified", a redirect from a payment provider,
  a webhook with no signature check.
- **Integrity of data** — negative / fractional / overflow quantities & amounts; stacking coupons;
  archived-price swap; currency confusion; editing an order after submission; race conditions on
  balance / coupon / invite / booking (send N parallel requests → over-redeem).
  → `claude-bughunter:hunt-business-logic`, `hunt-race-condition`
- **Segregation of duties** — one user performing two roles that should be separate (create + approve;
  request + fulfil; submit + review).

## 12. Cryptography

- **Data that should be encrypted isn't** — PII/PHI/secrets in cleartext in responses, logs, URLs,
  localStorage, JWT payload (it's only base64!), a non-TLS channel.
- **Wrong algorithm for context** — ECB mode (pattern leakage), encryption where you need a MAC,
  reversible encoding mistaken for encryption, predictable IV/nonce reuse.
- **Weak algorithms** — MD5/SHA1 for signatures/passwords, DES/3DES/RC4, RSA<2048, `alg:none` /
  HS256-where-RS256-expected (JWT), static keys.
  → `claude-bughunter:hunt-jwt-crypto`
- **Salting** — password hashes salted + slow (bcrypt/argon2/scrypt) — usually inferable only from
  a leak; check reset-token / API-key derivation isn't `hash(secret+id)` with a guessable secret.
- **Randomness** — tokens/IDs/nonces from a CSPRNG not `Math.random()` / timestamp / sequential
  counter. Collect samples, look for structure/predictability.

## 13. File Uploads

- **Acceptable types whitelisted** — try disallowed extensions & MIME (`.php .jsp .svg .html .xhtml
  .phtml .shtml`), double ext (`x.png.php`), null byte, case (`.PhP`), trailing dot/space, magic-byte
  spoof (real image header + appended payload), `Content-Type` spoof (does the server check the
  header or the bytes?).
- **Size / frequency / count limits** — enforced server-side? (test just past the limit, not a DoS).
- **Contents match declared type** — upload a polyglot / a text file as `image/png` — accepted?
- **Anti-virus scanning** — upload the EICAR test string — is it rejected/quarantined?
- **Unsafe filenames sanitised** — `../../x`, `x;id`, very long, unicode, `x.png%00.php`,
  reserved names (`CON`, `.htaccess`, `web.config`).
- **Not accessible in web root** — is the uploaded file retrievable at a predictable/guessable URL,
  and if so is it executed / rendered (stored XSS via SVG/HTML) or served safe (`Content-
  Disposition: attachment`, `X-Content-Type-Options: nosniff`, restrictive CSP, forced content-type)?
- **Served on a different hostname/port** — user content on the app origin = XSS risk; on a
  sandbox origin = good.
- **Integrated with authn/authz** — can you read another user's uploaded file by id (IDOR)? Is the
  upload URL / download URL / storage key guessable or client-controlled (→ arbitrary object read)?
  → `claude-bughunter:hunt-file-upload`

## 14. Card Payment (if a payment surface exists — else `N/A`)

- **Known vulns / misconfig on the payment components** — version-fingerprint the payment iframe /
  SDK / gateway integration; check for known CVEs.
- **Default / guessable passwords** — on any merchant/admin payment console found.
- **Non-prod data** — test card numbers accepted in prod; prod PANs in a test env.
- **Injection** — all Data Validation payloads against payment params (amount, currency, card ref,
  billing fields).
- **Buffer overflows** — boundary values on amount / quantity.
- **Insecure crypto storage** — is a card ref / token reversible; is CVV ever stored/echoed; is the
  card tokenisation done client-side to the gateway (good) or does the PAN transit your server (bad).
- **Insufficient TLS** — payment endpoints on modern TLS only.
- **Improper error handling** — a declined/errored payment leaking gateway internals / stack traces /
  card BIN data.
- **All vulns CVSS > 4.0** — treat the payment path as max-severity scope.
- **Authn/Authz** — can you retrieve/modify another user's saved card, payment method, transaction
  history (IDOR)? get a gateway ephemeral key (Stripe `ephemeralKey`) for a card you don't own?
- **CSRF** — add-card / change-payment-method / checkout without a CSRF token or SameSite.
  → `claude-bughunter:hunt-business-logic`, `hunt-api-misconfig`

## 15. HTML5

- **Web Messaging (postMessage)** — grep for `addEventListener("message"` handlers; do they check
  `event.origin`? do they route data into a sink (`eval`, `innerHTML`, `location`, token storage)?
  Send a cross-origin `postMessage` from your PoC page.
- **Web Storage** — sensitive data (tokens, PII) in `localStorage`/`sessionStorage` (readable by
  any XSS); any code that `eval`s / SQL-parses storage contents; storage keyed data trusted for authz.
- **CORS implementation** — for every API host: `Origin: https://evil.com`, `Origin: null`,
  `Origin: https://<target>.evil.com`, `Origin: https://evil-<target>.com`, plus a
  legit-subdomain origin. Check `Access-Control-Allow-Origin` reflection + `Access-Control-Allow-
  Credentials: true`. *Finding when:* arbitrary/null/regex-bypass origin reflected **with**
  credentials true.
  → `claude-bughunter:hunt-cors`
- **Offline Web Application** — `manifest`/AppCache/Service Worker caching sensitive pages; a
  Service Worker with an over-broad scope or a cache-poisoning angle.
- **WebSockets** (bonus — not in the source list but HTML5-era) — no origin check on the WS
  handshake (CSWSH), no auth on the socket, IDOR in WS messages, missing rate limit.
  → `claude-bughunter:hunt-websocket`

---

## GraphQL overlay (apply throughout if the target uses GraphQL)

- **Introspection** — `{__schema{types{name}}}` and the full introspection query. Off = good; on =
  config-disclosure finding + free schema.
- **Schema without introspection** — reconstruct from captured operations + JS bundle operation
  strings + field-suggestion errors ("Did you mean…").
- **Every `xById` / `xByY` / `node(id:)` resolver** — IDOR test (section 8).
- **Mutations** — mass-assignment on input types (section 9 auto-binding); missing authz (section 8);
  business logic (section 11).
- **Batching / aliasing** — array-of-queries body, 100× aliased field → anti-automation / cost
  (section 10, don't hammer).
- **Directives** — `@skip`/`@include` with weird args, `@defer`/`@stream` if supported.
- **CSRF** — does it accept `GET` / `application/x-www-form-urlencoded` / `text/plain`? (all = CSRF
  possible). JSON-only + no cookie auth = safe.
- **Depth / complexity limit** — a deeply nested recursive query (relationship cycles) — is it
  capped? (probe once, don't loop).
