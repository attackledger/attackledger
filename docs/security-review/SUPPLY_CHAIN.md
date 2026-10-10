# Security review: containers and dependencies

Date: 2026-10-10. Branch `sec3-supply`, from `cf286b5`. What the images are built from, how
the containers run, and which known advisories affect the dependencies; the fixes, what was
measured on a running copy, and what is left. How to maintain it is `docs/SUPPLY_CHAIN.md`.
A follow-up on 2026-10-11 (branch `sec4-deps`) closed four of the gaps: FastAPI past 0.136, Vite 5,
GitHub Actions by tag and the base-image refresh routine ("Follow-up" below).

Network traffic in this review went only to Docker Hub, PyPI, the npm registry, the Go module
proxy and checksum database, GitHub (the worker's pinned downloads, as the build already does)
and the advisory databases `pip-audit` and `npm audit` query, except one run's passive recon
step, which queried public passive sources about the fictional `lab.test` names (the traffic note
under "Measured"). The running copies had no published port; no target outside the lab container
was contacted.

## Summary

| ID | What was found | Severity | Fix | Test |
|---|---|---|---|---|
| SC-1 | Every container ran with Docker's default capabilities (14) and a writable root filesystem, without `no-new-privileges`; Postgres, nginx (web, lab, lab proxy) and Caddy ran as root; only the production file set memory limits, none set a process limit | Low (defence in depth: no escape path was found that it would have stopped) | both compose files | `test_supply_chain.py::test_every_service_is_hardened` and three more |
| SC-2 | Base images by mutable tag. Four had stopped receiving fixes: nginx 1.27 (web, lab, lab proxy; no build since 2025-04-16), Caddy 2.8.4 (the internet-facing TLS terminator; 2024-06-04), Node 20 (end of life 2026-04, build stage only), Go 1.23 (no fixes since 2025-08; it compiled seven of the recon tools) | Medium (Caddy and nginx face clients) | digests everywhere; nginx 1.30.5, Caddy 2.11.4, Node 24.21.0, Go 1.26.9 | `test_images_are_pinned_by_digest`, `test_dockerfile_base_images_are_pinned_by_digest` |
| SC-3 | Python dependencies pinned at the top only: 12 packages named, 46 installed, the other 34 resolved to whatever PyPI had on the day of the build, with no hash checked | Medium (a build is not reproducible, and a compromised release of any transitive package would have been installed) | `server/requirements.in` and a hash-pinned lock, installed with `--require-hashes --no-deps --only-binary :all:` | `test_every_pip_install_is_hash_pinned`, `test_locks_hash_every_package_and_match_their_input` |
| SC-4 | Known advisories in the API image: cryptography 43.0.3 (6 distinct), starlette 0.41.3 (7), pip 25.0.1 (6), pytest 8.3.4 (1) | Low as used here (below), fixed anyway | cryptography 50.0.0, starlette 1.6.0 (FastAPI 0.136.3), pip 26.2.1, pytest 9.1.1 | `pip-audit`: none left |
| SC-5 | Arjun and ratelimit are published as source only: pip built them with a setuptools it fetched unpinned (build isolation) | Low | hash-pinned setuptools, `--no-build-isolation`, in a throwaway venv | as SC-3 |
| SC-6 | The web build ran npm install scripts (npm 10 in Node 20 ignores `allowScripts`); 13 advisories in development dependencies | Info (none ships: the image serves static files) | `npm ci --ignore-scripts`; Vite 5.4.21, ESLint 9.39.5, typescript-eslint 8.71.1; 2 left (below) | `test_web_build_installs_the_lockfile_without_scripts` |
| SC-7 | No SBOM | Info | `tools/sbom.sh` (CycloneDX, per image) | run here: 18 files |
| SC-8 (found while fixing SC-1) | `tools/backup.sh` and `tools/restore.sh` run root steps in the API's container. Without capabilities, root cannot read the engagement keys (`e/<id>/key.json`, uid 10001, mode 0600): measured, `tar` as root in the hardened container failed on each with `Permission denied` and exit 2, so every backup would have failed. Restore's delete and chown as root need capabilities too (not run without the change) | would have been a regression | each root step is a one-off `docker compose run` with only the capabilities it needs (`DAC_READ_SEARCH` to read; `CHOWN`, `DAC_OVERRIDE`, `FOWNER` to restore); the same for the pre-encryption upgrade command in INSTALL §7 | run here (below) |
| SC-9 (found on the running copy) | Compose refuses inline `configs: content:` for a read-only service (`` `file` is the sole supported option ``): the lab proxy would not have started in production with `--profile lab` | would have been a regression | its nginx configuration moved, unchanged, to `deploy/lab-proxy.conf` | `test_configs_are_files` |

Tests: 878 passed and 1 skipped before; 898 passed and 1 skipped after, on the rebuilt API image
(20 new tests in `server/tests/test_supply_chain.py`). `tools/release_gate.sh` passes. `cd web && npm ci && npx tsc --noEmit`,
`npm run lint` and `npm run build` pass.

## SC-1: what each container may do now

Set in `docker-compose.yml` (an `x-hardening` block merged into every service) and, for the two
services only the production file has, in `deploy/compose.prod.yml`:

| Service | User | Capabilities | Root filesystem | Writable | Memory / processes | Low port |
|---|---|---|---|---|---|---|
| db (Postgres 16.15) | 70 (the image's `postgres`) | none | read-only | its volume; tmpfs `/var/run/postgresql` (socket), `/tmp`; `shm_size` 128m | 2g / 512 | none |
| api | 10001 (image) | none | read-only | blob volume; tmpfs `/tmp` | 1g / 512 | none (8000) |
| gateway | 10002 | none | read-only | its volumes; tmpfs `/tmp` (per-host leaf certificates) | 512m / 512 | 53 (resolver) through `net.ipv4.ip_unprivileged_port_start=0` |
| worker | 10001 (image) | none | read-only | token volume; tmpfs `/tmp` (1g) and its home `/var/lib/worker` (tool settings) | 4g / 2048 (Go tools are many threads each) | none |
| web (nginx 1.30.5) | 101 (`nginx`), master process included | none | read-only | tmpfs `/var/cache/nginx` (256m: request bodies over 16 KB wait there; evidence imports are up to 50 MB), `/run`, `/tmp` | 512m (was 256m in production) / 256 | 80 through the sysctl |
| lab (nginx) | 101 | none | read-only | tmpfs as web, 32m | 128m / 256 | 80 through the sysctl |
| lab-proxy (production, `--profile lab`) | 101 | none | read-only | tmpfs as lab | 128m / 256 | none (3128) |
| caddy (production) | root | `NET_BIND_SERVICE` only | read-only | its two volumes; tmpfs `/tmp` | 256m / 256 | 80, 443 |

Every service: `security_opt: no-new-privileges:true`, `cap_drop: [ALL]`; every tmpfs is
`noexec,nosuid,nodev` with a size. The production file's memory limits (from `.env`) still apply
on top.

Why these choices:
- **Postgres as uid 70.** The image's entrypoint starts as root to chown the data folder and then
  drops to `postgres` with `su-exec`, which needs `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETUID` and
  `SETGID`. Started as `postgres` from the beginning it needs none. A data volume from an earlier
  release is already owned by uid 70 (the entrypoint chowned it then), and an empty one is
  made world-writable by the image so that any user can initialize it. Measured both: a fresh
  volume started as uid 70, and a volume initialized by the old root entrypoint (a table written,
  the container killed) started as uid 70 with no capabilities and a read-only root, recovered and
  returned the row.
- **nginx unprivileged.** With the master process as root, nginx needs `SETUID`/`SETGID` to start
  its workers and `CHOWN` for its temp folders. As uid 101 it needs neither, warns that its
  `user` directive is ignored, and binds 80 through the unprivileged-port sysctl. Docker 20.10+
  sets that sysctl to 0 in every container already; the compose files set it explicitly where a
  service depends on it, so it does not depend on the engine's default.
- **Caddy stays root, with one capability.** Its volumes (certificates, the ACME account) were
  made by root, and the operator's `deploy/certs/key.pem` is root's (INSTALL §5). The `caddy`
  binary carries `cap_net_bind_service=ep` as a file capability: measured, with that capability
  missing from the bounding set the kernel refuses to run it (`exec /usr/bin/caddy: operation not
  permitted`); with `NET_BIND_SERVICE` alone it runs.
- **The worker's tools.** They run from `/opt` (read-only); `/tmp` and `$HOME` are tmpfs and
  `noexec`. Nothing in the worker executes from them (measured: the lab pipeline below).

Not done, with reasons:
- **No seccomp or AppArmor profile of our own.** Docker's default seccomp profile applies; a
  narrower one per service would need a syscall inventory of the Go tools, Postgres and Python,
  and is easy to get wrong in ways that fail at night.
- **No user namespace remapping (`userns-remap`, rootless Docker).** It is a daemon setting, not a
  compose one; operators who need it can enable it, nothing in the compose files prevents it.
- **CPU limits** stay in the production file only (a development machine is not shared).

## SC-2 and SC-3: what the images are built from

Every `FROM` and every `image:` names its multi-arch index digest (`application/vnd.oci.image.index.v1+json`,
checked for each), with the tag it had when pinned:

| Image | Used for | Pinned |
|---|---|---|
| `python:3.12-slim` (3.12.15) | api, gateway, worker | `sha256:05cda977…6b800b0d6f` |
| `golang:1.26-bookworm` (1.26.9) | the recon tools (build stage) | `sha256:d9c68c2c…1641453c` |
| `debian:bookworm-slim` | the pinned downloads (build stage) | `sha256:7c7b2c96…cc587` |
| `node:24-alpine` (24.21.0) | the web build (build stage) | `sha256:ebfe2f90…f905ec1c1` |
| `nginx:1.30-alpine` (1.30.5) | web, lab, lab proxy | `sha256:0985e772…e27d94` |
| `postgres:16-alpine` (16.15) | db | `sha256:721873c3…6080ea` |
| `caddy:2.11-alpine` (2.11.4) | HTTPS (production) | `sha256:6aeddd44…44cb2b` |

Where each download is checked is in `docs/SUPPLY_CHAIN.md`. In short: Python packages against
SHA-256 hashes in a lock (wheels only, except Arjun's two source packages, built with a
hash-pinned setuptools); Go modules against each tool's `go.sum` and sum.golang.org, with the
settings written out and `GOTOOLCHAIN=local`; feroxbuster, nuclei-templates and the word list
against SHA-256 values recorded in the Dockerfile; npm packages against the lockfile's SHA-512,
without install scripts.

The Go 1.26 rebuild of the seven older tools (subfinder 2.6.7, dnsx 1.2.1, httpx 1.6.9, katana
1.1.2, assetfinder 0.1.1, waybackurls 0.1.0, gau 2.2.4) changes the compiler and standard library
only, not their source. They were trusted after measurement (ARCHITECTURE.md, invariants), so the
lab pipeline was run again on the rebuilt image (below), and the gateway still enforces scope,
methods, rate and identification on whatever they send.

The base images no longer change under a fixed tag; they must now be refreshed deliberately.
That is the trade: an unpinned tag picks up Debian and Alpine security updates on every
build, a pinned one only when someone moves it. `docs/SUPPLY_CHAIN.md` says how, and suggests
monthly and on any advisory naming one.

## SC-4: the Python advisories, and whether they reached us

`pip-audit` 2.x on the installed packages of the API image (`--path` on its site-packages, from a
venv in a throwaway container), before and after:

| Package | Before | Advisories | Reached by how AttackLedger uses it? | After |
|---|---|---|---|---|
| cryptography | 43.0.3 | CVE-2024-12797 and GHSA-537c-gmf6-5ccf (the OpenSSL bundled in its wheels), CVE-2026-26007 (EC public keys not checked for the prime-order subgroup), CVE-2026-34073, CVE-2026-69248, CVE-2026-69249 (X.509 verification: name constraints, chain building) | Not as far as found. We use AES-GCM (`vault.py`), ECDSA P-256 and Ed25519 signatures (`signing.py`) and certificate *issuing* for the gateway's CA (`gateway.py`). TLS is Python's `ssl` with the system OpenSSL, not the wheel's. P-256 has cofactor 1, so every valid point is in the prime-order group. We never call `cryptography.x509.verification`. The bundled OpenSSL also runs our AES-GCM and signatures, so it was upgraded regardless | 50.0.0 |
| starlette | 0.41.3 | CVE-2025-54121 (multipart rollover blocks the loop), CVE-2025-62727 (Range header in `FileResponse`), CVE-2026-48710 and CVE-2026-54282 (Host header and path in `request.url`), CVE-2026-48817 (`HTTPEndpoint` method lookup), CVE-2026-48818 (`StaticFiles` on Windows), CVE-2026-54283 (urlencoded form limits) | Mostly not: the API takes JSON only (no `Form`, `UploadFile` or `request.form()`), serves no `FileResponse` or `StaticFiles`, has no `HTTPEndpoint`, and builds no URLs from the request. One reachable read: `authz.authorize` falls back to `request.url.path` for a request no route matched (a 404 anyway); the rule lookup there is no security decision we found exploitable | 1.6.0 |
| pip | 25.0.1 | 6 (path traversal and confusion when installing crafted archives or from a malicious index) | Build time only, and every file is now hash-pinned from PyPI; it was also in the running image | 26.2.1, installed first from its own hashed lock |
| pytest | 8.3.4 | CVE-2025-71176 (`/tmp/pytest-of-<user>` on multi-user hosts) | No: the tests run in a container of their own | 9.1.1 |

After: `No known vulnerabilities found` for the API image's site-packages and its lock; the
worker image's site-packages, `/opt/arjun`, and the pip, Arjun and setuptools locks.

FastAPI went from 0.115.6 to 0.136.3, the newest that allows a starlette with these fixes while
keeping one behaviour three tests rely on: from 0.137, `app.routes` holds included routers as
`_IncludedRouter` objects instead of their routes. Measured with 0.141.1: the four tests that walk
every route (every route has a permission rule, no route reaches another organization, the
worker's routes) saw none of the included routers' routes and failed. Nothing in the
application walks `app.routes`. Moving past 0.136 first needs those tests to walk included
routers. FastAPI 0.142.4 and 0.143.0 (the newest) also require `opentelemetry-api`.
(Done in the follow-up: the tests walk included routers, FastAPI 0.141.1, starlette 1.7.0.)

Version choice: the newest release at least two weeks old that fixes every advisory
(cryptography 50.0.0 of 2026-07-31 rather than 50.0.2 of 2026-09-30, starlette 1.6.0, setuptools
84.0.0), except pytest and pip, whose newest were older than that.

## SC-6: npm

`npm audit --omit=dev`: **0** before and after (react, react-dom, two font packages and their
three small dependencies: `web.npm.cdx.json` lists 7).

`npm audit` with development dependencies: 13 before (2 low, 1 moderate, 10 high), all in the
build and lint tools; 2 after:

| Package | Advisories left | Why it stays |
|---|---|---|
| vite 5.4.21 | GHSA-4w7w-66w2-5vf9 (path traversal in the dev server's optimized-deps `.map` handling), GHSA-v6wh-96g9-6wx3 and GHSA-fx2h-pf6j-xcff (Windows only: UNC paths, alternate paths) | All three are in the development server (`npm run dev`), which no image and no install runs; the build (`vite build`) is not affected. Fixed only in Vite 6.4.3+, a major upgrade (Vite 5 → 6 or later changes the configuration and the plugin API) |
| esbuild 0.21.5 (through vite) | GHSA-67mh-4wv8-2f99 (any web page can read from the dev server) | The same development server; Vite 5 requires esbuild 0.21 |

Developers who run `npm run dev` should keep it on loopback (Vite's default) and not browse
untrusted sites meanwhile, until the Vite major upgrade.
(Done in the follow-up: Vite 8.3.1, `npm audit` 0 with development dependencies.)

## Measured on a running copy

Images built under `attackledger-{api,worker,web}:sec3-sup` (the gateway runs the API image), run
as compose project `al-sec3-sup` with an override that removed every published port and pointed
at those images; nothing of the `attackledger-*` stacks was touched. Docker 29.5.2, Compose 5.6.0,
arm64.

1. **Development file** (`docker-compose.yml`, the lab on its network as `shop.lab.test` and
   `api.lab.test`, the public development key, no timestamp authority). `docker compose up -d
   --wait`: all six services healthy. In each container `/proc/1/status` read `CapEff` and
   `CapBnd` `0000000000000000` and `NoNewPrivs: 1`; `touch /probe` failed with `Read-only file
   system`; the uids were 70, 10001, 10002, 10001, 101, 101; no port was bound on the host.
   `tools/demo_stack.py` then ran from a throwaway container on the stack's network against the
   API **through the web container** (`http://web/api`): seeding, two evidence imports (nginx
   buffered the bodies into its tmpfs: `a client request body is buffered to a temporary file
   /var/cache/nginx/client_temp/…`), inbox mapping, and the full lab recon pipeline. All 13 steps
   finished, `done`; no tool reported a read-only or permission error.
2. **The same pipeline, old against new.** Run twice more at the same time, with the default
   network made internal (no way out) in both: once on this branch's compose file and images
   (the worker rebuilt after its home moved to `/var/lib/worker`), once on the compose file of
   `cf286b5` and the images the main stack runs (`attackledger-*:latest`, Go 1.23 tools):

   | Step | before (cf286b5) | after | after, first run |
   |---|---|---|---|
   | subdomains, archive | 0, 0 | 0, 0 | 0, 0 |
   | resolve, ports, probe, wellknown | 2, 2, 4, 12 | 2, 2, 4, 12 | 2, 2, 4, 12 |
   | crawl (katana) | 16 | 28 | 10 |
   | content (feroxbuster) | 33 | 32 | 34 |
   | jsanalyze, params (Arjun), paramclass | 2, 2, 10 | 4, 2 (`partial`), 10 | 1, 1, 5 |
   | nuclei, dorks | 1, 19 | 1, 19 | 1, 19 |
   | leads | 44 (robots 4, graphql 2, secret 4, sourcemap 2, parameter 2, param-class 10, nuclei 1, dork 19) | 44, the same kinds and counts | 34 |

   The crawl varies from run to run of the *same* images (10 and 28): katana finished a
   different number of the four live services' pages (the URL lists differ by which
   services' pages are there: 28 had six pages each of `api.lab.test:8443` and `shop.lab.test:80`
   that 16 lacked), and the later steps follow from it. `params` was `partial` in
   the run with 28 URLs because it reached its 20-target limit with 4 left, as designed. With the
   same leads before and after, nothing found suggests the Go 1.26 build changed a tool's
   behaviour.

   Gateway log, after against before: target `GET` 26,705 / 26,211, `HEAD` 1 / 1, `OPTIONS` 2 / 2,
   port probes 198 allowed and 99 refused in both, one `CONNECT` refused in both (out of scope), no
   other method. The lab's access log: 26,712 / 26,216 requests, every one with the research
   identification, none with a writing method. Passive sources: 22 failed in both (no way out).
3. **Production file** (`docker-compose.yml` + `deploy/compose.prod.yml`, `--profile lab`,
   `ATTACKLEDGER_TLS=internal`, a throwaway master key file, every published port removed). The
   first start failed on the lab proxy (SC-9); after the fix, all eight services up and healthy.
   Caddy ran as root with `CapEff` and `CapBnd` `0000000000000400` (`NET_BIND_SERVICE` alone);
   the others as in step 1, the lab proxy as 101. From a throwaway container on the default
   network: HTTPS to Caddy (TLS 1.3) answered `/api/health` with `"mode":"setup"` and
   `"master_key":"configured"`, with HSTS and the security headers, and `/` with the
   Content-Security-Policy. The first owner was created with `python -m app.people create` and
   signed in through Caddy: `200`, cookie `HttpOnly; SameSite=strict; Secure`. The lab proxy
   answered `shop.lab.test` with the lab's page and `example.com` with `403 This proxy reaches
   shop.lab.test only.`
4. **Backup and restore** on the copy of step 1, after its pipeline: `tools/backup.sh` finished
   (engagements 4, evidence entries 120, receipts 10, people 2, blob files 57, migration 0023);
   `tools/restore.sh --force` of that backup restored the same counts, the engagement keys
   owned by uid 10001 again, and all 53 encrypted blobs decrypted and matched their SHA-256.
   Without the change (SC-8), `tar` as root in the hardened API container failed on each
   engagement key.
5. **An existing Postgres volume** (SC-1): initialized by the old root entrypoint, then started as
   uid 70 with no capability and a read-only root, it recovered and returned its data.

Not measured: Caddy with Let's Encrypt or an organisation certificate (option A or B); the
production stack's recon pipeline (the development file's ran, with the same services and images);
an amd64 build (the digests are of multi-arch indexes; the build ran on arm64 only).

Traffic note. In the run of step 1 the gateway had its way out, as in a real install, and the
subdomain step queried 17 public passive sources (certificate transparency logs, web archives,
DNS aggregators; 23 GET requests, 4 of them failed, 1 POST refused) for the fictional `lab.test`
names. No target was contacted outside the lab; the later runs had no way out.

## SC-7: SBOM

`tools/sbom.sh [OUT_DIR]` writes CycloneDX JSON per image and kind (OS packages, Python, Go
modules per tool, npm), with generators pinned in the script (cyclonedx-bom 7.4.0,
@cyclonedx/cyclonedx-npm 6.0.1, cyclonedx-gomod 1.12.0) run in throwaway containers. Data goes
through stdin and stdout, not bind mounts. Run here on the `sec3-sup` images: api 87 OS packages
and 46 Python packages; worker 87 and 46, Arjun 8, Go modules per tool (dnsx 100, gau 26, httpx
137, katana 124, nuclei 378, subfinder 105; assetfinder and waybackurls use the standard library
only); web 71 OS packages and 7 npm packages; Postgres 45, nginx 71 and Caddy 32 OS packages.
The output is not committed.

## Follow-up, 2026-10-11: four gaps closed

Branch `sec4-deps`. Network traffic went only to PyPI, the npm registry (packages and its
advisory database), Docker Hub (manifest lookups, base images) and the GitHub API (tag lookups).

| Gap | Before | After | Test |
|---|---|---|---|
| FastAPI held back (SC-4) | FastAPI 0.136.3, starlette 1.6.0 | FastAPI 0.141.1, starlette 1.7.0 | `test_routes.py` (4 new), and the four route-walking tests on `routewalk.py` |
| Vite 5 (SC-6) | Vite 5.4.21, @vitejs/plugin-react 4.3.4, esbuild 0.21.5 (through Vite); `npm audit` 2 | Vite 8.3.1, @vitejs/plugin-react 6.1.1, esbuild 0.28.2 (a direct development dependency); `npm audit` 0 | `npm ci --ignore-scripts`, `tsc`, lint, build; outputs compared (below) |
| Actions by tag | `actions/checkout@v4`, `actions/setup-python@v5`, `actions/setup-node@v4` | each by the full commit SHA its tag pointed at, the tag in a comment | `test_supply_chain.py::test_github_actions_are_pinned_by_commit` |
| No refresh routine for base images (SC-2) | none | `tools/refresh_pins.sh`, monthly and on any advisory naming an image (`docs/SUPPLY_CHAIN.md`) | run here (below) |

Tests: 938 passed and 1 skipped before; 943 passed and 1 skipped after, on the rebuilt API image
(5 new); `tools/test_postgres.sh` passes (944 passed on Postgres 16, and the migration-0022 upgrade check). `pip-audit` on the rebuilt image's site-packages:
`No known vulnerabilities found`.

**FastAPI.** From 0.137, `app.routes` holds an included router as one `_IncludedRouter` entry
and its routes are reached through that entry's `effective_route_contexts()`. The four tests
that walk every route now use `server/tests/routewalk.py`, which walks both shapes and fails on
any entry it does not recognise, rather than skipping it. `test_routes.py` checks the walk
against two independent lists: FastAPI's own OpenAPI schema (93 method and path pairs, the same
as the walk apart from `/openapi.json` and `/docs`, which keep themselves out of it) and the
routes each router `main.py` includes declares. Measured on 0.141.1 and on 0.143.0: the old walk
(the `APIRoute` entries of `app.routes`) saw 72 of the 95 pairs and missed all 23 of the four
included routers; the new one sees 95.

`authz.authorize` looks the rule up by `request.scope["route"].path`. For an included route,
FastAPI 0.137+ puts the included router's own `APIRoute` there, whose path is the one its router
declared, without the prefix of the include. The includes take no prefix, so the two are the
same; `test_routes.py` fails if one gains a prefix (the rule lookup would then miss, and the route
would answer owners only, which fails closed). And it proves the lookup on the running app: a
request to each of the 95 routes, with a rules table that records the lookup and stops the
request there (HTTP 418, before anything else in `authorize` and before any handler runs).
Every route reached `authorize`, and each looked up its own (method, path), which has a rule. The
app-wide `dependencies=[Depends(authz.authorize)]` still applies to included routers' routes
(that request reached `authorize` for each of them).

Version choice, as before: the newest release at least two weeks old. FastAPI 0.142.0 (2026-09-29)
and 0.143.0 (2026-10-08, the newest) are younger than that, and from 0.142 FastAPI also requires
`opentelemetry-api`, a new package in the image. The route tests and `test_people.py`,
`test_organizations.py` and `test_worker_api.py` (51 tests) pass on 0.143.0 too, so moving on is
an `.in` edit and a re-lock once it is old enough and the new dependency is accepted. Starlette
1.7.0 is of 2026-09-23.

**Vite 8.** Version choice as above: Vite 8.3.1 of 2026-09-24 (8.3.3 and 8.3.4 are of October),
@vitejs/plugin-react 6.1.1 (6.1.2 is of 2026-10-05), esbuild 0.28.2. npm's advisory database lists
no advisory for any of them. Vite 8 bundles with Rolldown and minifies CSS with Lightning CSS;
plugin-react 6 transforms JSX with Oxc, so Babel and its packages left the lockfile (174 packages
before, 136 after). Their binaries, like esbuild's, come from per-platform packages in the
lockfile, so `npm ci --ignore-scripts` still installs a working build (measured: in
`node:24-alpine` for the image, and on macOS). esbuild is no longer one of Vite's dependencies;
it is now a development dependency of its own, because `tools/build_verify.sh` and
`tools/verifier_equivalence/run.sh` call it.

The built app, Vite 5 against Vite 8, from the same sources:
- the same files (`index.html`, one script, one stylesheet, 16 font files, the icons); the image's
  build in `node:24-alpine` gave the same asset names (content hashes) as the build on macOS;
- `index.html` identical apart from the two asset names; its one inline script unchanged, so the
  `sha256-UrXTevb7…` in `web/nginx.conf`'s Content-Security-Policy still matches and no other
  inline script appeared; the script and stylesheet are loaded as before (`type="module"
  crossorigin`, no `modulepreload` inlined);
- no `eval` and no `new Function` in either bundle (the one `Function(` match is React DOM's
  `MSApp.execUnsafeLocalFunction`, in both);
- script 391.05 kB (gzip 122.35) → 392.05 kB (119.77), stylesheet 57.55 kB → 57.07 kB;
- the default browser target moved from Vite 5's `modules` (Chrome 87, Firefox 78, Safari 14) to
  Vite 8's `baseline-widely-available` (Chrome and Edge 111, Firefox 114, Safari 16.4).
- The demo build (`VITE_DEMO=1 npx vite build --base ./`, into a scratch folder) gives the same
  file set as before, with relative asset paths. `tools/build_verify.sh` wrote a byte-identical
  `site/verify.html` with esbuild 0.28.2, `tools/build_pages.sh` accepted it (its inline script
  and style match its CSP), and `tools/verifier_equivalence/run.sh` found 0 differences on 126
  reports and 107 building-block cases.

**Actions.** Each tag was resolved through the GitHub API (`git/ref/tags/<tag>`; none was an
annotated tag): `actions/checkout` v4 = v4.4.0 `11d5960a…`, `actions/setup-python` v5 = v5.6.0
`a26af69b…`, `actions/setup-node` v4 = v4.4.0 `49933ea5…`. The CLA action was already pinned; its
tag comment moved onto the `uses:` line, where the test reads it. The test also failed, as it
should, with one action set back to `@v4` and with one tag comment removed.

**Base images.** `tools/refresh_pins.sh` asks the registry (HEAD on the tag's manifest, which
Docker Hub does not count against its pull limit) for the digest each pinned tag points at now.
Run here, one day after the pins: 10 pins, 3 stale (`python:3.12-slim` in both Dockerfiles,
`caddy:2.11-alpine`), every current digest a multi-arch index. They were not moved in this
branch: the routine is for a maintainer to run, on the cadence in `docs/SUPPLY_CHAIN.md`. `--write`
replaced exactly those three digests (checked, then reverted).

## Gaps left

- **OS packages are not version-pinned.** `apt-get install ca-certificates curl unzip` takes the
  versions of that day; apt checks the signed release files, so the risk is drift, not
  tampering. Pinning them would mean snapshot.debian.org, a source the build does not use.
- **No image vulnerability scan of OS packages** (Trivy, Grype). The SBOM's OS files are the input
  such a scanner needs; adding one means a scanner and its database as new sources.
- **feroxbuster, nuclei-templates and the word list** are checked against hashes recorded at pin
  time, not against signatures or checksums their publishers sign: feroxbuster publishes none.
- **The images are not signed** (cosign or similar) and no build provenance is published. An
  install builds its own images from the repository, so the trust anchor is the git checkout
  (`git checkout` of a tag; tags are not signed either).
- **Arjun's sources** are built from sdists (hash-pinned, but their `setup.py` runs at build time).
- **Base images are refreshed by hand** (closed as a routine in the follow-up): `tools/refresh_pins.sh`
  shows what is stale, but nothing runs it on a schedule yet; a scheduled CI job running it (it
  exits 1 when a pin is stale) would remind someone.
- **Actions are pinned, not watched**: a pinned action gets no fixes until someone moves the pin
  (no Dependabot or Renovate configuration; adding one is a new service with write access to
  pull requests).
- **FastAPI 0.142+** wait for the two-week rule and a decision on `opentelemetry-api` (follow-up).
