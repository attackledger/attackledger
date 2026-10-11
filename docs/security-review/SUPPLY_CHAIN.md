# Security review: containers and dependencies

Date: 2026-10-10. Branch `sec3-supply`, from `cf286b5`. What the images are built from, how
the containers run, and which known advisories affect the dependencies; the fixes, what was
measured on a running copy, and what is left. How to maintain it is `docs/SUPPLY_CHAIN.md`.
A follow-up on 2026-10-11 (branch `sec4-deps`) closed four of the gaps: FastAPI past 0.136, Vite 5,
GitHub Actions by tag and the base-image refresh routine ("Follow-up" below). A second follow-up
the same day (branch `sec5-pins`) refreshed the stale pins, added an OS-package vulnerability scan
and decided on OS-package pinning (SC-10, SC-11; "Follow-up, 2026-10-11 (sec5-pins)"). A third
(branch `sec5-ci`) brought the CI to what contributors run, added a weekly security workflow,
extended the image scan to Go binaries and widened Dependabot (SC-12; "Follow-up, 2026-10-11
(sec5-ci)").

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
| SC-10 (second follow-up) | Caddy 2.11.4, the internet-facing TLS terminator: its binary was built with Go 1.26.3 and older `golang.org/x/net`, `x/text` and `grpc`, with 33 known Go advisories (2 Critical, 20 High) | Medium (as SC-2: it faces clients; reachability of each advisory in Caddy was not analysed) | Caddy 2.11.7 (Go 1.26.8): 20 of them fixed, 13 left that no Caddy release fixes yet | image scan by hand (below) |
| SC-11 (second follow-up) | The web image (nginx 1.30.5 on Alpine 3.24) had 4 HIGH findings with an Alpine fix (zlib, pcre2, libexpat, tiff) and OpenSSL 3.5.8, matched by 4 HIGH advisories; no newer nginx build exists. No OS-package scanner existed | Low (none reachable as used: no TLS, no gzip, no regex from clients, the modules that use expat and tiff are not loaded) | the six packages raised to minimum versions in `web/Dockerfile`; `tools/scan_images.sh` | `tools/scan_images.sh`: 0 HIGH left in web; `test_os_packages_are_installed_as_decided` and two more |
| SC-12 (third follow-up) | The image scan read OS packages only. Given the Go binaries, it finds 35 HIGH or CRITICAL rows with a fix (14 advisories) in the worker's recon tools: `golang.org/x/net` 0.17.0 to 0.31.0 and `x/text` in subfinder 2.6.7, dnsx 1.2.1, httpx 1.6.9 and katana 1.1.2; `grpc` 1.82.1, `go-git` 5.19.1, `x/crypto` 0.53.0 and `x/net` 0.56.0 in nuclei 3.11.1; `fasthttp` 1.31.0 and `x/net` 0.17.0 in gau 2.2.4 | Low (the tools are HTTP and DNS clients in the worker's sandbox, behind the gateway; the likely effect is a hostile target crashing or hanging a tool within a job's limits; reachability per advisory not analysed) | not fixed here: the tools have to move (below). The scan now reports them, and the weekly workflow fails on them | `tools/scan_images.sh`; `test_image_scan_reads_go_binaries_and_fails_on_expired_entries` |

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

## Follow-up, 2026-10-11 (sec5-pins): stale pins, an OS-package scan, OS-package pinning

Branch `sec5-pins`. Network traffic went only to Docker Hub (manifest and tag lookups, base and
scanner images), Alpine's and Debian's mirrors (the web build, and `apk version` in throwaway
containers), PyPI and the npm registry (as the builds already do) and Anchore's vulnerability
database (`grype.anchore.io`). The running copy had no published port and no way out.

**Pins.** `tools/refresh_pins.sh` reported 3 of 10 pins stale. Decided by the two-week rule
(`docs/SUPPLY_CHAIN.md`: a build at least two weeks old, unless only a younger one fixes a known
advisory), with each image's age read from its platform image configs and from Docker Hub's tags:

| Pin | Before | Newest build of the tag | Decision |
|---|---|---|---|
| `python:3.12-slim` (`server/Dockerfile`, `worker/Dockerfile`) | `05cda977…` (Python 3.12.15, Debian 13.7; amd64 and arm64 built 2026-10-06) | `a6e34c59…` (index pushed 2026-10-09) | **unchanged**. The two indexes name the same amd64, arm64, arm/v5, arm/v7, 386, ppc64le and s390x images; only riscv64 was rebuilt, which AttackLedger does not build. The current pin is itself younger than two weeks; the newest build at least two weeks old is `3.12.14-slim` (`f77ac9e4…`, 2026-09-25), which would go back to Python 3.12.14, before the 3.12.15 security release: the advisory exception keeps 3.12.15 |
| `caddy:2.11-alpine` (`deploy/compose.prod.yml`) | `6aeddd44…` (Caddy 2.11.4, built 2026-09-17) | `d8542f48…` (Caddy 2.11.7, built 2026-10-05) | **moved to 2.11.7** under the advisory exception (SC-10). No newer build is two weeks old (2.11.6: 2026-10-04; 2.11.7 replaced it a day later, and their binaries match the same advisories). Both are Alpine 3.23.6, with the same OS findings as 2.11.4 |

Every other pin is current (nginx 1.30.5, Postgres 16.15, Node 24.21.0, Go 1.26.9, Debian
bookworm-slim). After the change `tools/refresh_pins.sh` reports 2 stale (the two Python lines, as
decided).

**SC-10: Caddy's binary.** The OS-package scan below cannot see what is compiled into a Go binary,
so each Caddy image was scanned whole once (`docker save`, Grype on `docker-archive:`): 2.11.4
(Go 1.26.3, `golang.org/x/net` 0.55.0, `x/text` 0.37.0, `grpc` 1.81.0, OpenTelemetry 1.43) had 33
known Go advisories (2 Critical, 20 High, 7 Medium, 1 Low, 3 unrated), every one with a fixed
version; 2.11.6 and 2.11.7 (Go 1.26.8, `x/net` 0.59.0) have 13 (2 Critical, 8 High, 3 unrated), all
fixed only in Go 1.26.9 and `x/net` 0.60.0, which no Caddy release is built with yet. Whether each
advisory is reachable through Caddy's configuration here was not analysed; Caddy terminates TLS
and HTTP/2 for every client, so the release with fewer of them was taken.

**SC-11: the OS-package scan.** `tools/scan_images.sh` copies each image's package database out
(`/etc/os-release`, `/var/lib/dpkg/status`, `/lib/apk/db/installed`; the image is not run) into
Grype 0.119.0 (`anchore/grype:v0.119.0-nonroot`, pinned by digest; released 2026-09-17, the newest
release at least two weeks old), which scans with no network, no capability and a read-only root.
The database (schema 6.1.10, built 2026-10-10) is downloaded first, in a container of its own.
Grype rather than Trivy: one static binary in a distroless image with no shell, run as a
non-root user, so the scanner brings no package of its own into the picture. Run on the
rebuilt images, before and after the fix:

| Image | Packages | HIGH or CRITICAL (all of them HIGH) | With a fix |
|---|---|---|---|
| api, worker (Debian 13, the same 87 packages) | 159 matches in 38 packages | 55 rows, 14 advisories | 0 |
| web, before (nginx 1.30.5, Alpine 3.24.2) | 37 matches in 11 packages | 12 rows: zlib CVE-2026-85091, pcre2 CVE-2026-103111, libexpat CVE-2026-93990, tiff CVE-2026-4775; libssl3 and libcrypto3 3.5.8 with CVE-2026-54873, -72897, -84782, -84784 | 4 (OpenSSL: fix state unknown) |
| web, after | 7 matches in 6 packages | 0 | 0 |
| caddy 2.11.7 (Alpine 3.23.6) | 31 matches in 7 packages | 9 rows: zlib, and OpenSSL 3.5.8 as above | 1, accepted |
| nginx 1.30.5 (lab, lab proxy) | 37 matches in 11 packages | 12 rows, as the web image before | 4, accepted |
| postgres 16.15 (Alpine 3.24.2) | 30 matches in 6 packages | 9 rows: zlib, and OpenSSL 3.5.8 | 1, accepted |

Final run: `0 HIGH/CRITICAL with a fix, 6 accepted, 134 without a fix`, exit 0. Without
`tools/scan_ignore.txt` it exits 1 on Postgres's zlib; on a missing image, 2.

*The web image.* No newer `nginx:1.30-alpine` build exists, so `web/Dockerfile` raises the six
packages to minimum versions (`apk add --no-cache 'zlib>=1.3.2-r1' 'pcre2>=10.49-r0'
'libexpat>=2.8.5-r0' 'tiff>=4.7.2-r0' 'libssl3>=3.5.9-r0' 'libcrypto3>=3.5.9-r0'`). Alpine
published the fixes on 2026-09-24 (libexpat), 2026-10-02 (pcre2), 2026-10-07 (zlib) and 2026-10-09
(tiff): all younger than two weeks except libexpat, taken under the advisory exception. OpenSSL
3.5.9 was the version `apk version -l '<'` offered; the scanner had no Alpine record for the four
OpenSSL advisories, and after the upgrade it matches none of them, so 3.5.9 is where they end.
Other packages with a newer build (libpng, nghttp2-libs, tzdata) were left alone: nothing HIGH,
and every package moved is one more that drifts between builds. nginx is still 1.30.5, the image
builds and serves the app (the running copy below).

*Accepted, in `tools/scan_ignore.txt` until 2026-11-11* (the images run as published, which a
Dockerfile here cannot change; reviewed again at the next refresh):
- zlib CVE-2026-85091 (heap overflow in `gz_vacate()`, through the `gzFile` API with non-blocking
  writes) in Postgres, nginx and Caddy. Postgres is on the database network only, and `pg_dump`
  writes the custom format with deflate streams (`tools/backup.sh`); nginx compresses with deflate
  streams, and neither the lab nor the lab proxy enables gzip; Caddy is a static Go binary with its
  own `compress/flate`, and libz is in its image for apk and curl.
- pcre2 CVE-2026-103111 (JIT out-of-bounds write with an attacker-controlled pattern) in nginx: the
  lab's and the lab proxy's patterns are their configuration files'.
- libexpat CVE-2026-93990 and tiff CVE-2026-4775 in nginx: used by fontconfig and libgd for the
  image-filter and xslt modules, which no configuration here loads (`load_module` appears nowhere).

*Without a fix, listed.* OpenSSL 3.5.8 in Postgres, nginx and Caddy (fix state unknown; Alpine
3.24 has 3.5.9): QUIC (-54873, -84784), DTLS (-84782) and `SSL_set_SSL_CTX` part way through a
handshake (-72897). None of those images speaks TLS here: Postgres has no TLS configured, the lab
and lab proxy listen on plain HTTP, and Caddy's TLS is Go's. Debian 13 (api, worker): glibc
CVE-2026-19499 and -5435, util-linux CVE-2026-76642 and -78408 to -78410, perl-base CVE-2026-82560
and -9538, gcc-14 runtime CVE-2026-102010 and -95619, ncurses CVE-2025-69720, acl CVE-2026-54369 and
-54370, all marked "will not fix" by Debian (minor issues left to a point release); zlib
CVE-2026-85091, not fixed in Debian yet. The scan lists them on every run; a point release or a
security update moves them to "with a fix", and the scan then fails until the base image moves.

**OS-package pinning: not pinned, decided.** Exact versions are not pinned in the Dockerfiles:
Debian's and Alpine's mirrors keep only the newest build of each package, so an exact pin stops
the build at the next security update, and pinning to snapshot.debian.org would add a source to
every build (Alpine has no snapshot service). The pin would also buy little: the API, gateway and
worker images ship only their base image's packages (the worker's `apt-get install
ca-certificates` installs nothing new: the base image has 20250419, the same version), and the
build stage's curl and unzip only download files that are then checked by SHA-256. What is
installed is recorded by `tools/sbom.sh`. Where a scan finding needs a newer package than the base
image has, the Dockerfile names a minimum version, as `web/Dockerfile` does now
(`docs/SUPPLY_CHAIN.md`, "OS packages"). `test_supply_chain.py::test_os_packages_are_installed_as_decided`
refuses exact pins (`pkg=version`) and installs without `--no-cache` or `--no-install-recommends`.

**Measured on a running copy.** Images rebuilt as `attackledger-{api,worker,web}:sec5-pins`; the
production file with `--profile lab` (`docker-compose.yml` + `deploy/compose.prod.yml` and an
override that pointed at those images, removed every published port and made the default network
internal), compose project `al-sec5-pins`, `ATTACKLEDGER_TLS=internal`, a throwaway master key and
API token, no timestamp authority. All eight services up and healthy (`up --wait`); `CapEff`
`0000000000000000` and `NoNewPrivs: 1` in each but Caddy (`0000000000000400`, as before), uids 0
(Caddy), 101, 10001, 10002, 10001, 70, 101, 101. From a throwaway container on the default network,
through Caddy 2.11.7 (TLS 1.3, HSTS) and the web container: `/api/health` answered; an engagement
with scope `*.lab.test` and an attestation; a `probe` job on `shop.lab.test` ended `done` with 1
result, and the lab's access log shows the request through the gateway with the research
identification. The lab proxy answered `shop.lab.test` with the lab's page and `example.com` with
`403 This proxy reaches shop.lab.test only.` The project's containers, networks and volumes were
removed after.

Tests: 1,050 passed and 1 skipped before; 1,055 passed and 1 skipped after, on the rebuilt API
image (5 new in `test_supply_chain.py`: OS-package installs per Dockerfile, the scanner pinned by
digest, the accepted findings' format; each failed with the rule broken).

## Follow-up, 2026-10-11 (sec5-ci): CI parity, a weekly security workflow, Go binaries, Dependabot

Branch `sec5-ci`. Network traffic went only to Docker Hub (base, scanner and linter images, tag
lookups), PyPI (the pip-audit lock and pip-audit's advisory queries), the npm registry (`npm ci`,
`npm audit`), the Go module proxy (`@latest` and `go.mod` of the recon tools, read only), Anchore's
vulnerability database, GitHub (the worker build's pinned downloads) and GET requests to the
GitHub API (action release tags). No target was contacted. The workflows could not be run on
GitHub from here: they were checked with actionlint, and each command they run was run locally.

**CI parity.** `.github/workflows/tests.yml` ran the SQLite suite and the web build only. It now
has five jobs, each a command a contributor runs (`CONTRIBUTING.md`, "What the CI runs"):

| Job | Runs | Measured here |
|---|---|---|
| `server` | `python -m pytest -q server/tests`; the fuzz tests (`test_fuzz.py`, `test_security_fuzz.py`) are part of it at their default, seeded size: nothing skips them | in the full run below |
| `postgres` (new) | `docker build` of the API image, then `tools/test_postgres.sh` (the full suite on Postgres 16 in a time zone other than UTC, then the migration-0022 upgrade of a database the 0.7.1 code filled; `fetch-depth: 0` for that commit). The script now defaults to the Postgres image `docker-compose.yml` pins by digest instead of the `postgres:16-alpine` tag | 1,055 passed and 1 skipped, then 2 passed (upgrade), `[pg] PASS`, 3 min 49 s |
| `verifier` (new) | `tools/verifier_equivalence/run.sh`, then `--fuzz 500 --seed 20261010` | 134 reports and 107 building blocks, 0 differences (80 s); the 500 mutants: 0 differences, 0 tracebacks (30 s) |
| `web` | `npm ci --ignore-scripts`, `npx tsc --noEmit` (new), lint, build | `tsc` passes |
| `workflows` (new) | `tools/lint_workflows.sh`: actionlint 1.7.12 (pinned by digest) with shellcheck and pyflakes, no network, no capability, the files through stdin | 0 problems on the three workflows; a deliberately broken one gave 2 (a shellcheck warning and an unknown `github.` property) and exit 1 |

Every job keeps `permissions: contents: read`, uses no secret, and every `actions/checkout` now
has `persist-credentials: false`, so the job's token is not left in `.git/config` for the build
steps to read.

**The weekly security workflow.** `.github/workflows/security.yml`, Mondays 05:23 UTC and on
demand, read-only, no secrets (`docs/SUPPLY_CHAIN.md`, "The weekly security workflow"):

| Job | Runs | Fails | Measured here |
|---|---|---|---|
| `images` | builds api, worker, web; `tools/scan_images.sh` (with the pinned Postgres, nginx and Caddy); `tools/sbom.sh`; uploads the SBOM and Grype's reports (`actions/upload-artifact` 7.0.1, the newest release at least two weeks old) | a fixable HIGH or CRITICAL not accepted, an expired `scan_ignore.txt` entry, a failed scan; the SBOM is written and uploaded either way | scan below; SBOM: the 18 files of `docs/SUPPLY_CHAIN.md` from the `sec5-ci` images (1 min 41 s) |
| `pins` | `tools/refresh_pins.sh`, report only | a failed lookup; stale is a warning | 10 pins, 2 stale (the two Python lines, as decided in the second follow-up): a warning |
| `python` | `pip-audit --disable-pip --require-hashes` on each of the five hashed locks, one at a time (given together, pip-audit refuses two files that pin one package at different versions: measured), pip-audit 2.10.1 from its own hashed lock (`tools/ci/requirements-audit.txt`, made by `tools/lock_requirements.sh`, installed `--require-hashes --no-deps --only-binary :all:`) | any advisory | no known vulnerability in any lock; a positive control (`cryptography==43.0.3`) gave 10 and exit 1 |
| `npm` | `npm audit --omit=dev --package-lock-only`, then `npm audit --package-lock-only --audit-level=high` | any production advisory; a HIGH or CRITICAL development one | 0 and 0 |

The scan step and the pin step write their output to the run's summary; a finding is an
`::error::` annotation, a stale pin a `::warning::`. The scan's rule for `scan_ignore.txt` changed
with it: an entry past its date now fails the scan by itself (before, it was only printed, and
failed nothing once the finding it covered was gone), and an entry that matches no finding in an
image that was scanned is printed as a note, so a fix that has arrived is seen.

**SC-12: the Go binaries.** `tools/scan_images.sh` now streams each image's filesystem out
(`docker export` of a created, never started container) through a short Python filter that keeps
every ELF file containing Go's build-information marker (`\xff Go buildinf:`), wherever it is, and
puts those files next to the package databases in the scanner's input. Grype's Go cataloger then
reads each binary's module list and Go version. Found: Caddy's `/usr/bin/caddy`, the worker's eight
Go tools in `/opt/pd/bin` (feroxbuster is Rust, without embedded dependency data), and `gosu` in
the Postgres image, which nobody had listed. The api and web images have none. The whole scan of
the six images took 44 s with the database cached.

On images rebuilt from this branch (`attackledger-{api,worker,web}:sec5-ci`): `35 HIGH/CRITICAL
with a fix, 20 accepted, 135 without a fix, 0 expired entries`, exit 1. The 35 are all the
worker's Go tools:

| Tool (`worker/Dockerfile`) | Modules with a fixable HIGH or CRITICAL | Newest release (Go module proxy) |
|---|---|---|
| subfinder 2.6.7, httpx 1.6.9 | `x/net` 0.29.0 (GO-2026-4918, -5026, -5942, -6603, -6610, -6611, -6612 Critical), `x/text` 0.18.0 (GO-2026-5970) | subfinder 2.17.0 (2026-10-08, `x/net` 0.59.0); httpx 1.12.0 (2026-09-08, 0.58.0) |
| dnsx 1.2.1 | `x/net` 0.17.0 (the same seven), `x/text` 0.14.0 | 1.3.1 (2026-08-31, 0.55.0) |
| katana 1.1.2 | `x/net` 0.31.0 (the same seven), `x/text` 0.20.0 | 1.8.0 (2026-10-05, 0.58.0) |
| nuclei 3.11.1 | `grpc` 1.82.1 (GHSA-2v4p-qf9q-27wj, GHSA-vp52-pcj8-j9qc), `go-git` 5.19.1 (GHSA-hc8v-wwc9-vgxm), `x/crypto` 0.53.0 (GO-2026-6354, -6355), `x/net` 0.56.0 (GO-2026-6603, -6610, -6611, -6612) | 3.11.1 is the newest |
| gau 2.2.4 | `fasthttp` 1.31.0 (GHSA-fx95-883v-4q4h), `x/net` 0.17.0 (GO-2026-5026), `x/text` 0.13.0 | 2.2.4 is the newest (2024-10) |

assetfinder and waybackurls have none; `mholt/archiver` 3.5.1 (GHSA-7vpp-9cxj-q8gv, in four tools)
has no fix. Not fixed in this branch: `go install module@version` builds each tool with its own
`go.mod`, so the only fix is a newer release of the tool, and moving four recon tools across many
minor versions changes the worker's behaviour (flags, output) and needs the lab pipeline, not a
dependency bump; subfinder 2.17.0 and katana 1.8.0 are also younger than two weeks. Even the newest
releases leave `x/net` below 0.60.0, so GO-2026-6603, -6610, -6611 and -6612 stay in every tool
until their authors rebuild. Severity Low: the tools are clients in the worker's sandbox (no
secret, no way out but the gateway), and most of these advisories are on the HTTP/2 or DNS-parsing
side a hostile target controls, so the likely effect is a target crashing or hanging a tool within
the job's time and memory limits; each advisory's reachability was not analysed. `scan_ignore.txt`
stays closed to images built here, so the weekly scan fails on them until the tools move: that is
the reminder.

Caddy 2.11.7 (Go 1.26.8, `x/net` 0.59.0) has 14 HIGH or CRITICAL rows, 10 advisories (four in
both the standard library and `x/net`), all fixed only in Go 1.26.9 and `x/net` 0.60.0, which no
Caddy release is built with (with three unrated ones, the 13 the second follow-up counted by
hand): accepted in `scan_ignore.txt` until 2026-11-11, the same date as the OS
findings. Four are reachable in principle (HTTP Trailer handling and HTTP/2 framing, flow control
and CPU exhaustion, GO-2026-6603, -6610, -6611, -6612: Caddy terminates HTTP/2 for every client);
four are code
`deploy/Caddyfile` does not use (Windows-only `os.Root` junctions, ECH, which is not configured,
multipart form parsing and `Range` handling in `FileServer`, with no `file_server` or form
matcher); for the two CONNECT ones (an outgoing CONNECT with a body; a handler answering CONNECT
with 2xx) whether a client's CONNECT reaches them through `reverse_proxy` was not analysed. The
reason is the same for all of them: nothing to move to yet. `server/tests/test_supply_chain.py`
now accepts a Go module path (`golang.org/x/net`) or `stdlib` as the package of an entry.

**Dependabot.** `.github/dependabot.yml` existed since 2026-10-09 (D-048, with Dependabot alerts
and security updates on), which the "Gaps left" list of this review had missed: weekly pip
(`/server` only), npm, Docker and Actions, ungrouped but for npm development packages, without the
two-week rule. Now: the pip entry covers `/worker` and `/tools/ci` too; compose images are a
`docker-compose` entry (`/`, `/deploy`); every ecosystem is grouped into one weekly pull request
(npm in two, production and development) with `cooldown: default-days: 14`; a Python minor, a
Node major and a Postgres major are ignored as weekly bumps. Security updates are not delayed by
the cooldown. A Python bump cannot pass the tests until a maintainer re-locks it (the lock test
compares each lock with its `.in` file); `docs/SUPPLY_CHAIN.md`, "Dependabot", says how.
Dependabot's own validation of the file happens only on GitHub: `cooldown` and `docker-compose`
are its newest keys, and if it refuses one, its Dependabot tab says so.

**Tests.** 14 new in `test_supply_chain.py` (some per workflow): every workflow but the CLA one
read-only at the top and in each job, no `secrets.`, no `pull_request_target` or `workflow_run`;
`pull_request_target` only in `cla.yml`, whose only step is the pinned CLA action (no `run:`, no
checkout); `persist-credentials: false` on every checkout, `--ignore-scripts` on every `npm ci`,
digest-pinned job containers; the tests workflow runs each command above; the security workflow
is scheduled and on demand only, uses `bash` (pipefail), fails on a scan finding and only warns on
a stale pin, uploads its artifact even after a failure; actionlint pinned by digest with no
network; the scan reads Go binaries and fails on an expired entry; Dependabot covers every lock
directory, Dockerfile, compose file directory and npm lockfile, weekly, grouped, with a cooldown of
at least 14 days; every `requirements*.in` is in `tools/lock_requirements.sh`, in the lock test
and in the pip-audit step. Each failed with its rule broken (17 mutations, all caught).
Counts: 1,055 passed and 1 skipped before; 1,069 passed and 1 skipped after, on SQLite (the API
image) and on Postgres (`tools/test_postgres.sh`, then the 2 upgrade tests). `tools/release_gate.sh`
passes.

## Gaps left

Closed by the third follow-up (sec5-ci):
- ~~The image scan reads OS packages only~~: it reads every Go binary as well (SC-12). What it
  still does not read: feroxbuster (Rust, no embedded dependency data; its version and hash are in
  `worker/Dockerfile`), and the Python and npm packages, which `pip-audit` and `npm audit` cover.
- ~~Nothing runs the scan on a schedule~~, ~~nothing runs `tools/refresh_pins.sh` on a schedule~~:
  the weekly security workflow runs both, with `pip-audit`, `npm audit` and the SBOM; an expired
  accepted finding fails it.
- ~~Actions are pinned, not watched~~: Dependabot's `github-actions` entry (there since 2026-10-09,
  which this list had missed) now groups them weekly with the two-week cooldown.
- ~~The CI ran the SQLite suite and the web build only~~: it runs the Postgres suite, the verifier
  equivalence and its seeded fuzzing, the type check and a workflow lint as well.

Still open:
- **The worker's Go recon tools have 35 HIGH or CRITICAL rows with a fix** (SC-12): moving
  subfinder, dnsx, httpx and katana to newer releases fixes most of them and needs the lab
  pipeline; nuclei and gau have no newer release; four `x/net` advisories wait for every tool to
  be rebuilt with `x/net` 0.60.0. Until then the weekly scan fails on them, on purpose.
- **Caddy's 14 Go rows**, accepted until 2026-11-11, wait for a Caddy release built with Go 1.26.9;
  the third-party images' OS findings end the same day.
- **The workflows have not run on GitHub yet.** They were checked with actionlint and each command
  was run locally; the first runs (and Dependabot's own check of `.github/dependabot.yml`, whose
  `cooldown` and `docker-compose` keys are its newest) are the real test. GitHub stops the weekly
  schedule after 60 days without activity in the repository.
- **pip-audit has no accepted-finding list**: any Python advisory fails the weekly job. One that is
  accepted would need `--ignore-vuln` in the workflow with a comment, which nothing tests yet.
- **The scanner and the linter are pinned outside `FROM` and `image:`** (`GRYPE`, `ACTIONLINT`), so
  neither Dependabot nor `tools/refresh_pins.sh` sees them; they are checked by hand with the base
  images.
- **OS packages are not version-pinned** (decided in the second follow-up: an exact pin breaks the
  build at the next security update; a scan finding gets a minimum version instead). apt and apk
  check the signed indexes, so the risk is drift between builds, not tampering.
- **OpenSSL 3.5.8 in the Postgres, nginx (lab) and Caddy images** matches four HIGH advisories that
  Alpine has no record of; not reachable as used (no TLS through it), and gone at the next rebuild
  of those images.
- **feroxbuster, nuclei-templates and the word list** are checked against hashes recorded at pin
  time, not against signatures or checksums their publishers sign: feroxbuster publishes none.
- **The images are not signed** (cosign or similar) and no build provenance is published. An
  install builds its own images from the repository, so the trust anchor is the git checkout
  (`git checkout` of a tag; tags are not signed either). The weekly workflow builds images to scan
  them and publishes none.
- **Arjun's sources** are built from sdists (hash-pinned, but their `setup.py` runs at build time).
- **Base images are moved by hand**: the weekly workflow and Dependabot say when a pin is stale;
  choosing the build (the two-week rule) and rebuilding stay a maintainer's.
- **FastAPI 0.142+** wait for the two-week rule and a decision on `opentelemetry-api` (follow-up).
