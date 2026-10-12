# Supply chain: what the images are built from, and how to check it

How AttackLedger's images get their contents, how a maintainer changes them, and how an
operator or an auditor lists what is inside (an SBOM). The review that set this up, with
what was measured and the gaps left, is `docs/security-review/SUPPLY_CHAIN.md`.

## What a build downloads, and how each download is checked

| What | From | Checked by |
|---|---|---|
| Base images (Python, Go, Debian, Node, nginx, Postgres, Caddy) | Docker Hub | the digest of the image's multi-arch index, in each `FROM` line and `image:` (the tag next to it is a comment for people) |
| Python packages (API, gateway, worker) | PyPI | `server/requirements.txt`: every package, transitive ones too, pinned with the SHA-256 of each of its files; installed with `pip --require-hashes --no-deps --only-binary :all:` (wheels only: no package's build code runs) |
| pip itself | PyPI | `server/requirements-pip.txt`, hashed; installed first |
| Arjun (worker) | PyPI | `worker/requirements-arjun.txt`, hashed, in its own folder. Arjun and ratelimit are published as source only; they are built with the hash-pinned setuptools of `worker/requirements-arjun-build.txt`, without pip's build isolation (which would fetch an unpinned one) |
| Go recon tools (subfinder, dnsx, httpx, katana, nuclei, assetfinder, waybackurls, gau) | the Go module proxy | `worker/build_go_tool.sh`, each tool an exact release: `go install module@version` (each module against the tool's `go.sum` and the public checksum database, sum.golang.org), or, for a tool with dependencies raised to fix advisories, the release built with those modules at exact versions, every module checked against the checksum database ("The Go recon tools" below). `worker/Dockerfile` writes these settings out (`GOSUMDB`, `GOPROXY`, no `GONOSUMDB`/`GOPRIVATE`/`GOINSECURE`) and sets `GOTOOLCHAIN=local`, so no other Go toolchain is fetched |
| feroxbuster, nuclei-templates, the SecLists word list | GitHub | a SHA-256 recorded in `worker/Dockerfile` when the version was pinned; the build fails on a mismatch |
| npm packages (web build stage only) | the npm registry | `npm ci` from `web/package-lock.json`, each package against its SHA-512 there; `--ignore-scripts`, so no install script runs |
| GitHub Actions (CI only: `.github/workflows/`) | GitHub | each `uses:` names the full commit SHA its tag pointed at when pinned, with the tag in a comment (`server/tests/test_supply_chain.py` checks) |
| Debian packages (`ca-certificates`, `curl`, `unzip`, in the worker's build stage; `ca-certificates` in its image is already the base image's) and Alpine packages (six raised to a minimum version in `web/Dockerfile`) | Debian's and Alpine's mirrors | apt's and apk's signed indexes. Not pinned to exact versions, on purpose ("OS packages" below); every other OS package is the pinned base image's |

## Changing a dependency

Python: edit the `.in` file, never the `.txt` lock, then re-lock and rebuild:

```sh
tools/lock_requirements.sh                         # every lock
tools/lock_requirements.sh server/requirements.in  # or one
git diff server/requirements.txt                   # read it: new packages, new hashes
```

`tools/lock_requirements.sh` runs `pip-compile` (pip-tools, pinned in the script) in a throwaway
container of the same Python image the Dockerfiles use, so the lock is resolved for Linux and
Python 3.12 on any machine. It talks to PyPI only. `server/tests/test_supply_chain.py` fails if
a lock no longer matches its `.in` file or a package has no hash.

The pip-audit the weekly workflow uses is locked the same way (`tools/ci/requirements-audit.in`).

npm: change `web/package.json`, run `npm install --package-lock-only` in `web/`, review the lock
diff, then `npm ci --ignore-scripts && npx tsc --noEmit && npm run lint && npm run build`.
`tools/build_verify.sh` and `tools/verifier_equivalence/run.sh` use the esbuild of
`web/node_modules` (a development dependency of its own, not Vite's): after changing it, run both
and check that `site/verify.html` is unchanged or that its change is intended.

Which version: the newest release at least two weeks old (a release that is withdrawn or
compromised is usually found within days), unless only a younger one fixes a known advisory.
Check with `pip-audit` and `npm audit` (below).

### Dependabot

`.github/dependabot.yml` asks Dependabot for one grouped pull request a week per ecosystem: the
Python `.in` files (`server/`, `worker/`, `tools/ci/`), the web's npm packages (production and
development in two groups), the Dockerfiles' base images, the compose files' images and the
GitHub Actions. Each waits 14 days after a release (`cooldown: default-days: 14`, the two-week
rule); security updates (on in the repository settings) come at once and skip it. A new Python
minor, a Node major and a Postgres major are left out of the weekly updates: each is a decision
of its own (the locks are resolved for Python 3.12). Dependabot's pull requests get a read-only
token and no secrets, like any pull request, and the CLA workflow lets `dependabot[bot]` through.

What a maintainer does with each pull request:

- **Python.** Dependabot edits a `.in` file or a lock, but the locks are made by
  `tools/lock_requirements.sh` (with every transitive package and its hashes, for Linux and
  Python 3.12), so `test_supply_chain.py` fails until the lock matches the `.in` file again. Check
  out the branch; for a package named in the `.in` file, make sure the new version is there (put
  it there if Dependabot changed only the lock); then re-lock. pip-compile keeps the versions
  already in the lock where it can, so a transitive package Dependabot raised in the lock stays
  raised, now with its full set of hashes:

  ```sh
  gh pr checkout <number>
  tools/lock_requirements.sh server/requirements.in     # or the .in file the pull request is about
  git diff                                              # new packages, new hashes
  git commit -am "Re-lock" && git push
  ```

  Once someone else has pushed to it, Dependabot stops rebasing the branch; rebase it yourself
  or ask Dependabot to recreate it (`@dependabot recreate`) and re-lock again.
- **npm.** Dependabot updates `package-lock.json` itself; the CI's `web` and `verifier` jobs
  build and check it. A change to esbuild needs the check in "Changing a dependency" (the
  verifier page).
- **Docker.** Each base image moves to its tag's newest build that is two weeks old. Update the
  version and date in the comment above the line, rebuild, run the tests, `tools/test_postgres.sh`
  and `tools/scan_images.sh`, as in "Refreshing the base images". Dependabot may not read
  `deploy/compose.prod.yml` (not a compose file name it looks for); the weekly
  `tools/refresh_pins.sh` covers every pin either way.
- **GitHub Actions.** Dependabot moves the commit SHA, but not always the version in the
  comment: #21 moved checkout to v7 and kept "v4.4.0". On such a pull request, correct the comment,
  record the new commit and tag in `tools/ci/action-pins.txt`, and run
  `tools/ci/check_action_pins.sh`, which confirms each line against GitHub.
  `test_supply_chain.py` fails until the pin, its comment and that file agree. Read the release
  notes before a new major.

If Dependabot ever refuses the configuration (a key it does not support for an ecosystem), it
says so on the repository's Insights, Dependency graph, Dependabot tab and stops that ecosystem's
updates; `cooldown` is the newest key here.

A base image: pull the new tag, read its index digest and put both in the file:

```sh
docker pull python:3.12-slim
docker image inspect python:3.12-slim --format '{{.Descriptor.Digest}}'   # containerd image store
docker buildx imagetools inspect python:3.12-slim                         # or, with buildx
```

The digest must be the index's (`application/vnd.oci.image.index.v1+json` or a Docker manifest
list), not one platform's, or the other architecture stops building.

### Refreshing the base images

A pinned digest does not pick up the Debian or Alpine security fixes later builds of the same
tag carry. `tools/refresh_pins.sh` lists every digest-pinned `FROM` and `image:` with the digest
its tag points at today:

```sh
tools/refresh_pins.sh            # report: current or STALE per pin; changes nothing
tools/refresh_pins.sh --write    # also put each tag's current digest in place of a stale one
```

It asks the registry with HEAD requests on the tags' manifests (Docker Hub does not count those
against its pull limit); nothing is pulled or run. Exit status 0 means every pin is current, 1 that
at least one is stale, 2 that a lookup failed, so a scheduled job can run it. It warns when a tag
resolves to a single-platform manifest. The benchmark target (`tools/benchmark/`) is pinned to one
release on purpose and is left out.

Suggested cadence: **monthly**, and **at once when an advisory names a base image** (Debian and
Alpine security announcements, the Docker Official Images' release notes) or one of its
packages. After `--write`: update the version and date in the comment above each changed line
(`docker run --rm IMAGE ...` shows the version, for example `python --version` or `nginx -v`),
review `git diff`, rebuild the images (`docker compose build`), run the tests,
`tools/test_postgres.sh` and `tools/scan_images.sh`, and for the worker image the lab pipeline.

To move to a new tag (a new minor or major), edit the tag in the file first, then run it with
`--write`.

Which digest: as for packages, a build at least two weeks old, unless only a younger one fixes a
known advisory. `--write` takes the tag's newest build, so check its age first (the `created` of
each platform's image config, or the tag's `last_updated` on Docker Hub, which also lists the
patch-version tags, `2.11.6-alpine`, `3.12.14-slim`, each still on its last build). The registry
keeps no history of a tag, so an older build of the same tag is reachable only through such a
patch-version tag. A tag can also move for a platform AttackLedger does not build: compare the
`linux/amd64` and `linux/arm64` manifest digests of the two indexes before rebuilding anything
(on 2026-10-11, `python:3.12-slim` was stale because its riscv64 image alone was rebuilt). The
binary inside an image counts too: Caddy's Go modules and Go version are in its binary, and
`tools/scan_images.sh` reports their advisories with the OS packages'; a Caddy release built with
a newer Go is a reason to move its pin even when Alpine has nothing new.

### OS packages

Exact versions of Debian and Alpine packages (`apt-get install pkg=1.2-3`, `apk add pkg=1.2-r3`)
are not pinned. Debian's and Alpine's mirrors keep only the newest build of each package in a
release, so an exact pin stops building at the package's next security update, the moment a
rebuild matters most; keeping old versions would mean snapshot.debian.org (Alpine has no
equivalent), a new source for every build. Pinning would also add little: the images ship the
pinned base image's packages, and the worker's `ca-certificates` is already in its base image
(the same version). The signed indexes keep the download honest, `tools/sbom.sh` records what a
build got, and `tools/scan_images.sh` says when a package needs to move.

When a scan finds a fixable HIGH or CRITICAL in an image built here, and no base-image build old
enough carries the fix, the Dockerfile raises that package to a minimum version:
`apk add --no-cache 'zlib>=1.3.2-r1'` (Alpine; apt has no equivalent, so a Debian image would use
`apt-get install --only-upgrade pkg` and a version check). The build fails if the mirror does not
have at least that version, and keeps working when a newer one replaces it. The comment above it
names the advisories; remove a package from the line once the pinned base image has that version.
`server/tests/test_supply_chain.py` refuses exact pins and lines without `--no-cache` or
`--no-install-recommends`.

### Scanning the images for known vulnerabilities

```sh
tools/scan_images.sh                             # api, worker, web (tag latest), Postgres, nginx, Caddy
ATTACKLEDGER_SCAN_TAG=v0.9.0 tools/scan_images.sh
tools/scan_images.sh postgres:16-alpine@sha256:…  # chosen images only
```

It copies each image's package database out (as `tools/sbom.sh` does; the image is not run), and
every Go binary in it: any executable file carrying Go's build information, found by reading the
image's filesystem as `docker export` writes it (Caddy, the worker's eight Go recon tools, `gosu`
in the Postgres image). It gives both to Grype (pinned by digest in the script), which runs with
no network and reports the binaries' Go modules and the Go release each was built with (`stdlib`)
next to the OS packages, with the binary each was found in. Grype's
vulnerability database is downloaded first from Anchore (`grype.anchore.io`), in a container of
its own, into the Docker volume `attackledger-scan-db` (`docker volume rm attackledger-scan-db`
drops it). It prints every HIGH and CRITICAL finding with its fix and exits 1 if one has a fix,
that is, if an upgrade or a newer base image would remove it. Findings without one ("no fix yet",
"will not be fixed": Debian marks many minor issues so) are listed and do not fail it; "fix state
unknown" means the distribution has no record and the scanner matched the upstream version, so
check by hand (`apk version -l '<'` or `apt list --upgradable` in a throwaway container).

A fixable finding in a third-party image the compose files run as published (Postgres, nginx for
the lab, Caddy) cannot be fixed in a Dockerfile here. If it is not reachable as AttackLedger uses
the image, or no release of the image has the fix yet, it goes into `tools/scan_ignore.txt` with
the reason and an end date (a month, the refresh cadence). For a Go binary the package is the Go
module (`golang.org/x/net`) or `stdlib`. After the end date the scan fails on it again, and it
also fails on the expired line itself, even once the finding is gone, until someone deletes or
renews it; an entry that matches nothing in the scanned images is printed as a note (the fix has
arrived: delete the line).

The worker's Go tools are built here, so a finding in one of them is fixed in `worker/Dockerfile`
(a newer release of the tool, or the release with the module raised: "The Go recon tools"
below), not accepted in `scan_ignore.txt`, which takes images run as published only.

The weekly security workflow runs the scan; run it by hand as well with the base-image refresh,
before a release, and after any rebuild.

### The Go recon tools

Each tool in `worker/Dockerfile` is one line of `worker/build_go_tool.sh`: the tool's package at an
exact release, then, when needed, modules at exact versions.

```dockerfile
RUN build_go_tool.sh github.com/tomnomnom/waybackurls@v0.1.0
RUN build_go_tool.sh github.com/lc/gau/v2/cmd/gau@v2.2.4 $XNET $XTEXT github.com/valyala/fasthttp@v1.74.0
```

With the release alone, the script runs `go install package@release`: the tool exactly as its
`go.mod` and `go.sum` say. With modules after it, it builds the same release with those
dependencies raised: in a throwaway module it runs `go get -tool package@release`, `go get` of
each module, `go mod tidy` and `go build`. Go's minimal version selection keeps every other
dependency at the version the release asks for, or the lowest one a raised module needs (the
build log prints each `upgraded` line). Each module downloaded is checked against the public
checksum database, as `go install` checks the ones not in the tool's `go.sum`. The script fails
if a raised module or the release ends up at any other version than the one given. The binary's
build information lists the release as a dependency of the throwaway module, so
`tools/scan_images.sh` and `tools/sbom.sh` still see the tool's version and every module.

Which version: for the tool, the newest release at least two weeks old; for a raised module, the
newest version at least two weeks old that has the fix, or a younger one when only it has the fix
(the rule above). Raise a module only when a scan finding has a fix that no release of the tool
old enough carries, and only the modules named by the findings (with what their own `go.mod`
pulls in). Remove a module from a line once a release of the tool requires that version or a
newer one. A finding no version fixes yet stays listed, and fails nothing.

After any change to a tool or a module, before the commit:

1. `docker run --rm --network none --entrypoint /opt/pd/bin/<tool> <new worker image> -h` for
   each tool changed, against the same output of the image before: every flag the worker passes
   (`worker/worker.py`, `commands`, `nuclei_cmd`, `ferox_cmd`, `_proxy_flags`; `-duc` from
   `app/egress.py`) still there with the same meaning.
2. The server tests (the worker's parsers are tested on recorded tool output).
3. The lab pipeline, before and after, on a stack whose default network is internal: the same
   steps finish, the same kinds of leads, only GET, HEAD and OPTIONS requests, DNS questions and
   port probes in the gateway log, the research identification on every request in the lab's
   access log (`docs/security-review/SUPPLY_CHAIN.md`, SC-12, has the commands).
4. `tools/scan_images.sh` on the new worker image.

### GitHub Actions

Each `uses:` in `.github/workflows/` is pinned to a commit, with its tag in a comment
(`uses: actions/checkout@<sha> # v7.0.1 (tag v7)`), and `tools/ci/action-pins.txt` records the
tag of every pinned commit. To move one, read the commit a tag points at
from the GitHub API, dereferencing an annotated tag:

```sh
gh api repos/actions/checkout/git/ref/tags/v4 --jq '.object.type + " " + .object.sha'
gh api repos/actions/checkout/git/tags/<sha> --jq .object.sha     # only when the type was "tag"
```

Put the commit SHA and the tag in the workflow and in `tools/ci/action-pins.txt`, then run
`tools/ci/check_action_pins.sh`. Check the actions at the same time as the base
images, and read the action's release notes before moving to a new major.

Advisories (the weekly security workflow runs these on the locks; by hand before a release):

```sh
docker run --rm --user 0 --entrypoint sh attackledger-api:latest -c \
  'python -m venv /tmp/pa >/dev/null && /tmp/pa/bin/pip install -q pip-audit &&
   /tmp/pa/bin/pip-audit --path /usr/local/lib/python3.12/site-packages'
(cd web && npm audit --omit=dev --package-lock-only && npm audit --package-lock-only --audit-level=high)
```

## The CI and the weekly security workflow

`.github/workflows/tests.yml` runs on every push and pull request: the server suite on SQLite
(with the default fuzz tests), the same suite on Postgres 16 (`tools/test_postgres.sh`, which
also upgrades a database the 0.7.1 code filled), the verifier equivalence with 500 seeded mutants,
the web type check, lint and build, and `tools/lint_workflows.sh` (actionlint with shellcheck,
pinned by digest, run with no network). `CONTRIBUTING.md` lists each job's command.

`.github/workflows/security.yml` runs every Monday at 05:23 UTC and on demand (Actions, security,
Run workflow; or `gh workflow run security.yml`). Its jobs:

| Job | Runs | Fails when |
|---|---|---|
| `images` | builds the api, worker and web images from the commit, `tools/scan_images.sh` on them and on the pinned Postgres, nginx and Caddy images, then `tools/sbom.sh`; the SBOM files and Grype's full reports are uploaded as the run's artifact `sbom-and-scan-<run>` (kept 90 days) | a HIGH or CRITICAL finding with a fix that `scan_ignore.txt` does not accept; an entry there past its date; the scan cannot run. The SBOM is written either way |
| `pins` | `tools/refresh_pins.sh`, report only | a registry lookup fails. A stale pin is a warning on the run |
| `python` | `pip-audit` on every hashed lock, one at a time (`--disable-pip`: it reads the pins, nothing is installed); pip-audit comes from its own hashed lock | any known advisory |
| `npm` | `npm audit --package-lock-only` on `web/`: the production packages, then every package | any advisory in a production package; a HIGH or CRITICAL one in a development package |

Each job's findings are in its log; the scan's and the pin report's are in the run's summary as
well. Nothing in it uses a secret; its
token can only read the repository; it pushes and publishes nothing, and it talks to the
registries the build uses, Anchore's database and the advisory services only. GitHub stops the
schedule of a public repository with no activity for 60 days (it says so on the Actions tab;
re-enable it there). A failed run mails whoever last changed the schedule line, by GitHub's
default notification settings.

The scanner (`GRYPE` in `tools/scan_images.sh`) and the linter (`ACTIONLINT` in
`tools/lint_workflows.sh`) are pinned by digest outside a `FROM` or `image:` line, so neither
`tools/refresh_pins.sh` nor Dependabot moves them: check them with the base images, by the same
two-week rule.

## A software bill of materials (SBOM)

`tools/sbom.sh` writes a CycloneDX JSON SBOM for each image, made from the built images
themselves. It needs Docker and the images (`docker compose build`); nothing is installed on the
machine or into the images, and nothing it writes is committed.

```sh
tools/sbom.sh /tmp/attackledger-sbom                       # images tagged latest
ATTACKLEDGER_SBOM_TAG=v0.9.0 tools/sbom.sh /tmp/attackledger-sbom
```

| File | Lists | Made by |
|---|---|---|
| `api.os.cdx.json`, `worker.os.cdx.json`, `web.os.cdx.json`, `postgres.os.cdx.json`, `nginx.os.cdx.json`, `caddy.os.cdx.json` | the Debian or Alpine packages, with package URLs | the image's package database, copied out (the image is not run) and converted by the script |
| `api.python.cdx.json`, `worker.python.cdx.json` | the installed Python packages | `cyclonedx-py environment`, run from a venv in the container's `/tmp` |
| `worker.arjun.cdx.json` | Arjun and its dependencies | `cyclonedx-py requirements` on Arjun's lock |
| `worker.go.<tool>.cdx.json` | the Go modules compiled into each recon tool | `cyclonedx-gomod bin`, from the binaries' build information |
| `web.npm.cdx.json` | the npm packages in the web bundle (production dependencies) | `@cyclonedx/cyclonedx-npm` on `web/package-lock.json` |

The gateway runs the API image, so `api.*` covers it. The generators are pinned in the script and
fetched from PyPI, the npm registry and the Go module proxy into throwaway containers. Not listed:
feroxbuster (a Rust binary without embedded dependency data; its version and SHA-256 are in
`worker/Dockerfile`), nuclei-templates and the word list (data, pinned the same way), and the
Caddy binary's Go modules (`tools/scan_images.sh` reads those for advisories). The weekly
security workflow keeps each run's SBOM as an artifact for 90 days.
