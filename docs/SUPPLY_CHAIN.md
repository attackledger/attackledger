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
| Go recon tools (subfinder, dnsx, httpx, katana, nuclei, assetfinder, waybackurls, gau) | the Go module proxy | `go install module@version`: each module against the tool's `go.sum` and the public checksum database (sum.golang.org). `worker/Dockerfile` writes these settings out (`GOSUMDB`, `GOPROXY`, no `GONOSUMDB`/`GOPRIVATE`/`GOINSECURE`) and sets `GOTOOLCHAIN=local`, so no other Go toolchain is fetched |
| feroxbuster, nuclei-templates, the SecLists word list | GitHub | a SHA-256 recorded in `worker/Dockerfile` when the version was pinned; the build fails on a mismatch |
| npm packages (web build stage only) | the npm registry | `npm ci` from `web/package-lock.json`, each package against its SHA-512 there; `--ignore-scripts`, so no install script runs |
| Debian packages (`ca-certificates`, `curl`, `unzip`) | Debian's mirrors | apt's signed release files. Versions are not pinned: they are whatever the pinned base image's release has that day (see the gaps in the review) |

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

npm: change `web/package.json`, run `npm install --package-lock-only` in `web/`, review the lock
diff, then `npm ci && npx tsc --noEmit && npm run lint && npm run build`.

A base image: pull the new tag, read its index digest and put both in the file:

```sh
docker pull python:3.12-slim
docker image inspect python:3.12-slim --format '{{.Descriptor.Digest}}'   # containerd image store
docker buildx imagetools inspect python:3.12-slim                         # or, with buildx
```

The digest must be the index's (`application/vnd.oci.image.index.v1+json` or a Docker manifest
list), not one platform's, or the other architecture stops building. Base images do not update
by themselves now: refresh them deliberately, for example monthly and when an advisory names
one, then rebuild and run the tests.

Advisories, before a release:

```sh
docker run --rm --user 0 --entrypoint sh attackledger-api:latest -c \
  'python -m venv /tmp/pa >/dev/null && /tmp/pa/bin/pip install -q pip-audit &&
   /tmp/pa/bin/pip-audit --path /usr/local/lib/python3.12/site-packages'
(cd web && npm audit --omit=dev)
```

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
Caddy binary's Go modules.
