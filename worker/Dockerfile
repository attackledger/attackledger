# Base images are pinned by the digest of their multi-arch index (docs/SUPPLY_CHAIN.md); the
# tag says what the digest was when it was pinned.
#
# The Go tools: `go install module@version` checks every module it downloads against the
# module's go.sum and the public checksum database (sum.golang.org), and fails on a mismatch.
# These settings are Go's defaults, written out so that a builder's environment cannot turn
# them off; GOTOOLCHAIN=local keeps a module from fetching another Go toolchain, and
# -trimpath keeps the build's paths out of the binaries. One toolchain for every tool: Go
# 1.23, which built the older ones, has had no security fixes since August 2025.
# golang:1.26.9-bookworm, pinned 2026-10-10.
FROM golang:1.26-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c AS tools
ENV GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GONOSUMDB= GOPRIVATE= \
    GOINSECURE= GOFLAGS=-trimpath GOTOOLCHAIN=local
# No naabu: port probes are made by the gateway (D-039), which can check them against scope.
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.7 \
 && go install github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.1 \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@v1.6.9 \
 && go install github.com/projectdiscovery/katana/cmd/katana@v1.1.2 \
 && go install github.com/tomnomnom/assetfinder@v0.1.1 \
 && go install github.com/tomnomnom/waybackurls@v0.1.0 \
 && go install github.com/lc/gau/v2/cmd/gau@v2.2.4 \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1

# Pinned downloads, each checked against a SHA-256 recorded when it was pinned.
# debian:bookworm-slim (2026-10-05 build), pinned 2026-10-10.
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS assets
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    case "$arch" in \
      arm64) f=aarch64; sum=1e5244e1f52e55a647b65e0c76ae7afe0b9983c1fbea30ed7c67e477175eb381 ;; \
      amd64) f=x86_64;  sum=0978619a10049ccaad290b2d1241bc4d8a6aac18da07d6231186fb9d343f99de ;; \
      *) echo "unsupported arch $arch"; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/ferox.zip "https://github.com/epi052/feroxbuster/releases/download/v2.13.1/${f}-linux-feroxbuster.zip"; \
    echo "$sum  /tmp/ferox.zip" | sha256sum -c -; \
    unzip -q /tmp/ferox.zip -d /opt/bin && chmod +x /opt/bin/feroxbuster
RUN set -eux; \
    curl -fsSL -o /tmp/nt.tar.gz https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v10.4.9.tar.gz; \
    echo "d7cd989935f9a84943cba8a193f567db37626dbf4e526ff57ba5b1f24badd5d6  /tmp/nt.tar.gz" | sha256sum -c -; \
    mkdir -p /opt/nuclei-templates && tar -xzf /tmp/nt.tar.gz -C /opt/nuclei-templates --strip-components=1
RUN set -eux; mkdir -p /opt/wordlists; \
    curl -fsSL -o /opt/wordlists/common.txt \
      https://raw.githubusercontent.com/danielmiessler/SecLists/2f19f39928b78e4be8b9a0f0a263baf531e33025/Discovery/Web-Content/common.txt; \
    echo "47fb86ca6fb3f97e5491161581900d6d99851fb16764eacddf16aa85617c956a  /opt/wordlists/common.txt" | sha256sum -c -

# python:3.12.15-slim, pinned 2026-10-10 (the API image's base, server/Dockerfile).
FROM python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --home-dir /var/lib/worker --uid 10001 worker \
 && mkdir -p /data/worker-control && chown worker /data/worker-control && chmod 700 /data/worker-control \
 && mkdir -p /data/gateway-public && chown 10002:10002 /data/gateway-public
# Its home, /var/lib/worker, is a tmpfs in docker-compose.yml: the tools write their settings there.
# /data/worker-control: the worker's token for the API's /worker/* routes, shared with the API
# only (D-042). No blob store, no database, no master key here: the API stores everything.
# /data/gateway-public: the gateway's CA certificate (written by the gateway, uid 10002;
# read-only here). Every tool trusts only that CA.
# Absolute paths on purpose: the Python "httpx" package installs a CLI with the same name.
COPY --from=tools /go/bin/ /opt/pd/bin/
COPY --from=assets /opt/bin/feroxbuster /opt/pd/bin/feroxbuster
COPY --from=assets /opt/nuclei-templates /opt/nuclei-templates
COPY --from=assets /opt/wordlists /opt/wordlists
WORKDIR /srv
# Hash-pinned, like the API's (tools/lock_requirements.sh). Arjun has its own lock, in its own
# folder, so its dependencies never mix with the worker's. Arjun and ratelimit are published
# as source only: they are built with a hash-pinned setuptools in a throwaway venv, without
# pip's build isolation (which would fetch an unpinned setuptools).
COPY server/requirements-pip.txt server/requirements.txt worker/requirements-arjun.txt worker/requirements-arjun-build.txt ./
RUN pip install --no-cache-dir --disable-pip-version-check --require-hashes --no-deps -r requirements-pip.txt \
 && pip install --no-cache-dir --disable-pip-version-check --require-hashes --no-deps --only-binary :all: -r requirements.txt \
 && python -m venv /tmp/arjun-build \
 && /tmp/arjun-build/bin/pip install --no-cache-dir --disable-pip-version-check --require-hashes --no-deps -r requirements-pip.txt -r requirements-arjun-build.txt \
 && /tmp/arjun-build/bin/pip install --no-cache-dir --disable-pip-version-check --require-hashes --no-deps \
      --no-build-isolation --target /opt/arjun -r requirements-arjun.txt \
 && rm -rf /tmp/arjun-build
COPY server/app ./app
# nuclei templates AttackLedger never runs, found by content (app/nucleisafe.py, D-020): every
# template that cannot be proven to send only GET/HEAD/OPTIONS requests to the target, with the
# research identification, no body and no out-of-band callback. Fails the build if the list is
# empty or nothing is left; the worker re-checks the list before its first scan.
RUN python -m app.nucleisafe build /opt/nuclei-templates /opt/nuclei-exclude.txt \
 && test -s /opt/nuclei-exclude.txt && chmod 444 /opt/nuclei-exclude.txt
COPY worker/worker.py .
COPY checklists ./checklists
COPY packs ./packs
ENV ATTACKLEDGER_HOME=/srv
USER worker
CMD ["python", "-u", "worker.py"]
