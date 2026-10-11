# Base images are pinned by the digest of their multi-arch index (docs/SUPPLY_CHAIN.md); the
# tag says what the digest was when it was pinned. tools/sbom.sh lists what each image holds.
# python:3.12.15-slim, pinned 2026-10-10.
# Kept on 2026-10-11: the tag's newer index (a6e34c59…) rebuilt its riscv64 image only.
FROM python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f
WORKDIR /srv
# Every package is pinned with the SHA-256 of its files (tools/lock_requirements.sh): pip
# installs exactly those files or fails. --no-deps: nothing outside the lock. pip itself
# first, since the base image's pip has advisories.
COPY server/requirements-pip.txt server/requirements.txt ./
RUN pip install --no-cache-dir --disable-pip-version-check --require-hashes --no-deps -r requirements-pip.txt \
 && pip install --no-cache-dir --disable-pip-version-check --require-hashes --no-deps --only-binary :all: -r requirements.txt
# The blob store is shared with the worker, and both run as uid 10001: each must read the
# engagement keys and write into the engagement folders the other created (D-043).
RUN useradd --create-home --uid 10001 api && mkdir -p /data/blobs && chown 10001 /data/blobs \
 && mkdir -p /data/worker-control && chown 10001 /data/worker-control && chmod 700 /data/worker-control
# /data/worker-control: the worker's token (D-042), written by the worker (uid 10001), read here.
# The gateway (same image, uid 10002, D-039) writes its CA and token there. A new named volume
# takes these owners, so the gateway can write it whichever container mounts it first.
RUN mkdir -p /data/gateway /data/gateway-public /data/gateway-control \
 && chown 10002:10002 /data/gateway /data/gateway-public /data/gateway-control && chmod 700 /data/gateway
COPY server/app ./app
COPY server/alembic.ini ./alembic.ini
COPY server/migrations ./migrations
COPY checklists ./checklists
COPY packs ./packs
# The offline verifier and its trusted timestamp roots, served for download (GET /verifier).
COPY tools/verify_report.py ./tools/verify_report.py
COPY tools/tsa-roots ./tools/tsa-roots
ENV ATTACKLEDGER_HOME=/srv
EXPOSE 8000
USER 10001
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
