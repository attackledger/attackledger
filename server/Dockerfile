FROM python:3.12-slim
WORKDIR /srv
COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
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
