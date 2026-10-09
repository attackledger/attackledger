FROM python:3.12-slim
WORKDIR /srv
COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# The blob store is shared with the worker, and both run as uid 10001: each must read the
# engagement keys and write into the engagement folders the other created (D-043).
RUN useradd --create-home --uid 10001 api && mkdir -p /data/blobs && chown 10001 /data/blobs
COPY server/app ./app
COPY server/alembic.ini ./alembic.ini
COPY server/migrations ./migrations
COPY checklists ./checklists
COPY packs ./packs
ENV ATTACKLEDGER_HOME=/srv
EXPOSE 8000
USER 10001
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
