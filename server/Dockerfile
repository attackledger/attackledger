FROM python:3.12-slim
WORKDIR /srv
COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Shared with the worker (uid 10001), which writes agent evidence there.
RUN mkdir -p /data/blobs && chown 10001 /data/blobs
COPY server/app ./app
COPY server/alembic.ini ./alembic.ini
COPY server/migrations ./migrations
COPY checklists ./checklists
COPY packs ./packs
ENV ATTACKLEDGER_HOME=/srv
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
