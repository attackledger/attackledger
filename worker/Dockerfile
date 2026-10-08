FROM golang:1.23-bookworm AS tools
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev && rm -rf /var/lib/apt/lists/*
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.7 \
 && go install github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.1 \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@v1.6.9 \
 && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.3 \
 && go install github.com/projectdiscovery/katana/cmd/katana@v1.1.2 \
 && go install github.com/tomnomnom/assetfinder@v0.1.1 \
 && go install github.com/tomnomnom/waybackurls@v0.1.0 \
 && go install github.com/lc/gau/v2/cmd/gau@v2.2.4

FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libpcap0.8 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 worker
# Absolute paths on purpose: the Python "httpx" package installs a CLI with the same name.
COPY --from=tools /go/bin/ /opt/pd/bin/
WORKDIR /srv
COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server/app ./app
COPY server/alembic.ini ./alembic.ini
COPY server/migrations ./migrations
COPY worker/worker.py .
COPY checklists ./checklists
COPY packs ./packs
ENV ATTACKLEDGER_HOME=/srv
USER worker
CMD ["python", "-u", "worker.py"]
