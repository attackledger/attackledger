FROM golang:1.23-bookworm AS tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.7 \
 && go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.1 \
 && go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.6.9

FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libpcap0.8 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 worker
# Absolute paths on purpose: the Python "httpx" package installs a CLI with the same name.
COPY --from=tools /go/bin/subfinder /go/bin/dnsx /go/bin/httpx /opt/pd/bin/
WORKDIR /srv
COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server/app ./app
COPY worker/worker.py .
COPY checklists ./checklists
COPY packs ./packs
ENV ATTACKLEDGER_HOME=/srv
USER worker
CMD ["python", "-u", "worker.py"]
