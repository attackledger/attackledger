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

# nuclei needs a newer Go than the other tools.
FROM golang:1.26-bookworm AS nuclei
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1

# Pinned downloads, each checked against a SHA-256 recorded when it was pinned.
FROM debian:bookworm-slim AS assets
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
# Templates AttackLedger never runs, found by content rather than by tags:
#  - raw ("unsafe") requests: nuclei does not apply -H to all of them, so they can leave
#    without the research identification (measured);
#  - hard-coded out-of-band hosts (oast.*, interact.sh) and interactsh URLs: they can make
#    the target call a third party.
#  - digest authentication (digest-username/password): a login attempt, and nuclei's digest
#    client drops custom headers (measured).
RUN set -eux; cd /opt/nuclei-templates; \
    { grep -rlE 'unsafe: *true' http || true; \
      grep -rlE 'oast\.(me|pro|fun|live|site|online|today)|interact\.sh|interactsh-url' http || true; \
      grep -rlE 'digest-(username|password)' http || true; } \
      | sort -u | sed 's#^#/opt/nuclei-templates/#' > /opt/nuclei-exclude.txt; \
    test -s /opt/nuclei-exclude.txt; wc -l /opt/nuclei-exclude.txt
RUN set -eux; mkdir -p /opt/wordlists; \
    curl -fsSL -o /opt/wordlists/common.txt \
      https://raw.githubusercontent.com/danielmiessler/SecLists/2f19f39928b78e4be8b9a0f0a263baf531e33025/Discovery/Web-Content/common.txt; \
    echo "47fb86ca6fb3f97e5491161581900d6d99851fb16764eacddf16aa85617c956a  /opt/wordlists/common.txt" | sha256sum -c -

FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libpcap0.8 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 worker
# Absolute paths on purpose: the Python "httpx" package installs a CLI with the same name.
COPY --from=tools /go/bin/ /opt/pd/bin/
COPY --from=nuclei /go/bin/nuclei /opt/pd/bin/nuclei
COPY --from=assets /opt/bin/feroxbuster /opt/pd/bin/feroxbuster
COPY --from=assets /opt/nuclei-templates /opt/nuclei-templates
COPY --from=assets /opt/nuclei-exclude.txt /opt/nuclei-exclude.txt
COPY --from=assets /opt/wordlists /opt/wordlists
WORKDIR /srv
COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir --target /opt/arjun arjun==2.2.7
COPY server/app ./app
COPY server/alembic.ini ./alembic.ini
COPY server/migrations ./migrations
COPY worker/worker.py .
COPY checklists ./checklists
COPY packs ./packs
ENV ATTACKLEDGER_HOME=/srv
USER worker
CMD ["python", "-u", "worker.py"]
