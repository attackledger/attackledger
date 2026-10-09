#!/usr/bin/env bash
# Regenerate the static site's sample report from the demo seed (fictional *.test hosts only).
# Runs a throwaway API on an empty SQLite database; the local stack's data is never used.
set -euo pipefail
cd "$(dirname "$0")/.."
PORT=${PORT:-8099}
docker compose build -q api
docker run -d --rm --name al-site-demo -e DATABASE_URL=sqlite:////tmp/demo.db \
  -p "127.0.0.1:${PORT}:8000" attackledger-api >/dev/null
trap 'docker stop al-site-demo >/dev/null 2>&1 || true' EXIT
for _ in $(seq 30); do curl -sf "localhost:${PORT}/health" >/dev/null && break; sleep 1; done
python3 -I tools/seed_demo.py "http://localhost:${PORT}" >/dev/null
ID=$(curl -s "localhost:${PORT}/engagements" | python3 -I -c \
  'import sys,json;print(next(e["id"] for e in json.load(sys.stdin) if e["name"]=="Client web app"))')
curl -sf "localhost:${PORT}/engagements/${ID}/report.html" -o site/sample-report.html
curl -sf "localhost:${PORT}/engagements/${ID}/report" -o site/sample-report.json
cp tools/verify_report.py site/verify_report.py
python3 -I site/verify_report.py site/sample-report.json
