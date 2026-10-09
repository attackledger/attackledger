#!/usr/bin/env bash
# Refresh the static site's sample report from the demo stack (fictional *.test hosts only):
# the "Client web app" pentest, with its scope and authorization recorded.
# Usage: tools/build_site.sh [API_BASE]   (default http://localhost:8098, see tools/demo_stack.py)
set -euo pipefail
cd "$(dirname "$0")/.."
API=${1:-http://localhost:8098}
ID=$(curl -sf "$API/engagements" | python3 -I -c \
  'import sys,json;print(next(e["id"] for e in json.load(sys.stdin) if e["name"]=="Client web app"))')
curl -sf "$API/engagements/${ID}/report.html" -o site/sample-report.html
curl -sf "$API/engagements/${ID}/report" -o site/sample-report.json
cp tools/verify_report.py site/verify_report.py
python3 -I site/verify_report.py site/sample-report.json
