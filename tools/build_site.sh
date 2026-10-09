#!/usr/bin/env bash
# Refresh the static site's sample report from the demo stack (fictional *.test hosts only):
# the "Client web app" pentest, with its scope and authorization recorded.
# Usage: tools/build_site.sh [API_BASE]   (default http://localhost:8098, see tools/demo_stack.py)
set -euo pipefail
cd "$(dirname "$0")/.."
# Set ATTACKLEDGER_API_TOKEN when the demo API requires sign-in.
API=${1:-http://localhost:8098}
AUTH=(); [ -n "${ATTACKLEDGER_API_TOKEN:-}" ] && AUTH=(-H "authorization: Bearer $ATTACKLEDGER_API_TOKEN")
ID=$(curl -sf ${AUTH[@]+"${AUTH[@]}"} "$API/engagements" | python3 -I -c \
  'import sys,json;print(next(e["id"] for e in json.load(sys.stdin) if e["name"]=="Client web app"))')
curl -sf ${AUTH[@]+"${AUTH[@]}"} "$API/engagements/${ID}/report.html" -o site/sample-report.html
curl -sf ${AUTH[@]+"${AUTH[@]}"} "$API/engagements/${ID}/report" -o site/sample-report.json
cp tools/verify_report.py site/verify_report.py
cp tools/tsa-roots/digicert-trusted-root-g4.pem site/digicert-trusted-root-g4.pem
(cd site && python3 -I verify_report.py sample-report.json --tsa-root digicert-trusted-root-g4.pem)
