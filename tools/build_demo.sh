#!/usr/bin/env bash
# Build the read-only demo into site/demo: the real web app in demo mode, plus a snapshot
# exported from a demo API. Use an API that holds fictional data only (seed + lab runs).
# Usage: tools/build_demo.sh API_BASE ENGAGEMENT_ID [ENGAGEMENT_ID ...]
set -euo pipefail
cd "$(dirname "$0")/.."
API=${1:?usage: tools/build_demo.sh API_BASE ENGAGEMENT_ID...}; shift
(cd web && VITE_DEMO=1 npx vite build --base ./ --outDir ../site/demo --emptyOutDir)
python3 -I tools/export_demo.py "$API" site/demo "$@"
