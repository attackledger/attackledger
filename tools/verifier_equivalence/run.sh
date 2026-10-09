#!/usr/bin/env bash
# Show that the browser verifier and tools/verify_report.py agree: same verdict per check and
# the same output, on every report in cases.json and on the building blocks one by one.
#
#   tools/verifier_equivalence/run.sh                     # against tools/verify_report.py
#   tools/verifier_equivalence/run.sh --python FILE       # against another copy of it
#   tools/verifier_equivalence/run.sh --markdown out.md   # also write the table
#
# Fixtures are made by make_fixtures.py (see there). Needs python3, node 20+ and
# web/node_modules (cd web && npm ci). Exit code 0 means no difference.
set -euo pipefail
cd "$(dirname "$0")/../.."
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
web/node_modules/.bin/esbuild web/src/verify_report.ts --bundle --format=esm --platform=neutral \
  --log-level=warning --outfile="$TMP/verify_report.mjs"
node tools/verifier_equivalence/run.mjs "$TMP/verify_report.mjs" "$@"
