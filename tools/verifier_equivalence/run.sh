#!/usr/bin/env bash
# Show that the browser verifier and tools/verify_report.py agree: same verdict per check and
# the same output, on every report in cases.json and on the building blocks one by one.
#
#   tools/verifier_equivalence/run.sh                     # against tools/verify_report.py
#   tools/verifier_equivalence/run.sh --with-v2-proposal  # same, with verify_report_v2.patch applied
#   tools/verifier_equivalence/run.sh --markdown out.md   # also write the table
#
# Reports with evidence chain record v2 entries count only once verify_report.py reads v2;
# until then they are listed as pending (or checked against the proposed patch). Fixtures are
# made by make_fixtures.py. Needs python3, node 20+ and web/node_modules (cd web && npm ci).
set -euo pipefail
cd "$(dirname "$0")/../.."
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
args=()
python=tools/verify_report.py
for a in "$@"; do
  if [ "$a" = "--with-v2-proposal" ]; then
    if grep -q summary_sha256 tools/verify_report.py; then
      echo "tools/verify_report.py already reads v2; the proposal is not needed" >&2
    else
      cp tools/verify_report.py "$TMP/verify_report.py"
      cp -R tools/tsa-roots "$TMP/tsa-roots"
      patch -s "$TMP/verify_report.py" tools/verifier_equivalence/verify_report_v2.patch
      python="$TMP/verify_report.py"
    fi
  else
    args+=("$a")
  fi
done
web/node_modules/.bin/esbuild web/src/verify_report.ts --bundle --format=esm --platform=neutral \
  --log-level=warning --outfile="$TMP/verify_report.mjs"
node tools/verifier_equivalence/run.mjs "$TMP/verify_report.mjs" --python "$python" ${args[@]+"${args[@]}"}
