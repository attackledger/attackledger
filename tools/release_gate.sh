#!/usr/bin/env bash
# Release gate — fail-closed. Blocks a commit/push unless the tree is free of
# (1) private denylisted strings (real targets, handles, internal hosts) and
# (2) verified/unverified secrets found by trufflehog.
# The denylist lives OUTSIDE the repo (it is itself sensitive):
#   ATTACKLEDGER_DENYLIST (default: ~/.attackledger_denylist), one ERE per line.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DENY="${ATTACKLEDGER_DENYLIST:-$HOME/.attackledger_denylist}"
FDENY="${ATTACKLEDGER_FINDINGS_DENYLIST:-$HOME/.attackledger_findings_denylist}"  # fingerprints of open/unreported findings
fail=0

if [ ! -s "$DENY" ]; then
  echo "[gate] FAIL: denylist not found at $DENY (fail-closed)"; exit 1
fi

echo "[gate] 1/3 denylist scan (targets + open-finding fingerprints)"
for f in "$DENY" "$FDENY"; do
  [ -s "$f" ] || { echo "[gate] FAIL: missing $f (fail-closed)"; fail=1; continue; }
  if grep -rnIiE -f "$f" --exclude-dir=.git "$ROOT"; then
    echo "[gate] FAIL: denylisted strings present ($f)"; fail=1
  fi
done

echo "[gate] 2/3 absolute personal paths"
if grep -rnIE '/Users/[A-Za-z0-9_]+|/home/[A-Za-z0-9_]+' --exclude-dir=.git --exclude=release_gate.sh "$ROOT"; then
  echo "[gate] FAIL: absolute user paths present"; fail=1
fi

echo "[gate] 3/3 secret scan (trufflehog)"
if ! command -v trufflehog >/dev/null; then
  echo "[gate] FAIL: trufflehog not installed (fail-closed)"; fail=1
else
  out="$(trufflehog filesystem "$ROOT" --exclude-paths=<(printf '\\.git/\n') --no-update --json 2>/dev/null || true)"
  if [ -n "$out" ]; then
    printf '%s\n' "$out" | jq -r '"\(.SourceMetadata.Data.Filesystem.file):\(.SourceMetadata.Data.Filesystem.line) \(.DetectorName) verified=\(.Verified)"'
    echo "[gate] FAIL: trufflehog findings"; fail=1
  fi
fi

[ "$fail" -eq 0 ] && echo "[gate] PASS" || { echo "[gate] BLOCKED"; exit 1; }
