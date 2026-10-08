#!/usr/bin/env bash
# close_gate.sh <program> -- the ONLY way to mark a target "CLOSED/DONE".
# FAIL-CLOSED: unless every gate passes it produces NO CLOSE_RECEIPT and prints the gap list.
# Boards / notebooks read the "closed" state ONLY from this receipt -> a verbal "done"
# without a receipt has no standing. Rule: "done is not my claim; it must be a
# computed, fail-closed state."
#
# Gates:
#   A. SURFACE DIFF   -- a host in all.txt was not scanned (not in scanned_ok) AND is not N/A in the matrix
#   B. MATRIX COVERAGE -- a scanned host never appears in CLASS_MATRIX (scanned but not hunted)
#   C. COVERAGE_AUDIT -- coverage_audit.sh finds hosts with >=50% untouched sections
#   D. PENDING WATCH  -- an untriaged WATCH_CANDIDATES_*.tsv exists (new surface)
#   E. REMOTE SCAN DEPTH (advisory, optional) -- ferox/nuclei host coverage on a remote recon box
#   F. THREE-GATE     -- UNVERIFIED/BLOCKED/partial verdicts are not closed
#   G. CROSS_LANE_LEADS -- known surface not yet tested
#   H. USER_TODO      -- open user-action items mean BLOCKED, not CLOSED
#
# Usage: close_gate.sh <program>          -> run the gate, write/delete the receipt
#        close_gate.sh <program> --quiet  -> for cron: print only the FAIL summary
set -uo pipefail

PROG="${1:-}"
[ -z "$PROG" ] && { echo "usage: $0 <program> [--quiet]"; exit 2; }
QUIET=0; [ "${2:-}" = "--quiet" ] && QUIET=1
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${ATTACKLEDGER_WORKDIR:-${ATTACKLEDGER_HOME:-$ROOT}/work}"
BASE="$ROOT/gates"
ENG="$WORKDIR/engagements/$PROG"
[ -d "$ENG" ] || { echo "engagement not found: $ENG"; exit 2; }
CM="$ENG/CLASS_MATRIX.tsv"
RECEIPT="$ENG/CLOSE_RECEIPT.txt"
GAPS=""
say() { [ "$QUIET" -eq 0 ] && echo "$@"; }

inmatrix() { [ -f "$CM" ] && grep -qF "$1" "$CM"; }               # does the host appear in the matrix?
is_na() { [ -f "$CM" ] && grep -F "$1" "$CM" | grep -qiE "N/A|NXDOMAIN|route confirmed absent|dead"; }

say "=== CLOSE GATE: $PROG ==="

# --- A. SURFACE DIFF: discovered but not scanned (and not N/A) ---
if [ -f "$ENG/all.txt" ] && [ -f "$ENG/scanned_ok.txt" ]; then
  while IFS= read -r h; do
    [ -z "$h" ] && continue
    if ! grep -qxF "$h" "$ENG/scanned_ok.txt"; then
      if is_na "$h"; then :; else
        GAPS+="A) UNSCANNED host (and not N/A): $h"$'\n'
      fi
    fi
  done < <(sort -u "$ENG/all.txt")
else
  # The all.txt/scanned_ok.txt convention is not used by every program; skip quietly if
  # absent (avoid noise). Recon depth is then left to E (remote) and the recon-pipeline receipt.
  say "A) all.txt/scanned_ok.txt missing -- surface diff skipped (this program may use a different inventory)"
fi

# --- B. MATRIX COVERAGE: scanned but absent from the matrix ---
if [ -f "$ENG/scanned_ok.txt" ] && [ -f "$CM" ]; then
  while IFS= read -r h; do
    [ -z "$h" ] && continue
    inmatrix "$h" || GAPS+="B) SCANNED but NOT in CLASS_MATRIX (not hunted): $h"$'\n'
  done < <(sort -u "$ENG/scanned_ok.txt")
elif [ ! -f "$CM" ]; then
  GAPS+="B) CLASS_MATRIX.tsv MISSING -- hunt coverage cannot be audited"$'\n'
fi

# --- C. COVERAGE_AUDIT: >=50% untouched sections ---
if [ -x "$BASE/coverage_audit.sh" ]; then
  CA="$("$BASE/coverage_audit.sh" "$PROG" 2>/dev/null | grep -E "NEVER TOUCHED.*%" | grep -E "%(5[0-9]|[6-9][0-9]|100)" || true)"
  if [ -n "$CA" ]; then
    cnt="$(echo "$CA" | grep -c .)"
    GAPS+="C) coverage_audit: $cnt hosts with >=50% untouched sections. Worst 3:"$'\n'"$(echo "$CA" | sort -t% -k2 -rn | head -3 | sed 's/^/     /')"$'\n'
  fi
fi

# --- D. PENDING WATCH: untriaged new surface ---
WC="$(ls "$ENG"/WATCH_CANDIDATES_*.tsv 2>/dev/null || true)"
if [ -n "$WC" ]; then
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    # no .triaged marker -> counts as pending
    [ -f "$f.triaged" ] || GAPS+="D) UNTRIAGED new surface: $(basename "$f") ($(wc -l < "$f" | tr -d ' ') lines)"$'\n'
  done <<< "$WC"
fi

# --- F. THREE-GATE: UNVERIFIED/BLOCKED/partial verdict = not closed ---
# DO-NOT-FILE, N/A, plain PASS and a filed FINDING are closed states. UNVERIFIED/
# BLOCKED/partial means the three gates did not pass and cannot count as "clean"
# (no PASS without a bypass attempt).
if [ -f "$CM" ]; then
  UV="$(cut -f1,4 "$CM" | tail -n +2 | grep -iE "UNVERIFIED|BLOCKED|partial" || true)"
  [ -n "$UV" ] && GAPS+="F) cells that did not pass the three gates (UNVERIFIED/BLOCKED/partial):"$'\n'"$(echo "$UV" | sed 's/^/     /' | head -20)"$'\n'
fi

# --- G. CROSS_LANE_LEADS: known but untested surface ---
CLL="$ENG/CROSS_LANE_LEADS.md"
if [ -f "$CLL" ]; then
  LEADS="$(grep -E "^[0-9]{4}-[0-9]{2}-[0-9]{2}" "$CLL" | grep -viE "DONE|TESTED|CLOSED|N/A" || true)"
  n="$(echo "$LEADS" | grep -c . || true)"
  [ "$n" -gt 0 ] && GAPS+="G) CROSS_LANE_LEADS has $n untested surface items (no done marker). Each lead must be tested and marked 'DONE' or 'N/A'."$'\n'
fi

# --- H. USER_TODO: waiting on a user action = BLOCKED, not CLOSED ---
UT="$ENG/USER_TODO.md"
if [ -f "$UT" ]; then
  open_items="$(grep -cE "^[0-9]+\.|^- \[ \]|^\* " "$UT" || true)"
  [ "$open_items" -gt 0 ] && GAPS+="H) USER_TODO.md has $open_items open items -- this target is BLOCKED (waiting on account/scope/user action), not CLOSED. Resolve them or empty the file."$'\n'
fi

# --- E. Remote scan depth (advisory, optional; never blocks the receipt) ---
# Enabled only when AL_REMOTE_HOST (an ssh alias) and AL_REMOTE_BASE (remote targets dir) are set.
if [ "$QUIET" -eq 0 ] && [ -n "${AL_REMOTE_HOST:-}" ] && [ -n "${AL_REMOTE_BASE:-}" ]; then
  RPROG="$(echo "$PROG" | sed 's/[^a-z0-9_-].*//')"
  REMOTE="$(ssh -o ConnectTimeout=8 -o BatchMode=yes "$AL_REMOTE_HOST" "d=$AL_REMOTE_BASE/$PROG; [ -d \$d ] || d=$AL_REMOTE_BASE/$RPROG; if [ -d \$d ]; then al=\$(cat \$d/triage/alive_*.txt 2>/dev/null | sort -u | wc -l | tr -d ' '); fx=\$(ls \$d/ferox* \$d/endpoints/ferox* 2>/dev/null | wc -l | tr -d ' '); nu=\$(ls \$d/nuclei* 2>/dev/null | wc -l | tr -d ' '); echo \"alive=\$al ferox_files=\$fx nuclei_files=\$nu\"; else echo 'no-remote-recon'; fi" 2>/dev/null || echo "remote-unreachable")"
  say "E) remote scan depth (advisory): $REMOTE"
fi

# --- DECISION ---
if [ -n "$GAPS" ]; then
  rm -f "$RECEIPT"   # delete a stale receipt so the board stays OPEN
  say ""
  say "GATE FAILED -- this target is NOT CLOSED. CLOSE_RECEIPT not produced / removed."
  say "--- GAPS ---"
  say "$GAPS"
  [ "$QUIET" -eq 1 ] && printf '%s\n%s' "CLOSE-GATE FAIL: $PROG" "$GAPS"
  exit 1
fi

cat > "$RECEIPT" <<EOF
CLOSE_RECEIPT -- $PROG
date    : $(date '+%Y-%m-%d %H:%M:%S %z')
machine : $(hostname)
gates   : A surface-diff, B matrix-coverage, C coverage-audit, D pending-watch = ALL PASS
NOTE    : while this file exists the board/notebook may show this target as CLOSED.
          If new surface appears, close_gate runs AGAIN and DELETES the receipt.
EOF
say ""
say "GATE PASSED -- CLOSE_RECEIPT written: $(basename "$RECEIPT")"
exit 0
