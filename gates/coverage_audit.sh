#!/bin/bash
# coverage_audit.sh -- audits host x checklist-section coverage for EVERY program.
# Catches hosts declared "done" that still have checklist sections never touched
# (a "." cell in CLASS_MATRIX.tsv). Usage:
#   ./coverage_audit.sh                 -> scan ALL engagements
#   ./coverage_audit.sh <program>       -> one program (engagements/<program>/)
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${ATTACKLEDGER_WORKDIR:-${ATTACKLEDGER_HOME:-$ROOT}/work}"
ENG_DIR="$WORKDIR/engagements"
TARGET="${1:-}"

audit_one() {
  local dir="$1" name="$2"
  local cm="$dir/CLASS_MATRIX.tsv"
  if [ ! -f "$cm" ]; then
    echo "  [CLASS_MATRIX.tsv MISSING -- this program cannot be audited structurally; it may use an older/different format]"
    return
  fi
  local total_hosts=0 total_cells=0 dot_cells=0
  local worst_hosts=""
  while IFS=$'\t' read -r line; do
    [ -z "$line" ] && continue
    IFS=$'\t' read -ra cols <<< "$line"
    local host="${cols[0]}"
    [ "$host" = "host" ] && continue   # header
    total_hosts=$((total_hosts+1))
    local ncols=${#cols[@]}
    local dots=0
    for ((i=1; i<ncols; i++)); do
      total_cells=$((total_cells+1))
      if [ "${cols[$i]}" = "." ]; then
        dots=$((dots+1))
        dot_cells=$((dot_cells+1))
      fi
    done
    local pct=0
    [ $((ncols-1)) -gt 0 ] && pct=$(( dots * 100 / (ncols-1) ))
    if [ "$pct" -ge 50 ]; then
      worst_hosts="$worst_hosts\n    $host -- ${dots}/$((ncols-1)) sections NEVER TOUCHED (%${pct})"
    fi
  done < "$cm"
  local overall_pct=0
  [ "$total_cells" -gt 0 ] && overall_pct=$(( dot_cells * 100 / total_cells ))
  echo "  hosts: $total_hosts | total cells: $total_cells | NEVER TOUCHED: $dot_cells (%${overall_pct})"
  if [ -n "$worst_hosts" ]; then
    echo "  --- hosts with >=50% of sections never touched ---"
    echo -e "$worst_hosts"
  fi
  # If ALL_SURFACES_TODO.txt exists: any host listed there that has NO row in CLASS_MATRIX?
  local todo="$dir/ALL_SURFACES_TODO.txt"
  if [ -f "$todo" ]; then
    local cm_hosts=$(tail -n +2 "$cm" | cut -f1)
    local missing=""
    while IFS= read -r h; do
      [ -z "$h" ] && continue
      case "$h" in *.*) ;; *) continue;; esac  # roughly host-shaped lines only
      if ! echo "$cm_hosts" | grep -qxF "$h"; then
        missing="$missing $h"
      fi
    done < <(grep -oE '\b[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}\b' "$todo" | sort -u)
    if [ -n "$missing" ]; then
      echo "  --- hosts mentioned in ALL_SURFACES_TODO.txt but with NO row in CLASS_MATRIX (rough scan, may contain false positives) ---"
      echo "   $missing" | tr ' ' '\n' | grep -v '^$' | sed 's/^/    /'
    fi
  fi
}

if [ -n "$TARGET" ]; then
  echo "=== $TARGET ==="
  audit_one "$ENG_DIR/$TARGET" "$TARGET"
else
  for d in "$ENG_DIR"/*/; do
    name=$(basename "$d")
    [ "$name" = "CVE_HUNT_LOG" ] && continue
    echo "=== $name ==="
    audit_one "$d" "$name"
    echo
  done
fi
