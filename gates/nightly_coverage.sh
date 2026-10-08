#!/usr/bin/env bash
# nightly_coverage.sh -- runs close_gate over the active engagements (e.g. nightly from
# cron/launchd) and reports the FAILs in ONE notification. Goal: let the MACHINE find
# surface/coverage gaps before a human does. Because close_gate is fail-closed, this
# report is the list of "targets you could not close + why".
#
# Notification is optional: set AL_TELEGRAM_TOKEN + AL_TELEGRAM_CHAT_ID (or point
# ATTACKLEDGER_SECRETS_FILE at a file defining them), or AL_NOTIFY_CMD (a command that
# receives the summary text as $1). With none set, the report is only printed/logged.
#
# Usage: nightly_coverage.sh           -> run + notify (if configured)
#        nightly_coverage.sh --dry     -> print only, do not notify
#
# The active list is $ATTACKLEDGER_WORKDIR/active_engagements.txt (one program per line, # comments ok).
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${ATTACKLEDGER_WORKDIR:-${ATTACKLEDGER_HOME:-$ROOT}/work}"
BASE="$ROOT/gates"
DRY=0; [ "${1:-}" = "--dry" ] && DRY=1
LIST="$WORKDIR/active_engagements.txt"
LOG="$WORKDIR/logs/nightly_coverage.log"
mkdir -p "$WORKDIR/logs"
TS="$(date '+%Y-%m-%d %H:%M')"
[ -f "$LIST" ] || { echo "active list not found: $LIST"; exit 1; }

REPORT=""
PASS_N=0; FAIL_N=0
while IFS= read -r prog; do
  prog="$(echo "$prog" | sed 's/#.*//; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  [ -z "$prog" ] && continue
  [ -d "$WORKDIR/engagements/$prog" ] || continue
  out="$(bash "$BASE/close_gate.sh" "$prog" --quiet 2>/dev/null)"
  if [ $? -eq 0 ]; then
    PASS_N=$((PASS_N+1))
  else
    FAIL_N=$((FAIL_N+1))
    # First line of the --quiet FAIL output is "CLOSE-GATE FAIL: <prog>", the rest are gaps
    REPORT+="> $prog"$'\n'
    # Keep the message compact: ~10 lines per program + a pointer to the full detail
    det="$(echo "$out" | grep -vE '^CLOSE-GATE FAIL' | sed 's/^/   /')"
    REPORT+="$(echo "$det" | head -10)"$'\n'
    [ "$(echo "$det" | wc -l)" -gt 10 ] && REPORT+="   ... (full list: close_gate.sh $prog)"$'\n'
    REPORT+=$'\n'
  fi
done < "$LIST"

SUMMARY="NIGHTLY COVERAGE AUDIT -- $TS
closable (PASS): $PASS_N  |  with gaps (FAIL): $FAIL_N

$REPORT"

echo "$SUMMARY"
echo "[$TS] PASS=$PASS_N FAIL=$FAIL_N" >> "$LOG"

if [ "$DRY" -eq 1 ]; then
  echo "(--dry: notification NOT sent)"
  exit 0
fi
# Notify only when there is a FAIL (no nightly "all clean" spam; remove this condition if you want it)
if [ "$FAIL_N" -gt 0 ]; then
  [ -n "${ATTACKLEDGER_SECRETS_FILE:-}" ] && [ -f "$ATTACKLEDGER_SECRETS_FILE" ] && { set -a; . "$ATTACKLEDGER_SECRETS_FILE" >/dev/null 2>&1; set +a; }
  if [ -n "${AL_NOTIFY_CMD:-}" ]; then
    $AL_NOTIFY_CMD "$SUMMARY" >/dev/null 2>&1 || true
  elif [ -n "${AL_TELEGRAM_TOKEN:-}" ] && [ -n "${AL_TELEGRAM_CHAT_ID:-}" ]; then
    curl -s -X POST "https://api.telegram.org/bot$AL_TELEGRAM_TOKEN/sendMessage" \
      -d "chat_id=$AL_TELEGRAM_CHAT_ID" --data-urlencode "text=$SUMMARY" >/dev/null 2>&1 || true
  fi
fi
