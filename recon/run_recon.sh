#!/usr/bin/env bash
# run_recon.sh <handle>
#
# Recon sweep + combined board in ONE command, both independent of the terminal
# session. Even if you log out, the sweep finishes and the board is generated
# (and a notification is sent if one is configured).
#
# Prerequisite -- the program prep output must be copied under
# $ATTACKLEDGER_WORKDIR/targets/<handle>/ :
#   domains.txt  scope.txt  oos.txt   (required)
#   crown.txt    apps.txt             (optional)
# Per-program variables live in $ATTACKLEDGER_WORKDIR/env/<handle>.env :
#   RESEARCH_HEADER, RATE_LIMIT, REQUIRE_AUTH, AUTH_HEADER
#
# WHY AN ENV FILE: RESEARCH_HEADER contains spaces and AUTH_HEADER contains spaces and
# semicolons. Embedding them inside `ssh host "screen -dmS x bash -c '...'"` breaks
# (the outer " and inner ' quoting is already exhausted), and because screen is
# detached the error is INVISIBLE -- the run never starts. The values are sourced
# from the file instead.
#
# Requires: screen. Companion scripts: recon/run_pipeline.sh and an optional
# auto_board.sh (board watcher) in the same directory.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ATTACKLEDGER_HOME="${ATTACKLEDGER_HOME:-$ROOT}"
ATTACKLEDGER_WORKDIR="${ATTACKLEDGER_WORKDIR:-$ATTACKLEDGER_HOME/work}"
SCRIPTS="$ATTACKLEDGER_HOME/recon"

HANDLE="${1:-}"
[ -n "$HANDLE" ] || { echo "usage: $0 <handle>"; exit 1; }

T="$ATTACKLEDGER_WORKDIR/targets/$HANDLE"
ENVF="$ATTACKLEDGER_WORKDIR/env/$HANDLE.env"

err=0
for f in domains.txt scope.txt; do
    [ -s "$T/$f" ] || { echo "[-] $T/$f is missing or empty"; err=1; }
done
[ -s "$T/oos.txt" ] || echo "[!] $T/oos.txt is missing -- if the scope has wildcards, out-of-scope hosts may be scanned."
[ "$err" -eq 0 ] || exit 1

if screen -ls 2>/dev/null | grep -q "${HANDLE}_sweep"; then
    echo "[-] ${HANDLE}_sweep is already running. Finish or close it first."; exit 1
fi

if [ -f "$ENVF" ]; then
    set -a; . "$ENVF"; set +a
    echo "[+] env: $ENVF"
else
    echo "[!] $ENVF is missing -- RESEARCH_HEADER/RATE_LIMIT will be empty."
fi

: "${RATE_LIMIT:=50}"
: "${REQUIRE_AUTH:=0}"

# AUTH gate: enforce it here too so the error is not lost inside screen.
if [ "$REQUIRE_AUTH" = "1" ] && [ -z "${AUTH_HEADER:-}" ]; then
    echo "[X] REQUIRE_AUTH=1 but AUTH_HEADER is empty. Log in and write it to $ENVF."
    echo "    If you deliberately run anonymously, set REQUIRE_AUTH=0 and WRITE DOWN THE DECISION."
    exit 1
fi

echo "[+] $HANDLE -- $(grep -c . "$T/domains.txt") roots · scope $(wc -l < "$T/scope.txt") lines · oos $(wc -l < "$T/oos.txt" 2>/dev/null || echo 0) lines"
echo "[+] header: ${RESEARCH_HEADER:-<none>} · rate: $RATE_LIMIT · REQUIRE_AUTH=$REQUIRE_AUTH"

# tee must be INSIDE bash -c; outside it would pipe screen's own (empty) output
# and the log would stay empty.
screen -dmS "${HANDLE}_sweep" bash -c "
    cd '$SCRIPTS'
    [ -f '$ENVF' ] && { set -a; . '$ENVF'; set +a; }
    RUN_LABEL='$HANDLE' RATE_LIMIT='$RATE_LIMIT' REQUIRE_AUTH='$REQUIRE_AUTH' \
    ./run_pipeline.sh '$T/domains.txt' '$T/scope.txt' 2>&1 | tee -a '$T/sweep.log'
"
sleep 3
screen -ls | grep -q "${HANDLE}_sweep" || { echo "[-] sweep did not start, check $T/sweep.log"; exit 1; }
echo "[+] sweep: screen ${HANDLE}_sweep"

screen -dmS "${HANDLE}_board" bash -c "'$SCRIPTS/auto_board.sh' '$HANDLE'"
sleep 2
screen -ls | grep -q "${HANDLE}_board" || echo "[!] board watcher did not start -- generate the board MANUALLY"
echo "[+] board watcher: screen ${HANDLE}_board"
echo
echo "    When done, automatically: BOARD.tsv + coverage statement + notification (if configured)."
echo "    You can log out; both keep running."
