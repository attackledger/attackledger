#!/usr/bin/env bash
# job_queue_runner.sh -- runs HEAVY jobs (recon sweeps, bulk scans, monitoring cron
# jobs) one at a time, in order. Rationale: several heavy jobs started at the same
# moment pushed the load average far past the core count and slowed each other down.
#
# Run it once inside a long-lived screen/tmux session or a service:
#   screen -dmS job_queue bash recon/job_queue_runner.sh
#
# Adding a job: drop an executable .sh file into pending/. Prefix the file name with
# a timestamp for ordering (example: $(date +%s)_example_recon.sh) -- see enqueue.sh.
# The runner executes files in NAME order (== insertion order), one at a time; it does
# not start the next one until the current one finishes.
#
# Env:
#   ATTACKLEDGER_JOB_QUEUE        queue dir (default: $ATTACKLEDGER_WORKDIR/job_queue)
#   ATTACKLEDGER_SECRETS_FILE     optional file that is sourced (may export AL_TELEGRAM_*)
#   AL_TELEGRAM_TOKEN / AL_TELEGRAM_CHAT_ID   optional notifications (skipped when unset)
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ATTACKLEDGER_HOME="${ATTACKLEDGER_HOME:-$ROOT}"
ATTACKLEDGER_WORKDIR="${ATTACKLEDGER_WORKDIR:-$ATTACKLEDGER_HOME/work}"
Q="${ATTACKLEDGER_JOB_QUEUE:-$ATTACKLEDGER_WORKDIR/job_queue}"
mkdir -p "$Q/pending" "$Q/running" "$Q/done"
LOG="$Q/runner.log"
exec >> "$LOG" 2>&1

echo "=== job_queue_runner started: $(date -u +%FT%TZ) ==="

if [ -n "${ATTACKLEDGER_SECRETS_FILE:-}" ] && [ -f "$ATTACKLEDGER_SECRETS_FILE" ]; then
    set -a; . "$ATTACKLEDGER_SECRETS_FILE" >/dev/null 2>&1 || true; set +a
fi
tg() {
    [ -n "${AL_TELEGRAM_TOKEN:-}" ] && [ -n "${AL_TELEGRAM_CHAT_ID:-}" ] || return 0
    curl -s -X POST "https://api.telegram.org/bot$AL_TELEGRAM_TOKEN/sendMessage" \
        -d "chat_id=$AL_TELEGRAM_CHAT_ID" -d "disable_web_page_preview=true" \
        --data-urlencode "text=$1" >/dev/null || true
}

while true; do
    next=$(ls -1 "$Q/pending" 2>/dev/null | sort | head -1)
    if [ -z "$next" ]; then
        sleep 30
        continue
    fi
    mv "$Q/pending/$next" "$Q/running/$next"
    echo "[*] starting: $next ($(date -u +%FT%TZ))"
    bash "$Q/running/$next"
    rc=$?
    mv "$Q/running/$next" "$Q/done/$next"
    echo "[+] finished: $next (rc=$rc, $(date -u +%FT%TZ))"
    # NOTE: per-job start/finish pings were deliberately REMOVED -- they were noise.
    # Notify only when (1) the orchestrator starts a broad multi-program scan and
    # sends its own message, or (2) a validated finding is reported.
    # The tg() function is kept here (other scripts may source it) but is
    # intentionally not called per job.
done
