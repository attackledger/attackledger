#!/usr/bin/env bash
# enqueue.sh <label> <command> -- writes a timestamped, executable job file into the
# pending/ dir of job_queue_runner.sh, which runs them one at a time, in order.
#
# Usage:
#   enqueue.sh example_recon 'recon/run_pipeline.sh work/targets/example/domains.txt work/targets/example/scope.txt'
#   from cron: 0 3 * * 1 /path/to/attackledger/recon/enqueue.sh example_watch '/path/to/watch.sh example >> cron.log 2>&1'
#
# Env: ATTACKLEDGER_JOB_QUEUE (default: $ATTACKLEDGER_WORKDIR/job_queue)
set -eu
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ATTACKLEDGER_HOME="${ATTACKLEDGER_HOME:-$ROOT}"
ATTACKLEDGER_WORKDIR="${ATTACKLEDGER_WORKDIR:-$ATTACKLEDGER_HOME/work}"
Q="${ATTACKLEDGER_JOB_QUEUE:-$ATTACKLEDGER_WORKDIR/job_queue}/pending"
mkdir -p "$Q"
label="${1:?usage: enqueue.sh <label> <command>}"; shift
cmd="${*:?usage: enqueue.sh <label> <command>}"
f="$Q/$(date +%s)_${label}.sh"
printf '%s\n' "$cmd" > "$f"
chmod +x "$f"
echo "queued: $f"
