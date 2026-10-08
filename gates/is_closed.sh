#!/usr/bin/env bash
# is_closed.sh <program> -- is a target REALLY closed? Single source of truth:
# the EXISTENCE of CLOSE_RECEIPT.txt (produced fail-closed by close_gate.sh). Boards and
# notebooks read the "closed" state ONLY from here -- never from a verbal "done".
#   exit 0 = CLOSED (receipt exists) | exit 1 = OPEN (no receipt)
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${ATTACKLEDGER_WORKDIR:-${ATTACKLEDGER_HOME:-$ROOT}/work}"
R="$WORKDIR/engagements/${1:?usage: is_closed.sh <program>}/CLOSE_RECEIPT.txt"
if [ -f "$R" ]; then echo "CLOSED ($(sed -n '2p' "$R"))"; exit 0
else echo "OPEN (no CLOSE_RECEIPT -- close_gate.sh did not pass)"; exit 1; fi
