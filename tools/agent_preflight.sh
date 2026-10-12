#!/usr/bin/env bash
# Pre-flight for a live agent run on the lab (tools/agent_live.py): checks the key is set at the
# gateway (never printed), that the gateway would forward the worker's real Claude API call and
# its GW-1 body filter passes it, the lab, the lab engagement and lane (created if missing), and
# the budget. Sends nothing to the Claude API or the target. Exit 1 with a message on any failure.
#   bash tools/agent_preflight.sh [--dry-run] [--no-prepare] [--project NAME] [--env-file FILE] [--api URL]
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
exec python3 tools/agent_live.py preflight "$@"
