#!/usr/bin/env bash
# One measured agent run on the lab (tools/agent_live.py): starts the lab if needed, prepares the
# lab engagement and lane, runs the pre-flight (and stops if it fails), runs ONE agent with the
# worker's model (the cheapest configured, unless --any-model), waits for it, prints what was sent
# and spent and appends it to docs/BENCHMARK.md. The API token comes from .env, never printed.
#   bash tools/agent_live_run.sh [--role errh|info|conf|inpv] [--any-model] [--max-turns N] [--max-requests N] [--no-append]
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
exec python3 tools/agent_live.py run "$@"
