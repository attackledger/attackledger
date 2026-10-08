#!/usr/bin/env bash
# SubagentStop gate -- completion-bias catcher.
# When a hunting agent says "done" and tries to STOP, find the LANE_CHECKLIST_*.md files
# that agent TOUCHED; if any unchecked `- [ ]` box remains, send the agent BACK
# (decision:block + reason). stop_hook_active prevents an endless loop.
#
# Input (stdin JSON): agent_type, agent_transcript_path, stop_hook_active ...
# Source: code.claude.com/docs/en/hooks (SubagentStop + Stop decision control).
set -euo pipefail
IN="$(cat)"
jqget() { printf '%s' "$IN" | jq -r "$1 // empty" 2>/dev/null || true; }

ACTIVE="$(jqget '.stop_hook_active')"
[ "$ACTIVE" = "true" ] && exit 0   # already continuing because of this gate -> let it stop

TR="$(jqget '.agent_transcript_path')"
TR="${TR/#\~/$HOME}"
[ -z "$TR" ] || [ ! -f "$TR" ] && exit 0

# Find the checklist files the agent touched in its own transcript (Write/Edit paths).
# bash 3.2 compatible (macOS): no mapfile, use while-read.
CL="$(grep -oE '[^"]*LANE_CHECKLIST_[^"]*\.md' "$TR" 2>/dev/null | sort -u || true)"
[ -z "$CL" ] && exit 0   # never touched a checklist -> not this gate's job

OPEN=""
while IFS= read -r f; do
  [ -z "$f" ] && continue
  f="${f/#\~/$HOME}"
  [ -f "$f" ] || continue
  n="$(grep -c '^- \[ \]' "$f" 2>/dev/null || true)"
  [ -z "$n" ] && n=0
  if [ "$n" -gt 0 ]; then
    OPEN+="$f ($n unchecked boxes)"$'\n'
    OPEN+="$(grep '^- \[ \]' "$f" | sed 's/^/    /')"$'\n'
  fi
done <<< "$CL"

[ -z "$OPEN" ] && exit 0   # all boxes handled -> the lane may close

REASON="LANE-GATE: your checklist still has unchecked boxes, the lane is NOT closed.
Mark each box either '- [x]' (work written to disk) or '- [~] N/A: <reason>'.
Do not tick by guesswork; every [x] must be verifiable by a file/line. Remaining:
${OPEN}"

jq -cn --arg r "$REASON" '{decision:"block", reason:$r}'
