#!/usr/bin/env bash
# PreToolUse guard -- confirmation gate for the HTTP DELETE method.
# Policy: for irreversible writes, DELETE/removal is the ONLY class that asks for approval.
# Catches the DELETE method in Bash(curl -X DELETE / --request DELETE) and in Caido
# send/edit/replay requests, and returns permissionDecision:"ask".
#
# NOTE: the behavior of "ask" under bypassPermissions mode is undocumented; in a background
# subagent "ask" is probably auto-DENIED (fail-safe, which is the desired direction).
# Source: code.claude.com/docs/en/hooks (PreToolUse permissionDecision).
set -euo pipefail
IN="$(cat)"
jqget() { printf '%s' "$IN" | jq -r "$1 // empty" 2>/dev/null || true; }

TOOL="$(jqget '.tool_name')"
HIT=0
case "$TOOL" in
  Bash)
    CMD="$(jqget '.tool_input.command')"
    printf '%s' "$CMD" | grep -qiE '(-X|--request)[[:space:]]+["'\'']?DELETE' && HIT=1
    ;;
  mcp__caido__caido_send_request|mcp__caido__caido_edit_request|mcp__caido__caido_replay_send|mcp__caido__caido_race_window_send|mcp__caido__caido_batch_send)
    RAW="$(printf '%s' "$IN" | jq -r '.tool_input | tostring' 2>/dev/null || true)"
    printf '%s' "$RAW" | grep -qE '"method"[[:space:]]*:[[:space:]]*"DELETE"' && HIT=1
    printf '%s' "$RAW" | grep -qE '(^|\\n|\\r\\n)DELETE[[:space:]]' && HIT=1
    ;;
esac

[ "$HIT" -eq 0 ] && exit 0

jq -cn '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"ask",permissionDecisionReason:"The DELETE method may be irreversible. Policy: removal/DELETE is the only class that asks for approval. Confirm the target and its reversibility."}}'
