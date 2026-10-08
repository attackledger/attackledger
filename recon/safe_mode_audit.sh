#!/usr/bin/env bash
# safe_mode_audit.sh <skill> -- "safe mode" skill trimming.
#
# IDEA: measure WHICH steps of a skill the model ALREADY performs natively on its own.
# If the model does a step natively, that step can be removed from the skill, which
# lowers the opening context budget. A skill-usage audit measures whether a skill is
# USED at all; this tool measures which STEP of a skill is unnecessary. The two
# complement each other.
#
# This tool is a MEASUREMENT HARNESS: it extracts the skill's steps, generates a
# "safe mode" probe prompt (to hand to a fresh agent that runs WITHOUT the skill
# loaded), and keeps a comparison ledger. The native-or-not decision belongs to the
# human/orchestrator -- the tool eases the diff, it does not decide.
set -euo pipefail

SKILL="${1:-}"
[ -z "$SKILL" ] && { echo "usage: $0 <skill-name>  (e.g. hunt-xss / some-plugin:hunt-ssrf)"; exit 1; }
BARE="${SKILL#*:}"   # strip an optional "plugin:" prefix
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ATTACKLEDGER_HOME="${ATTACKLEDGER_HOME:-$ROOT}"
ATTACKLEDGER_WORKDIR="${ATTACKLEDGER_WORKDIR:-$ATTACKLEDGER_HOME/work}"
mkdir -p "$ATTACKLEDGER_WORKDIR"
LEDGER="$ATTACKLEDGER_WORKDIR/SAFE_MODE_LEDGER.tsv"

# locate the skill's SKILL.md (repo skills/ first, then ~/.claude/skills override, then plugin cache)
MD=""
for c in "$ATTACKLEDGER_HOME/skills/$BARE/SKILL.md" \
         "$HOME/.claude/skills/$BARE/SKILL.md" \
         "$HOME"/.claude/plugins/*/*/skills/"$BARE"/SKILL.md; do
  [ -f "$c" ] && { MD="$c"; break; }
done
[ -z "$MD" ] && { echo "SKILL.md not found: $BARE"; exit 1; }

LINES=$(wc -l < "$MD" | tr -d ' ')
BYTES=$(wc -c < "$MD" | tr -d ' ')
TOKENS=$(( BYTES / 4 ))   # rough estimate ~4 bytes/token

echo "=== SAFE-MODE AUDIT: $BARE"
echo "file : $MD"
echo "size : $LINES lines · $BYTES bytes · ~$TOKENS tokens (ADDED to opening cost)"
echo
echo "--- ACTIONABLE STEPS OF THE SKILL (numbered/bullet lines) ---"
grep -nE '^\s*([0-9]+\.|[-*]|#{2,3} )' "$MD" | sed 's/^/  /' | head -60
echo
echo "--- SAFE-MODE PROBE PROMPT (give to a fresh agent WITHOUT loading the skill) ---"
cat <<PROMPT
  For the target class/surface below, WITHOUT loading any skill, write as an ordered
  list what you would do step by step from your own knowledge (send no requests, plan only):
    target: <example surface, e.g. "reflected search parameter in a JSON API" / "endpoint that takes a URL parameter">
  Output only a numbered list of steps. One line per step.
PROMPT
echo
echo "--- COMPARISON ---"
echo "  Compare the probe output with the skill steps. Steps the model does NATIVELY"
echo "  can be removed from the skill. Record each decision in the ledger:"
echo "    $0 $BARE --record '<step summary>' <native:y|n|?> <decision:keep|trim>"
echo

# ledger entry: $0 <skill> --record "<step>" <native> <decision>
if [ "${2:-}" = "--record" ]; then
  STEP="${3:-}"; NATIVE="${4:-?}"; DEC="${5:-keep}"
  [ ! -f "$LEDGER" ] && printf 'skill\tstep\tnative\tdecision\tdate\n' > "$LEDGER"
  printf '%s\t%s\t%s\t%s\t%s\n' "$BARE" "$STEP" "$NATIVE" "$DEC" "$(date +%Y-%m-%d)" >> "$LEDGER"
  echo "recorded in ledger: $LEDGER"
fi

[ -f "$LEDGER" ] && { echo "--- LEDGER ($BARE) ---"; grep -P "^$BARE\t" "$LEDGER" 2>/dev/null | sed 's/^/  /' || grep "^$BARE	" "$LEDGER" | sed 's/^/  /'; }
