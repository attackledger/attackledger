#!/usr/bin/env bash
# Install a pre-push hook that runs the release gate. A push is blocked unless
# the gate passes (denylists, personal paths, secrets).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOK="$ROOT/.git/hooks/pre-push"
cat > "$HOOK" <<'HOOK'
#!/usr/bin/env bash
exec "$(git rev-parse --show-toplevel)/tools/release_gate.sh"
HOOK
chmod +x "$HOOK"
echo "pre-push hook installed: $HOOK"
