#!/usr/bin/env bash
# dork.sh — companion recon (NOT part of run_pipeline.sh).
# Shodan + Censys + GitHub code-search + trufflehog org scan + a ready-to-click Google-dork list.
#
# Usage:  ./dork.sh <target-domain> [github-org[,org2,...]]
#   e.g.  ./dork.sh example.com example-corp,example-labs
#
# API keys are read from ~/.config/subfinder/provider-config.yaml (shodan/censys/github/fofa),
# falling back to the optional file named by ATTACKLEDGER_SECRETS_FILE
# (GITHUB_TOKEN, SHODAN_API_KEY, CENSYS_PAT; optionally AL_TELEGRAM_TOKEN / AL_TELEGRAM_CHAT_ID
# for the summary ping, which is OFF unless DORK_TG=1).
# Output goes to $ATTACKLEDGER_WORKDIR/dorks/<target> (default workdir: <repo>/work).
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ATTACKLEDGER_HOME="${ATTACKLEDGER_HOME:-$ROOT}"
ATTACKLEDGER_WORKDIR="${ATTACKLEDGER_WORKDIR:-$ATTACKLEDGER_HOME/work}"

TARGET="${1:?usage: dork.sh <target-domain> [org1,org2,...]}"
ORGS="${2:-}"
DATE="$(date +%Y%m%d_%H%M%S)"
OUT="$ATTACKLEDGER_WORKDIR/dorks/${TARGET}"
mkdir -p "$OUT"
[ -n "${ATTACKLEDGER_SECRETS_FILE:-}" ] && [ -f "$ATTACKLEDGER_SECRETS_FILE" ] && source "$ATTACKLEDGER_SECRETS_FILE"

log(){ echo "[$(date +%H:%M:%S)] $*"; }
enc(){ python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$1"; }
cnt(){ [ -f "$1" ] && wc -l < "$1" | tr -d ' ' || echo 0; }

# --- key loader: subfinder provider-config first, then the optional secrets file ---
sfkey(){ # $1 = provider name -> prints first key (or "")
  python3 - "$1" <<'PY' 2>/dev/null
import sys,yaml,os
p=os.path.expanduser("~/.config/subfinder/provider-config.yaml")
try:
    d=yaml.safe_load(open(p)) or {}
except Exception:
    sys.exit(0)
v=d.get(sys.argv[1])
if isinstance(v,list) and v: print(str(v[0]).strip())
PY
}
GH_TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-$(sfkey github)}}"
SHODAN_KEY="${SHODAN_API_KEY:-$(sfkey shodan)}"
CENSYS_PAT="${CENSYS_PAT:-}"    # new Censys Platform PAT (censys_...), e.g. from the secrets file

TID="${AL_TELEGRAM_TOKEN:-}"; CIDT="${AL_TELEGRAM_CHAT_ID:-}"
DORK_TG="${DORK_TG:-0}"   # notifications are OFF by default; set DORK_TG=1 to send the summary ping (needs AL_TELEGRAM_TOKEN/AL_TELEGRAM_CHAT_ID)
tg(){ [ "$DORK_TG" = "1" ] && [ -n "$TID" ] && [ -n "$CIDT" ] && curl -s -X POST "https://api.telegram.org/bot$TID/sendMessage" -d "chat_id=$CIDT" --data-urlencode "text=$1" >/dev/null || true; }

############################################
log "=== 1. Shodan ==="
if [ -n "$SHODAN_KEY" ]; then
  SH="$OUT/shodan_${DATE}.txt"
  : > "$SH"
  for q in "hostname:$TARGET" "ssl.cert.subject.CN:$TARGET" "ssl:$TARGET"; do
    log "  shodan: $q"
    curl -s "https://api.shodan.io/shodan/host/search?key=${SHODAN_KEY}&query=$(enc "$q")&minify=false" \
      | jq -r --arg q "$q" '
          if .error then "[\($q)] ERROR: \(.error)"
          else (.matches[]? | "[\($q)] \(.ip_str):\(.port)  \(.product // "")\(if .version then " "+.version else "" end)  org=\(.org // "-")  host=\((.hostnames // [])|join(","))  title=\((.http.title) // "-")  vulns=\((.vulns // {})|keys|join(","))")
          end' 2>/dev/null | tee -a "$SH"
    sleep 1
  done
  log "Shodan lines: $(cnt "$SH")  ->  $SH"
  # also dump the raw hostname facet for a clean host list
  curl -s "https://api.shodan.io/shodan/host/search?key=${SHODAN_KEY}&query=$(enc "hostname:$TARGET")&facets=port:20,org:20,product:20&minify=false" \
    | jq -r '.facets // {} | to_entries[] | "\(.key): " + ([.value[]? | "\(.value)(\(.count))"]|join(", "))' 2>/dev/null > "$OUT/shodan_facets_${DATE}.txt"
else
  log "  (no Shodan key in subfinder config or secrets file -- skip)"
fi

############################################
log "=== 2. Censys (free-tier Platform API — cert-SAN pivot on seed hosts) ==="
# Free-tier Censys PAT can't search, but CAN do exact asset lookups.
# We look up webproperty/{host}:443 for a handful of seed hosts and harvest cert SANs
# (each cert reveals sibling subdomains), plus host lookups for the IPs found.
if [ -n "$CENSYS_PAT" ]; then
  CB="$OUT/censys_${DATE}.txt"; : > "$CB"
  # seed hosts: recon output if present, else guesses
  RES=$(ls -t "$ATTACKLEDGER_WORKDIR/targets/$TARGET"/subdomains/resolved_*.txt 2>/dev/null | head -1)
  if [ -n "$RES" ]; then SEEDS=$(head -40 "$RES"); else SEEDS=$'\n'"$TARGET"$'\n'"www.$TARGET"$'\n'"api.$TARGET"$'\n'"app.$TARGET"; fi
  CJ(){ curl -s -m 15 -H "Authorization: Bearer $CENSYS_PAT" "$1"; }
  echo "$SEEDS" | grep -E '\.' | sort -u | head -40 | while read -r h; do
    [ -z "$h" ] && continue
    CJ "https://api.platform.censys.io/v3/global/asset/webproperty/${h}:443" \
      | jq -r --arg h "$h" '(.result.resource // {}) |
          select(.cert or .software or .endpoints) |
          "HOST \($h)  sw=\([.software[]?.product]|join(","))  tls=\(.tls.version_selected // "-")  labels=\((.labels // [])|join(","))",
          (.cert.names[]? | "SAN \(.)")' 2>/dev/null >> "$CB"
    sleep 0.4
  done
  sort -u "$CB" -o "$CB"
  grep '^SAN ' "$CB" | awk '{print $2}' | sed 's/^\*\.//' | grep -E "(^|\.)${TARGET//./\\.}$" | sort -u > "$OUT/censys_new_subdomains_${DATE}.txt"
  log "Censys lines: $(cnt "$CB")  | subdomains from cert SANs: $(cnt "$OUT/censys_new_subdomains_${DATE}.txt")  ->  $CB"
else
  log "  (no CENSYS_PAT in secrets file -- skip)"
fi

############################################
log "=== 3. GitHub code search ==="
GHCS="$OUT/github_codesearch_${DATE}.txt"
if [ -z "$GH_TOKEN" ]; then
  log "!! no GitHub token (subfinder 'github' empty + no GITHUB_TOKEN in secrets file) — skipping GitHub modules"
else
  : > "$GHCS"
  TERMS=( "$TARGET" "api.$TARGET" "internal.$TARGET" "$TARGET password" "$TARGET api_key"
          "$TARGET secret" "$TARGET token" "$TARGET s3.amazonaws.com" "$TARGET BEGIN RSA PRIVATE KEY"
          "$TARGET mongodb://" "$TARGET postgres://" "$TARGET .env" )
  # exclude the well-known bug-bounty scope-aggregator repos (pure noise)
  NOISE='bounty-targets-data|h1domains|/scope|h1_assets|hackerone-|bugbounty-targets|/recon-|public-bugbounty|disclosed-|/wordlist|SecLists|/dorks'
  gh_search(){ curl -s -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/vnd.github+json" \
      "https://api.github.com/search/code?q=$(enc "$1")&per_page=50" \
      | jq -r --arg q "$1" '.items[]? | "[\($q)] \(.repository.full_name)  ->  \(.html_url)"' 2>/dev/null \
      | grep -Eiv "$NOISE"; }
  for t in "${TERMS[@]}"; do log "  q: $t"; gh_search "$t" | tee -a "$GHCS"; sleep 7; done
  if [ -n "$ORGS" ]; then
    IFS=',' read -ra OA <<< "$ORGS"
    for o in "${OA[@]}"; do for kw in api_key secret password token aws_access_key_id "PRIVATE KEY" "$TARGET"; do
      log "  q: org:$o $kw"; gh_search "org:$o $kw" | tee -a "$GHCS"; sleep 7
    done; done
  fi
  log "GitHub code-search hits: $(cnt "$GHCS")  ->  $GHCS"

  log "=== 4. trufflehog GitHub org scan ==="
  if command -v trufflehog >/dev/null && [ -n "$ORGS" ]; then
    TH="$OUT/trufflehog_${DATE}.json"; : > "$TH"
    IFS=',' read -ra OA <<< "$ORGS"
    for o in "${OA[@]}"; do
      log "  trufflehog github --org=$o (verified only)"
      trufflehog github --org="$o" --token="$GH_TOKEN" --only-verified --json 2>/dev/null >> "$TH" || true
    done
    log "trufflehog verified-secret lines: $(cnt "$TH")  ->  $TH"
  else
    log "  (trufflehog missing or no --org given — skip)"
  fi
fi

############################################
log "=== 5. Google-dork list (manual — open in a browser) ==="
GD="$OUT/google_dorks_${DATE}.txt"; : > "$GD"
B="https://www.google.com/search?q="
DORKS=(
  "site:$TARGET ext:env OR ext:log OR ext:bak OR ext:old OR ext:sql OR ext:yml OR ext:yaml OR ext:ini OR ext:conf"
  "site:$TARGET intitle:\"index of\""
  "site:$TARGET inurl:api OR inurl:swagger OR inurl:graphql OR inurl:actuator OR inurl:v1 OR inurl:v2"
  "site:$TARGET inurl:login OR inurl:admin OR inurl:signin OR inurl:portal OR inurl:dashboard"
  "site:$TARGET intext:\"api_key\" OR intext:\"client_secret\" OR intext:\"access_token\""
  "site:$TARGET intext:\"sql syntax near\" OR intext:\"stack trace\" OR intext:\"Warning: mysql\""
  "site:$TARGET ext:json OR ext:xml intext:\"password\" OR intext:\"secret\""
  "site:*.$TARGET -www"
  "site:s3.amazonaws.com $TARGET"
  "site:blob.core.windows.net $TARGET"
  "site:storage.googleapis.com $TARGET"
  "site:digitaloceanspaces.com $TARGET"
  "site:github.com $TARGET password OR secret OR api_key"
  "site:gitlab.com $TARGET"
  "site:pastebin.com $TARGET"
  "site:trello.com $TARGET"
  "site:atlassian.net $TARGET"
  "site:*.zendesk.com $TARGET"
  "site:docs.google.com $TARGET"
  "\"$TARGET\" filetype:pdf confidential OR internal OR \"do not distribute\""
  "\"$TARGET\" \"password\" filetype:xls OR filetype:xlsx OR filetype:csv"
)
for d in "${DORKS[@]}"; do printf '%s\n  %s%s\n\n' "$d" "$B" "$(enc "$d")" >> "$GD"; done
log "Google-dork list: $(grep -c 'google.com/search' "$GD") queries  ->  $GD"

############################################
log "=== DONE ==="
tg "🔦 dork.sh done: $TARGET
Shodan: $(cnt "$OUT/shodan_${DATE}.txt")  Censys: $(cnt "$OUT/censys_${DATE}.txt")
GH code-search: $(cnt "$GHCS")  trufflehog: $(cnt "$OUT/trufflehog_${DATE}.json")
out: $OUT"
echo; echo "Output dir: $OUT"; ls -la "$OUT"
