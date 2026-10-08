#!/usr/bin/env bash
# Paths: all engagement data lives under $ATTACKLEDGER_WORKDIR (default: <repo>/work).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ATTACKLEDGER_HOME="${ATTACKLEDGER_HOME:-$ROOT}"
ATTACKLEDGER_WORKDIR="${ATTACKLEDGER_WORKDIR:-$ATTACKLEDGER_HOME/work}"
SECRETFINDER_DIR="${SECRETFINDER_DIR:-$HOME/tools/SecretFinder}"
mkdir -p "$ATTACKLEDGER_WORKDIR"

INPUT=$1
SCOPE_FILE=$2
DATE=$(date +"%Y%m%d_%H%M%S")

# Run label -- used in output file names so each run can be tied to a program.
# Single domain -> the domain name ("example.com").
# Domain list file -> the file name ("acme" <- acme.txt). Name your lists after the program.
# You can override it with the RUN_LABEL env var.
if [ -n "$RUN_LABEL" ]; then
    :
elif [ -f "$INPUT" ]; then
    RUN_LABEL=$(basename "$INPUT" | sed 's/\.[^.]*$//')
else
    RUN_LABEL="$INPUT"
fi
RUN_LABEL=$(echo "$RUN_LABEL" | tr -c 'A-Za-z0-9._-' '_' | sed 's/_*$//')

if [ -z "$INPUT" ]; then
    echo "[-] Usage: $0 <domain.com | domain_list.txt> [scope_file.txt]"
    echo "    scope_file.txt: the program's official in-scope asset list (one domain/*.domain per line)."
    echo "                    if omitted, nothing is filtered (everything found counts as in-scope) -- a WARNING is printed."
    exit 1
fi

# Check that required tools exist -- a missing tool must not silently produce an empty file
check_deps() {
    local required=(subfinder dnsx assetfinder naabu httpx gau waybackurls katana uro gf nuclei jq anew zip curl)
    local missing=()
    for tool in "${required[@]}"; do
        command -v "$tool" &>/dev/null || missing+=("$tool")
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        echo "[!] WARNING: these tools were not found in PATH, the related modules will produce empty/broken output: ${missing[*]}"
    fi
    # Optional tools -- if missing, the related module is silently skipped (not fatal)
    local optional=(feroxbuster arjun dnsgen puredns cloud_enum s3scanner apkeep apktool jadx)
    local opt_missing=()
    for tool in "${optional[@]}"; do
        command -v "$tool" &>/dev/null || opt_missing+=("$tool")
    done
    if [ "${#opt_missing[@]}" -gt 0 ]; then
        echo "[i] Optional tools missing (related module is skipped): ${opt_missing[*]}"
    fi
}
check_deps

# Optional secrets/config file: ATTACKLEDGER_SECRETS_FILE points at a shell-style KEY=VALUE
# file (API keys such as GITHUB_TOKEN, DEFAULT_RESEARCH_HEADER, DEFAULT_RATE_LIMIT, ...).
# Skipped silently if unset.
if [ -n "${ATTACKLEDGER_SECRETS_FILE:-}" ] && [ -f "$ATTACKLEDGER_SECRETS_FILE" ]; then
    # tighten permissions -- this file may hold API tokens
    SECRETS_PERMS=$(stat -c "%a" "$ATTACKLEDGER_SECRETS_FILE" 2>/dev/null)  # Linux/GNU
    [ -z "$SECRETS_PERMS" ] && SECRETS_PERMS=$(stat -f "%Lp" "$ATTACKLEDGER_SECRETS_FILE" 2>/dev/null)  # macOS/BSD
    if [ "$SECRETS_PERMS" != "600" ]; then
        chmod 600 "$ATTACKLEDGER_SECRETS_FILE"
        echo "[+] Secrets file permissions tightened to 600 (previous: $SECRETS_PERMS)."
    fi
    source "$ATTACKLEDGER_SECRETS_FILE"
fi


# No "recon started" notification is sent (see the note after the OOS section).

# --- Program-specific identification & rate limit ---
# IMPORTANT: these are PER PROGRAM -- verify them against each new target's own policy page,
# never reuse a value left over from another program.
# Two identification styles are seen across programs:
#   - fixed header style: RESEARCH_HEADER="X-Bug-Bounty: <your-handle>"
#   - User-Agent style:   RESEARCH_USER_AGENT="Mozilla/5.0 (compatible; bugbounty:<your-handle>)"
# Both can be set at the same time. A value exported as an env var before the call
# (e.g. RESEARCH_HEADER="" RESEARCH_USER_AGENT="..." ./run_pipeline.sh ...)
# takes precedence over the DEFAULT_* values from the secrets file.
RESEARCH_HEADER="${RESEARCH_HEADER:-$DEFAULT_RESEARCH_HEADER}"
RESEARCH_USER_AGENT="${RESEARCH_USER_AGENT:-$DEFAULT_RESEARCH_USER_AGENT}"
RATE_LIMIT="${RATE_LIMIT:-${DEFAULT_RATE_LIMIT:-50}}"

HEADER_ARGS=()
if [ -n "$RESEARCH_HEADER" ]; then
    echo "[+] Research header active: $RESEARCH_HEADER"
    HEADER_ARGS+=(-H "$RESEARCH_HEADER")
fi
if [ -n "$RESEARCH_USER_AGENT" ]; then
    echo "[+] Custom User-Agent active: $RESEARCH_USER_AGENT"
    HEADER_ARGS+=(-H "User-Agent: $RESEARCH_USER_AGENT")
fi
if [ ${#HEADER_ARGS[@]} -eq 0 ]; then
    echo "[!] WARNING: neither RESEARCH_HEADER nor RESEARCH_USER_AGENT is set. Test traffic will go out unidentified."
fi
echo "[+] Rate limit: ${RATE_LIMIT} req/s (httpx/katana/nuclei) -- adjust to the program's rules."
# The program's rate limit is a ceiling for port scanning too (it was RATE_LIMIT * 10).
NAABU_RATE=$RATE_LIMIT
NAABU_CONCURRENCY=$RATE_LIMIT
[ "$NAABU_CONCURRENCY" -gt 25 ] && NAABU_CONCURRENCY=25
# v13: nuclei bulk-size = hosts in parallel per template. RATE_LIMIT/10 keeps ~10 req/s per host
NUCLEI_BS=$(( RATE_LIMIT / 10 )); [ "$NUCLEI_BS" -lt 1 ] && NUCLEI_BS=1

# --- Optional depth modules ---
# Module 3 (ferox) + Module 5 (arjun) cost minutes per domain. In a MULTI-DOMAIN sweep
# (INPUT is a list file) they are OFF BY DEFAULT -- sweep = breadth, these = depth;
# after the sweep, run a focused single-domain pass on the chosen target, or set them to 1 in the env.
# In a SINGLE-DOMAIN run they are ON by default. Cheap modules (8 JS analysis, 9 dork checklist) are always on.
if [ -f "$INPUT" ]; then _DEEP_DEFAULT=0; else _DEEP_DEFAULT=1; fi

# v14 -- TWO-PHASE FLOW
#   PHASE A (discovery): DISCOVERY_ONLY=1 -> module 1 runs, deep modules (3/5) are off.
#                   Goal: get the live host list quickly, then present it to a HUMAN.
#   PHASE C (depth): DEPTH_ONLY=1 -> modules 1/1b/1c are SKIPPED, the given host is scanned
#                   directly. Discovery was already done in Phase A, so re-running subfinder/crt.sh/
#                   puredns per host was pure waste (20 hosts = 80
#                   needless external queries + 20x300k-word brute force).
DEPTH_ONLY="${DEPTH_ONLY:-0}"
DISCOVERY_ONLY="${DISCOVERY_ONLY:-0}"
if [ "$DEPTH_ONLY" = "1" ] && [ "$DISCOVERY_ONLY" = "1" ]; then
    echo "[-] DEPTH_ONLY and DISCOVERY_ONLY cannot both be 1."; exit 1
fi
# CAUTION: lowering _DEEP_DEFAULT wholesale is WRONG -- DNS_BRUTE (1c) and CLOUD_ENUM (9a)
# depend on it too, and both are DISCOVERY modules. Turning them off in the discovery phase would
# switch off discovery itself. So the toggles are set one by one; if the user
# passes one explicitly in the env, theirs wins (${VAR:-...} sees the user value first).
if [ "$DISCOVERY_ONLY" = "1" ]; then
    CONTENT_DISCOVERY="${CONTENT_DISCOVERY:-0}"   # 3 ferox  -- depth, in Phase C
    PARAM_MINING="${PARAM_MINING:-0}"             # 5 arjun  -- depth, in Phase C
    DNS_BRUTE="${DNS_BRUTE:-1}"                   # 1c       -- DISCOVERY, must stay on
    CLOUD_ENUM="${CLOUD_ENUM:-1}"                 # 9a       -- DISCOVERY, cheap
    DORK="${DORK:-1}"                             # 10       -- cheap, apex level
fi
if [ "$DEPTH_ONLY" = "1" ]; then
    CONTENT_DISCOVERY="${CONTENT_DISCOVERY:-1}"
    PARAM_MINING="${PARAM_MINING:-1}"
    CLOUD_ENUM="${CLOUD_ENUM:-1}"
    DORK="${DORK:-0}"                             # dorking is meaningful at apex level,
                                                                                                # repeating it per host is unnecessary
fi

GOLDEN_MAX="${GOLDEN_MAX:-120}"   # upper bound of the priority list carried into golden
CONTENT_DISCOVERY="${CONTENT_DISCOVERY:-$_DEEP_DEFAULT}"   # Module 3 -- feroxbuster active content discovery
PARAM_MINING="${PARAM_MINING:-$_DEEP_DEFAULT}"            # Module 5 -- arjun hidden parameter discovery
FEROX_TIME_LIMIT="${FEROX_TIME_LIMIT:-15m}"   # feroxbuster global time ceiling
FEROX_MAX_HOSTS="${FEROX_MAX_HOSTS:-40}"      # max golden hosts handed to ferox
ARJUN_MAX_URLS="${ARJUN_MAX_URLS:-25}"        # max endpoints handed to arjun
if [ -f "$INPUT" ]; then JS_MAX_FILES="${JS_MAX_FILES:-120}"; else JS_MAX_FILES="${JS_MAX_FILES:-200}"; fi  # Module 8
CONTENT_WORDLIST="${CONTENT_WORDLIST:-$ATTACKLEDGER_WORKDIR/wordlists/content_lean.txt}"
[ "$CONTENT_DISCOVERY" = "1" ] || echo "[i] Module 3 (ferox content discovery) OFF (multi-domain sweep). On in a focused run, or pass CONTENT_DISCOVERY=1."
[ "$PARAM_MINING" = "1" ] || echo "[i] Module 5 (arjun parameter mining) OFF (multi-domain sweep). On in a focused run, or pass PARAM_MINING=1."

# --- DNS discovery depth (Module 1b/1c) ---
DNS_PERMUTE="${DNS_PERMUTE:-1}"                 # 1b -- dnsgen permutation + resolve (every run, cheap/low noise)
DNS_PERMUTE_MAX="${DNS_PERMUTE_MAX:-200000}"    # permutation candidate ceiling
DNS_BRUTE="${DNS_BRUTE:-$_DEEP_DEFAULT}"        # 1c -- puredns wordlist bruteforce (on when focused, off in sweeps)
DNS_BRUTE_WORDLIST="${DNS_BRUTE_WORDLIST:-$ATTACKLEDGER_WORKDIR/wordlists/dns_brute_300k.txt}"
DNS_RATE="${DNS_RATE:-1000}"
RESOLVERS_FILE="${RESOLVERS_FILE:-$ATTACKLEDGER_WORKDIR/resolvers/resolvers.txt}"
[ "$DNS_BRUTE" = "1" ] || echo "[i] Module 1c (DNS wordlist bruteforce) OFF (multi-domain sweep). On in a focused run, or pass DNS_BRUTE=1."

# --- Authenticated crawl (Module 4b) ---
# For an authenticated crawl pass a header in the env:  AUTH_HEADER='Cookie: session=...'  or
#   AUTH_HEADER='Authorization: Bearer eyJ...'  -- the post-login surface (account pages,
#   /api/me, admin) is only visible this way. If empty, 4b is skipped.
AUTH_HEADER="${AUTH_HEADER:-}"
AUTH_CRAWL_SEEDS="${AUTH_CRAWL_SEEDS:-}"        # optional: file with URLs to crawl (default: golden)
AUTH_CRAWL_HEADLESS="${AUTH_CRAWL_HEADLESS:-0}" # headless chrome for SPAs (chrome must be installed)
# v14.6 -- HARD AUTH GATE.
# When program_info.md says "AUTH SURFACE -- YES", the prep step puts REQUIRE_AUTH=1 on the suggested command.
# Running unauthenticated in that case is a silent coverage loss: in a past run all 183 hosts of a
# program were mapped with the anonymous surface only; neither the script nor the operator enforced the gate.
# A warning is not enough -- there already was one and it went unseen. So the run stops before a single packet is sent.
REQUIRE_AUTH="${REQUIRE_AUTH:-0}"
if [ "$REQUIRE_AUTH" = "1" ] && [ -z "$AUTH_HEADER" ]; then
    echo "=================================================="
    echo "[X] STOPPED: REQUIRE_AUTH=1 but AUTH_HEADER is empty."
    echo "    This program has a login-gated surface; an unauthenticated run would miss it."
    echo "    Log in to the target (e.g. through your proxy), then on the machine running the pipeline:"
    echo "      \$EDITOR \"\$ATTACKLEDGER_WORKDIR/env/<handle>.env\"   ->   AUTH_HEADER='Cookie: ...'"
    echo "      source \"\$ATTACKLEDGER_WORKDIR/env/<handle>.env\" && ./run_pipeline.sh $INPUT ..."
    echo "    If you intend to run anonymously: pass REQUIRE_AUTH=0 (and write the decision down)."
    echo "=================================================="
    exit 1
fi
if [ -n "$AUTH_HEADER" ]; then
    echo "[+] Authenticated crawl ACTIVE (Module 4b) -- AUTH_HEADER provided."
else
    # v14.6: print in sweeps too. It used to be `elif [ ! -f "$INPUT" ]`, so in a multi-domain
    # run this line was NEVER shown -- and that is where the most surface gets missed.
    echo "[!] No AUTH_HEADER -> Module 4b (authenticated crawl) will be SKIPPED. Only the anonymous surface is scanned."
    echo "    If the target has a login: log in through your proxy, then"
    echo "    pass AUTH_HEADER='Cookie: ...'  or  AUTH_HEADER='Authorization: Bearer ...'  and run again."
fi

# --- Cloud / infra / mobile enum (Module 9) ---
# cloud_enum works at org level -- running it 14 times for the 14 roots of one program in a
# multi-domain sweep is waste. Default OFF in sweeps, ON in focused runs (once, with good keywords).
CLOUD_ENUM="${CLOUD_ENUM:-$_DEEP_DEFAULT}"      # 9a -- cloud bucket enum (cloud_enum + s3scanner; cheap, scope-safe)
CLOUD_ENUM_TIMEOUT="${CLOUD_ENUM_TIMEOUT:-600}"
ASN_EXPAND="${ASN_EXPAND:-0}"                   # 9b -- ASN->CIDR (SCOPE RISK: set 1 only if the program scopes IP ranges/ASNs; only writes a file, does not scan)
APK_PACKAGES="${APK_PACKAGES:-}"                # 9c -- mobile recon (apkeep+apktool+jadx) when given "com.a.b,com.c.d"
MOBILE_AUTODISCOVER="${MOBILE_AUTODISCOVER:-1}" # if the crawl finds a play.google.com link, pick up the package automatically
[ "$ASN_EXPAND" = "1" ] && echo "[!] ASN_EXPAND=1 -- ASN->CIDR ON. Use only if the program scopes IPs/ASNs; output is written to a file, never scanned automatically."
[ "$CLOUD_ENUM" = "1" ] || echo "[i] Module 9a (cloud bucket enum) OFF (multi-domain sweep). On in a focused run, or pass CLOUD_ENUM=1."

if [ -z "$SCOPE_FILE" ] || [ ! -f "$SCOPE_FILE" ]; then
    echo "[!] WARNING: no scope file given/found. Scope-diff will be SKIPPED -- everything found is assumed in-scope."
    SCOPE_FILE=""
else
    echo "[+] Scope file active: $SCOPE_FILE ($(wc -l < "$SCOPE_FILE") lines)"
fi

# v14.7 -- katana crawl-scope restriction.
# -jc (JS endpoint parsing) also discovered out-of-scope third-party domains and wrote them to the
# list; the default -fs (rdn) does not prevent that on its own. A regex is generated from scope.txt
# and ENFORCED with -cs.
KATANA_SCOPE_REGEX=""
if [ -n "$SCOPE_FILE" ] && [ -f "$SCOPE_FILE" ]; then
    KATANA_SCOPE_REGEX="$(grep -vE '^\s*$|^#' "$SCOPE_FILE" \
        | sed -E 's/^\*\.//; s/[.]/\\./g' \
        | paste -sd '|' -)"
    if [ -n "$KATANA_SCOPE_REGEX" ]; then
        echo "[+] Katana crawl-scope locked: ($KATANA_SCOPE_REGEX)"
    fi
fi

# v14.1 -- OOS DENY LIST (deny-wins).
# filter_scope() used to look only at the allow list. If a program says
# "*.example.com in scope" and "shop.example.com out of scope", the OOS host matches the
# wildcard, so it counted as in-scope and received naabu/httpx traffic.
# Deny always beats allow (the "deny-wins" rule of the zero-skip protocol).
# v14.3 defence line: if a file named `-` exists in the CWD, every ProjectDiscovery tool that reads stdin
# reads it and the run is silently polluted with another target's data. Stop early and loudly.
if [ -f ./- ]; then
    echo "[-] THERE IS A FILE NAMED '-' IN THE WORKING DIRECTORY ($(pwd)/-, $(wc -l < ./- 2>/dev/null) lines)."
    echo "    Tools like dnsx/httpx read this file instead of stdin and the run is silently polluted."
    echo "    Delete it and retry:  rm -- '$(pwd)/-'"
    exit 1
fi

OOS_FILE="${OOS_FILE:-}"
if [ -n "$OOS_FILE" ] && [ -f "$OOS_FILE" ]; then
    echo "[+] OOS deny list active: $OOS_FILE ($(grep -cvE '^\s*$|^#' "$OOS_FILE") lines)"
elif [ -n "$SCOPE_FILE" ]; then
    _auto_oos="$(dirname "$SCOPE_FILE")/oos.txt"
    if [ -f "$_auto_oos" ]; then
        OOS_FILE="$_auto_oos"
        echo "[+] OOS deny list found automatically: $OOS_FILE"
    else
        echo "[!] NO OOS deny list. If scope.txt has a wildcard, hosts that match it but are"
        echo "    explicitly OOS may get scanned. Produce an oos.txt (prep step) or pass OOS_FILE."
    fi
fi

# No "recon started" / "recon finished" notification is sent. Recon is routine and a ping per run
# is noise. If you want notifications, wire your own optional notifier in a wrapper and
# fire it on verified findings only.
# Launch details (scope/OOS/header/rate/outdir) are already printed to the terminal above.


# Golden target keywords -- edit per target (this list fits a generic corporate web app;
# fintech-specific leftovers such as kyc/cashier/p2p/wallet were removed)
GOLDEN_REGEX="admin|api|dev|uat|test|stg|portal|dashboard|login|payment|upload|extranet|sso|b2b|erp|sap|shop|account"

# v14: the local BORING_RE of module 7 was moved here -- module 2's prioritization
# uses the same "is this just a CDN/LB" list. One source, two consumers.
BORING_RE='^(amazoncloudfront|amazonelb|amazonwebservices|awselb|envoy|hsts|googlecloud|googlecloudcdn|googlefontapi|googlehostedlibraries|googletagmanager|microsofthttpapi|cloudflare|akamai|fastly|varnish)$'

# One-line-per-target stats accumulator -- every process_domain() call appends a line here
# instead of sending its own message; ONE summary is produced when the run ends
# (instead of hundreds of separate notifications in a multi-domain run).
RUN_STATS_FILE="$ATTACKLEDGER_WORKDIR/${RUN_LABEL}_run_stats_${DATE}.tsv"
: > "$RUN_STATS_FILE"

# ─────────────────────────────────────────────────────────────────────────────
# v14 -- TARGET OWNERSHIP FILTER
#
# Until now nothing in the pipeline asked "does this host really belong to $TARGET?".
# Of the 5 sources in module 1 only crt.sh had a suffix check; the outputs of
# subfinder/assetfinder/github-subdomains/dnsgen/puredns went straight into
# resolved. Without the check, alive hosts and js_files can be dominated by
# unrelated third-party domains.
#
# Suffix semantics match the crt.sh guard (module 1a): host == TARGET or ends with .TARGET.
# Tolerant of case and a trailing dot.
#
# EXEMPTION: hosts written LITERALLY (non-wildcard) in scope.txt pass. Reason:
# multi-apex programs (a run for one apex where a host under another apex is in
# scope) -- these are not subdomains of the target but they are legitimately in the program scope.
in_target_filter() {
    local infile="$1" outfile="$2" foreignfile="$3" target="$4"
    : > "$outfile"
    : > "$foreignfile"
    if [ -z "$target" ]; then
        echo "[-] in_target_filter: TARGET is empty -- cannot filter, aborting the run." >&2
        return 1
    fi
    awk -v target="$target" -v scopefile="${SCOPE_FILE:-}" -v outfile="$outfile" -v foreignfile="$foreignfile" '
        BEGIN {
            target = tolower(target); sub(/\.$/, "", target)
            # literal (non-wildcard) scope.txt entries -> exempt
            if (scopefile != "") {
                while ((getline line < scopefile) > 0) {
                    gsub(/\r$/, "", line)
                    if (line == "" || line ~ /^#/ || line ~ /^\*\./) continue
                    sub(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "", line)
                    sub(/[\/:].*/, "", line)
                    line = tolower(line); sub(/\.$/, "", line)
                    if (line != "") literal[line] = 1
                }
                close(scopefile)
            }
        }
        {
            host = $0
            sub(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "", host)
            sub(/[\/:].*/, "", host)
            host = tolower(host); sub(/\.$/, "", host)
            if (host == target || host ~ ("\\." target "$") || (host in literal))
                print $0 >> outfile
            else
                print $0 >> foreignfile
        }
    ' "$infile"
}

# Splits a URL list into in-scope / out-of-scope according to the scope file.
# Scope file entries can be "domain.com" (exactly that ONE host, exact match) or "*.domain.com"
# (that domain + ALL its subdomains, suffix match). This mirrors the platform's own
# WILDCARD vs URL asset_type split -- csv_to_scope.py preserves it.
# If a program uses no WILDCARD at all (every subdomain listed separately),
# everything except an exact match is correctly treated as out of scope.
filter_scope() {
    local infile="$1" outfile="$2" oosfile="$3"
    : > "$outfile"
    : > "$oosfile"
    if [ -z "$SCOPE_FILE" ]; then
        cp "$infile" "$outfile"
        return
    fi
    awk -v scopefile="$SCOPE_FILE" -v oosfile_in="${OOS_FILE:-}" -v outfile="$outfile" -v oosfile="$oosfile" '
        function norm(v) {
            sub(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "", v)
            sub(/[\/:].*/, "", v)
            v = tolower(v); sub(/\.$/, "", v)
            return v
        }
        BEGIN {
            # the deny list is loaded FIRST; a match never reaches the allow check
            if (oosfile_in != "") {
                while ((getline dline < oosfile_in) > 0) {
                    gsub(/\r$/, "", dline)
                    if (dline == "" || dline ~ /^#/) continue
                    if (dline !~ /\./ || dline ~ / /) continue   # free text such as "Any 3rd party domain"
                    if (dline ~ /^\*\./) { sub(/^\*\./, "", dline); d_wild[norm(dline)] = 1 }
                    else                  { d_exact[norm(dline)] = 1 }
                }
                close(oosfile_in)
            }
            while ((getline line < scopefile) > 0) {
                gsub(/\r$/, "", line)
                if (line == "" || line ~ /^#/) continue
                if (line ~ /^\*\./) {
                    sub(/^\*\./, "", line)
                    wildcard[line] = 1
                } else {
                    exact[line] = 1
                }
            }
        }
        {
            host = norm($0)
            # DENY-WINS: if OOS, the allow list is never consulted
            denied = 0
            if (host in d_exact) denied = 1
            else { for (dd in d_wild) if (host == dd || host ~ ("\\." dd "$")) { denied = 1; break } }
            if (denied) { print $0 >> oosfile; next }
            matched = 0
            if (host in exact) matched = 1
            else {
                for (s in wildcard) {
                    if (host == s || host ~ ("\\." s "$")) { matched = 1; break }
                }
            }
            if (matched) print $0 >> outfile
            else print $0 >> oosfile
        }
    ' "$infile"
}

# Module 9 helper -- Google dorks CANNOT be automated (Google blocks bots, no free API).
# So for every target the pipeline writes click-ready dork URLs + the dork.sh command to a file;
# it is referenced in CLAUDE_SUMMARY so this step is not forgotten as "skipped" after recon.
write_manual_next_steps() {
    local T="$1" OUT="$2"
    local O="${T%%.*}"   # rough org name guess (brand)
    urlenc() { python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "$1"; }
    local g="https://www.google.com/search?q="
    {
        echo "# Manual Next Steps -- $T"
        echo "_The pipeline cannot automate these. Recon is done; go through them before moving on to hunting._"
        echo
        echo "## 1) Google dork checklist (click to open)"
        echo "- Exposed files: ${g}$(urlenc "site:$T ext:env OR ext:log OR ext:bak OR ext:old OR ext:sql OR ext:yml OR ext:ini OR ext:conf")"
        echo "- Index of: ${g}$(urlenc "site:$T intitle:\"index of\"")"
        echo "- Config + password: ${g}$(urlenc "site:$T ext:json OR ext:xml intext:password OR intext:secret")"
        echo "- API / debug: ${g}$(urlenc "site:$T inurl:api OR inurl:swagger OR inurl:graphql OR inurl:actuator")"
        echo "- Token/key leakage: ${g}$(urlenc "site:$T intext:api_key OR intext:client_secret OR intext:access_token")"
        echo "- Panels / auth: ${g}$(urlenc "site:$T inurl:login OR inurl:admin OR inurl:portal OR inurl:dashboard")"
        echo "- Stack trace: ${g}$(urlenc "site:$T intext:\"stack trace\" OR intext:\"sql syntax near\" OR intext:\"Warning: mysql\"")"
        echo "- Subdomain sweep: ${g}$(urlenc "site:*.$T -www")"
        echo "- S3: ${g}$(urlenc "site:s3.amazonaws.com $O")"
        echo "- Azure blob: ${g}$(urlenc "site:blob.core.windows.net $O")"
        echo "- GCS: ${g}$(urlenc "site:storage.googleapis.com $O")"
        echo "- GitHub: ${g}$(urlenc "site:github.com $O password OR secret OR api_key")"
        echo "- Trello/Atlassian: ${g}$(urlenc "site:trello.com $O OR site:atlassian.net $O")"
        echo "- Confidential documents: ${g}$(urlenc "\"$O\" filetype:pdf confidential OR internal OR \"do not distribute\"")"
        echo
        echo "## 2) Dork automation (GitHub / Shodan / trufflehog)"
        echo '```'
        echo "./recon/dork.sh $T <github-org1,org2>   # you/the operator know the org names, the pipeline does not"
        echo '```'
        echo
        echo "## 3) Review the JS deep-analysis output"
        echo "- analysis/gf_patterns/js_analysis_${DATE}/js_sourcemaps.txt  -> if an open .map exists: source tree + embedded secrets"
        echo "- analysis/gf_patterns/js_analysis_${DATE}/js_graphql_ops.txt -> GraphQL schema map (gold if introspection is off)"
        echo "- analysis/gf_patterns/js_analysis_${DATE}/js_endpoints.txt   -> API paths that are not linked anywhere"
        echo
        echo "## 4) Deep recon modules (if skipped in the sweep)"
        if [ "$CONTENT_DISCOVERY" != "1" ] || [ "$PARAM_MINING" != "1" ]; then
            echo "This run was a multi-domain sweep -> Module 3 (ferox) / 5 (arjun) were skipped. When you focus on this target:"
            echo '```'
            echo "CONTENT_DISCOVERY=1 PARAM_MINING=1 RATE_LIMIT=<program-limit> ./recon/run_pipeline.sh $T <scope.txt>"
            echo '```'
        else
            echo "The deep modules (3 ferox + 5 arjun) ran in this run -- outputs are under analysis/ and endpoints/."
        fi
        echo
        echo "## 5) Authenticated crawl (Module 4b) -- run again once you have a session"
        if [ -z "$AUTH_HEADER" ]; then
            echo "No AUTH_HEADER in this run -> the post-login surface was not crawled. Once you have a session cookie/token:"
            echo '```'
            echo "AUTH_HEADER='Cookie: session=...' CONTENT_DISCOVERY=1 PARAM_MINING=1 ./recon/run_pipeline.sh $T <scope.txt>"
            echo "#  or:  AUTH_HEADER='Authorization: Bearer eyJ...'"
            echo "#  for an SPA:  AUTH_CRAWL_HEADLESS=1  (needs chrome)"
            echo '```'
            echo "Output: endpoints/authenticated_urls_*.txt -- the real BOLA/IDOR/mass-assignment surface."
        else
            echo "Authenticated crawl ran in this run -> endpoints/authenticated_urls_${DATE}.txt"
        fi
        echo
        echo "## 6) webapp-checklist"
        echo "As soon as you have an authed session run the web-app checklist -- all 15 sections, not just BOLA."
    } > "$OUT"
}

process_domain() {
    # SECOND DEFENCE LAYER (in addition to fd3): whatever command runs in the rest of this function
    # (naabu/httpx/katana/nuclei/xargs...) now sees fd0=/dev/null.
    # That removes the possibility of a command consuming the input of the outer
    # "while read domain <&3" loop from the inside and ending it early -- no need to
    # diagnose exactly which tool is guilty.
    exec < /dev/null
    local TARGET="$1"
    local BASE_DIR="$ATTACKLEDGER_WORKDIR/targets/$TARGET"
    local SUBS_DIR="$BASE_DIR/subdomains"
    local TRIAGE_DIR="$BASE_DIR/triage"
    local ENDPOINTS_DIR="$BASE_DIR/endpoints"
    local ANALYSIS_DIR="$BASE_DIR/analysis/gf_patterns"

    mkdir -p "$SUBS_DIR" "$TRIAGE_DIR" "$ENDPOINTS_DIR" "$ANALYSIS_DIR"

    # v13: lightweight checkpoint. RESUME=1 skips a domain whose last run finished cleanly.
    local STATE_FILE="$BASE_DIR/.pipeline_state"
    if [ "${RESUME:-0}" = "1" ] && grep -q "^COMPLETE=1" "$STATE_FILE" 2>/dev/null; then
        echo "[i] $TARGET: previous run completed (.pipeline_state COMPLETE=1) -- RESUME=1, skipping."
        return 0
    fi
    printf "STARTED=%s\nDATE=%s\n" "$(date -u +%FT%TZ)" "$DATE" > "$STATE_FILE"

    echo "=================================================="
    echo "[+] PIPELINE STARTED: $TARGET - $DATE"
    echo "=================================================="

    # Module 1: Subdomain Discovery
    # v14: skipped ENTIRELY when DEPTH_ONLY=1 -- the host was already discovered in Phase A,
    #      re-running subfinder/crt.sh/puredns is pure waste.
    local SUB_COUNT=0 PASSIVE_COUNT=0
    if [ "$DEPTH_ONLY" = "1" ]; then
    echo "[*] [1/11] SKIPPED (DEPTH_ONLY=1) -- single-host depth mode: $TARGET"
    printf '%s\n' "$TARGET" | dnsx -silent > "$SUBS_DIR/resolved_${DATE}.txt" 2>/dev/null || printf '%s\n' "$TARGET" > "$SUBS_DIR/resolved_${DATE}.txt"
    if [ ! -s "$SUBS_DIR/resolved_${DATE}.txt" ]; then
        echo "[-] $TARGET did not resolve in DNS -- run aborted."
        printf "FAILED=dns_unresolved\n" >> "$STATE_FILE"
        return 1
    fi
    SUB_COUNT=1
    else
    echo "[*] [1/11] Running subdomain discovery..."
    # 1a -- passive sources
    subfinder -d "$TARGET" -silent -all -timeout 25 | dnsx -silent | anew "$SUBS_DIR/resolved_${DATE}.txt" > /dev/null
    assetfinder --subs-only "$TARGET" | dnsx -silent | anew "$SUBS_DIR/resolved_${DATE}.txt" > /dev/null
    # v13: github-subdomains — subdomains mentioned in public GitHub code (needs GITHUB_TOKEN)
    GHS_BIN="${GITHUB_SUBDOMAINS_BIN:-$(command -v github-subdomains 2>/dev/null)}"
    if [ -n "$GHS_BIN" ] && [ -x "$GHS_BIN" ] && [ -n "${GITHUB_TOKEN:-}" ]; then
        # v14.3 -- DO NOT USE `-o -`. github-subdomains does not treat it as stdout, it
        # actually creates a file NAMED `-` in the CWD. Afterwards in the chain:
        # dnsx (and other stdin-reading PD tools) read `./-` in the same directory
        # IN PREFERENCE to stdin, so every `... | dnsx` call in that CWD
        # returns ANOTHER target's old host list.
        # Proven: `printf api.example.com | dnsx -silent`
        #   in a clean dir             -> 1 line  (correct)
        #   in a dir with a 27-line `-` -> 20 lines (hosts of another target)
        #   in a dir with an 11-line `-` -> 10 lines (hosts of another target)
        # The count always tracked the size of the `-` file.
        _GHS_OUT=$(mktemp -t ghsubs.XXXXXX)
        timeout 300 "$GHS_BIN" -d "$TARGET" -t "$GITHUB_TOKEN" -o "$_GHS_OUT" 2>/dev/null
        [ -s "$_GHS_OUT" ] && dnsx -l "$_GHS_OUT" -silent | anew "$SUBS_DIR/resolved_${DATE}.txt" > /dev/null
        rm -f "$_GHS_OUT"
    fi
    # v13.1: crt.sh dumps ALL SANs of the matching certificate row -- on shared/multi-tenant
    #   certificates (CDN/WAF) this can also bring unrelated third-party domains. Rows not ending in the
    #   $TARGET suffix are dropped here (the real active-scan protection is the scope gate above, but
    #   cutting the pollution at the source keeps the data clean for subfinder/amass too).
    curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' \
        | grep -iE "(^|\.)$(printf '%s' "$TARGET" | sed 's/\./\\./g')\$" | dnsx -silent | anew "$SUBS_DIR/resolved_${DATE}.txt" > /dev/null
    # v13.2: resolve the LITERAL (non-wildcard) hosts in scope.txt directly -- passive/brute
    #   sources may not find them organically (subfinder/crt.sh/amass only find what is
    #   "known"; the exact host names in the program's own scope list are already KNOWN
    #   candidates and must not be skipped without asking DNS). A past run missed this and
    #   left 6+ live hosts (including a Storybook instance and a whole sibling domain
    #   family) completely invisible.
    if [ -n "$SCOPE_FILE" ]; then
        grep -vE '^\*\.|^#|^$' "$SCOPE_FILE" 2>/dev/null | dnsx -silent | anew "$SUBS_DIR/resolved_${DATE}.txt" > /dev/null
    fi
    PASSIVE_COUNT=$(wc -l < "$SUBS_DIR/resolved_${DATE}.txt" 2>/dev/null || echo 0)

    # 1b -- DNS permutation (dnsgen): mutates known-good subdomains and resolves them. Catches predictable
    #   hosts (dev-api, api-staging, admin2 ...) that are NOT in certificate/passive
    #   sources. Low noise because it only mutates existing subdomains. puredns filters wildcards.
    if [ "$DNS_PERMUTE" = "1" ] && command -v dnsgen &>/dev/null && [ "$PASSIVE_COUNT" -gt 0 ]; then
        local PERM_RAW="$SUBS_DIR/permute_candidates_${DATE}.txt"
        dnsgen "$SUBS_DIR/resolved_${DATE}.txt" 2>/dev/null | head -n "$DNS_PERMUTE_MAX" > "$PERM_RAW"
        if [ -s "$PERM_RAW" ]; then
            if command -v puredns &>/dev/null && [ -s "$RESOLVERS_FILE" ]; then
                puredns resolve "$PERM_RAW" --resolvers "$RESOLVERS_FILE" --rate-limit "$DNS_RATE" -q 2>/dev/null \
                    | anew "$SUBS_DIR/resolved_${DATE}.txt" > /dev/null
            else
                dnsx -l "$PERM_RAW" -silent ${RESOLVERS_FILE:+-r "$RESOLVERS_FILE"} \
                    | anew "$SUBS_DIR/resolved_${DATE}.txt" > /dev/null
            fi
        fi
    fi

    # 1c -- DNS wordlist bruteforce (puredns -> massdns): wordlist against the apex. HEAVY -- default OFF in
    #   multi-domain sweeps, ON in focused runs. Wildcard DNS is filtered by puredns.
    if [ "$DNS_BRUTE" = "1" ] && command -v puredns &>/dev/null && [ -s "$DNS_BRUTE_WORDLIST" ] && [ -s "$RESOLVERS_FILE" ]; then
        echo "    -> DNS bruteforce ($(wc -l < "$DNS_BRUTE_WORDLIST") words)..."
        puredns bruteforce "$DNS_BRUTE_WORDLIST" "$TARGET" --resolvers "$RESOLVERS_FILE" \
            --rate-limit "$DNS_RATE" -q 2>/dev/null | anew "$SUBS_DIR/resolved_${DATE}.txt" > /dev/null
    fi

    SUB_COUNT=$(wc -l < "$SUBS_DIR/resolved_${DATE}.txt" 2>/dev/null || echo 0)
    echo "[+] Subdomains: $SUB_COUNT (passive: $PASSIVE_COUNT, +permutation/brute: $((SUB_COUNT - PASSIVE_COUNT)))"
    fi   # end of DEPTH_ONLY block

    # -- v14 GATE A: TARGET OWNERSHIP ------------------------------------------
    # BEFORE entering naabu/httpx, check "does this host really belong to $TARGET".
    # Rejected hosts are not lost: they go to the foreign file + promote_queue
    # (in one real run the only live candidate of the week came out of exactly this bucket).
    if ! in_target_filter "$SUBS_DIR/resolved_${DATE}.txt" \
                          "$SUBS_DIR/resolved_intarget_${DATE}.txt" \
                          "$SUBS_DIR/resolved_foreign_${DATE}.txt" "$TARGET"; then
        printf "FAILED=in_target_filter\n" >> "$STATE_FILE"; return 1
    fi
    local FOREIGN_COUNT=$(wc -l < "$SUBS_DIR/resolved_foreign_${DATE}.txt" 2>/dev/null || echo 0)
    if [ "$FOREIGN_COUNT" -gt 0 ]; then
        # write foreign apexes to the queue as separate target candidates
        sed -E 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##; s#[/:].*##' "$SUBS_DIR/resolved_foreign_${DATE}.txt" \
            | awk -F. 'NF>=2 {print tolower($(NF-1) "." $NF)}' | sort -u \
            > "$SUBS_DIR/promote_queue_${DATE}.txt"
        echo "[!] $FOREIGN_COUNT hosts do NOT BELONG to $TARGET -> $SUBS_DIR/resolved_foreign_${DATE}.txt"
        echo "    ($(wc -l < "$SUBS_DIR/promote_queue_${DATE}.txt" | tr -d ' ') distinct apexes -> promote_queue_${DATE}.txt)"
    fi
    cp "$SUBS_DIR/resolved_intarget_${DATE}.txt" "$SUBS_DIR/resolved_${DATE}.txt"
    SUB_COUNT=$(wc -l < "$SUBS_DIR/resolved_${DATE}.txt" 2>/dev/null || echo 0)
    echo "[+] Subdomains owned by the target: $SUB_COUNT (foreign dropped: $FOREIGN_COUNT)"

    # v13.1: scope gate BEFORE naabu/httpx (ACTIVE scanning) starts. Reason: passive sources like crt.sh
    #   can leak COMPLETELY unrelated third-party domains via shared/multi-SAN certificates (in a past run
    #   a whole unrelated domain family leaked; the old code ran scope-diff AFTER naabu+httpx, so active
    #   requests had already gone to those hosts).
    #   Now active scanning goes ONLY to hosts in scope.txt; DNS-only leaks are
    #   logged to resolved_preemptive_oos_${DATE}.txt and never enter naabu/httpx.
    local ACTIVE_SCAN_LIST="$SUBS_DIR/resolved_${DATE}.txt"
    if [ -n "$SCOPE_FILE" ]; then
        filter_scope "$SUBS_DIR/resolved_${DATE}.txt" "$SUBS_DIR/resolved_inscope_${DATE}.txt" "$SUBS_DIR/resolved_preemptive_oos_${DATE}.txt"
        ACTIVE_SCAN_LIST="$SUBS_DIR/resolved_inscope_${DATE}.txt"
        local PRE_OOS_COUNT=$(wc -l < "$SUBS_DIR/resolved_preemptive_oos_${DATE}.txt" 2>/dev/null || echo 0)
        [ "$PRE_OOS_COUNT" -gt 0 ] && echo "[!] $PRE_OOS_COUNT hosts are outside scope.txt (probably shared-certificate/passive-source leakage) -> did NOT enter naabu/httpx: $SUBS_DIR/resolved_preemptive_oos_${DATE}.txt"
    fi

    # Module 2: Triage, Scope-Diff & Golden Targets
    echo "[*] [2/11] Port scan, scope-diff and Golden Target filtering..."
    # Excluding 25/tcp (SMTP) -- it came with top-ports 100 and has no real recon value
    # (mail server behaviour is not tested, only a TCP connect to see if the port is open/closed)
    # but when accumulated against thousands of hosts it triggers the ISP's automatic "spam-bot" detection
    # (a hosting provider sent an abuse warning after such a run).
    naabu -l "$ACTIVE_SCAN_LIST" -top-ports 100 -exclude-ports 25 -silent -rate "$NAABU_RATE" -c "$NAABU_CONCURRENCY" -o "$TRIAGE_DIR/naabu_${DATE}.txt" > /dev/null
    cat "$TRIAGE_DIR/naabu_${DATE}.txt" | httpx -silent -title -tech-detect -status-code -cdn -cname -rl "$RATE_LIMIT" "${HEADER_ARGS[@]}" -json -o "$TRIAGE_DIR/httpx_${DATE}.json" > /dev/null

    cat "$TRIAGE_DIR/httpx_${DATE}.json" | jq -r '.url' | sort -u > "$TRIAGE_DIR/alive_raw_${DATE}.txt"
    filter_scope "$TRIAGE_DIR/alive_raw_${DATE}.txt" "$TRIAGE_DIR/alive_${DATE}.txt" "$TRIAGE_DIR/out_of_scope_${DATE}.txt"

    # -- v14: PRIORITIZATION -- RANKING, not elimination ---------------------
    # Old behaviour: golden = GOLDEN_REGEX keyword grep. Its real hit rate was
    # measured in past runs: 0% on some targets, 25% on another. So not
    # a filter but a coin toss. It picked 17 of 80 live hosts, but the wrong 17.
    #
    # New behaviour: ALL live hosts are scored with signal codes and RANKED.
    # Nothing is eliminated -- a human reads top to bottom and makes the selection.
    # golden_${DATE}.txt is now the first GOLDEN_MAX lines of this ranked list
    # (format unchanged, the 9 downstream call sites keep working as they are).
    python3 - "$TRIAGE_DIR/httpx_${DATE}.json" "$TRIAGE_DIR/alive_${DATE}.txt" \
             "$TRIAGE_DIR/priority_${DATE}.tsv" "$GOLDEN_REGEX" "$BORING_RE" <<'PYPRIO' 2>/dev/null || true
import json, re, sys, collections
httpx_json, alive_file, out_tsv, golden_rx, boring_rx = sys.argv[1:6]

# v14: one row per HOST (not URL). A human asks "which host should I scan deeply";
# showing the :80/:443/:8080 rows of the same host 3 times is noise.
alive = [l.strip() for l in open(alive_file) if l.strip()]
meta = {}
try:
    for line in open(httpx_json):
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if d.get('url'):
            meta[d['url']] = d
except OSError:
    pass

grx = re.compile(golden_rx, re.I)
trx = re.compile(r'login|sign[ -]?in|admin|portal|dashboard|swagger|graphql|jenkins|'
                 r'grafana|kibana|gitlab|jira|confluence|storybook|phpmyadmin|console|'
                 r'webmail|roundcube|sonarqube|airflow|kubernetes|rancher', re.I)
# 403 + these titles = WAF/bot block, NOT real auth. If not distinguished,
# "Attention Required! | Cloudflare" pages float to the top of the list.
# Edge/WAF error pages. CloudFront's "ERROR: The request could not be satisfied"
# page gave 7 hosts a fake AUTH signal on the first live run and pushed them to the top of the
# list -- Cloudflare patterns existed, CloudFront's did not.
wafx = re.compile(r'attention required|just a moment|blocked by our firewall|'
                  r'access denied|waf block|hello there, human|cloudflare|'
                  r'request could not be satisfied|generated by cloudfront|'
                  r'akamai|access to this page has been denied|incapsula|'
                  r'request blocked|error 10\d\d|bot detect', re.I)
# Edge/CDN/protocol labels -- they do not mean "there is an application here".
boring_extra = re.compile(boring_rx + r'|^(http/[0-9.]+|hsts|.*bot management|'
                          r'.*browser insights|.*radar|amazon.*|google.*|'
                          r'sucuri|imperva|incapsula|f5 big-?ip|open-?resty|'
                          r'ipv6|dns|acme|lets? ?encrypt)$', re.I)

hosts = collections.OrderedDict()
for url in alive:
    d = meta.get(url, {})
    hostport = re.sub(r'^[a-z]+://', '', url, flags=re.I).split('/')[0]
    host = hostport.split(':')[0]
    port = hostport.split(':')[1] if ':' in hostport else ('443' if url.lower().startswith('https') else '80')
    h = hosts.setdefault(host, {'ports': set(), 'status': set(), 'titles': [], 'tech': []})
    h['ports'].add(port)
    st = d.get('status_code') or d.get('status-code')
    if st:
        h['status'].add(str(st))
    t = (d.get('title') or '').strip()
    if t and t not in h['titles']:
        h['titles'].append(t)
    tech = d.get('tech') or d.get('technologies') or []
    if isinstance(tech, str):
        tech = [tech]
    for x in tech:
        if x not in h['tech']:
            h['tech'].append(x)

rows = []
for host, h in hosts.items():
    # CAUTION: matching is on the FULL title, truncation is for display ONLY.
    # (The first version cut to 60 chars and then searched; when "Attention Required" fell
    #  outside the 60 the WAF signal was missed and a bot block was mistaken for AUTH.)
    title_full = ' / '.join(h['titles']).replace('\t', ' ')
    title = title_full[:60]
    techs = ', '.join(h['tech'])[:50]
    real_tech = [t for t in h['tech'] if not boring_extra.match(t.strip())]
    odd = sorted(p for p in h['ports'] if p not in ('80', '443'))
    waf = bool(title_full and wafx.search(title_full))

    sig = []
    if '401' in h['status']:                    sig.append('AUTH')
    elif '403' in h['status'] and not waf:      sig.append('AUTH')
    if waf:                                     sig.append('WAF')
    if title_full and trx.search(title_full):   sig.append('TITLE')
    if real_tech:                               sig.append('APPTECH')
    if odd:                                     sig.append('ODDPORT')
    if grx.search(host):                        sig.append('KEYWORD')
    if '200' in h['status']:                    sig.append('200')

    score = (4 if 'AUTH'    in sig else 0) + \
            (4 if 'TITLE'   in sig else 0) + \
            (2 if 'APPTECH' in sig else 0) + \
            (1 if 'ODDPORT' in sig else 0) + \
            (1 if 'KEYWORD' in sig else 0) + \
            (1 if '200'     in sig else 0)
    # WAF NO LONGER lowers the score. It already blocks the AUTH signal (403 -> not counted as
    # fake auth); also subtracting from the total would punish the same thing twice and
    # pushed a real staging API (with a KEYWORD hit) to the bottom of a past run.
    # WAF is now just a displayed label.

    scheme = 'https' if '443' in h['ports'] else 'http'
    rows.append((score, host, scheme, '+'.join(sig) or '-',
                 ','.join(sorted(h['status'])), ','.join(sorted(h['ports'])), title, techs))

rows.sort(key=lambda r: (-r[0], r[1]))
with open(out_tsv, 'w') as f:
    f.write('#\tscore\tsignal\thost\tstatus\tport\ttitle\ttech\n')
    for i, (score, host, scheme, sig, st, ports, title, techs) in enumerate(rows, 1):
        f.write(f'{i}\t{score}\t{sig}\t{host}\t{st}\t{ports}\t{title}\t{techs}\n')

# golden_*.txt is still in URL format (9 downstream consumers) -- generate from the ranked hosts
with open(out_tsv + '.urls', 'w') as f:
    for score, host, scheme, *_ in rows:
        f.write(f'{scheme}://{host}\n')
PYPRIO

    if [ -s "$TRIAGE_DIR/priority_${DATE}.tsv.urls" ]; then
        head -n "$GOLDEN_MAX" "$TRIAGE_DIR/priority_${DATE}.tsv.urls" > "$TRIAGE_DIR/golden_${DATE}.txt"
        tail -n "+$((GOLDEN_MAX + 1))" "$TRIAGE_DIR/priority_${DATE}.tsv.urls" \
            > "$TRIAGE_DIR/golden_overflow_${DATE}.txt"
        rm -f "$TRIAGE_DIR/priority_${DATE}.tsv.urls"
    else
        # if python failed, fall back to the old behaviour -- never leave a silently empty list
        echo "[!] Prioritization could not be produced, falling back to GOLDEN_REGEX."
        grep -iE "$GOLDEN_REGEX" "$TRIAGE_DIR/alive_${DATE}.txt" | sort -u > "$TRIAGE_DIR/golden_${DATE}.txt"
    fi

    local ALIVE_COUNT=$(wc -l < "$TRIAGE_DIR/alive_${DATE}.txt" 2>/dev/null || echo 0)
    local OOS_COUNT=$(wc -l < "$TRIAGE_DIR/out_of_scope_${DATE}.txt" 2>/dev/null || echo 0)
    local GOLDEN_COUNT=$(wc -l < "$TRIAGE_DIR/golden_${DATE}.txt" 2>/dev/null || echo 0)
    echo "[+] Live services (in-scope): $ALIVE_COUNT | Out of scope (dropped): $OOS_COUNT | Golden targets: $GOLDEN_COUNT"

    # Module 3: Active Content Discovery (feroxbuster) -- ONLY golden hosts, with time + host ceilings.
    #   Finds live-but-unlinked directories/endpoints that passive gau/wayback/katana miss.
    #   Its output feeds the endpoint pool of Module 4. To keep it from bloating:
    #     - only golden_${DATE}.txt (max FEROX_MAX_HOSTS hosts)
    #     - lean ~4k-word list (content_lean.txt), depth 2
    #     - --time-limit global ceiling, --scan-limit 3 concurrent, rate-limited
    local CONTENT_FILE="$ENDPOINTS_DIR/content_discovery_${DATE}.txt"
    : > "$CONTENT_FILE"
    if [ "$CONTENT_DISCOVERY" = "1" ] && command -v feroxbuster &>/dev/null && [ -s "$TRIAGE_DIR/golden_${DATE}.txt" ]; then
        if [ ! -s "$CONTENT_WORDLIST" ]; then
            echo "[!] Content discovery wordlist missing ($CONTENT_WORDLIST) -- skipping Module 3."
        else
            echo "[*] [3/11] Active content discovery (feroxbuster, golden hosts)..."
            local FEROX_HOSTS="$TRIAGE_DIR/ferox_hosts_${DATE}.txt"
            local FEROX_CAND="$TRIAGE_DIR/ferox_candidates_${DATE}.txt"
            local FEROX_SKIP="$TRIAGE_DIR/ferox_skipped_baseline_${DATE}.tsv"
            head -n "$FEROX_MAX_HOSTS" "$TRIAGE_DIR/golden_${DATE}.txt" > "$FEROX_CAND"

            # -- v14.5 BASELINE CALIBRATION ------------------------------------------
            # Some hosts return the same code for EVERY non-existent path (Cloudflare
            # blanket 403, "error code: 1014", strict WAF). On such a host EVERY word in ferox's
            # wordlist comes back as "found".
            # Such hosts can yield dozens of fake "findings" -- every path, including a
            # random nonexistent one and /, returns 403.
            # This produces a confidently WRONG result without raising any error;
            # it was not noticed until a human sent a real request.
            #
            # Method: probe 2 random non-existent paths per host.
            #   if both probes return the SAME code and it is not 404 -> no discriminating
            #   power, content discovery is meaningless on that host, SKIP it and record why.
            : > "$FEROX_HOSTS"; : > "$FEROX_SKIP"
printf 'host\tbaseline_code\treason\n' >> "$FEROX_SKIP"
            local _bl_curl=(-s -o /dev/null -m 8 -k)
            [ -n "$RESEARCH_HEADER" ] && _bl_curl+=(-H "$RESEARCH_HEADER")
            [ -n "$RESEARCH_USER_AGENT" ] && _bl_curl+=(-A "$RESEARCH_USER_AGENT")
            local _bl_skipped=0 _bl_kept=0
            while read -r _bh; do
                [ -z "$_bh" ] && continue
                local _r1 _r2
                _r1=$(curl "${_bl_curl[@]}" -w '%{http_code}' \
                      "${_bh%/}/zzq-baseline-$RANDOM-$RANDOM" 2>/dev/null || echo 000)
                _r2=$(curl "${_bl_curl[@]}" -w '%{http_code}' \
                      "${_bh%/}/xnf-baseline-$RANDOM/$RANDOM" 2>/dev/null || echo 000)
                if [ "$_r1" = "$_r2" ] && [ "$_r1" != "404" ] && [ "$_r1" != "000" ]; then
                    printf '%s\t%s\tnonexistent paths also return %s - no discriminating power\n' \
                        "$_bh" "$_r1" "$_r1" >> "$FEROX_SKIP"
                    _bl_skipped=$((_bl_skipped+1))
                else
                    printf '%s\n' "$_bh" >> "$FEROX_HOSTS"
                    _bl_kept=$((_bl_kept+1))
                fi
            done < "$FEROX_CAND"
            echo "    -> baseline: $_bl_kept hosts will be scanned, $_bl_skipped skipped (same code for every path)"
            [ "$_bl_skipped" -gt 0 ] && echo "       skipped: $FEROX_SKIP"
            if [ ! -s "$FEROX_HOSTS" ]; then
                echo "[!] No host passed the baseline test -- content discovery SKIPPED."
                echo "    This is NOT 'no findings': the hosts return the same code for non-existent paths too,"
                echo "    so there is no signal ferox could discriminate on. See $FEROX_SKIP."
                : > "$CONTENT_FILE"
            fi
            if [ -s "$FEROX_HOSTS" ]; then
            local FEROX_JSON="$ENDPOINTS_DIR/ferox_${DATE}.json"
            local FEROX_HEADERS=()
            [ -n "$RESEARCH_HEADER" ] && FEROX_HEADERS+=(-H "$RESEARCH_HEADER")
            [ -n "$RESEARCH_USER_AGENT" ] && FEROX_HEADERS+=(-a "$RESEARCH_USER_AGENT")
            feroxbuster --stdin --silent -k \
                -w "$CONTENT_WORDLIST" \
                --depth 2 --scan-limit 3 --rate-limit "$RATE_LIMIT" \
                --time-limit "$FEROX_TIME_LIMIT" \
                --filter-status 404 500 502 503 --auto-tune \
                --no-state --json --output "$FEROX_JSON" \
                "${FEROX_HEADERS[@]}" < "$FEROX_HOSTS" > /dev/null 2>&1 || true
            # ferox JSON is one object per line; take the url of type=response entries
            if [ -s "$FEROX_JSON" ]; then
                jq -r 'select(.type=="response") | "\(.status) \(.url)"' "$FEROX_JSON" 2>/dev/null \
                    | LC_ALL=C sort -u > "$CONTENT_FILE.raw"
                # -- v14.5b: verify 401/403 results from the BODY ----------------------
                # The baseline probe catches blanket blocks, but some WAFs match EXACT FILE
                # NAMES: /.bak /.svn /.htaccess /error_log -> 403, but
                # /.bak-zzq123 -> 404. So a synthetic probe can NEVER trigger this
                # (7 different probe shapes were tried in a past run, all returned 404).
                # The only reliable discriminator: is the response BODY an edge page or the origin.
                # On one host the 403 of /.svn was a Cloudflare page (_cf_translation),
                # i.e. no such file, the WAF blocks -> 5 fake "findings".
                : > "$CONTENT_FILE"
                local _wafchecked=0 _wafdropped=0
                while read -r _line; do
                    local _code="${_line%% *}" _url="${_line#* }"
                    case "$_code" in
                        401|403)
                            if [ "$_wafchecked" -lt 50 ]; then
                                _wafchecked=$((_wafchecked+1))
                                if curl -s -m 8 -k "${_bl_curl[@]:3}" "$_url" 2>/dev/null \
                                   | grep -qiE '_cf_translation|cf-error|error code: 10[0-9][0-9]|attention required|request could not be satisfied|generated by cloudfront|access to this page has been denied|incapsula'; then
                                    _wafdropped=$((_wafdropped+1)); continue
                                fi
                            fi
                            ;;
                    esac
                    printf '%s\n' "$_line" >> "$CONTENT_FILE"
                done < "$CONTENT_FILE.raw"
                [ "$_wafdropped" -gt 0 ] && echo "    -> body verification: $_wafdropped/$_wafchecked results were WAF pages, dropped"
                rm -f "$CONTENT_FILE.raw"
            fi
            fi   # end of the "FEROX_HOSTS not empty" block
            local CONTENT_COUNT=$(wc -l < "$CONTENT_FILE" 2>/dev/null || echo 0)
            echo "[+] Content discovery: $CONTENT_COUNT paths (2xx/3xx/401/403)"
        fi
    else
        [ "$CONTENT_DISCOVERY" = "1" ] && echo "[i] Module 3 (content discovery) skipped -- no feroxbuster or no golden hosts."
    fi
    local CONTENT_COUNT=$(wc -l < "$CONTENT_FILE" 2>/dev/null || echo 0)

    # Module 4: Endpoints & JS Mining (only over in-scope targets)
    echo "[*] [4/11] Collecting endpoint and JS archive..."
    cat "$TRIAGE_DIR/alive_${DATE}.txt" | gau --threads 5 > "$ENDPOINTS_DIR/gau_${DATE}.txt" 2>/dev/null
    waybackurls "$TARGET" | anew "$ENDPOINTS_DIR/wayback_${DATE}.txt" > /dev/null 2>&1
    katana -list "$TRIAGE_DIR/golden_${DATE}.txt" -d 3 -jc -silent "${HEADER_ARGS[@]}" ${KATANA_SCOPE_REGEX:+-cs "$KATANA_SCOPE_REGEX"} -rl "$RATE_LIMIT" -o "$ENDPOINTS_DIR/katana_${DATE}.txt" > /dev/null

    # 4b -- Authenticated crawl: when AUTH_HEADER (env) is given, crawl golden hosts WITH A SESSION.
    #   The post-login surface (account pages, /api/me, admin, mass-assignment endpoints)
    #   is INVISIBLE to passive sources and the anonymous crawl -- this is the real BOLA/IDOR surface.
    #   Results go both into the clean_urls pool and, separately, into authenticated_urls_${DATE}.txt.
    local AUTH_URLS="$ENDPOINTS_DIR/authenticated_urls_${DATE}.txt"
    : > "$AUTH_URLS"
    local AUTH_URL_COUNT=0
    if [ -n "$AUTH_HEADER" ]; then
        local AUTH_SEED="$TRIAGE_DIR/golden_${DATE}.txt"
        [ -n "$AUTH_CRAWL_SEEDS" ] && [ -s "$AUTH_CRAWL_SEEDS" ] && AUTH_SEED="$AUTH_CRAWL_SEEDS"
        [ -s "$AUTH_SEED" ] || AUTH_SEED="$TRIAGE_DIR/alive_${DATE}.txt"
        if [ -s "$AUTH_SEED" ]; then
            local AUTH_PROBE=$(head -1 "$AUTH_SEED")
            local AUTH_CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH_HEADER" "${HEADER_ARGS[@]}" "$AUTH_PROBE" 2>/dev/null)
            echo "    -> authenticated crawl: seed=$(wc -l < "$AUTH_SEED") hosts | session probe $AUTH_PROBE -> HTTP $AUTH_CODE"
            { [ "$AUTH_CODE" = "401" ] || [ "$AUTH_CODE" = "403" ]; } && echo "    [!] WARNING: AUTH_HEADER returned 401/403 -- the session may have expired, trying anyway."
            # exclude links that would kill the session / change state from the crawl (katana sends GET,
            #   a GET like /logout ends the session; -aff is kept OFF so it does not submit forms)
            # Links that would kill the session / destroy the account are excluded from the crawl. These are
            #   operational: GET /logout ends the session mid-run, /delete causes
            #   irreversible data loss. Neither has any hunting value.
            # FINANCIAL PATHS ARE DELIBERATELY NOT EXCLUDED (v14.8 reverted):
            #   /cashier, /withdraw, /transfer are the most valuable IDOR/BOLA
            #   surface on a fintech target. Leaving them out of the crawl means not seeing sub-endpoints, the APIs they call
            #   and the parameters. Also, if money movement is triggered by GET,
            #   that is not an accident to avoid but a finding to report. katana sends GET and -aff
            #   is off (no form submission); starting a real transaction is the job of manual testing and
            #   the operator's decision.
            local AUTH_COS='logout|log-out|signout|sign-out|/delete|/destroy|/remove|/revoke|/deactivate|/close-account|/unsubscribe'
            local KATANA_AUTH_ARGS=(-list "$AUTH_SEED" -d 3 -jc -silent -rl "$RATE_LIMIT" -H "$AUTH_HEADER" -cos "$AUTH_COS")
            [ -n "$RESEARCH_HEADER" ] && KATANA_AUTH_ARGS+=(-H "$RESEARCH_HEADER")
            [ -n "$RESEARCH_USER_AGENT" ] && KATANA_AUTH_ARGS+=(-H "User-Agent: $RESEARCH_USER_AGENT")
            if [ "$AUTH_CRAWL_HEADLESS" = "1" ]; then
                if command -v google-chrome &>/dev/null || command -v chromium &>/dev/null || command -v chromium-browser &>/dev/null; then
                    KATANA_AUTH_ARGS+=(-hl -no-sandbox)
                else
                    echo "    [!] AUTH_CRAWL_HEADLESS=1 but chrome is missing -- continuing without headless."
                fi
            fi
            timeout 900 katana "${KATANA_AUTH_ARGS[@]}" -o "$AUTH_URLS.raw" > /dev/null 2>&1 || true
            # katana -fs rdn stays within the same registrable domain, but filter against the scope file anyway
            filter_scope "$AUTH_URLS.raw" "$AUTH_URLS" "$ENDPOINTS_DIR/authenticated_urls_out_of_scope_${DATE}.txt"
            rm -f "$AUTH_URLS.raw"
            AUTH_URL_COUNT=$(wc -l < "$AUTH_URLS" 2>/dev/null || echo 0)
            # also append to the anonymous katana output so uro/gf/js see everything (this later passes filter_scope too)
            cat "$AUTH_URLS" >> "$ENDPOINTS_DIR/katana_${DATE}.txt"
            echo "    -> authenticated crawl: $AUTH_URL_COUNT URLs (in-scope)"
        fi
    fi

    # add the live paths ferox found (dropping the status column) to the endpoint pool
    awk '{print $2}' "$CONTENT_FILE" 2>/dev/null > "$ENDPOINTS_DIR/content_urls_${DATE}.txt"
    cat "$ENDPOINTS_DIR/gau_${DATE}.txt" "$ENDPOINTS_DIR/wayback_${DATE}.txt" "$ENDPOINTS_DIR/katana_${DATE}.txt" "$ENDPOINTS_DIR/content_urls_${DATE}.txt" 2>/dev/null | sort -u | uro > "$ENDPOINTS_DIR/clean_urls_raw_${DATE}.txt"
    # -- v14 GATE B: target ownership in the endpoint pool too ----------------
    # gau/wayback/katana also return external links. In the old flow these went through
    # filter_scope, but when no scope.txt is given filter_scope does a plain
    # `cp` (unfiltered) -- in a past run 6890 lines of an unrelated company's JS
    # entered the endpoints/ folder this way, 0 of them hosted on the target.
    # Order: target ownership first, then scope. Both must pass.
    in_target_filter "$ENDPOINTS_DIR/clean_urls_raw_${DATE}.txt" \
                     "$ENDPOINTS_DIR/clean_urls_intarget_${DATE}.txt" \
                     "$ENDPOINTS_DIR/clean_urls_foreign_${DATE}.txt" "$TARGET" || true
    local _EP_FOREIGN=$(wc -l < "$ENDPOINTS_DIR/clean_urls_foreign_${DATE}.txt" 2>/dev/null || echo 0)
    [ "$_EP_FOREIGN" -gt 0 ] && echo "[!] $_EP_FOREIGN endpoints are hosted outside $TARGET -> clean_urls_foreign_${DATE}.txt"
    filter_scope "$ENDPOINTS_DIR/clean_urls_intarget_${DATE}.txt" "$ENDPOINTS_DIR/clean_urls_${DATE}.txt" "$ENDPOINTS_DIR/clean_urls_out_of_scope_${DATE}.txt"
    cat "$ENDPOINTS_DIR/clean_urls_${DATE}.txt" | grep -iE "\.js(\?.*)?$" | sort -u > "$ENDPOINTS_DIR/js_files_${DATE}.txt"

    local CLEAN_COUNT=$(wc -l < "$ENDPOINTS_DIR/clean_urls_${DATE}.txt" 2>/dev/null || echo 0)
    local JS_COUNT=$(wc -l < "$ENDPOINTS_DIR/js_files_${DATE}.txt" 2>/dev/null || echo 0)
    echo "[+] Clean endpoints: $CLEAN_COUNT | JS files: $JS_COUNT"

    # Module 5: Parameter Mining (arjun) -- over a capped number of dynamic endpoints
    #   finds hidden/undocumented GET parameters. To keep it from bloating:
    #     - only endpoints containing /api/, or extensionless, or already parameterized
    #     - ARJUN_MAX_URLS ceiling (default 25), 15 min timeout, rate-limited
    local PARAMS_FILE="$ANALYSIS_DIR/mined_params_${DATE}.txt"
    : > "$PARAMS_FILE"
    local PARAM_COUNT=0
    if [ "$PARAM_MINING" = "1" ] && command -v arjun &>/dev/null && [ -s "$ENDPOINTS_DIR/clean_urls_${DATE}.txt" ]; then
        echo "[*] [5/11] Parameter mining (arjun)..."
        local ARJUN_IN="$ENDPOINTS_DIR/arjun_targets_${DATE}.txt"
        # pick the dynamic-looking ones, drop the query string, dedup, cut to the ceiling
        grep -iE '/api/|/v[0-9]+/|/graphql|\?' "$ENDPOINTS_DIR/clean_urls_${DATE}.txt" \
            | sed 's/?.*//' | grep -ivE '\.(js|css|png|jpe?g|gif|svg|woff2?|ttf|ico|map)$' \
            | LC_ALL=C sort -u | head -n "$ARJUN_MAX_URLS" > "$ARJUN_IN"
        if [ -s "$ARJUN_IN" ]; then
            local ARJUN_HDR=()
            [ -n "$RESEARCH_HEADER" ] && ARJUN_HDR+=(--headers "$RESEARCH_HEADER")
            timeout 900 arjun -i "$ARJUN_IN" -oT "$PARAMS_FILE" \
                -t 10 -T 10 --rate-limit "$RATE_LIMIT" --stable -q "${ARJUN_HDR[@]}" > /dev/null 2>&1 || true
            PARAM_COUNT=$(grep -cve '^[[:space:]]*$' "$PARAMS_FILE" 2>/dev/null); PARAM_COUNT=${PARAM_COUNT:-0}
        fi
        echo "[+] Mined parameter lines: $PARAM_COUNT"
    else
        [ "$PARAM_MINING" = "1" ] && echo "[i] Module 5 (parameter mining) skipped -- no arjun or no endpoints."
    fi

    # Module 6: GF Parameter Routing
    echo "[*] [6/11] Splitting parameters with GF patterns..."
    PATTERNS=("xss" "sqli" "ssrf" "idor" "lfi" "redirect" "ssti" "rce")
    for p in "${PATTERNS[@]}"; do
        gf $p "$ENDPOINTS_DIR/clean_urls_${DATE}.txt" > "$ANALYSIS_DIR/${p}_${DATE}.txt" 2>/dev/null
        if [ ! -s "$ANALYSIS_DIR/${p}_${DATE}.txt" ]; then
            rm -f "$ANALYSIS_DIR/${p}_${DATE}.txt"
        else
            COUNT=$(wc -l < "$ANALYSIS_DIR/${p}_${DATE}.txt")
            echo "    -> $p : $COUNT parameters found."
        fi
    done

    # Module 7: Nuclei -- targeted (by detected technology) + generic vulnerability scan
    #   (dos/fuzz/intrusive templates excluded, rate-limited)
    echo "[*] [7/11] Running Nuclei scan..."

    # 5.0 -- Cluster the scan list: from hosts with the same (status + body length + title) signature
    #       only ONE representative is scanned. On CDN-heavy domains
    #       hundreds of hosts behind the same Fastly/Varnish return the identical response -- scanning each
    #       one separately is pure waste. The full list is kept in alive_${DATE}.txt; nuclei runs
    #       on this reduced list.
    local SCAN_LIST="$TRIAGE_DIR/alive_scan_${DATE}.txt"
    jq -r 'select(.url) | "\(.status_code // 0)|\(.content_length // 0)|\(.title // "")\t\(.url)"' \
        "$TRIAGE_DIR/httpx_${DATE}.json" 2>/dev/null \
        | LC_ALL=C sort -u -t "$(printf '\t')" -k1,1 | cut -f2 \
        | grep -Fxf "$TRIAGE_DIR/alive_${DATE}.txt" > "$SCAN_LIST" 2>/dev/null
    [ -s "$SCAN_LIST" ] || cp "$TRIAGE_DIR/alive_${DATE}.txt" "$SCAN_LIST"
    local SCAN_COUNT=$(wc -l < "$SCAN_LIST" 2>/dev/null || echo 0)
    echo "    -> scan list: $ALIVE_COUNT live hosts -> $SCAN_COUNT representatives (after clustering)"

    # 5.1 -- Technology fingerprints come from httpx -tech-detect (Module 2); the separate nuclei
    #       'http/technologies/' pass was REMOVED. Reason: it was all info severity,
    #       overlapped with what httpx gives, and because it threw ~600 templates at all live hosts it was
    #       BY FAR the most expensive step of the run. Its value was being input to the targeted scan --
    #       httpx now provides that input for free.
    local TECH_FILE="$ANALYSIS_DIR/nuclei_tech_${DATE}.txt"
    jq -r '(.tech // .technologies // [])[]?' "$TRIAGE_DIR/httpx_${DATE}.json" 2>/dev/null \
        | sed 's/:.*//' | LC_ALL=C tr 'A-Z' 'a-z' | tr -d ' ' \
        | LC_ALL=C sort -u > "$TECH_FILE"
    local NUCLEI_TECH=$(wc -l < "$TECH_FILE" 2>/dev/null || echo 0)
    local TECH_TAGS=$(paste -sd, "$TECH_FILE" 2>/dev/null)
    echo "    -> detected technologies: $NUCLEI_TECH  (${TECH_TAGS:-none})"

    # 5.1b -- Suspicious-target filter (DEFAULT ON, all programs; pass
    #   NUCLEI_SUSPICIOUS_ONLY=0 to turn off). Golden hosts always enter; among the remaining
    #   representatives, those whose tech signature is ONLY CDN/LB/edge-infra (no real
    #   application signal -- cloudfront/elb/envoy/hsts/cloudflare/akamai/fastly/varnish etc.) are dropped from 5.2
    #   (tech-targeted) and 5.3a (generic-light). Throwing thousands of templates at hundreds of empty edge
    #   nodes inflated runs by hours (in one run 5.3a alone took ~5.7 hours).
    #   Hosts with no/empty tech data are included to be safe. Nuclei itself was not removed --
    #   only the target set was narrowed (.git/.env/takeover/panel/CVE detection is
    #   valuable, scanning empty CDN nodes is not).
    local SCAN_LIST_T="$SCAN_LIST"
    if [ "${NUCLEI_SUSPICIOUS_ONLY:-1}" = "1" ]; then
        # v14: BORING_RE is now global (next to GOLDEN_REGEX) -- module 2's
        # prioritization uses the same list, it is not redefined here.
        local SUS_LIST="$TRIAGE_DIR/alive_scan_suspicious_${DATE}.txt"
        : > "$SUS_LIST"
        while IFS= read -r _u; do
            [ -z "$_u" ] && continue
            if grep -qFx "$_u" "$TRIAGE_DIR/golden_${DATE}.txt" 2>/dev/null; then
                echo "$_u" >> "$SUS_LIST"; continue
            fi
            local _tags=$(jq -r --arg u "$_u" 'select(.url==$u) | (.tech // .technologies // [])[]?' \
                "$TRIAGE_DIR/httpx_${DATE}.json" 2>/dev/null | sed 's/:.*//' | LC_ALL=C tr 'A-Z' 'a-z' | tr -d ' ')
            if [ -z "$_tags" ] || echo "$_tags" | grep -vqE "$BORING_RE"; then
                echo "$_u" >> "$SUS_LIST"
            fi
        done < "$SCAN_LIST"
        local SUS_COUNT=$(wc -l < "$SUS_LIST" 2>/dev/null || echo 0)
        echo "    -> suspicious-target filter ON: $SUS_COUNT of $SCAN_COUNT representatives enter 5.2/5.3a"
        [ -s "$SUS_LIST" ] && SCAN_LIST_T="$SUS_LIST"
    fi

    # Common nuclei parameters -- -retries 1 -timeout 8 so a slow/dead host cannot drag a scan on
    # for hours; noisy classes are excluded with -etags.
    local NUCLEI_COMMON=(-silent -rl "$RATE_LIMIT" -bs "$NUCLEI_BS" -retries 1 -timeout 8 -etags dos,fuzz,intrusive "${HEADER_ARGS[@]}")

    # 5.2 -- Templates matching the detected technology (including tech-specific CVEs) -- all representatives
    #   (or only the golden+suspicious subset if NUCLEI_SUSPICIOUS_ONLY=1)
    if [ -n "$TECH_TAGS" ]; then
        nuclei -l "$SCAN_LIST_T" -tags "$TECH_TAGS" -severity medium,high,critical \
            "${NUCLEI_COMMON[@]}" -o "$ANALYSIS_DIR/nuclei_targeted_${DATE}.txt" 2>/dev/null
    fi

    # 5.3 -- Technology-INDEPENDENT generic set, three layers:
    #   (a) LIGHT, on every representative: exposures/ssl/dns -- mostly single-request,
    #       things like .git/.env/backup that yield the most bounty findings.
    #   (b) TAKEOVER, on the full UNCLUSTERED alive list -- subdomain takeover is
    #       host-specific (dangling CNAME); one of two hosts with the same 404 body
    #       may be takeover-able; clustering would hide that. 73 templates, mostly DNS/fingerprint,
    #       cheap.
    #   (c) HEAVY path-brute (exposed-panels/misconfiguration/default-logins/generic-vuln) --
    #       only on golden representatives; throwing these at hundreds of hosts inflated the run
    #       by hours, and their value is mostly on the admin/dev/portal surface.
    #   A blanket http/cves/ (4200+) is DELIBERATELY absent -- the relevant CVEs already come in 5.2
    #   via the tech tags.
    nuclei -l "$SCAN_LIST_T" -t http/exposures/,http/misconfiguration/ \
        -severity medium,high,critical \
        "${NUCLEI_COMMON[@]}" -o "$ANALYSIS_DIR/nuclei_generic_${DATE}.txt" 2>/dev/null

    # v14.2 -- the takeover list is deduplicated per HOST.
    #   alive_*.txt holds one URL per line, so the same host is listed 4 times for
    #   443/80/8080/8443. Takeover is a DNS property (dangling CNAME) -- bound to the host, not
    #   the port -- so one probe per host is enough. The "clustering would hide it" warning in note (b) above
    #   was about CONTENT clustering (same 404 body), not about
    #   port repetition; per-host dedup does not break that protection.
    #   Measurement (past run): 80 URLs / 26 hosts, this step alone took 15 minutes
    #   -- the target was a WebSocket backend so most requests burned the whole 8 s timeout.
    #   Preference order: https+443 > https+other > http+80 > http+other.
    local TAKEOVER_LIST="$TRIAGE_DIR/takeover_targets_${DATE}.txt"
    awk '{
            u = $0; h = u
            sub(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "", h); sub(/[\/?].*/, "", h)
            n = split(h, pp, ":"); host = tolower(pp[1]); port = (n > 1 ? pp[2] : "")
            sc = 0
            if (u ~ /^https:/) sc = (port == "" || port == "443") ? 4 : 3
            else               sc = (port == "" || port == "80")  ? 2 : 1
            if (!(host in bs) || sc > bs[host]) { bs[host] = sc; best[host] = u }
         } END { for (h in best) print best[h] }' \
        "$TRIAGE_DIR/alive_${DATE}.txt" | sort -u > "$TAKEOVER_LIST"
    local _TK_IN=$(wc -l < "$TRIAGE_DIR/alive_${DATE}.txt" 2>/dev/null || echo 0)
    local _TK_OUT=$(wc -l < "$TAKEOVER_LIST" 2>/dev/null || echo 0)
    echo "    -> takeover: $_TK_IN URLs -> $_TK_OUT unique hosts"
    # A shorter timeout just for this step: takeover templates are single-request fingerprints,
    # the general 8 s timeout is pure waiting on unresponsive hosts.
    local NUCLEI_TAKEOVER=(-silent -rl "$RATE_LIMIT" -bs "$NUCLEI_BS" -retries 1 -timeout 5 -etags dos,fuzz,intrusive "${HEADER_ARGS[@]}")
    nuclei -l "$TAKEOVER_LIST" -t http/takeovers/ \
        "${NUCLEI_TAKEOVER[@]}" -o "$ANALYSIS_DIR/nuclei_takeover_${DATE}.txt" 2>/dev/null

    local GOLDEN_SCAN="$TRIAGE_DIR/golden_scan_${DATE}.txt"
    grep -Fxf "$TRIAGE_DIR/golden_${DATE}.txt" "$SCAN_LIST" > "$GOLDEN_SCAN" 2>/dev/null || : > "$GOLDEN_SCAN"
    if [ -s "$GOLDEN_SCAN" ]; then
        nuclei -l "$GOLDEN_SCAN" \
            -t http/exposed-panels/,http/misconfiguration/,http/default-logins/,http/vulnerabilities/,http/cve/ \
            -severity medium,high,critical \
            "${NUCLEI_COMMON[@]}" -o "$ANALYSIS_DIR/nuclei_generic_golden_${DATE}.txt" 2>/dev/null
    fi

	# 5.3d — v13: param -> DAST fuzz bridge. arjun (M5) mines params, nothing fuzzed them.
	#   DAST = active injection payloads -> gated behind DAST_FUZZ=1, OFF by default even
	#   on focused runs. Set it only after the engagement OKs active testing. Golden only.
	if [ "${DAST_FUZZ:-0}" = "1" ]; then
	    local FUZZ_URLS="$ANALYSIS_DIR/fuzz_urls_${DATE}.txt"
	    { [ -f "$ANALYSIS_DIR/gf_patterns/mined_params_${DATE}.txt" ] && cat "$ANALYSIS_DIR/gf_patterns/mined_params_${DATE}.txt"
	      grep -aE "\?[a-zA-Z0-9_]+=" "$ENDPOINTS_DIR/clean_urls_${DATE}.txt" 2>/dev/null | grep -iE "$GOLDEN_REGEX"
	    } 2>/dev/null | sort -u > "$FUZZ_URLS"
	    if [ -s "$FUZZ_URLS" ]; then
	        echo "    -> 5.3d DAST fuzz ($(wc -l < "$FUZZ_URLS") param URLs, golden)"
	        nuclei -l "$FUZZ_URLS" -dast -silent -rl "$RATE_LIMIT" -bs "$NUCLEI_BS" \
	            -retries 1 -timeout 10 -etags dos,intrusive "${HEADER_ARGS[@]}" \
	            -o "$ANALYSIS_DIR/nuclei_dast_${DATE}.txt" 2>/dev/null || true
	    fi
	fi

    # 5.4 — v13: API-spec discovery. Golden hosts, ~20 fixed paths, one GET each, no recursion.
    if [ -s "${GOLDEN_SCAN:-/dev/null}" ]; then
        local API_SPECS="$ANALYSIS_DIR/api_specs_${DATE}.txt"; : > "$API_SPECS"
        local _sp="/swagger.json /openapi.json /v2/api-docs /v3/api-docs /api-docs /api/swagger.json /swagger/v1/swagger.json /swagger-ui/ /swagger-ui.html /.well-known/openapi.json /.well-known/ /graphql /graphiql /playground /api/graphql /v1/graphql /api /openapi.yaml /docs/json"
        while IFS= read -r _h; do
            for _p in $_sp; do
                local _c=$(curl -s -o /tmp/_apisp -m 8 "${HEADER_ARGS[@]}" -w "%{http_code}" "${_h%/}$_p" 2>/dev/null)
                if [ "$_c" = "200" ] && grep -qiE "swagger|openapi|__schema|"paths"|graphql|"servers"" /tmp/_apisp 2>/dev/null; then
                    echo "$_c  ${_h%/}$_p" >> "$API_SPECS"
                fi
            done
        done < "$GOLDEN_SCAN"
        [ -s "$API_SPECS" ] && echo "    -> API specs: $(wc -l < "$API_SPECS") hit(s) -> $API_SPECS"
    fi

    # Combined vulnerability output -- the summary, the preview and the final aggregation read this file.
    cat "$ANALYSIS_DIR/nuclei_targeted_${DATE}.txt" \
        "$ANALYSIS_DIR/nuclei_generic_${DATE}.txt" \
        "$ANALYSIS_DIR/nuclei_takeover_${DATE}.txt" \
        "$ANALYSIS_DIR/nuclei_generic_golden_${DATE}.txt" "$ANALYSIS_DIR/nuclei_dast_${DATE}.txt" 2>/dev/null \
        | LC_ALL=C sort -u > "$ANALYSIS_DIR/nuclei_vulns_${DATE}.txt"
    local NUCLEI_VULN=$(wc -l < "$ANALYSIS_DIR/nuclei_vulns_${DATE}.txt" 2>/dev/null || echo 0)
    echo "[+] Detected tech: $NUCLEI_TECH | Nuclei vulns (targeted+generic): $NUCLEI_VULN"

    # Module 8: JS Deep Analysis -- secrets + endpoints + sourcemaps + GraphQL operations
    echo "[*] [8/11] JS deep analysis (secret / endpoint / sourcemap / GraphQL)..."
    local SECRET_FILE="$ANALYSIS_DIR/secrets_${DATE}.txt"
    local JS_ANALYSIS_DIR="$ANALYSIS_DIR/js_analysis_${DATE}"
    mkdir -p "$JS_ANALYSIS_DIR"
    local SECRET_COUNT=0
    local JS_ENDPOINT_COUNT=0 JS_SOURCEMAP_COUNT=0 JS_GQL_COUNT=0

    # 8a -- SecretFinder (existing behaviour preserved)
    if command -v python3 &>/dev/null && [ -f "$SECRETFINDER_DIR/SecretFinder.py" ]; then
        cat "$ENDPOINTS_DIR/js_files_${DATE}.txt" | head -n "$JS_MAX_FILES" \
            | xargs -P 5 -I{} python3 "$SECRETFINDER_DIR/SecretFinder.py" -i {} -o cli 2>/dev/null | grep -v "^$" >> "$SECRET_FILE"
        SECRET_COUNT=$(wc -l < "$SECRET_FILE" 2>/dev/null || echo 0)
    else
        echo "[!] SecretFinder missing -- 8a skipped (git clone https://github.com/m4ll0k/SecretFinder \"$SECRETFINDER_DIR\")"
    fi

    # 8b -- endpoint / sourcemap / GraphQL extraction (js_analyze.py; no linkfinder needed)
    if command -v python3 &>/dev/null && [ -f "$SCRIPT_DIR/js_analyze.py" ] && [ -s "$ENDPOINTS_DIR/js_files_${DATE}.txt" ]; then
        local JS_HDR=""
        [ -n "$RESEARCH_HEADER" ] && JS_HDR="$RESEARCH_HEADER"
        head -n "$JS_MAX_FILES" "$ENDPOINTS_DIR/js_files_${DATE}.txt" \
            | RESEARCH_HEADER="$JS_HDR" RESEARCH_USER_AGENT="$RESEARCH_USER_AGENT" \
              python3 "$SCRIPT_DIR/js_analyze.py" --outdir "$JS_ANALYSIS_DIR" 2>/dev/null || true
        JS_ENDPOINT_COUNT=$(wc -l < "$JS_ANALYSIS_DIR/js_endpoints.txt" 2>/dev/null || echo 0)
        JS_SOURCEMAP_COUNT=$(wc -l < "$JS_ANALYSIS_DIR/js_sourcemaps.txt" 2>/dev/null || echo 0)
        JS_GQL_COUNT=$(wc -l < "$JS_ANALYSIS_DIR/js_graphql_ops.txt" 2>/dev/null || echo 0)
        # add same-host endpoints extracted from JS to the clean URL pool
        [ -s "$JS_ANALYSIS_DIR/js_endpoints_abs.txt" ] && \
            cat "$JS_ANALYSIS_DIR/js_endpoints_abs.txt" >> "$ENDPOINTS_DIR/clean_urls_${DATE}.txt" && \
            sort -u -o "$ENDPOINTS_DIR/clean_urls_${DATE}.txt" "$ENDPOINTS_DIR/clean_urls_${DATE}.txt"
    else
        echo "[!] js_analyze.py missing or no JS files -- 8b skipped."
    fi
    echo "[+] Secrets: $SECRET_COUNT | JS endpoints: $JS_ENDPOINT_COUNT | sourcemaps: $JS_SOURCEMAP_COUNT | GraphQL ops: $JS_GQL_COUNT"

    # Module 9: Cloud / Infra / Mobile Enum
    echo "[*] [9/11] Cloud / infra / mobile enum..."
    local CLOUD_DIR="$ANALYSIS_DIR/cloud_${DATE}"
    mkdir -p "$CLOUD_DIR"
    local CLOUD_HIT_COUNT=0 MOBILE_EP_COUNT=0

    # 9a -- cloud bucket enum (keyword = apex + rough org name). Low request volume, no scope risk
    #   (only checks whether a bucket exists / is public). Open S3 buckets are verified with s3scanner.
    if [ "$CLOUD_ENUM" = "1" ] && command -v cloud_enum &>/dev/null; then
        # v14.4 -- ORG must be the first label of the APEX, NOT the first label of the target.
        # For a target like `api.example.com` in a depth run, the old code produced ORG="api"; cloud_enum
        # then probed generic buckets belonging to COMPLETELY OTHER PARTIES such as `api.s3.amazonaws.com`,
        # `storage.googleapis.com/api`, `api-prod`, `api-assets` and
        # reported "7 cloud hits" (seen in a real run).
        # Same class as building a search keyword from the wrong token:
        # probing the assets of unrelated third parties.
        local _APEX
        _APEX=$(printf '%s' "$TARGET" | awk -F. '
            NF<2 { print; next }
            {
                two = $(NF-1)"."$NF
                if (NF>=3 && (two=="co.uk"||two=="org.uk"||two=="com.au"||two=="com.br"||
                              two=="com.tr"||two=="co.jp"||two=="co.nz"||two=="co.za"||
                              two=="com.mx"||two=="com.sg"||two=="co.in"||two=="com.hk"))
                    print $(NF-2)"."two
                else print two
            }')
        local ORG="${_APEX%%.*}"
        printf "%s\n%s\n%s\n%s\n" "$ORG" "$TARGET" "${ORG}-prod" "${ORG}-assets" > "$CLOUD_DIR/keywords.txt"
        timeout "$CLOUD_ENUM_TIMEOUT" cloud_enum -kf "$CLOUD_DIR/keywords.txt" -qs -f text -l "$CLOUD_DIR/cloud_enum.txt" >/dev/null 2>&1 || true
        if [ -s "$CLOUD_DIR/cloud_enum.txt" ]; then
            grep -iE 'OPEN|PUBLIC|Protected .* Bucket|Container|storage\.googleapis|s3\.amazonaws|blob\.core\.windows' \
                "$CLOUD_DIR/cloud_enum.txt" 2>/dev/null | LC_ALL=C sort -u > "$CLOUD_DIR/cloud_hits.txt"
            CLOUD_HIT_COUNT=$(wc -l < "$CLOUD_DIR/cloud_hits.txt" 2>/dev/null || echo 0)
            grep -oE '[a-z0-9.-]+\.s3[.-][a-z0-9.-]*amazonaws\.com' "$CLOUD_DIR/cloud_enum.txt" 2>/dev/null \
                | sed -E 's/\.s3[.-].*//' | LC_ALL=C sort -u > "$CLOUD_DIR/s3_buckets.txt"
            if [ -s "$CLOUD_DIR/s3_buckets.txt" ] && command -v s3scanner &>/dev/null; then
                s3scanner -t 4 scan -f "$CLOUD_DIR/s3_buckets.txt" > "$CLOUD_DIR/s3scanner.txt" 2>/dev/null || true
            fi
        fi
        echo "    -> cloud hits: $CLOUD_HIT_COUNT (see $CLOUD_DIR/cloud_hits.txt)"
    fi

    # 9b -- ASN -> CIDR (SCOPE RISK). Default off. Even when on it ONLY writes a file, never scans.
    if [ "$ASN_EXPAND" = "1" ]; then
        local APEX_IP=$(printf '%s\n' "$TARGET" | dnsx -silent -a -resp-only 2>/dev/null | head -1)
        if [ -n "$APEX_IP" ]; then
            local ASN=$(curl -s --max-time 15 "https://api.bgpview.io/ip/$APEX_IP" 2>/dev/null | jq -r '.data.prefixes[0].asn.asn // empty' 2>/dev/null)
            if [ -n "$ASN" ]; then
                curl -s --max-time 20 "https://api.bgpview.io/asn/$ASN/prefixes" 2>/dev/null \
                    | jq -r '.data.ipv4_prefixes[].prefix' 2>/dev/null | LC_ALL=C sort -u > "$CLOUD_DIR/asn_cidrs.txt"
                echo "    -> ASN $ASN, $(wc -l < "$CLOUD_DIR/asn_cidrs.txt" 2>/dev/null || echo 0) IPv4 prefixes -> $CLOUD_DIR/asn_cidrs.txt (if in scope, feed to naabu by hand)"
            fi
        fi
    fi

    # 9c -- mobile recon: APK_PACKAGES env, otherwise play.google.com links found by the crawl
    local PKGS="$APK_PACKAGES"
    if [ -z "$PKGS" ] && [ "$MOBILE_AUTODISCOVER" = "1" ]; then
        PKGS=$(grep -rhoE 'play\.google\.com/store/apps/details\?id=[a-zA-Z0-9_.]+' \
            "$ENDPOINTS_DIR"/*_${DATE}.txt 2>/dev/null | sed 's/.*id=//' | LC_ALL=C sort -u | head -3 | paste -sd, -)
        [ -n "$PKGS" ] && echo "    -> mobile package found automatically: $PKGS"
    fi
    if [ -n "$PKGS" ] && [ -f "$SCRIPT_DIR/mobile_recon.sh" ]; then
        echo "    -> mobile recon: $PKGS"
        timeout 1800 bash "$SCRIPT_DIR/mobile_recon.sh" "$BASE_DIR/mobile_${DATE}" ${PKGS//,/ } 2>&1 | sed 's/^/       /' || true
        MOBILE_EP_COUNT=$(wc -l < "$BASE_DIR/mobile_${DATE}/all_mobile_endpoints.txt" 2>/dev/null || echo 0)
        # add the hosts of mobile endpoints to the subdomain pool (scope-diff already ran; these
        #   stay in a separate file, informational only -- not scanned automatically)
        grep -oE 'https?://[^/"]+' "$BASE_DIR/mobile_${DATE}/all_mobile_endpoints.txt" 2>/dev/null \
            | sed -E 's#https?://##' | LC_ALL=C sort -u > "$BASE_DIR/mobile_${DATE}/mobile_hosts.txt"
    elif [ -n "$PKGS" ]; then
        echo "    [!] mobile_recon.sh missing -- mobile recon skipped."
    fi
    echo "[+] Cloud hits: $CLOUD_HIT_COUNT | Mobile endpoints: $MOBILE_EP_COUNT"

    # Module 10: Manual Next Steps -- Google-dork checklist (cannot be automated, written to a file so it is not skipped)
    echo "[*] [10/11] Writing the manual next-steps file (dork checklist)..."
    write_manual_next_steps "$TARGET" "$BASE_DIR/MANUAL_NEXT_STEPS_${DATE}.md"
    # v13: real dorking (dork.sh: GitHub code-search + trufflehog + Censys). 5-15 min,
    #   API-quota bound, independent of the rest -> gated DORK=1. Default: ON focused, OFF sweep.
    if [ "${DORK:-$_DEEP_DEFAULT}" = "1" ] && [ -x "$SCRIPT_DIR/dork.sh" ]; then
        echo "    -> dork.sh $TARGET (DORK=1)"
        ( cd "$SCRIPT_DIR" && ./dork.sh "$TARGET" ${DORK_GH_ORG:+"$DORK_GH_ORG"} ) 2>/dev/null || true
        [ -d "$ATTACKLEDGER_WORKDIR/dorks/$TARGET" ] && cp -r "$ATTACKLEDGER_WORKDIR/dorks/$TARGET" "$BASE_DIR/dorks_${DATE}" 2>/dev/null || true
    fi
    echo "[+] Manual steps: $BASE_DIR/MANUAL_NEXT_STEPS_${DATE}.md"

    # -- v14.7: PENDING DECISIONS -------------------------------------------
    # Three rules existed only as prose until now, and all three were forgotten:
    # when the golden cap was hit nobody looked at the overflow,
    # promote_queue was read but never turned into a decision, and when content_discovery was left with
    # 0 lines it was read as "content discovery done, nothing there". Now they are
    # written to a file and stamped into .pipeline_state -- not dependent on anyone remembering.
    # NOTE: the type tokens (GOLDEN_OVERFLOW, PROMOTE_QUEUE, CONTENT_DISCOVERY_EMPTY,
    # CONTENT_DISCOVERY_NOT_RUN, INTERNAL_IP) and the .pipeline_state keys are machine-read by
    # recon/priority_board.py -- keep them stable.
    PENDING_FILE="$BASE_DIR/PENDING_DECISIONS_${DATE}.tsv"
    { printf 'type\tcount\tfile\twhat_to_do\n'
      _OVF="$TRIAGE_DIR/golden_overflow_${DATE}.txt"
      _N=$(wc -l < "$_OVF" 2>/dev/null || echo 0); _N=${_N// /}
      [ "${_N:-0}" -gt 0 ] && printf 'GOLDEN_OVERFLOW\t%s\t%s\t%s\n' "$_N" "$_OVF" \
        "GOLDEN_MAX=$GOLDEN_MAX ceiling hit; every overflowing host needs a decision (add to the board or drop with a reason) -- reporting the count is not enough"

      _PQ="$SUBS_DIR/promote_queue_${DATE}.txt"
      _N=$(wc -l < "$_PQ" 2>/dev/null || echo 0); _N=${_N// /}
      [ "${_N:-0}" -gt 0 ] && printf 'PROMOTE_QUEUE\t%s\t%s\t%s\n' "$_N" "$_PQ" \
        "decide per apex: separate engagement / out of program scope / dropped with a reason"

      _CD="$ENDPOINTS_DIR/content_discovery_${DATE}.txt"
      if [ -f "$_CD" ]; then
        _N=$(wc -l < "$_CD" 2>/dev/null || echo 0); _N=${_N// /}
        if [ "${_N:-0}" -eq 0 ]; then
          if [ "${CONTENT_DISCOVERY:-0}" = "1" ]; then
            printf 'CONTENT_DISCOVERY_EMPTY\t0\t%s\t%s\n' "$_CD" \
              "module RAN but 0 results -- verify the baseline/WAF calibration, do not read this as 'no findings'"
          else
            printf 'CONTENT_DISCOVERY_NOT_RUN\t0\t%s\t%s\n' "$_CD" \
              "module was OFF (sweep default). This target does not count as 'content discovery done' until a focused CONTENT_DISCOVERY=1 pass is made"
          fi
        fi
      fi
    } > "$PENDING_FILE"
    PENDING_N=$(( $(wc -l < "$PENDING_FILE") - 1 ))
    [ "$PENDING_N" -lt 0 ] && PENDING_N=0
    printf 'DECISIONS_PENDING=%s\n' "$PENDING_N" >> "$BASE_DIR/.pipeline_state"
    if [ "$PENDING_N" -gt 0 ]; then
        echo "[!] $PENDING_N decisions pending -> $PENDING_FILE"
        sed -n '2,$p' "$PENDING_FILE" | cut -f1,2 | sed 's/^/      /'
    fi

    # -- v14.7: FINDING CANDIDATES ------------------------------------------
    # Finding candidates produced by recon had no place in the flow; they stayed in chat and
    # got lost. First type: hosts that resolve from public DNS to a private IP --
    # unreachable from outside but they leak internal network topology (server names, internal
    # IPs, segmentation). One past run had 17 of them and none were triaged.
    CAND_FILE="$BASE_DIR/FINDING_CANDIDATES_${DATE}.tsv"
    _SRC="$SUBS_DIR/resolved_intarget_${DATE}.txt"
    [ -s "$_SRC" ] || _SRC="$SUBS_DIR/resolved_${DATE}.txt"
    { printf 'type\thost\tevidence\tnote\n'
      if [ -s "$_SRC" ] && command -v dnsx >/dev/null 2>&1; then
        dnsx -l "$_SRC" -a -json -silent 2>/dev/null \
          | jq -r 'select(.has_internal_ips == true)
                   | "INTERNAL_IP\t" + .host + "\t" + (.internal_ips | join(",")) +
                     "\tpublic DNS leaks an internal address -- to be taken to the finding-validator"' 2>/dev/null
      fi
    } > "$CAND_FILE"
    CAND_N=$(( $(wc -l < "$CAND_FILE") - 1 ))
    [ "$CAND_N" -lt 0 ] && CAND_N=0
    printf 'FINDING_CANDIDATES=%s\n' "$CAND_N" >> "$BASE_DIR/.pipeline_state"
    [ "$CAND_N" -gt 0 ] && echo "[!] $CAND_N finding candidates -> $CAND_FILE"

    # Module 11: Summary file
    echo "[*] [11/11] Creating the summary file..."
    cat > "$BASE_DIR/CLAUDE_SUMMARY_${DATE}.md" << SUMMARY
# Recon Summary: $TARGET
**Date:** $DATE
**Scope file:** ${SCOPE_FILE:-"(not used -- no filter applied)"}
**Research header:** ${RESEARCH_HEADER:-"(not defined)"}

## Statistics
| Category | Count |
|---|---|
| Subdomains | $SUB_COUNT |
| Live services (in-scope) | $ALIVE_COUNT |
| Out of scope (dropped) | $OOS_COUNT |
| Golden targets | $GOLDEN_COUNT |
| Content discovery (ferox, 2xx/3xx/401/403) | $CONTENT_COUNT |
| Clean endpoints | $CLEAN_COUNT |
| Authenticated crawl URLs | $AUTH_URL_COUNT |
| Mined parameters | $PARAM_COUNT |
| JS files | $JS_COUNT |
| Endpoints from JS | $JS_ENDPOINT_COUNT |
| Open sourcemaps | $JS_SOURCEMAP_COUNT |
| GraphQL operations | $JS_GQL_COUNT |
| Detected technologies | $NUCLEI_TECH |
| Nuclei vulns (targeted+generic) | $NUCLEI_VULN |
| Secret findings | $SECRET_COUNT |
| Cloud bucket hits | $CLOUD_HIT_COUNT |
| Mobile endpoints | $MOBILE_EP_COUNT |

## Golden Targets
$(cat "$TRIAGE_DIR/golden_${DATE}.txt" 2>/dev/null || echo "None")

## GF Findings
$(for f in "$ANALYSIS_DIR"/*_${DATE}.txt; do [ -f "$f" ] && echo "- $(basename $f .txt | sed 's/_'$DATE'//') : $(wc -l < $f) lines"; done)

## File Paths
- Subdomains: $SUBS_DIR/resolved_${DATE}.txt
- Alive (in-scope): $TRIAGE_DIR/alive_${DATE}.txt
- Out-of-scope (dropped): $TRIAGE_DIR/out_of_scope_${DATE}.txt
- Golden: $TRIAGE_DIR/golden_${DATE}.txt
- Clean URLs: $ENDPOINTS_DIR/clean_urls_${DATE}.txt
- JS Files: $ENDPOINTS_DIR/js_files_${DATE}.txt
- GF Patterns: $ANALYSIS_DIR/
- Content discovery (ferox): $ENDPOINTS_DIR/content_discovery_${DATE}.txt
- Authenticated crawl URLs: $ENDPOINTS_DIR/authenticated_urls_${DATE}.txt
- Mined parameters (arjun): $ANALYSIS_DIR/mined_params_${DATE}.txt
- JS deep analysis: $ANALYSIS_DIR/js_analysis_${DATE}/ (js_endpoints.txt, js_sourcemaps.txt, js_graphql_ops.txt)
- Manual next steps (dork checklist): $BASE_DIR/MANUAL_NEXT_STEPS_${DATE}.md
- **PENDING DECISIONS ($PENDING_N):** $BASE_DIR/PENDING_DECISIONS_${DATE}.tsv
  (if not 0, this run is NOT "done" -- every row needs a decision)
- **FINDING CANDIDATES ($CAND_N):** $BASE_DIR/FINDING_CANDIDATES_${DATE}.tsv
  (candidates produced by recon; they go to the finding-validator without waiting for the hunt)
- Cloud enum: $ANALYSIS_DIR/cloud_${DATE}/ (cloud_hits.txt, s3scanner.txt, asn_cidrs.txt)
- Mobile recon: $BASE_DIR/mobile_${DATE}/ (all_mobile_endpoints.txt, all_mobile_secrets.txt, <pkg>/manifest_summary.txt)
- Scan list (clustered): $TRIAGE_DIR/alive_scan_${DATE}.txt
- Detected technologies: $ANALYSIS_DIR/nuclei_tech_${DATE}.txt
- Nuclei vulns (combined): $ANALYSIS_DIR/nuclei_vulns_${DATE}.txt
- Nuclei vulns (targeted/tech): $ANALYSIS_DIR/nuclei_targeted_${DATE}.txt
- Nuclei vulns (generic-light): $ANALYSIS_DIR/nuclei_generic_${DATE}.txt
- Nuclei vulns (generic-golden): $ANALYSIS_DIR/nuclei_generic_golden_${DATE}.txt
- Secrets: $ANALYSIS_DIR/secrets_${DATE}.txt
SUMMARY

    echo "[+] Summary file: $BASE_DIR/CLAUDE_SUMMARY_${DATE}.md"

    # Zipping
    local ZIP_FILE="$BASE_DIR/${TARGET}_recon_${DATE}.zip"
    local TMP_ZIP_DIR="$BASE_DIR/tmp_zip_${DATE}"
    mkdir -p "$TMP_ZIP_DIR/subdomains" "$TMP_ZIP_DIR/triage" "$TMP_ZIP_DIR/endpoints" "$TMP_ZIP_DIR/analysis/gf_patterns"

    cp "$SUBS_DIR"/*_${DATE}.* "$TMP_ZIP_DIR/subdomains/" 2>/dev/null
    cp "$TRIAGE_DIR"/*_${DATE}.* "$TMP_ZIP_DIR/triage/" 2>/dev/null
    cp "$ENDPOINTS_DIR"/*_${DATE}.* "$TMP_ZIP_DIR/endpoints/" 2>/dev/null
    cp "$ANALYSIS_DIR"/*_${DATE}.* "$TMP_ZIP_DIR/analysis/gf_patterns/" 2>/dev/null
    cp -r "$ANALYSIS_DIR/js_analysis_${DATE}" "$TMP_ZIP_DIR/analysis/gf_patterns/" 2>/dev/null
    cp -r "$ANALYSIS_DIR/cloud_${DATE}" "$TMP_ZIP_DIR/analysis/gf_patterns/" 2>/dev/null
    # mobile recon can be large -- only the summary files go into the zip
    if [ -d "$BASE_DIR/mobile_${DATE}" ]; then
        mkdir -p "$TMP_ZIP_DIR/mobile"
        (cd "$BASE_DIR/mobile_${DATE}" && find . -maxdepth 2 -name '*.txt' -o -name 'manifest_summary.txt' -o -name 'AndroidManifest.xml') \
            | while read -r f; do mkdir -p "$TMP_ZIP_DIR/mobile/$(dirname "$f")"; cp "$BASE_DIR/mobile_${DATE}/$f" "$TMP_ZIP_DIR/mobile/$f" 2>/dev/null; done
    fi
    cp "$BASE_DIR/CLAUDE_SUMMARY_${DATE}.md" "$BASE_DIR/MANUAL_NEXT_STEPS_${DATE}.md" "$TMP_ZIP_DIR/" 2>/dev/null

    (cd "$TMP_ZIP_DIR" && zip -q -r "$ZIP_FILE" .)
    rm -rf "$TMP_ZIP_DIR"

    # No notification here -- so a multi-domain run does not spam, a one-line
    # stat is appended to the run-level file; the single run summary is produced when the run ends.
    # Columns 1-10 are fixed (so old consumers do not break); 11-18 are counters of the newer modules.
    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
        "$TARGET" "$SUB_COUNT" "$ALIVE_COUNT" "$OOS_COUNT" "$GOLDEN_COUNT" \
        "$CLEAN_COUNT" "$JS_COUNT" "$NUCLEI_TECH" "$NUCLEI_VULN" "$SECRET_COUNT" \
        "$CONTENT_COUNT" "$PARAM_COUNT" "$JS_ENDPOINT_COUNT" "$JS_SOURCEMAP_COUNT" "$JS_GQL_COUNT" \
        "$AUTH_URL_COUNT" "$CLOUD_HIT_COUNT" "$MOBILE_EP_COUNT" >> "$RUN_STATS_FILE"

    echo "=================================================="
    echo "[+] PIPELINE COMPLETE: $TARGET"
    printf "COMPLETE=1\nFINISHED=%s\n" "$(date -u +%FT%TZ)" >> "$BASE_DIR/.pipeline_state" 2>/dev/null
    echo "[+] Summary: $BASE_DIR/CLAUDE_SUMMARY_${DATE}.md"
    echo "[+] Archive: $ZIP_FILE"
    echo "=================================================="
}

# --- Dispatcher: single domain or domain list file? ---
if [ -f "$INPUT" ]; then
    echo "[+] Domain list detected: $INPUT -- each line will be processed as a separate target."
    # CRITICAL: the domain list is read from fd 3, not fd 0 (stdin). Reason: some tools
    # inside process_domain() (ProjectDiscovery tools can read stdin as EXTRA target input
    # even when -l/-list is given) consumed the loop's stdin from the inside and
    # silently dropped "while read" to EOF after the 1st domain -- a run over 11 domains
    # actually processed only 1 domain and finished. Using fd 3 removes this conflict completely
    # (every command inside process_domain() keeps using the normal fd 0).
    while IFS= read -r domain <&3; do
        [ -z "$domain" ] && continue
        [[ "$domain" == \#* ]] && continue
        process_domain "$domain"
    done 3< "$INPUT"
else
    process_domain "$INPUT"
fi

# --- Final summary ---
echo "=================================================="
echo "[+] ALL TARGETS COMPLETE -- preparing the summary"
echo "=================================================="

DOMAIN_COUNT=$(wc -l < "$RUN_STATS_FILE" 2>/dev/null | tr -d ' ' || echo 0)

if [ "$DOMAIN_COUNT" -gt 0 ]; then
    read -r T_SUB T_ALIVE T_OOS T_GOLDEN T_CLEAN T_JS T_NTECH T_NVULN T_SECRET T_CONTENT T_PARAM T_JSEP T_SMAP T_GQL T_AUTH T_CLOUD T_MOBEP < <(
        awk -F'\t' '{subc+=$2; alive+=$3; oos+=$4; golden+=$5; clean+=$6; js+=$7; ntech+=$8; nvuln+=$9; secret+=$10; content+=$11; param+=$12; jsep+=$13; smap+=$14; gql+=$15; auth+=$16; cloud+=$17; mobep+=$18}
                    END{print subc, alive, oos, golden, clean, js, ntech, nvuln, secret, content, param, jsep, smap, gql, auth, cloud, mobep}' "$RUN_STATS_FILE"
    )

    TOP_GOLDEN=$(while IFS=$'\t' read -r d _; do
        gf="$ATTACKLEDGER_WORKDIR/targets/$d/triage/golden_${DATE}.txt"
        [ -f "$gf" ] && cat "$gf"
    done < "$RUN_STATS_FILE" | head -10)

    VULN_PREVIEW=$(while IFS=$'\t' read -r d _; do
        vf="$ATTACKLEDGER_WORKDIR/targets/$d/analysis/gf_patterns/nuclei_vulns_${DATE}.txt"
        [ -f "$vf" ] && cat "$vf"
    done < "$RUN_STATS_FILE" | head -5)

SUMMARY_TXT="Recon complete -- [$RUN_LABEL] -- $DOMAIN_COUNT root domains
Date: $DATE

Totals:
- Subdomains: $T_SUB
- Live (in-scope): $T_ALIVE  |  Out of scope dropped: $T_OOS
- Golden targets: $T_GOLDEN
- Endpoints: $T_CLEAN  |  JS: $T_JS  |  Content discovery: $T_CONTENT
- Authenticated crawl URLs: $T_AUTH  |  Mined params: $T_PARAM  |  Endpoints from JS: $T_JSEP
- Cloud bucket hits: $T_CLOUD  |  Mobile endpoints: $T_MOBEP
- Open sourcemaps: $T_SMAP  |  GraphQL ops: $T_GQL
- Detected tech (total): $T_NTECH  |  Nuclei vulns: $T_NVULN
- Secret findings: $T_SECRET"

    if [ -n "$VULN_PREVIEW" ]; then
        SUMMARY_TXT="$SUMMARY_TXT

Nuclei vuln findings (first 5):
$VULN_PREVIEW"
    else
        SUMMARY_TXT="$SUMMARY_TXT

No findings in the Nuclei vuln scan."
    fi

    if [ -n "$TOP_GOLDEN" ]; then
        SUMMARY_TXT="$SUMMARY_TXT

Golden target samples (first 10):
$TOP_GOLDEN"
    fi

    echo "$SUMMARY_TXT"

    # Small final zip: each target's CLAUDE_SUMMARY.md + run_stats -- not huge raw-data
    # zips, just the summary material to hand over for review.
    FINAL_ZIP="$ATTACKLEDGER_WORKDIR/${RUN_LABEL}_summary_${DATE}.zip"
    TMP_FINAL="$ATTACKLEDGER_WORKDIR/tmp_final_${DATE}"
    mkdir -p "$TMP_FINAL"
    while IFS=$'\t' read -r d _; do
        cp "$ATTACKLEDGER_WORKDIR/targets/$d/CLAUDE_SUMMARY_${DATE}.md" "$TMP_FINAL/${d}_SUMMARY.md" 2>/dev/null
    done < "$RUN_STATS_FILE"
    cp "$RUN_STATS_FILE" "$TMP_FINAL/run_stats.tsv"
    (cd "$TMP_FINAL" && zip -q -r "$FINAL_ZIP" .)
    rm -rf "$TMP_FINAL"

    # No "done" ping is sent (see the note near the OOS section); the summary is already
    # on the terminal and in $FINAL_ZIP.

    echo "[+] Final summary zip: $FINAL_ZIP"
else
    echo "[!] No targets were processed, no summary produced."
fi
