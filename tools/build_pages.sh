#!/usr/bin/env bash
# Build the folder that goes to Cloudflare Pages (attackledger.com): the site, the demo,
# the sample report, and the security headers. The inline-script hashes in the CSP are
# computed from the files, so a changed script cannot run until the headers are rebuilt.
# Usage: tools/build_pages.sh [OUT]   (default: dist/pages)
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=${1:-dist/pages}
rm -rf "$OUT"
mkdir -p "$OUT"
cp site/index.html site/404.html site/sample-report.html site/sample-report.json site/verify_report.py \
   site/digicert-trusted-root-g4.pem site/favicon.svg site/favicon-32.png site/apple-touch-icon.png "$OUT"/
cp -R site/demo "$OUT"/demo
python3 -I - "$OUT" <<'PY'
import base64, hashlib, pathlib, re, sys
out = pathlib.Path(sys.argv[1])
hashes = set()
for f in out.rglob("*.html"):
    for m in re.finditer(r"<script(?![^>]*\bsrc=)([^>]*)>(.*?)</script>", f.read_text(), re.S):
        if "application/json" in m.group(1):
            continue                      # data, never executed
        hashes.add("'sha256-" + base64.b64encode(hashlib.sha256(m.group(2).encode()).digest()).decode() + "'")
csp = "; ".join([
    "default-src 'self'",
    "script-src 'self' " + " ".join(sorted(hashes)),
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data:",
    "connect-src 'self'",
    "frame-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
])
(out / "_headers").write_text(f"""/*
  Content-Security-Policy: {csp}
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
  Cross-Origin-Opener-Policy: same-origin
  Strict-Transport-Security: max-age=31536000; includeSubDomains

/verify_report.py
  Content-Type: text/plain; charset=utf-8

/digicert-trusted-root-g4.pem
  Content-Type: text/plain; charset=utf-8
""")
print(f"{out}: {sum(1 for _ in out.rglob('*') if _.is_file())} files, {len(hashes)} inline script hashes")
PY
