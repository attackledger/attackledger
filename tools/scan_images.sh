#!/usr/bin/env bash
# Known vulnerabilities in the OS packages (Debian, Alpine) of each AttackLedger image
# (docs/SUPPLY_CHAIN.md). Prints every HIGH and CRITICAL one, with the version that fixes it.
#
#   tools/scan_images.sh                          # the images tagged latest, and the pinned third-party ones
#   ATTACKLEDGER_SCAN_TAG=v0.9.0 tools/scan_images.sh
#   tools/scan_images.sh IMAGE...                 # these images only
#   ATTACKLEDGER_SCAN_JSON=DIR tools/scan_images.sh   # also keep Grype's full report per image there
#
# Exit status: 0 no HIGH or CRITICAL with a fix, 1 at least one with a fix (that is, an
# `apt-get`/`apk` upgrade or a newer base image would remove it) that tools/scan_ignore.txt does
# not accept, 2 the scan itself failed. HIGH and CRITICAL without a fix (Debian: "not fixed",
# "will not fix") are listed but do not fail it: there is nothing to move to.
#
# The scanner is Grype, run from its image pinned by digest. Its vulnerability database is
# downloaded first, in a container of its own, from Anchore (grype.anchore.io), into a Docker
# volume (ATTACKLEDGER_SCAN_DB_VOLUME, default attackledger-scan-db; `docker volume rm` it to
# drop the cache). The scans then run with no network. Only each image's package database
# (/etc/os-release, /var/lib/dpkg/status, /lib/apk/db/installed) is copied out of it, as
# tools/sbom.sh does: the image is not run, and nothing is mounted from this machine. Python and
# npm packages are checked by pip-audit and npm audit (docs/SUPPLY_CHAIN.md), not here.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG="${ATTACKLEDGER_SCAN_TAG:-latest}"
DB_VOLUME="${ATTACKLEDGER_SCAN_DB_VOLUME:-attackledger-scan-db}"
IGNORE="$ROOT/tools/scan_ignore.txt"
# grype 0.119.0 (2026-09-17), the "nonroot" variant (distroless, uid 65532, no shell).
GRYPE=anchore/grype:v0.119.0-nonroot@sha256:946f9705680946f07250059edc4fbdc11c8e948055fe30c99e6f3e239d5e7ab3
WORK="$(mktemp -d)"
cid=""; trap '[ -z "$cid" ] || docker rm -f "$cid" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT
fail() { echo "[scan] $*" >&2; exit 2; }

if [ "$#" -gt 0 ]; then
  images=("$@")
else
  images=("attackledger-api:$TAG" "attackledger-worker:$TAG" "attackledger-web:$TAG")
  # The third-party images, by the digests the compose files pin.
  while read -r image; do images+=("$image"); done < <(
    grep -hoE 'image: [a-z0-9./-]+:[^ @]+@sha256:[0-9a-f]{64}' "$ROOT/docker-compose.yml" "$ROOT/deploy/compose.prod.yml" \
      | awk '{print $2}' | sort -u)
fi

# The scanner's own container: no capability, no privilege gain, a read-only root filesystem.
HARDEN=(--cap-drop ALL --security-opt no-new-privileges:true -e GRYPE_CHECK_FOR_APP_UPDATE=false
        -e GRYPE_DB_CACHE_DIR=/home/nonroot/db -v "$DB_VOLUME:/home/nonroot")
docker run --rm --read-only --tmpfs /tmp:size=512m "${HARDEN[@]}" "$GRYPE" db update -q >&2 \
  || fail "the vulnerability database could not be downloaded"
docker run --rm --read-only --tmpfs /tmp:size=64m --network none "${HARDEN[@]}" -e GRYPE_DB_AUTO_UPDATE=false \
  "$GRYPE" db status >&2 || fail "no valid vulnerability database"

n=0
for image in "${images[@]}"; do
  docker image inspect "$image" >/dev/null 2>&1 || docker pull -q "$image" >/dev/null || fail "$image: not found (build it first)"
  n=$((n + 1)); dir="$WORK/$n"; mkdir -p "$dir/in/etc" "$dir/in/var/lib/dpkg" "$dir/in/lib/apk/db"
  cid="$(docker create "$image")"
  docker cp -L "$cid:/etc/os-release" "$dir/in/etc/os-release" 2>/dev/null || true
  docker cp -L "$cid:/var/lib/dpkg/status" "$dir/in/var/lib/dpkg/status" 2>/dev/null || true
  docker cp -L "$cid:/lib/apk/db/installed" "$dir/in/lib/apk/db/installed" 2>/dev/null || true
  docker rm -f "$cid" >/dev/null; cid=""
  [ -s "$dir/in/etc/os-release" ] || fail "$image: no /etc/os-release"
  [ -s "$dir/in/var/lib/dpkg/status" ] || [ -s "$dir/in/lib/apk/db/installed" ] || fail "$image: no dpkg or apk database"
  # The package lists go into the scanner's container by `docker cp` (an anonymous volume, removed with it).
  cid="$(docker create --network none --read-only --tmpfs /tmp:size=512m -v /scan "${HARDEN[@]}" -e GRYPE_DB_AUTO_UPDATE=false \
         "$GRYPE" dir:/scan -q -o json --name "$image")"
  docker cp "$dir/in/." "$cid:/scan/"
  docker start -a "$cid" > "$dir/grype.json" || fail "$image: the scan failed"
  docker rm -f -v "$cid" >/dev/null; cid=""
  printf '%s\n' "$image" > "$dir/image"
  if [ -n "${ATTACKLEDGER_SCAN_JSON:-}" ]; then
    mkdir -p "$ATTACKLEDGER_SCAN_JSON"
    cp "$dir/grype.json" "$ATTACKLEDGER_SCAN_JSON/$(printf '%s' "${image%%@*}" | tr '/:' '__').grype.json"
  fi
done

python3 -I - "$WORK" "$IGNORE" <<'PY' || exit $?
import datetime, fnmatch, json, sys
from pathlib import Path

def crash(kind, value, tb):   # a broken report or ignore file is a failed scan (2), not a finding (1)
    sys.__excepthook__(kind, value, tb)
    sys.stderr.flush()
    import os
    os._exit(2)
sys.excepthook = crash

work, ignore_file = Path(sys.argv[1]), Path(sys.argv[2])
today = datetime.date.today()
# tools/scan_ignore.txt: "<vulnerability id> <image glob> <package> <until YYYY-MM-DD> <reason>".
ignores, expired = [], []
if ignore_file.exists():
    for raw in ignore_file.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        vid, image, package, until, *reason = line.split()
        if not reason:
            sys.exit(f"[scan] {ignore_file.name}: no reason given in: {line}")
        if datetime.date.fromisoformat(until) < today:
            expired.append(line)
        else:
            ignores.append((vid, image, package))

fixable = accepted = unfixed = 0
for d in sorted((p for p in work.iterdir() if p.is_dir()), key=lambda p: int(p.name)):
    image = (d / "image").read_text().strip()
    doc = json.loads((d / "grype.json").read_text())
    distro = doc.get("distro") or {}
    pkgs = {(m["artifact"]["name"], m["artifact"]["version"]) for m in doc.get("matches", [])}
    rows = {}
    for m in doc.get("matches", []):
        v, a = m["vulnerability"], m["artifact"]
        sev = v.get("severity", "Unknown")
        if sev not in ("High", "Critical"):
            continue
        fix = v.get("fix") or {}
        state, versions = fix.get("state", "unknown"), fix.get("versions") or []
        key = (v["id"], a["name"], a["version"])
        rows[key] = (sev, state, ", ".join(versions))
    print(f"\n== {image} ({distro.get('name', '?')} {distro.get('version', '?')}): "
          f"{len(doc.get('matches', []))} matches in {len(pkgs)} packages, {len(rows)} HIGH or CRITICAL")
    for (vid, name, version), (sev, state, versions) in sorted(rows.items(), key=lambda r: (r[1][1] != "fixed", r[0])):
        if state == "fixed":
            ok = any(vid == i and fnmatch.fnmatch(image, g) and name == p for i, g, p in ignores)
            accepted += ok
            fixable += not ok
            what = f"fixed in {versions}" + (" (accepted in scan_ignore.txt)" if ok else "")
        else:
            unfixed += 1
            what = {"not-fixed": "no fix yet", "wont-fix": "will not be fixed (distribution)",
                    "unknown": "fix state unknown (no distribution record)"}.get(state, state)
        print(f"  {sev:8} {vid:20} {name} {version}: {what}")
for line in expired:
    print(f"[scan] expired entry in scan_ignore.txt (no longer applied): {line}")
print(f"\n[scan] {fixable} HIGH/CRITICAL with a fix, {accepted} accepted, {unfixed} without a fix")
sys.exit(1 if fixable else 0)
PY
