#!/usr/bin/env bash
# Known vulnerabilities in the OS packages (Debian, Alpine) of each AttackLedger image, and in the
# Go modules and Go standard library compiled into its Go binaries (docs/SUPPLY_CHAIN.md). Prints
# every HIGH and CRITICAL one, with the version that fixes it.
#
#   tools/scan_images.sh                          # the images tagged latest, and the pinned third-party ones
#   ATTACKLEDGER_SCAN_TAG=v0.9.0 tools/scan_images.sh
#   tools/scan_images.sh IMAGE...                 # these images only
#   ATTACKLEDGER_SCAN_JSON=DIR tools/scan_images.sh   # also keep Grype's full report per image there
#
# Exit status: 0 no HIGH or CRITICAL with a fix, 1 at least one with a fix (that is, an
# `apt-get`/`apk` upgrade, a newer base image or a newer release of the Go tool would remove it)
# that tools/scan_ignore.txt does not accept, or an entry of tools/scan_ignore.txt past its date
# (review it: delete the line, or renew it with a new date and reason), 2 the scan itself failed.
# HIGH and CRITICAL without a fix (Debian: "not fixed", "will not fix") are listed but do not fail
# it: there is nothing to move to.
#
# The scanner is Grype, run from its image pinned by digest. Its vulnerability database is
# downloaded first, in a container of its own, from Anchore (grype.anchore.io), into a Docker
# volume (ATTACKLEDGER_SCAN_DB_VOLUME, default attackledger-scan-db; `docker volume rm` it to
# drop the cache). The scans then run with no network. Only each image's package database
# (/etc/os-release, /var/lib/dpkg/status, /lib/apk/db/installed) and its Go binaries are copied
# out of it: the image is not run, and nothing is mounted from this machine. A Go binary is any
# executable file, wherever it is in the image, that carries Go's build information (the module
# list `go version -m` prints), found by reading the image's filesystem as `docker export` gives
# it (Caddy's /usr/bin/caddy, the worker's recon tools in /opt/pd/bin). Python and npm packages
# are checked by pip-audit and npm audit (docs/SUPPLY_CHAIN.md), not here.
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

# Reads an image's filesystem (a tar on stdin) and writes each Go binary in it under DIR, at its
# path in the image; prints the paths. Go's linker puts "\xff Go buildinf:" at the start of the
# build information it embeds, which is what Grype reads the module list from.
cat > "$WORK/gobin.py" <<'PY'
import os, sys, tarfile
out, magic, found = sys.argv[1], b"\xff Go buildinf:", []
with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as t:
    for m in t:
        if not m.isfile() or m.size < 64:
            continue
        f = t.extractfile(m)
        head = f.read(4)
        if head != b"\x7fELF":
            continue
        data, tail, hit = [head], b"", False
        while chunk := f.read(1 << 20):
            data.append(chunk)
            hit = hit or magic in tail + chunk
            tail = chunk[-len(magic):]
        if not hit:
            continue
        dest = os.path.join(out, m.name.lstrip("./"))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as w:
            w.write(b"".join(data))
        os.chmod(dest, 0o755)
        found.append("/" + m.name.lstrip("./"))
print(" ".join(found))
PY

if [ "$#" -gt 0 ]; then
  images=("$@")
else
  images=("attackledger-api:$TAG" "attackledger-worker:$TAG" "attackledger-web:$TAG")
  # The third-party images, by the digests the compose files pin.
  while read -r image; do images+=("$image"); done < <(
    grep -hoE 'image: [a-z0-9./-]+:[^ @]+@sha256:[0-9a-f]{64}' "$ROOT/docker-compose.yml" "$ROOT/deploy/compose.prod.yml" \
      | awk '{print $2}' | sort -u)
fi

# The scanner's own container: no capability, no privilege gain, a read-only root filesystem. Its
# one writable place is the database volume, mounted on /tmp: a new volume takes the mode of the
# image's /tmp (1777), so the scanner's user can write it.
HARDEN=(--read-only --cap-drop ALL --security-opt no-new-privileges:true -e GRYPE_CHECK_FOR_APP_UPDATE=false
        -e GRYPE_DB_CACHE_DIR=/tmp/db -v "$DB_VOLUME:/tmp")
docker run --rm "${HARDEN[@]}" "$GRYPE" db update -q >&2 \
  || fail "the vulnerability database could not be downloaded"
docker run --rm --network none "${HARDEN[@]}" -e GRYPE_DB_AUTO_UPDATE=false \
  "$GRYPE" db status >&2 || fail "no valid vulnerability database"

n=0
for image in "${images[@]}"; do
  docker image inspect "$image" >/dev/null 2>&1 || docker pull -q "$image" >/dev/null || fail "$image: not found (build it first)"
  n=$((n + 1)); dir="$WORK/$n"; mkdir -p "$dir/in/etc" "$dir/in/var/lib/dpkg" "$dir/in/lib/apk/db"
  cid="$(docker create "$image")"
  docker cp -L "$cid:/etc/os-release" "$dir/in/etc/os-release" 2>/dev/null || true
  docker cp -L "$cid:/var/lib/dpkg/status" "$dir/in/var/lib/dpkg/status" 2>/dev/null || true
  docker cp -L "$cid:/lib/apk/db/installed" "$dir/in/lib/apk/db/installed" 2>/dev/null || true
  gobins="$(docker export "$cid" | python3 -I "$WORK/gobin.py" "$dir/in")" || fail "$image: its filesystem could not be read"
  docker rm -f "$cid" >/dev/null; cid=""
  printf '%s\n' "$gobins" > "$dir/gobins"
  [ -s "$dir/in/etc/os-release" ] || fail "$image: no /etc/os-release"
  [ -s "$dir/in/var/lib/dpkg/status" ] || [ -s "$dir/in/lib/apk/db/installed" ] || fail "$image: no dpkg or apk database"
  # The package lists go into the scanner's container by `docker cp` (an anonymous volume, removed with it).
  cid="$(docker create --network none -v /scan "${HARDEN[@]}" -e GRYPE_DB_AUTO_UPDATE=false \
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
used = set()
for d in sorted((p for p in work.iterdir() if p.is_dir()), key=lambda p: int(p.name)):
    image = (d / "image").read_text().strip()
    doc = json.loads((d / "grype.json").read_text())
    distro = doc.get("distro") or {}
    gobins = (d / "gobins").read_text().split()
    pkgs = {(m["artifact"]["name"], m["artifact"]["version"]) for m in doc.get("matches", [])}
    rows, where = {}, {}
    for m in doc.get("matches", []):
        v, a = m["vulnerability"], m["artifact"]
        sev = v.get("severity", "Unknown")
        if sev not in ("High", "Critical"):
            continue
        fix = v.get("fix") or {}
        state, versions = fix.get("state", "unknown"), fix.get("versions") or []
        key = (v["id"], a["name"], a["version"])
        rows[key] = (sev, state, ", ".join(versions))
        if a.get("type") in ("go-module", "binary"):          # a Go module, or Go itself ("stdlib")
            where.setdefault(key, set()).update(Path(loc["path"]).name for loc in a.get("locations") or [])
    print(f"\n== {image} ({distro.get('name', '?')} {distro.get('version', '?')}"
          + (f"; {len(gobins)} Go binaries: {' '.join(sorted(Path(b).name for b in gobins))}" if gobins else "")
          + f"): {len(doc.get('matches', []))} matches in {len(pkgs)} packages, {len(rows)} HIGH or CRITICAL")
    for (vid, name, version), (sev, state, versions) in sorted(rows.items(), key=lambda r: (r[1][1] != "fixed", r[0])):
        if state == "fixed":
            hits = [(i, g, p) for i, g, p in ignores if vid == i and fnmatch.fnmatch(image, g) and name == p]
            used.update(hits)
            accepted += bool(hits)
            fixable += not hits
            what = f"fixed in {versions}" + (" (accepted in scan_ignore.txt)" if hits else "")
        else:
            unfixed += 1
            what = {"not-fixed": "no fix yet", "wont-fix": "will not be fixed (distribution)",
                    "unknown": "fix state unknown (no distribution record)"}.get(state, state)
        inside = f" [in {', '.join(sorted(where[(vid, name, version)]))}]" if (vid, name, version) in where else ""
        print(f"  {sev:8} {vid:20} {name} {version}{inside}: {what}")
for line in expired:
    print(f"[scan] FAIL: entry of scan_ignore.txt past its date (review it: delete the line, or renew "
          f"it with a new date and reason): {line}")
for entry in ignores:
    if entry not in used:
        print(f"[scan] note: scan_ignore.txt entry matched no finding in these images: {' '.join(entry)}")
print(f"\n[scan] {fixable} HIGH/CRITICAL with a fix, {accepted} accepted, {unfixed} without a fix, "
      f"{len(expired)} expired entries")
sys.exit(1 if fixable or expired else 0)
PY
