#!/usr/bin/env bash
# Software bill of materials (CycloneDX JSON) for each AttackLedger image, made from the images
# themselves (docs/SUPPLY_CHAIN.md). Nothing is committed: the files go to OUT_DIR.
#
#   tools/sbom.sh [OUT_DIR]                      # default: ./sbom-<date>
#   ATTACKLEDGER_SBOM_TAG=v0.9.0 tools/sbom.sh   # images tagged other than "latest"
#
# Per image, one file per kind of component:
#   <image>.os.cdx.json         the Debian or Alpine packages (from the image's package database)
#   <image>.python.cdx.json     the Python packages installed (api image, which the gateway runs too, and worker)
#   worker.arjun.cdx.json       Arjun and its dependencies, from their lock
#   worker.go.<tool>.cdx.json   the Go modules compiled into each recon tool
#   web.npm.cdx.json            the npm packages in the web bundle (from web/package-lock.json)
# and, for the third-party images the compose files run (Postgres, nginx, Caddy), their OS packages.
#
# The generators run in throwaway containers, pinned to one version each, and are downloaded from
# the registries the build already uses (PyPI, the npm registry, the Go module proxy). The images
# are only read: nothing is installed into them or on this machine. Data goes in and out of the
# containers through stdin and stdout, never a bind mount, so it works with any Docker VM.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$PWD/sbom-$(date -u +%Y%m%d)}"
TAG="${ATTACKLEDGER_SBOM_TAG:-latest}"
CYCLONEDX_PY=7.4.0          # PyPI: cyclonedx-bom
CYCLONEDX_NPM=6.0.1         # npm: @cyclonedx/cyclonedx-npm
CYCLONEDX_GOMOD=v1.12.0     # Go: github.com/CycloneDX/cyclonedx-gomod
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
cid=""; trap '[ -z "$cid" ] || docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT

pin() { sed -n "s/^FROM \($1:[^ ]*@sha256:[0-9a-f]\{64\}\).*/\1/p" "$ROOT/$2" | head -1; }
PYTHON="$(pin python server/Dockerfile)"
GOLANG="$(pin golang worker/Dockerfile)"
NODE="$(pin node web/Dockerfile)"
[ -n "$PYTHON" ] && [ -n "$GOLANG" ] && [ -n "$NODE" ] || { echo "[sbom] base image pins not found" >&2; exit 1; }

# Writes stdin to $OUT/$1 if it is a CycloneDX document with at least one component (or with
# none, when $2 is "empty-ok": a Go tool that uses the standard library only).
save() {
  local tmp="$OUT/.$1.tmp"
  cat > "$tmp"
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d.get("bomFormat")=="CycloneDX"; sys.exit(0 if d.get("components") or sys.argv[2]=="empty-ok" else 1)' "$tmp" "${2:-}" \
    || { echo "[sbom] $1: no components, or not CycloneDX" >&2; rm -f "$tmp"; exit 1; }
  mv "$tmp" "$OUT/$1"
  echo "[sbom] $1: $(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1])).get("components") or []))' "$OUT/$1") components"
}

# OS packages: the package database is copied out of the image (which is not run) and converted.
os_sbom() {   # image, name
  cid="$(docker create "$1")"
  rm -rf "$OUT/.os"; mkdir -p "$OUT/.os"
  docker cp -L "$cid:/etc/os-release" "$OUT/.os/os-release" 2>/dev/null || true
  docker cp -L "$cid:/var/lib/dpkg/status" "$OUT/.os/dpkg" 2>/dev/null || true
  docker cp -L "$cid:/lib/apk/db/installed" "$OUT/.os/apk" 2>/dev/null || true
  docker rm -f "$cid" >/dev/null; cid=""
  tar -c -C "$OUT/.os" . | docker run --rm -i --network none -e IMAGE="$1" "$PYTHON" python -I -c '
import json, os, sys, tarfile, uuid, datetime
files = {}
with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as t:
    for m in t:
        if m.isfile():
            files[os.path.basename(m.name)] = t.extractfile(m).read().decode("utf-8", "replace")
osr = dict(l.split("=", 1) for l in files.get("os-release", "").splitlines() if "=" in l)
distro = osr.get("ID", "").strip().strip(chr(34))
comps = []
for block in files.get("dpkg", "").split("\n\n"):
    f = {k: v.strip() for k, v in (l.split(":", 1) for l in block.splitlines() if ":" in l and l[:1] not in " \t")}
    if "installed" in f.get("Status", "") and f.get("Package"):
        comps.append(("deb", f["Package"], f.get("Version", ""), f.get("Architecture", "")))
p = {}
for line in files.get("apk", "").splitlines() + [""]:
    if not line:
        if p.get("P"): comps.append(("apk", p["P"], p.get("V", ""), p.get("A", "")))
        p = {}
    elif line[1:2] == ":":
        p.setdefault(line[0], line[2:])
json.dump({"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": "urn:uuid:" + str(uuid.uuid4()), "version": 1,
           "metadata": {"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                        "component": {"type": "container", "name": os.environ["IMAGE"]},
                        "tools": {"components": [{"type": "application", "name": "AttackLedger tools/sbom.sh"}]}},
           "components": [{"type": "library", "name": n, "version": v,
                           "purl": f"pkg:{t}/{distro}/{n}@{v}" + (f"?arch={a}" if a else "")} for t, n, v, a in sorted(comps)]},
          sys.stdout, indent=1)
' | save "$2.os.cdx.json"
  rm -rf "$OUT/.os"
}

# Python packages, read by cyclonedx-py from a venv in the container's /tmp (the image is not changed).
python_sbom() {   # image, name, what: "environment" or a lock file in the image
  local what="$3" file="$2.python.cdx.json"
  [ "$what" = environment ] && what="environment /usr/local/bin/python" || { file="$2.arjun.cdx.json"; what="requirements $what"; }
  docker run --rm --user 0 --read-only --tmpfs /tmp:size=256m,exec -e HOME=/tmp --entrypoint sh "$1" -ec "
    python -m venv /tmp/sbom >/dev/null
    /tmp/sbom/bin/pip install -q --disable-pip-version-check cyclonedx-bom==$CYCLONEDX_PY >&2
    /tmp/sbom/bin/cyclonedx-py $what --of JSON -o -" | save "$file"
}

# Go modules of each recon tool, from the binaries' build information.
go_sbom() {   # image, name
  cid="$(docker create "$1")"
  docker cp "$cid:/opt/pd/bin" - > "$OUT/.bin.tar"
  docker rm -f "$cid" >/dev/null; cid=""
  mkdir -p "$OUT/.go"
  docker run --rm -i -e HOME=/tmp -e GOPATH=/tmp/go -e GOFLAGS=-trimpath -e GOTOOLCHAIN=local "$GOLANG" sh -ec "
    go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@$CYCLONEDX_GOMOD 2>/dev/null
    mkdir -p /tmp/in /tmp/out && tar -x -C /tmp/in
    for b in /tmp/in/bin/*; do
      t=\$(basename \$b)
      [ \"\$t\" = feroxbuster ] && continue      # Rust, without embedded dependency data
      /tmp/go/bin/cyclonedx-gomod bin -json -output /tmp/out/$2.go.\$t.cdx.json \$b >&2
    done
    tar -c -C /tmp/out ." < "$OUT/.bin.tar" | tar -x -C "$OUT/.go"
  rm -f "$OUT/.bin.tar"
  for f in "$OUT"/.go/*.cdx.json; do save "$(basename "$f")" empty-ok < "$f"; done
  rm -rf "$OUT/.go"
}

npm_sbom() {
  tar -c -C "$ROOT/web" package.json package-lock.json | docker run --rm -i -e HOME=/tmp -e npm_config_cache=/tmp/npm \
    -e npm_config_update_notifier=false "$NODE" sh -ec "
      mkdir /tmp/web && tar -x -C /tmp/web && cd /tmp/web
      npx --yes @cyclonedx/cyclonedx-npm@$CYCLONEDX_NPM --omit dev --package-lock-only \
        --output-format JSON --output-file - 2>/dev/null" | save web.npm.cdx.json
}

for svc in api worker web; do
  docker image inspect "attackledger-$svc:$TAG" >/dev/null 2>&1 || { echo "[sbom] build attackledger-$svc:$TAG first" >&2; exit 1; }
done
os_sbom "attackledger-api:$TAG" api
python_sbom "attackledger-api:$TAG" api environment
os_sbom "attackledger-worker:$TAG" worker
python_sbom "attackledger-worker:$TAG" worker environment
python_sbom "attackledger-worker:$TAG" worker /srv/requirements-arjun.txt
go_sbom "attackledger-worker:$TAG" worker
os_sbom "attackledger-web:$TAG" web
npm_sbom
# The third-party images, by the digests the compose files pin; not OWASP Juice Shop, the optional
# practice target (D-060), which is vulnerable on purpose and not part of what runs AttackLedger.
for image in $(grep -hoE 'image: [a-z0-9./-]+:[^ @]+@sha256:[0-9a-f]{64}' "$ROOT/docker-compose.yml" "$ROOT/deploy/compose.prod.yml" | awk '{print $2}' | grep -v '^bkimminich/juice-shop:' | sort -u); do
  docker image inspect "$image" >/dev/null 2>&1 || docker pull -q "$image" >/dev/null
  os_sbom "$image" "$(echo "${image%%:*}" | tr / _)"
done
echo "[sbom] written to $OUT"
