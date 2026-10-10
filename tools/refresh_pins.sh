#!/usr/bin/env bash
# Which pinned base images are stale: for every digest-pinned image in a Dockerfile `FROM` or a
# compose `image:` (docs/SUPPLY_CHAIN.md), asks the registry for the digest its tag points at
# today and prints both. A pinned digest never picks up the security fixes of later builds of
# the same tag; this is how a maintainer sees which ones have moved.
#
#   tools/refresh_pins.sh            # report only; changes no file
#   tools/refresh_pins.sh --write    # also replace each stale digest with the tag's current one
#
# Exit status: 0 every pin is current, 1 at least one is stale (or was rewritten), 2 a lookup
# failed. After --write: update the version and date in the comment above each changed line
# (the script cannot know the image's release number), read `git diff`, rebuild the images and
# run the tests, as for any dependency change.
#
# Talks to the registries the images come from only (Docker Hub here), with HEAD requests on
# manifests, which Docker Hub does not count against its pull limit. Nothing is pulled and
# nothing runs. The digest it compares is the one of the tag's manifest itself: for a multi-arch
# image that is its index, as the pins are (a tag that resolves to a single-platform manifest
# is reported, since pinning it would stop the other architecture from building).
# The benchmark target (tools/benchmark/) is left out: it is pinned to one release on purpose,
# and its ground truth names that digest.
set -euo pipefail
cd "$(dirname "$0")/.."
case "${1:-}" in
  "") WRITE=0 ;;
  --write) WRITE=1 ;;
  *) echo "usage: tools/refresh_pins.sh [--write]" >&2; exit 2 ;;
esac

python3 -I - "$WRITE" <<'PY'
import json, re, subprocess, sys, urllib.error, urllib.parse, urllib.request
from pathlib import Path

WRITE = sys.argv[1] == "1"
INDEX_TYPES = ("application/vnd.oci.image.index.v1+json",
               "application/vnd.docker.distribution.manifest.list.v2+json")
ACCEPT = ", ".join(INDEX_TYPES + ("application/vnd.oci.image.manifest.v1+json",
                                  "application/vnd.docker.distribution.manifest.v2+json"))
PIN = re.compile(r"^(\s*(?:FROM\s+(?:--platform=\S+\s+)?|-?\s*image:\s*[\"']?))"
                 r"(?P<ref>[\w.\-/:]+?):(?P<tag>[\w.\-]+)@(?P<digest>sha256:[0-9a-f]{64})", re.I)


def wanted(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    if path.startswith("tools/benchmark/"):
        return False
    return name.startswith("Dockerfile") or bool(re.fullmatch(r"(docker-)?compose[\w.\-]*\.ya?ml", name))


def split(ref: str) -> tuple[str, str]:
    """Registry host and repository, with Docker Hub's defaults (python -> library/python)."""
    first, _, rest = ref.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        host, repo = first, rest
    else:
        host, repo = "registry-1.docker.io", ref
    if host in ("docker.io", "index.docker.io"):
        host = "registry-1.docker.io"
    if host == "registry-1.docker.io" and "/" not in repo:
        repo = "library/" + repo
    return host, repo


_tokens: dict[tuple[str, str], str] = {}


def head(host: str, repo: str, tag: str) -> tuple[str, str]:
    url = f"https://{host}/v2/{repo}/manifests/{urllib.parse.quote(tag)}"
    headers = {"Accept": ACCEPT}
    if (host, repo) in _tokens:
        headers["Authorization"] = "Bearer " + _tokens[(host, repo)]
    req = urllib.request.Request(url, method="HEAD", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.headers["Docker-Content-Digest"], r.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        challenge = e.headers.get("WWW-Authenticate", "")
        if e.code != 401 or (host, repo) in _tokens or not challenge.lower().startswith("bearer "):
            raise
        params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        q = urllib.parse.urlencode({"service": params.get("service", ""), "scope": f"repository:{repo}:pull"})
        with urllib.request.urlopen(f"{params['realm']}?{q}", timeout=30) as r:
            body = json.load(r)
        _tokens[(host, repo)] = body.get("token") or body["access_token"]
        return head(host, repo, tag)


current: dict[tuple[str, str], tuple[str, str]] = {}
stale = failed = 0
rows = []
tracked = subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=True).stdout.decode()
files = sorted(p for p in tracked.split("\0") if p and wanted(p))
for path in files:
    lines = Path(path).read_text().splitlines(keepends=True)
    changed = False
    for i, line in enumerate(lines):
        m = PIN.match(line)
        if not m:
            continue
        ref, tag, pinned = m["ref"], m["tag"], m["digest"]
        where = f"{path}:{i + 1}"
        try:
            if (ref, tag) not in current:
                current[(ref, tag)] = head(*split(ref), tag)
            now, ctype = current[(ref, tag)]
        except Exception as e:                  # noqa: BLE001 - reported, and the exit status says so
            failed += 1
            rows.append((where, f"{ref}:{tag}", pinned, f"lookup failed: {e}"))
            continue
        note = "" if ctype in INDEX_TYPES else f" (not a multi-arch index: {ctype or 'no type'})"
        if now == pinned:
            rows.append((where, f"{ref}:{tag}", pinned, "current" + note))
            continue
        stale += 1
        rows.append((where, f"{ref}:{tag}", pinned, f"STALE, the tag now points at {now}{note}"))
        if WRITE:
            lines[i] = line.replace(pinned, now, 1)
            changed = True
    if changed:
        Path(path).write_text("".join(lines))

for where, image, pinned, state in rows:
    print(f"{where:32} {image:28} {pinned[:19]}…  {state}")
print(f"{len(rows)} pins, {stale} stale, {failed} failed" + (" (stale ones rewritten)" if WRITE and stale else ""))
if WRITE and stale:
    print("now: update the version and date in the comment above each changed line, git diff, "
          "rebuild, run the tests")
sys.exit(2 if failed else 1 if stale else 0)
PY
