#!/bin/sh
# Confirms tools/ci/action-pins.txt against GitHub: each recorded commit must be the commit of
# the recorded tag in that action's repository. Needs the gh CLI (read-only API calls).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
fail=0
grep -v '^#' "$here/action-pins.txt" | while read -r action sha tag; do
  [ -n "$action" ] || continue
  repo=$(echo "$action" | cut -d/ -f1-2)
  got=$(gh api "repos/$repo/git/ref/tags/$tag" --jq '.object.sha + " " + .object.type')
  obj=${got% *}; kind=${got#* }
  if [ "$kind" = "tag" ]; then obj=$(gh api "repos/$repo/git/tags/$obj" --jq '.object.sha'); fi
  if [ "$obj" = "$sha" ]; then echo "ok    $action $tag"; else echo "WRONG $action $tag is $obj, not $sha"; exit 1; fi
done || fail=1
exit $fail
