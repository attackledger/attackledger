#!/usr/bin/env bash
# Checks the GitHub Actions workflows (.github/workflows/) with actionlint: the syntax, the
# expressions, the action inputs, and every `run:` script with shellcheck (docs/SUPPLY_CHAIN.md).
# The CI runs it on every push (.github/workflows/tests.yml, job "workflows").
#
#   tools/lint_workflows.sh
#
# actionlint runs from its image, pinned by digest, with no network and no capability; the
# workflow files go in through stdin (a tar), so nothing is mounted from this machine.
# Exit status (actionlint's): 0 no problem found, 1 a problem, 2 or 3 actionlint could not run.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# actionlint 1.7.12 (2026-03-30), with shellcheck and pyflakes; the multi-arch index digest.
ACTIONLINT=rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667

COPYFILE_DISABLE=1 tar -c -C "$ROOT" .github/workflows | docker run --rm -i --network none --cap-drop ALL \
  --security-opt no-new-privileges:true --read-only --tmpfs /tmp:size=64m --entrypoint sh "$ACTIONLINT" -ec '
    mkdir /tmp/repo && cd /tmp/repo && tar -x
    actionlint -no-color .github/workflows/*.y*ml'
