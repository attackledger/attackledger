#!/usr/bin/env bash
# Browser end-to-end security tests of the web app (docs/security-review/WEB_E2E.md).
#
# Builds this tree's API and web images, starts the database, the API and the web app as
# compose project "al-e2e" (its own containers, networks and volumes; no port published on
# the host, no gateway, worker or lab), and runs the Playwright suite in e2e/ in Chromium and
# Firefox, inside the Playwright image pinned in e2e/Dockerfile, on an internal network with
# no route out. Two phases:
#   1. token: the operator token signs in; e2e/tests/seed.ts fills the stack with hostile
#      content (and posts recon results as a worker would, with a worker token made here).
#   2. people: the first owner is created on the server the way docs/INSTALL.md section 9
#      says, with a password made here for this run; people mode, roles, sign-out, CSRF.
# Then it removes the containers, networks and volumes of project al-e2e, and nothing else.
# The tokens and passwords are random for each run and are never printed.
#
# Usage: tools/test_e2e.sh [--keep] [playwright test arguments...]
#   --keep   leave the stack running afterwards (tear it down with: tools/test_e2e.sh --down)
#   --down   only tear down a stack left by --keep
# Needs Docker with Compose 2.24 or later. About 3 minutes, more on the first build.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT=al-e2e
keep=0
if [ "${1:-}" = "--keep" ]; then keep=1; shift; fi

# Nothing from the caller's environment or an .env file decides how the test stack runs.
unset ATTACKLEDGER_API_TOKEN ATTACKLEDGER_WORKER_TOKEN ATTACKLEDGER_MASTER_KEY ATTACKLEDGER_MASTER_KEY_FILE \
      ATTACKLEDGER_DEV_KEY ATTACKLEDGER_TSA_URL ATTACKLEDGER_COOKIE_SECURE ATTACKLEDGER_REQUIRE_SIGN_IN \
      ANTHROPIC_API_KEY ATTACKLEDGER_GATEWAY_PASSIVE_HOSTS ATTACKLEDGER_AGENT_MODEL POSTGRES_PASSWORD COMPOSE_FILE \
      COMPOSE_PROJECT_NAME COMPOSE_PROFILES

TMP="$(mktemp -d "${TMPDIR:-/tmp}/al-e2e.XXXXXX")"
chmod 700 "$TMP"
ENV_FILE="$TMP/env"
rand() { od -An -N24 -tx1 /dev/urandom | tr -d ' \n'; }
{
  echo "E2E_API_TOKEN=$(rand)"
  echo "E2E_WORKER_TOKEN=$(rand)"
  echo "E2E_OWNER_EMAIL=owner@e2e.test"
  echo "E2E_OWNER_PASSWORD=$(rand)"
  echo "POSTGRES_PASSWORD=$(rand)"
} > "$ENV_FILE"

dc() {
  docker compose -p "$PROJECT" --project-directory "$ROOT" --env-file "$ENV_FILE" \
    -f "$ROOT/docker-compose.yml" -f "$ROOT/e2e/compose.e2e.yml" --profile runner "$@"
}

down() {
  # Only this project's containers, networks and volumes (al-e2e_*). Images are kept as a cache.
  dc down --volumes --remove-orphans --timeout 5 >/dev/null 2>&1 || true
}

cleanup() {
  status=$?
  if [ "$keep" -eq 1 ] && [ "$status" -eq 0 ]; then
    echo "[e2e] stack left running (project $PROJECT); tear it down with: tools/test_e2e.sh --down"
  else
    down
  fi
  rm -rf "$TMP"
  exit "$status"
}

if [ "${1:-}" = "--down" ]; then
  down
  rm -rf "$TMP"
  echo "[e2e] project $PROJECT removed"
  exit 0
fi
trap cleanup EXIT

echo "[e2e] removing what an earlier run of project $PROJECT left"
down

echo "[e2e] building the API, web and runner images"
dc build --quiet api web runner

echo "[e2e] starting the database, the API and the web app"
dc up -d --wait --wait-timeout 180 db api web

run_phase() {
  local phase="$1"; shift
  echo "[e2e] phase $phase: Chromium and Firefox"
  dc run --rm --no-deps -e E2E_PHASE="$phase" runner npx playwright test --pass-with-no-tests "$@"
}

run_phase token "$@"

echo "[e2e] creating the first owner on the server (docs/INSTALL.md section 9)"
# The password reaches the command in an environment variable, never as an argument.
# shellcheck disable=SC1090
( set -a; . "$ENV_FILE"; set +a
  ATTACKLEDGER_NEW_PASSWORD="$E2E_OWNER_PASSWORD" dc exec -T -e ATTACKLEDGER_NEW_PASSWORD api \
    python -m app.people create --owner --email "$E2E_OWNER_EMAIL" --name "E2E Owner" >/dev/null )

run_phase people "$@"
echo "[e2e] PASS"
