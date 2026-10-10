#!/usr/bin/env bash
# The server's tests on Postgres 16, as production runs, in one command (CONTRIBUTING.md).
#
#   tools/test_postgres.sh                 the whole suite, then the migration-0022 upgrade
#   tools/test_postgres.sh tests/test_x.py any pytest arguments instead of the whole suite
#
# It starts its own throwaway Postgres (data in memory, on a new internal Docker network, no
# port published on the host, a random password that is never printed) and removes it, the
# network and its temporary files when it ends, however it ends.
#
#  1. The suite with ATTACKLEDGER_TEST_PG (server/tests/testdb.py): every test gets new, empty
#     databases of its own. The server's TimeZone is not UTC (Asia/Tehran, +03:30), so a
#     time stored in a session's local zone shows.
#  2. The upgrade check of docs/ORGANIZATIONS.md ("Upgrading"): the 0.7.1 code (migration
#     0021) fills a database through its API (make_fixture.py), and test_org_migration.py
#     upgrades it with this code. Skipped, with a note, in a clone without that commit.
#
# Needs Docker, the postgres:16-alpine image and the API image (ATTACKLEDGER_TEST_IMAGE,
# default attackledger-api:latest; only its Python packages are used: the code is this tree).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${ATTACKLEDGER_TEST_IMAGE:-attackledger-api:latest}"
PG_IMAGE="${ATTACKLEDGER_TEST_PG_IMAGE:-postgres:16-alpine}"
RUN_AS="${ATTACKLEDGER_TEST_USER:-$(id -u):$(id -g)}"
OLD_CODE=ac64591                    # the commit at migration 0021 (make_fixture.py)

id="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
NET="al-pgtest-net-$id"
PG="al-pgtest-$id"
PGPASSWORD="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
export PGPASSWORD                   # handed to the containers by name, never on a command line
TMP="$(mktemp -d "$ROOT/.test-postgres.XXXXXX")"     # under the tree: Docker can mount it

cleanup() {
  docker rm -f -v "$PG" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$TMP"
  find "$ROOT/server" "$ROOT/worker" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
  rm -f "$ROOT/server/attackledger.db"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

echo "[pg] starting $PG_IMAGE ($PG, internal network $NET)"
docker network create --internal "$NET" >/dev/null
docker run -d --name "$PG" --network "$NET" --tmpfs /var/lib/postgresql/data:rw,size=1536m \
  -e POSTGRES_PASSWORD="$PGPASSWORD" "$PG_IMAGE" \
  -c fsync=off -c synchronous_commit=off -c full_page_writes=off -c max_connections=300 \
  -c timezone=Asia/Tehran >/dev/null
for _ in $(seq 1 120); do              # TCP answers only once the initial setup is done
  docker exec "$PG" psql -U postgres -h 127.0.0.1 -tAc "select 1" >/dev/null 2>&1 && break
  sleep 0.5
done
docker exec "$PG" psql -U postgres -h 127.0.0.1 -tAc "select 1" >/dev/null

URL="postgresql+psycopg://postgres@$PG:5432"
in_image() {   # in_image <docker run options...> -- <python arguments...>
  local opts=()
  while [ "$1" != "--" ]; do opts+=("$1"); shift; done
  shift
  docker run --rm --network "$NET" --user "$RUN_AS" -e PYTHONDONTWRITEBYTECODE=1 -e HOME=/tmp \
    -e PGPASSWORD "${opts[@]}" --entrypoint python "$IMAGE" "$@"
}

status=0
echo "[pg] 1/2 the suite on Postgres"
in_image -e ATTACKLEDGER_HOME=/w -e ATTACKLEDGER_TEST_PG="$URL/postgres" -v "$ROOT":/w -w /w/server -- \
  -m pytest -q -p no:cacheprovider "${@:-tests}" || status=1

if [ "$#" -gt 0 ]; then
  echo "[pg] 2/2 skipped: pytest arguments were given"
elif ! git -C "$ROOT" cat-file -e "$OLD_CODE^{commit}" 2>/dev/null; then
  echo "[pg] 2/2 skipped: commit $OLD_CODE (migration 0021) is not in this clone (git fetch --unshallow)"
else
  echo "[pg] 2/2 migration 0022 on a database the 0.7.1 code filled"
  mkdir -p "$TMP/old" "$TMP/fixture"
  git -C "$ROOT" archive "$OLD_CODE" | tar -x -C "$TMP/old"
  mkdir -p "$TMP/old/server/tests/data/org-migration"
  cp "$ROOT/server/tests/data/org-migration/make_fixture.py" "$TMP/old/server/tests/data/org-migration/"
  cp "$ROOT/server/tests/orgfill.py" "$TMP/old/server/tests/"
  chmod -R a+rwX "$TMP"
  docker exec "$PG" psql -U postgres -h 127.0.0.1 -qc "CREATE DATABASE al_at_0021" >/dev/null
  # PGTZ=UTC: the 0.7.1 code stored times in its session's zone, and this server's is not UTC.
  if in_image -e PGTZ=UTC -e DATABASE_URL="$URL/al_at_0021" -v "$TMP/old":/w -v "$TMP/fixture":/out -w /w/server -- \
       tests/data/org-migration/make_fixture.py /out/fx; then
    in_image -e ATTACKLEDGER_HOME=/w -e ATTACKLEDGER_TEST_PG_URL="$URL/al_at_0021" -e ATTACKLEDGER_TEST_PG_FIXTURE=/fx \
      -v "$ROOT":/w -v "$TMP/fixture/fx":/fx -w /w/server -- \
      -m pytest -q -p no:cacheprovider tests/test_org_migration.py || status=1
  else
    echo "[pg] FAIL: the 0.7.1 code could not fill the database"; status=1
  fi
fi

[ "$status" -eq 0 ] && echo "[pg] PASS" || echo "[pg] FAIL"
exit "$status"
