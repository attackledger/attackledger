#!/usr/bin/env bash
# Back up an AttackLedger install: the Postgres database and the evidence blob store.
#
#   tools/backup.sh /var/backups/attackledger
#
# Run it from anywhere; it works on the install folder it lives in (or ATTACKLEDGER_DIR),
# with the same docker compose settings as that folder's .env. The stack must be running.
#
# Writes one folder per run, <dest>/attackledger-<UTC time>/, holding
#   postgres.dump      pg_dump custom format: a consistent snapshot of the whole database
#   blobs.tar.gz       the evidence blob store
#   info.txt           when, which migration, which Postgres, row and file counts
#   MANIFEST.sha256    the SHA-256 of each of the three, checked by tools/restore.sh
# The folder appears under its final name only when everything in it is complete.
#
# The database is dumped first and the blobs archived second. Blobs are content-addressed
# and written before the evidence row that cites them is committed, so every blob the dump
# refers to is already on disk when the archive starts: the archive may hold a few newer
# blobs, never fewer. Nothing has to be stopped.
#
# What is NOT in the backup, on purpose: .env (the secrets) and, once encryption at rest is
# installed, the master key. Keep those separately (docs/INSTALL.md, "Backup and restore").
#
# Compatible with bash 3.2 (macOS) and later. Stops at the first error.
set -euo pipefail

die() { echo "backup: $*" >&2; exit 1; }

[ $# -eq 1 ] || die "usage: tools/backup.sh DESTINATION_FOLDER"
DEST=$1

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  die "need sha256sum or shasum"
fi

HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "${ATTACKLEDGER_DIR:-$HERE}"
[ -f docker-compose.yml ] || die "no docker-compose.yml in $(pwd); set ATTACKLEDGER_DIR to the install folder"

dc() { docker compose "$@"; }

# Both services must be up: pg_dump runs in the database container, tar in the API's.
for svc in db api; do
  [ -n "$(dc ps --status running -q "$svc")" ] || die "the $svc service is not running (docker compose up -d)"
done

umask 077                      # the backup holds every engagement's data
mkdir -p "$DEST"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
FINAL="$DEST/attackledger-$STAMP"
[ ! -e "$FINAL" ] || die "$FINAL already exists"
WORK="$DEST/.attackledger-$STAMP.partial"
mkdir "$WORK"
# A failed run leaves nothing that looks like a backup.
trap 'rm -rf "$WORK"' EXIT

echo "backup: dumping the database"
dc exec -T db pg_dump -U attackledger -d attackledger --format=custom --no-owner > "$WORK/postgres.dump"
[ -s "$WORK/postgres.dump" ] || die "pg_dump wrote nothing"

echo "backup: archiving the blob store"
# Half-written blobs are temporary files named .<hash>.<pid>.tmp; they are not evidence yet.
dc exec -T api tar -C /data/blobs --exclude='.*.tmp' -czf - . > "$WORK/blobs.tar.gz"
[ -s "$WORK/blobs.tar.gz" ] || die "the blob archive is empty"

MIGRATION=$(dc exec -T api python -c "from app import migrate; print(migrate.current())" | tr -d '\r')
ROWS=$(dc exec -T db psql -U attackledger -d attackledger -tA -c \
  "select (select count(*) from engagements) || ' engagements, ' || (select count(*) from evidence) || ' evidence entries, ' || (select count(*) from receipts) || ' receipts, ' || (select count(*) from users) || ' people'" | tr -d '\r')
BLOBS=$(dc exec -T api sh -c "find /data/blobs -type f ! -name '.*.tmp' | wc -l" | tr -d ' \r')
PG=$(dc exec -T db postgres --version | tr -d '\r')
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)

cat > "$WORK/info.txt" <<EOF
format: attackledger-backup-v1
created_at: $STAMP
project: $(basename "$(pwd)")
code_commit: $COMMIT
migration: $MIGRATION
postgres: $PG
contents: $ROWS, $BLOBS blob files
not_included: .env and the encryption master key; keep them separately
EOF

( cd "$WORK"
  for f in postgres.dump blobs.tar.gz info.txt; do
    printf '%s  %s\n' "$(sha256 "$f")" "$f"
  done > MANIFEST.sha256 )

mv "$WORK" "$FINAL"
trap - EXIT
echo "backup: done: $FINAL"
echo "backup: $ROWS, $BLOBS blob files, migration $MIGRATION"
