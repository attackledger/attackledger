#!/usr/bin/env bash
# Restore an AttackLedger backup made by tools/backup.sh.
#
#   tools/restore.sh /var/backups/attackledger/attackledger-20261009T120000Z
#   tools/restore.sh --force /var/backups/attackledger/attackledger-20261009T120000Z
#
# Order of work, and where it stops:
#   1. checks MANIFEST.sha256: every part is present and has the recorded SHA-256. A backup
#      that fails this is not touched any further;
#   2. checks that this version of AttackLedger knows the backup's migration (a backup from
#      a newer version needs that version's code);
#   3. refuses to restore over a database that holds any rows, or a blob store that holds
#      any files, unless --force is given. A fresh install that only ran its migrations is
#      empty and needs no --force;
#   4. stops the API and the worker, replaces the database and the blob store with the
#      backup's, and starts the stack again. The API then migrates the restored database
#      forward to this version, as on any upgrade.
#
# The encryption master key is not in the backup; put the original one in place before
# restoring (docs/INSTALL.md, "Backup and restore"). The script works on the install folder
# it lives in (or ATTACKLEDGER_DIR). Compatible with bash 3.2 and later. Stops at the first error.
set -euo pipefail

die() { echo "restore: $*" >&2; exit 1; }

FORCE=0
if [ "${1:-}" = "--force" ]; then FORCE=1; shift; fi
[ $# -eq 1 ] || die "usage: tools/restore.sh [--force] BACKUP_FOLDER"
SRC=$(cd "$1" && pwd) || die "no such folder: $1"

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  die "need sha256sum or shasum"
fi

# ---- 1. the manifest -------------------------------------------------------------------
[ -f "$SRC/MANIFEST.sha256" ] || die "$SRC has no MANIFEST.sha256; is it a backup folder?"
seen=""
while read -r want name; do
  [ -n "${want:-}" ] || continue
  case "$name" in
    postgres.dump|blobs.tar.gz|info.txt) ;;
    *) die "the manifest lists an unexpected file: $name" ;;
  esac
  case " $seen " in *" $name "*) die "the manifest lists $name twice" ;; esac
  [ -f "$SRC/$name" ] || die "missing part: $name"
  got=$(sha256 "$SRC/$name")
  [ "$got" = "$want" ] || die "$name does not match the manifest (sha256 $got, expected $want): the backup is damaged or was changed"
  seen="$seen $name"
done < "$SRC/MANIFEST.sha256"
for name in postgres.dump blobs.tar.gz info.txt; do
  case " $seen " in *" $name "*) ;; *) die "the manifest does not cover $name" ;; esac
done
grep -qx 'format: attackledger-backup-v1' "$SRC/info.txt" || die "unknown backup format (info.txt)"
MIGRATION=$(sed -n 's/^migration: //p' "$SRC/info.txt")
[ -n "$MIGRATION" ] || die "info.txt names no migration"
echo "restore: manifest verified: $(sed -n 's/^contents: //p' "$SRC/info.txt"), migration $MIGRATION"

HERE=$(cd "$(dirname "$0")/.." && pwd)
cd "${ATTACKLEDGER_DIR:-$HERE}"
[ -f docker-compose.yml ] || die "no docker-compose.yml in $(pwd); set ATTACKLEDGER_DIR to the install folder"
dc() { docker compose "$@"; }

# ---- 2. the migration --------------------------------------------------------------------
dc run --rm --no-deps -T api python -c "
import sys
from alembic.script import ScriptDirectory
from app.migrate import _config
try:
    ScriptDirectory.from_config(_config()).get_revision(sys.argv[1])
except Exception:
    sys.exit('restore: this version does not know migration ' + sys.argv[1] + '; check out the version that made the backup (or a newer one)')
" "$MIGRATION"

# ---- 3. is the target empty? -------------------------------------------------------------
dc up -d --wait db
ROWS=$(dc exec -T db psql -U attackledger -d attackledger -tA -c "
  select coalesce(sum((xpath('/row/c/text()', query_to_xml(format('select count(*) as c from %I.%I', schemaname, tablename), false, true, '')))[1]::text::bigint), 0)
  from pg_tables where schemaname = 'public' and tablename <> 'alembic_version'" | tr -d '\r')
BLOBS=$(dc run --rm --no-deps -T --entrypoint sh api -c "find /data/blobs -type f | wc -l" | tr -d ' \r')
if [ "$ROWS" != "0" ] || [ "$BLOBS" != "0" ]; then
  if [ "$FORCE" != "1" ]; then
    die "this install is not empty ($ROWS database rows, $BLOBS blob files). Restoring replaces all of it. Back it up first, then run again with --force"
  fi
  echo "restore: --force: replacing $ROWS database rows and $BLOBS blob files"
fi

# ---- 4. replace ----------------------------------------------------------------------------
echo "restore: stopping the API and the worker"
dc stop api worker

echo "restore: restoring the database"
dc exec -T db psql -U attackledger -d attackledger -v ON_ERROR_STOP=1 -q \
  -c "drop schema public cascade" -c "create schema public"
dc exec -T db pg_restore -U attackledger -d attackledger --no-owner --exit-on-error < "$SRC/postgres.dump"

echo "restore: restoring the blob store"
dc run --rm --no-deps -T --entrypoint sh api -c \
  "find /data/blobs -mindepth 1 -delete && tar -C /data/blobs -xzf - && find /data/blobs -type f | wc -l" \
  < "$SRC/blobs.tar.gz" | tr -d ' \r' | sed 's/^/restore: blob files restored: /'

echo "restore: starting the stack"
dc up -d --wait
echo "restore: done. Sign in and check the engagements; tools/verify_report.py checks any report."
