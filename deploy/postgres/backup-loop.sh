#!/bin/sh
# Daily base backup + retention. Runs in the background of the postgres container.
[ -z "$WALG_S3_PREFIX" ] && { echo "backup-loop: WALG_S3_PREFIX not set, backups disabled"; exit 0; }
INTERVAL="${BACKUP_INTERVAL_SECONDS:-86400}"
KEEP="${BACKUP_RETAIN_FULL:-7}"
export PGHOST=/var/run/postgresql PGUSER="${POSTGRES_USER:-postgres}" PGDATABASE="${POSTGRES_DB:-${POSTGRES_USER:-postgres}}"
until pg_isready -q; do sleep 5; done
sleep 60
while true; do
  echo "backup-loop: starting base backup"
  if wal-g backup-push "$PGDATA"; then
    wal-g delete retain FULL "$KEEP" --confirm || true
    echo "backup-loop: base backup done"
  else
    echo "backup-loop: base backup FAILED" >&2
  fi
  sleep "$INTERVAL"
done
