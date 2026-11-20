#!/bin/sh
# archive_command: push a WAL segment to S3 with WAL-G.
# Without WALG_S3_PREFIX backups are disabled and the segment is dropped
# (exit 0), so WAL does not pile up on disk.
[ -z "$WALG_S3_PREFIX" ] && exit 0
exec wal-g wal-push "$1"
