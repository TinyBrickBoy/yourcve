#!/bin/sh
# Start the backup loop as the postgres user next to the official entrypoint.
if [ "$(id -u)" = "0" ]; then
  su postgres -s /bin/sh -c "PGDATA=$PGDATA /usr/local/bin/backup-loop.sh" &
else
  /usr/local/bin/backup-loop.sh &
fi
exec docker-entrypoint.sh "$@"
