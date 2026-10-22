#!/bin/sh
# Nightly consistent backup of the VEN server database (ciphertext only).
# Cron (crontab -e as traceiq):  17 3 * * * /home/traceiq/ven/backup.sh
set -eu
DIR=/home/traceiq/ven
umask 077
mkdir -p "$DIR/backups"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
sqlite3 "$DIR/data/server.db" ".backup '$DIR/backups/server-$STAMP.db'"
gzip "$DIR/backups/server-$STAMP.db"
# Keep the 14 newest.
ls -1t "$DIR"/backups/server-*.db.gz | tail -n +15 | xargs -r rm --
