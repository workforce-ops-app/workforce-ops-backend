#!/bin/bash
# Backups and restores of the database (#117, decision 0028,
# docs/operations/backup-and-restore.md). Runs in the backup image (docker/backup).
#
#   backup.sh run       the service: ship the binary log every 5 minutes, and on its own
#                       schedule a full backup every night (and at once if the server has
#                       none yet), then prune
#   backup.sh full      one full backup now
#   backup.sh nightly   a full backup and a prune if the server is due one
#   backup.sh binlogs   ship the binary log now
#   backup.sh prune     remove backups past the retention rules
#   backup.sh list      what there is to restore from
#   backup.sh restore [--until "YYYY-MM-DD HH:MM:SS"]
#                       restore into the server at RESTORE_HOST, to the given UTC moment
#                       (the latest backed-up moment without --until). Refused, before
#                       anything is written, if the backups cannot reach that moment
#   backup.sh restore --snapshot-only
#                       only the newest full backup, to the moment it was taken: for when
#                       its binary log never reached the backups
#
# What a backup is, in a folder per database server (servers/<server_uuid>/):
#   full/<time>.sql.zst.cms   mysqldump of the database: one consistent snapshot (a single
#                             transaction), with the binary log position it was taken at
#   binlog/<name>.cms         one closed binary log file: every change after a snapshot
#   *.sha256                  each file's checksum, to notice damage before a restore
#   last-full-day, last-binlog-ship   when this server last had each (freshness)
# A folder per server because a server that a backup was restored into is a new server:
# it numbers its binary log from binlog.000001 again, and those files must not be taken
# for the old server's files of the same name.
# Everything is compressed (zstd) and encrypted (OpenSSL CMS, AES-256-GCM) to the public
# certificate in BACKUP_CERT. Only the matching private key (BACKUP_KEY, kept off this
# machine) can read a backup, so someone who breaks into the server cannot read them, and
# GCM notices any change to an encrypted file.
#
# Settings (environment):
#   MYSQL_HOST, MYSQL_PORT (db, 3306)     the database server to back up
#   MYSQL_DATABASE (workforce_ops)        the database
#   MYSQL_BACKUP_USER (workforce_backup), MYSQL_BACKUP_PASSWORD   the backup user
#   BACKUP_CERT (/run/backup/backup-cert.pem)   the public certificate to encrypt to
#   BACKUP_DIR (/backups)                 where backups are written
#   BINLOG_EVERY (300)                    seconds between binary log shipments
#   FULL_AT_HOUR (2)                      the UTC hour after which the nightly full runs
#   KEEP_DAILY_DAYS (30), KEEP_WEEKLY_DAYS (92)   retention (Sunday's full is the weekly)
# For a restore, also:
#   BACKUP_KEY (/run/backup/backup-key.pem)     the private key
#   RESTORE_HOST, RESTORE_PORT (3306), RESTORE_USER (root), RESTORE_PASSWORD
#                                         the new, empty server to restore into

set -euo pipefail
umask 077  # every file written here is readable by this user only

MYSQL_HOST="${MYSQL_HOST:-db}"
MYSQL_PORT="${MYSQL_PORT:-3306}"
MYSQL_DATABASE="${MYSQL_DATABASE:-workforce_ops}"
MYSQL_BACKUP_USER="${MYSQL_BACKUP_USER:-workforce_backup}"
BACKUP_CERT="${BACKUP_CERT:-/run/backup/backup-cert.pem}"
BACKUP_KEY="${BACKUP_KEY:-/run/backup/backup-key.pem}"
BACKUP_DIR="${BACKUP_DIR:-/backups}"
BINLOG_EVERY="${BINLOG_EVERY:-300}"
FULL_AT_HOUR="${FULL_AT_HOUR:-2}"
KEEP_DAILY_DAYS="${KEEP_DAILY_DAYS:-30}"
KEEP_WEEKLY_DAYS="${KEEP_WEEKLY_DAYS:-92}"

SERVERS_DIR="$BACKUP_DIR/servers"
STATE_DIR="$BACKUP_DIR/state"
WORK_DIR="$(mktemp -d)"  # plain-text pieces live here only briefly, and are removed
trap 'rm -rf "$WORK_DIR"' EXIT
mkdir -p "$SERVERS_DIR" "$STATE_DIR"

log() { printf '%s backup: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }

# The database name goes into SQL and command lines as it is: plain names only.
[[ "$MYSQL_DATABASE" =~ ^[A-Za-z0-9_]{1,64}$ ]] || { log "not a plain name: $MYSQL_DATABASE"; exit 1; }

# --- Connecting ----------------------------------------------------------------------

# A client options file with the password, so it never appears in a command line (where
# any process on the machine could read it).
client_file() {  # client_file <file> <host> <port> <user> <password>
  {
    printf '[client]\nhost=%s\nport=%s\nuser=%s\n' "$2" "$3" "$4"
    printf 'password="%s"\n' "$(printf '%s' "$5" | sed 's/\\/\\\\/g; s/"/\\"/g')"
  } > "$1"
}

source_client() {
  local file="$WORK_DIR/source.cnf"
  if [[ ! -f "$file" ]]; then
    : "${MYSQL_BACKUP_PASSWORD:?set MYSQL_BACKUP_PASSWORD}"
    client_file "$file" "$MYSQL_HOST" "$MYSQL_PORT" "$MYSQL_BACKUP_USER" "$MYSQL_BACKUP_PASSWORD"
  fi
  printf '%s' "$file"
}

source_sql() { mysql --defaults-extra-file="$(source_client)" -N -B -e "$1"; }

# The folder of the server being backed up: servers/<its server_uuid>, made on first use.
server_dir() {
  local uuid
  uuid="$(source_sql "SELECT @@server_uuid")"
  [[ "$uuid" =~ ^[0-9a-f-]{36}$ ]] || { log "odd server_uuid: $uuid"; exit 1; }
  mkdir -p "$SERVERS_DIR/$uuid/full" "$SERVERS_DIR/$uuid/binlog"
  printf '%s' "$SERVERS_DIR/$uuid"
}

# --- Encrypting ------------------------------------------------------------------------

# Compress and encrypt standard input into <file>.part. Nothing is published here: in
# "producer | seal", seal cannot know whether the producer finished or failed halfway (a
# pipeline's status is known only once every part has ended), so the caller publishes
# the file only after the whole pipeline succeeded (review of #205).
seal() {  # seal <file>
  [[ -r "$BACKUP_CERT" ]] || { log "no certificate at $BACKUP_CERT"; exit 1; }
  zstd -q -T0 \
    | openssl cms -encrypt -binary -aes-256-gcm -recip "$BACKUP_CERT" -outform DER -out "$1.part"
}

# Make a sealed <file>.part a finished backup. The checksum is written first (as
# <file>.sha256, under the finished file's name) and the file is renamed last, in one
# step: the rename is the moment the backup exists, so a stop anywhere before it leaves
# no <file> at all, and the next run makes it again (second review of #205).
publish() {  # publish <file>
  local name digest
  name="$(basename "$1")"
  digest="$(sha256sum < "$1.part" | cut -d' ' -f1)"
  printf '%s  %s\n' "$digest" "$name" > "$1.sha256.part"
  mv "$1.sha256.part" "$1.sha256"
  mv "$1.part" "$1"
}

# Whether <file> is a finished backup: the file, its checksum, and the two agree.
published() {  # published <file>
  [[ -f "$1" && -f "$1.sha256" ]] \
    && (cd "$(dirname "$1")" && sha256sum --quiet -c "$(basename "$1").sha256" >/dev/null 2>&1)
}

# Check a backup file's checksum, then decrypt and decompress it to standard output.
unseal() {  # unseal <file>
  [[ -r "$BACKUP_KEY" ]] || { log "no private key at $BACKUP_KEY"; exit 1; }
  (cd "$(dirname "$1")" && sha256sum --quiet -c "$(basename "$1").sha256") \
    || { log "checksum does not match: $1"; exit 1; }
  openssl cms -decrypt -binary -inform DER -in "$1" -inkey "$BACKUP_KEY" | zstd -q -d
}

# --- Backing up ------------------------------------------------------------------------

full_backup() {
  local name dir
  dir="$(server_dir)"
  name="$(date -u +%Y%m%dT%H%M%SZ).sql.zst.cms"
  log "full backup: $name"
  # --single-transaction: one consistent snapshot, without locking the tables while it
  #   reads (all tables are InnoDB).
  # --source-data=2: the binary log position of that snapshot, as a comment at the top;
  #   a restore replays the binary log from exactly there.
  # --skip-triggers, and no --routines or --events: the database defines tables only
  #   (scripts/check_migrations.py fails if a trigger, event, or routine appears), so the
  #   backup user needs no TRIGGER or EVENT right, which could change definitions.
  # --hex-blob: binary columns (the UUIDs) as hex, so nothing is changed in transit.
  # --no-tablespaces: tablespaces are server-wide, and the backup user may not read them.
  # --set-gtid-purged=OFF: the server does not use GTIDs, and a restore starts fresh.
  # Published only if mysqldump and the sealing all succeeded (pipefail): a dump that
  # stopped halfway leaves no backup behind, only its .part, which is removed.
  if ! mysqldump --defaults-extra-file="$(source_client)" \
    --single-transaction --source-data=2 --skip-triggers \
    --hex-blob --no-tablespaces --set-gtid-purged=OFF \
    --databases "$MYSQL_DATABASE" \
    | seal "$dir/full/$name"; then
    rm -f "$dir/full/$name.part"
    log "full backup failed: $name not kept"
    exit 1
  fi
  publish "$dir/full/$name"
  date -u +%Y-%m-%d > "$dir/last-full-day"
  log "full backup done: $name ($(stat -c %s "$dir/full/$name") bytes)"
}

# The nightly full backup and prune, if this server is due one: none yet (a server a
# backup was restored into starts with none, so it gets one at once), or none today and
# it is past FULL_AT_HOUR. Freshness is per server, in its own folder.
nightly() {
  local dir today
  dir="$(server_dir)"
  today="$(date -u +%Y-%m-%d)"
  if [[ ! -s "$dir/last-full-day" ]] \
    || { [[ "$(cat "$dir/last-full-day")" != "$today" ]] && (( $(date -u +%-H) >= FULL_AT_HOUR )); }; then
    "$0" full
    "$0" prune
  fi
}

ship_binlogs() {
  # Close the binary log file the server is writing, so everything up to now is in a
  # closed file; then download each closed file not shipped yet. The file the server
  # opens next is shipped next time, so at most BINLOG_EVERY seconds of changes are only
  # on the server (the 5 minutes of decision 0028).
  local dir binlog_dir names shipped=0
  dir="$(server_dir)"
  binlog_dir="$dir/binlog"
  source_sql "FLUSH BINARY LOGS"
  mapfile -t names < <(source_sql "SHOW BINARY LOGS" | cut -f1)
  local current="${names[-1]}"
  for name in "${names[@]}"; do
    [[ "$name" == "$current" ]] && continue
    [[ "$name" =~ ^[A-Za-z0-9_.-]+$ ]] || { log "odd binary log name: $name"; exit 1; }
    # Skipped only if shipped whole: the file and a checksum that matches it (second
    # review of #205). Anything less (a run stopped while publishing, or a damaged
    # copy) is shipped again while the server still has the file.
    published "$binlog_dir/$name.cms" && continue
    rm -f "$binlog_dir/$name.cms" "$binlog_dir/$name.cms.sha256" "$binlog_dir/$name.cms.sha256.part"
    # --raw writes the file exactly as the server has it.
    mysqlbinlog --defaults-extra-file="$(source_client)" \
      --read-from-remote-server --raw --result-file="$WORK_DIR/" "$name"
    seal "$binlog_dir/$name.cms" < "$WORK_DIR/$name"
    publish "$binlog_dir/$name.cms"
    rm -f "$WORK_DIR/$name"
    shipped=$((shipped + 1))
  done
  # Freshness, per server; the health check reads the server being backed up now.
  touch "$dir/last-binlog-ship"
  basename "$dir" > "$STATE_DIR/current-server"
  log "binary log shipped: $shipped file(s)"
}

prune() {
  # Fulls: every one from the last KEEP_DAILY_DAYS days, and Sunday's up to
  # KEEP_WEEKLY_DAYS. Binary logs: KEEP_DAILY_DAYS days, the span a restore to any
  # minute covers. (On write-once storage the storage's own retention does this.)
  local now file day age
  now="$(date -u +%s)"
  for file in "$SERVERS_DIR"/*/full/*.sql.zst.cms; do
    [[ -e "$file" ]] || continue
    day="$(basename "$file" | cut -c1-8)"
    age=$(( (now - $(date -u -d "$day" +%s)) / 86400 ))
    if (( age > KEEP_WEEKLY_DAYS )) || { (( age > KEEP_DAILY_DAYS )) && [[ "$(date -u -d "$day" +%u)" != 7 ]]; }; then
      log "prune: $(basename "$file")"
      rm -f "$file" "$file.sha256"
    fi
  done
  find "$SERVERS_DIR" -path '*/binlog/*.cms' -mtime +"$KEEP_DAILY_DAYS" -print -exec rm -f {} {}.sha256 \; \
    | sed 's/^/prune: /' >&2
}

# Shipping the binary log, every BINLOG_EVERY seconds, in a process of its own.
ship_loop() {
  while true; do
    "$0" binlogs || log "ERROR: shipping the binary log failed"
    sleep "$BINLOG_EVERY"
  done
}

run_service() {
  log "started: binary log every ${BINLOG_EVERY}s, full backup daily after ${FULL_AT_HOUR}:00 UTC"
  # Two schedules, so a long full backup never holds up the binary log, which must leave
  # the server every 5 minutes (decision 0028; review of #205): shipping runs in its own
  # process, and this one checks once a minute whether a full backup is due.
  # Each step runs as its own process ("$0" ...): inside "step || log", bash would stop
  # treating a failed command as fatal, and a half-done step could look finished. A
  # failure is logged and tried again next round; the health check turns red if the
  # binary log has not been shipped for 11 minutes.
  ship_loop &
  local shipper=$!
  trap 'kill "$shipper" 2>/dev/null; rm -rf "$WORK_DIR"' EXIT
  while true; do
    # If shipping ever stopped, stop the service too, so the container restarts it.
    kill -0 "$shipper" 2>/dev/null || { log "ERROR: the binary log shipping stopped"; exit 1; }
    "$0" nightly || log "ERROR: the full backup failed"
    sleep 60
  done
}

list_backups() {
  local dir found=0
  for dir in "$SERVERS_DIR"/*/; do
    [[ -d "$dir/full" ]] || continue
    found=1
    echo "server $(basename "$dir"):"
    echo "  full backups: $(ls -1 "$dir/full" | grep '\.cms$' | tr '\n' ' ')"
    echo "  binary log files: $(ls -1 "$dir/binlog" | grep -c '\.cms$' || true)"
  done
  (( found )) || echo "no backups yet"
}

# --- Restoring -------------------------------------------------------------------------

# The time of the last event in a binary log file, as "YYYY-MM-DD HH:MM:SS" (UTC: the
# image runs in UTC). A shipped file was closed by FLUSH BINARY LOGS, and its last event
# is that closing, so this is how far the file reaches. mysqlbinlog prints each event's
# time as "#YYMMDD HH:MM:SS server id ...", the hour padded with a space.
log_reaches() {  # log_reaches <plain binary log file>
  mysqlbinlog "$1" \
    | sed -n 's/^#\([0-9]\{2\}\)\([0-9]\{2\}\)\([0-9]\{2\}\) *\([0-9]\{1,2\}\):\([0-9]\{2\}\):\([0-9]\{2\}\) server id.*/20\1-\2-\3 \4:\5:\6/p' \
    | tail -n 1 \
    | awk '{ split($2, t, ":"); printf "%s %02d:%s:%s\n", $1, t[1], t[2], t[3] }'
}

# Refuse a restore: nothing has been written to the new server yet.
refuse() { log "restore refused, nothing was written: $*"; exit 1; }

restore() {
  local until="" snapshot_only=0
  if [[ "${1:-}" == "--until" ]]; then
    until="${2:?--until needs a UTC time, YYYY-MM-DD HH:MM:SS}"
    [[ "$until" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}\ [0-9]{2}:[0-9]{2}:[0-9]{2}$ ]] \
      || { log "--until must look like 2026-11-25 14:30:00 (UTC)"; exit 1; }
  elif [[ "${1:-}" == "--snapshot-only" ]]; then
    snapshot_only=1
  fi
  : "${RESTORE_HOST:?set RESTORE_HOST: the new, empty server to restore into}"
  : "${RESTORE_PASSWORD:?set RESTORE_PASSWORD}"
  local target="$WORK_DIR/target.cnf"
  client_file "$target" "$RESTORE_HOST" "${RESTORE_PORT:-3306}" "${RESTORE_USER:-root}" "$RESTORE_PASSWORD"

  # 1. The newest full backup taken before the moment, from any server (file names are
  #    UTC times), and the binary log of the server it came from.
  local full="" best="" file stamp limit
  limit="$(printf '%s' "${until:-9999-12-31 23:59:59}" | tr -d ' :-')"
  for file in "$SERVERS_DIR"/*/full/*.sql.zst.cms; do
    [[ -e "$file" ]] || continue
    stamp="$(basename "$file" | cut -c1-8,10-15)"
    if [[ ! "$stamp" > "$limit" && ( -z "$best" || "$stamp" > "$best" ) ]]; then
      best="$stamp"
      full="$file"
    fi
  done
  [[ -n "$full" ]] || { log "no full backup before ${until:-now}"; exit 1; }
  log "restore: from $(basename "$full")${until:+, until $until UTC}"

  # 2. Read it, and check it is whole: mysqldump ends a dump it finished with "-- Dump
  #    completed". The binary log position it was taken at is in its first lines.
  unseal "$full" > "$WORK_DIR/full.sql"
  tail -n 1 "$WORK_DIR/full.sql" | grep -q '^-- Dump completed' \
    || refuse "$(basename "$full") is not a whole dump"
  local position file_name position_number
  position="$(head -c 65536 "$WORK_DIR/full.sql" | grep -m1 -o "SOURCE_LOG_FILE='[^']*', SOURCE_LOG_POS=[0-9]*")" \
    || refuse "no binary log position in $(basename "$full")"
  file_name="$(printf '%s' "$position" | sed "s/SOURCE_LOG_FILE='\([^']*\)'.*/\1/")"
  position_number="${position##*=}"

  # 3. The binary log from the snapshot on, checked whole before anything is written
  #    (review of #205): the snapshot's own file must be there, every file after it with
  #    no number missing, and the last one must reach the moment asked for. Otherwise
  #    the restore would end earlier than asked and look as if it had worked.
  local logs=() reached="" name number expected=""
  if (( ! snapshot_only )); then
    for file in "$(dirname "$(dirname "$full")")"/binlog/*.cms; do
      [[ -e "$file" ]] || continue
      name="$(basename "$file" .cms)"
      [[ "$name" < "$file_name" ]] && continue
      number=$((10#${name##*.}))
      if [[ -z "$expected" ]]; then
        [[ "$name" == "$file_name" ]] \
          || refuse "$file_name, where the snapshot starts, was never shipped (the first file there is $name); use --snapshot-only to restore the full backup alone"
      elif (( number != expected )); then
        refuse "the binary log has a gap: $(printf '%s.%06d' "${name%.*}" "$expected") is missing before $name"
      fi
      expected=$((number + 1))
      unseal "$file" > "$WORK_DIR/$name"
      logs+=("$WORK_DIR/$name")
    done
    (( ${#logs[@]} )) \
      || refuse "$file_name, where the snapshot starts, was never shipped; use --snapshot-only to restore the full backup alone"
    reached="$(log_reaches "${logs[-1]}")"
    [[ -n "$reached" ]] || refuse "cannot read how far $(basename "${logs[-1]}") reaches"
    if [[ -n "$until" && "$until" > "$reached" ]]; then
      refuse "the backed-up binary log reaches only $reached UTC, before $until; choose an earlier --until, or wait for the next shipment"
    fi
  fi

  # 4. Load the full backup.
  local started
  started="$(date +%s)"
  mysql --defaults-extra-file="$target" < "$WORK_DIR/full.sql"
  rm -f "$WORK_DIR/full.sql"
  log "restore: full backup loaded in $(( $(date +%s) - started ))s (log position $file_name:$position_number)"
  if (( snapshot_only )); then
    log "restore: done, to the moment of $(basename "$full") only (--snapshot-only); next, run the migrate tool, then verify (the runbook's steps 5 and 6)"
    return
  fi

  # 5. Replay the binary log from that position to the moment. Only this database's
  #    changes are replayed (--database): the new server has its own users, and the
  #    migrate tool sets the application user's rights afterwards.
  started="$(date +%s)"
  if (( ${#logs[@]} )); then
    # --start-position applies to the first file only, which is the snapshot's file.
    mysqlbinlog --database="$MYSQL_DATABASE" --start-position="$position_number" \
      ${until:+--stop-datetime="$until"} "${logs[@]}" \
      | mysql --defaults-extra-file="$target"
  fi
  rm -f "${logs[@]}"
  log "restore: ${#logs[@]} binary log file(s) replayed in $(( $(date +%s) - started ))s"
  log "restore: done, to ${until:-$reached} UTC; next, run the migrate tool, then verify (the runbook's steps 5 and 6)"
}

# --- Command -----------------------------------------------------------------------------

case "${1:-run}" in
  run) run_service ;;
  full) full_backup ;;
  nightly) nightly ;;
  binlogs) ship_binlogs ;;
  prune) prune ;;
  list) list_backups ;;
  restore) shift; restore "$@" ;;
  *) echo "usage: backup.sh run | full | nightly | binlogs | prune | list | restore [--until TIME | --snapshot-only]" >&2; exit 2 ;;
esac
