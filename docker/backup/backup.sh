#!/bin/bash
# Backups and restores of the database (#117, decision 0028,
# docs/operations/backup-and-restore.md). Runs in the backup image (docker/backup).
#
#   backup.sh run       the service: ship the binary log every 5 minutes, a full backup
#                       every night (and at once if there is none yet), then prune
#   backup.sh full      one full backup now
#   backup.sh binlogs   ship the binary log now
#   backup.sh prune     remove backups past the retention rules
#   backup.sh list      what there is to restore from
#   backup.sh restore [--until "YYYY-MM-DD HH:MM:SS"]
#                       restore into the server at RESTORE_HOST, to the given UTC moment
#                       (the latest backed-up moment without --until)
#
# What a backup is, in a folder per database server (servers/<server_uuid>/):
#   full/<time>.sql.zst.cms   mysqldump of the database: one consistent snapshot (a single
#                             transaction), with the binary log position it was taken at
#   binlog/<name>.cms         one closed binary log file: every change after a snapshot
#   *.sha256                  each file's checksum, to notice damage before a restore
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

# Compress and encrypt standard input into <file>, written under a temporary name first
# so a half-written backup never looks finished; then its checksum next to it.
seal() {  # seal <file>
  [[ -r "$BACKUP_CERT" ]] || { log "no certificate at $BACKUP_CERT"; exit 1; }
  zstd -q -T0 \
    | openssl cms -encrypt -binary -aes-256-gcm -recip "$BACKUP_CERT" -outform DER -out "$1.part"
  mv "$1.part" "$1"
  (cd "$(dirname "$1")" && sha256sum "$(basename "$1")" > "$(basename "$1").sha256")
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
  local name full_dir
  full_dir="$(server_dir)/full"
  name="$(date -u +%Y%m%dT%H%M%SZ).sql.zst.cms"
  log "full backup: $name"
  # --single-transaction: one consistent snapshot, without locking the tables while it
  #   reads (all tables are InnoDB).
  # --source-data=2: the binary log position of that snapshot, as a comment at the top;
  #   a restore replays the binary log from exactly there.
  # --routines --triggers --events: everything else defined in the database.
  # --hex-blob: binary columns (the UUIDs) as hex, so nothing is changed in transit.
  # --no-tablespaces: tablespaces are server-wide, and the backup user may not read them.
  # --set-gtid-purged=OFF: the server does not use GTIDs, and a restore starts fresh.
  mysqldump --defaults-extra-file="$(source_client)" \
    --single-transaction --source-data=2 --routines --triggers --events \
    --hex-blob --no-tablespaces --set-gtid-purged=OFF \
    --databases "$MYSQL_DATABASE" \
    | seal "$full_dir/$name"
  date -u +%Y-%m-%d > "$STATE_DIR/last-full-day"
  log "full backup done: $name ($(stat -c %s "$full_dir/$name") bytes)"
}

ship_binlogs() {
  # Close the binary log file the server is writing, so everything up to now is in a
  # closed file; then download each closed file not shipped yet. The file the server
  # opens next is shipped next time, so at most BINLOG_EVERY seconds of changes are only
  # on the server (the 5 minutes of decision 0028).
  local binlog_dir names shipped=0
  binlog_dir="$(server_dir)/binlog"
  source_sql "FLUSH BINARY LOGS"
  mapfile -t names < <(source_sql "SHOW BINARY LOGS" | cut -f1)
  local current="${names[-1]}"
  for name in "${names[@]}"; do
    [[ "$name" == "$current" ]] && continue
    [[ -f "$binlog_dir/$name.cms" ]] && continue
    [[ "$name" =~ ^[A-Za-z0-9_.-]+$ ]] || { log "odd binary log name: $name"; exit 1; }
    # --raw writes the file exactly as the server has it.
    mysqlbinlog --defaults-extra-file="$(source_client)" \
      --read-from-remote-server --raw --result-file="$WORK_DIR/" "$name"
    seal "$binlog_dir/$name.cms" < "$WORK_DIR/$name"
    rm -f "$WORK_DIR/$name"
    shipped=$((shipped + 1))
  done
  touch "$STATE_DIR/last-binlog-ship"
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

run_service() {
  log "started: binary log every ${BINLOG_EVERY}s, full backup daily after ${FULL_AT_HOUR}:00 UTC"
  while true; do
    # Each step runs as its own process: inside "step || log", bash would stop treating
    # a failed command as fatal, and a half-done step could look finished. A failure is
    # logged and tried again next round; the health check turns red if the binary log
    # has not been shipped for 11 minutes.
    "$0" binlogs || log "ERROR: shipping the binary log failed"
    local today hour
    today="$(date -u +%Y-%m-%d)"
    hour="$(date -u +%-H)"
    if [[ ! -s "$STATE_DIR/last-full-day" ]] \
      || { [[ "$(cat "$STATE_DIR/last-full-day")" != "$today" ]] && (( hour >= FULL_AT_HOUR )); }; then
      { "$0" full && "$0" prune; } || log "ERROR: the full backup failed"
    fi
    sleep "$BINLOG_EVERY"
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

restore() {
  local until=""
  if [[ "${1:-}" == "--until" ]]; then
    until="${2:?--until needs a UTC time, YYYY-MM-DD HH:MM:SS}"
    [[ "$until" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}\ [0-9]{2}:[0-9]{2}:[0-9]{2}$ ]] \
      || { log "--until must look like 2026-11-25 14:30:00 (UTC)"; exit 1; }
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

  # 2. Load it. The binary log position it was taken at is in its first lines.
  local started
  started="$(date +%s)"
  unseal "$full" > "$WORK_DIR/full.sql"
  local position file_name position_number
  position="$(head -c 65536 "$WORK_DIR/full.sql" | grep -m1 -o "SOURCE_LOG_FILE='[^']*', SOURCE_LOG_POS=[0-9]*")"
  [[ -n "$position" ]] || { log "no binary log position in $(basename "$full")"; exit 1; }
  file_name="$(printf '%s' "$position" | sed "s/SOURCE_LOG_FILE='\([^']*\)'.*/\1/")"
  position_number="${position##*=}"
  mysql --defaults-extra-file="$target" < "$WORK_DIR/full.sql"
  rm -f "$WORK_DIR/full.sql"
  log "restore: full backup loaded in $(( $(date +%s) - started ))s (log position $file_name:$position_number)"

  # 3. Replay the binary log from that position to the moment. Only this database's
  #    changes are replayed (--database): the new server has its own users, and the
  #    migrate tool sets the application user's rights afterwards.
  started="$(date +%s)"
  local logs=()
  for file in "$(dirname "$(dirname "$full")")"/binlog/*.cms; do
    [[ -e "$file" ]] || continue
    name="$(basename "$file" .cms)"
    [[ "$name" < "$file_name" ]] && continue
    unseal "$file" > "$WORK_DIR/$name"
    logs+=("$WORK_DIR/$name")
  done
  if (( ${#logs[@]} )); then
    # --start-position applies to the first file only, which is the snapshot's file.
    mysqlbinlog --database="$MYSQL_DATABASE" --start-position="$position_number" \
      ${until:+--stop-datetime="$until"} "${logs[@]}" \
      | mysql --defaults-extra-file="$target"
  fi
  rm -f "${logs[@]}"
  log "restore: ${#logs[@]} binary log file(s) replayed in $(( $(date +%s) - started ))s"
  log "restore: done; next, run the migrate tool, then verify (the runbook's steps 5 and 6)"
}

# --- Command -----------------------------------------------------------------------------

case "${1:-run}" in
  run) run_service ;;
  full) full_backup ;;
  binlogs) ship_binlogs ;;
  prune) prune ;;
  list) list_backups ;;
  restore) shift; restore "$@" ;;
  *) echo "usage: backup.sh run | full | binlogs | prune | list | restore [--until TIME]" >&2; exit 2 ;;
esac
