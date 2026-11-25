#!/bin/bash
# Creates the two database users (T2, #43). MySQL's official image runs this once, the
# first time it starts with an empty data volume, after it created the database
# (MYSQL_DATABASE). It uses the image's own docker_process_sql, which runs SQL as root on
# the setup server.
#
#   application user (MYSQL_APP_USER, default workforce_app): created with no rights at
#     all; every `alembic upgrade` then gives it exactly the data rights listed in
#     app/db/grants.py, table by table.
#   migrations user (MYSQL_MIGRATIONS_USER, default workforce_migrations): everything on
#     this one database, including handing out rights there (WITH GRANT OPTION), so the
#     migrations can grant the application user its rights. Used by Alembic only.
#   backup user (MYSQL_BACKUP_USER, default workforce_backup), only when
#     MYSQL_BACKUP_PASSWORD is set (#117, docs/operations/backup-and-restore.md): reads this
#     database and the binary log, and can change nothing. SELECT, SHOW VIEW, TRIGGER, and
#     EVENT let mysqldump read every table and definition; RELOAD lets it close the binary
#     log and take the brief read lock for a consistent snapshot; REPLICATION CLIENT and
#     REPLICATION SLAVE let it list and download the binary log files.
#
# The passwords come from the environment (the first two are required); nothing is
# stored here.

: "${MYSQL_DATABASE:?MYSQL_DATABASE must be set}"
: "${MYSQL_APP_PASSWORD:?MYSQL_APP_PASSWORD must be set}"
: "${MYSQL_MIGRATIONS_PASSWORD:?MYSQL_MIGRATIONS_PASSWORD must be set}"
app_user="${MYSQL_APP_USER:-workforce_app}"
migrations_user="${MYSQL_MIGRATIONS_USER:-workforce_migrations}"
backup_user="${MYSQL_BACKUP_USER:-workforce_backup}"

# Names go into the SQL text as they are, so only plain names are accepted.
for name in "$MYSQL_DATABASE" "$app_user" "$migrations_user" "$backup_user"; do
  if [[ ! "$name" =~ ^[A-Za-z0-9_]{1,32}$ ]]; then
    echo "not a plain name: $name" >&2
    exit 1
  fi
done

# A password as a quoted SQL string: backslashes and single quotes are escaped, so any
# character works in it (the integration test uses @ : / % # ?).
sql_string() {
  local value=${1//\\/\\\\}
  printf "'%s'" "${value//\'/\\\'}"
}

# The entrypoint sources a script that is not executable, so its functions are there;
# an executable one (as every file mounted from Windows looks) runs on its own. Then load
# the functions here: sourcing the entrypoint only defines them, it starts nothing.
if ! declare -F docker_process_sql >/dev/null; then
  # shellcheck source=/dev/null
  source /usr/local/bin/docker-entrypoint.sh
  SOCKET="${SOCKET:-/var/run/mysqld/mysqld.sock}"
fi

docker_process_sql <<SQL
CREATE USER '${app_user}'@'%' IDENTIFIED BY $(sql_string "$MYSQL_APP_PASSWORD");
CREATE USER '${migrations_user}'@'%' IDENTIFIED BY $(sql_string "$MYSQL_MIGRATIONS_PASSWORD");
GRANT ALL PRIVILEGES ON \`${MYSQL_DATABASE}\`.* TO '${migrations_user}'@'%' WITH GRANT OPTION;
SQL

# The backup user, if a password for it is given.
if [[ -n "${MYSQL_BACKUP_PASSWORD:-}" ]]; then
  docker_process_sql <<SQL
CREATE USER '${backup_user}'@'%' IDENTIFIED BY $(sql_string "$MYSQL_BACKUP_PASSWORD");
GRANT SELECT, SHOW VIEW, TRIGGER, EVENT ON \`${MYSQL_DATABASE}\`.* TO '${backup_user}'@'%';
GRANT RELOAD, REPLICATION CLIENT, REPLICATION SLAVE ON *.* TO '${backup_user}'@'%';
SQL
fi
