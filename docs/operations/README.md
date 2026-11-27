# Operations

**In short:** how to keep the system running and bring it back when something goes wrong: backups, restores, and (later) deployment.

New procedures start from the [runbook template](https://github.com/workforce-ops-app/.github/blob/main/docs/templates/runbook.md). Targets and rules are in [decision 0028](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0028-backup-and-recovery.md): lose at most 5 minutes of data, be running again within 4 hours, and practise restores.

## Database users

The application, the migrations, and the backups use three different database users ([contributor guide: database users](../contributing/README.md#database-users), #43):

- The **application user** may only read and write data, table by table (`app/db/grants.py`): no structure changes, and only adding to the audit log. It is the only database user the running API gets.
- The **migrations user** may change the structure of this one database and hand out rights in it. Use it only to apply migrations (`alembic upgrade head`, or `docker compose run --rm migrate`); each upgrade then resets the application user's rights to the list.
- On a new server, create both users before the first migration, as `docker/mysql/init/01-users.sh` does, and keep the two passwords in separate places: whoever runs the API never needs the migrations password.
- The **backup user** (#117) may only read this database and the binary log; it can change nothing. It is created on the first start when `MYSQL_BACKUP_PASSWORD` is set ([backup and restore](backup-and-restore.md#set-up-backups-once-per-machine)).
- Do not grant the application user rights by hand: the next upgrade takes away whatever the list does not say. To change its rights, change the list and run an upgrade.

## Procedures

| Procedure | Tier | Status |
|---|---|---|
| [Back up the database](backup-and-restore.md#set-up-backups-once-per-machine) (nightly full, binary log every 5 minutes, encrypted; #117) | next | done; the write-once copy off the machine waits for hosting |
| [Restore from a backup](backup-and-restore.md#restore) (to any second; timed drill, audit chains verified afterwards) | next | done; drilled 2026-11-25, next drill due 2026-12-25 |
| Rotate secrets (database passwords, audit signing key, CSRF key) | next | to do |
| Deploy | not decided | no hosting target yet; the [deploy workflow](../../.github/workflows/deploy.yml) runs as a dry run. Whether a local HTTPS deployment is enough for the course is being asked in workforce-ops-app/.github#32 |
