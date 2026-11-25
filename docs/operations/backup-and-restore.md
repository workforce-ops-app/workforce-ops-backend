# Back up and restore the database

- **When to use:** setting up backups on a machine (once); restoring after data was lost, destroyed, or damaged; the monthly restore drill
- **Who can run it:** a teammate with access to the machine running Docker Compose, its `.env`, and (for a restore) the private backup key
- **Last tested:** 2026-11-25 (two timed drills, below, and these steps run as written in a separate Compose project: setup, a change only in the binary log, then restore steps 2 to 5 and 7)

## In short

The `backup` service in Docker Compose saves the database in two ways ([decision 0028](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0028-backup-and-recovery.md), #117):

- **Every night, a full backup:** one consistent snapshot of the whole database, made with `mysqldump` inside a single transaction, so the API keeps working while it runs.
- **Every 5 minutes, the binary log:** MySQL writes every change to its binary log. The service closes the current log file and copies every closed file. A restore loads the last full backup before the chosen moment, then replays the binary log up to that moment, so the database can be put back to **any second** since the oldest backup kept.

At most 5 minutes of changes are on the database server only (the RPO, recovery point objective, of decision 0028). Every file is compressed and **encrypted to a public certificate**: the machine making backups cannot read them, and only the private key, kept off that machine, can. The service signs in as its own **backup user**, which can read the database and the binary log and change nothing.

After a restore, the database is exactly as it was at the chosen moment: every audit chain verifies, and the drill below checks row by row counts that nothing before the moment is missing and nothing after it is there.

| Decision 0028 | How | Status |
|---|---|---|
| Nightly full backup | `backup.sh full` after `FULL_AT_HOUR` (02:00 UTC), and at once when there is none | done |
| Binary log off the server every 5 minutes (RPO 5 minutes) | `backup.sh binlogs` every `BINLOG_EVERY` (300) seconds | done |
| Encrypted | OpenSSL CMS with AES-256-GCM, to the backup certificate (RSA 3072); GCM also notices any change to a file, and each file has a SHA-256 checksum | done |
| Separate credentials | the backup user (read only), the backup volume (mounted by the backup service only), and the private key (not on the machine) | done |
| Write-once storage, off the server | the backups are in the `backups` volume on the same machine until there is hosting | **waits for hosting** (limit 1) |
| Retention 30 days daily, 3 months weekly | `backup.sh prune` after each full backup: fulls of the last 30 days and Sundays' up to 92 days; the binary log for 30 days | done |
| Restore within 4 hours (RTO, recovery time objective), measured in every drill | this runbook and `scripts/restore_drill.py` | done: about 1 minute of machine time in the drills |
| Monthly timed drill, audit chains verified after every restore | the drill script; step 6 below | done; next drill due 2026-12-25 |

## Before you start

**Tools:** Docker Desktop (or Docker Engine) and the backend folder with its `.env`. On Windows, run the commands in Git Bash or PowerShell from the backend folder. In Git Bash, first run `export MSYS_NO_PATHCONV=1`: otherwise Git Bash rewrites container paths such as `/run/restore-key` into Windows paths.

**What a backup looks like** (in the `backups` volume, one folder per database server):

```
servers/<server_uuid>/full/20261125T020000Z.sql.zst.cms     a full backup (UTC time)
servers/<server_uuid>/full/20261125T020000Z.sql.zst.cms.sha256
servers/<server_uuid>/binlog/binlog.000042.cms             one binary log file
servers/<server_uuid>/last-full-day, last-binlog-ship       this server's freshness
state/current-server                                        the server backed up now (health check)
```

Freshness is kept per server: a server that a backup was restored into has no full backup of its own yet, so the service takes one at once, instead of waiting for the night because the old server had one today.

**How the service runs:** two schedules. Shipping the binary log runs in a process of its own, every `BINLOG_EVERY` seconds, so a long full backup never holds it up past the 5 minutes; the other process checks once a minute whether a full backup is due (`backup.sh nightly`), then prunes. If shipping ever stops, the service stops, and Docker restarts it.

**What fails safely** (review of #205):

- A full backup is published (its checksum written, then the file renamed from `.part`, so the rename is the moment the backup exists) only after `mysqldump` and the encryption have both finished without an error. A dump that stopped halfway leaves nothing behind, and the server is not marked as backed up today.
- A binary log file counts as shipped only if the file and its checksum are both there and agree (second review of #205). A run stopped while publishing one, or a damaged copy, leaves something less, so the next run ships that file again while the server still has it.
- A restore checks everything before it writes to the new server, and refuses with `restore refused, nothing was written` if: the full backup's dump did not finish (no `-- Dump completed` at its end); the binary log file the snapshot starts in was never shipped; a binary log file is missing between the first and the last (a gap); or the last file does not reach the `--until` moment (each shipped file ends with the rotation that closed it, so its last event says how far it reaches).
- If the snapshot's own binary log file never left the server (the server was lost between a full backup and the next shipment), `restore --snapshot-only` restores the full backup alone, to the moment it was taken. It is never chosen without being asked for.

`tests/unit/test_backup_script.py` tries each of these with stand-ins for the database tools; the restore drills below try the real ones.

A database restored onto a new server is a new server with a new `server_uuid`: it numbers its binary log from 1 again, so its backups go to a folder of their own and never mix with the old server's files.

**What could go wrong:**
- Losing the private key loses every backup. Keep two copies (step 1 of the setup).
- A restore replaces the database. Copy the damaged one first (restore step 2), so nothing is lost for good if the wrong moment was chosen.
- Changes after the chosen moment are lost unless they are put back by hand. Choose the latest moment before the damage.

## Set up backups (once per machine)

1. **Make the key pair** on your own computer, not the server:

   ```sh
   openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -subj "/CN=workforce-ops backups" \
     -keyout backup-key.pem -out backup-cert.pem
   ```

   - `backup-cert.pem` is public: put it in a folder of its own on the machine that runs the backups, outside the repository, for example `C:/Users/you/workforce-ops-backup-cert/`.
   - `backup-key.pem` is the only way to read the backups. Keep it **off that machine**, in two places, one per teammate (for example each teammate's password manager). Never commit it or put it in the certificate's folder.

2. **Set the two settings** in `.env` (see `.env.example`):

   ```sh
   MYSQL_BACKUP_PASSWORD=<a long random password>
   BACKUP_CERT_DIR=C:/Users/you/workforce-ops-backup-cert
   ```

3. **Create the backup user.** A database started for the first time with `MYSQL_BACKUP_PASSWORD` set creates it by itself (`docker/mysql/init/01-users.sh`). For a database that already exists, create it once as root:

   ```sh
   docker compose exec db mysql -uroot -p
   ```
   ```sql
   CREATE USER 'workforce_backup'@'%' IDENTIFIED BY '<the same password>';
   GRANT SELECT, SHOW VIEW ON `workforce_ops`.* TO 'workforce_backup'@'%';
   GRANT RELOAD, REPLICATION CLIENT, REPLICATION SLAVE ON *.* TO 'workforce_backup'@'%';
   ```

   It reads every table and the binary log; `RELOAD` lets it close the binary log and take the brief lock `mysqldump` needs for a consistent snapshot. It can change nothing, definitions included: no `TRIGGER` or `EVENT` right, since both would let it create or drop triggers and events (review of #205). The database defines only tables, so the backup takes tables only, and `scripts/check_migrations.py` fails if a trigger, event, or routine ever appears, which the backups would otherwise leave out. It looks for them as the migration user, since MySQL hides definitions from a user without rights to them, so the backup user would never see one (second review of #205); a probe event shows the check can see one. That check also tries what the backup user must and must not be able to do, creating and dropping triggers, events, and procedures included.

   A server set up with the earlier rights takes them away with:

   ```sql
   REVOKE TRIGGER, EVENT ON `workforce_ops`.* FROM 'workforce_backup'@'%';
   ```

4. **Start the service:**

   ```sh
   docker compose --profile backup up -d --build backup
   docker compose --profile backup logs backup      # "full backup done", "binary log shipped"
   docker compose --profile backup ps backup        # "healthy" once the binary log was shipped
   ```

   It takes the first full backup at once, then ships the binary log every 5 minutes. The health check turns unhealthy if the binary log has not been shipped for 11 minutes.

5. **On a server** (once there is hosting): copy the `backups` volume off the machine at least every 5 minutes to write-once storage, such as object storage with a retention lock of 92 days, using credentials that can add files but not delete or change them. Until then, backups are on the same machine as the database (limit 1).

## Restore

Restoring is the same whether the database was destroyed, damaged by an attacker, or changed by mistake. All times are UTC (the database's time).

1. **Choose the moment** to restore to: the last second before the damage. The audit log (`/api/audit-log`), the application log, and the backup tool's list help:

   ```sh
   docker compose --profile backup run --rm backup list
   ```

2. **Stop the API**, so nothing writes while you work, and **keep a copy of the damaged database** (only if it still exists):

   ```sh
   docker compose stop api backup
   docker compose stop db
   docker run --rm -v workforce-ops-backend_db-data:/from -v workforce-ops-backend_db-damaged:/to \
     mysql:8.4.13 bash -c "cp -a /from/. /to/"
   ```

3. **Start a new, empty database:** remove the old data volume (it is copied in step 2) and start the database again. It creates the database and its three users on its first start.

   ```sh
   docker compose rm -f db
   docker volume rm workforce-ops-backend_db-data
   docker compose up -d db
   ```

4. **Restore** to the chosen moment. Put the private key in a folder of its own for this step only, and give the root password through the environment, never on the command line. This one step runs as root inside the container (`--user root`): the key file is readable by its owner only, as a private key should be, and the backup tool's own user is not its owner.

   ```sh
   export RESTORE_PASSWORD="<MYSQL_ROOT_PASSWORD from .env>"
   docker compose --profile backup run --rm --user root \
     -e RESTORE_HOST=db -e RESTORE_PASSWORD -e BACKUP_KEY=/run/restore-key/backup-key.pem \
     -v "C:/Users/you/restore-key:/run/restore-key:ro" \
     backup restore --until "2026-11-25 14:30:00"
   ```

   Without `--until`, it restores everything backed up, and says how far that reaches. It checks each file's checksum, decrypts it, and checks that the backups reach the moment (see "What fails safely" above) before writing anything; then it loads the newest full backup before the moment and replays the binary log from that backup's position up to the moment. Only this database's changes are replayed: the new server keeps its own users. If it refuses because the snapshot's binary log file never left the server, `backup restore --snapshot-only` restores the full backup alone.

5. **Set the application user's rights** (they belong to the server, not the database, so they are not in the backup):

   ```sh
   docker compose run --rm migrate
   ```

6. **Start the API and verify** (see Verify).

7. **Back up the new server at once,** and start the service again:

   ```sh
   docker compose --profile backup run --rm backup full
   docker compose --profile backup up -d backup
   ```

   Then remove the private key from the machine.

## Verify

- `docker compose up -d api`, then `docker compose exec -T api python -m app.jobs.verify_audit_log` prints `0 failed`. Every chain is checked from its first entry; a backup that was changed would fail here.
- Compare each chain's head (`last_seq` in the "audit chain head" lines of that command) with the copies of earlier nights in the application log. A restore to a moment shows the head of that moment: older than the newest copy, by the entries after the moment.
- Sign in and check the last thing you know happened before the moment is there, and the damage is not.

## Roll back

If the wrong moment was chosen, repeat from step 3 with another one: the backups are not changed by a restore. To go back to the damaged database instead, stop `db`, copy `workforce-ops-backend_db-damaged` back into `workforce-ops-backend_db-data` the same way as in step 2, and start it.

## Record

- Write an issue: what happened, the moment restored to, what was lost after it (the changes between the moment and the damage), and the times of each step.
- The restore itself is not in the audit log: the database was put back to before it. The issue is the record, together with the `audit.verified` entries step 6 adds.
- A drill: add a row to the drill record below.

## The restore drill

`scripts/restore_drill.py` plays a disaster from start to end in throwaway containers (nothing of yours is touched), and times the restore part, steps 3 to 6 above:

```sh
docker build -t workforce-ops-backup:drill docker/backup   # the script builds it too
uv run python scripts/restore_drill.py --runs 2 --bulk 20000
```

1. A source database is set up as Docker Compose sets it up, migrated, and filled with the demo data plus `--bulk` signed audit entries (half before the full backup, half after, so the binary log replay has work too).
2. A full backup, then change A (a signed audit entry). Every table is counted: the state to get back. The moment T is a second later. Then change B, after T, and the binary log is shipped.
3. The source server and its data are deleted.
4. Timed: a new server (step 3), the restore to T (step 4), the migrate tool (step 5), and the checks (step 6): every table's count equals the count at T, A is there and B is not, and every audit chain verifies.
5. The new server is backed up, and its files must land in a folder of their own.

It exits 1 if the restored database is not the database at T.

### Drill record

Each drill restored the demo data plus 10,000 signed audit entries (`--bulk 10000`; 5,000 in the full backup and 5,000 only in the binary log), on a Windows 11 laptop with Docker Desktop, MySQL 8.4.13. The two runs were separate, one after the other.

| Drill | Date | Rows at T | Full backup (encrypted) | New server | Restore (full / binary log) | Migrate | Verify | Total | Result |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 2026-11-25 | 10,373 | 416 KiB | 15.8 s | 25.5 s (2 s / 22 s) | 3.2 s | 5.8 s | **50.3 s** | the database at T: every table's count matches, A there and B not, 3 audit chains verified, the new server's backups kept apart |
| 2 | 2026-11-25 | 10,373 | 417 KiB | 36.7 s | 26.5 s (2 s / 23 s) | 3.3 s | 6.1 s | **72.6 s** | the same |

After the review changes (#205: publishing only finished backups, the checks of the binary log chain before a restore, the two schedules, and the narrower rights), a third drill ran with the real tools and a smaller load (`--bulk 2000`, 2,388 rows at T): the restore passed its new checks (the snapshot's binary log file there, no gap, the log reaching T) and gave back the database at T, 3 audit chains verified, in 34.9 s in all.

Against decision 0028's targets: the machine part of a restore took **under 75 seconds**, far inside the 4-hour RTO, and nothing before the chosen second was lost. Most of the time goes to starting the new server (which varies with the laptop's load) and to replaying the binary log, which re-applies every change one by one: 5,000 changes took about 22 seconds, so a day with far more changes would make the replay the step to watch. A drill with more data before the full backup and fewer after it restores faster, since loading a full backup is the quick part (2 seconds here). The next drill is due 2026-12-25.

## Limits

1. **No write-once copy off the machine yet.** Until there is hosting (decision 0028's hosting-dependent part), the backups are in a Docker volume on the same machine as the database. They are encrypted, and only the backup service mounts that volume, but someone in control of the whole machine could delete them. Step 5 of the setup is what closes this.
2. **The machine time is not the whole RTO.** The drill times the commands. A real restore adds noticing the problem, choosing the moment, and getting the private key, which is why decision 0028 promises 4 hours rather than minutes.
3. **The binary log of the last 5 minutes.** A change in the binary log file the server is writing is not shipped until it is closed, so a lost server loses up to 5 minutes (the RPO), as decision 0028 allows.
4. **Demo-sized data.** The drills restore the demo data plus 10,000 audit entries (under half a megabyte, encrypted). A real company's database would take longer to load; the drill's `--bulk` option is there to measure that.
