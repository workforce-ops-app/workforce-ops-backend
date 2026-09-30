# Operations

**In short:** how to keep the system running and bring it back when something goes wrong: backups, restores, and (later) deployment.

New procedures start from the [runbook template](https://github.com/workforce-ops-app/.github/blob/main/docs/templates/runbook.md). Targets and rules are in [decision 0028](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0028-backup-and-recovery.md): lose at most 5 minutes of data, be running again within 4 hours, and practise restores.

| Procedure | Tier | Status |
|---|---|---|
| Back up the database | next | to do |
| Restore from a backup (timed drill, audit chains verified afterwards) | next | to do |
| Rotate secrets (database passwords, audit signing key, CSRF key) | next | to do |
| Deploy | not decided | no hosting target yet; the [deploy workflow](../../.github/workflows/deploy.yml) runs as a dry run. Whether a local HTTPS deployment is enough for the course is being asked in workforce-ops-app/.github#32 |
