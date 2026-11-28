"""The timed restore drill (#117, decision 0028, docs/operations/backup-and-restore.md).

    uv run python scripts/restore_drill.py [--runs 2]

Each run plays a disaster from start to end, with Docker and nothing else of yours (it
uses its own containers, network, volume, and keys, all removed afterwards):

1. A source MySQL, set up as Docker Compose sets it up (docker/mysql/init), migrated and
   filled with the demo data.
2. The backup tool (docker/backup) takes a full backup.
3. Change A is made (a signed audit entry), and every table is counted: the state to get
   back. A moment T a second later is the restore point. Then change B is made after T,
   and the binary log is shipped.
4. The disaster: the source server and its data are deleted.
5. The timed part, as the runbook does it: a new empty server is started, the backup is
   restored into it up to T, the migrate tool sets the application user's rights, and
   the result is checked: every table has the count it had at T, change A is there and
   change B is not, and every audit chain verifies (app.jobs.verify_audit_log).

Prints the times of each run as a table row for the runbook's drill record. Exits 1 if a
run's restored database is not the database at T.
"""

import argparse
import json
import os
import re
import secrets
import shutil
import socket
import subprocess  # noqa: S404 (runs docker and this project's own tools)
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INIT_SCRIPTS = ROOT / "docker" / "mysql" / "init"
BACKUP_CONTEXT = ROOT / "docker" / "backup"
MYSQL_IMAGE = "mysql:8.4.13"
BACKUP_IMAGE = "workforce-ops-backup:drill"
DATABASE = "workforce_ops"
# The timed phases of a restore, in order, and the total of all of them.
PHASES = ("new server", "restore", "migrate", "verify", "total")


# --- Small helpers ---------------------------------------------------------------------


def _docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run docker with these arguments (all fixed or generated here)."""
    program = shutil.which("docker")
    if not program:
        sys.exit("Docker is needed for the restore drill; start Docker Desktop")
    done = subprocess.run([program, *arguments], capture_output=True, text=True)  # noqa: S603
    if check and done.returncode != 0:
        raise RuntimeError(f"docker {arguments[0]} failed: {done.stderr.strip()}")
    return done


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _make_keys(folder: Path) -> None:
    """A throwaway key pair, as the runbook makes the real one: the certificate (public)
    for the backup tool, the private key for the restore."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "workforce-ops restore drill")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    (folder / "backup-cert.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    (folder / "backup-key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


class Server:
    """One MySQL container on the drill's network, set up as Docker Compose sets it up."""

    def __init__(self, network: str, name: str, backup_password: str) -> None:
        self.name = name
        self.root = secrets.token_hex(16)
        self.app = secrets.token_hex(16)
        self.migrations = secrets.token_hex(16)
        self.port = _free_port()
        _docker(
            "run", "--detach", "--name", name, "--network", network,
            "--publish", f"127.0.0.1:{self.port}:3306",
            "--volume", f"{INIT_SCRIPTS}:/docker-entrypoint-initdb.d:ro",
            "--env", f"MYSQL_ROOT_PASSWORD={self.root}",
            "--env", f"MYSQL_DATABASE={DATABASE}",
            "--env", f"MYSQL_APP_PASSWORD={self.app}",
            "--env", f"MYSQL_MIGRATIONS_PASSWORD={self.migrations}",
            "--env", f"MYSQL_BACKUP_PASSWORD={backup_password}",
            MYSQL_IMAGE,
        )  # fmt: skip

    def wait_until_ready(self) -> None:
        """Until the server answers over TCP: the image's first-start setup runs without
        networking, so this is only true once the users exist."""
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            ping = _docker(
                "exec", self.name, "mysqladmin", "ping", "--host=127.0.0.1", "--silent",
                check=False,
            )  # fmt: skip
            if ping.returncode == 0:
                return
            time.sleep(1)
        raise RuntimeError(f"{self.name} did not start: {_docker('logs', self.name).stderr[-500:]}")

    def environment(self, audit_key: str) -> dict[str, str]:
        """The settings this project's tools read, pointed at this server."""
        address = f"127.0.0.1:{self.port}/{DATABASE}"
        names = ("DATABASE_URL", "DATABASE_PASSWORD", "MIGRATIONS_DATABASE_URL")
        environment = {key: value for key, value in os.environ.items() if key not in names}
        environment |= {
            "APP_ENV": "development",
            "LOG_LEVEL": "WARNING",
            "DATABASE_URL": f"mysql+pymysql://workforce_app@{address}",
            "DATABASE_PASSWORD": self.app,
            "MIGRATIONS_DATABASE_URL": f"mysql+pymysql://workforce_migrations@{address}",
            "MIGRATIONS_DATABASE_PASSWORD": self.migrations,
            "AUDIT_SIGNING_KEY": audit_key,
            "AUDIT_KEY_ID": "drill-1",
        }
        environment.pop("DEMO_PASSWORD", None)
        return environment


def _tool(environment: dict[str, str], *arguments: str) -> str:
    """Run one of this project's tools (as a separate process, so each reads the settings
    for its own server) and return what it printed."""
    done = subprocess.run(  # noqa: S603 (this project's own tools)
        [sys.executable, *arguments],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
    )
    if done.returncode != 0:
        raise RuntimeError(f"{' '.join(arguments)} failed:\n{done.stdout}\n{done.stderr}")
    return done.stdout


# --- The steps this script runs in its own process (--step) -----------------------------


def _step_marker(label: str) -> None:
    """Add one signed entry to the platform audit chain, with the label in its details."""
    from sqlalchemy.orm import Session

    from app.audit.record import Actor, record
    from app.db.registry import import_all_models
    from app.db.session import get_engine

    import_all_models()  # the audit tables refer to companies: every model must be known
    with Session(get_engine()) as session:
        record(session, actor=Actor.system(), action="drill.marker", details={"marker": label})
        session.commit()


def _step_bulk(count: int) -> None:
    """Add count signed entries to the platform audit chain, in commits of 1,000: data for
    the drill to move. The audit log is the table that grows fastest in real use, and its
    chain must still verify after the restore."""
    from sqlalchemy.orm import Session

    from app.audit.record import Actor, record
    from app.db.registry import import_all_models
    from app.db.session import get_engine

    import_all_models()
    note = "a drill entry the size of a typical change, with its details " * 3
    with Session(get_engine()) as session:
        for number in range(1, count + 1):
            record(
                session,
                actor=Actor.system(),
                action="drill.bulk",
                details={"number": number, "note": note},
            )
            if number % 1000 == 0 or number == count:
                session.commit()


def _step_state() -> None:
    """Print every table's row count and the drill markers present, as JSON. Read as the
    application user, so it also shows that user's rights are back after a restore."""
    from sqlalchemy import text

    from app.db.session import get_engine

    with get_engine().connect() as connection:
        tables = connection.execute(
            text(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE' "
                "AND table_name <> 'alembic_version' ORDER BY table_name"
            )
        ).scalars()
        counts = {
            table: connection.execute(text(f"SELECT COUNT(*) FROM `{table}`")).scalar_one()  # noqa: S608 (names from the catalog)
            for table in list(tables)
        }
        markers = connection.execute(
            text("SELECT details FROM audit_events WHERE action = 'drill.marker' ORDER BY seq")
        ).scalars()
        labels = [
            json.loads(value)["marker"] if isinstance(value, str) else value["marker"]
            for value in markers
        ]
    print(json.dumps({"counts": counts, "markers": labels}))


# --- One drill -----------------------------------------------------------------------------


def _backup_tool(
    network: str, volume: str, keys: Path, command: list[str], env: dict[str, str]
) -> str:
    """Run the backup image once with the drill's volume and keys; return its log."""
    arguments = [
        "run", "--rm", "--network", network,
        "--volume", f"{volume}:/backups",
        "--volume", f"{keys}:/run/backup:ro",
    ]  # fmt: skip
    if command[0] == "restore":
        # As the runbook's step 4: root reads a private key only its owner may read.
        arguments += ["--user", "root"]
    for key, value in env.items():
        arguments += ["--env", f"{key}={value}"]
    done = _docker(*arguments, BACKUP_IMAGE, *command, check=False)
    if done.returncode != 0:
        raise RuntimeError(f"backup.sh {' '.join(command)} failed:\n{done.stderr}")
    return done.stdout + done.stderr


def drill(number: int, bulk: int) -> dict[str, object]:
    """One run, from a fresh source to a verified restore, with bulk extra audit entries
    (half before the full backup, half after it). Returns its times and sizes."""
    tag = secrets.token_hex(4)
    network, volume = f"wfo-drill-{tag}", f"wfo-drill-backups-{tag}"
    backup_password, audit_key = secrets.token_hex(16), secrets.token_urlsafe(32)
    keys = Path(tempfile.mkdtemp(prefix="wfo-drill-keys-"))
    containers: list[str] = []
    _docker("network", "create", network)
    _docker("volume", "create", volume)
    try:
        _make_keys(keys)
        source_env = {
            "MYSQL_HOST": f"wfo-drill-source-{tag}",
            "MYSQL_DATABASE": DATABASE,
            "MYSQL_BACKUP_PASSWORD": backup_password,
        }

        # 1. The source, migrated and with the demo data.
        source = Server(network, f"wfo-drill-source-{tag}", backup_password)
        containers.append(source.name)
        source.wait_until_ready()
        source_tools = source.environment(audit_key)
        _tool(source_tools, "-m", "alembic", "upgrade", "head")
        _tool(source_tools, "-m", "scripts.seed_demo")
        if bulk:
            _tool(source_tools, "scripts/restore_drill.py", "--step", "bulk", str(bulk // 2))

        # 2. The full backup, then more changes, which only the binary log will have.
        _backup_tool(network, volume, keys, ["full"], source_env)
        if bulk:
            _tool(source_tools, "scripts/restore_drill.py", "--step", "bulk", str(bulk - bulk // 2))

        # 3. Change A, the state to get back, the moment T, then change B after it.
        _tool(source_tools, "scripts/restore_drill.py", "--step", "marker", "A")
        wanted = json.loads(_tool(source_tools, "scripts/restore_drill.py", "--step", "state"))
        # T: the next whole second plus one, so A is before it; B waits until after.
        moment = datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=2)
        while datetime.now(UTC) < moment + timedelta(seconds=1):
            time.sleep(0.1)
        _tool(source_tools, "scripts/restore_drill.py", "--step", "marker", "B")
        _backup_tool(network, volume, keys, ["binlogs"], source_env)
        listing = _backup_tool(network, volume, keys, ["list"], source_env)
        sizes = _docker(
            "run", "--rm", "--volume", f"{volume}:/backups", "--entrypoint", "sh", BACKUP_IMAGE,
            "-c", "du -cb /backups/servers/*/full/*.cms | tail -1 | cut -f1;"
            " ls /backups/servers/*/binlog | grep -c 'cms$'",
        ).stdout.split()  # fmt: skip

        # 4. The disaster: the server and its data are gone.
        _docker("rm", "--force", "--volumes", source.name)
        containers.remove(source.name)

        # 5. The timed restore, as in the runbook.
        times: dict[str, float] = {}
        started = time.monotonic()
        # The same backup password, as a rebuilt server gets it from the same .env.
        target = Server(network, f"wfo-drill-target-{tag}", backup_password)
        containers.append(target.name)
        target.wait_until_ready()
        times["new server"] = time.monotonic() - started

        step = time.monotonic()
        until = moment.strftime("%Y-%m-%d %H:%M:%S")
        log = _backup_tool(
            network, volume, keys, ["restore", "--until", until],
            {
                **source_env,
                "RESTORE_HOST": target.name,
                "RESTORE_PASSWORD": target.root,
                "BACKUP_KEY": "/run/backup/backup-key.pem",
            },
        )  # fmt: skip
        times["restore"] = time.monotonic() - step

        step = time.monotonic()
        target_tools = target.environment(audit_key)
        _tool(target_tools, "-m", "alembic", "upgrade", "head")
        times["migrate"] = time.monotonic() - step

        step = time.monotonic()
        found = json.loads(_tool(target_tools, "scripts/restore_drill.py", "--step", "state"))
        verified = _tool(target_tools, "-m", "app.jobs.verify_audit_log")
        times["verify"] = time.monotonic() - step
        times["total"] = time.monotonic() - started

        # After a restore the new server numbers its binary log from 1 again: its
        # backups must go to a folder of their own, not be taken for the old server's.
        target_env = {**source_env, "MYSQL_HOST": target.name}
        _backup_tool(network, volume, keys, ["binlogs"], target_env)
        after = _backup_tool(network, volume, keys, ["list"], target_env)

        # The result must be the database at T: nothing lost before it, nothing after it.
        problems = []
        if found["counts"] != wanted["counts"]:
            differ = {
                table: (wanted["counts"].get(table), count)
                for table, count in found["counts"].items()
                if wanted["counts"].get(table) != count
            }
            problems.append(f"row counts differ (wanted, found): {differ}")
        if found["markers"] != ["A"]:
            problems.append(f"markers found: {found['markers']} (wanted only A)")
        if after.count("server ") != 2:
            problems.append(f"the new server's backups were not kept apart: {after!r}")
        if not re.search(r"checked \d+ audit chains: 0 failed", verified):
            problems.append(f"audit chains: {verified.strip()}")
        return {
            "run": number,
            "date": datetime.now(UTC).strftime("%Y-%m-%d"),
            "full_bytes": int(sizes[0]),
            "binlog_files": int(sizes[1]),
            "rows": sum(wanted["counts"].values()),
            "times": times,
            "chains": re.search(r"checked (\d+) audit chains", verified).group(1),  # type: ignore[union-attr]
            "log": log + listing + after,
            "problems": problems,
        }
    finally:
        for name in containers:
            _docker("rm", "--force", "--volumes", name, check=False)
        _docker("volume", "rm", "--force", volume, check=False)
        _docker("network", "rm", network, check=False)
        shutil.rmtree(keys, ignore_errors=True)


def main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument(
        "--bulk", type=int, default=0, help="extra signed audit entries to back up and restore"
    )
    parser.add_argument("--step", nargs="*", help=argparse.SUPPRESS)  # used by drill() itself
    options = parser.parse_args(arguments)

    if options.step:
        if options.step[0] == "marker":
            _step_marker(options.step[1])
        elif options.step[0] == "bulk":
            _step_bulk(int(options.step[1]))
        elif options.step[0] == "state":
            _step_state()
        return 0

    # The backup image, built from this checkout.
    _docker("build", "--quiet", "--tag", BACKUP_IMAGE, str(BACKUP_CONTEXT))
    results = []
    for number in range(1, options.runs + 1):
        print(f"run {number} of {options.runs}...", flush=True)
        results.append(drill(number, options.bulk))

    print()
    columns = ["Run", "Date", "Rows", "Full backup", "Binary log files", *PHASES, "Result"]
    print("| " + " | ".join(column.capitalize() for column in columns) + " |")
    print("|" + "---|" * len(columns))
    failed = False
    for result in results:
        times: dict[str, float] = result["times"]  # type: ignore[assignment]
        outcome = "the database at T, " + f"{result['chains']} chains verified"
        if result["problems"]:
            failed = True
            outcome = "FAILED: " + "; ".join(result["problems"])  # type: ignore[arg-type]
        cells = [
            str(result["run"]), str(result["date"]), str(result["rows"]),
            f"{float(str(result['full_bytes'])) / 1024:.0f} KiB", str(result["binlog_files"]),
            *(f"{times[name]:.1f} s" for name in PHASES),
            outcome,
        ]  # fmt: skip
        print("| " + " | ".join(cells) + " |")
    for result in results:
        print(f"\nrun {result['run']}, the backup tool's log:\n{result['log']}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
