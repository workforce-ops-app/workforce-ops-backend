"""docker/backup/backup.sh fails safely (review of #205): an interrupted full backup is never
published, and a restore whose backups cannot reach the moment asked for is refused before
anything is written to the new server.

The script runs as it is, with bash, but with stand-ins for the tools it calls (mysql,
mysqldump, mysqlbinlog, zstd, openssl) put first on PATH: compressing and encrypting become
plain copies, and the stand-ins write down what reached the new server. So these tests
need no database and no keys; the real tools are tried in the restore drills
(scripts/restore_drill.py, docs/operations/backup-and-restore.md).
"""

import os
import shutil
import subprocess  # noqa: S404 (runs bash on the repository's own script)
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "docker" / "backup" / "backup.sh"
SERVER = "3e11fa47-71ca-11e1-9e33-c80aa9429562"  # any server_uuid

# bash and the coreutils the script uses (date -d, stat -c, sha256sum). On Windows the
# bash on PATH may be WSL's, which cannot see these paths, so there it runs only when
# BACKUP_TEST_BASH names a bash to use (Git Bash, for example).
BASH = os.environ.get("BACKUP_TEST_BASH") or (None if os.name == "nt" else shutil.which("bash"))
pytestmark = pytest.mark.skipif(BASH is None, reason="needs bash (set BACKUP_TEST_BASH on Windows)")

# The stand-ins. Each is a small bash script; "$STUB_LOG" collects what they were asked.
STUBS = {
    # The server's ID for server_dir; anything else read from standard input is
    # something loaded into the new server, which is written down.
    "mysql": """#!/bin/bash
case "$*" in
  *"SELECT @@server_uuid"*) echo "$STUB_SERVER" ;;
  *"FLUSH BINARY LOGS"*) ;;
  # The server's binary log files, oldest first; the last is the one it is writing.
  *"SHOW BINARY LOGS"*) ls -1 "$STUB_SOURCE" | sort | sed 's/$/	400	No/' ;;
  *) echo "loaded: $(cat | wc -l) line(s)" >> "$STUB_LOG" ;;
esac
""",
    # A dump that ends whole, or one that stops halfway with an error.
    "mysqldump": """#!/bin/bash
echo "-- CHANGE REPLICATION SOURCE TO SOURCE_LOG_FILE='binlog.000003', SOURCE_LOG_POS=157;"
echo "INSERT INTO users VALUES (1);"
if [[ "$STUB_DUMP" == "fail" ]]; then
  echo "mysqldump: Error 2013: Lost connection to MySQL server during query" >&2
  exit 2
fi
echo "-- Dump completed on 2026-11-25 10:00:00"
""",
    # Reading binary log files: their contents as they are (the tests write them in
    # mysqlbinlog's own text form). Downloading one from the server (--result-file)
    # copies it from "$STUB_SOURCE" and writes down its name. Other options are skipped.
    "mysqlbinlog": """#!/bin/bash
result=""
for argument in "$@"; do
  case "$argument" in
    --result-file=*) result="${argument#--result-file=}" ;;
    -*) ;;
    *) if [[ -n "$result" ]]; then
         cp "$STUB_SOURCE/$argument" "$result$argument"
         echo "downloaded: $argument" >> "$STUB_LOG"
       else
         cat "$argument"
       fi ;;
  esac
done
""",
    "zstd": """#!/bin/bash
cat
""",
    # Encrypting writes standard input to -out; decrypting prints -in.
    "openssl": """#!/bin/bash
while (( $# )); do
  case "$1" in
    -out) out="$2"; shift ;;
    -in) in="$2"; shift ;;
  esac
  shift
done
if [[ -n "${out:-}" ]]; then cat > "$out"; else cat "$in"; fi
""",
}


@pytest.fixture
def backups(tmp_path: Path) -> dict[str, object]:
    """A backup folder, the stand-ins, and the environment to run the script with."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in STUBS.items():
        stub = bin_dir / name
        stub.write_text(body, newline="\n")
        stub.chmod(0o755)
    # The server's own binary log files, for shipping (the stand-in mysqlbinlog reads them).
    source = tmp_path / "server-binlogs"
    source.mkdir()
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "cert.pem").write_text("not a real certificate")
    (keys / "key.pem").write_text("not a real key")
    environment = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "BACKUP_DIR": str(tmp_path / "backups"),
        "BACKUP_CERT": str(keys / "cert.pem"),
        "BACKUP_KEY": str(keys / "key.pem"),
        "MYSQL_BACKUP_PASSWORD": "not a real password",
        "RESTORE_HOST": "target",
        "RESTORE_PASSWORD": "not a real password",
        "STUB_SERVER": SERVER,
        "STUB_LOG": str(tmp_path / "stub.log"),
        "STUB_DUMP": "ok",
        "STUB_SOURCE": str(source),
        "TZ": "UTC",
    }
    return {
        "env": environment,
        "server": tmp_path / "backups" / "servers" / SERVER,
        "log": tmp_path / "stub.log",
        "source": source,
    }


def run(backups: dict[str, object], *arguments: str, **env: str) -> subprocess.CompletedProcess:
    assert BASH is not None
    return subprocess.run(  # noqa: S603 (a fixed script, test arguments)
        [BASH, str(SCRIPT), *arguments],
        env={**backups["env"], **env},  # type: ignore[dict-item]
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def stub_log(backups: dict[str, object]) -> list[str]:
    """What the stand-ins were asked to do, one line each."""
    log = backups["log"]
    assert isinstance(log, Path)
    return log.read_text().splitlines() if log.exists() else []


def loaded(backups: dict[str, object]) -> list[str]:
    """What reached the new server, one line per load."""
    return [line for line in stub_log(backups) if line.startswith("loaded:")]


def downloaded(backups: dict[str, object]) -> list[str]:
    """The binary log files shipping downloaded from the server, by name."""
    return [line.split(": ", 1)[1] for line in stub_log(backups) if line.startswith("downloaded:")]


def on_the_server(backups: dict[str, object], *names: str) -> None:
    """Binary log files the server still has; the last is the one it is writing."""
    source = backups["source"]
    assert isinstance(source, Path)
    for name in names:
        (source / name).write_text(binlog("10:30:00"), newline="\n")


def checksum_matches(folder: Path, name: str) -> bool:
    assert BASH is not None
    return (
        subprocess.run(  # noqa: S603 (coreutils, a test file)
            [BASH, "-c", f"cd '{folder.as_posix()}' && sha256sum --quiet -c '{name}.sha256'"],
            capture_output=True,
            check=False,
        ).returncode
        == 0
    )


def put(folder: Path, name: str, content: str) -> None:
    """A finished backup file (the stand-ins make sealing a copy) and its checksum."""
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text(content, newline="\n")
    digest = subprocess.run(  # noqa: S603, S607 (coreutils, a test file)
        [BASH, "-c", f"cd '{folder.as_posix()}' && sha256sum '{name}'"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    (folder / f"{name}.sha256").write_text(digest, newline="\n")


WHOLE_DUMP = (
    "-- CHANGE REPLICATION SOURCE TO SOURCE_LOG_FILE='binlog.000003', SOURCE_LOG_POS=157;\n"
    "INSERT INTO users VALUES (1);\n"
    "-- Dump completed on 2026-11-25 10:00:00\n"
)


def binlog(closed_at: str) -> str:
    """A binary log file as mysqlbinlog prints it, closed at `closed_at` (HH:MM:SS on
    2026-11-25): its last event is the rotation that closed it. The hour is padded with
    a space, as mysqlbinlog does."""
    hour, rest = closed_at.split(":", 1)
    return (
        "#261125 10:00:01 server id 1  end_log_pos 300 CRC32 0x1  Query\n"
        "INSERT INTO shifts VALUES (1);\n"
        f"#261125 {int(hour):2d}:{rest} server id 1  end_log_pos 400 CRC32 0x2  Rotate\n"
    )


def a_snapshot(backups: dict[str, object], dump: str = WHOLE_DUMP) -> Path:
    server = backups["server"]
    assert isinstance(server, Path)
    put(server / "full", "20261125T100000Z.sql.zst.cms", dump)
    return server


# --- Backing up ------------------------------------------------------------------------


def test_a_full_backup_that_stops_halfway_is_never_published(
    backups: dict[str, object],
) -> None:
    done = run(backups, "full", STUB_DUMP="fail")
    assert done.returncode != 0
    server = backups["server"]
    assert isinstance(server, Path)
    # No backup, no checksum, no half-written part, and the server is not marked done.
    assert list((server / "full").iterdir()) == []
    assert not (server / "last-full-day").exists()


def test_a_whole_full_backup_is_published_with_its_checksum(backups: dict[str, object]) -> None:
    done = run(backups, "full")
    assert done.returncode == 0, done.stderr
    server = backups["server"]
    assert isinstance(server, Path)
    names = sorted(path.name for path in (server / "full").iterdir())
    assert len(names) == 2
    assert names[0].endswith(".sql.zst.cms")
    assert names[1] == f"{names[0]}.sha256"
    assert (server / "last-full-day").exists()  # freshness, in this server's own folder


# Shipping the binary log (second review of #205): a file is skipped only if it was
# shipped whole, with a checksum that matches it. A run stopped while publishing leaves
# a part, or a file without its checksum; the next run ships that file again.


def test_shipping_publishes_each_closed_file_with_its_checksum(
    backups: dict[str, object],
) -> None:
    on_the_server(backups, "binlog.000003", "binlog.000004")  # 000004 is being written
    done = run(backups, "binlogs")
    assert done.returncode == 0, done.stderr
    assert downloaded(backups) == ["binlog.000003"]
    server = backups["server"]
    assert isinstance(server, Path)
    assert sorted(path.name for path in (server / "binlog").iterdir()) == [
        "binlog.000003.cms",
        "binlog.000003.cms.sha256",
    ]
    assert checksum_matches(server / "binlog", "binlog.000003.cms")


def test_a_file_shipped_whole_is_not_shipped_again(backups: dict[str, object]) -> None:
    on_the_server(backups, "binlog.000003", "binlog.000004")
    server = backups["server"]
    assert isinstance(server, Path)
    put(server / "binlog", "binlog.000003.cms", binlog("10:30:00"))
    done = run(backups, "binlogs")
    assert done.returncode == 0, done.stderr
    assert downloaded(backups) == []


@pytest.mark.parametrize(
    "left_behind",
    [
        "the file without its checksum",
        "the checksum and the part, stopped before the rename",
        "a checksum that does not match",
    ],
)
def test_a_file_whose_shipping_was_interrupted_is_shipped_again(
    backups: dict[str, object], left_behind: str
) -> None:
    on_the_server(backups, "binlog.000003", "binlog.000004")
    server = backups["server"]
    assert isinstance(server, Path)
    folder = server / "binlog"
    put(folder, "binlog.000003.cms", "half of it\n")
    if left_behind == "the file without its checksum":
        (folder / "binlog.000003.cms.sha256").unlink()
    elif left_behind == "the checksum and the part, stopped before the rename":
        (folder / "binlog.000003.cms").rename(folder / "binlog.000003.cms.part")
    else:
        (folder / "binlog.000003.cms").write_text("changed since\n", newline="\n")
    done = run(backups, "binlogs")
    assert done.returncode == 0, done.stderr
    assert downloaded(backups) == ["binlog.000003"]
    assert (folder / "binlog.000003.cms").read_text() == binlog("10:30:00")
    assert checksum_matches(folder, "binlog.000003.cms")
    assert not list(folder.glob("*.part"))


# --- Restoring -------------------------------------------------------------------------


def test_a_restore_without_the_snapshots_binary_log_file_is_refused(
    backups: dict[str, object],
) -> None:
    server = a_snapshot(backups)
    put(server / "binlog", "binlog.000004.cms", binlog("11:00:00"))  # 000003 never shipped
    done = run(backups, "restore")
    assert done.returncode != 0
    assert "binlog.000003, where the snapshot starts, was never shipped" in done.stderr
    assert loaded(backups) == []  # nothing reached the new server


def test_a_restore_with_a_gap_in_the_binary_log_is_refused(backups: dict[str, object]) -> None:
    server = a_snapshot(backups)
    put(server / "binlog", "binlog.000003.cms", binlog("10:30:00"))
    put(server / "binlog", "binlog.000005.cms", binlog("11:30:00"))  # 000004 is missing
    done = run(backups, "restore")
    assert done.returncode != 0
    assert "gap: binlog.000004 is missing before binlog.000005" in done.stderr
    assert loaded(backups) == []


def test_a_restore_past_what_the_binary_log_reaches_is_refused(
    backups: dict[str, object],
) -> None:
    server = a_snapshot(backups)
    put(server / "binlog", "binlog.000003.cms", binlog("9:30:00"))  # hour padded
    put(server / "binlog", "binlog.000004.cms", binlog("10:30:00"))
    done = run(backups, "restore", "--until", "2026-11-25 11:00:00")
    assert done.returncode != 0
    assert "reaches only 2026-11-25 10:30:00 UTC, before 2026-11-25 11:00:00" in done.stderr
    assert loaded(backups) == []


def test_a_restore_the_backups_reach_loads_the_snapshot_and_replays_the_log(
    backups: dict[str, object],
) -> None:
    server = a_snapshot(backups)
    put(server / "binlog", "binlog.000003.cms", binlog("10:30:00"))
    put(server / "binlog", "binlog.000004.cms", binlog("11:30:00"))
    done = run(backups, "restore", "--until", "2026-11-25 11:00:00")
    assert done.returncode == 0, done.stderr
    assert len(loaded(backups)) == 2  # the full backup, then the replayed binary log
    assert "done, to 2026-11-25 11:00:00 UTC" in done.stderr


def test_a_restore_from_a_dump_that_did_not_finish_is_refused(
    backups: dict[str, object],
) -> None:
    server = a_snapshot(backups, dump=WHOLE_DUMP.rsplit("-- Dump completed", 1)[0])
    put(server / "binlog", "binlog.000003.cms", binlog("10:30:00"))
    done = run(backups, "restore")
    assert done.returncode != 0
    assert "is not a whole dump" in done.stderr
    assert loaded(backups) == []


def test_the_snapshot_alone_can_be_restored_when_asked_for(backups: dict[str, object]) -> None:
    a_snapshot(backups)  # no binary log at all
    done = run(backups, "restore", "--snapshot-only")
    assert done.returncode == 0, done.stderr
    assert len(loaded(backups)) == 1  # the full backup only
    assert "--snapshot-only" in done.stderr
