#!/usr/bin/python3
"""Back up and restore oVirt event tables using a PostgreSQL custom dump."""

import argparse
import gzip
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from ovirt_engine import configfile

ENGINE_DEFAULTS = Path("/usr/share/ovirt-engine/services/ovirt-engine/ovirt-engine.conf")
ENGINE_VARS = Path("/etc/ovirt-engine/engine.conf")
PG_DUMP = Path("/usr/bin/pg_dump")
PG_RESTORE = Path("/usr/bin/pg_restore")
PSQL = Path("/usr/bin/psql")
EVENT_TABLES = (
    "audit_log",
    "event_map",
    "event_notification_hist",
    "event_subscriber",
)
DUMP_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.dump$")
DATABASE_COMMAND_TIMEOUT_SECONDS = 30 * 60
PURGE_ARCHIVE_PREFIX = "purged-audit-log-"


class AuditLogBackupError(RuntimeError):
    """An expected and safe-to-display backup or restore failure."""


def _real_directory(value):
    directory = Path(value)
    try:
        if directory.is_symlink() or not directory.is_dir():
            raise AuditLogBackupError("저장 위치가 실제 디렉터리가 아닙니다: %s" % directory)
        return directory.resolve(strict=True)
    except OSError as error:
        raise AuditLogBackupError("저장 위치를 확인할 수 없습니다: %s" % directory) from error


def _dump_path(directory, filename):
    if not DUMP_NAME.fullmatch(filename or ""):
        raise AuditLogBackupError("허용되지 않은 이벤트 덤프 파일명입니다.")
    dump = directory / filename
    try:
        if dump.is_symlink() or not dump.is_file():
            raise AuditLogBackupError("복구할 이벤트 덤프를 찾을 수 없습니다: %s" % filename)
        resolved = dump.resolve(strict=True)
    except OSError as error:
        raise AuditLogBackupError("이벤트 덤프 파일을 확인할 수 없습니다: %s" % filename) from error
    if resolved.parent != directory:
        raise AuditLogBackupError("이벤트 덤프 파일이 저장 위치 밖에 있습니다.")
    return resolved


def _timestamp():
    return datetime.now().strftime("%Y%m%d%H%M%S%f")


def _database_arguments(program):
    return [str(program)]


def _database_config():
    try:
        config = configfile.ConfigFile((str(ENGINE_DEFAULTS), str(ENGINE_VARS)))
    except Exception as error:
        raise AuditLogBackupError("이벤트 DB 설정을 읽을 수 없습니다: %s" % error) from error
    values = {}
    for name in ("HOST", "PORT", "USER", "PASSWORD", "DATABASE"):
        key = "ENGINE_DB_%s" % name
        values[name.lower()] = config.get(key, "")
    missing = [name for name, value in values.items() if name != "password" and not value]
    if missing:
        raise AuditLogBackupError("이벤트 DB 설정이 비어 있습니다: %s" % ", ".join(missing))
    return values


def _run_database_command(arguments, connect=True):
    # ConfigFile transparently decrypts protected configuration envelopes.  Do
    # not source them as shell files: engine-prolog deliberately skips binary
    # encrypted files and therefore cannot supply ENGINE_DB_PASSWORD.
    command = list(arguments)
    environment = os.environ.copy()
    environment.pop("PGPASSWORD", None)
    if connect:
        database = _database_config()
        command = [
            arguments[0],
            "--host=%s" % database["host"],
            "--port=%s" % database["port"],
            "--username=%s" % database["user"],
            "--dbname=%s" % database["database"],
            "--no-password",
        ] + arguments[1:]
        environment["PGPASSWORD"] = database["password"]
    try:
        result = subprocess.run(
            command,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=True,
            check=False,
            timeout=DATABASE_COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise AuditLogBackupError("이벤트 DB 작업이 30분 시간 제한을 초과했습니다.") from error
    except OSError as error:
        raise AuditLogBackupError("이벤트 DB 도구를 실행할 수 없습니다: %s" % error) from error
    if result.returncode != 0:
        detail = result.stderr
        if isinstance(detail, bytes):
            detail = detail.decode("utf-8", errors="replace")
        raise AuditLogBackupError(
            "이벤트 DB 작업 실패 (종료 코드 %s): %s"
            % (result.returncode, (detail or "").strip())
        )
    return result


def _dump_table_arguments():
    arguments = []
    for table in EVENT_TABLES:
        arguments.extend(("--table", "public.%s" % table))
    return arguments


def _restore_table_arguments():
    # pg_restore's --table pattern matches table names, not the schema-qualified
    # pg_dump pattern used above. Restrict the schema separately or no TABLE DATA
    # archive entries are selected on supported PostgreSQL versions.
    arguments = ["--schema", "public"]
    for table in EVENT_TABLES:
        arguments.extend(("--table", table))
    return arguments


def create_backup(directory, prefix=""):
    """Create a compressed custom-format dump containing event table data only."""
    directory = _real_directory(directory)
    dump = directory / (prefix + _timestamp() + ".dump")
    temporary = dump.with_name(".%s.tmp" % dump.name)
    arguments = _database_arguments(PG_DUMP) + [
        "--format=custom",
        "--compress=3",
        "--lock-wait-timeout=30s",
        "--data-only",
        "--no-owner",
        "--no-privileges",
        "--file=%s" % temporary,
    ] + _dump_table_arguments()
    try:
        _run_database_command(arguments)
        if not temporary.is_file() or temporary.stat().st_size == 0:
            raise AuditLogBackupError("이벤트 DB 덤프 파일이 생성되지 않았습니다.")
        os.chmod(str(temporary), 0o640)
        os.replace(str(temporary), str(dump))
    except (OSError, AuditLogBackupError) as error:
        try:
            temporary.unlink()
        except OSError:
            pass
        if isinstance(error, AuditLogBackupError):
            raise
        raise AuditLogBackupError("이벤트 DB 덤프 실패: %s" % error) from error
    return dump


def _render_restore_sql(dump, output):
    arguments = [
        str(PG_RESTORE),
        "--data-only",
        "--no-owner",
        "--no-privileges",
        "--strict-names",
        "--file=%s" % output,
    ] + _restore_table_arguments() + [str(dump)]
    # Do not add --dbname here: for pg_restore that means "restore directly into
    # this database". PostgreSQL versions that require one of --dbname/--file
    # are supported by explicitly selecting the staging SQL output with --file.
    _run_database_command(arguments, connect=False)
    if output.stat().st_size == 0:
        raise AuditLogBackupError("복구할 이벤트 데이터가 덤프에 없습니다.")


def _restore_tables(dump, staging):
    rendered = staging / "event-data.sql"
    restore_sql = staging / "restore-events.sql"
    _render_restore_sql(dump, rendered)
    with restore_sql.open("wb") as output:
        output.write(b"BEGIN;\n")
        output.write(
            ("TRUNCATE TABLE %s;\n" % ", ".join(
                "public.%s" % table for table in EVENT_TABLES
            )).encode("utf-8")
        )
        with rendered.open("rb") as source:
            shutil.copyfileobj(source, output)
        output.write(
            # pg_restore clears search_path in its generated SQL, so the
            # sequence must remain schema-qualified after that SQL is copied.
            b"\nSELECT setval('public.audit_log_seq', COALESCE(MAX(audit_log_id), 1), "
            b"MAX(audit_log_id) IS NOT NULL) FROM public.audit_log;\nCOMMIT;\n"
        )
    arguments = _database_arguments(PSQL) + [
        "--no-psqlrc",
        "--set=ON_ERROR_STOP=1",
        "--file=%s" % restore_sql,
    ]
    _run_database_command(arguments)


def restore_backup(directory, filename):
    """Back up current event rows, then restore selected event dump."""
    directory = _real_directory(directory)
    dump = _dump_path(directory, filename)

    # Do not replace event data unless a recoverable current dump exists.
    current_backup = create_backup(directory, prefix="pre-restore-current-events-")
    staging = Path(tempfile.mkdtemp(prefix="event-db-restore-"))
    try:
        _restore_tables(dump, staging)
    finally:
        shutil.rmtree(str(staging), ignore_errors=True)
    return current_backup, dump


def _purge_cutoff(value):
    """Parse the engine's cutoff, which must name its time zone, into a SQL literal."""
    try:
        cutoff = datetime.fromisoformat((value or "").replace("Z", "+00:00"))
    except ValueError as error:
        raise AuditLogBackupError("삭제 기준 시각이 올바르지 않습니다: %s" % value) from error
    if cutoff.tzinfo is None:
        raise AuditLogBackupError("삭제 기준 시각에 시간대가 없습니다: %s" % value)
    return cutoff.astimezone(timezone.utc).isoformat()


def _archive_directory(value):
    """The archive directory, created for the purge when it does not exist yet."""
    directory = Path(value)
    if not directory.is_absolute():
        raise AuditLogBackupError("보관 위치는 절대 경로여야 합니다: %s" % value)
    if not directory.exists() and not directory.is_symlink():
        try:
            directory.mkdir(mode=0o750, parents=True)
        except OSError as error:
            raise AuditLogBackupError("보관 위치를 만들 수 없습니다: %s (%s)" % (value, error)) from error
    directory = _real_directory(str(directory))
    if "'" in str(directory) or "\\" in str(directory):
        raise AuditLogBackupError("보관 위치 경로에 사용할 수 없는 문자가 있습니다: %s" % directory)
    return directory


def _count_from(output, tag):
    match = re.search(r"^%s (\d+)$" % tag, output or "", re.MULTILINE)
    return int(match.group(1)) if match else None


def _same_filesystem(directory, other):
    """Whether the archive directory is on the file system of another path."""
    if not other:
        return False
    path = Path(other)
    if not path.is_absolute():
        raise AuditLogBackupError("비교할 경로는 절대 경로여야 합니다: %s" % other)
    try:
        return os.stat(str(directory)).st_dev == os.stat(str(path)).st_dev
    except OSError as error:
        raise AuditLogBackupError("파일시스템을 확인할 수 없습니다: %s (%s)" % (other, error)) from error


def purge_older_than(directory, cutoff_value, skip_archive_on=None):
    """Archive the audit records logged before the cutoff, then remove them.

    The records are copied to a CSV file and deleted in one repeatable-read
    transaction, so exactly the rows that were archived are the rows removed; a
    failure anywhere before the commit removes nothing. The archive is
    compressed only after the commit, and is kept uncompressed if that fails.

    With skip_archive_on - the DB data directory, when its file system is at the
    critical level - an archive directory on that same file system is not
    written: the archive would take the very space the removal is to make room
    for. The records are then removed without one, and the result says so.
    Returns (deleted, archive, vacuum failure, why the archive was skipped).
    """
    directory = _archive_directory(directory)
    cutoff = _purge_cutoff(cutoff_value)
    if _same_filesystem(directory, skip_archive_on):
        deleted, vacuum_error = _delete_older_than(cutoff)
        return deleted, None, vacuum_error, (
            "보관 위치(%s)가 DB 데이터(%s)와 같은 파일시스템이어서 보관하지 않음" % (directory, skip_archive_on))
    stamp = _timestamp()
    temporary = directory / (".%s%s.csv.tmp" % (PURGE_ARCHIVE_PREFIX, stamp))
    archive = directory / ("%s%s.csv.gz" % (PURGE_ARCHIVE_PREFIX, stamp))
    staging = Path(tempfile.mkdtemp(prefix="event-db-purge-"))
    script = staging / "purge-audit-log.sql"
    condition = "log_time < '%s'::timestamptz" % cutoff
    script.write_text(
        "BEGIN ISOLATION LEVEL REPEATABLE READ;\n"
        "\\copy (SELECT * FROM public.audit_log WHERE %s ORDER BY audit_log_id) "
        "TO '%s' WITH (FORMAT csv, HEADER true)\n"
        "DELETE FROM public.audit_log WHERE %s;\n"
        "COMMIT;\n" % (condition, temporary, condition),
        encoding="utf-8",
    )
    try:
        result = _run_database_command(_database_arguments(PSQL) + [
            "--no-psqlrc",
            "--set=ON_ERROR_STOP=1",
            "--file=%s" % script,
        ])
    except AuditLogBackupError:
        _remove(temporary)
        raise
    finally:
        shutil.rmtree(str(staging), ignore_errors=True)

    output = result.stdout if isinstance(result.stdout, str) else (result.stdout or b"").decode("utf-8", "replace")
    copied = _count_from(output, "COPY")
    deleted = _count_from(output, "DELETE")
    if deleted is None:
        deleted = copied or 0
    if deleted == 0:
        _remove(temporary)
        return 0, None, _vacuum_audit_log(False), None

    kept = temporary.with_name(temporary.name[1:-len(".tmp")])
    try:
        with open(str(temporary), "rb") as source, gzip.open(str(archive), "wb") as target:
            shutil.copyfileobj(source, target)
        os.chmod(str(archive), 0o640)
        _remove(temporary)
        kept = archive
    except OSError:
        _remove(archive)
        os.replace(str(temporary), str(kept))
        os.chmod(str(kept), 0o640)
    return deleted, kept, _vacuum_audit_log(True), None


def _delete_older_than(cutoff):
    """Remove the audit records logged before the cutoff without archiving them."""
    condition = "log_time < '%s'::timestamptz" % cutoff
    result = _run_database_command(_database_arguments(PSQL) + [
        "--no-psqlrc",
        "--set=ON_ERROR_STOP=1",
        "--command=DELETE FROM public.audit_log WHERE %s" % condition,
    ])
    output = result.stdout if isinstance(result.stdout, str) else (result.stdout or b"").decode("utf-8", "replace")
    deleted = _count_from(output, "DELETE") or 0
    return deleted, _vacuum_audit_log(deleted > 0)


def _vacuum_audit_log(run):
    """Let the space of the removed rows be reused; a failure is reported, not raised."""
    if not run:
        return None
    try:
        _run_database_command(_database_arguments(PSQL) + [
            "--no-psqlrc",
            "--set=ON_ERROR_STOP=1",
            "--command=VACUUM (ANALYZE) public.audit_log",
        ])
    except AuditLogBackupError as error:
        return str(error)
    return None


def _remove(path):
    try:
        path.unlink()
    except OSError:
        pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation")
    backup_parser = subparsers.add_parser("backup")
    backup_parser.add_argument("directory")
    restore_parser = subparsers.add_parser("restore")
    restore_parser.add_argument("directory")
    restore_parser.add_argument("filename")
    purge_parser = subparsers.add_parser("purge")
    purge_parser.add_argument("directory")
    purge_parser.add_argument("cutoff")
    purge_parser.add_argument(
        "--skip-archive-on-filesystem-of", dest="skip_archive_on", default=None,
        help="보관 위치가 이 경로와 같은 파일시스템이면 보관하지 않고 삭제한다 (DB 위기 수준)")
    args = parser.parse_args(argv)
    if args.operation is None:
        parser.error("backup, restore 또는 purge 작업이 필요합니다.")
    try:
        if args.operation == "backup":
            dump = create_backup(args.directory)
            print("SUCCESS: %s" % dump)
        elif args.operation == "purge":
            deleted, archive, vacuum_error, skipped = purge_older_than(
                args.directory, args.cutoff, args.skip_archive_on)
            print("SUCCESS")
            print("DELETED: %d" % deleted)
            print("ARCHIVE: %s" % (archive or ""))
            if skipped:
                print("ARCHIVE_SKIPPED: %s" % skipped)
            if vacuum_error:
                print("VACUUM_FAILED: %s" % vacuum_error)
        else:
            current, restored = restore_backup(args.directory, args.filename)
            print("SUCCESS")
            print("CURRENT_BACKUP: %s" % current)
            print("RESTORED_FROM: %s" % restored)
    except AuditLogBackupError as error:
        print("FAIL: %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
