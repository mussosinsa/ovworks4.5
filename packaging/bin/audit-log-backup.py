#!/usr/bin/python3
"""Back up and restore oVirt event tables using a PostgreSQL custom dump."""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
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


def _run_database_command(arguments, stdout_file=None):
    # ConfigFile transparently decrypts protected configuration envelopes.  Do
    # not source them as shell files: engine-prolog deliberately skips binary
    # encrypted files and therefore cannot supply ENGINE_DB_PASSWORD.
    database = _database_config()
    command = [
        arguments[0],
        "--host=%s" % database["host"],
        "--port=%s" % database["port"],
        "--username=%s" % database["user"],
        "--dbname=%s" % database["database"],
        "--no-password",
    ] + arguments[1:]
    environment = os.environ.copy()
    environment["PGPASSWORD"] = database["password"]
    try:
        result = subprocess.run(
            command,
            env=environment,
            stdout=stdout_file if stdout_file is not None else subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=stdout_file is None,
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


def _table_arguments():
    arguments = []
    for table in EVENT_TABLES:
        arguments.extend(("--table", "public.%s" % table))
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
    ] + _table_arguments()
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
    ] + _table_arguments() + [str(dump)]
    with output.open("wb") as stream:
        _run_database_command(arguments, stdout_file=stream)
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation")
    backup_parser = subparsers.add_parser("backup")
    backup_parser.add_argument("directory")
    restore_parser = subparsers.add_parser("restore")
    restore_parser.add_argument("directory")
    restore_parser.add_argument("filename")
    args = parser.parse_args(argv)
    if args.operation is None:
        parser.error("backup 또는 restore 작업이 필요합니다.")
    try:
        if args.operation == "backup":
            dump = create_backup(args.directory)
            print("SUCCESS: %s" % dump)
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
