#!/usr/bin/python3
"""Export and restore oVirt event tables as CSV files in a tar.gz archive."""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path, PurePosixPath


ENGINE_PSQL = Path("/usr/share/ovirt-engine/dbscripts/engine-psql.sh")
EVENT_TABLES = (
    "audit_log",
    "event_map",
    "event_notification_hist",
    "event_subscriber",
)
ARCHIVE_ROOT = "event-database"
ARCHIVE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.tar\.gz$")
MAX_RESTORE_BYTES = 10 * 1024 * 1024 * 1024


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


def _archive_path(directory, filename):
    if not ARCHIVE_NAME.fullmatch(filename or ""):
        raise AuditLogBackupError("허용되지 않은 백업 파일명입니다.")
    archive = directory / filename
    try:
        if archive.is_symlink() or not archive.is_file():
            raise AuditLogBackupError("복구 파일을 찾을 수 없습니다: %s" % filename)
        resolved = archive.resolve(strict=True)
    except OSError as error:
        raise AuditLogBackupError("복구 파일을 확인할 수 없습니다: %s" % filename) from error
    if resolved.parent != directory:
        raise AuditLogBackupError("복구 파일이 저장 위치 밖에 있습니다.")
    return resolved


def _timestamp():
    return datetime.now().strftime("%Y%m%d%H%M%S%f")


def _sql_path(path):
    return str(path).replace("'", "''")


def _run_psql(command, success_marker=None):
    try:
        result = subprocess.run(
            [str(ENGINE_PSQL), "--no-psqlrc", "--set=ON_ERROR_STOP=1", "--command", command],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
    except OSError as error:
        raise AuditLogBackupError("Engine DB 도구를 실행할 수 없습니다: %s" % error) from error
    if result.returncode != 0:
        raise AuditLogBackupError(
            "이벤트 DB 작업 실패 (종료 코드 %s): %s"
            % (result.returncode, (result.stdout or "").strip())
        )
    if success_marker is not None and success_marker not in (result.stdout or ""):
        raise AuditLogBackupError("이벤트 DB 작업이 완료되지 않았습니다.")


def _export_tables(staging):
    for table in EVENT_TABLES:
        csv_file = staging / (table + ".csv")
        _run_psql(
            "\\copy public.%s TO '%s' WITH (FORMAT CSV, HEADER true)"
            % (table, _sql_path(csv_file))
        )
        if not csv_file.is_file():
            raise AuditLogBackupError("이벤트 테이블 CSV가 생성되지 않았습니다: %s" % table)


def create_backup(directory, prefix=""):
    """Export every event-related table to CSV and create an atomic archive."""
    directory = _real_directory(directory)
    archive = directory / (prefix + _timestamp() + ".tar.gz")
    temporary = archive.with_name(".%s.tmp" % archive.name)
    staging = Path(tempfile.mkdtemp(prefix="event-db-export-"))
    try:
        _export_tables(staging)
        (staging / "manifest.json").write_text(
            json.dumps({"version": 1, "tables": list(EVENT_TABLES)}, sort_keys=True),
            encoding="utf-8",
        )
        with tarfile.open(str(temporary), "w:gz") as stream:
            stream.add(str(staging), arcname=ARCHIVE_ROOT)
        os.chmod(str(temporary), 0o640)
        os.replace(str(temporary), str(archive))
    except (OSError, tarfile.TarError, AuditLogBackupError) as error:
        try:
            temporary.unlink()
        except OSError:
            pass
        if isinstance(error, AuditLogBackupError):
            raise
        raise AuditLogBackupError("이벤트 DB 백업 실패: %s" % error) from error
    finally:
        shutil.rmtree(str(staging), ignore_errors=True)
    return archive


def _validate_archive(archive):
    expected = {"%s/%s.csv" % (ARCHIVE_ROOT, table) for table in EVENT_TABLES}
    expected.add("%s/manifest.json" % ARCHIVE_ROOT)
    files = set()
    expanded_size = 0
    manifest = None
    try:
        with tarfile.open(str(archive), "r:gz") as stream:
            for member in stream:
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts:
                    raise AuditLogBackupError("백업 파일에 안전하지 않은 경로가 있습니다.")
                if member.isdir() and member.name == ARCHIVE_ROOT:
                    continue
                if not member.isfile() or member.name not in expected:
                    raise AuditLogBackupError("백업 파일에 허용되지 않은 항목이 있습니다: %s" % member.name)
                if member.name in files:
                    raise AuditLogBackupError("백업 파일에 중복 항목이 있습니다: %s" % member.name)
                files.add(member.name)
                expanded_size += member.size
                if expanded_size > MAX_RESTORE_BYTES:
                    raise AuditLogBackupError("백업 파일의 복구 크기가 제한을 초과합니다.")
                if member.name == "%s/manifest.json" % ARCHIVE_ROOT:
                    source = stream.extractfile(member)
                    if source is not None:
                        manifest = json.loads(source.read().decode("utf-8"))
    except (OSError, UnicodeError, ValueError, tarfile.TarError) as error:
        raise AuditLogBackupError("백업 파일을 읽을 수 없습니다: %s" % error) from error
    if files != expected:
        raise AuditLogBackupError("백업 파일에 필요한 이벤트 테이블 CSV가 없습니다.")
    if manifest != {"version": 1, "tables": list(EVENT_TABLES)}:
        raise AuditLogBackupError("지원하지 않는 이벤트 백업 형식입니다.")


def _extract_archive(archive, staging):
    with tarfile.open(str(archive), "r:gz") as stream:
        for member in stream:
            if not member.isfile():
                continue
            destination = staging / Path(*PurePosixPath(member.name).parts[1:])
            source = stream.extractfile(member)
            if source is None:
                raise AuditLogBackupError("백업 파일 항목을 읽을 수 없습니다: %s" % member.name)
            with source, destination.open("wb") as output:
                shutil.copyfileobj(source, output)
            destination.chmod(0o600)


def _restore_tables(staging):
    success_marker = "EVENT_RESTORE_COMPLETED"
    copy_commands = [
        "\\copy public.%s FROM '%s' WITH (FORMAT CSV, HEADER true)"
        % (table, _sql_path(staging / (table + ".csv")))
        for table in EVENT_TABLES
    ]
    command = "BEGIN;\nTRUNCATE TABLE %s;\n%s\n%s\nCOMMIT;\nSELECT '%s';" % (
        ", ".join("public.%s" % table for table in EVENT_TABLES),
        "\n".join(copy_commands),
        "SELECT setval('audit_log_seq', COALESCE(MAX(audit_log_id), 1), "
        "MAX(audit_log_id) IS NOT NULL) FROM public.audit_log;",
        success_marker,
    )
    _run_psql(command, success_marker)


def restore_backup(directory, filename):
    """Back up current event rows, then atomically import every event CSV."""
    directory = _real_directory(directory)
    archive = _archive_path(directory, filename)
    _validate_archive(archive)

    current_backup = create_backup(directory, prefix="pre-restore-current-events-")
    staging = Path(tempfile.mkdtemp(prefix="event-db-restore-"))
    try:
        _extract_archive(archive, staging)
        _restore_tables(staging)
    finally:
        shutil.rmtree(str(staging), ignore_errors=True)
    return current_backup, archive


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
            archive = create_backup(args.directory)
            print("SUCCESS: %s" % archive)
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
