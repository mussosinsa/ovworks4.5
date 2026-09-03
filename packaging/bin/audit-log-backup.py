#!/usr/bin/python3
"""Back up and restore every table in the oVirt Engine database.

This helper runs the supported ``engine-backup`` utility through the narrowly
scoped sudo rule installed by engine-setup. Archives contain a complete Engine
database dump, including the ``audit_log`` table used by the Events screen.
"""

import argparse
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path


ENGINE_BACKUP = Path("/usr/bin/engine-backup")
ARCHIVE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.tar\.gz$")


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


def _run_engine_backup(mode, archive, log_file):
    command = [
        str(ENGINE_BACKUP),
        "--mode=%s" % mode,
        "--scope=db",
        "--file=%s" % archive,
        "--log=%s" % log_file,
    ]
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
    except OSError as error:
        raise AuditLogBackupError("Engine DB 백업 도구를 실행할 수 없습니다: %s" % error) from error
    if result.returncode != 0:
        detail = (result.stdout or "").strip()
        raise AuditLogBackupError(
            "Engine DB %s 실패 (종료 코드 %s): %s" % (mode, result.returncode, detail)
        )


def create_backup(directory, prefix=""):
    """Create a compressed dump containing every table in the Engine DB."""
    directory = _real_directory(directory)
    archive = directory / (prefix + _timestamp() + ".tar.gz")
    temporary = archive.with_name(".%s.tmp" % archive.name)
    log_file = archive.with_name(".%s.log" % archive.name)
    try:
        _run_engine_backup("backup", temporary, log_file)
        if not temporary.is_file() or temporary.stat().st_size == 0:
            raise AuditLogBackupError("Engine DB 백업 파일이 생성되지 않았습니다.")
        os.chmod(str(temporary), 0o640)
        os.replace(str(temporary), str(archive))
    except (OSError, AuditLogBackupError) as error:
        try:
            temporary.unlink()
        except OSError:
            pass
        if isinstance(error, AuditLogBackupError):
            raise
        raise AuditLogBackupError("Engine DB 백업 실패: %s" % error) from error
    finally:
        try:
            log_file.unlink()
        except OSError:
            pass
    return archive


def restore_backup(directory, filename):
    """Back up the current DB, then restore all tables from an archive."""
    directory = _real_directory(directory)
    archive = _archive_path(directory, filename)

    # A recoverable copy of the current database must exist before replacement.
    current_backup = create_backup(directory, prefix="pre-restore-current-db-")
    log_file = directory / (".restore-%s.log" % _timestamp())
    try:
        _run_engine_backup("restore", archive, log_file)
    finally:
        try:
            log_file.unlink()
        except OSError:
            pass
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
