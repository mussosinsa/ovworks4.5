#!/usr/bin/python3
"""Create and safely restore oVirt audit-log archives.

This helper is intended to run as root through the narrowly scoped sudo rule
installed by engine-setup. Restores are placed in an isolated directory below
the configured backup directory; active audit logs are never overwritten.
"""

import argparse
import os
import re
import shutil
import sys
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path, PurePosixPath


AUDIT_LOG_DIR = Path("/var/log/ovirt-engine")
ARCHIVE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.tar\.gz$")
ARCHIVE_PREFIXES = (("ovirt-engine",), ("var", "log", "ovirt-engine"))
MAX_RESTORE_MEMBERS = 1_000_000
MAX_RESTORE_BYTES = 100 * 1024 * 1024 * 1024


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


def _relative_member(member):
    """Return a safe path below the archive's ovirt-engine root."""
    path = PurePosixPath(member.name)
    if path.is_absolute() or ".." in path.parts:
        raise AuditLogBackupError("백업 파일에 안전하지 않은 경로가 있습니다: %s" % member.name)
    if not member.isdir() and not member.isfile():
        raise AuditLogBackupError("백업 파일에 링크 또는 특수 파일이 있습니다: %s" % member.name)
    for prefix in ARCHIVE_PREFIXES:
        if path.parts[:len(prefix)] == prefix:
            relative = path.parts[len(prefix):]
            if not relative:
                return None
            return Path(*relative)
    raise AuditLogBackupError("백업 파일에 감사기록 외 경로가 있습니다: %s" % member.name)


def _validate_archive(archive):
    members = []
    destinations = set()
    expanded_size = 0
    try:
        with tarfile.open(str(archive), "r:gz") as stream:
            for member in stream:
                relative = _relative_member(member)
                if relative is not None:
                    if relative in destinations:
                        raise AuditLogBackupError(
                            "백업 파일에 중복 경로가 있습니다: %s" % member.name
                        )
                    destinations.add(relative)
                    expanded_size += member.size
                    if len(destinations) > MAX_RESTORE_MEMBERS or expanded_size > MAX_RESTORE_BYTES:
                        raise AuditLogBackupError("백업 파일의 복구 크기 또는 항목 수가 제한을 초과합니다.")
                    members.append((member.name, relative, member.isdir()))
    except (OSError, tarfile.TarError) as error:
        raise AuditLogBackupError("백업 파일을 읽을 수 없습니다: %s" % error) from error
    if not members:
        raise AuditLogBackupError("백업 파일에 복구할 감사기록이 없습니다.")
    return members


def _timestamp():
    return datetime.now().strftime("%Y%m%d%H%M%S%f")


def create_backup(directory, prefix=""):
    directory = _real_directory(directory)
    if not AUDIT_LOG_DIR.is_dir():
        raise AuditLogBackupError("감사기록 디렉터리를 찾을 수 없습니다: %s" % AUDIT_LOG_DIR)
    audit_directory = AUDIT_LOG_DIR.resolve(strict=True)
    if directory == audit_directory or audit_directory in directory.parents:
        raise AuditLogBackupError("저장 위치는 감사기록 디렉터리 밖에 있어야 합니다.")
    archive = directory / (prefix + _timestamp() + ".tar.gz")
    temporary = archive.with_name(".%s.tmp" % archive.name)
    try:
        with tarfile.open(str(temporary), "w:gz") as stream:
            def exclude_restore_area(member):
                if member.name == "ovirt-engine/restored" or member.name.startswith("ovirt-engine/restored/"):
                    return None
                return member

            stream.add(
                str(AUDIT_LOG_DIR),
                arcname="ovirt-engine",
                recursive=True,
                filter=exclude_restore_area,
            )
        os.chmod(str(temporary), 0o640)
        os.replace(str(temporary), str(archive))
    except (OSError, tarfile.TarError) as error:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise AuditLogBackupError("현재 감사기록 백업 실패: %s" % error) from error
    return archive


def _extract_to_staging(archive, members, staging):
    with tarfile.open(str(archive), "r:gz") as stream:
        for original_name, relative, is_directory in members:
            destination = staging / relative
            if is_directory:
                destination.mkdir(mode=0o750, parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
            source = stream.extractfile(original_name)
            if source is None:
                raise AuditLogBackupError("백업 파일 항목을 읽을 수 없습니다: %s" % original_name)
            with source, destination.open("wb") as output:
                shutil.copyfileobj(source, output)
            destination.chmod(0o640)


def restore_backup(directory, filename):
    directory = _real_directory(directory)
    archive = _archive_path(directory, filename)
    members = _validate_archive(archive)

    # This must complete before any selected archive data is restored.
    current_backup = create_backup(directory, prefix="pre-restore-current-audit-")

    restored_root = directory
    restored_root.mkdir(mode=0o750, parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".restore-", dir=str(restored_root)))
    final = restored_root / (archive.name[:-7] + "-restored-" + _timestamp())
    try:
        _extract_to_staging(archive, members, staging)
        os.replace(str(staging), str(final))
    except (OSError, tarfile.TarError, AuditLogBackupError) as error:
        shutil.rmtree(str(staging), ignore_errors=True)
        if isinstance(error, AuditLogBackupError):
            raise
        raise AuditLogBackupError("감사기록 복구 실패: %s" % error) from error
    return current_backup, final


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
            print("RESTORED_TO: %s" % restored)
    except AuditLogBackupError as error:
        print("FAIL: %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
