#!/usr/bin/python3
"""Measure the storage the oVirt audit records depend on.

The physical limit of the audit records is the file system under the PostgreSQL
data directory, not a number in the engine configuration.  This helper runs as
root - the engine through sudo, the watch timer through systemd - because the
data directory is private to postgres and only postgres may read the server
settings that say where it is.

usage   prints what it measured as JSON for the engine.
watch   writes the same measurement to syslog (authpriv) with the level each
        store reached, so the storage is watched even while the engine is down.
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import syslog
from pathlib import Path

ENGINE_DEFAULTS = Path("/usr/share/ovirt-engine/services/ovirt-engine/ovirt-engine.conf")
ENGINE_VARS = Path("/etc/ovirt-engine/engine.conf")
PSQL = Path("/usr/bin/psql")
RUNUSER = Path("/usr/sbin/runuser")
DEFAULT_DATA_DIRECTORIES = (Path("/var/lib/pgsql/data"),)
DEFAULT_LOG_DIRECTORY = "/var/log"
DEFAULT_STATE_FILE = Path("/var/lib/ovirt-engine/audit-storage-watch.json")
DEFAULT_THRESHOLDS = (70, 80, 90, 95)
PSQL_TIMEOUT_SECONDS = 20
LONG_TRANSACTION_SECONDS = 3600
LOCAL_HOSTS = ("", "localhost", "127.0.0.1", "::1", "localhost.localdomain")

# Ordered from the least to the most serious, like the engine's levels.
LEVELS = ("NORMAL", "NOTICE", "WARNING", "HIGH", "CRITICAL", "FULL")
LEVEL_LABELS = {
    "NORMAL": "정상",
    "NOTICE": "주의",
    "WARNING": "경계",
    "HIGH": "심각",
    "CRITICAL": "위기",
    "FULL": "포화",
}
LEVEL_PRIORITIES = {
    "NOTICE": syslog.LOG_NOTICE,
    "WARNING": syslog.LOG_WARNING,
    "HIGH": syslog.LOG_CRIT,
    "CRITICAL": syslog.LOG_ALERT,
    "FULL": syslog.LOG_ALERT,
}
LEVEL_ACTIONS = {
    "NOTICE": "Check backups, central log transfer and the growth trend.",
    "WARNING": "Analyse audit-log, WAL and log growth and request a capacity expansion.",
    "HIGH": "Validate backup/archive and execute the approved capacity expansion.",
    "CRITICAL": "Expand storage immediately; do not remove PostgreSQL files manually.",
    "FULL": "Database writes may fail. Follow the emergency procedure; "
            "do not remove PostgreSQL files, pg_wal or audit records manually.",
}


class MeasurementError(RuntimeError):
    """A store that could not be measured, with a reason safe to display."""


# ---------------------------------------------------------------------------
# File systems
# ---------------------------------------------------------------------------

def _checked_directory(value):
    """Return an absolute, normalized directory path or raise MeasurementError."""
    if not value or "\0" in value:
        raise MeasurementError("경로가 비어 있습니다.")
    if not os.path.isabs(value) or os.path.normpath(value) != (value.rstrip("/") or "/"):
        raise MeasurementError("정규화된 절대 경로가 아닙니다: %s" % value)
    path = Path(value)
    if not path.is_dir():
        raise MeasurementError("디렉터리가 없습니다: %s" % value)
    return path


def _mount_point(path):
    path = path.resolve()
    device = path.stat().st_dev
    while path.parent != path and path.parent.stat().st_dev == device:
        path = path.parent
    return path


def filesystem_usage(value):
    """Measure the file system holding a directory, the way df reports it."""
    path = _checked_directory(value)
    try:
        status = os.statvfs(str(path))
        device = path.stat().st_dev
        mount = _mount_point(path)
    except OSError as error:
        raise MeasurementError("파일시스템을 확인할 수 없습니다: %s (%s)" % (value, error)) from error
    total = status.f_blocks * status.f_frsize
    used = total - status.f_bfree * status.f_frsize
    available = status.f_bavail * status.f_frsize
    result = {
        "path": str(path),
        "mount": str(mount),
        "device": "%d:%d" % (os.major(device), os.minor(device)),
        "total_bytes": total,
        "used_bytes": used,
        "available_bytes": available,
        "used_percent": round(used * 100.0 / (used + available), 1) if used + available else 0.0,
    }
    if status.f_files:
        result["inode_used_percent"] = round(
            (status.f_files - status.f_ffree) * 100.0 / status.f_files, 1)
    return result


def directory_size(path):
    """Total size of the regular files under a directory, symbolic links not followed."""
    total = 0
    for root, _directories, files in os.walk(str(path)):
        for name in files:
            try:
                status = os.lstat(os.path.join(root, name))
            except OSError:
                continue
            if not os.path.islink(os.path.join(root, name)):
                total += status.st_size
    return total


def _error(path, reason, expected=False):
    entry = {"path": str(path or ""), "error": reason}
    if expected:
        entry["expected"] = True
    return entry


def _measure(value):
    try:
        return filesystem_usage(value)
    except MeasurementError as error:
        return _error(value, str(error))


# ---------------------------------------------------------------------------
# The engine database
# ---------------------------------------------------------------------------

def database_config():
    """The engine database connection settings, or empty values when unreadable."""
    try:
        from ovirt_engine import configfile
        config = configfile.ConfigFile((str(ENGINE_DEFAULTS), str(ENGINE_VARS)))
        return {
            "host": config.get("ENGINE_DB_HOST", "") or "",
            "database": config.get("ENGINE_DB_DATABASE", "") or "engine",
        }
    except Exception:  # pylint: disable=broad-except
        return {"host": "localhost", "database": "engine"}


def is_local_host(host):
    host = (host or "").strip().lower()
    if host in LOCAL_HOSTS or host.startswith("/"):
        return True
    try:
        return host in (socket.gethostname().lower(), socket.getfqdn().lower())
    except OSError:
        return False


# Read-only (pg_monitor), reachable by peer authentication from root only through
# the ovworks_ops map - the login this uses once local logins need a password.
# See ovirt_engine.pg_local_auth.
DB_OPS_ROLE = "ovworks_ops"


def run_postgres_query(sql, database="postgres"):
    """Run one query over the local socket; return its rows.

    As the read-only monitoring role where local logins need a password, and as
    the postgres user where they do not yet. Never prompts for a password.
    """
    psql = [
        str(PSQL), "-X", "-q", "-w", "-At", "-F", "\t",
        "-v", "ON_ERROR_STOP=1",
        "-d", database,
        "-c", sql,
    ]
    try:
        return _run_psql(psql + ["-U", DB_OPS_ROLE])
    except MeasurementError:
        return _run_psql([str(RUNUSER), "-u", "postgres", "--"] + psql)


def _run_psql(command):
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            universal_newlines=True,
            check=False,
            timeout=PSQL_TIMEOUT_SECONDS,
            cwd="/",
        )
    except subprocess.TimeoutExpired as error:
        raise MeasurementError("PostgreSQL 조회가 %d초 안에 끝나지 않았습니다." % PSQL_TIMEOUT_SECONDS) from error
    except OSError as error:
        raise MeasurementError("PostgreSQL 조회를 실행할 수 없습니다: %s" % error) from error
    if result.returncode != 0:
        raise MeasurementError("PostgreSQL 조회 실패: %s" % (result.stderr or "").strip())
    return [line.split("\t") for line in result.stdout.splitlines() if line]


def _is_data_directory(path):
    return path.is_dir() and (path / "PG_VERSION").is_file()


def find_data_directory(configured, database):
    """Locate the PostgreSQL data directory, or explain why it cannot be measured here."""
    if configured:
        path = _checked_directory(configured)
        if not _is_data_directory(path):
            raise MeasurementError("PostgreSQL 데이터 디렉터리가 아닙니다 (PG_VERSION 없음): %s" % configured)
        return path
    if not is_local_host(database["host"]):
        raise MeasurementError(
            "Engine DB가 원격 서버(%s)에 있어 이 서버에서는 DB 파일시스템을 측정할 수 없습니다. "
            "DB 서버에서 audit-storage-usage.py watch 로 감시하십시오." % database["host"])
    try:
        rows = run_postgres_query("SHOW data_directory")
        if rows and rows[0][0]:
            path = Path(rows[0][0])
            if _is_data_directory(path):
                return path
    except MeasurementError:
        pass
    for candidate in DEFAULT_DATA_DIRECTORIES:
        if _is_data_directory(candidate):
            return candidate
    raise MeasurementError("PostgreSQL 데이터 디렉터리를 찾을 수 없습니다. ENGINE_AUDIT_DB_DATA_DIR을 설정하십시오.")


def wal_usage(data_directory):
    wal = data_directory / "pg_wal"
    if not wal.exists():
        wal = data_directory / "pg_xlog"
    try:
        size = directory_size(wal.resolve(strict=True))
    except OSError as error:
        raise MeasurementError("WAL 디렉터리를 확인할 수 없습니다: %s" % error) from error
    result = {"path": str(wal), "size_bytes": size}
    if wal.is_symlink():
        result["target"] = str(wal.resolve())
    try:
        rows = run_postgres_query("SELECT pg_size_bytes(current_setting('max_wal_size'))")
        result["max_wal_size_bytes"] = int(rows[0][0])
    except (MeasurementError, IndexError, ValueError):
        pass
    return result


def maintenance_warnings(database, wal):
    """What keeps the engine database from reusing or releasing space."""
    warnings = []
    name = database["database"]
    try:
        for setting in ("autovacuum", "track_counts"):
            rows = run_postgres_query("SELECT current_setting('%s')" % setting, name)
            if rows and rows[0][0] != "on":
                warnings.append(
                    "%s이(가) 꺼져 있습니다. 삭제·갱신된 행의 공간이 재사용되지 않아 DB가 계속 커집니다." % setting)

        rows = run_postgres_query(
            "SELECT pid, COALESCE(application_name, ''), "
            "EXTRACT(EPOCH FROM now() - xact_start)::bigint "
            "FROM pg_stat_activity "
            "WHERE xact_start IS NOT NULL AND pid <> pg_backend_pid() "
            "ORDER BY xact_start LIMIT 1", name)
        if rows and int(rows[0][2]) >= LONG_TRANSACTION_SECONDS:
            warnings.append(
                "트랜잭션(pid %s, %s)이 %.1f시간째 열려 있어 VACUUM이 공간을 회수하지 못합니다."
                % (rows[0][0], rows[0][1] or "-", int(rows[0][2]) / 3600.0))

        maximum = wal.get("max_wal_size_bytes") if wal else None
        rows = run_postgres_query(
            "SELECT slot_name, active, "
            "COALESCE(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn), 0)::bigint "
            "FROM pg_replication_slots", name)
        for slot, active, retained in rows:
            retained = int(retained)
            if active != "t" or (maximum and retained > maximum):
                warnings.append(
                    "복제 슬롯 %s(%s)이 WAL %s를 붙잡고 있습니다."
                    % (slot, "활성" if active == "t" else "비활성", format_bytes(retained)))
    except (MeasurementError, IndexError, ValueError) as error:
        warnings.append("DB 공간 관리 상태를 확인하지 못했습니다: %s" % error)

    if wal and wal.get("max_wal_size_bytes") and wal["size_bytes"] > 2 * wal["max_wal_size_bytes"]:
        warnings.append(
            "pg_wal(%s)이 max_wal_size(%s)의 2배를 넘었습니다. 복제 슬롯, 장기 트랜잭션, archive_command 실패를 확인하십시오."
            % (format_bytes(wal["size_bytes"]), format_bytes(wal["max_wal_size_bytes"])))
    return warnings


def format_bytes(value):
    value = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return "%d B" % value if unit == "B" else "%.1f %s" % (value, unit)
        value /= 1024
    return "%.1f PiB" % value


# ---------------------------------------------------------------------------
# Measurement
# ---------------------------------------------------------------------------

def measure(log_dir, data_dir="", backup_dir="", selected_dir=""):
    database = database_config()
    local = is_local_host(database["host"])
    report = {
        "database": {"host": database["host"], "local": local},
        "filesystems": {},
        "maintenance_warnings": [],
    }
    filesystems = report["filesystems"]
    try:
        data_directory = find_data_directory(data_dir, database)
        report["database"]["data_directory"] = str(data_directory)
        filesystems["db"] = _measure(str(data_directory))
        try:
            report["wal"] = wal_usage(data_directory)
        except MeasurementError as error:
            report["wal"] = _error(data_directory / "pg_wal", str(error))
        if local or data_dir:
            report["maintenance_warnings"] = maintenance_warnings(database, report["wal"])
    except MeasurementError as error:
        remote = not local and not data_dir
        filesystems["db"] = _error(data_dir, str(error), expected=remote)
        report["wal"] = _error("", str(error), expected=remote)

    filesystems["log"] = _measure(log_dir or DEFAULT_LOG_DIRECTORY)
    if backup_dir:
        filesystems["backup"] = _measure(backup_dir)
    if selected_dir:
        filesystems["selected"] = _measure(selected_dir)
    return report


def parse_thresholds(value):
    try:
        values = tuple(int(part.strip()) for part in value.split(","))
    except (AttributeError, ValueError):
        return DEFAULT_THRESHOLDS
    if len(values) != 4 or values[0] < 1 or values[-1] > 99 or list(values) != sorted(set(values)):
        return DEFAULT_THRESHOLDS
    return values


def level_of(percent, thresholds):
    if percent >= 100:
        return "FULL"
    for level, threshold in zip(("CRITICAL", "HIGH", "WARNING", "NOTICE"), reversed(thresholds)):
        if percent >= threshold:
            return level
    return "NORMAL"


def should_report(previous, current):
    """The same decision the engine takes: lower levels once, serious ones every time."""
    if current == "NORMAL":
        return previous not in (None, "NORMAL")
    if LEVELS.index(current) >= LEVELS.index("HIGH"):
        return True
    return previous is None or LEVELS.index(current) > LEVELS.index(previous)


def _load_state(path):
    try:
        with open(str(path), encoding="utf-8") as state:
            data = json.load(state)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_state(path, state):
    temporary = Path(str(path) + ".tmp")
    try:
        temporary.parent.mkdir(parents=True, exist_ok=True)
        with open(str(temporary), "w", encoding="utf-8") as output:
            json.dump(state, output)
        os.replace(str(temporary), str(path))
    except OSError:
        pass


WATCHED = (
    ("db", "Engine DB filesystem"),
    ("log", "Log filesystem"),
    ("backup", "Audit backup filesystem"),
)


def watch(report, thresholds, state_file, log=syslog.syslog):
    """Write each store's level to syslog. Returns the most serious level."""
    previous_levels = _load_state(state_file)
    levels = {}
    worst = "NORMAL"
    for key, name in WATCHED:
        entry = report["filesystems"].get(key)
        if entry is None:
            continue
        if "error" in entry:
            if not entry.get("expected"):
                log(syslog.LOG_ERR, "oVirt %s could not be measured: %s" % (name, entry["error"]))
            continue
        percent = max(entry["used_percent"], entry.get("inode_used_percent", 0))
        level = level_of(percent, thresholds)
        levels[key] = level
        if LEVELS.index(level) > LEVELS.index(worst):
            worst = level
        if not should_report(previous_levels.get(key), level):
            continue
        if level == "NORMAL":
            log(syslog.LOG_NOTICE, "oVirt %s RECOVERED: %.1f%% used (%s)." % (name, percent, entry["path"]))
            continue
        log(LEVEL_PRIORITIES[level],
            "oVirt %s %s: %.1f%% used (%s of %s, %s). %s" % (
                name, level, percent,
                format_bytes(entry["used_bytes"]),
                format_bytes(entry["used_bytes"] + entry["available_bytes"]),
                entry["path"], LEVEL_ACTIONS[level]))
    for warning in report.get("maintenance_warnings", ()):
        log(syslog.LOG_WARNING, "oVirt Engine DB maintenance: %s" % warning)
    _save_state(state_file, levels)
    return worst


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(dest="operation")
    for name in ("usage", "watch"):
        sub = subparsers.add_parser(name)
        sub.add_argument("--log-dir", default=os.environ.get("AUDIT_STORAGE_LOG_DIR", DEFAULT_LOG_DIRECTORY))
        sub.add_argument("--data-dir", default=os.environ.get("AUDIT_STORAGE_DATA_DIR", ""))
        sub.add_argument("--backup-dir", default=os.environ.get("AUDIT_STORAGE_BACKUP_DIR", ""))
        if name == "usage":
            sub.add_argument("--selected-dir", default="")
        else:
            sub.add_argument("--thresholds", default=os.environ.get("AUDIT_STORAGE_THRESHOLDS", "70,80,90,95"))
            sub.add_argument("--state-file", default=str(DEFAULT_STATE_FILE))
    args = parser.parse_args(argv)
    if args.operation is None:
        parser.error("usage 또는 watch 작업이 필요합니다.")

    if args.operation == "usage":
        report = measure(args.log_dir, args.data_dir, args.backup_dir, args.selected_dir)
        print(json.dumps(report, ensure_ascii=False))
        return 0

    thresholds = parse_thresholds(args.thresholds)
    report = measure(args.log_dir, args.data_dir, args.backup_dir)
    syslog.openlog("ovirt-audit-storage", 0, syslog.LOG_AUTHPRIV)
    worst = watch(report, thresholds, Path(args.state_file))
    print("audit storage: %s (%s), thresholds %s" % (
        worst, LEVEL_LABELS[worst], ",".join(str(value) for value in thresholds)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
