#!/usr/bin/python3

import importlib.util
import json
import sys
import syslog
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).parents[1] / "bin" / "audit-storage-usage.py"
ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "packaging/pythonlib"))
SPEC = importlib.util.spec_from_file_location("audit_storage_usage", str(MODULE_PATH))
usage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(usage)


class AuditStorageUsageTest(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.data = self.root / "data"
        (self.data / "pg_wal").mkdir(parents=True)
        (self.data / "PG_VERSION").write_text("13\n")
        (self.data / "pg_wal" / "000000010000000000000001").write_bytes(b"w" * 4096)
        (self.data / "pg_wal" / "archive_status").mkdir()
        self.logs = self.root / "logs"
        self.logs.mkdir()
        self.config = mock.patch.object(
            usage, "database_config", return_value={"host": "localhost", "database": "engine"})
        self.config.start()

    def tearDown(self):
        self.config.stop()
        self.temporary.cleanup()

    @staticmethod
    def postgres(settings=None, transaction_age=10, slots=(), max_wal_size=1024 ** 3):
        settings = settings or {}

        def run(sql, database="postgres"):
            if sql.startswith("SHOW data_directory"):
                return []
            if "max_wal_size" in sql:
                return [[str(max_wal_size)]]
            if "current_setting" in sql:
                name = sql.split("'")[1]
                return [[settings.get(name, "on")]]
            if "pg_stat_activity" in sql:
                return [["4242", "psql", str(transaction_age)]]
            if "pg_replication_slots" in sql:
                return [list(slot) for slot in slots]
            raise AssertionError(sql)
        return run

    def test_usage_reports_the_database_file_system_and_its_wal(self):
        with mock.patch.object(usage, "run_postgres_query", side_effect=self.postgres()):
            report = usage.measure(str(self.logs), data_dir=str(self.data))

        database = report["filesystems"]["db"]
        self.assertEqual(str(self.data), database["path"])
        for key in ("mount", "device", "used_bytes", "available_bytes", "used_percent"):
            self.assertIn(key, database)
        self.assertEqual(4096, report["wal"]["size_bytes"])
        self.assertEqual(1024 ** 3, report["wal"]["max_wal_size_bytes"])
        self.assertEqual([], report["maintenance_warnings"])
        self.assertIn("log", report["filesystems"])
        self.assertNotIn("backup", report["filesystems"])
        json.dumps(report)

    def test_data_directory_must_be_a_postgresql_one(self):
        (self.data / "PG_VERSION").unlink()
        report = usage.measure(str(self.logs), data_dir=str(self.data))
        self.assertIn("PG_VERSION", report["filesystems"]["db"]["error"])
        self.assertNotIn("expected", report["filesystems"]["db"])

    def test_relative_or_unnormalized_paths_are_refused(self):
        for value in ("relative/dir", str(self.logs) + "/../logs"):
            with self.assertRaises(usage.MeasurementError):
                usage.filesystem_usage(value)

    def test_remote_database_is_an_expected_gap(self):
        self.config.stop()
        with mock.patch.object(
                usage, "database_config", return_value={"host": "db.example.test", "database": "engine"}), \
                mock.patch.object(usage.socket, "gethostname", return_value="engine.example.test"), \
                mock.patch.object(usage.socket, "getfqdn", return_value="engine.example.test"):
            report = usage.measure(str(self.logs))
        self.config.start()
        self.assertTrue(report["filesystems"]["db"]["expected"])
        self.assertTrue(report["wal"]["expected"])
        self.assertIn("db.example.test", report["filesystems"]["db"]["error"])

    def test_local_data_directory_falls_back_to_the_default_location(self):
        with mock.patch.object(usage, "run_postgres_query", side_effect=self.postgres()), \
                mock.patch.object(usage, "DEFAULT_DATA_DIRECTORIES", (self.data,)):
            report = usage.measure(str(self.logs))
        self.assertEqual(str(self.data), report["database"]["data_directory"])

    def test_maintenance_problems_are_reported(self):
        slots = (("standby", "f", "5000"),)
        with mock.patch.object(
                usage, "run_postgres_query",
                side_effect=self.postgres(
                    {"autovacuum": "off"}, transaction_age=7200, slots=slots, max_wal_size=1024)):
            report = usage.measure(str(self.logs), data_dir=str(self.data))
        warnings = " ".join(report["maintenance_warnings"])
        self.assertIn("autovacuum", warnings)
        self.assertIn("4242", warnings)
        self.assertIn("standby", warnings)
        # 4 KiB of WAL is more than twice the 1 KiB max_wal_size.
        self.assertIn("max_wal_size", warnings)

    def test_levels_follow_the_thresholds(self):
        thresholds = usage.parse_thresholds("70,80,90,95")
        self.assertEqual("NORMAL", usage.level_of(69.9, thresholds))
        self.assertEqual("NOTICE", usage.level_of(70, thresholds))
        self.assertEqual("WARNING", usage.level_of(85, thresholds))
        self.assertEqual("HIGH", usage.level_of(90, thresholds))
        self.assertEqual("CRITICAL", usage.level_of(99, thresholds))
        self.assertEqual("FULL", usage.level_of(100, thresholds))

    def test_unusable_thresholds_fall_back_to_the_defaults(self):
        for value in ("95,90,80,70", "70,80,90", "70,80,90,100", "x"):
            self.assertEqual(usage.DEFAULT_THRESHOLDS, usage.parse_thresholds(value))
        self.assertEqual((60, 75, 85, 97), usage.parse_thresholds("60, 75,85,97"))

    def test_watch_reports_lower_levels_once_and_serious_levels_every_time(self):
        state = self.root / "state.json"
        thresholds = usage.DEFAULT_THRESHOLDS

        def report(percent):
            used = int(percent)
            return {"filesystems": {"db": {
                "path": "/var/lib/pgsql/data", "used_bytes": used, "available_bytes": 100 - used,
                "used_percent": percent}}, "maintenance_warnings": []}

        messages = []

        def log(priority, message):
            messages.append((priority, message))

        usage.watch(report(82.0), thresholds, state, log)
        usage.watch(report(83.0), thresholds, state, log)
        self.assertEqual(1, len(messages))
        self.assertEqual(syslog.LOG_WARNING, messages[0][0])
        self.assertIn("WARNING", messages[0][1])

        usage.watch(report(96.0), thresholds, state, log)
        usage.watch(report(96.0), thresholds, state, log)
        self.assertEqual(3, len(messages))
        self.assertEqual(syslog.LOG_ALERT, messages[-1][0])
        self.assertIn("do not remove PostgreSQL files manually", messages[-1][1])

        usage.watch(report(10.0), thresholds, state, log)
        self.assertIn("RECOVERED", messages[-1][1])

    def test_watch_logs_measurement_failures_but_not_a_remote_database(self):
        messages = []

        def log(priority, message):
            messages.append((priority, message))
        report = {"filesystems": {
            "db": {"path": "", "error": "remote", "expected": True},
            "backup": {"path": "/backup", "error": "디렉터리가 없습니다"},
        }, "maintenance_warnings": ["autovacuum off"]}
        usage.watch(report, usage.DEFAULT_THRESHOLDS, self.root / "state.json", log)
        self.assertEqual([syslog.LOG_ERR, syslog.LOG_WARNING], [priority for priority, _ in messages])

    def test_usage_command_prints_json(self):
        with mock.patch.object(usage, "run_postgres_query", side_effect=self.postgres()), \
                mock.patch.object(usage, "read_settings", return_value={"AUDIT_STORAGE_RESERVE_MB": "1"}), \
                mock.patch.object(usage.syslog, "syslog"), \
                mock.patch("builtins.print") as printed:
            self.assertEqual(0, usage.main(["usage", "--log-dir", str(self.logs), "--data-dir", str(self.data),
                                            "--selected-dir", str(self.root)]))
        report = json.loads(printed.call_args[0][0])
        self.assertIn("selected", report["filesystems"])
        # The engine's run keeps the reserve as well; it goes next to the data directory.
        self.assertEqual(str(self.root / usage.RESERVE_NAME), report["reserve"]["path"])
        self.assertIn(report["reserve"]["state"], ("present", "insufficient"))

    def test_wal_on_the_data_file_system_is_reported(self):
        with mock.patch.object(usage, "run_postgres_query", side_effect=self.postgres()):
            report = usage.measure(str(self.logs), data_dir=str(self.data))
        self.assertTrue(report["wal"]["same_filesystem"])
        self.assertIn("PANIC", usage.wal_shared_warning(report))
        report["wal"]["same_filesystem"] = False
        self.assertIsNone(usage.wal_shared_warning(report))

    def _measured(self, percent):
        with mock.patch.object(usage, "run_postgres_query", side_effect=self.postgres()):
            report = usage.measure(str(self.logs), data_dir=str(self.data))
        database = report["filesystems"]["db"]
        database["used_percent"] = percent
        total = database["used_bytes"] + database["available_bytes"]
        database["used_bytes"] = int(total * percent / 100)
        database["available_bytes"] = total - database["used_bytes"]
        return report

    def test_reserve_is_created_released_at_the_critical_level_and_put_back(self):
        settings = {"AUDIT_STORAGE_RESERVE_MB": "1"}
        reserve = self.root / usage.RESERVE_NAME
        messages = []

        def log(priority, message):
            messages.append((priority, message))

        entry = usage.manage_reserve(self._measured(10.0), usage.DEFAULT_THRESHOLDS, settings, log)
        self.assertEqual(("present", "created"), (entry["state"], entry["action"]))
        self.assertEqual(usage.MIB, reserve.stat().st_size)

        entry = usage.manage_reserve(self._measured(50.0), usage.DEFAULT_THRESHOLDS, settings, log)
        self.assertEqual("present", entry["state"])
        self.assertNotIn("action", entry)

        entry = usage.manage_reserve(self._measured(96.0), usage.DEFAULT_THRESHOLDS, settings, log)
        self.assertEqual(("released", "released"), (entry["state"], entry["action"]))
        self.assertFalse(reserve.exists())
        self.assertEqual(syslog.LOG_ALERT, messages[-1][0])
        self.assertIn("RELEASED", messages[-1][1])

        # Not put back while the file system is still above the high level.
        entry = usage.manage_reserve(self._measured(92.0), usage.DEFAULT_THRESHOLDS, settings, log)
        self.assertEqual("released", entry["state"])
        self.assertFalse(reserve.exists())

        entry = usage.manage_reserve(self._measured(40.0), usage.DEFAULT_THRESHOLDS, settings, log)
        self.assertEqual(("present", "restored"), (entry["state"], entry["action"]))
        self.assertTrue(reserve.exists())
        self.assertFalse(usage._released_marker(reserve).exists())

        entry = usage.manage_reserve(
            self._measured(40.0), usage.DEFAULT_THRESHOLDS, {"AUDIT_STORAGE_RESERVE_MB": "0"}, log)
        self.assertEqual(("disabled", "removed"), (entry["state"], entry["action"]))
        self.assertFalse(reserve.exists())

    def test_reserve_is_not_created_when_it_would_raise_an_alarm(self):
        report = self._measured(89.9)
        database = report["filesystems"]["db"]
        settings = {"AUDIT_STORAGE_RESERVE_MB": str(database["available_bytes"] // usage.MIB)}
        entry = usage.manage_reserve(report, usage.DEFAULT_THRESHOLDS, settings, lambda *_: None)
        self.assertEqual("insufficient", entry["state"])
        self.assertFalse((self.root / usage.RESERVE_NAME).exists())

    def test_reserve_refuses_paths_it_cannot_use(self):
        log = lambda *_: None  # noqa: E731
        inside = {"AUDIT_STORAGE_RESERVE_MB": "1", "AUDIT_STORAGE_RESERVE_PATH": str(self.data / "reserve")}
        entry = usage.manage_reserve(self._measured(10.0), usage.DEFAULT_THRESHOLDS, inside, log)
        self.assertEqual("error", entry["state"])
        self.assertFalse((self.data / "reserve").exists())

        relative = {"AUDIT_STORAGE_RESERVE_PATH": "reserve"}
        self.assertEqual("error", usage.manage_reserve(
            self._measured(10.0), usage.DEFAULT_THRESHOLDS, relative, log)["state"])

        target = self.root / "precious"
        target.write_text("keep")
        (self.root / usage.RESERVE_NAME).symlink_to(target)
        entry = usage.manage_reserve(
            self._measured(99.0), usage.DEFAULT_THRESHOLDS, {"AUDIT_STORAGE_RESERVE_MB": "1"}, log)
        self.assertEqual("error", entry["state"])
        self.assertEqual("keep", target.read_text())
        self.assertTrue((self.root / usage.RESERVE_NAME).is_symlink())

    def test_reserve_is_not_kept_for_a_database_it_cannot_measure(self):
        report = {"database": {}, "filesystems": {"db": {"path": "", "error": "remote", "expected": True}}}
        self.assertEqual("unavailable", usage.manage_reserve(
            report, usage.DEFAULT_THRESHOLDS, {}, lambda *_: None)["state"])

    def test_settings_come_from_the_watch_configuration_and_the_environment(self):
        config = self.root / "watch.conf"
        config.write_text(
            "# comment\nAUDIT_STORAGE_RESERVE_MB=512\nAUDIT_STORAGE_RESERVE_PATH=\"/srv/reserve\"\nOTHER=1\n")
        settings = usage.read_settings(config, {"AUDIT_STORAGE_RESERVE_MB": "256"})
        self.assertEqual("256", settings["AUDIT_STORAGE_RESERVE_MB"])
        self.assertEqual("/srv/reserve", settings["AUDIT_STORAGE_RESERVE_PATH"])
        self.assertNotIn("OTHER", settings)
        self.assertEqual(256 * usage.MIB, usage.reserve_size(settings))
        self.assertEqual(usage.DEFAULT_RESERVE_MB * usage.MIB, usage.reserve_size({}))
        self.assertEqual(usage.DEFAULT_RESERVE_MB * usage.MIB,
                         usage.reserve_size({"AUDIT_STORAGE_RESERVE_MB": "x"}))
        self.assertEqual({}, usage.read_settings(self.root / "missing.conf", {}))

    def test_watch_repeats_serious_levels_at_most_every_repeat_interval(self):
        state = self.root / "state.json"
        clock = [1000.0]
        messages = []

        def log(priority, message):
            messages.append((priority, message))

        report = {"filesystems": {"db": {
            "path": "/var/lib/pgsql/data", "used_bytes": 96, "available_bytes": 4,
            "used_percent": 96.0}}, "maintenance_warnings": []}
        for _ in range(3):
            usage.watch(report, usage.DEFAULT_THRESHOLDS, state, log, 600, lambda: clock[0])
            clock[0] += 120
        self.assertEqual(1, len(messages))
        clock[0] += 600
        usage.watch(report, usage.DEFAULT_THRESHOLDS, state, log, 600, lambda: clock[0])
        self.assertEqual(2, len(messages))

    def test_watch_writes_the_wal_layout_and_reserve_problems_once(self):
        state = self.root / "state.json"
        messages = []

        def log(priority, message):
            messages.append((priority, message))

        report = {"filesystems": {"db": {
            "path": "/var/lib/pgsql/data", "mount": "/", "used_bytes": 10, "available_bytes": 90,
            "used_percent": 10.0}}, "maintenance_warnings": [],
            "wal": {"same_filesystem": True},
            "reserve": {"state": "insufficient", "detail": "no room"}}
        usage.watch(report, usage.DEFAULT_THRESHOLDS, state, log)
        usage.watch(report, usage.DEFAULT_THRESHOLDS, state, log)
        texts = [message for _, message in messages]
        self.assertEqual(1, sum("WAL" in text for text in texts))
        self.assertEqual(1, sum("no room" in text for text in texts))


class AuditStorageIntegrationTest(unittest.TestCase):

    def test_engine_may_run_the_helper_through_sudo(self):
        acl = (ROOT / "packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/system/acl.py").read_text(
            encoding="utf-8")
        self.assertIn("/usr/share/ovirt-engine/bin/audit-storage-usage.py usage *", acl)

    def test_helper_is_packaged_and_executable(self):
        spec = (ROOT / "ovirt-engine.spec.in").read_text(encoding="utf-8")
        self.assertIn("%{engine_data}/bin/audit-storage-usage.py", spec)
        self.assertTrue(MODULE_PATH.stat().st_mode & 0o111)

    def test_engine_calls_the_same_helper_and_operation(self):
        helper = (ROOT / "backend/manager/modules/bll/src/main/java/org/ovirt/engine/core/bll"
                  / "AuditStorageHelper.java").read_text(encoding="utf-8")
        self.assertIn('"/usr/share/ovirt-engine/bin/audit-storage-usage.py"', helper)
        self.assertIn('"usage"', helper)
        for option in ("--log-dir", "--data-dir", "--backup-dir", "--selected-dir"):
            self.assertIn('"%s"' % option, helper)


if __name__ == "__main__":
    unittest.main()
