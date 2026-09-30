#!/usr/bin/python3

import gzip
import importlib.util
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).parents[1] / "bin" / "audit-log-backup.py"
ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "packaging/pythonlib"))
SPEC = importlib.util.spec_from_file_location("audit_log_backup_purge", str(MODULE_PATH))
backup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backup)


class AuditLogPurgeTest(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.archive = self.root / "archive" / "purged"
        self.scripts = []
        self.commands = []

    def tearDown(self):
        self.temporary.cleanup()

    def database(self, rows=3, fail=False, vacuum_fails=False):
        def run(arguments, connect=True):
            self.commands.append(arguments)
            script = next((a.split("=", 1)[1] for a in arguments if a.startswith("--file=")), None)
            if script:
                text = Path(script).read_text(encoding="utf-8")
                self.scripts.append(text)
                if fail:
                    raise backup.AuditLogBackupError("이벤트 DB 작업 실패 (종료 코드 3): lock timeout")
                target = re.search(r"TO '([^']+)'", text).group(1)
                Path(target).write_text("audit_log_id,log_time\n" + "1,2026-01-01\n" * rows)
                return mock.Mock(returncode=0, stdout="BEGIN\nCOPY %d\nDELETE %d\nCOMMIT\n" % (rows, rows),
                                 stderr="")
            if vacuum_fails:
                raise backup.AuditLogBackupError("VACUUM 실패")
            return mock.Mock(returncode=0, stdout="VACUUM\n", stderr="")
        return run

    def test_archives_then_removes_in_one_repeatable_read_transaction(self):
        with mock.patch.object(backup, "_run_database_command", side_effect=self.database()):
            deleted, archive, vacuum_error = backup.purge_older_than(
                str(self.archive), "2026-07-02T03:35:35Z")

        self.assertEqual(3, deleted)
        self.assertIsNone(vacuum_error)
        self.assertTrue(archive.name.startswith("purged-audit-log-"))
        self.assertTrue(archive.name.endswith(".csv.gz"))
        with gzip.open(str(archive), "rt") as content:
            self.assertEqual(4, len(content.read().splitlines()))
        self.assertEqual(0o640, archive.stat().st_mode & 0o777)
        self.assertEqual([], list(self.archive.glob(".*.tmp")))

        script = self.scripts[0]
        self.assertTrue(script.startswith("BEGIN ISOLATION LEVEL REPEATABLE READ;"))
        copy = script.index("\\copy (SELECT * FROM public.audit_log WHERE log_time < '2026-07-02T03:35:35+00:00'")
        delete = script.index("DELETE FROM public.audit_log WHERE log_time < '2026-07-02T03:35:35+00:00'")
        self.assertLess(copy, delete)
        self.assertLess(delete, script.index("COMMIT;"))
        # The freed space is handed back for reuse once the rows are gone.
        self.assertIn("--command=VACUUM (ANALYZE) public.audit_log", self.commands[-1])

    def test_a_failed_transaction_removes_nothing_and_leaves_no_archive(self):
        with mock.patch.object(backup, "_run_database_command", side_effect=self.database(fail=True)):
            with self.assertRaises(backup.AuditLogBackupError):
                backup.purge_older_than(str(self.archive), "2026-07-02T03:35:35+00:00")
        self.assertEqual([], list(self.archive.iterdir()))

    def test_nothing_to_remove_leaves_no_archive(self):
        with mock.patch.object(backup, "_run_database_command", side_effect=self.database(rows=0)):
            deleted, archive, _ = backup.purge_older_than(str(self.archive), "2026-07-02T03:35:35Z")
        self.assertEqual(0, deleted)
        self.assertIsNone(archive)
        self.assertEqual([], list(self.archive.iterdir()))

    def test_a_failed_vacuum_is_reported_not_raised(self):
        with mock.patch.object(backup, "_run_database_command",
                               side_effect=self.database(vacuum_fails=True)):
            deleted, _archive, vacuum_error = backup.purge_older_than(str(self.archive), "2026-07-02T03:35:35Z")
        self.assertEqual(3, deleted)
        self.assertIn("VACUUM", vacuum_error)

    def test_cutoff_must_be_a_time_with_its_zone(self):
        for value in ("2026-07-02", "2026-07-02T03:35:35", "'; DROP TABLE audit_log; --", ""):
            with self.assertRaises(backup.AuditLogBackupError):
                backup._purge_cutoff(value)

    def test_archive_path_cannot_break_out_of_the_sql_literal(self):
        directory = self.root / "it's"
        directory.mkdir()
        with self.assertRaises(backup.AuditLogBackupError):
            backup._archive_directory(str(directory))

    def test_command_line_reports_what_was_removed(self):
        with mock.patch.object(backup, "_run_database_command", side_effect=self.database()), \
                mock.patch("builtins.print") as printed:
            self.assertEqual(0, backup.main(["purge", str(self.archive), "2026-07-02T03:35:35Z"]))
        lines = [call.args[0] for call in printed.call_args_list]
        self.assertEqual("SUCCESS", lines[0])
        self.assertEqual("DELETED: 3", lines[1])
        self.assertTrue(lines[2].startswith("ARCHIVE: " + str(self.archive)))

    def test_engine_may_run_the_purge_through_sudo(self):
        acl = (ROOT / "packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/system/acl.py").read_text(
            encoding="utf-8")
        self.assertIn("/usr/share/ovirt-engine/bin/audit-log-backup.py purge *", acl)
        purger = (ROOT / "backend/manager/modules/bll/src/main/java/org/ovirt/engine/core/bll"
                  / "AuditLogPurger.java").read_text(encoding="utf-8")
        self.assertIn('"/usr/share/ovirt-engine/bin/audit-log-backup.py"', purger)
        self.assertIn('"purge"', purger)

    def test_daily_cleanup_no_longer_deletes_without_an_archive(self):
        cleanup = (ROOT / "backend/manager/modules/bll/src/main/java/org/ovirt/engine/core/bll"
                   / "AuditLogCleanupManager.java").read_text(encoding="utf-8")
        self.assertNotIn("removeAllBeforeDate", cleanup)
        self.assertIn("purger.purgeOlderThan(", cleanup)


if __name__ == "__main__":
    unittest.main()
