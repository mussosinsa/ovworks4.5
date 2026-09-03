#!/usr/bin/python3

import importlib.util
import io
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).parents[1] / "bin" / "audit-log-backup.py"
SPEC = importlib.util.spec_from_file_location("audit_log_backup", str(MODULE_PATH))
audit_log_backup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit_log_backup)


class AuditLogBackupTest(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.backup_dir = self.root / "backups"
        self.backup_dir.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def successful_engine_backup(command, **kwargs):
        file_argument = next(value for value in command if value.startswith("--file="))
        mode_argument = next(value for value in command if value.startswith("--mode="))
        if mode_argument == "--mode=backup":
            Path(file_argument.split("=", 1)[1]).write_bytes(b"complete engine database")
        return mock.Mock(returncode=0, stdout="Done")

    @mock.patch.object(audit_log_backup.subprocess, "run")
    def test_backup_uses_engine_backup_for_all_database_tables(self, run):
        run.side_effect = self.successful_engine_backup

        archive = audit_log_backup.create_backup(self.backup_dir)

        self.assertTrue(archive.is_file())
        command = run.call_args.args[0]
        self.assertIn("--mode=backup", command)
        self.assertIn("--scope=db", command)
        self.assertTrue(any(value.startswith("--file=") for value in command))
        self.assertEqual(0o640, archive.stat().st_mode & 0o777)

    @mock.patch.object(audit_log_backup.subprocess, "run")
    def test_restore_backs_up_current_database_before_full_restore(self, run):
        run.side_effect = self.successful_engine_backup
        archive = self.backup_dir / "selected.tar.gz"
        archive.write_bytes(b"previous complete database")

        current_backup, restored = audit_log_backup.restore_backup(
            self.backup_dir,
            archive.name,
        )

        self.assertTrue(current_backup.name.startswith("pre-restore-current-db-"))
        self.assertEqual(archive, restored)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual("--mode=backup", commands[0][1])
        self.assertEqual("--mode=restore", commands[1][1])
        self.assertIn("--scope=db", commands[1])

    @mock.patch.object(audit_log_backup.subprocess, "run")
    def test_restore_failure_keeps_pre_restore_database_backup(self, run):
        def fail_restore(command, **kwargs):
            result = self.successful_engine_backup(command, **kwargs)
            if "--mode=restore" in command:
                return mock.Mock(returncode=1, stdout="restore failed")
            return result

        run.side_effect = fail_restore
        archive = self.backup_dir / "selected.tar.gz"
        archive.write_bytes(b"previous complete database")

        with self.assertRaises(audit_log_backup.AuditLogBackupError):
            audit_log_backup.restore_backup(self.backup_dir, archive.name)

        self.assertEqual(1, len(list(self.backup_dir.glob("pre-restore-current-db-*.tar.gz"))))

    def test_restore_rejects_path_traversal_filename_before_current_backup(self):
        with mock.patch.object(audit_log_backup, "create_backup") as create_backup:
            with self.assertRaises(audit_log_backup.AuditLogBackupError):
                audit_log_backup.restore_backup(self.backup_dir, "../outside.tar.gz")
        create_backup.assert_not_called()

    def test_restore_rejects_symbolic_link_archive(self):
        outside = self.root / "outside.tar.gz"
        outside.write_bytes(b"not an archive")
        link = self.backup_dir / "linked.tar.gz"
        link.symlink_to(outside)

        with self.assertRaises(audit_log_backup.AuditLogBackupError):
            audit_log_backup.restore_backup(self.backup_dir, link.name)

    @mock.patch.object(audit_log_backup.subprocess, "run")
    def test_failed_database_backup_removes_partial_archive(self, run):
        run.return_value = mock.Mock(returncode=1, stdout="database unavailable")

        with self.assertRaises(audit_log_backup.AuditLogBackupError):
            audit_log_backup.create_backup(self.backup_dir)

        self.assertEqual([], list(self.backup_dir.glob("*.tar.gz")))

    def test_main_reports_safe_failure(self):
        error_output = io.StringIO()
        with redirect_stderr(error_output):
            status = audit_log_backup.main(["backup", str(self.root / "missing")])
        self.assertEqual(1, status)
        self.assertIn("FAIL:", error_output.getvalue())


if __name__ == "__main__":
    unittest.main()
