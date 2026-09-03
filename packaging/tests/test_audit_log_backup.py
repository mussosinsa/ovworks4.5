#!/usr/bin/python3

import importlib.util
import io
import re
import tarfile
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
    def successful_psql(command, **kwargs):
        sql = command[-1]
        export = re.search(r"TO '([^']+)'", sql)
        if export:
            Path(export.group(1)).write_text("id,value\n1,test\n", encoding="utf-8")
        return mock.Mock(returncode=0, stdout="COPY 1")

    @mock.patch.object(audit_log_backup.subprocess, "run")
    def test_backup_exports_all_event_tables_as_csv(self, run):
        run.side_effect = self.successful_psql

        archive = audit_log_backup.create_backup(self.backup_dir)

        self.assertTrue(archive.is_file())
        commands = [call.args[0][-1] for call in run.call_args_list]
        for table in audit_log_backup.EVENT_TABLES:
            self.assertTrue(any("public.%s TO" % table in command for command in commands))
        with tarfile.open(str(archive), "r:gz") as stream:
            names = set(stream.getnames())
        for table in audit_log_backup.EVENT_TABLES:
            self.assertIn("event-database/%s.csv" % table, names)
        self.assertIn("event-database/manifest.json", names)
        self.assertEqual(0o640, archive.stat().st_mode & 0o777)

    @mock.patch.object(audit_log_backup.subprocess, "run")
    def test_restore_backs_up_current_events_then_imports_every_csv(self, run):
        run.side_effect = self.successful_psql
        archive = audit_log_backup.create_backup(self.backup_dir)
        run.reset_mock()

        current_backup, restored = audit_log_backup.restore_backup(self.backup_dir, archive.name)

        self.assertTrue(current_backup.name.startswith("pre-restore-current-events-"))
        self.assertEqual(archive, restored)
        restore_sql = run.call_args_list[-1].args[0][-1]
        self.assertIn("BEGIN;", restore_sql)
        self.assertIn("TRUNCATE TABLE", restore_sql)
        self.assertIn("COMMIT;", restore_sql)
        self.assertIn("setval('audit_log_seq'", restore_sql)
        for table in audit_log_backup.EVENT_TABLES:
            self.assertIn("public.%s FROM" % table, restore_sql)

    @mock.patch.object(audit_log_backup.subprocess, "run")
    def test_restore_failure_keeps_pre_restore_event_backup(self, run):
        run.side_effect = self.successful_psql
        archive = audit_log_backup.create_backup(self.backup_dir)

        def fail_import(command, **kwargs):
            if "TRUNCATE TABLE" in command[-1]:
                return mock.Mock(returncode=1, stdout="import failed")
            return self.successful_psql(command, **kwargs)

        run.side_effect = fail_import
        with self.assertRaises(audit_log_backup.AuditLogBackupError):
            audit_log_backup.restore_backup(self.backup_dir, archive.name)

        backups = list(self.backup_dir.glob("pre-restore-current-events-*.tar.gz"))
        self.assertEqual(1, len(backups))

    def test_restore_rejects_archive_missing_an_event_table(self):
        archive = self.backup_dir / "incomplete.tar.gz"
        with tarfile.open(str(archive), "w:gz") as stream:
            value = self.root / "manifest.json"
            value.write_text("{}", encoding="utf-8")
            stream.add(str(value), arcname="event-database/manifest.json")

        with mock.patch.object(audit_log_backup, "create_backup") as create_backup:
            with self.assertRaises(audit_log_backup.AuditLogBackupError):
                audit_log_backup.restore_backup(self.backup_dir, archive.name)
        create_backup.assert_not_called()

    @mock.patch.object(audit_log_backup.subprocess, "run")
    def test_restore_rejects_unsupported_manifest_before_current_backup(self, run):
        run.side_effect = self.successful_psql
        archive = audit_log_backup.create_backup(self.backup_dir)
        replacement = self.backup_dir / "unsupported.tar.gz"
        staging = self.root / "archive"
        staging.mkdir()
        with tarfile.open(str(archive), "r:gz") as stream:
            stream.extractall(str(staging), filter="data")
        (staging / "event-database/manifest.json").write_text(
            '{"version": 2, "tables": []}', encoding="utf-8"
        )
        with tarfile.open(str(replacement), "w:gz") as stream:
            stream.add(str(staging / "event-database"), arcname="event-database")

        with mock.patch.object(audit_log_backup, "create_backup") as create_backup:
            with self.assertRaises(audit_log_backup.AuditLogBackupError):
                audit_log_backup.restore_backup(self.backup_dir, replacement.name)
        create_backup.assert_not_called()

    def test_restore_rejects_path_traversal_member(self):
        archive = self.backup_dir / "malicious.tar.gz"
        with tarfile.open(str(archive), "w:gz") as stream:
            member = tarfile.TarInfo("event-database/../../outside.csv")
            member.size = 0
            stream.addfile(member, io.BytesIO())

        with self.assertRaises(audit_log_backup.AuditLogBackupError):
            audit_log_backup.restore_backup(self.backup_dir, archive.name)

    def test_restore_rejects_symbolic_link_archive(self):
        outside = self.root / "outside.tar.gz"
        outside.write_bytes(b"not an archive")
        link = self.backup_dir / "linked.tar.gz"
        link.symlink_to(outside)

        with self.assertRaises(audit_log_backup.AuditLogBackupError):
            audit_log_backup.restore_backup(self.backup_dir, link.name)

    @mock.patch.object(audit_log_backup.subprocess, "run")
    def test_failed_export_removes_partial_archive(self, run):
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
