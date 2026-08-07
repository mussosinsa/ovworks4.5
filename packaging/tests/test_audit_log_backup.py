#!/usr/bin/python3

import importlib.util
import io
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
        self.audit_dir = self.root / "audit"
        self.backup_dir = self.root / "backups"
        self.audit_dir.mkdir()
        self.backup_dir.mkdir()
        (self.audit_dir / "engine.log").write_text("current\n", encoding="utf-8")
        self.audit_dir_patch = mock.patch.object(
            audit_log_backup,
            "AUDIT_LOG_DIR",
            self.audit_dir,
        )
        self.audit_dir_patch.start()

    def tearDown(self):
        self.audit_dir_patch.stop()
        self.temporary.cleanup()

    def test_backup_and_restore_preserve_active_log(self):
        archive = audit_log_backup.create_backup(self.backup_dir)
        (self.audit_dir / "engine.log").write_text("new current\n", encoding="utf-8")

        current_backup, restored = audit_log_backup.restore_backup(
            self.backup_dir,
            archive.name,
        )

        self.assertTrue(current_backup.is_file())
        self.assertEqual("new current\n", (self.audit_dir / "engine.log").read_text(encoding="utf-8"))
        self.assertEqual("current\n", (restored / "engine.log").read_text(encoding="utf-8"))
        self.assertEqual(self.backup_dir, restored.parent)
        self.assertTrue(restored.name.startswith(archive.name[:-7] + "-restored-"))

    def test_restore_rejects_path_traversal_member_before_current_backup(self):
        archive = self.backup_dir / "malicious.tar.gz"
        with tarfile.open(str(archive), "w:gz") as stream:
            value = b"bad"
            member = tarfile.TarInfo("ovirt-engine/../../outside")
            member.size = len(value)
            stream.addfile(member, io.BytesIO(value))

        with self.assertRaises(audit_log_backup.AuditLogBackupError):
            audit_log_backup.restore_backup(self.backup_dir, archive.name)

        self.assertFalse(any(self.backup_dir.glob("pre-restore-current-audit-*.tar.gz")))

    def test_restore_rejects_symbolic_link_member(self):
        archive = self.backup_dir / "symlink.tar.gz"
        with tarfile.open(str(archive), "w:gz") as stream:
            member = tarfile.TarInfo("ovirt-engine/link")
            member.type = tarfile.SYMTYPE
            member.linkname = "/etc/shadow"
            stream.addfile(member)

        with self.assertRaises(audit_log_backup.AuditLogBackupError):
            audit_log_backup.restore_backup(self.backup_dir, archive.name)

    def test_restore_rejects_archive_outside_real_directory(self):
        outside = self.root / "outside.tar.gz"
        outside.write_bytes(b"not an archive")
        link = self.backup_dir / "linked.tar.gz"
        link.symlink_to(outside)

        with self.assertRaises(audit_log_backup.AuditLogBackupError):
            audit_log_backup.restore_backup(self.backup_dir, link.name)

    def test_backup_rejects_destination_below_audit_directory(self):
        destination = self.audit_dir / "backups"
        destination.mkdir()

        with self.assertRaises(audit_log_backup.AuditLogBackupError):
            audit_log_backup.create_backup(destination)

    def test_main_reports_safe_failure(self):
        error_output = io.StringIO()
        with mock.patch.object(audit_log_backup, "AUDIT_LOG_DIR", self.root / "missing"), \
                redirect_stderr(error_output):
            status = audit_log_backup.main(["backup", str(self.backup_dir)])
        self.assertEqual(1, status)
        self.assertIn("FAIL:", error_output.getvalue())


if __name__ == "__main__":
    unittest.main()
