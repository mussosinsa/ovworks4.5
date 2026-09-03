#!/usr/bin/python3

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).parents[1] / "bin" / "audit-log-backup.py"
ROOT = Path(__file__).parents[2]
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
    def successful_database_tool(command, **kwargs):
        if str(audit_log_backup.PG_DUMP) in command:
            output = next(value for value in command if value.startswith("--file="))
            Path(output.split("=", 1)[1]).write_bytes(b"PGDMP event tables")
        elif str(audit_log_backup.PG_RESTORE) in command:
            kwargs["stdout"].write(b"COPY public.audit_log FROM stdin;\n\\.\n")
        return mock.Mock(returncode=0, stdout="", stderr="")

    def test_long_running_backup_commands_are_non_transactional(self):
        command_root = ROOT / "backend/manager/modules/bll/src/main/java/org/ovirt/engine/core/bll"
        for command in ("FullLogBackupCommand.java", "RestoreAuditLogBackupCommand.java"):
            source = (command_root / command).read_text(encoding="utf-8")
            self.assertIn("@NonTransactiveCommandAttribute", source)

    def test_backup_list_only_includes_dump_files(self):
        command = (
            ROOT
            / "backend/manager/modules/bll/src/main/java/org/ovirt/engine/core/bll"
            / "ListAuditLogBackupsCommand.java"
        ).read_text(encoding="utf-8")
        self.assertIn('name.endsWith(".dump")', command)
        self.assertNotIn('name.endsWith(".tar.gz")', command)

    @mock.patch.object(audit_log_backup.subprocess, "run")
    def test_backup_dumps_only_event_tables_in_compressed_custom_format(self, run):
        run.side_effect = self.successful_database_tool

        dump = audit_log_backup.create_backup(self.backup_dir)

        self.assertTrue(dump.is_file())
        command = run.call_args.args[0]
        self.assertIn(str(audit_log_backup.PG_DUMP), command)
        self.assertIn("--format=custom", command)
        self.assertIn("--compress=3", command)
        self.assertIn("--lock-wait-timeout=30s", command)
        self.assertIn("--data-only", command)
        for table in audit_log_backup.EVENT_TABLES:
            self.assertIn("public.%s" % table, command)
        self.assertIn("--no-password", command[2])
        self.assertEqual(subprocess.DEVNULL, run.call_args.kwargs["stdin"])
        self.assertEqual(
            audit_log_backup.DATABASE_COMMAND_TIMEOUT_SECONDS,
            run.call_args.kwargs["timeout"],
        )
        self.assertEqual(0o640, dump.stat().st_mode & 0o777)

    @mock.patch.object(audit_log_backup.subprocess, "run")
    def test_restore_uses_selected_dump_and_restores_only_event_tables(self, run):
        run.side_effect = self.successful_database_tool
        dump = audit_log_backup.create_backup(self.backup_dir)
        run.reset_mock()

        current_backup, restored = audit_log_backup.restore_backup(self.backup_dir, dump.name)

        self.assertTrue(current_backup.name.startswith("pre-restore-current-events-"))
        self.assertEqual(dump, restored)
        commands = [call.args[0] for call in run.call_args_list]
        restore_command = next(command for command in commands if str(audit_log_backup.PG_RESTORE) in command)
        self.assertIn(str(dump), restore_command)
        self.assertIn("--data-only", restore_command)
        for table in audit_log_backup.EVENT_TABLES:
            self.assertIn("public.%s" % table, restore_command)
        psql_command = next(command for command in commands if str(audit_log_backup.PSQL) in command)
        sql_file = next(value for value in psql_command if value.startswith("--file="))
        # The staging directory has been securely removed after psql returns.
        self.assertFalse(Path(sql_file.split("=", 1)[1]).exists())

    @mock.patch.object(audit_log_backup.subprocess, "run")
    def test_restore_failure_keeps_pre_restore_event_dump(self, run):
        run.side_effect = self.successful_database_tool
        dump = audit_log_backup.create_backup(self.backup_dir)

        def fail_psql(command, **kwargs):
            if str(audit_log_backup.PSQL) in command:
                return mock.Mock(returncode=1, stdout="", stderr="import failed")
            return self.successful_database_tool(command, **kwargs)

        run.side_effect = fail_psql
        with self.assertRaises(audit_log_backup.AuditLogBackupError):
            audit_log_backup.restore_backup(self.backup_dir, dump.name)

        backups = list(self.backup_dir.glob("pre-restore-current-events-*.dump"))
        self.assertEqual(1, len(backups))

    def test_restore_rejects_non_dump_filename_before_current_backup(self):
        archive = self.backup_dir / "legacy.tar.gz"
        archive.write_bytes(b"not a dump")
        with mock.patch.object(audit_log_backup, "create_backup") as create_backup:
            with self.assertRaises(audit_log_backup.AuditLogBackupError):
                audit_log_backup.restore_backup(self.backup_dir, archive.name)
        create_backup.assert_not_called()

    def test_restore_rejects_symbolic_link_dump(self):
        outside = self.root / "outside.dump"
        outside.write_bytes(b"not a dump")
        link = self.backup_dir / "linked.dump"
        link.symlink_to(outside)
        with self.assertRaises(audit_log_backup.AuditLogBackupError):
            audit_log_backup.restore_backup(self.backup_dir, link.name)

    @mock.patch.object(audit_log_backup.subprocess, "run")
    def test_failed_dump_removes_partial_file(self, run):
        run.return_value = mock.Mock(returncode=1, stdout="", stderr="database unavailable")
        with self.assertRaises(audit_log_backup.AuditLogBackupError):
            audit_log_backup.create_backup(self.backup_dir)
        self.assertEqual([], list(self.backup_dir.glob("*.dump")))

    @mock.patch.object(audit_log_backup.subprocess, "run")
    def test_database_command_timeout_is_reported(self, run):
        run.side_effect = subprocess.TimeoutExpired([str(audit_log_backup.PG_DUMP)], 1800)
        with self.assertRaisesRegex(audit_log_backup.AuditLogBackupError, "30분"):
            audit_log_backup.create_backup(self.backup_dir)

    @mock.patch.object(audit_log_backup.subprocess, "run")
    def test_database_command_does_not_interpolate_user_path_into_shell(self, run):
        run.side_effect = self.successful_database_tool
        dangerous = self.backup_dir / "$(touch injected)"
        dangerous.mkdir()
        audit_log_backup.create_backup(dangerous)
        shell_text = run.call_args.args[0][2]
        self.assertNotIn(str(dangerous), shell_text)
        self.assertFalse((self.root / "injected").exists())

    @mock.patch.object(audit_log_backup.subprocess, "run")
    def test_engine_prolog_is_sourced_before_strict_shell_options(self, run):
        run.side_effect = self.successful_database_tool

        audit_log_backup.create_backup(self.backup_dir)

        shell_lines = [line.strip() for line in run.call_args.args[0][2].splitlines() if line.strip()]
        self.assertEqual('. "$1"', shell_lines[0])
        self.assertNotIn("nounset", run.call_args.args[0][2])
        self.assertGreater(shell_lines.index("set -o errexit -o pipefail"), shell_lines.index('. "$1"'))


if __name__ == "__main__":
    unittest.main()
