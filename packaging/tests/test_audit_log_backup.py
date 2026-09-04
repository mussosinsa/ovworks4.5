#!/usr/bin/python3

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).parents[1] / "bin" / "audit-log-backup.py"
ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "packaging/pythonlib"))
SPEC = importlib.util.spec_from_file_location("audit_log_backup", str(MODULE_PATH))
audit_log_backup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit_log_backup)


class AuditLogBackupTest(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.backup_dir = self.root / "backups"
        self.backup_dir.mkdir()
        self.database_config = mock.patch.object(
            audit_log_backup,
            "_database_config",
            return_value={
                "host": "db.example.test",
                "port": "5432",
                "user": "engine",
                "password": "secret",
                "database": "engine",
            },
        )
        self.database_config_mock = self.database_config.start()

    def tearDown(self):
        self.database_config.stop()
        self.temporary.cleanup()

    @staticmethod
    def successful_database_tool(command, **kwargs):
        if str(audit_log_backup.PG_DUMP) in command:
            output = next(value for value in command if value.startswith("--file="))
            Path(output.split("=", 1)[1]).write_bytes(b"PGDMP event tables")
        elif str(audit_log_backup.PG_RESTORE) in command:
            output = next(value for value in command if value.startswith("--file="))
            Path(output.split("=", 1)[1]).write_bytes(b"COPY public.audit_log FROM stdin;\n\\.\n")
        return mock.Mock(returncode=0, stdout="", stderr="")

    def test_long_running_backup_commands_are_non_transactional(self):
        command_root = ROOT / "backend/manager/modules/bll/src/main/java/org/ovirt/engine/core/bll"
        for command in ("FullLogBackupCommand.java", "RestoreAuditLogBackupCommand.java"):
            source = (command_root / command).read_text(encoding="utf-8")
            self.assertIn("@NonTransactiveCommandAttribute", source)

    def test_backup_command_logs_helper_failure_detail(self):
        command = (
            ROOT
            / "backend/manager/modules/bll/src/main/java/org/ovirt/engine/core/bll"
            / "FullLogBackupCommand.java"
        ).read_text(encoding="utf-8")
        self.assertIn("Audit log backup helper failed with exit code", command)
        self.assertIn("result.exitCode, result.output", command)

    def test_restore_command_logs_helper_failure_detail(self):
        command = (
            ROOT
            / "backend/manager/modules/bll/src/main/java/org/ovirt/engine/core/bll"
            / "RestoreAuditLogBackupCommand.java"
        ).read_text(encoding="utf-8")
        self.assertIn("Audit log restore helper failed with exit code", command)
        self.assertIn("restoreResult.exitCode, restoreResult.output", command)

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
        self.assertIn("--no-password", command)
        self.assertEqual("secret", run.call_args.kwargs["env"]["PGPASSWORD"])
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
        self.assertIn("--strict-names", restore_command)
        self.assertIn("--schema", restore_command)
        self.assertIn("public", restore_command)
        self.assertFalse(any(value.startswith("--dbname=") for value in restore_command))
        for table in audit_log_backup.EVENT_TABLES:
            self.assertIn(table, restore_command)
            self.assertNotIn("public.%s" % table, restore_command)
        psql_command = next(command for command in commands if str(audit_log_backup.PSQL) in command)
        sql_file = next(value for value in psql_command if value.startswith("--file="))
        # The staging directory has been securely removed after psql returns.
        self.assertFalse(Path(sql_file.split("=", 1)[1]).exists())

    @mock.patch.object(audit_log_backup, "_run_database_command")
    def test_restore_schema_qualifies_sequence_after_pg_restore_clears_search_path(self, run):
        def render_restore(arguments, connect=True):
            if str(audit_log_backup.PG_RESTORE) in arguments:
                self.assertFalse(connect)
                output = next(value for value in arguments if value.startswith("--file="))
                Path(output.split("=", 1)[1]).write_bytes(
                    b"SELECT pg_catalog.set_config('search_path', '', false);\n"
                    b"COPY public.audit_log FROM stdin;\n\\.\n"
                )
            elif str(audit_log_backup.PSQL) in arguments:
                sql_file = next(value for value in arguments if value.startswith("--file="))
                sql = Path(sql_file.split("=", 1)[1]).read_text(encoding="utf-8")
                self.assertIn("setval('public.audit_log_seq'", sql)
                self.assertNotIn("setval('audit_log_seq'", sql)
            return mock.Mock(returncode=0, stdout="", stderr="")

        run.side_effect = render_restore
        dump = self.backup_dir / "selected.dump"
        dump.write_bytes(b"PGDMP event tables")
        staging = self.root / "staging"
        staging.mkdir()

        audit_log_backup._restore_tables(dump, staging)

    @mock.patch.object(audit_log_backup.subprocess, "run")
    def test_pg_restore_renders_without_database_connection(self, run):
        def render_sql(command, **kwargs):
            output = next(value for value in command if value.startswith("--file="))
            Path(output.split("=", 1)[1]).write_bytes(b"COPY public.audit_log FROM stdin;\n\\.\n")
            return mock.Mock(returncode=0, stdout="", stderr="")

        run.side_effect = render_sql
        dump = self.backup_dir / "selected.dump"
        dump.write_bytes(b"PGDMP event tables")
        rendered = self.root / "rendered.sql"

        audit_log_backup._render_restore_sql(dump, rendered)

        command = run.call_args.args[0]
        self.assertEqual(str(audit_log_backup.PG_RESTORE), command[0])
        self.assertIn("--file=%s" % rendered, command)
        self.assertFalse(any(value.startswith("--dbname=") for value in command))
        self.assertNotIn("PGPASSWORD", run.call_args.kwargs["env"])
        self.database_config_mock.assert_not_called()

    def test_dump_and_restore_use_postgresql_specific_table_patterns(self):
        dump_arguments = audit_log_backup._dump_table_arguments()
        restore_arguments = audit_log_backup._restore_table_arguments()

        self.assertNotIn("--schema", dump_arguments)
        self.assertEqual(
            ["public.%s" % table for table in audit_log_backup.EVENT_TABLES],
            [dump_arguments[index + 1]
             for index, value in enumerate(dump_arguments) if value == "--table"],
        )
        self.assertEqual(["--schema", "public"], restore_arguments[:2])
        self.assertEqual(
            list(audit_log_backup.EVENT_TABLES),
            [restore_arguments[index + 1]
             for index, value in enumerate(restore_arguments) if value == "--table"],
        )

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
    def test_database_command_does_not_invoke_a_shell(self, run):
        run.side_effect = self.successful_database_tool
        dangerous = self.backup_dir / "$(touch injected)"
        dangerous.mkdir()
        audit_log_backup.create_backup(dangerous)
        self.assertNotIn("/bin/bash", run.call_args.args[0])
        self.assertFalse((self.root / "injected").exists())

    def test_database_config_uses_encryption_aware_reader(self):
        self.database_config.stop()
        values = {
            "ENGINE_DB_HOST": "db.example.test",
            "ENGINE_DB_PORT": "5432",
            "ENGINE_DB_USER": "engine",
            "ENGINE_DB_PASSWORD": "decrypted-secret",
            "ENGINE_DB_DATABASE": "engine",
        }
        with mock.patch.object(audit_log_backup.configfile, "ConfigFile") as reader:
            reader.return_value.get.side_effect = lambda key, default="": values.get(key, default)
            database = audit_log_backup._database_config()
        self.database_config.start()

        reader.assert_called_once_with((
            str(audit_log_backup.ENGINE_DEFAULTS),
            str(audit_log_backup.ENGINE_VARS),
        ))
        self.assertEqual("decrypted-secret", database["password"])


if __name__ == "__main__":
    unittest.main()
