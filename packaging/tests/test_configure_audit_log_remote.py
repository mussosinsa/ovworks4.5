#!/usr/bin/python3

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).parents[1] / "bin" / "configure-audit-log-remote.py"
SPEC = importlib.util.spec_from_file_location("configure_audit_log_remote", str(MODULE_PATH))
remote_config = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(remote_config)


class RemoteConfigTest(unittest.TestCase):

    def test_normalize_target_accepts_supported_addresses(self):
        self.assertEqual("logs.example.com:6514", remote_config.normalize_target("logs.example.com:6514"))
        self.assertEqual("192.0.2.10", remote_config.normalize_target("192.0.2.10"))
        self.assertEqual("[2001:db8::1]:514", remote_config.normalize_target("[2001:db8::1]:514"))

    def test_normalize_target_rejects_configuration_injection(self):
        for target in ("server\nlocal0.* /tmp/log", "server name", "server:0", "2001:db8::1"):
            with self.subTest(target=target), self.assertRaises(remote_config.RemoteConfigError):
                remote_config.normalize_target(target)

    def test_configure_replaces_existing_config_and_restarts(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "remote.conf"
            config.write_text("old\n", encoding="utf-8")
            completed = mock.Mock(returncode=0, stdout="")
            with mock.patch.object(remote_config, "CONFIG_FILE", config), \
                    mock.patch.object(remote_config.subprocess, "run", return_value=completed) as run:
                remote_config.configure("logs.example.com:6514")

            self.assertIn("@@logs.example.com:6514", config.read_text(encoding="utf-8"))
            self.assertEqual([remote_config.RSYSLOGD, "-N1"], run.call_args_list[0].args[0])
            self.assertEqual([remote_config.SYSTEMCTL, "restart", "rsyslog"], run.call_args_list[1].args[0])

    def test_configure_rolls_back_when_validation_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "remote.conf"
            config.write_text("old\n", encoding="utf-8")
            failed = mock.Mock(returncode=1, stdout="invalid config")
            with mock.patch.object(remote_config, "CONFIG_FILE", config), \
                    mock.patch.object(remote_config.subprocess, "run", return_value=failed), \
                    self.assertRaises(remote_config.RemoteConfigError):
                remote_config.configure("logs.example.com")

            self.assertEqual("old\n", config.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
