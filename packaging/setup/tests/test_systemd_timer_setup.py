import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
SYSTEM = (
    ROOT / 'packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/system'
)
SPEC = importlib.util.spec_from_file_location(
    'systemd_timer', str(SYSTEM / 'systemd_timer.py')
)
systemd_timer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(systemd_timer)


class FakeCommand:
    def __init__(self, path):
        self.path = path

    def get(self, name, optional=False):
        return self.path


class FakeLogger:
    def __init__(self):
        self.warnings = []

    def warning(self, message):
        self.warnings.append(message)


class FakePlugin:
    def __init__(self, enable_rc=0, systemctl='/usr/bin/systemctl'):
        self.command = FakeCommand(systemctl)
        self.logger = FakeLogger()
        self.calls = []
        self.enable_rc = enable_rc

    def execute(self, args, raiseOnError=True):
        self.calls.append((tuple(args), raiseOnError))
        if 'enable' in args:
            stderr = ['Unit not found.'] if self.enable_rc else []
            return self.enable_rc, [], stderr
        return 0, [], []


class SystemdTimerSetupTest(unittest.TestCase):
    TIMER = 'ovirt-engine-audit-storage-watch.timer'

    def test_timer_is_enabled_by_its_own_unit_name(self):
        plugin = FakePlugin()
        self.assertTrue(systemd_timer.enable_timer(plugin, self.TIMER))
        commands = [call[0] for call in plugin.calls]
        self.assertIn(('/usr/bin/systemctl', 'daemon-reload'), commands)
        self.assertIn(
            ('/usr/bin/systemctl', 'enable', '--now', self.TIMER), commands
        )
        # Never the '.timer.service' name otopi's service provider makes.
        for command in commands:
            self.assertNotIn(self.TIMER + '.service', command)
        self.assertEqual([], plugin.logger.warnings)

    def test_a_timer_that_cannot_be_enabled_does_not_fail_setup(self):
        plugin = FakePlugin(enable_rc=5)
        self.assertFalse(systemd_timer.enable_timer(plugin, self.TIMER))
        self.assertTrue(all(not call[1] for call in plugin.calls))
        self.assertEqual(1, len(plugin.logger.warnings))
        self.assertIn('systemctl enable --now ' + self.TIMER,
                      plugin.logger.warnings[0])

    def test_missing_systemctl_is_reported(self):
        plugin = FakePlugin(systemctl=None)
        self.assertFalse(systemd_timer.enable_timer(plugin, self.TIMER))
        self.assertEqual([], plugin.calls)
        self.assertEqual(1, len(plugin.logger.warnings))

    def test_timer_plugins_do_not_use_the_service_provider(self):
        for name in ('audit_storage_watch.py', 'security_audit.py'):
            source = (SYSTEM / name).read_text(encoding='utf-8')
            self.assertNotIn('self.services.state(', source, name)
            self.assertNotIn('self.services.startup(', source, name)
            self.assertIn('systemd_timer.enable_timer(self, ', source, name)
            self.assertIn("self.command.detect('systemctl')", source, name)


if __name__ == '__main__':
    unittest.main()
