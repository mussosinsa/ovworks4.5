import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
SERVICES = ROOT / 'packaging/services/ovirt-engine'
RUNNER = ROOT / 'ovirt-engine-security-verification-runner.sh'
PLUGIN = (
    ROOT / 'packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/system/'
    'security_audit.py'
)


def tracked(path):
    return subprocess.run(
        ['git', 'ls-files', '--error-unmatch', str(path)],
        cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0


class UnitsTest(unittest.TestCase):

    def test_only_the_templates_are_in_the_repository(self):
        # A generated copy in the repository is as new as its template, so
        # make takes it as up to date and the package ships the paths of
        # whatever build produced it - which made the service skip on its
        # ConditionPathExists every time.
        for unit in ('ovirt-engine-security-audit.service',
                     'ovirt-engine-security-audit.timer'):
            self.assertTrue(tracked(SERVICES / (unit + '.in')), unit)
            self.assertFalse(tracked(SERVICES / unit), unit)

    def test_the_service_template_uses_the_install_paths(self):
        service = (SERVICES / 'ovirt-engine-security-audit.service.in'
                   ).read_text(encoding='utf-8')
        self.assertIn(
            'ConditionPathExists=@ENGINE_USR@/bin/'
            'ovirt-engine-security-verification-runner.sh', service)
        self.assertIn('runner.sh all timer', service)

    def test_the_timer_runs_twice_a_day(self):
        timer = (SERVICES / 'ovirt-engine-security-audit.timer.in'
                 ).read_text(encoding='utf-8')
        self.assertIn('OnCalendar=*-*-* 02:30:00', timer)
        self.assertIn('OnCalendar=*-*-* 18:00:00', timer)
        self.assertIn('Persistent=true', timer)

    def test_setup_enables_the_timer_by_default(self):
        plugin = PLUGIN.read_text(encoding='utf-8')
        self.assertIn(
            "setdefault('OVESETUP_SECURITY_AUDIT/enableTimer', True)", plugin)


class SkippedRunTest(unittest.TestCase):

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp())
        self.addCleanup(subprocess.run, ['rm', '-rf', str(self.directory)])
        self.lock = self.directory / 'lock'
        self.skipped = self.directory / 'security' / 'skipped-runs'
        self.syslog = self.directory / 'syslog'
        logger = self.directory / 'logger'
        logger.write_text('#!/bin/sh\necho "$@" >> "%s"\n' % self.syslog)
        logger.chmod(0o755)
        self.environment = dict(
            os.environ,
            LOCK_FILE=str(self.lock),
            SECURITY_VERIFICATION_SKIPPED=str(self.skipped),
            LOGGER_COMMAND=str(logger),
        )

    def run_while_locked(self, source):
        holder = subprocess.Popen(
            ['flock', str(self.lock), 'sleep', '5'])
        self.addCleanup(holder.kill)
        for _ in range(50):
            if subprocess.run(['flock', '-n', str(self.lock), 'true']
                              ).returncode != 0:
                break
            subprocess.run(['sleep', '0.1'])
        return subprocess.run(
            ['bash', str(RUNNER), 'all', source], env=self.environment,
            stdout=subprocess.PIPE, universal_newlines=True)

    def test_a_skipped_scheduled_run_is_recorded(self):
        result = self.run_while_locked('timer')
        self.assertEqual(75, result.returncode)
        lines = self.skipped.read_text().splitlines()
        self.assertEqual(1, len(lines))
        time, mode, source = lines[0].split('\t')
        self.assertRegex(time, r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$')
        self.assertEqual(('all', 'timer'), (mode, source))
        self.assertEqual(0o600, self.skipped.stat().st_mode & 0o777)
        self.assertIn('skipped (mode=all, source=timer)',
                      self.syslog.read_text())

    def test_what_reports_itself_is_not_recorded_twice(self):
        for source in ('engine-start', 'webadmin'):
            self.assertEqual(75, self.run_while_locked(source).returncode)
        self.assertFalse(self.skipped.exists())

    def test_the_source_cannot_inject_a_line(self):
        self.run_while_locked('timer\tx\nforged')
        line, = self.skipped.read_text().splitlines()
        self.assertEqual('timerxforged', line.split('\t')[2])


if __name__ == '__main__':
    unittest.main()
