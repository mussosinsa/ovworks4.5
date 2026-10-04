import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
SERVICES = ROOT / 'packaging/services/ovirt-engine'
HALT = ROOT / 'packaging/bin/ovirt-engine-security-halt.sh'
PLUGIN = (
    ROOT / 'packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/system/'
    'security_audit.py'
)
BLL = ROOT / 'backend/manager/modules/bll/src/main/java/org/ovirt/engine/core/bll'
REQUEST = '/var/lib/ovirt-engine/security/halt-request.json'


class HaltScriptTest(unittest.TestCase):

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp())
        self.addCleanup(subprocess.run, ['rm', '-rf', str(self.directory)])
        self.request = self.directory / 'halt-request.json'
        self.calls = self.directory / 'calls'
        self.syslog = self.directory / 'syslog'
        for name, target in (('systemctl', self.calls),
                             ('logger', self.syslog)):
            tool = self.directory / name
            tool.write_text('#!/bin/sh\necho "$@" >> "%s"\n' % target)
            tool.chmod(0o755)
        sleep = self.directory / 'sleep'
        sleep.write_text('#!/bin/sh\n[ -n "$CANCEL" ] && rm -f "$CANCEL"\n'
                         'exit 0\n')
        sleep.chmod(0o755)
        self.environment = dict(
            os.environ,
            SECURITY_HALT_REQUEST=str(self.request),
            SYSTEMCTL_COMMAND=str(self.directory / 'systemctl'),
            LOGGER_COMMAND=str(self.directory / 'logger'),
            SLEEP_COMMAND=str(sleep),
            PYTHON_COMMAND='python3',
        )

    def run_halt(self, **extra):
        return subprocess.run(
            ['bash', str(HALT)], env=dict(self.environment, **extra),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True, timeout=30,
        )

    def write_request(self, not_before):
        self.request.write_text(json.dumps({
            'reason': 'SCHEDULED_VERIFICATION_FAILED',
            'check': 'security',
            'not_before': not_before,
        }))

    def stops(self):
        return (self.calls.read_text().splitlines()
                if self.calls.exists() else [])

    def test_stops_the_engine_once_the_delay_is_over(self):
        self.write_request(int(time.time()) - 1)
        result = self.run_halt()
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertEqual(['stop ovirt-engine.service'], self.stops())
        # Removed, or the path unit would start the service again at once.
        self.assertFalse(self.request.exists())
        self.assertIn('authpriv.crit', self.syslog.read_text())

    def test_waits_for_the_delay_the_engine_asked_for(self):
        self.write_request(int(time.time()) + 25)
        result = self.run_halt()
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn('will be stopped in', result.stdout)
        self.assertEqual(['stop ovirt-engine.service'], self.stops())

    def test_removing_the_request_during_the_delay_cancels_the_stop(self):
        self.write_request(int(time.time()) + 600)
        result = self.run_halt(CANCEL=str(self.request))
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn('cancelled', result.stdout)
        self.assertEqual([], self.stops())

    def test_an_unreadable_request_still_stops_the_engine(self):
        self.request.write_text('not json')
        result = self.run_halt()
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertEqual(['stop ovirt-engine.service'], self.stops())

    def test_no_request_does_nothing(self):
        result = self.run_halt()
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertEqual([], self.stops())

    def test_a_failed_stop_is_reported(self):
        self.write_request(0)
        failing = self.directory / 'systemctl'
        failing.write_text('#!/bin/sh\nexit 1\n')
        result = self.run_halt()
        self.assertEqual(1, result.returncode, result.stdout)
        self.assertIn('Failed to stop', self.syslog.read_text())


class PackagingTest(unittest.TestCase):

    def test_the_path_unit_watches_the_request_the_engine_writes(self):
        path = (SERVICES / 'ovirt-engine-security-halt.path').read_text()
        self.assertIn('PathExists=' + REQUEST, path)
        self.assertIn('Unit=ovirt-engine-security-halt.service', path)
        java = (BLL / 'ScheduledVerificationFailureResponse.java').read_text()
        self.assertIn('"' + REQUEST + '"', java)

    def test_the_service_runs_the_script_as_root_long_enough(self):
        service = (SERVICES / 'ovirt-engine-security-halt.service').read_text()
        self.assertIn(
            'ExecStart=/usr/share/ovirt-engine/bin/ovirt-engine-security-halt.sh',
            service)
        self.assertNotIn('User=', service)
        # The longest delay is an hour, and the stop itself takes time.
        self.assertIn('TimeoutStartSec=75min', service)

    def test_the_package_ships_and_setup_enables_it(self):
        spec = (ROOT / 'ovirt-engine.spec.in').read_text()
        for name in ('%{_unitdir}/ovirt-engine-security-halt.path',
                     '%{_unitdir}/ovirt-engine-security-halt.service',
                     '%{engine_data}/bin/ovirt-engine-security-halt.sh'):
            self.assertIn(name, spec)
        self.assertIn('chmod a+x packaging/bin/ovirt-engine-security-halt.sh',
                      (ROOT / 'Makefile').read_text())
        self.assertIn("_HALT_PATH = 'ovirt-engine-security-halt.path'",
                      PLUGIN.read_text())

    def test_both_settings_default_to_stopping_after_five_minutes(self):
        for sql in (ROOT / 'packaging/dbscripts/upgrade/pre_upgrade/0000_config.sql',
                    ROOT / 'packaging/dbscripts/upgrade/'
                    '04_05_0348_add_security_verification_failure_action.sql'):
            text = sql.read_text().replace(' ', '')
            self.assertIn(
                "('ENGINE_SECURITY_VERIFICATION_FAILURE_ACTION','STOP','general')",
                text)
            self.assertIn(
                "('ENGINE_SECURITY_VERIFICATION_HALT_DELAY_SECONDS','300','general')",
                text)

    def test_both_verifications_respond_to_a_failure(self):
        for manager in ('StartupSecurityAuditManager.java',
                        'IntegrityVerificationAuditManager.java'):
            self.assertIn('failureResponse.respond(KIND',
                          (BLL / manager).read_text(), manager)


if __name__ == '__main__':
    unittest.main()
