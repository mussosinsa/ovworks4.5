import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]


class StartupSecurityAuditTest(unittest.TestCase):
    """The engine reads the runner script's exit codes, so the two have to agree."""

    def setUp(self):
        self.runner = (
            ROOT / 'ovirt-engine-security-verification-runner.sh'
        ).read_text(encoding='utf-8')
        self.java_runner = (
            ROOT
            / 'backend/manager/modules/bll/src/main/java/org/ovirt/engine'
            / 'core/bll/SecurityAuditRunner.java'
        ).read_text(encoding='utf-8')
        self.manager = (
            ROOT
            / 'backend/manager/modules/bll/src/main/java/org/ovirt/engine'
            / 'core/bll/StartupSecurityAuditManager.java'
        ).read_text(encoding='utf-8')

    def test_runner_reports_findings_and_busy_with_the_codes_java_reads(self):
        # 20: the audit ran and found something. 75: another verification holds the lock.
        self.assertIn('return 20', self.runner)
        self.assertIn('exit 75', self.runner)
        self.assertIn('EXIT_FINDINGS = 20', self.java_runner)
        self.assertIn('EXIT_BUSY = 75', self.java_runner)

    def test_the_service_runs_the_audit_before_the_java_daemon_starts(self):
        launcher = (
            ROOT / 'packaging/services/ovirt-engine/ovirt-engine.py'
        ).read_text(encoding='utf-8')

        self.assertIn('_runPreStartSecurityVerification', launcher)
        self.assertIn("[runner, 'security', 'engine-start']", launcher)
        self.assertIn('security)', self.runner)

    def test_the_engine_reports_that_run_rather_than_repeating_it(self):
        # Running it again would spend minutes rechecking what was just checked, and the two runs
        # would contend for the lock the verification script takes.
        self.assertIn('SecurityAuditRunner.readResult()', self.manager)
        self.assertNotIn('SecurityAuditRunner.run(', self.manager)

    def test_startup_audit_reads_the_results_file_the_audit_script_writes(self):
        audit = (ROOT / 'ov-works-security_audit.sh').read_text(encoding='utf-8')

        self.assertIn(
            'AUDIT_RESULTS="/tmp/ovirt-security-audit-results.json"', audit
        )
        self.assertIn(
            'RESULTS = "/tmp/ovirt-security-audit-results.json"', self.java_runner
        )
        for field in ('passed', 'warnings', 'failed'):
            self.assertIn(f'"{field}": $', audit)
            self.assertIn(f'summary.path("{field}")', self.java_runner)
        # The detail of each check is in the log the audit names in its result.
        for field in ('timestamp', 'status', 'log_file'):
            self.assertIn(f'"{field}":', audit)
            self.assertIn(f'root.path("{field}")', self.java_runner)

    def test_startup_audit_runs_without_blocking_the_engine_coming_up(self):
        self.assertIn('implements BackendService', self.manager)
        self.assertIn('executor.schedule(this::reportPreStartAudit', self.manager)

    def test_scheduled_services_are_registered_so_they_are_created_at_all(self):
        # A BackendService is not found by type: ServiceLoader takes the class, and
        # InitBackendServicesOnStartupBean names every service that is to be started. A service
        # left out of it is never constructed, so its @PostConstruct never runs and it silently
        # does nothing.
        startup = (
            ROOT
            / 'backend/manager/modules/bll/src/main/java/org/ovirt/engine'
            / 'core/bll/InitBackendServicesOnStartupBean.java'
        ).read_text(encoding='utf-8')

        self.assertIn(
            'serviceLoader.load(StartupSecurityAuditManager.class)', startup
        )
        self.assertIn(
            'serviceLoader.load(UserLoginLockoutExpiryManager.class)', startup
        )
        self.assertIn(
            'import org.ovirt.engine.core.bll.aaa.UserLoginLockoutExpiryManager;', startup
        )
        self.assertIn(
            'serviceLoader.load(ClientAccessDeniedAuditManager.class)', startup
        )


if __name__ == '__main__':
    unittest.main()
