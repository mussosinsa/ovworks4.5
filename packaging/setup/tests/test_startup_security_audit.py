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

    def test_runner_accepts_the_mode_the_startup_audit_asks_for(self):
        self.assertIn('security)', self.runner)
        self.assertIn('SecurityAuditRunner.run("security", SOURCE)', self.manager)

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

    def test_startup_audit_runs_without_blocking_the_engine_coming_up(self):
        self.assertIn('implements BackendService', self.manager)
        self.assertIn('executor.schedule(this::auditOnStartup', self.manager)


if __name__ == '__main__':
    unittest.main()
