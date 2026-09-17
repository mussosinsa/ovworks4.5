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
        self.audit = (ROOT / 'ov-works-security_audit.sh').read_text(encoding='utf-8')
        # The template, not the generated copy beside it: the build regenerates that from this.
        self.launcher = (
            ROOT / 'packaging/services/ovirt-engine/ovirt-engine.py.in'
        ).read_text(encoding='utf-8')

    def test_runner_reports_findings_and_busy_with_the_codes_java_reads(self):
        # 20: the audit ran and found something. 75: another verification holds the lock.
        self.assertIn('return 20', self.runner)
        self.assertIn('exit 75', self.runner)
        self.assertIn('EXIT_FINDINGS = 20', self.java_runner)
        self.assertIn('EXIT_BUSY = 75', self.java_runner)

    def test_the_service_runs_the_audit_before_the_java_daemon_starts(self):
        self.assertIn('_runPreStartSecurityVerification', self.launcher)
        self.assertIn("[runner, 'security', 'engine-start']", self.launcher)
        self.assertIn('security)', self.runner)

    def test_the_engine_reports_that_run_rather_than_repeating_it(self):
        # Running it again would spend minutes rechecking what was just checked, and the two runs
        # would contend for the lock the verification script takes.
        self.assertIn('SecurityAuditRunner.readResult()', self.manager)
        self.assertNotIn('SecurityAuditRunner.run(', self.manager)

    RESULTS = '/var/lib/ovirt-engine/security/audit-results.json'
    BLOCKED = '/var/lib/ovirt-engine/security/last-failed-start.json'

    def test_startup_audit_reads_the_results_file_the_audit_script_writes(self):
        for field in ('passed', 'warnings', 'failed'):
            self.assertIn(f'"{field}": $', self.audit)
            self.assertIn(f'summary.path("{field}")', self.java_runner)
        # The detail of each check is in the log the audit names in its result.
        for field in ('timestamp', 'status', 'log_file'):
            self.assertIn(f'"{field}":', self.audit)
            self.assertIn(f'root.path("{field}")', self.java_runner)

    def test_the_result_is_not_left_in_a_world_writable_directory(self):
        # Under /tmp any local user can pre-create the path or replace the file between the
        # audit writing it and the engine reading it, and what the engine then reports as its
        # own audit result is whatever they wrote.
        self.assertIn(f'SECURITY_AUDIT_RESULTS:-{self.RESULTS}', self.audit)
        self.assertIn(f'SECURITY_AUDIT_RESULTS:-{self.RESULTS}', self.runner)
        self.assertIn(f'DEFAULT_RESULTS =\n            "{self.RESULTS}"', self.java_runner)
        self.assertNotIn('/tmp/ovirt-security-audit-results.json', self.audit)
        self.assertNotIn('/tmp/ovirt-security-audit-results.json', self.java_runner)
        self.assertIn('chmod 0600 "$AUDIT_RESULTS"', self.audit)

    def test_all_three_agree_on_where_the_result_is(self):
        # The runner used to read a path it never passed on, so overriding it made the runner
        # delete and read one file while the audit wrote another - which reads from the gate's
        # side as an audit that reported nothing, and refuses the start.
        self.assertIn(
            'SECURITY_AUDIT_RESULTS="$SECURITY_AUDIT_RESULTS"', self.runner
        )
        self.assertIn('RESULTS_ENV = "SECURITY_AUDIT_RESULTS"', self.java_runner)
        self.assertIn('System.getenv(RESULTS_ENV)', self.java_runner)

    def test_a_verification_already_running_is_not_reported_as_a_failed_one(self):
        # 75 means nothing was checked because another verification holds the lock - a restart
        # during the daily audit. Telling the administrator the host failed its security checks
        # would be untrue and would send them looking for a fault that is not there.
        self.assertIn('_VERIFICATION_EXIT_BUSY = 75', self.launcher)
        self.assertIn('_VERIFICATION_EXIT_FINDINGS = 20', self.launcher)
        self.assertIn("'VERIFICATION_BUSY'", self.launcher)
        self.assertIn("'SECURITY_CHECKS_FAILED'", self.launcher)
        # And it waits out the tail of one rather than refusing the start at the first try.
        self.assertIn('_VERIFICATION_BUSY_ATTEMPTS', self.launcher)
        self.assertIn('time.sleep(self._VERIFICATION_BUSY_WAIT_SECONDS)', self.launcher)

    def test_a_refused_start_is_reported_by_the_next_start_that_succeeds(self):
        # The verification is a gate: a start it refuses produces no engine, so nothing writes
        # to the event list and the failure that matters most is the one that can never report
        # itself. The gate leaves a record; the next start that comes up says it and removes it.
        state_dir, name = self.BLOCKED.rsplit('/', 1)
        self.assertIn(f"SECURITY_STATE_DIR = '{state_dir}'", self.launcher)
        self.assertIn(f"'{name}',", self.launcher)
        self.assertIn('_recordBlockedStart', self.launcher)
        self.assertIn(f'DEFAULT_BLOCKED_START =\n            "{self.BLOCKED}"', self.java_runner)
        self.assertIn('SecurityAuditRunner.readBlockedStart()', self.manager)
        self.assertIn('SecurityAuditRunner.clearBlockedStart()', self.manager)
        self.assertIn('reportBlockedStart();', self.manager)

    def test_the_gate_and_the_engine_agree_on_why_a_start_was_refused(self):
        for reason in (
            'SECURITY_CHECKS_FAILED',
            'VERIFICATION_BUSY',
            'RUNNER_MISSING',
            'VERIFICATION_ERROR',
        ):
            self.assertIn(f"'{reason}'", self.launcher)
            self.assertIn(f'"{reason}"', self.java_runner)
        for field in ('timestamp', 'reason', 'detail'):
            self.assertIn(f"'{field}':", self.launcher)
            self.assertIn(f'root.path("{field}")', self.java_runner)
        # The tally of the audit that refused the start travels with it - but only when an
        # audit ran for this attempt. Nothing is checked when another verification holds the
        # lock or the runner is missing, and the result file still holds the previous run's
        # numbers, which would then be read as the reason this start was refused.
        self.assertIn('self._readSecurityAuditResults()', self.launcher)
        self.assertIn('if reason in self._REASONS_WITH_RESULTS', self.launcher)
        self.assertIn(
            '_REASONS_WITH_RESULTS = (_REASON_CHECKS_FAILED, _REASON_ERROR)', self.launcher
        )
        self.assertIn('root.path("results").path("summary")', self.java_runner)

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
