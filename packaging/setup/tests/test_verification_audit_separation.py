import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
BLL = ROOT / 'backend/manager/modules/bll/src/main/java/org/ovirt/engine/core/bll'


class VerificationAuditSeparationTest(unittest.TestCase):
    """Two checks answering two questions. A record that ran them together lets one pass for
    the other, so they are run, kept and reported apart the whole way through."""

    def setUp(self):
        self.runner = (
            ROOT / 'ovirt-engine-security-verification-runner.sh'
        ).read_text(encoding='utf-8')
        self.audit = (ROOT / 'ov-works-security_audit.sh').read_text(encoding='utf-8')
        self.integrity = (BLL / 'IntegrityVerification.java').read_text(encoding='utf-8')
        self.integrity_manager = (
            BLL / 'IntegrityVerificationAuditManager.java'
        ).read_text(encoding='utf-8')
        self.security_manager = (
            BLL / 'StartupSecurityAuditManager.java'
        ).read_text(encoding='utf-8')
        self.command = (BLL / 'IntegrityVerificationCommand.java').read_text(encoding='utf-8')

    def test_each_check_keeps_its_own_result(self):
        self.assertIn(
            'SECURITY_AUDIT_RESULTS:-/var/lib/ovirt-engine/security/audit-results.json',
            self.runner,
        )
        self.assertIn(
            'INTEGRITY_VERIFICATION_RESULTS:-'
            '/var/lib/ovirt-engine/security/integrity-results.json',
            self.runner,
        )
        self.assertIn('"/var/lib/ovirt-engine/security/integrity-results.json"', self.integrity)

    def test_running_both_does_not_merge_what_each_one_found(self):
        # systemd has one exit code, so the worse of the two is still what the caller gets -
        # but which check produced it has to remain readable, or a failure is attributed to
        # the check that passed.
        self.assertIn('security_result=0', self.runner)
        self.assertIn('integrity_result=0', self.runner)
        self.assertIn(
            'log "Security audit status=$security_result; '
            'integrity verification status=$integrity_result"',
            self.runner,
        )

    def test_aide_finding_something_is_told_apart_from_aide_not_running(self):
        # AIDE reports what it found as a bit set (1 added, 2 removed, 4 changed); 14 and up is
        # AIDE saying it could not check. "Nothing found" and "nothing checked" look the same in
        # an event list, so they must not be recorded the same way.
        self.assertIn('[ "$aide_status" -ge 1 ] && [ "$aide_status" -le 7 ]', self.runner)
        self.assertIn('write_integrity_result "FAIL"', self.runner)
        self.assertIn('write_integrity_result "ERROR"', self.runner)
        self.assertIn('isError()', self.integrity)
        self.assertIn('could not be carried out', self.integrity_manager)

    def test_each_check_reports_under_its_own_event_types(self):
        for event in (
            'INTEGRITY_VERIFICATION_STARTED',
            'INTEGRITY_VERIFICATION_COMPLETED',
            'INTEGRITY_VERIFICATION_FAILED',
            'INTEGRITY_VERIFICATION_FILE_MISSING',
            'INTEGRITY_VERIFICATION_FILE_MODIFIED',
        ):
            self.assertIn(f'AuditLogType.{event}', self.integrity_manager)
            self.assertNotIn(event, self.security_manager)
        for event in ('SECURITY_AUDIT_STARTED', 'SECURITY_AUDIT_COMPLETED'):
            self.assertIn(f'AuditLogType.{event}', self.security_manager)
            self.assertNotIn(event, self.integrity_manager)

    def test_which_files_aide_named_reaches_the_event_list(self):
        # An exit code says something no longer matches; it does not say what, and that answer
        # was only in a report on the engine host.
        self.assertIn('changesInLog', self.integrity_manager)
        self.assertIn('changesInLog', self.command)
        self.assertIn('Kind.REMOVED', self.integrity_manager)
        self.assertIn('Kind.REMOVED', self.command)

    def test_a_scheduled_run_reaches_the_event_list_at_all(self):
        # The daily timer's run is the one nobody is watching, and it used to write to a log
        # file on the engine host and nothing else.
        service = (
            ROOT / 'packaging/services/ovirt-engine/ovirt-engine-security-audit.service.in'
        ).read_text(encoding='utf-8')
        self.assertIn('ovirt-engine-security-verification-runner.sh all timer', service)

        for manager in (self.security_manager, self.integrity_manager):
            self.assertIn('scheduleWithFixedDelay', manager)
            self.assertIn('VerificationReportLedger.alreadyReported', manager)
            self.assertIn('VerificationReportLedger.markReported', manager)

    def test_a_run_from_the_screen_is_not_reported_twice(self):
        # SecurityAuditCommand and IntegrityVerificationCommand record their own runs as they
        # go, with the account that asked for them.
        self.assertIn('"source": "${SECURITY_AUDIT_SOURCE:-unknown}"', self.audit)
        self.assertIn('SECURITY_AUDIT_SOURCE="$SOURCE"', self.runner)
        self.assertIn('"source": "$SOURCE"', self.runner)
        for manager in (self.security_manager, self.integrity_manager):
            self.assertIn('WEBADMIN = "webadmin"', manager)
            self.assertIn('WEBADMIN.equals(', manager)

    def test_a_start_verifies_integrity_without_holding_the_start_up(self):
        # AIDE walks the whole filesystem and takes minutes. As a start gate that is systemd's
        # start timeout, and the engine would not come up at all - so the engine comes up first
        # and the verification follows it, on the scheduled pool, with nothing waiting on it.
        launcher = (
            ROOT / 'packaging/services/ovirt-engine/ovirt-engine.py.in'
        ).read_text(encoding='utf-8')
        self.assertIn("[runner, 'security', 'engine-start']", launcher)
        self.assertNotIn("'integrity'", launcher)

        self.assertIn(
            'executor.schedule(this::verifyOnStart', self.integrity_manager
        )
        self.assertIn(
            'SecurityAuditRunner.run(INTEGRITY_MODE, ENGINE_START)', self.integrity_manager
        )

    def test_a_start_does_not_re_verify_what_was_verified_an_hour_ago(self):
        # Restarts come in threes when somebody is working on a host, and a full AIDE run for
        # each of them is minutes of disk for an answer given minutes ago.
        self.assertIn('MAX_AGE = Duration.ofHours(12)', self.integrity_manager)
        self.assertIn(
            'ON_START_ENV = "INTEGRITY_VERIFICATION_ON_START"', self.integrity_manager
        )
        for setting in ('"false"', '"always"'):
            self.assertIn(f'{setting}.equalsIgnoreCase(configured)', self.integrity_manager)

    def test_every_start_says_what_the_last_verification_found(self):
        # A start within the twelve hours runs no verification, and without this the event list
        # said nothing at all then: a host with three altered files and a host verified clean
        # looked exactly alike at the moment of a start.
        self.assertIn('reportAsItStoodAtStartup', self.integrity_manager)
        self.assertIn('At engine start, the last integrity verification', self.integrity_manager)
        # Said once per start, and the pass that follows does not say it again.
        self.assertIn('reportedAtStartup', self.integrity_manager)
        self.assertIn('VerificationReportLedger.markReported', self.integrity_manager)

    def test_a_start_with_nothing_to_report_and_nothing_to_run_says_so(self):
        # Silence would leave the event list saying nothing about integrity, which is what it
        # also says about a host that was checked and found clean.
        self.assertIn('reportNothingToStandOn', self.integrity_manager)
        self.assertIn('No integrity verification result was available', self.integrity_manager)

    def test_a_start_verification_that_never_finished_does_not_pass_for_a_clean_one(self):
        # A run that timed out leaves no result for the watching pass to find, and silence
        # reads as a host that verified clean.
        self.assertIn('Outcome.TIMED_OUT', self.integrity_manager)
        self.assertIn('did not finish', self.integrity_manager)

    def test_the_integrity_reporter_is_registered_so_it_is_created_at_all(self):
        # A BackendService left out of InitBackendServicesOnStartupBean is never constructed,
        # so its @PostConstruct never runs and it silently does nothing.
        startup = (BLL / 'InitBackendServicesOnStartupBean.java').read_text(encoding='utf-8')
        self.assertIn(
            'serviceLoader.load(IntegrityVerificationAuditManager.class)', startup
        )


if __name__ == '__main__':
    unittest.main()
