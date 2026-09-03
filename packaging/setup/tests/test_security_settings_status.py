import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
VIEW = (
    ROOT
    / 'frontend/webadmin/modules/webadmin/src/main/java'
    / 'org/ovirt/engine/ui/webadmin/section/main/view/popup/security'
    / 'IntegrityCheckView.java'
)


class SecuritySettingsStatusTest(unittest.TestCase):
    def setUp(self):
        self.view = VIEW.read_text(encoding='utf-8')

    def test_statuses_are_restored_when_the_view_is_loaded(self):
        self.assertIn('protected void onLoad()', self.view)
        self.assertIn('loadVerificationHistory(true);', self.view)
        self.assertIn('if (restoreStatuses)', self.view)
        self.assertEqual(2, self.view.count('restoreLastExecutionState(') - 1)

    def test_latest_completed_result_controls_the_status(self):
        self.assertIn('AuditLog latestResult = getLatestResult(history);', self.view)
        self.assertIn('AuditLogType.SECURITY_AUDIT_COMPLETED', self.view)
        self.assertIn('AuditLogType.INTEGRITY_VERIFICATION_COMPLETED', self.view)
        self.assertIn('setNormalState(button, statusLabel, errorLabel);', self.view)
        self.assertIn('setFailedState(button, statusLabel, errorLabel);', self.view)

    def test_started_events_are_not_treated_as_final_results(self):
        self.assertIn('AuditLogType.SECURITY_AUDIT_STARTED', self.view)
        self.assertIn('AuditLogType.INTEGRITY_VERIFICATION_STARTED', self.view)
        self.assertIn('continue;', self.view)


if __name__ == '__main__':
    unittest.main()
