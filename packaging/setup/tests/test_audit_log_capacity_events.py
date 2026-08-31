import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]


class AuditLogCapacityEventsTest(unittest.TestCase):
    def test_capacity_lifecycle_events_are_visible_to_webadmin(self):
        audit_types = (
            ROOT
            / 'backend/manager/modules/common/src/main/java'
            / 'org/ovirt/engine/core/common/AuditLogType.java'
        ).read_text(encoding='utf-8')
        messages = (
            ROOT
            / 'backend/manager/modules/dal/src/main/resources/bundles'
            / 'AuditLogMessages.properties'
        ).read_text(encoding='utf-8')
        webadmin_events = (
            ROOT
            / 'frontend/webadmin/modules/uicommonweb/src/main/java'
            / 'org/ovirt/engine/ui/uicommonweb/dataprovider'
            / 'VdcEventNotificationUtils.java'
        ).read_text(encoding='utf-8')

        for event in (
            'AUDIT_LOG_CAPACITY_MONITOR_STARTED',
            'AUDIT_LOG_CAPACITY_WARNING',
            'AUDIT_LOG_CAPACITY_EXCEEDED',
            'AUDIT_LOG_CAPACITY_RECOVERED',
        ):
            self.assertIn(event, audit_types)
            self.assertIn(event + '=', messages)
            self.assertIn('AuditLogType.' + event, webadmin_events)


if __name__ == '__main__':
    unittest.main()
