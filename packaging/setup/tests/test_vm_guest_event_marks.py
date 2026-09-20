import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
UPGRADE = 'packaging/dbscripts/upgrade/04_05_0344_add_guest_event_marks.sql'
MANAGER = (
    'backend/manager/modules/bll/src/main/java'
    '/org/ovirt/engine/core/bll/GuestCriticalEventAuditManager.java'
)


class VmGuestEventMarkTest(unittest.TestCase):
    def test_marks_are_kept_in_the_database(self):
        manager = (ROOT / MANAGER).read_text(encoding='utf-8')

        # Held in memory, a restart of the engine reports again everything the lookback
        # window still holds.
        self.assertIn('VmGuestEventMarkDao', manager)
        self.assertNotIn('Map<Guid, Map<String, Long>> recorded', manager)

    def test_mark_table_is_created_on_install_and_on_upgrade(self):
        tables = (
            ROOT / 'packaging/dbscripts/create_tables.sql'
        ).read_text(encoding='utf-8')
        upgrade = (ROOT / UPGRADE).read_text(encoding='utf-8')

        self.assertIn('CREATE TABLE vm_guest_event_mark', tables)
        self.assertIn('CREATE TABLE IF NOT EXISTS vm_guest_event_mark', upgrade)
        self.assertIn('--#source vm_guest_event_mark_sp.sql', upgrade)
        # A removed VM must not leave its marks behind.
        self.assertIn('FOREIGN KEY (vm_id)', upgrade)
        self.assertIn('REFERENCES vm_static(vm_guid) ON DELETE CASCADE', upgrade)

    def test_the_security_log_can_be_turned_off_on_its_own(self):
        properties = (
            ROOT / 'packaging/etc/engine-config/engine-config.properties'
        ).read_text(encoding='utf-8')
        defaults = (
            ROOT / 'packaging/dbscripts/upgrade/pre_upgrade/0000_config.sql'
        ).read_text(encoding='utf-8')
        upgrade = (ROOT / UPGRADE).read_text(encoding='utf-8')

        key = 'VmGuestSecurityEventsEnabled'
        self.assertIn(key + '.description=', properties)
        self.assertIn("'" + key + "'", defaults)
        self.assertIn("'" + key + "'", upgrade)


if __name__ == '__main__':
    unittest.main()
