import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
KEYS = (
    'ENGINE_AUDIT_LOG_MAX_SIZE_MB',
    'ENGINE_AUDIT_LOG_CAPACITY_CHECK_INTERVAL_SECONDS',
    'ENGINE_AUDIT_LOG_DIR',
)


class AuditLogEngineConfigTest(unittest.TestCase):
    def test_capacity_monitor_uses_engine_config(self):
        monitor = (
            ROOT
            / 'backend/manager/modules/bll/src/main/java'
            / 'org/ovirt/engine/core/bll/AuditLogCapacityMonitor.java'
        ).read_text(encoding='utf-8')

        self.assertIn('Config.<Long> getValue', monitor)
        self.assertIn('Config.<String> getValue', monitor)
        self.assertNotIn('EngineLocalConfig', monitor)
        for key in KEYS:
            self.assertIn('ConfigValues.' + key, monitor)

    def test_keys_are_available_to_engine_environment_management(self):
        properties = (
            ROOT / 'packaging/etc/engine-config/engine-config.properties'
        ).read_text(encoding='utf-8')
        defaults = (
            ROOT / 'packaging/dbscripts/upgrade/pre_upgrade/0000_config.sql'
        ).read_text(encoding='utf-8')
        upgrade = (
            ROOT
            / 'packaging/dbscripts/upgrade'
            / '04_05_0324_add_audit_log_capacity_config.sql'
        ).read_text(encoding='utf-8')

        for key in KEYS:
            self.assertIn(key + '.description=', properties)
            self.assertIn("'" + key + "'", defaults)
            self.assertIn("'" + key + "'", upgrade)


if __name__ == '__main__':
    unittest.main()
