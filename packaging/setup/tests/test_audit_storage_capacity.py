import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
BLL = ROOT / 'backend/manager/modules/bll/src/main/java/org/ovirt/engine/core/bll'
KEYS = (
    'ENGINE_AUDIT_STORAGE_THRESHOLDS',
    'ENGINE_AUDIT_DB_DATA_DIR',
    'ENGINE_AUDIT_BACKUP_DIR',
)
EVENTS = (
    'AUDIT_STORAGE_USAGE_NOTICE',
    'AUDIT_STORAGE_USAGE_WARNING',
    'AUDIT_STORAGE_USAGE_HIGH',
    'AUDIT_STORAGE_MEASUREMENT_FAILED',
    'AUDIT_STORAGE_DB_MAINTENANCE_WARNING',
    'AUDIT_LOG_RECORDS_PURGED',
    'AUDIT_LOG_RECORDS_PURGE_FAILED',
    'AUDIT_LOG_CAPACITY_PURGE_BLOCKED',
    'AUDIT_STORAGE_RESERVE_RELEASED',
    'AUDIT_STORAGE_RESERVE_READY',
    'AUDIT_STORAGE_RESERVE_UNAVAILABLE',
    'AUDIT_STORAGE_WAL_ON_DATA_FILESYSTEM',
    'AUDIT_STORAGE_CAPACITY_PLAN_WARNING',
)


def read(path):
    return (ROOT / path).read_text(encoding='utf-8')


class AuditStorageCapacityTest(unittest.TestCase):
    def test_storage_keys_are_available_to_engine_environment_management(self):
        properties = read('packaging/etc/engine-config/engine-config.properties')
        defaults = read('packaging/dbscripts/upgrade/pre_upgrade/0000_config.sql')
        upgrade = read(
            'packaging/dbscripts/upgrade/'
            '04_05_0346_add_audit_storage_thresholds.sql'
        )
        config_values = read(
            'backend/manager/modules/common/src/main/java/org/ovirt/engine/'
            'core/common/config/ConfigValues.java'
        )
        monitor = (BLL / 'AuditLogCapacityMonitor.java').read_text(encoding='utf-8')
        validator = (BLL / 'SetEngineConfigValueCommand.java').read_text(encoding='utf-8')
        for key in KEYS:
            self.assertIn(key + '.description=', properties)
            self.assertIn("'" + key + "'", defaults)
            self.assertIn("'" + key + "'", upgrade)
            self.assertIn(key + ',', config_values)
            self.assertIn('ConfigValues.' + key, monitor)
            self.assertIn('"' + key + '"', validator)
        self.assertIn("'70,80,90,95'", upgrade)

    def test_event_tables_limit_and_purge_have_their_defaults(self):
        properties = read('packaging/etc/engine-config/engine-config.properties')
        defaults = read('packaging/dbscripts/upgrade/pre_upgrade/0000_config.sql')
        upgrade = read(
            'packaging/dbscripts/upgrade/'
            '04_05_0347_add_audit_event_tables_limit.sql'
        )
        config_values = read(
            'backend/manager/modules/common/src/main/java/org/ovirt/engine/'
            'core/common/config/ConfigValues.java'
        )
        validator = (BLL / 'SetEngineConfigValueCommand.java').read_text(encoding='utf-8')
        expected = {
            'ENGINE_AUDIT_EVENT_TABLES_MAX_SIZE_MB': '10240',
            'ENGINE_AUDIT_CAPACITY_PURGE_ENABLED': 'true',
            'ENGINE_AUDIT_CAPACITY_PURGE_MIN_RETENTION_DAYS': '30',
            'ENGINE_AUDIT_CAPACITY_PURGE_TARGET_PERCENT': '80',
            'ENGINE_AUDIT_PURGE_ARCHIVE_DIR': '/var/lib/ovirt-engine-backup/audit-log-purged',
        }
        for key, value in expected.items():
            self.assertIn(key + '.description=', properties)
            self.assertIn("'%s','%s'" % (key, value), defaults)
            self.assertIn("'%s', '%s'" % (key, value), upgrade)
            self.assertIn(key + ',', config_values)
            self.assertIn('"' + key + '"', validator)
        # Audit records are kept 90 days; an installation still on the old default moves with it.
        self.assertIn("fn_db_add_config_value('AuditLogAgingThreshold','90','general')", defaults)
        self.assertIn(
            "fn_db_update_default_config_value('AuditLogAgingThreshold', '30', '90', 'general', false)",
            upgrade,
        )

    def test_storage_events_are_visible_to_webadmin(self):
        audit_types = read(
            'backend/manager/modules/common/src/main/java/org/ovirt/engine/'
            'core/common/AuditLogType.java'
        )
        messages = read(
            'backend/manager/modules/dal/src/main/resources/bundles/'
            'AuditLogMessages.properties'
        )
        webadmin = read(
            'frontend/webadmin/modules/uicommonweb/src/main/java/org/ovirt/'
            'engine/ui/uicommonweb/dataprovider/VdcEventNotificationUtils.java'
        )
        for event in EVENTS:
            self.assertIn(event + '(', audit_types)
            self.assertIn(event + '=', messages)
            self.assertIn('AuditLogType.' + event + ')', webadmin)
        # The critical and full levels keep the events subscribers already have.
        for event in ('AUDIT_LOG_CAPACITY_WARNING', 'AUDIT_LOG_CAPACITY_EXCEEDED'):
            message = next(
                line for line in messages.splitlines()
                if line.startswith(event + '=')
            )
            self.assertIn('${Target}', message)

    def test_protection_tab_shows_the_storage_and_refreshes_it(self):
        view_dir = (
            'frontend/webadmin/modules/webadmin/src/main/java/org/ovirt/engine/'
            'ui/webadmin/section/main/view/popup/security/'
        )
        view = read(view_dir + 'AuditLogProtectionTabView.java')
        layout = read(view_dir + 'AuditLogProtectionTabView.ui.xml')
        self.assertIn('ActionType.GetAuditLogStorageStatus', view)
        # The periodic refresh reads the rows the engine last measured.
        self.assertIn('status.getStorageRows()', view)
        for field in ('capacityStateLabel', 'refreshCapacityButton',
                      'capacityGaugeLabel', 'capacityDetailLabel'):
            self.assertIn('ui:field="%s"' % field, layout)
            self.assertIn(' ' + field + ';', view)
        self.assertEqual(1, layout.count('감사기록 저장소 용량'))

    def test_backup_and_restore_consult_the_storage_first(self):
        backup = (BLL / 'FullLogBackupCommand.java').read_text(encoding='utf-8')
        restore = (BLL / 'RestoreAuditLogBackupCommand.java').read_text(encoding='utf-8')
        self.assertLess(backup.index('backupBlockReason()'), backup.index('runCommand(Arrays.asList('))
        self.assertLess(restore.index('restoreBlockReason()'), restore.index('runCommand(Arrays.asList('))

    def test_watch_timer_is_packaged_and_enabled_by_setup(self):
        service = read('packaging/services/ovirt-engine/ovirt-engine-audit-storage-watch.service')
        timer = read('packaging/services/ovirt-engine/ovirt-engine-audit-storage-watch.timer')
        spec = read('ovirt-engine.spec.in')
        plugins = read('packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/system/__init__.py')
        plugin = read('packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/system/audit_storage_watch.py')

        self.assertIn('/usr/share/ovirt-engine/bin/audit-storage-usage.py watch', service)
        self.assertNotIn('User=', service)
        self.assertIn('Unit=ovirt-engine-audit-storage-watch.service', timer)
        self.assertIn('WantedBy=timers.target', timer)
        for unit in ('service', 'timer'):
            self.assertIn('%{_unitdir}/ovirt-engine-audit-storage-watch.' + unit, spec)
        self.assertIn('audit_storage_watch.Plugin(context=context)', plugins)
        self.assertIn("'ovirt-engine-audit-storage-watch.timer'", plugin)


    def test_setup_checks_the_storage_layout_before_the_engine_starts(self):
        source = read(
            'packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/system/'
            'audit_storage_watch.py'
        )
        self.assertIn("'usage', '--log-dir', '/var/log'", source)
        check = source[source.index('def _check_storage_layout'):]
        events = source[:source.index('def _check_storage_layout')]
        self.assertIn(
            'before=(oengcommcons.Stages.CORE_ENGINE_START,)',
            events[events.rindex('@plugin.event'):],
        )
        self.assertIn('raiseOnError=False', check)

        # layout_warnings needs nothing from otopi; run it on its own.
        tree = ast.parse(source)
        function = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and
            node.name == 'layout_warnings'
        )
        namespace = {'_': lambda message: message}
        exec(compile(ast.Module(body=[function], type_ignores=[]),
                     'audit_storage_watch', 'exec'), namespace)
        layout_warnings = namespace['layout_warnings']

        self.assertEqual([], layout_warnings({}))
        self.assertEqual([], layout_warnings({
            'wal': {'same_filesystem': False},
            'reserve': {'state': 'present'},
        }))
        warnings = layout_warnings({
            'filesystems': {'db': {'mount': '/var/lib/pgsql'}},
            'wal': {'path': '/var/lib/pgsql/data/pg_wal',
                    'same_filesystem': True},
            'reserve': {'state': 'insufficient', 'detail': 'no room'},
        })
        self.assertEqual(2, len(warnings))
        self.assertIn('/var/lib/pgsql', warnings[0])
        self.assertIn('PANIC', warnings[0])
        self.assertIn('no room', warnings[1])

    def test_watch_timer_runs_often_enough_to_release_the_reserve(self):
        timer = read(
            'packaging/services/ovirt-engine/'
            'ovirt-engine-audit-storage-watch.timer'
        )
        self.assertIn('OnUnitActiveSec=2min', timer)


if __name__ == '__main__':
    unittest.main()
