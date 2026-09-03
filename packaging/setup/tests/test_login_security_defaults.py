import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]


class LoginSecurityDefaultsTest(unittest.TestCase):
    def test_force_change_on_first_login_is_wired_to_password_reset(self):
        option = 'PasswordPolicyForceChangeOnFirstLogin'
        config_properties = (
            ROOT / 'packaging/etc/engine-config/engine-config.properties'
        ).read_text(encoding='utf-8')
        config_values = (
            ROOT
            / 'backend/manager/modules/common/src/main/java/org/ovirt/engine/core/common/config/ConfigValues.java'
        ).read_text(encoding='utf-8')
        resolver = (
            ROOT
            / 'backend/manager/modules/bll/src/main/java/org/ovirt/engine/core/bll/aaa/PasswordPolicyResolver.java'
        ).read_text(encoding='utf-8')
        reset_command = (
            ROOT
            / 'backend/manager/modules/bll/src/main/java/org/ovirt/engine/core/bll/aaa/ResetUserPasswordCommand.java'
        ).read_text(encoding='utf-8')
        config_sql = (
            ROOT / 'packaging/dbscripts/upgrade/pre_upgrade/0000_config.sql'
        ).read_text(encoding='utf-8')

        self.assertIn(f'{option}.type=Boolean', config_properties)
        self.assertIn(f'{option}.validValues=true,false', config_properties)
        self.assertIn(f'{option},', config_values)
        self.assertIn(f'ConfigValues.{option}', resolver)
        self.assertIn('PasswordPolicyResolver.isForceChangeOnFirstLogin()', reset_command)
        self.assertIn('passwordValidTo(forceChangeOnFirstLogin)', reset_command)
        self.assertIn(f"'{option}','true'", config_sql)

    def test_engine_config_enforces_security_ranges(self):
        config = (
            ROOT / 'packaging/etc/engine-config/engine-config.properties'
        ).read_text(encoding='utf-8')

        self.assertIn('UserSessionTimeOutInterval.validValues=1..10', config)
        self.assertIn(
            'ENGINE_SSO_ADMIN_LOCK_MAX_FAILURES.validValues=1..5',
            config,
        )
        self.assertIn(
            'ENGINE_SSO_ADMIN_LOCK_MINUTES.validValues=5..100000',
            config,
        )
        self.assertIn(
            'ENGINE_SSO_SINGLE_SESSION_POLICY.validValues='
            'REPLACE_EXISTING,REJECT_NEW',
            config,
        )

    def test_new_install_defaults_use_minutes(self):
        config_sql = (
            ROOT / 'packaging/dbscripts/upgrade/pre_upgrade/0000_config.sql'
        ).read_text(encoding='utf-8')

        self.assertIn("'UserSessionTimeOutInterval','10'", config_sql)
        self.assertIn("'ENGINE_SSO_ADMIN_LOCK_MAX_FAILURES','5'", config_sql)
        self.assertIn("'ENGINE_SSO_ADMIN_LOCK_MINUTES','5'", config_sql)
        self.assertIn(
            "'ENGINE_SSO_SINGLE_SESSION_POLICY','REPLACE_EXISTING'",
            config_sql,
        )
        self.assertNotIn('ENGINE_SSO_ADMIN_LOCK_HOURS', config_sql)

    def test_upgrade_replaces_legacy_hours_and_excessive_values(self):
        upgrade_sql = (
            ROOT
            / 'packaging/dbscripts/upgrade'
            / '04_05_0323_enforce_login_security_limits.sql'
        ).read_text(encoding='utf-8')

        self.assertIn(
            "fn_db_update_config_value('UserSessionTimeOutInterval', "
            "'10', 'general')",
            upgrade_sql,
        )
        self.assertIn(
            "fn_db_update_config_value('ENGINE_SSO_ADMIN_LOCK_MAX_FAILURES', "
            "'5', 'general')",
            upgrade_sql,
        )
        self.assertIn(
            "fn_db_delete_config_value_all_versions("
            "'ENGINE_SSO_ADMIN_LOCK_HOURS')",
            upgrade_sql,
        )
        self.assertIn(
            "fn_db_add_config_value('ENGINE_SSO_ADMIN_LOCK_MINUTES', "
            "'5', 'general')",
            upgrade_sql,
        )


if __name__ == '__main__':
    unittest.main()
