import re
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
PLUGIN = (
    ROOT / 'packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/config/aaajdbc.py'
)
AUTH = (
    ROOT / 'backend/manager/modules/enginesso/src/main/java/org/ovirt/engine/core/sso'
    / 'service/AuthenticationService.java'
)
CONFIG_SQL = ROOT / 'packaging/dbscripts/upgrade/pre_upgrade/0000_config.sql'


class AaaJdbcLockMinutesTest(unittest.TestCase):
    """There are two locks on one login, and an account is usable again only when both lift.

    The engine applies its own from the SSO path; aaa-jdbc applies one inside the
    authentication it performs. aaa-jdbc holding a lock for its default hour makes the
    engine's five minutes mean nothing - the account stays locked for the hour while the
    engine's audit log says the lock was released.
    """

    def setUp(self):
        self.plugin = PLUGIN.read_text(encoding='utf-8')

    def test_setup_sets_the_aaa_jdbc_lock(self):
        self.assertIn("'settings',", self.plugin)
        self.assertIn("'set',", self.plugin)
        self.assertIn("'--name=%s' % self._AAA_JDBC_LOCK_MINUTES_SETTING", self.plugin)
        self.assertIn("_AAA_JDBC_LOCK_MINUTES_SETTING = 'LOCK_MINUTES'", self.plugin)
        self.assertIn("'--value=%s' % minutes", self.plugin)

    def test_the_value_is_the_engines_own_and_not_a_second_opinion(self):
        # Asked for once. An administrator who changes it with engine-config and runs
        # engine-setup gets both halves of the lock moving together.
        self.assertIn(
            "_ENGINE_LOCK_MINUTES_OPTION = 'ENGINE_SSO_ADMIN_LOCK_MINUTES'", self.plugin
        )
        self.assertIn('getVdcOption(', self.plugin)
        self.assertIn('self._ENGINE_LOCK_MINUTES_OPTION,', self.plugin)

    def test_five_when_the_engine_has_not_been_told_otherwise(self):
        self.assertIn('_DEFAULT_LOCK_MINUTES = 5', self.plugin)
        # The same five the engine falls back to, and the same five the database ships.
        self.assertIn(
            'DEFAULT_LOCK_MINUTES = 5', AUTH.read_text(encoding='utf-8')
        )
        self.assertIn(
            "fn_db_add_config_value('ENGINE_SSO_ADMIN_LOCK_MINUTES','5','general')",
            CONFIG_SQL.read_text(encoding='utf-8'),
        )

    def test_a_value_that_is_not_a_number_of_minutes_does_not_reach_the_tool(self):
        # engine-config validates 5..100000, but the row can be written by other means, and a
        # lock of zero minutes is no lock at all.
        self.assertIn('except (TypeError, ValueError):', self.plugin)
        self.assertIn('if minutes <= 0:', self.plugin)
        self.assertIn('return self._DEFAULT_LOCK_MINUTES', self.plugin)

    def test_it_runs_where_there_is_an_internal_provider_to_align(self):
        step = self.plugin[
            self.plugin.index('def _setupLockMinutes'):
            self.plugin.index('def _setupAdminPassword')
        ]
        self.assertIn('AAA_JDBC_CONFIG_DB', step)
        self.assertIn('os.path.exists', step)

        # After the schema exists - the tool writes to it - and not tied to the admin account's
        # authz type: an installation whose administrator came from a directory still has an
        # internal provider with a lock on it.
        decorator = self.plugin[
            self.plugin.index('def _engineLockMinutes'):
            self.plugin.index('def _setupLockMinutes')
        ]
        self.assertIn('oengcommcons.Stages.DB_SCHEMA', decorator)
        self.assertNotIn('ADMIN_USER_AUTHZ_TYPE', decorator)

    def test_the_engine_reads_the_same_option_it_is_aligned_to(self):
        # If the engine ever read the lock from somewhere else, aligning aaa-jdbc to this one
        # would keep the two apart while looking like it kept them together.
        auth = AUTH.read_text(encoding='utf-8')
        self.assertIn('ADMIN_LOCK_MINUTES_KEY = "ENGINE_SSO_ADMIN_LOCK_MINUTES"', auth)
        self.assertTrue(
            re.search(r'getLockDuration\(ssoContext,\s*protectedAdmin', auth),
            'the admin lock duration is no longer read from that key',
        )


if __name__ == '__main__':
    unittest.main()
