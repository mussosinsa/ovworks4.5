import unittest
from pathlib import Path


AAA_PLUGIN = (
    Path(__file__).parents[1]
    / 'plugins/ovirt-engine-setup/ovirt-engine/config/aaa.py'
)
AAA_JDBC_PLUGIN = (
    Path(__file__).parents[1]
    / 'plugins/ovirt-engine-setup/ovirt-engine/config/aaajdbc.py'
)


class AdminFirstLoginOptionTest(unittest.TestCase):
    def test_bootstrap_admin_always_requires_first_login_password_change(self):
        source = AAA_PLUGIN.read_text(encoding='utf-8')

        self.assertIn(
            'self.environment[\n'
            '            oenginecons.ConfigEnv.'
            'ADMIN_PASSWORD_FORCE_CHANGE_ON_FIRST_LOGIN\n'
            '        ] = True',
            source,
        )
        self.assertNotIn(
            'self.environment.setdefault(\n'
            '            oenginecons.ConfigEnv.'
            'ADMIN_PASSWORD_FORCE_CHANGE_ON_FIRST_LOGIN',
            source,
        )

    def test_admin_password_is_unconditionally_expired(self):
        source = AAA_JDBC_PLUGIN.read_text(encoding='utf-8')

        self.assertIn('forceChange = True', source)
        self.assertNotIn(
            'forceChange = self.environment[\n'
            '            oenginecons.ConfigEnv.'
            'ADMIN_PASSWORD_FORCE_CHANGE_ON_FIRST_LOGIN',
            source,
        )


if __name__ == '__main__':
    unittest.main()
