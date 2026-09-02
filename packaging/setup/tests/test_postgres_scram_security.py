import ast
import unittest
from pathlib import Path


SETUP_ROOT = Path(__file__).parents[1]
PROVISIONING = (
    SETUP_ROOT / 'ovirt_engine_setup' / 'engine_common' / 'postgres.py'
)
PLUGIN = (
    SETUP_ROOT
    / 'plugins'
    / 'ovirt-engine-setup'
    / 'ovirt-engine'
    / 'provisioning'
    / 'postgres.py'
)
BACKUP_SCRIPT = SETUP_ROOT.parent / 'bin' / 'engine-backup.sh.in'
BACKUP_MAN_PAGE = SETUP_ROOT.parent / 'man' / 'man8' / 'engine-backup.8'


class PostgresScramSecurityTest(unittest.TestCase):
    def test_backup_restore_guidance_uses_scram_authentication(self):
        for path in (BACKUP_SCRIPT, BACKUP_MAN_PAGE):
            content = path.read_text(encoding='utf-8')
            self.assertIn('scram-sha-256', content)
            self.assertNotIn('0.0.0.0/0               md5', content)
            self.assertNotIn('::0/0                   md5', content)

    def test_provisioning_uses_scram_for_roles_config_and_hba(self):
        source = PROVISIONING.read_text(encoding='utf-8')
        self.assertGreaterEqual(
            source.count("set password_encryption = 'scram-sha-256'"),
            3,
        )
        self.assertIn("'key': 'password_encryption'", source)
        self.assertIn("'expected': \"'scram-sha-256'\"", source)
        self.assertIn("auth='scram-sha-256'", source)
        self.assertIn("auth='md5'", source)
        self.assertIn('alter role postgres', source)
        self.assertIn("args={'password': password}", source)

    def test_password_prompt_is_hidden_and_confirmed(self):
        source = PLUGIN.read_text(encoding='utf-8')
        tree = ast.parse(source)
        prompts = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == 'queryString'
            and any(
                keyword.arg == 'name'
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value ==
                'OVESETUP_PROVISIONING_POSTGRES_SUPERUSER_PASSWORD'
                for keyword in node.keywords
            )
        ]
        self.assertEqual(2, len(prompts))
        for prompt in prompts:
            hidden = next(
                keyword.value.value
                for keyword in prompt.keywords
                if keyword.arg == 'hidden'
            )
            self.assertTrue(hidden)
        self.assertIn('password != confirmation', source)
        self.assertIn('len(password) < 14', source)

    def test_superuser_password_is_deferred_until_closeup(self):
        provisioning_source = PROVISIONING.read_text(encoding='utf-8')
        plugin_source = PLUGIN.read_text(encoding='utf-8')

        provision_body = provisioning_source.split(
            '    def provision(self):', 1
        )[1].split('    def createUser(self):', 1)[0]
        self.assertNotIn('_setPostgresSuperuserPassword', provision_body)
        self.assertIn(
            'def setPostgresSuperuserPassword(self):',
            provisioning_source,
        )
        self.assertIn(
            'stage=plugin.Stages.STAGE_CLOSEUP',
            plugin_source,
        )
        self.assertIn(
            "'setPostgresSuperuserPassword'",
            plugin_source,
        )
        self.assertIn('if not callable(set_password):', plugin_source)
        self.assertIn('set_password()', plugin_source)

    def test_scram_authentication_is_enabled_only_at_closeup(self):
        source = PROVISIONING.read_text(encoding='utf-8')
        provision_body = source.split(
            '    def provision(self):', 1
        )[1].split('    def createUser(self):', 1)[0]
        perform_database_body = source.split(
            '    def _performDatabase(', 1
        )[1].split('    def _initDbIfRequired(', 1)[0]
        closeup_body = source.split(
            '    def setPostgresSuperuserPassword(self):', 1
        )[1].split('    def provision(self):', 1)[0]

        self.assertIn(
            "set password_encryption = 'md5'",
            perform_database_body,
        )
        self.assertIn("auth='md5'", provision_body)
        self.assertIn(
            "set password_encryption = 'scram-sha-256'",
            closeup_body,
        )
        self.assertIn("auth='scram-sha-256'", closeup_body)

    def test_plugin_supports_older_engine_common_constants(self):
        source = PLUGIN.read_text(encoding='utf-8')
        self.assertIn("getattr(\n    oengcommcons.ProvisioningEnv", source)
        self.assertIn(
            "'OVESETUP_PROVISIONING/postgresSuperuserPassword'",
            source,
        )
        self.assertNotIn(
            'oengcommcons.ProvisioningEnv.POSTGRES_SUPERUSER_PASSWORD',
            source,
        )


if __name__ == '__main__':
    unittest.main()
