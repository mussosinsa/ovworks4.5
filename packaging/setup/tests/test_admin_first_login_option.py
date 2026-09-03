import ast
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
    def test_answer_file_can_override_first_login_password_change(self):
        source = AAA_PLUGIN.read_text(encoding='utf-8')
        tree = ast.parse(source)

        defaults = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == 'setdefault'
            and any(
                isinstance(argument, ast.Attribute)
                and argument.attr ==
                'ADMIN_PASSWORD_FORCE_CHANGE_ON_FIRST_LOGIN'
                for argument in node.args
            )
        ]

        self.assertEqual(1, len(defaults))
        self.assertIs(defaults[0].args[1].value, True)

    def test_admin_password_expiration_uses_answer_file_option(self):
        source = AAA_JDBC_PLUGIN.read_text(encoding='utf-8')

        self.assertIn(
            'forceChange = self.environment[\n'
            '            oenginecons.ConfigEnv.'
            'ADMIN_PASSWORD_FORCE_CHANGE_ON_FIRST_LOGIN\n'
            '        ]',
            source,
        )
        self.assertNotIn('forceChange = True', source)


if __name__ == '__main__':
    unittest.main()
