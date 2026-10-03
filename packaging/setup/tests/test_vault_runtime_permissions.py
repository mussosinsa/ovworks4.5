import ast
import grp
import os
import pwd
import shutil
import stat
import tempfile
import unittest
from pathlib import Path


CLIENT_CONTROL = (
    Path(__file__).parents[1] / 'plugins' / 'ovirt-engine-setup' /
    'ovirt-engine' / 'config' / 'client_control.py'
)


def module_imports(tree):
    names = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            names.update(alias.asname or alias.name for alias in node.names)
    return names


def ensure_vault_runtime_permissions():
    """The setup method, run without otopi, with the module's own imports."""
    tree = ast.parse(CLIENT_CONTROL.read_text(encoding='utf-8'))
    method = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and
        node.name == '_ensure_vault_runtime_permissions'
    )
    namespace = {}
    for name in module_imports(tree):
        namespace[name] = __import__(name)
    namespace['_'] = lambda message: message
    namespace['osetupcons'] = type('C', (), {
        'SystemEnv': type('S', (), {'USER_ENGINE': 'u', 'GROUP_ENGINE': 'g'}),
    })
    module = ast.Module(body=[method], type_ignores=[])
    exec(compile(module, str(CLIENT_CONTROL), 'exec'), namespace)
    return namespace['_ensure_vault_runtime_permissions']


class FakePlugin(object):
    def __init__(self):
        self.environment = {
            'u': pwd.getpwuid(os.getuid()).pw_name,
            'g': grp.getgrgid(os.getgid()).gr_name,
        }
        self.logger = type('L', (), {'info': lambda *args: None})()


class VaultRuntimePermissionsTest(unittest.TestCase):

    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.directory)
        self.method = ensure_vault_runtime_permissions()

    def config(self, token_file):
        return {'vault_transit': {'enabled': True, 'token_file': token_file}}

    def test_the_module_imports_what_the_method_uses(self):
        tree = ast.parse(CLIENT_CONTROL.read_text(encoding='utf-8'))
        self.assertIn('stat', module_imports(tree))

    def test_the_token_is_made_private(self):
        token = os.path.join(self.directory, 'vault-token')
        Path(token).write_text('s.token\n')
        os.chmod(token, 0o644)
        self.method(FakePlugin(), self.config(token))
        self.assertEqual(0o600, stat.S_IMODE(os.stat(token).st_mode))

    def test_a_symbolic_link_is_refused(self):
        target = os.path.join(self.directory, 'elsewhere')
        Path(target).write_text('s.token\n')
        token = os.path.join(self.directory, 'vault-token')
        os.symlink(target, token)
        with self.assertRaises(RuntimeError):
            self.method(FakePlugin(), self.config(token))

    def test_nothing_to_do_without_vault(self):
        self.method(FakePlugin(), {'vault_transit': {'enabled': False}})
        self.method(FakePlugin(), {})


if __name__ == '__main__':
    unittest.main()
