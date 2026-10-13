import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
LAUNCHER = ROOT / 'packaging/services/ovirt-engine/ovirt-engine.py.in'
LOGIN_CRYPTO = (
    ROOT
    / 'backend/manager/modules/enginesso/src/main/java/org/ovirt/engine'
    / 'core/sso/utils/LoginEnvelopeCrypto.java'
)


class LoginKeyRuntimeDecryptTest(unittest.TestCase):
    """The engine launcher decrypts the login private key to a private runtime file before Java
    starts and names it to Java, which reads it from there and removes nothing itself: the runtime
    directory is destroyed when the engine stops."""

    def setUp(self):
        self.launcher = LAUNCHER.read_text(encoding='utf-8')
        self.java = LOGIN_CRYPTO.read_text(encoding='utf-8')

    def test_launcher_decrypts_the_key_before_java_and_names_it(self):
        tree = ast.parse(self.launcher)
        method = next(
            node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == '_decryptLoginKey'
        )
        body = ast.get_source_segment(self.launcher, method)
        self.assertIn('login_key.py', self.launcher)
        self.assertIn("'--decrypt'", body)
        # A private runtime file, 0700 directory, under the temporary directory destroyed on stop.
        self.assertIn('0o700', body)
        self.assertIn('self._tempDir.directory', body)
        # A key that is not there is not a failure; a key that will not decrypt stops the start.
        self.assertIn('no login private key', body)
        self.assertIn('raise RuntimeError', body)

    def test_the_decrypted_key_is_named_to_java_as_a_system_property(self):
        self.assertIn(
            "LOGIN_KEY_PROPERTY = 'ovirt.engine.sso.login.key.path'", self.launcher)
        self.assertIn(
            "'-D%s=%s' % (self.LOGIN_KEY_PROPERTY, self._loginKeyPath)", self.launcher)
        # Set only when a key was decrypted; left unset the engine reads the on-disk key.
        self.assertIn('if self._loginKeyPath:', self.launcher)

    def test_the_decrypt_runs_after_the_runtime_directory_exists(self):
        self.assertLess(
            self.launcher.index('self._tempDir.create()'),
            self.launcher.index('self._decryptLoginKey()'),
        )

    def test_java_reads_the_runtime_path_then_falls_back_to_the_on_disk_key(self):
        self.assertIn(
            'ovirt.engine.sso.login.key.path', self.java)
        self.assertIn('System.getProperty(PRIVATE_KEY_PROPERTY)', self.java)
        self.assertIn(
            '/etc/ovirt-engine/encryptor/private_pkcs8.der', self.java)


if __name__ == '__main__':
    unittest.main()
