import ast
import unittest
from pathlib import Path


REMOVE_MISC = (
    Path(__file__).parents[1]
    / 'plugins'
    / 'ovirt-engine-remove'
    / 'ovirt-engine'
    / 'config'
    / 'misc.py'
)

EXPECTED_CONFIG = {
    'encrypt_flag': 'NO',
    'watch_path': [
        '/etc/ovirt-engine',
        '/etc/ovirt-engine-dwh',
    ],
    'allowed_files': [
        '10-setup-database.conf',
        '10-setup-dwh-database.conf',
        'internal.properties',
    ],
    'legacy_cbc': {
        'enabled': False,
    },
    'kek_agent': {
        'enabled': True,
        'socket': '/run/ovirt-engine-kek/agent.sock',
    },
}


class RemoveEncryptorConfigTest(unittest.TestCase):
    def test_cleanup_leaves_a_config_without_vault_or_passphrase_file(self):
        tree = ast.parse(REMOVE_MISC.read_text(encoding='utf-8'))
        plugin = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == 'Plugin'
        )
        assignment = next(
            node
            for node in plugin.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name)
                and target.id == '_ENCRYPTOR_CONFIG'
                for target in node.targets
            )
        )
        self.assertEqual(EXPECTED_CONFIG, ast.literal_eval(assignment.value))

    def test_cleanup_writes_config_atomically_as_mode_0600(self):
        source = REMOVE_MISC.read_text(encoding='utf-8')
        self.assertIn("tempfile.mkstemp(", source)
        self.assertIn("os.chmod(temporary_path, 0o600)", source)
        self.assertIn("os.replace(temporary_path, self._ENCRYPTOR_CONFIG_PATH)", source)

    def test_cleanup_removes_stale_secrets_and_forgets_the_passphrase(self):
        source = REMOVE_MISC.read_text(encoding='utf-8')
        self.assertIn("'/etc/ovirt-engine/encryptor/passphrase',", source)
        self.assertIn("'/etc/ovirt-engine/encryptor/vault-token',", source)
        self.assertIn("'/etc/ovirt-engine/encryptor/dek.enc',", source)
        self.assertIn("('systemctl', 'disable', '--now', self._KEK_AGENT_SERVICE)", source)
        self.assertIn("self._remove_stale_secrets(keep_dek=bool(needed))", source)
        self.assertIn("self._forget_kek_passphrase()", source)


if __name__ == '__main__':
    unittest.main()
