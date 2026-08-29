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
    'secret_file': '/etc/ovirt-engine/encryptor/passphrase',
    'legacy_cbc': {
        'enabled': False,
    },
    'vault_transit': {
        'enabled': True,
        'address': 'https://127.0.0.1:8200',
        'mount': 'transit',
        'key_name': 'ovirt-engine-config',
        'token_file': '/etc/ovirt-engine/encryptor/vault-token',
        'ca_cert': '/etc/pki/ca-trust/source/anchors/vault-ca.pem',
        'timeout': 5,
    },
}


class RemoveEncryptorConfigTest(unittest.TestCase):
    def test_cleanup_restores_vault_ready_config(self):
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


if __name__ == '__main__':
    unittest.main()
