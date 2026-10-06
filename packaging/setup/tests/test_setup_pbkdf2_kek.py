import ast
import base64
import os
import unittest
from pathlib import Path


CLIENT_CONTROL = (
    Path(__file__).parents[1] / 'plugins' / 'ovirt-engine-setup' /
    'ovirt-engine' / 'config' / 'client_control.py'
)


def setup_method(name):
    """A method of the setup plugin, run without otopi, with the module's own imports."""
    tree = ast.parse(CLIENT_CONTROL.read_text(encoding='utf-8'))
    method = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    namespace = {'os': os, 'base64': base64, '_': lambda message: message,
                 '_VAULT_PASSPHRASE_TOOL_PATH': __file__,
                 '_ENCRYPTOR_CONFIG_PATH': '/etc/ovirt-engine/encryptor/config.json'}
    exec(compile(ast.Module(body=[method], type_ignores=[]), str(CLIENT_CONTROL), 'exec'),
         namespace)
    return namespace[name]


class FakeEncryptor(object):
    KEK_PBKDF2_ITERATIONS = 600000
    KEK_MIN_PASSPHRASE = 16

    class EncryptorError(Exception):
        pass

    def __init__(self):
        self.provisioned = []
        self.written = []
        self.wiped = []
        self.salts = []

    def wipe(self, buffer):
        if buffer is not None:
            self.wiped.append(bytes(buffer))
            buffer[:] = bytearray(len(buffer))

    def check_kek_passphrase(self, passphrase):
        if len(passphrase) < 16:
            raise self.EncryptorError('too short')

    def new_kek_salt(self):
        return b'\x01' * 32

    def kek_derivation_record(self, salt, key_name):
        return {'kdf': 'PBKDF2-HMAC-SHA256', 'salt': 'AQ==', 'key_name': key_name,
                'verified': None, 'status': 'pending'}

    def provision_pbkdf2_kek(self, settings, token, passphrase, salt=None,
                             adopt_existing=False):
        self.provisioned.append((bytes(token), bytes(passphrase)))
        self.salts.append((bytes(salt) if salt is not None else None, adopt_existing))
        return {'kdf': 'PBKDF2-HMAC-SHA256', 'key_name': settings['key_name'],
                'verified': True, 'status': 'active'}

    def atomic_update_config(self, path, config):
        self.written.append(dict(config))


class FakePlugin(object):
    def __init__(self, answers, preflight_ok=False):
        self.answers = list(answers)
        self.asked = []
        self.encryptor = FakeEncryptor()
        self.preflight_ok = preflight_ok
        self.events = []
        self.logger = type('L', (), {
            'info': lambda *a: None, 'warning': lambda *a: None})()
        self.dialog = type('D', (), {'note': lambda *a, **k: None})()

    def _vault_preflight_succeeds(self):
        return self.preflight_ok

    def _load_encryptor(self):
        return self.encryptor

    def _query_secret(self, name, note):
        self.asked.append(name)
        return bytearray(self.answers.pop(0).encode())

    def _record_kek_event(self, event, error=None):
        self.events.append(event)


VAULT = {'vault_transit': {'enabled': True, 'key_name': 'ovirt-engine-config'}}


class SetupPbkdf2KekTest(unittest.TestCase):

    def setUp(self):
        self.method = setup_method('_ensure_pbkdf2_kek')

    def test_a_first_installation_asks_and_imports_a_derived_kek(self):
        plugin = FakePlugin(['admin-token', 'Initial-Data-2026!', 'Initial-Data-2026!'])
        config = {'vault_transit': dict(VAULT['vault_transit'])}
        self.method(plugin, config)
        self.assertEqual(
            ['OVESETUP_VAULT_KEK_IMPORT_TOKEN', 'OVESETUP_VAULT_KEK_PASSPHRASE',
             'OVESETUP_VAULT_KEK_PASSPHRASE_CONFIRM'], plugin.asked)
        self.assertEqual([(b'admin-token', b'Initial-Data-2026!')],
                         plugin.encryptor.provisioned)
        # The salt is recorded (pending) before the import, then the result (active).
        self.assertEqual(['pending', 'active'],
                         [w['kek_derivation']['status'] for w in plugin.encryptor.written])
        self.assertEqual('ovirt-engine-config',
                         plugin.encryptor.written[-1]['kek_derivation']['key_name'])
        self.assertEqual([(b'\x01' * 32, False)], plugin.encryptor.salts)
        self.assertEqual(['KEY_CREATED'], plugin.events)
        # Nothing secret is written; the secrets are overwritten after use.
        self.assertNotIn('Initial-Data', repr(plugin.encryptor.written))
        self.assertIn(b'admin-token', plugin.encryptor.wiped)
        self.assertIn(b'Initial-Data-2026!', plugin.encryptor.wiped)

    def test_a_mismatch_or_a_weak_passphrase_is_asked_again(self):
        plugin = FakePlugin(['admin-token', 'Initial-Data-2026!', 'different',
                             'short', 'short', 'Initial-Data-2026!', 'Initial-Data-2026!'])
        self.method(plugin, {'vault_transit': dict(VAULT['vault_transit'])})
        self.assertEqual(7, len(plugin.asked))
        self.assertEqual(1, len(plugin.encryptor.provisioned))

    def test_an_interrupted_import_is_finished_with_the_recorded_salt(self):
        plugin = FakePlugin(['admin-token', 'Initial-Data-2026!', 'Initial-Data-2026!'],
                            preflight_ok=True)
        salt = b'\x07' * 32
        config = dict(VAULT, kek_derivation={
            'kdf': 'PBKDF2-HMAC-SHA256', 'status': 'pending',
            'salt': base64.b64encode(salt).decode(), 'key_name': 'ovirt-engine-config'})
        self.method(plugin, config)
        self.assertEqual([(salt, True)], plugin.encryptor.salts)
        self.assertEqual(['active'],
                         [w['kek_derivation']['status'] for w in plugin.encryptor.written])

    def test_an_existing_kek_is_kept_and_nothing_is_asked(self):
        plugin = FakePlugin([], preflight_ok=True)
        self.method(plugin, {'vault_transit': dict(VAULT['vault_transit'])})
        self.assertEqual([], plugin.asked)
        self.assertEqual([], plugin.encryptor.provisioned)

    def test_a_recorded_derivation_is_not_redone(self):
        plugin = FakePlugin([])
        config = dict(VAULT, kek_derivation={'kdf': 'PBKDF2-HMAC-SHA256'})
        self.method(plugin, config)
        self.assertEqual([], plugin.asked)

    def test_an_installation_already_encrypted_is_never_asked(self):
        # Vault sealed during an upgrade fails the preflight; that is not a missing KEK.
        plugin = FakePlugin([], preflight_ok=False)
        self.method(plugin, dict(VAULT, active_format='OVVLT001'))
        self.assertEqual([], plugin.asked)

    def test_without_vault_nothing_happens(self):
        plugin = FakePlugin([])
        self.method(plugin, {'vault_transit': {'enabled': False}})
        self.method(plugin, {})
        self.assertEqual([], plugin.asked)

    def test_the_secrets_are_asked_never_taken_from_the_environment(self):
        source = CLIENT_CONTROL.read_text(encoding='utf-8')
        query = source[source.index('def _query_secret'):source.index('def _ensure_pbkdf2_kek')]
        self.assertIn('hidden=True', query)
        self.assertNotIn('self.environment', query)


if __name__ == '__main__':
    unittest.main()
