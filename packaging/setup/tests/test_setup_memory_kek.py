import ast
import os
import tempfile
import unittest
from pathlib import Path


CLIENT_CONTROL = (
    Path(__file__).parents[1] / 'plugins' / 'ovirt-engine-setup' /
    'ovirt-engine' / 'config' / 'client_control.py'
)


def setup_method(name, **names):
    """A method of the setup plugin, run without otopi, with the module's own imports."""
    tree = ast.parse(CLIENT_CONTROL.read_text(encoding='utf-8'))
    method = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    namespace = dict({
        'os': os, '_': lambda message: message,
        '_KEK_AGENT_SERVICE': 'ovirt-engine-kek-agent.service',
        '_KEK_AGENT_TOOL_PATH': __file__,
        '_ENCRYPTOR_SECRET_FILE': '/nonexistent/passphrase',
    }, **names)
    exec(compile(ast.Module(body=[method], type_ignores=[]), str(CLIENT_CONTROL), 'exec'),
         namespace)
    return namespace[name]


class FakeEncryptor(object):
    PBKDF2_ITERATIONS = 600000
    MEMORY_MIN_PASSPHRASE = 4
    MEMORY_KEK_SOCKET = '/run/ovirt-engine-kek/agent.sock'

    class EncryptorError(Exception):
        pass

    def __init__(self, loaded=False, file_passphrase=None):
        self.loaded = loaded
        self.file_passphrase = file_passphrase
        self.held = []
        self.wiped = []

    def wipe(self, buffer):
        if buffer is not None:
            self.wiped.append(bytes(buffer))
            buffer[:] = bytearray(len(buffer))

    def check_memory_passphrase(self, passphrase):
        if len(passphrase) < 4:
            raise self.EncryptorError('KEK passphrase must be 4 to 256 characters')

    def memory_passphrase_loaded(self, socket_path):
        return self.loaded

    def load_memory_passphrase(self, socket_path, passphrase):
        self.held.append(bytes(passphrase))

    def decrypt_gcm_bytes(self, data, passphrase):
        if bytes(passphrase) != self.file_passphrase:
            raise self.EncryptorError('Authentication failed: the key is wrong')
        return b''


class FakePlugin(object):
    def __init__(self, answers, encryptor, files=()):
        self.answers = list(answers)
        self.asked = []
        self.encryptor = encryptor
        self.files = list(files)
        self.events = []
        self.started = []
        self.logger = type('L', (), {
            'info': lambda *a: None, 'warning': lambda *a: None})()
        self.dialog = type('D', (), {'note': lambda *a, **k: None})()

    def _load_encryptor(self):
        return self.encryptor

    def _start_kek_agent(self):
        self.started.append(True)

    def _database_credential_files(self):
        return self.files

    def _is_encrypted_file(self, path):
        with open(path, 'rb') as stream:
            return stream.read(8) in (b'OVENC001', b'OVVLT001')

    def _query_secret(self, name, note):
        self.asked.append(name)
        return bytearray(self.answers.pop(0).encode())

    def _record_kek_event(self, event, error=None):
        self.events.append((event, str(error) if error else None))


class SetupMemoryKekTest(unittest.TestCase):

    def setUp(self):
        self.ensure = setup_method('_ensure_memory_kek')
        self.uses = setup_method('_uses_memory_kek')

    def test_a_first_installation_asks_twice_and_holds_it_in_memory(self):
        encryptor = FakeEncryptor()
        plugin = FakePlugin(['ab12', 'ab12'], encryptor)
        self.ensure(plugin, {})
        self.assertEqual(['OVESETUP_KEK_PASSPHRASE', 'OVESETUP_KEK_PASSPHRASE_CONFIRM'],
                         plugin.asked)
        self.assertEqual([b'ab12'], encryptor.held)
        self.assertEqual([('KEY_CREATED', None)], plugin.events)
        self.assertIn(b'ab12', encryptor.wiped)
        self.assertEqual([True], plugin.started)

    def test_a_short_or_mismatched_passphrase_is_recorded_and_asked_again(self):
        encryptor = FakeEncryptor()
        plugin = FakePlugin(['abc', 'ab12', 'ab13', 'ab12', 'ab12'], encryptor)
        self.ensure(plugin, {})
        self.assertEqual([b'ab12'], encryptor.held)
        self.assertEqual(
            ['KEY_CREATION_FAILED', 'KEY_CREATION_FAILED', 'KEY_CREATED'],
            [event for event, _error in plugin.events])

    def test_three_failures_stop_setup(self):
        encryptor = FakeEncryptor()
        plugin = FakePlugin(['a', 'b', 'c'], encryptor)
        with self.assertRaises(RuntimeError):
            self.ensure(plugin, {})
        self.assertEqual([], encryptor.held)
        self.assertEqual(3, len(plugin.events))

    def test_an_encrypted_installation_checks_the_passphrase_against_its_file(self):
        encrypted = tempfile.NamedTemporaryFile(delete=False)
        encrypted.write(b'OVENC001' + bytes(80))
        encrypted.close()
        self.addCleanup(os.unlink, encrypted.name)
        encryptor = FakeEncryptor(file_passphrase=b'ab12')
        plugin = FakePlugin(['wxyz', 'ab12'], encryptor, files=[encrypted.name])
        self.ensure(plugin, {})
        self.assertEqual(['OVESETUP_KEK_PASSPHRASE'] * 2, plugin.asked)
        self.assertEqual([b'ab12'], encryptor.held)
        self.assertEqual('KEY_CREATION_FAILED', plugin.events[0][0])
        self.assertIn('Authentication failed', plugin.events[0][1])

    def test_a_passphrase_already_in_memory_is_not_asked_again(self):
        plugin = FakePlugin([], FakeEncryptor(loaded=True))
        self.ensure(plugin, {})
        self.assertEqual([], plugin.asked)
        self.assertEqual([], plugin.events)

    def test_which_installations_hold_the_passphrase_in_memory(self):
        plugin = FakePlugin([], FakeEncryptor())
        self.assertTrue(self.uses(plugin, {}))     # first installation, no Vault
        self.assertTrue(self.uses(plugin, {'kek_agent': {'enabled': True}}))
        self.assertFalse(self.uses(plugin, {'kek_agent': {'enabled': False}}))
        self.assertFalse(self.uses(plugin, {'vault_transit': {'enabled': True},
                                            'kek_agent': {'enabled': True}}))
        # An existing installation with a passphrase file keeps it until --migrate.
        self.assertFalse(self.uses(plugin, {'secret_file': __file__}))
        encrypted = tempfile.NamedTemporaryFile(delete=False)
        encrypted.write(b'OVENC001')
        encrypted.close()
        self.addCleanup(os.unlink, encrypted.name)
        plugin.files = [encrypted.name]
        self.assertFalse(self.uses(plugin, {}))

    def test_the_passphrase_is_asked_never_taken_from_the_environment(self):
        source = CLIENT_CONTROL.read_text(encoding='utf-8')
        method = source[source.index('def _ensure_memory_kek'):
                        source.index('def _record_kek_event')]
        self.assertNotIn('self.environment', method)
        self.assertNotIn('atomic_update_config', method)   # nothing of it is written


if __name__ == '__main__':
    unittest.main()
