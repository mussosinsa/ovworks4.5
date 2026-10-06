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
        '_KEK_AGENT_UNIT_PATH': __file__,
        '_ENCRYPTOR_SECRET_FILE': '/nonexistent/passphrase',
    }, **names)
    exec(compile(ast.Module(body=[method], type_ignores=[]), str(CLIENT_CONTROL), 'exec'),
         namespace)
    return namespace[name]


class FakeEncryptor(object):
    PBKDF2_ITERATIONS = 600000
    MEMORY_MIN_PASSPHRASE = 6
    MEMORY_KEK_SOCKET = '/run/ovirt-engine-kek/agent.sock'

    class EncryptorError(Exception):
        pass

    def __init__(self, loaded=False, file_passphrase=None, dek_file='/nonexistent/dek.enc'):
        self.dek_file = dek_file
        self.loaded = loaded
        self.file_passphrase = file_passphrase
        self.held = []
        self.wiped = []

    def wipe(self, buffer):
        if buffer is not None:
            self.wiped.append(bytes(buffer))
            buffer[:] = bytearray(len(buffer))

    def check_memory_passphrase(self, passphrase):
        if len(passphrase) < 6:
            raise self.EncryptorError('KEK passphrase must be 6 to 256 characters')

    def memory_passphrase_loaded(self, socket_path):
        return self.loaded

    def load_memory_passphrase(self, socket_path, passphrase):
        self.held.append(bytes(passphrase))

    def dek_file_path(self, config):
        return self.dek_file

    def read_dek(self, config, passphrase):
        if bytes(passphrase) != self.file_passphrase:
            raise self.EncryptorError(
                'Authentication failed: the DEK file does not open with this KEK passphrase')
        return bytearray(32)

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

    def _passphrase_check(self, encryptor, config):
        return setup_method('_passphrase_check')(self, encryptor, config)

    def _wait_for_kek_agent(self, encryptor, socket_path):
        return encryptor.memory_passphrase_loaded(socket_path)

    def _start_kek_agent(self):
        self.started.append(True)

    def _database_credential_files(self):
        return self.files

    def _credential_file_magics(self):
        magics = set()
        for path in self.files:
            with open(path, 'rb') as stream:
                magics.add(stream.read(8))
        return magics

    def _is_encrypted_file(self, path):
        with open(path, 'rb') as stream:
            return stream.read(8) in (b'OVENC002', b'OVENC001', b'OVVLT001')

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
        plugin = FakePlugin(['ab12cd', 'ab12cd'], encryptor)
        self.ensure(plugin, {})
        self.assertEqual(['OVESETUP_KEK_PASSPHRASE', 'OVESETUP_KEK_PASSPHRASE_CONFIRM'],
                         plugin.asked)
        self.assertEqual([b'ab12cd'], encryptor.held)
        self.assertEqual([('KEY_CREATED', None)], plugin.events)
        self.assertIn(b'ab12cd', encryptor.wiped)
        self.assertEqual([True], plugin.started)

    def test_a_short_or_mismatched_passphrase_is_recorded_and_asked_again(self):
        encryptor = FakeEncryptor()
        plugin = FakePlugin(['abcde', 'ab12cd', 'ab13cd', 'ab12cd', 'ab12cd'], encryptor)
        self.ensure(plugin, {})
        self.assertEqual([b'ab12cd'], encryptor.held)
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
        encryptor = FakeEncryptor(file_passphrase=b'ab12cd')
        plugin = FakePlugin(['wxyzuv', 'ab12cd'], encryptor, files=[encrypted.name])
        self.ensure(plugin, {})
        self.assertEqual(['OVESETUP_KEK_PASSPHRASE'] * 2, plugin.asked)
        self.assertEqual([b'ab12cd'], encryptor.held)
        self.assertEqual('KEY_CREATION_FAILED', plugin.events[0][0])
        self.assertIn('Authentication failed', plugin.events[0][1])

    def _file(self, content):
        handle = tempfile.NamedTemporaryFile(delete=False)
        handle.write(content)
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_the_passphrase_is_checked_against_the_dek_file(self):
        encrypted = self._file(b'OVENC002' + bytes(80))
        dek = self._file(b'OVDEK001' + bytes(80))
        encryptor = FakeEncryptor(file_passphrase=b'ab12cd', dek_file=dek)
        plugin = FakePlugin(['wxyzuv', 'ab12cd'], encryptor, files=[encrypted])
        self.ensure(plugin, {})
        self.assertEqual(['OVESETUP_KEK_PASSPHRASE'] * 2, plugin.asked)
        self.assertEqual([b'ab12cd'], encryptor.held)
        self.assertIn('DEK file does not open', plugin.events[0][1])

    def test_a_passphrase_already_in_memory_for_encrypted_files_is_not_asked_again(self):
        encrypted = self._file(b'OVENC001' + bytes(80))
        plugin = FakePlugin([], FakeEncryptor(loaded=True), files=[encrypted])
        self.ensure(plugin, {})
        self.assertEqual([], plugin.asked)
        self.assertEqual([], plugin.events)

    def test_a_new_installation_asks_even_if_an_old_passphrase_is_still_in_memory(self):
        encryptor = FakeEncryptor(loaded=True)
        plugin = FakePlugin(['ab12cd', 'ab12cd'], encryptor)
        self.ensure(plugin, {})
        self.assertEqual([b'ab12cd'], encryptor.held)

    def test_which_installations_hold_the_passphrase_in_memory(self):
        plugin = FakePlugin([], FakeEncryptor())
        self.assertTrue(self.uses(plugin, {}))     # first installation
        # What engine-cleanup used to leave behind: Vault on, a passphrase file named.
        stale = {'secret_file': __file__,
                 'vault_transit': {'enabled': True, 'token_file': '/nonexistent'}}
        self.assertTrue(self.uses(plugin, stale))
        plain = self._file(b'ENGINE_DB_PASSWORD="x"\n')
        plugin.files = [plain]
        self.assertTrue(self.uses(plugin, stale))
        # Encrypted under a passphrase file that is still there: kept until --migrate.
        plugin.files = [self._file(b'OVENC001' + bytes(8))]
        self.assertFalse(self.uses(plugin, {'secret_file': __file__}))
        self.assertTrue(self.uses(plugin, {}))     # no file: the passphrase was in memory
        self.assertTrue(self.uses(plugin, {'secret_file': __file__,
                                           'kek_agent': {'enabled': True}}))

    def test_a_missing_kek_agent_stops_setup_before_anything_changes(self):
        # Skipping the question here only moved the failure to closeup, where the
        # files could not be encrypted because nothing held the passphrase.
        plugin = FakePlugin([], FakeEncryptor())
        for missing in ('_KEK_AGENT_TOOL_PATH', '_KEK_AGENT_UNIT_PATH'):
            uses = setup_method('_uses_memory_kek', **{missing: '/nonexistent/kek'})
            with self.assertRaisesRegex(RuntimeError, '/nonexistent/kek'):
                uses(plugin, {'kek_agent': {'enabled': True}})
        # A passphrase-file installation does not need it.
        uses = setup_method('_uses_memory_kek', _KEK_AGENT_TOOL_PATH='/nonexistent/kek')
        plugin.files = [self._file(b'OVENC001' + bytes(8))]
        self.assertFalse(uses(plugin, {'secret_file': __file__}))

    def test_files_still_encrypted_by_vault_must_be_moved_first(self):
        plugin = FakePlugin([], FakeEncryptor(), files=[self._file(b'OVVLT001' + bytes(8))])
        with self.assertRaisesRegex(RuntimeError, '--migrate'):
            self.uses(plugin, {})

    def test_setup_waits_for_the_agent_socket_to_appear(self):
        import time
        wait = setup_method('_wait_for_kek_agent', time=time)
        encryptor = FakeEncryptor(loaded=True)
        calls = []

        def loaded(socket_path):
            calls.append(socket_path)
            if len(calls) < 3:
                raise encryptor.EncryptorError('KEK agent is not reachable')
            return True
        encryptor.memory_passphrase_loaded = loaded
        self.assertTrue(wait(FakePlugin([], encryptor), encryptor, '/run/x', timeout=5))
        self.assertEqual(3, len(calls))
        encryptor.memory_passphrase_loaded = lambda path: (_ for _ in ()).throw(
            encryptor.EncryptorError('KEK agent is not reachable'))
        with self.assertRaisesRegex(encryptor.EncryptorError, 'journalctl -u'):
            wait(FakePlugin([], encryptor), encryptor, '/run/x', timeout=0)

    def test_the_questions_come_after_the_engine_is_enabled(self):
        # Before CORE_ENABLE asks, CoreEnv.ENABLE is None: the condition was false and
        # a new installation never saw the passphrase question, then failed at closeup.
        tree = ast.parse(CLIENT_CONTROL.read_text(encoding='utf-8'))
        method = next(node for node in ast.walk(tree)
                      if isinstance(node, ast.FunctionDef) and node.name == '_customization')
        event = ast.unparse(method.decorator_list[0])
        self.assertIn('STAGE_CUSTOMIZATION', event)
        self.assertIn('after=(oenginecons.Stages.CORE_ENABLE,)', event)
        closeup = ast.unparse(next(
            node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == '_closeup'))
        self.assertIn('if not self._customized:', closeup)

    def test_the_passphrase_is_asked_never_taken_from_the_environment(self):
        source = CLIENT_CONTROL.read_text(encoding='utf-8')
        method = source[source.index('def _ensure_memory_kek'):
                        source.index('def _record_kek_event')]
        self.assertNotIn('self.environment', method)
        self.assertNotIn('atomic_update_config', method)   # nothing of it is written


if __name__ == '__main__':
    unittest.main()
