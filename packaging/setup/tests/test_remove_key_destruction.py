import ast
import os
import stat
import tempfile
import types
import unittest
from pathlib import Path


CONFIG = Path(__file__).parents[1] / 'plugins' / 'ovirt-engine-remove' / 'ovirt-engine' / 'config'


def methods(module, names, **namespace):
    """Methods of a plugin module, run without otopi, with the names they use."""
    tree = ast.parse((CONFIG / module).read_text(encoding='utf-8'))
    found = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in names:
            node.decorator_list = []
            scope = dict({'os': os, 'stat': stat, '_': lambda m: m}, **namespace)
            exec(compile(ast.Module(body=[node], type_ignores=[]), module, 'exec'), scope)
            found[node.name] = scope[node.name]
    return found


class FakeSyslog(object):
    LOG_PID = LOG_AUTHPRIV = LOG_NOTICE = LOG_ERR = LOG_WARNING = 0

    def __init__(self):
        self.messages = []

    def openlog(self, *a):
        pass

    def closelog(self):
        pass

    def syslog(self, priority, message):
        self.messages.append(message)


class Logger(object):
    def __init__(self):
        self.lines = []

    def __getattr__(self, name):
        return lambda *a, **k: self.lines.append((name, a))


class DecryptPluginTest(unittest.TestCase):
    """engine-cleanup decrypts in place; nothing it decrypted may be left in plain text."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.calls = []
        found = methods('decrypt.py', {
            '_magic', '_require_kek_passphrase', '_decrypt_config_file',
            '_reencrypt_leftovers', '_init', '_misc'})
        self.found = found

    def plugin(self, files, status_rc=0, decrypt_ok=True, encrypt_ok=True):
        calls = self.calls

        def execute(args, raiseOnError=False):
            calls.append(args)
            if '--status' in args:
                return status_rc, [], ['not loaded']
            path = Path(args[-1])
            if '--decrypt' in args:
                if decrypt_ok:
                    path.write_bytes(b'ENGINE_DB_PASSWORD="pw"\n')
                    return 0, [], []
                return 1, [], ['Authentication failed']
            if '--encrypt' in args:
                if encrypt_ok:
                    path.write_bytes(b'OVENC002' + bytes(40))
                    return 0, [], []
                return 1, [], ['KEK agent is not reachable']
            return 1, [], []

        plugin = types.SimpleNamespace(
            environment={'OVESETUP_REMOVE_ENCRYPTOR/decryptedFiles': [],
                         'OVESETUP_REMOVE/filesToRemove': set()},
            logger=Logger(), execute=execute,
            command=types.SimpleNamespace(
                detect=lambda n: None, get=lambda n, optional=False: None),
            _ENCRYPTOR_PATH=__file__, _KEK_AGENT_PATH=__file__,
            _ENCRYPTOR_CONFIG_PATH='/etc/ovirt-engine/encryptor/config.json',
            _DECRYPT_ALLOWED_FILES=files, _python=lambda: '/usr/bin/python3')
        for name, function in self.found.items():
            if name == '_magic':
                setattr(plugin, name, function)
            else:
                setattr(plugin, name, types.MethodType(function, plugin))
        return plugin

    def file(self, name, content):
        path = self.dir / name
        path.write_bytes(content)
        return str(path)

    def namespace(self):
        return {'DECRYPTED_FILES_ENV': 'OVESETUP_REMOVE_ENCRYPTOR/decryptedFiles',
                '_ENCRYPTED_MAGICS': (b'OVENC002', b'OVENC001', b'OVVLT001'),
                'osetupcons': types.SimpleNamespace(RemoveEnv=types.SimpleNamespace(
                    FILES_TO_REMOVE='OVESETUP_REMOVE/filesToRemove'))}

    def bind(self):
        # The module-level names the methods read.
        for function in self.found.values():
            function.__globals__.update(self.namespace())

    def test_a_passphrase_not_in_memory_stops_cleanup_before_anything_changes(self):
        self.bind()
        encrypted = self.file('10-setup-database.conf', b'OVENC002' + bytes(40))
        plugin = self.plugin([encrypted], status_rc=3)
        with self.assertRaisesRegex(RuntimeError, '--unlock'):
            plugin._init()
        self.assertEqual(b'OVENC002', Path(encrypted).read_bytes()[:8])
        self.assertFalse(any('--decrypt' in call for call in self.calls))

    def test_a_file_that_does_not_decrypt_stops_cleanup(self):
        self.bind()
        encrypted = self.file('internal.properties', b'OVENC002' + bytes(40))
        plugin = self.plugin([encrypted], decrypt_ok=False)
        with self.assertRaisesRegex(RuntimeError, 'Failed to decrypt'):
            plugin._init()

    def test_what_stays_on_disk_is_encrypted_again(self):
        # Answered No to removing the engine, or stopped half way.
        self.bind()
        encrypted = self.file('10-setup-database.conf', b'OVENC002' + bytes(40))
        plugin = self.plugin([encrypted])
        plugin._init()
        self.assertEqual(b'ENGINE_DB_PASSWORD="pw"\n', Path(encrypted).read_bytes())
        self.assertEqual([], plugin._reencrypt_leftovers())
        self.assertEqual(b'OVENC002', Path(encrypted).read_bytes()[:8])

    def test_a_file_that_cannot_be_encrypted_again_is_reported(self):
        self.bind()
        encrypted = self.file('10-setup-database.conf', b'OVENC002' + bytes(40))
        plugin = self.plugin([encrypted], encrypt_ok=False)
        plugin._init()
        self.assertEqual([encrypted], plugin._reencrypt_leftovers())
        self.assertIn('error', [name for name, _args in plugin.logger.lines])

    def test_passwords_decrypted_for_removal_are_overwritten_before_it(self):
        self.bind()
        encrypted = self.file('10-setup-database.conf', b'OVENC002' + bytes(40))
        plugin = self.plugin([encrypted])
        plugin._init()
        plugin.environment['OVESETUP_REMOVE/filesToRemove'] = {encrypted}
        plugin._misc()
        self.assertEqual(set(Path(encrypted).read_bytes()), {0})


class KeyDestructionTest(unittest.TestCase):

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.syslog = FakeSyslog()

    def test_every_pki_private_key_is_overwritten_and_removed_with_no_backup(self):
        keys = self.dir / 'keys'
        private = self.dir / 'private'
        keys.mkdir()
        private.mkdir()
        for path in (keys / 'apache.key.nopass', keys / 'engine.p12', private / 'ca.pem',
                     keys / 'enrolled-later.key'):
            path.write_bytes(b'-----BEGIN PRIVATE KEY-----')
        constants = types.SimpleNamespace(FileLocations=types.SimpleNamespace(
            OVIRT_ENGINE_PKIKEYSDIR=str(keys), OVIRT_ENGINE_PKIPRIVATEDIR=str(private)))
        found = methods('ca.py', {'_audit', '_destroy', '_key_files', '_misc'},
                        syslog=self.syslog, oenginecons=constants)
        plugin = types.SimpleNamespace(logger=Logger())
        plugin._audit = found['_audit']
        for name in ('_destroy', '_key_files', '_misc'):
            setattr(plugin, name, types.MethodType(found[name], plugin))
        plugin._misc()
        self.assertEqual([], list(keys.iterdir()) + list(private.iterdir()))
        self.assertEqual(4, sum('status=success' in m for m in self.syslog.messages))
        source = (CONFIG / 'ca.py').read_text(encoding='utf-8')
        self.assertNotIn('tarfile', source)       # no backup of the keys is made
        self.assertNotIn('engine-pki-', source)

    def test_the_dek_is_kept_while_anything_is_still_encrypted_under_it(self):
        found = methods('misc.py', {'_dek_still_needed'},
                        remove_decrypt=types.SimpleNamespace(
                            DECRYPTED_FILES_ENV='OVESETUP_REMOVE_ENCRYPTOR/decryptedFiles'),
                        importlib=__import__('importlib.util'))
        left = self.dir / '10-setup-dwh-database.conf'
        left.write_bytes(b'ENGINE_DB_PASSWORD="pw"\n')
        plugin = types.SimpleNamespace(
            environment={'OVESETUP_REMOVE_ENCRYPTOR/decryptedFiles': [str(left)]},
            logger=Logger(), _ENCRYPTOR_TOOL_PATH='/nonexistent',
            _ENCRYPTOR_CONFIG_PATH='/nonexistent')
        self.assertEqual([str(left)], found['_dek_still_needed'](plugin))
        left.unlink()
        self.assertEqual([], found['_dek_still_needed'](plugin))

    def test_closeup_keeps_the_dek_and_agent_for_what_stays_and_destroys_otherwise(self):
        source = (CONFIG / 'misc.py').read_text(encoding='utf-8')
        closeup = source[source.index('    def _closeup(self):'):]
        self.assertIn('needed = self._dek_still_needed()', closeup)
        self.assertIn('self._remove_stale_secrets(keep_dek=bool(needed))', closeup)
        self.assertIn("('systemctl', 'disable', '--now', self._KEK_AGENT_SERVICE)", source)
        self.assertIn('remove_decrypt.REENCRYPTED_EVENT', source)
        self.assertIn("'operation=key-destroy file=%s status=success' % path", source)

    def _destroy_source(self, module):
        source = (CONFIG / module).read_text(encoding='utf-8')
        destroy = source[source.index('    def _destroy(self, path):'):]
        return destroy[:destroy.index('\n    def ', 1)] if '\n    def ' in destroy[1:] else destroy

    def test_dek_and_login_key_files_are_zero_overwritten_three_times(self):
        """Security examiner guideline: the DEK and login key files are zero-overwritten three
        times, each flushed to the device, before being unlinked."""
        destroy = self._destroy_source('misc.py')
        self.assertIn('for _pass in range(3):', destroy)
        self.assertIn("stream.write(b'\\0' * info.st_size)", destroy)
        self.assertIn('stream.seek(0)', destroy)
        self.assertIn('stream.flush()', destroy)
        self.assertIn('os.fsync(stream.fileno())', destroy)

    def test_tls_private_keys_are_overwritten_with_zeros_and_ones_three_times(self):
        """Security examiner guideline: TLS/PKI private keys are overwritten three times
        alternating zeros and ones (0x00, 0xFF, 0x00), each flushed to the device."""
        destroy = self._destroy_source('ca.py')
        self.assertIn("for fill in (b'\\x00', b'\\xff', b'\\x00'):", destroy)
        self.assertIn('stream.write(fill * info.st_size)', destroy)
        self.assertIn('stream.seek(0)', destroy)
        self.assertIn('stream.flush()', destroy)
        self.assertIn('os.fsync(stream.fileno())', destroy)

    def test_the_tls_key_passes_write_both_zeros_and_ones_and_end_zeroed(self):
        """The three passes write 0x00 then 0xFF then 0x00: every byte of the file takes both the
        zero and the one pattern, and the file is left all zeros before removal."""
        found = methods('ca.py', {'_audit', '_destroy'}, syslog=self.syslog)
        plugin = types.SimpleNamespace(logger=Logger())
        plugin._audit = found['_audit']
        plugin._destroy = types.MethodType(found['_destroy'], plugin)
        key = self.dir / 'victim.key'
        key.write_bytes(b'-----BEGIN PRIVATE KEY-----sensitive-material')
        import os as _os
        real_unlink, real_fsync = _os.unlink, _os.fsync
        fills = []
        seen = {}

        def capture_fsync(fd):
            # Record the byte pattern written on each pass, before the next pass overwrites it.
            fills.append(set(Path(str(key)).read_bytes()))
            real_fsync(fd)

        def capture_unlink(path):
            seen['bytes'] = set(Path(path).read_bytes())
            real_unlink(path)
        _os.fsync, _os.unlink = capture_fsync, capture_unlink
        try:
            self.assertTrue(plugin._destroy(str(key)))
        finally:
            _os.fsync, _os.unlink = real_fsync, real_unlink
        self.assertEqual([{0x00}, {0xFF}, {0x00}], fills)   # 0, 1, 0 across three passes
        self.assertEqual({0}, seen['bytes'])                # left all zeros


class MemoryWipeTest(unittest.TestCase):
    """Secrets held as a bytearray are overwritten with zeros three times before release."""

    def test_wipe_overwrites_three_times(self):
        encryptor_src = (
            Path(__file__).parents[2] / 'encryptor' / 'encryptor.py'
        ).read_text(encoding='utf-8')
        self.assertIn('WIPE_PASSES = 3', encryptor_src)
        wipe = encryptor_src[encryptor_src.index('def wipe(buffer):'):]
        wipe = wipe[:wipe.index('\ndef ', 1)]
        self.assertIn('for _ in range(WIPE_PASSES):', wipe)
        # The passphrase from the environment or a prompt is held as a bytearray so it, too, is
        # reachable by wipe() (an immutable str/bytes could not be zeroed).
        self.assertIn('bytearray(environment_secret.encode("utf-8"))', encryptor_src)
        self.assertIn('bytearray(getpass.getpass', encryptor_src)


if __name__ == '__main__':
    unittest.main()
