#
# Copyright 새올정보기술 (OV-Works), 2026
# SPDX-License-Identifier: Apache-2.0
#
import ast
import importlib
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).parents[3]
LAUNCHER = ROOT / 'packaging/services/ovirt-engine/ovirt-engine.py.in'
TOOL_DIR = ROOT / 'packaging/encryptor'
DEK_ENVELOPE = (
    ROOT / 'backend/manager/modules/uutils/src/main/java/org/ovirt/engine/core/uutils'
    / 'crypto/DekEnvelope.java'
)


def _method(source, name):
    tree = ast.parse(source.replace('@', ''))
    node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)
    return ast.get_source_segment(source.replace('@', ''), node)


class RuntimeDekLauncherTest(unittest.TestCase):
    """The launcher hands the engine the DEK for one run - a private runtime file named to Java -
    and destroys it when the engine stops: overwritten three times with zeros, then removed."""

    def setUp(self):
        self.launcher = LAUNCHER.read_text(encoding='utf-8')

    def test_the_dek_is_written_to_a_private_runtime_file_before_java_starts(self):
        body = _method(self.launcher, '_writeRuntimeDek')
        self.assertIn("'--write'", body)
        self.assertIn('0o700', body)
        self.assertIn('self._tempDir.directory', body)
        # No DEK configured: start without it. A DEK that does not open: stop the start.
        self.assertIn('RUNTIME_DEK_NO_DEK', body)
        self.assertIn('raise RuntimeError', body)
        self.assertLess(self.launcher.index('self._tempDir.create()'),
                        self.launcher.index('self._writeRuntimeDek()'))

    def test_the_runtime_dek_is_named_to_java(self):
        self.assertIn("RUNTIME_DEK_PROPERTY = 'ovirt.engine.dek.path'", self.launcher)
        self.assertIn("'-D%s=%s' % (self.RUNTIME_DEK_PROPERTY, self._runtimeDekPath)", self.launcher)
        java = DEK_ENVELOPE.read_text(encoding='utf-8')
        self.assertIn('DEK_PATH_PROPERTY = "ovirt.engine.dek.path"', java)

    def test_the_runtime_dek_is_destroyed_before_the_directory_that_holds_it(self):
        cleanup = _method(self.launcher, 'daemonCleanup')
        self.assertLess(cleanup.index('_destroyKeyFile(self._runtimeDekPath)'),
                        cleanup.index('self._tempDir.destroy()'))
        self.assertIn('KEY_DESTROY_PASSES = 3', self.launcher)

    def test_destroying_overwrites_with_zeros_three_times_then_removes(self):
        destroy = _method(self.launcher, '_destroyKeyFile')
        namespace = {'os': os}
        source = 'class Daemon:\n    KEY_DESTROY_PASSES = 3\n    @classmethod\n' + '\n'.join(
            '    ' + line if line else line for line in destroy.splitlines())
        exec(source, namespace)  # noqa: S102 - the launcher's own method, in isolation
        writes = []
        real_open = open

        def recording_open(path, mode='r', buffering=-1):
            stream = real_open(path, mode, buffering)
            original = stream.write

            def write(data):
                writes.append(bytes(data))
                return original(data)
            stream.write = write
            return stream

        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / 'dek'
            key.write_bytes(os.urandom(32))
            with mock.patch('builtins.open', recording_open):
                namespace['Daemon']._destroyKeyFile(str(key))
            self.assertFalse(key.exists())
        self.assertEqual([b'\0' * 32] * 3, writes)


class RuntimeDekToolTest(unittest.TestCase):
    """runtime_dek.py writes the 32-byte DEK, 0600, and wipes its own copy. The encryptor's
    cryptography is replaced: the tool only hands over what read_dek opens."""

    def setUp(self):
        fake = types.ModuleType('encryptor')
        fake.DEFAULT_CONFIG = Path('/etc/ovirt-engine/encryptor/config.json')
        fake.DATA_KEY_SIZE = 32
        fake.EncryptorError = type('EncryptorError', (RuntimeError,), {})
        self.dek = bytearray(os.urandom(32))
        self.wiped = []
        fake._load_crypto_config = lambda path: {'memory_kek': True}
        fake.memory_kek_settings = lambda config: {} if config.get('memory_kek') else None
        fake.obtain_passphrase = lambda config: bytearray(b'passphrase')
        fake.read_dek = lambda config, passphrase, source=None: bytearray(self.dek)

        def wipe(buffer):
            self.wiped.append(bytes(buffer))
            for i in range(len(buffer)):
                buffer[i] = 0
        fake.wipe = wipe

        def atomic_write(path, data, owner=None, mode=0o600):
            Path(path).write_bytes(data)
            os.chmod(str(path), mode)
        fake._atomic_write = atomic_write
        self.fake = fake
        patcher = mock.patch.dict(sys.modules, {'encryptor': fake})
        patcher.start()
        self.addCleanup(patcher.stop)
        sys.path.insert(0, str(TOOL_DIR))
        self.addCleanup(sys.path.remove, str(TOOL_DIR))
        sys.modules.pop('runtime_dek', None)
        self.tool = importlib.import_module('runtime_dek')

    def test_the_dek_is_written_private_and_the_tools_copy_wiped(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'dek'
            self.assertEqual(0, self.tool.main(['--write', str(out)]))
            self.assertEqual(bytes(self.dek), out.read_bytes())
            self.assertEqual(0o600, os.stat(out).st_mode & 0o777)
        self.assertIn(bytes(self.dek), self.wiped)
        self.assertIn(b'passphrase', self.wiped)

    def test_a_configuration_without_a_dek_is_reported_apart(self):
        self.fake._load_crypto_config = lambda path: {}
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(self.tool.EXIT_NO_DEK, self.tool.main(['--write', str(Path(directory) / 'dek')]))

    def test_a_dek_that_does_not_open_is_an_error(self):
        def fail(config, passphrase, source=None):
            raise self.fake.EncryptorError('Authentication failed')
        self.fake.read_dek = fail
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'dek'
            self.assertEqual(self.tool.EXIT_ERROR, self.tool.main(['--write', str(out)]))
            self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main()
