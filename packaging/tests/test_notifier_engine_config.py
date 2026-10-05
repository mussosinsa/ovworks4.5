import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / 'packaging/pythonlib'))

from ovirt_engine import configfile  # noqa: E402

NOTIFIER = ROOT / 'packaging/services/ovirt-engine-notifier/ovirt-engine-notifier.py.in'


class EncryptedFilesTest(unittest.TestCase):
    """The notifier is a Java process, and the Java loader skips encrypted files."""

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp())
        self.vars = self.directory / 'engine.conf'
        self.vars.write_text('ENGINE_FQDN=engine.example\n')
        (self.directory / 'engine.conf.d').mkdir()

    def test_finds_the_encrypted_database_settings(self):
        db = self.directory / 'engine.conf.d' / '10-setup-database.conf'
        db.write_bytes(b'OVVLT001' + b'ciphertext')
        self.assertEqual([str(db)], configfile.encrypted_files([str(self.vars)]))

    def test_plain_settings_are_not_encrypted(self):
        (self.directory / 'engine.conf.d' / '10-setup-database.conf').write_text(
            'ENGINE_DB_PASSWORD="secret"\n')
        self.assertEqual([], configfile.encrypted_files([str(self.vars)]))

    def test_only_the_files_that_are_ever_encrypted_count(self):
        (self.directory / 'engine.conf.d' / '99-other.conf').write_bytes(b'OVVLT001x')
        self.assertEqual([], configfile.encrypted_files([str(self.vars)]))


class WriteShellConfigTest(unittest.TestCase):

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp())
        self.path = self.directory / 'engine.conf'

    def test_values_read_back_exactly(self):
        values = {
            'ENGINE_DB_PASSWORD': 'p@ss "w$rd" \\ # with spaces',
            'ENGINE_DB_URL': 'jdbc:postgresql://localhost:5432/engine?sslfactory=x',
            'SENSITIVE_KEYS': ',ENGINE_DB_PASSWORD',
            'EMPTY': '',
        }
        configfile.write_shell_config(values, str(self.path))
        read = configfile.ConfigFile([str(self.path)])
        for key, value in values.items():
            self.assertEqual(value, read.get(key), key)

    def test_the_file_is_private_and_never_overwritten(self):
        configfile.write_shell_config({'A': 'b'}, str(self.path))
        self.assertEqual(0o600, stat.S_IMODE(os.stat(self.path).st_mode))
        with self.assertRaises(FileExistsError):
            configfile.write_shell_config({'A': 'b'}, str(self.path))

    def test_values_spanning_lines_are_left_out(self):
        configfile.write_shell_config({'A': 'x\ny', 'B': 'z'}, str(self.path))
        self.assertEqual('B="z"\n', self.path.read_text())

    def test_decrypted_values_reach_the_file(self):
        db = self.directory / 'engine.conf.d'
        db.mkdir()
        vars_file = self.directory / 'source.conf'
        vars_file.write_text('ENGINE_DB_USER=engine\n')
        (self.directory / 'source.conf.d').mkdir()
        encrypted = self.directory / 'source.conf.d' / '10-setup-database.conf'
        encrypted.write_bytes(b'OVVLT001ciphertext')
        with mock.patch.object(configfile.ConfigFile, '_decrypt',
                               return_value=b'ENGINE_DB_PASSWORD="s3cr\\$t"\n'):
            merged = configfile.ConfigFile([str(vars_file)])
        configfile.write_shell_config(merged.values, str(self.path))
        self.assertEqual('s3cr$t', configfile.ConfigFile([str(self.path)]).get('ENGINE_DB_PASSWORD'))


class NotifierStartTest(unittest.TestCase):

    def test_the_java_notifier_gets_the_decrypted_configuration(self):
        script = NOTIFIER.read_text()
        self.assertIn("'ENGINE_VARS': self._engineVarsForJava(),", script)
        self.assertIn('configfile.encrypted_files(engineFiles)', script)
        self.assertIn('configfile.write_shell_config(engineConfig.values, engineVars)', script)
        # Removed when the notifier stops, and when it fails to start.
        self.assertIn('def daemonCleanup(self):', script)
        self.assertIn('self.daemonCleanup()\n            raise', script)


if __name__ == '__main__':
    unittest.main()
