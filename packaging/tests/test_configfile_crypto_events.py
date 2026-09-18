import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / 'packaging/pythonlib'))

from ovirt_engine import configfile  # noqa: E402
from ovirt_engine import cryptoevents  # noqa: E402


class ConfigFileCryptoEventsTest(unittest.TestCase):
    """What the engine's own start did with the encrypted configuration.

    It happens before the Java daemon exists, so nothing inside the engine can record it.
    """

    def setUp(self):
        self.spool = tempfile.mkdtemp()
        self.directory = tempfile.mkdtemp()
        self.file = os.path.join(self.directory, '10-setup-database.conf')
        with open(self.file, 'wb') as stream:
            stream.write(b'OVENC001' + b'ciphertext')

        patch = mock.patch.object(cryptoevents, 'SPOOL_DIR', self.spool)
        patch.start()
        self.addCleanup(patch.stop)

    def _entries(self):
        entries = []
        for name in sorted(os.listdir(self.spool)):
            with open(os.path.join(self.spool, name), encoding='utf-8') as stream:
                entries.append(json.load(stream))
        return entries

    def _load(self, source, decrypt):
        config = configfile.ConfigFile(cryptoEventSource=source)
        with mock.patch.object(configfile.ConfigFile, '_decrypt', decrypt):
            return config._loadFileContent(self.file)

    def test_records_a_decryption_that_worked(self):
        self._load('engine-start', lambda self, f, c: b'KEY=value\n')

        entry, = self._entries()
        self.assertEqual('CONFIG_FILE_DECRYPTION_COMPLETED', entry['event'])
        self.assertEqual('10-setup-database.conf', entry['file'])
        self.assertEqual('OVENC001', entry['scheme'])
        self.assertEqual('engine-start', entry['source'])
        self.assertNotIn('reason', entry)

    def test_records_a_decryption_that_did_not_and_still_fails_the_start(self):
        def boom(self, f, c):
            raise RuntimeError('Authentication failed: file is damaged or modified')

        with self.assertRaises(RuntimeError):
            self._load('engine-start', boom)

        entry, = self._entries()
        self.assertEqual('CONFIG_FILE_DECRYPTION_FAILED', entry['event'])
        self.assertEqual('AUTHENTICATION_FAILED', entry['reason'])

    def test_names_the_envelope_and_not_the_plaintext(self):
        # The scheme is read from the file as it was on disk. Taking it from the variable the
        # plaintext was assigned to would name whatever the first eight bytes of the decrypted
        # configuration happen to be.
        self._load('engine-start', lambda self, f, c: b'OVVLT001 not really\n')

        entry, = self._entries()
        self.assertEqual('OVENC001', entry['scheme'])

    def test_a_tool_that_does_not_say_who_it_is_records_nothing(self):
        # This reader is used by every tool that loads the engine's configuration. An event per
        # tool per invocation would say nothing about the engine's own start.
        self._load(None, lambda self, f, c: b'KEY=value\n')

        self.assertEqual([], self._entries())

    def test_a_plain_configuration_file_is_not_an_event(self):
        plain = os.path.join(self.directory, 'plain.conf')
        with open(plain, 'w', encoding='utf-8') as stream:
            stream.write('KEY=value\n')

        config = configfile.ConfigFile(cryptoEventSource='engine-start')
        self.assertEqual('KEY=value\n', config._loadFileContent(plain))
        self.assertEqual([], self._entries())

    def test_a_spool_that_cannot_be_written_does_not_change_the_outcome(self):
        with mock.patch.object(cryptoevents, 'SPOOL_DIR', '/proc/nowhere'):
            self.assertEqual(
                'KEY=value\n',
                self._load('engine-start', lambda self, f, c: b'KEY=value\n'),
            )


if __name__ == '__main__':
    unittest.main()
