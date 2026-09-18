import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / 'packaging/pythonlib'))

from ovirt_engine import cryptoevents  # noqa: E402

ENCRYPT_CONF_FILES = ROOT / 'packaging/encryptor/encrypt_conf_files.py'
VAULT_PASSPHRASE = ROOT / 'packaging/encryptor/vault_passphrase.py'


class EncryptorToolCryptoEventsTest(unittest.TestCase):
    """Key creation and file encryption run from engine-setup, with no engine to record them.

    The tools cannot be imported here - the container's cryptography module cannot be loaded -
    so the wiring is read from the source. The behaviour of what it calls is covered by
    test_crypto_events.
    """

    def setUp(self):
        self.encrypt_conf_files = ENCRYPT_CONF_FILES.read_text(encoding='utf-8')
        self.vault_passphrase = VAULT_PASSPHRASE.read_text(encoding='utf-8')

    def test_the_key_encryption_key_being_created_is_recorded(self):
        # Vault generates it and keeps it; it never leaves Vault, so this is the only record on
        # this host that it was asked for.
        self.assertIn('client.ensure_key()', self.vault_passphrase)
        self.assertIn('_record("KEY_CREATED")', self.vault_passphrase)
        self.assertIn('_record("KEY_CREATION_FAILED", error)', self.vault_passphrase)

    def test_each_file_getting_a_data_key_is_recorded_as_its_own_event(self):
        # A summary alone would show a run that encrypted nine of ten files as a run that
        # failed, and would not say which one it was.
        self.assertIn(
            '_record("ENCRYPTION_COMPLETED", file=path.name, scheme=scheme)',
            self.encrypt_conf_files,
        )
        self.assertIn(
            '_record("ENCRYPTION_FAILED", error, file=path.name, scheme=scheme)',
            self.encrypt_conf_files,
        )
        # And the run still stops where it stopped.
        self.assertIn('                raise\n', self.encrypt_conf_files)

    def test_the_tools_still_work_without_the_engines_python_library(self):
        for source in (self.encrypt_conf_files, self.vault_passphrase):
            self.assertIn('except ImportError:', source)
            self.assertIn('cryptoevents = None', source)
            self.assertIn('if cryptoevents is None:\n        return', source)

    def test_the_event_names_the_tools_use_are_ones_that_exist(self):
        used = set()
        for source in (self.encrypt_conf_files, self.vault_passphrase):
            for line in source.splitlines():
                if '_record("' in line:
                    used.add(line.split('_record("', 1)[1].split('"', 1)[0])

        self.assertTrue(used)
        for name in used:
            self.assertTrue(hasattr(cryptoevents, name), name)
            self.assertIn(getattr(cryptoevents, name), cryptoevents.EVENTS)

    def test_a_source_name_is_one_the_engine_will_accept(self):
        # CryptoEvent rejects an entry whose source is not [A-Za-z0-9._-]{1,64}.
        for source, expected in (
            (self.encrypt_conf_files, 'encrypt-conf-files'),
            (self.vault_passphrase, 'vault-passphrase'),
        ):
            self.assertIn('_EVENT_SOURCE = "%s"' % expected, source)
            self.assertLessEqual(len(expected), 64)
            self.assertTrue(all(c.isalnum() or c in '._-' for c in expected))

    def test_a_spool_that_cannot_be_written_does_not_stop_the_tool(self):
        with mock.patch.object(cryptoevents, 'SPOOL_DIR', '/proc/nowhere'):
            self.assertIsNone(
                cryptoevents.record(cryptoevents.KEY_CREATED, 'vault-passphrase')
            )

    def test_what_a_tool_writes_is_what_the_engine_reads(self):
        spool = tempfile.mkdtemp()
        path = cryptoevents.record(
            cryptoevents.KEY_CREATED, 'vault-passphrase', spool_dir=spool,
        )

        with open(path, encoding='utf-8') as stream:
            entry = json.load(stream)
        # No file: a key-encryption key is not a file, and CryptoEvent only insists on one for
        # the events that are about a file.
        self.assertNotIn('file', entry)
        self.assertEqual('CRYPTO_KEY_CREATED', entry['event'])
        self.assertEqual(0o600, os.stat(path).st_mode & 0o777)


if __name__ == '__main__':
    unittest.main()
