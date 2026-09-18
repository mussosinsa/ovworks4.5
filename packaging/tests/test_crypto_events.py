import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / 'packaging/pythonlib'))

from ovirt_engine import cryptoevents  # noqa: E402


class CryptoEventsTest(unittest.TestCase):
    """What is written here is read by the engine and shown to whoever reads the audit log.

    Nothing in it may carry a secret: several of the encryptor's own messages name a filesystem
    path, and a path says where the installation keeps its keys.
    """

    def setUp(self):
        self.spool = tempfile.mkdtemp()

    def _record(self, *args, **kwargs):
        kwargs.setdefault('spool_dir', self.spool)
        path = cryptoevents.record(*args, **kwargs)
        self.assertIsNotNone(path)
        with open(path, encoding='utf-8') as stream:
            return path, json.load(stream)

    def test_records_what_happened_and_nothing_else(self):
        path, entry = self._record(
            cryptoevents.DECRYPTION_FAILED,
            'engine-start',
            file='/etc/ovirt-engine/engine.conf.d/10-setup-database.conf',
            scheme='OVENC001',
            reason=cryptoevents.REASON_AUTHENTICATION_FAILED,
        )

        self.assertEqual('10-setup-database.conf', entry['file'])
        self.assertEqual('AUTHENTICATION_FAILED', entry['reason'])
        self.assertEqual('engine-start', entry['source'])
        self.assertEqual(1, entry['version'])
        # The directory the file came from is not in it.
        self.assertNotIn('/etc/', json.dumps(entry))
        self.assertEqual(0o600, os.stat(path).st_mode & 0o777)

    def test_a_reason_is_a_code_and_never_the_message_it_came_from(self):
        # "Vault CA certificate is missing: /etc/pki/..." and half a dozen others name a path.
        for message, expected in (
            ('Vault CA certificate is missing: /etc/pki/ovirt-engine/vault-ca.pem',
             cryptoevents.REASON_VAULT_UNAVAILABLE),
            ('Refusing group/other-writable file: /etc/ovirt-engine/encryptor/passphrase',
             cryptoevents.REASON_PATH_REJECTED),
            ('Path is outside approved oVirt directories: /home/someone/key',
             cryptoevents.REASON_PATH_REJECTED),
            ('Symbolic links are not allowed: /var/lib/ovirt-engine/link',
             cryptoevents.REASON_PATH_REJECTED),
            ('Authentication failed: file is damaged, modified, or the key is wrong',
             cryptoevents.REASON_AUTHENTICATION_FAILED),
            ('Vault Transit connection failed', cryptoevents.REASON_VAULT_UNAVAILABLE),
            ('Encrypted file is truncated', cryptoevents.REASON_FILE_DAMAGED),
            ('Passphrase file is empty', cryptoevents.REASON_PASSPHRASE_UNAVAILABLE),
            ('Encryptor tool is missing: /usr/share/ovirt-engine/encryptor/encryptor.py',
             cryptoevents.REASON_ENCRYPTOR_MISSING),
        ):
            reason = cryptoevents.reason_for(RuntimeError(message))
            self.assertEqual(expected, reason, message)
            _, entry = self._record(
                cryptoevents.DECRYPTION_FAILED, 'engine-start', file='f.conf', reason=reason,
            )
            self.assertNotIn('/', json.dumps(entry).replace('\\/', ''))

    def test_a_reason_it_does_not_know_becomes_unknown_rather_than_itself(self):
        # A message that changes in the encryptor without changing here makes a duller event,
        # not a leaking one.
        self.assertEqual(
            cryptoevents.REASON_UNKNOWN,
            cryptoevents.reason_for(RuntimeError('/etc/secret exploded')),
        )
        _, entry = self._record(
            cryptoevents.DECRYPTION_FAILED, 'engine-start', file='f.conf',
            reason='anything at all',
        )
        self.assertEqual(cryptoevents.REASON_UNKNOWN, entry['reason'])

    def test_it_never_raises_at_the_caller(self):
        # The caller is usually in the middle of failing. A spool that cannot be written must
        # not replace the reason it was failing with a reason about the spool.
        self.assertIsNone(cryptoevents.record(
            cryptoevents.DECRYPTION_FAILED, 'engine-start',
            spool_dir='/proc/nowhere-writable',
        ))
        self.assertIsNone(cryptoevents.record(
            'NOT_AN_EVENT', 'engine-start', spool_dir=self.spool,
        ))

    def test_an_entry_is_only_visible_once_it_is_whole(self):
        # The engine reads this directory while things are writing to it.
        self._record(cryptoevents.KEY_CREATED, 'engine-setup')

        names = os.listdir(self.spool)
        self.assertEqual(1, len(names))
        self.assertTrue(names[0].endswith('.json'))
        self.assertFalse(names[0].startswith('.'))

    def test_two_events_do_not_land_on_one_another(self):
        first, _ = self._record(cryptoevents.KEY_CREATED, 'engine-setup')
        second, _ = self._record(cryptoevents.KEY_CREATED, 'engine-setup')

        self.assertNotEqual(first, second)
        self.assertEqual(2, len(os.listdir(self.spool)))


if __name__ == '__main__':
    unittest.main()
