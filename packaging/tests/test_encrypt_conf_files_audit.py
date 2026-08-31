import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


ENCRYPTOR_PATH = Path(__file__).parents[1] / 'encryptor' / 'encryptor.py'
ENCRYPTOR_SPEC = importlib.util.spec_from_file_location('encryptor', ENCRYPTOR_PATH)
encryptor = importlib.util.module_from_spec(ENCRYPTOR_SPEC)
try:
    ENCRYPTOR_SPEC.loader.exec_module(encryptor)
except ModuleNotFoundError as error:
    if error.name != 'cryptography':
        raise
sys.modules['encryptor'] = encryptor

SCRIPT_PATH = Path(__file__).parents[1] / 'encryptor' / 'encrypt_conf_files.py'
SCRIPT_SPEC = importlib.util.spec_from_file_location(
    'encrypt_conf_files',
    SCRIPT_PATH,
)
encrypt_conf_files = importlib.util.module_from_spec(SCRIPT_SPEC)
SCRIPT_SPEC.loader.exec_module(encrypt_conf_files)


class EncryptConfFilesAuditTest(unittest.TestCase):
    def test_audit_record_contains_metadata_without_secrets(self):
        with mock.patch.object(encrypt_conf_files.syslog, 'openlog'), \
                mock.patch.object(encrypt_conf_files.syslog, 'syslog') as log, \
                mock.patch.object(encrypt_conf_files.syslog, 'closelog'), \
                mock.patch.object(encrypt_conf_files.os, 'geteuid', return_value=0):
            encrypt_conf_files._audit('success', 'vault', 3)

        record = log.call_args.args[1]
        self.assertIn('operation=encrypt-config', record)
        self.assertIn('status=success', record)
        self.assertIn('mode=vault', record)
        self.assertIn('files=3', record)
        self.assertIn('uid=0', record)
        self.assertNotIn('token', record.lower())
        self.assertNotIn('passphrase', record.lower())


if __name__ == '__main__':
    unittest.main()
