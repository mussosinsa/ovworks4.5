import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).parents[2]
ENCRYPTOR_DIR = ROOT / "packaging" / "encryptor"
sys.path.insert(0, str(ROOT / "packaging" / "pythonlib"))
sys.path.insert(0, str(ENCRYPTOR_DIR))

import encryptor  # noqa: E402
import login_key  # noqa: E402


class LoginKeyCryptoTest(unittest.TestCase):
    """The web administration login's RSA private key is kept encrypted at rest under the DEK and
    decrypted to a private runtime file for the engine to read."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.key = self.dir / "private_pkcs8.der"
        self.plaintext = b"\x30\x82 PKCS8 private key DER"
        self.key.write_bytes(self.plaintext)
        os.chmod(self.key, 0o600)
        self.dek = bytearray(os.urandom(32))
        patcher = mock.patch.object(login_key, "_dek", lambda config: bytearray(self.dek))
        patcher.start()
        self.addCleanup(patcher.stop)
        self._atomic = mock.patch.object(
            encryptor, "_atomic_write",
            lambda path, data, owner=None, mode=0o600: (
                Path(path).write_bytes(data), os.chmod(str(path), mode)))
        self._atomic.start()
        self.addCleanup(self._atomic.stop)

    def test_encrypt_seals_the_key_in_place_and_is_idempotent(self):
        self.assertTrue(login_key.encrypt(key_path=self.key))
        self.assertTrue(self.key.read_bytes().startswith(encryptor.ENVELOPE_MAGIC))
        self.assertEqual(0o600, os.stat(self.key).st_mode & 0o777)
        # Encrypted once: a second run leaves the envelope as it is.
        self.assertFalse(login_key.encrypt(key_path=self.key))
        self.assertTrue(self.key.read_bytes().startswith(encryptor.ENVELOPE_MAGIC))

    def test_decrypt_writes_the_plaintext_key_for_the_engine(self):
        login_key.encrypt(key_path=self.key)
        out = self.dir / "runtime.der"
        self.assertTrue(login_key.decrypt(out, key_path=self.key))
        self.assertEqual(self.plaintext, out.read_bytes())
        self.assertEqual(0o600, os.stat(out).st_mode & 0o777)

    def test_a_key_still_in_plaintext_is_passed_through(self):
        # An installation upgraded before the key was encrypted: the first start must still work.
        out = self.dir / "runtime.der"
        self.assertTrue(login_key.decrypt(out, key_path=self.key))
        self.assertEqual(self.plaintext, out.read_bytes())

    def test_a_key_encrypted_under_another_dek_does_not_decrypt(self):
        login_key.encrypt(key_path=self.key)
        self.dek = bytearray(os.urandom(32))   # another DEK
        with self.assertRaises(encryptor.EncryptorError):
            login_key.decrypt(self.dir / "runtime.der", key_path=self.key)

    def test_a_key_that_is_not_there_is_not_an_error(self):
        missing = self.dir / "absent.der"
        self.assertFalse(login_key.encrypt(key_path=missing))
        self.assertFalse(login_key.decrypt(self.dir / "runtime.der", key_path=missing))

    def test_it_takes_no_path_from_its_caller_but_the_decrypt_destination(self):
        source = (ENCRYPTOR_DIR / "login_key.py").read_text()
        main = source[source.index("def main("):]
        self.assertNotIn('add_argument("--config', main)
        self.assertIn('add_argument("--encrypt"', main)
        self.assertIn('add_argument("--decrypt"', main)


if __name__ == "__main__":
    unittest.main()
