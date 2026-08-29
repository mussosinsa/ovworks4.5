import importlib.util
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).parents[1] / "encryptor" / "encryptor.py"
SPEC = importlib.util.spec_from_file_location("encryptor", MODULE_PATH)
encryptor = importlib.util.module_from_spec(SPEC)
try:
    SPEC.loader.exec_module(encryptor)
    CRYPTOGRAPHY_AVAILABLE = True
except ModuleNotFoundError as error:
    if error.name != "cryptography":
        raise
    CRYPTOGRAPHY_AVAILABLE = False

VAULT_TOOL_PATH = Path(__file__).parents[1] / "encryptor" / "vault_passphrase.py"
VAULT_CONFIG_EXAMPLE = (
    Path(__file__).parents[1] / "encryptor" / "config.vault.example.json"
)


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "python3-cryptography is not installed")
class EncryptorTest(unittest.TestCase):
    def setUp(self):
        self.passphrase = b"unit-test-passphrase"

    def test_vault_config_example_is_ready_for_preinstall(self):
        config = json.loads(VAULT_CONFIG_EXAMPLE.read_text(encoding="utf-8"))
        self.assertTrue(config["vault_transit"]["enabled"])
        self.assertEqual(
            "/etc/ovirt-engine/encryptor/passphrase",
            config["secret_file"],
        )
        for generated in (
            "active_format",
            "format_version",
            "pbkdf2_iterations",
            "salt",
            "nonce",
            "decrypt_key",
            "rsaPublicKey",
        ):
            self.assertNotIn(generated, config)

    class FakeTransitClient:
        def __init__(self):
            self.kek = bytes(range(32))

        def wrap(self, plaintext):
            return b"vault:v1:" + encryptor.AESGCM(self.kek).encrypt(
                b"\0" * 12, plaintext, None
            ).hex().encode("ascii")

        def unwrap(self, ciphertext):
            value = bytes.fromhex(ciphertext.split(b":", 2)[2].decode("ascii"))
            return encryptor.AESGCM(self.kek).decrypt(b"\0" * 12, value, None)

    def test_round_trip_uses_versioned_gcm_format(self):
        plaintext = b'ENGINE_DB_PASSWORD="secret"\n'
        encrypted = encryptor.encrypt_bytes(plaintext, self.passphrase)
        self.assertTrue(encrypted.startswith(encryptor.MAGIC))
        self.assertEqual(encrypted[len(encryptor.MAGIC)], encryptor.VERSION)
        self.assertEqual(
            plaintext,
            encryptor.decrypt_bytes(encrypted, self.passphrase),
        )

    def test_aaa_jdbc_internal_properties_is_approved_for_encryption(self):
        self.assertIn(
            "internal.properties",
            encryptor.ALLOWED_CONFIG_BASENAMES,
        )

    def test_random_nonces_produce_different_ciphertexts(self):
        first = encryptor.encrypt_bytes(b"same", self.passphrase)
        second = encryptor.encrypt_bytes(b"same", self.passphrase)
        self.assertNotEqual(first, second)

    def test_vault_transit_envelope_round_trip_and_tamper_detection(self):
        client = self.FakeTransitClient()
        encrypted = encryptor.encrypt_vault_bytes(b"database secret", client)
        self.assertTrue(encrypted.startswith(encryptor.VAULT_MAGIC))
        self.assertEqual(
            b"database secret",
            encryptor.decrypt_bytes(encrypted, transit_client=client),
        )
        damaged = bytearray(encrypted)
        damaged[-1] ^= 1
        with self.assertRaisesRegex(encryptor.EncryptorError, "Authentication failed"):
            encryptor.decrypt_bytes(bytes(damaged), transit_client=client)

    def test_vault_client_reports_missing_token_file(self):
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / "missing-token"
            with self.assertRaisesRegex(
                encryptor.EncryptorError,
                "Vault token file is missing.*before running engine-setup",
            ):
                encryptor.VaultTransitClient({"token_file": str(token)})

    def test_plain_http_requires_explicit_loopback_opt_in(self):
        with self.assertRaisesRegex(
            encryptor.EncryptorError,
            "allow_plaintext_loopback=true",
        ):
            encryptor.VaultTransitClient({
                "address": "http://127.0.0.1:8200",
            })
        with self.assertRaisesRegex(
            encryptor.EncryptorError,
            "allow_plaintext_loopback must be true or false",
        ):
            encryptor.VaultTransitClient({
                "address": "http://127.0.0.1:8200",
                "allow_plaintext_loopback": "true",
            })

    def test_vault_config_rejects_ambiguous_enabled_value(self):
        with self.assertRaisesRegex(
            encryptor.EncryptorError,
            "vault_transit.enabled must be true or false",
        ):
            encryptor.vault_client_from_config({
                "vault_transit": {"enabled": "true"},
            })

    def test_vault_client_reports_certificate_san_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / "token"
            token.write_text("test-token\n", encoding="utf-8")
            token.chmod(0o600)
            client = encryptor.VaultTransitClient({"token_file": str(token)})
            certificate_error = encryptor.ssl.SSLCertVerificationError(
                1, "IP address mismatch"
            )
            client.opener.open = mock.Mock(
                side_effect=encryptor.urllib.error.URLError(certificate_error)
            )
            with self.assertRaisesRegex(
                encryptor.EncryptorError,
                "must match a certificate subjectAltName",
            ):
                client.wrap(b"data key")

    def test_encrypted_passphrase_file_is_decrypted_when_read(self):
        client = self.FakeTransitClient()
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory) / "passphrase.enc"
            secret.write_bytes(encryptor.encrypt_vault_bytes(b"passphrase", client))
            secret.chmod(0o600)
            self.assertEqual(
                b"passphrase", encryptor._read_secret_file(secret, client)
            )

    def test_vault_passphrase_can_encrypt_configured_secret_in_place(self):
        client = self.FakeTransitClient()
        spec = importlib.util.spec_from_file_location(
            "vault_passphrase_test", VAULT_TOOL_PATH
        )
        module = importlib.util.module_from_spec(spec)
        with mock.patch.dict(sys.modules, {"encryptor": encryptor}):
            spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory) / "passphrase"
            secret.write_bytes(b"legacy passphrase\n")
            secret.chmod(0o600)
            with mock.patch.object(
                encryptor, "_load_crypto_config", return_value={}
            ), mock.patch.object(
                encryptor, "vault_client_from_config", return_value=client
            ):
                self.assertEqual(0, module.main(["--check"]))
                self.assertEqual(
                    0,
                    module.main(["--encrypt-in-place", str(secret)]),
                )
            self.assertTrue(secret.read_bytes().startswith(encryptor.VAULT_MAGIC))
            self.assertEqual(
                b"legacy passphrase",
                encryptor._read_secret_file(secret, client),
            )
            self.assertEqual(0o600, stat.S_IMODE(secret.stat().st_mode))

    def test_tampering_and_wrong_key_are_rejected(self):
        encrypted = bytearray(encryptor.encrypt_bytes(b"secret", self.passphrase))
        encrypted[-1] ^= 1
        with self.assertRaisesRegex(encryptor.EncryptorError, "Authentication failed"):
            encryptor.decrypt_bytes(bytes(encrypted), self.passphrase)
        valid = encryptor.encrypt_bytes(b"secret", self.passphrase)
        with self.assertRaisesRegex(encryptor.EncryptorError, "Authentication failed"):
            encryptor.decrypt_bytes(valid, b"wrong")

    def test_truncated_and_legacy_data_are_rejected(self):
        with self.assertRaisesRegex(encryptor.EncryptorError, "truncated"):
            encryptor.decrypt_bytes(encryptor.MAGIC, self.passphrase)
        with self.assertRaisesRegex(encryptor.EncryptorError, "denied"):
            encryptor.decrypt_bytes(
                b"legacy",
                self.passphrase,
                deny_legacy_cbc=True,
            )

    def test_legacy_cbc_is_available_only_for_migration(self):
        key = bytes(range(32))
        iv = bytes(range(16))
        padder = encryptor.padding.PKCS7(128).padder()
        padded = padder.update(b"legacy secret") + padder.finalize()
        worker = encryptor.Cipher(
            encryptor.algorithms.AES(key),
            encryptor.modes.CBC(iv),
        ).encryptor()
        ciphertext = iv + worker.update(padded) + worker.finalize()
        config = {
            "legacy_cbc": {
                "enabled": True,
                "key": "hex:" + key.hex(),
                "iv_prefix": True,
            }
        }
        self.assertEqual(
            b"legacy secret",
            encryptor.decrypt_bytes(ciphertext, self.passphrase, config),
        )
        with self.assertRaisesRegex(encryptor.EncryptorError, "denied"):
            encryptor.decrypt_bytes(
                ciphertext,
                self.passphrase,
                config,
                deny_legacy_cbc=True,
            )

    def test_file_transform_is_atomic_and_preserves_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "config.conf"
            source.write_bytes(b"secret")
            source.chmod(0o640)
            roots = (root,)
            encryptor.transform_file(
                source,
                source,
                self.passphrase,
                allowed_roots=roots,
            )
            self.assertEqual(0o640, stat.S_IMODE(source.stat().st_mode))
            with self.assertRaisesRegex(encryptor.EncryptorError, "already"):
                encryptor.transform_file(
                    source,
                    source,
                    self.passphrase,
                    allowed_roots=roots,
                )
            encryptor.transform_file(
                source,
                source,
                self.passphrase,
                decrypt=True,
                deny_legacy_cbc=True,
                allowed_roots=roots,
            )
            self.assertEqual(b"secret", source.read_bytes())
            self.assertEqual(0o600, stat.S_IMODE(source.stat().st_mode))

    def test_existing_distinct_output_requires_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.conf"
            output = root / "output.conf"
            source.write_bytes(b"secret")
            output.write_bytes(b"do not replace")
            with self.assertRaisesRegex(encryptor.EncryptorError, "Output exists"):
                encryptor.transform_file(
                    source,
                    output,
                    self.passphrase,
                    allowed_roots=(root,),
                )

    def test_symlink_and_writable_input_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.write_bytes(b"secret")
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaisesRegex(encryptor.EncryptorError, "Symbolic|symbolic"):
                encryptor.validate_ovirt_path(link, allowed_roots=(root,))
            target.chmod(0o662)
            with self.assertRaisesRegex(encryptor.EncryptorError, "writable"):
                encryptor.validate_ovirt_path(target, allowed_roots=(root,))

    def test_secret_file_requires_mode_0600(self):
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory) / "secret"
            secret.write_text("passphrase", encoding="utf-8")
            secret.chmod(0o644)
            with self.assertRaisesRegex(encryptor.EncryptorError, "0600"):
                encryptor._read_secret_file(secret)
            secret.chmod(0o600)
            self.assertEqual(b"passphrase", encryptor._read_secret_file(secret))


if __name__ == "__main__":
    unittest.main()
