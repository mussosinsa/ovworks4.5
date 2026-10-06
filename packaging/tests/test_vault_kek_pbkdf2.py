import base64
import importlib.util
import io
import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock


ENCRYPTOR_DIR = Path(__file__).parents[1] / "encryptor"
SPEC = importlib.util.spec_from_file_location("encryptor", ENCRYPTOR_DIR / "encryptor.py")
encryptor = importlib.util.module_from_spec(SPEC)
try:
    SPEC.loader.exec_module(encryptor)
    sys.modules["encryptor"] = encryptor
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.keywrap import aes_key_unwrap_with_padding
    CRYPTOGRAPHY_AVAILABLE = True
except (ModuleNotFoundError, BaseException) as error:  # a broken binding panics, not raises
    if isinstance(error, (KeyboardInterrupt, SystemExit)):
        raise
    CRYPTOGRAPHY_AVAILABLE = False

if CRYPTOGRAPHY_AVAILABLE:
    TOOL_SPEC = importlib.util.spec_from_file_location(
        "vault_passphrase", ENCRYPTOR_DIR / "vault_passphrase.py")
    vault_passphrase = importlib.util.module_from_spec(TOOL_SPEC)
    TOOL_SPEC.loader.exec_module(vault_passphrase)

ADMIN = "admin-import-token"
SERVICE = "service-token"
PASSPHRASE = bytearray(b"Kek-Initial-Data-2026!")


class FakeVault:
    """Vault Transit as far as this feature uses it: wrapping_key, keys/<n>, keys/<n>/import,
    encrypt/<n>, decrypt/<n> - with the import format Vault documents (RSA-OAEP-SHA256 of an
    ephemeral AES key, followed by the target key under AES-KWP), and admin/service tokens
    with different rights."""

    def __init__(self):
        self.private = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        self.keys = {}
        self.imports = []

    def handle(self, method, path, token, body):
        parts = path.strip("/").split("/")[2:]   # after v1/transit
        if parts == ["wrapping_key"] and method == "GET" and token == ADMIN:
            pem = self.private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
            return 200, {"data": {"public_key": pem}}
        if parts[0] == "keys" and len(parts) == 2 and method == "GET" and token == ADMIN:
            return (200, {"data": {"name": parts[1]}}) if parts[1] in self.keys else (404, {})
        if parts[0] == "keys" and len(parts) == 3 and parts[2] == "import" and token == ADMIN:
            if parts[1] in self.keys:
                return 400, {"errors": ["the import path cannot be used with an existing key"]}
            raw = base64.b64decode(body["ciphertext"])
            ephemeral = self.private.decrypt(raw[:512], padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            self.keys[parts[1]] = aes_key_unwrap_with_padding(ephemeral, raw[512:])
            self.imports.append(body)
            return 204, None
        if parts[0] in ("encrypt", "decrypt") and token in (SERVICE, ADMIN) and method == "POST":
            key = self.keys.get(parts[1])
            if key is None:
                return 400, {"errors": ["encryption key not found"]}
            if parts[0] == "encrypt":
                nonce = b"\x01" * 12
                sealed = AESGCM(key).encrypt(nonce, base64.b64decode(body["plaintext"]), None)
                return 200, {"data": {"ciphertext": "vault:v1:" + base64.b64encode(
                    nonce + sealed).decode("ascii")}}
            raw = base64.b64decode(body["ciphertext"].split(":", 2)[2])
            try:
                plain = AESGCM(key).decrypt(raw[:12], raw[12:], None)
            except Exception:
                return 400, {"errors": ["cipher: message authentication failed"]}
            return 200, {"data": {"plaintext": base64.b64encode(plain).decode("ascii")}}
        return 403, {"errors": ["permission denied"]}


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "python3-cryptography is not usable here")
class VaultKekPbkdf2Test(unittest.TestCase):

    def setUp(self):
        self.vault = FakeVault()
        vault = self.vault

        class Handler(BaseHTTPRequestHandler):
            def _serve(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else None
                status, answer = vault.handle(
                    self.command, self.path, self.headers.get("X-Vault-Token"), body)
                data = b"" if answer is None else json.dumps(answer).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = _serve

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.dir = Path(tempfile.mkdtemp())
        token = self.dir / "vault-token"
        token.write_text(SERVICE + "\n")
        token.chmod(0o600)
        self.settings = {
            "enabled": True,
            "address": "http://127.0.0.1:%d" % self.server.server_port,
            "allow_plaintext_loopback": True,
            "key_name": "ovirt-engine-config",
            "token_file": str(token),
        }

    def test_the_kek_is_pbkdf2_of_the_passphrase_and_salt(self):
        salt = bytes(range(32))
        kek = encryptor.derive_kek(PASSPHRASE, salt)
        expected = __import__("hashlib").pbkdf2_hmac("sha256", bytes(PASSPHRASE), salt, 600000, 32)
        self.assertEqual(expected, bytes(kek))
        self.assertIsInstance(kek, bytearray)

    def test_each_installation_derives_a_different_kek_from_the_same_passphrase(self):
        first = encryptor.derive_kek(PASSPHRASE, encryptor.new_kek_salt())
        second = encryptor.derive_kek(PASSPHRASE, encryptor.new_kek_salt())
        self.assertNotEqual(first, second)

    def test_weak_settings_are_refused(self):
        with self.assertRaises(encryptor.EncryptorError):
            encryptor.derive_kek(PASSPHRASE, bytes(32), iterations=1000)
        with self.assertRaises(encryptor.EncryptorError):
            encryptor.derive_kek(PASSPHRASE, bytes(16))
        for weak in (b"short1A!", b"alllowercaseletters", b"ALLUPPER1234567890"):
            with self.assertRaises(encryptor.EncryptorError):
                encryptor.check_kek_passphrase(bytearray(weak))
        encryptor.check_kek_passphrase(PASSPHRASE)

    def test_vault_holds_exactly_the_derived_kek_and_config_gets_the_salt(self):
        salt = encryptor.new_kek_salt()
        record = encryptor.provision_pbkdf2_kek(
            self.settings, bytearray(ADMIN.encode()), bytearray(PASSPHRASE), salt=salt)
        self.assertEqual(
            bytes(encryptor.derive_kek(PASSPHRASE, salt)),
            self.vault.keys["ovirt-engine-config"])
        self.assertTrue(record["verified"])
        self.assertEqual("PBKDF2-HMAC-SHA256", record["kdf"])
        self.assertEqual(600000, record["iterations"])
        self.assertEqual(salt, base64.b64decode(record["salt"]))
        self.assertNotIn("passphrase", json.dumps(record))
        imported = self.vault.imports[0]
        self.assertEqual("aes256-gcm96", imported["type"])
        self.assertFalse(imported["exportable"])
        self.assertFalse(imported["allow_plaintext_backup"])
        # Vault rotating it itself would produce a random, not a derived, version.
        self.assertFalse(imported["allow_rotation"])

    def test_an_existing_key_is_never_replaced(self):
        self.vault.keys["ovirt-engine-config"] = bytes(32)
        with self.assertRaisesRegex(encryptor.EncryptorError, "already exists"):
            encryptor.provision_pbkdf2_kek(
                self.settings, bytearray(ADMIN.encode()), bytearray(PASSPHRASE))
        self.assertEqual(bytes(32), self.vault.keys["ovirt-engine-config"])

    def test_an_interrupted_import_is_finished_and_a_foreign_key_is_refused(self):
        salt = encryptor.new_kek_salt()
        # The import went through but the record stayed pending: adopted after checking.
        self.vault.keys["ovirt-engine-config"] = bytes(encryptor.derive_kek(PASSPHRASE, salt))
        record = encryptor.provision_pbkdf2_kek(
            self.settings, bytearray(ADMIN.encode()), bytearray(PASSPHRASE),
            salt=salt, adopt_existing=True)
        self.assertEqual(("active", True), (record["status"], record["verified"]))
        self.assertEqual([], self.vault.imports)
        # A key that this passphrase and salt do not derive is never adopted.
        self.vault.keys["ovirt-engine-config"] = bytes(32)
        with self.assertRaisesRegex(encryptor.EncryptorError, "is not the KEK"):
            encryptor.provision_pbkdf2_kek(
                self.settings, bytearray(ADMIN.encode()), bytearray(PASSPHRASE),
                salt=salt, adopt_existing=True)

    def test_the_salt_is_recorded_before_the_import(self):
        config_path = self.dir / "config.json"
        config = {"vault_transit": self.settings}
        config_path.write_text(json.dumps(config))
        seen = []
        real = encryptor.provision_pbkdf2_kek

        def provision(*args, **kwargs):
            seen.append(json.loads(config_path.read_text())["kek_derivation"])
            raise encryptor.EncryptorError("connection lost")

        def reader(prompt):
            return bytearray({"Vault": ADMIN.encode()}.get(prompt.split()[0], PASSPHRASE))

        with mock.patch.object(encryptor, "validate_ovirt_path",
                               return_value=config_path.stat()), \
                mock.patch("sys.stdout", new=io.StringIO()):
            with mock.patch.object(encryptor, "provision_pbkdf2_kek", provision):
                with self.assertRaises(encryptor.EncryptorError):
                    vault_passphrase.init_kek_from_passphrase(
                        str(config_path), config, reader=reader)
            self.assertEqual("pending", seen[0]["status"])
            # Re-running finishes it with the same salt.
            with mock.patch.object(encryptor, "provision_pbkdf2_kek", real):
                vault_passphrase.init_kek_from_passphrase(
                    str(config_path), json.loads(config_path.read_text()), reader=reader)
        written = json.loads(config_path.read_text())["kek_derivation"]
        self.assertEqual((seen[0]["salt"], "active"), (written["salt"], written["status"]))
        self.assertEqual(
            bytes(encryptor.derive_kek(PASSPHRASE, base64.b64decode(written["salt"]))),
            self.vault.keys["ovirt-engine-config"])

    def test_the_service_token_cannot_import(self):
        with self.assertRaisesRegex(encryptor.EncryptorError, "HTTP 403"):
            encryptor.provision_pbkdf2_kek(
                self.settings, bytearray(SERVICE.encode()), bytearray(PASSPHRASE))
        self.assertEqual({}, self.vault.keys)

    def test_the_tool_reads_secrets_typed_in_and_wipes_them(self):
        config_path = self.dir / "config.json"
        config = {"vault_transit": self.settings}
        config_path.write_text(json.dumps(config))
        config_path.chmod(0o640)
        typed = []

        def reader(prompt):
            value = bytearray({"Vault": ADMIN.encode()}.get(prompt.split()[0], PASSPHRASE))
            typed.append(value)
            return value

        with mock.patch.object(encryptor, "validate_ovirt_path",
                               return_value=config_path.stat()), \
                mock.patch("sys.stdout", new=io.StringIO()):
            vault_passphrase.init_kek_from_passphrase(str(config_path), config, reader=reader)
        written = json.loads(config_path.read_text())
        self.assertEqual("ovirt-engine-config", written["kek_derivation"]["key_name"])
        self.assertEqual("active", written["kek_derivation"]["status"])
        self.assertIn("ovirt-engine-config", self.vault.keys)
        for secret in typed:
            self.assertEqual(bytearray(len(secret)), secret)   # overwritten with zeros

    def test_a_lost_kek_is_recreated_identically_from_the_recorded_salt(self):
        config_path = self.dir / "config.json"
        config = {"vault_transit": self.settings}
        config_path.write_text(json.dumps(config))

        def reader(prompt):
            return bytearray({"Vault": ADMIN.encode()}.get(prompt.split()[0], PASSPHRASE))

        with mock.patch.object(encryptor, "validate_ovirt_path",
                               return_value=config_path.stat()), \
                mock.patch("sys.stdout", new=io.StringIO()):
            vault_passphrase.init_kek_from_passphrase(str(config_path), config, reader=reader)
            original = self.vault.keys.pop("ovirt-engine-config")    # Vault loses it
            config = json.loads(config_path.read_text())
            vault_passphrase.init_kek_from_passphrase(
                str(config_path), config, reader=reader, recover=True)
        self.assertEqual(original, self.vault.keys["ovirt-engine-config"])

    def test_rewrap_moves_every_file_to_the_new_key_and_switches_config(self):
        self.vault.keys["ovirt-engine-config"] = bytes(range(32))
        old = encryptor.VaultTransitClient(self.settings)
        root = self.dir / "etc"
        (root / "engine.conf.d").mkdir(parents=True)
        target = root / "engine.conf.d" / "10-setup-database.conf"
        target.write_bytes(encryptor.encrypt_vault_bytes(b'ENGINE_DB_PASSWORD="x"\n', old))
        target.chmod(0o640)
        encryptor.provision_pbkdf2_kek(
            dict(self.settings, key_name="ovirt-engine-config-pbkdf2"),
            bytearray(ADMIN.encode()), bytearray(PASSPHRASE))
        config_path = self.dir / "config.json"
        config = {"vault_transit": dict(self.settings), "watch_path": [str(root)]}
        config_path.write_text(json.dumps(config))
        with mock.patch.object(encryptor, "_within_allowed_root", return_value=True), \
                mock.patch.object(encryptor, "validate_ovirt_path",
                                  return_value=config_path.stat()), \
                mock.patch("sys.stdout", new=io.StringIO()):
            moved = vault_passphrase.rewrap_to_key(
                str(config_path), config, "ovirt-engine-config-pbkdf2")
            # A second run finds nothing left to move.
            config["vault_transit"]["key_name"] = "ovirt-engine-config"
            again = vault_passphrase.rewrap_to_key(
                str(config_path), config, "ovirt-engine-config-pbkdf2")
        self.assertEqual((1, 0), (moved, again))
        new = encryptor.VaultTransitClient(self.settings, key_name="ovirt-engine-config-pbkdf2")
        self.assertEqual(b'ENGINE_DB_PASSWORD="x"\n',
                         encryptor.decrypt_vault_bytes(target.read_bytes(), new))
        self.assertEqual(0o640, target.stat().st_mode & 0o777)
        self.assertEqual("ovirt-engine-config-pbkdf2",
                         json.loads(config_path.read_text())["vault_transit"]["key_name"])


if __name__ == "__main__":
    unittest.main()
