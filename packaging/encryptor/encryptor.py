#!/usr/bin/python3
"""Authenticated encryption for sensitive oVirt configuration files."""

import argparse
import base64
import getpass
import json
import os
import ssl
import stat
import struct
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"OVENC001"
VAULT_MAGIC = b"OVVLT001"
VERSION = 1
PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16
NONCE_SIZE = 12
DATA_KEY_SIZE = 32
WRAPPED_KEY_SIZE = DATA_KEY_SIZE + 16
HEADER = struct.Struct(">8sBI16s12s12sH")
VAULT_HEADER = struct.Struct(">8sB12sH")
DEFAULT_CONFIG = Path("/etc/ovirt-engine/encryptor/config.json")
DEFAULT_CREDENTIAL = "ovirt-encryptor-passphrase"
PASSPHRASE_ENV = "OVIRT_ENCRYPTOR_PASSPHRASE"
ALLOWED_ROOTS = (Path("/etc/ovirt-engine"), Path("/etc/ovirt-engine-dwh"))
ALLOWED_CONFIG_BASENAMES = frozenset((
    "10-setup-database.conf",
    "10-setup-dwh-database.conf",
    "internal.properties",
))


class EncryptorError(RuntimeError):
    """A safe, user-facing encryption failure."""


class VaultTransitClient:
    """Small, dependency-free client for a local Vault Transit KMS."""

    def __init__(self, settings):
        if not isinstance(settings, dict):
            raise EncryptorError("vault_transit configuration must be an object")
        self.address = settings.get("address", "https://127.0.0.1:8200").rstrip("/")
        parsed = urllib.parse.urlparse(self.address)
        if parsed.scheme not in ("http", "https"):
            raise EncryptorError("Vault address must use HTTP or HTTPS")
        if parsed.scheme == "http" and not (
                settings.get("allow_plaintext_loopback", False)
                and parsed.hostname in ("127.0.0.1", "::1", "localhost")):
            raise EncryptorError("Plain HTTP is allowed only for an explicitly enabled loopback Vault")
        self.mount = settings.get("mount", "transit").strip("/")
        self.key_name = settings.get("key_name", "ovirt-engine-config")
        if not self.mount or "/" in self.mount or not self.key_name or "/" in self.key_name:
            raise EncryptorError("Invalid Vault Transit mount or key name")
        self.token_file = Path(settings.get(
            "token_file", "/etc/ovirt-engine/encryptor/vault-token"
        ))
        if not self.token_file.exists():
            raise EncryptorError(
                "Vault token file is missing: %s; provision a least-privilege "
                "Transit token before running engine-setup" % self.token_file
            )
        try:
            self.token = _read_secret_file(self.token_file).decode("utf-8")
        except UnicodeDecodeError as error:
            raise EncryptorError("Vault token file is not valid UTF-8") from error
        self.namespace = settings.get("namespace")
        ca_cert = settings.get("ca_cert")
        if ca_cert and not Path(ca_cert).is_file():
            raise EncryptorError("Vault CA certificate is missing: %s" % ca_cert)
        context = ssl.create_default_context(cafile=ca_cert)
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
        self.timeout = int(settings.get("timeout", 5))

    def _request(self, operation, payload):
        url = "%s/v1/%s/%s/%s" % (
            self.address,
            urllib.parse.quote(self.mount, safe=""),
            operation,
            urllib.parse.quote(self.key_name, safe=""),
        )
        headers = {"Content-Type": "application/json", "X-Vault-Token": self.token}
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        request = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST"
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                body = response.read()
                if operation == "keys" and not body:
                    return {}
                result = json.loads(body.decode("utf-8"))
        except urllib.error.HTTPError as error:
            raise EncryptorError(
                "Vault Transit request failed (HTTP %s)" % error.code
            ) from error
        except urllib.error.URLError as error:
            if isinstance(error.reason, ssl.SSLCertVerificationError):
                raise EncryptorError(
                    "Vault TLS certificate verification failed: the configured "
                    "address must match a certificate subjectAltName and the "
                    "configured CA must trust the certificate"
                ) from error
            raise EncryptorError("Vault Transit connection failed") from error
        except (OSError, ValueError) as error:
            raise EncryptorError("Vault Transit request failed") from error
        if not isinstance(result, dict) or not isinstance(result.get("data"), dict):
            raise EncryptorError("Vault Transit returned an invalid response")
        return result["data"]

    def ensure_key(self):
        """Ask Vault to generate and retain a non-exportable AES-256 KEK."""
        self._request("keys", {
            "type": "aes256-gcm96",
            "exportable": False,
            "allow_plaintext_backup": False,
        })

    def wrap(self, plaintext):
        result = self._request("encrypt", {
            "plaintext": base64.b64encode(plaintext).decode("ascii"),
        })
        ciphertext = result.get("ciphertext")
        if not isinstance(ciphertext, str) or not ciphertext.startswith("vault:v"):
            raise EncryptorError("Vault Transit did not return wrapped key material")
        return ciphertext.encode("ascii")

    def unwrap(self, ciphertext):
        result = self._request("decrypt", {"ciphertext": ciphertext.decode("ascii")})
        try:
            return base64.b64decode(result["plaintext"], validate=True)
        except (KeyError, TypeError, ValueError) as error:
            raise EncryptorError("Vault Transit did not return valid key material") from error


def vault_client_from_config(config):
    settings = config.get("vault_transit")
    if isinstance(settings, dict) and settings.get("enabled", False):
        return VaultTransitClient(settings)
    return None


def _load_crypto_config(path):
    path = Path(path)
    if not path.exists():
        return {}
    _validate_regular_file(path, reject_writable=True)
    try:
        with path.open(encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, ValueError) as error:
        raise EncryptorError("Unable to read encryptor configuration") from error
    if not isinstance(value, dict):
        raise EncryptorError("Encryptor configuration must be a JSON object")
    return value


def _validate_regular_file(path, reject_writable=False):
    path = Path(path)
    try:
        info = path.lstat()
    except OSError as error:
        raise EncryptorError("Unable to inspect path: %s" % path) from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise EncryptorError("Refusing non-regular or symbolic-link file: %s" % path)
    if reject_writable and info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise EncryptorError("Refusing group/other-writable file: %s" % path)
    return info


def _within_allowed_root(path, allowed_roots=ALLOWED_ROOTS):
    resolved = Path(path).resolve(strict=False)
    return any(resolved == root or root in resolved.parents for root in allowed_roots)


def validate_ovirt_path(path, must_exist=True, allowed_roots=ALLOWED_ROOTS):
    path = Path(path)
    if not _within_allowed_root(path, allowed_roots):
        raise EncryptorError("Path is outside approved oVirt directories: %s" % path)
    current = path if must_exist else path.parent
    while True:
        if current.exists() and stat.S_ISLNK(current.lstat().st_mode):
            raise EncryptorError("Symbolic links are not allowed: %s" % current)
        if current.parent == current:
            break
        current = current.parent
    if must_exist:
        return _validate_regular_file(path, reject_writable=True)
    return None


def is_encrypted(data_or_path):
    if isinstance(data_or_path, (str, Path)):
        with Path(data_or_path).open("rb") as stream:
            prefix = stream.read(len(MAGIC))
    else:
        prefix = bytes(data_or_path[:len(MAGIC)])
    return prefix in (MAGIC, VAULT_MAGIC)


def _read_secret_file(path, transit_client=None):
    info = _validate_regular_file(path, reject_writable=True)
    if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise EncryptorError("Passphrase file permissions must be 0600 or stricter")
    with Path(path).open("rb") as stream:
        secret = stream.read().rstrip(b"\r\n")
    if transit_client is not None and secret.startswith(VAULT_MAGIC):
        secret = decrypt_vault_bytes(secret, transit_client)
    if not secret:
        raise EncryptorError("Passphrase file is empty")
    return secret


def obtain_passphrase(config, secret_file=None, allow_prompt=False, transit_client=None):
    """Load a passphrase without hardware identifiers or command-line values."""
    credential_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    credential_name = config.get("systemd_credential", DEFAULT_CREDENTIAL)
    if credential_dir:
        credential_path = Path(credential_dir) / credential_name
        if credential_path.exists():
            return _read_secret_file(credential_path, transit_client)
    environment_secret = os.environ.get(PASSPHRASE_ENV)
    if environment_secret:
        return environment_secret.encode("utf-8")
    configured_file = secret_file or config.get("secret_file")
    if configured_file:
        return _read_secret_file(configured_file, transit_client)
    if allow_prompt and sys.stdin.isatty():
        secret = getpass.getpass("Encryption passphrase: ").encode("utf-8")
        if secret:
            return secret
    raise EncryptorError(
        "No key credential available (systemd credential, environment, or 0600 secret file)"
    )


def _derive_kek(passphrase, salt, iterations=PBKDF2_ITERATIONS):
    if iterations < PBKDF2_ITERATIONS:
        raise EncryptorError("PBKDF2 iteration count is below the security minimum")
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    ).derive(passphrase)


def encrypt_bytes(plaintext, passphrase):
    salt = os.urandom(SALT_SIZE)
    key_nonce = os.urandom(NONCE_SIZE)
    data_nonce = os.urandom(NONCE_SIZE)
    data_key = os.urandom(DATA_KEY_SIZE)
    fixed_header = HEADER.pack(
        MAGIC,
        VERSION,
        PBKDF2_ITERATIONS,
        salt,
        key_nonce,
        data_nonce,
        WRAPPED_KEY_SIZE,
    )
    kek = _derive_kek(passphrase, salt)
    wrapped_key = AESGCM(kek).encrypt(key_nonce, data_key, fixed_header)
    ciphertext = AESGCM(data_key).encrypt(
        data_nonce,
        plaintext,
        fixed_header + wrapped_key,
    )
    return fixed_header + wrapped_key + ciphertext


def encrypt_vault_bytes(plaintext, transit_client):
    """Envelope-encrypt bytes with a random DEK wrapped by Vault Transit."""
    data_key = os.urandom(DATA_KEY_SIZE)
    data_nonce = os.urandom(NONCE_SIZE)
    wrapped_key = transit_client.wrap(data_key)
    if len(wrapped_key) > 65535:
        raise EncryptorError("Vault wrapped data key is too large")
    fixed_header = VAULT_HEADER.pack(
        VAULT_MAGIC, VERSION, data_nonce, len(wrapped_key)
    )
    ciphertext = AESGCM(data_key).encrypt(
        data_nonce, plaintext, fixed_header + wrapped_key
    )
    return fixed_header + wrapped_key + ciphertext


def decrypt_vault_bytes(data, transit_client):
    if len(data) < VAULT_HEADER.size + 16:
        raise EncryptorError("Vault-encrypted file is truncated")
    magic, version, data_nonce, wrapped_size = VAULT_HEADER.unpack_from(data)
    if magic != VAULT_MAGIC or version != VERSION or not wrapped_size:
        raise EncryptorError("Invalid Vault envelope header")
    end = VAULT_HEADER.size + wrapped_size
    if len(data) < end + 16:
        raise EncryptorError("Vault-encrypted file is truncated")
    fixed_header, wrapped_key, ciphertext = data[:VAULT_HEADER.size], data[VAULT_HEADER.size:end], data[end:]
    data_key = transit_client.unwrap(wrapped_key)
    if len(data_key) != DATA_KEY_SIZE:
        raise EncryptorError("Vault returned an invalid data key length")
    try:
        return AESGCM(data_key).decrypt(
            data_nonce, ciphertext, fixed_header + wrapped_key
        )
    except InvalidTag as error:
        raise EncryptorError("Authentication failed: file is damaged or modified") from error


def _parse_gcm(data):
    if len(data) < HEADER.size + WRAPPED_KEY_SIZE + 16:
        raise EncryptorError("Encrypted file is truncated")
    magic, version, iterations, salt, key_nonce, data_nonce, wrapped_size = HEADER.unpack_from(data)
    if magic != MAGIC:
        raise EncryptorError("Encrypted file magic header is missing")
    if version != VERSION:
        raise EncryptorError("Unsupported encrypted file version: %s" % version)
    if iterations != PBKDF2_ITERATIONS:
        raise EncryptorError("Invalid PBKDF2 iteration count for this format version")
    if wrapped_size != WRAPPED_KEY_SIZE:
        raise EncryptorError("Invalid wrapped data-key length")
    end = HEADER.size + wrapped_size
    return iterations, salt, key_nonce, data_nonce, data[HEADER.size:end], data[end:], data[:HEADER.size]


def decrypt_gcm_bytes(data, passphrase):
    iterations, salt, key_nonce, data_nonce, wrapped_key, ciphertext, fixed_header = _parse_gcm(data)
    try:
        kek = _derive_kek(passphrase, salt, iterations)
        data_key = AESGCM(kek).decrypt(key_nonce, wrapped_key, fixed_header)
        return AESGCM(data_key).decrypt(
            data_nonce,
            ciphertext,
            fixed_header + wrapped_key,
        )
    except InvalidTag as error:
        raise EncryptorError("Authentication failed: file is damaged, modified, or the key is wrong") from error


def _decode_legacy_value(value, name):
    if not value:
        raise EncryptorError("Legacy CBC %s is not configured" % name)
    try:
        if value.startswith("hex:"):
            return bytes.fromhex(value[4:])
        if len(value) == 64:
            return bytes.fromhex(value)
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise EncryptorError("Invalid legacy CBC %s encoding" % name) from error


def decrypt_legacy_cbc(data, config):
    """Migration-only CBC reader; it never writes legacy ciphertext."""
    legacy = config.get("legacy_cbc")
    if not isinstance(legacy, dict) or not legacy.get("enabled", False):
        raise EncryptorError("Legacy CBC format is not enabled in the configuration")
    key = _decode_legacy_value(legacy.get("key"), "key")
    if len(key) != 32:
        raise EncryptorError("Legacy CBC key must be exactly 256 bits")
    if legacy.get("base64", False):
        try:
            data = base64.b64decode(data, validate=True)
        except (ValueError, TypeError) as error:
            raise EncryptorError("Legacy CBC ciphertext is not valid Base64") from error
    if legacy.get("iv_prefix", True):
        if len(data) < 32:
            raise EncryptorError("Legacy CBC file is truncated")
        iv, ciphertext = data[:16], data[16:]
    else:
        iv = _decode_legacy_value(legacy.get("iv"), "IV")
        ciphertext = data
    if len(iv) != 16 or not ciphertext or len(ciphertext) % 16:
        raise EncryptorError("Legacy CBC IV or ciphertext length is invalid")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    try:
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as error:
        raise EncryptorError("Legacy CBC decryption failed") from error


def decrypt_bytes(data, passphrase=None, config=None, deny_legacy_cbc=False,
                  transit_client=None):
    if data.startswith(VAULT_MAGIC):
        if transit_client is None:
            raise EncryptorError("Vault Transit is required for this encrypted file")
        return decrypt_vault_bytes(data, transit_client)
    if data.startswith(MAGIC):
        if passphrase is None:
            raise EncryptorError("A passphrase is required for the legacy envelope format")
        return decrypt_gcm_bytes(data, passphrase)
    if deny_legacy_cbc:
        raise EncryptorError("Legacy AES-CBC ciphertext is denied")
    return decrypt_legacy_cbc(data, config or {})


def _atomic_write(path, data, owner=None, mode=0o600):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix=".%s." % path.name, dir=str(path.parent))
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_path, mode)
        if owner is not None:
            os.chown(temporary_path, owner[0], owner[1])
        os.replace(temporary_path, path)
        directory_fd = os.open(str(path.parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def atomic_update_config(path, config):
    """Persist non-secret metadata with the same atomicity as ciphertext."""
    path = Path(path)
    info = validate_ovirt_path(path)
    content = (json.dumps(config, indent=4, sort_keys=True) + "\n").encode("utf-8")
    _atomic_write(
        path,
        content,
        owner=(info.st_uid, info.st_gid),
        mode=stat.S_IMODE(info.st_mode),
    )


def transform_file(source, output, passphrase, decrypt=False, config=None,
                   deny_legacy_cbc=False, overwrite=False, allowed_roots=ALLOWED_ROOTS,
                   transit_client=None):
    source = Path(source)
    output = Path(output)
    source_info = validate_ovirt_path(source, allowed_roots=allowed_roots)
    validate_ovirt_path(output, must_exist=output.exists(), allowed_roots=allowed_roots)
    if source.resolve() != output.resolve() and output.exists() and not overwrite:
        raise EncryptorError("Output exists; use --overwrite to replace it")
    data = source.read_bytes()
    if decrypt:
        result = decrypt_bytes(data, passphrase, config, deny_legacy_cbc, transit_client)
        output_mode = 0o600
    else:
        if is_encrypted(data):
            raise EncryptorError("File already uses an encrypted envelope format")
        result = (encrypt_vault_bytes(data, transit_client) if transit_client
                  else encrypt_bytes(data, passphrase))
        # Verify before replacing any persistent file.
        verified = (decrypt_vault_bytes(result, transit_client) if transit_client
                    else decrypt_gcm_bytes(result, passphrase))
        if verified != data:
            raise EncryptorError("Post-encryption self-verification failed")
        output_mode = stat.S_IMODE(source_info.st_mode)
    _atomic_write(
        output,
        result,
        owner=(source_info.st_uid, source_info.st_gid),
        mode=output_mode,
    )


def _parser():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("-e", "--encrypt", action="store_true")
    action.add_argument("-d", "--decrypt", action="store_true")
    parser.add_argument("source")
    parser.add_argument("output", nargs="?")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--secret-file")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--deny-legacy-cbc", action="store_true")
    parser.add_argument("--prompt", action="store_true")
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    try:
        config = _load_crypto_config(args.config)
        transit_client = vault_client_from_config(config)
        passphrase = None
        needs_passphrase = transit_client is None
        if args.decrypt and transit_client is not None:
            with Path(args.source).open("rb") as source:
                needs_passphrase = source.read(len(MAGIC)) == MAGIC
        if needs_passphrase:
            passphrase = obtain_passphrase(
                config, args.secret_file, args.prompt, transit_client
            )
        transform_file(
            args.source,
            args.output or args.source,
            passphrase,
            decrypt=args.decrypt,
            config=config,
            deny_legacy_cbc=args.deny_legacy_cbc,
            overwrite=args.overwrite,
            transit_client=transit_client,
        )
    except (EncryptorError, OSError) as error:
        print("encryptor: %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
