#!/usr/bin/python3
"""Authenticated encryption for sensitive oVirt configuration files."""

import argparse
import base64
import getpass
import json
import os
import stat
import struct
import sys
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"OVENC001"
VERSION = 1
PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16
NONCE_SIZE = 12
DATA_KEY_SIZE = 32
WRAPPED_KEY_SIZE = DATA_KEY_SIZE + 16
HEADER = struct.Struct(">8sBI16s12s12sH")
DEFAULT_CONFIG = Path("/etc/ovirt-engine/encryptor/config.json")
DEFAULT_CREDENTIAL = "ovirt-encryptor-passphrase"
PASSPHRASE_ENV = "OVIRT_ENCRYPTOR_PASSPHRASE"
ALLOWED_ROOTS = (Path("/etc/ovirt-engine"), Path("/etc/ovirt-engine-dwh"))
# Keep /etc/ovirt-engine/aaa/internal.properties out of tree encryption:
# ovirt-engine-extension-aaa-jdbc reads it directly from config.datasource.file
# while loading authentication/authorization extensions.
ALLOWED_CONFIG_BASENAMES = frozenset((
    "10-setup-database.conf",
    "10-setup-dwh-database.conf",
))


class EncryptorError(RuntimeError):
    """A safe, user-facing encryption failure."""


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
    return prefix == MAGIC


def _read_secret_file(path):
    info = _validate_regular_file(path, reject_writable=True)
    if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise EncryptorError("Passphrase file permissions must be 0600 or stricter")
    with Path(path).open("rb") as stream:
        secret = stream.read().rstrip(b"\r\n")
    if not secret:
        raise EncryptorError("Passphrase file is empty")
    return secret


def obtain_passphrase(config, secret_file=None, allow_prompt=False):
    """Load a passphrase without hardware identifiers or command-line values."""
    credential_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    credential_name = config.get("systemd_credential", DEFAULT_CREDENTIAL)
    if credential_dir:
        credential_path = Path(credential_dir) / credential_name
        if credential_path.exists():
            return _read_secret_file(credential_path)
    environment_secret = os.environ.get(PASSPHRASE_ENV)
    if environment_secret:
        return environment_secret.encode("utf-8")
    configured_file = secret_file or config.get("secret_file")
    if configured_file:
        return _read_secret_file(configured_file)
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


def decrypt_bytes(data, passphrase, config=None, deny_legacy_cbc=False):
    if data.startswith(MAGIC):
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
                   deny_legacy_cbc=False, overwrite=False, allowed_roots=ALLOWED_ROOTS):
    source = Path(source)
    output = Path(output)
    source_info = validate_ovirt_path(source, allowed_roots=allowed_roots)
    validate_ovirt_path(output, must_exist=output.exists(), allowed_roots=allowed_roots)
    if source.resolve() != output.resolve() and output.exists() and not overwrite:
        raise EncryptorError("Output exists; use --overwrite to replace it")
    data = source.read_bytes()
    if decrypt:
        result = decrypt_bytes(data, passphrase, config, deny_legacy_cbc)
        output_mode = 0o600
    else:
        if is_encrypted(data):
            raise EncryptorError("File already uses the OVENC001 encrypted format")
        result = encrypt_bytes(data, passphrase)
        # Verify before replacing any persistent file.
        if decrypt_gcm_bytes(result, passphrase) != data:
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
        passphrase = obtain_passphrase(config, args.secret_file, args.prompt)
        transform_file(
            args.source,
            args.output or args.source,
            passphrase,
            decrypt=args.decrypt,
            config=config,
            deny_legacy_cbc=args.deny_legacy_cbc,
            overwrite=args.overwrite,
        )
    except (EncryptorError, OSError) as error:
        print("encryptor: %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
