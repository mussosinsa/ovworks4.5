#!/usr/bin/python3
#
# Copyright 새올정보기술 (OV-Works), 2026
# SPDX-License-Identifier: Apache-2.0
#
"""Keep the web administration login's RSA private key encrypted at rest under the DEK.

The browser encrypts the user's name and password to this engine's RSA public key (RSA-OAEP,
SHA-256) before it leaves the client; the engine opens them with the matching private key
(``LoginEnvelopeCrypto``). That private key is a file - ``/etc/ovirt-engine/encryptor/
private_pkcs8.der`` - and until now it was a plaintext PKCS#8 DER protected only by its file
permissions.

It is now kept as an AES-256-GCM envelope (``OVENC002``) under the installation's DEK, the same
key and envelope the configuration files use, so that a copy of the file alone does not yield the
key:

  --encrypt         after engine-setup has the DEK and the KEK passphrase in memory (root). Idempotent:
                    a file already enveloped is left as it is, and a file that is not there is not an
                    error - an installation that does not use login encryption simply has no key.
  --decrypt <path>  at engine start, before Java is launched (the engine account). Writes the
                    plaintext key to <path> (0600, meant for a private runtime directory removed
                    when the engine stops) for ``LoginEnvelopeCrypto`` to read. A key still stored
                    in plaintext (an installation upgraded before this change, before engine-setup
                    re-encrypts it) is passed through unchanged, so the first start after an upgrade
                    does not fail.

Takes no path from its caller but the one --decrypt writes to, which the engine's launcher fixes;
the key read and encrypted in place is fixed here.
"""

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import encryptor  # noqa: E402


PRIVATE_KEY = Path("/etc/ovirt-engine/encryptor/private_pkcs8.der")

EXIT_ERROR = 1


class LoginKeyError(Exception):
    """The login private key could not be encrypted or decrypted."""


def _dek(config_path):
    config = encryptor._load_crypto_config(config_path)
    if encryptor.memory_kek_settings(config) is None:
        raise LoginKeyError(
            "the configuration is not encrypted under a DEK, so the login key cannot be sealed")
    try:
        passphrase = encryptor.obtain_passphrase(config)
    except encryptor.EncryptorError as error:
        raise LoginKeyError("the KEK passphrase is not available: %s" % error) from error
    try:
        return encryptor.read_dek(config, passphrase, source="login-key")
    except encryptor.EncryptorError as error:
        raise LoginKeyError("the DEK is not available: %s" % error) from error
    finally:
        encryptor.wipe(passphrase)


def _is_encrypted(data):
    return data[:len(encryptor.ENVELOPE_MAGIC)] == encryptor.ENVELOPE_MAGIC


def encrypt(config_path=encryptor.DEFAULT_CONFIG, key_path=PRIVATE_KEY):
    """Encrypts the login private key in place under the DEK (AES-256-GCM). Idempotent.

    Keeps the file's owner and mode, so the key a decryption later writes is as private as the
    key was. A key that is not there is not encrypted and is not an error.
    """
    path = Path(key_path)
    if not path.exists():
        return False
    data = path.read_bytes()
    if _is_encrypted(data):
        return False
    info = path.stat()
    dek = _dek(config_path)
    try:
        ciphertext = encryptor.encrypt_envelope(data, dek)
        # Opened back before the plaintext is replaced: a file that cannot be decrypted again is
        # a file the engine could not start with, and is not written over the one that works.
        encryptor.decrypt_envelope(ciphertext, dek)
    finally:
        encryptor.wipe(dek)
    encryptor._atomic_write(path, ciphertext, owner=(info.st_uid, info.st_gid),
                            mode=0o600)
    encryptor.wipe(bytearray(data))
    return True


def decrypt(out_path, config_path=encryptor.DEFAULT_CONFIG, key_path=PRIVATE_KEY):
    """Writes the plaintext login private key to out_path (0600) for Java to read.

    A key still stored in plaintext (before engine-setup re-encrypts it) is passed through as it
    is. @return True when a key was written, False when there is no key to write.
    """
    path = Path(key_path)
    if not path.exists():
        return False
    data = path.read_bytes()
    if _is_encrypted(data):
        dek = _dek(config_path)
        try:
            plaintext = encryptor.decrypt_envelope(data, dek)
        finally:
            encryptor.wipe(dek)
    else:
        plaintext = data
    encryptor._atomic_write(Path(out_path), plaintext, mode=0o600)
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--encrypt", action="store_true",
                        help="encrypt the login private key in place under the DEK")
    action.add_argument("--decrypt", metavar="PATH",
                        help="write the plaintext login private key to PATH for the engine to read")
    args = parser.parse_args(argv)
    if os.geteuid() != 0 and args.encrypt:
        print("login_key: --encrypt must run as root", file=sys.stderr)
        return EXIT_ERROR
    try:
        if args.encrypt:
            if encrypt():
                print("Login private key encrypted at rest: %s" % PRIVATE_KEY)
            else:
                print("Login private key needs no encryption: %s" % PRIVATE_KEY)
            return 0
        wrote = decrypt(args.decrypt)
        if not wrote:
            print("login_key: no login private key to decrypt: %s" % PRIVATE_KEY,
                  file=sys.stderr)
            return EXIT_ERROR
        return 0
    except (LoginKeyError, encryptor.EncryptorError, OSError) as error:
        print("login_key: %s" % error, file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
