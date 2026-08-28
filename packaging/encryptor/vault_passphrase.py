#!/usr/bin/python3
"""Initialize Vault Transit or envelope-encrypt a passphrase file."""

import argparse
import stat
import sys
from pathlib import Path

import encryptor


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--init-key", action="store_true")
    action.add_argument("--encrypt", action="store_true")
    parser.add_argument("source", nargs="?")
    parser.add_argument("output", nargs="?")
    parser.add_argument("--config", default=str(encryptor.DEFAULT_CONFIG))
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args(argv)
    try:
        config = encryptor._load_crypto_config(args.config)
        client = encryptor.vault_client_from_config(config)
        if client is None:
            raise encryptor.EncryptorError("Vault Transit is not enabled")
        if args.init_key:
            client.ensure_key()
            return 0
        if not args.source or not args.output:
            raise encryptor.EncryptorError("SOURCE and OUTPUT are required for --encrypt")
        source, output = Path(args.source), Path(args.output)
        info = encryptor._validate_regular_file(source, reject_writable=True)
        if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise encryptor.EncryptorError("Passphrase file permissions must be 0600 or stricter")
        if output.exists() and not args.overwrite:
            raise encryptor.EncryptorError("Output exists; use --overwrite to replace it")
        plaintext = source.read_bytes().rstrip(b"\r\n")
        if not plaintext:
            raise encryptor.EncryptorError("Passphrase file is empty")
        if encryptor.is_encrypted(plaintext):
            raise encryptor.EncryptorError("Passphrase file is already encrypted")
        encrypted = encryptor.encrypt_vault_bytes(plaintext, client)
        if encryptor.decrypt_vault_bytes(encrypted, client) != plaintext:
            raise encryptor.EncryptorError("Post-encryption self-verification failed")
        encryptor._atomic_write(output, encrypted, mode=0o600)
    except (encryptor.EncryptorError, OSError) as error:
        print("vault_passphrase: %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
