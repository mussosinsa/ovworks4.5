#!/usr/bin/python3
"""Initialize Vault Transit or envelope-encrypt a passphrase file."""

import argparse
import grp
import os
import pwd
import stat
import sys
from pathlib import Path

import encryptor


def install_token_from_stream(config, stream, overwrite=False):
    """Install a pre-issued Vault application token without command-line exposure."""
    settings = config.get("vault_transit")
    if not isinstance(settings, dict) or settings.get("enabled") is not True:
        raise encryptor.EncryptorError(
            "An enabled vault_transit object is required to install its token"
        )
    if os.geteuid() != 0:
        raise encryptor.EncryptorError("Vault token installation must run as root")
    token_file = Path(settings.get(
        "token_file", "/etc/ovirt-engine/encryptor/vault-token"
    ))
    approved_directory = Path("/etc/ovirt-engine/encryptor").resolve()
    if token_file.parent.resolve() != approved_directory:
        raise encryptor.EncryptorError(
            "Token installation is restricted to /etc/ovirt-engine/encryptor"
        )
    encryptor.validate_ovirt_path(
        token_file,
        must_exist=token_file.exists(),
    )
    if token_file.exists() and not overwrite:
        raise encryptor.EncryptorError(
            "Vault token file exists; use --overwrite to rotate it"
        )
    try:
        engine_user = pwd.getpwnam("ovirt")
        engine_group = grp.getgrnam("ovirt")
    except KeyError as error:
        raise encryptor.EncryptorError(
            "The ovirt service account is required to install its Vault token"
        ) from error
    os.chown(approved_directory, 0, engine_group.gr_gid)
    os.chmod(approved_directory, 0o750)
    token = stream.read(4097).strip()
    if (
        not token or
        len(token) > 4096 or
        any(byte <= 0x20 or byte > 0x7e for byte in token)
    ):
        raise encryptor.EncryptorError(
            "Vault token from standard input is empty or malformed"
        )
    encryptor._atomic_write(
        token_file,
        token + b"\n",
        owner=(engine_user.pw_uid, engine_group.gr_gid),
        mode=0o600,
    )
    print("Installed Vault application token: %s" % token_file)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--init-key", action="store_true")
    action.add_argument("--check", action="store_true")
    action.add_argument("--encrypt", action="store_true")
    action.add_argument("--encrypt-in-place", action="store_true")
    action.add_argument("--install-token-stdin", action="store_true")
    parser.add_argument("source", nargs="?")
    parser.add_argument("output", nargs="?")
    parser.add_argument("--config", default=str(encryptor.DEFAULT_CONFIG))
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args(argv)
    try:
        config = encryptor._load_crypto_config(args.config)
        if args.install_token_stdin:
            install_token_from_stream(
                config,
                sys.stdin.buffer,
                overwrite=args.overwrite,
            )
            return 0
        client = encryptor.vault_client_from_config(config)
        if client is None:
            state = (
                "missing vault_transit object"
                if "vault_transit" not in config
                else "vault_transit.enabled is false"
            )
            raise encryptor.EncryptorError(
                "Vault Transit is not enabled in %s (%s)" %
                (args.config, state)
            )
        if args.init_key:
            client.ensure_key()
            return 0
        if args.check:
            probe = os.urandom(encryptor.DATA_KEY_SIZE)
            if client.unwrap(client.wrap(probe)) != probe:
                raise encryptor.EncryptorError(
                    "Vault Transit preflight round trip failed"
                )
            print("Vault Transit preflight succeeded")
            return 0
        if args.encrypt_in_place:
            if not args.source or args.output:
                raise encryptor.EncryptorError(
                    "SOURCE only is required for --encrypt-in-place"
                )
            source = output = Path(args.source)
            args.overwrite = True
        else:
            if not args.source or not args.output:
                raise encryptor.EncryptorError(
                    "SOURCE and OUTPUT are required for --encrypt"
                )
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
        encryptor._atomic_write(
            output,
            encrypted,
            owner=(info.st_uid, info.st_gid),
            mode=0o600,
        )
    except (encryptor.EncryptorError, OSError) as error:
        print("vault_passphrase: %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
