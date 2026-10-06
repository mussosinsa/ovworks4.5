#!/usr/bin/python3
"""Initialize Vault Transit or envelope-encrypt a passphrase file."""

import argparse
import base64
import grp
import os
import pwd
import stat
import sys
import termios
from pathlib import Path

import encryptor

try:
    from ovirt_engine import cryptoevents
except ImportError:  # pragma: no cover - the engine's python library is not installed
    cryptoevents = None

_EVENT_SOURCE = "vault-passphrase"


def _record(event, error=None, **fields):
    """Leaves the result where the engine can report it in the audit log.

    The engine is not running when this runs - these tools are what engine-setup calls - so
    nothing inside it can record what happened here. Never raises, and does nothing at all
    where the engine's python library is not installed: a spool that cannot be written must
    not change what the tool was doing.
    """
    if cryptoevents is None:
        return
    if error is not None:
        fields["reason"] = cryptoevents.reason_for(error)
    cryptoevents.record(getattr(cryptoevents, event), _EVENT_SOURCE, **fields)


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


def read_secret(prompt, stream_in=None, stream_out=None):
    """Reads one line from the terminal without echo, into a bytearray the caller can wipe.

    Not getpass: that returns an immutable str, which Python can never overwrite.
    """
    tty = stream_in or open("/dev/tty", "rb", buffering=0)
    out = stream_out or sys.stderr
    fd = tty.fileno() if stream_in is None else None
    old = None
    if fd is not None:
        old = termios.tcgetattr(fd)
        new = termios.tcgetattr(fd)
        new[3] &= ~termios.ECHO
        termios.tcsetattr(fd, termios.TCSAFLUSH, new)
    secret = bytearray()
    try:
        out.write(prompt)
        out.flush()
        while True:
            char = tty.read(1)
            if not char or char in (b"\n", b"\r"):
                break
            secret += char
            if len(secret) > 4096:
                raise encryptor.EncryptorError("Input is too long")
    finally:
        if old is not None:
            termios.tcsetattr(fd, termios.TCSAFLUSH, old)
        out.write("\n")
        if stream_in is None:
            tty.close()
    return secret


def init_kek_from_passphrase(config_path, config, key_name=None, reader=read_secret,
                             recover=False):
    """Derive the KEK from a passphrase typed in here and import it into Vault Transit.

    Both the passphrase and the Vault token allowed to import are typed in and held in memory
    only; neither is an argument, an environment variable or a file. The derivation record -
    salt, iterations, key name, nothing secret - is written to config.json.
    """
    settings = config.get("vault_transit")
    if not isinstance(settings, dict) or settings.get("enabled") is not True:
        raise encryptor.EncryptorError("An enabled vault_transit object is required")
    token = passphrase = again = None
    try:
        token = reader("Vault token allowed to import the KEK: ")
        passphrase = reader("KEK passphrase (initial data, %d+ characters): "
                            % encryptor.KEK_MIN_PASSPHRASE)
        again = reader("KEK passphrase again: ")
        if passphrase != again:
            raise encryptor.EncryptorError("The two passphrases differ")
        effective = dict(settings)
        if key_name:
            effective["key_name"] = key_name
        previous = config.get("kek_derivation")
        pending = isinstance(previous, dict) and previous.get("status") == "pending"
        if recover or pending:
            # The same KEK as before: into a Vault that lost it, or to finish an import whose
            # record was left pending - the recorded salt and key name, and the passphrase
            # kept offline.
            if not isinstance(previous, dict) or not previous.get("salt"):
                raise encryptor.EncryptorError(
                    "config.json has no kek_derivation record to recover from")
            salt = base64.b64decode(previous["salt"], validate=True)
            effective["key_name"] = previous.get("key_name", effective.get("key_name"))
        else:
            salt = encryptor.new_kek_salt()
            # Recorded before the import, so a failure after it cannot lose the salt.
            config["kek_derivation"] = dict(
                encryptor.kek_derivation_record(
                    salt, effective.get("key_name", "ovirt-engine-config")),
                status="pending")
            encryptor.atomic_update_config(config_path, config)
        try:
            record = encryptor.provision_pbkdf2_kek(
                effective, token, passphrase, salt=salt, adopt_existing=pending)
        except Exception as error:
            _record("KEY_CREATION_FAILED", error)
            raise
    finally:
        for secret in (token, passphrase, again):
            encryptor.wipe(secret)
    _record("KEY_CREATED")
    config["kek_derivation"] = record
    encryptor.atomic_update_config(config_path, config)
    print("Imported the PBKDF2-derived KEK into Vault Transit key %s%s" % (
        record["key_name"],
        "" if record.get("verified") is True else
        " (WARNING: not verified through the service token - check its policy covers this key)",
    ))
    return record


def _rewrap_targets(config):
    """The files a key change re-encrypts: the encrypted configuration files and the encrypted
    passphrase file, as encrypt_conf_files.py finds them."""
    names = set(config.get("allowed_files", sorted(encryptor.ALLOWED_CONFIG_BASENAMES)))
    if not names <= encryptor.ALLOWED_CONFIG_BASENAMES:
        raise encryptor.EncryptorError("allowed_files contains an unapproved filename")
    targets = []
    for root in config.get("watch_path", [str(path) for path in encryptor.ALLOWED_ROOTS]):
        root = Path(root)
        if not encryptor._within_allowed_root(root) or root.is_symlink() or not root.is_dir():
            continue
        for directory, directories, files in os.walk(root, followlinks=False):
            directories[:] = [d for d in directories if not (Path(directory) / d).is_symlink()]
            for name in files:
                path = Path(directory) / name
                if name in names and not path.is_symlink() and path.is_file():
                    targets.append(path)
    secret_file = config.get("secret_file")
    if secret_file and Path(secret_file).is_file():
        targets.append(Path(secret_file))
    return [path for path in targets if path.read_bytes()[:8] == encryptor.VAULT_MAGIC]


def rewrap_to_key(config_path, config, new_key):
    """Re-encrypts every OVVLT001 file from the configured Transit key to new_key, then makes
    new_key the configured one.

    Every file is decrypted, re-encrypted and verified in memory before any is written, and a
    file that already opens with the new key is left as it is, so a run that stopped half way
    is finished by running it again.
    """
    settings = config.get("vault_transit")
    if not isinstance(settings, dict) or settings.get("enabled") is not True:
        raise encryptor.EncryptorError("An enabled vault_transit object is required")
    old_client = encryptor.VaultTransitClient(settings)
    new_client = encryptor.VaultTransitClient(settings, key_name=new_key)
    if old_client.key_name == new_client.key_name:
        raise encryptor.EncryptorError("The new key is the configured key")
    probe = encryptor.random_bytes(encryptor.DATA_KEY_SIZE)
    if new_client.unwrap(new_client.wrap(probe)) != probe:
        raise encryptor.EncryptorError(
            "The service token cannot use %s; add it to the token's policy first" % new_key)
    pending = []
    for path in _rewrap_targets(config):
        data = path.read_bytes()
        try:
            plaintext = encryptor.decrypt_vault_bytes(data, old_client)
        except encryptor.EncryptorError:
            encryptor.decrypt_vault_bytes(data, new_client)   # already rewrapped, or raises
            continue
        rewrapped = encryptor.encrypt_vault_bytes(plaintext, new_client)
        if encryptor.decrypt_vault_bytes(rewrapped, new_client) != plaintext:
            raise encryptor.EncryptorError("Post-encryption self-verification failed: %s" % path)
        pending.append((path, rewrapped))
    scheme = encryptor.VAULT_MAGIC.decode("ascii")
    for path, rewrapped in pending:
        info = path.stat()
        encryptor._atomic_write(path, rewrapped, owner=(info.st_uid, info.st_gid),
                                mode=stat.S_IMODE(info.st_mode))
        _record("ENCRYPTION_COMPLETED", file=path.name, scheme=scheme)
        print("Re-encrypted under %s: %s" % (new_key, path))
    settings["key_name"] = new_key
    encryptor.atomic_update_config(config_path, config)
    print("Configured Vault Transit key is now %s; restart ovirt-engine, then remove %s from "
          "Vault and from the service token's policy" % (new_key, old_client.key_name))
    return len(pending)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--init-key", action="store_true",
                        help="legacy: let Vault generate a random KEK")
    action.add_argument("--init-kek-from-passphrase", action="store_true",
                        help="derive the KEK with PBKDF2 from a passphrase typed in, and "
                             "import it into Vault Transit")
    action.add_argument("--rewrap-to-key", metavar="KEY_NAME",
                        help="re-encrypt the encrypted files under another Transit key and "
                             "make it the configured one")
    action.add_argument("--check", action="store_true")
    action.add_argument("--encrypt", action="store_true")
    action.add_argument("--encrypt-in-place", action="store_true")
    action.add_argument("--install-token-stdin", action="store_true")
    parser.add_argument("source", nargs="?")
    parser.add_argument("output", nargs="?")
    parser.add_argument("--config", default=str(encryptor.DEFAULT_CONFIG))
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--key-name", help="with --init-kek-from-passphrase: the Transit key "
                                           "to create instead of the configured one")
    parser.add_argument("--recover", action="store_true",
                        help="with --init-kek-from-passphrase: re-create the recorded KEK "
                             "(salt from config.json) in a Vault that lost it")
    args = parser.parse_args(argv)
    try:
        config = encryptor._load_crypto_config(args.config)
        if args.init_kek_from_passphrase:
            init_kek_from_passphrase(args.config, config, key_name=args.key_name,
                                     recover=args.recover)
            return 0
        if args.rewrap_to_key:
            rewrap_to_key(args.config, config, args.rewrap_to_key)
            return 0
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
            # The key-encryption key. Vault generates it and keeps it; it never leaves Vault,
            # so this is the only record on this host that it was asked for.
            try:
                client.ensure_key()
            except Exception as error:
                _record("KEY_CREATION_FAILED", error)
                raise
            _record("KEY_CREATED")
            return 0
        if args.check:
            probe = encryptor.random_bytes(encryptor.DATA_KEY_SIZE)
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
        scheme = encryptor.VAULT_MAGIC.decode("ascii")
        try:
            # A data key of its own, wrapped by the key-encryption key above.
            encrypted = encryptor.encrypt_vault_bytes(plaintext, client)
            if encryptor.decrypt_vault_bytes(encrypted, client) != plaintext:
                raise encryptor.EncryptorError("Post-encryption self-verification failed")
        except Exception as error:
            _record("ENCRYPTION_FAILED", error, file=output.name, scheme=scheme)
            raise
        _record("ENCRYPTION_COMPLETED", file=output.name, scheme=scheme)
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
