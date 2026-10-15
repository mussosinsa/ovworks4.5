#!/usr/bin/python3
"""Hand the engine the installation's DEK for the duration of one run.

The engine encrypts what it keeps of a user's terminal serial under the DEK (``OVENC002``, the
envelope the configuration files use), and opens it again at every login. The DEK is kept only
wrapped by the KEK (``dek.enc``); the engine's Java process cannot unwrap it, so the launcher has
it unwrapped here before Java starts, the way the login private key is (``login_key.py``):

  --write <path>   at engine start, as the engine account. Writes the 32-byte DEK to <path> (0600,
                   in a private runtime directory removed when the engine stops; the launcher
                   overwrites it three times with zeros before it goes). The opening is recorded
                   as DEK_DECRYPTION_COMPLETED / _FAILED like every other.

An installation whose configuration is not under a DEK has nothing to hand over; that is reported
with its own message and exit code, and the launcher starts the engine without it.
"""

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import encryptor  # noqa: E402

EXIT_ERROR = 1
EXIT_NO_DEK = 3

SOURCE = "engine-runtime-dek"


class RuntimeDekError(Exception):
    """The DEK could not be handed to the engine."""


class NoDekError(RuntimeDekError):
    """The configuration is not encrypted under a DEK."""


def _dek(config_path):
    config = encryptor._load_crypto_config(config_path)
    if encryptor.memory_kek_settings(config) is None:
        raise NoDekError("the configuration is not encrypted under a DEK")
    try:
        passphrase = encryptor.obtain_passphrase(config)
    except encryptor.EncryptorError as error:
        raise RuntimeDekError("the KEK passphrase is not available: %s" % error) from error
    try:
        return encryptor.read_dek(config, passphrase, source=SOURCE)
    except encryptor.EncryptorError as error:
        raise RuntimeDekError("the DEK is not available: %s" % error) from error
    finally:
        encryptor.wipe(passphrase)


def write(out_path, config_path=encryptor.DEFAULT_CONFIG):
    """Writes the DEK to out_path (0600) for the engine, and wipes the copy held here."""
    dek = _dek(config_path)
    try:
        if len(dek) != encryptor.DATA_KEY_SIZE:
            raise RuntimeDekError("the DEK has an unexpected length")
        encryptor._atomic_write(Path(out_path), bytes(dek), mode=0o600)
    finally:
        encryptor.wipe(dek)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--write", metavar="PATH", required=True,
                        help="write the DEK to PATH for the engine to read")
    args = parser.parse_args(argv)
    try:
        write(args.write)
    except NoDekError as error:
        print("runtime_dek: no DEK: %s" % error, file=sys.stderr)
        return EXIT_NO_DEK
    except (RuntimeDekError, encryptor.EncryptorError, OSError) as error:
        print("runtime_dek: %s" % error, file=sys.stderr)
        return EXIT_ERROR
    return 0


if __name__ == "__main__":
    sys.exit(main())
