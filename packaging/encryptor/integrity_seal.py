#!/usr/bin/python3
"""Seal the integrity verification's baseline, and check the seal before every verification.

AIDE compares the measured files against a database of their hashes (SHA-512) written by
engine-setup. That database, and the configuration naming what it measures, are files like any
other: whoever can change the files measured could change those two to match and the
verification would pass. They are sealed, then, with an HMAC-SHA256 under a key only the
installation's DEK yields - and the DEK is only had with the KEK passphrase held in memory:

  seal key   HMAC-SHA256(DEK, "ovworks integrity baseline seal v1")
  seal       HMAC-SHA256(seal key, "<name>\\0" || SHA-512(file)), for the configuration and the
             database each, so that a mismatch names which of the two no longer matches

  --seal     after engine-setup has taken the baseline (root)
  --verify   before every verification, through the sudo rule engine-setup writes (root):
             exit 0 the seal matches; 3 it does not, and the file is printed as AIDE prints a
             changed or removed one; 2 it could not be checked (no seal, no passphrase in memory,
             another DEK)

Takes no paths from its caller: the sudo rule lets the engine's account run --verify and nothing
else, and what it checks is fixed here.
"""

import argparse
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import encryptor  # noqa: E402


AIDE_CONFIG = Path("/etc/ovirt-engine/aide/ovworks-aide.conf")
DATABASE = Path("/var/lib/aide/ovworks.db.gz")
SEAL = Path("/var/lib/aide/ovworks.db.seal")

_KEY_LABEL = b"ovworks integrity baseline seal v1"
VERSION = 1

EXIT_TAMPERED = 3
EXIT_UNVERIFIABLE = 2


class SealError(Exception):
    """The seal could not be made or checked."""


def seal_key(dek):
    return hmac.new(bytes(dek), _KEY_LABEL, hashlib.sha256).digest()


def file_mac(key, name, path):
    digest = hashlib.sha512(Path(path).read_bytes()).digest()
    return hmac.new(key, name.encode("ascii") + b"\0" + digest, hashlib.sha256).hexdigest()


def _dek(config_path):
    config = encryptor._load_crypto_config(config_path)
    if encryptor.memory_kek_settings(config) is None:
        raise SealError("the configuration is not encrypted under a DEK, so nothing seals the baseline")
    try:
        passphrase = encryptor.obtain_passphrase(config)
    except encryptor.EncryptorError as error:
        raise SealError("the KEK passphrase is not available: %s" % error) from error
    try:
        return encryptor.read_dek(config, passphrase)
    except encryptor.EncryptorError as error:
        raise SealError("the DEK is not available: %s" % error) from error
    finally:
        encryptor.wipe(passphrase)


def make_seal(dek, aide_config, database):
    key = seal_key(dek)
    return {
        "version": VERSION,
        "dek_id": encryptor.dek_id(dek).hex(),
        "config": file_mac(key, "config", aide_config),
        "database": file_mac(key, "database", database),
        "sealed_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def check_seal(dek, seal, aide_config, database):
    """@return the files that no longer match, as (kind, path); raises SealError if unverifiable"""
    if seal.get("version") != VERSION:
        raise SealError("the seal is of an unknown version")
    if seal.get("dek_id") != encryptor.dek_id(dek).hex():
        raise SealError("the baseline was sealed under another DEK; run engine-setup")
    key = seal_key(dek)
    mismatched = []
    for name, path in (("config", aide_config), ("database", database)):
        path = Path(path)
        if not path.exists():
            mismatched.append(("removed", path))
        elif not hmac.compare_digest(file_mac(key, name, path), str(seal.get(name, ""))):
            mismatched.append(("changed", path))
    return mismatched


def seal(config_path=encryptor.DEFAULT_CONFIG, aide_config=AIDE_CONFIG, database=DATABASE,
         seal_path=SEAL):
    dek = _dek(config_path)
    try:
        record = make_seal(dek, aide_config, database)
    finally:
        encryptor.wipe(dek)
    encryptor._atomic_write(Path(seal_path), (json.dumps(record, indent=2) + "\n").encode("utf-8"),
                            mode=0o600)


def verify(config_path=encryptor.DEFAULT_CONFIG, aide_config=AIDE_CONFIG, database=DATABASE,
           seal_path=SEAL, out=sys.stdout):
    """@return the exit code"""
    try:
        try:
            record = json.loads(Path(seal_path).read_text(encoding="utf-8"))
        except FileNotFoundError as error:
            raise SealError("the baseline is not sealed (%s); run engine-setup" % seal_path) from error
        except (OSError, ValueError) as error:
            raise SealError("the seal cannot be read: %s" % error) from error
        dek = _dek(config_path)
        try:
            mismatched = check_seal(dek, record, aide_config, database)
        finally:
            encryptor.wipe(dek)
    except SealError as error:
        print("integrity_seal: %s" % error, file=sys.stderr)
        return EXIT_UNVERIFIABLE
    if mismatched:
        print("Baseline seal mismatch: the integrity baseline or its configuration was altered", file=out)
        for kind, path in mismatched:
            print("%s: %s" % (kind, path), file=out)
        return EXIT_TAMPERED
    print("Baseline seal verified (HMAC-SHA256): %s, %s" % (aide_config, database), file=out)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--seal", action="store_true")
    action.add_argument("--verify", action="store_true")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("integrity_seal: this must run as root", file=sys.stderr)
        return EXIT_UNVERIFIABLE
    if args.verify:
        return verify()
    try:
        seal()
    except (SealError, encryptor.EncryptorError, OSError) as error:
        print("integrity_seal: %s" % error, file=sys.stderr)
        return 1
    print("Integrity baseline sealed: %s" % SEAL)
    return 0


if __name__ == "__main__":
    sys.exit(main())
