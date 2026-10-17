#!/usr/bin/python3
#
# Copyright 새올정보기술 (OV-Works), 2026
# SPDX-License-Identifier: Apache-2.0
#
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
import contextlib
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import encryptor  # noqa: E402


AIDE_CONFIG = Path("/etc/ovirt-engine/aide/ovworks-aide.conf")
DATABASE = Path("/var/lib/aide/ovworks.db.gz")
SEAL = Path("/var/lib/aide/ovworks.db.seal")

# The baseline is kept encrypted at rest (AES-256-GCM under the DEK). AIDE cannot read the
# ciphertext, so --open decrypts it to a plaintext copy on tmpfs (memory, never the disk) and
# writes a throwaway AIDE configuration that points at that copy; --close shreds both afterwards.
# Fixed paths, so the sudo rule needs no caller-supplied path (which would let the caller have
# root write anywhere).
TMP_DIR = Path("/dev/shm")  # noqa: S108 - tmpfs, 0600, removed right after the check
TMP_DATABASE = TMP_DIR / "ovworks-aide.db.gz"
TMP_CONFIG = TMP_DIR / "ovworks-aide.conf"

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
        return encryptor.read_dek(config, passphrase, source="integrity-seal")
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


def _is_encrypted(data):
    return data[:len(encryptor.ENVELOPE_MAGIC)] == encryptor.ENVELOPE_MAGIC


def encrypt_database(dek, database):
    """Encrypts the baseline in place under the DEK (AES-256-GCM). Idempotent."""
    path = Path(database)
    data = path.read_bytes()
    if _is_encrypted(data):
        return
    ciphertext = encryptor.encrypt_envelope(data, dek)
    encryptor._atomic_write(path, ciphertext, mode=0o600)
    encryptor.wipe(bytearray(data))


def decrypt_database(dek, database, out_path):
    """Writes the plaintext baseline to out_path (tmpfs, 0600) for AIDE to read.

    A baseline from before encryption was added is still plaintext; it is used as it is, so an
    upgrade's first verification does not fail before engine-setup re-seals (and encrypts) it.
    """
    data = Path(database).read_bytes()
    plaintext = encryptor.decrypt_envelope(data, dek) if _is_encrypted(data) else data
    encryptor._atomic_write(Path(out_path), plaintext, mode=0o600)


AIDE_COMMAND = "/usr/sbin/aide"


def installed_aide_database_key(run=None):
    """The option naming the input database for the AIDE installed now: database_in from 0.17 on
    (0.18 dropped the old name), database before. The current name when it cannot be told."""
    try:
        if run is None:
            completed = subprocess.run([AIDE_COMMAND, "--version"], stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, universal_newlines=True,
                                       check=False, timeout=30)
            output = (completed.stdout or "") + "\n" + (completed.stderr or "")
        else:
            output = run()
    except (OSError, subprocess.SubprocessError):
        return "database_in"
    match = re.search(r"\baide\s+v?(\d+)\.(\d+)", output or "", re.IGNORECASE)
    if match and (int(match.group(1)), int(match.group(2))) < (0, 17):
        return "database"
    return "database_in"


def write_open_config(aide_config, database_path, out_path, database_key=None):
    """Writes a throwaway AIDE configuration that reads the decrypted baseline at database_path.

    Only the input database line is rewritten - named for the AIDE installed now, so that an AIDE
    updated since engine-setup still reads it; everything else - the files measured and how - is
    the sealed configuration's, which --open has just verified.
    """
    key = database_key or installed_aide_database_key()
    lines = []
    for line in Path(aide_config).read_text(encoding="utf-8").splitlines():
        if line.startswith("database=") or line.startswith("database_in="):
            lines.append(key + "=file:" + str(database_path))
        else:
            lines.append(line)
    encryptor._atomic_write(Path(out_path), ("\n".join(lines) + "\n").encode("utf-8"), mode=0o600)


def _shred(path):
    path = Path(path)
    try:
        if path.exists():
            with open(path, "r+b") as stream:
                length = stream.seek(0, os.SEEK_END)
                stream.seek(0)
                stream.write(b"\0" * length)
                stream.flush()
                os.fsync(stream.fileno())
            path.unlink()
    except OSError:
        with contextlib.suppress(OSError):
            path.unlink()


def seal(config_path=encryptor.DEFAULT_CONFIG, aide_config=AIDE_CONFIG, database=DATABASE,
         seal_path=SEAL):
    dek = _dek(config_path)
    try:
        # Encrypt the baseline first, then seal over the ciphertext: the seal names the file as it
        # is stored, and the GCM envelope already binds it to this DEK and detects tampering.
        encrypt_database(dek, database)
        record = make_seal(dek, aide_config, database)
    finally:
        encryptor.wipe(dek)
    encryptor._atomic_write(Path(seal_path), (json.dumps(record, indent=2) + "\n").encode("utf-8"),
                            mode=0o600)


def open_baseline(config_path=encryptor.DEFAULT_CONFIG, aide_config=AIDE_CONFIG, database=DATABASE,
                  seal_path=SEAL, tmp_database=TMP_DATABASE, tmp_config=TMP_CONFIG, out=sys.stdout):
    """Verifies the seal, then decrypts the baseline to tmpfs so AIDE can read it.

    @return the exit code: 0 ready (tmp_config written), 3 the baseline was altered, 2 it could
    not be checked or decrypted. Leaves no plaintext behind on any path but the success one, which
    --close removes.
    """
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
            if mismatched:
                print("Baseline seal mismatch: the integrity baseline or its configuration was altered",
                      file=out)
                for kind, path in mismatched:
                    print("%s: %s" % (kind, path), file=out)
                return EXIT_TAMPERED
            decrypt_database(dek, database, tmp_database)
        finally:
            encryptor.wipe(dek)
        write_open_config(aide_config, tmp_database, tmp_config)
    except (SealError, encryptor.EncryptorError) as error:
        close_baseline(tmp_database, tmp_config)
        print("integrity_seal: %s" % error, file=sys.stderr)
        return EXIT_UNVERIFIABLE
    except OSError as error:
        close_baseline(tmp_database, tmp_config)
        print("integrity_seal: the baseline could not be opened: %s" % error, file=sys.stderr)
        return EXIT_UNVERIFIABLE
    print("Baseline opened for verification: %s" % tmp_config, file=out)
    return 0


def close_baseline(tmp_database=TMP_DATABASE, tmp_config=TMP_CONFIG):
    """Shreds the decrypted baseline and the throwaway configuration. Always safe to call."""
    _shred(tmp_database)
    _shred(tmp_config)
    return 0


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
    action.add_argument("--open", dest="open_", action="store_true",
                        help="verify the seal and decrypt the baseline to tmpfs for AIDE")
    action.add_argument("--close", action="store_true",
                        help="remove the decrypted baseline left on tmpfs by --open")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("integrity_seal: this must run as root", file=sys.stderr)
        return EXIT_UNVERIFIABLE
    if args.verify:
        return verify()
    if args.open_:
        return open_baseline()
    if args.close:
        return close_baseline()
    try:
        seal()
    except (SealError, encryptor.EncryptorError, OSError) as error:
        print("integrity_seal: %s" % error, file=sys.stderr)
        return 1
    print("Integrity baseline sealed: %s" % SEAL)
    return 0


if __name__ == "__main__":
    sys.exit(main())
