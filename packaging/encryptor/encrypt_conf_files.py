#!/usr/bin/python3
"""Encrypt approved regular files below configured oVirt watch paths."""

import argparse
import os
import stat
import sys
import syslog
from pathlib import Path

import encryptor


def _audit(status, mode, file_count=0):
    """Write a secret-free OS audit record for privileged encryption work."""
    priority = syslog.LOG_INFO if status == "success" else syslog.LOG_ERR
    syslog.openlog("ovirt-encrypt-conf", syslog.LOG_PID, syslog.LOG_AUTHPRIV)
    try:
        syslog.syslog(
            priority,
            "operation=encrypt-config status=%s mode=%s files=%d uid=%d" %
            (status, mode, file_count, os.geteuid()),
        )
    finally:
        syslog.closelog()


def _watch_paths(config):
    values = config.get("watch_path", [str(path) for path in encryptor.ALLOWED_ROOTS])
    if not isinstance(values, list) or not values:
        raise encryptor.EncryptorError("watch_path must be a non-empty list")
    paths = []
    for value in values:
        path = Path(value)
        if not encryptor._within_allowed_root(path):
            raise encryptor.EncryptorError("watch_path is outside approved oVirt directories: %s" % path)
        if path.is_symlink() or not path.is_dir():
            raise encryptor.EncryptorError("watch_path must be a real directory: %s" % path)
        paths.append(path)
    return paths


def encrypt_tree(root, passphrase, config, excluded=(), transit_client=None):
    encrypted = 0
    excluded = {Path(path).resolve() for path in excluded}
    requested_names = config.get(
        "allowed_files",
        sorted(encryptor.ALLOWED_CONFIG_BASENAMES),
    )
    if not isinstance(requested_names, list):
        raise encryptor.EncryptorError("allowed_files must be a list")
    allowed_names = set(requested_names)
    if not allowed_names or not allowed_names <= encryptor.ALLOWED_CONFIG_BASENAMES:
        raise encryptor.EncryptorError("allowed_files contains an unapproved filename")
    for directory, directories, files in os.walk(root, followlinks=False):
        directories[:] = [
            name for name in directories
            if not (Path(directory) / name).is_symlink()
        ]
        for name in files:
            if name not in allowed_names:
                continue
            path = Path(directory) / name
            if path.resolve() in excluded:
                continue
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                continue
            if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise encryptor.EncryptorError("Refusing writable configuration file: %s" % path)
            if encryptor.is_encrypted(path):
                continue
            encryptor.transform_file(
                path, path, passphrase, config=config, transit_client=transit_client
            )
            encrypted += 1
    return encrypted


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=str(encryptor.DEFAULT_CONFIG))
    parser.add_argument("--secret-file")
    parser.add_argument("--prompt", action="store_true")
    args = parser.parse_args(argv)
    try:
        config = encryptor._load_crypto_config(args.config)
        transit_client = encryptor.vault_client_from_config(config)
        passphrase = None
        if transit_client is None:
            passphrase = encryptor.obtain_passphrase(config, args.secret_file, args.prompt)
        excluded = [args.config]
        if args.secret_file or config.get("secret_file"):
            excluded.append(args.secret_file or config["secret_file"])
        total = sum(
            encrypt_tree(path, passphrase, config, excluded, transit_client)
            for path in _watch_paths(config)
        )
        config["encrypt_flag"] = "YES"
        config["active_format"] = (
            encryptor.VAULT_MAGIC if transit_client else encryptor.MAGIC
        ).decode("ascii")
        config["format_version"] = encryptor.VERSION
        config["pbkdf2_iterations"] = encryptor.PBKDF2_ITERATIONS
        encryptor.atomic_update_config(args.config, config)
        _audit("success", "vault" if transit_client else "local", total)
        print("Encrypted %d file(s)" % total)
    except (encryptor.EncryptorError, OSError) as error:
        _audit("failure", "unknown")
        print("encrypt_conf_files: %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
