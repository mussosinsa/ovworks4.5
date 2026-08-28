#!/usr/bin/python3
"""Safely decrypt one oVirt configuration file to a mode-0600 output."""

import argparse
import sys

import encryptor


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source")
    parser.add_argument("output")
    parser.add_argument("--config", default=str(encryptor.DEFAULT_CONFIG))
    parser.add_argument("--secret-file")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--deny-legacy-cbc", action="store_true")
    parser.add_argument("--prompt", action="store_true")
    args = parser.parse_args(argv)
    try:
        config = encryptor._load_crypto_config(args.config)
        transit_client = encryptor.vault_client_from_config(config)
        passphrase = None
        if transit_client is None or args.secret_file or config.get("secret_file"):
            passphrase = encryptor.obtain_passphrase(
                config, args.secret_file, args.prompt, transit_client
            )
        encryptor.transform_file(
            args.source,
            args.output,
            passphrase,
            decrypt=True,
            config=config,
            deny_legacy_cbc=args.deny_legacy_cbc,
            overwrite=args.overwrite,
            transit_client=transit_client,
        )
    except (encryptor.EncryptorError, OSError) as error:
        print("decrypt_conf: %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
