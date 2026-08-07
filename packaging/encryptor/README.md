# oVirt configuration encryptor

The encryptor writes only the authenticated `OVENC001` format. It uses:

* AES-256-GCM with a random 256-bit data-encryption key for file contents;
* AES-256-GCM to wrap the data key;
* PBKDF2-HMAC-SHA-256 with 600,000 iterations and a random 128-bit salt to
  derive the wrapping key; and
* independent random 96-bit nonces for key wrapping and content encryption.

Both GCM operations authenticate the versioned header. Decryption fails without
writing output when the ciphertext, metadata, key, or authentication tag is
wrong.

## Key sources

Key sources are checked in this order:

1. `${CREDENTIALS_DIRECTORY}/ovirt-encryptor-passphrase` (systemd credential);
2. `OVIRT_ENCRYPTOR_PASSPHRASE` (environment variable); and
3. a mode-0600 file selected by `--secret-file` or `secret_file` in config.

Hardware identifiers, including MAC addresses, are never used. Prefer a systemd
credential. Environment variables are supported for compatibility but can be
exposed to privileged process inspection.

Example service override:

```ini
[Service]
LoadCredentialEncrypted=ovirt-encryptor-passphrase:/etc/credstore.encrypted/ovirt-encryptor-passphrase
```

## Commands

```console
encryptor.py --encrypt /etc/ovirt-engine/engine.conf.d/10-setup-database.conf
encryptor.py --decrypt --deny-legacy-cbc /etc/ovirt-engine/engine.conf.d/10-setup-database.conf
decrypt_conf.py --deny-legacy-cbc SOURCE OUTPUT
encrypt_conf_files.py
```

`encrypt_conf_files.py` processes only `10-setup-database.conf` and
`10-setup-dwh-database.conf` below approved oVirt
directories. It does not follow symbolic links. Already-versioned files are
skipped.

Legacy AES-256-CBC is read-only and disabled unless an explicit `legacy_cbc`
migration configuration supplies the old key and IV representation. Raw and
Base64 ciphertext, with an IV prefix or configured IV, are supported. Use
`--deny-legacy-cbc` after migration to prohibit it completely. New and migrated
files must always be written as `OVENC001`.
