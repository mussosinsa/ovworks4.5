# oVirt configuration encryptor

Without Vault Transit, the encryptor writes the authenticated `OVENC001` format. It uses:

* AES-256-GCM with a random 256-bit data-encryption key for file contents;
* AES-256-GCM to wrap the data key;
* PBKDF2-HMAC-SHA-256 with 600,000 iterations and a random 128-bit salt to
  derive the wrapping key; and
* independent random 96-bit nonces for key wrapping and content encryption.

Both GCM operations authenticate the versioned header. Decryption fails without
writing output when the ciphertext, metadata, key, or authentication tag is
wrong.

When `vault_transit.enabled` is true, new files instead use `OVVLT001`:
the file is encrypted by AES-256-GCM with a fresh 256-bit DEK and Vault Transit
wraps that DEK with its non-exportable `aes256-gcm96` KEK. The Vault ciphertext
(including its key version), file nonce, and authenticated ciphertext are stored
together; the KEK and Vault token are never stored in the envelope.

## Local Vault Transit on Rocky Linux 9.5

Installing the Vault RPM is **not sufficient**. Vault Transit is disabled by
default. The operator must configure storage and a TLS listener, initialize and
unseal Vault, enable the Transit secrets engine, create the KEK, and issue a
least-privilege application token. See
[`docs/vault-transit-rocky-linux-9.5.md`](../../docs/vault-transit-rocky-linux-9.5.md)
for a complete same-host procedure and reboot checklist.

The application token should have only these capabilities:

```hcl
path "transit/encrypt/ovirt-engine-config" { capabilities = ["update"] }
path "transit/decrypt/ovirt-engine-config" { capabilities = ["update"] }
```

Create `/etc/ovirt-engine/encryptor/vault-token` as root with mode `0600`, and
configure `/etc/ovirt-engine/encryptor/config.json` (also root-owned and not
group/other writable):

For a new installation, copy the shipped
`config.vault.example.json` before running `engine-setup`:

```console
install -d -o root -g root -m 0700 /etc/ovirt-engine/encryptor
install -o root -g root -m 0600 \
  /usr/share/ovirt-engine/encryptor/config.vault.example.json \
  /etc/ovirt-engine/encryptor/config.json
```

```json
{
  "secret_file": "/etc/ovirt-engine/encryptor/passphrase",
  "vault_transit": {
    "enabled": true,
    "address": "https://127.0.0.1:8200",
    "mount": "transit",
    "key_name": "ovirt-engine-config",
    "token_file": "/etc/ovirt-engine/encryptor/vault-token",
    "ca_cert": "/etc/pki/ca-trust/source/anchors/vault-ca.pem",
    "timeout": 5
  }
}
```

Do not pre-populate generated fields such as `active_format`, `format_version`,
`pbkdf2_iterations`, `serialNum`, `salt`, `nonce`, `decrypt_key`, or
`rsaPublicKey`. Setup writes only the applicable non-secret status metadata.
With the example's explicit `secret_file`, setup creates a random passphrase and
immediately protects it as an `OVVLT001` recovery envelope. Omit `secret_file`
for pure Vault mode when no legacy passphrase recovery file is required.

An administrator token may initialize the non-exportable AES-256 Transit KEK;
remove that privilege immediately afterward and deploy the restricted token:

```console
vault_passphrase.py --init-key
```

Before `engine-setup`, verify that the configured CA, token file, Transit mount,
policy, and KEK work together:

```console
vault_passphrase.py --check
```

Create the initial least-privilege application token without exposing it in a
command argument or temporary file:

```console
vault token create -policy=ovirt-engine-transit -no-default-policy \
  -field=token | vault_passphrase.py --install-token-stdin
```

The command must run as root after `config.json` and its parent directory have
been installed. Use `--overwrite` only for an intentional token rotation.

`engine-setup` runs the same random wrap/unwrap preflight during customization,
so a missing token or sealed/unreachable Vault is reported before closeup.

For development only, plain HTTP can be enabled with
`"allow_plaintext_loopback": true`; it is rejected for non-loopback addresses
and is not suitable for production.

## Key sources

Key sources are checked in this order:

1. `${CREDENTIALS_DIRECTORY}/ovirt-encryptor-passphrase` (systemd credential);
2. `OVIRT_ENCRYPTOR_PASSPHRASE` (environment variable); and
3. a mode-0600 file selected by `--secret-file` or `secret_file` in config.

In Vault mode, a secret file beginning with `OVVLT001` is transparently
unwrapped and decrypted when read. Protect an existing passphrase without ever
placing it on a command line, verify the encrypted output, then securely retire
the plaintext according to site policy:

```console
vault_passphrase.py --encrypt /root/passphrase \
  /etc/ovirt-engine/encryptor/passphrase.enc
```

To migrate the configured passphrase atomically in place after enabling
`vault_transit`, use:

```console
vault_passphrase.py --encrypt-in-place \
  /etc/ovirt-engine/encryptor/passphrase
```

`engine-setup` performs this in-place migration automatically when Vault Transit
is enabled and an explicit plaintext `secret_file` already exists. The resulting
file begins with `OVVLT001`; `cat` is not expected to display readable text.

If `config.json` reports `"active_format": "OVENC001"` and contains no enabled
`vault_transit` object, Vault mode is not configured. In that state the
passphrase intentionally remains the KEK input for PBKDF2 and cannot be wrapped
by a Vault KEK. Configure the Vault address, mount, key, token file, and CA first,
then rerun `engine-setup` or the command above.

Set `secret_file` to the resulting mode-0600 file. Vault availability and its
unseal state are intentionally required for decryption (fail closed). Back up
Vault's storage and recovery/unseal material under separate operational control.

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

`encrypt_conf_files.py` processes only `10-setup-database.conf`,
`10-setup-dwh-database.conf`, and the AAA JDBC `internal.properties` file below
approved oVirt directories. It does not follow symbolic links. Already-versioned
files are skipped. During a subsequent `engine-setup`, `internal.properties` is
decrypted in place before AAA JDBC tools use it and is encrypted again during
closeup before Engine starts.

Legacy AES-256-CBC is read-only and disabled unless an explicit `legacy_cbc`
migration configuration supplies the old key and IV representation. Raw and
Base64 ciphertext, with an IV prefix or configured IV, are supported. Use
`--deny-legacy-cbc` after migration to prohibit it completely. New and migrated
files must always be written as authenticated `OVENC001` or Vault-backed
`OVVLT001` envelopes.
