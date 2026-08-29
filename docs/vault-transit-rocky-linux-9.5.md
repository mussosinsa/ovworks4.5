# Local Vault Transit setup on Rocky Linux 9.5

## Is separate Transit configuration required?

Yes. Installing the `vault` RPM installs the binary, service unit, and example
configuration only. It does not initialize Vault, enable the Transit secrets
engine, create an encryption key, or issue an oVirt policy/token. The DB
configuration encryptor cannot operate until every item below is complete.

This example binds Vault only to loopback because Vault and oVirt Engine run on
the same server. Adjust paths and certificate management to the site's security
policy. Do not use development mode (`vault server -dev`) in production.

## 1. Install the official RPM

```console
sudo dnf install -y dnf-plugins-core
sudo dnf config-manager --add-repo \
  https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo
sudo dnf install -y vault
vault version
```

Pin and validate the package version under the site's change-management and
supply-chain policy. Package installation alone is not a usable KMS.

## 2. Configure local storage and TLS

Create a CA-issued server certificate whose subject alternative names include
`127.0.0.1` (and `localhost` if it will be used). Protect the private key so it
is readable by the `vault` service account and not by group/other users.

Example `/etc/vault.d/vault.hcl`:

```hcl
ui           = false
api_addr     = "https://127.0.0.1:8200"
cluster_addr = "https://127.0.0.1:8201"

storage "raft" {
  path    = "/opt/vault/data"
  node_id = "ovirt-engine-local"
}

listener "tcp" {
  address         = "127.0.0.1:8200"
  cluster_address = "127.0.0.1:8201"
  tls_disable     = false
  tls_cert_file   = "/etc/vault.d/tls/vault.crt"
  tls_key_file    = "/etc/vault.d/tls/vault.key"
  tls_min_version = "tls12"
}
```

Prepare the integrated-storage directory and validate the configuration before
starting the service:

```console
sudo install -d -o vault -g vault -m 0700 /opt/vault/data
sudo -u vault vault server -config=/etc/vault.d/vault.hcl -verify-only
sudo systemctl enable --now vault
sudo systemctl --no-pager --full status vault
```

Do not set `tls_skip_verify`, and do not enable plaintext HTTP in production.
The encryptor accepts HTTP only when both the address is loopback and
`allow_plaintext_loopback` is explicitly enabled.

## 3. Initialize and unseal Vault

Set the CLI address and CA certificate without putting a root token on a command
line:

```console
export VAULT_ADDR=https://127.0.0.1:8200
export VAULT_CACERT=/etc/pki/ca-trust/source/anchors/vault-ca.pem
vault operator init -key-shares=5 -key-threshold=3
vault operator unseal
vault status
```

Run `vault operator unseal` with three different unseal-key custodians in this
example. Never store unseal/recovery keys or the initial root token with the
Vault data directory, oVirt backup, encryptor configuration, or ciphertext.
Revoke the initial root token after bootstrap administration is complete.

An auto-unseal mechanism is optional but requires a separately protected seal
provider. Without auto-unseal, Vault is sealed after every Vault/server restart,
so oVirt DB configuration decryption remains unavailable until the documented
manual unseal ceremony finishes.

## 4. Enable Transit and create the KEK

Authenticate temporarily with an administrative token, then enable Transit once:

```console
vault secrets enable -path=transit transit
vault secrets list
```

Choose one of the following KEK creation methods. Both create the key inside
Vault; key bytes are not returned to the caller.

```console
vault write transit/keys/ovirt-engine-config \
  type=aes256-gcm96 exportable=false allow_plaintext_backup=false
```

or, after writing the encryptor JSON and temporarily supplying a token allowed
to create this key:

```console
/usr/share/ovirt-engine/encryptor/vault_passphrase.py --init-key
```

The application runtime token must not retain `transit/keys/*` create, update,
delete, export, backup, restore, or configuration permissions.

## 5. Create a least-privilege policy and token

Create `/root/ovirt-engine-transit.hcl`:

```hcl
path "transit/encrypt/ovirt-engine-config" {
  capabilities = ["update"]
}

path "transit/decrypt/ovirt-engine-config" {
  capabilities = ["update"]
}
```

Load the policy and issue a token without the default policy:

```console
vault policy write ovirt-engine-transit /root/ovirt-engine-transit.hcl
umask 077
vault token create \
  -policy=ovirt-engine-transit \
  -no-default-policy \
  -format=json > /root/ovirt-engine-transit-token.json
sudo install -d -o root -g root -m 0700 /etc/ovirt-engine/encryptor
sudo python3 - <<'PY'
import json
from pathlib import Path

source = Path('/root/ovirt-engine-transit-token.json')
token = json.loads(source.read_text(encoding='utf-8'))['auth']['client_token']
target = Path('/etc/ovirt-engine/encryptor/vault-token')
target.write_text(token + '\n', encoding='utf-8')
target.chmod(0o600)
PY
sudo rm -f /root/ovirt-engine-transit-token.json
```

The token has a TTL unless the Vault server/auth method is configured otherwise.
Monitor its expiry and renew or rotate it before expiration. For unattended
production operation, prefer Vault Agent auto-auth with a mode-`0600` file sink
and a machine authentication method rather than creating a non-expiring token.

The configured `token_file` is mandatory; the encryptor never creates a Vault
token because doing so would require embedding an administrative credential. If
setup reports `Vault token file is missing`, create it with an authenticated
Vault administrator session (or configure a Vault Agent file sink) before
rerunning setup:

```console
sudo install -d -o root -g root -m 0700 /etc/ovirt-engine/encryptor
umask 077
vault token create -policy=ovirt-engine-transit -no-default-policy \
  -field=token > /tmp/ovirt-engine-vault-token
sudo install -o root -g root -m 0600 /tmp/ovirt-engine-vault-token \
  /etc/ovirt-engine/encryptor/vault-token
rm -f /tmp/ovirt-engine-vault-token
sudo /usr/share/ovirt-engine/encryptor/vault_passphrase.py \
  --check --config /etc/ovirt-engine/encryptor/config.json
```

Do not put the initial root token in `vault-token`. A successful preflight
performs a random wrap/unwrap round trip and prints no token, KEK, or DEK.

## 6. Configure and verify the encryptor

Create `/etc/ovirt-engine/encryptor/config.json` as mode `0600`:

```json
{
  "encrypt_flag": "NO",
  "watch_path": [
    "/etc/ovirt-engine",
    "/etc/ovirt-engine-dwh"
  ],
  "allowed_files": [
    "10-setup-database.conf",
    "10-setup-dwh-database.conf",
    "internal.properties"
  ],
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

```console
sudo chown root:root /etc/ovirt-engine/encryptor/config.json
sudo chmod 0600 /etc/ovirt-engine/encryptor/config.json
sudo /usr/share/ovirt-engine/encryptor/encrypt_conf_files.py \
  --config /etc/ovirt-engine/encryptor/config.json
sudo head -c 8 \
  /etc/ovirt-engine/engine.conf.d/10-setup-database.conf
```

The final command must print `OVVLT001`. Do not print, copy, or submit the rest
of the ciphertext or any plaintext DB credential as evidence.

An existing installation may still show `active_format` as `OVENC001` and keep
a readable `/etc/ovirt-engine/encryptor/passphrase`. That means the
`vault_transit` object above has not been enabled; installing or starting Vault
does not change encryptor configuration automatically. After enabling and
verifying Transit, rerun `engine-setup`. It atomically converts an explicitly
configured existing passphrase to an `OVVLT001` Vault envelope. The equivalent
manual migration is:

```console
sudo /usr/share/ovirt-engine/encryptor/vault_passphrase.py \
  --encrypt-in-place \
  --config /etc/ovirt-engine/encryptor/config.json \
  /etc/ovirt-engine/encryptor/passphrase
sudo head -c 8 /etc/ovirt-engine/encryptor/passphrase
```

The final command must print `OVVLT001`. Never delete the old passphrase until
all remaining `OVENC001` files have been migrated or independently recovered;
Vault mode uses Transit directly for new `OVVLT001` configuration envelopes,
so the wrapped passphrase is retained only for controlled legacy recovery.

The same encryption pass also protects
`/etc/ovirt-engine/aaa/internal.properties`. A later `engine-setup` decrypts that
file only for the setup window in which the AAA JDBC command-line tool needs it,
then writes a newly encrypted envelope during closeup. The setup cleanup stage
also attempts to restore encryption when setup aborts before closeup. Treat a
reported cleanup encryption failure as a security incident and immediately
rerun setup or invoke `encrypt_conf_files.py` after correcting the cause.

## 7. Boot ordering and operational checks

The Vault process being active does not mean it is unsealed. Before starting or
restarting Engine, require all of these checks to pass:

```console
systemctl is-active vault
VAULT_ADDR=https://127.0.0.1:8200 \
VAULT_CACERT=/etc/pki/ca-trust/source/anchors/vault-ca.pem \
  vault status
sudo systemctl restart ovirt-engine
sudo systemctl --no-pager --full status ovirt-engine
```

Optionally add a systemd ordering drop-in so Vault is started first:

```console
sudo systemctl edit ovirt-engine
```

```ini
[Unit]
Wants=vault.service
After=vault.service network-online.target
```

Then run `sudo systemctl daemon-reload`. Ordering does not unseal Vault and does
not replace a health check. The encryptor deliberately fails closed if Vault is
sealed, unreachable, the TLS chain is invalid, the token is expired/revoked, or
the KEK has been deleted.

Back up and restore the Raft storage using Vault's supported snapshot procedure.
Test restoration, key rotation, token rotation, Vault restart/unseal, and Engine
restart together. A ciphertext backup without the matching Vault storage/key is
not decryptable.
