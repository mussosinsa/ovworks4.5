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

If setup reports `Plain HTTP Vault is disabled`, the configured URL uses
`http://` but has not acknowledged that downgrade. The recommended fix is to
restore HTTPS and correct the certificate SAN as described below. For a
formally accepted loopback-only deployment where Vault's listener really has
`tls_disable = true`, the explicit exception is:

```json
"vault_transit": {
  "enabled": true,
  "address": "http://127.0.0.1:8200",
  "allow_plaintext_loopback": true,
  "mount": "transit",
  "key_name": "ovirt-engine-config",
  "token_file": "/etc/ovirt-engine/encryptor/vault-token",
  "timeout": 5
}
```

Remove `ca_cert` from this HTTP-only block because no TLS certificate is used.
The exception is rejected for non-loopback hosts. It still sends the Vault token
and wrapped-key requests without TLS, so record the risk acceptance and prefer
the HTTPS configuration for production. Ensure the CLI tests the same endpoint:

```console
export VAULT_ADDR=http://127.0.0.1:8200
vault status
/usr/share/ovirt-engine/encryptor/vault_passphrase.py --check \
  --config /etc/ovirt-engine/encryptor/config.json
```

### Fix an IP subjectAltName mismatch

The URL host must match a certificate `subjectAltName` (SAN); a certificate
common name alone is not sufficient. Inspect the certificate without exposing
its private key:

```console
openssl x509 -in /etc/vault.d/tls/vault.crt \
  -noout -subject -issuer -ext subjectAltName
```

For `https://127.0.0.1:8200`, the output must contain
`IP Address:127.0.0.1`. There are two secure remedies:

1. **Use a matching DNS SAN.** If the certificate contains `DNS:localhost`, use
   `https://localhost:8200` consistently in `VAULT_ADDR`, `api_addr`, and
   `vault_transit.address`. If it contains another DNS name, that name must
   resolve to loopback and be used consistently.
2. **Reissue the server certificate with an IP SAN.** Generate a new private key
   and CSR, have the site's CA sign it while preserving the SAN extension, then
   restart Vault:

```console
umask 077
openssl req -new -newkey rsa:3072 -nodes \
  -keyout /root/vault-new.key \
  -out /root/vault-new.csr \
  -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
# Submit vault-new.csr to the site CA. After receiving vault-new.crt:
install -o vault -g vault -m 0600 /root/vault-new.key \
  /etc/vault.d/tls/vault.key
install -o vault -g vault -m 0644 /root/vault-new.crt \
  /etc/vault.d/tls/vault.crt
systemctl restart vault
```

Do not work around this error with `VAULT_SKIP_VERIFY`, `tls_skip_verify`, or
`curl -k`; those settings disable server identity verification. After applying
one remedy, set the CA and retry:

```console
export VAULT_ADDR=https://127.0.0.1:8200
export VAULT_CACERT=/etc/pki/ca-trust/source/anchors/vault-ca.pem
vault status
```

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

There are two different credentials in this procedure:

* the initial root/admin token is used interactively only to bootstrap Vault;
* `/etc/ovirt-engine/encryptor/vault-token` contains a newly issued application
  token with only the two Transit paths above.

Never copy the initial root token into the application token file. Log in at the
prompt so the admin token is not placed in shell history, load the policy, and
redirect only the newly issued application token into the protected file:

```console
export VAULT_ADDR=https://127.0.0.1:8200
export VAULT_CACERT=/etc/pki/ca-trust/source/anchors/vault-ca.pem
vault status
vault login
vault policy write ovirt-engine-transit /root/ovirt-engine-transit.hcl
install -d -o root -g root -m 0700 /etc/ovirt-engine/encryptor
umask 077
vault token create \
  -policy=ovirt-engine-transit \
  -no-default-policy \
  -field=token | \
  /usr/share/ovirt-engine/encryptor/vault_passphrase.py \
    --install-token-stdin \
    --config /etc/ovirt-engine/encryptor/config.json
```

The pipeline never places the application token in an argument, environment
variable, terminal output, or intermediate file. The helper accepts one ASCII
token from standard input, restricts the destination to
`/etc/ovirt-engine/encryptor`, changes that directory to `root:ovirt` mode
`0750`, and atomically creates the token as `ovirt:ovirt` mode `0600`. The
Engine launcher runs as `ovirt`, so a `root:root` mode-`0600` token makes Vault
decryption fail during service startup. To intentionally rotate an existing token, add `--overwrite` to the
helper invocation. If the Vault command fails, its empty output is rejected and
the current token is not replaced.

The token has a TTL unless the Vault server/auth method is configured otherwise.
Monitor its expiry and renew or rotate it before expiration. For unattended
production operation, prefer Vault Agent auto-auth with a mode-`0600` file sink
and a machine authentication method rather than creating a non-expiring token.

The configured `token_file` is mandatory; the encryptor never creates a Vault
token because doing so would require embedding an administrative credential. If
setup reports `Vault token file is missing`, complete the procedure above (or
configure a Vault Agent file sink), then verify permissions and perform a real
wrap/unwrap preflight before rerunning setup:

```console
stat -c '%U:%G %a %n' /etc/ovirt-engine/encryptor/vault-token
sudo /usr/share/ovirt-engine/encryptor/vault_passphrase.py \
  --check --config /etc/ovirt-engine/encryptor/config.json
```

The `stat` output must report
`ovirt:ovirt 600 /etc/ovirt-engine/encryptor/vault-token` and preflight must report
`Vault Transit preflight succeeded`. Do not use `cat` to inspect the token.

During closeup, `engine-setup` now enforces this token ownership and mode even
when the token was created earlier as `root:root`. It rejects symbolic links and
non-regular token paths before changing metadata. This is required because setup
runs as root but the service performs every subsequent unwrap as `ovirt`.

If `engine-setup` succeeded but `ovirt-engine.service` reports that it cannot
parse an `OVVLT001` DB configuration, repair a token installed with the old
root-only ownership and verify access as the actual service account:

```console
chown root:ovirt /etc/ovirt-engine/encryptor
chmod 0750 /etc/ovirt-engine/encryptor
chown root:ovirt /etc/ovirt-engine/encryptor/config.json
chmod 0640 /etc/ovirt-engine/encryptor/config.json
chown ovirt:ovirt /etc/ovirt-engine/encryptor/vault-token
chmod 0600 /etc/ovirt-engine/encryptor/vault-token
sudo -u ovirt test -r /etc/ovirt-engine/encryptor/config.json
sudo -u ovirt test -r /etc/ovirt-engine/encryptor/vault-token
sudo -u ovirt /usr/share/ovirt-engine/encryptor/vault_passphrase.py \
  --check --config /etc/ovirt-engine/encryptor/config.json
systemctl restart ovirt-engine
```

If permission is still denied, identify the exact path component and check
SELinux instead of repeatedly changing the ciphertext permissions:

```console
namei -l /etc/ovirt-engine/encryptor/config.json
ls -ldZ /etc/ovirt-engine /etc/ovirt-engine/encryptor
ls -lZ /etc/ovirt-engine/encryptor/config.json \
  /etc/ovirt-engine/encryptor/vault-token
restorecon -RFv /etc/ovirt-engine/encryptor
ausearch -m AVC -ts recent | tail -50
```

Every parent directory needs traverse permission for `ovirt`. Do not use
`chmod 777`, make the token group-readable, or disable SELinux. The config is
non-secret routing metadata and is safely `root:ovirt` mode `0640`; keeping it
root-owned prevents the service from redirecting its trusted Vault endpoint.

Do not put the initial root token in `vault-token`. A successful preflight
performs a random wrap/unwrap round trip and prints no token, KEK, or DEK.

## 6. Configure and verify the encryptor

Create `/etc/ovirt-engine/encryptor/config.json` as `root:ovirt` mode `0640`;
its parent must be traversable by the service as `root:ovirt` mode `0750`:

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

If `vault status` succeeds but `vault_passphrase.py --check` reports
`Vault Transit is not enabled`, Vault itself is healthy but the encryptor did
not load an enabled `vault_transit` object from the selected JSON file. Validate
the exact file (these commands print configuration metadata, never the token):

```console
python3 -m json.tool /etc/ovirt-engine/encryptor/config.json >/dev/null
python3 - <<'PY'
import json
from pathlib import Path

path = Path('/etc/ovirt-engine/encryptor/config.json')
config = json.loads(path.read_text(encoding='utf-8'))
vault = config.get('vault_transit')
print('config:', path)
print('vault_transit type:', type(vault).__name__)
print('enabled:', vault.get('enabled') if isinstance(vault, dict) else None)
print('address:', vault.get('address') if isinstance(vault, dict) else None)
PY
```

The expected type is `dict` and `enabled` must print Python `True`. JSON boolean
syntax is lowercase `true` without quotes; `"true"`, `"YES"`, and `1` are
rejected rather than silently falling back to passphrase mode. Restore the
shipped preinstall example if the object is absent:

```console
install -o root -g root -m 0600 \
  /usr/share/ovirt-engine/encryptor/config.vault.example.json \
  /etc/ovirt-engine/encryptor/config.json
```

Then rerun the check as one command. In a shell, use a trailing backslash for
line continuation; do not type the two characters `\n`:

```console
/usr/share/ovirt-engine/encryptor/vault_passphrase.py --check \
  --config /etc/ovirt-engine/encryptor/config.json
```

This is also shipped as
`/usr/share/ovirt-engine/encryptor/config.vault.example.json`. Copy it to
`/etc/ovirt-engine/encryptor/config.json` with owner `root:ovirt` and mode `0640`
before `engine-setup`. The explicit `secret_file` requests creation of a random
recovery passphrase; closeup immediately replaces its plaintext with an
`OVVLT001` Vault envelope. Omit that field for pure Vault mode.

```console
sudo chown root:ovirt /etc/ovirt-engine/encryptor
sudo chmod 0750 /etc/ovirt-engine/encryptor
sudo chown root:ovirt /etc/ovirt-engine/encryptor/config.json
sudo chmod 0640 /etc/ovirt-engine/encryptor/config.json
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
