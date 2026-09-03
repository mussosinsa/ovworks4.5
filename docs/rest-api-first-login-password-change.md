# REST API first-login password change

REST clients use the OAuth token endpoint to complete a mandatory password
change. All three credential values are independently encrypted with the
Engine login RSA public key using RSA-OAEP, SHA-256, MGF1-SHA256, and an empty
OAEP label. Plaintext passwords must never be sent.

## Configuration

For the bootstrap `admin@internal` password created by `engine-setup`, use the
following answer-file environment setting. The default is `True`:

```text
# Require a password change on the first REST login
OVESETUP_CONFIG/adminPasswordForceChangeOnFirstLogin=bool:True

# Do not require a password change on the first REST login
OVESETUP_CONFIG/adminPasswordForceChangeOnFirstLogin=bool:False
```

For passwords subsequently assigned through the Engine password-reset action,
use the reloadable Engine setting `PasswordPolicyForceChangeOnFirstLogin`:

```console
# Require the user to change an administratively assigned password
engine-config -s PasswordPolicyForceChangeOnFirstLogin=true

# Let the user log in with the administratively assigned password
engine-config -s PasswordPolicyForceChangeOnFirstLogin=false

# Apply the Engine setting before assigning/resetting the user password
systemctl restart ovirt-engine
```

The setting controls how a password is stored when it is assigned: enabled
stores it already expired, while disabled gives it the normal validity period.
It does not bypass an independently expired password during authentication and
does not change credentials that were already assigned. Set the option first,
then assign or reset the password. The option does not weaken the password
policy.

The exact option name ends in **`Login`**. `PasswordPolicyForceChangeOnFirstLogi`
(without the final `n`) is not a valid Engine option. Verify the active value
before adding a user or assigning its initial password:

```console
engine-config -g PasswordPolicyForceChangeOnFirstLogin
```

This policy is evaluated by `ResetUserPasswordCommand` when an administrator
assigns or resets a local user's password. With `true`, the command writes a
past `password-valid-to`, so the authentication provider reports
`CREDENTIALS_EXPIRED` on both REST and interactive first login. With `false`,
it writes the normal validity period and REST authentication can issue a token
without entering the password-change grant. Passwords managed independently by
an external authentication provider are governed by that provider instead.

## 1. Detect the first login

The initial REST request continues to use the encrypted Basic credential
envelope. If authentication reports expired credentials, the API responds with
HTTP 401 and these headers:

```text
X-OVirt-Password-Change-Required: true
X-OVirt-Password-Change-Grant-Type: urn:ovirt:params:oauth:grant-type:password-change
```

The underlying OAuth response uses HTTP 400 and contains:

```json
{
  "error": "password_change_required",
  "error_description": "Unable to log in because the password has expired. Please change the password to proceed.",
  "password_change_grant_type": "urn:ovirt:params:oauth:grant-type:password-change"
}
```

No access token or Engine session is created while the password is expired.

## 2. Change the password and log in

POST an URL-encoded request to `/ovirt-engine/sso/oauth/token`. Authenticate
the OAuth client in the same way as other token requests and submit:

```text
grant_type=urn:ovirt:params:oauth:grant-type:password-change
scope=ovirt-app-api
encrypted_username=<RSA-OAEP ciphertext for user@profile>
encrypted_current_password=<RSA-OAEP ciphertext for the current password>
encrypted_new_password=<RSA-OAEP ciphertext for the new password>
```

The server validates the username/profile, applies the Engine password policy,
invokes the authentication provider's credential-change operation, and then
authenticates with the new password. A successful response is the normal OAuth
token response, so the client can immediately retry API operations with the
returned bearer token. A failed password change never returns a token.
