# REST API first-login password change

REST clients use the OAuth token endpoint to complete a mandatory password
change. All three credential values are independently encrypted with the
Engine login RSA public key using RSA-OAEP, SHA-256, MGF1-SHA256, and an empty
OAEP label. Plaintext passwords must never be sent.

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
