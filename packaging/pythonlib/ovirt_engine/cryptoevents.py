#
#
# Copyright oVirt Authors
# SPDX-License-Identifier: Apache-2.0
#
#


"""Records what the configuration-file cryptography did, for the engine to report.

The engine decrypts its database configuration before the Java daemon exists, so a failure
there has no engine to write an audit event and the event list says nothing at all about it -
the only sign is that the engine did not start. Each result is written here instead, one file
per event, and the engine records them in the audit log at the next start it manages.

Nothing written here may carry a secret. The event names the file by its basename and the
reason by a code from a fixed vocabulary - never the message the code was derived from, because
several of the encryptor's messages name a filesystem path, and never the exception chain,
which can carry a URL or a token.
"""


import errno
import gettext
import json
import os
import tempfile
import uuid

from datetime import datetime


def _(m):
    return gettext.dgettext(message=m, domain='ovirt-engine')


SPOOL_DIR = '/var/lib/ovirt-engine/security/crypto-events'

# What the engine records. The names are the audit log types it raises.
DECRYPTION_COMPLETED = 'CONFIG_FILE_DECRYPTION_COMPLETED'
DECRYPTION_FAILED = 'CONFIG_FILE_DECRYPTION_FAILED'
ENCRYPTION_COMPLETED = 'CONFIG_FILE_ENCRYPTION_COMPLETED'
ENCRYPTION_FAILED = 'CONFIG_FILE_ENCRYPTION_FAILED'
KEY_CREATED = 'CRYPTO_KEY_CREATED'
KEY_CREATION_FAILED = 'CRYPTO_KEY_CREATION_FAILED'

EVENTS = frozenset((
    DECRYPTION_COMPLETED,
    DECRYPTION_FAILED,
    ENCRYPTION_COMPLETED,
    ENCRYPTION_FAILED,
    KEY_CREATED,
    KEY_CREATION_FAILED,
))

# The whole vocabulary a reason can be. An event carries one of these or nothing.
REASON_UNKNOWN = 'UNKNOWN'
REASON_AUTHENTICATION_FAILED = 'AUTHENTICATION_FAILED'
REASON_FILE_DAMAGED = 'FILE_DAMAGED'
REASON_VAULT_UNAVAILABLE = 'VAULT_UNAVAILABLE'
REASON_VAULT_RESPONSE_INVALID = 'VAULT_RESPONSE_INVALID'
REASON_PASSPHRASE_UNAVAILABLE = 'PASSPHRASE_UNAVAILABLE'
REASON_CONFIGURATION_INVALID = 'CONFIGURATION_INVALID'
REASON_PATH_REJECTED = 'PATH_REJECTED'
REASON_LEGACY_DENIED = 'LEGACY_DENIED'
REASON_ENCRYPTOR_MISSING = 'ENCRYPTOR_MISSING'

REASONS = frozenset((
    REASON_UNKNOWN,
    REASON_AUTHENTICATION_FAILED,
    REASON_FILE_DAMAGED,
    REASON_VAULT_UNAVAILABLE,
    REASON_VAULT_RESPONSE_INVALID,
    REASON_PASSPHRASE_UNAVAILABLE,
    REASON_CONFIGURATION_INVALID,
    REASON_PATH_REJECTED,
    REASON_LEGACY_DENIED,
    REASON_ENCRYPTOR_MISSING,
))

# Read in order; the first whose text appears in the message wins. Matched on the encryptor's
# own wording, which is written in this source tree - so a message that changes there without
# changing here becomes UNKNOWN, which is a duller event, not a leaking one.
_REASON_BY_TEXT = (
    ('Authentication failed', REASON_AUTHENTICATION_FAILED),
    ('is truncated', REASON_FILE_DAMAGED),
    ('magic header is missing', REASON_FILE_DAMAGED),
    ('Invalid Vault envelope header', REASON_FILE_DAMAGED),
    ('Unsupported encrypted file version', REASON_FILE_DAMAGED),
    ('Invalid wrapped data-key length', REASON_FILE_DAMAGED),
    ('Invalid PBKDF2 iteration count', REASON_FILE_DAMAGED),
    ('Vault returned an invalid data key length', REASON_VAULT_RESPONSE_INVALID),
    ('did not return', REASON_VAULT_RESPONSE_INVALID),
    ('returned an invalid response', REASON_VAULT_RESPONSE_INVALID),
    ('Vault Transit connection failed', REASON_VAULT_UNAVAILABLE),
    ('Vault Transit request failed', REASON_VAULT_UNAVAILABLE),
    ('Vault CA certificate is missing', REASON_VAULT_UNAVAILABLE),
    ('Vault token', REASON_VAULT_UNAVAILABLE),
    ('Vault Transit is required', REASON_VAULT_UNAVAILABLE),
    ('Passphrase file', REASON_PASSPHRASE_UNAVAILABLE),
    ('A passphrase is required', REASON_PASSPHRASE_UNAVAILABLE),
    ('configuration', REASON_CONFIGURATION_INVALID),
    ('Encryptor tool is missing', REASON_ENCRYPTOR_MISSING),
    ('Legacy', REASON_LEGACY_DENIED),
    ('Symbolic links are not allowed', REASON_PATH_REJECTED),
    ('Refusing', REASON_PATH_REJECTED),
    ('outside approved oVirt directories', REASON_PATH_REJECTED),
    ('Unable to inspect path', REASON_PATH_REJECTED),
)


def reason_for(error):
    """@return a code from REASONS, chosen by what the error says and never carrying it"""
    message = str(error) if error is not None else ''
    for text, reason in _REASON_BY_TEXT:
        if text in message:
            return reason
    return REASON_UNKNOWN


def record(
    event,
    source,
    file=None,
    scheme=None,
    reason=None,
    spool_dir=None,
):
    """Leaves one event for the engine to record. Never raises.

    The caller is usually in the middle of failing, and a spool that cannot be written must not
    replace the reason it was failing with a reason about the spool.

    @param event one of EVENTS
    @param source what was running: engine-start, engine-setup, vault-passphrase
    @param file the basename of the file the operation was on, if any
    @param scheme the envelope the file uses: OVENC001 or OVVLT001
    @param reason one of REASONS, for an event that failed
    @param spool_dir where to write it, defaulting to SPOOL_DIR
    @return the path written, or None
    """
    try:
        if event not in EVENTS:
            return None
        # Read here rather than bound as a default argument, so that SPOOL_DIR stays the one
        # place the location is written down.
        if spool_dir is None:
            spool_dir = SPOOL_DIR
        entry = {
            'version': 1,
            'id': str(uuid.uuid4()),
            'timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
            'event': event,
            'source': str(source)[:64],
        }
        if file is not None:
            # Basename only: a path says where the installation keeps its keys.
            entry['file'] = os.path.basename(str(file))[:255]
        if scheme is not None:
            entry['scheme'] = str(scheme)[:16]
        if reason is not None:
            entry['reason'] = reason if reason in REASONS else REASON_UNKNOWN

        _makedirs(spool_dir)
        return _write(spool_dir, entry)
    except Exception:
        return None


def _makedirs(spool_dir):
    try:
        os.makedirs(spool_dir, mode=0o700)
    except OSError as error:
        if error.errno != errno.EEXIST:
            raise


def _write(spool_dir, entry):
    """Writes the entry under a name nothing else will take, and only once it is whole.

    The engine reads this directory while things are writing to it, so a half-written file must
    never be one it can see. It is written elsewhere in the same directory and renamed, which
    is atomic.
    """
    handle, temporary = tempfile.mkstemp(dir=spool_dir, prefix='.tmp-')
    try:
        with os.fdopen(handle, 'w', encoding='utf-8') as stream:
            json.dump(entry, stream)
        os.chmod(temporary, 0o600)
        final = os.path.join(spool_dir, '%s.json' % entry['id'])
        os.rename(temporary, final)
        return final
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


# vim: expandtab tabstop=4 shiftwidth=4
