import re
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
SPEC = 'docs/db-config-key-management-specification.md'

# What the specification tells a security evaluator, and where the code says it. A change to
# either side without the other leaves the evaluator reading something that is no longer true.
CLAIMS = (
    ('packaging/encryptor/encryptor.py', 'PBKDF2_ITERATIONS = 600_000'),
    ('packaging/encryptor/encryptor.py', 'SALT_SIZE = 16'),
    ('packaging/encryptor/encryptor.py', 'NONCE_SIZE = 12'),
    ('packaging/encryptor/encryptor.py', 'DATA_KEY_SIZE = 32'),
    ('packaging/encryptor/encryptor.py', 'WRAPPED_KEY_SIZE = DATA_KEY_SIZE + 16'),
    ('packaging/encryptor/encryptor.py', 'HEADER = struct.Struct(">8sBI16s12s12sH")'),
    ('packaging/encryptor/encryptor.py', 'VAULT_HEADER = struct.Struct(">8sB12sH")'),
    ('packaging/encryptor/encryptor.py', 'algorithm=hashes.SHA256()'),
    ('packaging/encryptor/encryptor.py', '"type": "aes256-gcm96"'),
    ('packaging/encryptor/encryptor.py', '"exportable": False'),
    ('packaging/encryptor/encryptor.py', '"allow_plaintext_backup": False'),
    (
        'packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/config/client_control.py',
        'base64.urlsafe_b64encode(os.urandom(48))',
    ),
    (
        'backend/manager/modules/enginesso/src/main/java/org/ovirt/engine/core/sso'
        '/utils/LoginEnvelopeCrypto.java',
        'RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING',
    ),
    ('docs/vault-transit-rocky-linux-9.5.md', '-key-shares=5 -key-threshold=3'),
    ('packaging/pythonlib/ovirt_engine/cryptoevents.py',
     "SPOOL_DIR = '/var/lib/ovirt-engine/security/crypto-events'"),
)

# Every file whose lines the specification cites, by the basename it cites them under.
CITED_FILES = {
    'encryptor.py': 'packaging/encryptor/encryptor.py',
    'encrypt_conf_files.py': 'packaging/encryptor/encrypt_conf_files.py',
    'vault_passphrase.py': 'packaging/encryptor/vault_passphrase.py',
    'client_control.py':
        'packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/config/client_control.py',
    'configfile.py': 'packaging/pythonlib/ovirt_engine/configfile.py',
    'cryptoevents.py': 'packaging/pythonlib/ovirt_engine/cryptoevents.py',
    'service.py': 'packaging/pythonlib/ovirt_engine/service.py',
    'aaajdbc.py': 'packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/config/aaajdbc.py',
    'database.py': 'packaging/setup/ovirt_engine_setup/engine_common/database.py',
    'constants.py': 'packaging/setup/ovirt_engine_setup/engine/constants.py',
    'misc.py': 'packaging/setup/plugins/ovirt-engine-remove/ovirt-engine/config/misc.py',
    'decrypt.py': 'packaging/setup/plugins/ovirt-engine-remove/ovirt-engine/config/decrypt.py',
    'ShellLikeConfd.java':
        'backend/manager/modules/uutils/src/main/java/org/ovirt/engine/core/uutils'
        '/config/ShellLikeConfd.java',
    'LoginEnvelopeCrypto.java':
        'backend/manager/modules/enginesso/src/main/java/org/ovirt/engine/core/sso'
        '/utils/LoginEnvelopeCrypto.java',
    'AuditLogType.java':
        'backend/manager/modules/common/src/main/java/org/ovirt/engine/core/common'
        '/AuditLogType.java',
    'ovirt-engine.py': 'packaging/services/ovirt-engine/ovirt-engine.py',
    'vault-transit-rocky-linux-9.5.md': 'docs/vault-transit-rocky-linux-9.5.md',
    'webadmin-login-credential-encryption-verification-form.md':
        'docs/webadmin-login-credential-encryption-verification-form.md',
}

AUDIT_EVENTS = (
    ('CONFIG_FILE_DECRYPTION_COMPLETED', 13658),
    ('CONFIG_FILE_DECRYPTION_FAILED', 13659),
    ('CONFIG_FILE_ENCRYPTION_COMPLETED', 13660),
    ('CONFIG_FILE_ENCRYPTION_FAILED', 13661),
    ('CRYPTO_KEY_CREATED', 13662),
    ('CRYPTO_KEY_CREATION_FAILED', 13663),
    ('CRYPTO_EVENT_SPOOL_REJECTED', 13664),
)


def read(relative):
    return (ROOT / relative).read_text(encoding='utf-8')


class KeyManagementSpecificationTest(unittest.TestCase):

    def test_every_stated_parameter_is_what_the_code_uses(self):
        for path, needle in CLAIMS:
            self.assertIn(needle, read(path), '%s no longer contains %r' % (path, needle))

    def test_every_cited_line_exists_in_the_file_it_names(self):
        spec = read(SPEC)
        lengths = {
            name: len(read(path).splitlines())
            for name, path in CITED_FILES.items()
        }
        for match in re.finditer(r'([A-Za-z0-9_.\-]+\.(?:py|java|md)):(\d+)(?:-(\d+))?', spec):
            name, first, last = match.group(1), int(match.group(2)), match.group(3)
            if name not in lengths:
                continue
            highest = int(last) if last else first
            self.assertLessEqual(
                highest, lengths[name],
                '%s cites %s:%s which is past the end of the file' % (SPEC, name, highest))
            self.assertGreaterEqual(first, 1)

    def test_the_audit_events_it_lists_are_the_ones_the_engine_raises(self):
        types = read(CITED_FILES['AuditLogType.java'])
        spec = read(SPEC)
        for name, value in AUDIT_EVENTS:
            self.assertRegex(types, r'\b%s\(%d' % (name, value))
            self.assertIn(name, spec)

    def test_the_three_protected_files_are_the_ones_the_tool_allows(self):
        allowed = read('packaging/encryptor/encryptor.py')
        spec = read(SPEC)
        for name in ('10-setup-database.conf', '10-setup-dwh-database.conf',
                     'internal.properties'):
            self.assertIn('"%s"' % name, allowed)
            self.assertIn(name, spec)

    def test_it_separates_the_unseal_shares_from_the_key_encryption_key(self):
        spec = read(SPEC)

        # The five keys Vault prints at init are unseal shares, not the KEK. An evaluator
        # reading them as the KEK would look for key material in the wrong place entirely.
        self.assertIn('Unseal Key Share', spec)
        self.assertIn('DEK도 KEK도 아니다', spec)


if __name__ == '__main__':
    unittest.main()
