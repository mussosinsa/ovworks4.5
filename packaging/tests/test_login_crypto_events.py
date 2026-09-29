import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / 'packaging/pythonlib'))

from ovirt_engine import cryptoevents  # noqa: E402

SPOOL_WRITER = (
    ROOT
    / 'backend/manager/modules/enginesso/src/main/java/org/ovirt/engine'
    / 'core/sso/utils/CryptoEventSpool.java'
)
LOGIN_CRYPTO = (
    ROOT
    / 'backend/manager/modules/enginesso/src/main/java/org/ovirt/engine'
    / 'core/sso/utils/LoginEnvelopeCrypto.java'
)
CRYPTO_EVENT = (
    ROOT
    / 'backend/manager/modules/bll/src/main/java/org/ovirt/engine'
    / 'core/bll/CryptoEvent.java'
)
CRYPTO_EVENT_MANAGER = (
    ROOT
    / 'backend/manager/modules/bll/src/main/java/org/ovirt/engine'
    / 'core/bll/CryptoEventAuditManager.java'
)
AUDIT_LOG_TYPE = (
    ROOT
    / 'backend/manager/modules/common/src/main/java/org/ovirt/engine'
    / 'core/common/AuditLogType.java'
)
AUDIT_LOG_MESSAGES = (
    ROOT / 'backend/manager/modules/dal/src/main/resources/bundles/AuditLogMessages.properties'
)

EVENT = 'LOGIN_CREDENTIAL_DECRYPTION_FAILED'
LOGIN_REASONS = (
    'PRIVATE_KEY_UNAVAILABLE',
    'CIPHERTEXT_INVALID',
    'ALGORITHM_UNAVAILABLE',
)


class LoginCryptoEventsTest(unittest.TestCase):
    """The single sign-on service writes these and the engine reads them, so the two must agree.

    An entry naming an event or a reason the engine does not know is not recorded: CryptoEvent
    checks both against closed vocabularies and sets the entry aside. That failure mode is silent
    from the writer's side, which is why the vocabularies are compared here rather than left to be
    discovered on a host where a login has just failed.
    """

    def setUp(self):
        self.writer = SPOOL_WRITER.read_text(encoding='utf-8')
        self.login = LOGIN_CRYPTO.read_text(encoding='utf-8')
        self.reader = CRYPTO_EVENT.read_text(encoding='utf-8')
        self.manager = CRYPTO_EVENT_MANAGER.read_text(encoding='utf-8')
        self.types = AUDIT_LOG_TYPE.read_text(encoding='utf-8')
        self.messages = AUDIT_LOG_MESSAGES.read_text(encoding='utf-8')

    def test_the_writer_and_the_engine_name_the_same_event(self):
        self.assertIn(f'LOGIN_CREDENTIAL_DECRYPTION_FAILED = "{EVENT}"', self.writer)
        # In the set of events the engine accepts, and an audit log type it can resolve by name.
        self.assertIn(f'"{EVENT}"', self._events_in(self.reader))
        self.assertRegex(self.types, rf'\n    {EVENT}\(\d+, AuditLogSeverity\.ERROR\),')
        self.assertRegex(self.messages, rf'\n{EVENT}=')

    def test_every_reason_the_writer_uses_is_one_the_engine_accepts(self):
        accepted = self._reasons_in(self.reader)
        for reason in LOGIN_REASONS + ('UNKNOWN',):
            self.assertIn(f'"{reason}"', self.writer)
            self.assertIn(f'"{reason}"', accepted)

    def test_the_python_vocabulary_carries_them_too(self):
        # cryptoevents.py is where the vocabulary is written down for the tools that share this
        # spool; a name missing there is a name the next reader of it will not know about.
        self.assertIn(EVENT, cryptoevents.EVENTS)
        for reason in LOGIN_REASONS:
            self.assertIn(reason, cryptoevents.REASONS)

    def test_both_sides_use_the_same_spool_directory(self):
        spool = '/var/lib/ovirt-engine/security/crypto-events'
        self.assertIn(f'DEFAULT_SPOOL_DIR = "{spool}"', self.writer)
        self.assertIn(f'SPOOL_DIR = "{spool}"', self.manager)
        self.assertEqual(spool, cryptoevents.SPOOL_DIR)

    def test_the_engine_skips_what_is_still_being_written(self):
        # The writer builds each entry under a dotted name and renames it, which is atomic; the
        # reader skips dotted names. Either half alone lets a half-written entry be read.
        self.assertIn('spool.resolve(".tmp-" + id)', self.writer)
        self.assertIn('StandardCopyOption.ATOMIC_MOVE', self.writer)
        self.assertIn('startsWith(".")', self.manager)

    def test_both_login_paths_record_and_neither_changes_what_the_caller_sees(self):
        # decryptCredential delegates to decrypt(String), so recording there as well would put
        # two rows in the event list for one failure.
        self.assertEqual(2, self.login.count('CryptoEventSpool.recordLoginDecryptionFailure('))
        self.assertIn('CryptoEventSpool.SOURCE_CREDENTIAL, e);', self.login)
        self.assertIn('CryptoEventSpool.SOURCE_USERNAME, e);', self.login)
        # The same exception object, so the login fails exactly as it failed before.
        self.assertEqual(
            2,
            len(re.findall(
                r'catch \(GeneralSecurityException \| IOException \| RuntimeException e\) \{\n'
                r'(?:.*\n)*?\s*throw e;\n',
                self.login,
            )),
        )

    def test_a_flood_of_attempts_cannot_fill_the_event_list(self):
        # The operation is reachable by anyone who can reach the login page, unlike everything
        # else that writes to this spool.
        self.assertIn('THROTTLE_SECONDS', self.writer)
        self.assertIn('shouldSpool(reason, Instant.now())', self.writer)

    def test_no_secret_reaches_the_entry(self):
        # The reason is derived from the exception's type, never from its message: provider
        # messages name the key file, and a path says where the installation keeps its keys.
        self.assertIn('error instanceof', self.writer)
        self.assertNotIn('error.getMessage()', self.writer)
        body = self.writer.split('private static void write(', 1)[1]
        for forbidden in ('getMessage', 'encryptedText', 'ciphertext'):
            self.assertNotIn(forbidden, body)

    @staticmethod
    def _events_in(reader):
        return reader.split('Set<String> EVENTS = Set.of(', 1)[1].split(');', 1)[0]

    @staticmethod
    def _reasons_in(reader):
        return reader.split('Set<String> REASONS = Set.of(', 1)[1].split(');', 1)[0]


if __name__ == '__main__':
    unittest.main()
