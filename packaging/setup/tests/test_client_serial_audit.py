import re
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
MODULES = ROOT / 'backend/manager/modules'
TYPES = MODULES / 'common/src/main/java/org/ovirt/engine/core/common/AuditLogType.java'
MESSAGES = MODULES / 'dal/src/main/resources/bundles/AuditLogMessages.properties'
CALLBACK = MODULES / 'services/src/main/java/org/ovirt/engine/core/services/SsoCallbackServlet.java'
WELCOME = MODULES / 'welcome/src/main/java/org/ovirt/engine/core/WelcomeServlet.java'
SSO = MODULES / 'enginesso/src/main/java/org/ovirt/engine/core/sso'
REST_FILTER = MODULES / 'aaa/src/main/java/org/ovirt/engine/core/aaa/filters/SsoRestApiAuthFilter.java'
CHECK = MODULES / 'uutils/src/main/java/org/ovirt/engine/core/uutils/security/ClientSerialCheck.java'


def read(path):
    return path.read_text(encoding='utf-8')


class ClientSerialAuditTest(unittest.TestCase):
    def test_a_refusal_is_an_event_of_its_own_with_a_flood_guard(self):
        self.assertRegex(
            read(TYPES),
            r'CLIENT_SERIAL_REJECTED\(13718, AuditLogSeverity\.ERROR, AuditLogTimeInterval\.MINUTE\.getValue\(\)\)')
        message = re.search(r'^CLIENT_SERIAL_REJECTED=.*$', read(MESSAGES), re.M).group(0)
        self.assertIn('${SourceIP}', message)
        self.assertIn('${ClientSerialRefusal}', message)

    def test_the_engine_accepts_it_from_the_sso_and_keys_the_guard_on_the_source(self):
        callback = read(CALLBACK)

        self.assertIn('AuditLogType.CLIENT_SERIAL_REJECTED.name().equals(requestedType)', callback)
        self.assertIn("event.setCustomId(sourceIp + '|' + refusal);", callback)

    def test_every_place_that_checks_the_serial_records_the_refusal(self):
        self.assertIn('TerminalAccessAudit.check(request) != null', read(WELCOME))
        self.assertIn('TerminalAccessAudit.check(req) != null', read(REST_FILTER))
        self.assertIn('ClientSerialAudit.require(request);', read(SSO / 'service/SsoService.java'))
        self.assertIn('SsoService::validateClientSerial', read(SSO / 'servlets/RsaPublicKeyServlet.java'))

    def test_the_presented_serial_is_never_logged(self):
        welcome = read(WELCOME)

        self.assertNotIn('Unauthorized client serial: {}', welcome)
        self.assertNotIn('clientSerial)', re.sub(r'request\.setAttribute\("CLIENT_SERIAL", clientSerial\)', '', welcome))

    def test_a_login_without_the_header_is_refused_rather_than_let_through(self):
        authorize = read(SSO / 'servlets/OAuthAuthorizeServlet.java')
        token = read(SSO / 'servlets/OAuthTokenServlet.java')

        handle = authorize[authorize.index('protected void handleRequest'):]
        self.assertLess(handle.index('requireRegisteredTerminal(request);'),
                        handle.index('SsoConstants.JSON_RESPONSE_TYPE'))
        self.assertIn('if (presentsUserCredentials(grantType, scope)) {', token)
        # The engine talking to its own SSO has no terminal behind it.
        self.assertIn('ovirt-ext=token:login-on-behalf', token[token.index('presentsUserCredentials(String'):])

    def test_an_unreadable_serial_lets_nothing_in(self):
        check = read(CHECK)

        self.assertIn('return Refusal.UNVERIFIABLE;', check)
        self.assertIn('MessageDigest.isEqual(', check)


if __name__ == '__main__':
    unittest.main()
