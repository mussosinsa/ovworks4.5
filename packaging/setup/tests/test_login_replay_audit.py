import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
SSO = ROOT / 'backend/manager/modules/enginesso/src/main'


def read(path):
    return (ROOT / path).read_text(encoding='utf-8')


class LoginReplayAuditTest(unittest.TestCase):
    def test_the_login_page_wraps_the_password_with_its_issued_nonce(self):
        page = (SSO / 'webapp/WEB-INF/login.jsp').read_text(encoding='utf-8')
        self.assertIn('LoginFormNonce.issue(loginFormSession)', page)
        self.assertIn('id="loginFormNonce"', page)
        self.assertIn("'ovirt-login:v1:' + loginFormIssuedAt + ':' + loginFormNonce + ':'", page)
        self.assertIn('encryptText(publicKey, wrappedPassword)', page)

    def test_the_login_form_is_checked_and_a_refusal_is_audited(self):
        servlet = (
            SSO / 'java/org/ovirt/engine/core/sso/servlets/InteractiveAuthServlet.java'
        ).read_text(encoding='utf-8')
        self.assertIn('LoginFormNonce.unwrap(', servlet)
        self.assertIn('LoginReplayAudit.Channel.LOGIN_PAGE', servlet)

    def test_a_rest_replay_is_audited(self):
        servlet = (
            SSO / 'java/org/ovirt/engine/core/sso/servlets/OAuthTokenServlet.java'
        ).read_text(encoding='utf-8')
        self.assertEqual(2, servlet.count(
            'LoginReplayAudit.report(ssoContext, request, username[0], '
            'LoginReplayAudit.Channel.API'))

    def test_the_engine_records_the_event_under_its_own_type(self):
        callback = read(
            'backend/manager/modules/services/src/main/java/org/ovirt/engine/'
            'core/services/SsoCallbackServlet.java'
        )
        types = read(
            'backend/manager/modules/common/src/main/java/org/ovirt/engine/'
            'core/common/AuditLogType.java'
        )
        messages = read(
            'backend/manager/modules/dal/src/main/resources/bundles/'
            'AuditLogMessages.properties'
        )
        self.assertIn('AuditLogType.USER_VDC_LOGIN_REPLAY_BLOCKED.name().equals(requestedType)', callback)
        self.assertIn('USER_VDC_LOGIN_REPLAY_BLOCKED(13675', types)
        self.assertIn('USER_VDC_LOGIN_REPLAY_BLOCKED=', messages)


if __name__ == '__main__':
    unittest.main()
