import ast
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
SSO = ROOT / 'backend/manager/modules/enginesso/src/main'
POLICY = (
    ROOT / 'backend/manager/modules/uutils/src/main/java/org/ovirt/engine/'
    'core/uutils/security/LoginInputPolicy.java'
)
SETUP_AAA = (
    ROOT / 'packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/'
    'config/aaa.py'
)


def read(path):
    return path.read_text(encoding='utf-8')


def java_patterns():
    source = read(POLICY)
    block = source[
        source.index('SQL_INJECTION_PATTERNS = '):
        source.index('private static final List<Pattern> SQL_INJECTION')
    ]
    literals = re.findall(r'^\s*"((?:[^"\\]|\\.)*)"', block, re.M)
    return [
        literal.encode('latin-1').decode('unicode_escape')
        for literal in literals
    ]


def setup_plugin():
    """The login input check of the setup plugin, without otopi."""
    tree = ast.parse(read(SETUP_AAA))
    plugin = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and node.name == 'Plugin'
    )
    wanted = {
        '_MAX_LOGIN_INPUT_LENGTH',
        '_FORBIDDEN_LOGIN_CHARACTERS',
        '_SQL_INJECTION_PATTERNS',
    }
    body = [
        node for node in plugin.body
        if (
            isinstance(node, ast.Assign) and
            node.targets[0].id in wanted
        ) or (
            isinstance(node, ast.FunctionDef) and
            node.name == '_validateLoginInput'
        )
    ]
    module = ast.Module(
        body=[ast.ClassDef(
            name='Checker', bases=[], keywords=[], body=body,
            decorator_list=[],
        )],
        type_ignores=[],
    )
    namespace = {'re': re, '_': lambda message: message}
    exec(compile(ast.fix_missing_locations(module), 'aaa.py', 'exec'),
         namespace)
    return namespace['Checker']


class LoginInputRestrictionTest(unittest.TestCase):
    def test_the_setup_refuses_what_the_login_page_refuses(self):
        checker = setup_plugin()
        self.assertEqual(20, checker._MAX_LOGIN_INPUT_LENGTH)
        self.assertEqual('|;:`', checker._FORBIDDEN_LOGIN_CHARACTERS)
        self.assertEqual(java_patterns(),
                         list(checker._SQL_INJECTION_PATTERNS))

    def test_the_setup_check(self):
        checker = setup_plugin()
        checker._validateLoginInput('Vm!Xk7pLq2Zt#2024')
        for refused in (
            'Vm!Xk7pLq2Zt-Vm!Xk7pL',
            'Vm!Xk7 pLq2Zt',
            'Vm!Xk7:pLq2Zt',
            'Vm!Xk7|pLq2Zt',
            'Vm!Xk7;pLq2Zt',
            'Vm!Xk7`pLq2Zt',
            "Vm!'or1=1Zt",
            'Vm!Xk7--Lq2Zt',
        ):
            with self.assertRaises(RuntimeError, msg=refused):
                checker._validateLoginInput(refused)

    def test_the_generated_password_fits_the_login_page(self):
        self.assertIn('for i in range(20)', read(SETUP_AAA))

    def test_the_login_page_enforces_the_server_rules(self):
        page = read(SSO / 'webapp/WEB-INF/login.jsp')
        self.assertIn('LoginInputPolicy.toJson()', page)
        self.assertIn(
            '<script type="application/json" id="loginInputPolicy">'
            '${loginInputPolicy}</script>',
            page,
        )
        self.assertEqual(2, page.count('maxlength="${loginInputMaxLength}"'))
        self.assertIn('id="usernameInputError"', page)
        self.assertIn('id="passwordInputError"', page)
        # checked as typed, before the password is wrapped and encrypted
        self.assertLess(
            page.index('checkLoginInput(loginInputPolicy, entry.field'),
            page.index('encryptAndSubmit(form).catch'),
        )

    def test_the_server_refuses_before_authentication_and_audits(self):
        interactive = read(
            SSO / 'java/org/ovirt/engine/core/sso/servlets/'
            'InteractiveAuthServlet.java'
        )
        token = read(
            SSO / 'java/org/ovirt/engine/core/sso/servlets/'
            'OAuthTokenServlet.java'
        )
        self.assertIn('LoginInputAudit.check(', interactive)
        self.assertIn(
            'SsoConstants.APP_ERROR_LOGIN_INPUT_REJECTED', interactive)
        self.assertIn('LoginInputAudit.check(', token)
        callback = read(
            ROOT / 'backend/manager/modules/services/src/main/java/org/ovirt/'
            'engine/core/services/SsoCallbackServlet.java'
        )
        self.assertIn(
            'AuditLogType.USER_VDC_LOGIN_INPUT_REJECTED.name().equals('
            'requestedType)',
            callback,
        )
        types = read(
            ROOT / 'backend/manager/modules/common/src/main/java/org/ovirt/'
            'engine/core/common/AuditLogType.java'
        )
        self.assertIn('USER_VDC_LOGIN_INPUT_REJECTED(13719,', types)
        self.assertEqual(1, types.count('(13719'))
        messages = read(
            ROOT / 'backend/manager/modules/dal/src/main/resources/bundles/'
            'AuditLogMessages.properties'
        )
        self.assertIn('USER_VDC_LOGIN_INPUT_REJECTED=', messages)

    def test_new_passwords_follow_the_same_rules(self):
        validator = read(
            ROOT / 'backend/manager/modules/uutils/src/main/java/org/ovirt/'
            'engine/core/uutils/security/PasswordPolicyValidator.java'
        )
        self.assertIn('LoginInputPolicy.checkPassword(password)', validator)
        change = read(SSO / 'webapp/WEB-INF/credentialsChange.jsp')
        self.assertEqual(
            3, change.count('maxlength="<%= LoginInputPolicy.MAX_LENGTH %>"'))


if __name__ == '__main__':
    unittest.main()
