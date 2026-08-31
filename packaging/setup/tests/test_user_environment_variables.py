import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
VIEW_ROOT = (
    ROOT
    / 'frontend/webadmin/modules/webadmin/src/main/java'
    / 'org/ovirt/engine/ui/webadmin/section/main/view/popup/configure'
)
COMMAND = (
    ROOT
    / 'backend/manager/modules/bll/src/main/java'
    / 'org/ovirt/engine/core/bll/UserEnvironmentVariableCommandBase.java'
)


class UserEnvironmentVariablesTest(unittest.TestCase):
    def test_max_login_minutes_is_not_exposed(self):
        view = (VIEW_ROOT / 'UserEnvironmentVariablesView.java').read_text(
            encoding='utf-8'
        )
        template = (
            VIEW_ROOT / 'UserEnvironmentVariablesView.ui.xml'
        ).read_text(encoding='utf-8')
        command = COMMAND.read_text(encoding='utf-8')

        self.assertNotIn('MAX_LOGIN_MINUTES', view)
        self.assertNotIn('MAX_LOGIN_MINUTES', template)
        self.assertNotIn('MAX_LOGIN_MINUTES', command)
        self.assertNotIn('기본 로그인 세션 시간', template)

    def test_failed_login_limit_remains_available(self):
        view = (VIEW_ROOT / 'UserEnvironmentVariablesView.java').read_text(
            encoding='utf-8'
        )
        command = COMMAND.read_text(encoding='utf-8')

        self.assertIn('MAX_FAILURES_SINCE_SUCCESS', view)
        self.assertIn('MAX_FAILURES_SINCE_SUCCESS', command)


if __name__ == '__main__':
    unittest.main()
