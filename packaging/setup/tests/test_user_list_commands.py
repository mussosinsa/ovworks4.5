import re
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
USER_LIST_MODEL = (
    ROOT
    / 'frontend/webadmin/modules/uicommonweb/src/main/java/org/ovirt/engine'
    / 'ui/uicommonweb/models/users/UserListModel.java'
)


class UserListCommandsTest(unittest.TestCase):
    def test_every_dialog_button_reaches_its_handler(self):
        # A button is created with a command name and does nothing unless executeCommand()
        # dispatches that name. The group creation dialog's OK button was created as
        # "OnAddLocalGroup" with no such branch, so pressing it did nothing at all.
        source = USER_LIST_MODEL.read_text(encoding='utf-8')
        created = set(re.findall(
            r'UICommand\.createDefaultOkUiCommand\("([A-Za-z]+)", this\)', source
        ))
        self.assertIn('OnAddLocalGroup', created)
        for name in created:
            self.assertIn('"%s".equals(command.getName())' % name, source, name)

    def test_group_ok_button_creates_the_group(self):
        source = USER_LIST_MODEL.read_text(encoding='utf-8')
        branch = re.search(
            r'if \("OnAddLocalGroup"\.equals\(command\.getName\(\)\)\) \{'
            r' //\$NON-NLS-1\$\s+onAddLocalGroup\(\);',
            source,
        )
        self.assertIsNotNone(branch)
        self.assertIn('ActionType.AddLocalGroup', source)


if __name__ == '__main__':
    unittest.main()
