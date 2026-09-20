import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
UI = 'frontend/webadmin/modules/uicommonweb/src/main/java/org/ovirt/engine/ui/uicommonweb'
COMMON = 'frontend/webadmin/modules/gwt-common/src/main/java/org/ovirt/engine/ui/common'
POPUP = COMMON + '/view/popup/permissions/AbstractPermissionsPopupView'
PRESENTER = COMMON + '/presenter/popup/permissions/AbstractPermissionsPopupPresenterWidget.java'


def read(relative):
    return (ROOT / relative).read_text(encoding='utf-8')


class VmPermissionSearchPanelTest(unittest.TestCase):
    def test_the_whole_row_is_hidden_rather_than_its_parts(self):
        layout = read(POPUP + '.ui.xml')
        view = read(POPUP + '.java')

        # The row holds the profile, the namespace, the search box and the button; naming it is
        # what lets all four go at once and leaves nothing of the row behind.
        self.assertIn('<b:Row ui:field="searchPanel">', layout)
        self.assertIn('searchPanel.setVisible(!indic)', view)

    def test_only_the_virtual_machine_list_hides_it(self):
        permissions = read(UI + '/models/configure/PermissionListModel.java')
        vms = read(UI + '/models/vms/VmListModel.java')

        # Off unless a list turns it on, so every other permission tab is as it was.
        self.assertIn('private boolean searchPanelHidden;', permissions)
        self.assertIn('model.getIsSearchPanelHidden().setEntity(searchPanelHidden);', permissions)
        self.assertIn('permissionListModel.setSearchPanelHidden(true);', vms)

    def test_no_other_list_turns_it_on(self):
        turned_on = [
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / UI).rglob('*.java')
            if 'setSearchPanelHidden(true)' in path.read_text(encoding='utf-8')
        ]

        self.assertEqual([UI + '/models/vms/VmListModel.java'], turned_on)

    def test_switching_between_users_and_groups_fills_the_list_again(self):
        presenter = read(PRESENTER)

        # Switching empties the list, which is a thing to press Search after. With the row gone
        # there is nothing to press, so the list would stay empty and read as "there are none".
        self.assertEqual(2, presenter.count('searchAgainWhereThereIsNothingToPress(model);'))
        self.assertIn('getIsSearchPanelHidden().getEntity()', presenter)

    def test_the_list_is_filled_without_anyone_pressing_search(self):
        model = read(UI + '/models/users/AdElementListModel.java')

        # Hiding the row only works because the dialog searches as it opens.
        self.assertIn('searchOnOpen();', model)


if __name__ == '__main__':
    unittest.main()
