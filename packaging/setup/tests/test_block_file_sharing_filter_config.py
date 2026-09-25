import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
KEY = 'EnforceBlockFileSharingFilter'
UPGRADE = 'packaging/dbscripts/upgrade/04_05_0345_add_enforce_block_file_sharing_filter.sql'
BLL = 'backend/manager/modules/bll/src/main/java/org/ovirt/engine/core/bll'
UI = 'frontend/webadmin/modules/uicommonweb/src/main/java/org/ovirt/engine/ui/uicommonweb'
WEBADMIN = 'frontend/webadmin/modules/webadmin/src/main/java/org/ovirt/engine/ui/webadmin'


def read(relative):
    return (ROOT / relative).read_text(encoding='utf-8')


class BlockFileSharingFilterConfigTest(unittest.TestCase):
    def test_the_setting_is_installed_off_and_reaches_engine_config(self):
        self.assertIn(KEY + '.description=', read(
            'packaging/etc/engine-config/engine-config.properties'))
        # Off, both on a clean install and on an upgrade, and the same in both: an engine
        # should not behave differently depending on which of the two it arrived by.
        for path in ('packaging/dbscripts/upgrade/pre_upgrade/0000_config.sql', UPGRADE):
            self.assertIn("fn_db_add_config_value('" + KEY + "','false','general')",
                          read(path).replace("', '", "','"))

    def test_a_setting_that_cannot_be_read_leaves_the_engine_as_installed(self):
        helper = read(BLL + '/network/cluster/NetworkHelper.java')
        model = read(UI + '/models/profiles/VnicProfileModel.java')

        # Falling back to enforced would turn on, on a missing value, what a clean install
        # leaves off - which is the one state nobody chose.
        self.assertIn(
            'Boolean.TRUE.equals(Config.<Boolean> getValue(ConfigValues.' + KEY + '))', helper)
        self.assertIn('Boolean.TRUE.equals(AsyncDataProvider.getInstance()', model)

    def test_both_write_paths_consult_the_setting(self):
        add = read(BLL + '/network/vm/AddVnicProfileCommand.java')
        update = read(BLL + '/network/vm/UpdateVnicProfileCommand.java')

        # The REST API and the SDK reach the same two commands as the dialog does, so a
        # setting the dialog alone honoured would not be a setting at all.
        self.assertIn('isVnicProfileNetworkFilterEnforced()', add)
        self.assertIn('isVnicProfileNetworkFilterEnforced()', update)

    def test_a_passthrough_profile_carries_no_filter_either_way(self):
        # libvirt has nowhere to put one, and the engine refuses a profile that has both.
        update = read(BLL + '/network/vm/UpdateVnicProfileCommand.java')
        self.assertIn('if (getVnicProfile().isPassthrough()) {', update)

        model = read(UI + '/models/profiles/VnicProfileModel.java')
        # Decided before the filter is, or the profile answers with its previous state.
        self.assertLess(model.index('vnicProfile.setPassthrough(getPassthrough().getEntity());'),
                        model.index('vnicProfile.setNetworkFilterId(flushedNetworkFilterId());'))

    def test_the_lists_show_the_filter_a_profile_actually_has(self):
        for path in (WEBADMIN + '/section/main/view/MainVnicProfileView.java',
                     WEBADMIN + '/section/main/view/tab/network/SubTabNetworkProfileView.java'):
            source = read(path)
            self.assertIn('object.getNetworkFilterName()', source)
            self.assertNotIn('return NetworkFilter.BLOCK_FILE_SHARING;', source)

    def test_the_dialog_does_not_offer_a_choice_it_will_discard(self):
        model = read(UI + '/models/profiles/VnicProfileModel.java')
        self.assertIn('networkFilterEnforcedByPolicy()', model)
        self.assertIn('getNetworkFilter().setIsChangeable(false)', model)


if __name__ == '__main__':
    unittest.main()
