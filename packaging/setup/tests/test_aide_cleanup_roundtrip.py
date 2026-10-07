import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
SYSTEM = ROOT / 'packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/system'
ACL_PLUGIN = SYSTEM / 'acl.py'
BASELINE_PLUGIN = SYSTEM / 'integrity_baseline.py'
REMOVE_PLUGIN = (
    ROOT / 'packaging/setup/plugins/ovirt-engine-remove/ovirt-engine/system/aide.py'
)


class AideSetupCleanupTest(unittest.TestCase):
    """engine-setup writes the verification's AIDE configuration and takes its baseline;
    engine-cleanup removes both. /etc/aide.conf belongs to the aide package and is never
    deleted: only a block an earlier engine-setup wrote into it is taken out."""

    def setUp(self):
        self.acl = ACL_PLUGIN.read_text(encoding='utf-8')
        self.baseline = BASELINE_PLUGIN.read_text(encoding='utf-8')
        self.remove = REMOVE_PLUGIN.read_text(encoding='utf-8')

    def test_setup_takes_the_baseline_after_every_file_is_written_and_before_the_engine_starts(self):
        self.assertIn("_DB_CREDENTIALS_ENCRYPTED = 'osetup.db.connection.credentials.encrypted'",
                      self.baseline)
        closeup = self.baseline[self.baseline.index('stage=plugin.Stages.STAGE_CLOSEUP'):]
        self.assertIn('after=(\n            _DB_CREDENTIALS_ENCRYPTED,', closeup)
        self.assertIn('oengcommcons.Stages.CORE_ENGINE_START,', closeup)
        self.assertIn('oaide.Aide.init_command()', closeup)
        self.assertIn('os.replace(oaide.Aide.DATABASE_NEW, oaide.Aide.DATABASE)', closeup)
        self.assertIn('os.chmod(config, 0o644)', closeup)

    def test_setup_says_when_the_baseline_could_not_be_taken(self):
        self.assertIn('AIDE is not installed', self.baseline)
        self.assertIn('baseline could not be taken', self.baseline)

    def test_sudo_allows_exactly_the_commands_the_verification_runs(self):
        self.assertIn("' '.join(oaide.Aide.check_command()).replace('=', '\\\\=')", self.acl)
        self.assertIn("'ovirt ALL=(root) NOPASSWD: {seal}, {check}\\n'", self.acl)
        self.assertIn("seal=' '.join(oaide.Aide.verify_seal_command())", self.acl)
        self.assertNotIn('process-file-stat', self.acl)
        self.assertNotIn('/usr/sbin/aide --check', self.acl)

    def test_the_old_rules_in_aide_conf_are_taken_out_not_the_file(self):
        for plugin in (self.baseline, self.remove):
            self.assertIn('oaide.Aide.without_legacy_block(content)', plugin)
            self.assertIn('if without == content:', plugin)
        self.assertNotIn('os.unlink(path)\n        try:\n            os.rmdir', self.baseline)

    def test_setup_seals_the_baseline_and_takes_it_after_the_sudo_rule(self):
        closeup = self.baseline[self.baseline.index('stage=plugin.Stages.STAGE_CLOSEUP'):]
        self.assertIn('oaide.Aide.SUDOERS_WRITTEN_EVENT,', closeup)
        self.assertIn('name=oaide.Aide.SUDOERS_WRITTEN_EVENT,', self.acl)
        self.assertLess(closeup.index('os.replace(oaide.Aide.DATABASE_NEW'),
                        closeup.index('oaide.Aide.seal_command()'))
        self.assertIn('could not be sealed', closeup)

    def test_cleanup_removes_the_configuration_and_the_baseline(self):
        for name in ('oaide.Aide.CONFIG_PATH', 'oaide.Aide.DATABASE', 'oaide.Aide.DATABASE_NEW',
                     'oaide.Aide.SEAL'):
            self.assertIn(name, self.remove)
        self.assertIn('os.unlink(path)', self.remove)
        # /etc/aide.conf is rewritten, never unlinked.
        self.assertIn('filetransaction.FileTransaction', self.remove)

    def test_both_sides_read_the_markers_from_one_place(self):
        for plugin in (self.baseline, self.remove):
            self.assertIn('from ovirt_engine_setup import aide as oaide', plugin)
            self.assertNotIn('BEGIN OVIRT-ENGINE MANAGED EXCLUSIONS', plugin)


if __name__ == '__main__':
    unittest.main()
