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

    def test_a_baseline_left_unsealed_is_unsealed_not_mismatched(self):
        closeup = self.baseline[self.baseline.index('stage=plugin.Stages.STAGE_CLOSEUP'):]
        # The old seal goes before the new baseline takes its place, so that a seal that cannot
        # be renewed reads as missing (not verifiable) rather than as an altered baseline.
        self.assertLess(closeup.index('os.unlink(oaide.Aide.SEAL)'),
                        closeup.index('os.replace(oaide.Aide.DATABASE_NEW'))
        self.assertIn('if rc != 0 or not os.path.exists(oaide.Aide.SEAL):', closeup)

    def test_what_kept_the_verification_from_being_ready_is_in_the_summary(self):
        self.assertIn('self.logger.error(message)', self.baseline)
        self.assertNotIn('self.logger.warning(', self.baseline)
        summary = self.baseline[self.baseline.index('def _summary(self):'):]
        self.assertIn('for problem in self._problems:', summary)
        self.assertIn('osetupcons.Stages.DIALOG_TITLES_S_SUMMARY,\n            _BASELINE_TAKEN,',
                      self.baseline)

    def test_an_aide_installed_later_in_the_run_still_gets_its_baseline(self):
        # A site's own setup step may install AIDE after the baseline was first due; the baseline
        # is tried again after the engine start and before the end of the summary, and only
        # reported as a problem when AIDE is still not there.
        retry = self.baseline[self.baseline.index('name=_BASELINE_RETRIED,'):]
        retry = retry[:retry.index('def _take_baseline')]
        self.assertIn('oengcommcons.Stages.CORE_ENGINE_START,', retry)
        self.assertIn('osetupcons.Stages.DIALOG_TITLES_E_SUMMARY,', retry)
        self.assertNotIn('DIALOG_TITLES_S_SUMMARY', retry)
        self.assertIn("'AIDE is not installed ({command})", retry)
        self.assertIn('self._take_baseline(content, config)', retry)
        first = self.baseline[self.baseline.index('name=_BASELINE_TAKEN,'):
                              self.baseline.index('name=_BASELINE_RETRIED,')]
        self.assertIn('self._retry = (content, config)', first)
        self.assertNotIn('self._problem(\n                _(\n                    \'AIDE is not installed', first)

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
