import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
SETUP_PLUGIN = (
    ROOT / 'packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/system/acl.py'
)
REMOVE_PLUGIN = (
    ROOT / 'packaging/setup/plugins/ovirt-engine-remove/ovirt-engine/system/aide.py'
)


class AideCleanupRoundtripTest(unittest.TestCase):
    """/etc/aide.conf belongs to the aide package, not to this product.

    engine-cleanup deletes every file registered as one setup modified - it does not restore
    them - so registering this one took the distribution's whole AIDE configuration with it on
    cleanup. engine-setup then found no file, skipped, and left the installation measured
    against nothing at all.
    """

    def setUp(self):
        self.setup = SETUP_PLUGIN.read_text(encoding='utf-8')
        self.remove = REMOVE_PLUGIN.read_text(encoding='utf-8')

    def test_setup_does_not_register_aide_conf_for_deletion(self):
        aide_transaction = self.setup[
            self.setup.index('def _configure_aide_exclusions'):
            self.setup.index('def _closeup')
        ]

        self.assertIn('oaide.Aide.with_block(content)', aide_transaction)
        # modifiedList= is what puts a file in MODIFIED_FILES, which is the list cleanup
        # deletes. Matched on the keyword rather than the constant, so that naming the
        # constant in a comment saying why it is absent does not satisfy the test.
        self.assertNotIn('modifiedList', aide_transaction)
        self.assertIn(
            'osetupcons.CoreEnv.UNINSTALL_UNREMOVABLE_FILES\n        ].append(',
            aide_transaction,
        )

    def test_cleanup_removes_the_block_and_leaves_the_file(self):
        self.assertIn('oaide.Aide.without_block(content)', self.remove)
        # Rewritten, not unlinked.
        self.assertIn('filetransaction.FileTransaction', self.remove)
        self.assertNotIn('os.unlink', self.remove)
        self.assertNotIn('os.remove', self.remove)

    def test_cleanup_does_nothing_to_a_file_with_no_block_in_it(self):
        # A host where aide was installed after engine-setup ran, or where somebody took the
        # block out by hand. Rewriting the file for nothing would change its mtime, which is
        # what AIDE is watching.
        self.assertIn('if without == content:', self.remove)
        self.assertIn('if not os.path.exists(oaide.Aide.CONFIG_PATH):', self.remove)

    def test_both_sides_read_the_markers_from_one_place(self):
        # The block engine-cleanup looks for has to be the block engine-setup wrote, and the
        # two run from different plugin trees.
        for plugin in (self.setup, self.remove):
            self.assertIn('from ovirt_engine_setup import aide as oaide', plugin)
            self.assertNotIn('BEGIN OVIRT-ENGINE MANAGED EXCLUSIONS', plugin)

    def test_a_missing_aide_conf_is_not_passed_over_quietly(self):
        # Without the file nothing is measured, and an integrity check that checks nothing
        # looks, in the event list, like one that found nothing wrong.
        self.assertIn('self.logger.warning', self.setup)
        self.assertIn('has no rules to check the installation against', self.setup)


if __name__ == '__main__':
    unittest.main()
