import re
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
ACL = ROOT / 'packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/system/acl.py'

EXPECTED = """### oVirt Specific Monitoring Rules ###
/etc/ovirt-engine/ NORMAL
!/var/lib/ovirt-engine/
/usr/share/ovirt-cockpit-sso/ NORMAL
/usr/share/ovirt-engine-dwh/ NORMAL
/usr/share/ovirt-engine-extension-aaa-jdbc/ NORMAL
/usr/share/ovirt-engine/ovirt-engine-keycloak/ NORMAL
/usr/share/ovirt-engine/ovirt-engine-wildfly/ NORMAL
!/var/log/ovirt-engine/
!/var/run/ovirt-engine/
/etc/httpd CONTENT_EX
!/etc/httpd/conf\\.d/z-ovirt-engine-proxy\\.conf$"""


def plugin():
    """The real class, with the otopi machinery it does not need here left out."""
    src = ACL.read_text(encoding='utf-8')
    body = src[src.index('class Plugin'):src.index('    def __init__(self, context):')]
    body = body.replace('class Plugin(plugin.PluginBase):', 'class Plugin:')
    method = re.search(
        r'    def _aide_config_with_exclusions.*?\n        return content \+ .*?\n',
        src,
        re.DOTALL,
    ).group(0)
    namespace = {'re': re}
    exec(body + method, namespace)  # noqa: S102 - the file under test is the point
    return namespace['Plugin']()


class AideManagedRulesTest(unittest.TestCase):
    """What engine-setup writes into /etc/aide.conf is what the host is measured against, so
    the rules are pinned here rather than left to be noticed missing after a change."""

    def setUp(self):
        self.plugin = plugin()

    def test_writes_the_rules_the_installation_is_measured_against(self):
        written = self.plugin._aide_config_with_exclusions('/boot NORMAL\n')

        self.assertIn(EXPECTED, written)

    def test_replaces_its_own_block_rather_than_adding_another(self):
        # engine-setup runs again on every upgrade, and two blocks would leave the older set of
        # rules in force alongside the newer one.
        once = self.plugin._aide_config_with_exclusions(
            '/boot NORMAL\n\n'
            '# BEGIN OVIRT-ENGINE MANAGED EXCLUSIONS\n'
            '/etc/httpd CONTENT_EX\n'
            '!/tmp/ovirt-jar-checksums\\..*$\n'
            '# END OVIRT-ENGINE MANAGED EXCLUSIONS\n'
        )
        twice = self.plugin._aide_config_with_exclusions(once)

        self.assertEqual(1, once.count('# BEGIN OVIRT-ENGINE MANAGED EXCLUSIONS'))
        self.assertNotIn('ovirt-jar-checksums', once)
        self.assertEqual(once, twice)

    def test_leaves_the_rest_of_the_file_alone(self):
        written = self.plugin._aide_config_with_exclusions(
            '# AIDE configuration\n/boot   NORMAL\n/bin    NORMAL\n'
        )

        self.assertTrue(written.startswith('# AIDE configuration\n/boot   NORMAL\n/bin    NORMAL'))

    def test_the_engines_own_state_is_not_measured(self):
        # It is written while the engine runs - the verification results among it - so every
        # check would report it and bury whatever else the check found.
        written = self.plugin._aide_config_with_exclusions('')

        for excluded in ('!/var/lib/ovirt-engine/', '!/var/log/ovirt-engine/'):
            self.assertIn(f'\n{excluded}\n', written)


if __name__ == '__main__':
    unittest.main()
