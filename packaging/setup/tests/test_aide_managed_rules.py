import re
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
ACL = ROOT / 'packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/system/acl.py'

# The files the engine and engine-setup rewrite in the course of approved work, each with
# what rewrites it. Watched for ownership and permissions, never left out.
REWRITTEN = (
    # engine-setup, on every run
    r'/etc/ovirt-engine/engine\.conf\.d/[12][0-9]-setup-.*\.conf$',
    r'/etc/ovirt-engine/aaa/.*\.properties$',
    r'/etc/ovirt-engine/extensions\.d/internal-auth[nz]\.properties$',
    # the engine, when a change is applied from the screen
    r'/etc/ovirt-engine/encryptor/config\.json$',
    r'/etc/ovirt-engine/engine\.conf\.d/99-limit-user-sessions\.conf$',
    r'/etc/httpd/conf\.d/z-ovirt-engine-proxy\.conf$',
    # secrets an administrator rotates
    r'/etc/ovirt-engine/encryptor/passphrase$',
    r'/etc/ovirt-engine/encryptor/vault-token$',
    r'/etc/ovirt-engine/encryptor/private_pkcs8\.der$',
    # certificates, renewed on expiry and replaced from the screen
    r'/etc/pki/ovirt-engine/certs/apache\.cer$',
    r'/etc/pki/ovirt-engine/keys/apache\.key\.nopass$',
    r'/etc/pki/ovirt-engine/apache-ca\.pem$',
)

# What the installation is measured against. Nothing here may be lowered or dropped without
# the change being deliberate.
WATCHED = (
    '/usr/share/ovirt-engine/ NORMAL',
    '/usr/share/ovirt-engine-wildfly/ NORMAL',
    '/usr/share/ovirt-engine-keycloak/ NORMAL',
    '/usr/share/ovirt-engine-dwh/ NORMAL',
    '/usr/share/ovirt-engine-extension-aaa-jdbc/ NORMAL',
    '/usr/share/ovirt-cockpit-sso/ NORMAL',
    '/etc/ovirt-engine/ NORMAL',
    '/etc/pki/ovirt-engine/ NORMAL',
    '/etc/httpd CONTENT_EX',
)


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

        for rule in WATCHED:
            self.assertIn(f'\n{rule}\n', written)

    def test_watches_the_engines_own_code_and_not_two_of_its_directories(self):
        # /usr/share/ovirt-engine/ovirt-engine-wildfly does not exist - wildfly is installed at
        # /usr/share/ovirt-engine-wildfly (see JBOSS_HOME in the Makefile) - so naming it
        # watched nothing, and naming two subdirectories left engine.ear, bin and services,
        # which are the engine itself, measured by nothing at all.
        written = self.plugin._aide_config_with_exclusions('')

        self.assertNotIn('/usr/share/ovirt-engine/ovirt-engine-wildfly', written)
        self.assertNotIn('/usr/share/ovirt-engine/ovirt-engine-keycloak', written)
        self.assertIn('\n/usr/share/ovirt-engine/ NORMAL\n', written)

    def test_what_is_rewritten_in_approved_work_is_lowered_and_never_excluded(self):
        # Excluded outright, any of these could be made world-writable, given away or
        # relabelled and nothing would report it. Watching ownership and permissions keeps the
        # control while the content changes as it is meant to.
        written = self.plugin._aide_config_with_exclusions('')

        self.assertIn('\nOVIRT_PERMS = p+u+g+acl+selinux+xattrs\n', written)
        for path in REWRITTEN:
            self.assertIn(f'\n{path} OVIRT_PERMS\n', written)
            self.assertNotIn(f'\n!{path}', written)

    def test_the_group_is_defined_before_the_rules_that_use_it(self):
        # aide.conf is read top to bottom, and a group used before it is defined is an error
        # that stops the whole check - which reads in the event list as a host nobody checked.
        written = self.plugin._aide_config_with_exclusions('')

        self.assertLess(
            written.index('OVIRT_PERMS = '),
            written.index(f'{REWRITTEN[0]} OVIRT_PERMS'),
        )

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

        for excluded in (
            '!/var/lib/ovirt-engine/',
            '!/var/log/ovirt-engine/',
            '!/var/cache/ovirt-engine/',
            '!/var/tmp/ovirt-engine/',
            # /var/run is a symlink to /run on current systems, and AIDE matches the path as
            # the rule spells it, so excluding one of the two excludes only one of the two.
            '!/run/ovirt-engine/',
            '!/var/run/ovirt-engine/',
        ):
            self.assertIn(f'\n{excluded}\n', written)


if __name__ == '__main__':
    unittest.main()
