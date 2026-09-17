import importlib.util
import sys
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]

# otopi is not installed here and none of what is under test needs it.
_otopi = sys.modules.setdefault('otopi', types.ModuleType('otopi'))
_util = sys.modules.setdefault('otopi.util', types.ModuleType('otopi.util'))
_util.export = lambda obj: obj
_otopi.util = _util


def _load(path, name):
    """Load by path: tests/ has a stub ovirt_engine_setup package that shadows the real one."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


Aide = _load(ROOT / 'packaging/setup/ovirt_engine_setup/aide.py', '_aide_under_test').Aide


ORIGINAL = '# AIDE configuration\n/boot   NORMAL\n/bin    NORMAL\n'

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

# The files the engine and engine-setup rewrite in the course of approved work, each watched
# for ownership and permissions, never left out.
REWRITTEN = (
    r'/etc/ovirt-engine/engine\.conf\.d/[12][0-9]-setup-.*\.conf$',
    r'/etc/ovirt-engine/aaa/.*\.properties$',
    r'/etc/ovirt-engine/extensions\.d/internal-auth[nz]\.properties$',
    r'/etc/ovirt-engine/encryptor/config\.json$',
    r'/etc/ovirt-engine/engine\.conf\.d/99-limit-user-sessions\.conf$',
    r'/etc/httpd/conf\.d/z-ovirt-engine-proxy\.conf$',
    r'/etc/ovirt-engine/encryptor/passphrase$',
    r'/etc/ovirt-engine/encryptor/vault-token$',
    r'/etc/ovirt-engine/encryptor/private_pkcs8\.der$',
    r'/etc/pki/ovirt-engine/certs/apache\.cer$',
    r'/etc/pki/ovirt-engine/keys/apache\.key\.nopass$',
    r'/etc/pki/ovirt-engine/apache-ca\.pem$',
)


class AideManagedRulesTest(unittest.TestCase):
    """What engine-setup writes into /etc/aide.conf is what the host is measured against, so
    the rules are pinned here rather than left to be noticed missing after a change."""

    def test_writes_the_rules_the_installation_is_measured_against(self):
        written = Aide.with_block(ORIGINAL)

        for rule in WATCHED:
            self.assertIn(f'\n{rule}\n', written)

    def test_watches_the_engines_own_code_and_not_two_of_its_directories(self):
        # /usr/share/ovirt-engine/ovirt-engine-wildfly does not exist - wildfly is installed at
        # /usr/share/ovirt-engine-wildfly (see JBOSS_HOME in the Makefile) - so naming it
        # watched nothing, and naming two subdirectories left engine.ear, bin and services,
        # which are the engine itself, measured by nothing at all.
        written = Aide.with_block(ORIGINAL)

        self.assertNotIn('/usr/share/ovirt-engine/ovirt-engine-wildfly', written)
        self.assertNotIn('/usr/share/ovirt-engine/ovirt-engine-keycloak', written)
        self.assertIn('\n/usr/share/ovirt-engine/ NORMAL\n', written)

    def test_what_is_rewritten_in_approved_work_is_lowered_and_never_excluded(self):
        # Excluded outright, any of these could be made world-writable, given away or
        # relabelled and nothing would report it.
        written = Aide.with_block(ORIGINAL)

        self.assertIn('\nOVIRT_PERMS = p+u+g+acl+selinux+xattrs\n', written)
        for path in REWRITTEN:
            self.assertIn(f'\n{path} OVIRT_PERMS\n', written)
            self.assertNotIn(f'\n!{path}', written)

    def test_the_group_is_defined_before_the_rules_that_use_it(self):
        # aide.conf is read top to bottom, and a group used before it is defined is an error
        # that stops the whole check - which reads in the event list as a host nobody checked.
        written = Aide.with_block(ORIGINAL)

        self.assertLess(
            written.index('OVIRT_PERMS = '),
            written.index(f'{REWRITTEN[0]} OVIRT_PERMS'),
        )

    def test_the_engines_own_state_is_not_measured(self):
        # It is written while the engine runs - the verification results among it - so every
        # check would report it and bury whatever else the check found.
        written = Aide.with_block(ORIGINAL)

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

    def test_replaces_its_own_block_rather_than_adding_another(self):
        # engine-setup runs again on every upgrade, and two blocks would leave the older set of
        # rules in force alongside the newer one.
        once = Aide.with_block(
            ORIGINAL + '\n'
            f'{Aide.BEGIN}\n/etc/httpd CONTENT_EX\n!/tmp/ovirt-jar-checksums\\..*$\n{Aide.END}\n'
        )
        twice = Aide.with_block(once)

        self.assertEqual(1, once.count(Aide.BEGIN))
        self.assertNotIn('ovirt-jar-checksums', once)
        self.assertEqual(once, twice)

    def test_leaves_the_rest_of_the_file_alone(self):
        self.assertTrue(Aide.with_block(ORIGINAL).startswith(ORIGINAL.rstrip('\n')))

    def test_cleanup_takes_back_exactly_what_setup_wrote(self):
        # engine-cleanup removes the block; it does not remove the file. /etc/aide.conf belongs
        # to the aide package, and deleting it takes the distribution's whole AIDE
        # configuration with it - after which engine-setup finds no file and writes no rules,
        # so the installation is measured against nothing.
        self.assertEqual(ORIGINAL, Aide.without_block(Aide.with_block(ORIGINAL)))

    def test_setup_after_cleanup_gives_back_what_setup_gave_before(self):
        first = Aide.with_block(ORIGINAL)
        after_cleanup = Aide.without_block(first)
        second = Aide.with_block(after_cleanup)

        self.assertEqual(first, second)

    def test_cleanup_on_a_file_it_never_touched_changes_nothing(self):
        self.assertEqual(ORIGINAL, Aide.without_block(ORIGINAL))


if __name__ == '__main__':
    unittest.main()
