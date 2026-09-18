import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
SCRIPT = ROOT / 'packaging/bin/ovirt-engine-check-deployment.sh'


class DeploymentCheckTest(unittest.TestCase):
    """The files that are not compiled into the engine's jars are deployed separately.

    A deployment that carries the jars alone leaves the engine calling things that are not
    there, and each time it has looked like a different bug: a verification runner older than
    the engine reading a result nobody wrote, a stored function called once a minute that did
    not exist, a setup plugin importing a module that had not been copied.
    """

    def setUp(self):
        self.script = SCRIPT.read_text(encoding='utf-8')

    def test_it_only_reads(self):
        # Run on a production engine by somebody diagnosing an outage.
        for writing in ('cp ', 'rm ', 'mv ', 'install ', 'chown', 'chmod', '> "$target"'):
            self.assertNotIn(writing, self.script, writing)

    def test_it_names_the_file_and_not_the_directory_it_is_in(self):
        # Testing whether the target is a directory would be wrong: on the installation this is
        # meant to find, the directory is exactly what does not exist.
        self.assertIn('local target="$2/$(basename "$1")"', self.script)

    def test_it_covers_everything_this_product_ships_outside_the_jars(self):
        for path in (
            'ov-works-security_audit.sh',
            'ovirt-engine-security-verification-runner.sh',
            'packaging/pythonlib/ovirt_engine/configfile.py',
            'packaging/pythonlib/ovirt_engine/cryptoevents.py',
            'packaging/setup/ovirt_engine_setup/aide.py',
            'packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/system/acl.py',
            'packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/config/aaajdbc.py',
            'packaging/setup/plugins/ovirt-engine-remove/ovirt-engine/system/aide.py',
            'packaging/encryptor/encrypt_conf_files.py',
            'packaging/encryptor/vault_passphrase.py',
            'packaging/dbscripts/user_login_failures_sp.sql',
        ):
            self.assertIn(path, self.script, path)
            self.assertTrue((ROOT / path).is_file(), f'{path} is named but not in the tree')

    def test_the_find_is_bounded_to_one_directory(self):
        # Without the parentheses -maxdepth applies to the first -name alone and the rest of the
        # expression walks the whole tree, which reported four hundred files instead of twelve.
        find = re.search(r'find "\$SOURCE/packaging/dbscripts/upgrade".*?\| sort',
                         self.script, re.S).group(0)
        self.assertIn('-maxdepth 1', find)
        self.assertIn("-name '04_05_03*.sql'", find)

    def test_it_reports_what_is_missing_and_says_so_in_its_exit_code(self):
        result = subprocess.run(
            ['bash', str(SCRIPT), str(ROOT)],
            capture_output=True, text=True, env={'ENGINE_USR': '/nonexistent', 'PATH': '/usr/bin:/bin'},
        )

        self.assertEqual(1, result.returncode, result.stdout)
        self.assertIn('MISSING  /nonexistent/bin/ov-works-security_audit.sh', result.stdout)
        self.assertIn('engine-setup', result.stdout)
        # And it does not drown the answer in the scripts this product did not write.
        self.assertNotIn('04_01_0000_set_version.sql', result.stdout)

    def test_a_complete_deployment_is_reported_as_one(self):
        # Pointed at the tree as if it were the installation, everything matches itself.
        import shutil
        import tempfile

        with tempfile.TemporaryDirectory() as installed:
            root = Path(installed)
            for source, target in (
                ('ov-works-security_audit.sh', 'bin'),
                ('ovirt-engine-security-verification-runner.sh', 'bin'),
                ('packaging/setup/ovirt_engine_setup/aide.py', 'setup/ovirt_engine_setup'),
            ):
                (root / target).mkdir(parents=True, exist_ok=True)
                shutil.copy(ROOT / source, root / target / Path(source).name)

            result = subprocess.run(
                ['bash', str(SCRIPT), str(ROOT)],
                capture_output=True, text=True,
                env={'ENGINE_USR': str(root), 'PATH': '/usr/bin:/bin'},
            )

        self.assertNotIn('MISSING  %s/bin/ov-works-security_audit.sh' % root, result.stdout)
        self.assertNotIn('DIFFERS', result.stdout)


if __name__ == '__main__':
    unittest.main()
