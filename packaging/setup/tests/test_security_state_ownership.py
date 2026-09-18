import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
AUDIT = ROOT / 'ov-works-security_audit.sh'
RUNNER = ROOT / 'ovirt-engine-security-verification-runner.sh'
ACL = ROOT / 'packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/system/acl.py'

STATE_DIR = '/var/lib/ovirt-engine/security'


def helper_from(script):
    """The ensure_engine_dir function as the script defines it."""
    return re.search(
        r'^ensure_engine_dir\(\) \{.*?^\}', script.read_text(encoding='utf-8'), re.M | re.S
    ).group(0)


class SecurityStateOwnershipTest(unittest.TestCase):
    """The start gate writes its verdict into the engine's security state directory.

    A directory the engine user cannot write is not an inconvenience there: the gate cannot
    record a verdict, so it refuses the start, and the whole account of it is "Permission
    denied". Anything that runs as root and creates the directory first - an audit run by hand,
    an earlier engine-setup - leaves it owned by root and does exactly that.
    """

    def test_both_scripts_create_it_the_same_way(self):
        self.assertEqual(helper_from(AUDIT), helper_from(RUNNER))

    def test_nothing_creates_it_with_a_bare_mkdir(self):
        for script in (AUDIT, RUNNER):
            text = script.read_text(encoding='utf-8')
            for line in text.splitlines():
                if 'mkdir -p' in line and 'ensure_engine_dir' not in line:
                    self.assertNotIn(
                        'INTEGRITY_RESULTS', line,
                        f'{script.name}: {line.strip()}',
                    )
                    self.assertNotIn(
                        'AUDIT_RESULTS', line,
                        f'{script.name}: {line.strip()}',
                    )
                    self.assertNotIn(
                        'INTEGRITY_BASELINE', line,
                        f'{script.name}: {line.strip()}',
                    )

    def test_it_takes_the_owner_from_the_parent_rather_than_a_name(self):
        # The parent is the engine's state directory, which the package owns. A user name
        # written down here would be a second place for it to be wrong.
        helper = helper_from(AUDIT)
        self.assertIn('chown --reference="$(dirname "$dir")"', helper)
        self.assertIn('chmod 0700', helper)
        self.assertIn('[ "$(id -u)" -eq 0 ]', helper)

    def test_it_corrects_a_directory_that_is_already_root_owned(self):
        # Not only creates: an installation this has already happened to has to be repairable.
        with tempfile.TemporaryDirectory() as base:
            parent = Path(base) / 'ovirt-engine'
            state = parent / 'security'
            state.mkdir(parents=True)
            state.chmod(0o755)

            subprocess.run(
                ['bash', '-c', helper_from(AUDIT) + f'\nensure_engine_dir "{state}"'],
                check=True,
            )

            # Running as root here it would also chown; unprivileged it must at least not fail
            # and must leave the directory there.
            self.assertTrue(state.is_dir())

    def test_engine_setup_repairs_it_because_it_is_the_one_thing_running_as_root(self):
        acl = ACL.read_text(encoding='utf-8')

        self.assertIn(f"'{STATE_DIR}',", acl)
        self.assertIn(f"'{STATE_DIR}/crypto-events',", acl)
        self.assertIn('_ensure_security_state_dirs', acl)
        self.assertIn('shutil.chown(directory, user=engine_user, group=engine_group)', acl)
        # Corrected on every run, not only when the directory is missing.
        self.assertIn('os.makedirs(directory, mode=0o700, exist_ok=True)', acl)
        # And it does not fail the rest of engine-setup.
        self.assertIn('self.logger.warning(', acl)

    def test_it_runs_before_the_rest_of_the_closeup(self):
        acl = ACL.read_text(encoding='utf-8')
        closeup = acl[acl.index('def _closeup'):acl.index('def _ensure_security_state_dirs')]

        self.assertLess(
            closeup.index('self._ensure_security_state_dirs()'),
            closeup.index('sudoers_path'),
        )


if __name__ == '__main__':
    unittest.main()
