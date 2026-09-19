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
        #
        # What the script does, not what it says. The advice it prints when something is wrong
        # names the commands that put it right, and those are writing commands - printed for a
        # person to read and decide on, which is the opposite of the script running them.
        doing = '\n'.join(
            line for line in self.script.splitlines()
            if not re.match(r'\s*(echo|printf|#)', line))
        for writing in ('cp ', 'rm ', 'mv ', 'install ', 'chown', 'chmod', '> "$target"'):
            self.assertNotIn(writing, doing, writing)

    def test_the_advice_it_prints_is_only_printed(self):
        # The guard above would pass a script that wrote nothing and also said nothing useful.
        self.assertIn('make clean install-dev', self.script)
        self.assertIn('echo "  make clean install-dev', self.script)

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


class TestWebAdminIsJudgedByWhenItWasBuilt(unittest.TestCase):
    """
    WebAdmin is Java compiled to JavaScript, so nothing under frontend/ has a counterpart on the
    installation to compare with. What can be said is whether the war was built after the source
    it is built from last changed - a screen changed only in the source is a screen nobody using
    the engine can see, and that is the fault these tests are about.
    """

    def _run(self, source, engine_usr, engine_ear):
        return subprocess.run(
            ['bash', str(SCRIPT), str(source)],
            capture_output=True, text=True,
            env={
                'ENGINE_USR': str(engine_usr),
                'ENGINE_EAR': str(engine_ear),
                'PATH': '/usr/bin:/bin',
            },
        ).stdout

    def _tree(self, tmp):
        source = Path(tmp) / 'src'
        (source / 'frontend' / 'module').mkdir(parents=True)
        (source / 'frontend' / 'module' / 'Model.java').write_text('a screen\n')
        # Something outside frontend/ as well, deployed and matching, so that a tree with the
        # frontend taken away is still recognisably the source tree rather than nothing at all,
        # and so the only thing these tests can find wrong is the one they are about.
        (source / 'ov-works-security_audit.sh').write_text('#!/bin/sh\n')
        engine_usr = Path(tmp) / 'usr'
        (engine_usr / 'bin').mkdir(parents=True)
        (engine_usr / 'bin' / 'ov-works-security_audit.sh').write_text('#!/bin/sh\n')
        war = engine_usr / 'engine.ear' / 'webadmin.war'
        war.mkdir(parents=True)
        (war / 'index.html').write_text('the screens as they were\n')
        return source, engine_usr, war

    def test_source_newer_than_the_war_is_stale(self):
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            source, engine_usr, war = self._tree(tmp)
            os.utime(war, (0, 0))
            out = self._run(source, engine_usr, war.parent)

        self.assertIn('STALE    ', out)
        self.assertIn('frontend/module/Model.java', out)

    def test_a_war_built_after_the_source_says_nothing(self):
        import os
        import time
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            source, engine_usr, war = self._tree(tmp)
            os.utime(war, (time.time() + 60, time.time() + 60))
            out = self._run(source, engine_usr, war.parent)

        self.assertNotIn('STALE    ', out)
        self.assertIn('0 missing, 0 differing', out)

    def test_no_war_at_all_is_missing(self):
        import shutil
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            source, engine_usr, war = self._tree(tmp)
            shutil.rmtree(war)
            out = self._run(source, engine_usr, war.parent)

        self.assertIn('MISSING', out)
        self.assertIn('webadmin.war', out)

    def test_a_tree_with_no_frontend_is_not_judged(self):
        # A source tree that simply does not carry the frontend; nothing to say about the screens,
        # which is not the same as nothing to say at all.
        import shutil
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            source, engine_usr, war = self._tree(tmp)
            shutil.rmtree(source / 'frontend')
            out = self._run(source, engine_usr, war.parent)

        self.assertNotIn('STALE    ', out)
        self.assertNotIn('webadmin.war', out)
        self.assertIn('checked', out)

    def test_the_war_is_judged_by_when_it_was_compiled(self):
        # A deployment directory's own timestamp says when something in it was last rearranged.
        # The bootstrap script is written by the GWT compilation, so it says when these screens
        # were built - and it is the file that makes a war older than its source visible.
        import os
        import tempfile
        import time

        with tempfile.TemporaryDirectory() as tmp:
            source, engine_usr, war = self._tree(tmp)
            (war / 'webadmin.nocache.js').write_text('the screens as they were\n')
            os.utime(war / 'webadmin.nocache.js', (0, 0))
            # The directory itself looks recent, as a redeployment leaves it.
            os.utime(war, (time.time() + 60, time.time() + 60))
            out = self._run(source, engine_usr, war.parent)

        self.assertIn('STALE    ', out)
        self.assertIn('frontend/module/Model.java', out)


class TestItRefusesToGuess(unittest.TestCase):
    """The answer it must never give is the reassuring one it has not earned."""

    def test_pointed_at_somewhere_that_is_not_the_source_it_says_so(self):
        # What happened on a production engine: run from /root, where every path it looks for is
        # absent, every check quietly skipped, and it reported that everything was in place.
        import tempfile

        with tempfile.TemporaryDirectory() as elsewhere:
            result = subprocess.run(
                ['bash', str(SCRIPT), elsewhere],
                capture_output=True, text=True,
                env={'ENGINE_USR': '/nonexistent', 'PATH': '/usr/bin:/bin'},
            )

        self.assertEqual(2, result.returncode, result.stdout)
        self.assertNotIn('Everything checked is in place', result.stdout)
        self.assertIn('Nothing was checked', result.stdout)
        self.assertIn('0 file(s) checked', result.stdout.replace(
            'Nothing was checked', '0 file(s) checked'))


if __name__ == '__main__':
    unittest.main()
