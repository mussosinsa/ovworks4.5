import subprocess
import tempfile
import unittest
from pathlib import Path


SOURCE = Path(__file__).parents[1] / 'bin' / 'engine-prolog.sh.in'


class EnginePrologPathTest(unittest.TestCase):
    def test_missing_prefixed_engine_usr_uses_installed_script_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'ovirt-engine'
            bin_directory = root / 'bin'
            bin_directory.mkdir(parents=True)
            java_home = bin_directory / 'java-home'
            java_home.write_text('#!/bin/bash\necho /test-java\n', encoding='utf-8')
            java_home.chmod(0o755)

            defaults = root / 'services' / 'ovirt-engine' / 'ovirt-engine.conf'
            defaults.parent.mkdir(parents=True)
            defaults.write_text(
                'ENGINE_USR="/usr/share/ovirt-engine/share/ovirt-engine"\n'
                'JBOSS_HOME="/test-jboss"\n'
                'ENGINE_JAVA_MODULEPATH=""\n',
                encoding='utf-8',
            )
            prolog = bin_directory / 'engine-prolog.sh'
            content = SOURCE.read_text(encoding='utf-8')
            malformed_defaults = root / 'share' / 'ovirt-engine' / 'services' / 'ovirt-engine' / 'ovirt-engine.conf'
            content = content.replace('@ENGINE_DEFAULTS@', str(malformed_defaults))
            content = content.replace('@ENGINE_VARS@', str(root / 'missing.conf'))
            content = content.replace('@ENGINE_LOG@', str(root / 'log'))
            content = content.replace('@PACKAGE_NAME@', 'ovirt-engine')
            content = content.replace('@PACKAGE_VERSION@', 'test')
            content = content.replace('@DISPLAY_VERSION@', 'test')
            prolog.write_text(content, encoding='utf-8')

            completed = subprocess.run(
                [
                    '/bin/bash',
                    '-c',
                    '. "$1"; printf "%s\\n%s\\n" "$ENGINE_USR" "$JAVA_HOME"',
                    'bash',
                    str(prolog),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertEqual(
                [str(root), '/test-java'],
                completed.stdout.splitlines(),
            )
            self.assertIn('Ignoring malformed ENGINE_USR', completed.stderr)
            self.assertIn('Ignoring malformed ENGINE_DEFAULTS', completed.stderr)


if __name__ == '__main__':
    unittest.main()
