import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[2]
SOURCE = ROOT / 'packaging' / 'bin' / 'engine-prolog.sh.in'

# Stands in for ovirt_engine.configfile: "encrypted" when the vars file says so, and failing to
# decrypt when it says that.
STUB = '''
import os


def encrypted_files(files):
    return [f for f in files if os.path.exists(f) and 'ENCRYPTED' in open(f).read()]


class ConfigFile(object):
    def __init__(self, files, cryptoEventSource=None):
        self.values = {'ENGINE_DB_PASSWORD': 'secret', 'TOOL': cryptoEventSource}
        for f in files:
            if os.path.exists(f) and 'NO_KEK' in open(f).read():
                raise RuntimeError('KEK passphrase is not held in memory')


def write_shell_config(values, path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        for key in sorted(values):
            stream.write('%s="%s"\\n' % (key, values[key]))
'''


class EngineToolDecryptedConfigTest(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / 'bin').mkdir()
        java_home = self.root / 'bin' / 'java-home'
        java_home.write_text('#!/bin/sh\necho /test-java\n')
        java_home.chmod(0o755)
        self.defaults = self.root / 'defaults.conf'
        self.defaults.write_text(
            'ENGINE_USR="{}"\nJBOSS_HOME="/test-jboss"\nENGINE_JAVA_MODULEPATH=""\n'.format(self.root))
        self.vars = self.root / 'engine.conf'
        self.vars.write_text('ENGINE_ETC="/etc/ovirt-engine"\n')
        package = self.root / 'lib' / 'ovirt_engine'
        package.mkdir(parents=True)
        (package / '__init__.py').write_text('')
        (package / 'configfile.py').write_text(STUB)
        self.runtime = self.root / 'run'
        self.runtime.mkdir()
        content = SOURCE.read_text(encoding='utf-8')
        for name, value in (('@ENGINE_DEFAULTS@', self.defaults), ('@ENGINE_VARS@', self.vars),
                            ('@ENGINE_LOG@', self.root / 'log'), ('@PACKAGE_NAME@', 'ovirt-engine'),
                            ('@PACKAGE_VERSION@', 'test'), ('@DISPLAY_VERSION@', 'test')):
            content = content.replace(name, str(value))
        self.prolog = self.root / 'bin' / 'engine-prolog.sh'
        self.prolog.write_text(content, encoding='utf-8')

    def tearDown(self):
        self.temporary.cleanup()

    def run_tool(self, shell='/bin/bash'):
        script = (
            '. "$1"\n'
            'use_decrypted_engine_config test-tool\n'
            'echo "VARS=$ENGINE_VARS"\n'
            '[ -f "$ENGINE_VARS" ] && cat "$ENGINE_VARS"\n'
            'stat -c "%a" "$(dirname "$ENGINE_VARS")" "$ENGINE_VARS"\n'
        )
        environment = dict(os.environ)
        environment.update(PYTHONPATH=str(self.root / 'lib'), ENGINE_TOOL_RUNTIME=str(self.runtime))
        environment.pop('ENGINE_DEFAULTS', None)
        environment.pop('ENGINE_VARS', None)
        return subprocess.run([shell, '-c', script, 'tool', str(self.prolog)], env=environment,
                              universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              check=False)

    def test_nothing_encrypted_leaves_the_configuration_as_it_is(self):
        result = self.run_tool()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn('VARS=%s' % self.vars, result.stdout)
        self.assertEqual([], list(self.runtime.iterdir()))

    def test_encrypted_configuration_is_handed_over_decrypted_and_removed_afterwards(self):
        self.vars.write_text('ENCRYPTED\n')
        # bash only: /bin/sh is bash on the engine host, and the prolog already relies on it.
        for shell in ('/bin/bash',):
            result = self.run_tool(shell)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn('VARS=%s/ovirt-engine-tool.' % self.runtime, result.stdout)
            self.assertIn('ENGINE_DB_PASSWORD="secret"', result.stdout)
            self.assertIn('TOOL="test-tool"', result.stdout)
            # The directory 0700, the file 0600 - it holds the database password.
            self.assertEqual(['700', '600'], result.stdout.strip().splitlines()[-2:])
            # Removed when the tool ends.
            self.assertEqual([], list(self.runtime.iterdir()), shell)

    def test_a_configuration_that_cannot_be_decrypted_says_so(self):
        self.vars.write_text('ENCRYPTED NO_KEK\n')
        result = self.run_tool()
        self.assertNotEqual(0, result.returncode)
        self.assertIn('could not be decrypted (KEK passphrase is not held in memory)', result.stderr)
        self.assertIn('kek_agent.py --status', result.stderr)
        self.assertEqual([], list(self.runtime.iterdir()))

    def test_the_tools_use_it_and_are_not_execed(self):
        for name, tool in (('engine-config.sh', 'engine-config'),
                           ('ovirt-register-sso-client-tool.sh', 'ovirt-register-sso-client-tool')):
            script = (ROOT / 'packaging' / 'bin' / name).read_text(encoding='utf-8')
            self.assertIn('use_decrypted_engine_config %s\n' % tool, script)
            self.assertNotIn('exec "${JAVA_HOME}/bin/java"', script)
            self.assertLess(script.index('use_decrypted_engine_config'), script.index('"${JAVA_HOME}/bin/java"'))


if __name__ == '__main__':
    unittest.main()
