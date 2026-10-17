#
# Copyright 새올정보기술 (OV-Works), 2026
# SPDX-License-Identifier: Apache-2.0
#
import importlib.util
import os
import re
import stat
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
SETUP = ROOT / 'packaging/setup'
CLIENT_CONTROL = SETUP / 'plugins/ovirt-engine-setup/ovirt-engine/config/client_control.py'
PROVISIONING = SETUP / 'plugins/ovirt-engine-setup/ovirt-engine/provisioning/postgres.py'


def _load(path, name):
    """Load by path: tests/ has a stub ovirt_engine_setup package that shadows the real one."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


preset = _load(SETUP / 'ovirt_engine_setup/hosted_preset.py', '_hosted_preset_under_test')

# Example values only: the real ones live in the file on the engine VM, never in the source.
EXAMPLE = 'Flag=hosted\nKEK=example-kek-1\nPostgres=Example-Pg#2026\n'


class HostedPresetTest(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, 'develop.txt')

    def tearDown(self):
        self.dir.cleanup()

    def write(self, text, mode=0o600):
        with open(self.path, 'w', encoding='utf-8') as stream:
            stream.write(text)
        os.chmod(self.path, mode)

    @unittest.skipUnless(os.geteuid() == 0, 'the file has to be owned by root')
    def test_a_hosted_file_gives_both_answers(self):
        self.write(EXAMPLE)
        found = preset.read(self.path)
        self.assertEqual('example-kek-1', found.kek)
        self.assertEqual('Example-Pg#2026', found.postgres)

    @unittest.skipUnless(os.geteuid() == 0, 'the file has to be owned by root')
    def test_keys_are_not_case_sensitive_and_values_keep_every_character(self):
        self.write('flag = HOSTED\nkek=a=b c\nPOSTGRES= Pg@#$%x \n')
        found = preset.read(self.path)
        self.assertEqual('a=b c', found.kek)
        self.assertEqual('Pg@#$%x', found.postgres)

    def test_no_file_or_another_flag_means_nothing_preset(self):
        self.assertIsNone(preset.read(self.path))
        self.write('Flag=standalone\nKEK=x\nPostgres=y\n', mode=0o644)
        self.assertIsNone(preset.read(self.path))

    @unittest.skipUnless(os.geteuid() == 0, 'the file has to be owned by root')
    def test_a_hosted_file_others_can_read_is_refused(self):
        self.write(EXAMPLE, mode=0o644)
        with self.assertRaises(RuntimeError) as raised:
            preset.read(self.path)
        self.assertIn('chmod 600', str(raised.exception))

    def test_a_hosted_file_not_owned_by_root_is_refused(self):
        status = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=1000)
        with self.assertRaises(RuntimeError) as raised:
            preset.check_owner_and_mode(self.path, status)
        self.assertIn('owned by root', str(raised.exception))

    def test_a_symbolic_link_is_not_followed(self):
        target = os.path.join(self.dir.name, 'elsewhere')
        with open(target, 'w', encoding='utf-8') as stream:
            stream.write(EXAMPLE)
        os.symlink(target, self.path)
        with self.assertRaises(RuntimeError):
            preset.read(self.path)

    def test_the_source_holds_no_password(self):
        # The preset values are read at run time from the engine VM, not shipped.
        literal = re.compile(r'''(?i)\b(kek|postgres)\w*\s*=\s*b?['"][^'"]+['"]''')
        for path in (SETUP / 'ovirt_engine_setup/hosted_preset.py', CLIENT_CONTROL, PROVISIONING):
            self.assertIsNone(literal.search(path.read_text(encoding='utf-8')), path)


class HostedPresetWiringTest(unittest.TestCase):

    def test_the_kek_passphrase_is_taken_from_the_preset_before_asking(self):
        source = CLIENT_CONTROL.read_text(encoding='utf-8')
        ensure = source[source.index('def _ensure_memory_kek(self, config):'):]
        ensure = ensure[:ensure.index('def _record_kek_event')]
        self.assertLess(ensure.index('self._preset_kek_passphrase()'),
                        ensure.index("'OVESETUP_KEK_PASSPHRASE'"))
        # Held to the same rules, and proven against files already encrypted.
        self.assertIn('encryptor.check_memory_passphrase(passphrase)', ensure)
        self.assertIn('for _attempt in range(0 if passphrase is not None else 3):', ensure)
        # Never put in the environment, so never in an answer file or the log.
        helper = source[source.index('def _preset_kek_passphrase(self):'):]
        helper = helper[:helper.index('def _database_credential_files')]
        self.assertNotIn('self.environment[', helper)
        self.assertIn('bytearray(', helper)

    def test_the_superuser_password_is_taken_from_the_preset_and_filtered_from_the_log(self):
        source = PROVISIONING.read_text(encoding='utf-8')
        customization = source[source.index('def _customization(self):'):]
        self.assertLess(customization.index('_hostedPresetPassword()'),
                        customization.index('while self.environment[password_key] is None:'))
        self.assertIn('self.environment[otopicons.CoreEnv.LOG_FILTER].append(preset)', customization)

    def test_only_a_preset_password_breaking_the_rules_is_let_through(self):
        source = PROVISIONING.read_text(encoding='utf-8')
        validation = source[source.index('def _validation(self):'):]
        validation = validation[:validation.index('self._provisioning.validate()')]
        self.assertIn('if problem and self._passwordPreset and password:', validation)
        self.assertIn('raise RuntimeError(problem)', validation)


if __name__ == '__main__':
    unittest.main()
