#
# Copyright 새올정보기술 (OV-Works), 2026
# SPDX-License-Identifier: Apache-2.0
#
import importlib.util
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
sys.path.insert(0, str(ROOT / 'packaging/pythonlib'))
SETUP = ROOT / 'packaging/setup'


def _load(path, name):
    """Load by path: tests/ has a stub ovirt_engine_setup package that shadows the real one."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


policy = _load(SETUP / 'ovirt_engine_setup/password_policy.py', '_password_policy_under_test')


class GeneratedDatabasePasswordTest(unittest.TestCase):
    """The password engine-setup generates for the engine database user."""

    def test_every_generated_password_follows_the_rules(self):
        for _ in range(300):
            password = policy.generate()
            self.assertEqual(22, len(password))
            self.assertRegex(password, r'[A-Z]')
            self.assertRegex(password, r'[a-z]')
            self.assertRegex(password, r'[0-9]')
            self.assertRegex(password, r'[^A-Za-z0-9]')
            self.assertIsNone(policy.violation(password, min_length=22), password)

    def test_its_special_characters_need_no_quoting_where_it_is_kept(self):
        # engine.conf.d double-quoted values, .pgpass, INI interpolation, the login input policy
        # and the SQL syntax it refuses.
        for character in '"$\\`:%|;- /*\'#':
            self.assertNotIn(character, policy.GENERATED_SPECIALS)
        for _ in range(300):
            self.assertIsNone(re.search(r'--|/\*|\*/', policy.generate()))

    def test_the_database_provisioning_uses_it(self):
        source = (SETUP / 'ovirt_engine_setup/engine_common/postgres.py').read_text(encoding='utf-8')
        body = source[source.index('def generatePassword(self):'):]
        body = body[:body.index('def applyEnvironment')]
        self.assertIn('password_policy.generate(password_policy.GENERATED_LENGTH)', body)
        self.assertNotIn('_PASSWORD_CHARS', source)


class SuperuserPasswordTest(unittest.TestCase):
    """The PostgreSQL superuser password the administrator enters."""

    def check(self, password):
        return policy.violation(password, account='postgres', min_length=14)

    def test_a_password_following_the_rules_is_taken(self):
        self.assertIsNone(self.check('Vm!Xk7pLq2Zt#9w'))

    def test_what_the_rules_refuse(self):
        for refused in (
            'Vm!Xk7pLq2Zt',        # shorter than 14
            'vm!xk7plq2zt#9w',     # no upper case
            'VM!XK7PLQ2ZT#9W',     # no lower case
            'Vm!XkapLqbZt#cw',     # no digit
            'VmXk7pLq2Zt09wR',     # no special character
            'Vm!Xk7pLq2Zt#aaa',    # a character three times
            'Vm!Xk7pLq2Zt#abcd',   # an alphabetical run
            'Vm!Xk7pLq2Zt#1234',   # a numerical run
            'Vm!Xk7Postgres#9w',   # the account name / a common word
            'Vm!Xk7pLqxyxy#9w',    # a repeated block
        ):
            self.assertIsNotNone(self.check(refused), refused)


if __name__ == '__main__':
    unittest.main()
