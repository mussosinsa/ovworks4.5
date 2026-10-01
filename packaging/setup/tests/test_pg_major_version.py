import ast
import re
import unittest
from pathlib import Path


DATABASE = (
    Path(__file__).parents[1]
    / 'ovirt_engine_setup' / 'engine_common' / 'database.py'
)


def load_pg_major_version():
    # The module imports otopi, which the test environment does not have; the
    # function itself needs only re, so it is compiled on its own.
    tree = ast.parse(DATABASE.read_text(encoding='utf-8'))
    node = next(
        n for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == 'pg_major_version'
    )
    namespace = {'re': re}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(DATABASE), 'exec'), namespace)
    return namespace['pg_major_version']


class PgMajorVersionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.major = staticmethod(load_pg_major_version())

    def test_a_minor_update_is_the_same_server(self):
        self.assertEqual(self.major('17.5'), self.major('17.6'))
        self.assertEqual(self.major('13.18'), self.major('13.23'))

    def test_a_new_first_number_is_a_major_upgrade(self):
        self.assertLess(self.major('13.18'), self.major('17.6'))
        self.assertLess(self.major('16.10'), self.major('17.0'))
        self.assertFalse(self.major('17.6') < self.major('17.5'))

    def test_before_ten_the_first_two_numbers_are_the_major(self):
        self.assertEqual((9, 6), self.major('9.6.24'))
        self.assertNotEqual(self.major('9.5.3'), self.major('9.6.1'))
        self.assertLess(self.major('9.6.24'), self.major('13.18'))

    def test_what_follows_the_numbers_is_ignored(self):
        self.assertEqual((17,), self.major('17.6 (Red Hat 17.6-1.el9)'))
        self.assertEqual((18,), self.major('18beta1'))
        self.assertEqual((17,), self.major(' 17'))
        self.assertEqual((), self.major(''))
        self.assertEqual((), self.major(None))

    def test_the_setup_checks_use_it(self):
        source = DATABASE.read_text(encoding='utf-8')
        self.assertNotIn('distutils', source)
        self.assertIn('return pg_major_version(current) == pg_major_version(expected)', source)
        self.assertIn('client_v = pg_major_version(self.checkClientVersion())', source)


if __name__ == '__main__':
    unittest.main()
