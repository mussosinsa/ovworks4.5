import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
UPGRADE = ROOT / 'packaging/dbscripts/upgrade'
DBSCRIPTS = ROOT / 'packaging/dbscripts'


def sourced_by(script):
    """What dbfunc-common actually sources, by its own rule.

    _dbfunc_common_run_required_scripts reads the script from the top and stops at the first
    line that is not a --#source directive, so one written anywhere else is read by nobody.
    """
    sourced = []
    for line in script.read_text(encoding='utf-8').splitlines():
        if not line.split(' ')[0].strip() == '--#source':
            break
        sourced.append(line.split(' ')[1])
    return sourced


class DbscriptsSourceDirectivesTest(unittest.TestCase):

    def test_every_source_directive_is_where_it_is_read(self):
        # A directive at the foot of the file is silent: the upgrade runs, the script is
        # recorded as installed, and the functions it meant to create are not there. The engine
        # then fails on every call with "no procedure/function/signature for ...".
        for script in sorted(UPGRADE.glob('*.sql')):
            written = [
                line.split(' ')[1]
                for line in script.read_text(encoding='utf-8').splitlines()
                if line.startswith('--#source')
            ]
            self.assertEqual(
                written,
                sourced_by(script),
                f'{script.name} names a source file that dbfunc-common never reads',
            )

    def test_what_is_sourced_exists_and_is_named_as_the_loop_requires(self):
        # dbfunc-common refuses a source file whose name does not end in _sp.sql, and a missing
        # one fails the upgrade partway.
        for script in sorted(UPGRADE.glob('*.sql')):
            for name in sourced_by(script):
                self.assertTrue(name.endswith('_sp.sql'), f'{script.name}: {name}')
                self.assertTrue((DBSCRIPTS / name).is_file(), f'{script.name}: {name} is missing')


if __name__ == '__main__':
    unittest.main()
