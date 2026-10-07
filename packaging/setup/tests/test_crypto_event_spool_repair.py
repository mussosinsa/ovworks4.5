import ast
import os
import shutil
import tempfile
import types
import unittest
from pathlib import Path


ACL = Path(__file__).parents[1] / 'plugins/ovirt-engine-setup/ovirt-engine/system/acl.py'
CRYPTOEVENTS = Path(__file__).parents[2] / 'pythonlib/ovirt_engine/cryptoevents.py'


def method(name):
    tree = ast.parse(ACL.read_text(encoding='utf-8'))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            node.decorator_list = []
            scope = {'os': os, 'shutil': shutil, '_': lambda m: m,
                     'osetupcons': types.SimpleNamespace(SystemEnv=types.SimpleNamespace(
                         USER_ENGINE='user', GROUP_ENGINE='group'))}
            exec(compile(ast.Module(body=[node], type_ignores=[]), 'acl.py', 'exec'), scope)
            return scope[name]
    raise AssertionError(name)


class Logger(object):
    def __init__(self):
        self.lines = []

    def __getattr__(self, name):
        return lambda *a, **k: self.lines.append((name, a))


class CryptoEventSpoolRepairTest(unittest.TestCase):
    """Events root wrote before the fix were root's and 0600, so the engine set them aside as
    unreadable. engine-setup gives them to the engine and puts them back to be recorded."""

    def test_the_writer_gives_root_entries_to_the_spool_owner(self):
        source = CRYPTOEVENTS.read_text(encoding='utf-8')
        self.assertIn('os.fchown(handle, *owner)', source)
        self.assertIn('if os.geteuid() == 0:', source)

    def test_setup_runs_the_repair(self):
        acl = ACL.read_text(encoding='utf-8')
        closeup = acl[acl.index('def _closeup'):acl.index('def _repair_crypto_event_spool')]
        self.assertLess(closeup.index('self._ensure_security_state_dirs()'),
                        closeup.index('self._repair_crypto_event_spool()'))

    @unittest.skipUnless(os.geteuid() == 0, 'needs root to own files as root')
    def test_root_entries_are_given_away_and_rejected_ones_put_back(self):
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, True)
        spool = base / 'crypto-events'
        (spool / 'rejected').mkdir(parents=True)
        (spool / 'waiting.json').write_text('{}')
        (spool / 'rejected' / 'unreadable.json').write_text('{}')
        (spool / 'rejected' / 'damaged.json').write_text('x')
        os.chown(spool / 'rejected' / 'damaged.json', 65534, 65534)   # not root's: really damaged

        plugin = types.SimpleNamespace(
            _SECURITY_STATE_DIRS=(str(base), str(spool)),
            environment={'user': 'nobody', 'group': 'nogroup'},
            logger=Logger(),
        )
        method('_repair_crypto_event_spool')(plugin)

        for path in (spool / 'waiting.json', spool / 'unreadable.json'):
            self.assertEqual(65534, path.stat().st_uid, path)
        self.assertFalse((spool / 'rejected' / 'unreadable.json').exists())
        # One the engine could read and still rejected stays where it is.
        self.assertTrue((spool / 'rejected' / 'damaged.json').exists())


if __name__ == '__main__':
    unittest.main()
