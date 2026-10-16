import importlib.util
import sys
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
LIST = ROOT / 'packaging/conf/ovworks-process-files.conf'

# otopi is not installed here and none of what is under test needs it.
_otopi = sys.modules.setdefault('otopi', types.ModuleType('otopi'))
_util = sys.modules.setdefault('otopi.util', types.ModuleType('otopi.util'))
_util.export = lambda obj: obj
_otopi.util = _util


def _load(path, name):
    """Load by path: tests/ has a stub ovirt_engine_setup package that shadows the real one."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_aide = _load(ROOT / 'packaging/setup/ovirt_engine_setup/aide.py', '_aide_under_test')
Aide = _aide.Aide
ProcessFiles = _aide.ProcessFiles

PROCESSES = (
    'ovirt-engine',
    'ovirt-engine-kek-agent',
    'ovirt-engine-proxy',
    'postgresql',
    'ovirt-engine-dwhd',
    'ovirt-websocket-proxy',
    'security-verification',
)


def entries():
    return ProcessFiles.read(str(LIST))


class ProcessFileListTest(unittest.TestCase):
    """The self-test and the integrity verification cover the six main processes and their files,
    by exact name, and nothing else."""

    def test_lists_the_processes_and_the_verification_itself_and_not_ovn(self):
        listed = []
        for entry in entries():
            if entry.process not in listed:
                listed.append(entry.process)
        self.assertEqual(list(PROCESSES), listed)
        self.assertEqual({'exec', 'conf'}, {e.type for e in entries()})
        self.assertFalse([e for e in entries() if 'ovn' in e.path])

    def test_libraries_and_the_security_functions_are_measured(self):
        paths = {e.path for e in entries()}
        for path in (
            '/usr/share/ovirt-engine/modules',
            '/usr/lib/python3*/site-packages/ovirt_engine',
            '/usr/share/ovirt-engine/encryptor/kek_agent.py',
            '/usr/share/ovirt-engine/encryptor/encryptor.py',
            '/usr/share/ovirt-engine/encryptor/login_key.py',
            '/usr/share/ovirt-engine/encryptor/integrity_seal.py',
            '/usr/share/ovirt-engine/bin/ov-works-security_audit.sh',
            '/usr/share/ovirt-engine/bin/ovirt-engine-security-verification-runner.sh',
            '/usr/sbin/aide',
            '/etc/sudoers.d/ovirt-aide',
        ):
            self.assertIn(path, paths)

    def test_every_process_has_an_executable_and_configuration_files_by_exact_name(self):
        for process in PROCESSES:
            mine = [e for e in entries() if e.process == process]
            self.assertTrue([e for e in mine if e.type == 'exec'], process)
            confs = [e for e in mine if e.type == 'conf']
            if process != 'postgresql':
                self.assertTrue(confs, process)
            for entry in confs:
                # A file, never a directory or a pattern.
                self.assertTrue(entry.path.startswith('/'), entry.path)
                self.assertNotIn('*', entry.path)
                self.assertFalse(entry.path.endswith('/'), entry.path)
                self.assertFalse(entry.has('tree'), entry.path)

    def test_the_database_passwords_and_private_keys_are_secret(self):
        secret = {e.path for e in entries() if e.has('secret')}
        for path in (
            '/etc/ovirt-engine/engine.conf.d/10-setup-database.conf',
            '/etc/ovirt-engine/aaa/internal.properties',
            '/etc/ovirt-engine/encryptor/dek.enc',
            '/etc/pki/ovirt-engine/keys/apache.key.nopass',
            '/etc/pki/ovirt-engine/keys/websocket-proxy.key.nopass',
            '/etc/ovirt-engine-dwh/ovirt-engine-dwhd.conf.d/10-setup-database.conf',
            '/var/lib/pgsql/data/pg_hba.conf',
        ):
            self.assertIn(path, secret)

    def test_no_operating_system_network_or_log_settings(self):
        for entry in entries():
            for excluded in ('/var/log/', '/etc/sysconfig/', '/etc/ssh/', '/etc/firewalld/',
                             '/etc/security/', '/etc/pam.d/', '/etc/audit/', '/etc/rsyslog'):
                self.assertFalse(entry.path.startswith(excluded), entry.path)


class AideConfigTest(unittest.TestCase):
    """What engine-setup writes as the integrity verification's own AIDE configuration."""

    def setUp(self):
        self.config = Aide.config(
            entries(),
            exists=lambda path: '10-setup-java' not in path,
            expand=lambda pattern: ['/usr/lib/python3.9/site-packages/ovirt_engine'],
        )

    def test_a_missing_aide_is_installed_with_dnf_then_yum(self):
        self.assertEqual(
            (('/usr/bin/dnf', '-y', 'install', 'aide'), ('/usr/bin/yum', '-y', 'install', 'aide')),
            Aide.install_commands())

    def test_group_names_are_letters_and_digits_only(self):
        # AIDE 0.19: "special characters in group names are DEPRECATED".
        for line in self.config.splitlines():
            if ' = ' in line and not line.startswith('#'):
                name = line.split(' = ', 1)[0]
                if name not in ('database_in', 'database_out', 'database'):
                    self.assertRegex(name, r'^[A-Za-z0-9]+$')

    def test_the_baseline_option_is_named_for_the_installed_aide(self):
        # AIDE 0.19 (Rocky Linux 9.8) refuses 'database=': "unexpected character: ':'".
        self.assertEqual((0, 19), Aide.parse_version('Aide 0.19.2\n\nCompiled with the following options:'))
        self.assertEqual((0, 16), Aide.parse_version('Aide 0.16'))
        self.assertIsNone(Aide.parse_version(''))
        self.assertEqual('database_in', Aide.database_key((0, 19)))
        self.assertEqual('database_in', Aide.database_key((0, 17)))
        self.assertEqual('database', Aide.database_key((0, 16)))
        self.assertEqual('database_in', Aide.database_key(None))
        old = Aide.for_version(self.config, (0, 16))
        self.assertIn('\ndatabase=file:/var/lib/aide/ovworks.db.gz\n', old)
        self.assertNotIn('database_in=', old)
        # The output option is the same in every version.
        self.assertIn('\ndatabase_out=file:/var/lib/aide/ovworks.db.new.gz\n', old)
        self.assertEqual(self.config, Aide.for_version(old, (0, 19)))

    def test_has_its_own_database_and_does_not_touch_the_distributions(self):
        self.assertIn('\ndatabase_in=file:/var/lib/aide/ovworks.db.gz\n', self.config)
        self.assertIn('\ndatabase_out=file:/var/lib/aide/ovworks.db.new.gz\n', self.config)
        self.assertEqual('/etc/ovirt-engine/aide/ovworks-aide.conf', Aide.CONFIG_PATH)
        # AIDE --check reads the throwaway tmpfs configuration integrity_seal.py --open writes
        # (which points at the decrypted baseline), never the sealed on-disk configuration, since
        # the baseline at rest is encrypted under the DEK.
        self.assertEqual(
            ('/usr/sbin/aide', '--config=/dev/shm/ovworks-aide.conf', '--check'),
            Aide.check_command())
        self.assertEqual(
            ('/usr/bin/python3', '/usr/share/ovirt-engine/encryptor/integrity_seal.py', '--open'),
            Aide.open_command())
        self.assertEqual(
            ('/usr/bin/python3', '/usr/share/ovirt-engine/encryptor/integrity_seal.py', '--close'),
            Aide.close_command())

    def test_measures_each_file_by_exact_name_and_names_its_process(self):
        self.assertIn(
            '#@ ovirt-engine /etc/ovirt-engine/engine.conf.d/10-setup-database.conf\n'
            '=/etc/ovirt-engine/engine\\.conf\\.d/10-setup-database\\.conf$ OVWORKSCONTENT\n',
            self.config)
        self.assertIn('#@ postgresql /var/lib/pgsql/data/postgresql.conf\n', self.config)
        self.assertIn('=/usr/sbin/httpd$ OVWORKSCONTENT\n', self.config)
        # The engine's application is a directory measured with everything in it.
        self.assertIn('/usr/share/ovirt-engine/engine\\.ear/ OVWORKSCONTENT\n', self.config)

    def test_measures_nothing_but_the_listed_files(self):
        selections = [
            line for line in self.config.splitlines()
            if line and not line.startswith('#') and '=' not in line.split()[0][1:]
            and not line.startswith(('database', 'gzip_dbout', 'report_url', 'OVWORKS'))
        ]
        listed = [e for e in entries() if e.type != 'unit']
        trees = [e for e in listed if e.has('tree')]
        measured = [e for e in listed if '10-setup-java' not in e.path]
        self.assertEqual(len(measured) + len(trees), len(selections))
        for line in selections:
            self.assertFalse(line.startswith('!'), line)
            self.assertNotIn('/etc NORMAL', line)

    def test_files_rewritten_in_approved_work_are_watched_for_permissions_not_content(self):
        self.assertIn('\nOVWORKSPERMS = p+u+g+acl+selinux+xattrs\n', self.config)
        for path in ('/etc/httpd/conf\\.d/z-ovirt-engine-proxy\\.conf',
                     '/var/lib/pgsql/data/pg_hba\\.conf'):
            self.assertIn(f'\n={path}$ OVWORKSPERMS\n', self.config)

    def test_the_kek_agent_settings_are_not_measured(self):
        # Rewritten by the engine (terminal serial number) and by every engine-setup run.
        self.assertNotIn('/etc/ovirt-engine/encryptor/config', self.config)
        self.assertNotIn('encryptor/config.json',
                         [e.path.split('/etc/ovirt-engine/')[-1] for e in entries()])

    def test_the_rules_are_defined_before_they_are_used(self):
        self.assertLess(self.config.index('OVWORKSCONTENT = '),
                        self.config.index(' OVWORKSCONTENT\n'))
        self.assertLess(self.config.index('OVWORKSPERMS = '),
                        self.config.index(' OVWORKSPERMS\n'))

    def test_a_file_that_is_not_there_is_named_and_not_measured(self):
        self.assertIn(
            '#- ovirt-engine /etc/ovirt-engine/engine.conf.d/10-setup-java.conf\n', self.config)
        self.assertNotIn('10-setup-java\\.conf$', self.config)

    def test_a_path_with_a_star_is_resolved(self):
        self.assertIn('#@ ovirt-engine /usr/lib/python3.9/site-packages/ovirt_engine\n', self.config)
        self.assertIn('/usr/lib/python3\\.9/site-packages/ovirt_engine/ OVWORKSCONTENT\n', self.config)
        self.assertNotIn('python3*', self.config)


class LegacyBlockTest(unittest.TestCase):
    """Rules an earlier engine-setup wrote into /etc/aide.conf are taken out, and nothing else."""

    ORIGINAL = '# AIDE configuration\n/boot   NORMAL\n/bin    NORMAL\n'

    def test_the_block_is_taken_out_and_the_rest_left(self):
        written = (self.ORIGINAL + '\n' + Aide.LEGACY_BEGIN + '\n/etc/ovirt-engine/ NORMAL\n'
                   + Aide.LEGACY_END + '\n')
        self.assertEqual(self.ORIGINAL, Aide.without_legacy_block(written))

    def test_a_file_without_the_block_is_unchanged(self):
        self.assertEqual(self.ORIGINAL, Aide.without_legacy_block(self.ORIGINAL))


if __name__ == '__main__':
    unittest.main()
