import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
sys.path.insert(0, str(ROOT / 'packaging/pythonlib'))

from ovirt_engine import pg_local_auth  # noqa: E402


PROVISIONING = (
    ROOT / 'packaging/setup/ovirt_engine_setup/engine_common/postgres.py'
)
AUDIT = ROOT / 'ov-works-security_audit.sh'
STORAGE = ROOT / 'packaging/bin/audit-storage-usage.py'
TOOL = ROOT / 'packaging/bin/ovirt-engine-db-local-auth.py'


def read(path):
    return path.read_text(encoding='utf-8')


def function(source, name):
    return source.split('    def {0}('.format(name), 1)[1].split(
        '\n    def ', 1)[0]


class DbLocalAuthenticationTest(unittest.TestCase):

    def test_setup_hardens_after_setting_the_superuser_password(self):
        source = function(read(PROVISIONING), 'setPostgresSuperuserPassword')
        password = source.index('self._setPostgresSuperuserPassword(')
        role = source.index('pg_local_auth.OPS_ROLE_STATEMENTS')
        host_rules = source.index('self.addPgHbaDatabaseAccess(')
        harden = source.index('self.enforceLocalPasswordAuthentication(')
        self.assertLess(password, role)
        self.assertLess(role, host_rules)
        self.assertLess(host_rules, harden)
        self.assertIn("opsenv[self._dbenvkeys[DEK.DATABASE]] = 'postgres'",
                      source)

    def test_setup_reopens_the_socket_for_its_own_superuser_work(self):
        source = read(PROVISIONING)
        for name in (
            'getConfigFiles',
            'installUuidOsspExtension',
            'grantReadOnlyAccessToUser',
            'getPostgresLocaleAndEncodingInitEnv',
        ):
            self.assertIn(
                'with self.localSuperuserAccess(), AlternateUser(',
                function(source, name),
                name,
            )
        self.assertIn(
            'pg_local_auth.relax_for_setup(',
            function(source, '_setPgHbaLocalPeer'),
        )
        # the regular expression that turned scram-sha-256 into
        # scram-sha-ident is gone
        self.assertNotIn('_RE_POSTGRES_PGHBA_LOCAL', source)

    def test_a_dbms_upgrade_relaxes_and_restores_the_old_cluster(self):
        source = function(read(PROVISIONING), 'prepare')
        relax = source.index('pg_local_auth.relax_for_setup(')
        upgrade = source.index("'--upgrade',")
        restore = source.index(
            'self._writeKeepingMode(old_hba, old_hba_content)')
        copy = source.index("conf_f['hba_file'],")
        self.assertLess(relax, upgrade)
        self.assertLess(upgrade, restore)
        self.assertLess(restore, copy)
        self.assertIn("conf_f['ident_file']", source)

    def test_the_verification_reads_the_same_rules_as_the_library(self):
        audit = read(AUDIT)
        query = re.search(
            r'^DB_PASSWORDLESS_RULES_QUERY="(.*)"$', audit, re.M).group(1)
        self.assertEqual(pg_local_auth.PASSWORDLESS_RULES_QUERY, query)
        self.assertIn('DB_OPS_ROLE="{0}"'.format(pg_local_auth.OPS_ROLE),
                      audit)

    def test_the_verification_warns_and_never_fails(self):
        audit = read(AUDIT)
        check = audit.split('check_local_db_authentication() {', 1)[1].split(
            '\n}\n', 1)[0]
        self.assertNotIn('log_fail', check)
        self.assertIn('ovirt-engine-db-local-auth enable', check)
        main = audit.split('\nmain() {', 1)[1]
        self.assertIn('check_local_db_authentication', main)

    def test_nothing_unattended_waits_for_a_password(self):
        audit = read(AUDIT)
        helper = audit.split('postgres_psql() {', 1)[1].split('\n}\n', 1)[0]
        self.assertEqual(2, helper.count('psql -X -w'))
        self.assertIn('-U "$DB_OPS_ROLE"', helper)
        storage = read(STORAGE)
        self.assertIn('"-w"', storage)
        self.assertIn('DB_OPS_ROLE = "{0}"'.format(pg_local_auth.OPS_ROLE),
                      storage)
        # information_schema lists only what the role may read
        self.assertNotIn(
            "information_schema.tables WHERE table_name='audit_log'", audit)

    def test_the_tool_is_installed(self):
        tool = read(TOOL)
        self.assertIn("choices=('status', 'enable', 'disable')", tool)
        self.assertIn('stored_passwords=False', tool)
        self.assertIn('restore()', tool)
        makefile = read(ROOT / 'Makefile')
        spec = read(ROOT / 'ovirt-engine.spec.in')
        self.assertIn('ovirt-engine-db-local-auth.py" '
                      '"$(DESTDIR)$(BIN_DIR)/ovirt-engine-db-local-auth"',
                      makefile)
        self.assertIn('%{_bindir}/ovirt-engine-db-local-auth\n', spec)
        self.assertIn('%{engine_data}/bin/ovirt-engine-db-local-auth.py\n',
                      spec)


if __name__ == '__main__':
    unittest.main()
