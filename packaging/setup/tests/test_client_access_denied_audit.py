import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]


class ClientAccessDeniedAuditTest(unittest.TestCase):
    """The web server writes the refusals and the engine reads them, so the two have to agree."""

    def setUp(self):
        self.proxy_conf = (
            ROOT / 'packaging/conf/ovirt-engine-proxy.conf.v2.in'
        ).read_text(encoding='utf-8')
        self.reader = (
            ROOT
            / 'backend/manager/modules/bll/src/main/java/org/ovirt/engine'
            / 'core/bll/ClientAccessDeniedAuditManager.java'
        ).read_text(encoding='utf-8')
        self.parser = (
            ROOT
            / 'backend/manager/modules/bll/src/main/java/org/ovirt/engine'
            / 'core/bll/ClientAccessDeniedLog.java'
        ).read_text(encoding='utf-8')

    def test_engine_reads_the_file_the_web_server_writes(self):
        path = '/var/log/httpd/ovirt-engine-admin-access-denied-audit.log'

        self.assertIn(f'CustomLog "{path}"', self.proxy_conf)
        self.assertIn(f'DENIED_LOG = "{path}"', self.reader)

    def test_every_engine_uri_is_covered_not_only_the_admin_page(self):
        # The Require ip block guards all of /ovirt-engine, so an unregistered address is turned
        # away from the REST API and the login page too.
        self.assertIn('m#^/ovirt-engine#', self.proxy_conf)
        self.assertNotIn('m#^/ovirt-engine/webadmin#', self.proxy_conf)

    def test_the_parser_reads_the_fields_the_log_format_writes(self):
        log_format = next(
            line for line in self.proxy_conf.splitlines()
            if line.strip().startswith('LogFormat')
        )

        for field in ('time', 'remote_ip', 'request'):
            self.assertIn(f'{field}=', log_format)
            self.assertIn(f'case "{field}":', self.parser)

    def test_the_reader_carries_on_after_the_file_is_rotated(self):
        # httpd's own logrotate rule covers this file (its glob is /var/log/httpd/*log), so the
        # engine has to cope with the path becoming a new, empty file: reading on from where it
        # stopped in a file that no longer exists reports nothing ever again.
        self.assertIn('file.length() < offset', self.reader)
        self.assertIn('offset = 0', self.reader)

    def test_the_engine_is_told_when_it_cannot_read_the_file(self):
        # An unreadable file looks exactly like nobody trying, so silence is not an option.
        self.assertIn('reportUnreadable', self.reader)
        self.assertIn('are not being reported', self.reader)

    def test_setup_lets_the_engine_reach_the_file(self):
        acl = (
            ROOT
            / 'packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/system/acl.py'
        ).read_text(encoding='utf-8')

        self.assertIn("_HTTPD_LOG_DIR, 'x'", acl)
        self.assertIn("_CLIENT_ACCESS_DENIED_LOG, 'r'", acl)


if __name__ == '__main__':
    unittest.main()
