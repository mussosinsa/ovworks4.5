import re
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]

PROXY_TEMPLATE = ROOT / 'packaging/conf/ovirt-engine-proxy.conf.v2.in'
HALT_PAGE = ROOT / 'packaging/conf/service-halted/service-halted.html'
APACHE_PLUGIN = (
    ROOT / 'packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/apache/engine.py'
)
ENGINE_CONSTANTS = ROOT / 'packaging/setup/ovirt_engine_setup/engine/constants.py'
SPEC = ROOT / 'ovirt-engine.spec.in'
TERMINAL_IP = (
    ROOT
    / 'backend/manager/modules/bll/src/main/java/org/ovirt/engine'
    / 'core/bll/TerminalIpConfigUtils.java'
)
STARTUP_MANAGER = (
    ROOT
    / 'backend/manager/modules/bll/src/main/java/org/ovirt/engine'
    / 'core/bll/StartupSecurityAuditManager.java'
)
RUNNER = (
    ROOT
    / 'backend/manager/modules/bll/src/main/java/org/ovirt/engine'
    / 'core/bll/SecurityAuditRunner.java'
)
AUDIT_LOG_TYPE = (
    ROOT
    / 'backend/manager/modules/common/src/main/java/org/ovirt/engine'
    / 'core/common/AuditLogType.java'
)
AUDIT_LOG_MESSAGES = (
    ROOT / 'backend/manager/modules/dal/src/main/resources/bundles/AuditLogMessages.properties'
)
VIEW = (
    ROOT
    / 'frontend/webadmin/modules/webadmin/src/main/java/org/ovirt/engine/ui/webadmin'
    / 'section/main/view/popup/security/IntegrityCheckView.java'
)
VIEW_XML = VIEW.with_suffix('.ui.xml')

HALT_TYPE = 'SECURITY_VERIFICATION_SERVICE_HALTED'
HALT_URI = '/ovirt-engine-service-halted.html'


class ServiceHaltScreenTest(unittest.TestCase):
    """The response to a failed self-test is that the service is not started, and it is shown.

    Two screens, because one cannot cover both moments. While the service is stopped there is no
    engine to serve anything, so the web server shows a page from disk; afterwards the refusal is
    on the security settings screen, read back out of the audit log.
    """

    def setUp(self):
        self.proxy = PROXY_TEMPLATE.read_text(encoding='utf-8')
        self.page = HALT_PAGE.read_text(encoding='utf-8')
        self.plugin = APACHE_PLUGIN.read_text(encoding='utf-8')
        self.constants = ENGINE_CONSTANTS.read_text(encoding='utf-8')
        self.spec = SPEC.read_text(encoding='utf-8')
        self.terminal_ip = TERMINAL_IP.read_text(encoding='utf-8')
        self.manager = STARTUP_MANAGER.read_text(encoding='utf-8')
        self.runner = RUNNER.read_text(encoding='utf-8')
        self.types = AUDIT_LOG_TYPE.read_text(encoding='utf-8')
        self.messages = AUDIT_LOG_MESSAGES.read_text(encoding='utf-8')
        self.view = VIEW.read_text(encoding='utf-8')
        self.view_xml = VIEW_XML.read_text(encoding='utf-8')

    def test_the_web_server_answers_a_stopped_engine_with_the_halt_page(self):
        # 503 is what mod_proxy returns when the engine is not listening, which is the state a
        # refused start leaves behind.
        self.assertIn(f'ErrorDocument 503 {HALT_URI}', self.proxy)
        self.assertIn(f'Alias {HALT_URI} "@ENGINE_SERVICE_HALTED_PAGE@"', self.proxy)

    def test_the_page_is_not_served_by_the_engine_it_is_reporting_on(self):
        # A path under /ovirt-engine is proxied to the engine, so it could not be the page shown
        # when the engine is the thing that is down.
        self.assertFalse(HALT_URI.startswith('/ovirt-engine/'))
        self.assertNotRegex(HALT_URI, r'^/ovirt-engine($|/)')

    def test_setup_fills_in_both_paths_the_template_asks_for(self):
        for token in ('@ENGINE_SERVICE_HALTED_DIR@', '@ENGINE_SERVICE_HALTED_PAGE@'):
            self.assertIn(token, self.proxy)
            self.assertIn(f"'{token}': (", self.plugin)
        self.assertIn('HTTPD_SERVICE_HALTED_DIR', self.constants)
        self.assertIn('HTTPD_SERVICE_HALTED_PAGE', self.constants)
        self.assertIn("'service-halted',", self.constants)
        self.assertIn("'service-halted.html',", self.constants)
        # And the file is installed where those constants point.
        self.assertIn('%{engine_data}/conf/service-halted/', self.spec)

    def test_the_page_is_guarded_by_the_terminal_list_like_everything_else(self):
        directory = self._block(self.proxy, '<Directory "@ENGINE_SERVICE_HALTED_DIR@">', '</Directory>')
        self.assertIn('@CLIENT_CONTROL_REQUIRE_IPS@', directory)

    def test_registering_a_terminal_does_not_empty_the_second_block(self):
        # Two RequireAny blocks now carry the list. Writing it into the first and dropping the
        # lines of the second would leave "<RequireAny></RequireAny>", which answers nobody - so
        # the first terminal registered would have shut off the page explaining the halt.
        self.assertEqual(2, self.proxy.count('@CLIENT_CONTROL_REQUIRE_IPS@'))
        self.assertIn('boolean insideRun = false;', self.terminal_ip)
        self.assertIn('if (!insideRun) {', self.terminal_ip)
        # Each block gets the whole list, written with that block's own indentation.
        self.assertIn(
            'updated.append(requireLines(lineMatcher.group(1), addresses));',
            self.terminal_ip,
        )
        self.assertIn('replacedAny = true;', self.terminal_ip)

    def test_the_page_stands_on_its_own(self):
        # Everything the engine serves is unavailable at exactly the moment this page is needed.
        self.assertNotIn('<script', self.page)
        self.assertNotIn('<link', self.page)
        self.assertNotRegex(self.page, r'(?:src|href)\s*=\s*"https?://')
        self.assertIn('<style>', self.page)
        self.assertIn('lang="ko"', self.page)

    def test_the_page_states_the_policy_and_where_the_reason_is(self):
        self.assertIn('서비스를 중단', self.page)
        self.assertIn('자체 보안 검증', self.page)
        self.assertIn(HALT_TYPE, self.page)

    def test_the_page_does_not_show_where_the_host_keeps_its_records(self):
        # Security policy: the page does not say where the host keeps the reason - no state file,
        # log or diagnostic command. That is in the operator documentation, not on the screen.
        for detail in ('/var/lib/ovirt-engine', '/var/log/ovirt-engine', 'last-failed-start.json',
                       'audit-results.json', 'engine.log', 'journalctl', 'systemctl status',
                       '중단 사유 확인 방법'):
            self.assertNotIn(detail, self.page)

    def test_the_halt_is_its_own_audit_record(self):
        # Under SECURITY_AUDIT_FAILED a refused start read exactly like a host that had carried on
        # serving with findings against it, and the screen had nothing to look for.
        self.assertRegex(self.types, rf'\n    {HALT_TYPE}\(\d+, AuditLogSeverity\.ERROR\),')
        self.assertRegex(self.messages, rf'\n{HALT_TYPE}=')
        self.assertIn(f'logAuditEvent(AuditLogType.{HALT_TYPE},', self.manager)

    def test_the_reason_code_travels_beside_the_message_not_only_inside_it(self):
        self.assertIn('start.getReason() == null ? "" : start.getReason()', self.manager)
        self.assertIn(
            'private void logAuditEvent(AuditLogType type, String message, String customData) {',
            self.manager,
        )
        self.assertIn('auditLog.setCustomData(customData);', self.manager)

    def test_the_screen_names_every_reason_the_gate_can_write(self):
        for reason in (
            'SECURITY_CHECKS_FAILED',
            'VERIFICATION_BUSY',
            'RUNNER_MISSING',
            'VERIFICATION_ERROR',
        ):
            self.assertIn(f'"{reason}"', self.runner)
            self.assertIn(f'"{reason}"', self.view)

    def test_the_screen_shows_the_halt_history_and_says_when_there_is_none(self):
        self.assertIn(f'AuditLogType.{HALT_TYPE}', self.view)
        self.assertIn('showServiceHalts(serviceHaltHistory);', self.view)
        self.assertIn('getCustomData()', self.view)
        self.assertIn('서비스 중단 이력이 없습니다.', self.view)
        for field in ('serviceHaltAlertLabel', 'serviceHaltClearLabel', 'serviceHaltHistoryLabel'):
            self.assertIn(f'ui:field="{field}"', self.view_xml)
            self.assertIn(f'HTML {field};', self.view)
        self.assertIn('보안 검증 실패 대응 (서비스 중단)', self.view_xml)

    def test_a_halt_is_not_counted_as_one_more_failed_self_test(self):
        # isSecurityAuditResult lists the audit's own four types; the halt is not one of them, so
        # it no longer turns the self-test status red on a host whose last audit passed.
        audit_filter = self._block(
            self.view, 'private boolean isSecurityAuditResult(AuditLogType logType) {', '}')
        self.assertNotIn(HALT_TYPE, audit_filter)

    @staticmethod
    def _block(content, opening, closing):
        start = content.index(opening)
        return content[start:content.index(closing, start) + len(closing)]


if __name__ == '__main__':
    unittest.main()
