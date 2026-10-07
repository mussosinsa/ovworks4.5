import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
AUDIT = ROOT / 'ov-works-security_audit.sh'

PROCESSES = ('ovirt-engine', 'ovirt-engine-proxy', 'postgresql', 'ovirt-engine-kek-agent',
             'ovirt-websocket-proxy')
ITEMS = ('프로세스 실행 상태', '응답 확인')

# A systemctl that knows the units named in INSTALLED, with the states given there.
FAKE_SYSTEMCTL = r'''#!/bin/bash
state() { awk -v u="$1" -v f="$2" '$1 == u { print $f }' "$INSTALLED"; }
case "$1" in
    list-unit-files) state "$3" 1 | sed 's/$/ enabled enabled/' ;;
    is-enabled) state "$2" 2 ;;
    is-active) a=$(state "$2" 3); echo "${a:-inactive}"; [ "$a" = active ] ;;
    show) echo 4242 ;;
esac
'''

# curl: the health page answers as HEALTH says, the web server root as ROOT_CODE says.
FAKE_CURL = r'''#!/bin/bash
for arg; do url="$arg"; done
case "$url" in
    */services/health) printf '%s\n%s' "${HEALTH_BODY:-DB Up!Welcome to Health Status!}" "${HEALTH_CODE:-200}" ;;
    *) printf '%s' "${ROOT_CODE:-302}" ;;
esac
'''


def fake(directory, name, body):
    path = directory / name
    path.write_text(body)
    path.chmod(0o755)
    return path


class FindingTagTest(unittest.TestCase):
    """Every item prints its result, tagged with the process and the item it belongs to."""

    def setUp(self):
        self.script = AUDIT.read_text(encoding='utf-8')

    def test_the_self_test_is_the_processes_running_and_answering_and_nothing_else(self):
        for process in PROCESSES:
            self.assertRegex(self.script, r'\n%s\|[^|]+\.service\|' % re.escape(process))
        for excluded in ('ovirt-engine-dwhd|', 'ovirt-provider-ovn|'):
            self.assertNotIn(excluded, self.script)
        for item in ITEMS:
            self.assertIn('run_check "$process" "%s"' % item, self.script)
        # Files are the integrity verification's; OS, network, logs and policy are not checked.
        for gone in ('"설정 파일"', '"실행 파일"', 'process-file-stat', 'PROCESS_FILES',
                     'check_network_security', 'check_audit_logging', 'getenforce', 'firewall'):
            self.assertNotIn(gone, self.script)

    def test_every_result_prints_the_tag_the_engine_reads(self):
        out = subprocess.run(
            ['bash', '-c',
             'source <(sed "s/^if \\[ \\"\\${BASH_SOURCE\\[0\\]}\\" = \\"\\$0\\" \\]; then/if false; then/" "$0"); '
             'AUDIT_LOG=/dev/null; f(){ log_pass "ok"; log_fail "bad"; log_warn "meh"; log_skip "n/a"; }; '
             'run_check "ovirt-engine" "응답 확인" f; log_fail "untagged"',
             str(AUDIT)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
        ).stdout
        self.assertIn('[PASS] [ovirt-engine/응답 확인] ok', out)
        self.assertIn('[FAIL] [ovirt-engine/응답 확인] bad', out)
        self.assertIn('[WARN] [ovirt-engine/응답 확인] meh', out)
        self.assertIn('[SKIP] [ovirt-engine/응답 확인] n/a', out)
        # Outside run_check nothing is tagged, and nothing is left over from the last check.
        self.assertIn('[FAIL] untagged', out)


class SelfTestRunTest(unittest.TestCase):
    """The self-test run against fake services."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.installed = self.dir / 'installed'
        self.installed.write_text(
            'ovirt-engine.service enabled active\n'
            'httpd.service enabled active\n'
            'postgresql.service enabled active\n'
            'ovirt-engine-kek-agent.service enabled active\n'
            'ovirt-websocket-proxy.service disabled inactive\n')
        fake(self.dir, 'systemctl', FAKE_SYSTEMCTL)
        fake(self.dir, 'curl', FAKE_CURL)
        self.ps = fake(self.dir, 'ps', '#!/bin/sh\necho "${PS_USER:-ovirt}"\n')
        self.pg = fake(self.dir, 'pg_isready', '#!/bin/sh\nexit "${PG_RC:-0}"\n')
        self.kek = fake(self.dir, 'kek_agent', '#!/bin/sh\necho "${KEK_OUT:-KEK passphrase is held in memory}"\n'
                        'exit "${KEK_RC:-0}"\n')
        (self.dir / 'etc').mkdir()

    def run_audit(self, **env):
        environment = dict(
            os.environ,
            SYSTEMCTL=str(self.dir / 'systemctl'),
            CURL_COMMAND=str(self.dir / 'curl'),
            PS_COMMAND=str(self.ps),
            PG_ISREADY_COMMAND=str(self.pg),
            KEK_AGENT_COMMAND=str(self.kek),
            ENGINE_CONF_DIR=str(self.dir / 'etc'),
            INSTALLED=str(self.installed),
            SECURITY_AUDIT_RESULTS=str(self.dir / 'results.json'),
            AUDIT_LOCK=str(self.dir / 'lock'),
            NO_COLOR='1',
            SECURITY_AUDIT_LOG_FILE=str(self.dir / 'audit.log'),
            **env,
        )
        result = subprocess.run(
            ['bash', str(AUDIT)], env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
        )
        return result.returncode, result.stdout

    def lines(self, out, level):
        return [line for line in out.splitlines() if line.startswith('[%s]' % level)]

    def test_running_and_answering_processes_pass_every_item(self):
        rc, out = self.run_audit(PS_USER='ovirt')
        self.assertEqual([], self.lines(out, 'FAIL'), out)
        self.assertEqual(0, rc, out)
        passed = '\n'.join(self.lines(out, 'PASS'))
        self.assertIn('[ovirt-engine/응답 확인] health 응답 정상(https://127.0.0.1:443/ovirt-engine/services/health,'
                      ' HTTP 200, DB Up!', passed)
        self.assertIn('[ovirt-engine-proxy/응답 확인] HTTPS 응답 정상(https://127.0.0.1:443/, HTTP 302)', passed)
        self.assertIn('[postgresql/응답 확인] 접속 수락 중', passed)
        self.assertIn('[ovirt-engine-kek-agent/응답 확인] KEK 패스프레이즈 메모리 보관 중', passed)
        skipped = '\n'.join(self.lines(out, 'SKIP'))
        self.assertIn('[ovirt-websocket-proxy/프로세스 실행 상태] ovirt-websocket-proxy.service: 사용 안 함', skipped)
        self.assertIn('[ovirt-websocket-proxy/응답 확인] 점검 대상 아님', skipped)
        # Every item of every process is named.
        for process in PROCESSES:
            for item in ITEMS:
                self.assertIn('[%s/%s]' % (process, item), out)
        result = json.loads((self.dir / 'results.json').read_text())
        self.assertEqual('PASS', result['status'])

    def test_a_process_that_stopped_or_does_not_answer_fails(self):
        self.installed.write_text(
            'ovirt-engine.service enabled active\nhttpd.service enabled failed\n'
            'postgresql.service enabled active\novirt-engine-kek-agent.service enabled active\n')
        rc, out = self.run_audit(HEALTH_CODE='500', HEALTH_BODY='DB Down!', PG_RC='2', KEK_RC='3')
        self.assertEqual(1, rc, out)
        failed = '\n'.join(self.lines(out, 'FAIL'))
        self.assertIn('[ovirt-engine/응답 확인] health 응답 이상(', failed)
        self.assertIn('HTTP 500, DB Down!', failed)
        self.assertIn('[ovirt-engine-proxy/프로세스 실행 상태] httpd.service: 실행 중이 아님(failed)', failed)
        self.assertIn('[postgresql/응답 확인] 응답 없음(pg_isready 종료코드 2', failed)
        self.assertIn('[ovirt-engine-kek-agent/응답 확인] KEK 패스프레이즈가 메모리에 없음 - kek_agent.py --unlock 필요',
                      failed)
        self.assertEqual(4, len(self.lines(out, 'FAIL')), out)
        # Not running, so its answer is not asked for.
        self.assertIn('[SKIP] [ovirt-engine-proxy/응답 확인] 프로세스가 실행 중이 아니어서 확인하지 않음', out)

    def test_before_the_engine_starts_nothing_up_yet_keeps_it_from_starting(self):
        self.installed.write_text(
            'ovirt-engine.service enabled activating\nhttpd.service enabled inactive\n'
            'postgresql.service enabled active\novirt-engine-kek-agent.service enabled active\n')
        rc, out = self.run_audit(SECURITY_AUDIT_SOURCE='engine-start', PG_RC='1')
        self.assertEqual(0, rc, out)
        self.assertIn('[PASS] [ovirt-engine/프로세스 실행 상태] ovirt-engine.service: 실행 중(activating', out)
        self.assertIn('[SKIP] [ovirt-engine/응답 확인] 엔진 기동 전 점검', out)
        self.assertIn('[WARN] [ovirt-engine-proxy/프로세스 실행 상태] httpd.service: 실행 중이 아님', out)
        self.assertIn('[WARN] [postgresql/응답 확인] 접속 거부 중', out)

    def test_a_process_under_the_wrong_account_is_said(self):
        rc, out = self.run_audit(PS_USER='nobody')
        self.assertIn('[WARN] [ovirt-engine/프로세스 실행 상태] ovirt-engine.service: 실행 중(active, PID 4242)'
                      '이나 실행 계정이 nobody (기대값 ovirt)', out)

    def test_the_ports_come_from_the_configuration(self):
        conf = self.dir / 'etc' / 'engine.conf.d'
        conf.mkdir()
        (conf / '10-setup-protocols.conf').write_text('ENGINE_PROXY_HTTPS_PORT=8443\n')
        rc, out = self.run_audit()
        self.assertIn('https://127.0.0.1:8443/ovirt-engine/services/health', out)

    def test_an_installation_without_the_kek_agent_in_use_skips_it(self):
        rc, out = self.run_audit(
            KEK_RC='1', KEK_OUT='kek_agent: kek_agent is not enabled in the encryptor configuration')
        self.assertIn('[SKIP] [ovirt-engine-kek-agent/응답 확인] 설정 파일 암호화에 KEK 보관 서비스를 사용하지 않음', out)


if __name__ == '__main__':
    unittest.main()
