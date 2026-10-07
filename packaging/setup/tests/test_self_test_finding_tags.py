import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
AUDIT = ROOT / 'ov-works-security_audit.sh'
HELPER = ROOT / 'packaging/bin/ovirt-engine-process-file-stat.sh'
LIST = ROOT / 'packaging/conf/ovworks-process-files.conf'

PROCESSES = ('ovirt-engine', 'ovirt-engine-proxy', 'postgresql', 'ovirt-engine-dwhd',
             'ovirt-websocket-proxy', 'ovirt-provider-ovn')
ITEMS = ('프로세스 실행 상태', '실행 파일', '설정 파일')

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


class FindingTagTest(unittest.TestCase):
    """Every item prints its result, tagged with the process and the item it belongs to."""

    def setUp(self):
        self.script = AUDIT.read_text(encoding='utf-8')

    def test_the_self_test_is_the_six_processes_and_nothing_else(self):
        self.assertIn('PROCESS_ORDER="%s"' % ' '.join(PROCESSES), self.script)
        for item in ITEMS:
            self.assertIn('run_check "$process" "%s"' % item, self.script)
        # Operating system, network, logs and policy settings are not part of it.
        for gone in ('check_network_security', 'check_audit_logging', 'check_session_timeout',
                     'check_auth_failure_controls', 'check_backup_configuration',
                     'check_ssl_certificates', 'getenforce', 'firewall', 'integrity-baseline'):
            self.assertNotIn(gone, self.script)

    def test_every_result_prints_the_tag_the_engine_reads(self):
        out = subprocess.run(
            ['bash', '-c',
             'source <(sed "s/^if \\[ \\"\\${BASH_SOURCE\\[0\\]}\\" = \\"\\$0\\" \\]; then/if false; then/" "$0"); '
             'AUDIT_LOG=/dev/null; f(){ log_pass "ok"; log_fail "bad"; log_warn "meh"; log_skip "n/a"; }; '
             'run_check "ovirt-engine" "설정 파일" f; log_fail "untagged"',
             str(AUDIT)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
        ).stdout
        self.assertIn('[PASS] [ovirt-engine/설정 파일] ok', out)
        self.assertIn('[FAIL] [ovirt-engine/설정 파일] bad', out)
        self.assertIn('[WARN] [ovirt-engine/설정 파일] meh', out)
        self.assertIn('[SKIP] [ovirt-engine/설정 파일] n/a', out)
        # Outside run_check nothing is tagged, and nothing is left over from the last check.
        self.assertIn('[FAIL] untagged', out)


class SelfTestRunTest(unittest.TestCase):
    """The self-test run against a host made of temporary files."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)
        files = self.dir / 'files'
        (files / 'ear').mkdir(parents=True)
        (files / 'ear' / 'a.jar').write_text('x')
        for name in ('engine.py', 'httpd'):
            (files / name).write_text('#!/bin/sh\n')
            (files / name).chmod(0o755)
        for name, mode in (('database.conf', 0o640), ('engine.conf', 0o644),
                           ('httpd.conf', 0o644), ('apache.key', 0o600)):
            (files / name).write_text('x')
            (files / name).chmod(mode)
        self.files = files
        self.list = self.dir / 'list.conf'
        self.list.write_text('\n'.join((
            '# test',
            'ovirt-engine unit user=root ovirt-engine.service',
            f'ovirt-engine exec - {files}/engine.py',
            f'ovirt-engine exec tree {files}/ear',
            f'ovirt-engine conf secret {files}/database.conf',
            f'ovirt-engine conf - {files}/engine.conf',
            f'ovirt-engine conf optional {files}/optional.conf',
            'ovirt-engine-proxy unit user=root httpd.service',
            f'ovirt-engine-proxy exec - {files}/httpd',
            f'ovirt-engine-proxy conf - {files}/httpd.conf',
            f'ovirt-engine-proxy conf secret {files}/apache.key',
            'postgresql unit user=postgres postgresql.service',
            f'postgresql exec - {files}/postgres',
            f'postgresql conf secret {files}/pg_hba.conf',
            'ovirt-engine-dwhd unit user=ovirt ovirt-engine-dwhd.service',
            f'ovirt-engine-dwhd exec - {files}/dwhd.py',
            f'ovirt-engine-dwhd conf secret {files}/dwh.conf',
            'ovirt-websocket-proxy unit user=ovirt ovirt-websocket-proxy.service',
            f'ovirt-websocket-proxy exec - {files}/wsp.py',
            f'ovirt-websocket-proxy conf - {files}/wsp.conf',
            'ovirt-provider-ovn unit user=root ovirt-provider-ovn.service',
            f'ovirt-provider-ovn exec - {files}/ovn.py',
            f'ovirt-provider-ovn conf - {files}/ovn.conf',
        )) + '\n')
        self.installed = self.dir / 'installed'
        self.installed.write_text(
            'ovirt-engine.service enabled active\n'
            'httpd.service enabled active\n'
            'ovirt-websocket-proxy.service disabled inactive\n')
        systemctl = self.dir / 'systemctl'
        systemctl.write_text(FAKE_SYSTEMCTL)
        systemctl.chmod(0o755)
        self.ps = self.dir / 'ps'
        self.ps.write_text('#!/bin/sh\necho root\n')
        self.ps.chmod(0o755)

    def run_audit(self, **env):
        environment = dict(
            os.environ,
            OVWORKS_PROCESS_FILES=str(self.list),
            FILE_STAT_HELPER=str(HELPER),
            SYSTEMCTL=str(self.dir / 'systemctl'),
            PS_COMMAND=str(self.ps),
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

    def test_a_sound_host_passes_every_item_and_names_every_file(self):
        rc, out = self.run_audit()
        self.assertEqual(0, rc, out)
        self.assertEqual([], self.lines(out, 'FAIL'), out)
        passed = '\n'.join(self.lines(out, 'PASS'))
        self.assertIn('[PASS] [ovirt-engine/프로세스 실행 상태] ovirt-engine.service: 실행 중(active', passed)
        for name in ('engine.py', 'ear', 'database.conf', 'engine.conf'):
            self.assertRegex(passed, r'\[ovirt-engine/(실행|설정) 파일\] \S*/%s: 정상' % re.escape(name))
        self.assertIn('[ovirt-engine-proxy/설정 파일] %s/apache.key: 정상 (권한 0600' % self.files, passed)
        skipped = '\n'.join(self.lines(out, 'SKIP'))
        self.assertIn('optional.conf: 없음(선택 파일)', skipped)
        # Not installed, and installed but not in use: every item still named.
        for process in ('postgresql', 'ovirt-engine-dwhd', 'ovirt-provider-ovn'):
            for item in ITEMS:
                self.assertIn('[%s/%s]' % (process, item), skipped)
        self.assertIn('[ovirt-websocket-proxy/프로세스 실행 상태] ovirt-websocket-proxy.service: 사용 안 함',
                      skipped)
        result = json.loads((self.dir / 'results.json').read_text())
        self.assertEqual('PASS', result['status'])
        self.assertEqual(len(self.lines(out, 'SKIP')), result['summary']['skipped'])

    def test_each_problem_fails_its_own_item(self):
        (self.files / 'database.conf').chmod(0o644)      # a password readable by everyone
        (self.files / 'engine.conf').chmod(0o666)        # writable by everyone
        (self.files / 'ear' / 'a.jar').chmod(0o666)      # inside the application
        (self.files / 'httpd.conf').unlink()             # required and gone
        self.installed.write_text(
            'ovirt-engine.service enabled active\nhttpd.service enabled failed\n')
        rc, out = self.run_audit()
        self.assertEqual(1, rc, out)
        failed = '\n'.join(self.lines(out, 'FAIL'))
        self.assertIn('[ovirt-engine/설정 파일] %s/database.conf: 비밀정보 파일에 기타 사용자 접근 권한'
                      % self.files, failed)
        self.assertIn('engine.conf: 기타 사용자 쓰기 권한', failed)
        self.assertIn('[ovirt-engine/실행 파일] %s/ear: 하위 파일에 그룹·기타 사용자 쓰기 권한' % self.files,
                      failed)
        self.assertIn('[ovirt-engine-proxy/설정 파일] %s/httpd.conf: 파일이 없음' % self.files, failed)
        self.assertIn('[ovirt-engine-proxy/프로세스 실행 상태] httpd.service: 실행 중이 아님(failed)', failed)
        self.assertEqual(5, len(self.lines(out, 'FAIL')), out)

    def test_before_the_engine_starts_a_process_not_up_yet_is_a_warning(self):
        self.installed.write_text(
            'ovirt-engine.service enabled activating\nhttpd.service enabled inactive\n')
        rc, out = self.run_audit(SECURITY_AUDIT_SOURCE='engine-start')
        self.assertEqual(0, rc, out)
        self.assertIn('[PASS] [ovirt-engine/프로세스 실행 상태] ovirt-engine.service: 실행 중(activating',
                      out)
        self.assertIn('[WARN] [ovirt-engine-proxy/프로세스 실행 상태] httpd.service: 실행 중이 아님', out)

    def test_a_process_under_the_wrong_account_is_said(self):
        self.ps.write_text('#!/bin/sh\necho nobody\n')
        rc, out = self.run_audit()
        self.assertIn('[WARN] [ovirt-engine/프로세스 실행 상태] ovirt-engine.service: 실행 중(active, PID 4242)'
                      '이나 실행 계정이 nobody (기대값 root)', out)


class FileStatHelperTest(unittest.TestCase):
    """The helper reads only the list, and tells a missing file from one out of sight."""

    def test_reports_present_missing_and_hidden(self):
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, True)
        os.chmod(base, 0o755)
        (base / 'shown.conf').write_text('x')
        (base / 'shown.conf').chmod(0o640)
        (base / 'private' / 'data').mkdir(parents=True)
        (base / 'private' / 'data' / 'pg_hba.conf').write_text('x')
        os.chmod(base / 'private', 0o700)
        listed = base / 'list.conf'
        listed.write_text(
            f'p unit - p.service\np conf - {base}/shown.conf\np conf - {base}/gone.conf\n'
            f'p conf - {base}/private/data/pg_hba.conf\n')
        listed.chmod(0o644)
        command = ['bash', str(HELPER)]
        if os.geteuid() == 0:
            # As the engine user would, without the sudo rule.
            command = ['setpriv', '--reuid=65534', '--regid=65534', '--clear-groups'] + command
        out = subprocess.run(
            command, env=dict(os.environ, OVWORKS_PROCESS_FILES=str(listed)),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
        ).stdout
        rows = {line.split('\t')[0]: line.split('\t') for line in out.splitlines()}
        self.assertEqual(3, len(rows), out)
        self.assertEqual(['present', '640'], rows[f'{base}/shown.conf'][1:3])
        self.assertEqual('file', rows[f'{base}/shown.conf'][6])
        self.assertEqual('missing', rows[f'{base}/gone.conf'][1])
        if os.geteuid() == 0:
            self.assertEqual('denied', rows[f'{base}/private/data/pg_hba.conf'][1])

    def test_sudo_cannot_point_it_at_another_list(self):
        helper = HELPER.read_text(encoding='utf-8')
        self.assertIn('if [ -z "${SUDO_USER:-}" ] && [ -n "${OVWORKS_PROCESS_FILES:-}" ]; then', helper)
        self.assertIn('LIST=/usr/share/ovirt-engine/conf/ovworks-process-files.conf', helper)
        self.assertTrue(HELPER.stat().st_mode & stat.S_IXUSR)


if __name__ == '__main__':
    unittest.main()
