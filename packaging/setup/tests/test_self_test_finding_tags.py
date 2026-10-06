import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
AUDIT = ROOT / 'ov-works-security_audit.sh'


class FindingTagTest(unittest.TestCase):
    """Every [FAIL]/[WARN] line names the component and item it belongs to."""

    def setUp(self):
        self.script = AUDIT.read_text(encoding='utf-8')

    def test_every_check_in_the_audit_runs_tagged(self):
        main = self.script[self.script.index('# Run all security checks'):
                           self.script.index('# Generate summary')]
        calls = re.findall(r'^    (\S+.*)$', main, re.M)
        checks = [c for c in calls if c.startswith(('check_', 'verify_', 'run_check'))]
        self.assertTrue(checks)
        for call in checks:
            self.assertRegex(call, r'^run_check "(엔진 서버|클라이언트\(WebAdmin\))" "[^/\]"]+" \w+$')

    def test_findings_print_the_tag_the_engine_reads(self):
        out = subprocess.run(
            ['bash', '-c',
             'source <(sed "s/^if \\[ \\"\\${BASH_SOURCE\\[0\\]}\\" = \\"\\$0\\" \\]; then/if false; then/" "$0"); '
             'AUDIT_LOG=/dev/null; f(){ log_fail "bad"; log_warn "meh"; }; '
             'run_check "엔진 서버" "설정 파일 권한" f; log_fail "untagged"',
             str(AUDIT)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
        ).stdout
        self.assertIn('[FAIL] [엔진 서버/설정 파일 권한] bad', out)
        self.assertIn('[WARN] [엔진 서버/설정 파일 권한] meh', out)
        # Outside run_check nothing is tagged, and nothing is left over from the last check.
        self.assertIn('[FAIL] untagged', out)


if __name__ == '__main__':
    unittest.main()
