import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
RUNNER = ROOT / 'ovirt-engine-security-verification-runner.sh'


def fake(directory, name, body):
    path = directory / name
    path.write_text('#!/bin/bash\n' + body)
    path.chmod(0o755)
    return path


class IntegrityRunnerSealTest(unittest.TestCase):
    """The baseline's seal is checked before AIDE runs, and a baseline that does not match it
    fails the verification without AIDE being asked to compare anything against it."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.calls = self.dir / 'calls'
        fake(self.dir, 'sudo', 'shift; exec "$@"\n')   # drops -n
        fake(self.dir, 'seal', 'echo seal "$@" >> "$CALLS"; printf "%s" "$SEAL_OUT"; exit "${SEAL_RC:-0}"\n')
        fake(self.dir, 'aide', 'echo aide "$@" >> "$CALLS"; printf "%s" "$AIDE_OUT"; exit "${AIDE_RC:-0}"\n')
        (self.dir / 'aide.conf').write_text('# test\n')

    def run_runner(self, **env):
        environment = dict(
            os.environ,
            OVIRT_SUDO_COMMAND=str(self.dir / 'sudo'),
            INTEGRITY_SEAL_COMMAND=str(self.dir / 'seal'),
            AIDE_COMMAND=str(self.dir / 'aide'),
            AIDE_CONFIG=str(self.dir / 'aide.conf'),
            LOCK_FILE=str(self.dir / 'lock'),
            LOGGER_COMMAND='/bin/true',
            INTEGRITY_VERIFICATION_RESULTS=str(self.dir / 'integrity-results.json'),
            INTEGRITY_LOG_DIR=str(self.dir / 'log'),
            SECURITY_VERIFICATION_SKIPPED=str(self.dir / 'skipped'),
            CALLS=str(self.calls),
            **env,
        )
        result = subprocess.run(['bash', str(RUNNER), 'integrity', 'test'], env=environment,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                universal_newlines=True)
        results = json.loads((self.dir / 'integrity-results.json').read_text())
        return result.returncode, result.stdout, results

    def calls_made(self):
        return self.calls.read_text().splitlines() if self.calls.exists() else []

    def test_a_sealed_baseline_is_then_compared_by_aide(self):
        rc, out, results = self.run_runner()
        self.assertEqual(0, rc, out)
        self.assertEqual('PASS', results['status'])
        self.assertEqual(['seal --verify', 'aide --config=%s --check' % (self.dir / 'aide.conf')],
                         self.calls_made())

    def test_a_baseline_that_does_not_match_its_seal_fails_without_aide(self):
        rc, out, results = self.run_runner(
            SEAL_RC='3', SEAL_OUT='changed: /var/lib/aide/ovworks.db.gz\n')
        self.assertEqual(20, rc, out)
        self.assertEqual('FAIL', results['status'])
        self.assertEqual(['seal --verify'], self.calls_made())
        report = Path(results['log_file']).read_text()
        self.assertIn('changed: /var/lib/aide/ovworks.db.gz', report)

    def test_a_seal_that_cannot_be_checked_is_an_error_not_a_pass(self):
        rc, out, results = self.run_runner(SEAL_RC='2')
        self.assertEqual(40, rc, out)
        self.assertEqual('ERROR', results['status'])
        self.assertEqual(['seal --verify'], self.calls_made())

    def test_aides_report_follows_the_seal_line_in_the_same_report(self):
        rc, out, results = self.run_runner(
            SEAL_OUT='Baseline seal verified\n', AIDE_RC='4', AIDE_OUT='changed: /usr/sbin/httpd\n')
        self.assertEqual(20, rc, out)
        report = Path(results['log_file']).read_text()
        self.assertIn('Baseline seal verified', report)
        self.assertIn('changed: /usr/sbin/httpd', report)


if __name__ == '__main__':
    unittest.main()
