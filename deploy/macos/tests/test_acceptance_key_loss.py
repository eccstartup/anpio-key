"""Losing the SE key must leave the daemon locked and the helper unable to start."""
import sys
import hashlib
from pathlib import Path
import subprocess
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'acceptance'))

import acceptance_se

LABEL = 'anpio-key/e1_' + 'A' * 43


class KeyLoss(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.base = Path(self.directory.name)
        self.cleanup = self.base / 'Cleanup.app'
        binary = self.cleanup / 'Contents' / 'MacOS' / 'anpio-key'
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b'cleanup')
        self.digest = hashlib.sha256(b'cleanup').hexdigest()
        self.checks = SimpleNamespace(
            args=SimpleNamespace(key_loss_cleanup=self.cleanup,
                                 key_loss_cleanup_sha256=self.digest),
            credentials=lambda user: {}, env={}, base=self.base,
            admin=SimpleNamespace(pw_uid=501),
            grant=Mock(return_value='grant'), expect_locked=Mock())

    def tearDown(self):
        self.directory.cleanup()

    def output(self, private, public):
        lines = []
        for part, count in (('private', private), ('public', public)):
            lines.append(f'FOUND {LABEL} {part} count={count}')
            lines.append(f'ABSENT_AFTER_DELETE {LABEL} {part}')
        return '\n'.join(lines)

    def invoke(self, results, helper=None):
        helper = helper or FakeHelper
        with patch.object(acceptance_se.subprocess, 'run', side_effect=results), \
             patch.object(acceptance_se.subprocess, 'Popen', helper):
            acceptance_se.Checks.exercise_key_loss(self.checks, LABEL, ['helper'])

    def test_missing_key_is_deleted_by_an_exact_label_and_signing_stays_locked(self):
        results = [subprocess.CompletedProcess([], 0, self.output(1, 1), ''),
                   subprocess.CompletedProcess([], 0, self.output(0, 0), '')]
        self.invoke(results)
        self.checks.expect_locked.assert_called_once_with('grant')

    def test_absent_key_before_deletion_fails_closed(self):
        results = [subprocess.CompletedProcess([], 0, self.output(0, 0), '')]
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            self.invoke(results)
        self.checks.expect_locked.assert_not_called()

    def test_cleanup_failure_is_refused(self):
        results = [subprocess.CompletedProcess([], 1, '', 'denied')]
        with self.assertRaisesRegex(ValueError, 'cleanup failed'):
            self.invoke(results)

    def test_helper_success_after_key_loss_is_refused(self):
        results = [subprocess.CompletedProcess([], 0, self.output(1, 1), ''),
                   subprocess.CompletedProcess([], 0, self.output(0, 0), '')]
        with self.assertRaisesRegex(ValueError, 'reported success'):
            self.invoke(results, helper=lambda *a, **k: FakeHelper(*a, returncode=0, **k))

    def test_helper_that_establishes_a_session_is_refused(self):
        results = [subprocess.CompletedProcess([], 0, self.output(1, 1), ''),
                   subprocess.CompletedProcess([], 0, self.output(0, 0), '')]
        with self.assertRaisesRegex(ValueError, 'established an SE session'):
            self.invoke(results, helper=lambda *a, **k: FakeHelper(
                *a, text='SE session active for exact key x\n', returncode=1, **k))

    def test_digest_mismatch_is_refused_before_deletion(self):
        self.checks.args.key_loss_cleanup_sha256 = '0' * 64
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            self.invoke([])


class FakeHelper:
    def __init__(self, command, stdout=None, text='key not found\n', returncode=1, **kwargs):
        stdout.write(text)
        stdout.flush()
        self.returncode = returncode

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        pass


if __name__ == '__main__':
    unittest.main()
