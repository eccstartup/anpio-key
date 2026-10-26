"""Opt-in real framework smoke: no model call, real identity or privileged UID.
ANPIO_KEY_TEST_CLAUDE must name a reviewed standalone executable. For full
cross-UID signing acceptance use test-runtime.py, not this smoke check.
"""
import sys
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'acceptance'))

import claude_fixture


@unittest.skipUnless(os.environ.get('ANPIO_KEY_TEST_CLAUDE'), 'opt-in standalone Claude Code executable required')
class ActualFramework(unittest.TestCase):
    def test_actual_bash_tool_runs_with_clean_home(self):
        binary = Path(os.environ['ANPIO_KEY_TEST_CLAUDE']).resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix='keyd-claude-smoke-') as directory:
            home = Path(directory)
            (home / 'tmp').mkdir()
            command = '/usr/bin/id -u > ' + shlex.quote(str(home / 'uid'))
            with claude_fixture.messages_api(command) as endpoint:
                result = subprocess.run(claude_fixture.arguments(binary), cwd=home,
                    env=claude_fixture.environment(home, 'fixture-agent', endpoint),
                    capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((home / 'uid').read_text().strip(), str(os.getuid()))


if __name__ == '__main__':
    unittest.main()
