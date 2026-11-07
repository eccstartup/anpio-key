"""Static checks on every entry-point shell script; no root and no writes."""
import re
import subprocess
from pathlib import Path
import unittest

REPO = Path(__file__).resolve().parents[2]
SKIP_DIRS = {'.git', 'target', 'node_modules'}
# macOS ships bash 3.2. With a UTF-8 locale it folds the next multibyte byte
# into an adjacent variable name, so `$var（` becomes an unbound variable under
# set -u. Braces are the only portable spelling.
ADJACENT = re.compile(r'\$[A-Za-z_][A-Za-z0-9_]*[^\x00-\x7F]')


def shell_scripts():
    return sorted(path for path in REPO.rglob('*.sh')
                  if not SKIP_DIRS.intersection(path.relative_to(REPO).parts))


class ShellScripts(unittest.TestCase):
    def test_parse(self):
        scripts = shell_scripts()
        self.assertTrue(scripts)
        for script in scripts:
            with self.subTest(script=script.relative_to(REPO)):
                result = subprocess.run(['/bin/bash', '-n', str(script)],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_no_variable_adjacent_to_non_ascii(self):
        for script in shell_scripts():
            for number, line in enumerate(script.read_text(encoding='utf-8').splitlines(), 1):
                with self.subTest(script=script.relative_to(REPO), line=number):
                    self.assertIsNone(ADJACENT.search(line),
                                      'use ${var} before a non-ASCII character')


if __name__ == '__main__':
    unittest.main()
