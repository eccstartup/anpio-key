#!/bin/bash
# Operator-run acceptance: existing installation + temporary signing instances.
# No new accounts, real keys, daily state/config changes, or launchd replacement.
set -euo pipefail
if [ "${1:-}" = --help ] || [ "$#" -lt 5 ] || [ "$#" -gt 6 ]; then
  echo 'Usage: sudo bash check-local-use.sh INSTALLED_SHA256 CANDIDATE_ABSOLUTE_PATH CANDIDATE_SHA256 HELPER_ABSOLUTE_PATH HELPER_SHA256 [--interactive-ui]'
  echo 'Review the trusted checkout first. Default checks are noninteractive and use only temporary identities.'
  echo 'Optional --interactive-ui adds Cancel, 120-second timeout and public temporary-password windows for the candidate.'
  if [ "${1:-}" = --help ]; then exit 0; else exit 2; fi
fi
if [ "$(uname -s)" != Darwin ] || [ "$(id -u)" != 0 ]; then
  echo 'Requires macOS root in the human terminal; enter any sudo password locally.' >&2
  exit 1
fi
if [ "$#" = 6 ] && [ "$6" != --interactive-ui ]; then
  echo 'Only --interactive-ui is accepted as the sixth argument.' >&2
  exit 2
fi
script_dir="$(cd -- "$(dirname -- "$0")" && pwd -P)"
installed=/Library/ANPIOKey/bin/anpio-key
# Pin every executable before the first test. Never run the mutable build-tree
# candidate as root; test-runtime copies the pinned bytes into a temporary domain.
/usr/bin/python3 - "$installed" "$1" "$2" "$3" "$4" "$5" <<'PY'
import hashlib
from pathlib import Path
import re
import stat
import sys
for name, digest in zip(sys.argv[1::2], sys.argv[2::2]):
    path = Path(name)
    if not path.is_absolute() or not stat.S_ISREG(path.lstat().st_mode):
        sys.exit('expected absolute regular executable, not symlink: ' + name)
    if not re.fullmatch('[0-9a-f]{64}', digest):
        sys.exit('expected verified lowercase SHA-256')
    with path.open('rb') as source:
        content = source.read(128 * 1024 * 1024 + 1)
    if len(content) > 128 * 1024 * 1024 or hashlib.sha256(content).hexdigest() != digest:
        sys.exit('executable digest/size mismatch: ' + name)
print('PASS all three executable digests pinned before acceptance', flush=True)
PY
echo 'CHECK read-only installed UID boundary'
/usr/bin/python3 "$script_dir/test-install.py"
echo 'CHECK installed binary signing/revocation/restart in a temporary instance'
/usr/bin/python3 "$script_dir/test-runtime.py" \
  --signing-helper "$4" --helper-sha256 "$5"
echo 'CHECK candidate signing/revocation/restart in a second temporary instance'
if [ "$#" = 6 ]; then
  /usr/bin/python3 "$script_dir/test-runtime.py" \
    --candidate-binary "$2" --candidate-sha256 "$3" \
    --signing-helper "$4" --helper-sha256 "$5" --interactive-ui
else
  /usr/bin/python3 "$script_dir/test-runtime.py" \
    --candidate-binary "$2" --candidate-sha256 "$3" \
    --signing-helper "$4" --helper-sha256 "$5"
fi
echo 'PASS local-use acceptance; daily installation unchanged. This does not accept persistent SE, whole-machine reboot, or a complete Agent framework.'
