#!/bin/bash
# Explicit local host changes; run by the human from their terminal with sudo.
set -euo pipefail
if [ "$(uname -s)" != Darwin ] || [ "$(id -u)" != 0 ]; then
  echo 'Run in the human terminal: sudo bash deploy/macos/setup-local.sh HUMAN_ACCOUNT VERIFIED_SHA256 [BINARY]' >&2
  exit 1
fi
if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo 'Expected HUMAN_ACCOUNT, independently reviewed binary SHA-256, and optional binary path.' >&2
  exit 1
fi
script_dir="$(cd -- "$(dirname -- "$0")" && pwd -P)"
repo_dir="$(cd -- "$script_dir/../.." && pwd -P)"
local_binary="${3:-$repo_dir/target/release/anpio-key}"
# Validate the digest before account changes. Python and source are trusted
# operator inputs; do not run this from an Agent-controlled checkout.
/usr/bin/python3 - "$local_binary" "$2" <<'PY'
import hashlib, pathlib, sys
binary = pathlib.Path(sys.argv[1])
if hashlib.sha256(binary.read_bytes()).hexdigest() != sys.argv[2]:
    sys.exit('binary digest mismatch')

PY
/usr/bin/python3 "$script_dir/provision-accounts.py" --admin-user "$1" --apply
/usr/bin/python3 "$script_dir/install.py" --binary "$local_binary" --sha256 "$2" \
  --service-user _anpio --agent-user _anpagent --admin-user "$1" \
  --sign-group _anpio_sign --admin-group _anpio_admin --apply
/bin/launchctl bootstrap system /Library/LaunchDaemons/org.anpio-key.local.plist
# launchd starts asynchronously. Bound the wait and leave failures for inspection.
for attempt in {1..30}; do
  if [ -S /Library/ANPIOKey/admin/admin.sock ]; then break; fi
  /bin/sleep 1
done
/usr/bin/python3 "$script_dir/test-install.py"
echo 'Service is already loaded and running; do not run launchctl bootstrap again.'
echo 'Local empty-state installation checked. No real keys migrated. Log out/in before operator use.'
