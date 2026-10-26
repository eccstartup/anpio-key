#!/bin/bash
# Regression for shared signing/fixture orchestration. NOT macOS OS/UI evidence.
set -euo pipefail
if [ "$(id -u)" != 0 ] || [ "$(uname -s)" != Linux ] || [ ! -f /.dockerenv ]; then
  echo 'Disposable Linux root Docker only' >&2
  exit 1
fi
export CARGO_TARGET_DIR=/tmp/keyd-signing-target
export RUST_LOG=info
for account in signing-admin signing-agent; do
  useradd --create-home --shell /bin/sh "$account"
done
cargo build --locked
cargo build --locked --release --example local-preview-fixture
python3 deploy/linux/install.py --binary "$CARGO_TARGET_DIR/debug/anpio-key" \
  --sha256 "$(sha256sum "$CARGO_TARGET_DIR/debug/anpio-key" | cut -d' ' -f1)" \
  --allow-development-build --admin-user signing-admin --agent-user signing-agent
framework_args=()
if [ -n "${ANPIO_KEY_TEST_CLAUDE:-}" ]; then
  framework_args=(--claude-binary "$ANPIO_KEY_TEST_CLAUDE" --claude-sha256 "$(sha256sum "$ANPIO_KEY_TEST_CLAUDE" | cut -d' ' -f1)")
fi
python3 deploy/macos/acceptance/test-runtime.py "${framework_args[@]}" --container-regression \
  --binary /usr/local/libexec/anpio-key --config /etc/anpio-key/service.json \
  --migrate-fixture \
  --signing-helper "$CARGO_TARGET_DIR/release/examples/local-preview-fixture" \
  --helper-sha256 "$(sha256sum "$CARGO_TARGET_DIR/release/examples/local-preview-fixture" | cut -d' ' -f1)"
