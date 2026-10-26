#!/bin/bash
set -euo pipefail
if [ "$(id -u)" != 0 ] || [ "$(uname -s)" != Linux ] || [ ! -f /.dockerenv ]; then
  echo 'This harness must run as root inside a disposable Docker container.' >&2
  exit 1
fi
export CARGO_TARGET_DIR=/tmp/keyd-target
export RUST_LOG=info
python3 deploy/linux/acceptance/test-migration.py
cargo build --locked
cargo build --locked --example local-preview-fixture
cargo test --locked --quiet
ANPIO_KEY_DISPOSABLE_LINUX_TEST=1 cargo test --locked --test security_boundary -- --ignored
if [ "${ANPIO_KEY_TEST_MCP:-0}" = 1 ]; then
  cargo build --locked --features mcp
fi
python3 deploy/linux/acceptance/test-boundary.py --binary "$CARGO_TARGET_DIR/debug/anpio-key"
