# macOS local-use deployment (UID boundary preview)

Start with the [local-use guide](../LOCAL-USE.md). Ordinary local use does not
require full Xcode, a paid Apple developer membership, Secure Enclave or TPM.
Rust and the macOS build toolchain are needed to build from source. This mode
always reports `protected_supported=false`; it is not a formally accepted
protected macOS distribution.

Layout: this directory holds the install, update and migration entry points.
Root-only acceptance tools live in [`acceptance/`](acceptance/); CI unit tests
live in [`tests/`](tests/). Normal use needs neither.

## What the boundary requires

A trusted human administrator, a separate non-login service UID, and a distinct
non-admin UID for every untrusted Agent. The complete Agent process must run under
that UID. Root owns the code, config and launchd job; the service UID owns
protected state and sockets. Agents receive only signing transport access and
explicit, limited hot-key grants. PTY/TTY, executable names and socket-group
membership cannot replace kernel UID authorization. Same-UID arbitrary code is one
principal.

For Secure Enclave use, the launch context is part of the boundary. Agents and
any process that must not hold SE capability run as root-owned system
LaunchDaemons in a non-login audit session, where the data protection keychain is
unavailable (tested on 2026-10-19; see
[the validation record](../../docs/validation/macos-se-system-context-2026-10-19.md)).
Code started in the administrator's graphical login session, including through
`sudo`, is trusted management input: it can reach the login keychain and is not
separated by UID. The signed foreground helper is the only component intended to
run there; see [SE session scope](SE-SESSION.md).

The installer requires local APFS, symlink-free trusted paths and no extended ACLs
on protected installation paths. It refuses insecure existing permissions instead
of loosening checks. PT_DENY_ATTACH/core-dump restrictions are additional
defenses; root/admin/kernel compromise and all possible OS escape paths are not
covered.

## Fresh installation: human terminal

Use a trusted, reviewed checkout. Do not run privileged installation scripts from
an Agent-controlled working tree. From the repository root, one command builds,
provisions the accounts and starts the local preview:

```sh
./install.sh
```

Add `--bootstrap --did-host HOST --target https://...` (or answer the terminal
prompts) to create a disposable preview identity, migrate it into protected
state and issue one grant in the same run. This path always uses
`_anpagent` and `--hardware none`; it still reports `protected_supported=false`.
Passphrases are read by Anpio Key from the human terminal only. Use a disposable
identity and a public password, never real keys.

The script asks for sudo only after the build. It creates `_anpio` / `_anpagent`,
four groups, root-owned installation/configuration and a launchd job, starts the
service and runs limited read-only checks. It refuses existing or partial setup.
It is not an update or repair command. Do not repeat `launchctl bootstrap` after
successful setup: the job is already loaded. Log out/in to refresh group
membership. Initial state contains no user keys. `--bootstrap` only applies to a
fresh empty installation; use the operator procedure in [AGENT.md](AGENT.md) to
import an existing identity or real keys. Further Agents need their own
independently provisioned non-admin UIDs, transport membership and explicit
principal registration; this setup creates one Agent.

For a manually reviewed release, the same steps are:

```sh
cargo build --locked --release --features mcp
shasum -a 256 target/release/anpio-key
python3 deploy/macos/provision-accounts.py --admin-user YOUR_HUMAN_ACCOUNT
sudo bash deploy/macos/setup-local.sh YOUR_HUMAN_ACCOUNT VERIFIED_SHA256
```

Check the installed instance:

```sh
/Library/ANPIOKey/bin/anpio-key admin --config /Library/ANPIOKey/service.json status
/Library/ANPIOKey/bin/anpio-key admin --config /Library/ANPIOKey/service.json catalog
sudo /usr/bin/python3 deploy/macos/acceptance/test-install.py
```

`OK` is necessary but does not prove real signing or a fully isolated Agent.
Continue with temporary-key acceptance below. Do not manually copy into managed
state or loosen ownership to make an Agent work. macOS fresh deployment does not
promise the Linux offline vault-migration tool as a supported macOS workflow;
the operator-run [Agent and migration procedure](AGENT.md) provides an offline
cutover. Validate it with temporary identities before any real migration.

## Temporary-key acceptance: existing installation stays unchanged

Build the public test-only fixture/verifier and record both reviewed hashes:

```sh
cargo build --locked --release --example local-preview-fixture
shasum -a 256 /Library/ANPIOKey/bin/anpio-key target/release/anpio-key \
  target/release/examples/local-preview-fixture
sudo bash deploy/macos/acceptance/check-local-use.sh INSTALLED_SHA256 \
  "$PWD/target/release/anpio-key" CANDIDATE_SHA256 \
  "$PWD/target/release/examples/local-preview-fixture" HELPER_SHA256
```

The driver pins all three executable digests before testing. It first checks the
installed UID boundary read-only, then runs the installed and candidate binaries
in separate temporary `/Library/ANPIOKeyChecks-*` instances. It reuses existing
accounts; second-subject transport groups are assigned only to test children.
It creates no accounts and does not update the daily binary/state/config/launchd
job or read real keys. Root is needed for credential switching and secure
temporary paths; an assistant's sandbox exemption does not replace the human's
sudo password.

Tests cover actual hot-key signing with independent upstream verification,
changed-target rejection, stable-ID retry/conflict, cross-UID
grant/document/result isolation, PTY/admin/group bypass denial, task-port denial,
revocation, loaded-key and active-grant invalidation after graceful restart and
SIGKILL, and a forged socket rejected before any request/password. These are
bounded tests, not proof of every host escape or a complete AI framework's account
isolation.

Default acceptance is noninteractive. Append `--interactive-ui` to check the
candidate's native dialog: Cancel, 120-second timeout, then masked input of the
public password `temporary-boundary-test-secret`. Use that password only for the
fixture, never for real identities. The human must confirm the exact displayed
target and masking. Whole-machine reboot, sleep/logout, and persistent SE tests
are separate; default driver success does not complete those gates.

Complete-framework Claude Code acceptance and the offline identity cutover are
described in [AGENT.md](AGENT.md). Its deterministic local API fixture is separate
from live model-provider acceptance.

## Migrating an installation made under the old name

Installations created before the rename use `/Library/ANPKeyd`, the
`org.anp-keyd.local` launchd label, the `_anpkeyd*` accounts and a binary at
`bin/anp-keyd`. The migration tool rewrites all four; it is plan-only until
`--apply`, and needs root for the apply. Renaming a Directory Services record
keeps its UID/GID, so file ownership and group memberships survive, but the old
names stop existing and there is no automatic rollback.

```sh
python3 deploy/macos/migrate-name.py --user-home "$HOME"
# Review the plan, then the human may run the same command with sudo and --apply.
```

It stops the job, waits for both sockets to disappear, renames the users/groups,
flushes the Directory Services cache, moves and renames the installation and its
binary, rewrites `service.json` and the plist (including `UserName`/`GroupName`),
and bootstraps the renamed job. An incomplete or already-migrated tree is refused
rather than half-converted. Restarting locks keys and revokes grants, so re-unlock
before signing.

## Daily workflow, updates and restart

The human alone prepares/commits catalog, roles, policy and grants. An exact-key
unlock can use the installed trusted UI:

```sh
/Library/ANPIOKey/bin/anpio-key admin --config /Library/ANPIOKey/service.json unlock \
  --vault-id VAULT_UUID --did DID --kid EXACT_KID --native-ui
```

It authenticates the daemon before prompting and again before sending. Cancel,
timeout and UI errors fail closed, with no terminal fallback. Unlock does not
create a grant. Root/recovery keys cannot be used by ordinary Agent grants.
See the [daily workflow](../LOCAL-USE.md) for explicit grant creation and running
the entire Agent under its own UID.

Stopping/restarting leaves configuration/state intact but locks keys and
invalidates grants. `KeepAlive=false`; crash recovery does not automatically
restart/unlock. The verified binary updater is plan-only by default:

```sh
python3 deploy/macos/update-local.py --binary target/release/anpio-key --sha256 VERIFIED_SHA256
# Review the plan, then the human may run the same command with sudo and --apply.
```

It retains `bin/anpio-key.previous`; if that slot already exists, review it and add
`--archive-previous` to the plan and apply commands to preserve it in an exclusive
SHA-256-named archive first. Existing archives are never overwritten. It atomically
replaces the binary under the state lock and checks identity/health after restart.
Never delete a backup or state database merely to make an update succeed. There is
no automatic rollback, state reset or schema downgrade. Do not automatically
install an unaccepted SE candidate over a working daily deployment.

## Secure Enclave is a separate, unfinished enhancement

The current SE backend needs the user's data protection keychain; signing a
system LaunchDaemon cannot give it that login context. The foreground
`admin se-session` bridge is implemented, but formal signing/profile
authorization, persistent SE keys, real logout/relogin/sleep/reboot and upgrade
acceptance remain outstanding. The [SE guide](SE-SESSION.md) explains the limits,
the `se-release.py` bundle tool, the cross-process `se-persistence.py` probe and
the read-only `se-preflight.py` check. Ordinary local preview does not require a
paid membership or full Xcode. A CSR alone does not authorize entitlements.

Historical per-stage results, older pending messages and local installation hashes
are preserved in [HISTORY.md](HISTORY.md); they are not acceptance of your machine.
