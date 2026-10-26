# Historical macOS local-preview implementation and acceptance

Preserved stage-by-stage records. Earlier pending/failure notes are historical;
the latest operator acceptance near the end supersedes them only for its stated
binary and local-use scope. Follow [the current deployment guide](README.md) and
[SE session scope](SE-SESSION.md). No historical result accepts a new machine or
formal SE distribution automatically.

# macOS local UID boundary preview (U2)

## U3 Secure Enclave execution-context gate

The current SE backend uses the data protection keychain. Apple
[TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)
limits that keychain to a user login context; a system LaunchDaemon cannot use
it. Signing the existing `_anpio` LaunchDaemon does not resolve this limitation.
Do not purchase a certificate on the assumption that it makes this deployment
SE-capable. Non-persistent ECDH tests in a human login session do not demonstrate
persistent service access. The existing local preview remains usable without SE.

This limitation was probed against the real keychain on 2026-10-19: the same
signed SE example running as `_anpagent` under one-shot system LaunchDaemons —
both raw and with `SessionCreate` — was refused with `errSecNotAvailable`
(`-25291`), while the login-session open and post-delete refusal passed. See
[the validation record](../../docs/validation/macos-se-system-context-2026-10-19.md)
and `deploy/macos/se-system-context.py`.

The read-only release prerequisite gate never runs or signs the candidate and
never touches a keychain, account, service or vault:

```sh
python3 deploy/macos/se-preflight.py --binary /absolute/path/to/signed/anpio-key \
  --sha256 VERIFIED_SIGNED_BINARY_SHA256 --execution-context system-daemon \
  --team-id APPLE_TEAM_ID --application-id APPLE_TEAM_ID.APP_IDENTIFIER
```

It requires a verified signature, expected team/application identifiers, a narrow
keychain group, hardened runtime and no debug/code-loading exceptions. System
daemon context always fails this gate. `user-session` is an explicit candidate
architecture, not an accepted replacement for the existing service boundary.
Even exit 0 covers only the checked signature prerequisites; provisioning
authorization, distribution assessment, persistent hardware operations, isolation,
reboot and upgrade remain pending. All reports retain `protected_supported=false`.

The foreground login-session bridge is implemented as `admin se-session`.
Its [protocol, lifetime, deployment prerequisites and acceptance checklist](SE-SESSION.md)
remain preview-only. No automatic restoration of grants is authorized by a
hardware probe. U3 formal SE service acceptance and dependent SE recovery stay
open until signed persistent-key and complete host lifecycle checks pass.

This is a local-use implementation, not an accepted protected macOS release.
`macos-boundary-preview` always reports `protected_supported=false`, including
release builds. No paid Apple membership is needed to build and test this path.
Linux modes are rejected on macOS; no `macos-protected-v1` mode is accepted.

## Execution domains

The OS, root, installed daemon and human management account are trusted. Each
untrusted Agent must run under a distinct non-admin UID; all arbitrary code under
one UID is one principal. The provided installer configures one Agent account;
additional Agents require distinct accounts and explicit principal registration.
An Agent running in the human account has the human account's authority. Moving
only the signing client into another UID does not isolate an Agent that retains
access to the human account. No sudo, admin-group membership, stored human login
credentials, remote login to the management account, or inherited management
sessions may be handed to Agents. A UID boundary is not a VM or a general sandbox.

The service runs as `_anpio`, with a disabled login shell. `_anpagent` has no
login password and is launched by a trusted operator. It can reach only the data
socket; its primary home `/var/empty` must not be used as a writable workspace.
Assign an Agent-owned working directory separately, without granting access to
the human's home. Do not install passwordless sudo or an Agent-controlled launchd
job with authority over the service or management account.

Root owns `/Library/ANPIOKey`, its executable/config and the launchd plist. The
service owns mode-0700 state and separate mode-0750 socket directories; sockets
are 0660. Socket groups allow transport access, while kernel UID authentication
and SQLite principal state decide authorization. Clients verify config ownership,
symlink-free paths, socket inode and daemon UID before sending secrets. macOS
extended ACL entries on trusted paths are rejected conservatively, even deny-only
entries. Do not remove system ACLs to get around a failure; choose/review a safe
installation location or resolve the policy explicitly. Local APFS is required.

The daemon disables core dumps and future debugger attachment using
`PT_DENY_ATTACH`. These are additional defenses, not claims of kernel/root
isolation. Unlike the Linux systemd unit, this launchd job does not claim a
filesystem/network syscall sandbox. Root/admin compromise, kernel escapes,
physical attacks, copied historical keys and same-UID arbitrary code are outside
this boundary. No Secure Enclave capability or hardware acceptance is introduced.

## Review and install

Build from the reviewed checkout, using the checked-in lockfile:

```sh
cargo build --locked --release --features mcp
shasum -a 256 target/release/anpio-key
python3 deploy/macos/provision-accounts.py --admin-user YOUR_HUMAN_ACCOUNT
```

For the complete, explicitly approved local setup (account creation, installation,
launchd startup and limited read-only acceptance), the human may run:

```sh
sudo bash deploy/macos/setup-local.sh YOUR_HUMAN_ACCOUNT VERIFIED_SHA256
```

The setup script already runs `launchctl bootstrap`; do not bootstrap it again.
To inspect a loaded job use `launchctl print system/org.anpio-key.local`.

Enter the sudo password only in your own terminal. Run from a human-controlled
checkout after reviewing the scripts and exact binary digest. The script refuses
existing/partial installations; it is not an update or repair tool. The longer
commands below allow the same steps to be reviewed/run individually.

The account tool prints its complete command plan without modifying anything.
Review it before explicitly applying it as root:

```sh
sudo python3 deploy/macos/provision-accounts.py --admin-user YOUR_HUMAN_ACCOUNT --apply
```

This creates two hidden, password-disabled accounts and four groups, and adds
the human account to the management group. It refuses existing names, including
partially created installations; it never silently adopts or repairs accounts.
Interrupted provisioning needs administrator inspection. Log out/in for group
changes to take effect. Do not type a password into a chat or give it to an Agent.

Plan the installation first (replace the digest with the actual reviewed build):

```sh
python3 deploy/macos/install.py --binary target/release/anpio-key \
  --sha256 VERIFIED_SHA256 --service-user _anpio --agent-user _anpagent \
  --admin-user YOUR_HUMAN_ACCOUNT --sign-group _anpio_sign --admin-group _anpio_admin
# Repeat the same arguments with sudo and --apply only after reviewing the plan.
```

Installation requires a release build without seed-export or software hardware.
It copies exactly the SHA-256-checked bytes, initializes EMPTY state, and writes
the plist without starting it. Existing installations/state are never overwritten;
updates, migration and automatic recovery are not provided by this fresh installer.
It does not touch real identities or copy a daily-use vault. Failed installation
is retained for inspection, never automatically deleted/reinitialized.

```sh
sudo launchctl bootstrap system /Library/LaunchDaemons/org.anpio-key.local.plist
/Library/ANPIOKey/bin/anpio-key admin --config /Library/ANPIOKey/service.json status
sudo python3 deploy/macos/test-install.py
# Explicit stop; keys lock and old grants are invalidated on next startup:
sudo launchctl bootout system/org.anpio-key.local
```

`RunAtLoad` starts the job after future boots once installed; crashes are not
silently retried (`KeepAlive=false`). SIGTERM/interrupt follow normal key-locking
shutdown. Startup refuses missing/corrupt state. Restart never restores grants.
Stopping/unloading is reversible; accounts, configuration, plist and state remain.
Retirement or updates require a separately reviewed offline procedure; do not
remove state to fix startup. New setup has no vaults; enrolling temporary keys
and approving roles/policies/grants use existing typed management operations.
Vault migration from Linux is not promised by this macOS installer.

## Native unlock window

From the trusted human account and installed root-owned binary:

```sh
/Library/ANPIOKey/bin/anpio-key admin --config /Library/ANPIOKey/service.json unlock \
  --vault-id VAULT_UUID --did DID --kid KID --native-ui
```

The client authenticates the daemon before opening the native secure text field,
shows instance/service UID and exact vault/DID/key, then reconnects and re-verifies
identity before sending the password. Cancel is the default button; timeout,
close, empty input and unavailable UI fail closed, without terminal fallback.
No password passes through argv, environment, stdin, stdout or an AppleScript
helper. Application-owned secret copies are zeroized; CoreFoundation's internal
input storage cannot be guaranteed zeroized. Unlocking does not issue a grant.
The terminal management workflow remains authorized only for the separate human
UID. A PTY or a window's appearance does not confer administration. This initial
UI covers exact-key unlock; catalog/policy/grant/rotation remain typed admin CLI
operations. It is not a full graphical management application.

## Validation status and remaining acceptance

Automated local tests cover mode gates, extended ACL rejection, installer identity
policy, and existing persistence/protocol/signing regressions. Normal tests do
not create accounts, install launchd jobs, open password dialogs or use real keys.
`test-install.py` is a limited read-only live check: administrator service identity,
Agent PTY management rejection, unreadable state and inaccessible admin socket.
A successful run alone does not complete U2.

Before any supported macOS declaration, record a real multi-UID launchd run with
temporary identities, fake socket (including forged owner metadata), cross-principal
grant rejection, debugger/task-port denial, Agent access/escape attempts, UI
cancel/timeout/fake-daemon behavior, lock/revocation, service crash/reboot and a
real signed request. Native UI must also be visually checked in the human login
session. These host/interactive checks remain pending until the operator provides
and approves that environment. Software tests are not substitutes for them.

Apple references:
[launchd UserName/GroupName](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html),
[ACL entry semantics](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/acl_get_entry.3.html),
[code signing trust policies](https://developer.apple.com/library/archive/technotes/tn2206/).

Recorded 2026-10-16 before host installation: macOS default 494 tests, MCP 506
tests, six installer policy tests, strict Clippy and local release build passed.
Rust 1.90 Linux container regression passed 492 default tests, one explicit fixture
generator and 124 boundary checks. See the live installation results below;
interactive UI and temporary-key signing checks remain pending.

After installation, additional bounded runtime checks can be run separately:

```sh
sudo python3 deploy/macos/test-runtime.py
```

This uses the existing accounts with a separate temporary configuration, state and
daemon under a new `/Library/ANPIOKeyChecks-*` directory. It tests Agent task-port
access denial, socket cleanup/restart boot epochs, and a fake root listener whose
socket has forged expected ownership and mode. The native unlock client must
reject it without showing a window or sending request/secret bytes. Temporary
files are removed after stopping that temporary daemon; installed launchd state,
keys and configuration are not changed. This does not test actual key/grant
restart invalidation, full escape resistance or native UI appearance.

Live installation evidence, 2026-10-16: operator setup reported administrator
service authentication and UID 601 PTY/admin-socket/state-read denials. Independent
read-only follow-up confirmed launchd `running` as UID 600, daemon `OK`,
`boot_epoch=1`, and healthy audit projection. A subsequent bootstrap error 5 was
a duplicate load; the existing job remained healthy.

After fixes through `2d48025`, the operator reran both acceptance scripts and
reported all checks passing: administrator service authentication; Agent PTY admin,
state-read and admin-socket access denial; Agent task-port access denial; graceful
socket cleanup and restart epoch advance; and rejection of a fake listener despite
forged expected socket ownership/mode, with no request or secret bytes transmitted.
The probes use `/usr/bin/python3 -I` from `/` so an inaccessible operator home or
Conda interpreter cannot be mistaken for a security refusal. Earlier socket-denial
results before this fix were superseded by the successful explicit permission probe.

These are operator-executed host results. Task-port denial alone does not prove
full isolation/escape resistance. The restart check used empty state, so it does
not verify macOS live grant/key invalidation. Interactive UI, temporary-key signing,
cross-principal grants and full reboot acceptance remain pending; macOS continues
to report `protected_supported=false`.


## Full temporary-key and native UI acceptance

Build the test-only fixture/verifier example as the human user (never use its
fixed public password/reduced KDF for real identities):

```sh
cargo build --locked --release --example local-preview-fixture
shasum -a 256 target/release/examples/local-preview-fixture
sudo /usr/bin/python3 deploy/macos/test-runtime.py \
  --signing-helper "$PWD/target/release/examples/local-preview-fixture" \
  --helper-sha256 VERIFIED_HELPER_SHA256 --interactive-ui
```

The driver copies exactly the digest-checked helper into its new root-owned test
directory, generates root/hot/next test keys, and provisions only that separate
temporary service. It does not enroll keys into the installed launchd instance,
change existing account memberships, or access real vaults. A second real OS UID
(`_www` on macOS, `nobody` in Linux regression) receives transport group
access only in its temporary child process.
Typed management operations confirm roles/policy/grants; there are no SQL shortcuts.
Public generated signatures are verified independently with the upstream verifier,
including rejection of a changed target URL. Checks cover cross-principal grants,
request-ID conflicts, target policy, management-group bypass, revocation, graceful
restart and abrupt process death with real loaded keys and active grants.

`--interactive-ui` adds three human steps in the trusted login session:

1. Inspect exact instance/vault/DID/key and click Cancel.
2. Leave the next window untouched until its 120-second timeout.
3. Enter **only** `temporary-boundary-test-secret` into the masked field, then
   click Unlock. Confirm the displayed target/input masking in the terminal.

The driver verifies that cancel and timeout leave the key locked, and only the
successful native unlock enables signing with the fresh grant. No terminal secret
fallback is allowed; fake-daemon and Agent-UID rejection happen before a window.
Without `--interactive-ui`, only automated checks run. UI/key host results remain
pending until this full command passes on macOS.

The same non-UI signing orchestration was exercised in a disposable Rust 1.90
Linux container using `test-signing-container.sh`; all checks passed. Its explicit
container-only mode cannot run on an unmarked Linux host or claim macOS task-port
or graphical UI acceptance. Strict all-target Clippy and local helper generation
also passed. CI includes that orchestration regression.

Child credential setup reserves group slot 0 for the primary GID before socket
groups. This matters on Darwin: [CPython 3.9](https://raw.githubusercontent.com/python/cpython/v3.9.6/Modules/_posixsubprocess.c)
calls `setgroups` before `setregid`, and [XNU](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/kern_credential.c)
uses group slot 0 for EGID, replacing that entry when changing primary group.
Passing only the administrator socket group there can discard it and cause a
false EACCES in the harness. Primary-first role-group policy has a dedicated
regression check; preflight reports libc kernel groups rather than the macOS
Python account-group lookup. This correction does not widen filesystem modes or
change any account membership.

On 2026-10-16 the operator ran the full non-UI command at `9085cf3` on
macOS and reported all checks passing, including actual upstream-verified hot-key
signing, cross-UID grant/document/result denial, revocation, task-port denial,
active grant/result invalidation and locked keys after both graceful restart and
SIGKILL, and forged-socket rejection before any request/secret. Kernel service
groups were `[600,602,603]`, confirming the primary-first credential correction.
The installed launchd instance was not modified. Native window interaction,
whole-machine reboot and formal protected release remain unaccepted.


For native-window diagnostics, the driver can use a SHA-256-pinned candidate
without updating the installed daemon or executable:

```sh
cargo build --locked --release --features mcp
shasum -a 256 target/release/anpio-key
sudo /usr/bin/python3 deploy/macos/test-runtime.py \
  --candidate-binary "$PWD/target/release/anpio-key" --candidate-sha256 VERIFIED_APP_SHA256 \
  --signing-helper "$PWD/target/release/examples/local-preview-fixture" \
  --helper-sha256 VERIFIED_HELPER_SHA256 --interactive-ui
```

The candidate is copied into a root-owned mode-0755 `bin/` in the new temporary
instance; the installed launchd job continues using its existing executable.
Candidate permissions are set explicitly even under umask 0077. Native UI errors
identify initial connection/capabilities, config, executable lookup, installation
validation, service preflight, process hardening, notification creation/response,
and post-prompt connection/unlock stages. Actual framework errors and unexpected
button responses cannot masquerade as human cancellation. Only explicit Unlock
releases input. The human separately confirmed one installed-binary window was
visible and manually cancelled; the full temporary-key UI EINVAL remains pending
until rerun, and this independent cancel check is not full UI acceptance.

For a failure before the first native window, use `--ui-preflight-only` with the
digest-pinned candidate, omitting `--signing-helper` and `--interactive-ui`.
It creates only empty temporary state, checks administrator status, then runs
native unlock for a nonexistent temporary key. Click Cancel if a window appears;
never enter a password. It does not exercise key unlock/signing and is diagnostic
only. Socket errors identify timeout option setup, read, write or flush without
logging frame data, and whole-frame deadlines remain unchanged.

Operator follow-up at `f2be478`: the short empty-instance UI preflight passed
administrator authentication and returned a cancellation response on macOS.
The earlier EINVAL after the full signing sequence was not reproduced in that
short context. This does not establish a fix or full temporary-key UI acceptance;
the three-stage interactive command remains required with the same candidate.


## Latest full host result and installing the accepted candidate

The operator completed the **full interactive** command using candidate SHA-256
`453f5aa6bf6c8f6e74cd0f8e2199ef0e775864fdbec8e924b564da4a2a12b7ee`.
Every non-UI check passed again. Cancel and the 120-second timeout left the real
temporary key locked; the operator confirmed exact target details and masked
input, entered the public test password, and Agent signing succeeded. Subsequent
SIGKILL/restart and fake-socket checks also passed. These results supersede older
pending-UI notes above. Formal release and whole-machine reboot remain untested.
The earlier initial-capabilities EINVAL did not recur; its root cause remains
unknown and is not claimed fixed. No retry/downgrade bypass was added.

The temporary candidate does not automatically replace the installed executable.
Review a local update plan, then apply explicitly:

```sh
/usr/bin/python3 deploy/macos/update-local.py --binary target/release/anpio-key \
  --sha256 453f5aa6bf6c8f6e74cd0f8e2199ef0e775864fdbec8e924b564da4a2a12b7ee
# Same arguments with sudo and --apply to install the accepted build.
```

The updater verifies root-owned paths and the digest-checked release, stops the
known launchd job, requires clean socket removal and the exclusive state lock,
retains `bin/anpio-key.previous`, atomically replaces the executable and restarts
with unchanged configuration/state/accounts. It verifies the installed digest,
instance identity and status. Restart revokes grants and locks keys. Existing
backup files are refused rather than overwritten. Errors leave artifacts/state
for inspection; there is no automatic rollback, schema downgrade, or state reset.
The default plan changes no system files or service state.


## Accepted build activated on the local host

The operator applied the updater successfully. Independent read-only checks
confirmed the installed SHA-256 matches the accepted `453f5aa6...12b7ee` build
and `bin/anpio-key.previous` retains the original
`41e39c6c9ff955422cb285bb8311f4d413157f908e54357eb3582cada595e4b9` build.
The instance remains `80a37601-db74-44b6-8a17-d3ea5ad9a7ef`; status is OK,
`boot_epoch=2`, and audit projection and transaction executor are healthy.
Configuration/state were preserved; no real keys were migrated.

U2 is complete for the operator's selected local-use preview scope.
`protected_supported=false` remains unchanged. Formal distribution and
whole-machine reboot acceptance remain separate; the earlier intermittent
EINVAL remains an observation with unknown root cause. Only Agents actually
running under the independent Agent UID receive this isolation boundary.


## One-command preview bootstrap (implementation and acceptance, 2026-10-19)

`install.sh --bootstrap` now works on macOS in addition to Linux. On macOS it
runs `deploy/macos/setup-local.sh` and then `deploy/macos/bootstrap.py`, which
uses the same fixed order as the Linux path: generate a disposable did:wba
identity under `/var/root`, create a daily hot key, stop the launchd job, migrate
the identity offline through `deploy/macos/migrate-vault.py`, restart the job,
enroll the vault, confirm root/hot roles, publish a narrow policy, create one
grant and unlock the hot key. It is fixed to `_anpagent` and `--hardware none`,
refuses a configuration that already has vaults, and keeps management commands
under the administrator UID via `sudo -n -u`; passphrases are still read only by
Anpio Key from the human terminal.

Verified in this change: 12 pure policy/command-construction unit tests
(`deploy/macos/test_bootstrap.py`), the Python syntax check and `bash -n
install.sh`.

The interactive flow was then run end to end on this Mac on 2026-10-19. The
existing empty-state preview installation was first archived intact to
`/private/var/root/anpio-key-reinstall-20261019-211724` (binary, config, launchd
plist and state); the dedicated `_anpio`/`_anpagent` accounts and their groups
were kept. Because `provision-accounts.py` deliberately refuses to adopt existing
accounts, the rerun invoked `deploy/macos/install.py`, `launchctl bootstrap` and
`deploy/macos/bootstrap.py` directly instead of `setup-local.sh`; account
creation was not re-exercised. The installed binary was the rebuilt
`c57ff641f29ecf90d3d2d62ba46d2d5e5f85c75cfd61558f638ab19a457bebde`.

The run completed in 18 seconds with all five passphrase-bearing commands driven
through a PTY (keygen, publish, rotate-hot-key, migration verification twice, and
unlock); no prompt timed out. Independent checks with the installed binary
reported `signing_available=true`, `protected_supported=false`, `boot_epoch=2`
and a healthy audit projection; `catalog` showed the active vault
`fe6cc2d5-4d1a-402f-8332-823fea8e6b34`, one confirmed `root` and one confirmed
`hot` key, and the published policy; `service.json` recorded the same vault id.
The grant id was `b46aaf01d316c3150f3277382cdb1d6852f3d7d8b5ac981f8367cc192bf716a8`.
Recovery material is under
`/private/var/root/anpio-key-recovery-20261019-132014`.

The acceptance exposed and this change fixes three real defects:

- a fresh install did not create `/Library/ANPIOKey/state/vaults` (now created,
  with a layout unit test in `test_install.py`);
- migration rejected `/var/root` because `/var` is a symlink, so the bootstrap
  staging root is now `/private/var/root`;
- `admin unlock` aborted with `EINTR` while changing terminal echo under a
  PTY/sudo wrapper; `src/tty.rs` now retries `tcgetattr`/`tcsetattr` on `EINTR`
  instead of reporting a transient signal as a broken terminal.

Scope: this was an empty installation, not a machine with no dedicated accounts.
A literal fresh-host run of `install.sh --bootstrap` still requires removing and
recreating `_anpio`, `_anpagent`, `_anpio_sign` and `_anpio_admin`; that
destructive step was not performed here and remains noted in `TODO.md`. This is
preview convenience only and does not change the macOS protection claim.


