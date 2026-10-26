# Secure Enclave foreground login helper

This bridge lets a trusted human login process perform the hardware portion of
unlocking one approved hot key while the existing separate-UID daemon continues
to own its vault, passphrase KDF, in-memory signing key, policy and grants.
It implements the operator's accepted login-dependent scope. It is not an
accepted formal SE distribution. `protected_supported=false` remains unchanged.

## Trust and protocol

The administrator UID, daemon, root-owned code/configuration and OS are trusted.
Agents must stay in separate non-admin UIDs. Neither a different Unix UID nor a
fresh SessionCreate audit session is a demonstrated keychain boundary for code
carrying this helper's trusted signature and access group. Production SE seal/open
also enforce the current local graphical-login identity in software. This policy
is separate from raw keychain authorization. The helper runs as the configured
administrator in the active local graphical login session. A second service
account or a system LaunchDaemon cannot substitute for that login context.

A one-shot system LaunchDaemon was used to test the reverse direction on
2026-10-19: the same signed probe running as `_anpagent` (UID 601), both in a raw
non-login job and with `SessionCreate`, could not reach any keychain
(`errSecNotAvailable`, `-25291`), while the login-session positive control and
the post-delete refusal passed. The accepted deployment constraint is therefore:

- Agents and any process that must not hold SE capability run as root-owned
  system LaunchDaemons in a non-login audit session.
- Code started inside the administrator's graphical login session, including
  through `sudo`, is trusted management input. An arbitrary process under a
  different UID in that inherited session can still open the keychain item; that
  counterexample stands and is not called UID isolation.

Details: [validation record](../../docs/validation/macos-se-system-context-2026-10-19.md).

Unrestricted code in the human UID remains part of the trusted management
principal; a native dialog is not an independent authorization boundary.

The helper opens no listener. It connects to the existing management socket,
authenticates its inode and kernel service UID and validates the daemon instance.
The daemon checks the helper's kernel UID against `admin_uids` before reading a
frame, then obtains the audit-session ID from `LOCAL_PEERTOKEN`. It requires a
local, graphical, non-root audit session and the matching primary console UID.
Root/system, remote and inactive-console sessions are refused. A signed binary
or claimed UID/session in a message cannot replace these checks.

The native prompt shows the exact vault/DID/kid and global session-end effects.
It has the existing Cancel/default and 120-second timeout, with no terminal
fallback. After consent, one authenticated persistent connection carries:

1. `START_SE_SESSION` with exact vault/DID/kid. The daemon accepts only an active
   catalog-confirmed hot key with an SE envelope; root/recovery/v1/software keys
   are refused. It returns its own validated encrypted envelope snapshot and a
   random session ID. No supplied path or caller-selected ECDH input is accepted.
2. The helper validates the envelope and calls SE locally. It sends the 32-byte
   HS in a fixed binary frame, followed by the existing bounded binary password
   frame. Neither is JSON, argv, environment, stdout, audit or persistent state.
   The helper holds no DEK, seed or `device.secret`. The daemon never returns HS.
3. The daemon performs the password/device/HS KDF and authenticated decryption,
   checks the resulting public key, and rechecks the exact envelope, mutation
   epoch, vault generation and live login context before installing the key.
   A concurrent lock or management mutation cancels installation.
4. The helper erases its HS/password containers and sends strictly sequenced,
   session-bound heartbeats once per second. It never reconnects automatically.

Hardware still performs P-256 ECDH wrapping/unwrapping. Business Ed25519 signing
runs in daemon software. HS necessarily crosses the authenticated local stream;
the trusted administrator and daemon can observe their own process memory.
This is not hardware-internal Ed25519 signing or protection against root/admin.

## Session lifetime and loss

Only one exact-key SE session is admitted at a time. The initial lease lasts at
most 900 seconds, using both an absolute wall deadline and continuous monotonic
time that includes macOS sleep. Heartbeats cannot move either deadline. A missing
heartbeat for 5 seconds, clock rollback relative to the last heartbeat, EOF,
invalid heartbeat, observed console-session change, unavailable console/audit
information or an unhealthy observer ends the lease.

The daemon observes console-user changes with SystemConfiguration notifications;
an observed logout/switch invalidates the old lease even if the same UID logs in
again. It also checks the current primary console UID and original audit session
directly. Observer failure/staleness refuses signing. OS notification dispatch is
asynchronous; this is detection-driven locking, not an instantaneous logout
barrier or a proof that no bytes could be in flight at the transition.

Session validity is checked before data execution, before a new signature and
before delivery of new or cached results. The signing coordinator remains held
through bounded data-frame delivery, so acknowledged teardown/revocation cannot
overtake a queued signature frame. Previously delivered signatures cannot be
recalled. The sweeper checks idle sessions once per second; heartbeat reads have
a 5-second deadline. On observed loss the daemon conservatively:

- Locks **all** loaded keys and cancels in-flight unlock installation.
- Transactionally revokes **all active and exhausted grants**, suppressing even
  the cached last-use result. Request IDs, quota use and tombstones remain.
- Advances the management mutation epoch, invalidating all prepared approvals.
- Persists `SE_SESSION_ENDED` audit evidence before continuing management/data.

Audit or cleanup failure latches emergency stop. There is no automatic software
fallback, quota refund, reconnect, grant issuance or restoration. A fresh session
requires a fresh unlock; a grant revoked by the old session requires a new
explicit approval. Existing per-key idle autolock remains in force and heartbeats
do not refresh it.

A long sleep expires the heartbeat on wake; the original 900-second deadlines
also continue across sleep. Screen lock alone is not promised to revoke all
already loaded keys: OS keychain restrictions may deny new unsealing, while an
existing live lease can continue signing until a loss condition or original
deadline. Fast user switching ends the old lease on observation. User switch,
logout/relogin, sleep, whole-machine reboot and helper upgrade have been
exercised against temporary fixtures; physical Secure Enclave failure has not.
Raw keychain isolation between UIDs is not established (see below).

## Build and controlled use

Both helper and daemon must contain the bridge:

```sh
cargo build --locked --release --features mcp,hardware-se
```

`se-release.py` turns that executable into the helper bundle once the operator
has a real Apple-issued identity and provisioning profile. `plan` is the default
and changes nothing:

```sh
python3 deploy/macos/se-release.py plan --team-id TEAMID --application-id TEAMID.org.example.keyd
python3 deploy/macos/se-release.py build --team-id TEAMID \
  --application-id TEAMID.org.example.keyd --identity 'Developer ID Application: ...' \
  --profile /path/to/helper.provisionprofile
python3 deploy/macos/se-release.py verify --bundle target/se-release/ANPIOKey.app \
  --team-id TEAMID --application-id TEAMID.org.example.keyd --require-notarized
sudo python3 deploy/macos/se-release.py install --bundle target/se-release/ANPIOKey.app \
  --team-id TEAMID --application-id TEAMID.org.example.keyd --upgrade
```

`build` signs with hardened runtime and a timestamp, embeds the exact
provisioning profile and verifies the resulting bundle before reporting success.
`install` requires root, refuses an existing destination without `--upgrade`,
checks the Team/application identity and designated-requirement continuity, and
replaces the root-owned bundle atomically. No step claims hardware or
distribution acceptance.

Do not add `seed-export` or `hardware-software`. Run the signed helper from an
app-like bundle containing its authorized provisioning profile; use a narrow,
exact application/keychain group identity. Review the signed bytes with
`se-preflight.py --execution-context user-session`. Exit 0 of that tool is only
a signature prerequisite check, not profile/hardware/distribution acceptance.
The bundle and every installed executable/config ancestor must be root-owned,
non-writable by the Agent/human, with the existing no-symlink/no-extra-ACL policy.
The daemon remains a system service and never accesses the login keychain itself.

The current daily installation is not automatically updated. The existing update
tool refuses an occupied backup path; do not delete that backup just to proceed.
Review/archive it and approve the exact new binary digest as part of a controlled
update. Do not migrate real keys during initial acceptance.

After signed packaging, temporary SE hot-key provisioning and catalog approval,
run the installed helper from the human's local login session, using the approved
bundle executable path:

```sh
/ROOT_OWNED_BUNDLE/Contents/MacOS/anpio-key admin \
  --config /Library/ANPIOKey/service.json se-session \
  --vault-id TEMPORARY_VAULT_UUID --did TEMPORARY_DID --kid EXACT_TEMPORARY_HOT_KID
```

The command opens the native prompt and stays in the foreground after unlock.
Closing its terminal/process ends the session. Approve a narrowly scoped grant
through the existing management workflow in a separate terminal. There is no
LaunchAgent auto-start or unattended passphrase storage in this initial version.

The cross-process persistence probe is a separate test example, not the helper
binary and not a release command. Use a dedicated temporary keychain group.
Its raw `open` intentionally bypasses the application's login policy; do not
distribute this signed test capability with access to real production wrapping
keys. `open-checked` exercises the software policy separately.

```sh
cargo build --locked --release --features mcp,hardware-se,se-acceptance \
  --example se-persistence
sha256sum target/release/examples/se-persistence
python3 deploy/macos/se-release.py sign-example --team-id TEAMID \
  --application-id TEAMID.org.example.keyd \
  --identity 'Developer ID Application: ...' \
  --binary target/release/examples/se-persistence \
  --sha256 VERIFIED_UNSIGNED_EXAMPLE_SHA256 \
  --out target/se-release/se-persistence.signed
python3 deploy/macos/acceptance/se-persistence.py \
  --binary target/se-release/se-persistence.signed \
  --sha256 VERIFIED_SIGNED_EXAMPLE_SHA256 --team-id TEAMID \
  --application-id TEAMID.org.example.keyd \
  --other-uid 501 \
  --unsigned-binary target/release/examples/se-persistence \
  --unsigned-sha256 VERIFIED_UNSIGNED_EXAMPLE_SHA256
```

Run this from the login user's own terminal, never through `sudo`: root has no
login data protection keychain. `--other-uid` makes sudo run only the denial
probe as that second user, so the sudo prompt may appear once. On macOS the
`keychain-access-groups` authorization depends on the signing and distribution
context. Do not assume a development-signed bare example can run without a
matching provisioning profile. `sign-example --profile` validates profile
metadata but does not embed or install it. If AMFI reports `No matching profile
found`, stop and provision a matching development app/profile before hardware
acceptance. A successful signature preflight does not prove runtime admission.

It creates a persistent SE key in process A, reopens it in a new process B,
tests whether another UID is denied, deletes the key and checks that the old
envelope no longer opens. Raw other-UID access has succeeded on the test host;
the harness reports that as failed isolation acceptance. The `open-checked`
mode labels application-policy refusal separately. The `--unsigned-binary` phase checks that a build
without the entitlement cannot create a persistent key; an unsigned build is
expected to fail with `errSecMissingEntitlement` (`-34018`). Passing this tool
does not prove logout/relogin, sleep, reboot, upgrade or distribution.

The non-login launchd context has its own probe. It requires the current signed
example (one that reports `SE_CONTEXT`) inside an app bundle with its embedded
profile, and root through `sudo` for the system phase:

```sh
python3 deploy/macos/acceptance/se-system-context.py \
  --binary target/se-release/SESystemContext.app/Contents/MacOS/se-persistence \
  --sha256 VERIFIED_SIGNED_EXAMPLE_SHA256 --team-id TEAMID \
  --application-id TEAMID.org.example.keyd --session-create
```

It creates and opens a temporary key in the login session as the positive
control, runs one-shot system jobs as `_anpagent` (raw and `SessionCreate`),
deletes the key and checks the old envelope. A start in the login session is
mandatory; the tool refuses to create the key as root.

## Verification boundaries

Ordinary regressions cover HS/password/device binding, envelope tampering,
concurrent lock cancellation, ordered non-renewable leases, socket disconnect,
observed login generation changes, cached exhausted-grant suppression and atomic
audit failure. They do not prove real SE persistence or OS lifecycle handling.

Two explicit tests require a real local graphical console and are ignored by
normal/headless CI. Run only against temporary fixtures:

```sh
cargo test --locked --features mcp,hardware-se --lib \
  security::se_session::tests::local_console_observer_and_kernel_audit_session_are_available \
  -- --ignored --exact --nocapture
cargo test --locked --features mcp,hardware-se --lib \
  persistence::tests::local_console_se_bridge_signs_and_disconnect_revokes_without_hardware_mock_claims \
  -- --ignored --exact --nocapture
```

The second uses synthetic HS, not a persistent SE key. It exercises real kernel
session/console checks, the management stream, KDF, upstream-verified hot-key
signing and changed-target rejection, then actual disconnect/lock/revocation and
cached-result suppression. Passing it is bridge evidence, not hardware evidence.

The following have been exercised with the development-signed helper and a
separate-UID service against temporary SE keys: persistent create/open in
independent processes; forged daemon rejection; UI cancel/timeout; helper
crash and hang; user switch; logout/relogin; short and long sleep; whole-machine
reboot; helper upgrade; missing-key recovery; signing-identity change; and
keychain permission change. Each run recorded exact hashes, feature flags,
profile/team/application identity and failures separately.

Still open before any formal protection claim:

- **Raw keychain isolation between UIDs failed inside a login context.** A probe
  carrying the same signature and access group re-derived HS under the Agent UID,
  including in a fresh SessionCreate audit session. A non-login system launchd
  job was tested separately on 2026-10-19 and is refused by the data protection
  keychain; the deployment constraint above relies on that tested refusal, not
  on UID-based isolation. The software login-identity policy is not a substitute
  for an OS keychain boundary; the in-session counterexample stands.
- **Physical Secure Enclave or device failure was not induced.** Only the
  software-visible refusal paths were observed: the probe reports the root
  unusable when a persistent key cannot be created, and a deleted key yields
  "no key with that label".
- **Formal distribution is unaccepted.** The test helper uses a short-lived
  Apple Development identity/profile. Developer ID signing, notarization and a
  long-lived deployment identity remain outstanding.
- Screen lock revokes nothing by itself; the lease and deadline rules above are
  the actual behavior.

Certificate/profile setup and interactive lifecycle transitions require the
operator.

References: [Apple TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains),
[primary console information](https://developer.apple.com/documentation/systemconfiguration/scdynamicstorecopyconsoleuser(_:_:_:)).
