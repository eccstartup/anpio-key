# Historical Linux implementation notes

These are preserved stage records. Statements that systemd acceptance or protected
release support is still pending describe earlier baselines, not the current
software release. Follow [the current deployment guide](README.md). Physical TPM
acceptance remains separate.

# Linux v2 signing service and release gate

Linux v2 provides limited grants and durable signing. Protected release support
remains false pending actual systemd-host acceptance. The legacy `serve` command
is a separate development service. See the M5 section below for current migration,
client and update workflows; earlier command examples require `--sha256` too.

Build on Linux, then install a **new** instance as root:

```sh
cargo build --locked --release
sudo python3 deploy/linux/install.py --binary target/release/anpio-key \
  --admin-user operator --agent-user agent-a --agent-user agent-b
sudo systemctl daemon-reload
sudo systemctl enable --now anpio-key
anpio-key admin status
anpio-key probe --security
```

The installer refuses existing state, accounts, groups or deployment files. It
does not migrate keys. It creates a non-login service account, separate socket
groups/directories, root-owned config/binary and a systemd sandbox. Administrators
and Agents need fresh sessions after their groups change. Agents must have distinct
UIDs, no sudo, Docker/host-control socket or access to administrator processes.
The runtime does not infer this isolation from executable names or TTYs.

`admin status`, `admin lock-all` and `admin unlock --vault-id UUID --did DID --kid KID`
use the independent admin endpoint. Unlock is only usable for vaults explicitly
staged by an administrator and listed in the root-owned bootstrap config; managed
migration is available through the offline tool below. Unlock prompts only after a service preflight, and
re-authenticates the next connection before sending the password. There is no
`--socket`, password argument or password environment override on this path.

`probe --security` prints observed ownership, modes, registry identities and the
kernel-authenticated service identity. It returns nonzero because full protected
release support remains unavailable. macOS refuses this mode explicitly.

Deployment configuration changes require restart. The installer explicitly initializes
`state.sqlite` once as the service UID; startup refuses a missing, corrupt, linked,
foreign-instance or newer-schema database. Bootstrap principals are imported only
at initialization. Editing bootstrap flags cannot restore disabled identities.

List live/history principal metadata and prepare an exact management operation:

```sh
anpio-key admin list-principals
anpio-key admin prepare-disable-principal --principal-id UUID
anpio-key admin commit --operation-id UUID --digest SHA256
anpio-key admin prepare-register-principal --uid UID
```

Inspect the returned effect and digest before committing. Commit accepts only the
stored operation, bound to the same admin UID, boot epoch, mutation epoch, wall
expiry and suspend-aware monotonic deadline. It is single use. Disable applies to
new connections immediately and revokes existing active grants in the same SQLite
transaction. Reassigning a disabled OS UID creates a new principal UUID/generation.

SQLite uses rollback journal DELETE, synchronous EXTRA, foreign keys and strict
schema checks. Audit/state changes commit together. Restart increments boot epoch,
revokes active grants, marks reserved requests outcome_unknown, invalidates pending
approvals and leaves all keys locked. Audit write failure latches emergency stop;
a restart is required after repair. These tables/recovery rules are implemented,
and grants/signing now execute through the v2 transaction coordinator.

M2 adds `admin catalog` and typed `admin prepare --file CHANGE.json` operations.
The supported catalog actions are `EnrollVault`, `ConfirmRole`, `PublishPolicy`
and `InstallDocument`, wrapped as `{"kind":"Catalog","change":{...}}`.
Prepare returns the exact effect/digest; use the existing `admin commit` with that
operation ID and digest. Only authenticated administrators can access this API.

An administrator must first stage an existing vault under a configured UUID while
the service is stopped, preserving its encrypted envelopes/device secret and
protected ownership. `EnrollVault` validates the complete inventory against signed
DID documents and records every key as `unclassified`. `ConfirmRole` binds an
explicit role to exact kid, envelope and document digests. It checks the public key
and relationships; an identity binding key cannot be marked hot/recovery/challenge.
Re-enrollment revokes grants, preserves key handles and resets roles for confirmation.
The automated old-vault copy/backup/cutover workflow remains M5.

For example, prepare vault enrollment with this public JSON file:

```json
{"kind":"Catalog","change":{"action":"EnrollVault","vault_id":"VAULT_UUID"}}
```

Then inspect `admin catalog` and prepare role confirmation:

```json
{"kind":"Catalog","change":{"action":"ConfirmRole","key_id":"KEY_UUID","role":"root"}}
```

`PublishPolicy` accepts a UUID, consecutive positive version and fixed-schema
policy content (schema 1). Content is canonicalized and immutable; unknown fields,
ambiguous origins/paths/queries and unsupported profiles are rejected. This stores
policy versions used by the current request/grant evaluator.

`InstallDocument` accepts a vault UUID and an already signed public DID document.
It verifies the proof/path binding and existing key roles, binds the previous and
new document digests, and journals the exact approved bytes in SQLite. It provides
no caller-supplied signing-input operation. The commit first enters maintenance and
revokes grants, then atomically installs/fsyncs the document and records completion.
Restart rolls a durable intent forward only if the file matches the approved old
or new digest; an unknown file stops startup without overwriting it. Catalog-only
changes and audit records are atomic; interrupted file completion remains in
maintenance until recovery succeeds. Broader identity creation/rotation/backup
adapters remain subsequent lifecycle work.

KDF runs in a separate non-queueing single slot. Lock/metadata commit invalidates
older unlocks by generation; key installation rechecks catalog/disk state under
the management gate. Old local CLI commands (including `--root` symlinks, relative
paths and standalone probe) reject managed state directories. They remain available
for development vaults. No Agent gains access to protected vault files.

Schema 1 upgrades transactionally to schema 2 after integrity, instance and audit
validation; failed migration rolls back. Existing roles reset to unclassified.
Unknown newer versions are refused. New management events use SQLite; existing
JSONL files are retained without rewriting. Runtime state is not silently imported
from old M1 preview configurations.
For a NEW empty deployment only, explicit initialization is also available as
`anpio-key init-protected-state` under the configured service UID. Never use deletion
and reinitialization as a migration or repair procedure.

The dependency is pinned to rusqlite 0.39.0 without default features, using bundled
SQLite (libsqlite3-sys 0.37.0, SQLite 3.51.3 in this lockfile). See the
[upstream source](https://github.com/rusqlite/rusqlite). This is not a full dependency
vulnerability audit.

To remove the service/binary, use `sudo python3 deploy/linux/install.py --uninstall`.
State, configuration and accounts are retained intentionally. Remove those only
through a separately reviewed backup/retirement procedure.

For isolated acceptance testing (never run the script on a daily-use host):

```sh
docker run --rm -v "$PWD:/src:ro" -w /src rust:1.90-bookworm \
  bash deploy/linux/test-container.sh
```

The harness requires a root Linux container and creates only disposable accounts
and files. It builds into `/tmp`, never into the read-only checkout. Tests include
cross-UID admin rejection through a PTY, v1/password rejection on the data socket,
service impersonation, unsafe path rejection, and lock/shutdown behavior. A running
container test does not verify the systemd sandbox; systemd host acceptance remains
an independent release gate.

## M1 baseline verification recorded on 2026-10-16

Linux Docker (Rust 1.90): 431 default tests passed, the explicit disposable fixture
passed, and all 33 multi-UID boundary checks passed. The installer was tested with
umask 0077. macOS: 444 tests passed with `mcp,hardware-software`. Clippy completed
with the existing unused import warning in `tests/hardware.rs`. New Rust modules
pass rustfmt; the repository-wide formatting baseline still has older differences.
No real user identities or host accounts were modified. The systemd unit has not
been accepted on a booted systemd host, and no production protected-mode support
is claimed.

## M2 persistence verification recorded on 2026-10-16

Rust 1.88 and 1.90 Linux Docker: each passed 438 default tests, one explicitly
requested disposable identity fixture, and all 49 boundary/persistence checks.
macOS (`mcp,hardware-software`): 451 tests passed. Seven persistence tests cover
restart invalidation, preserved quota consumption, unknown outcomes, audit failure
rollback, actor/digest/epoch binding, UID generation replacement, and deadline or
payload substitution rejection. The container also injects audit insertion failure
to verify emergency stop, and refuses missing/newer/corrupt/linked databases.

rusqlite 0.39.0 is pinned to preserve the tested Rust 1.88 baseline; future dependency
updates must pass both toolchain jobs. Clippy completed with the existing hardware
test import warning at that baseline. No physical power-loss test or systemd host
acceptance was claimed for that baseline.

## Historical M2 completion verification on 2026-10-16

Rust 1.88 and 1.90 Linux containers each passed 452 default tests, one explicit
disposable identity fixture and 60 multi-UID boundary/management checks. macOS
`mcp,hardware-software` passed 465 tests. Eighteen persistence tests include actual
old/new signed-document replacement with injected completion-audit failure, durable
intent before the first file write, repeated restart recovery, journal substitution
rejection, migration rollback, unknown roles and policy immutability. Strict
all-targets Clippy passed; the prior hardware import warning's feature guard is
corrected. These are deterministic crash-boundary tests, not physical power-loss
experiments. At that checkpoint M3/M4 was still pending; the current executor is implemented, while systemd-host acceptance remains open.

## Historical M3 authorization preview verification on 2026-10-16

Rust 1.88 and 1.90 disposable Linux containers each passed 467 default tests and
one explicit temporary-identity fixture. Their independent-UID harnesses passed
85 and 89 checks respectively; the 1.90 run also builds MCP and verifies real
stdio initialization, v2 tool schemas, caller-scoped keys and no legacy fallback.
Set `ANPIO_KEY_TEST_MCP=1` to include those MCP checks in the container harness.
macOS `mcp,hardware-software` passed 481 tests; strict all-targets Clippy passed.

At the M3 checkpoint, the implementation added exact-hot-key grants, revocation, immutable policy evaluation, dual-clock
deadlines, schema v3 and authenticated v2 CLI/MCP clients. Valid `SIGN_HTTP`
requests then returned `SIGNING_UNAVAILABLE`; M4 subsequently supplied transactional quota
reservation, idempotency, signing and durable result delivery.
At that historical checkpoint `protected_supported` remained false. The later M5 systemd-host acceptance below supersedes that release status.

## Strong-integration P1-P5 container acceptance recorded on 2026-10-26

Scope: the three-layer interface in `docs/ADAPTER.md` §11 (`anpio_key::client`, the
v2 socket, CLI `--json`) against a real daemon, a real socket and independent UIDs.
This run answers whether the daemon side of P1-P5 works on Linux. It does not
accept the systemd host sandbox, physical TPM/SE, release artifacts, or the client
half of P1-P5, which lives in the awiki and anpio-cli repositories.

Baseline `6227350` plus this working tree's `test-boundary.py` and `docs/ADAPTER.md`
§7.5. Environment: Docker 29.5.2 (colima), `rust:1.90-bookworm`, Ubuntu 24.04.4,
container mode (not systemd), `--allow-development-build`; the harness creates four
disposable UIDs and installs the service itself. Re-run with:

```sh
docker run --rm -v "$PWD:/src:ro" -w /src rust:1.90-bookworm \
  bash deploy/linux/acceptance/test-container.sh
```

One run, exit code 0: 3 migration/recovery checks; `cargo test --locked` 597 passed,
0 failed, 1 ignored by design (physical hardware) — 514 lib tests, the disposable
fixture, 41 multi-UID boundary checks, and the remaining integration targets;
`acceptance/test-boundary.py` reported `{"passed": 190, "protected_supported":
false, "systemd": false}`. `protected_supported=false` is expected here: the
container built a development binary and made no protected-mode declaration, so the
Linux release gate still requires a release build on a declared deployment.

Twenty of those 190 checks are new and cover P5 on the same daemon and socket:
both proof paths are `OPERATION_DISABLED` and absent from capabilities until their
own switch is on; enabling origin and purpose signing does not enable them; an
object-proof policy cannot declare a purpose that path cannot produce and a
document-proof policy only takes W3C proof purposes; the document-proof grant is
refused for any key that is not the root. Both paths then return the input with the
proof folded in, in the published multibase base58btc alphabet, naming the key the
grant chose, timestamped by the daemon (a caller-supplied `created` is not a field).
Replay returns the identical result without a second use, a changed payload is
`REQUEST_ID_CONFLICT`, another principal is `GRANT_INVALID`, and a document whose
`id` names another DID is `PROOF_INVALID` with `used_uses` unchanged — the binding
check really does run before quota. The audit chain carries one switch line per
path, the proof shape and the input digest, and neither body.

Not accepted by this run: systemd host sandbox and `systemd-checks.py` (container
mode skips them), the Linux release build and its protected-mode declaration,
physical TPM, all of macOS (frozen this cycle), and the awiki-cli-rs2 / anpio-cli
adapters — those remain the P1-P5 收尾 items in `TODO.md`.


