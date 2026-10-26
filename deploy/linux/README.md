# Linux v2 deployment

Start with the [local-use guide](../LOCAL-USE.md) for the trust model and daily
administrator/Agent workflow. This page describes the Linux service. Ordinary
use does not require Apple membership, Xcode, SE or TPM.

A release build without seed export or software hardware, explicitly deployed as
`linux-protected-v1`, reports `protected_supported=true`. This is a support
declaration, not proof that every new machine is configured safely. Physical TPM
protection is a separate claim; see [TPM.md](TPM.md).

Layout: this directory holds the install, update and migration entry points.
Root-only, container and boot acceptance tools live in [`acceptance/`](acceptance/);
CI unit tests live in [`tests/`](tests/). Normal use needs neither.

## New installation

Use a human-controlled checkout and a separate non-admin Agent account for each
security principal. The human must review code/build provenance. From the
repository root, one command installs the service, creates a fresh identity,
migrates it into protected state, publishes a policy, creates one grant and
unlocks the hot key:

```sh
./install.sh --bootstrap --did-host agents.example.com \
  --target https://api.example.com/v1/status
```

The operator enters every passphrase at the terminal; the binary reads it from
the controlling tty, never from argv, environment, stdin or the Agent.

To install only the empty service and finish identity and authorization
manually, run `./install.sh` without `--bootstrap` and follow
[LOCAL-USE.md](../LOCAL-USE.md). Choose accounts or grant a TPM device
explicitly:

```sh
./install.sh --admin-user operator --agent-user agent-a --agent-user agent-b
./install.sh --tpm-device
```

With `--bootstrap`, add `--method` (repeatable, default `GET`), `--body-bytes`,
`--grant-days` and `--max-uses` to shape the policy and grant. Multiple
`--agent-user` values share the service; bootstrap issues the first grant to the
first account.

Inspect the plan without changing the host:

```sh
./install.sh --dry-run
```

`--features mcp` is included by default; a CLI-only build needs the manual
procedure below. For a TPM root, `--tpm-device` selects the `hardware-tpm`
feature; the installer grants only `/dev/tpmrm0` and pins the transport. Run the
separate acceptance in [TPM.md](TPM.md) before claiming hardware protection.

The installer creates its own non-login service account, socket groups,
root-owned executable/configuration, SQLite state and systemd unit. It refuses
partial or existing installations rather than silently repairing or replacing
them. Without `--bootstrap` it does not migrate user keys; use the offline
migration procedure below for existing installations. Establish fresh sessions
after group changes.

Agents must have no sudo/admin rights, Docker/host-control sockets, administrator
credentials, or access to administrator processes. The entire Agent must run under
its assigned UID, not just its signing subprocess. `cargo install` plus legacy
`serve` is a development workflow and does not establish this boundary.

## Manual installation with a reviewed release

Use this path when an administrator must independently verify the digest before
any root write:

```sh
cargo build --locked --release --features mcp
sha256sum target/release/anpio-key
sudo python3 deploy/linux/install.py --binary target/release/anpio-key \
  --sha256 VERIFIED_SHA256 --admin-user operator --agent-user agent-a --agent-user agent-b
sudo systemctl daemon-reload
sudo systemctl enable --now anpio-key
/usr/local/libexec/anpio-key admin --config /etc/anpio-key/service.json status
/usr/local/libexec/anpio-key probe --security --config /etc/anpio-key/service.json
```

## Acceptance on your own installation

First use a temporary identity and narrow grant, independently verify a real
signature, check that another Agent cannot use the grant/result or administer the
service, revoke the grant, and confirm that restart locks keys and invalidates old
authority. Run destructive fault and systemd sandbox tests only in an explicitly
marked disposable VM/container, never against daily state. The container harness
creates disposable accounts and is not a general host installation test:

```sh
docker run --rm -v "$PWD:/src:ro" -w /src rust:1.90-bookworm \
  bash deploy/linux/acceptance/test-container.sh
```

This harness requires dependencies/network or a separately mounted Cargo cache.
It does not by itself accept the systemd sandbox, physical power loss or TPM.
Keep actual host acceptance separate from unit tests, container results and build
capability flags. TPM grants and acceptance are covered in [TPM.md](TPM.md); an
`swtpm` result is emulator evidence, not physical acceptance.

## Management and release behavior

v2 signs through durable reservation/result transactions and exact hot-key
grants. Restart revokes all old grants and locks keys.

`build-info.protected_supported` describes Linux release build capability (no
software test double or seed export). Daemon replies and `probe --security` require
that capability AND root configuration `mode: "linux-protected-v1"`. Fresh release
installs select that explicit mode; development installs remain preview. Offline
updates preserve the existing mode: upgrading an old preview deployment requires
an explicit administrator config edit while stopped. The flag is a support
declaration, not continuous attestation of arbitrary host configuration.

Release binaries cannot enable `hardware-software`; the compiler rejects that
combination. `build-info` reports build mode and sensitive feature flags. Install
and update require a SHA-256 supplied from an independently verified build:

```sh
cargo build --locked --release
sha256sum target/release/anpio-key
sudo python3 deploy/linux/install.py --binary target/release/anpio-key \
  --sha256 VERIFIED_SHA256 --admin-user operator --agent-user agent-a --agent-user agent-b
# Stop the service before update. The tool also requires the exclusive state lock.
sudo python3 deploy/linux/install.py --update --binary target/release/anpio-key --sha256 VERIFIED_SHA256
```

`--allow-development-build` is an explicit testing opt-in; software test doubles
and seed-export builds are rejected even with this flag. Updates never overwrite
configuration/state or restart implicitly. Keep a compatible previous binary and
verified state backup; a schema downgrade must remain offline rather than enable v1.

### Renaming an installation made under the old name

Deployments created before the rename use the `anp-keyd`, `anp-keyd-agent` and
`anp-keyd-admin` accounts plus `/etc/anp-keyd`, `/var/lib/anp-keyd` and
`/run/anp-keyd`. Stop the service and move them once:

```sh
sudo systemctl disable --now anp-keyd.service
sudo usermod -l anpio-key anp-keyd
sudo groupmod -n anpio-key anp-keyd
sudo groupmod -n anpio-key-agent anp-keyd-agent
sudo groupmod -n anpio-key-admin anp-keyd-admin
sudo mv /var/lib/anp-keyd /var/lib/anpio-key
sudo mv /etc/anp-keyd /etc/anpio-key
sudo mv /etc/tmpfiles.d/anp-keyd.conf /etc/tmpfiles.d/anpio-key.conf
# Rewrite every /anp-keyd path inside /etc/anpio-key/service.json, then:
sudo python3 deploy/linux/install.py --update --binary target/release/anpio-key --sha256 VERIFIED_SHA256
```

Renaming users and groups keeps their numeric IDs, so file and socket ownership
survive. `install.py` re-creates `/run/anpio-key`, the unit and the tmpfiles entry
under the new names. Review the plan; an incomplete or already-renamed tree is
refused rather than half-converted. Restart locks keys and revokes grants.

### Offline migration and restore

Stop all legacy daemons and lifecycle writers, including versions that predate the
maintenance lock. Move the complete source into a root-owned directory with a
root-controlled parent chain, take ownership of all files, and restrict secrets
to 0600/directories to 0700. Do not leave another Agent-readable live source copy.
Then run the read-only inventory and the explicit cutover:

```sh
sudo python3 deploy/linux/migrate-vault.py --source /root/frozen-vault
sudo python3 deploy/linux/migrate-vault.py --source /root/frozen-vault --apply --recovery-dir /root/keyd-recovery
```

The tool preserves encrypted envelopes, device.secret, public documents and audit
history, checks hashes, and opens every backup key through the operator's tty.
It copies only necessary recovery material, never runtime sockets/PIDs or plaintext
keys. Root remains responsible for stopping older processes and open FDs before
freezing the source. New legacy writers hold shared maintenance leases; cutover
requires the exclusive lease. Source gets a managed marker and remains root-owned.

`migration.json` records the exact inventory/vault/instance and durable cutover
phase. Re-run the same arguments after interruption. Partial backup/staging copies
resume only from matching completed files; uncommitted private temporary files are
discarded. Unknown completed bytes are preserved and refused for administrator
inspection. Never discard the source or recovery copy. Completed copies must match
the original manifest; unknown bytes stop the tool. Crashes between catalog/config
changes cannot create grants: only root config introduces the UUID, and startup
registers it with audit in one SQLite recovery transaction. Restart always
invalidates grants.

After restart: prepare/commit `Catalog.EnrollVault`, confirm roles explicitly,
publish policy, unlock the exact hot key, issue a fresh grant, verify a real
service, then switch clients to v2. Every imported key starts locked and
unclassified. Restoring a recovery copy is the same migration process with its
`vault/` as the source and a fresh recovery directory/UUID. Do not restore old
grants or overwrite an active vault. Coordinate current remotely published
documents before issuing grants: local restore cannot roll back a remote
publication.

The complete software snapshot plus its password can unlock keys; the recovery
copy is sensitive. Hardware envelopes require their actual backend/device and
fail closed when unavailable. Portable per-key archives remain readable through
the existing offline import flow; import into an administrator-owned staging
vault and then migrate. Historical plaintext exports/copies are not revoked.

### Client and service validation

`adapters/anpio-key-v2.mjs` provides a Node client and an existing anp-sdk connector.
The Rust CLI performs service authentication, callers persist request IDs, and
there is no automatic retry/downgrade. Production fetch uses the canonical signed
URL, original body, daemon headers and manual redirects.

Registration: prepare a `RegistrationChallenge` with the exact root key, HTTPS
origin and the supported 32-character lowercase hex challenge. Confirm its digest,
then `admin complete-secret-operation --operation-id ID --digest DIGEST`; the root
is transient and never becomes a data key. Runtime uses hot grants. `RotateHotKey`
selects an already provisioned next hot key, removes the old method, signs the new
document, revokes grants and journals file recovery. Independently publish and
verify the returned document before making fresh grants. New hot material can be
provisioned in an offline administrator staging vault; online generation is
outside this first migration/rotation tool.

The disposable multi-UID harness exercises the actual migrator. Optionally set
`ANPIO_KEY_ANP_TARGET` to a throwaway awiki-open-server physical origin configured
with `public_base_url=https://example.com`, `did_domain=example.com` and strict
signed-document verification. `anp-service-acceptance.py` verifies registration,
hot authentication, replay/body/expiry rejection and published hot rotation.
Only this test can send a logical HTTPS target over a separate physical local
HTTP route; the production adapter does not offer that override.

The host harness is deliberately destructive and only accepts an isolated VM
whose PID 1 is systemd and whose root-owned mode-0600
`/var/lib/keyd-systemd-disposable` contains
`anpio-key-disposable-systemd-v1`. With the temporary fixture generated by
`security_boundary::disposable_linux_fixture` copied under `/tmp`, run as root:

```sh
python3 deploy/linux/acceptance/test-boundary.py --systemd --binary /path/to/release/anpio-key
python3 deploy/linux/acceptance/systemd-boot-check.py prepare
# Completely shut down and boot this disposable VM, then:
python3 deploy/linux/acceptance/systemd-boot-check.py verify
```

The harness checks actual sandbox effects using a temporary ExecStartPost hook,
then removes that hook and restores the exact pre-fault test database before
checking boot with the original unit. It must never run on a production host.
