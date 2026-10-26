# Complete Claude Code process under the Agent UID

This is the macOS UID boundary preview (`protected_supported=false`). The first
supported integration target is a disposable local HTTPS receiver. Claude Code
2.1.173 is exercised as the complete framework, including its Bash/tool child.
A deterministic loopback Messages API drives the tool call; it performs no model
inference and uses no human model credential. This does not accept a live model
provider, arbitrary plugin set, remote business service, or real identity.

For a fresh disposable preview, `./install.sh --bootstrap` now creates the
identity, migrates it, publishes a policy, issues one grant and unlocks the hot
key automatically. This document remains the procedure for the complete
framework, existing-identity cutover and real keys.

## Temporary acceptance, human terminal

Build `anpio-key` with `cargo build --locked --release --features mcp` and the public
fixture with `cargo build --locked --release --example local-preview-fixture`.
Resolve the installed Claude symlink to its standalone binary, review provenance
and SHA-256 for all three executables, then run from a trusted reviewed checkout:

```sh
sudo bash deploy/macos/acceptance/check-agent.sh \
  /ABS/target/release/anpio-key CANDIDATE_SHA256 \
  /ABS/target/release/examples/local-preview-fixture HELPER_SHA256 \
  /ABS/claude/versions/2.1.173 CLAUDE_SHA256
```

Only the human enters sudo locally. This reuses existing accounts and creates
isolated `/Library/ANPIOKeyChecks-*` state. It does not change the daily binary,
keys, launchd job, account records, or model authentication. The default run does
not exercise the native dialog. The optional seventh argument `--interactive-ui`
explicitly runs all three windows: Cancel, an untouched 120-second timeout, then
masked input. Do not record a default run as UI acceptance.

The driver pins and copies executable bytes into a new root-owned directory.
Its disposable source is installed by the supported offline migrator, with
backup recovery for every key, resume and tampered-backup rejection. Management
prepare/commit enrolls the vault, confirms roles, and creates an exact hot-key,
principal, origin/path/method, five-minute/20-use policy and bounded grant.

Claude's entire process and tool child use the registered Agent UID, dedicated
0700 HOME/workspace/tmp and only primary/signing groups. The environment contains
no inherited human auth, SSH agent, Docker endpoint or library injection. No
human HOME, plugins, skills, hooks or project settings are loaded. The actual
HTTPS receiver reconstructs the target from its listening authority and observed
path and independently verifies the upstream signature under the administrator
UID. It rejects signature replay. Checks include stable request IDs, status
lookup, unknown IDs, conflicting payloads, target denial, cross-principal denial,
revocation and no second HTTP send after revocation. Restart/crash and forged
socket checks run as well.

When explicitly requested, the native UI steps require Cancel, an untouched 120-second timeout, then the
public fixture password `temporary-boundary-test-secret`. Confirm exact
instance/vault/DID/key and masked input locally. Never enter a real password in
this fixture. No log is sufficient to replace visual confirmation.

## Existing identity: administrator cutover

First pass the temporary exercise. Inventory the identity's origin, remotely
published active DID document and key roles. Use only a source containing the
complete encrypted envelopes, device.secret and verified public documents; do
not generate replacement keys or change its DID to make import pass. Every
required hot key must already be authorized in that document. Recovery may
require the original hardware/device; software backup does not remove that need.

Stop all legacy writers and the installed launchd job in the human terminal.
Move/freeze the source under a root-controlled APFS parent with ownership enabled,
no extended ACLs, directories 0700 and secret files 0600. Preserve it, stop old
processes/open FDs, and review the source before running:

```sh
sudo /usr/bin/python3 deploy/macos/migrate-vault.py --source /PRIVATE/FROZEN_SOURCE
sudo /usr/bin/python3 deploy/macos/migrate-vault.py --source /PRIVATE/FROZEN_SOURCE \
  --apply --recovery-dir /PRIVATE/NEW_RECOVERY
```

Dry-run is read-only. Apply requires the service lock and no live sockets. It
creates a recovery copy, verifies each key via the human tty and resumes from a
journal on interruption. Unknown backup/target bytes are preserved and refused.
Use the same arguments to resume. Never remove recovery/source to clear an error.
A separate restore uses `RECOVERY/vault` as source, a fresh recovery location and
a fresh vault UUID; it never overwrites an active vault or restores old grants.

Restart the service explicitly. Use `admin prepare --file` and `admin commit`
for `Catalog.EnrollVault`; every key begins unclassified and locked. Inspect
`admin catalog`, confirm root/recovery/hot roles, publish a narrow policy, then
approve a fresh grant bound to the configured principal and exact hot key.
Unlock through `admin unlock --native-ui`. Do not copy files into managed state,
reuse database active flags, use root/recovery as ordinary hot keys, or bypass
management with legacy lifecycle commands. Coordinate remote document publication
before client cutover. The whole software recovery copy plus its password can
permit offline decryption; preserve it under administrator control.

## Daily framework launch

Use `launch-agent.py` to drop the entire framework process to the configured UID.
Unix UID isolation is not a promise that a program carrying the helper's trusted
signing identity and keychain group cannot use the human's SE wrapping key.
Stage the reviewed standalone framework binary root-owned outside Agent-writable
paths. Prepare a dedicated Agent-owned 0700 HOME, workspace and HOME/tmp beneath
root/Agent-controlled, non-shared parents. Review shared directories, all readable
credentials, network paths and framework extensions separately; this launcher is
not a filesystem/network sandbox or proof against every host escape.

```sh
sudo /usr/bin/python3 deploy/macos/launch-agent.py --uid AGENT_UID \
  --home /PRIVATE/AGENT_HOME --workspace /PRIVATE/AGENT_WORKSPACE \
  --binary /ROOT_OWNED/claude --sha256 REVIEWED_SHA256 -- --bare
```

The launcher rejects disabled/ambiguous principals, root/service/admin UIDs,
privileged/management memberships, sudo rights, symlinks, ACLs and shared writable
paths. It drops supplementary shared groups and closes extra descriptors. Give a
live provider only an explicitly scoped Agent credential configured in the
Agent's dedicated account; do not copy a human login token or pass it via this
launcher. Actual live-provider authentication and real-identity cutover require
separate operator execution and evidence.
