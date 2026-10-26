# Independent checkpoint collection

Run `collector.py` on a separate trusted host or protected execution/storage domain.
The service UID and Agents must not be able to modify this collector, its SSH key,
pinned host keys, config or evidence directory. The source daemon and host OS/admin
remain trusted; this detects rollback of source-side evidence, not a lying daemon
or a compromised keeper/admin. The source never receives the keeper database.

The signing core does not connect to the network. An independently authenticated
SSH fixed command invokes `anpio-key audit-source` to validate the complete SQLite
chain and the keeper's retained prefix in one read transaction. The keeper binds
instance ID, SSH destination, identity and host-key material at initial enrollment.
It rejects source changes, malformed responses, conflicting/lower positions and
responses not tied to its previous checkpoint. No SSH config, agent, TOFU,
password prompts, user commands, forwarding or automatic host-key updates apply.

## Source host

Install the current binary root-owned with protected ancestors. Keep the existing
service UID and state directory mode 0700. Do not grant the observer or Agents
read access to that directory. Create a dedicated `keyd-observer` SSH account
with `/bin/sh` and public-key authentication only; the daemon UID can retain its
`nologin` shell. Install the root-owned fixed wrapper in
`source-command.sh.example`, substituting the trusted instance ID and paths.
Install/validate the exact no-argument rule from `source-sudoers.example` with
`visudo -cf`; it only permits the fixed wrapper as the daemon UID.

Place the collector public key (no private key) in the root-owned authorized-keys
path, prefixed with `restrict`. Apply the `Match User` block from
`source-sshd.conf.example` and validate with `sshd -t` before reloading. Keep
`PermitUserRC no`; a caller-controlled SSH rc file must not run before the forced
command. Verify the account cannot obtain a shell, override arguments, forward
ports or read files directly. This endpoint is only for the trusted collector;
it does not add a new Agent capability.

## Keeper host

Python 3.9+ with SQLite 3.37+ and OpenSSH client at `/usr/bin/ssh` are required.
Use a dedicated `keyd-checkpoint` UID. Install `collector.py` root-owned at
`/usr/local/libexec/keyd-checkpoint-collector.py`. Set up a private, local-filesystem
`/var/lib/keyd-checkpoint-collector` owned by the keeper UID, mode 0700. Generate a
dedicated Ed25519 SSH key there as that UID with mode 0600. Authenticate the
source's Ed25519 host-key fingerprint through trusted provisioning; install its
known_hosts entry root-owned (non-default ports require `[host]:port`). Do not
bootstrap trust by accepting an unauthenticated `ssh-keyscan` result.

Install a config based on `config.json.example` root-owned, readable by the keeper
(e.g. group keeper, mode 0640). All ancestors must be symlink-free and owned by
root or the keeper, with no group/other writes. The identity itself must belong
to the keeper with mode 0600. The configured `max_age_seconds` is an observation
alert threshold, not a limit enforced by the signing daemon.

Explicitly enroll once, as the keeper UID, after verifying the source/instance:

```sh
python3 /usr/local/libexec/keyd-checkpoint-collector.py enroll \
  --config /etc/keyd-checkpoint-collector/config.json \
  --store /var/lib/keyd-checkpoint-collector
```

Then run `collect` with the same arguments, or install the included systemd
service/timer on the keeper host. The timer polls every minute; configure the
age threshold to cover your expected cadence and transport deadline. Units are
templates, not an installer or a security attestation. They do not auto-enroll.
Inspect service failures and the collector's JSON output with your monitoring.
`status` reports retained evidence without contacting the source; exit 2 means
missing observation/deadline exceeded, exit 1 is an unavailable/invalid store or
clock. Collection failures exit 1. Successful late collection reports
`observation_deadline_missed=true`; it must not erase the monitoring gap.

## Commit and failure behavior

The keeper acquires `BEGIN IMMEDIATE` before fetching. A concurrent collector
fails within SQLite's 500 ms lease wait without starting another source request.
The source response is bounded to 4096 bytes; the configured wall deadline kills
a stalled SSH client. Each new tip is inserted as an immutable history row and
the latest pointer/last-success observation is updated in the same transaction
with DELETE journal and synchronous EXTRA. Only a committed result is reported
as retained. Equal tips refresh the observation, without duplicating history.

A crash before commit recovers the previous checkpoint; a crash after commit
recovers the new one. Retrying uses whichever checkpoint actually committed.
Failed enrollment may leave an explicit pending store: repeating `enroll` is
allowed only while no checkpoint has committed. An empty/unknown/corrupt store
is a maintenance failure, never automatically replaced. Missing stores require
explicit enrollment; the periodic service always uses `collect`, so deletion
cannot trigger a new trust root. Back up the keeper store through a consistent
SQLite backup or while stopped, preserving ownership and permissions.

On network/authentication/validation/storage failure, retain old evidence and
report failure. The signing daemon continues its existing durable local audit
policy. There is no promise to bound unobserved events or to stop signing after
an outage: status explicitly reports `unobserved_tail=unknown`. Age measures the
last successful observation, not a signature on every intervening operation.
A collector wall-clock regression is rejected; correct its trusted clock before
retrying, never reset evidence. Changing source/key material requires a reviewed
migration retaining old history; this implementation fails closed instead of
silently migrating or re-enrolling.

## Validation

```sh
python3 -m unittest discover -s deploy/checkpoints -p test_collector.py -v
python3 deploy/checkpoints/acceptance.py --cargo-cache anpio-key-m3-cargo
```

The second command builds current Rust code and installs sshd only inside two
uniquely named disposable containers. It uses separate filesystems/UIDs, pinned
real SSH, source rollback, network loss and reconnect. The optional cache is
mounted read-only. All created containers/networks are removed even on failure.
No runtime identities, writable checkout, Docker socket or host services are
mounted. A shared Docker host/admin remains trusted: container acceptance is not
an assertion of physical-host or administrator independence.
