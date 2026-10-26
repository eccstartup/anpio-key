# TPM root: deployment and acceptance

This page separates three setups that are easy to conflate:

| Setup | What it proves | What it does not prove |
|---|---|---|
| Software envelope, no `--hardware` | The v2 transaction format and service boundary work | The disk copy plus passphrase still opens the key |
| `swtpm` / `mssim` emulator (`TPM2TOOLS_TCTI=swtpm:...`) | The TPM code path, persistence and failure handling | Any physical device, firmware or owner-hierarchy property |
| `/dev/tpmrm0` on bare metal | The device the deployment actually uses | Physical protection until the physical checks below pass |

An `swtpm` run is not physical acceptance evidence. `tpm-acceptance.py` classifies
the transport and refuses `--attest-physical-hardware` unless it sees a kernel
device, a non-virtual TPM driver and `systemd-detect-virt` reporting `none`.

## Installation

From the repository root, one command builds with the TPM backend and installs
with an explicit device grant:

```sh
./install.sh --tpm-device
```

To create the identity, policy, grant and first unlock in the same run, add the
bootstrap options; both the binding key and the hot key are generated with the
TPM backend:

```sh
./install.sh --tpm-device --bootstrap --did-host agents.example.com \
  --target https://api.example.com/v1/status
```

Use `--tpm-device /dev/tpmrm0` to name the device explicitly. The manual
reviewed-release path is:

```sh
cargo build --locked --release --features hardware-tpm
sha256sum target/release/anpio-key
sudo python3 deploy/linux/install.py --binary target/release/anpio-key \
  --sha256 VERIFIED_SHA256 --admin-user operator --agent-user agent-a \
  --tpm-device
```

`--tpm-device` defaults to `/dev/tpmrm0`; `--tpm-device /dev/tpmrm0` is the same
thing. The installer:

- validates the device before creating accounts or files: character device, no
  symlink, TPM 2.0 sysfs entry, no access for users outside its group;
- adds the service account to the device group (normally `tss`);
- opens the device as the service account before enabling the unit;
- writes `/etc/systemd/system/anpio-key.service.d/10-tpm.conf` with
  `PrivateDevices=no`, `DevicePolicy=closed`, `DeviceAllow=/dev/tpmrm0 rw`,
  the service's supplementary groups, and an explicit
  `TPM2TOOLS_TCTI=device:/dev/tpmrm0`.

The drop-in is deliberately narrow: turning off `PrivateDevices` would otherwise
expose the whole of `/dev`. `DevicePolicy=closed` plus the single allow entry is
what keeps the rest out. The unit still has `ProtectSystem=strict`,
`CapabilityBoundingSet=`, `NoNewPrivileges=yes` and no network families.

If the service was already installed without the TPM grant, uninstall and
reinstall; the installer refuses to repair or overwrite an existing deployment.

## Acceptance

The cross-process probe is a test tool, not a release command. Build it with the
acceptance feature enabled and keep it out of the installed binary:

```sh
cargo build --locked --release --features hardware-tpm,tpm-acceptance \
  --example tpm-persistence
sha256sum target/release/examples/tpm-persistence
sudo python3 deploy/linux/acceptance/tpm-acceptance.py \
  --binary target/release/examples/tpm-persistence \
  --sha256 VERIFIED_SHA256 \
  --other-uid 1001 \
  --attest-physical-hardware \
  --out /root/tpm-acceptance.json
```

`--other-uid` must name a non-root account outside the TPM device group. Without
it the tool still runs, but `cross_uid_denial` stays `null` and
`acceptance_scope_complete` stays `false`.

The tool checks, in order:

1. device facts from `/dev` and `/sys/class/tpm`;
2. the service account's group membership and a real `O_RDWR` open;
3. `tpm-persistence probe` (seal, persist, unseal, evict) as the service UID;
4. create in process A, open in a new process B;
5. a copied state file opened by the second UID must fail at the device;
6. delete the persistent object, then the old envelope must fail;
7. the effective systemd properties and, when running, the service's groups.

A passing run sets `passed` and, with every optional check,
`acceptance_scope_complete`. `physical_tpm_acceptance_complete` additionally
requires `--attest-physical-hardware`. The tool never sets
`hardware_acceptance_complete` or `protected_supported`.

Deployment acceptance covers the device grant, the systemd sandbox, the service
UID opening the device, cross-process seal/open, cross-UID denial, and refusal
after deletion. It has been exercised with `swtpm` exposed through the kernel's
`tpm_vtpm_proxy`, so the device under test is a kernel `/dev/tpmrm0` character
device rather than a TPM socket. Such a report records `virtualization=docker`,
`virtual_device_hint=true`, `acceptance_scope_complete=true`, and both physical
and protected flags false.

Not covered, and therefore still required for a physical protection claim:

- logout/relogin and user switching;
- sleep/wake and wall-clock rollback;
- whole-machine reboot;
- upgrade with the same device and owner hierarchy;
- TPM unavailable, cleared owner hierarchy, key loss and recovery;
- copying an envelope to a second machine (needs a second physical TPM);
- distribution review of the TPM protection claim.

## Failure and recovery

- `does not have` / `HardwareMissing`: the persistent object is gone. A TPM
  sealed object is bound to the chip that made it, so a copied envelope cannot
  open elsewhere. The supported way to move a key is `export-seed` on the
  machine that still has it.
- `could not open a TPM session`: the device is missing or unreadable by the
  service UID. Check `systemctl show anpio-key -p DeviceAllow -p Environment`,
  the device group, and `dmesg | grep -i tpm`.
- Probe says the owner hierarchy cannot persist: check non-volatile space and
  owner auth. This build uses the well-known empty owner auth; a device with a
  non-empty owner hierarchy is not supported by this build.
- Never clear or replace the persistent object to "fix" an envelope. That
  silently makes the existing envelope unopenable.
