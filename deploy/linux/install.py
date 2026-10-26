#!/usr/bin/env python3
"""Install a NEW Linux signing boundary. Never migrate or overwrite an existing vault."""
import argparse
import grp
import hashlib
import importlib.util
import tempfile
import fcntl
import socket
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import uuid

SERVICE = "anpio-key"
AGENTS = "anpio-key-agent"
ADMINS = "anpio-key-admin"
CONFIG = Path("/etc/anpio-key/service.json")
STATE = Path("/var/lib/anpio-key")
BINARY = Path("/usr/local/libexec/anpio-key")
SYSTEMD = Path("/etc/systemd/system/anpio-key.service")
TPM_DROPIN = Path("/etc/systemd/system/anpio-key.service.d/10-tpm.conf")


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TPM_DEVICE = load('tpm_device', 'tpm-device.py')


def run(*args):
    subprocess.run(args, check=True)


def trusted_parent(path):
    for parent in [path, *path.parents]:
        if parent.exists() or parent.is_symlink():
            stat = parent.lstat()
            if parent.is_symlink() or stat.st_uid != 0 or stat.st_mode & 0o022:
                raise RuntimeError(f"untrusted installation path: {parent}")
            if not parent.is_dir():
                raise RuntimeError(f"not an installation directory: {parent}")


def directory(path, uid=0, gid=0, mode=0o755):
    path.mkdir(parents=True, exist_ok=True)
    os.chown(path, uid, gid)
    path.chmod(mode)


def write(path, content):
    # Only new files in root-owned directories, never follow an existing symlink.
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
    os.fchmod(fd, 0o644)
    with os.fdopen(fd, "w") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def verified_binary(args):
    if not args.sha256 or len(args.sha256) != 64:
        raise RuntimeError('installation/update requires administrator-verified --sha256')
    with args.binary.open('rb') as stream:
        content = stream.read(128 * 1024 * 1024 + 1)
    if len(content) > 128 * 1024 * 1024 or hashlib.sha256(content).hexdigest() != args.sha256.lower():
        raise RuntimeError('binary digest mismatch or size exceeds bound')
    # Execute exactly the digest-checked bytes from a private root-owned location.
    with tempfile.TemporaryDirectory(prefix='keyd-build-check-') as temp:
        candidate = Path(temp) / 'anpio-key'
        candidate.write_bytes(content)
        candidate.chmod(0o700)
        info = json.loads(subprocess.check_output([str(candidate), 'build-info'], timeout=10))
    if info['hardware_software'] or info['seed_export'] or (not info['release'] and not args.allow_development_build):
        raise RuntimeError('installer requires a release build without software test double or seed export')
    return content, info


def update(args):
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise RuntimeError('update requires Linux root')
    trusted_parent(CONFIG.parent)
    trusted_parent(BINARY.parent)
    if CONFIG.is_symlink() or BINARY.is_symlink():
        raise RuntimeError('linked managed deployment')
    for path in (CONFIG, BINARY):
        meta = path.lstat()
        if not path.is_file() or meta.st_uid != 0 or meta.st_nlink != 1 or meta.st_mode & 0o022:
            raise RuntimeError('untrusted managed deployment')
    config = json.loads(CONFIG.read_text())
    content, build_info = verified_binary(args)
    # No implicit restart, downgrade of configuration, or replacement of state.
    for endpoint in (config['sign_socket'], config['admin_socket']):
        with socket.socket(socket.AF_UNIX) as connection:
            try:
                connection.connect(endpoint)
            except (FileNotFoundError, ConnectionRefusedError):
                continue
            raise RuntimeError('stop service before updating')
    from importlib.util import spec_from_file_location, module_from_spec
    spec = spec_from_file_location('keyd_migration_paths', Path(__file__).with_name('migrate-vault.py'))
    paths = module_from_spec(spec)
    spec.loader.exec_module(paths)
    paths.trusted(Path(config['state_dir']), owners=(0, config['service_uid']))
    lock_path = Path(config['state_dir']) / 'service.lock'
    fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
    with os.fdopen(fd, 'r+b') as lock:
        meta = os.fstat(lock.fileno())
        if meta.st_uid != config['service_uid'] or meta.st_nlink != 1 or meta.st_mode & 0o777 != 0o600:
            raise RuntimeError('untrusted service lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        paths.atomic(BINARY, content, 0o755)
    print('Verified binary replaced while offline; state/config retained. Review schema compatibility before restart.')


def install(args):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("installation requires Linux root")
    if CONFIG.exists() or CONFIG.is_symlink() or STATE.exists() or STATE.is_symlink() or BINARY.exists() or BINARY.is_symlink():
        raise RuntimeError("existing installation/state detected; refusing overwrite or implicit migration")
    for path in [CONFIG.parent, STATE.parent, BINARY.parent, Path('/etc/systemd/system'), Path('/etc/tmpfiles.d'), Path('/run/anpio-key')]:
        trusted_parent(path)
    tpm = None
    if args.tpm_device:
        # Validate the device before creating any account, group or file: a
        # failed deployment must not leave half a TPM grant behind.
        tpm = TPM_DEVICE.report(args.tpm_device)
        trusted_parent(TPM_DROPIN.parent)
    for path in [Path('/etc/tmpfiles.d/anpio-key.conf'), SYSTEMD]:
        if path.exists() or path.is_symlink():
            raise RuntimeError(f"existing deployment file: {path}")
    if tpm and (TPM_DROPIN.exists() or TPM_DROPIN.is_symlink()):
        raise RuntimeError(f"existing deployment file: {TPM_DROPIN}")
    admins = [pwd.getpwnam(name) for name in args.admin_user]
    agents = [pwd.getpwnam(name) for name in args.agent_user]
    admin_uids = {p.pw_uid for p in admins}
    agent_uids = {p.pw_uid for p in agents}
    if len(agent_uids) != len(agents) or len(admin_uids) != len(admins) or 0 in agent_uids or admin_uids & agent_uids:
        raise RuntimeError("administrators and distinct Agent UIDs must not overlap")
    content, build_info = verified_binary(args)
    if tpm and not build_info.get("hardware_tpm"):
        raise RuntimeError("--tpm-device requires a build compiled with the hardware-tpm feature")
    for name in [SERVICE, AGENTS, ADMINS]:
        try:
            grp.getgrnam(name)
        except KeyError:
            pass
        else:
            raise RuntimeError(f"pre-existing group {name}; refusing to inherit membership")
    try:
        pwd.getpwnam(SERVICE)
    except KeyError:
        pass
    else:
        raise RuntimeError("pre-existing service account; refusing to inherit access")
    source = args.binary.resolve(strict=True)
    if not source.is_file() or not os.access(source, os.X_OK):
        raise RuntimeError("binary must be an executable regular file")
    for name in [AGENTS, ADMINS]:
        run("groupadd", "--system", name)
    run("useradd", "--system", "--user-group", "--home-dir", str(STATE), "--no-create-home", "--shell", "/usr/sbin/nologin", SERVICE)
    run("usermod", "-a", "-G", f"{AGENTS},{ADMINS}", SERVICE)
    if tpm and tpm['group'] not in (AGENTS, ADMINS):
        run("usermod", "-a", "-G", tpm['group'], SERVICE)
    for user in agents:
        run("usermod", "-a", "-G", AGENTS, user.pw_name)
    for user in admins:
        run("usermod", "-a", "-G", ADMINS, user.pw_name)
    service = pwd.getpwnam(SERVICE)
    agent_gid = grp.getgrnam(AGENTS).gr_gid
    admin_gid = grp.getgrnam(ADMINS).gr_gid
    directory(CONFIG.parent)
    directory(Path("/etc/tmpfiles.d"))
    directory(Path("/etc/systemd/system"))
    directory(BINARY.parent)
    directory(STATE, service.pw_uid, service.pw_gid, 0o700)
    directory(STATE / "vaults", service.pw_uid, service.pw_gid, 0o700)
    directory(Path('/run/anpio-key'))
    directory(Path('/run/anpio-key/sign'), service.pw_uid, agent_gid, 0o750)
    directory(Path('/run/anpio-key/admin'), service.pw_uid, admin_gid, 0o750)
    fd = os.open(BINARY, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o755)
    os.fchmod(fd, 0o755)
    with os.fdopen(fd, 'wb') as dest:
        dest.write(content)
        os.fsync(dest.fileno())
    config = {
        "schema_version": 1, "mode": "linux-protected-v1" if build_info["protected_supported"] else "linux-boundary-preview", "instance_id": str(uuid.uuid4()),
        "service_uid": service.pw_uid, "admin_uids": sorted(admin_uids),
        "agent_gid": agent_gid, "admin_gid": admin_gid, "state_dir": str(STATE),
        "sign_socket": "/run/anpio-key/sign/sign.sock", "admin_socket": "/run/anpio-key/admin/admin.sock",
        "principals": [{"principal_id": str(uuid.uuid4()), "uid": p.pw_uid, "generation": 1, "enabled": True} for p in agents],
        "vault_ids": [],
    }
    write(CONFIG, json.dumps(config, indent=2) + "\n")
    write(Path('/etc/tmpfiles.d/anpio-key.conf'),
          f"d /run/anpio-key 0755 root root -\nd /run/anpio-key/sign 0750 {SERVICE} {AGENTS} -\nd /run/anpio-key/admin 0750 {SERVICE} {ADMINS} -\n")
    write(Path('/etc/systemd/system/anpio-key.service'), Path(__file__).with_name('anpio-key.service').read_text())
    def service_identity():
        os.initgroups(SERVICE, service.pw_gid)
        os.setgid(service.pw_gid)
        os.setuid(service.pw_uid)
    if tpm:
        groups = set(os.getgrouplist(SERVICE, service.pw_gid))
        if tpm['gid'] not in groups:
            raise RuntimeError(f"service account did not receive group {tpm['group']!r}")
        # A group entry is not access: open the device exactly the way the
        # daemon will, before the unit is enabled.
        opened = subprocess.run(
            [sys.executable, '-I', '-c',
             'import os, sys; os.close(os.open(sys.argv[1], os.O_RDWR))', tpm['path']],
            preexec_fn=service_identity, capture_output=True, text=True)
        if opened.returncode:
            raise RuntimeError(
                f"service user cannot open {tpm['path']}: "
                f"{(opened.stderr or opened.stdout).strip()}")
        supplementary = [AGENTS, ADMINS]
        if tpm['group'] not in supplementary:
            supplementary.append(tpm['group'])
        template = Path(__file__).with_name('anpio-key-tpm.conf.in').read_text()
        rendered = (template.replace('@TPM_DEVICE@', tpm['path'])
                    .replace('@SUPPLEMENTARY_GROUPS@', ' '.join(supplementary)))
        directory(TPM_DROPIN.parent)
        write(TPM_DROPIN, rendered)
    subprocess.run([str(BINARY), 'init-protected-state', '--config', str(CONFIG)], preexec_fn=service_identity, check=True)
    print(f"Installed v2 transaction signer; mode: {config['mode']}. Migration requires the separate offline tool.")
    if tpm:
        print(f"TPM device {tpm['path']} granted through {TPM_DROPIN} (group {tpm['group']}).")
        print("Run the separate physical-TPM acceptance before claiming hardware protection.")
    print("Review config, then run: systemctl daemon-reload && systemctl enable --now anpio-key")
    print("Agents/admins need fresh login sessions for group membership. Keep Agents away from sudo, Docker and admin IPC.")


def uninstall():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("uninstallation requires Linux root")
    trusted_parent(CONFIG.parent)
    if not CONFIG.is_file() or CONFIG.is_symlink():
        raise RuntimeError("managed configuration missing")
    trusted_parent(BINARY.parent)
    # Fail if an active service cannot be stopped. Never remove identity/state.
    run("systemctl", "disable", "--now", "anpio-key.service")
    for path in [Path('/etc/systemd/system/anpio-key.service'), Path('/etc/tmpfiles.d/anpio-key.conf'), BINARY]:
        if path.is_symlink():
            raise RuntimeError(f"unexpected symlink: {path}")
        path.unlink()
    if TPM_DROPIN.exists() or TPM_DROPIN.is_symlink():
        if TPM_DROPIN.is_symlink():
            raise RuntimeError(f"unexpected symlink: {TPM_DROPIN}")
        TPM_DROPIN.unlink()
        try:
            TPM_DROPIN.parent.rmdir()
        except OSError:
            pass
    run("systemctl", "daemon-reload")
    print("Service/binary removed. Config, state, accounts and groups retained to prevent UID reuse or identity loss.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--admin-user", action="append", default=[])
    parser.add_argument("--agent-user", action="append", default=[])
    parser.add_argument("--uninstall", action="store_true")
    parser.add_argument("--update", action="store_true")
    parser.add_argument("--sha256")
    parser.add_argument("--allow-development-build", action="store_true", help="explicit preview testing only")
    parser.add_argument("--tpm-device", nargs="?", const="/dev/tpmrm0", default=None,
                        help="grant the service access to this TPM 2.0 resource-manager device "
                             "(default /dev/tpmrm0); requires a hardware-tpm build")
    args = parser.parse_args()
    try:
        if args.uninstall and args.update:
            parser.error('choose uninstall or update')
        if (args.uninstall or args.update) and args.tpm_device:
            parser.error('--tpm-device applies only to a new installation')
        if args.update:
            if not args.binary:
                parser.error('--update requires --binary and --sha256')
            update(args)
        elif args.uninstall:
            uninstall()
        elif args.binary and args.admin_user and args.agent_user:
            install(args)
        else:
            parser.error("new installation requires --binary, --admin-user and --agent-user")
    except (RuntimeError, KeyError, OSError, subprocess.CalledProcessError,
            TPM_DEVICE.DeviceError) as error:
        sys.exit(str(error))
