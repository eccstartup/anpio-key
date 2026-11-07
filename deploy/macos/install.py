#!/usr/bin/env python3
"""Fresh local-preview installation, never account creation or automatic startup.
Run without --apply to inspect the exact plan. Accounts/groups must already exist.
Updates/migration are deliberately refused; existing state is never overwritten.
--uninstall stops the launchd job and removes the binary and plist, but keeps
configuration, state and accounts so an uninstall cannot destroy an identity.

Installation only installs the service: no identity is created, no passphrase is
collected and no grant is issued. A fresh install presets one empty vault so the
first `anpio-cli did create --key anpio-key` has somewhere to live.
"""
import argparse
import ctypes
import errno
import grp
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import stat
import subprocess
import sys
import time
import uuid

BASE = Path('/Library/ANPIOKey')
CONFIG = BASE / 'service.json'
BINARY = BASE / 'bin/anpio-key'
PLIST = Path('/Library/LaunchDaemons/org.anpio-key.local.plist')
SOCKETS = (BASE / 'sign/sign.sock', BASE / 'admin/admin.sock')
LABEL = 'org.anpio-key.local'
# Data-plane switches a freshly created identity is expected to use. Explicit
# values in an existing service.json are never overwritten.
DEFAULT_FEATURES = {
    'sign_document_proof': True,
    'sign_origin_proof': True,
    'sign_purpose': {'device_assertion': True, 'application_assertion': False},
    'ecdh': True,
}


def check_chain(path):
    """Fail closed on symlinks, writable ancestors and extended macOS ACLs."""
    for part in [*reversed(path.parents), path]:
        meta = part.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
            raise ValueError(f'untrusted installation ancestor: {part}')
        if sys.platform == 'darwin':
            libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
            libc.acl_get_file.argtypes = [ctypes.c_char_p, ctypes.c_int]
            libc.acl_get_file.restype = ctypes.c_void_p
            libc.acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
            libc.acl_free.argtypes = [ctypes.c_void_p]
            acl = libc.acl_get_file(os.fsencode(part), 0x100)
            if not acl:
                if ctypes.get_errno() == errno.ENOENT:
                    part.lstat()
                    continue
                raise ValueError(f'cannot inspect ACL: {part}')
            entry = ctypes.c_void_p()
            status = libc.acl_get_entry(acl, 0, ctypes.byref(entry))
            error = ctypes.get_errno()
            libc.acl_free(acl)
            if status != -1 or error != errno.EINVAL:
                raise ValueError(f'extended ACL on installation ancestor: {part}')


def memberships(user):
    return set(os.getgrouplist(user.pw_name, user.pw_gid))


def configuration(service, admin, agents, sign_group, admin_group):
    users = [service, admin, *agents]
    if any(u.pw_uid in (0, 2**32-1) for u in users) or len({u.pw_uid for u in users}) != len(users):
        raise ValueError('service, administrator and each Agent need distinct non-root UIDs')
    if sign_group.gr_gid == admin_group.gr_gid or min(sign_group.gr_gid, admin_group.gr_gid) <= 0:
        raise ValueError('separate non-root socket groups required')
    forbidden = {0, grp.getgrnam('admin').gr_gid}
    for user in [service, *agents]:
        if memberships(user) & forbidden or (user in agents and admin_group.gr_gid in memberships(user)):
            raise ValueError(f'{user.pw_name} must not belong to wheel/admin or management group')
    if not {sign_group.gr_gid, admin_group.gr_gid} <= memberships(service):
        raise ValueError('service needs both socket groups to assign socket ownership')
    for user in agents:
        if sign_group.gr_gid not in memberships(user):
            raise ValueError(f'{user.pw_name} needs signing group membership')
    if admin_group.gr_gid not in memberships(admin):
        raise ValueError('administrator needs management group membership')
    if service.pw_shell not in ('/usr/bin/false', '/bin/false', '/usr/sbin/nologin'):
        raise ValueError('service account must have a disabled login shell')
    return {
        'schema_version': 1, 'mode': 'macos-boundary-preview',
        'instance_id': str(uuid.uuid4()), 'service_uid': service.pw_uid,
        'admin_uids': [admin.pw_uid], 'agent_gid': sign_group.gr_gid,
        'admin_gid': admin_group.gr_gid, 'state_dir': str(BASE / 'state'),
        'sign_socket': str(BASE / 'sign/sign.sock'),
        'admin_socket': str(BASE / 'admin/admin.sock'),
        'principals': [{'principal_id': str(uuid.uuid4()), 'uid': u.pw_uid,
                        'generation': 1, 'enabled': True} for u in agents],
        'vault_ids': [str(uuid.uuid4())],
        'features': json.loads(json.dumps(DEFAULT_FEATURES)),
    }


def upgraded_config(config, state_dir):
    """Fill provisioning defaults absent from an installed service.json.

    `vault_ids` is preserved verbatim. Only a config that never had a vault and
    never had a catalog gets one: presetting an ID beside an existing catalog
    would make `Database::recover` inspect a vault that was never registered.
    """
    updated = json.loads(json.dumps(config))
    changed = False
    features = updated.setdefault('features', {})
    for key, value in DEFAULT_FEATURES.items():
        if key not in features:
            features[key] = value
            changed = True
    if not updated.get('vault_ids'):
        if (Path(state_dir) / 'catalog.sqlite3').exists():
            print('note: existing catalog with no vault ID; run --adopt or configure a vault by hand',
                  file=sys.stderr)
        else:
            updated['vault_ids'] = [str(uuid.uuid4())]
            changed = True
    return updated, changed


def launch_job(service):
    return {'Label': 'org.anpio-key.local', 'UserName': service.pw_name,
            'GroupName': grp.getgrgid(service.pw_gid).gr_name,
            'ProgramArguments': [str(BINARY), 'serve-protected', '--config', str(CONFIG)],
            'WorkingDirectory': str(BASE), 'RunAtLoad': True, 'KeepAlive': False,
            'Umask': 0o077, 'SoftResourceLimits': {'Core': 0},
            'HardResourceLimits': {'Core': 0},
            'EnvironmentVariables': {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'RUST_LOG': 'info'}}


def directory(path, uid, gid, mode):
    path.mkdir(mode=mode)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def create_directories(base, service, config):
    directory(base, 0, 0, 0o755)
    directory(base / 'bin', 0, 0, 0o755)
    directory(base / 'state', service.pw_uid, service.pw_gid, 0o700)
    directory(base / 'state' / 'vaults', service.pw_uid, service.pw_gid, 0o700)
    for vault_id in config.get('vault_ids', []):
        directory(base / 'state' / 'vaults' / vault_id, service.pw_uid, service.pw_gid, 0o700)
    directory(base / 'sign', service.pw_uid, config['agent_gid'], 0o750)
    directory(base / 'admin', service.pw_uid, config['admin_gid'], 0o750)


def write_new(path, data, mode=0o644):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.chown(path, 0, 0)
    os.chmod(path, mode)


def uninstall(apply):
    plan = {'bootout': f'system/{LABEL}',
            'remove': [str(BINARY), str(PLIST)],
            'retain': [str(CONFIG), str(BASE / 'state'), str(BASE / 'sign'), str(BASE / 'admin')],
            'apply': apply}
    print(json.dumps(plan, indent=2))
    if not apply:
        return
    if os.geteuid() != 0:
        raise ValueError('--apply requires root')
    check_chain(PLIST.parent)
    if os.path.lexists(BASE):
        check_chain(BASE)
    # Not loaded is the expected steady state; the socket wait below is what
    # decides whether the service actually went away.
    result = subprocess.run(['/bin/launchctl', 'bootout', f'system/{LABEL}'],
                            capture_output=True, text=True, check=False)
    if result.returncode != 0 and result.stderr.strip():
        print('launchctl: ' + result.stderr.strip(), file=sys.stderr)
    for _ in range(30):
        if not any(os.path.lexists(socket) for socket in SOCKETS):
            break
        time.sleep(1)
    else:
        raise ValueError('service sockets still present after 30s; refusing to remove the binary')
    for path in (BINARY, PLIST):
        if not os.path.lexists(path):
            continue
        meta = path.lstat()
        if stat.S_ISLNK(meta.st_mode):
            raise ValueError(f'refusing to remove symlink: {path}')
        if meta.st_uid != 0:
            raise ValueError(f'refusing to remove non-root file: {path}')
        path.unlink()
    print('Uninstalled. Service stopped; binary and launchd job removed.')
    print('Retained: ' + str(CONFIG) + ', ' + str(BASE / 'state') + ', accounts.')
    print('To remove the retained state by hand: sudo rm -rf ' + str(BASE) +
          ' ' + str(PLIST) + ' (destroys the identity; accounts are separate).')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--uninstall', action='store_true')
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--sha256')
    parser.add_argument('--service-user')
    parser.add_argument('--admin-user')
    parser.add_argument('--agent-user', action='append')
    parser.add_argument('--sign-group')
    parser.add_argument('--admin-group')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if sys.platform != 'darwin':
        raise ValueError('macOS only')
    if args.uninstall:
        given = [args.binary, args.sha256, args.service_user, args.admin_user,
                 args.agent_user, args.sign_group, args.admin_group]
        if any(value is not None for value in given):
            raise ValueError('--uninstall takes no installation arguments')
        uninstall(args.apply)
        return
    missing = [name for name in ('binary', 'sha256', 'service_user', 'admin_user',
                                 'agent_user', 'sign_group', 'admin_group')
               if getattr(args, name) is None]
    if missing:
        raise ValueError('missing installation arguments: ' + ', '.join('--' + n.replace('_', '-') for n in missing))
    if not re.fullmatch(r'[0-9a-f]{64}', args.sha256):
        raise ValueError('expected lowercase SHA-256 required')
    service, admin = map(pwd.getpwnam, (args.service_user, args.admin_user))
    agents = list(map(pwd.getpwnam, args.agent_user))
    config = configuration(service, admin, agents, grp.getgrnam(args.sign_group), grp.getgrnam(args.admin_group))
    # Capture exact source bytes before privileged writes; digest identifies this
    # copy, regardless of later modifications to the user-owned build directory.
    with args.binary.open('rb') as source:
        binary = source.read(128 * 1024 * 1024 + 1)
    if len(binary) > 128 * 1024 * 1024:
        raise ValueError('binary exceeds 128 MiB')
    if hashlib.sha256(binary).hexdigest() != args.sha256:
        raise ValueError('binary digest mismatch')
    check_chain(BASE.parent)
    check_chain(PLIST.parent)
    if os.path.lexists(BASE) or os.path.lexists(PLIST):
        raise ValueError('fresh installation only; existing or interrupted installation retained for inspection')
    print(json.dumps({'config': config, 'launchd': launch_job(service),
                      'binary_sha256': args.sha256, 'apply': args.apply}, indent=2))
    if not args.apply:
        return
    if os.geteuid() != 0:
        raise ValueError('--apply requires root')
    os.umask(0o077)
    create_directories(BASE, service, config)
    write_new(BINARY, binary, 0o755)
    write_new(CONFIG, json.dumps(config, indent=2).encode())
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}
    prefix = ['/usr/bin/sudo', '-n', '-u', service.pw_name, '--']
    info = json.loads(subprocess.check_output(prefix + [str(BINARY), 'build-info'], env=env))
    if not info.get('release') or info.get('hardware_software') or info.get('seed_export') or info.get('protected_supported'):
        raise ValueError('local preview requires release build without software hardware or seed export')
    subprocess.run(prefix + [str(BINARY), 'init-protected-state', '--config', str(CONFIG)], env=env, check=True)
    write_new(PLIST, plistlib.dumps(launch_job(service)))
    print('Installed, NOT started. Start explicitly: sudo launchctl bootstrap system ' + str(PLIST))
    print('Empty service only: no identity, passphrase or grant was created. '
          'Create one with `anpio-cli did create --key anpio-key` (one passphrase confirmation).')
    print('Restart locks keys and revokes grants.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
