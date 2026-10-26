#!/usr/bin/env python3
"""Rename an existing macOS local-preview installation to the anpio-key names.
Plan-only by default. --apply requires root, stops the launchd job, renames the
Directory Services records, moves the installation and restarts the job.

Renaming a record keeps its UID/GID, so file ownership and group memberships
survive. There is no automatic rollback: the old names are gone once applied.
"""
import argparse
import grp
import json
import os
from pathlib import Path
import plistlib
import pwd
import subprocess
import sys
import time

OLD_BASE = Path('/Library/ANPKeyd')
NEW_BASE = Path('/Library/ANPIOKey')
OLD_PLIST = Path('/Library/LaunchDaemons/org.anp-keyd.local.plist')
NEW_PLIST = Path('/Library/LaunchDaemons/org.anpio-key.local.plist')
OLD_LABEL = 'org.anp-keyd.local'
NEW_LABEL = 'org.anpio-key.local'
ACCOUNTS = [('_anpkeyd', '_anpio'), ('_anpkeyd_sign', '_anpio_sign'),
            ('_anpkeyd_admin', '_anpio_admin')]
RECORDS = dict(ACCOUNTS)
BINARY_OLD = OLD_BASE / 'bin/anp-keyd'
BINARY_NEW = NEW_BASE / 'bin/anpio-key'
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}


def rebase(value):
    """Rewrite one path or path-shaped string onto the new installation root."""
    text, old, new = str(value), str(OLD_BASE), str(NEW_BASE)
    if text == old:
        return new
    if text.startswith(old + '/'):
        return new + text[len(old):]
    return text


def rewrite_config(config):
    updated = dict(config)
    for key in ('state_dir', 'sign_socket', 'admin_socket'):
        if key in updated:
            updated[key] = rebase(updated[key])
    return updated


def rewrite_job(job):
    updated = dict(job)
    updated['Label'] = NEW_LABEL
    for key in ('UserName', 'GroupName'):
        if key in updated:
            updated[key] = RECORDS.get(updated[key], updated[key])
    arguments = [str(BINARY_NEW) if arg == str(BINARY_OLD) else rebase(arg)
                 for arg in job.get('ProgramArguments', [])]
    updated['ProgramArguments'] = arguments
    if 'WorkingDirectory' in updated:
        updated['WorkingDirectory'] = rebase(updated['WorkingDirectory'])
    return updated


def account_plan(user_names, group_names):
    """[(kind, old, new)] for every record that still carries an old name."""
    plan = []
    for old, new in ACCOUNTS:
        is_user, is_group = old in user_names, old in group_names
        if is_user and is_group:
            plan.append(('both', old, new))
        elif is_user:
            plan.append(('user', old, new))
        elif is_group:
            plan.append(('group', old, new))
    return plan


def rename_commands(plan):
    commands = []
    for kind, old, new in plan:
        if kind in ('user', 'both'):
            commands.append(['/usr/bin/dscl', '.', '-change', '/Users/' + old, 'RecordName', old, new])
        if kind in ('group', 'both'):
            commands.append(['/usr/bin/dscl', '.', '-change', '/Groups/' + old, 'RecordName', old, new])
    return commands


def wait_for_sockets_gone(config, timeout=10):
    deadline = time.monotonic() + timeout
    while any(os.path.lexists(config[name]) for name in ('sign_socket', 'admin_socket')):
        if time.monotonic() >= deadline:
            raise ValueError('service sockets remain after stop; nothing renamed')
        time.sleep(0.1)


def write_file(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--user-home', type=Path,
                        help='also rename <home>/.anp-keyd to <home>/.anpio-key (development mode)')
    args = parser.parse_args()
    if sys.platform != 'darwin':
        raise ValueError('macOS only')
    if not os.path.lexists(OLD_BASE) or not os.path.lexists(OLD_PLIST):
        raise ValueError('no complete old-name installation found; nothing to migrate')
    if os.path.lexists(NEW_BASE) or os.path.lexists(NEW_PLIST):
        raise ValueError('new-name installation already exists; inspect both before continuing')
    config = json.loads((OLD_BASE / 'service.json').read_text())
    with OLD_PLIST.open('rb') as handle:
        job = plistlib.load(handle)
    plan = account_plan({u.pw_name for u in pwd.getpwall()}, {g.gr_name for g in grp.getgrall()})
    moves = [(str(OLD_BASE), str(NEW_BASE))]
    if os.path.lexists(BINARY_OLD):
        moves.append((str(BINARY_OLD), str(BINARY_NEW)))
    moves.append((str(OLD_PLIST), str(NEW_PLIST)))
    if args.user_home and os.path.lexists(args.user_home / '.anp-keyd'):
        moves.append((str(args.user_home / '.anp-keyd'), str(args.user_home / '.anpio-key')))
    print(json.dumps({'rename_records': plan, 'commands': rename_commands(plan), 'moves': moves,
                      'config': rewrite_config(config), 'launchd': rewrite_job(job),
                      'apply': args.apply,
                      'warning': 'no automatic rollback; the old record names stop existing'},
                     indent=2))
    if not args.apply:
        return
    if os.geteuid() != 0:
        raise ValueError('--apply requires root')
    subprocess.run(['/bin/launchctl', 'bootout', 'system/' + OLD_LABEL], env=ENV, timeout=20)
    wait_for_sockets_gone(config)
    for command in rename_commands(plan):
        subprocess.run(command, env=ENV, check=True, timeout=20)
    subprocess.run(['/usr/bin/dscacheutil', '-flushcache'], env=ENV, timeout=20)
    os.rename(OLD_BASE, NEW_BASE)
    moved_binary = NEW_BASE / 'bin' / BINARY_OLD.name
    if os.path.lexists(moved_binary):
        os.rename(moved_binary, BINARY_NEW)
    staged = NEW_BASE / '.service.json.new'
    write_file(staged, json.dumps(rewrite_config(config), indent=2).encode(), 0o644)
    os.replace(staged, NEW_BASE / 'service.json')
    write_file(NEW_PLIST, plistlib.dumps(rewrite_job(job)), 0o644)
    os.unlink(OLD_PLIST)
    if args.user_home and os.path.lexists(args.user_home / '.anp-keyd'):
        os.rename(args.user_home / '.anp-keyd', args.user_home / '.anpio-key')
    subprocess.run(['/bin/launchctl', 'bootstrap', 'system', str(NEW_PLIST)], env=ENV, check=True, timeout=20)
    print('Renamed. Restart locks keys and revokes grants; re-unlock before signing.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
