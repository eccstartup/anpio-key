#!/usr/bin/env python3
"""Plan or explicitly create local keyd accounts. No passwords or login sessions.
--apply changes Directory Services and group membership; review the printed plan.
Does not move any existing Agent process into the new UID.
"""
import argparse
import grp
import json
import os
import pwd
import re
import subprocess
import sys

SERVICE = '_anpio'
AGENT = '_anpagent'
SIGN = '_anpio_sign'
ADMIN = '_anpio_admin'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--admin-user', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if sys.platform != 'darwin':
        raise ValueError('macOS only')
    if not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_-]{0,63}', args.admin_user):
        raise ValueError('invalid administrator account name')
    operator = pwd.getpwnam(args.admin_user)
    if operator.pw_uid < 501 or args.admin_user in (SERVICE, AGENT):
        raise ValueError('use an existing dedicated trusted human login account')
    users, groups = pwd.getpwall(), grp.getgrall()
    if {SERVICE, AGENT} & {u.pw_name for u in users} or {SERVICE, AGENT, SIGN, ADMIN} & {g.gr_name for g in groups}:
        raise ValueError('reserved name exists; refusing to adopt or overwrite accounts, including partial installations')
    used = {u.pw_uid for u in users} | {g.gr_gid for g in groups}
    ids = []
    for value in range(600, 60000):
        if value not in used:
            ids.append(value)
            if len(ids) == 4:
                break
    if len(ids) != 4:
        raise ValueError('no free local IDs')
    service_id, agent_id, sign_id, admin_id = ids
    commands = []
    for name, gid in [(SERVICE, service_id), (AGENT, agent_id), (SIGN, sign_id), (ADMIN, admin_id)]:
        commands += [['/usr/bin/dscl', '.', '-create', '/Groups/' + name],
                     ['/usr/bin/dscl', '.', '-create', '/Groups/' + name, 'PrimaryGroupID', str(gid)]]
    for name, uid, shell in [(SERVICE, service_id, '/usr/bin/false'), (AGENT, agent_id, '/bin/zsh')]:
        prefix = ['/usr/bin/dscl', '.', '-create', '/Users/' + name]
        commands.append(prefix)
        for key, value in [('UniqueID', str(uid)), ('PrimaryGroupID', str(uid)),
                           ('NFSHomeDirectory', '/var/empty'), ('UserShell', shell),
                           ('IsHidden', '1'), ('AuthenticationAuthority', ';DisabledUser;'),
                           ('Password', '*')]:
            commands.append(prefix + [key, value])
    for user, group in [(SERVICE, SIGN), (SERVICE, ADMIN), (AGENT, SIGN), (args.admin_user, ADMIN)]:
        commands.append(['/usr/sbin/dseditgroup', '-o', 'edit', '-a', user, '-t', 'user', group])
    print(json.dumps({'commands': commands, 'apply': args.apply,
                      'warning': 'Agent processes must be started as _anpagent. Existing sessions keep their current UID.'}, indent=2))
    if args.apply:
        if os.geteuid() != 0:
            raise ValueError('--apply requires root')
        for command in commands:
            subprocess.run(command, check=True, env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'})
        print('Accounts prepared. Log out/in before using new operator group membership.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
