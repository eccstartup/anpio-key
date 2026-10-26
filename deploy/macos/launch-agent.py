#!/usr/bin/env python3
"""Launch a whole Agent under a configured non-admin UID and a clean environment.

Human-run root command. Uses existing accounts; never copies human credentials.
The reviewed framework executable must be root-owned, digest-pinned, and outside
Agent-writable paths. HOME/workspace must be dedicated to this Agent.
"""
import argparse
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import resource
import stat
import subprocess
import sys


def environment(home, user):
    return {'HOME': str(home), 'USER': user, 'LOGNAME': user,
            'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'TMPDIR': str(home / 'tmp'),
            'LANG': 'en_US.UTF-8', 'RUST_LOG': 'info'}


def account(config, uid):
    if uid in {0, config['service_uid'], *config['admin_uids']}:
        raise ValueError('Agent needs an independent non-root UID')
    subjects = [p for p in config['principals'] if p['uid'] == uid and p['enabled']]
    if len(subjects) != 1:
        raise ValueError('exactly one enabled configured principal required')
    user = pwd.getpwuid(uid)
    groups = set(os.getgrouplist(user.pw_name, user.pw_gid))
    forbidden = {0, config['admin_gid'], grp.getgrnam('admin').gr_gid}
    if groups & forbidden:
        raise ValueError('Agent belongs to a privileged or management group')
    if config['agent_gid'] not in groups:
        raise ValueError('Agent lacks signing transport membership')
    return user


def dedicated(path, uid, check_acl):
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('absolute dedicated path required')
    # Parents may belong to root or the Agent, but no other user may rename them.
    for node in [*reversed(path.parents), path]:
        meta = node.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid not in (0, uid) or meta.st_mode & 0o022:
            raise ValueError('untrusted Agent path: ' + str(node))
        check_acl(node)
    meta = path.lstat()
    if meta.st_uid != uid or meta.st_mode & 0o777 != 0o700:
        raise ValueError('Agent HOME/workspace/tmp must be Agent-owned mode 0700')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path('/Library/ANPIOKey/service.json'))
    parser.add_argument('--uid', type=int, required=True)
    parser.add_argument('--home', type=Path, required=True)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if sys.platform != 'darwin' or os.geteuid() != 0:
        raise ValueError('requires macOS root in the human terminal')
    spec = importlib.util.spec_from_file_location('agent_migration_policy', Path(__file__).with_name('migrate-vault.py'))
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    spec = importlib.util.spec_from_file_location('agent_installer_policy', Path(__file__).with_name('install.py'))
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    for path in [args.config, args.binary]:
        installer.check_chain(path.parent)
        meta = path.lstat()
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_nlink != 1 or meta.st_mode & 0o022:
            raise ValueError('expected root-owned trusted regular file: ' + str(path))
        policy.no_acl(path)
    config = json.loads(args.config.read_text())
    if config['mode'] != 'macos-boundary-preview':
        raise ValueError('macOS preview configuration required')
    user = account(config, args.uid)
    # sudo -l -U <user> exits 0 for a root caller even when the target is denied,
    # because the denial answers the query. Sudo's own policy verdict is the
    # evidence; the exit status carries no permission bit.
    privileges = subprocess.run(['/usr/bin/sudo', '-n', '-l', '-U', user.pw_name],
        env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}, capture_output=True, text=True, timeout=15)
    if 'is not allowed to run sudo' not in privileges.stdout:
        raise ValueError('Agent has sudo privileges or sudo audit failed; inspect before launch: '
                         + privileges.stdout + privileges.stderr)
    for path in [args.home, args.workspace, args.home / 'tmp']:
        dedicated(path, user.pw_uid, policy.no_acl)
    with args.binary.open('rb') as source:
        content = source.read(256 * 1024 * 1024 + 1)
    if len(content) > 256 * 1024 * 1024 or hashlib.sha256(content).hexdigest() != args.sha256:
        raise ValueError('reviewed framework digest mismatch')
    arguments = args.arguments[1:] if args.arguments[:1] == ['--'] else args.arguments
    env = environment(args.home, user.pw_name)
    # No inherited admin group, agent-unrelated shared-directory group, auth/SSH
    # agent, Docker socket, cloud credential, DYLD or shell startup environment.
    os.setgroups([user.pw_gid, *sorted({config['agent_gid']} - {user.pw_gid})])
    os.setgid(user.pw_gid)
    os.setuid(user.pw_uid)
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.chdir(args.workspace)
    os.closerange(3, resource.getrlimit(resource.RLIMIT_NOFILE)[0])
    os.execve(args.binary, [str(args.binary), *arguments], env)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError) as error:
        sys.exit(str(error))
