#!/usr/bin/env python3
"""Read-only boundary acceptance against an explicitly installed local preview.
Requires root to run probes as configured UIDs. Does not modify keys or grants.
Not a substitute for debugger, escape, sleep/reboot or interactive UI acceptance.
"""
import argparse
import json
import os
from pathlib import Path
import pty
import pwd
import select
import time
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path('/Library/ANPIOKey/service.json'))
    parser.add_argument('--binary', type=Path, default=Path('/Library/ANPIOKey/bin/anpio-key'))
    args = parser.parse_args()
    args.config = args.config.absolute()
    args.binary = args.binary.absolute()
    if sys.platform != 'darwin' or os.geteuid() != 0:
        raise ValueError('requires macOS root; no automatic privilege elevation')
    config = json.loads(args.config.read_text())
    if config['mode'] != 'macos-boundary-preview':
        raise ValueError('explicit macOS preview configuration required')
    admin = pwd.getpwuid(config['admin_uids'][0]).pw_name
    def run(user, *command):
        return subprocess.run(['/usr/bin/sudo', '-n', '-u', user, '--', *map(str, command)],
                              capture_output=True, text=True, timeout=15, cwd="/",
                              env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'})
    def cli(user, *command):
        return run(user, args.binary, 'admin', '--config', args.config, *command)
    status = cli(admin, 'status')
    assert status.returncode == 0, status.stderr
    reply = json.loads(status.stdout)
    assert reply['instance_id'] == config['instance_id']
    assert reply['protected_supported'] is False
    print('PASS administrator authenticated service; protected_supported=false')
    for principal in config['principals']:
        user = pwd.getpwuid(principal['uid']).pw_name
        # Exercise with a PTY too: PTY presence does not grant management identity.
        pid, terminal = pty.fork()
        if pid == 0:
            account = pwd.getpwnam(user)
            os.chdir("/")
            os.initgroups(user, account.pw_gid)
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)
            os.execv(str(args.binary), [str(args.binary), 'admin', '--config', str(args.config), 'status'])
        output = bytearray()
        deadline = time.monotonic() + 15
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([terminal], [], [], remaining)[0]:
                    os.kill(pid, 9)
                    raise ValueError('Agent PTY check timed out')
                try:
                    chunk = os.read(terminal, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                output.extend(chunk)
            _, status = os.waitpid(pid, 0)
            assert os.waitstatus_to_exitcode(status) != 0 and b'ADMIN_REQUIRED' in output, output
        finally:
            os.close(terminal)
        denied = run(user, '/bin/cat', Path(config['state_dir']) / 'state.sqlite')
        assert denied.returncode != 0, 'Agent read daemon state'
        # Direct management-socket access must fail before it can send a payload.
        script = """import errno,socket,sys
s=socket.socket(socket.AF_UNIX)
try:
 s.connect(sys.argv[1])
except PermissionError as error:
 if error.errno not in (errno.EACCES, errno.EPERM): raise
 print('ADMIN_SOCKET_ACCESS_DENIED')
else:
 sys.exit('Agent reached admin socket')
"""
        direct = run(user, '/usr/bin/python3', '-I', '-c', script, config['admin_socket'])
        assert direct.returncode == 0 and direct.stdout.strip() == 'ADMIN_SOCKET_ACCESS_DENIED', direct.stdout + direct.stderr
        print(f'PASS uid={principal["uid"]}: PTY admin denied, state unreadable, admin socket denied')
    print('PASS limited live installation checks. Outstanding gates are listed in README.md.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, AssertionError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
