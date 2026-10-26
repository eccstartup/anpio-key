#!/usr/bin/env python3
"""Update the reviewed local-preview binary, preserving config/state/accounts.
Default is plan-only. --apply requires root and stops/reloads the launchd job.
A restart locks keys and invalidates grants; there is no automatic rollback.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import time
import uuid

BASE = Path('/Library/ANPIOKey')
BINARY = BASE / 'bin/anpio-key'
CONFIG = BASE / 'service.json'
PLIST = Path('/Library/LaunchDaemons/org.anpio-key.local.plist')
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}


def read_binary(path):
    with path.open('rb') as handle:
        content = handle.read(128 * 1024 * 1024 + 1)
    if len(content) > 128 * 1024 * 1024:
        raise ValueError('binary exceeds 128 MiB')
    return content


def trusted_file(path):
    meta = path.lstat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_nlink != 1 or meta.st_mode & 0o022:
        raise ValueError('untrusted installed file: ' + str(path))
    return meta


def write_new(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(content)
        handle.flush()
        os.fchmod(handle.fileno(), 0o755)
        os.fsync(handle.fileno())


def archive_previous(previous, archive):
    # Exclusive copy + durable directory entry before removing the old slot.
    # Interruption may leave both copies, but never discards the only backup.
    trusted_file(previous)
    content = read_binary(previous)
    write_new(archive, content)
    fd = os.open(previous.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
        previous.unlink()
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--archive-previous', action='store_true',
                        help='preserve an existing previous binary in an exclusive digest-named archive')
    args = parser.parse_args()
    if sys.platform != 'darwin':
        raise ValueError('macOS only')
    if not re.fullmatch('[0-9a-f]{64}', args.sha256):
        raise ValueError('expected lowercase verified SHA-256')
    content = read_binary(args.binary)
    if hashlib.sha256(content).hexdigest() != args.sha256:
        raise ValueError('candidate binary digest mismatch')
    spec = importlib.util.spec_from_file_location('local_installer', Path(__file__).with_name('install.py'))
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    for directory in [BINARY.parent, CONFIG.parent, PLIST.parent]:
        installer.check_chain(directory)
    before = trusted_file(BINARY)
    trusted_file(CONFIG)
    trusted_file(PLIST)
    config = json.loads(CONFIG.read_text())
    if config['mode'] != 'macos-boundary-preview':
        raise ValueError('explicit local macOS preview required')
    previous = BINARY.with_name('anpio-key.previous')
    archive = None
    if os.path.lexists(previous):
        trusted_file(previous)
        if not args.archive_previous:
            raise ValueError('previous backup exists; inspect it and use --archive-previous to preserve it')
        digest = hashlib.sha256(read_binary(previous)).hexdigest()
        archive = previous.with_name('anpio-key.archive-' + digest)
        if os.path.lexists(archive):
            raise ValueError('backup archive already exists; retain both files and inspect separately')
    print(json.dumps({'binary': str(BINARY), 'candidate_sha256': args.sha256,
                      'backup': str(previous), 'archive_existing_backup': str(archive) if archive else None,
                      'restart_locks_keys_and_revokes_grants': True,
                      'config_and_state_preserved': True, 'apply': args.apply}, indent=2), flush=True)
    if not args.apply:
        return
    if os.geteuid() != 0:
        raise ValueError('--apply requires root')
    if archive is not None:
        archive_previous(previous, archive)
    service = pwd.getpwuid(config['service_uid'])
    admin = pwd.getpwuid(config['admin_uids'][0])
    candidate = BINARY.with_name('.anpio-key-update-' + str(uuid.uuid4()))
    try:
        write_new(candidate, content)
        info = json.loads(subprocess.check_output(['/usr/bin/sudo', '-n', '-u', service.pw_name,
                          '--', str(candidate), 'build-info'], env=ENV, timeout=15))
        if not info['release'] or info['protected_supported'] or info['seed_export'] or info['hardware_software']:
            raise ValueError('expected preview release without export or test-double features')
        subprocess.run(['/bin/launchctl', 'bootout', 'system/org.anpio-key.local'], env=ENV, check=True, timeout=20)
        deadline = time.monotonic() + 10
        while any(os.path.lexists(config[name]) for name in ['sign_socket', 'admin_socket']):
            if time.monotonic() >= deadline:
                raise ValueError('service sockets remain after stop; binary/state left unchanged')
            time.sleep(0.1)
        state = Path(config['state_dir'])
        meta = state.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != service.pw_uid or meta.st_mode & 0o777 != 0o700:
            raise ValueError('untrusted state directory; stopped for inspection')
        fd = os.open(state / 'service.lock', os.O_RDWR | os.O_NOFOLLOW)
        with os.fdopen(fd, 'r+b') as lock:
            meta = os.fstat(lock.fileno())
            if not stat.S_ISREG(meta.st_mode) or meta.st_uid != service.pw_uid or meta.st_nlink != 1 or meta.st_mode & 0o777 != 0o600:
                raise ValueError('untrusted service lock')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            now = trusted_file(BINARY)
            if (now.st_dev, now.st_ino) != (before.st_dev, before.st_ino):
                raise ValueError('installed binary changed during update')
            write_new(previous, read_binary(BINARY))
            os.replace(candidate, BINARY)
            directory = os.open(BINARY.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        subprocess.run(['/bin/launchctl', 'bootstrap', 'system', str(PLIST)], env=ENV, check=True, timeout=20)
        deadline = time.monotonic() + 10
        while not Path(config['admin_socket']).exists():
            if time.monotonic() >= deadline:
                raise ValueError('updated job did not expose admin socket; retain both binaries and inspect launchd')
            time.sleep(0.1)
        result = subprocess.run(['/usr/bin/sudo', '-n', '-u', admin.pw_name, '--', str(BINARY),
                                'admin', '--config', str(CONFIG), 'status'], env=ENV,
                                capture_output=True, text=True, timeout=15)
        if result.returncode:
            raise ValueError('post-update status failed: ' + result.stderr)
        reply = json.loads(result.stdout)
        if reply['code'] != 'OK' or reply['protected_supported'] or reply['instance_id'] != config['instance_id']:
            raise ValueError('unexpected updated daemon status')
        if hashlib.sha256(read_binary(BINARY)).hexdigest() != args.sha256:
            raise ValueError('installed digest changed')
        print('PASS reviewed binary installed atomically; old binary retained; config/state preserved', flush=True)
        print(json.dumps(reply), flush=True)
    finally:
        if candidate.exists():
            candidate.unlink()


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
