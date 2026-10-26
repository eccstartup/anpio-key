#!/usr/bin/env python3
"""Offline Linux vault cutover. Run dry-run first; stop ALL legacy writers before apply.

Copies encrypted envelopes and device.secret, never plaintext keys. Recovery copies
remain sensitive and must stay under administrator control. Historical copies are
not revoked. Resume an interrupted operation with the same arguments and journal.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import uuid

MAX_TOTAL = 128 * 1024 * 1024


def sync_dir(path):
    fd = os.open(path, os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic(path, data, mode=0o600):
    tmp = path.with_name('.' + path.name + '.new')
    if tmp.exists() or tmp.is_symlink():
        meta = tmp.lstat()
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.geteuid() or meta.st_nlink != 1 or meta.st_mode & 0o022:
            raise RuntimeError('unsafe interrupted temporary file')
        tmp.unlink()  # uncommitted temporary bytes; original file remains intact
        sync_dir(path.parent)
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
    os.fchmod(fd, mode)  # Caller umask must not make config/binary unreadable to service.
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, path)
    sync_dir(path.parent)


def encoded(data):
    return (json.dumps(data, sort_keys=True, indent=2) + '\n').encode()


def trusted(path, directory=True, owners=(0,)):
    if not path.is_absolute() or '..' in path.parts or str(path) != os.path.normpath(path):
        raise RuntimeError('absolute normalized paths required')
    for node in [*reversed(path.parents), path]:
        m = node.lstat()
        is_dir = node != path or directory
        if m.st_uid not in owners or m.st_mode & 0o022 or not (stat.S_ISDIR(m.st_mode) if is_dir else stat.S_ISREG(m.st_mode)):
            raise RuntimeError(f'untrusted path: {node}')
        if not is_dir and m.st_nlink != 1:
            raise RuntimeError(f'linked file: {node}')


def inventory(source, owners=None):
    """Only recovery materials; never follow symlinks or silently omit key files."""
    uid = source.lstat().st_uid
    owners = (uid,) if owners is None else owners
    entries = [source / 'device.secret']
    for name in ('keys', 'dids', 'audit'):
        directory = source / name
        if not directory.exists() and name == 'audit':
            continue
        m = directory.lstat()
        if not stat.S_ISDIR(m.st_mode) or m.st_uid not in owners or m.st_mode & 0o077:
            raise RuntimeError('unsafe source directory')
        entries.extend(sorted(directory.iterdir()))
    result = {}
    total = 0
    for path in entries:
        m = path.lstat()
        if not stat.S_ISREG(m.st_mode) or m.st_uid not in owners or m.st_nlink != 1 or m.st_mode & 0o022:
            raise RuntimeError(f'unsafe source file: {path}')
        if path.parent.name != 'dids' and m.st_mode & 0o077:
            raise RuntimeError(f'public recovery secret: {path}')
        total += m.st_size
        if m.st_size > 64 * 1024 * 1024 or total > MAX_TOTAL:
            raise RuntimeError('migration inventory exceeds bounds')
        with path.open('rb') as stream:
            hasher = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                hasher.update(chunk)
            digest = hasher.hexdigest()
        result[str(path.relative_to(source))] = {'sha256': digest, 'size': m.st_size}
    return result


def copy_checked(source, dest, manifest):
    dest.mkdir(mode=0o700, exist_ok=True)
    for directory in [dest, *(dest / name for name in ('keys', 'dids', 'audit'))]:
        directory.mkdir(mode=0o700, exist_ok=True)
        meta = directory.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.geteuid() or meta.st_mode & 0o077:
            raise RuntimeError('unsafe interrupted copy directory')
    for rel, expected in manifest.items():
        data = (source / rel).read_bytes()
        if len(data) != expected['size'] or hashlib.sha256(data).hexdigest() != expected['sha256']:
            raise RuntimeError('source changed during copy')
        output = dest / rel
        if output.exists() or output.is_symlink():
            meta = output.lstat()
            if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or meta.st_uid != os.geteuid() or meta.st_mode & 0o077 or output.read_bytes() != data:
                raise RuntimeError('unknown bytes in interrupted copy')
        else:
            atomic(output, data)
    for folder in ('keys', 'dids', 'audit'):
        sync_dir(dest / folder)
    sync_dir(dest)
    sync_dir(dest.parent)
    if inventory(dest) != manifest:
        raise RuntimeError('recovery copy verification failed')


def offline(config):
    for endpoint in (config['sign_socket'], config['admin_socket']):
        with socket.socket(socket.AF_UNIX) as stream:
            try:
                stream.connect(endpoint)
            except (FileNotFoundError, ConnectionRefusedError):
                continue
            raise RuntimeError('stop protected service before migration')


def run(args, platform='linux', path_check=None):
    if sys.platform != platform or platform not in ('linux', 'darwin') or os.geteuid() != 0:
        raise RuntimeError('offline migration requires ' + platform + ' root')
    def check(path, directory=True, owners=(0,)):
        trusted(path, directory, owners)
        if path_check:
            for node in [*reversed(path.parents), path]:
                path_check(node)
    check(args.config, False)
    config = json.loads(args.config.read_text())
    if platform == 'darwin' and config['mode'] != 'macos-boundary-preview':
        raise RuntimeError('explicit macOS boundary preview required')
    check(args.binary, False)
    state = Path(config['state_dir'])
    check(state, owners=(0, config['service_uid']))
    check(state / 'vaults', owners=(0, config['service_uid']))
    check(args.source, owners=(0, args.source.lstat().st_uid))
    if args.source == state or args.source.is_relative_to(state) or state.is_relative_to(args.source):
        raise RuntimeError('source and protected state must be disjoint')
    subprocess.run([str(args.binary), 'inspect-vault', '--path', str(args.source)], check=True)
    manifest = inventory(args.source)
    if path_check:
        for rel in manifest:
            path_check(args.source / rel)
        for name in ('keys', 'dids', 'audit'):
            if (args.source / name).exists():
                path_check(args.source / name)
    if not args.apply:
        print(json.dumps({'dry_run': True, 'files': manifest, 'next': 'stop writers; rerun --apply --recovery-dir ROOT_OWNED_NEW_PATH'}))
        return
    # Apply accepts only a root-controlled offline source, including parents.
    # This closes symlink/rename races with the former Agent UID. Stop old
    # processes, move/chown the source into an administrator-owned directory first.
    check(args.source)
    if args.source.lstat().st_uid != 0:
        raise RuntimeError('apply requires a root-owned frozen source')
    if not args.recovery_dir:
        raise RuntimeError('--apply requires --recovery-dir')
    check(args.recovery_dir.parent)
    if args.recovery_dir == args.source or args.recovery_dir.is_relative_to(args.source) or args.source.is_relative_to(args.recovery_dir):
        raise RuntimeError('recovery and source paths must be disjoint')
    if args.recovery_dir == state or args.recovery_dir.is_relative_to(state) or state.is_relative_to(args.recovery_dir):
        raise RuntimeError('recovery and protected state must be disjoint')
    # Root-controlled recovery location is required before source ownership changes.
    offline(config)
    fd = os.open(state / 'service.lock', os.O_RDWR | os.O_NOFOLLOW)
    with os.fdopen(fd, 'r+b') as lock:
        meta = os.fstat(lock.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != config['service_uid'] or meta.st_nlink != 1 or meta.st_mode & 0o777 != 0o600:
            raise RuntimeError('unsafe service lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        legacy_fd = os.open(args.source / '.maintenance.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(legacy_fd, 'r+b') as legacy:
            fcntl.flock(legacy, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Older binaries do not know this lock. Never assume a failed connect
            # means old writers are stopped; reject live pid/socket evidence.
            pidfile = args.source / 'run/keyd.pid'
            if pidfile.exists():
                pid = int(pidfile.read_text().strip())
                if pid <= 0:
                    raise RuntimeError('invalid legacy daemon PID')
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    pass
                else:
                    raise RuntimeError('legacy daemon is still running')
            sock = args.source / 'run/keyd.sock'
            if sock.exists():
                with socket.socket(socket.AF_UNIX) as connection:
                    try:
                        connection.connect(str(sock))
                    except (FileNotFoundError, ConnectionRefusedError):
                        pass
                    else:
                        raise RuntimeError('legacy socket is live')
            journal = args.recovery_dir / 'migration.json'
            if not args.recovery_dir.exists():
                args.recovery_dir.mkdir(mode=0o700)
                sync_dir(args.recovery_dir.parent)
                record = {'format': 1, 'source': str(args.source), 'instance_id': config['instance_id'],
                          'vault_id': str(uuid.uuid4()), 'files': manifest, 'phase': 'prepared'}
                atomic(journal, encoded(record))
            else:
                check(args.recovery_dir)
                check(journal, False)
                record = json.loads(journal.read_text())
                if record['source'] != str(args.source) or record['instance_id'] != config['instance_id'] or record['files'] != manifest:
                    raise RuntimeError('recovery journal does not match source/installation')
            if path_check:
                for node in [args.recovery_dir, *args.recovery_dir.rglob('*')]:
                    path_check(node)
            vault_id = str(uuid.UUID(record['vault_id']))
            # Freeze the old location. New legacy commands detect the marker;
            # ownership prevents old non-root binaries from reopening files.
            # Pre-existing processes/FDs must have been stopped by the operator.
            for path in [args.source, *(args.source / 'keys').iterdir(), *(args.source / 'dids').iterdir(),
                         args.source / 'device.secret', args.source / 'keys', args.source / 'dids']:
                os.chown(path, 0, 0, follow_symlinks=False)
                path.chmod(0o700 if path.is_dir() else 0o600)
            if (args.source / 'audit').exists():
                for path in [*(args.source / 'audit').iterdir(), args.source / 'audit']:
                    os.chown(path, 0, 0, follow_symlinks=False)
                    path.chmod(0o700 if path.is_dir() else 0o600)
            marker = args.source / '.anpio-key-managed'
            if not marker.exists():
                atomic(marker, encoded({'migration': vault_id, 'legacy_disabled': True}))
            backup = args.recovery_dir / 'vault'
            copy_checked(args.source, backup, manifest)
            if inventory(backup) != manifest:
                raise RuntimeError('recovery backup changed; preserve and inspect manually')
            # Open every backup key with the operator's tty before cutover.
            # Hardware keys fail closed on hosts missing their required backend.
            subprocess.run([str(args.binary), 'inspect-vault', '--path', str(backup), '--verify'], check=True)
            target = state / 'vaults' / vault_id
            if not target.exists():
                stage = state / 'vaults' / ('.migration-' + vault_id)
                copy_checked(backup, stage, manifest)
                os.rename(stage, target)
                sync_dir(target.parent)
            if path_check:
                for node in [target, *target.rglob('*')]:
                    path_check(node)
            if inventory(target, owners=(0, config['service_uid'])) != manifest:
                raise RuntimeError('staged vault differs from verified backup')
            # Before any DB/config mutation, record the exact backup and vault ID.
            record['phase'] = 'copied'
            atomic(journal, encoded(record))
            for path in [*target.rglob('*'), target]:
                os.chown(path, config['service_uid'], -1, follow_symlinks=False)
            if vault_id not in config['vault_ids']:
                config['vault_ids'].append(vault_id)
                atomic(args.config, encoded(config), 0o644)
            record['phase'] = 'installed_locked_unclassified'
            atomic(journal, encoded(record))
            print(json.dumps({'vault_id': vault_id, 'phase': record['phase'],
                'recovery': str(args.recovery_dir), 'next': 'start service; admin EnrollVault; confirm roles; publish policy and create fresh grants; verify service before client cutover'}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--config', type=Path, default=Path('/etc/anpio-key/service.json'))
    parser.add_argument('--binary', type=Path, default=Path('/usr/local/libexec/anpio-key'))
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--recovery-dir', type=Path)
    try:
        run(parser.parse_args())
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
