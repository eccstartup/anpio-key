#!/usr/bin/env python3
"""Operator-run offline macOS preview migration; dry-run unless --apply.

Stop the launchd job and ALL legacy writers first. Freeze the source under a
root-controlled parent. Recovery verification prompts only in the human tty.
Never creates grants or unlocks managed keys. Preserve source and recovery copy.
"""
import argparse
import ctypes
import errno
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys


def no_acl(path):
    lib = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    lib.acl_get_file.argtypes = [ctypes.c_char_p, ctypes.c_int]
    lib.acl_get_file.restype = ctypes.c_void_p
    lib.acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    lib.acl_free.argtypes = [ctypes.c_void_p]
    acl = lib.acl_get_file(os.fsencode(path), 0x100)
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:
            path.lstat()  # only an existing node without an ACL is acceptable
            return
        raise RuntimeError('cannot inspect ACL: ' + str(path))
    try:
        entry = ctypes.c_void_p()
        result = lib.acl_get_entry(acl, 0, ctypes.byref(entry))
        error = ctypes.get_errno()
        if result != -1 or error != errno.EINVAL:
            raise RuntimeError('extended ACL: ' + str(path))
    finally:
        lib.acl_free(acl)


def apfs(path):
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'}
    rows = subprocess.check_output(['/bin/df', '-P', str(path)], env=env, timeout=15).decode().splitlines()
    if len(rows) != 2 or len(rows[1].split(None, 5)) != 6:
        raise RuntimeError('cannot resolve filesystem device: ' + str(path))
    device = rows[1].split(None, 5)[0]
    if not device.startswith('/dev/'):
        raise RuntimeError('local disk device required: ' + str(path))
    data = subprocess.check_output(['/usr/sbin/diskutil', 'info', '-plist', device], env=env, timeout=15)
    info = plistlib.loads(data)
    if info.get('FilesystemType') != 'apfs' or info.get('GlobalPermissionsEnabled') is not True:
        raise RuntimeError('local APFS with ownership enabled required: ' + str(path))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--config', type=Path, default=Path('/Library/ANPIOKey/service.json'))
    parser.add_argument('--binary', type=Path, default=Path('/Library/ANPIOKey/bin/anpio-key'))
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--recovery-dir', type=Path)
    args = parser.parse_args()
    if sys.platform != 'darwin' or os.geteuid() != 0:
        raise RuntimeError('requires macOS root in the human terminal; no automatic elevation')
    spec = importlib.util.spec_from_file_location('offline_vault_cutover', Path(__file__).parents[1] / 'linux/migrate-vault.py')
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    # Validate before reading configuration or querying filesystem capabilities.
    migration.trusted(args.config, False)
    no_acl(args.config)
    config = json.loads(args.config.read_text())
    for path in [Path(config['state_dir']), args.source,
                 *([args.recovery_dir.parent] if args.recovery_dir else [])]:
        apfs(path)
    migration.run(args, platform='darwin', path_check=no_acl)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
