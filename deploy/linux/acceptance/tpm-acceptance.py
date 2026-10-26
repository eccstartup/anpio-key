#!/usr/bin/env python3
"""U3 acceptance: a physical TPM must behave like the deployment claims.

This checks the deployment as a whole, not just that a file exists:

1. `/dev/tpmrm0` is a TPM 2.0 character device, not a symlink, and is not
   accessible outside its owning group.
2. The service account is in that group and can really open the device.
3. The service unit's effective sandbox keeps `PrivateDevices` off, the device
   policy closed, and only `/dev/tpmrm0` on the allow-list.
4. Another local UID cannot open the same key.
5. `tpm-persistence` seals an object in one process, opens it in a second,
   then deletes it and proves the envelope no longer opens.
6. The transport is explicit (`device:/dev/tpmrm0`), not an inherited
   `swtpm` emulator.

Passing this tool is not a physical-hardware claim on its own. That requires a
bare-metal device (`systemd-detect-virt` reports `none`), a kernel-device
transport, every check above, and the operator's explicit
`--attest-physical-hardware`. An `swtpm` result must never be presented as
physical acceptance evidence.

It never writes key material: only the public handle, the ECDH-free state file
and a SHA-256 of the derived HS are stored, all in a temporary directory.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid

SERVICE = 'anpio-key'
DROPIN = Path('/etc/systemd/system/anpio-key.service.d/10-tpm.conf')
UNIT = Path('/etc/systemd/system/anpio-key.service')

PENDING = [
    'logout/relogin and user switching',
    'sleep/wake and wall-clock rollback',
    'whole-machine reboot',
    'upgrade with the same device and owner hierarchy',
    'TPM unavailable, cleared owner hierarchy, key loss and recovery',
    'copy to a second machine (requires a second physical TPM)',
    'distribution review of the TPM protection claim',
]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# The device policy lives beside install.py, which is the other loader of it.
DEVICE = load('tpm_device', Path(__file__).resolve().parents[1] / 'tpm-device.py')


class AcceptanceError(Exception):
    pass


def run(binary, *arguments, uid=None, environment=None, timeout=120):
    env = os.environ.copy() if environment is None else environment
    preexec = None
    if uid is not None:
        try:
            account = pwd.getpwuid(uid)
        except KeyError as error:
            raise AcceptanceError(f'no such UID: {uid}') from error
        if account.pw_uid == 0:
            raise AcceptanceError('the target UID must be non-root')
        env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin',
               'HOME': account.pw_dir, 'USER': account.pw_name, **env}

        def preexec():
            # A real login session carries supplementary groups; the service
            # account needs the TPM group to reach /dev/tpmrm0. The second UID
            # is checked for membership separately before this runs.
            os.initgroups(account.pw_name, account.pw_gid)
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)

    try:
        return subprocess.run([str(binary), *map(str, arguments)], env=env,
                              capture_output=True, timeout=timeout, preexec_fn=preexec)
    except (OSError, subprocess.SubprocessError) as error:
        raise AcceptanceError(f'{binary} failed to run: {error}') from error


def output(result):
    return (result.stdout + result.stderr).decode(errors='replace').strip()


def require_success(result, operation):
    if result.returncode:
        raise AcceptanceError(f'{operation} failed ({result.returncode}): {output(result)}')
    return output(result)


def read_state(path):
    meta = path.lstat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_mode & 0o077:
        raise AcceptanceError(f'state file is not a private regular file: {path}')
    state = json.loads(path.read_text())
    for key in ('schema', 'tag_hint', 'root', 'ciphertext_b64', 'hs_sha256'):
        if key not in state:
            raise AcceptanceError(f'state file has no {key!r}')
    if state['schema'] != 1:
        raise AcceptanceError(f"state schema is {state['schema']}, expected 1")
    if not state['tag_hint'].startswith('acceptance-'):
        raise AcceptanceError('state does not name an acceptance tag')
    root = state['root']
    if root.get('kind') != 'tpm' or not isinstance(root.get('handle'), int):
        raise AcceptanceError('state does not name a TPM object')
    if not 0x81000000 <= root['handle'] <= 0x817FFFFF:
        raise AcceptanceError(f"handle {root['handle']:#010x} is outside the owner range")
    return state


def service_account():
    try:
        return pwd.getpwnam(SERVICE)
    except KeyError as error:
        raise AcceptanceError(f'no service account {SERVICE!r}; install the service first') from error


def service_groups(account):
    try:
        return set(os.getgrouplist(account.pw_name, account.pw_gid))
    except OSError as error:
        raise AcceptanceError(f'cannot read groups for {SERVICE!r}: {error}') from error


def service_tcti():
    """The transport the installed unit actually uses, if it is pinned."""
    try:
        result = subprocess.run(
            ['systemctl', 'show', 'anpio-key.service', '-p', 'Environment', '--value'],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    for token in shlex.split(result.stdout):
        if token.startswith('TPM2TOOLS_TCTI='):
            return token.split('=', 1)[1]
    return None


def open_device(path, uid):
    result = run(sys.executable, '-I', '-c',
                 'import os, sys; os.close(os.open(sys.argv[1], os.O_RDWR))',
                 path, uid=uid)
    if result.returncode:
        raise AcceptanceError(f'UID {uid} cannot open {path}: {output(result)}')


def probe(binary, uid, tcti):
    result = run(binary, 'probe', uid=uid, environment={'TPM2TOOLS_TCTI': tcti})
    require_success(result, 'TPM probe')
    text = output(result)
    # The example prints one JSON object on stdout; tss2 may still log
    # warnings on stderr after it. Parse the JSON line, not the last line.
    for line in reversed(result.stdout.decode(errors='replace').splitlines()):
        try:
            report = json.loads(line)
        except ValueError:
            continue
        if isinstance(report, dict) and 'usable' in report:
            break
    else:
        raise AcceptanceError(f'TPM probe did not print JSON: {text}')
    if not report.get('usable'):
        raise AcceptanceError(f"TPM probe says it is not usable: {report.get('detail')}")
    return report



def systemd_report(device):
    report = {
        'unit_present': UNIT.is_file(),
        'dropin_present': DROPIN.is_file(),
        'active': False,
        'checks': {},
        'blockers': [],
    }

    def check(name, condition, detail):
        report['checks'][name] = bool(condition)
        if not condition:
            report['blockers'].append(detail)

    check('unit_present', report['unit_present'], 'the service unit is not installed')
    check('dropin_present', report['dropin_present'],
          'the TPM drop-in is missing; reinstall with --tpm-device')

    def prop(name):
        result = subprocess.run(
            ['systemctl', 'show', 'anpio-key.service', '-p', name, '--value'],
            capture_output=True, text=True, timeout=10)
        return result.stdout.strip()

    try:
        check('private_devices_off', prop('PrivateDevices') == 'no',
              'PrivateDevices is not off, so /dev/tpmrm0 is not visible')
        check('device_policy_closed', prop('DevicePolicy') == 'closed',
              'DevicePolicy is not closed')
        allowed = prop('DeviceAllow')
        check('only_tpm_device_allow', f"{device['path']} rw" in allowed,
              f'{device["path"]} rw is not in DeviceAllow: {allowed!r}')
        environment = prop('Environment')
        check('transport_pinned', f'TPM2TOOLS_TCTI=device:{device["path"]}' in environment,
              'the unit does not pin TPM2TOOLS_TCTI to the kernel device')
        report['active'] = prop('ActiveState') == 'active'
        if report['active']:
            pid = int(prop('MainPID'))
            fields = dict(line.split(':', 1)
                          for line in Path(f'/proc/{pid}/status').read_text().splitlines()
                          if ':' in line)
            groups = set(map(int, fields['Groups'].split()))
            check('service_has_device_group', device['gid'] in groups,
                  'the running service is not in the TPM device group')
        else:
            report['checks']['service_has_device_group'] = None
            report['blockers'].append(
                'the service is not running, so its effective device group was not observed')
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        report['blockers'].append(f'could not read the effective unit: {error}')

    report['verified'] = (report['unit_present'] and report['dropin_present']
                          and all(value is True for value in report['checks'].values())
                          and report['active'])
    return report


def verify_binary(binary, digest):
    if not binary.is_file() or binary.is_symlink():
        raise AcceptanceError(f'candidate must be a regular file: {binary}')
    if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
        raise AcceptanceError('candidate digest mismatch')


def accept(args):
    if sys.platform != 'linux':
        raise AcceptanceError('physical TPM acceptance requires Linux')
    if os.geteuid() != 0:
        raise AcceptanceError('physical TPM acceptance requires root (device and UID checks)')
    if args.other_uid is not None and args.other_uid == 0:
        raise AcceptanceError('--other-uid must be non-root')
    binary = args.binary.resolve(strict=True)
    verify_binary(binary, args.sha256)
    device = DEVICE.report(args.device)
    tcti = args.tcti or service_tcti() or f"device:{device['path']}"
    kind = DEVICE.tcti_kind(tcti)
    virtual = DEVICE.virtualization()
    if args.attest_physical_hardware:
        if kind != 'kernel-device' or device['virtual_device_hint'] or virtual != 'none':
            raise AcceptanceError(
                'refusing to attest physical hardware: transport, device or virtualization '
                f'does not support it (transport={kind}, driver={device["driver"]}, '
                f'virtualization={virtual})')
    account = service_account()
    groups = service_groups(account)
    if device['gid'] not in groups:
        raise AcceptanceError(
            f'{SERVICE} is not in the owning group {device["group"]!r}; reinstall with '
            '--tpm-device or fix group membership')

    work = Path(tempfile.mkdtemp(prefix='anp-tpm-acceptance-'))
    os.chmod(work, 0o700)
    os.chown(work, account.pw_uid, account.pw_gid)
    public_directories = []
    state = work / 'state.json'
    tag = 'acceptance-' + uuid.uuid4().hex
    report = {
        'schema': 1,
        'candidate_sha256': args.sha256,
        'device': device,
        'transport': {'tcti': tcti, 'kind': kind},
        'virtualization': virtual,
        'physical_candidate': kind == 'kernel-device' and not device['virtual_device_hint']
                              and virtual == 'none',
        'physical_attested': bool(args.attest_physical_hardware),
        'service_user': SERVICE,
        'tag': tag,
        'work_directory': str(work),
        'phases': {},
        'persistence_across_processes': False,
        'cross_uid_denial': None,
        'deleted_object_rejected': False,
        'systemd': None,
        'hardware_acceptance_complete': False,
        'physical_tpm_acceptance_complete': False,
        'protected_supported': False,
        'pending': PENDING,
    }
    created = False
    try:
        open_device(device['path'], account.pw_uid)
        report['phases']['service_opens_device'] = 'ok'

        report['probe'] = probe(binary, account.pw_uid, tcti)
        report['phases']['probe'] = 'ok'

        # 1. Process A seals an object and writes its public locator.
        result = run(binary, 'create', state, tag, uid=account.pw_uid,
                     environment={'TPM2TOOLS_TCTI': tcti})
        require_success(result, 'create')
        created = True
        state_data = read_state(state)
        if state_data['tag_hint'] != tag:
            raise AcceptanceError('created state names a different tag')
        report['phases']['create'] = 'ok'
        report['state_sha256'] = hashlib.sha256(state.read_bytes()).hexdigest()

        # 2. Process B reopens it. This is the persistence claim.
        result = run(binary, 'open', state, uid=account.pw_uid,
                     environment={'TPM2TOOLS_TCTI': tcti})
        text = require_success(result, 'open in a new process')
        if 'PASS ' + tag not in text:
            raise AcceptanceError(f'open did not report PASS for {tag}: {text}')
        report['phases']['open_new_process'] = 'ok'
        report['persistence_across_processes'] = True

        # 3. Another UID must not reopen it. The state file is public on
        #    purpose: the denial has to come from the device, not from file
        #    permissions on the state.
        if args.other_uid is not None:
            other = pwd.getpwuid(args.other_uid)
            other_groups = set(os.getgrouplist(other.pw_name, other.pw_gid))
            if device['gid'] in other_groups:
                raise AcceptanceError(
                    f'UID {args.other_uid} is already in {device["group"]!r}; pick a UID outside '
                    'the TPM device group')
            public = Path(tempfile.mkdtemp(prefix='anp-tpm-public-'))
            public_directories.append(public)
            os.chmod(public, 0o755)
            public_state = public / 'state.json'
            shutil.copyfile(state, public_state)
            os.chmod(public_state, 0o644)
            public_binary = public / 'tpm-persistence'
            shutil.copyfile(binary, public_binary)
            os.chmod(public_binary, 0o755)
            denied = run(public_binary, 'open', public_state, uid=args.other_uid,
                         environment={'TPM2TOOLS_TCTI': tcti})
            if denied.returncode == 0:
                raise AcceptanceError('another UID reopened the TPM sealed object')
            detail = output(denied)
            if not any(marker in detail for marker in
                       ('Permission denied', 'could not open a TPM session',
                        'HardwareUnavailable', 'not readable', 'not allowed')):
                raise AcceptanceError('second UID failed for an unexpected reason: ' + detail)
            report['phases']['cross_uid_denied'] = 'ok'
            report['cross_uid_denial'] = True
        else:
            report['phases']['cross_uid_denied'] = 'not tested (no --other-uid)'

        # 4. Remove the persistent object and prove the old envelope fails.
        result = run(binary, 'delete', state, uid=account.pw_uid,
                     environment={'TPM2TOOLS_TCTI': tcti})
        text = require_success(result, 'delete')
        if 'DELETED ' + tag not in text:
            raise AcceptanceError(f'delete did not report DELETED for {tag}: {text}')
        created = False
        report['phases']['delete'] = 'ok'
        gone = run(binary, 'open', state, uid=account.pw_uid,
                   environment={'TPM2TOOLS_TCTI': tcti})
        if gone.returncode == 0:
            raise AcceptanceError('the envelope still opened after the TPM object was deleted')
        detail = output(gone)
        if not any(marker in detail for marker in
                   ('does not have', 'HardwareMissing', 'not a valid TPM persistent handle')):
            raise AcceptanceError('post-delete open failed for an unexpected reason: ' + detail)
        report['phases']['open_after_delete_rejected'] = 'ok'
        report['deleted_object_rejected'] = True

        report['systemd'] = systemd_report(device)
    finally:
        if created:
            try:
                cleanup = run(binary, 'delete', state, uid=account.pw_uid,
                              environment={'TPM2TOOLS_TCTI': tcti})
                report['phases']['cleanup'] = 'ok' if cleanup.returncode == 0 else output(cleanup)
            except AcceptanceError as error:
                report['phases']['cleanup'] = str(error)
        shutil.rmtree(work, ignore_errors=True)
        for directory in public_directories:
            shutil.rmtree(directory, ignore_errors=True)

    scope = (report['persistence_across_processes']
             and report['deleted_object_rejected']
             and report['cross_uid_denial'] is True
             and report['systemd'] is not None and report['systemd']['verified'])
    report['passed'] = report['persistence_across_processes'] and report['deleted_object_rejected']
    report['acceptance_scope_complete'] = scope
    report['physical_tpm_acceptance_complete'] = (
        scope and report['physical_candidate'] and report['physical_attested'])
    return report


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--binary', type=Path, required=True,
                        help='tpm-persistence example built with hardware-tpm,tpm-acceptance')
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--device', type=Path, default=DEVICE.DEVICE)
    parser.add_argument('--tcti', help='transport used by the deployment; defaults to the unit')
    parser.add_argument('--other-uid', type=int,
                        help='second non-root UID outside the TPM group; enables the denial test')
    parser.add_argument('--attest-physical-hardware', action='store_true',
                        help='operator attestation; requires a bare-metal kernel device')
    parser.add_argument('--timeout', type=int, default=120)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    try:
        if not args.sha256.islower() or len(args.sha256) != 64:
            raise AcceptanceError('expected a lowercase SHA-256')
        report = accept(args)
    except (AcceptanceError, DEVICE.DeviceError, ValueError, OSError) as error:
        report = {'schema': 1, 'passed': False, 'error': str(error),
                  'hardware_acceptance_complete': False,
                  'physical_tpm_acceptance_complete': False,
                  'protected_supported': False}
        print(json.dumps(report, indent=2))
        return 1
    if args.out:
        args.out.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
