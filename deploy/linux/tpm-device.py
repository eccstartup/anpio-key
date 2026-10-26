"""Physical TPM facts shared by install.py and tpm-acceptance.py.

The point of this module is to keep one definition of "a real TPM device this
deployment may claim".  Both the installer (which grants access) and the
acceptance tool (which reports evidence) load it, so a change to the device
policy cannot drift between them.

It reads facts only.  It never writes to the TPM and never changes ownership.
"""
import grp
import os
from pathlib import Path
import re
import stat
import subprocess

DEVICE = Path('/dev/tpmrm0')
SYSFS = Path('/sys/class/tpm')


class DeviceError(Exception):
    pass


def _sysfs(meta, device=DEVICE, root=SYSFS):
    """Find the /sys/class/tpm entry for a TPM character device.

    `/dev/tpmrm0` is a misc device, so its major:minor does not match
    `/sys/class/tpm/tpm0/dev`; map it by name first, then fall back to the
    major:minor match that works for `/dev/tpm0`.
    """
    match = re.fullmatch(r'tpmrm(\d+)', device.name)
    if match:
        entry = root / f'tpm{match.group(1)}'
        if (entry / 'dev').exists():
            return entry
    wanted = (os.major(meta.st_rdev), os.minor(meta.st_rdev))
    for entry in sorted(root.glob('tpm*')):
        if not re.fullmatch(r'tpm\d+', entry.name):
            continue
        try:
            major, minor = (int(part) for part in (entry / 'dev').read_text().split(':'))
        except (OSError, ValueError):
            continue
        if (major, minor) == wanted:
            return entry
    return None


def _read(path):
    try:
        return path.read_text().strip()
    except OSError:
        return None


def _driver(sysfs):
    """The driver name, or None when this TPM class device has no parent driver."""
    link = sysfs / 'device' / 'driver'
    try:
        return Path(os.readlink(link)).name
    except OSError:
        return None


def _virtual(sysfs, driver, uevent):
    text = (driver or '') + ' ' + (uevent or '')
    if any(marker in text.lower() for marker in ('vtpm', 'xen', 'ibmvtpm')):
        return True
    try:
        return 'virtual' in sysfs.resolve().parts
    except OSError:
        return False


def report(device=DEVICE):
    """Return the device facts or raise DeviceError with an actionable reason."""
    device = Path(device)
    if device.is_symlink():
        raise DeviceError(f'{device} is a symlink; point the deployment at the real device node')
    if not device.exists():
        raise DeviceError(
            f'{device} does not exist. On a machine with a physical TPM 2.0, check that the '
            'kernel module is loaded (`dmesg | grep -i tpm`) and that the resource-manager '
            'device `/dev/tpmrm0` is present. An emulator is not a substitute for this check.'
        )
    meta = device.stat()
    if not stat.S_ISCHR(meta.st_mode):
        raise DeviceError(f'{device} is not a character device')
    if meta.st_mode & 0o007:
        raise DeviceError(
            f'{device} is accessible to users outside its owning group '
            f'(mode {stat.S_IMODE(meta.st_mode):04o}); fix the udev rule before deploying'
        )
    try:
        group = grp.getgrgid(meta.st_gid).gr_name
    except KeyError:
        raise DeviceError(
            f'{device} is owned by gid {meta.st_gid}, which has no group name; create the '
            'group (usually `tss`) before deploying'
        ) from None
    if meta.st_gid == 0 or group == 'root':
        raise DeviceError(
            f'{device} is owned by the root group; the service must not be added to root '
            'to reach a TPM. Use a dedicated group (usually `tss`) via udev'
        )
    sysfs = _sysfs(meta, device)
    if sysfs is None:
        raise DeviceError(f'{device} has no matching /sys/class/tpm entry; it is not a TPM')
    version = _read(sysfs / 'tpm_version_major')
    if version != '2':
        raise DeviceError(
            f'{device} reports TPM version {version!r}, not 2; this backend only supports TPM 2.0'
        )
    uevent = _read(sysfs / 'device' / 'uevent') or ''
    driver = _driver(sysfs) or ''
    virtual = _virtual(sysfs, driver, uevent)
    return {
        'path': str(device),
        'exists': True,
        'char_device': True,
        'uid': meta.st_uid,
        'gid': meta.st_gid,
        'group': group,
        'mode': f'{stat.S_IMODE(meta.st_mode):04o}',
        'sysfs': str(sysfs),
        'version_major': version,
        'description': _read(sysfs / 'device' / 'description'),
        'driver': driver or None,
        'virtual_device_hint': virtual,
    }


def tcti_kind(tcti):
    """Classify the transport the deployment actually uses."""
    value = (tcti or '').strip().lower()
    if value.startswith('swtpm') or 'tcti-swtpm' in value:
        return 'swtpm-emulator'
    if value.startswith('device:'):
        return 'kernel-device'
    if value.startswith('mssim') or 'libtpms' in value:
        return 'software-emulator'
    return 'other'


def virtualization():
    """`none` on bare metal, the hypervisor name in a VM, `unknown` if undetectable."""
    try:
        result = subprocess.run(['systemd-detect-virt'], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return 'unknown'
    value = result.stdout.strip()
    return value or 'unknown'
