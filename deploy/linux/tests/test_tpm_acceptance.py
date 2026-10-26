"""U3 TPM acceptance regressions; no TPM, systemd or signatures involved."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ACCEPTANCE = HERE.parent / 'acceptance'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


device = load('tpm_device', HERE.parent / 'tpm-device.py')
harness = load('tpm_acceptance', ACCEPTANCE / 'tpm-acceptance.py')

DEVICE_REPORT = {
    'path': '/dev/tpmrm0', 'exists': True, 'char_device': True, 'uid': 0, 'gid': 123,
    'group': 'tss', 'mode': '0660', 'sysfs': '/sys/class/tpm/tpm0', 'version_major': '2',
    'description': 'Example TPM', 'driver': 'tpm_tis', 'virtual_device_hint': False,
}
ACCOUNT = SimpleNamespace(pw_name='anpio-key', pw_uid=321, pw_gid=321,
                          pw_dir='/var/lib/anpio-key')


class DeviceFacts(unittest.TestCase):
    def test_dropin_template_keeps_the_device_boundary(self):
        template = (HERE.parent / 'anpio-key-tpm.conf.in').read_text()
        for line in ('PrivateDevices=no', 'DevicePolicy=closed',
                     'DeviceAllow=@TPM_DEVICE@ rw',
                     'SupplementaryGroups=@SUPPLEMENTARY_GROUPS@',
                     'TPM2TOOLS_TCTI=device:@TPM_DEVICE@'):
            with self.subTest(line=line):
                self.assertIn(line, template)

    def test_transport_classification(self):
        self.assertEqual(device.tcti_kind('device:/dev/tpmrm0'), 'kernel-device')
        self.assertEqual(device.tcti_kind('swtpm:host=localhost,port=2321'), 'swtpm-emulator')
        self.assertEqual(device.tcti_kind('libtpms'), 'software-emulator')
        self.assertEqual(device.tcti_kind('mssim:host=x'), 'software-emulator')
        self.assertEqual(device.tcti_kind(''), 'other')

    def test_regular_file_is_not_a_tpm(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'tpm'
            path.write_text('x')
            with self.assertRaisesRegex(device.DeviceError, 'not a character device'):
                device.report(path)

    def test_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / 'tpm'
            link.symlink_to('/dev/null')
            with self.assertRaisesRegex(device.DeviceError, 'symlink'):
                device.report(link)

    def test_root_owned_device_group_is_refused(self):
        # udev's raw-device rule leaves /dev/tpm0 in the root group. Adding the
        # service to root to reach it would widen every other root-file grant.
        meta = SimpleNamespace(st_mode=stat.S_IFCHR | 0o660, st_uid=0, st_gid=0,
                               st_rdev=os.makedev(10, 224))
        with patch.object(Path, 'is_symlink', return_value=False):
            with patch.object(Path, 'exists', return_value=True):
                with patch.object(Path, 'stat', return_value=meta):
                    with patch.object(device.grp, 'getgrgid',
                                      return_value=SimpleNamespace(gr_name='root')):
                        with self.assertRaisesRegex(device.DeviceError, 'root group'):
                            device.report(Path('/dev/tpm0'))

    def test_resource_manager_device_maps_by_name(self):
        # /dev/tpmrm0 is a misc device whose major:minor does not match
        # /sys/class/tpm/tpm0/dev, so the name mapping has to come first.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'tpm0').mkdir()
            (root / 'tpm0' / 'dev').write_text('253:0\n')
            meta = SimpleNamespace(st_rdev=os.makedev(253, 1))
            self.assertEqual(device._sysfs(meta, Path('/dev/tpmrm0'), root),
                             root / 'tpm0')
            self.assertIsNone(device._sysfs(meta, Path('/dev/tpmrm1'), root))

    def test_raw_device_maps_by_major_minor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'tpm0').mkdir()
            (root / 'tpm0' / 'dev').write_text('253:0\n')
            meta = SimpleNamespace(st_rdev=os.makedev(253, 0))
            self.assertEqual(device._sysfs(meta, Path('/dev/tpm0'), root),
                             root / 'tpm0')

    def test_driver_and_virtual_device_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entry = root / 'tpm0'
            (entry / 'device').mkdir(parents=True)
            (entry / 'device' / 'driver').symlink_to('../../../bus/tpm/drivers/tpm_vtpm_proxy')
            self.assertEqual(device._driver(entry), 'tpm_vtpm_proxy')
            self.assertTrue(device._virtual(entry, 'tpm_vtpm_proxy', ''))
            self.assertFalse(device._virtual(entry, 'tpm_tis', 'DRIVER=tpm_tis'))
            bare = root / 'virtual' / 'tpm' / 'tpm0'
            bare.mkdir(parents=True)
            self.assertIsNone(device._driver(bare))
            self.assertTrue(device._virtual(bare, '', ''))


class StateFile(unittest.TestCase):
    def state(self, directory, **overrides):
        body = {'schema': 1, 'tag_hint': 'acceptance-x',
                'root': {'kind': 'tpm', 'handle': 0x81000001},
                'ciphertext_b64': '', 'hs_sha256': '00'}
        body.update(overrides)
        path = Path(directory) / 'state.json'
        path.write_text(json.dumps(body))
        os.chmod(path, 0o600)
        return path

    def test_acceptance_state_is_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            parsed = harness.read_state(self.state(directory))
        self.assertEqual(parsed['tag_hint'], 'acceptance-x')

    def test_non_acceptance_tag_and_bad_handle_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(harness.AcceptanceError, 'acceptance tag'):
                harness.read_state(self.state(directory, tag_hint='production'))
            with self.assertRaisesRegex(harness.AcceptanceError, 'owner range'):
                harness.read_state(self.state(directory, root={'kind': 'tpm', 'handle': 1}))

    def test_public_state_file_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.state(directory)
            os.chmod(path, 0o644)
            with self.assertRaisesRegex(harness.AcceptanceError, 'private regular file'):
                harness.read_state(path)


class ProbeOutput(unittest.TestCase):
    def test_stdout_json_survives_later_stderr_noise(self):
        result = SimpleNamespace(
            returncode=0, stdout=b'{"usable":true,"detail":"ok"}\n',
            stderr=b'ERROR:esys:TR_FromTPMPublic failed\n')
        with patch.object(harness, 'run', return_value=result):
            report = harness.probe(Path('/binary'), 999, 'device:/dev/tpmrm0')
        self.assertTrue(report['usable'])

    def test_an_unusable_probe_is_refused(self):
        result = SimpleNamespace(returncode=0, stdout=b'{"usable":false,"detail":"none"}\n',
                                 stderr=b'')
        with patch.object(harness, 'run', return_value=result):
            with self.assertRaisesRegex(harness.AcceptanceError, 'not usable'):
                harness.probe(Path('/binary'), 999, 'device:/dev/tpmrm0')


class AcceptanceFlow(unittest.TestCase):
    def fake_run(self):
        def run(binary, *arguments, uid=None, environment=None, timeout=120):
            command = arguments[0]
            if uid == 999:
                return SimpleNamespace(returncode=1, stdout=b'',
                                       stderr=b'Permission denied opening /dev/tpmrm0')
            if command == 'create':
                tag = arguments[2]
                body = {'schema': 1, 'tag_hint': tag,
                        'root': {'kind': 'tpm', 'handle': 0x81000001},
                        'ciphertext_b64': '', 'hs_sha256': '00'}
                Path(arguments[1]).write_text(json.dumps(body))
                os.chmod(arguments[1], 0o600)
                return SimpleNamespace(returncode=0, stdout=(b'CREATED ' + tag.encode()),
                                       stderr=b'')
            if command == 'open':
                tag = json.loads(Path(arguments[1]).read_text())['tag_hint']
                if Path(str(arguments[1]) + '.deleted').exists():
                    return SimpleNamespace(
                        returncode=1,
                        stdout=b'',
                        stderr=b'HardwareMissing: this machine does not have it')
                return SimpleNamespace(returncode=0, stdout=(b'PASS ' + tag.encode()),
                                       stderr=b'')
            if command == 'delete':
                tag = json.loads(Path(arguments[1]).read_text())['tag_hint']
                Path(str(arguments[1]) + '.deleted').write_text('')
                return SimpleNamespace(returncode=0, stdout=(b'DELETED ' + tag.encode()),
                                       stderr=b'')
            raise AssertionError(arguments)
        return run

    def args(self, directory):
        binary = Path(directory) / 'tpm-persistence'
        binary.write_bytes(b'binary')
        binary.chmod(0o755)
        return SimpleNamespace(
            binary=binary,
            sha256=harness.hashlib.sha256(b'binary').hexdigest(),
            device=Path('/dev/tpmrm0'), tcti='device:/dev/tpmrm0', other_uid=999,
            attest_physical_hardware=True, timeout=30)

    def accept(self, directory, args, systemd=None):
        report = systemd or {
            'verified': True, 'checks': {'unit_present': True},
            'blockers': [], 'unit_present': True, 'dropin_present': True,
        }
        with patch.object(harness.sys, 'platform', 'linux'):
            with patch.object(harness.os, 'geteuid', return_value=0):
                with patch.object(harness.os, 'chown'):
                    with patch.object(harness.pwd, 'getpwuid', return_value=SimpleNamespace(
                            pw_name='other', pw_uid=999, pw_gid=999, pw_dir='/home/other')):
                        with patch.object(harness.os, 'getgrouplist', return_value=[999]):
                            with patch.object(harness.DEVICE, 'report', return_value=dict(DEVICE_REPORT)):
                                with patch.object(harness.DEVICE, 'virtualization', return_value='none'):
                                    with patch.object(harness, 'service_account', return_value=ACCOUNT):
                                        with patch.object(harness, 'service_groups', return_value={123, 321}):
                                            with patch.object(harness, 'open_device'):
                                                with patch.object(harness, 'probe',
                                                                  return_value={'usable': True}):
                                                    with patch.object(harness, 'run',
                                                                      side_effect=self.fake_run()):
                                                        with patch.object(harness, 'systemd_report',
                                                                          return_value=report):
                                                            return harness.accept(args)

    def test_cross_process_persistence_and_cross_uid_denial(self):
        with tempfile.TemporaryDirectory() as directory:
            report = self.accept(directory, self.args(directory))
        self.assertTrue(report['persistence_across_processes'])
        self.assertTrue(report['deleted_object_rejected'])
        self.assertTrue(report['cross_uid_denial'])
        self.assertTrue(report['acceptance_scope_complete'])
        self.assertTrue(report['physical_tpm_acceptance_complete'])
        self.assertFalse(report['hardware_acceptance_complete'])
        self.assertFalse(report['protected_supported'])
        self.assertTrue(report['pending'])

    def test_no_scope_claim_without_the_other_uid(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.args(directory)
            args.other_uid = None
            report = self.accept(directory, args)
        self.assertIsNone(report['cross_uid_denial'])
        self.assertFalse(report['acceptance_scope_complete'])

    def test_physical_attestation_requires_bare_metal_and_kernel_device(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.args(directory)
            with patch.object(harness.sys, 'platform', 'linux'):
                with patch.object(harness.os, 'geteuid', return_value=0):
                    with patch.object(harness.DEVICE, 'report', return_value=dict(DEVICE_REPORT)):
                        with patch.object(harness.DEVICE, 'virtualization', return_value='kvm'):
                            with self.assertRaisesRegex(harness.AcceptanceError,
                                                        'refusing to attest'):
                                harness.accept(args)

    def test_service_must_be_in_the_device_group(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.args(directory)
            with patch.object(harness.sys, 'platform', 'linux'):
                with patch.object(harness.os, 'geteuid', return_value=0):
                    with patch.object(harness.DEVICE, 'report', return_value=dict(DEVICE_REPORT)):
                        with patch.object(harness.DEVICE, 'virtualization', return_value='none'):
                            with patch.object(harness, 'service_account', return_value=ACCOUNT):
                                with patch.object(harness, 'service_groups', return_value={321}):
                                    with self.assertRaisesRegex(harness.AcceptanceError,
                                                                'owning group'):
                                        harness.accept(args)



if __name__ == '__main__':
    unittest.main()
