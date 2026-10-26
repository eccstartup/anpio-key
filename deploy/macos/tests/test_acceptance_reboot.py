"""Whole-machine reboot must discard runtime authority and keep the key locked."""
import sys
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'acceptance'))

import acceptance_se

spec = importlib.util.spec_from_file_location('reboot_launcher', Path(__file__).resolve().parents[1] / 'acceptance' / 'launch-reboot-test.py')
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)

spec = importlib.util.spec_from_file_location('post_reboot', Path(__file__).resolve().parents[1] / 'acceptance' / 'post-reboot.py')
post_reboot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(post_reboot)


class RebootJob(unittest.TestCase):
    def test_one_shot_root_system_job_has_no_restart_or_boot_install(self):
        stage = Path('/Library/ANPIOKeyRebootChecks-example')
        job = launcher.job_spec(stage, Path('/usr/bin/python3'), ['--candidate-binary', '/fixture'])
        self.assertEqual(job['Label'], 'org.anpio-key.reboot-check.ANPIOKeyRebootChecks-example')
        self.assertFalse(job['KeepAlive'])
        self.assertTrue(job['SessionCreate'])
        self.assertTrue(job['LaunchOnlyOnce'])
        self.assertEqual(job['WorkingDirectory'], '/')
        self.assertNotIn('UserName', job)
        self.assertEqual(job['ProgramArguments'][3:5], ['--se-ending', 'reboot'])
        self.assertEqual(job['StandardOutPath'], str(stage / 'host.log'))
        self.assertNotIn('--logout-diagnostics', job['ProgramArguments'])
        self.assertNotIn('--post-relogin-probes', job['ProgramArguments'])


class BootEvidence(unittest.TestCase):
    def test_boot_time_must_advance_and_stay_in_the_past(self):
        self.assertEqual(post_reboot.reboot_confirmed(1000, 1002, 1100),
                         {'pre_boottime': 1000, 'boottime': 1002})
        for before, current, now in ((1000, 1001, 1100), (1000, 900, 1100),
                                     (1000, 1200, 1100), (0, 1002, 1100)):
            with self.subTest(before=before, current=current), \
                 self.assertRaises(ValueError):
                post_reboot.reboot_confirmed(before, current, now)

    def test_approval_window_distinguishes_expired_from_still_usable(self):
        # Prepared operations last exactly 120 seconds; a reboot normally
        # crosses that window, and both outcomes still forbid a commit.
        self.assertEqual(post_reboot.approval_state({'expires_at': 1120}, 1000), 'unexpired')
        self.assertEqual(post_reboot.approval_state({'expires_at': 1004}, 1000), 'expired')
        self.assertEqual(post_reboot.approval_state({'expires_at': 1005}, 1000), 'expired')
        for pending in ({}, {'expires_at': '1120'}, {'expires_at': True}):
            with self.subTest(pending=pending), self.assertRaisesRegex(ValueError, 'expiry'):
                post_reboot.approval_state(pending, 1000)


class RebootState(unittest.TestCase):
    def checks(self, base):
        return SimpleNamespace(base=base, config={'instance_id': 'instance'},
            path=base / 'service.json', args=SimpleNamespace(binary=Path('/usr/local/bin/anpio-key'),
                se_login_sha256='a' * 64),
            admin=SimpleNamespace(pw_uid=501), agent=SimpleNamespace(pw_uid=601),
            key={'key_id': 'k', 'did': 'did', 'kid': 'kid'}, policy_id='p',
            env={'PATH': '/usr/bin'}, cli=lambda user, *command: subprocess.CompletedProcess(
                [], 0, json.dumps({'instance_id': 'instance', 'boot_epoch': 7}), ''),
            credentials=lambda user: {'user': user.pw_uid, 'group': user.pw_uid,
                                      'extra_groups': [20]},
            fixture={'helper': '/base/Fixture.app/helper', 'vault_id': 'v',
                     'manifest': {'document': {'did': 'did'}, 'hot_hardware': {'kind': 'secure_enclave'}}})

    def test_state_schema_matches_the_checker_and_is_root_only(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'post-reboot-result.json').write_text('{"ok": true}')
            with patch.object(acceptance_se, 'host_boottime', return_value=1000.5):
                state = acceptance_se.write_post_reboot_state(
                    self.checks(base), {'operation': 'X'}, {'operation_id': 'o', 'digest': 'd'})
            self.assertEqual(state.stat().st_mode & 0o777, 0o600)
            self.assertFalse((base / 'post-reboot-result.json').exists())
            loaded = json.loads(state.read_text())
            self.assertEqual(set(loaded), post_reboot.SCHEMA)
            self.assertEqual(loaded['pre_boot_epoch'], 7)
            self.assertEqual(loaded['helper_sha256'], 'a' * 64)
            post_reboot.validate_state(loaded)

    def test_launcher_is_fixed_and_untrusted_entries_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / 'launcher.sh'
            with patch.object(acceptance_se, 'POST_REBOOT_LAUNCHER', target):
                made = acceptance_se.write_post_reboot_launcher(base / 'state.json')
                self.assertEqual(made, target)
                self.assertEqual(target.stat().st_mode & 0o777, 0o700)
                content = target.read_text()
                self.assertIn(str(Path(acceptance_se.__file__).resolve().parent / 'post-reboot.py'),
                              content)
                self.assertIn(str(base / 'state.json'), content)
                self.assertIn('no pending reboot acceptance', content)
            link = base / 'link.sh'
            link.symlink_to(target)
            with patch.object(acceptance_se, 'POST_REBOOT_LAUNCHER', link), \
                 self.assertRaisesRegex(ValueError, 'untrusted'):
                acceptance_se.write_post_reboot_launcher(base / 'state.json')

    def test_schema_is_exact(self):
        complete = {name: {} for name in post_reboot.SCHEMA}
        complete['pending'], complete['key'], complete['config'], complete['fixture'] = {}, {}, {}, {}
        complete['pre_boottime'], complete['pre_boot_epoch'] = 1.5, 2
        post_reboot.validate_state(complete)
        missing = dict(complete)
        missing.pop('helper_sha256')
        with self.assertRaisesRegex(ValueError, 'schema'):
            post_reboot.validate_state(missing)
        for name, value, message in (('pending', [], 'value type'),
                                     ('pre_boottime', '1', 'boot time value'),
                                     ('pre_boot_epoch', '2', 'boot epoch value')):
            wrong = dict(complete)
            wrong[name] = value
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, message):
                post_reboot.validate_state(wrong)

    def test_checker_requires_root(self):
        with patch.object(post_reboot.os, 'geteuid', return_value=501):
            with self.assertRaisesRegex(ValueError, 'requires root'):
                post_reboot.run_checks({})

    def test_credentials_are_limited_to_the_recorded_identities(self):
        credentials = post_reboot.credentials_for({'admin_uid': 501, 'agent_uid': 601,
            'admin_credentials': {'user': 501}, 'agent_credentials': {'user': 601}})
        self.assertEqual(credentials(SimpleNamespace(pw_uid=501)), {'user': 501})
        self.assertEqual(credentials(SimpleNamespace(pw_uid=601)), {'user': 601})
        with self.assertRaisesRegex(ValueError, 'unexpected'):
            credentials(SimpleNamespace(pw_uid=504))
        with self.assertRaisesRegex(ValueError, 'unexpected'):
            credentials(SimpleNamespace(pw_uid=501), extra_admin_group=True)


if __name__ == '__main__':
    unittest.main()
