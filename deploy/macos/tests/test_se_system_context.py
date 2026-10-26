"""Non-login launchd probe policy; no keychain, launchd job or hardware used."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'se_system_context', Path(__file__).resolve().parents[1] / 'acceptance' / 'se-system-context.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

TAG = 'acceptance-0123456789abcdef'


def state_bytes(tag=TAG, schema=1, root=None):
    return json.dumps({
        'schema': schema,
        'tag_hint': tag,
        'root': root if root is not None else {'kind': 'secure_enclave', 'tag': 'anpio-key/' + tag},
        'ciphertext_b64': 'AA==',
        'hs_sha256': '00' * 32,
    }).encode()


class StateValidation(unittest.TestCase):
    def test_acceptance_state_is_accepted(self):
        state, tag = probe.parse_state(state_bytes())
        self.assertEqual(tag, 'anpio-key/' + TAG)

    def test_non_acceptance_label_is_refused(self):
        for tag in ('production-key', ''):
            with self.assertRaises(ValueError):
                probe.parse_state(state_bytes(tag=tag))

    def test_label_and_hint_must_agree(self):
        content = state_bytes()
        data = json.loads(content)
        data['tag_hint'] = 'acceptance-other'
        with self.assertRaises(ValueError):
            probe.parse_state(json.dumps(data).encode())

    def test_non_secure_enclave_root_is_refused(self):
        for root in ({'kind': 'tpm', 'handle': 7},
                     {'kind': 'secure_enclave', 'tag': 'anpio-key/acceptance-x',
                      'handle': 7},
                     {'SecureEnclave': {'tag': 'anpio-key/' + TAG}}):
            with self.assertRaises(ValueError):
                probe.parse_state(state_bytes(root=root))

    def test_schema_and_links_are_refused(self):
        with self.assertRaises(ValueError):
            probe.parse_state(state_bytes(schema=2))
        with tempfile.TemporaryDirectory() as root:
            real = Path(root) / 'real.json'
            real.write_bytes(state_bytes())
            link = Path(root) / 'state.json'
            link.symlink_to(real)
            with self.assertRaises(OSError):
                probe.read_user_state(link, os.getuid())


class StateOwnership(unittest.TestCase):
    def write(self, root, mode=0o600):
        path = Path(root) / 'state.json'
        path.write_bytes(state_bytes())
        path.chmod(mode)
        return path

    def test_private_regular_file_is_read(self):
        with tempfile.TemporaryDirectory() as root:
            path = self.write(root)
            content, state, tag = probe.read_user_state(path, os.getuid())
            self.assertEqual(content, state_bytes())
            self.assertEqual(tag, 'anpio-key/' + TAG)

    def test_world_writable_state_is_refused(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(ValueError):
                probe.read_user_state(self.write(root, 0o666), os.getuid())

    def test_wrong_owner_is_refused(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(ValueError):
                probe.read_user_state(self.write(root), os.getuid() + 1)


class Staging(unittest.TestCase):
    def test_app_bundle_with_profile_is_staged_whole(self):
        with tempfile.TemporaryDirectory() as root:
            bundle = Path(root) / 'Probe.app'
            (bundle / 'Contents' / 'MacOS').mkdir(parents=True)
            executable = bundle / 'Contents' / 'MacOS' / 'Probe'
            executable.write_bytes(b'probe')
            (bundle / 'Contents' / 'embedded.provisionprofile').write_bytes(b'profile')
            stage = Path(root) / 'stage'
            stage.mkdir()
            staged = probe.stage_binary(executable, probe.sha256_file(executable), stage)
            self.assertEqual(staged.read_bytes(), b'probe')
            self.assertTrue((stage / 'Probe.app' / 'Contents' / 'embedded.provisionprofile').is_file())

    def test_bundle_links_are_refused(self):
        with tempfile.TemporaryDirectory() as root:
            bundle = Path(root) / 'Probe.app'
            (bundle / 'Contents' / 'MacOS').mkdir(parents=True)
            executable = bundle / 'Contents' / 'MacOS' / 'Probe'
            executable.write_bytes(b'probe')
            (bundle / 'Contents' / 'embedded.provisionprofile').write_bytes(b'profile')
            (bundle / 'Contents' / 'link').symlink_to(executable)
            stage = Path(root) / 'stage'
            stage.mkdir()
            with self.assertRaises(ValueError):
                probe.stage_binary(executable, probe.sha256_file(executable), stage)


class JobSpec(unittest.TestCase):
    def account(self):
        return SimpleNamespace(pw_name='_anpagent', pw_uid=601, pw_dir='/var/empty')

    def test_default_job_is_one_shot_and_non_login(self):
        spec = probe.job_spec('label', Path('/stage/probe'), Path('/stage/state.json'),
                              Path('/stage/probe.log'), self.account())
        self.assertEqual(spec['UserName'], '_anpagent')
        self.assertTrue(spec['RunAtLoad'])
        self.assertTrue(spec['LaunchOnlyOnce'])
        self.assertFalse(spec['KeepAlive'])
        self.assertNotIn('SessionCreate', spec)
        self.assertEqual(spec['ProgramArguments'][1:], ['open', '/stage/state.json'])
        self.assertEqual(spec['EnvironmentVariables']['HOME'], '/var/empty')
        self.assertEqual(spec['StandardOutPath'], '/stage/probe.log')

    def test_explicit_session_creation_is_added_only_on_request(self):
        spec = probe.job_spec('label', Path('/stage/probe'), Path('/stage/state.json'),
                              Path('/stage/probe.log'), self.account(), session_create=True)
        self.assertTrue(spec['SessionCreate'])


class Classification(unittest.TestCase):
    def test_pass_is_access(self):
        verdict, detail = probe.classify(0, 'SE_CONTEXT {}\nPASS ' + TAG, TAG)
        self.assertEqual(verdict, 'allowed')
        self.assertIn('non-login', detail)

    def test_known_keychain_refusals_are_denials(self):
        for text in ('se-persistence: keychain returned errSecItemNotFound (-25300)',
                     'se-persistence: errSecInteractionNotAllowed',
                     'se-persistence: the keychain has no key with that label',
                     'se-persistence: errSecAuthFailed (-25293)'):
            self.assertEqual(probe.classify(1, text, TAG)[0], 'denied', text)

    def test_admission_failure_is_inconclusive(self):
        for text in ('Disallowing probe because no eligible provisioning profiles found',
                     'se-persistence: errSecMissingEntitlement (-34018)',
                     'Code Signature Invalid'):
            self.assertEqual(probe.classify(1, text, TAG)[0], 'inconclusive', text)

    def test_zero_exit_without_pass_is_inconclusive(self):
        self.assertEqual(probe.classify(0, 'SE_CONTEXT {}', TAG)[0], 'inconclusive')

    def test_unknown_refusal_is_inconclusive(self):
        self.assertEqual(probe.classify(1, 'se-persistence: something else', TAG)[0],
                         'inconclusive')


class ContextConfirmation(unittest.TestCase):
    def context(self, **changes):
        value = {'uid': 601, 'euid': 601, 'audit_uid': 601,
                 'audit_session': 100000, 'session_attributes': 0}
        value.update(changes)
        return value

    def test_agent_identity_and_separate_session_are_required(self):
        self.assertTrue(probe.context_confirmed(self.context(), 601, 105654))
        self.assertFalse(probe.context_confirmed(None, 601, 105654))
        self.assertFalse(probe.context_confirmed(self.context(uid=501), 601, 105654))
        self.assertFalse(probe.context_confirmed(self.context(euid=501), 601, 105654))
        self.assertFalse(probe.context_confirmed(self.context(audit_session=105654), 601, 105654))

    def test_context_parser_uses_the_last_report(self):
        text = ('SE_CONTEXT {"uid": 1}\nnoise\nSE_CONTEXT {"uid": 601, "euid": 601}\nPASS x')
        self.assertEqual(probe.parse_context(text)['uid'], 601)


class Dispatch(unittest.TestCase):
    def test_root_and_user_paths_are_separate(self):
        # The module must never silently run the system phase as the human or
        # create a key as root; main chooses strictly by effective UID.
        args = SimpleNamespace(finish=None, binary=Path('/probe'), sha256='0' * 64,
                               team_id='ABCDEFGHIJ',
                               application_id='ABCDEFGHIJ.org.anp.keyd')
        with patch.object(probe.os, 'geteuid', return_value=0):
            with patch.object(probe, 'system_phase', return_value=7) as system:
                with patch.object(probe, 'run_phase') as run:
                    with patch.object(probe.argparse.ArgumentParser, 'parse_args',
                                      return_value=args):
                        self.assertEqual(probe.main(), 7)
                    system.assert_called_once_with(args)
                    run.assert_not_called()

    def test_finish_needs_no_signing_arguments(self):
        args = SimpleNamespace(finish=Path('/Library/ANPIOKeySystemContextChecks-x'),
                               binary=None, sha256=None, team_id=None,
                               application_id=None)
        with patch.object(probe, 'finish_phase') as finish:
            with patch.object(probe.argparse.ArgumentParser, 'parse_args',
                              return_value=args):
                self.assertEqual(probe.main(), 0)
            finish.assert_called_once_with(args.finish)


if __name__ == '__main__':
    unittest.main()
