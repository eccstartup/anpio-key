"""U3 SE persistence harness regressions; no SE, keychain or signatures involved."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1] / 'acceptance'


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


harness = load('se_persistence', 'se-persistence.py')
TEAM = 'ABCDEFGHIJ'
APP = TEAM + '.org.anp.keyd.helper'

FAKE = '''#!/usr/bin/env python3
import json, os, stat, sys
command = sys.argv[1]
if command == 'create':
    state, tag = sys.argv[2], sys.argv[3]
    body = {"schema": 1, "tag_hint": tag,
            "root": {"kind": "secure_enclave", "tag": "anp-keyd/" + tag},
            "ciphertext_b64": "", "hs_sha256": "00"}
    with open(state, 'x') as handle:
        handle.write(json.dumps(body))
    os.chmod(state, 0o600)
    print('CREATED ' + tag)
elif command in ('open', 'open-checked'):
    state = sys.argv[2]
    body = json.load(open(state))
    if os.path.exists(state + '.deleted'):
        print('this envelope cannot use it: no key with that label', file=sys.stderr)
        sys.exit(1)
    print('PASS ' + body['tag_hint'])
elif command == 'delete':
    state = sys.argv[2]
    body = json.load(open(state))
    open(state + '.deleted', 'w').close()
    print('DELETED ' + body['tag_hint'])
else:
    sys.exit(2)
'''

UNSIGNED = '''#!/usr/bin/env python3
import sys
print('this binary is not allowed to save a Secure Enclave key '
      '(errSecMissingEntitlement, -34018)', file=sys.stderr)
sys.exit(1)
'''


def script(directory, name, body):
    path = Path(directory) / name
    path.write_text(body)
    path.chmod(0o755)
    return path


def digest(path):
    return harness.hashlib.sha256(Path(path).read_bytes()).hexdigest()


class PersistenceHarness(unittest.TestCase):
    def args(self, binary, unsigned=None):
        return SimpleNamespace(binary=Path(binary), sha256=digest(binary),
                               unsigned_binary=Path(unsigned) if unsigned else None,
                               unsigned_sha256=digest(unsigned) if unsigned else None,
                               team_id=TEAM, application_id=APP, other_uid=None,
                               timeout=30)

    def test_create_open_delete_and_post_delete_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = script(directory, 'se-persistence', FAKE)
            with patch.object(harness, 'verify_binary', return_value={'signature_prerequisites_passed': True}):
                report = harness.accept(self.args(binary))
        self.assertTrue(report['persistence_across_processes'])
        self.assertTrue(report['deleted_key_rejected'])
        self.assertEqual(report['phases']['create'], 'ok')
        self.assertEqual(report['phases']['open_new_process'], 'ok')
        self.assertEqual(report['phases']['delete'], 'ok')
        self.assertEqual(report['phases']['open_after_delete_rejected'], 'ok')
        self.assertFalse(report['hardware_acceptance_complete'])
        self.assertFalse(report['lifecycle_acceptance_complete'])
        self.assertFalse(report['acceptance_scope_complete'])

    def test_unsigned_binary_cannot_create_a_persistent_key(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = script(directory, 'se-persistence', FAKE)
            unsigned = script(directory, 'unsigned', UNSIGNED)
            with patch.object(harness, 'verify_binary', return_value={'signature_prerequisites_passed': True}):
                report = harness.accept(self.args(binary, unsigned))
        self.assertTrue(report['unsigned_persistent_creation_refused'])
        self.assertEqual(report['phases']['unsigned_create_refused'], 'ok')

    def test_cross_uid_probe_preserves_development_bundle_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / 'Probe.app'
            executable_dir = bundle / 'Contents' / 'MacOS'
            executable_dir.mkdir(parents=True)
            profile = bundle / 'Contents' / 'embedded.provisionprofile'
            profile.write_bytes(b'profile fixture')
            binary = script(executable_dir, 'probe', FAKE)
            args = self.args(binary)
            args.other_uid = os.geteuid() + 1
            original_run = harness.run

            def run(candidate, *arguments, uid=None, timeout=120):
                if uid is not None:
                    public = candidate.parent.parent.parent.parent
                    self.assertEqual(public.parent, Path('/private/tmp'))
                    self.assertEqual(stat.S_IMODE(public.stat().st_mode), 0o755)
                    self.assertEqual(stat.S_IMODE(Path(arguments[1]).stat().st_mode), 0o644)
                    self.assertEqual(candidate.parent.name, 'MacOS')
                    self.assertEqual((candidate.parent.parent / 'embedded.provisionprofile').read_bytes(),
                                     profile.read_bytes())
                    self.assertEqual(candidate.read_bytes(), binary.read_bytes())
                    return SimpleNamespace(returncode=1, stdout=b'',
                                           stderr=('SE_CONTEXT ' + json.dumps({'uid': uid, 'euid': uid})
                                                   + '\nno key with that label').encode())
                return original_run(candidate, *arguments, timeout=timeout)

            with patch.object(harness, 'verify_binary', return_value={}), patch.object(harness, 'run', side_effect=run):
                report = harness.accept(args)
            self.assertTrue(report['cross_uid_denial'])

    def test_state_file_must_be_private_and_well_formed(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state.json'
            body = {'schema': 1, 'tag_hint': 'acceptance-x',
                    'root': {'kind': 'secure_enclave', 'tag': 'anpio-key/acceptance-x'},
                    'ciphertext_b64': '', 'hs_sha256': '00'}
            state.write_text(json.dumps(body))
            os.chmod(state, 0o644)
            with self.assertRaisesRegex(harness.AcceptanceError, 'private regular file'):
                harness.read_state(state)
            os.chmod(state, 0o600)
            body['schema'] = 2
            state.write_text(json.dumps(body))
            with self.assertRaisesRegex(harness.AcceptanceError, 'schema'):
                harness.read_state(state)

    def test_digest_mismatch_is_refused_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = script(directory, 'se-persistence', FAKE)
            args = self.args(binary)
            args.sha256 = '0' * 64
            with self.assertRaisesRegex(harness.AcceptanceError, 'digest mismatch'):
                harness.verify_binary(Path(binary), args.sha256, TEAM, APP)

    def test_second_uid_denial_uses_the_other_account(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = script(directory, 'se-persistence', FAKE)
            args = self.args(binary)
            args.other_uid = 502
            real_run = harness.run

            def fake_run(command, *arguments, uid=None, timeout=120):
                if uid == 502:
                    return SimpleNamespace(returncode=1, stdout=b'',
                                           stderr=b'SE_CONTEXT {"uid":502,"euid":502}\nno key with that label')
                return real_run(command, *arguments, timeout=timeout)

            with patch.object(harness, 'verify_binary',
                              return_value={'signature_prerequisites_passed': True}):
                with patch.object(harness.os, 'geteuid', return_value=501):
                    with patch.object(harness, 'run', side_effect=fake_run):
                        report = harness.accept(args)
        self.assertTrue(report['cross_uid_denial'])
        self.assertEqual(report['phases']['cross_uid_denied'], 'ok')

    def test_cross_uid_success_remains_failure_and_preserves_context_and_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = script(directory, 'se-persistence', FAKE)
            args = self.args(binary)
            args.other_uid = 502
            real_run = harness.run

            def run(command, *arguments, uid=None, timeout=120):
                if uid is not None:
                    return SimpleNamespace(returncode=0, stdout=b'PASS unexpected',
                        stderr=b'SE_CONTEXT {"uid":502,"euid":502,"audit_uid":501,"audit_session":123}')
                return real_run(command, *arguments, timeout=timeout)

            with patch.object(harness, 'verify_binary', return_value={}), patch.object(harness, 'run', side_effect=run):
                with self.assertRaisesRegex(harness.AcceptanceError, 'another UID reopened') as caught:
                    harness.accept(args)
            report = caught.exception.report
            self.assertEqual(report['other_uid_probe']['context']['audit_uid'], 501)
            self.assertEqual(report['other_uid_probe']['returncode'], 0)
            self.assertEqual(report['phases']['cleanup'], 'ok')
            self.assertIsNone(report['cross_uid_denial'])

    def test_missing_kernel_context_is_not_keychain_denial_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = script(directory, 'se-persistence', FAKE)
            args = self.args(binary)
            args.other_uid = 502
            real_run = harness.run

            def run(command, *arguments, uid=None, timeout=120):
                if uid is not None:
                    return SimpleNamespace(returncode=1, stdout=b'', stderr=b'no key with that label')
                return real_run(command, *arguments, timeout=timeout)

            with patch.object(harness, 'verify_binary', return_value={}), patch.object(harness, 'run', side_effect=run):
                with self.assertRaisesRegex(harness.AcceptanceError, 'kernel identity was not confirmed'):
                    harness.accept(args)

    def test_root_invocation_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = script(directory, 'se-persistence', FAKE)
            args = self.args(binary)
            with patch.object(harness.os, 'geteuid', return_value=0):
                with self.assertRaisesRegex(harness.AcceptanceError,
                                            'login data protection keychain'):
                    harness.accept(args)

    def test_other_uid_is_run_through_sudo(self):
        account = SimpleNamespace(pw_name='other', pw_uid=502, pw_gid=20, pw_dir='/Users/other')
        result = SimpleNamespace(returncode=1, stdout=b'', stderr=b'no key with that label')
        with patch.object(harness.os, 'geteuid', return_value=501):
            with patch.object(harness.pwd, 'getpwuid', return_value=account):
                with patch.object(harness.subprocess, 'run', return_value=result) as started:
                    self.assertIs(harness.run(Path('/tmp/probe'), 'open', '/tmp/state', uid=502),
                                  result)
        command = started.call_args[0][0]
        self.assertEqual(command[:5],
                         ['/usr/bin/sudo', '-u', 'other', '--', '/tmp/probe'])
        self.assertEqual(command[5:], ['open', '/tmp/state'])
        self.assertNotIn('preexec_fn', started.call_args[1])

    def test_software_policy_denial_is_not_raw_keychain_denial(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = script(directory, 'se-persistence', FAKE)
            args = self.args(binary)
            args.other_uid = 502
            real_run = harness.run

            def run(command, *arguments, uid=None, timeout=120):
                if uid is not None:
                    return SimpleNamespace(returncode=1, stdout=b'',
                        stderr=b'SE_CONTEXT {"uid":502,"euid":502}\nmisuse: SE_LOGIN_SESSION_REQUIRED')
                return real_run(command, *arguments, timeout=timeout)

            with patch.object(harness, 'verify_binary', return_value={}), patch.object(harness, 'run', side_effect=run):
                with self.assertRaisesRegex(harness.AcceptanceError, 'unexpected reason'):
                    harness.accept(args)
                args.checked_open = True
                report = harness.accept(args)
            self.assertTrue(report['cross_uid_denial'])
            self.assertEqual(report['denial_layer'], 'application-login-policy')
            self.assertIn('application-policy denial does not establish raw OS keychain separation',
                          report['scope_limitations'])

    def test_independent_probe_requires_new_audit_session_and_target_audit_uid(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = script(directory, 'se-persistence', FAKE)
            args = self.args(binary)
            args.other_uid = 502
            args.isolated_session = True
            real_run = harness.run
            creator = {'uid': 501, 'euid': 501, 'audit_uid': 501,
                       'audit_session': 100, 'session_attributes': 0x10}
            good = {'uid': 502, 'euid': 502, 'audit_uid': 502,
                    'audit_session': 200, 'session_attributes': 0}
            for changes in ({}, {'audit_uid': 501}, {'audit_session': 100},
                            {'session_attributes': 0x10}):
                other = {**good, **changes}

                def run(command, *arguments, uid=None, timeout=120, isolated_session=False):
                    if uid is not None:
                        self.assertTrue(isolated_session)
                        return SimpleNamespace(returncode=1, stdout=b'',
                            stderr=('SE_CONTEXT ' + json.dumps(other) + '\nno key with that label').encode())
                    result = real_run(command, *arguments, timeout=timeout)
                    if arguments[0] == 'create':
                        result.stderr += ('SE_CONTEXT ' + json.dumps(creator) + '\n').encode()
                    return result

                with self.subTest(changes=changes), patch.object(harness, 'verify_binary', return_value={}), patch.object(harness, 'run', side_effect=run):
                    if changes:
                        with self.assertRaisesRegex(harness.AcceptanceError, 'independent security session'):
                            harness.accept(args)
                    else:
                        report = harness.accept(args)
                        self.assertTrue(report['cross_uid_denial'])
                        self.assertEqual(report['cross_uid_scope'], 'independent-security-session')
                        self.assertTrue(report['scope_limitations'])


if __name__ == '__main__':
    unittest.main()
