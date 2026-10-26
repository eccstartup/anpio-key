"""U3 helper release-pipeline regressions; no signing, keychain or system files changed."""
import datetime
import importlib.util
import json
from pathlib import Path
import plistlib
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release = load('se_release', 'se-release.py')
preflight = load('se_preflight', 'se-preflight.py')

TEAM = 'ABCDEFGHIJ'
APP = TEAM + '.org.anp.keyd.helper'


class ReleasePolicy(unittest.TestCase):
    def test_exact_identity_fields(self):
        release.validate_identity_fields(TEAM, APP)
        for team, app in [(TEAM.lower(), APP), ('SHORT', APP), (TEAM, TEAM + '.*'),
                          (TEAM, 'OTHER.' + APP), (TEAM, TEAM + '.')]:
            with self.subTest(team=team, app=app), self.assertRaises(release.ReleaseError):
                release.validate_identity_fields(team, app)

    def test_entitlements_are_the_preflight_policy(self):
        self.assertEqual(release.entitlements(TEAM, APP), {
            'com.apple.application-identifier': APP,
            'com.apple.developer.team-identifier': TEAM,
            'keychain-access-groups': [APP],
        })
        metadata = {'TeamIdentifier': TEAM, 'Authority': 'Apple Root CA',
                    'authorities': ['Developer ID Application: Example',
                                    'Developer ID Certification Authority',
                                    'Apple Root CA'],
                    'flags': 'runtime'}
        self.assertEqual(preflight.policy('user-session', TEAM, APP, metadata,
                                         release.entitlements(TEAM, APP)), [])

    def test_a_non_apple_signing_chain_is_refused(self):
        metadata = {'TeamIdentifier': TEAM, 'Authority': 'Self-Signed Root',
                    'authorities': ['Self-Signed Leaf', 'Self-Signed Root'],
                    'flags': 'runtime'}
        blockers = preflight.policy('user-session', TEAM, APP, metadata,
                                    release.entitlements(TEAM, APP))
        self.assertTrue(any('Apple root CA' in blocker for blocker in blockers))

    def test_info_plist_matches_bundle_identity(self):
        plist = release.info_plist(APP, '0.1.0')
        self.assertEqual(plist['CFBundleIdentifier'], APP.split('.', 1)[1])
        self.assertEqual(plist['CFBundleExecutable'], 'anpio-key')
        self.assertEqual(plist['CFBundlePackageType'], 'APPL')
        self.assertIs(plist['LSBackgroundOnly'], True)

    def test_identity_parsing_and_resolution(self):
        text = (b'  1) ' + b'A' * 40 + b' "Developer ID Application: Example (ABCDEFGHIJ)"\n'
                b'     1 valid identities found\n')
        with patch.object(release, 'checked', return_value=SimpleNamespace(stdout=text)):
            found = release.identities()
            self.assertEqual(found[0]['sha1'], 'A' * 40)
            self.assertEqual(release.resolve_identity('A' * 40), found[0])
            self.assertEqual(release.resolve_identity('Developer ID Application: Example (ABCDEFGHIJ)'),
                             found[0])
            with self.assertRaisesRegex(release.ReleaseError, 'available:'):
                release.resolve_identity('missing')

    def test_plan_reports_missing_identity_and_profile_without_mutation(self):
        args = SimpleNamespace(team_id=TEAM, application_id=APP, identity=None,
                               profile=None, out=Path('target/se-release/ANPIOKey.app'))
        with patch.object(release, 'identities', return_value=[]):
            report = release.plan(args)
        self.assertTrue(report['plan_only'])
        self.assertFalse(report['ready_to_build'])
        self.assertTrue(any('no code-signing identity' in blocker for blocker in report['blockers']))
        self.assertTrue(any('--profile is required' in blocker for blocker in report['blockers']))
        self.assertFalse(report['hardware_acceptance_complete'])
        self.assertFalse(report['protected_supported'])


class ReleaseProfile(unittest.TestCase):
    def profile(self, expires=datetime.datetime(2099, 1, 1), team=TEAM, app=APP,
                platforms=('OSX',)):
        return {'Name': 'ANP helper', 'UUID': 'uuid', 'TeamIdentifier': [team],
                'Entitlements': {'com.apple.application-identifier': app},
                'ExpirationDate': expires, 'Platform': list(platforms)}

    def decode(self, value, capture=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'profile'
            path.write_bytes(b'profile')
            with patch.object(release, 'checked',
                              return_value=SimpleNamespace(stdout=plistlib.dumps(value))) as checked:
                result = release.profile_metadata(path, TEAM, APP)
                if capture is not None:
                    capture.append(checked.call_args.args[0])
                return result

    def test_profile_decoding_does_not_require_a_keychain(self):
        # Installation runs as root, which has no default keychain; `security
        # cms -D` failed there before the bundle could be verified.
        arguments = []
        self.decode(self.profile(), arguments)
        command = arguments[0]
        self.assertEqual(command[:7], ['/usr/bin/openssl', 'cms', '-verify', '-noverify',
                                       '-inform', 'der', '-in'])
        self.assertTrue(command[7].endswith('/profile'))
        self.assertNotIn('/usr/bin/security', command)

    def test_valid_profile_is_accepted(self):
        metadata = self.decode(self.profile())
        self.assertEqual(metadata['application_identifier'], APP)
        self.assertEqual(metadata['team_identifiers'], [TEAM])

    def test_wrong_team_application_platform_or_expiry_is_refused(self):
        cases = [self.profile(team='OTHERTEAM0'), self.profile(app='OTHER.app'),
                 self.profile(platforms=('iOS',)),
                 self.profile(expires=datetime.datetime(2000, 1, 1))]
        for profile in cases:
            with self.subTest(profile=profile), self.assertRaises(release.ReleaseError):
                self.decode(profile)


class BundleVerification(unittest.TestCase):
    def bundle(self, directory, application=APP):
        bundle = Path(directory) / 'ANPIOKey.app'
        contents = bundle / 'Contents'
        (contents / 'MacOS').mkdir(parents=True)
        (contents / 'MacOS' / 'anpio-key').write_bytes(b'helper')
        (contents / 'Info.plist').write_bytes(plistlib.dumps(release.info_plist(application, '0.1.0')))
        (contents / 'embedded.provisionprofile').write_bytes(b'profile')
        return bundle

    def verify(self, bundle, requirement='requirement', **kwargs):
        report = {'signature_prerequisites_passed': True, 'blockers': [],
                  'hardware_acceptance_complete': False, 'protected_supported': False}
        with patch.object(release, 'profile_metadata', return_value={'sha256': 'a' * 64}):
            with patch.object(release.PREFLIGHT, 'inspect', return_value=report):
                with patch.object(release, 'checked', return_value=SimpleNamespace(stdout=b'', stderr=b'')):
                    with patch.object(release, 'code_signature',
                                      return_value={'TeamIdentifier': TEAM, 'Authority': 'Developer ID Application'}):
                        with patch.object(release, 'designated_requirement', side_effect=requirement):
                            return release.verify_bundle(bundle, TEAM, APP, **kwargs)

    def test_verification_never_claims_hardware_acceptance(self):
        with tempfile.TemporaryDirectory() as directory:
            report = self.verify(self.bundle(directory))
        self.assertTrue(report['signature_prerequisites_passed'])
        self.assertFalse(report['hardware_acceptance_complete'])
        self.assertFalse(report['protected_supported'])
        self.assertTrue(report['pending'])

    def test_symlink_in_bundle_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = self.bundle(directory)
            (bundle / 'Contents' / 'extra').symlink_to('/etc/passwd')
            with self.assertRaisesRegex(release.ReleaseError, 'symlink'):
                release.bundle_layout(bundle, TEAM, APP)

    def test_wrong_bundle_identifier_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = self.bundle(directory, application='OTHER.app')
            with self.assertRaisesRegex(release.ReleaseError, 'CFBundleIdentifier'):
                release.bundle_layout(bundle, TEAM, APP)

    def test_upgrade_continuity_is_reported_on_the_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            old = self.bundle(directory)
            new = self.bundle(Path(directory) / 'new')
            report = self.verify(new, previous=old, requirement=lambda path: 'same')
        self.assertEqual(report['upgrade_continuity'],
                         'profile unchanged; Team ID and application identifier match')

    def test_upgrade_without_readable_requirements_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            old = self.bundle(directory)
            new = self.bundle(Path(directory) / 'new')
            with self.assertRaisesRegex(release.ReleaseError, 'designated requirement'):
                self.verify(new, previous=old, requirement=lambda path: None)

    def test_upgrade_with_a_different_designated_requirement_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            old = self.bundle(directory)
            new = self.bundle(Path(directory) / 'new')
            requirement = lambda path: 'old' if str(path).startswith(str(old)) else 'new'
            with self.assertRaisesRegex(release.ReleaseError, 'designated requirement'):
                self.verify(new, previous=old, requirement=requirement)


class DesignatedRequirement(unittest.TestCase):
    def test_requirement_is_read_from_whichever_stream_carries_it(self):
        line = b'designated => identifier "x" and anchor apple generic'
        for stdout, stderr in ((line, b''), (b'', line)):
            with self.subTest(stdout=stdout), \
                 patch.object(release, 'checked', return_value=SimpleNamespace(
                     stdout=stdout, stderr=stderr)):
                self.assertEqual(release.designated_requirement(Path('/bundle')),
                                 'identifier "x" and anchor apple generic')


class SignExample(unittest.TestCase):
    def args(self, directory, digest='correct'):
        binary = Path(directory) / 'se-persistence'
        binary.write_bytes(b'example')
        actual = release.hashlib.sha256(b'example').hexdigest()
        return SimpleNamespace(
            team_id=TEAM, application_id=APP, identity='Developer ID Application',
            profile=None, binary=binary, out=Path(directory) / 'se-persistence.signed',
            sha256=actual if digest == 'correct' else '0' * 64)

    def test_digest_mismatch_is_refused_before_signing(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.args(directory, digest='wrong')
            with patch.object(release, 'resolve_identity',
                              return_value={'sha1': 'A' * 40}):
                with self.assertRaisesRegex(release.ReleaseError, 'digest mismatch'):
                    release.sign_example(args)
            self.assertFalse(args.out.exists())

    def test_signs_with_hardened_runtime_and_the_exact_entitlements(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.args(directory)
            signed = SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
            report = {'signature_prerequisites_passed': True, 'blockers': []}
            with patch.object(release, 'resolve_identity',
                              return_value={'sha1': 'A' * 40}):
                with patch.object(release, 'run', return_value=signed) as started:
                    with patch.object(release.PREFLIGHT, 'inspect', return_value=report):
                        result = release.sign_example(args)
            command = started.call_args[0][0]
            self.assertIn('--options', command)
            self.assertEqual(command[command.index('--options') + 1], 'runtime')
            self.assertIn('--timestamp', command)
            entitlement = Path(command[command.index('--entitlements') + 1])
            self.assertEqual(plistlib.loads(entitlement.read_bytes()),
                             release.entitlements(TEAM, APP))
            self.assertFalse(result['hardware_acceptance_complete'])
            self.assertFalse(result['protected_supported'])
            self.assertEqual(result['source_sha256'], args.sha256)
            self.assertTrue(args.out.is_file())

    def test_failed_signing_leaves_no_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.args(directory)
            failed = SimpleNamespace(returncode=1, stdout=b'', stderr=b'rejected')
            with patch.object(release, 'resolve_identity',
                              return_value={'sha1': 'A' * 40}):
                with patch.object(release, 'run', return_value=failed):
                    with self.assertRaisesRegex(release.ReleaseError, 'codesign failed'):
                        release.sign_example(args)
            self.assertFalse(args.out.exists())


class InstallSafety(unittest.TestCase):
    def test_upgrade_requires_root_before_touching_anything(self):
        args = SimpleNamespace(bundle=Path('/nonexistent'), team_id=TEAM, application_id=APP,
                               profile_sha256=None, destination=Path('/tmp/ANPIOKey.app'),
                               upgrade=True, require_notarized=False)
        with patch.object(release.os, 'geteuid', return_value=501):
            with self.assertRaisesRegex(release.ReleaseError, 'root'):
                release.install(args)

    def test_install_compares_upgrade_against_installed_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / 'source'
            (source / 'Contents' / 'MacOS').mkdir(parents=True)
            (source / 'Contents' / 'MacOS' / 'anpio-key').write_bytes(b'new')
            destination = base / 'ANPIOKey.app'
            destination.mkdir()
            report = {'upgrade_continuity': 'profile unchanged'}
            args = SimpleNamespace(bundle=source, destination=destination, upgrade=True,
                                   team_id=TEAM, application_id=APP, profile_sha256=None,
                                   require_notarized=False)
            with patch.object(release.os, 'geteuid', return_value=0), \
                 patch.object(release.os, 'chown'), \
                 patch.object(release, 'verify_bundle', return_value=report) as verify:
                result = release.install(args)
        self.assertEqual(verify.call_args_list[0].kwargs['previous'], destination)
        self.assertIs(result, report)
        self.assertEqual(result['upgrade_continuity'], 'profile unchanged')

    def test_build_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'ANPIOKey.app'
            out.mkdir()
            args = SimpleNamespace(team_id=TEAM, application_id=APP, identity='x',
                                   profile=Path('/nonexistent'), out=out, binary=None,
                                   require_notarized=False)
            with patch.object(release, 'resolve_identity', return_value={'sha1': 'A' * 40}):
                with patch.object(release, 'profile_metadata', return_value={'sha256': 'a' * 64}):
                    with self.assertRaisesRegex(release.ReleaseError, 'existing output'):
                        release.build(args)


if __name__ == '__main__':
    unittest.main()
