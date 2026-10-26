"""In-place helper upgrade must preserve identity and leave failures recoverable."""
import sys
import hashlib
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'acceptance'))

import acceptance_se

TEAM = 'ABCDEFGHIJ'
APP = TEAM + '.org.anp.keyd.helper'


class FakeReleaseError(Exception):
    pass


def release_stub():
    return SimpleNamespace(ReleaseError=FakeReleaseError,
                           verify_bundle=lambda *args, **kwargs: {})


def make_bundle(path, payload):
    (path / 'Contents/MacOS').mkdir(parents=True)
    (path / 'Contents/MacOS/anpio-key').write_bytes(payload)
    return path


def digest(bundle):
    return hashlib.sha256((Path(bundle) / 'Contents/MacOS/anpio-key').read_bytes()).hexdigest()


class UpgradeExercise(unittest.TestCase):
    def test_release_error_class_is_shared_across_loads(self):
        # Two module instances would define two ReleaseError classes, so the
        # expected refusal would escape exercise_upgrade as a traceback.
        self.assertIs(acceptance_se.load_release_tool(), acceptance_se.load_release_tool())
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        base = Path(self.directory.name)
        self.destination = make_bundle(base / 'InstalledHelper.app', b'old build')
        self.upgrade = make_bundle(base / 'UpgradeHelper.app', b'new build')
        self.old_sha = digest(self.destination)
        self.new_sha = digest(self.upgrade)
        self.checks = SimpleNamespace(base=base, args=SimpleNamespace(
            helper_team_id=TEAM, helper_application_id=APP,
            upgrade_sha256=self.new_sha))

    def tearDown(self):
        self.directory.cleanup()

    def test_failures_are_recoverable_and_success_preserves_identity(self):
        calls = []

        def install(source, destination, team, application, upgrade):
            calls.append(Path(source).name)
            backup = Path(destination).with_name(Path(destination).name + '.previous')
            if len(calls) == 1:
                raise FakeReleaseError('code signature invalid')
            if len(calls) == 2:
                self.assertTrue(backup.is_dir())
                raise FakeReleaseError('refusing to replace existing backup ' + str(backup))
            shutil.move(str(destination), str(backup))
            shutil.copytree(source, destination)
            return {'upgrade_continuity': 'profile unchanged; Team ID and application '
                    'identifier match', 'candidate_sha256': self.new_sha}

        with patch.object(acceptance_se, 'load_release_tool', return_value=release_stub()), \
             patch.object(acceptance_se, 'install_helper', side_effect=install):
            acceptance_se.Checks.exercise_upgrade(self.checks, self.destination, self.upgrade)

        self.assertEqual(calls, ['TamperedHelper.app', 'UpgradeHelper.app',
                                 'UpgradeHelper.app'])
        self.assertEqual(digest(self.destination), self.new_sha)
        self.assertEqual(digest(self.destination.with_name('InstalledHelper.app.previous')),
                         self.old_sha)

    def test_upgrade_without_continuity_is_refused(self):
        calls = []

        def install(source, destination, team, application, upgrade):
            calls.append(1)
            if len(calls) == 1:
                raise FakeReleaseError('code signature invalid')
            if len(calls) == 2:
                raise FakeReleaseError('refusing to replace existing backup')
            backup = Path(destination).with_name(Path(destination).name + '.previous')
            shutil.move(str(destination), str(backup))
            shutil.copytree(source, destination)
            return {'upgrade_continuity': None, 'candidate_sha256': self.new_sha}

        with patch.object(acceptance_se, 'load_release_tool', return_value=release_stub()), \
             patch.object(acceptance_se, 'install_helper', side_effect=install), \
             self.assertRaisesRegex(ValueError, 'continuity'):
            acceptance_se.Checks.exercise_upgrade(self.checks, self.destination, self.upgrade)

    def test_backup_collision_must_be_the_refusal_reason(self):
        def install(source, destination, team, application, upgrade):
            if len(install.calls) == 0:
                install.calls.append(1)
                raise FakeReleaseError('bad source')
            raise FakeReleaseError('some other failure')

        install.calls = []
        with patch.object(acceptance_se, 'load_release_tool', return_value=release_stub()), \
             patch.object(acceptance_se, 'install_helper', side_effect=install), \
             self.assertRaisesRegex(FakeReleaseError, 'other failure'):
            acceptance_se.Checks.exercise_upgrade(self.checks, self.destination, self.upgrade)


if __name__ == '__main__':
    unittest.main()
