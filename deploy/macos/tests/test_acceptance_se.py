"""Privileged bundle-copy guards; these tests make no hardware claims."""
import sys
from pathlib import Path
import tempfile
import unittest
import hashlib
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'acceptance'))

from acceptance_se import validate_bundle, sleep_times, verify_sleep_transition, wait_for_sleep_transition
import acceptance_signing


class BundleChecks(unittest.TestCase):
    def test_prepare_preserves_bundle_from_executable_path(self):
        with tempfile.TemporaryDirectory() as root:
            bundle = self.fixture(root)
            macos = bundle / 'Contents/MacOS'
            macos.mkdir()
            binary = macos / 'anpio-key'
            binary.write_bytes(b'fixture-executable')
            base = Path(root) / 'runtime'
            base.mkdir()
            args = SimpleNamespace(signing_helper=binary,
                helper_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                se_login_bundle=bundle)
            class ReachedGeneration(Exception):
                pass
            def run(admin, helper, mode, source):
                self.assertEqual(helper, base / 'Fixture.app/Contents/MacOS/anpio-key')
                self.assertEqual(mode, 'generate-se')
                self.assertEqual(helper.read_bytes(), binary.read_bytes())
                self.assertTrue((base / 'Fixture.app/Contents/embedded.provisionprofile').is_file())
                raise ReachedGeneration()
            with patch.object(acceptance_signing.os, 'chown'):
                with self.assertRaises(ReachedGeneration):
                    acceptance_signing.prepare(base, {}, args,
                        SimpleNamespace(pw_uid=501, pw_gid=20), None, run)

    def fixture(self, root):
        bundle = Path(root) / 'Fixture.app'
        contents = bundle / 'Contents'
        contents.mkdir(parents=True)
        (contents / 'embedded.provisionprofile').write_bytes(b'test-profile')
        return bundle

    def test_profile_required(self):
        with tempfile.TemporaryDirectory() as root:
            bundle = self.fixture(root)
            validate_bundle(bundle)
            (bundle / 'Contents/embedded.provisionprofile').unlink()
            with self.assertRaises(ValueError):
                validate_bundle(bundle)

    def test_links_refused_before_privileged_copy(self):
        with tempfile.TemporaryDirectory() as root:
            bundle = self.fixture(root)
            (bundle / 'Contents/link').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):
                validate_bundle(bundle)

    def test_entry_bound(self):
        with tempfile.TemporaryDirectory() as root:
            bundle = self.fixture(root)
            for index in range(257):
                (bundle / str(index)).touch()
            with self.assertRaises(ValueError):
                validate_bundle(bundle)


class SleepEvidence(unittest.TestCase):
    def test_kernel_format_and_microseconds(self):
        result = sleep_times('kern.sleeptime: { sec = 100, usec = 500000 } date\n'
                             'kern.waketime: { sec = 110, usec = 250000 } date\n')
        self.assertEqual(result, {'sleeptime': 100.5, 'waketime': 110.25})

    def test_unavailable_or_invalid_timestamp_is_not_sleep(self):
        for text in ('permission denied', 'kern.sleeptime: { sec = 1, usec = 1000000 }\n'
                     'kern.waketime: { sec = 3, usec = 0 }'):
            with self.assertRaises(ValueError):
                sleep_times(text)

    def test_only_new_bounded_sleep_pair_is_accepted(self):
        before = {'sleeptime': 10, 'waketime': 20}
        verify_sleep_transition(before, {'sleeptime': 102, 'waketime': 110}, 100, 115)
        for after, end in [
            (before, 115),
            ({'sleeptime': 99, 'waketime': 110}, 115),
            ({'sleeptime': 102, 'waketime': 104}, 115),
            ({'sleeptime': 102, 'waketime': 120}, 115),
            ({'sleeptime': 102, 'waketime': 110}, 195),
        ]:
            with self.assertRaises(ValueError):
                verify_sleep_transition(before, after, 100, end)


class AutomaticWakeDetection(unittest.TestCase):
    def test_maintenance_wake_is_logged_and_does_not_end_long_observation(self):
        before = {'sleeptime': 10, 'waketime': 20}
        short = {'sleeptime': 102, 'waketime': 150}
        long = {'sleeptime': 200, 'waketime': 1160}
        reads = iter([short, short, long])
        ticks = iter([151, 152, 1161])
        observations = []
        self.assertEqual(wait_for_sleep_transition(before, 100,
            read_times=lambda: next(reads), clock=lambda: next(ticks),
            pause=lambda _: None, long_sleep=True,
            observe=lambda pair, end: observations.append((pair, end))), (long, 1161))
        self.assertEqual(observations, [(short, 151), (long, 1161)])

    def test_short_sleep_cannot_pass_by_waiting_past_deadline(self):
        before = {'sleeptime': 10, 'waketime': 20}
        short = {'sleeptime': 102, 'waketime': 150}
        ticks = iter([1100, 2201])
        with self.assertRaisesRegex(ValueError, 'within 2100 seconds'):
            wait_for_sleep_transition(before, 100, read_times=lambda: short,
                clock=lambda: next(ticks), pause=lambda _: None, long_sleep=True)

    def test_invalid_short_pair_fails_in_long_mode(self):
        with self.assertRaisesRegex(ValueError, 'outside acceptance interval'):
            wait_for_sleep_transition({'sleeptime': 10, 'waketime': 20}, 100,
                read_times=lambda: {'sleeptime': 99, 'waketime': 150},
                clock=lambda: 151, pause=lambda _: None, long_sleep=True)

    def test_long_sleep_requires_kernel_sleep_beyond_original_deadline(self):
        before = {'sleeptime': 10, 'waketime': 20}
        verify_sleep_transition(before, {'sleeptime': 102, 'waketime': 1062},
                                100, 1065, long_sleep=True)
        for after, end in [
            ({'sleeptime': 102, 'waketime': 1002}, 1005),
            # Long elapsed wall time with only short kernel sleep is insufficient.
            ({'sleeptime': 102, 'waketime': 110}, 1065),
            ({'sleeptime': 102, 'waketime': 1062}, 2201),
            ({'sleeptime': 99, 'waketime': 1062}, 1065),
            (before, 1065),
        ]:
            with self.assertRaises(ValueError):
                verify_sleep_transition(before, after, 100, end, long_sleep=True)

    def test_long_sleep_wait_uses_extended_window(self):
        before = {'sleeptime': 10, 'waketime': 20}
        after = {'sleeptime': 102, 'waketime': 1062}
        reads = iter([before, after])
        ticks = iter([200, 1065])
        self.assertEqual(wait_for_sleep_transition(before, 100,
            read_times=lambda: next(reads), clock=lambda: next(ticks),
            pause=lambda _: None, long_sleep=True), (after, 1065))

    def test_long_sleep_timeout_is_bounded(self):
        before = {'sleeptime': 10, 'waketime': 20}
        with self.assertRaisesRegex(ValueError, 'within 2100 seconds'):
            wait_for_sleep_transition(before, 100, read_times=lambda: before,
                clock=lambda: 2201, pause=lambda _: None, long_sleep=True)

    def test_wake_resumes_checks_without_terminal_input(self):
        before = {'sleeptime': 10, 'waketime': 20}
        after = {'sleeptime': 102, 'waketime': 110}
        reads = iter([before, after])
        ticks = iter([101, 111])
        pauses = []
        self.assertEqual(wait_for_sleep_transition(before, 100,
            read_times=lambda: next(reads), clock=lambda: next(ticks), pause=pauses.append),
            (after, 111))
        self.assertEqual(pauses, [.5])

    def test_no_sleep_times_out_without_reading_stdin(self):
        before = {'sleeptime': 10, 'waketime': 20}
        with self.assertRaisesRegex(ValueError, 'within 90 seconds'):
            wait_for_sleep_transition(before, 100, read_times=lambda: before,
                                      clock=lambda: 191, pause=lambda _: None)

    def test_clock_rollback_fails_closed(self):
        before = {'sleeptime': 10, 'waketime': 20}
        with self.assertRaisesRegex(ValueError, 'backwards'):
            wait_for_sleep_transition(before, 100, read_times=lambda: before,
                                      clock=lambda: 99, pause=lambda _: None)
