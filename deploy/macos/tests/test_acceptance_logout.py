"""Logout requires a new graphical audit session, not just console UID changes."""
import sys
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch, call
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'acceptance'))

from acceptance_console import wait_logout
import acceptance_graphical as graphical
import acceptance_se
import acceptance_signing

spec = importlib.util.spec_from_file_location('logout_launcher', Path(__file__).resolve().parents[1] / 'acceptance' / 'launch-logout-test.py')
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)

spec = importlib.util.spec_from_file_location('post_relogin', Path(__file__).resolve().parents[1] / 'acceptance' / 'post-relogin.py')
post_relogin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(post_relogin)


class Logout(unittest.TestCase):
    def run_logout(self, users, times, session=200, check=None):
        users, times = iter(users), iter([*times, times[-1]])
        return wait_logout(501, 100, check or Mock(), lambda: session,
            read_uid=lambda: next(users), clock=lambda: next(times), pause=lambda _: None)

    def test_new_session_after_checks_at_login_window(self):
        check = Mock()
        self.assertEqual(self.run_logout([501, 0, 0, 501], [0, 1, 7, 8], check=check), 200)
        check.assert_called_once_with()

    def test_fast_user_switch_back_is_not_logout(self):
        with self.assertRaisesRegex(ValueError, 'did not change'):
            self.run_logout([501, 0, 0, 501], [0, 1, 7, 8], session=100)

    def test_other_desktop_is_not_logout(self):
        with self.assertRaisesRegex(ValueError, 'unexpected console UID'):
            self.run_logout([501, 504], [0, 1])

    def test_invalid_new_audit_session_is_refused(self):
        for value in (0, 0xffffffff):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'did not change'):
                self.run_logout([501, 0, 0, 501], [0, 1, 7, 8], session=value)

    def test_login_too_soon_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'at least six seconds'):
            self.run_logout([501, 0, 501], [0, 1, 2])

    def test_logout_start_is_bounded_but_generous(self):
        with self.assertRaisesRegex(ValueError, 'within 300 seconds'):
            self.run_logout([501, 501], [0, 1, 301])

    def test_slow_logout_does_not_consume_the_relogin_window(self):
        check = Mock()
        self.assertEqual(self.run_logout([501, 501, 0, 0, 501], [0, 200, 201, 207, 208],
                                         check=check), 200)
        check.assert_called_once_with()

    def test_login_window_time_is_bounded(self):
        with self.assertRaisesRegex(ValueError, 'from the login window'):
            self.run_logout([501, 0, 0, 501], [0, 1, 92, 93])

    def test_clock_rollback_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'backwards'):
            self.run_logout([501, 0], [0, 2, 1])

    def test_away_check_failure_stops_acceptance(self):
        with self.assertRaisesRegex(ValueError, 'old authority remains'):
            self.run_logout([501, 0, 0], [0, 1, 7],
                check=Mock(side_effect=ValueError('old authority remains')))

    def test_initial_console_must_be_administrator(self):
        with self.assertRaisesRegex(ValueError, 'initially own'):
            self.run_logout([504], [0])


class SystemJob(unittest.TestCase):
    def test_diagnostic_job_selects_no_logout_diagnostic_branch(self):
        spec = launcher.job_spec(Path('/Library/ANPIOKeyLogoutChecks-test'),
            Path('/usr/bin/python3'), [], diagnostic=True)
        self.assertIn('--logout-diagnostics', spec['ProgramArguments'])
        self.assertFalse(spec['KeepAlive'])

    def test_probe_layers_are_opt_in(self):
        stage = Path('/Library/ANPIOKeyLogoutChecks-example')
        plain = launcher.job_spec(stage, Path('/usr/bin/python3'), [])
        enabled = launcher.job_spec(stage, Path('/usr/bin/python3'), [], post_relogin_probes=True)
        self.assertNotIn('--post-relogin-probes', plain['ProgramArguments'])
        self.assertIn('--post-relogin-probes', enabled['ProgramArguments'])

    def test_one_shot_root_system_job_has_no_restart_or_boot_install(self):
        stage = Path('/Library/ANPIOKeyLogoutChecks-example')
        job = launcher.job_spec(stage, Path('/usr/bin/python3'), ['--candidate-binary', '/fixture'])
        self.assertFalse(job['KeepAlive'])
        self.assertTrue(job['SessionCreate'])
        self.assertTrue(job['LaunchOnlyOnce'])
        self.assertEqual(job['WorkingDirectory'], '/')
        self.assertNotIn('UserName', job)  # root runner drops each child's credentials
        self.assertEqual(job['ProgramArguments'][3:5], ['--se-ending', 'logout'])
        self.assertEqual(job['StandardOutPath'], str(stage / 'host.log'))
        self.assertEqual(job['StandardErrorPath'], str(stage / 'host.log'))


class PostReloginProbes(unittest.TestCase):
    def checks(self, broker):
        return SimpleNamespace(env={}, admin=SimpleNamespace(pw_uid=501),
            agent=SimpleNamespace(pw_uid=601), credentials=lambda user: {'user': user.pw_uid},
            args=SimpleNamespace(process_broker=broker), base=Path('/nonexistent'))

    def test_broker_desync_after_timeout_skips_remaining_probes(self):
        broker = Mock()
        broker.run.side_effect = [subprocess.CompletedProcess([], 0, 'probe-ok', ''),
            subprocess.TimeoutExpired('probe', 6), subprocess.CompletedProcess([], 0, 'probe-ok', '')]
        with patch.object(acceptance_se.subprocess, 'run',
                          side_effect=subprocess.TimeoutExpired('probe', 6)), \
             patch.object(acceptance_se, 'fresh_job_probe',
                          return_value=subprocess.CompletedProcess([], 1, '', '')), \
             patch('builtins.print') as output:
            acceptance_se.log_post_relogin_probes(self.checks(broker))
        lines = [item.args[0] for item in output.call_args_list]
        self.assertTrue(any('FAIL post-relogin probe survivor-true' in line for line in lines))
        self.assertTrue(any('PASS post-relogin probe broker-root-true' in line for line in lines))
        self.assertTrue(any('FAIL post-relogin probe broker-admin-python' in line for line in lines))
        # A timed-out broker request leaves a late reply in the pipe; later
        # broker probes would read stale protocol state. The launchd layer
        # does not share that pipe and is still attempted.
        self.assertFalse(any('broker-agent-python' in line for line in lines))
        self.assertTrue(any('FAIL post-relogin probe launchd-fresh-job' in line for line in lines))
        self.assertEqual(broker.run.call_count, 2)

    def test_successful_broker_probes_reach_every_layer(self):
        broker = Mock()
        broker.run.return_value = subprocess.CompletedProcess([], 0, 'probe-ok', '')
        with patch.object(acceptance_se.subprocess, 'run',
                          return_value=subprocess.CompletedProcess([], 0, '', '')), \
             patch.object(acceptance_se, 'fresh_job_probe',
                          return_value=subprocess.CompletedProcess([], 0, '', '')), \
             patch('builtins.print') as output:
            acceptance_se.log_post_relogin_probes(self.checks(broker))
        lines = [item.args[0] for item in output.call_args_list]
        for label in ('survivor-true', 'survivor-python', 'broker-root-true',
                      'broker-admin-python', 'broker-agent-python', 'launchd-fresh-job'):
            self.assertTrue(any('PASS post-relogin probe ' + label in line for line in lines), label)
        self.assertEqual(broker.run.call_count, 3)

    def test_fresh_job_without_marker_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(acceptance_se.subprocess, 'run',
                          return_value=subprocess.CompletedProcess([], 0, '', '')), \
             patch.object(acceptance_se.time, 'monotonic', side_effect=[0, 0, 100]), \
             patch.object(acceptance_se.time, 'sleep'):
            result = acceptance_se.fresh_job_probe(Path(directory))
        self.assertEqual(result.returncode, 1)


class GraphicalBridge(unittest.TestCase):
    def test_runner_session_must_be_distinct_nongraphical_and_unchanged(self):
        valid = {'session':123, 'attributes':0}
        with patch.object(graphical, 'audit_context', return_value=valid):
            self.assertEqual(graphical.require_runner_session(500, valid), valid)
            with self.assertRaisesRegex(ValueError, 'changed'):
                graphical.require_runner_session(500, {'session':122,'attributes':0})
        for context in ({'session':500,'attributes':0}, {'session':0,'attributes':0},
                        {'session':123,'attributes':0x10}):
            with patch.object(graphical, 'audit_context', return_value=context):
                with self.assertRaisesRegex(ValueError, 'own non-graphical'):
                    graphical.require_runner_session(500)

    def state(self):
        return {'UID':501, 'SessionInfo':[{'kCGSSessionUserIDKey':501,
            'kCGSSessionOnConsoleKey':True, 'kCGSessionLoginDoneKey':True,
            'kCGSSessionAuditIDKey':105604, 'kSCSecuritySessionID':105604}]}

    def test_native_console_requires_unique_active_completed_exact_user(self):
        import copy
        state = self.state()
        self.assertEqual(graphical.console_session_id(state, 501), 105604)
        bad = []
        wrong = copy.deepcopy(state); wrong['UID'] = 504; bad.append(wrong)
        duplicate = copy.deepcopy(state); duplicate['SessionInfo'] *= 2; bad.append(duplicate)
        for field, value in [('kCGSSessionUserIDKey',504), ('kCGSSessionOnConsoleKey',False),
                ('kCGSessionLoginDoneKey',False), ('kSCSecuritySessionID',100),
                ('kCGSSessionAuditIDKey',0), ('kCGSSessionAuditIDKey',True)]:
            wrong = copy.deepcopy(state); wrong['SessionInfo'][0][field] = value; bad.append(wrong)
        for item in bad:
            with self.assertRaises(ValueError):
                graphical.console_session_id(item, 501)

    def test_native_readiness_does_not_spawn_any_subprocess(self):
        with patch.object(graphical, 'console_state', side_effect=[ValueError('not ready'),self.state()]), \
             patch.object(graphical, 'current_session', return_value=105604) as validate, \
             patch.object(graphical.subprocess, 'run') as run, \
             patch.object(graphical.time, 'sleep'):
            self.assertEqual(graphical.relogin_session(SimpleNamespace(pw_uid=501)),105604)
        validate.assert_called_once_with(105604)
        run.assert_not_called()

    def test_bootstrap_readiness_deadline_is_bounded(self):
        with patch.object(graphical.time, 'monotonic', side_effect=[0, 21]):
            with self.assertRaisesRegex(ValueError, 'readiness timed out'):
                graphical.relogin_session(SimpleNamespace(pw_uid=501))

    def test_drops_credentials_before_exec(self):
        with patch.object(graphical.os, 'geteuid', return_value=0), \
             patch.object(graphical.sys, 'argv', ['bridge', '/config', '501', '/helper', 'generate-se']), \
             patch.object(graphical.Path, 'read_text', return_value='{"admin_uids":[501],"admin_gid":602}'), \
             patch.object(graphical.pwd, 'getpwuid', return_value=SimpleNamespace(pw_gid=20)), \
             patch.object(graphical, 'current_session', return_value=123), \
             patch.object(graphical.os, 'setgroups') as groups, \
             patch.object(graphical.os, 'setgid') as gid, \
             patch.object(graphical.os, 'setuid') as uid, \
             patch.object(graphical.os, 'execv') as execute:
            ordering = Mock()
            for name, item in [('groups', groups), ('gid', gid), ('uid', uid), ('execute', execute)]:
                ordering.attach_mock(item, name)
            graphical.main()
        self.assertEqual(ordering.mock_calls, [call.groups([20, 602]), call.gid(20),
            call.uid(501), call.execute('/helper', ['/helper', 'generate-se'])])

    def test_nonadministrator_and_root_targets_are_refused(self):
        for target in ('0', '601'):
            with patch.object(graphical.os, 'geteuid', return_value=0), \
                 patch.object(graphical.sys, 'argv', ['bridge', '/config', target, '/helper']), \
                 patch.object(graphical.Path, 'read_text', return_value='{"admin_uids":[501]}'):
                with self.assertRaisesRegex(ValueError, 'configured non-root administrator'):
                    graphical.main()


class GrantWindow(unittest.TestCase):
    def checks(self, end):
        return acceptance_se.Checks(Path('/nonexistent'), {}, Path('/nonexistent'),
            SimpleNamespace(se_ending=end), None, None, None, None, {}, None)

    def test_approval_never_exceeds_the_published_policy_limit(self):
        for ending, seconds in (('logout', 900), ('reboot', 900), ('upgrade', 240),
                                ('kill', 240)):
            checks = self.checks(ending)
            limit = checks.policy_content()['grant_limits']['max_duration_seconds']
            self.assertEqual(checks.grant_limit(), limit)
            self.assertEqual(checks.approval_seconds(ending), seconds)
            self.assertLessEqual(seconds, limit)

    def test_default_ending_keeps_the_short_policy_limit(self):
        checks = self.checks('kill')
        self.assertEqual(checks.policy_content()['grant_limits']['max_duration_seconds'], 300)


class PostReloginState(unittest.TestCase):
    def checks(self, base):
        return SimpleNamespace(base=base, config={'instance_id': 'x'}, path=base / 'service.json',
            args=SimpleNamespace(binary=Path('/usr/local/bin/anpio-key')),
            admin=SimpleNamespace(pw_uid=501), agent=SimpleNamespace(pw_uid=601),
            key={'key_id': 'k'}, policy_id='p', env={'PATH': '/usr/bin'},
            credentials=lambda user: {'user': user.pw_uid, 'group': user.pw_uid,
                                      'extra_groups': [20]})

    def test_state_is_root_only_and_stale_result_is_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'post-relogin-result.json').write_text('{"ok": true}')
            state = acceptance_se.write_post_relogin_state(self.checks(base), {'operation': 'X'},
                                                           {'operation_id': 'o', 'digest': 'd'})
            self.assertEqual(state.stat().st_mode & 0o777, 0o600)
            self.assertFalse((base / 'post-relogin-result.json').exists())
            loaded = json.loads(state.read_text())
            self.assertEqual(loaded['admin_uid'], 501)
            self.assertEqual(loaded['request'], {'operation': 'X'})

    def test_launcher_is_fixed_and_untrusted_entries_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / 'launcher.sh'
            with patch.object(acceptance_se, 'POST_RELOGIN_LAUNCHER', target):
                made = acceptance_se.write_post_relogin_launcher(base / 'state.json')
                self.assertEqual(made, target)
                self.assertEqual(target.stat().st_mode & 0o777, 0o700)
                content = target.read_text()
                # The state is in the temporary service directory, but the
                # checker module is beside this one; pointing at the state's
                # directory would make the command die with a missing file.
                self.assertIn(str(Path(acceptance_se.__file__).resolve().parent / 'post-relogin.py'),
                              content)
                self.assertNotIn(str(base / 'post-relogin.py'), content)
                self.assertIn(str(base / 'state.json'), content)
                self.assertIn('no pending logout acceptance', content)
            link = base / 'link.sh'
            link.symlink_to(target)
            with patch.object(acceptance_se, 'POST_RELOGIN_LAUNCHER', link), \
                 self.assertRaisesRegex(ValueError, 'untrusted'):
                acceptance_se.write_post_relogin_launcher(base / 'state.json')

    def test_state_schema_is_exact(self):
        complete = {name: {} for name in post_relogin.SCHEMA}
        complete['pending'], complete['key'] = {}, {}
        post_relogin.validate_state(complete)
        missing = dict(complete)
        missing.pop('request')
        with self.assertRaisesRegex(ValueError, 'schema'):
            post_relogin.validate_state(missing)
        wrong = dict(complete)
        wrong['pending'] = []
        with self.assertRaisesRegex(ValueError, 'value type'):
            post_relogin.validate_state(wrong)

    def test_checker_requires_root(self):
        with patch.object(post_relogin.os, 'geteuid', return_value=501):
            with self.assertRaisesRegex(ValueError, 'requires root'):
                post_relogin.run_checks({})


class PostReloginResult(unittest.TestCase):
    def write(self, base, outcome):
        path = base / 'post-relogin-result.json'
        path.write_text(json.dumps(outcome))
        return path

    def test_success_is_read_after_root_owned_check(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            self.write(base, {'ok': True, 'result': {'session': 105900}})
            with patch.object(Path, 'lstat',
                    return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0)):
                outcome = acceptance_se.wait_for_post_relogin_result(base, timeout=1)
            self.assertEqual(outcome['result']['session'], 105900)

    def test_failure_and_untrusted_result_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            self.write(base, {'ok': False, 'error': 'KEY_LOCKED missing'})
            with patch.object(Path, 'lstat',
                    return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0)), \
                 self.assertRaisesRegex(ValueError, 'KEY_LOCKED missing'):
                acceptance_se.wait_for_post_relogin_result(base, timeout=1)
            for mode, uid in ((stat.S_IFREG | 0o666, 0), (stat.S_IFLNK | 0o600, 0),
                              (stat.S_IFREG | 0o600, 501)):
                with patch.object(Path, 'lstat',
                        return_value=SimpleNamespace(st_mode=mode, st_uid=uid)), \
                     self.assertRaisesRegex(ValueError, 'root-owned regular file'):
                    acceptance_se.wait_for_post_relogin_result(base, timeout=1)

    def test_missing_result_is_bounded_and_names_the_command(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(acceptance_se.time, 'monotonic', side_effect=[0, 2]), \
             patch.object(acceptance_se.time, 'sleep'):
            with self.assertRaisesRegex(ValueError, 'post-relogin checker did not run'):
                acceptance_se.wait_for_post_relogin_result(Path(directory), timeout=1)
