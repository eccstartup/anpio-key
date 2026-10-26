"""Pure macOS preview bootstrap policy tests; no accounts, services or root."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('mac_bootstrap', Path(__file__).resolve().parents[1] / 'bootstrap.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Policy(unittest.TestCase):
    def test_empty_body_methods_use_no_body_budget(self):
        policy = module.build_policy('https://api.example.com/v1/status', ['get', 'HEAD'],
                                     4096, 2, 10)
        self.assertEqual(policy['origin'], 'https://api.example.com')
        self.assertEqual(policy['methods'], ['GET', 'HEAD'])
        self.assertEqual(policy['paths'], ['/v1/status'])
        self.assertEqual(policy['body'], {'mode': 'empty', 'max_bytes': 0})
        self.assertEqual(policy['grant_limits'], {'max_duration_seconds': 172800, 'max_uses': 10})

    def test_body_methods_keep_bounded_budget(self):
        policy = module.build_policy('https://api.example.com/v1/items', ['POST'],
                                     2048, 1, 5)
        self.assertEqual(policy['body'], {'mode': 'bounded', 'max_bytes': 2048})

    def test_mixed_body_and_empty_methods_are_refused(self):
        with self.assertRaises(SystemExit):
            module.build_policy('https://api.example.com/', ['GET', 'POST'], 10, 1, 1)

    def test_default_port_and_query_handling(self):
        self.assertEqual(module.parse_target('https://API.example.com:443/a?b=1'),
                         ('https://api.example.com', '/a', 'b=1'))
        self.assertEqual(module.parse_target('https://api.example.com:8443/'),
                         ('https://api.example.com:8443', '/', ''))
        policy = module.build_policy('https://api.example.com/a?x=1', ['GET'], 1, 1, 1)
        self.assertEqual(policy['query'], {'mode': 'exact', 'value': 'x=1'})

    def test_invalid_targets_are_refused(self):
        for target in ('http://api.example.com/', 'https://user:pass@api.example.com/',
                       'https://api.example.com/#frag', 'https:///missing-host',
                       'https://api.example.com:notaport/'):
            with self.assertRaises(SystemExit):
                module.parse_target(target)


class Management(unittest.TestCase):
    def setUp(self):
        self.saved = {name: vars(module).get(name) for name in ('ADMIN', 'BINARY', 'CONFIG')}
        module.ADMIN = 'operator'
        module.BINARY = Path('/Library/ANPIOKey/bin/anpio-key')
        module.CONFIG = Path('/Library/ANPIOKey/service.json')
        self.addCleanup(self.restore)

    def restore(self):
        for name, value in self.saved.items():
            if value is None:
                vars(module).pop(name, None)
            else:
                setattr(module, name, value)

    def test_management_never_runs_as_root(self):
        command = module.admin_command('status')
        self.assertEqual(command[:5], ['/usr/bin/sudo', '-n', '-u', 'operator', '--'])
        self.assertEqual(command[5:], ['/Library/ANPIOKey/bin/anpio-key', 'admin',
                                       '--config', '/Library/ANPIOKey/service.json', 'status'])

    def test_non_ok_reply_is_fatal(self):
        reply = NS(returncode=0, stdout='{"code":"ADMIN_REQUIRED"}\n', stderr='')
        with patch.object(module, 'admin_raw', return_value=reply):
            with self.assertRaises(SystemExit):
                module.admin('status')

    def test_command_failure_is_fatal(self):
        reply = NS(returncode=1, stdout='', stderr='denied')
        with patch.object(module, 'admin_raw', return_value=reply):
            with self.assertRaises(SystemExit):
                module.admin('status')

    def test_status_reply_is_parsed_from_last_line(self):
        reply = NS(returncode=0, stdout='progress\n{"code":"OK","signing_available":true}\n', stderr='')
        with patch.object(module, 'admin_raw', return_value=reply):
            self.assertTrue(module.admin('status')['signing_available'])


class ServiceRecovery(unittest.TestCase):
    def test_bootstrap_falls_back_to_kickstart(self):
        failed = NS(returncode=1, stdout='already loaded', stderr='')
        started = NS(returncode=0, stdout='', stderr='')
        with patch.object(module.subprocess, 'run', side_effect=[failed, started]) as called:
            self.assertTrue(module.restore_service())
        self.assertEqual(called.call_args_list[0].args[0][:3], ['/bin/launchctl', 'bootstrap', 'system'])
        self.assertEqual(called.call_args_list[1].args[0][:3], ['/bin/launchctl', 'kickstart', 'system/org.anpio-key.local'])

    def test_failed_recovery_is_reported(self):
        failed = NS(returncode=1, stdout='', stderr='')
        with patch.object(module.subprocess, 'run', return_value=failed):
            self.assertFalse(module.restore_service())


class InstallIntegration(unittest.TestCase):
    def test_install_script_offers_bootstrap_on_macos(self):
        script = (Path(__file__).resolve().parents[3] / 'install.sh').read_text()
        self.assertIn('deploy/macos/bootstrap.py', script)
        self.assertIn('--agent-user "_anpagent"', script)
        self.assertNotIn('--bootstrap 目前只支持 Linux', script)
        self.assertIn('deploy/linux/bootstrap.py', script)


if __name__ == '__main__':
    unittest.main()
