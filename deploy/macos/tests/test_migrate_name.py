"""Pure rename-plan tests; no accounts, services or system files touched."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('mac_migrate_name', Path(__file__).resolve().parents[1] / 'migrate-name.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Rebase(unittest.TestCase):
    def test_the_root_itself(self):
        self.assertEqual(module.rebase('/Library/ANPKeyd'), '/Library/ANPIOKey')

    def test_children_keep_their_tail(self):
        self.assertEqual(module.rebase('/Library/ANPKeyd/state/vaults'), '/Library/ANPIOKey/state/vaults')

    def test_unrelated_paths_are_untouched(self):
        self.assertEqual(module.rebase('/var/lib/anp-keyd'), '/var/lib/anp-keyd')
        self.assertEqual(module.rebase('/Library/ANPKeydBackup'), '/Library/ANPKeydBackup')


class Config(unittest.TestCase):
    def test_paths_move_and_identifiers_do_not(self):
        config = {'instance_id': 'abc', 'service_uid': 601,
                  'state_dir': '/Library/ANPKeyd/state',
                  'sign_socket': '/Library/ANPKeyd/sign/sign.sock',
                  'admin_socket': '/Library/ANPKeyd/admin/admin.sock'}
        updated = module.rewrite_config(config)
        self.assertEqual(updated['state_dir'], '/Library/ANPIOKey/state')
        self.assertEqual(updated['sign_socket'], '/Library/ANPIOKey/sign/sign.sock')
        self.assertEqual(updated['admin_socket'], '/Library/ANPIOKey/admin/admin.sock')
        self.assertEqual(updated['instance_id'], 'abc')
        self.assertEqual(updated['service_uid'], 601)
        self.assertEqual(config['state_dir'], '/Library/ANPKeyd/state')


class Job(unittest.TestCase):
    def job(self):
        return {'Label': 'org.anp-keyd.local', 'UserName': '_anpkeyd',
                'ProgramArguments': ['/Library/ANPKeyd/bin/anp-keyd', 'serve-protected',
                                     '--config', '/Library/ANPKeyd/service.json'],
                'WorkingDirectory': '/Library/ANPKeyd', 'RunAtLoad': True}

    def test_the_label_moves(self):
        self.assertEqual(module.rewrite_job(self.job())['Label'], 'org.anpio-key.local')

    def test_program_and_working_directory_move(self):
        updated = module.rewrite_job(self.job())
        self.assertEqual(updated['ProgramArguments'],
                         ['/Library/ANPIOKey/bin/anp-keyd', 'serve-protected',
                          '--config', '/Library/ANPIOKey/service.json'])
        self.assertEqual(updated['WorkingDirectory'], '/Library/ANPIOKey')

    def test_the_record_name_is_left_to_directory_services(self):
        self.assertEqual(module.rewrite_job(self.job())['UserName'], '_anpkeyd')

    def test_the_input_is_not_mutated(self):
        job = self.job()
        module.rewrite_job(job)
        self.assertEqual(job['WorkingDirectory'], '/Library/ANPKeyd')


class Accounts(unittest.TestCase):
    def test_user_and_group_of_the_same_name_rename_once_each(self):
        plan = module.account_plan({'_anpkeyd', '_anpkeyd_sign'}, {'_anpkeyd', '_anpkeyd_admin'})
        self.assertIn(('both', '_anpkeyd', '_anpio'), plan)
        self.assertIn(('user', '_anpkeyd_sign', '_anpio_sign'), plan)
        self.assertIn(('group', '_anpkeyd_admin', '_anpio_admin'), plan)

    def test_already_migrated_records_produce_nothing(self):
        self.assertEqual(module.account_plan({'_anpio', '_anpagent'}, {'_anpio', '_anpio_sign'}), [])

    def test_commands_target_the_right_record_class(self):
        plan = [('both', '_anpkeyd', '_anpio'), ('user', '_anpkeyd_sign', '_anpio_sign')]
        commands = module.rename_commands(plan)
        self.assertEqual(commands, [
            ['/usr/bin/dscl', '.', '-change', '/Users/_anpkeyd', 'RecordName', '_anpkeyd', '_anpio'],
            ['/usr/bin/dscl', '.', '-change', '/Groups/_anpkeyd', 'RecordName', '_anpkeyd', '_anpio'],
            ['/usr/bin/dscl', '.', '-change', '/Users/_anpkeyd_sign', 'RecordName', '_anpkeyd_sign', '_anpio_sign'],
        ])


class SocketWait(unittest.TestCase):
    def test_a_missing_socket_is_not_waited_on(self):
        module.wait_for_sockets_gone({'sign_socket': '/nonexistent/sign.sock',
                                      'admin_socket': '/nonexistent/admin.sock'}, timeout=0.1)


if __name__ == '__main__':
    unittest.main()
