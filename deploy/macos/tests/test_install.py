"""Pure installer policy tests; no accounts, services, or system files modified."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace as NS
import tempfile
import unittest
from unittest.mock import patch
import uuid

spec = importlib.util.spec_from_file_location('mac_install', Path(__file__).resolve().parents[1] / 'install.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Policy(unittest.TestCase):
    def setUp(self):
        self.service = NS(pw_uid=501, pw_gid=601, pw_name='service', pw_shell='/usr/bin/false')
        self.admin = NS(pw_uid=502, pw_gid=602, pw_name='operator')
        self.agent = NS(pw_uid=503, pw_gid=603, pw_name='agent')
        self.groups = {'service': {601, 610, 611}, 'operator': {602, 611}, 'agent': {603, 610}}
        self.sign, self.management = NS(gr_gid=610), NS(gr_gid=611)
        self.getgroup = patch.object(module.grp, 'getgrnam', return_value=NS(gr_gid=80))
        self.members = patch.object(module, 'memberships', side_effect=lambda u: self.groups[u.pw_name])
        self.getgroup.start()
        self.members.start()
        self.addCleanup(self.getgroup.stop)
        self.addCleanup(self.members.stop)

    def config(self):
        return module.configuration(self.service, self.admin, [self.agent], self.sign, self.management)

    def test_preview_only(self):
        config = self.config()
        self.assertEqual(config['mode'], 'macos-boundary-preview')
        self.assertEqual(len(config['vault_ids']), 1)
        uuid.UUID(config['vault_ids'][0])
        self.assertTrue(config['features']['sign_document_proof'])
        self.assertEqual(config['features']['sign_purpose'],
                         {'device_assertion': True, 'application_assertion': False})
        self.assertNotEqual(config['admin_uids'][0], config['principals'][0]['uid'])

    def test_shared_uid_refused(self):
        self.agent.pw_uid = self.admin.pw_uid
        with self.assertRaises(ValueError): self.config()

    def test_agent_privilege_groups_refused(self):
        for gid in [0, 80, 611]:
            self.groups['agent'] = {603, 610, gid}
            with self.assertRaises(ValueError): self.config()

    def test_service_needs_socket_groups_but_not_admin(self):
        self.groups['service'] = {601}
        with self.assertRaises(ValueError): self.config()
        self.groups['service'] = {601, 610, 611, 80}
        with self.assertRaises(ValueError): self.config()

    def test_service_login_refused(self):
        self.service.pw_shell = '/bin/zsh'
        with self.assertRaises(ValueError): self.config()

    def test_shared_socket_group_refused(self):
        self.management.gr_gid = self.sign.gr_gid
        with self.assertRaises(ValueError): self.config()


class Upgrade(unittest.TestCase):
    def test_existing_vault_and_explicit_features_are_preserved(self):
        config = {'vault_ids': ['11111111-1111-4111-8111-111111111111'],
                  'features': {'sign_document_proof': False, 'ecdh': True}}
        with tempfile.TemporaryDirectory() as directory:
            updated, changed = module.upgraded_config(config, Path(directory))
        self.assertEqual(updated['vault_ids'], config['vault_ids'])
        self.assertFalse(updated['features']['sign_document_proof'])
        self.assertTrue(updated['features']['sign_origin_proof'])
        self.assertFalse(updated['features']['sign_purpose']['application_assertion'])
        self.assertTrue(changed)

    def test_empty_config_gets_one_vault_only_without_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            updated, changed = module.upgraded_config({'vault_ids': []}, Path(directory))
            self.assertEqual(len(updated['vault_ids']), 1)
            uuid.UUID(updated['vault_ids'][0])
            self.assertTrue(changed)
            (Path(directory) / 'catalog.sqlite3').write_bytes(b'')
            kept, untouched = module.upgraded_config(
                {'vault_ids': [], 'features': dict(module.DEFAULT_FEATURES)}, Path(directory))
            self.assertEqual(kept['vault_ids'], [])
            self.assertFalse(untouched)


class Layout(unittest.TestCase):
    def test_state_layout_includes_vaults(self):
        service = NS(pw_uid=501, pw_gid=601)
        config = {'agent_gid': 610, 'admin_gid': 611,
                  'vault_ids': ['11111111-1111-4111-8111-111111111111']}
        calls = []
        with patch.object(module, 'directory', side_effect=lambda *args: calls.append(args)):
            module.create_directories(Path('/base'), service, config)
        self.assertIn((Path('/base/state'), 501, 601, 0o700), calls)
        self.assertIn((Path('/base/state/vaults'), 501, 601, 0o700), calls)
        self.assertIn((Path('/base/state/vaults/11111111-1111-4111-8111-111111111111'),
                       501, 601, 0o700), calls)
        self.assertIn((Path('/base/sign'), 501, 610, 0o750), calls)
        self.assertIn((Path('/base/admin'), 501, 611, 0o750), calls)


class ChildCredentials(unittest.TestCase):
    def test_runtime_failure_preserves_signal_and_output(self):
        spec = importlib.util.spec_from_file_location('runtime_failure', Path(__file__).resolve().parents[1] / 'acceptance' / 'test-runtime.py')
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        with self.assertRaisesRegex(ValueError, r'exit=-9 \(signal 9\)'):
            runtime.require_success(NS(returncode=-9, stdout='', stderr=''), 'admission')
        with self.assertRaises(ValueError) as raised:
            runtime.require_success(NS(returncode=1, stdout='progress', stderr='refused'), 'init')
        self.assertIn('progress', str(raised.exception))
        self.assertIn('refused', str(raised.exception))
        runtime.require_success(NS(returncode=0, stdout='', stderr=''), 'ok')

    def test_primary_group_survives_darwin_egid_replacement(self):
        spec = importlib.util.spec_from_file_location('runtime_checks', Path(__file__).resolve().parents[1] / 'acceptance' / 'test-runtime.py')
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        config = {'service_uid': 600, 'admin_uids': [501], 'agent_gid': 602, 'admin_gid': 603}
        for uid, primary, required in [(600, 600, {602, 603}), (501, 20, {603}), (601, 601, {602}), (70, 70, {602})]:
            user = NS(pw_uid=uid, pw_gid=primary)
            result = runtime.child_credentials(user, config)
            self.assertEqual(result['extra_groups'][0], primary)
            # BSD setregid replaces group slot 0 after setgroups. Socket groups
            # must survive that documented kernel transition.
            after_setregid = [primary, *result['extra_groups'][1:]]
            self.assertTrue(required <= set(after_setregid))
            if uid in (601, 70):
                self.assertNotIn(603, after_setregid)
        agent = NS(pw_uid=601, pw_gid=601)
        elevated_transport = runtime.child_credentials(agent, config, extra_admin_group=True)
        self.assertEqual(elevated_transport['user'], 601)
        self.assertIn(603, elevated_transport['extra_groups'][1:])


class UpdateWrites(unittest.TestCase):
    def test_archive_keeps_bytes_and_refuses_existing_destination(self):
        import tempfile
        spec = importlib.util.spec_from_file_location('local_update', Path(__file__).resolve().parents[1] / 'update-local.py')
        update = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(update)
        with tempfile.TemporaryDirectory() as directory:
            previous = Path(directory) / 'previous'
            archive = Path(directory) / 'archive'
            previous.write_bytes(b'old-reviewed-binary')
            with patch.object(update, 'trusted_file'):
                update.archive_previous(previous, archive)
                self.assertFalse(previous.exists())
                self.assertEqual(archive.read_bytes(), b'old-reviewed-binary')
                previous.write_bytes(b'keep-this-backup')
                with self.assertRaises(FileExistsError):
                    update.archive_previous(previous, archive)
                self.assertEqual(previous.read_bytes(), b'keep-this-backup')
                self.assertEqual(archive.read_bytes(), b'old-reviewed-binary')

    def test_backup_and_stage_are_exclusive_and_ignore_restrictive_umask(self):
        import os
        import tempfile
        spec = importlib.util.spec_from_file_location('local_update', Path(__file__).resolve().parents[1] / 'update-local.py')
        update = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(update)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'binary'
            mask = os.umask(0o077)
            try:
                update.write_new(path, b'reviewed-binary')
            finally:
                os.umask(mask)
            self.assertEqual(path.read_bytes(), b'reviewed-binary')
            self.assertEqual(path.stat().st_mode & 0o777, 0o755)
            with self.assertRaises(FileExistsError):
                update.write_new(path, b'overwrite')
            alias = Path(directory) / 'alias'
            alias.symlink_to(path)
            with self.assertRaises(FileExistsError):
                update.write_new(alias, b'follow-link')
            self.assertEqual(path.read_bytes(), b'reviewed-binary')


if __name__ == '__main__':
    unittest.main()
