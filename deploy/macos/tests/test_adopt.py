"""Pure adopt-identity policy tests; no accounts, services or root."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'adopt-identity.py'
spec = importlib.util.spec_from_file_location('mac_adopt', SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

DID = 'did:wba:awiki.me:user:anpiotest1108:e1_m4DGr0MfPJ6ppLSoeXbSUa1wEnFiNmPHVwmh8X5hk-k'
SIGN_KID = DID + '#anpiotest1108/default-sign'
AGREEMENT_KID = DID + '#anpiotest1108/default-agreement'
ROOT_KID = DID + '#key-1'


def identity():
    return {
        'did': DID,
        'agent': 'anpiotest1108',
        'profile': 'default',
        'custody': {
            'kind': 'anpio-key',
            'name': 'named-root',
            'device_keys': {'sign': 'named-sign', 'agreement': 'named-agreement'},
        },
        'did_document': {'id': DID},
    }


class IdentityValidation(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__('shutil').rmtree(self.tmp, ignore_errors=True))
        self.uid = os.geteuid()

    def write(self, data, mode=0o600):
        path = self.tmp / 'identity.json'
        path.write_text(json.dumps(data))
        path.chmod(mode)
        return path

    def test_accepts_a_did_bound_named_key_identity(self):
        record, did = module.validate_identity(self.write(identity()), self.uid)
        self.assertEqual(did, DID)
        self.assertEqual(record['custody']['name'], 'named-root')

    def test_refuses_custody_that_is_not_anpio_key(self):
        bad = identity()
        bad['custody']['kind'] = 'local'
        with self.assertRaises(module.AdoptError):
            module.validate_identity(self.write(bad), self.uid)

    def test_refuses_a_missing_role_or_a_key_used_twice(self):
        for mutate in (
            lambda record: record['custody'].pop('name'),
            lambda record: record['custody'].pop('device_keys'),
            lambda record: record['custody']['device_keys'].pop('sign'),
            lambda record: record['custody']['device_keys'].update(sign='named-root'),
        ):
            bad = identity()
            mutate(bad)
            with self.assertRaises(module.AdoptError):
                module.validate_identity(self.write(bad), self.uid)

    def test_refuses_a_document_for_another_did(self):
        bad = identity()
        bad['did_document']['id'] = DID + '-other'
        with self.assertRaises(module.AdoptError):
            module.validate_identity(self.write(bad), self.uid)

    def test_refuses_a_writable_identity_file(self):
        with self.assertRaises(module.AdoptError):
            module.validate_identity(self.write(identity(), 0o666), self.uid)


class SourceValidation(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__('shutil').rmtree(self.tmp, ignore_errors=True))
        self.uid = os.geteuid()
        self.root = self.tmp / '.anpio-key'
        (self.root / 'keys').mkdir(parents=True)
        (self.root / 'dids').mkdir()
        self.root.chmod(0o700)
        (self.root / 'device.secret').write_bytes(b'\x07' * 32)
        (self.root / 'device.secret').chmod(0o600)
        for index in range(3):
            (self.root / 'keys' / f'k{index}.json').write_text('{}')

    def test_accepts_a_sealed_source_store(self):
        module.validate_source(self.root, self.uid)

    def test_refuses_missing_device_secret(self):
        (self.root / 'device.secret').unlink()
        with self.assertRaises(module.AdoptError):
            module.validate_source(self.root, self.uid)

    def test_refuses_fewer_than_three_keys(self):
        (self.root / 'keys' / 'k2.json').unlink()
        with self.assertRaises(module.AdoptError):
            module.validate_source(self.root, self.uid)

    def test_refuses_a_group_writable_store_or_file(self):
        self.root.chmod(0o770)
        with self.assertRaises(module.AdoptError):
            module.validate_source(self.root, self.uid)
        self.root.chmod(0o700)
        (self.root / 'keys' / 'k0.json').chmod(0o620)
        with self.assertRaises(module.AdoptError):
            module.validate_source(self.root, self.uid)

    def test_refuses_a_readable_by_others_device_secret(self):
        (self.root / 'device.secret').chmod(0o644)
        with self.assertRaises(module.AdoptError):
            module.validate_source(self.root, self.uid)


class Policies(unittest.TestCase):
    def setUp(self):
        self.boot = module.load_bootstrap()

    def test_http_policy_is_v2_and_covers_every_target_path(self):
        policies = module.http_policies(
            self.boot,
            ['https://awiki.me/anp-im/rpc', 'https://awiki.me/user-service/v1/did-auth/rpc'],
            ['POST'], 1024, 30, 100,
        )
        self.assertEqual(len(policies), 1)
        policy = policies[0]
        self.assertEqual(policy['schema_version'], 2)
        self.assertEqual(policy['purpose'], 'http-authentication')
        self.assertEqual(policy['content']['origin'], 'https://awiki.me')
        self.assertEqual(policy['content']['methods'], ['POST'])
        self.assertEqual(
            policy['content']['paths'],
            ['/anp-im/rpc', '/user-service/v1/did-auth/rpc'],
        )
        self.assertEqual(policy['content']['body'], {'mode': 'bounded', 'max_bytes': 1024})
        self.assertEqual(policy['content']['signature_profile'], 'anp-http-v2')
        self.assertEqual(policy['limits']['max_uses'], 100)
        self.assertLessEqual(len(policy['name']), 128)

    def test_empty_body_methods_get_no_body_budget(self):
        policy = module.http_policies(
            self.boot, ['https://awiki.me/v1/status'], ['GET', 'HEAD'], 1, 1, 1,
        )[0]
        self.assertEqual(policy['content']['methods'], ['GET', 'HEAD'])
        self.assertEqual(policy['content']['body'], {'mode': 'empty', 'max_bytes': 0})

    def test_mixed_methods_two_origins_and_queries_are_refused(self):
        for targets, methods in (
            (['https://awiki.me/a'], ['GET', 'POST']),
            (['https://awiki.me/a', 'https://other.example/b'], ['POST']),
            (['https://awiki.me/a?x=1'], ['POST']),
        ):
            with self.assertRaises(module.AdoptError):
                module.http_policies(self.boot, targets, methods, 1024, 30, 100)

    def test_document_proof_policy_allows_assertion_method(self):
        policy = module.document_proof_policy(DID, 30, 100)
        self.assertEqual(policy['schema_version'], 2)
        self.assertEqual(policy['purpose'], 'document-proof')
        self.assertEqual(policy['content']['proof_purposes'], ['assertionMethod'])
        self.assertEqual(policy['limits']['max_renewals'], 0)

    def test_a_document_proof_policy_name_stays_under_the_limit(self):
        long_did = 'did:wba:awiki.me:user:' + 'x' * 200 + ':e1_' + 'y' * 100
        policy = module.document_proof_policy(long_did, 30, 100)
        self.assertLessEqual(len(policy['name']), 128)


class Catalog(unittest.TestCase):
    def row(self, policy_id, version, content):
        return {'policy_id': policy_id, 'version': version, 'content': json.dumps(content)}

    def test_find_policy_matches_the_whole_document_and_takes_the_newest_version(self):
        desired = module.document_proof_policy(DID, 30, 100)
        rows = [
            self.row('old', 1, desired),
            self.row('new', 2, desired),
            self.row('other', 9, dict(desired, purpose='http-authentication')),
        ]
        self.assertEqual(module.find_policy(rows, desired)['policy_id'], 'new')

    def test_find_policy_ignores_unreadable_rows(self):
        desired = module.document_proof_policy(DID, 30, 100)
        rows = [{'policy_id': 'broken', 'version': 1, 'content': '{'}]
        self.assertIsNone(module.find_policy(rows, desired))

    def test_publish_or_reuse_publishes_once_and_reuses_the_next_time(self):
        published = []

        class Boot:
            def apply_change(self, change, description):
                published.append(change)
                return {'effect': {}}

        desired = module.document_proof_policy(DID, 30, 100)
        boot = Boot()
        policy_id, version = module.publish_or_reuse(boot, {}, desired, 'proof')
        self.assertEqual(len(published), 1)
        self.assertEqual(published[0]['kind'], 'Catalog')
        self.assertEqual(published[0]['change']['action'], 'PublishPolicy')
        self.assertEqual(published[0]['change']['content'], desired)
        self.assertEqual((policy_id, version), (published[0]['change']['policy_id'], 1))

        catalog = {'policies': [self.row(policy_id, version, desired)]}
        again = module.publish_or_reuse(boot, catalog, desired, 'proof')
        self.assertEqual(again, (policy_id, 1))
        self.assertEqual(len(published), 1)


class GrantsAndUnlock(unittest.TestCase):
    def test_create_grant_targets_the_agent_principal_and_the_named_key(self):
        changes = []

        class Boot:
            def apply_change(self, change, description):
                changes.append(change)
                return {'effect': {'grant': {'grant_id': 'grant-1'}}}

        key = {'key_id': 'key-uuid', 'kid': SIGN_KID}
        grant = module.create_grant(Boot(), 'principal-601', key, 'policy-1', 3, 30, 100)
        self.assertEqual(grant, 'grant-1')
        change = changes[0]['change']
        self.assertEqual(changes[0]['kind'], 'Grant')
        self.assertEqual(change['principal_id'], 'principal-601')
        self.assertEqual(change['key_id'], 'key-uuid')
        self.assertEqual(change['policy_id'], 'policy-1')
        self.assertEqual(change['policy_version'], 3)
        self.assertEqual(change['max_uses'], 100)
        self.assertGreater(change['expiry'], 0)

    def test_create_grant_refuses_a_reply_without_a_grant_id(self):
        class Boot:
            def apply_change(self, change, description):
                return {'effect': {}}

        with self.assertRaises(module.AdoptError):
            module.create_grant(
                Boot(), 'p', {'key_id': 'k', 'kid': ROOT_KID}, 'policy', 1, 1, 1,
            )

    def test_unlock_names_the_exact_vault_did_and_kid(self):
        calls = []

        class Boot:
            def admin(self, *args):
                calls.append(args)
                return {}

        module.unlock(Boot(), 'vault-1', DID, ROOT_KID, 'Root')
        self.assertEqual(
            calls,
            [('unlock', '--vault-id', 'vault-1', '--did', DID, '--kid', ROOT_KID)],
        )


class AgentRecord(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__('shutil').rmtree(self.tmp, ignore_errors=True))
        self.saved = module.AGENT_ROOT
        module.AGENT_ROOT = self.tmp / 'agent'
        (module.AGENT_ROOT / 'home').mkdir(parents=True, mode=0o700)
        self.addCleanup(lambda: setattr(module, 'AGENT_ROOT', self.saved))
        self.uid = os.geteuid()
        self.gid = os.getegid()

    def test_record_keeps_the_identity_and_switches_custody_to_the_service(self):
        record = identity()
        record['custody']['device_keys'] = {'sign': 'named-sign', 'agreement': 'named-agreement'}
        agent = module.write_agent_identity(
            record, SIGN_KID, 'http-grant', 'proof-grant', self.uid, self.gid,
        )
        self.assertEqual(agent, 'anpiotest1108')
        path = module.AGENT_ROOT / 'home/.anpio-cli/anpiotest1108/default/identity.json'
        written = json.loads(path.read_text())
        self.assertEqual(written['did'], DID)
        custody = written['custody']
        self.assertEqual(custody['config'], str(module.CONFIG))
        self.assertEqual(custody['kid'], 'anpiotest1108/default-sign')
        self.assertEqual(custody['grant'], 'http-grant')
        self.assertEqual(
            custody['grants'], {'http': 'http-grant', 'document_proof': 'proof-grant'},
        )
        self.assertEqual(custody['device_keys']['sign'], 'named-sign')
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)

    def test_missing_agent_and_profile_falls_back_to_the_device_id(self):
        record = identity()
        record.pop('agent')
        record.pop('profile')
        record['device_id'] = 'anpiotest1108/default'
        agent = module.write_agent_identity(
            record, SIGN_KID, 'h', 'd', self.uid, self.gid,
        )
        self.assertEqual(agent, 'anpiotest1108')
        self.assertTrue(
            (module.AGENT_ROOT / 'home/.anpio-cli/anpiotest1108/default/identity.json').is_file()
        )


class CliInstall(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__('shutil').rmtree(self.tmp, ignore_errors=True))
        self.saved = module.CLI_INSTALL
        module.CLI_INSTALL = self.tmp / 'bin/anpio-cli'
        module.CLI_INSTALL.parent.mkdir()
        self.addCleanup(lambda: setattr(module, 'CLI_INSTALL', self.saved))
        self.source = self.tmp / 'source-cli'
        self.source.write_bytes(b'#!/bin/sh\necho cli\n')
        self.source.chmod(0o755)
        # The real helper chowns to root; as a normal user these tests keep the
        # current owner while exercising the same atomic write and modes.
        real = module.write_atomic
        uid, gid = os.geteuid(), os.getegid()
        owner = patch.object(
            module, 'write_atomic',
            lambda path, data, mode, owner_uid=0, owner_gid=0: real(
                path, data, mode, uid, gid,
            ),
        )
        owner.start()
        self.addCleanup(owner.stop)

    def digest(self):
        return module.sha256_file(self.source)

    def test_installs_only_the_pinned_binary(self):
        module.install_cli(self.source, self.digest())
        self.assertEqual(module.CLI_INSTALL.read_bytes(), self.source.read_bytes())
        self.assertEqual(module.CLI_INSTALL.stat().st_mode & 0o777, 0o755)

    def test_refuses_a_digest_that_does_not_match(self):
        with self.assertRaises(module.AdoptError):
            module.install_cli(self.source, '0' * 64)
        self.assertFalse(module.CLI_INSTALL.exists())


class ApplyOrder(unittest.TestCase):
    """Grants and unlocks must come after the last restart: a restart revokes both."""

    def setUp(self):
        self.source = SOURCE.read_text()

    def test_no_grant_or_unlock_precedes_the_final_restart(self):
        apply = self.source.index("if args.dry_run:")
        restart = self.source.index('ensure_service_started(boot, config, PLIST)', apply)
        first_grant = self.source.index('create_grant(', apply)
        first_unlock = self.source.index('unlock(boot,', apply)
        self.assertGreater(first_grant, restart)
        self.assertGreater(first_unlock, restart)

    def test_the_last_restart_follows_the_feature_update(self):
        apply = self.source.index("if args.dry_run:")
        feature = self.source.index("config['features'] = wanted", apply)
        restart = self.source.index('ensure_service_started(boot, config, PLIST)', apply)
        self.assertGreater(restart, feature)

    def test_the_source_store_is_never_removed(self):
        self.assertIn('源钥匙库没有被删除', self.source)
        for removal in ('shutil.rmtree', 'os.unlink', 'os.remove'):
            for line in self.source.splitlines():
                if removal in line:
                    self.assertNotIn('source_root', line)
                    self.assertNotIn('args.identity', line)
                    self.assertNotIn('frozen_identity', line)


if __name__ == '__main__':
    unittest.main()
