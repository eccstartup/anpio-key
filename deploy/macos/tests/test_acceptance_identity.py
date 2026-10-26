"""A re-signed helper copy must be refused before it can obtain an SE session."""
import sys
from pathlib import Path
import plistlib
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'acceptance'))

import acceptance_se

ENTITLEMENTS = {
    'com.apple.application-identifier': 'TEAM.org.anpio-key.se-acceptance',
    'com.apple.developer.team-identifier': 'TEAM',
    'keychain-access-groups': ['TEAM.org.anpio-key.se-acceptance', 'TEAM.shared'],
}


def xml(values):
    return b'warning: deprecated syntax\n' + plistlib.dumps(values)


class Entitlements(unittest.TestCase):
    def test_warning_text_does_not_hide_the_plist(self):
        self.assertEqual(acceptance_se.parse_entitlements(xml(ENTITLEMENTS)), ENTITLEMENTS)

    def test_missing_or_empty_entitlements_fail_closed(self):
        for output in (b'warning only\n', xml({})):
            with self.assertRaisesRegex(ValueError, 'entitlements'):
                acceptance_se.parse_entitlements(output)

    def test_application_identifier_change_moves_the_keychain_group(self):
        changed = acceptance_se.with_application_identifier(
            ENTITLEMENTS, 'TEAM.org.anpio-key.se-acceptance.other')
        self.assertEqual(changed['com.apple.application-identifier'],
                         'TEAM.org.anpio-key.se-acceptance.other')
        self.assertEqual(changed['keychain-access-groups'],
                         ['TEAM.org.anpio-key.se-acceptance.other', 'TEAM.shared'])
        self.assertEqual(ENTITLEMENTS['com.apple.application-identifier'],
                         'TEAM.org.anpio-key.se-acceptance')

    def test_missing_application_identifier_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'application identifier'):
            acceptance_se.with_application_identifier({'keychain-access-groups': []}, 'x')


class Refusal(unittest.TestCase):
    def test_foreign_identity_cannot_see_the_key_group(self):
        acceptance_se.require_refused_helper(
            'foreign-identity', 1, 'this machine cannot use it: the keychain has no key with that label\n')

    def test_keychain_permission_names_the_invisible_key(self):
        acceptance_se.require_refused_helper(
            'keychain-permission', 1, 'this machine cannot use it: the keychain has no key with that label\n')

    def test_success_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'reported success'):
            acceptance_se.require_refused_helper('foreign-identity', 0, 'errSecMissingEntitlement')

    def test_established_session_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'established an SE session'):
            acceptance_se.require_refused_helper(
                'foreign-identity', 1, 'errSecMissingEntitlement\nSE session active for exact key x\n')

    def test_a_different_refusal_is_not_accepted_as_evidence(self):
        with self.assertRaisesRegex(ValueError, 'did not name'):
            acceptance_se.require_refused_helper('keychain-permission', 1, 'ADMIN_REQUIRED\n')

    def test_unknown_probe_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'unknown helper identity probe'):
            acceptance_se.require_refused_helper('signed-by-a-friend', 1, '')

    def test_unavailable_se_root_is_required(self):
        acceptance_se.require_unavailable_probe(
            'macOS Secure Enclave ... NOT USABLE\n(errSecMissingEntitlement, -34018)\n')
        with self.assertRaisesRegex(ValueError, 'unavailable SE root'):
            acceptance_se.require_unavailable_probe(
                'macOS Secure Enclave ... USABLE\n(errSecMissingEntitlement)\n')

    def test_unavailable_root_must_name_the_missing_entitlement(self):
        with self.assertRaisesRegex(ValueError, 'missing entitlement'):
            acceptance_se.require_unavailable_probe('macOS Secure Enclave ... NOT USABLE\n')


if __name__ == '__main__':
    unittest.main()
