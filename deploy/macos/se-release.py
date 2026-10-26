#!/usr/bin/env python3
"""U3 Secure Enclave helper release tool: plan, build, verify, install.

This tool prepares the **login-session helper** bundle. It never signs with an
ad-hoc identity and never claims hardware acceptance. `plan` is the default and
changes nothing; `build`, `verify --installed` and `install` are explicit.

The policy source is `se-preflight.py`: the same Team ID, exact application
identifier, hardened runtime, keychain-access-groups and forbidden-entitlement
checks gate the bundle. Passing here means the signature prerequisites are met,
not that persistent SE keys, logout/reboot or distribution were accepted.
"""
import argparse
import calendar
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

BASE = Path('/Library/ANPIOKey')
HELPER = BASE / 'ANPIOKey.app'
EXECUTABLE = 'anpio-key'
FEATURES = 'mcp,hardware-se'
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}
PENDING = [
    'persistent SE create/open across independent processes with temporary keys',
    'cross-UID keychain denial and helper crash/hang behavior',
    'logout/relogin, user switch, sleep/wake and whole-machine reboot',
    'SE unavailable, key loss, signature identity change and upgrade recovery',
    'distribution review of the macOS protection claim',
]


class ReleaseError(Exception):
    pass


def run(arguments, env=None, timeout=600):
    try:
        return subprocess.run(arguments, env=env, capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as error:
        raise ReleaseError(f'{arguments[0]} failed to run: {error}') from error


def checked(arguments, env=None, timeout=600):
    result = run(arguments, env=env, timeout=timeout)
    if result.returncode:
        detail = result.stderr.decode(errors='replace').strip()
        raise ReleaseError(f'{" ".join(map(str, arguments))} failed: {detail}')
    return result


def load_preflight():
    path = Path(__file__).with_name('se-preflight.py')
    spec = importlib.util.spec_from_file_location('se_preflight', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PREFLIGHT = load_preflight()


def validate_identity_fields(team, application):
    if not re.fullmatch(r'[A-Z0-9]{10}', team):
        raise ReleaseError('expected an explicit 10-character Apple Team ID')
    if not re.fullmatch(r'[A-Za-z0-9.-]{1,200}', application):
        raise ReleaseError('application identifier has invalid characters')
    if not application.startswith(team + '.') or '*' in application:
        raise ReleaseError('application identifier must be an exact team-prefixed identifier')
    if application == team + '.':
        raise ReleaseError('application identifier has no suffix')


def entitlements(team, application):
    """The complete entitlement set for this isolated keychain profile.

    No application groups, no debug/JIT/library-validation relaxation. This is
    exactly what `se-preflight.py` accepts; adding anything here is a policy
    change, not a packaging detail.
    """
    return {
        'com.apple.application-identifier': application,
        'com.apple.developer.team-identifier': team,
        'keychain-access-groups': [application],
    }


def info_plist(application, version):
    return {
        'CFBundleDevelopmentRegion': 'en',
        'CFBundleExecutable': EXECUTABLE,
        'CFBundleIdentifier': application.split('.', 1)[1],
        'CFBundleInfoDictionaryVersion': '6.0',
        'CFBundleName': 'ANPIOKey',
        'CFBundlePackageType': 'APPL',
        'CFBundleShortVersionString': version,
        'CFBundleVersion': version,
        'LSBackgroundOnly': True,
        'LSMinimumSystemVersion': '13.0',
    }


def identities():
    result = checked(['/usr/bin/security', 'find-identity', '-v', '-p', 'codesigning'], env=ENV)
    found = []
    for line in result.stdout.decode(errors='replace').splitlines():
        match = re.match(r'\s*\d+\)\s+([0-9A-F]{40})\s+"(.+)"\s*$', line)
        if match:
            found.append({'sha1': match.group(1), 'name': match.group(2)})
    return found


def resolve_identity(wanted):
    available = identities()
    for identity in available:
        if wanted in (identity['sha1'], identity['name']):
            return identity
    names = ', '.join(f'{i["name"]} [{i["sha1"]}]' for i in available) or 'none'
    raise ReleaseError(f'no code-signing identity matches {wanted!r}; available: {names}')


def profile_metadata(path, team, application):
    # `security cms -D` needs a default keychain, which the root install context
    # does not have, so installation failed before it could inspect the bundle.
    result = checked(['/usr/bin/openssl', 'cms', '-verify', '-noverify', '-inform', 'der',
                      '-in', str(path)], env=ENV)
    try:
        decoded = plistlib.loads(result.stdout)
    except plistlib.InvalidFileException as error:
        raise ReleaseError(f'provisioning profile is not a readable plist: {error}') from error
    if not isinstance(decoded, dict):
        raise ReleaseError('provisioning profile did not decode to a dictionary')
    profile_entitlements = decoded.get('Entitlements', {})
    teams = decoded.get('TeamIdentifier', [])
    if isinstance(teams, str):
        teams = [teams]
    if team not in teams:
        raise ReleaseError(f'provisioning profile is not for Team ID {team}')
    entitled = profile_entitlements.get('com.apple.application-identifier')
    if entitled != application:
        raise ReleaseError(
            'provisioning profile application identifier differs from the approved identifier: '
            f'{entitled!r} != {application!r}'
        )
    expiration = decoded.get('ExpirationDate')
    if hasattr(expiration, 'utctimetuple'):
        expires = float(calendar.timegm(expiration.utctimetuple()))
    elif isinstance(expiration, (int, float)):
        expires = float(expiration)
    else:
        raise ReleaseError('provisioning profile has no expiration date')
    if expires <= time.time():
        raise ReleaseError('provisioning profile has expired')
    platforms = decoded.get('Platform', [])
    if isinstance(platforms, str):
        platforms = [platforms]
    if platforms and 'OSX' not in platforms:
        raise ReleaseError(f'provisioning profile is not a macOS profile: {platforms}')
    return {
        'name': decoded.get('Name'),
        'uuid': decoded.get('UUID'),
        'team_identifiers': teams,
        'application_identifier': entitled,
        'expires': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(expires)),
        'sha256': hashlib.sha256(Path(path).read_bytes()).hexdigest(),
        'platforms': platforms,
    }


def build_info(binary):
    result = checked([str(binary), 'build-info'], env=os.environ.copy(), timeout=30)
    try:
        info = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ReleaseError(f'build-info did not return JSON: {error}') from error
    required = {'release': True, 'hardware_se': True, 'mcp': True,
                'seed_export': False, 'hardware_software': False,
                'protected_supported': False}
    for key, expected in required.items():
        if info.get(key) is not expected:
            raise ReleaseError(f'candidate build-info {key}={info.get(key)!r}, expected {expected!r}')
    return info


def code_signature(path):
    result = checked(['/usr/bin/codesign', '-d', '--verbose=4', str(path)], env=ENV)
    text = result.stderr.decode(errors='replace')
    metadata = {}
    authorities = []
    for line in text.splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            metadata[key] = value
            if key == 'Authority':
                authorities.append(value)
    metadata['authorities'] = authorities
    flags = re.search(r'flags=0x[0-9a-f]+\(([^)]*)\)', text)
    metadata['flags'] = flags.group(1) if flags else ''
    return metadata


def designated_requirement(path):
    result = checked(['/usr/bin/codesign', '-d', '-r-', str(path)], env=ENV)
    prefix = 'designated => '
    # codesign versions differ on which stream carries the requirement.
    text = (result.stdout + b'\n' + result.stderr).decode(errors='replace')
    for line in text.splitlines():
        if line.startswith(prefix):
            return line[len(prefix):].strip()
    return None


def bundle_layout(bundle, team, application):
    if not bundle.is_dir() or bundle.is_symlink():
        raise ReleaseError(f'bundle is not a real directory: {bundle}')
    for root, directories, files in os.walk(bundle, followlinks=False):
        for name in directories + files:
            path = Path(root) / name
            if path.is_symlink():
                raise ReleaseError(f'bundle contains a symlink: {path}')
    executable = bundle / 'Contents' / 'MacOS' / EXECUTABLE
    plist_path = bundle / 'Contents' / 'Info.plist'
    profile_path = bundle / 'Contents' / 'embedded.provisionprofile'
    for path in (executable, plist_path, profile_path):
        if not path.is_file() or path.is_symlink():
            raise ReleaseError(f'bundle is missing a regular file: {path}')
    try:
        plist = plistlib.loads(plist_path.read_bytes())
    except (OSError, plistlib.InvalidFileException) as error:
        raise ReleaseError(f'cannot read bundle Info.plist: {error}') from error
    if plist.get('CFBundleIdentifier') != application.split('.', 1)[1]:
        raise ReleaseError('bundle CFBundleIdentifier differs from the approved identifier')
    if plist.get('CFBundleExecutable') != EXECUTABLE:
        raise ReleaseError('bundle CFBundleExecutable is not the expected helper executable')
    if plist.get('CFBundlePackageType') != 'APPL':
        raise ReleaseError('bundle is not an application package')
    return executable, profile_path, plist


def verify_bundle(bundle, team, application, *, installed=False, expected_profile=None,
                  require_notarized=False, previous=None):
    validate_identity_fields(team, application)
    executable, profile_path, plist = bundle_layout(bundle, team, application)
    if installed:
        trusted_bundle_chain(bundle)
    profile = profile_metadata(profile_path, team, application)
    if expected_profile and profile['sha256'] != expected_profile:
        raise ReleaseError('embedded provisioning profile does not match the reviewed profile')
    checked(['/usr/bin/codesign', '--verify', '--deep', '--strict', '--verbose=2', str(bundle)], env=ENV)
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    report = PREFLIGHT.inspect(executable, digest, 'user-session', team, application)
    if not report['signature_prerequisites_passed']:
        raise ReleaseError('signature prerequisites failed: ' + '; '.join(report['blockers']))
    metadata = code_signature(executable)
    if metadata.get('TeamIdentifier') != team:
        raise ReleaseError('signature TeamIdentifier differs from the approved Team ID')
    continuity = None
    if previous is not None:
        previous = Path(previous)
        previous_executable, previous_profile, _ = bundle_layout(previous, team, application)
        previous_metadata = code_signature(previous_executable)
        if previous_metadata.get('TeamIdentifier') != team:
            raise ReleaseError('previous helper was signed by a different Team ID')
        if previous_profile.read_bytes() != profile_path.read_bytes():
            # A renewed profile may legitimately differ; its Team/app must match,
            # which profile_metadata above already checked.
            continuity = 'profile changed; Team ID and application identifier match'
        else:
            continuity = 'profile unchanged; Team ID and application identifier match'
        old_requirement = designated_requirement(previous_executable)
        new_requirement = designated_requirement(executable)
        if not old_requirement or not new_requirement:
            raise ReleaseError(
                'cannot read the designated requirement for the upgrade identity comparison')
        if old_requirement != new_requirement:
            raise ReleaseError(
                'the new helper has a different designated requirement; an upgrade would be a '
                f'different code identity: {old_requirement!r} != {new_requirement!r}'
            )
    notarization = {'required': require_notarized, 'stapler': None, 'gatekeeper': None}
    if require_notarized:
        staple = run(['/usr/bin/stapler', 'validate', str(bundle)], env=ENV)
        gate = run(['/usr/sbin/spctl', '--assess', '--type', 'execute', '--verbose=2', str(bundle)], env=ENV)
        notarization['stapler'] = staple.returncode == 0
        notarization['gatekeeper'] = gate.returncode == 0
        notarization['gatekeeper_detail'] = gate.stdout.decode(errors='replace').strip()
        if not (notarization['stapler'] and notarization['gatekeeper']):
            raise ReleaseError('notarization validation failed (stapler or Gatekeeper)')
    return {
        'schema': 1,
        'bundle': str(bundle),
        'candidate_sha256': digest,
        'team_id': team,
        'application_identifier': application,
        'plist': {'CFBundleIdentifier': plist['CFBundleIdentifier'],
                  'CFBundleShortVersionString': plist.get('CFBundleShortVersionString')},
        'profile': profile,
        'signature': {'team_identifier': metadata.get('TeamIdentifier'),
                      'authority': metadata.get('Authority'),
                      'authorities': metadata.get('authorities', []),
                      'flags': metadata.get('flags'),
                      'designated_requirement': designated_requirement(executable)},
        'upgrade_continuity': continuity,
        'notarization': notarization,
        'signature_prerequisites_passed': True,
        'hardware_acceptance_complete': False,
        'protected_supported': False,
        'pending': PENDING,
    }


def trusted_bundle_chain(bundle):
    install = load_install()
    install.check_chain(bundle)
    for root, directories, files in os.walk(bundle, followlinks=False):
        for name in directories + files:
            path = Path(root) / name
            meta = path.lstat()
            if not stat.S_ISDIR(meta.st_mode) and not stat.S_ISREG(meta.st_mode):
                raise ReleaseError(f'installed bundle contains a non-regular entry: {path}')
            if meta.st_uid != 0 or meta.st_mode & 0o022:
                raise ReleaseError(f'installed bundle entry is not root-owned and read-only: {path}')


def load_install():
    path = Path(__file__).with_name('install.py')
    spec = importlib.util.spec_from_file_location('macos_install', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cargo_build():
    command = ['cargo', 'build', '--locked', '--release', '--features', FEATURES]
    checked(command, env=os.environ.copy(), timeout=1800)


def plan(args):
    blockers = []
    available = []
    try:
        available = identities()
        if not available:
            blockers.append(
                'no code-signing identity found: install a Developer ID Application (or equivalent '
                'Apple-issued) certificate in this login keychain'
            )
    except ReleaseError as error:
        blockers.append(str(error))
    identity = None
    if args.identity:
        try:
            identity = resolve_identity(args.identity)
        except ReleaseError as error:
            blockers.append(str(error))
    if args.team_id:
        try:
            validate_identity_fields(args.team_id, args.application_id)
        except ReleaseError as error:
            blockers.append(str(error))
    profile = None
    if args.profile:
        try:
            profile = profile_metadata(args.profile, args.team_id, args.application_id)
        except ReleaseError as error:
            blockers.append(str(error))
    if not args.team_id:
        blockers.append('--team-id is required to evaluate the release profile')
    if not args.application_id:
        blockers.append('--application-id is required to evaluate the release profile')
    if not args.profile:
        blockers.append('--profile is required: this profile must authorize the application identifier')
    return {
        'schema': 1,
        'plan_only': True,
        'identities_found': len(available),
        'identity': identity,
        'team_id': args.team_id,
        'application_identifier': args.application_id,
        'profile': profile,
        'features': FEATURES,
        'bundle': str(args.out),
        'signing_command': [
            '/usr/bin/codesign', '--force', '--options', 'runtime', '--timestamp',
            '--entitlements', '<generated>', '--sign', '<identity>', str(args.out),
        ],
        'blockers': blockers,
        'ready_to_build': not blockers,
        'hardware_acceptance_complete': False,
        'protected_supported': False,
        'pending': PENDING,
    }


def build(args):
    validate_identity_fields(args.team_id, args.application_id)
    identity = resolve_identity(args.identity)
    profile = profile_metadata(args.profile, args.team_id, args.application_id)
    out = args.out.resolve()
    if out.exists():
        raise ReleaseError(f'refusing to replace an existing output bundle: {out}')
    if args.binary:
        binary = args.binary.resolve(strict=True)
    else:
        cargo_build()
        binary = Path('target/release') / EXECUTABLE
        if not binary.is_file():
            raise ReleaseError(f'cargo build did not produce {binary}')
    info = build_info(binary)
    out.mkdir(parents=True)
    contents = out / 'Contents'
    (contents / 'MacOS').mkdir(parents=True)
    (contents / 'Resources').mkdir()
    executable = contents / 'MacOS' / EXECUTABLE
    shutil.copyfile(binary, executable)
    os.chmod(executable, 0o755)
    (contents / 'Info.plist').write_bytes(plistlib.dumps(info_plist(args.application_id, info['version'])))
    (contents / 'embedded.provisionprofile').write_bytes(Path(args.profile).read_bytes())
    for path in contents.rglob('*'):
        if path.is_file():
            os.chmod(path, 0o755 if path == executable else 0o644)
    entitlement_path = out.parent / (out.name + '.entitlements')
    entitlement_path.write_bytes(plistlib.dumps(entitlements(args.team_id, args.application_id)))
    signed = run([
        '/usr/bin/codesign', '--force', '--options', 'runtime', '--timestamp',
        '--entitlements', str(entitlement_path), '--sign', identity['sha1'], str(out),
    ], env=ENV, timeout=300)
    if signed.returncode:
        shutil.rmtree(out, ignore_errors=True)
        raise ReleaseError('codesign failed: ' + signed.stderr.decode(errors='replace').strip())
    report = verify_bundle(out, args.team_id, args.application_id,
                           expected_profile=profile['sha256'],
                           require_notarized=args.require_notarized)
    report['identity'] = identity
    report['build_info'] = info
    report['report_path'] = str(out.parent / (out.name + '.report.json'))
    (out.parent / (out.name + '.report.json')).write_text(json.dumps(report, indent=2) + '\n')
    return report


def sign_example(args):
    """Sign a bare acceptance example with the reviewed entitlement set.

    The example gets the helper's exact entitlement set. Profile requirements
    depend on the signing context: development signing may require a matching
    profile for runtime admission. This command does not embed or install one;
    preflight success alone does not establish that the OS will run the probe.
    """
    validate_identity_fields(args.team_id, args.application_id)
    identity = resolve_identity(args.identity)
    profile = None
    if args.profile:
        profile = profile_metadata(args.profile, args.team_id, args.application_id)
    source = args.binary.resolve(strict=True)
    if not source.is_file() or source.is_symlink():
        raise ReleaseError(f'candidate must be a regular file: {source}')
    source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    if not re.fullmatch(r'[0-9a-f]{64}', args.sha256):
        raise ReleaseError('expected a lowercase SHA-256')
    if source_digest != args.sha256:
        raise ReleaseError('candidate digest mismatch')
    out = args.out.resolve()
    if out.exists():
        raise ReleaseError(f'refusing to replace an existing output: {out}')
    out.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, out)
    os.chmod(out, 0o755)
    entitlement_path = out.parent / (out.name + '.entitlements')
    entitlement_path.write_bytes(plistlib.dumps(entitlements(args.team_id, args.application_id)))
    signed = run([
        '/usr/bin/codesign', '--force', '--options', 'runtime', '--timestamp',
        '--entitlements', str(entitlement_path), '--sign', identity['sha1'], str(out),
    ], env=ENV, timeout=300)
    if signed.returncode:
        out.unlink(missing_ok=True)
        raise ReleaseError('codesign failed: ' + signed.stderr.decode(errors='replace').strip())
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    try:
        report = PREFLIGHT.inspect(out, digest, 'user-session', args.team_id, args.application_id)
    except (ValueError, OSError, subprocess.SubprocessError):
        out.unlink(missing_ok=True)
        raise
    if not report['signature_prerequisites_passed']:
        out.unlink(missing_ok=True)
        raise ReleaseError('signature prerequisites failed: ' + '; '.join(report['blockers']))
    return {
        'schema': 1,
        'binary': str(out),
        'source_sha256': source_digest,
        'candidate_sha256': digest,
        'team_id': args.team_id,
        'application_identifier': args.application_id,
        'identity': identity,
        'profile': profile,
        'profile_embedded': False,
        'signature_prerequisites_passed': True,
        'hardware_acceptance_complete': False,
        'protected_supported': False,
        'pending': PENDING,
    }


def install(args):
    if os.geteuid() != 0:
        raise ReleaseError('installation requires root')
    if sys.platform != 'darwin':
        raise ReleaseError('macOS only')
    source = args.bundle.resolve(strict=True)
    destination = Path(args.destination)
    upgrading = args.upgrade and destination.exists()
    candidate = verify_bundle(source, args.team_id, args.application_id,
                              expected_profile=args.profile_sha256,
                              require_notarized=args.require_notarized,
                              previous=destination if upgrading else None)
    if destination.exists() and not args.upgrade:
        raise ReleaseError(f'{destination} exists; pass --upgrade for an in-place upgrade')
    backup = destination.with_name(destination.name + '.previous')
    if backup.exists():
        raise ReleaseError(f'refusing to replace existing backup {backup}; review or archive it first')
    if args.upgrade and not destination.exists():
        raise ReleaseError('--upgrade was requested but no installed helper exists')
    if args.upgrade:
        verify_bundle(destination, args.team_id, args.application_id,
                      installed=True, require_notarized=False)
    destination.parent.mkdir(parents=True, exist_ok=True)
    staged = Path(tempfile.mkdtemp(prefix='.ANPIOKey.app.', dir=destination.parent)) / 'bundle'
    try:
        shutil.copytree(source, staged, symlinks=False)
        for root, directories, files in os.walk(staged):
            for name in directories + files:
                path = Path(root) / name
                os.chown(path, 0, 0)
                if path.is_dir():
                    os.chmod(path, 0o755)
                else:
                    os.chmod(path, 0o755 if name == EXECUTABLE else 0o644)
        os.chown(staged, 0, 0)
        os.chmod(staged, 0o755)
        verify_bundle(staged, args.team_id, args.application_id, installed=True,
                      expected_profile=args.profile_sha256)
        if destination.exists():
            os.rename(destination, backup)
        try:
            os.rename(staged, destination)
        except OSError:
            if backup.exists() and not destination.exists():
                os.rename(backup, destination)
            raise
        directory_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        shutil.rmtree(staged.parent, ignore_errors=True)
    candidate.update({'installed': str(destination), 'backup': str(backup) if backup.exists() else None,
                      'installed_ownership_verified': True})
    return candidate


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(dest='command')
    for name, handler in [('plan', plan), ('build', build),
                          ('sign-example', sign_example), ('install', install)]:
        sub = subparsers.add_parser(name)
        sub.add_argument('--team-id', required=True)
        sub.add_argument('--application-id', required=True)
        sub.set_defaults(handler=handler)
        if name == 'plan':
            sub.add_argument('--identity')
            sub.add_argument('--profile', type=Path)
            sub.add_argument('--out', type=Path, default=Path('target/se-release/ANPIOKey.app'))
        if name == 'build':
            sub.add_argument('--identity', required=True)
            sub.add_argument('--profile', type=Path, required=True)
            sub.add_argument('--out', type=Path, default=Path('target/se-release/ANPIOKey.app'))
            sub.add_argument('--binary', type=Path, help='use an already built candidate')
            sub.add_argument('--require-notarized', action='store_true')
        if name == 'sign-example':
            sub.add_argument('--identity', required=True)
            sub.add_argument('--profile', type=Path,
                             help='optional: validate the renewal/expiry of the reviewed profile')
            sub.add_argument('--binary', type=Path, required=True)
            sub.add_argument('--sha256', required=True)
            sub.add_argument('--out', type=Path,
                             default=Path('target/se-release/se-persistence.signed'))
        if name == 'install':
            sub.add_argument('--bundle', type=Path, required=True)
            sub.add_argument('--profile-sha256')
            sub.add_argument('--destination', type=Path, default=HELPER)
            sub.add_argument('--upgrade', action='store_true')
            sub.add_argument('--require-notarized', action='store_true')
    verify = subparsers.add_parser('verify')
    verify.add_argument('--bundle', type=Path, required=True)
    verify.add_argument('--team-id', required=True)
    verify.add_argument('--application-id', required=True)
    verify.add_argument('--previous', type=Path)
    verify.add_argument('--expected-profile', type=Path)
    verify.add_argument('--installed', action='store_true')
    verify.add_argument('--require-notarized', action='store_true')
    verify.set_defaults(handler=lambda a: verify_bundle(
        a.bundle.resolve(strict=True), a.team_id, a.application_id, installed=a.installed,
        expected_profile=profile_metadata(a.expected_profile, a.team_id, a.application_id)['sha256']
        if a.expected_profile else None,
        require_notarized=a.require_notarized, previous=a.previous))
    args = parser.parse_args()
    if not args.command:
        parser.error('choose plan, build, sign-example, verify or install')
    try:
        report = args.handler(args)
    except (ReleaseError, ValueError, OSError, plistlib.InvalidFileException) as error:
        print(json.dumps({'schema': 1, 'passed': False, 'error': str(error),
                          'hardware_acceptance_complete': False,
                          'protected_supported': False}, indent=2))
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
