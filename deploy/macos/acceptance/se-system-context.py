#!/usr/bin/env python3
"""Probe whether the data protection keychain is usable in a non-login context.

`run` must start in the human's login session. It creates a disposable SE key
and reopens it once there (the positive control), then asks sudo to install a
one-shot system LaunchDaemon that runs the same signed probe as `_anpagent`.
The parent then deletes the key and proves the old envelope no longer opens.

This answers exactly one open question: does a system launchd job with
UserName=_anpagent, outside any login session, still open the key? It does not
accept UID isolation, a protection claim or distribution. A refusal only closes
this documented context; access requires a boundary decision.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid

PENDING = [
    'raw keychain isolation between UIDs remains a separate counterexample',
    'formal distribution and notarization are not accepted',
    'physical Secure Enclave failure was not induced',
]
DENIAL_MARKERS = [
    'errSecItemNotFound', '-25300',
    'errSecInteractionNotAllowed', '-25308',
    'errSecAuthFailed', '-25293',
    'no key with that label', 'cannot use it', 'not allowed',
]
ADMISSION_MARKERS = [
    'errSecMissingEntitlement', '-34018',
    'No matching profile found', 'no eligible provisioning profiles',
    'Disallowing', 'Code Signature Invalid', 'Killed: 9',
    'exited due to signal', 'SIGKILL',
]
TERMINAL_MARKERS = ['PASS ', 'se-persistence:', 'Disallowing', 'Killed: 9',
                    'Code Signature Invalid', 'exited due to signal']
STAGE_PREFIX = 'ANPIOKeySystemContextChecks-'
MAX_STATE = 64 * 1024


def load_preflight():
    spec = importlib.util.spec_from_file_location(
        'se_preflight', Path(__file__).resolve().parents[1] / 'se-preflight.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256_bytes(content):
    return hashlib.sha256(content).hexdigest()


def sha256_file(path):
    return sha256_bytes(Path(path).read_bytes())


def signature_report(binary, digest, team, application):
    report = load_preflight().inspect(Path(binary), digest, 'user-session', team, application)
    if not report['signature_prerequisites_passed']:
        raise ValueError('signature prerequisites failed: ' + '; '.join(report['blockers']))
    return report


def validate_agent(name):
    account = pwd.getpwnam(name)
    if account.pw_uid == 0 or account.pw_uid == 0xffffffff:
        raise ValueError('the Agent account must be a real non-root UID')
    return account


def parse_context(text):
    context = None
    for line in text.splitlines():
        if not line.startswith('SE_CONTEXT '):
            continue
        value = json.loads(line[len('SE_CONTEXT '):])
        if not isinstance(value, dict):
            raise ValueError('probe context must be a dictionary')
        context = value
    return context


def context_confirmed(context, uid, creator_session=None):
    if context is None or context.get('uid') != uid or context.get('euid') != uid:
        return False
    if creator_session is not None:
        session = context.get('audit_session')
        if session is None or session == creator_session:
            return False
    return True


def classify(returncode, text, tag):
    admission = [marker for marker in ADMISSION_MARKERS if marker in text]
    if admission:
        return 'inconclusive', 'the probe was not admitted: ' + ', '.join(admission)
    if returncode == 0:
        if 'PASS ' + tag in text:
            return 'allowed', 'the non-login context reopened the key'
        return 'inconclusive', 'the probe exited zero without reporting PASS'
    denial = [marker for marker in DENIAL_MARKERS if marker in text]
    if denial:
        return 'denied', 'the OS refused the key: ' + ', '.join(denial)
    return 'inconclusive', 'the probe refused for an unrecognised reason'


def state_shape(state):
    root = state.get('root')
    if (not isinstance(root, dict) or root.get('kind') != 'secure_enclave'
            or not set(root) <= {'kind', 'tag'}):
        raise ValueError('state does not name a Secure Enclave root')
    tag = root.get('tag')
    if not isinstance(tag, str) or not tag.startswith('anpio-key/acceptance-'):
        raise ValueError('state label is outside the acceptance namespace')
    hint = state.get('tag_hint')
    if not isinstance(hint, str) or hint != tag[len('anpio-key/'):]:
        raise ValueError('state label and hint disagree')
    return tag


def parse_state(content, path='state'):
    if len(content) > MAX_STATE:
        raise ValueError(path + ' is too large')
    try:
        state = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(path + ' is not JSON: ' + str(error)) from error
    if not isinstance(state, dict) or state.get('schema') != 1:
        raise ValueError(path + ' does not carry schema 1')
    tag = state_shape(state)
    for key in ('ciphertext_b64', 'hs_sha256'):
        if not isinstance(state.get(key), str):
            raise ValueError(path + ' has no ' + key)
    return state, tag


def read_user_state(path, expected_uid):
    """Read a state file owned by the invoking user without following links."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode):
            raise ValueError('state must be a regular file')
        if meta.st_uid != expected_uid:
            raise ValueError('state owner does not match the invoking user')
        if meta.st_mode & 0o022:
            raise ValueError('state must not be group/world writable')
        if meta.st_size > MAX_STATE:
            raise ValueError('state is too large')
        chunks = []
        remaining = MAX_STATE + 1
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b''.join(chunks)
    finally:
        os.close(fd)
    state, tag = parse_state(content, path=path)
    return content, state, tag


def check_tree(source):
    count = 0
    size = 0
    for root, directories, files in os.walk(source, followlinks=False):
        base = Path(root)
        for entry in [base, *(base / name for name in directories),
                      *(base / name for name in files)]:
            meta = entry.lstat()
            if stat.S_ISLNK(meta.st_mode):
                raise ValueError('bundle contains a symbolic link')
            if not (stat.S_ISREG(meta.st_mode) or stat.S_ISDIR(meta.st_mode)):
                raise ValueError('bundle contains a special file')
            count += 1
            size += meta.st_size
    if count > 512 or size > 128 * 1024 * 1024:
        raise ValueError('bundle exceeds the acceptance bound')


def stage_binary(binary, digest, stage):
    binary = Path(binary)
    parent = binary.parent
    bundle = parent.parent.parent
    if (parent.name == 'MacOS' and bundle.suffix == '.app'
            and (bundle / 'Contents' / 'embedded.provisionprofile').is_file()):
        check_tree(bundle)
        destination = stage / bundle.name
        shutil.copytree(bundle, destination, symlinks=False)
        staged = destination / 'Contents' / 'MacOS' / binary.name
    else:
        staged = stage / 'se-persistence'
        shutil.copyfile(binary, staged)
        staged.chmod(0o755)
    if sha256_file(staged) != digest:
        raise ValueError('staged probe digest changed')
    return staged


def job_spec(label, binary, state, log, account, session_create=False):
    spec = {
        'Label': label,
        'ProgramArguments': [str(binary), 'open', str(state)],
        'UserName': account.pw_name,
        'RunAtLoad': True,
        'KeepAlive': False,
        'LaunchOnlyOnce': True,
        'ProcessType': 'Background',
        'WorkingDirectory': '/',
        'StandardOutPath': str(log),
        'StandardErrorPath': str(log),
        'EnvironmentVariables': {
            'PATH': '/usr/bin:/bin:/usr/sbin:/sbin',
            'HOME': account.pw_dir,
            'USER': account.pw_name,
            'LOGNAME': account.pw_name,
            'TMPDIR': '/private/tmp',
            'LANG': 'en_US.UTF-8',
        },
    }
    if session_create:
        spec['SessionCreate'] = True
    return spec


def launchctl_print(label):
    result = subprocess.run(['/bin/launchctl', 'print', 'system/' + label],
                            capture_output=True, text=True, timeout=15)
    if result.returncode:
        return None
    return result.stdout


def terminal(text):
    return any(marker in text for marker in TERMINAL_MARKERS)


def wait_for_probe(label, log, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = log.read_text(errors='replace') if log.exists() else ''
        status = launchctl_print(label)
        if terminal(text) or status is None or 'state = exited' in status:
            time.sleep(0.3)
            text = log.read_text(errors='replace') if log.exists() else ''
            return text, status or ''
        time.sleep(0.5)
    raise ValueError('system probe did not finish within ' + str(timeout) + ' seconds')


def exit_code(status, text):
    match = re.search(r'last exit code = (\d+)', status)
    if match:
        return int(match.group(1))
    return 0 if 'PASS ' in text else 1


def run_one_probe(stage, staged_binary, staged_state, account, tag,
                  creator_session, timeout, session_create):
    suffix = 'session-create' if session_create else 'raw'
    label = 'org.anpio-key.system-context-check.' + stage.name + '.' + suffix
    log = stage / ('probe-' + suffix + '.log')
    log.touch(mode=0o644)
    log.chmod(0o644)
    # launchd opens StandardOutPath as the job user before exec.
    os.chown(log, account.pw_uid, account.pw_gid)
    plist = stage / ('probe-' + suffix + '.plist')
    plist.write_bytes(plistlib.dumps(job_spec(
        label, staged_binary, staged_state, log, account, session_create)))
    plist.chmod(0o644)
    try:
        result = subprocess.run(['/bin/launchctl', 'bootstrap', 'system', str(plist)],
                                capture_output=True, text=True, timeout=20)
        if result.returncode:
            raise ValueError('cannot bootstrap the system probe: ' + result.stderr.strip())
        text, status = wait_for_probe(label, log, timeout)
    finally:
        subprocess.run(['/bin/launchctl', 'bootout', 'system/' + label],
                       capture_output=True, timeout=20)
    context = parse_context(text)
    confirmed = context_confirmed(context, account.pw_uid, creator_session)
    code = exit_code(status, text)
    verdict, detail = classify(code, text, tag)
    return {
        'mode': 'system-launchd' + ('-session-create' if session_create else ''),
        'session_create': session_create,
        'label': label,
        'context': context,
        'context_confirmed': confirmed,
        'creator_session': creator_session,
        'returncode': code,
        'classification': 'inconclusive' if not confirmed else verdict,
        'detail': detail if confirmed else 'the Agent kernel identity or a separate audit session was not confirmed',
        'output': text,
        'launchd_status': status[-8192:],
        'log': str(log),
    }


def system_phase(args):
    if sys.platform != 'darwin' or os.geteuid() != 0:
        raise ValueError('the system phase requires macOS root')
    if not re.fullmatch('[0-9a-f]{64}', args.sha256):
        raise ValueError('expected a lowercase SHA-256')
    if args.state is None or args.state_uid is None or args.creator_session is None:
        raise ValueError('the system phase requires --state, --state-uid and --creator-session')
    binary = Path(args.binary).resolve(strict=True)
    if binary.is_symlink() or not binary.is_file():
        raise ValueError('the probe must be a regular file')
    if sha256_file(binary) != args.sha256:
        raise ValueError('probe digest mismatch')
    signature = signature_report(binary, args.sha256, args.team_id, args.application_id)
    account = validate_agent(args.agent_user)
    content, state, tag = read_user_state(args.state, args.state_uid)
    state_sha = sha256_bytes(content)
    stage = Path(tempfile.mkdtemp(prefix=STAGE_PREFIX, dir='/Library'))
    stage.chmod(0o755)
    staged_state = stage / 'state.json'
    staged_state.write_bytes(content)
    staged_state.chmod(0o644)
    staged_binary = stage_binary(binary, args.sha256, stage)
    probes = []
    for session_create in ([False, True] if args.session_create else [False]):
        probes.append(run_one_probe(stage, staged_binary, staged_state, account, tag,
                                    args.creator_session, args.timeout, session_create))
    denied = all(probe['classification'] == 'denied' for probe in probes)
    report = {
        'schema': 1,
        'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'stage': str(stage),
        'state_sha256': state_sha,
        'tag': tag,
        'agent': {'name': account.pw_name, 'uid': account.pw_uid},
        'signature': signature,
        'probes': probes,
        'non_login_denied': denied,
        'hardware_acceptance_complete': False,
        'lifecycle_acceptance_complete': False,
        'protected_supported': False,
        'boundary_decision_required': not denied,
        'pending': PENDING,
    }
    (stage / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    (stage / 'result.json').chmod(0o644)
    print(json.dumps(report, indent=2))
    return 0


def execute(binary, *arguments, timeout):
    return subprocess.run([str(binary), *map(str, arguments)],
                          env=os.environ.copy(), capture_output=True, timeout=timeout)


def require_success(result, operation):
    if result.returncode:
        detail = b'\n'.join((result.stdout, result.stderr)).decode(errors='replace').strip()
        raise ValueError(operation + ' failed (' + str(result.returncode) + '): ' + detail)
    return b'\n'.join((result.stdout, result.stderr)).decode(errors='replace')


def run_phase(args):
    if sys.platform != 'darwin':
        raise ValueError('macOS only')
    if os.geteuid() == 0:
        raise ValueError('run from the login user\'s terminal; the key is created in the login context')
    if not re.fullmatch('[0-9a-f]{64}', args.sha256):
        raise ValueError('expected a lowercase SHA-256')
    binary = Path(args.binary).resolve(strict=True)
    signature = signature_report(binary, args.sha256, args.team_id, args.application_id)
    work = Path(tempfile.mkdtemp(prefix='anp-se-system-context-'))
    work.chmod(0o700)
    state = work / 'state.json'
    tag = 'acceptance-' + uuid.uuid4().hex
    report = {
        'schema': 1,
        'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'binary': str(binary),
        'candidate_sha256': args.sha256,
        'team_id': args.team_id,
        'application_identifier': args.application_id,
        'agent_user': args.agent_user,
        'tag': tag,
        'signature': signature,
        'phases': {},
        'creator_context': None,
        'probes': [],
        'non_login_denied': None,
        'hardware_acceptance_complete': False,
        'lifecycle_acceptance_complete': False,
        'protected_supported': False,
        'boundary_decision_required': False,
        'pending': PENDING,
        'scope_limitations': [
            'a refusal closes only the non-login launchd context; it does not establish UID isolation',
            'a positive result requires a documented boundary restatement or a user-presence control',
            'the probe binary is a test-only example, not a release command',
        ],
    }
    created = False
    try:
        result = execute(binary, 'create', state, tag, timeout=args.timeout)
        require_success(result, 'create')
        created = True
        creator_text = b'\n'.join((result.stdout, result.stderr)).decode(errors='replace')
        report['creator_context'] = parse_context(creator_text)
        if report['creator_context'] is None:
            raise ValueError('creator process did not report its kernel context')
        report['phases']['create'] = 'ok'

        result = execute(binary, 'open', state, timeout=args.timeout)
        text = require_success(result, 'login-context open')
        if 'PASS ' + tag not in text:
            raise ValueError('the login-context positive control did not report PASS')
        report['phases']['login_open'] = 'ok'

        command = ['/usr/bin/sudo', '--', '/usr/bin/python3', '-I',
                   str(Path(__file__).resolve()),
                   '--state', str(state), '--state-uid', str(os.getuid()),
                   '--binary', str(binary), '--sha256', args.sha256,
                   '--team-id', args.team_id, '--application-id', args.application_id,
                   '--agent-user', args.agent_user,
                   '--creator-session', str(report['creator_context']['audit_session']),
                   '--timeout', str(args.timeout)]
        if args.session_create:
            command.append('--session-create')
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=args.timeout + 60)
        if result.returncode:
            raise ValueError('system phase failed: ' + (result.stderr or result.stdout).strip())
        system = json.loads(result.stdout)
        report['phases']['system_probe'] = 'ok'
        report['probes'] = system['probes']
        report['stage'] = system['stage']
        report['non_login_denied'] = system['non_login_denied']
        report['boundary_decision_required'] = system['boundary_decision_required']
    except (ValueError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        report['error'] = str(error)
    finally:
        if created:
            try:
                result = execute(binary, 'delete', state, timeout=args.timeout)
                require_success(result, 'delete')
                if 'DELETED ' + tag not in b'\n'.join((result.stdout, result.stderr)).decode(
                        errors='replace'):
                    raise ValueError('delete did not report DELETED')
                report['phases']['delete'] = 'ok'
                created = False
                gone = execute(binary, 'open', state, timeout=args.timeout)
                if gone.returncode == 0:
                    raise ValueError('the envelope still opened after the SE key was deleted')
                detail = b'\n'.join((gone.stdout, gone.stderr)).decode(errors='replace')
                if not any(marker in detail for marker in DENIAL_MARKERS[:4]
                           + ['no key with that label', 'cannot use it']):
                    raise ValueError('post-delete open failed for an unexpected reason: ' + detail)
                report['phases']['delete_verified'] = 'ok'
            except (ValueError, OSError, subprocess.SubprocessError) as error:
                report['phases']['cleanup'] = str(error)
                report['cleanup_failed'] = True
        if report.get('cleanup_failed'):
            # Keep the public state so the operator can delete the exact label.
            report['work_directory'] = str(work)
        else:
            shutil.rmtree(work, ignore_errors=True)
    report['passed'] = (
        report['non_login_denied'] is True
        and not report.get('error')
        and report.get('cleanup_failed') is not True
        and report['phases'].get('login_open') == 'ok'
        and report['phases'].get('delete_verified') == 'ok'
        and all(probe.get('context_confirmed') for probe in report['probes'])
    )
    if args.out:
        args.out.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


def finish_phase(stage):
    if sys.platform != 'darwin' or os.geteuid() != 0:
        raise ValueError('finishing requires macOS root')
    stage = Path(stage).absolute()
    if stage.parent != Path('/Library') or not stage.name.startswith(STAGE_PREFIX):
        raise ValueError('unexpected system-context test directory')
    meta = stage.lstat()
    if stat.S_ISLNK(meta.st_mode) or not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0:
        raise ValueError('expected a root-owned test directory')
    removed = []
    for plist in stage.glob('probe-*.plist'):
        try:
            label = plistlib.loads(plist.read_bytes())['Label']
        except (KeyError, plistlib.InvalidFileException):
            continue
        status = launchctl_print(label)
        if status is not None and 'state = running' in status:
            raise ValueError(label + ' is still running; wait for completion')
        result = subprocess.run(['/bin/launchctl', 'bootout', 'system/' + label],
                                capture_output=True, text=True, timeout=20)
        if result.returncode and 'Could not find service' not in result.stderr:
            raise ValueError('cannot boot out ' + label + ': ' + result.stderr.strip())
        removed.append(label)
    print('Removed system-context jobs; evidence retained at ' + str(stage))
    for label in removed:
        print('  ' + label)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--binary', type=Path,
                        help='signed se-persistence example or its app bundle executable')
    parser.add_argument('--sha256',
                        help='reviewed lowercase SHA-256 of --binary')
    parser.add_argument('--team-id')
    parser.add_argument('--application-id')
    parser.add_argument('--agent-user', default='_anpagent')
    parser.add_argument('--state', type=Path, help='internal: state file from the login phase')
    parser.add_argument('--state-uid', type=int, help='internal: owning UID of --state')
    parser.add_argument('--creator-session', type=int,
                        help='internal: audit session of the login-context creator')
    parser.add_argument('--session-create', action='store_true',
                        help='also run a job with an explicit new security audit session')
    parser.add_argument('--timeout', type=int, default=120)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--finish', type=Path,
                        help='boot out the jobs of a completed run; retain its evidence')
    args = parser.parse_args()
    try:
        if args.finish:
            finish_phase(args.finish)
            return 0
        if args.binary is None or args.sha256 is None or args.team_id is None \
                or args.application_id is None:
            raise ValueError('--binary, --sha256, --team-id and --application-id are required')
        if os.geteuid() == 0:
            return system_phase(args)
        return run_phase(args)
    except (ValueError, OSError, KeyError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
