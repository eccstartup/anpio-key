"""Real SE joint acceptance; invoked only inside test-runtime's disposable service.
The public fixture password is not a production secret. No automatic UI consent.
"""
import hashlib
import importlib.util
import json
import os
import plistlib
import re
from pathlib import Path
import shutil
import shlex
import signal
import stat
import subprocess
import sys
import time
from types import SimpleNamespace

import acceptance_signing


def sleep_times(output):
    values = {}
    for name in ('sleeptime', 'waketime'):
        match = re.search(r'^kern\.' + name + r': \{ sec = (\d+), usec = (\d+) \}', output, re.M)
        if not match:
            raise ValueError('missing kernel sleep/wake evidence: ' + name)
        seconds, micros = map(int, match.groups())
        if not 0 <= micros < 1_000_000:
            raise ValueError('invalid kernel timestamp')
        values[name] = seconds + micros / 1_000_000
    return values


def kernel_sleep_times():
    result = subprocess.run(['/usr/sbin/sysctl', 'kern.sleeptime', 'kern.waketime'],
                            capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise ValueError('kernel sleep evidence unavailable: ' + result.stderr)
    return sleep_times(result.stdout)


def verify_sleep_transition(before, after, started, finished, long_sleep=False):
    sleep, wake = after['sleeptime'], after['waketime']
    if sleep <= before['sleeptime'] or wake <= before['waketime']:
        raise ValueError('no new kernel sleep/wake pair')
    if not started <= sleep < wake <= finished:
        raise ValueError('sleep/wake pair outside acceptance interval')
    if long_sleep:
        if wake - sleep <= 900:
            raise ValueError('long sleep must cross the original 900-second session limit')
        if finished - started > 2100:
            raise ValueError('long sleep exceeded the 2100-second acceptance window')
        return
    if wake - sleep < 6:
        raise ValueError('sleep must exceed the five-second heartbeat window')
    if finished - started > 90:
        raise ValueError('transition exceeded short acceptance window; approval expiry could confound evidence')


def wait_for_sleep_transition(before, started, read_times=None, clock=None, pause=None,
                              long_sleep=False, observe=None):
    read_times = read_times or kernel_sleep_times
    clock = clock or time.time
    pause = pause or time.sleep
    last_pair = None
    while True:
        after = read_times()
        finished = clock()
        if finished < started:
            raise ValueError('wall clock moved backwards during sleep acceptance')
        limit = 2100 if long_sleep else 90
        if finished - started > limit:
            raise ValueError(f'no valid sleep/wake pair within {limit} seconds')
        if after['sleeptime'] > before['sleeptime'] and after['waketime'] > before['waketime']:
            pair = (after['sleeptime'], after['waketime'])
            if pair != last_pair:
                if observe:
                    observe(after, finished)
                last_pair = pair
            if long_sleep and after['waketime'] - after['sleeptime'] <= 900:
                if not started <= after['sleeptime'] < after['waketime'] <= finished:
                    raise ValueError('sleep/wake pair outside acceptance interval')
                # Maintenance wakes can expose short pairs before the operator
                # wakes the display. Keep observing; never sum separate sleeps.
                pause(.5)
                continue
            verify_sleep_transition(before, after, started, finished, long_sleep=long_sleep)
            return after, finished
        pause(.5)


def operator_sleep_transition(long_sleep=False):
    before = kernel_sleep_times()
    started = time.time()
    timing = ('leave asleep for 16 minutes, then wake within 35 minutes. '
              if long_sleep else 'wait at least 6 seconds, then wake within 90 seconds. ')
    print('READY FOR MANUAL SLEEP: use Apple menu Sleep now; ' + timing +
          'Wake detection is automatic; DO NOT press Enter. '
          'This script does not trigger sleep.', flush=True)
    def observe(after, finished):
        print('KERNEL_SLEEP_EVIDENCE ' + json.dumps({'before': before, 'after': after,
              'started': started, 'finished': finished,
              'sleep_seconds': after['waketime'] - after['sleeptime']}), flush=True)
        if long_sleep and after['waketime'] - after['sleeptime'] <= 900:
            print('WAIT short sleep/wake pair; possibly a maintenance wake. '
                  'Still require one kernel sleep longer than 900 seconds within 35 minutes; '
                  'separate sleeps are not added together.', flush=True)
    wait_for_sleep_transition(before, started, long_sleep=long_sleep, observe=observe)


def probe_result(label, action, timeout):
    started = time.monotonic()
    try:
        result = action()
        elapsed = time.monotonic() - started
        ok = result.returncode == 0
        print(f'{"PASS" if ok else "FAIL"} post-relogin probe {label} '
              f'elapsed={elapsed:.3f}s exit={result.returncode} '
              f'stdout={(result.stdout or "").strip()[:120]!r} '
              f'stderr={(result.stderr or "").strip()[:240]!r}', flush=True)
        return ok
    except subprocess.TimeoutExpired:
        print(f'FAIL post-relogin probe {label} timeout={timeout}s '
              f'elapsed={time.monotonic() - started:.3f}s', flush=True)
    except Exception as error:
        print(f'FAIL post-relogin probe {label} elapsed={time.monotonic() - started:.3f}s '
              f'{type(error).__name__}: {error}', flush=True)
    return False


def fresh_job_probe(base):
    """One-shot launchd job created after relogin; never authority or retries."""
    label = 'org.anpio-key.logout-check.probe.' + str(os.getpid())
    marker = base / 'post-relogin-probe.marker'
    spec_path = base / 'post-relogin-probe.plist'
    try:
        marker.unlink()
    except FileNotFoundError:
        pass
    spec = {'Label': label, 'ProgramArguments': ['/bin/sh', '-c', 'echo fresh-job-ok > ' + str(marker)],
            'RunAtLoad': True, 'KeepAlive': False, 'LaunchOnlyOnce': True, 'SessionCreate': True,
            'ProcessType': 'Background', 'WorkingDirectory': '/',
            'StandardOutPath': str(base / 'post-relogin-probe.log'),
            'StandardErrorPath': str(base / 'post-relogin-probe.log')}
    spec_path.write_bytes(plistlib.dumps(spec))
    spec_path.chmod(0o644)
    try:
        bootstrap = subprocess.run(['/bin/launchctl', 'bootstrap', 'system', str(spec_path)],
                                   capture_output=True, text=True, timeout=6, cwd='/')
        if bootstrap.returncode:
            return bootstrap
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline and not marker.exists():
            time.sleep(.1)
        text = marker.read_text() if marker.exists() else ''
        return subprocess.CompletedProcess([], 0 if text.strip() == 'fresh-job-ok' else 1, text, '')
    finally:
        try:
            subprocess.run(['/bin/launchctl', 'bootout', 'system/' + label],
                           capture_output=True, text=True, timeout=6, cwd='/')
        except subprocess.SubprocessError:
            pass


def log_post_relogin_probes(checks):
    """Bounded layer probes after relogin. Evidence only; never unlocks or signs."""
    python = str(Path(sys.executable).resolve())
    survivor = lambda *command: subprocess.run(list(command), capture_output=True, text=True,
                                               timeout=6, env=checks.env, cwd='/')
    probe_result('survivor-true', lambda: survivor('/usr/bin/true'), 5)
    probe_result('survivor-python', lambda: survivor(python, '-I', '-c', 'print("probe-ok")'), 5)
    broker = getattr(checks.args, 'process_broker', None)
    if not broker:
        return
    # After any broker timeout the late reply stays in the pipe; later broker
    # requests would read stale replies and produce bogus fast results, so stop
    # the broker layer there. The launchd layer does not use the broker.
    broker_ok = probe_result('broker-root-true', lambda: broker.run(['/usr/bin/true'], {}, checks.env, timeout=2), 2)
    if broker_ok:
        for name, user in (('admin', checks.admin), ('agent', checks.agent)):
            if not probe_result('broker-' + name + '-python', lambda user=user: broker.run(
                    [python, '-I', '-c', 'print("probe-ok")'],
                    checks.credentials(user), checks.env, timeout=4), 4):
                break
    probe_result('launchd-fresh-job', lambda: fresh_job_probe(checks.base), 20)


POST_RELOGIN_LAUNCHER = Path('/Library/ANPIOKeyLogoutChecks-post-relogin.sh')


def write_post_relogin_state(checks, request, pending):
    """Serialize only what the new-session checker needs; root-owned, 0600."""
    base = checks.base
    result = base / 'post-relogin-result.json'
    try:
        result.unlink()
    except FileNotFoundError:
        pass
    state = {
        'config': checks.config,
        'path': str(checks.path),
        'base': str(base),
        'binary': str(Path(checks.args.binary).resolve()),
        'admin_uid': checks.admin.pw_uid,
        'agent_uid': checks.agent.pw_uid,
        'key': checks.key,
        'policy_id': checks.policy_id,
        'request': request,
        'pending': pending,
        'env': checks.env,
        'admin_credentials': checks.credentials(checks.admin),
        'agent_credentials': checks.credentials(checks.agent),
    }
    state_path = base / 'post-relogin-state.json'
    state_path.write_text(json.dumps(state))
    state_path.chmod(0o600)
    return state_path


def write_post_relogin_launcher(state_path):
    """Fixed root-only entry point so the operator does not type stage paths."""
    launcher = POST_RELOGIN_LAUNCHER
    if launcher.is_symlink() or launcher.exists():
        meta = launcher.lstat()
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0:
            raise ValueError('refusing to replace untrusted post-relogin launcher')
    # The state lives in the temporary service directory; the checker script
    # lives beside this module in the retained stage directory.
    module = Path(__file__).resolve().parent / 'post-relogin.py'
    script = ('#!/bin/sh\n'
              'state=' + shlex.quote(str(state_path)) + '\n'
              'if [ ! -f "$state" ]; then\n'
              '  echo "no pending logout acceptance at $state; start a new run" >&2\n'
              '  exit 1\n'
              'fi\n'
              'exec /usr/bin/python3 ' + shlex.quote(str(module)) + ' "$state"\n')
    launcher.write_text(script)
    launcher.chmod(0o700)
    return launcher


def wait_for_post_relogin_result(base, timeout=600):
    result_path = base / 'post-relogin-result.json'
    deadline = time.monotonic() + timeout
    while not result_path.exists():
        if time.monotonic() >= deadline:
            raise ValueError('post-relogin checker did not run within '
                             f'{timeout} seconds; run: sudo sh {POST_RELOGIN_LAUNCHER}')
        time.sleep(.5)
    meta = result_path.lstat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
        raise ValueError('post-relogin result is not a root-owned regular file')
    outcome = json.loads(result_path.read_text())
    if not outcome.get('ok'):
        raise ValueError('post-relogin checker failed: ' + str(outcome.get('error')))
    return outcome


POST_REBOOT_LAUNCHER = Path('/Library/ANPIOKeyRebootChecks-post-reboot.sh')


def host_boottime():
    """Seconds since the epoch at which the running kernel booted."""
    result = subprocess.run(['/usr/sbin/sysctl', '-n', 'kern.boottime'],
                            capture_output=True, text=True, timeout=10)
    match = re.search(r'sec = (\d+), usec = (\d+)', result.stdout)
    if result.returncode or not match:
        raise ValueError('kernel boot time unavailable: ' + result.stderr)
    seconds, micros = map(int, match.groups())
    if not 0 <= micros < 1_000_000:
        raise ValueError('invalid kernel boot timestamp')
    return seconds + micros / 1_000_000


def write_post_reboot_state(checks, request, pending):
    """Serialize only what the fresh-boot checker needs; root-owned, 0600."""
    base = checks.base
    result = base / 'post-reboot-result.json'
    try:
        result.unlink()
    except FileNotFoundError:
        pass
    status = checks.cli(checks.admin, 'status')
    if status.returncode != 0:
        raise ValueError('pre-reboot status failed: ' + status.stderr)
    current = json.loads(status.stdout)
    if current['instance_id'] != checks.config['instance_id']:
        raise ValueError('pre-reboot instance mismatch')
    state = {
        'config': checks.config,
        'path': str(checks.path),
        'base': str(base),
        'binary': str(Path(checks.args.binary).resolve()),
        'admin_uid': checks.admin.pw_uid,
        'agent_uid': checks.agent.pw_uid,
        'key': checks.key,
        'policy_id': checks.policy_id,
        'request': request,
        'pending': pending,
        'env': checks.env,
        'admin_credentials': checks.credentials(checks.admin),
        'agent_credentials': checks.credentials(checks.agent),
        'pre_boottime': host_boottime(),
        'pre_boot_epoch': current['boot_epoch'],
        'instance_id': current['instance_id'],
        'fixture': {'document': checks.fixture['manifest']['document'],
                    'helper': str(checks.fixture['helper']),
                    'vault_id': checks.fixture['vault_id']},
        'helper': str(base / 'LoginHelper.app/Contents/MacOS/anpio-key'),
        'helper_sha256': str(checks.args.se_login_sha256),
        'hardware': checks.fixture['manifest']['hot_hardware'],
    }
    state_path = base / 'post-reboot-state.json'
    state_path.write_text(json.dumps(state))
    state_path.chmod(0o600)
    return state_path


def write_post_reboot_launcher(state_path):
    """Fixed root-only entry point so the operator does not type stage paths."""
    launcher = POST_REBOOT_LAUNCHER
    if launcher.is_symlink() or launcher.exists():
        meta = launcher.lstat()
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0:
            raise ValueError('refusing to replace untrusted post-reboot launcher')
    module = Path(__file__).resolve().parent / 'post-reboot.py'
    script = ('#!/bin/sh\n'
              'state=' + shlex.quote(str(state_path)) + '\n'
              'if [ ! -f "$state" ]; then\n'
              '  echo "no pending reboot acceptance at $state; start a new run" >&2\n'
              '  exit 1\n'
              'fi\n'
              'exec /usr/bin/python3 ' + shlex.quote(str(module)) + ' "$state"\n')
    launcher.write_text(script)
    launcher.chmod(0o700)
    return launcher


def wait_for_manual_reboot(timeout=1800):
    """Hold the runner open until the machine reboots and kills this process."""
    print('READY FOR MANUAL REBOOT: save work and restart the Mac now. '
          'This script does not restart the machine. '
          'After logging in again, run the post-reboot command printed above.', flush=True)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(1)
    raise ValueError('machine did not reboot within '
                     f'{timeout} seconds; the prepared approval is abandoned')


def validate_bundle(bundle):
    """Bound a privileged copy and refuse links, including the bundle itself."""
    if bundle.suffix != '.app' or bundle.is_symlink():
        raise ValueError('expected a real app bundle')
    total = 0
    paths = [bundle, *bundle.rglob('*')]
    if len(paths) > 256:
        raise ValueError('bundle has too many entries')
    for path in paths:
        mode = path.lstat().st_mode
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise ValueError('bundle contains a link or special file')
        total += path.stat().st_size
    if total > 160 * 1024 * 1024:
        raise ValueError('bundle exceeds acceptance size bound')
    if not (bundle / 'Contents/embedded.provisionprofile').is_file():
        raise ValueError('bundle lacks an embedded profile')


_release_tool = None


def load_release_tool():
    global _release_tool
    if _release_tool is None:
        path = Path(__file__).resolve().parent.parent / 'se-release.py'
        spec = importlib.util.spec_from_file_location('anp_se_release', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _release_tool = module
    return _release_tool


def install_helper(source, destination, team, application, upgrade):
    """Use the shipped release path, so ownership, identity and atomicity are real."""
    release = load_release_tool()
    return release.install(SimpleNamespace(
        bundle=Path(source), destination=Path(destination), upgrade=upgrade,
        team_id=team, application_id=application,
        profile_sha256=None, require_notarized=False))


def helper_digest(bundle):
    return hashlib.sha256((Path(bundle) / 'Contents/MacOS/anpio-key').read_bytes()).hexdigest()


def parse_entitlements(output):
    text = output.decode(errors='replace') if isinstance(output, bytes) else output
    start = text.find('<?xml')
    end = text.find('</plist>', start)
    if start < 0 or end < 0:
        raise ValueError('the helper has no readable entitlements: ' + text.strip())
    value = plistlib.loads(text[start:end + len('</plist>')].encode())
    if not isinstance(value, dict) or not value:
        raise ValueError('the helper entitlements are empty or not a dictionary')
    return value


def with_application_identifier(entitlements, identifier):
    key = 'com.apple.application-identifier'
    old = entitlements.get(key)
    if not isinstance(old, str) or not old:
        raise ValueError('the helper has no application identifier entitlement')
    changed = dict(entitlements)
    changed[key] = identifier
    groups = entitlements.get('keychain-access-groups')
    if groups is None:
        changed['keychain-access-groups'] = [identifier]
    else:
        changed['keychain-access-groups'] = [identifier if group == old else group for group in groups]
    return changed


def require_refused_helper(kind, returncode, text):
    # An ad-hoc copy loses the entitlements: creating a persistent SE key fails
    # with errSecMissingEntitlement, while reading an existing label only sees
    # an invisible key group and surfaces errSecItemNotFound. Both are refused
    # by the OS before any session; the probe carries the entitlement evidence.
    expected = {'foreign-identity': 'the keychain has no key with that label',
                'keychain-permission': 'the keychain has no key with that label'}
    if kind not in expected:
        raise ValueError('unknown helper identity probe: ' + kind)
    if returncode == 0:
        raise ValueError(f'the {kind} helper reported success: ' + text)
    if 'SE session active for exact key' in text:
        raise ValueError(f'the {kind} helper established an SE session: ' + text)
    if expected[kind] not in text:
        raise ValueError(f'the {kind} helper refusal did not name {expected[kind]!r}: ' + text)


def require_unavailable_probe(text):
    if 'macOS Secure Enclave ... NOT USABLE' not in text:
        raise ValueError('the foreign-signed helper did not report an unavailable SE root: ' + text)
    # The persistence half is what the Apple signature unlocks; without it the
    # keychain write is refused for the missing entitlement.
    if 'errSecMissingEntitlement' not in text:
        raise ValueError('the unavailable SE root did not name the missing entitlement: ' + text)


def codesign_output(arguments):
    result = subprocess.run(['/usr/bin/codesign', *map(str, arguments)], capture_output=True,
                            timeout=60, env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}, cwd='/')
    return result, (result.stdout + result.stderr).decode(errors='replace')


def helper_entitlements(bundle):
    _, text = codesign_output(['-d', '--entitlements', ':-', str(bundle)])
    return parse_entitlements(text)


def helper_is_adhoc(bundle):
    _, text = codesign_output(['-d', '--verbose=2', str(bundle)])
    return 'Signature=adhoc' in text


def helper_authority(bundle):
    _, text = codesign_output(['-d', '--verbose=2', str(bundle)])
    for line in text.splitlines():
        if line.startswith('Authority='):
            return line[len('Authority='):].strip()
    raise ValueError('cannot determine the helper signing identity: ' + text.strip())


class Checks(acceptance_signing.Checks):
    def approval_seconds(self, ending):
        # The fixture policy's duration bound and the approval expiry must come
        # from one source; a longer approval is refused as ADMIN_OPERATION_INVALID.
        return self.grant_limit() if ending in ('logout', 'reboot') else 240

    def exercise_upgrade(self, destination, upgrade_bundle):
        release = load_release_tool()
        old_digest = helper_digest(destination)

        tampered = self.base / 'TamperedHelper.app'
        shutil.copytree(upgrade_bundle, tampered)
        binary = tampered / 'Contents/MacOS/anpio-key'
        data = bytearray(binary.read_bytes())
        data[len(data) // 2] ^= 0xff
        binary.write_bytes(data)
        try:
            install_helper(tampered, destination, self.args.helper_team_id,
                           self.args.helper_application_id, True)
        except (release.ReleaseError, ValueError):
            pass
        else:
            raise ValueError('tampered upgrade helper was installed')
        if helper_digest(destination) != old_digest:
            raise ValueError('failed upgrade changed the installed helper')
        release.verify_bundle(destination, self.args.helper_team_id,
                              self.args.helper_application_id, installed=True)
        print('PASS failed upgrade left the installed helper intact', flush=True)

        backup = destination.with_name(destination.name + '.previous')
        backup.mkdir()
        try:
            install_helper(upgrade_bundle, destination, self.args.helper_team_id,
                           self.args.helper_application_id, True)
        except release.ReleaseError as error:
            if 'backup' not in str(error):
                raise
        else:
            raise ValueError('upgrade proceeded with an existing backup')
        finally:
            backup.rmdir()
        if helper_digest(destination) != old_digest:
            raise ValueError('backup-collision check changed the installed helper')
        print('PASS interrupted-replacement backup blocks another upgrade', flush=True)

        report = install_helper(upgrade_bundle, destination, self.args.helper_team_id,
                                self.args.helper_application_id, True)
        if not report['upgrade_continuity']:
            raise ValueError('upgrade continuity was not established')
        if report['candidate_sha256'] != self.args.upgrade_sha256:
            raise ValueError('upgrade candidate digest mismatch')
        if helper_digest(destination) != self.args.upgrade_sha256:
            raise ValueError('installed upgrade digest mismatch')
        if helper_digest(backup) != old_digest:
            raise ValueError('upgrade backup digest mismatch')
        print('PASS helper upgrade continuity ' + json.dumps({
            'continuity': report['upgrade_continuity'], 'old_sha256': old_digest,
            'new_sha256': helper_digest(destination)}), flush=True)

    def upgraded_helper_sign(self, binary):
        command = [str(binary), 'admin', '--config', str(self.path), 'se-session',
                   '--vault-id', self.fixture['vault_id'], '--did', self.key['did'],
                   '--kid', self.key['kid']]
        denied = subprocess.run(command, capture_output=True, text=True, timeout=15,
                                **self.credentials(self.agent), env=self.env, cwd='/')
        if denied.returncode == 0 or 'ADMIN_REQUIRED' not in denied.stderr:
            raise ValueError('upgraded helper accepted the Agent identity')
        print('UI: check the temporary exact key again for the upgraded helper and enter ONLY '
              'the public test password: ' + acceptance_signing.PASSWORD, flush=True)
        log = self.base / 'se-upgrade-helper.log'
        with log.open('w+') as output:
            helper = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output,
                                      stderr=output, **self.credentials(self.admin),
                                      env=self.env, cwd='/')
            try:
                deadline = time.monotonic() + 145
                while time.monotonic() < deadline:
                    if helper.poll() is not None:
                        raise ValueError('upgraded helper exited: ' + log.read_text())
                    if 'SE session active for exact key' in log.read_text():
                        break
                    time.sleep(.2)
                else:
                    raise ValueError('upgraded helper did not establish a real SE session')
                grant = self.grant()
                request = self.signing(grant)
                reply = self.request_as(self.agent, request)
                if reply['code'] != 'OK' or reply['data']['state'] != 'completed':
                    raise ValueError('upgraded helper signature failed: ' + json.dumps(reply))
                public = {'document': self.fixture['manifest']['document'],
                          **reply['data']['result']}
                verified = subprocess.run([str(self.fixture['helper']), 'verify'],
                    input=json.dumps(public), capture_output=True, text=True, timeout=15,
                    **self.credentials(self.admin), env=self.env, cwd='/')
                if verified.returncode != 0 or verified.stdout.strip() != 'VERIFIED':
                    raise ValueError('upgraded signature verification failed: ' + verified.stderr)
                changed = {**public, 'url': 'https://example.com/other'}
                rejected = subprocess.run([str(self.fixture['helper']), 'verify'],
                    input=json.dumps(changed), capture_output=True, text=True, timeout=15,
                    **self.credentials(self.admin), env=self.env, cwd='/')
                if rejected.returncode == 0:
                    raise ValueError('independent verifier accepted a changed target')
                if self.request_as(self.agent, request)['data'] != reply['data']:
                    raise ValueError('upgraded helper retry returned a different result')
                print('PASS upgraded helper signed and retried consistently', flush=True)
            finally:
                if helper.poll() is None:
                    helper.terminate()
                    try:
                        helper.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        helper.kill()
                        helper.wait(timeout=10)
                print('SE upgraded helper log: ' + log.read_text(errors='replace'), flush=True)
        # Replacing and exiting the helper revokes the session's grants; a new
        # grant must still observe the locked key.
        final = self.grant()
        self.expect_locked(final)

    def exercise_key_loss(self, label, helper_command):
        cleanup = self.args.key_loss_cleanup
        binary = cleanup / 'Contents/MacOS/anpio-key'
        if not binary.is_file() or binary.is_symlink():
            raise ValueError('key-loss cleanup is not a signed app bundle')
        if hashlib.sha256(binary.read_bytes()).hexdigest() != self.args.key_loss_cleanup_sha256:
            raise ValueError('key-loss cleanup digest mismatch')

        def delete():
            return subprocess.run([str(binary), '--delete', label], capture_output=True,
                                  text=True, timeout=30, **self.credentials(self.admin),
                                  env=self.env, cwd='/')
        deleted = delete()
        if deleted.returncode != 0:
            raise ValueError('key-loss cleanup failed: ' + deleted.stderr)
        for part in ('private', 'public'):
            if f'FOUND {label} {part} count=1' not in deleted.stdout:
                raise ValueError('key-loss cleanup did not find exactly one ' + part + ' key')
        if deleted.stdout.count('ABSENT_AFTER_DELETE') != 2:
            raise ValueError('key-loss cleanup did not confirm deletion')
        absent = delete()
        if absent.returncode != 0:
            raise ValueError('key-loss absence recheck failed: ' + absent.stderr)
        for part in ('private', 'public'):
            if f'FOUND {label} {part} count=0' not in absent.stdout:
                raise ValueError('key-loss absence was not confirmed by a new process')
        print('PASS disposable SE private/public key deleted by exact label', flush=True)

        log = self.base / 'se-key-loss-helper.log'
        with log.open('w+') as output:
            helper = subprocess.Popen(helper_command, stdin=subprocess.DEVNULL,
                                      stdout=output, stderr=output,
                                      **self.credentials(self.admin), env=self.env, cwd='/')
            try:
                helper.wait(timeout=45)
            except subprocess.TimeoutExpired:
                helper.kill()
                helper.wait(timeout=10)
                raise ValueError('helper stayed alive after its SE key was deleted: '
                                 + log.read_text(errors='replace'))
        text = log.read_text(errors='replace')
        if helper.returncode == 0:
            raise ValueError('helper reported success after its SE key was deleted: ' + text)
        if 'SE session active for exact key' in text:
            raise ValueError('helper established an SE session after its key was deleted')
        if not text.strip():
            raise ValueError('helper produced no refusal after its SE key was deleted')
        print('PASS signed helper cannot establish an SE session after key loss', flush=True)

        self.expect_locked(self.grant())
        print('PASS signing stays locked after key loss; no automatic key re-creation', flush=True)

    def exercise_modified_helper(self, kind, destination):
        """Re-sign a copy and require it to fail before any SE session exists."""
        names = {'foreign-identity': 'ForeignHelper.app',
                 'keychain-permission': 'ChangedPermission.app'}
        if kind not in names:
            raise ValueError('unknown helper identity probe: ' + kind)
        copy = self.base / names[kind]
        shutil.copytree(destination, copy)
        owner = f'{self.admin.pw_uid}:{self.admin.pw_gid}'
        chowned = subprocess.run(['/usr/sbin/chown', '-R', owner, str(copy)],
                                 capture_output=True, text=True, timeout=60, env=self.env, cwd='/')
        if chowned.returncode:
            raise ValueError('cannot hand the probe bundle to the signing user: ' + chowned.stderr)
        # The signing identity lives in the administrator's login keychain;
        # the acceptance process itself is root and has a different keychain.
        env = {**self.env, 'HOME': self.admin.pw_dir}
        if kind == 'foreign-identity':
            command = ['/usr/bin/codesign', '--force', '--options', 'runtime',
                       '--sign', '-', str(copy)]
        elif kind == 'keychain-permission':
            original = helper_entitlements(destination)
            identifier = original.get('com.apple.application-identifier', '') + '.other'
            changed = with_application_identifier(original, identifier)
            entitlement_path = self.base / 'changed.entitlements'
            entitlement_path.write_bytes(plistlib.dumps(changed))
            command = ['/usr/bin/codesign', '--force', '--options', 'runtime',
                       '--entitlements', str(entitlement_path),
                       '--sign', helper_authority(destination), str(copy)]
        signed = subprocess.run(command, capture_output=True, text=True, timeout=300,
                                **self.credentials(self.admin), env=env, cwd='/')
        if signed.returncode:
            raise ValueError('the modified helper could not be re-signed: ' + signed.stderr)
        restored = subprocess.run(['/usr/sbin/chown', '-R', '0:0', str(copy)],
                                  capture_output=True, text=True, timeout=60, env=self.env, cwd='/')
        if restored.returncode:
            raise ValueError('cannot restore the probe bundle ownership: ' + restored.stderr)
        if kind == 'foreign-identity':
            if not helper_is_adhoc(copy):
                raise ValueError('the probe helper did not lose its signing identity')
        else:
            if helper_entitlements(copy)['com.apple.application-identifier'] != identifier:
                raise ValueError('the probe helper kept its former keychain permission')
        print(f'PASS prepared {kind} helper copy', flush=True)

        binary = copy / 'Contents/MacOS/anpio-key'
        if kind == 'foreign-identity':
            # The same probe that is usable under the original signature must
            # report the SE root unavailable once the identity is gone.
            probe = subprocess.run([str(binary), 'probe'], capture_output=True, text=True,
                                   timeout=120, **self.credentials(self.admin),
                                   env={**self.env, 'HOME': self.admin.pw_dir}, cwd='/')
            require_unavailable_probe(probe.stdout + probe.stderr)
            print('FOREIGN_SIGNED_PROBE ' + (probe.stdout + probe.stderr).strip(), flush=True)
            print('PASS foreign-signed helper reports the SE root unavailable', flush=True)

        command = [str(binary), 'admin', '--config', str(self.path), 'se-session',
                   '--vault-id', self.fixture['vault_id'], '--did', self.key['did'],
                   '--kid', self.key['kid']]
        log = self.base / f'se-{kind}-helper.log'
        with log.open('w+') as output:
            helper = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output,
                                      stderr=output, **self.credentials(self.admin),
                                      env=self.env, cwd='/')
            try:
                helper.wait(timeout=60)
            except subprocess.TimeoutExpired:
                helper.kill()
                helper.wait(timeout=10)
                raise ValueError(f'the {kind} helper stayed alive: ' + log.read_text(errors='replace'))
        require_refused_helper(kind, helper.returncode, log.read_text(errors='replace'))
        print(f'{kind} helper refusal: ' + log.read_text(errors='replace').strip(), flush=True)
        print(f'PASS {kind} helper cannot establish an SE session', flush=True)

        self.expect_locked(self.grant())
        print(f'PASS signing stays locked after {kind} refusal; no automatic key re-creation', flush=True)

    def exercise_signing(self):
        manifest = self.fixture['manifest']
        assert manifest.get('fixture_only') is True
        assert manifest['hot_kid'] == self.key['kid']
        hardware = manifest['hot_hardware']
        assert hardware['kind'] == 'secure_enclave', hardware
        # Keep the tag even if later UI/service checks fail: no claim that
        # removing the disposable filesystem also removes a keychain key.
        print('SE temporary wrapping-key locator: ' + json.dumps(hardware), flush=True)
        ending = getattr(self.args, 'se_ending', 'kill')
        bundle = self.args.se_login_bundle
        validate_bundle(bundle)
        source = bundle / 'Contents/MacOS/anpio-key'
        assert hashlib.sha256(source.read_bytes()).hexdigest() == self.args.se_login_sha256
        if ending == 'upgrade':
            upgrade_bundle = self.args.upgrade_bundle
            validate_bundle(upgrade_bundle)
            if helper_digest(upgrade_bundle) != self.args.upgrade_sha256:
                raise ValueError('upgrade helper digest mismatch')
            if self.args.upgrade_sha256 == self.args.se_login_sha256:
                raise ValueError('upgrade helper must be a different build')
            destination = self.base / 'InstalledHelper.app'
            installed = install_helper(bundle, destination, self.args.helper_team_id,
                                       self.args.helper_application_id, False)
            if installed['candidate_sha256'] != self.args.se_login_sha256:
                raise ValueError('initial helper install digest mismatch')
            print('PASS initial helper installed through the release path', flush=True)
        else:
            destination = self.base / 'LoginHelper.app'
            shutil.copytree(bundle, destination)
        binary = destination / 'Contents/MacOS/anpio-key'
        assert hashlib.sha256(binary.read_bytes()).hexdigest() == self.args.se_login_sha256
        info = subprocess.run([str(binary), 'build-info'], capture_output=True, text=True, timeout=15, **self.credentials(self.admin), env=self.env, cwd='/')
        assert info.returncode == 0, info.stderr
        flags = json.loads(info.stdout)
        assert flags['release'] and flags['hardware_se'] and not flags['hardware_software']
        assert not flags['seed_export'] and not flags['protected_supported']
        command = [str(binary), 'admin', '--config', str(self.path), 'se-session',
                   '--vault-id', self.fixture['vault_id'], '--did', self.key['did'], '--kid', self.key['kid']]
        denied = subprocess.run(command, capture_output=True, text=True, timeout=15,
                                **self.credentials(self.agent), env=self.env, cwd='/')
        assert denied.returncode != 0 and 'ADMIN_REQUIRED' in denied.stderr, denied.stderr
        if ending == 'key-loss':
            self.exercise_key_loss(hardware['tag'], command)
            return
        refusal = None
        if ending in ('foreign-identity', 'keychain-permission'):
            self.exercise_modified_helper(ending, destination)
            refusal = ending
            # The original helper must still recover once the modified copy is
            # refused; the rest of the run is the ordinary kill ending.
            ending = 'kill'
        print('UI: check the temporary exact key and enter ONLY the public test password: '
              + acceptance_signing.PASSWORD, flush=True)
        helper_credentials = self.credentials(self.admin)
        if self.args.se_ending in ('logout', 'reboot'):
            import acceptance_graphical
            old_session = acceptance_graphical.session(self.admin, self.path)
            print('OLD_GRAPHICAL_AUDIT_SESSION ' + str(old_session), flush=True)
            command = acceptance_graphical.command(self.admin, self.path, command)
            helper_credentials = {}
        log = self.base / 'se-helper.log'
        with log.open('w+') as output:
            helper = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                      **helper_credentials, env=self.env, cwd='/')
            try:
                deadline = time.monotonic() + 145
                while time.monotonic() < deadline:
                    if helper.poll() is not None:
                        raise ValueError('signed helper exited: ' + log.read_text())
                    if 'SE session active for exact key' in log.read_text():
                        break
                    time.sleep(.2)
                else:
                    raise ValueError('signed helper did not establish a real SE session')
                request = self.signing()
                reply = self.request_as(self.agent, request)
                assert reply['code'] == 'OK' and reply['data']['state'] == 'completed', reply
                public = {'document': manifest['document'], **reply['data']['result']}
                verified = subprocess.run([str(self.fixture['helper']), 'verify'], input=json.dumps(public),
                    capture_output=True, text=True, timeout=15, **self.credentials(self.admin), env=self.env, cwd='/')
                assert verified.returncode == 0 and verified.stdout.strip() == 'VERIFIED', verified.stderr
                changed = {**public, 'url': 'https://example.com/other'}
                rejected = subprocess.run([str(self.fixture['helper']), 'verify'], input=json.dumps(changed),
                    capture_output=True, text=True, timeout=15, **self.credentials(self.admin), env=self.env, cwd='/')
                assert rejected.returncode != 0
                assert self.request_as(self.agent, request)['data'] == reply['data']
                # Prepare an approval before lease loss; it must not recreate
                # authority after teardown advances the management epoch.
                change = self.base / 'stale-grant.json'
                change.write_text(json.dumps({'kind': 'Grant', 'change': {'action': 'Create',
                    'principal_id': self.config['principals'][0]['principal_id'],
                    'key_id': self.key['key_id'], 'policy_id': self.policy_id,
                    'policy_version': 1,
                    # Logout covers operator time away and back; other endings
                    # keep the short window that bounds the check itself.
                    'expiry': int(time.time()) + self.approval_seconds(ending),
                    'max_uses': 1}}))
                change.chmod(0o644)
                prepared = self.cli(self.admin, 'prepare', '--file', change)
                assert prepared.returncode == 0, prepared.stderr
                pending = json.loads(prepared.stdout)['prepared']
                if ending in ('restart', 'crash'):
                    self.restart_service(ending == 'crash')
                elif ending in ('sleep', 'long-sleep'):
                    operator_sleep_transition(long_sleep=ending == 'long-sleep')
                elif ending == 'user-switch':
                    from acceptance_console import operator_user_switch
                    def check_away():
                        cached = self.request_as(self.agent, request)
                        assert cached['code'] != 'OK' or 'result' not in cached.get('data', {}), cached
                        listed = self.request_as(self.agent, {'operation': 'LIST_AUTHORIZED_KEYS'})
                        assert listed['code'] == 'OK' and listed['data']['keys'] == [], listed
                        print('PASS cached signature suppressed and authorized keys empty while other user owns console', flush=True)
                    operator_user_switch(self.admin.pw_uid, check_away)
                elif ending == 'logout':
                    from acceptance_console import operator_logout
                    # Serialization must happen before logout; the surviving
                    # runner cannot start Python after relogin.
                    state_path = write_post_relogin_state(self, request, pending)
                    launcher = write_post_relogin_launcher(state_path)
                    print('ACTION REQUIRED after you log back in: sudo sh ' + str(launcher), flush=True)
                    def check_logged_out():
                        cached = self.request_as(self.agent, request)
                        assert cached['code'] != 'OK' or 'result' not in cached.get('data', {}), cached
                        listed = self.request_as(self.agent, {'operation': 'LIST_AUTHORIZED_KEYS'})
                        assert listed['code'] == 'OK' and listed['data']['keys'] == [], listed
                        print('PASS old cache suppressed and authorized keys empty at login window', flush=True)
                    operator_logout(self.admin.pw_uid, old_session, check_logged_out,
                        lambda: acceptance_graphical.relogin_session(self.admin))
                    context = acceptance_graphical.require_runner_session(
                        acceptance_graphical.relogin_session(self.admin), self.args.runner_audit_context)
                    print('PASS unchanged independent system runner audit context ' + json.dumps(context), flush=True)
                    if getattr(self.args, 'post_relogin_probes', False):
                        started = time.monotonic()
                        log_post_relogin_probes(self)
                        print(f'POST_RELOGIN_PROBE_SECONDS {time.monotonic() - started:.3f}', flush=True)
                    outcome = wait_for_post_relogin_result(self.base)
                    print('PASS post-relogin fresh-session checker ' + json.dumps(outcome['result']), flush=True)
                    if helper.poll() is None:
                        print('SE_HELPER_STATE running_after_relogin; terminating by signal', flush=True)
                        helper.terminate()
                        try:
                            helper.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            helper.kill()
                            helper.wait(timeout=10)
                    else:
                        print('SE_HELPER_STATE exited_after_relogin', flush=True)
                elif ending == 'reboot':
                    # The runner is killed by the reboot; the fresh-boot checker
                    # runs from the operator's new login and writes the verdict.
                    state_path = write_post_reboot_state(self, request, pending)
                    launcher = write_post_reboot_launcher(state_path)
                    print('ACTION REQUIRED after you log in following the reboot: sudo sh '
                          + str(launcher), flush=True)
                    wait_for_manual_reboot()
                elif ending == 'upgrade':
                    # End the live session before replacing the helper, as an
                    # installed upgrade does; everything after must re-earn trust.
                    helper.terminate()
                    try:
                        helper.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        helper.kill()
                        helper.wait(timeout=10)
                    self.exercise_upgrade(destination, upgrade_bundle)
                else:
                    helper.send_signal(signal.SIGSTOP if ending == 'hang' else signal.SIGKILL)
                if ending not in ('logout', 'reboot'):
                    if ending == 'kill':
                        helper.wait(timeout=10)
                    # Allow the documented observation deadline; then require both
                    # cached-result suppression and no authorized keys.
                    deadline = time.monotonic() + 10
                    while True:
                        replay = self.request_as(self.agent, request)
                        if replay['code'] != 'OK' or 'result' not in replay.get('data', {}):
                            break
                        if time.monotonic() >= deadline:
                            raise ValueError('SE session loss did not suppress cached signature')
                        time.sleep(.2)
                    keys = self.request_as(self.agent, {'operation': 'LIST_AUTHORIZED_KEYS'})
                    assert keys['code'] == 'OK' and keys['data']['keys'] == [], keys
                    if ending != 'long-sleep':
                        assert time.time() + 5 < pending['expires_at'], 'approval expired before teardown check'
                    else:
                        assert time.time() > pending['expires_at'], 'long-sleep approval should have expired'
                        print('NOTE old approval and original grant naturally expire during long sleep; '
                              'their rejection alone does not prove session-loss revocation.', flush=True)
                    stale = self.cli(self.admin, 'commit', '--operation-id', pending['operation_id'],
                                     '--digest', pending['digest'])
                    assert stale.returncode != 0, 'old approval survived SE session loss'
                    if ending == 'hang':
                        assert helper.poll() is None, 'hang test requires a live stopped helper'
                        helper.send_signal(signal.SIGCONT)
                        helper.wait(timeout=10)
                        replay = self.request_as(self.agent, request)
                        assert replay['code'] != 'OK' or 'result' not in replay.get('data', {}), replay
                    if ending in ('sleep', 'long-sleep', 'user-switch', 'restart', 'crash'):
                        helper.wait(timeout=10)
                    fresh = self.grant()
                    self.expect_locked(fresh)
                if ending == 'upgrade':
                    self.upgraded_helper_sign(destination / 'Contents/MacOS/anpio-key')
                authority = ('expired authority remains unusable' if ending == 'long-sleep'
                             else 'revocation and stale-approval refusal')
                if ending == 'upgrade':
                    authority += ', failed-upgrade recovery and upgraded-helper signing'
                if refusal:
                    authority += f', {refusal} refusal and original-helper recovery'
                print(f'PASS independently verified SE hot-key signature, retry, changed-target refusal, helper {ending}, cache suppression, {authority} and fresh-grant locked key', flush=True)
            finally:
                if helper.poll() is None:
                    helper.kill()
                    helper.wait(timeout=10)
                print('SE helper log: ' + log.read_text(), flush=True)
                print('Temporary SE wrapping key requires explicit keychain cleanup; locator above. Host lifecycle and raw OS isolation remain unaccepted.', flush=True)
