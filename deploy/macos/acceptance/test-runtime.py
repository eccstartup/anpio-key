#!/usr/bin/env python3
"""Bounded local runtime checks in a separate temporary service instance.
Requires the explicitly provisioned accounts and root. Never touches the running
installation's state, keys, configuration or launchd job. No new accounts created.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid

PYTHON = str(Path(sys.executable).resolve())


def require_success(result, phase):
    if result.returncode != 0:
        signal_note = f' (signal {-result.returncode})' if result.returncode < 0 else ''
        raise ValueError(f'{phase} failed: exit={result.returncode}{signal_note}; '
                         f'stdout={result.stdout!r}; stderr={result.stderr!r}')


def wait_ready(proc, probe, instance_id, timeout=10):
    deadline = time.monotonic() + timeout
    last_error = 'no successful management response'
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise ValueError('temporary service failed to start')
        result = probe()
        if result.returncode == 0:
            status = json.loads(result.stdout)
            if status.get('instance_id') != instance_id:
                raise ValueError('startup management instance mismatch')
            return
        last_error = result.stderr.strip()
        time.sleep(.05)
    raise ValueError('temporary service startup timed out: ' + last_error)


def child_credentials(user, config, extra_admin_group=False):
    groups = [config['agent_gid']]
    if user.pw_uid == config['service_uid']:
        groups.append(config['admin_gid'])
    elif user.pw_uid in config['admin_uids']:
        groups = [config['admin_gid']]
    if extra_admin_group:
        groups.append(config['admin_gid'])
    # Darwin stores EGID in kernel group slot 0. CPython calls setgroups first,
    # then setregid, which can displace slot 0. Reserve it for the primary group
    # so the required socket groups survive. Linux accepts the same list.
    groups = [user.pw_gid, *sorted(set(groups) - {user.pw_gid})]
    return {'user': user.pw_uid, 'group': user.pw_gid, 'extra_groups': groups}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path('/Library/ANPIOKey/service.json'))
    parser.add_argument('--binary', type=Path, default=Path('/Library/ANPIOKey/bin/anpio-key'))
    parser.add_argument('--ui-preflight-only', action='store_true', help='only reproduce native preflight on an empty temporary service; cancel the single window if shown')
    parser.add_argument('--candidate-binary', type=Path, help='test a digest-pinned candidate in the temporary instance, without updating the installation')
    parser.add_argument('--candidate-sha256')
    parser.add_argument('--signing-helper', type=Path, help='digest-pinned local-preview-fixture example; enables full temporary signing checks')
    parser.add_argument('--helper-sha256')
    parser.add_argument('--se-login-bundle', type=Path, help='profile-embedded full signed helper; enables real SE joint acceptance with a signed generate-se fixture helper')
    parser.add_argument('--se-login-sha256')
    parser.add_argument('--se-ending', choices=('kill', 'hang', 'sleep', 'long-sleep', 'user-switch', 'logout', 'reboot', 'upgrade', 'key-loss', 'foreign-identity', 'keychain-permission', 'restart', 'crash'), default='kill',
                        help='real SE lease loss: helper kill/hang, operator sleep/user switch/logout/reboot, in-place helper upgrade, key loss, a differently-signed or differently-permissioned helper copy, or isolated service restart/crash')
    parser.add_argument('--upgrade-bundle', type=Path,
                        help='different real build with the same signing identity; replaces the installed helper in place')
    parser.add_argument('--upgrade-sha256')
    parser.add_argument('--helper-team-id')
    parser.add_argument('--helper-application-id')
    parser.add_argument('--key-loss-cleanup', type=Path,
                        help='signed test-only app that deletes one exact disposable SE key label')
    parser.add_argument('--key-loss-cleanup-sha256')
    parser.add_argument('--interactive-ui', action='store_true', help='human window checks: cancel, 120-second timeout, masked temporary-password unlock')
    parser.add_argument('--migrate-fixture', action='store_true', help='install only the disposable fixture through the supported offline migrator and verify recovery/resume')
    parser.add_argument('--claude-binary', type=Path, help='reviewed standalone Claude Code binary; enables complete framework/tool execution with a local API fixture')
    parser.add_argument('--claude-sha256', help='SHA-256 of the reviewed framework binary')
    parser.add_argument('--container-regression', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--logout-diagnostics', action='store_true',
                        help='system-runner client/console diagnostics only; no SE fixture, UI or logout')
    parser.add_argument('--post-relogin-probes', action='store_true',
                        help='after logout, run bounded spawn-layer probes from the surviving runner (evidence only; requires --se-ending logout)')
    args = parser.parse_args()
    if args.post_relogin_probes and args.se_ending != 'logout':
        raise ValueError('--post-relogin-probes requires --se-ending logout')
    if args.logout_diagnostics and args.se_ending != 'logout':
        raise ValueError('--logout-diagnostics requires the system logout runner')
    if args.se_ending in ('logout', 'reboot'):
        if os.getppid() != 1 or os.geteuid() != 0:
            raise ValueError(f'{args.se_ending} mode requires the temporary system launchd runner')
    if args.se_login_bundle:
        args.se_login_bundle = args.se_login_bundle.absolute()
        if not args.signing_helper or not args.se_login_sha256 or not args.candidate_binary:
            raise ValueError('SE joint acceptance requires fixture helper, pinned login helper and candidate service')
        if args.migrate_fixture or args.claude_binary or args.ui_preflight_only or args.container_regression:
            raise ValueError('SE joint acceptance must run separately from other acceptance modes')
    elif args.se_ending != 'kill':
        raise ValueError('--se-ending requires --se-login-bundle')
    elif args.se_login_sha256:
        raise ValueError('--se-login-sha256 requires --se-login-bundle')
    upgrade = (args.upgrade_bundle, args.upgrade_sha256,
               args.helper_team_id, args.helper_application_id)
    if args.se_ending == 'upgrade':
        if not all(upgrade) or not args.se_login_bundle:
            raise ValueError('upgrade mode requires the upgrade bundle/digest and signed identity fields')
    elif any(upgrade):
        raise ValueError('upgrade options require --se-ending upgrade')
    key_loss = (args.key_loss_cleanup, args.key_loss_cleanup_sha256)
    if args.se_ending == 'key-loss':
        if not all(key_loss):
            raise ValueError('key-loss mode requires the cleanup app and its digest')
    elif any(key_loss):
        raise ValueError('key-loss options require --se-ending key-loss')
    args.config = args.config.absolute()
    args.binary = args.binary.absolute()
    if args.candidate_binary:
        args.candidate_binary = args.candidate_binary.absolute()
    elif args.candidate_sha256:
        raise ValueError('--candidate-sha256 requires --candidate-binary')
    if args.upgrade_bundle:
        args.upgrade_bundle = args.upgrade_bundle.absolute()
    if args.key_loss_cleanup:
        args.key_loss_cleanup = args.key_loss_cleanup.absolute()
    if args.signing_helper:
        args.signing_helper = args.signing_helper.absolute()
    elif (args.interactive_ui and not args.ui_preflight_only) or args.helper_sha256:
        raise ValueError('UI/digest options require --signing-helper')
    if args.migrate_fixture and not args.signing_helper:
        raise ValueError('--migrate-fixture requires --signing-helper')
    if args.claude_binary:
        args.claude_binary = args.claude_binary.absolute()
        if not args.claude_sha256 or not args.signing_helper:
            raise ValueError('--claude-binary requires --claude-sha256 and --signing-helper')
    elif args.claude_sha256:
        raise ValueError('--claude-sha256 requires --claude-binary')
    portable = args.container_regression
    if os.geteuid() != 0:
        raise ValueError('requires root; run in the human terminal')
    if portable:
        if sys.platform != 'linux' or not Path('/.dockerenv').exists() or args.interactive_ui or args.ui_preflight_only:
            raise ValueError('container regression requires disposable root Linux Docker without UI')
    elif sys.platform != 'darwin':
        raise ValueError('requires macOS')
    if args.ui_preflight_only and args.signing_helper:
        raise ValueError('--ui-preflight-only requires an empty instance without --signing-helper')
    installed = json.loads(args.config.read_text())
    expected_mode = 'linux-boundary-preview' if portable else 'macos-boundary-preview'
    if installed['mode'] != expected_mode or not installed['principals']:
        raise ValueError('requires a configured macOS preview with an Agent')
    service = pwd.getpwuid(installed['service_uid'])
    admin = pwd.getpwuid(installed['admin_uids'][0])
    agent = pwd.getpwuid(installed['principals'][0]['uid'])
    if args.se_ending in ('logout', 'reboot'):
        import acceptance_graphical
        from acceptance_console import console_uid
        if args.se_ending == 'logout':
            import acceptance_process
            args.process_broker = acceptance_process.Broker()
        if console_uid() != admin.pw_uid:
            raise ValueError(f'{args.se_ending} test must start on the configured administrator desktop')
        graphical = acceptance_graphical.session(admin, args.config)
        if args.se_ending == 'logout':
            args.runner_audit_context = acceptance_graphical.require_runner_session(graphical)
            print('SYSTEM_RUNNER_AUDIT_CONTEXT ' + json.dumps(args.runner_audit_context), flush=True)
        if acceptance_graphical.relogin_session(admin) != graphical:
            raise ValueError('native console audit session does not match graphical bridge')
        print(f'PASS system runner pid={os.getpid()} ppid=1; graphical audit bridge session={graphical}; no SE key created yet', flush=True)
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'RUST_LOG': 'info'}
    def credentials(user, extra_admin_group=False):
        return child_credentials(user, installed, extra_admin_group)
    def run(user, *command):
        if command and Path(str(command[0])).name == 'anpio-key':
            print(f'CHECK uid={user.pw_uid} keyd ' + ' '.join(map(str, command[1:4])), flush=True)
        try:
            if args.se_ending in ('logout', 'reboot') and len(command) > 1 and command[1] == 'generate-se':
                import acceptance_graphical
                return subprocess.run(acceptance_graphical.command(user, path, command),
                    env=env, capture_output=True, text=True, timeout=30, cwd='/')
            if args.se_ending == 'logout':
                return args.process_broker.run(command, credentials(user), env, timeout=15)
            return subprocess.run(list(map(str, command)), **credentials(user),
                                  env=env, capture_output=True, text=True, timeout=15, cwd="/")
        except subprocess.TimeoutExpired as error:
            def decoded(value):
                return value.decode(errors='replace') if isinstance(value, bytes) else (value or '')
            raise ValueError(f'UID {user.pw_uid} command timed out: {command[0]}; '
                             f'stdout={decoded(error.stdout)!r}; stderr={decoded(error.stderr)!r}') from error
    parent = '/tmp' if portable else '/Library'
    if portable:
        parent = '/keyd-checks'
        Path(parent).mkdir(mode=0o755, exist_ok=True)
    directory_context = (tempfile.TemporaryDirectory(prefix='ANPIOKeyChecks-', dir=parent)
                         if args.se_ending != 'reboot'
                         else contextlib.nullcontext(
                             tempfile.mkdtemp(prefix='ANPIOKeyChecks-', dir=parent)))
    with directory_context as directory:
        base = Path(directory)
        base.chmod(0o755)
        if args.candidate_binary:
            with args.candidate_binary.open('rb') as source:
                content = source.read(128 * 1024 * 1024 + 1)
            if len(content) > 128 * 1024 * 1024 or hashlib.sha256(content).hexdigest() != args.candidate_sha256:
                raise ValueError('candidate binary digest mismatch')
            (base / 'bin').mkdir(mode=0o755)
            (base / 'bin').chmod(0o755)
            candidate = base / 'bin/anpio-key'
            with candidate.open('xb') as target:
                target.write(content)
            candidate.chmod(0o755)
            args.binary = candidate
            print('CHECK testing root-owned candidate; installed binary remains unchanged', flush=True)
        config = {**installed, 'instance_id': str(uuid.uuid4()), 'vault_ids': [],
                  'state_dir': str(base / 'state'), 'sign_socket': str(base / 'sign/sign.sock'),
                  'admin_socket': str(base / 'admin/admin.sock')}
        for name, gid, mode in [('state', service.pw_gid, 0o700),
                                ('sign', config['agent_gid'], 0o750),
                                ('admin', config['admin_gid'], 0o750)]:
            path = base / name
            path.mkdir()
            os.chown(path, service.pw_uid, gid)
            path.chmod(mode)
        fixture = None
        path = base / 'service.json'
        path.write_text(json.dumps(config))
        path.chmod(0o644)
        def cli(user, *command):
            return run(user, args.binary, 'admin', '--config', path, *command)
        # Check the effective child credentials and exact config/state access
        # before asking the Rust initializer to operate on this new test state.
        probe = r'''import sys
print('python-started',file=sys.stderr,flush=True)
import ctypes,json,os
config,state=sys.argv[1:]
with open(config) as handle: json.load(handle)
print('config-read',file=sys.stderr,flush=True)
fd=os.open(state,os.O_RDONLY);os.close(fd)
name=os.path.join(state,'.acceptance-access-probe')
fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
os.write(fd,b'temporary access probe');os.fsync(fd);os.close(fd);os.unlink(name)
print('state-write-fsync-complete',file=sys.stderr,flush=True)
lib=ctypes.CDLL(None,use_errno=True)
count=lib.getgroups(0,None)
if count<0: raise OSError(ctypes.get_errno(),'getgroups')
groups=(ctypes.c_uint*count)()
if lib.getgroups(count,groups)<0: raise OSError(ctypes.get_errno(),'getgroups')
print(json.dumps({'uid':os.getuid(),'euid':os.geteuid(),'gid':os.getgid(),'kernel_groups':list(groups),'config_read':True,'state_write':True}))
'''
        print(f'CHECK service UID {service.pw_uid} interpreter/filesystem preflight: {PYTHON}', flush=True)
        access = run(service, PYTHON, '-I', '-c', probe, path, config['state_dir'])
        assert access.returncode == 0, 'service credential/filesystem preflight failed: ' + access.stderr
        print('PASS service access preflight: ' + access.stdout.strip(), flush=True)
        # A restricted-entitlement helper copied out of its profile-bearing app
        # can be killed by AMFI without stderr. Test the actual copied service
        # executable under its own UID before creating any persistent SE key.
        info = run(service, args.binary, 'build-info')
        require_success(info, 'service executable admission')
        flags = json.loads(info.stdout)
        if args.se_login_bundle:
            if not (flags['release'] and flags['hardware_se'] and flags['mcp']) or any(
                flags[name] for name in ('hardware_software', 'seed_export', 'protected_supported')
            ):
                raise ValueError('SE joint service has unexpected build flags')
        print('PASS service executable admission: ' + info.stdout.strip(), flush=True)
        # Do not create persistent hardware objects before this no-hardware gate.
        if args.signing_helper and not args.logout_diagnostics:
            import acceptance_signing
            fixture = acceptance_signing.prepare(base, config, args, admin, service, run)
            path.write_text(json.dumps(config))
        result = run(service, args.binary, 'init-protected-state', '--config', path)
        require_success(result, 'init-protected-state')
        print('PASS temporary state initialized', flush=True)
        if args.migrate_fixture:
            import acceptance_migration
            acceptance_migration.install(base, config, path, args, fixture)
        process = None
        daemon_log = base / 'daemon-output.log'
        def start():
            print('CHECK starting temporary daemon', flush=True)
            with daemon_log.open('a') as output:
                proc = subprocess.Popen([str(args.binary), 'serve-protected', '--config', str(path)],
                                        **credentials(service), env=env, cwd="/",
                                        stdout=output, stderr=output)
            try:
                wait_ready(proc, lambda: cli(admin, 'status'), config['instance_id'])
                return proc
            except BaseException:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
                raise
        def stop(proc):
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
                raise ValueError('temporary service graceful shutdown timed out')
            assert proc.returncode == 0, 'temporary service did not shut down normally'
        try:
            process = start()
            result = cli(admin, 'status')
            assert result.returncode == 0, 'administrator status failed: ' + result.stderr
            print('PASS administrator authenticated temporary daemon', flush=True)
            first = json.loads(result.stdout)
            assert first['instance_id'] == config['instance_id'] and not first['protected_supported']
            if args.logout_diagnostics:
                import acceptance_signing
                checks = acceptance_signing.Checks(base, config, path, args, None, admin, agent,
                    credentials, env, cli)
                for index in range(3):
                    print(f'CHECK nondisruptive system console/client round {index + 1}', flush=True)
                    session = acceptance_graphical.relogin_session(admin)
                    assert acceptance_graphical.require_runner_session(session,
                        args.runner_audit_context) == args.runner_audit_context
                    print(f'PASS native graphical audit session {session}', flush=True)
                    result = cli(admin, 'status')
                    require_success(result, 'post-console management subprocess')
                    reply = checks.request_as(agent, {'operation': 'LIST_AUTHORIZED_KEYS'})
                    assert reply['code'] == 'OK' and reply['data']['keys'] == [], reply
                print('PASS system console/client diagnostics; no SE fixture, UI, logout, sleep or reboot', flush=True)
                return
            if args.ui_preflight_only:
                print('UI PREFLIGHT: if a window appears, click Cancel only; no password or existing key is used.', flush=True)
                command = [str(args.binary), 'admin', '--config', str(path), 'unlock', '--native-ui',
                           '--vault-id', str(uuid.uuid4()), '--did', 'did:wba:example.com:ui-preflight-probe', '--kid', 'ui-preflight-probe']
                result = subprocess.run(command, **credentials(admin), env=env, cwd='/',
                                        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=150)
                if result.returncode != 0 and 'native unlock cancelled' in result.stderr:
                    print('PASS native preflight reached a cancellation response; no key or password used', flush=True)
                else:
                    raise ValueError('native preflight result: ' + result.stderr)
                return
            checks = None
            if fixture:
                if args.se_login_bundle:
                    import acceptance_se
                    checks_type = acceptance_se.Checks
                else:
                    checks_type = acceptance_signing.Checks
                checks = checks_type(base, config, path, args, fixture, admin, agent, credentials, env, cli)
                if args.se_login_bundle:
                    def restart_se_service(abrupt):
                        nonlocal process
                        before = json.loads(cli(admin, 'status').stdout)['boot_epoch']
                        if abrupt:
                            process.kill()
                            process.wait(timeout=10)
                        else:
                            stop(process)
                        process = None
                        process = start()
                        result = cli(admin, 'status')
                        assert result.returncode == 0, result.stderr
                        after = json.loads(result.stdout)['boot_epoch']
                        assert after > before, 'service restart did not advance boot epoch'
                        print(f'PASS isolated service restart boot epoch {before} -> {after}; abrupt={abrupt}', flush=True)
                    checks.restart_service = restart_se_service
                checks.before_restart()
                if args.se_login_bundle:
                    print(f'PASS real SE/full helper/separate service signing and {args.se_ending} checks; raw OS isolation and other host lifecycle cases remain unaccepted', flush=True)
                    return
                if args.claude_binary:
                    import acceptance_agent
                    acceptance_agent.Framework(checks).run()
                    checks.unlock()  # framework policy changes lock the shared test key
            # task_for_pid queries a task port, never attaches a debugger or reads
            # memory. Root performs only the UID switch; the Agent makes the call.
            script = '''import ctypes,sys
lib=ctypes.CDLL('/usr/lib/libSystem.B.dylib')
lib.task_for_pid.argtypes=[ctypes.c_uint,ctypes.c_int,ctypes.POINTER(ctypes.c_uint)]
port=ctypes.c_uint()
self_task=ctypes.c_uint.in_dll(lib,'mach_task_self_').value
status=lib.task_for_pid(self_task,int(sys.argv[1]),ctypes.byref(port))
if status == 0:
 lib.mach_port_deallocate(self_task,port)
 sys.exit('Agent obtained daemon task port')
print('task_for_pid denied')
'''
            if not portable:
                result = run(agent, PYTHON, '-I', '-c', script, process.pid)
                assert result.returncode == 0 and 'task_for_pid denied' in result.stdout, result.stderr
                print('PASS independent Agent UID cannot obtain daemon task port', flush=True)
            else:
                print('SKIP macOS task-port probe in Linux container regression', flush=True)
            stop(process)
            process = None
            assert not Path(config['admin_socket']).exists()
            process = start()
            second = json.loads(cli(admin, 'status').stdout)
            assert second['boot_epoch'] > first['boot_epoch']
            print('PASS graceful shutdown cleans sockets; restart advances boot epoch', flush=True)
            if checks:
                checks.after_restart()
                checks.arm_crash()
                process.kill()
                process.wait(timeout=10)
                process = None
                process = start()
                checks.after_restart(interactive=False)
                print('PASS abrupt process death also revokes active grants, suppresses cached results and locks keys', flush=True)
            stop(process)
            process = None
            # Forge the expected filesystem UID/group/mode, but keep the listener
            # running as root. Kernel peer identity must still reject this server
            # BEFORE a native dialog or credential frame could be sent.
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(config['admin_socket'])
                os.chown(config['admin_socket'], service.pw_uid, config['admin_gid'])
                os.chmod(config['admin_socket'], 0o660)
                listener.listen(1)
                listener.settimeout(15)
                received = []
                def accept():
                    try:
                        connection, _ = listener.accept()
                        with connection:
                            connection.settimeout(10)
                            received.append(connection.recv(1))
                    except OSError as error:
                        received.append(str(error))
                thread = threading.Thread(target=accept)
                thread.start()
                result = cli(admin, 'unlock', '--native-ui', '--vault-id', str(uuid.uuid4()),
                             '--did', 'did:wba:example.com:temporary', '--kid', 'temporary')
                thread.join(timeout=16)
                assert not thread.is_alive(), 'fake-server check timed out'
                assert result.returncode != 0 and 'SERVER_IDENTITY_MISMATCH' in result.stderr, result.stderr
                assert received == [b''], 'client sent bytes before authenticating server'
                print('PASS forged socket owner/mode cannot impersonate daemon; no request/secret sent', flush=True)
            print('PASS temporary runtime checks; installed launchd instance was not modified', flush=True)
        finally:
            try:
                if process is not None and process.poll() is None:
                    stop(process)
            finally:
                if args.se_ending in ('logout', 'reboot') and daemon_log.exists():
                    print('TEMPORARY_DAEMON_LOG_TAIL\n' + daemon_log.read_text()[-16384:], flush=True)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, AssertionError, KeyError, subprocess.SubprocessError) as error:
        # An assertion whose message is a dict would otherwise print as a bare
        # dict and read like ordinary output.
        sys.exit('FAIL ' + str(error))
