#!/usr/bin/env python3
"""Run only the disposable SE reboot harness as a one-shot system job.

Run as root from the human terminal after saving work. Does not log out, reboot
by itself, install a daily service, restart failed tests, or enable a job at
the next boot. Reboot manually only after the runner prints READY, then run the
fixed post-reboot command from your new login.
"""
import argparse
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile


def job_spec(stage, python, arguments):
    return {'Label': 'org.anpio-key.reboot-check.' + stage.name,
        'ProgramArguments': [str(python), '-u', str(stage / 'test-runtime.py'),
                             '--se-ending', 'reboot', *arguments],
        'RunAtLoad': True, 'KeepAlive': False, 'LaunchOnlyOnce': True,
        'SessionCreate': True,
        'ProcessType': 'Background', 'WorkingDirectory': '/',
        'StandardOutPath': str(stage / 'host.log'),
        'StandardErrorPath': str(stage / 'host.log'),
        'EnvironmentVariables': {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'RUST_LOG': 'info'}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--finish', type=Path, help='boot out a completed test job; retain its log directory')
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if sys.platform != 'darwin' or os.geteuid() != 0:
        raise ValueError('requires macOS root; run with sudo in your own terminal')
    if args.finish:
        stage = args.finish.absolute()
        if stage.parent != Path('/Library') or not stage.name.startswith('ANPIOKeyRebootChecks-'):
            raise ValueError('unexpected reboot test directory')
        if stage.is_symlink() or not stage.is_dir() or stage.stat().st_uid != 0:
            raise ValueError('expected a root-owned test directory')
        label = 'org.anpio-key.reboot-check.' + stage.name
        status = subprocess.run(['/bin/launchctl', 'print', 'system/' + label],
                                capture_output=True, text=True, timeout=10)
        if status.returncode:
            if status.returncode == 113 and 'Could not find service' in status.stderr:
                print('One-shot test job already removed; evidence retained at ' + str(stage))
                return
            raise ValueError('cannot verify test job status: ' + status.stderr)
        if 'state = running' in status.stdout:
            raise ValueError('test job is still running; wait for completion')
        subprocess.run(['/bin/launchctl', 'bootout', 'system/' + label], check=True, timeout=15)
        print('Removed completed test job; evidence retained at ' + str(stage))
        return
    arguments = args.arguments
    if arguments[:1] == ['--']:
        arguments = arguments[1:]
    allowed = {'--candidate-binary', '--candidate-sha256', '--signing-helper',
               '--helper-sha256', '--se-login-bundle', '--se-login-sha256'}
    if len(arguments) != 12 or set(arguments[::2]) != allowed:
        raise ValueError('supply exactly the six pinned SE candidate/helper options')
    stage = Path(tempfile.mkdtemp(prefix='ANPIOKeyRebootChecks-', dir='/Library'))
    stage.chmod(0o755)
    attempted = False
    try:
        for source in Path(__file__).resolve().parent.glob('*.py'):
            if source.is_symlink() or not source.is_file() or source.stat().st_size > 1024 * 1024:
                raise ValueError('unexpected acceptance source file')
            (stage / source.name).write_bytes(source.read_bytes())
            (stage / source.name).chmod(0o644)
        spec = job_spec(stage, Path(sys.executable).resolve(), arguments)
        (stage / 'job.plist').write_bytes(plistlib.dumps(spec))
        (stage / 'job.plist').chmod(0o644)
        (stage / 'host.log').touch(mode=0o644)
        (stage / 'host.log').chmod(0o644)
        print('SYSTEM TEST DIRECTORY: ' + str(stage), flush=True)
        attempted = True
        subprocess.run(['/bin/launchctl', 'bootstrap', 'system', str(stage / 'job.plist')],
                       check=True, timeout=15)
        print('Read before the reboot and after logging back in: tail -f ' + str(stage / 'host.log'), flush=True)
        print('Wait for READY FOR MANUAL REBOOT before rebooting; the runner then waits for it.', flush=True)
        print('After you log back in, run the fixed command it printed.', flush=True)
        print('When completed, remove job: sudo /usr/bin/python3 ' + str(Path(__file__).resolve())
              + ' --finish ' + str(stage), flush=True)
    finally:
        if not attempted:
            shutil.rmtree(stage)


if __name__ == '__main__':
    main()
