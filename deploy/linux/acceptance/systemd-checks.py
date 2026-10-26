"""Checks invoked by test-boundary.py --systemd in an explicitly disposable VM."""
import json
import os
from pathlib import Path
import subprocess
import time


def run(config, check):
    def prop(name):
        return subprocess.check_output(['systemctl','show','anpio-key.service','-p',name,'--value'], text=True).strip()
    check(Path('/proc/1/comm').read_text().strip() == 'systemd', 'VM PID 1 is actual systemd')
    tpm = Path('/etc/systemd/system/anpio-key.service.d/10-tpm.conf').is_file()
    expected = {'User':'anpio-key','Group':'anpio-key','NoNewPrivileges':'yes',
        'PrivateTmp':'yes','PrivateDevices':'no' if tpm else 'yes','ProtectSystem':'strict',
        'ProtectHome':'yes','ProtectKernelTunables':'yes','ProtectKernelModules':'yes',
        'ProtectControlGroups':'yes','RestrictSUIDSGID':'yes','RestrictNamespaces':'yes',
        'LockPersonality':'yes','RestrictAddressFamilies':'AF_UNIX',
        'CapabilityBoundingSet':'','AmbientCapabilities':'','LimitCORE':'0',
        'LimitMEMLOCK':'67108864','TasksMax':'64','Restart':'on-failure'}
    for name, value in expected.items():
        check(prop(name) == value, 'effective systemd property ' + name)
    pid = int(prop('MainPID'))
    fields = dict(line.split(':',1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
    check(all(int(uid) == config['service_uid'] for uid in fields['Uid'].split()), 'running daemon has only dedicated service UID')
    groups = set(map(int, fields['Groups'].split()))
    check({config['agent_gid'],config['admin_gid']} <= groups, 'running daemon has separate socket connection groups')
    if tpm:
        check(prop('DevicePolicy') == 'closed', 'TPM deployment keeps the closed device policy')
        check('/dev/tpmrm0 rw' in prop('DeviceAllow'), 'TPM deployment allows only /dev/tpmrm0 rw')
        check('TPM2TOOLS_TCTI=device:/dev/tpmrm0' in prop('Environment'),
              'TPM deployment pins the transport to the kernel device')
        check(os.stat('/dev/tpmrm0').st_gid in groups, 'running daemon belongs to the TPM device group')
    report = json.loads((Path(config['state_dir'])/'systemd-sandbox-report.json').read_text())
    for name, passed in report.items():
        check(passed is True, 'sandbox effect ' + name)
    check(not Path('/tmp/keyd-private-visible-marker').exists(), 'service private temp file is absent in host namespace')
    check(subprocess.check_output(['systemctl','is-enabled','anpio-key.service'],text=True).strip() == 'enabled', 'service is enabled for boot')
    check(subprocess.run(['systemd-analyze','verify','/etc/systemd/system/anpio-key.service'],capture_output=True).returncode == 0, 'installed unit passes systemd-analyze verify')
    # A crash must restart through systemd, not a test's direct Popen launcher.
    subprocess.run(['systemctl','kill','--kill-whom=main','--signal=SIGKILL','anpio-key.service'],check=True)
    for _ in range(100):
        time.sleep(.1)
        current = int(prop('MainPID'))
        if current not in (0, pid) and Path(config['admin_socket']).exists() and prop('ActiveState') == 'active':
            break
    else:
        raise AssertionError('systemd failed to restart crashed daemon')
    check(current != pid and int(prop('NRestarts')) >= 1, 'systemd on-failure restart recovers a killed daemon')
    check(prop('ActiveState') == 'active', 'service is active after systemd crash recovery')
    return prop('InvocationID')
