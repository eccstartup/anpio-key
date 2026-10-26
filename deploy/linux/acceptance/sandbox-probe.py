#!/usr/bin/env python3
"""Executed ONLY as ExecStartPost in a marked disposable systemd VM.
Records observable sandbox effects, not just configured unit properties.
"""
import ctypes
import json
import os
from pathlib import Path
import resource
import socket

results = {}
status = Path('/proc/self/status').read_text()
results['no_new_privileges'] = 'NoNewPrivs:\t1' in status
results['no_effective_capabilities'] = 'CapEff:\t0000000000000000' in status
results['core_limit_zero'] = resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
results['memlock_limit_64m'] = resource.getrlimit(resource.RLIMIT_MEMLOCK) == (67108864, 67108864)
for name, path in [('system_write_denied', '/etc/.keyd-systemd-probe'),
                   ('program_write_denied', '/usr/local/libexec/anpio-key'),
                   ('config_write_denied', '/etc/anpio-key/service.json'),
                   ('kernel_write_denied', '/proc/sys/kernel/hostname')]:
    try:
        fd = os.open(path, os.O_WRONLY | (os.O_CREAT if name == 'system_write_denied' else 0), 0o600)
    except OSError:
        results[name] = True
    else:
        os.close(fd)
        results[name] = False
results['private_tmp_hides_host_file'] = not Path('/tmp/keyd-host-visible-marker').exists()
Path('/tmp/keyd-private-visible-marker').write_text('disposable service namespace')
try:
    list(Path('/home/boundary-admin').iterdir())
except OSError:
    results['home_inaccessible'] = True
else:
    results['home_inaccessible'] = False
results['private_devices_no_kmsg'] = not Path('/dev/kmsg').exists()
try:
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except OSError:
    results['inet_socket_denied'] = True
else:
    connection.close()
    results['inet_socket_denied'] = False
left, right = socket.socketpair(socket.AF_UNIX)
left.close()
right.close()
results['unix_socket_allowed'] = True
results['user_namespace_denied'] = ctypes.CDLL(None, use_errno=True).unshare(0x10000000) == -1
config = json.loads(Path('/etc/anpio-key/service.json').read_text())
results['dedicated_service_uid'] = os.geteuid() == config['service_uid']
report = Path(config['state_dir']) / 'systemd-sandbox-report.json'
fd = os.open(report, os.O_CREAT | os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'w') as stream:
    json.dump(results, stream)
    stream.flush()
    os.fsync(stream.fileno())
if not all(results.values()):
    raise SystemExit('systemd sandbox effect mismatch: ' + ','.join(k for k,v in results.items() if not v))
