#!/usr/bin/env python3
"""Two disposable Linux containers: real SSH, separate UIDs/storage, rollback.

Requires Docker. Creates/removes only uniquely named resources belonging to this
run. Never mounts runtime identities, the Docker socket, or a writable checkout.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
import uuid

INSTANCE = '12345678-1234-4234-8234-123456789abc'
REPO = Path(__file__).resolve().parents[2]


def run(*args, input=None, ok=True):
    result = subprocess.run(args, input=input, text=True, capture_output=True)
    if ok and result.returncode:
        raise RuntimeError(f'{args[0:3]} failed: {result.stderr[-1500:]} {result.stdout[-1500:]}')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='rust:1.90-bookworm@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f')
    parser.add_argument('--cargo-cache', help='Existing cargo cache volume, mounted read-only')
    args = parser.parse_args()
    tag = 'keyd-u4-' + uuid.uuid4().hex[:10]
    source, keeper, network = tag+'-source', tag+'-keeper', tag+'-net'
    created = []

    def execute(container, script, user=None, ok=True):
        command = ['docker', 'exec', '-i']
        if user:
            command += ['--user', user]
        return run(*command, container, '/bin/bash', '-se', input=script, ok=ok)

    def collect(action='collect', ok=True):
        result = execute(keeper, f'python3 /src/deploy/checkpoints/collector.py {action} --config /home/keeper/config.json --store /home/keeper/evidence', user='1002', ok=ok)
        value = json.loads(result.stdout)
        if ok:
            assert result.returncode == 0 and value['state'] in ('retained', 'observed'), value
        return result, value

    try:
        run('docker', 'network', 'create', '--internal', network)
        created.append(('network', network))
        command = ['docker', 'run', '-d', '--name', source, '-v', str(REPO)+':/src:ro']
        if args.cargo_cache:
            command += ['-v', args.cargo_cache+':/cargo-cache:ro']
        command += [args.image, 'sleep', 'infinity']
        run(*command)
        created.append(('container', source))
        print('building source and installing sshd in disposable container', flush=True)
        cache = 'cp -a /cargo-cache/. /usr/local/cargo/\n' if args.cargo_cache else ''
        execute(source, cache+'''
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq openssh-server sudo >/dev/null
cd /src
if [ -d /cargo-cache ]; then offline=--offline; else offline=; fi
CARGO_TARGET_DIR=/tmp/keyd-target cargo build --locked ${offline} --quiet
install -m 755 /tmp/keyd-target/debug/anpio-key /usr/local/bin/anpio-key
useradd -m -u 1001 -s /usr/sbin/nologin keydservice
useradd -m -u 1003 -s /bin/sh audit
usermod -p x audit
install -d -m 700 -o 1001 -g 1001 /srv/keyd
install -d -m 755 /run/sshd /etc/ssh/authorized_keys
''')
        execute(source, f'''install -d -m 755 /usr/local/libexec
cat > /usr/local/libexec/keyd-audit-source <<'WRAPPER'
#!/bin/sh
exec /usr/local/bin/anpio-key audit-source --database /srv/keyd/state.sqlite --instance-id {INSTANCE}
WRAPPER
chmod 755 /usr/local/libexec/keyd-audit-source
printf '%s\\n' 'audit ALL=(keydservice) NOPASSWD: /usr/local/libexec/keyd-audit-source ""' > /etc/sudoers.d/keyd-audit
chmod 440 /etc/sudoers.d/keyd-audit
visudo -cf /etc/sudoers.d/keyd-audit
''')
        # Actual SQLite audit format, with an independently saved pre-tip backup.
        execute(source, f'''python3 - <<'PYFIX'
import sqlite3,hashlib,json,os,shutil
p='/srv/keyd/state.sqlite'
c=sqlite3.connect(p)
c.executescript(open('/src/src/persistence/schema.sql').read())
c.execute('PRAGMA application_id=1095651403')
c.execute('PRAGMA user_version=3')
c.execute('INSERT INTO service_meta VALUES(1,3,?,0,0)', ('{INSTANCE}',))
data=json.dumps({{'event':'INITIALIZED','instance_id':'{INSTANCE}','at':100}},sort_keys=True,separators=(',',':')).encode()
prev='0'*64
h=hashlib.sha256(b'anpio-key/sqlite-audit/v1\\0'+(1).to_bytes(8,'big',signed=True)+prev.encode()+data).hexdigest()
c.execute('INSERT INTO audit_events VALUES(1,?,?,?)',(prev,h,data));c.commit();c.close()
os.chown(p,1001,1001);os.chmod(p,0o600)
shutil.copy2(p,'/srv/keyd/old.sqlite')
PYFIX
''')
        run('docker', 'network', 'connect', '--alias', 'audit-source', network, source)
        run('docker', 'network', 'disconnect', 'bridge', source)
        run('docker', 'run', '-d', '--name', keeper, '--network', network,
            '-v', str(REPO)+':/src:ro', args.image, 'sleep', 'infinity')
        created.append(('container', keeper))
        execute(keeper, '''
useradd -m -u 1002 -s /bin/sh keeper
install -d -m 700 -o 1002 -g 1002 /home/keeper/evidence
runuser -u keeper -- ssh-keygen -q -t ed25519 -N '' -f /home/keeper/id_ed25519
''')
        pub = execute(keeper, 'cat /home/keeper/id_ed25519.pub').stdout
        execute(source, 'cat > /etc/ssh/authorized_keys/audit <<\'KEY\'\nrestrict '+pub+'KEY\nchmod 644 /etc/ssh/authorized_keys/audit\n')
        host_pub = execute(source, 'cat /etc/ssh/ssh_host_ed25519_key.pub').stdout.split()
        execute(keeper, "printf '%s\\n' 'audit-source "+' '.join(host_pub[:2])+"' > /home/keeper/known_hosts\nchown 1002:1002 /home/keeper/known_hosts\nchmod 600 /home/keeper/known_hosts\n")
        execute(source, f'''cat > /etc/keyd-sshd_config <<'SSHD'
Port 22
HostKey /etc/ssh/ssh_host_ed25519_key
AuthorizedKeysFile /etc/ssh/authorized_keys/%u
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
AllowUsers audit
DisableForwarding yes
PermitTTY no
PermitUserEnvironment no
PermitUserRC no
ForceCommand /usr/bin/sudo -n -u keydservice -- /usr/local/libexec/keyd-audit-source
SSHD
/usr/sbin/sshd -t -f /etc/keyd-sshd_config
''')
        run('docker', 'exec', '-d', source, '/usr/sbin/sshd', '-D', '-e', '-f', '/etc/keyd-sshd_config')
        config = {'version': 1, 'instance_id': INSTANCE, 'host': 'audit-source', 'port': 22,
                  'user': 'audit', 'identity_file': '/home/keeper/id_ed25519',
                  'known_hosts_file': '/home/keeper/known_hosts', 'timeout_seconds': 5, 'max_age_seconds': 60}
        execute(keeper, "cat > /home/keeper/config.json <<'CONFIG'\n"+json.dumps(config)+"\nCONFIG\nchown 1002:1002 /home/keeper/config.json\nchmod 600 /home/keeper/config.json\n")
        time.sleep(.3)
        _, first = collect('enroll')
        assert first['checkpoint']['sequence'] == 1
        execute(source, '''python3 - <<'PYADD'
import sqlite3,hashlib
c=sqlite3.connect('/srv/keyd/state.sqlite')
seq,prev=c.execute('SELECT seq,event_digest FROM audit_events ORDER BY seq DESC LIMIT 1').fetchone()
data=b'{"event":"CHECKPOINT_ACCEPTANCE"}'
seq+=1
h=hashlib.sha256(b'anpio-key/sqlite-audit/v1\\0'+seq.to_bytes(8,'big',signed=True)+prev.encode()+data).hexdigest()
c.execute('INSERT INTO audit_events VALUES(?,?,?,?)',(seq,prev,h,data));c.commit();c.close()
PYADD
''')
        _, latest = collect()
        assert latest['checkpoint']['sequence'] == 2
        collect()  # unchanged tip is an observation, never a duplicate history row
        print('PASS real SSH enrollment, extension and unchanged-tip observation', flush=True)
        # Independent store and key are absent from the source's mount namespace.
        result = execute(source, 'test ! -e /home/keeper/evidence/checkpoints.sqlite')
        assert result.returncode == 0
        denied = execute(keeper, 'cat /home/keeper/evidence/checkpoints.sqlite', user='65534', ok=False)
        assert denied.returncode != 0
        print('PASS separate storage namespace and non-collector UID denial', flush=True)
        # Replacing every source-side evidence file cannot reset the keeper.
        execute(source, 'cp /srv/keyd/state.sqlite /srv/keyd/new.sqlite\ncp /srv/keyd/old.sqlite /srv/keyd/state.sqlite\n')
        failed, report = collect(ok=False)
        assert failed.returncode != 0 and report['checkpoint'] == latest['checkpoint']
        print('PASS complete source database rollback rejected; retained evidence preserved', flush=True)
        execute(source, 'cp /srv/keyd/new.sqlite /srv/keyd/state.sqlite\n')
        collect()
        # Disconnect network and ensure there is a bounded failure, no reset.
        run('docker', 'network', 'disconnect', network, source)
        start = time.monotonic()
        failed, report = collect(ok=False)
        assert failed.returncode != 0 and report['checkpoint'] == latest['checkpoint']
        assert time.monotonic()-start < 10
        run('docker', 'network', 'connect', '--alias', 'audit-source', network, source)
        collect()
        print('PASS source unavailable, bounded failure and reconnect recovery', flush=True)
        # Replace the server key, leaving collector trust material unchanged:
        # failure must occur in real SSH host authentication, not config binding.
        execute(source, "cp /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key.good\nrm /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key.pub\nssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key\npkill -x sshd\n")
        run('docker', 'exec', '-d', source, '/usr/sbin/sshd', '-D', '-e', '-f', '/etc/keyd-sshd_config')
        time.sleep(.3)
        failed, report = collect(ok=False)
        assert failed.returncode != 0 and report['checkpoint'] == latest['checkpoint']
        execute(source, 'cp /etc/ssh/ssh_host_ed25519_key.good /etc/ssh/ssh_host_ed25519_key\npkill -x sshd\n')
        run('docker', 'exec', '-d', source, '/usr/sbin/sshd', '-D', '-e', '-f', '/etc/keyd-sshd_config')
        time.sleep(.3)
        collect()
        print('PASS changed server host key rejected by pinned SSH authentication', flush=True)
        # A valid alternate chain with the same length must still be rejected.
        execute(source, '''python3 - <<'PYFORK'
import sqlite3,hashlib
c=sqlite3.connect('/srv/keyd/state.sqlite')
prev=c.execute('SELECT event_digest FROM audit_events WHERE seq=1').fetchone()[0]
data=b'{"event":"ALTERNATE_BRANCH"}'
h=hashlib.sha256(b'anpio-key/sqlite-audit/v1\\0'+(2).to_bytes(8,'big',signed=True)+prev.encode()+data).hexdigest()
c.execute('UPDATE audit_events SET event_data=?,event_digest=? WHERE seq=2',(data,h));c.commit();c.close()
PYFORK
''')
        failed, report = collect(ok=False)
        assert failed.returncode != 0 and report['checkpoint'] == latest['checkpoint']
        execute(source, 'cp /srv/keyd/new.sqlite /srv/keyd/state.sqlite\n')
        collect()
        denied = execute(source, 'cat /srv/keyd/state.sqlite', user='1003', ok=False)
        assert denied.returncode != 0
        denied = execute(source, 'sudo -n -u keydservice -- /usr/local/libexec/keyd-audit-source extra </dev/null', user='1003', ok=False)
        assert denied.returncode != 0
        print('PASS valid-chain fork, observer directory denial and sudo argument restriction', flush=True)
        # Even an authenticated requester cannot turn the forced endpoint into a shell.
        denial = execute(keeper, "ssh -F /dev/null -i /home/keeper/id_ed25519 -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/home/keeper/known_hosts audit@audit-source 'cat /srv/keyd/state.sqlite' </dev/null", user='1002', ok=False)
        assert denial.returncode != 0 and not denial.stdout
        print('PASS forced-command boundary; no arbitrary shell or database output', flush=True)
        print('ALL CHECKPOINT ACCEPTANCE CHECKS PASSED', flush=True)
    finally:
        for kind, name in reversed(created):
            if kind == 'container':
                run('docker', 'rm', '-f', name, ok=False)
            else:
                run('docker', 'network', 'rm', name, ok=False)


if __name__ == '__main__':
    main()
