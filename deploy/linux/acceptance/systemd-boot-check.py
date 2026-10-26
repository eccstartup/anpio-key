#!/usr/bin/env python3
"""Before/after actual VM reboot checks; only for an explicitly marked test VM."""
import argparse
import json
import os
from pathlib import Path
import pwd
import socket
import sqlite3
import struct
import subprocess
import time
import uuid


def exact(stream, n):
    data = b''
    while len(data) < n:
        chunk = stream.recv(n-len(data))
        if not chunk:
            raise EOFError('closed test connection')
        data += chunk
    return data


def main(phase):
    marker = Path('/var/lib/keyd-systemd-disposable')
    assert os.geteuid() == 0 and not Path('/.dockerenv').exists()
    assert not marker.is_symlink() and marker.stat().st_uid == 0 and marker.read_text().strip() == 'anpio-key-disposable-systemd-v1'
    assert Path('/proc/1/comm').read_text().strip() == 'systemd'
    config = json.loads(Path('/etc/anpio-key/service.json').read_text())
    binary = '/usr/local/libexec/anpio-key'
    state = Path('/root/keyd-systemd-boot-evidence.json')
    results = []

    def check(ok, name):
        assert ok, name
        results.append(name)
        print('PASS ' + name, flush=True)

    def identity(name):
        user = pwd.getpwnam(name)
        def drop():
            os.initgroups(user.pw_name, user.pw_gid)
            os.setgid(user.pw_gid)
            os.setuid(user.pw_uid)
        return drop

    def cli(name, *args):
        value = subprocess.run([binary,*args],preexec_fn=identity(name),capture_output=True,text=True,timeout=15)
        assert value.returncode == 0, value.stderr
        return json.loads(value.stdout)

    def change(value):
        path = Path('/var/tmp/keyd-boot-public-change.json')
        path.write_text(json.dumps(value))
        path.chmod(0o644)
        prepared = cli('boundary-admin','admin','prepare','--file',str(path))['prepared']
        cli('boundary-admin','admin','commit','--operation-id',prepared['operation_id'],'--digest',prepared['digest'])
        return prepared

    def data(value):
        path = Path('/var/tmp/keyd-boot-public-request.json')
        path.write_text(json.dumps(value))
        path.chmod(0o644)
        result = subprocess.run([binary,'data','--file',str(path)],preexec_fn=identity('boundary-agent-a'),capture_output=True,text=True,timeout=15)
        return result

    def unlock(key):
        request = json.dumps({'version':2,'request':{'operation':'UNLOCK_KEY','vault_id':key['vault_id'],'did':key['did'],'kid':key['kid']}}).encode()
        code = '''import socket,struct,json,sys
s=socket.socket(socket.AF_UNIX);s.settimeout(10);s.connect(sys.argv[1]);p=sys.argv[2].encode();secret=b'temporary-boundary-test-secret';s.sendall(struct.pack('!I',len(p))+p+struct.pack('!I',len(secret))+secret)
def exact(n):
 b=b''
 while len(b)<n:b+=s.recv(n-len(b))
 return b
print(exact(struct.unpack('!I',exact(4))[0]).decode())'''
        result = subprocess.run(['python3','-c',code,config['admin_socket'],request.decode()],preexec_fn=identity('boundary-admin'),capture_output=True,text=True,timeout=15)
        assert result.returncode == 0 and json.loads(result.stdout)['code'] == 'OK', result.stdout+result.stderr

    def grant(key, principal, policy):
        prepared = change({'kind':'Grant','change':{'action':'Create','principal_id':principal,'key_id':key['key_id'],'policy_id':policy,'policy_version':1,'expiry':int(time.time())+55,'max_uses':2}})
        return prepared['effect']['effect']['grant']['grant_id']

    def signing(grant_id):
        return {'operation':'SIGN_HTTP','grant_id':grant_id,'request_id':str(uuid.uuid4()),'http':{'method':'GET','url':'https://example.com/test','headers':{},'body':{'state':'absent'},'nonce':uuid.uuid4().hex}}

    if phase == 'prepare':
        subprocess.run(['systemctl','enable','--now','anpio-key.service'],check=True)
        deadline = time.monotonic() + 10
        while not Path(config['admin_socket']).exists():
            assert time.monotonic() < deadline, 'service did not become ready'
            time.sleep(.05)
        properties = subprocess.check_output(['systemctl','show','anpio-key.service','-p','DropInPaths','--value'],text=True).strip()
        check(not properties, 'boot validation uses the original installed unit without test overrides')
        catalog = cli('boundary-admin','admin','catalog')['catalog']
        key = next(k for k in catalog['keys'] if k['role']=='hot' and k['state']=='active')
        policy = catalog['policies'][0]['policy_id']
        principals = cli('boundary-admin','admin','list-principals')['principals']
        principal = next(p['principal_id'] for p in principals if p['uid']==pwd.getpwnam('boundary-agent-a').pw_uid and p['enabled'])
        g = grant(key, principal, policy)
        unlock(key)
        request = signing(g)
        first = data(request)
        check(first.returncode == 0 and json.loads(first.stdout)['data'].get('result') is not None, 'vanilla systemd unit delivers a durable signature before reboot')
        evidence = {'pre_boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'pre_epoch':cli('boundary-admin','admin','status')['boot_epoch'], 'key':key,'policy':policy,'principal':principal,'grant_id':g,'request_id':request['request_id']}
        state.write_text(json.dumps(evidence,indent=2))
        state.chmod(0o600)
        check(subprocess.check_output(['systemctl','is-enabled','anpio-key.service'],text=True).strip()=='enabled', 'original unit is enabled for actual guest boot')
    else:
        evidence = json.loads(state.read_text())
        check(Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=evidence['pre_boot_id'], 'kernel boot ID changed across real VM reboot')
        check(subprocess.check_output(['systemctl','is-active','anpio-key.service'],text=True).strip()=='active', 'service started automatically after real boot')
        check(subprocess.check_output(['systemctl','show','systemd-tmpfiles-setup.service','-p','Result','--value'],text=True).strip()=='success', 'boot tmpfiles setup completed successfully')
        for name in ('sign_socket','admin_socket'):
            path = Path(config[name]); meta = path.stat(); parent = path.parent.stat()
            check(meta.st_uid==config['service_uid'] and meta.st_mode&0o777==0o660 and parent.st_mode&0o777==0o750, 'boot recreated trusted '+name)
        check(cli('boundary-admin','admin','status')['boot_epoch']>evidence['pre_epoch'], 'boot invalidates the prior daemon epoch')
        with sqlite3.connect(Path(config['state_dir'])/'state.sqlite') as db:
            old = db.execute('SELECT state FROM grants WHERE grant_id=?',(evidence['grant_id'],)).fetchone()[0]
        check(old=='revoked_restart', 'real reboot persistently revokes the old grant')
        prior = data({'operation':'GET_REQUEST_STATUS','request_id':evidence['request_id']})
        check(prior.returncode==0 and 'result' not in json.loads(prior.stdout)['data'], 'reboot suppresses cached signature delivery')
        fresh = grant(evidence['key'],evidence['principal'],evidence['policy'])
        locked = data(signing(fresh))
        check(locked.returncode != 0 and 'KEY_LOCKED' in locked.stderr, 'all hot keys are locked after actual reboot')
        unlock(evidence['key'])
        signed = data(signing(fresh))
        check(signed.returncode==0 and json.loads(signed.stdout)['data'].get('result') is not None, 'fresh grant and explicit unlock restore signing after boot')
        evidence['post_boot_id'] = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        evidence['post_epoch'] = cli('boundary-admin','admin','status')['boot_epoch']
        evidence['checks'] = results
        state.write_text(json.dumps(evidence,indent=2))
    print(json.dumps({'phase':phase,'passed':len(results)}),flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',choices=['prepare','verify'])
    main(parser.parse_args().phase)
