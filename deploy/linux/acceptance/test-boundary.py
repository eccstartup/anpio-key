#!/usr/bin/env python3
"""Destructive to its container only. Root, Docker and explicit harness required."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pty
import pwd
import select
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import time
import uuid
import urllib.parse

parser = argparse.ArgumentParser()
parser.add_argument('--binary', required=True)
parser.add_argument('--systemd', action='store_true', help='requires a marked disposable VM with systemd PID 1')
args = parser.parse_args()
if sys.platform != 'linux' or os.geteuid() != 0:
    sys.exit('requires disposable root Linux environment')
if args.systemd:
    marker = Path('/var/lib/keyd-systemd-disposable')
    if (Path('/.dockerenv').exists() or Path('/proc/1/comm').read_text().strip() != 'systemd'
            or marker.is_symlink() or not marker.is_file() or marker.stat().st_uid != 0
            or marker.stat().st_mode & 0o077
            or marker.read_text().strip() != 'anpio-key-disposable-systemd-v1'):
        sys.exit('systemd mode requires an explicitly marked disposable systemd VM')
elif not Path('/.dockerenv').exists():
    sys.exit('container mode requires Docker; systemd VM testing needs --systemd')
os.umask(0o077)  # Installer must set permissions independently of caller umask.
for name in ['boundary-admin', 'boundary-agent-a', 'boundary-agent-b', 'boundary-stranger']:
    subprocess.run(['useradd', '--create-home', '--shell', '/bin/sh', name], check=True)
subprocess.run([sys.executable, 'deploy/linux/install.py', '--binary', args.binary,
                *([] if args.systemd else ['--allow-development-build']), '--sha256', hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(), '--admin-user', 'boundary-admin', '--agent-user', 'boundary-agent-a', '--agent-user', 'boundary-agent-b'], check=True)
config_path = Path('/etc/anpio-key/service.json')
config = json.loads(config_path.read_text())
fixture = json.loads(Path('/tmp/keyd-boundary-fixture-info.json').read_text())
service = pwd.getpwnam('anpio-key')
binary = '/usr/local/libexec/anpio-key'
source = Path('/root/keyd-migration-source')
migration_source = source
recovery = Path('/root/keyd-migration-recovery')
shutil.copytree('/tmp/keyd-boundary-fixture', source)
# Exercise the actual migration tool; no test-only SQL or catalog staging.
dry = subprocess.run([sys.executable, 'deploy/linux/migrate-vault.py', '--source', str(source)], capture_output=True, text=True)
assert dry.returncode == 0, dry.stderr
assert json.loads(dry.stdout.splitlines()[-1])['dry_run']
assert not recovery.exists()
def apply_migration(source, recovery):
    pid, terminal = pty.fork()
    if pid == 0:
        os.execv(sys.executable, [sys.executable, 'deploy/linux/migrate-vault.py', '--source', str(source), '--apply', '--recovery-dir', str(recovery)])
    output = b''
    sent = 0
    import re
    while True:
        ready, _, _ = select.select([terminal], [], [], 30)
        assert ready, 'migration verification timed out'
        try:
            chunk = os.read(terminal, 8192)
            if not chunk:
                break
            output += chunk
            prompts = len(re.findall(rb'Verify recovery of [^\r\n]*: ', output))
            while sent < prompts:
                os.write(terminal, b'temporary-boundary-test-secret\n')
                sent += 1
        except OSError:
            break
    _, status = os.waitpid(pid, 0)
    os.close(terminal)
    assert os.waitstatus_to_exitcode(status) == 0, output.decode(errors='replace')
    # 每个密钥一次口令提示;钥匙列表在 inspection JSON 里,recovery 目录的
    # migration.json 只写 apply 报告。
    text = output.decode(errors='replace')
    inspection, _ = json.JSONDecoder().raw_decode(text[text.index('{'):])
    assert sent == len(inspection['keys']), output
    migration = json.loads((recovery / 'migration.json').read_text())
    return migration

migration = apply_migration(source, recovery)
assert migration['phase'] == 'installed_locked_unclassified'
config = json.loads(config_path.read_text())
vault_id = migration['vault_id']
assert config['vault_ids'] == [vault_id]
vault = Path(config['state_dir']) / 'vaults' / vault_id
passed = ['migration dry-run is read-only', 'actual encrypted recovery copy opens every key', 'offline migration freezes source and installs locked unclassified vault']


def identity(name):
    user = pwd.getpwnam(name)
    def change():
        os.initgroups(user.pw_name, user.pw_gid)
        os.setgid(user.pw_gid)
        os.setuid(user.pw_uid)
    return change


def command(name, *argv):
    return subprocess.run([binary, *argv], preexec_fn=identity(name), capture_output=True, text=True, timeout=12)


def check(condition, label):
    assert condition, label
    passed.append(label)
    print('PASS', label, flush=True)


def frame(value):
    payload = json.dumps(value).encode()
    return struct.pack('!I', len(payload)) + payload


def exact(sock, size):
    out = b''
    while len(out) < size:
        data = sock.recv(size - len(out))
        if not data:
            raise EOFError('connection closed')
        out += data
    return out


def reply(sock):
    return json.loads(exact(sock, struct.unpack('!I', exact(sock, 4))[0]))


def request(endpoint, value, secret=None):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(8)
        sock.connect(endpoint)
        sock.sendall(frame(value))
        if secret is not None:
            sock.sendall(struct.pack('!I', len(secret)) + secret)
        return reply(sock)


def start():
    if args.systemd:
        Path('/tmp/keyd-host-visible-marker').write_text('disposable host namespace')
        Path('/tmp/keyd-host-visible-marker').chmod(0o644)
        dropin = Path('/run/systemd/system/anpio-key.service.d')
        dropin.mkdir(parents=True, exist_ok=True)
        (dropin / 'sandbox-probe.conf').write_text('[Service]\nExecStartPost=/usr/bin/python3 ' + str(Path(__file__).resolve().with_name('sandbox-probe.py')) + '\n')
        subprocess.run(['systemctl','enable','anpio-key.service'], check=True)
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        subprocess.run(['systemd-tmpfiles', '--create', '/etc/tmpfiles.d/anpio-key.conf'], check=True)
        subprocess.run(['systemctl', 'reset-failed', 'anpio-key.service'], check=True)
        subprocess.run(['systemctl', 'start', 'anpio-key.service'], check=True)
        for _ in range(100):
            if Path(config['admin_socket']).exists():
                invocation = subprocess.check_output(['systemctl','show','anpio-key.service','-p','InvocationID','--value'], text=True).strip()
                return invocation
            time.sleep(.05)
        raise AssertionError(subprocess.check_output(['journalctl','-u','anpio-key.service','--no-pager','-n','40'], text=True))
    process = subprocess.Popen([binary, 'serve-protected'], preexec_fn=identity('anpio-key'), stderr=subprocess.PIPE, text=True)
    for _ in range(100):
        if process.poll() is not None:
            raise AssertionError(process.stderr.read())
        if Path(config['admin_socket']).exists():
            return process
        time.sleep(.05)
    raise AssertionError('service did not start')


def stop(process):
    if args.systemd:
        subprocess.run(['systemctl','stop','anpio-key.service'], check=True)
        stderr = subprocess.check_output(['journalctl','_SYSTEMD_INVOCATION_ID=' + process, '--no-pager'], text=True)
    else:
        process.terminate()
        process.wait(timeout=12)
        stderr = process.stderr.read()
    check('temporary-boundary-test-secret' not in stderr, 'service log has no password')
    check(not Path(config['sign_socket']).exists() and not Path(config['admin_socket']).exists(), 'shutdown cleans owned socket inodes')


def capabilities(endpoint):
    return request(endpoint, {'version': 2, 'request': {'operation': 'GET_CAPABILITIES'}})


process = start()
try:
    if args.systemd:
        spec = __import__('importlib.util', fromlist=['spec_from_file_location']).spec_from_file_location('systemd_checks', Path(__file__).with_name('systemd-checks.py'))
        host_checks = __import__('importlib.util', fromlist=['module_from_spec']).module_from_spec(spec)
        spec.loader.exec_module(host_checks)
        process = host_checks.run(config, check)
    # Root uses explicit privilege drop so probes are real SO_PEERCRED identities.
    code = '''import json,socket,struct,sys
s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);data=json.dumps({'version':2,'request':{'operation':'GET_CAPABILITIES'}}).encode();s.sendall(struct.pack('!I',len(data))+data)
def exact(n):
 b=b''
 while len(b)<n:b+=s.recv(n-len(b))
 return b
print(exact(struct.unpack('!I',exact(4))[0]).decode())'''
    def as_agent(name):
        result = subprocess.run([sys.executable, '-c', code, config['sign_socket']], preexec_fn=identity(name), capture_output=True, text=True, timeout=8)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)
    a, b = as_agent('boundary-agent-a'), as_agent('boundary-agent-b')
    check(a['code'] == b['code'] == 'OK' and a['principal_id'] != b['principal_id'], 'same client maps A/B to distinct kernel principals')
    expected_supported = config['mode'] == 'linux-protected-v1' and json.loads(subprocess.check_output([binary, 'build-info']))['protected_supported']
    check(a['signing_available'] and a['protected_supported'] == expected_supported, 'runtime protection declaration matches build and explicit deployment mode')
    check(command('boundary-admin', 'admin', 'status').returncode == 0, 'independent administrator authenticated')
    check((command('boundary-admin', 'probe', '--security').returncode == 0) == expected_supported, 'probe accepts only supported protected deployment')
    check(command('boundary-agent-a', 'admin', 'status').returncode != 0, 'Agent cannot invoke admin CLI')
    # A real controlling PTY does not grant administrative identity.
    pid, terminal = pty.fork()
    if pid == 0:
        identity('boundary-agent-a')()
        os.execv(binary, [binary, 'admin', 'unlock', '--vault-id', vault_id, '--did', fixture['did'], '--kid', fixture['kid']])
    output = b''
    while True:
        readable, _, _ = select.select([terminal], [], [], 5)
        assert readable, 'PTY admin denial timed out'
        try:
            chunk = os.read(terminal, 4096)
            if not chunk:
                break
            output += chunk
        except OSError:
            break
    _, status = os.waitpid(pid, 0)
    os.close(terminal)
    check(os.waitstatus_to_exitcode(status) != 0 and b'ADMIN_REQUIRED' in output and b'Passphrase:' not in output, 'PTY does not bypass admin UID or prompt for password')
    for protected_path in [config['sign_socket'], str(config_path)]:
        tamper = subprocess.run([sys.executable, '-c', 'import os,sys;os.unlink(sys.argv[1])', protected_path], preexec_fn=identity('boundary-agent-a'), capture_output=True)
        check(tamper.returncode != 0 and Path(protected_path).exists(), 'Agent cannot replace ' + protected_path)
    # Even giving Agent A the admin connection group cannot override the UID check.
    subprocess.run(['usermod', '-a', '-G', 'anpio-key-admin', 'boundary-agent-a'], check=True)
    raw_admin = subprocess.run([sys.executable, '-c', code, config['admin_socket']], preexec_fn=identity('boundary-agent-a'), capture_output=True, text=True, timeout=8)
    check('ADMIN_REQUIRED' in raw_admin.stdout, 'admin socket group alone cannot authorize Agent')
    # Data protocol cannot parse old operations, even for an authorized Agent.
    data_probe = code.replace("{'operation':'GET_CAPABILITIES'}", "{'operation':'UNLOCK_KEY','passphrase':'temporary-boundary-test-secret'}")
    refused = subprocess.run([sys.executable, '-c', data_probe, config['sign_socket']], preexec_fn=identity('boundary-agent-a'), capture_output=True, text=True, timeout=8)
    check('PROTOCOL_INVALID' in refused.stdout and 'temporary-boundary-test-secret' not in refused.stdout, 'data socket has no password operation')
    # Unknown UID with connection-group membership is still denied.
    subprocess.run(['usermod', '-a', '-G', 'anpio-key-agent', 'boundary-stranger'], check=True)
    check(as_agent('boundary-stranger')['code'] == 'PRINCIPAL_DISABLED', 'unregistered UID rejected despite socket group')
    # Admin mutation is unavailable to an Agent even with vault/did/kid knowledge.
    unlock = {'version': 2, 'request': {'operation': 'UNLOCK_KEY', 'vault_id': vault_id, **fixture}}
    secret = b'temporary-boundary-test-secret'
    # Root is not configured as admin in this deployment. Use a child client UID.
    admin_call = '''import socket,struct,json,sys
s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);p=sys.argv[2].encode();secret=b'temporary-boundary-test-secret';s.sendall(struct.pack('!I',len(p))+p+struct.pack('!I',len(secret))+secret)
def exact(n):
 b=b''
 while len(b)<n:b+=s.recv(n-len(b))
 return b
print(exact(struct.unpack('!I',exact(4))[0]).decode())
try:assert s.recv(1)==b''
except ConnectionResetError:pass  # Early refusal closes with unread request bytes.
'''
    def prepare_change(change):
        source = Path('/tmp/keyd-management-change.json')
        source.write_text(json.dumps(change))
        source.chmod(0o644)
        result = command('boundary-admin', 'admin', 'prepare', '--file', str(source))
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)['prepared']

    def commit_change(change):
        prepared = prepare_change(change)
        result = command('boundary-admin', 'admin', 'commit', '--operation-id', prepared['operation_id'], '--digest', prepared['digest'])
        assert result.returncode == 0, result.stderr
        return prepared

    commit_change({'kind': 'Catalog', 'change': {'action': 'EnrollVault', 'vault_id': vault_id}})
    listed = command('boundary-admin', 'admin', 'catalog')
    catalog = json.loads(listed.stdout)['catalog']
    check(all(k['role'] == 'unclassified' for k in catalog['keys']), 'vault enrollment never infers key roles from fragments')
    refused = subprocess.run([sys.executable, '-c', admin_call, config['admin_socket'], json.dumps(unlock)], preexec_fn=identity('boundary-admin'), capture_output=True, text=True, timeout=12)
    check(json.loads(refused.stdout)['code'] == 'KEY_ROLE_FORBIDDEN', 'unclassified key cannot be unlocked')
    root_key = next(k for k in catalog['keys'] if k['kid'] == fixture['kid'])
    change = {'kind':'Catalog','change':{'action':'ConfirmRole','key_id':root_key['key_id'],'role':'hot'}}
    source = Path('/tmp/keyd-management-change.json'); source.write_text(json.dumps(change)); source.chmod(0o644)
    check(command('boundary-admin','admin','prepare','--file',str(source)).returncode != 0, 'root cannot be relabeled as a hot signing key')
    commit_change({'kind':'Catalog','change':{'action':'ConfirmRole','key_id':root_key['key_id'],'role':'root'}})
    check(command('boundary-agent-a','admin','catalog').returncode != 0, 'Agent cannot inspect or mutate managed key roles')
    for local_command in [('keygen','--spec','/tmp/unused-spec.json'),('publish','--did',fixture['did']),('serve',)]:
        result = command('anpio-key','--root',str(vault),*local_command)
        check(result.returncode != 0 and 'managed vault requires' in result.stderr, 'service UID cannot use legacy local ' + local_command[0])
    relative = subprocess.run([binary,'--root','new-untracked-vault','keygen','--spec','/tmp/unused-spec.json'],cwd=str(vault),preexec_fn=identity('anpio-key'),capture_output=True,text=True,timeout=12)
    check(relative.returncode != 0 and 'managed vault requires' in relative.stderr, 'relative nonexistent root cannot bypass managed directory guard')
    alias=Path('/tmp/keyd-managed-vault-alias');alias.symlink_to(vault)
    check(command('anpio-key','--root',str(alias),'status').returncode != 0, 'symlink root cannot bypass managed directory guard')
    alias.unlink()
    policy_id = str(uuid.uuid4())
    policy = {'schema_version':1,'name':'read-only','purpose':'http-authentication','origin':'https://example.com','methods':['GET'],'paths':['/test'],'query':{'mode':'none'},'body':{'mode':'empty','max_bytes':0},'signature_profile':'anp-http-v2','grant_limits':{'max_duration_seconds':60,'max_uses':2}}
    commit_change({'kind':'Catalog','change':{'action':'PublishPolicy','policy_id':policy_id,'version':1,'content':policy}})
    # M3 uses actual OS subjects, signed root/hot documents and typed v2 frames.
    hot_key = next(k for k in catalog['keys'] if k['kid'].endswith('#http-hot'))
    commit_change({'kind':'Catalog','change':{'action':'ConfirmRole','key_id':hot_key['key_id'],'role':'hot'}})
    device_key = next(k for k in catalog['keys'] if k['kid'].endswith('#device-sign'))
    source.write_text(json.dumps({'kind':'Catalog','change':{'action':'ConfirmRole','key_id':device_key['key_id'],'role':'device_signing'}})); source.chmod(0o644)
    check(command('boundary-admin','admin','prepare','--file',str(source)).returncode != 0, 'device signing role without a purpose binding is refused')
    commit_change({'kind':'Catalog','change':{'action':'ConfirmRole','key_id':device_key['key_id'],'role':'device_signing','purpose':'device_assertion'}})
    source.write_text(json.dumps({'kind':'Catalog','change':{'action':'ConfirmRole','key_id':device_key['key_id'],'role':'device_signing','purpose':'application_assertion'}})); source.chmod(0o644)
    check(command('boundary-admin','admin','prepare','--file',str(source)).returncode != 0, 'a device key purpose binding is set once')
    def data_as(name, operation):
        script = admin_call.replace("secret=b'temporary-boundary-test-secret';", "secret=b'';").replace("+struct.pack('!I',len(secret))+secret", "")
        result = subprocess.run([sys.executable,'-c',script,config['sign_socket'],json.dumps({'version':2,'request':operation})],preexec_fn=identity(name),capture_output=True,text=True,timeout=12)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)
    check(data_as('boundary-agent-a',{'operation':'LIST_AUTHORIZED_KEYS'})['data']['keys'] == [], 'unlocked or enrolled keys alone give no data authorization')
    principal_a=a['principal_id']; principal_b=b['principal_id']
    create_grant={'action':'Create','principal_id':principal_a,'key_id':hot_key['key_id'],'policy_id':policy_id,'policy_version':1,'expiry':int(time.time())+55,'max_uses':2}
    granted=commit_change({'kind':'Grant','change':create_grant})['effect']['effect']['grant']
    grant_id=granted['grant_id']
    check(len(grant_id)==64, 'grant references contain 256 random bits')
    keys=data_as('boundary-agent-a',{'operation':'LIST_AUTHORIZED_KEYS'})['data']['keys']
    check(len(keys)==1 and keys[0]['kid']==hot_key['kid'], 'Agent A sees exact granted hot key only')
    check(data_as('boundary-agent-b',{'operation':'LIST_AUTHORIZED_KEYS'})['data']['keys']==[], 'Agent B cannot list Agent A keys')
    check(data_as('boundary-agent-b',{'operation':'GET_GRANT_STATUS','grant_id':grant_id})['code']=='GRANT_INVALID', 'cross-principal grant lookup uniformly refused')
    check(data_as('boundary-agent-b',{'operation':'GET_DOCUMENT','key_id':hot_key['key_id']})['code']=='GRANT_INVALID', 'cross-principal document handle refused')
    check(data_as('boundary-agent-a',{'operation':'GET_DOCUMENT','key_id':hot_key['key_id']})['data']['document']['id']==fixture['did'], 'authorized public document returned')
    http={'method':'GET','url':'https://EXAMPLE.com:443/test','headers':{},'body':{'state':'absent'},'nonce':None}
    signing={'operation':'SIGN_HTTP','grant_id':grant_id,'request_id':str(uuid.uuid4()),'http':http}
    def unlock_key(kid):
        op={'version':2,'request':{'operation':'UNLOCK_KEY','vault_id':vault_id,'did':fixture['did'],'kid':kid}}
        result=subprocess.run([sys.executable,'-c',admin_call,config['admin_socket'],json.dumps(op)],preexec_fn=identity('boundary-admin'),capture_output=True,text=True,timeout=12)
        assert result.returncode==0 and json.loads(result.stdout)['code']=='OK', result.stdout+result.stderr
    def unlock_hot():
        unlock_key(hot_key['kid'])
    unlock_hot()
    if os.environ.get('ANPIO_KEY_TEST_SDK'):
        sdk_policy_id = str(uuid.uuid4())
        sdk_policy = {**policy, 'name': 'sdk-hot-login', 'methods': ['POST'],
                      'paths': ['/user-service/v1/did-auth/rpc'],
                      'body': {'mode': 'bounded', 'max_bytes': 16384}}
        commit_change({'kind': 'Catalog', 'change': {'action': 'PublishPolicy',
                      'policy_id': sdk_policy_id, 'version': 1, 'content': sdk_policy}})
        sdk_grant = commit_change({'kind': 'Grant', 'change': {**create_grant,
                      'policy_id': sdk_policy_id}})['effect']['effect']['grant']['grant_id']
        unlock_hot()  # Publishing management state deliberately locks loaded keys.
        sdk_result = subprocess.run(['node', 'adapters/test-sdk.mjs', os.environ['ANPIO_KEY_TEST_SDK'],
                      sdk_grant, hot_key['key_id'], str(uuid.uuid4()), str(uuid.uuid4())],
                      preexec_fn=identity('boundary-agent-a'), capture_output=True, text=True, timeout=20)
        check(sdk_result.returncode == 0, 'SDK high-level hot-key login under independent Agent UID: ' + sdk_result.stderr)
        check(json.loads(sdk_result.stdout)['sdkHotResolverSupported'], 'SDK hot resolver requires no public-key override')
    first=data_as('boundary-agent-a',signing)
    check(first['code']=='OK' and first['data']['state']=='completed' and first['data']['result']['url']=='https://example.com/test', 'M4 signs canonical target after durable reservation and result commit')
    check(data_as('boundary-agent-a',signing)['data']==first['data'], 'same ID returns identical cached signature without a second use')
    check(data_as('boundary-agent-a',{'operation':'GET_REQUEST_STATUS','request_id':signing['request_id']})['data']==first['data'], 'lost response can be recovered by request status')
    check(data_as('boundary-agent-b',{'operation':'GET_REQUEST_STATUS','request_id':signing['request_id']})['code']=='REQUEST_NOT_FOUND', 'request results remain scoped to principal')
    check(data_as('boundary-agent-a',{**signing,'http':{**http,'nonce':'different'}})['code']=='REQUEST_ID_CONFLICT', 'request ID cannot be rebound to another payload')
    check(data_as('boundary-agent-b',signing)['code']=='GRANT_INVALID', 'cross-principal signing refused')
    for target in ['https://evil.com/test','https://example.com/other','https://example.com/%74est','https://example.com/a/../test','https://example.com//test','https://example.com/test?a=1&a=2']:
        denied={**signing,'request_id':str(uuid.uuid4()),'http':{**http,'url':target}}
        check(data_as('boundary-agent-a',denied)['code']=='POLICY_DENIED', 'policy and canonical target reject '+target)
    check(data_as('boundary-agent-a',{**signing,'did':fixture['did']})['code']=='PROTOCOL_INVALID', 'data caller cannot override exact grant key')
    for operation in ['SIGN_RAW','SIGN_CHALLENGE','LOCK_ALL']:
        check(data_as('boundary-agent-a',{'operation':operation})['code']=='PROTOCOL_INVALID','v2 excludes '+operation)
    origin={'method':'direct.send','meta':{'profile':'anp.direct.base.v1','sender_did':fixture['did'],'target':{'kind':'agent','did':fixture['did']},'message_id':'msg-p1'},'body':{'text':'hi'}}
    check(data_as('boundary-agent-a',{'operation':'SIGN_ORIGIN_PROOF','grant_id':grant_id,'request_id':str(uuid.uuid4()),'origin':origin})['code']=='OPERATION_DISABLED','origin proof path is off until the deployment switch is on')
    check(data_as('boundary-agent-a',{'operation':'SIGN_PURPOSE','grant_id':grant_id,'request_id':str(uuid.uuid4()),'purpose':'device_assertion','payload':'00ff'})['code']=='OPERATION_DISABLED','purpose signing is off until its own switch is on')
    check(data_as('boundary-agent-a',{'operation':'SIGN_PURPOSE','grant_id':grant_id,'request_id':str(uuid.uuid4()),'purpose':'authentication','payload':'00ff'})['code']=='PURPOSE_INVALID','an unknown purpose is refused before any switch is consulted')
    caps_off=data_as('boundary-agent-a',{'operation':'GET_CAPABILITIES'})['data']
    check('SIGN_ORIGIN_PROOF' not in caps_off['operations'] and 'RENEW_GRANT' in caps_off['operations'] and caps_off['grant_kinds']==['request','session'],'capabilities hide a disabled signing path but still announce renewal')
    check('SIGN_PURPOSE' not in caps_off['operations'] and caps_off['signing_purposes']==[],'capabilities hide every disabled signing purpose')
    check(data_as('boundary-agent-a',{'operation':'SIGN_OBJECT_PROOF','grant_id':grant_id,'request_id':str(uuid.uuid4()),'object':{'@type':'Probe'}})['code']=='OPERATION_DISABLED','object proof is off until its own switch is on')
    check(data_as('boundary-agent-a',{'operation':'SIGN_DOCUMENT_PROOF','grant_id':grant_id,'request_id':str(uuid.uuid4()),'document':{'id':fixture['did']}})['code']=='OPERATION_DISABLED','document proof has its own switch, not the object one')
    check('SIGN_OBJECT_PROOF' not in caps_off['operations'] and 'SIGN_DOCUMENT_PROOF' not in caps_off['operations'] and 'object-proof' not in caps_off['purposes'] and 'document-proof' not in caps_off['purposes'],'capabilities hide both disabled proof paths and their purposes')
    root_grant={**create_grant,'key_id':root_key['key_id']}
    source.write_text(json.dumps({'kind':'Grant','change':root_grant}));source.chmod(0o644)
    check(command('boundary-admin','admin','prepare','--file',str(source)).returncode!=0, 'root role cannot enter an Agent grant')
    check(data_as('boundary-agent-a',{'operation':'GET_GRANT_STATUS','grant_id':grant_id})['data']['used_uses']==1,'retries and policy denials do not consume extra quota')
    # Revoke A while a separate grant to B remains usable.
    second=commit_change({'kind':'Grant','change':{**create_grant,'principal_id':principal_b}})['effect']['effect']['grant']['grant_id']
    commit_change({'kind':'Grant','change':{'action':'Revoke','grant_id':grant_id}})
    check('result' not in data_as('boundary-agent-a',signing)['data'],'revocation suppresses cached signature delivery')
    check(data_as('boundary-agent-b',{**signing,'grant_id':second})['data']['state']=='completed','revoking A leaves B signing usable without unlocking again')
    source.write_text(json.dumps({'operation':'LIST_AUTHORIZED_KEYS'}));source.chmod(0o644)
    check(command('boundary-agent-b','data','--file',str(source)).returncode==0,'v2 CLI authenticates fixed configured endpoint')
    check(command('boundary-agent-b','data','--socket','/tmp/evil','--file',str(source)).returncode!=0,'v2 CLI has no socket override')
    if command('boundary-agent-b','mcp','--help').returncode == 0:
        child=subprocess.Popen([binary,'mcp','--config',str(config_path)],preexec_fn=identity('boundary-agent-b'),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
        def rpc(value):
            child.stdin.write(json.dumps(value)+'\n');child.stdin.flush()
            assert select.select([child.stdout],[],[],10)[0], 'MCP reply timed out'
            return json.loads(child.stdout.readline())
        try:
            init=rpc({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2024-11-05','capabilities':{},'clientInfo':{'name':'boundary-test','version':'1'}}})
            check('result' in init,'protected MCP initializes with clean JSON stdout')
            child.stdin.write(json.dumps({'jsonrpc':'2.0','method':'notifications/initialized'})+'\n');child.stdin.flush()
            tools=rpc({'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}})['result']['tools']
            check(len(tools)==5 and all(t['name'] not in ['unlock','lock_all','sign_raw','sign_challenge'] for t in tools),'protected MCP exposes only five authorized v2 tools')
            listed=rpc({'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'list_my_keys','arguments':{}}})
            result=json.loads(listed['result']['content'][0]['text'])
            check(result['data']['keys'][0]['key_id']==hot_key['key_id'],'protected MCP lists only caller-authorized hot key')
            signed=rpc({'jsonrpc':'2.0','id':4,'method':'tools/call','params':{'name':'sign_request','arguments':{'grant_id':second,'request_id':str(uuid.uuid4()),'http':http}}})
            check('Signature-Input' in json.dumps(signed),'protected MCP completes durable v2 signature without legacy fallback')
        finally:
            child.terminate();child.wait(timeout=10)
    # Last remaining use: many distinct requests contend for one durable slot.
    from concurrent.futures import ThreadPoolExecutor
    one=commit_change({'kind':'Grant','change':{**create_grant,'max_uses':1}})['effect']['effect']['grant']['grant_id']
    calls=[{**signing,'grant_id':one,'request_id':str(uuid.uuid4())} for _ in range(8)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes=list(pool.map(lambda op:data_as('boundary-agent-a',op),calls))
    check(sum(r['code']=='OK' and r['data'].get('result') is not None for r in outcomes)==1, 'eight concurrent final-use requests yield exactly one signature')
    winner=next(op for op,r in zip(calls,outcomes) if r['code']=='OK')
    cached=data_as('boundary-agent-a',winner)
    check(cached['data']['result'] is not None,'last completed signature remains retrievable after exhaustion')
    # A response lost on the socket still leaves a single completed result.
    lost=commit_change({'kind':'Grant','change':{**create_grant,'max_uses':1}})['effect']['effect']['grant']['grant_id']
    lostop={**signing,'grant_id':lost,'request_id':str(uuid.uuid4())}
    drop_script="import socket,struct,sys;s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);p=sys.argv[2].encode();s.sendall(struct.pack('!I',len(p))+p);s.close()"
    subprocess.run([sys.executable,'-c',drop_script,config['sign_socket'],json.dumps({'version':2,'request':lostop})],preexec_fn=identity('boundary-agent-a'),check=True)
    for _ in range(50):
        recovered=data_as('boundary-agent-a',{'operation':'GET_REQUEST_STATUS','request_id':lostop['request_id']})
        if recovered['code']=='OK':break
        time.sleep(.02)
    check(recovered['data']['state']=='completed' and recovered['data'].get('result') is not None,'disconnect after send preserves completed result for explicit recovery')
    # P1: the origin-proof path only exists once the deployment switch is on.
    # P2: every signing purpose has its own switch, and only its own.
    config['features']={'sign_origin_proof':True,'sign_purpose':{'device_assertion':True}}
    config_path.write_text(json.dumps(config))
    stop(process); process=start()
    check(data_as('boundary-agent-a',{'operation':'GET_GRANT_STATUS','grant_id':lost})['data']['state'] in ['revoked_restart','exhausted'],'restart never revives consumed grants')
    check('result' not in data_as('boundary-agent-a',{'operation':'GET_REQUEST_STATUS','request_id':lostop['request_id']})['data'],'restart suppresses old completed signature')
    check(data_as('boundary-agent-a',{**signing,'grant_id':lost,'request_id':str(uuid.uuid4())})['code'] in ['GRANT_INVALID','GRANT_EXHAUSTED'],'restart refuses old grant for new signing')
    origin_policy_id=str(uuid.uuid4())
    origin_path='/'+urllib.parse.quote(fixture['did'],safe='')
    origin_policy={'schema_version':2,'name':'im-origin-proof','purpose':'origin-proof',
                   'limits':{'max_duration_seconds':600,'max_uses':1000,'max_lifetime_seconds':3600,'max_renewals':1},
                   'content':{'origin':'anp://agent','methods':['direct.send'],'paths':[origin_path],'body':{'mode':'bounded','max_bytes':1024}}}
    commit_change({'kind':'Catalog','change':{'action':'PublishPolicy','policy_id':origin_policy_id,'version':1,'content':origin_policy}})
    session=commit_change({'kind':'Grant','change':{'action':'CreateSession','principal_id':principal_a,'key_id':hot_key['key_id'],'policy_id':origin_policy_id,'policy_version':1,'expiry':int(time.time())+300,'max_uses':50}})['effect']['effect']['grant']
    check(session['kind']=='session' and session['max_renewals']==1 and session['renewals']==0,'session grant takes its renewal budget from the policy, not the caller')
    unlock_hot()
    caps=data_as('boundary-agent-a',{'operation':'GET_CAPABILITIES'})['data']
    check('SIGN_ORIGIN_PROOF' in caps['operations'] and 'origin-proof' in caps['purposes'],'capabilities announce the enabled origin path')
    origin_op={'operation':'SIGN_ORIGIN_PROOF','grant_id':session['grant_id'],'request_id':str(uuid.uuid4()),'origin':origin}
    proof=data_as('boundary-agent-a',origin_op)
    check(proof['code']=='OK' and proof['data']['state']=='completed','origin proof signs over the real v2 socket')
    result=proof['data']['result']
    digest=result['content_digest']
    check(result['signature_input'].startswith('sig1=(') and result['signature'].startswith('sig1=:') and digest.startswith('sha-256=:') and len(digest)==len('sha-256=::')+44 and result['expires'] is None and set(result)=={'request_id','content_digest','signature_input','signature','created','expires'},'origin proof returns header-ready RFC 9421 values and no key material')
    check(data_as('boundary-agent-a',origin_op)['data']==proof['data'],'same origin request ID returns the identical cached proof without a second use')
    check(data_as('boundary-agent-a',{**origin_op,'origin':{**origin,'body':{'text':'different'}}})['code']=='REQUEST_ID_CONFLICT','origin proof ID cannot be rebound to another body')
    check(data_as('boundary-agent-a',{**origin_op,'request_id':lostop['request_id']})['code']=='REQUEST_ID_CONFLICT','HTTP and origin proofs share one request-id namespace')
    check(data_as('boundary-agent-b',origin_op)['code']=='GRANT_INVALID','origin proof stays bound to its principal')
    group_origin={**origin,'meta':{**origin['meta'],'target':{'kind':'group','did':fixture['did']}}}
    check(data_as('boundary-agent-a',{**origin_op,'request_id':str(uuid.uuid4()),'origin':group_origin})['code']=='POLICY_DENIED','origin policy gates the signed target kind')
    other_did_origin={**origin,'meta':{**origin['meta'],'target':{'kind':'agent','did':'did:wba:example.com:someone-else'}}}
    check(data_as('boundary-agent-a',{**origin_op,'request_id':str(uuid.uuid4()),'origin':other_did_origin})['code']=='POLICY_DENIED','origin policy gates the DID itself, not just its kind')
    big_origin={**origin,'body':{'text':'x'*2048}}
    check(data_as('boundary-agent-a',{**origin_op,'request_id':str(uuid.uuid4()),'origin':big_origin})['code']=='POLICY_DENIED','origin policy gates the signed body size')
    for bad in [{**origin,'method':'Direct.Send'},{**origin,'meta':{'profile':'p'}}]:
        check(data_as('boundary-agent-a',{'operation':'SIGN_ORIGIN_PROOF','grant_id':session['grant_id'],'request_id':str(uuid.uuid4()),'origin':bad})['code']=='ORIGIN_INVALID','malformed origin facts are refused before signing')
    check(data_as('boundary-agent-a',{'operation':'SIGN_ORIGIN_PROOF','grant_id':session['grant_id'],'request_id':str(uuid.uuid4()),'origin':{**origin,'did':fixture['did']}})['code']=='PROTOCOL_INVALID','origin caller cannot bring its own exact key')
    renewed=data_as('boundary-agent-a',{'operation':'RENEW_GRANT','grant_id':session['grant_id'],'expiry':int(time.time())+3000})['data']
    check(renewed['renewals']==1 and renewed['expiry']>session['expiry'],'session renewal extends the same grant')
    check(renewed['expiry']<=renewed['created_at']+origin_policy['limits']['max_lifetime_seconds'],'renewal clamps at the absolute lifetime ceiling')
    check(data_as('boundary-agent-a',{'operation':'RENEW_GRANT','grant_id':session['grant_id'],'expiry':int(time.time())+3000})['code']=='GRANT_RENEWALS_EXHAUSTED','renewal budget from the policy is enforced')
    backwards=commit_change({'kind':'Grant','change':{'action':'CreateSession','principal_id':principal_a,'key_id':hot_key['key_id'],'policy_id':origin_policy_id,'policy_version':1,'expiry':int(time.time())+300,'max_uses':50}})['effect']['effect']['grant']
    check(data_as('boundary-agent-a',{'operation':'RENEW_GRANT','grant_id':backwards['grant_id'],'expiry':backwards['expiry']-10})['code']=='GRANT_INVALID','renewal never shortens a grant')
    one_shot=commit_change({'kind':'Grant','change':{'action':'Create','principal_id':principal_a,'key_id':hot_key['key_id'],'policy_id':origin_policy_id,'policy_version':1,'expiry':int(time.time())+300,'max_uses':2}})['effect']['effect']['grant']
    check(one_shot['max_renewals']==0 and data_as('boundary-agent-a',{'operation':'RENEW_GRANT','grant_id':one_shot['grant_id'],'expiry':int(time.time())+600})['code']=='GRANT_INVALID','a one-shot request grant cannot be renewed')
    # P2: one purpose, one dedicated key, one switch. The key is bound when it is
    # classified; the policy can only narrow further.
    purpose_policy_id=str(uuid.uuid4())
    purpose_policy={'schema_version':2,'name':'mls-device-assertion','purpose':'purpose-signing',
                    'limits':{'max_duration_seconds':600,'max_uses':1000,'max_lifetime_seconds':3600,'max_renewals':1},
                    'content':{'purposes':['device_assertion']}}
    commit_change({'kind':'Catalog','change':{'action':'PublishPolicy','policy_id':purpose_policy_id,'version':1,'content':purpose_policy}})
    purpose_grant=commit_change({'kind':'Grant','change':{'action':'CreateSession','principal_id':principal_a,'key_id':device_key['key_id'],'policy_id':purpose_policy_id,'policy_version':1,'expiry':int(time.time())+300,'max_uses':50}})['effect']['effect']['grant']
    unlock_key(device_key['kid'])
    caps=data_as('boundary-agent-a',{'operation':'GET_CAPABILITIES'})['data']
    check('SIGN_PURPOSE' in caps['operations'] and 'purpose-signing' in caps['purposes'] and caps['signing_purposes']==['device_assertion'],'capabilities announce exactly the enabled signing purpose')
    purpose_payload=b'anp-device-assertion'
    purpose_op={'operation':'SIGN_PURPOSE','grant_id':purpose_grant['grant_id'],'request_id':str(uuid.uuid4()),'purpose':'device_assertion','payload':purpose_payload.hex()}
    signed_purpose=data_as('boundary-agent-a',purpose_op)
    check(signed_purpose['code']=='OK' and signed_purpose['data']['state']=='completed','device assertion signs over the real v2 socket')
    assertion=signed_purpose['data']['result']
    check(set(assertion)=={'request_id','signature','public_multibase','purpose'} and len(assertion['signature'])==128 and assertion['public_multibase'].startswith('z') and assertion['purpose']=={'purpose':'device_assertion'},'device assertion returns raw signature bytes and a public multibase only')
    published=data_as('boundary-agent-a',{'operation':'GET_DOCUMENT','key_id':device_key['key_id']})['data']['document']
    check(assertion['public_multibase'] in json.dumps(published),'the assertion came from the key the DID document publishes')
    check(data_as('boundary-agent-a',purpose_op)['data']==signed_purpose['data'],'same assertion request ID returns the identical cached signature')
    check(data_as('boundary-agent-a',{'operation':'GET_REQUEST_STATUS','request_id':purpose_op['request_id']})['data']==signed_purpose['data'],'assertion result is recoverable by request status')
    check(data_as('boundary-agent-a',{**purpose_op,'payload':b'other'.hex()})['code']=='REQUEST_ID_CONFLICT','assertion ID cannot be rebound to another payload')
    check(data_as('boundary-agent-b',purpose_op)['code']=='GRANT_INVALID','assertion stays bound to its principal')
    check(data_as('boundary-agent-a',{**purpose_op,'request_id':str(uuid.uuid4()),'purpose':'application_assertion'})['code']=='OPERATION_DISABLED','a sibling purpose switch that is off stays off')
    check(data_as('boundary-agent-a',{**purpose_op,'request_id':str(uuid.uuid4()),'purpose':'authentication'})['code']=='PURPOSE_INVALID','unknown purposes never reach a key')
    check(data_as('boundary-agent-a',{**purpose_op,'request_id':str(uuid.uuid4()),'domain':'chat.alpha'})['code']=='PURPOSE_INVALID','a domain belongs to application assertions only')
    check(data_as('boundary-agent-a',{**purpose_op,'request_id':str(uuid.uuid4()),'payload':'AB'})['code']=='PURPOSE_INVALID','assertion payload must be strict lowercase hex')
    check(data_as('boundary-agent-a',{**purpose_op,'request_id':str(uuid.uuid4()),'key_id':hot_key['key_id']})['code']=='PROTOCOL_INVALID','assertion caller cannot bring its own exact key')
    narrower_policy_id=str(uuid.uuid4())
    commit_change({'kind':'Catalog','change':{'action':'PublishPolicy','policy_id':narrower_policy_id,'version':1,'content':{**purpose_policy,'name':'mls-app-only','content':{'purposes':['application_assertion']}}}})
    narrower_grant=commit_change({'kind':'Grant','change':{'action':'Create','principal_id':principal_a,'key_id':device_key['key_id'],'policy_id':narrower_policy_id,'policy_version':1,'expiry':int(time.time())+55,'max_uses':2}})['effect']['effect']['grant']['grant_id']
    check(data_as('boundary-agent-a',{**purpose_op,'grant_id':narrower_grant,'request_id':str(uuid.uuid4())})['code']=='POLICY_DENIED','a policy that does not list the purpose denies it even for the bound key')
    check(data_as('boundary-agent-a',{'operation':'GET_GRANT_STATUS','grant_id':purpose_grant['grant_id']})['data']['used_uses']==1,'assertion retries and denials do not consume extra quota')
    with sqlite3.connect(Path(config['state_dir'])/'state.sqlite') as database:
        audit_rows=[row[0].decode() for row in database.execute('SELECT event_data FROM audit_events')]
    events=''.join(audit_rows).replace(' ','')
    check('"GRANT_RENEWED"' in events and '"event":"FEATURES"' in events and '"sign_origin_proof":true' in events,'renewals and the enabled switch are both on the audit chain')
    check('"event":"SIGN_PURPOSE_ENABLED","purpose":"device_assertion"' in events,'the enabled signing purpose has its own audit line')
    signed_events=[json.loads(row) for row in audit_rows if 'SIGN_COMPLETED' in row]
    check(any(event.get('signing',{}).get('purpose')=='device_assertion' for event in signed_events),'the audit chain records the bound purpose, not just the grant')
    check(purpose_payload.hex() not in events,'signed assertion bytes never reach the audit chain')
    with sqlite3.connect(Path(config['state_dir'])/'state.sqlite') as database:
        check(database.execute("SELECT count(*) FROM audit_events WHERE CAST(event_data AS TEXT) LIKE '%LEGACY_AUDIT_LINKED%'").fetchone()[0]>=1,'SQLite history links verified legacy audit without rewriting it')
    # P5: object and document proofs over the same socket. Each returns the input
    # with its proof folded in; neither ever hands the key to the caller.
    config['features']={'sign_origin_proof':True,'sign_purpose':{'device_assertion':True},
                        'sign_object_proof':True,'sign_document_proof':True}
    config_path.write_text(json.dumps(config))
    stop(process); process=start()
    object_policy_id=str(uuid.uuid4())
    object_policy={'schema_version':2,'name':'device-object-proof','purpose':'object-proof',
                   'limits':{'max_duration_seconds':600,'max_uses':1000,'max_lifetime_seconds':3600,'max_renewals':1},
                   'content':{'proof_purposes':['assertionMethod']}}
    commit_change({'kind':'Catalog','change':{'action':'PublishPolicy','policy_id':object_policy_id,'version':1,'content':object_policy}})
    source.write_text(json.dumps({'kind':'Catalog','change':{'action':'PublishPolicy','policy_id':str(uuid.uuid4()),'version':1,'content':{**object_policy,'content':{'proof_purposes':['authentication']}}}})); source.chmod(0o644)
    check(command('boundary-admin','admin','prepare','--file',str(source)).returncode!=0,'an object-proof policy cannot promise a purpose that path cannot produce')
    document_policy_id=str(uuid.uuid4())
    document_policy={'schema_version':2,'name':'identity-document-proof','purpose':'document-proof',
                     'limits':{'max_duration_seconds':600,'max_uses':1000,'max_lifetime_seconds':3600,'max_renewals':1},
                     'content':{'proof_purposes':['assertionMethod','authentication']}}
    commit_change({'kind':'Catalog','change':{'action':'PublishPolicy','policy_id':document_policy_id,'version':1,'content':document_policy}})
    source.write_text(json.dumps({'kind':'Catalog','change':{'action':'PublishPolicy','policy_id':str(uuid.uuid4()),'version':1,'content':{**document_policy,'content':{'proof_purposes':['capabilityInvocation']}}}})); source.chmod(0o644)
    check(command('boundary-admin','admin','prepare','--file',str(source)).returncode!=0,'a document-proof policy only declares W3C proof purposes')
    object_grant=commit_change({'kind':'Grant','change':{'action':'Create','principal_id':principal_a,'key_id':device_key['key_id'],'policy_id':object_policy_id,'policy_version':1,'expiry':int(time.time())+300,'max_uses':5}})['effect']['effect']['grant']
    document_grant=commit_change({'kind':'Grant','change':{'action':'Create','principal_id':principal_a,'key_id':root_key['key_id'],'policy_id':document_policy_id,'policy_version':1,'expiry':int(time.time())+300,'max_uses':5}})['effect']['effect']['grant']
    source.write_text(json.dumps({'kind':'Grant','change':{'action':'Create','principal_id':principal_a,'key_id':device_key['key_id'],'policy_id':document_policy_id,'policy_version':1,'expiry':int(time.time())+300,'max_uses':1}})); source.chmod(0o644)
    check(command('boundary-admin','admin','prepare','--file',str(source)).returncode!=0,'the document-proof policy refuses every key that is not the root')
    unlock_key(device_key['kid']); unlock_key(root_key['kid'])
    caps=data_as('boundary-agent-a',{'operation':'GET_CAPABILITIES'})['data']
    check('SIGN_OBJECT_PROOF' in caps['operations'] and 'SIGN_DOCUMENT_PROOF' in caps['operations'] and 'object-proof' in caps['purposes'] and 'document-proof' in caps['purposes'],'capabilities announce both proof paths once their switches are on')
    device_object={'@type':'AnpDeviceAssertion','device':fixture['did'],'nonce':'p5-object-nonce'}
    object_op={'operation':'SIGN_OBJECT_PROOF','grant_id':object_grant['grant_id'],'request_id':str(uuid.uuid4()),'object':device_object}
    signed_object=data_as('boundary-agent-a',object_op)
    check(signed_object['code']=='OK' and signed_object['data']['state']=='completed','object proof signs over the real v2 socket')
    folded=signed_object['data']['result']
    check(set(folded)=={'request_id','value','proof'} and folded['value']['@type']=='AnpDeviceAssertion' and folded['proof']==folded['value']['proof'],'an object proof returns the object with its proof folded in and nothing else')
    object_proof=folded['value']['proof']
    check(object_proof['proofValue'].startswith('z') and object_proof['type']=='DataIntegrityProof' and object_proof['cryptosuite']=='eddsa-jcs-2022' and object_proof['proofPurpose']=='assertionMethod' and object_proof['verificationMethod']==device_key['kid'],'object proof is multibase base58btc, a fixed cryptosuite, and the granted key')
    check('created' in object_proof and data_as('boundary-agent-a',{**object_op,'request_id':str(uuid.uuid4()),'created':1})['code']=='PROTOCOL_INVALID','the daemon chooses the proof timestamp; a caller-supplied one is not a field')
    check(data_as('boundary-agent-a',object_op)['data']==signed_object['data'],'same object proof ID returns the identical cached proof without a second use')
    check(data_as('boundary-agent-a',{**object_op,'object':{**device_object,'nonce':'other'}})['code']=='REQUEST_ID_CONFLICT','object proof ID cannot be rebound to another object')
    check(data_as('boundary-agent-b',object_op)['code']=='GRANT_INVALID','object proof stays bound to its principal')
    published_document=json.loads(next((vault/'dids').glob('*.json')).read_text())
    document_op={'operation':'SIGN_DOCUMENT_PROOF','grant_id':document_grant['grant_id'],'request_id':str(uuid.uuid4()),'document':published_document}
    signed_document=data_as('boundary-agent-a',document_op)
    check(signed_document['code']=='OK' and signed_document['data']['state']=='completed','document proof signs the published identity document over the real v2 socket')
    signed_identity=signed_document['data']['result']['value']
    check(signed_identity['id']==fixture['did'] and signed_identity['proof']['proofValue'].startswith('z') and signed_identity['proof']['proofPurpose']=='assertionMethod' and signed_identity['proof']['verificationMethod']==root_key['kid'] and signed_identity['proof']['type']=='DataIntegrityProof' and signed_identity['proof']['cryptosuite']=='eddsa-jcs-2022','the root key signs its own document in the published multibase alphabet')
    authentication=data_as('boundary-agent-a',{**document_op,'request_id':str(uuid.uuid4()),'proof_purpose':'authentication'})
    check(authentication['code']=='OK' and authentication['data']['result']['value']['proof']['proofPurpose']=='authentication','the document takes the second declared purpose too')
    check(data_as('boundary-agent-a',{**document_op,'request_id':str(uuid.uuid4()),'proof_purpose':'capabilityInvocation'})['code']=='PROOF_INVALID','a purpose outside the vocabulary never reaches a key')
    stranger=json.loads(json.dumps(published_document));stranger['id']='did:wba:example.com:someone-else'
    spent=data_as('boundary-agent-a',{'operation':'GET_GRANT_STATUS','grant_id':document_grant['grant_id']})['data']['used_uses']
    check(data_as('boundary-agent-a',{**document_op,'request_id':str(uuid.uuid4()),'document':stranger})['code']=='PROOF_INVALID','a document bound to another identity is refused')
    check(data_as('boundary-agent-a',{'operation':'GET_GRANT_STATUS','grant_id':document_grant['grant_id']})['data']['used_uses']==spent,'a refused binding never spends quota')
    with sqlite3.connect(Path(config['state_dir'])/'state.sqlite') as database:
        audit_rows=[row[0].decode() for row in database.execute('SELECT event_data FROM audit_events')]
    proof_events=''.join(audit_rows).replace(' ','')
    check('"event":"SIGN_OBJECT_PROOF_ENABLED"' in proof_events and '"event":"SIGN_DOCUMENT_PROOF_ENABLED"' in proof_events,'each proof path records its own switch on the audit chain')
    completions=[json.loads(row) for row in audit_rows if 'SIGN_COMPLETED' in row]
    check(any(event.get('proof',{}).get('purpose')=='assertionMethod' and event.get('proof',{}).get('document_digest') for event in completions),'the completion audit records the proof shape and the input digest')
    check('p5-object-nonce' not in proof_events and json.dumps(device_object) not in proof_events,'neither proof body reaches the audit chain')
    policy['unexpected'] = True
    source.write_text(json.dumps({'kind':'Catalog','change':{'action':'PublishPolicy','policy_id':policy_id,'version':2,'content':policy}}))
    check(command('boundary-admin','admin','prepare','--file',str(source)).returncode != 0, 'policy schema rejects unknown fields')
    doc = json.loads(next((vault / 'dids').glob('*.json')).read_text())
    commit_change({'kind':'Catalog','change':{'action':'InstallDocument','vault_id':vault_id,'document':doc}})
    with sqlite3.connect(Path(config['state_dir']) / 'state.sqlite') as database:
        check(database.execute("SELECT count(*) FROM file_operations WHERE state='complete'").fetchone()[0] == 1, 'managed document install completes durable file journal')
    unlocked = subprocess.run([sys.executable, '-c', admin_call, config['admin_socket'], json.dumps(unlock)], preexec_fn=identity('boundary-admin'), capture_output=True, text=True, timeout=12)
    check(unlocked.returncode == 0 and json.loads(unlocked.stdout)['code'] == 'OK', 'authenticated admin unlocks temporary vault, connection closes: ' + unlocked.stdout + unlocked.stderr)
    check(command('boundary-admin', 'admin', 'lock-all').returncode == 0, 'independent management lock works')
    with sqlite3.connect(Path(config['state_dir']) / 'state.sqlite') as database:
        audit = ''.join(row[0].decode() for row in database.execute('SELECT event_data FROM audit_events'))
    check('temporary-boundary-test-secret' not in audit and '"dropped":1' in audit.replace(' ', ''), 'transactional audit records management lock count without secrets')
    # The old data wire must fail, not downgrade. A known principal sends LIST_KEYS.
    legacy = code.replace("data=json.dumps({'version':2,'request':{'operation':'GET_CAPABILITIES'}}).encode()", "data=bytes([1])")
    refused = subprocess.run([sys.executable, '-c', legacy, config['sign_socket']], preexec_fn=identity('boundary-agent-b'), capture_output=True, text=True, timeout=8)
    check('PROTOCOL_INVALID' in refused.stdout, 'v1 cannot downgrade data endpoint')
    # Service-owned state is inaccessible even through the same public executable.
    read = subprocess.run(['cat', str(vault / 'device.secret')], preexec_fn=identity('boundary-agent-a'), capture_output=True)
    check(read.returncode != 0 and not read.stdout, 'Agent cannot read service vault material')
    # Stale config mutations and bad ownership are rejected at client side.
    original = config_path.read_text()
    config_path.chmod(0o666)
    check(command('boundary-admin', 'admin', 'status').returncode != 0, 'client rejects writable trust config')
    config_path.chmod(0o644)
    bad = dict(config, service_uid=pwd.getpwnam('boundary-stranger').pw_uid)
    config_path.write_text(json.dumps(bad))
    check(command('boundary-admin', 'admin', 'status').returncode != 0, 'client rejects mismatched service ownership')
    config_path.write_text(original)
    second = command('anpio-key', 'serve-protected')
    check(second.returncode != 0 and 'state lock' in second.stderr, 'second daemon cannot replace sockets')
    # Slow partial data frames consume only bounded data slots, not admin slots.
    slow_code = """import socket,sys,time
sockets=[]
for _ in range(20):
 s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);sockets.append(s)
print('ready',flush=True)
sys.stdin.readline()
for s in sockets:s.close()
"""
    slow = subprocess.Popen([sys.executable, '-c', slow_code, config['sign_socket']], preexec_fn=identity('boundary-agent-b'), stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    assert slow.stdout.readline().strip() == 'ready'
    started = time.monotonic()
    check(command('boundary-admin', 'admin', 'lock-all').returncode == 0 and time.monotonic() - started < 3, 'authorized slow data clients do not starve management')
    slow.communicate('done\n', timeout=8)
    # Inject failure after a real backend signature but before its durable result.
    failed_grant=commit_change({'kind':'Grant','change':{**create_grant,'expiry':int(time.time())+55}})['effect']['effect']['grant']['grant_id']
    unlock_hot()
    failed_request={**signing,'grant_id':failed_grant,'request_id':str(uuid.uuid4())}
    with sqlite3.connect(Path(config['state_dir'])/'state.sqlite') as database:
        database.execute("CREATE TRIGGER fail_result BEFORE INSERT ON audit_events WHEN CAST(NEW.event_data AS TEXT) LIKE '%SIGN_COMPLETED%' BEGIN SELECT RAISE(ABORT,'result failure'); END")
    failed=data_as('boundary-agent-a',failed_request)
    check(failed['code']=='AUDIT_UNAVAILABLE' and failed.get('data') is None,'result audit failure releases no real backend signature and stops signing')
    with sqlite3.connect(Path(config['state_dir'])/'state.sqlite') as database:
        check(database.execute('SELECT used_uses FROM grants WHERE grant_id=?',(failed_grant,)).fetchone()[0]==1,'result audit failure preserves consumed quota')
        database.execute('DROP TRIGGER fail_result')
    check(data_as('boundary-agent-a',failed_request)['code']=='AUDIT_UNAVAILABLE','repair cannot silently retry a failed result commit')

finally:
    stop(process)

# Impersonation test: socket inode owner looks correct, actual server UID differs.
# Only root can manufacture this setup; the client must still check SO_PEERCRED.
fake_path = config['admin_socket']
fake_code = '''import socket,sys,time
s=socket.socket(socket.AF_UNIX);s.bind(sys.argv[1]);s.listen();print('ready',flush=True);c,_=s.accept();c.settimeout(3)
try:data=c.recv(100)
except Exception:data=b''
print(len(data),flush=True)
'''
fake = subprocess.Popen([sys.executable, '-c', fake_code, fake_path], stdout=subprocess.PIPE, text=True)
assert fake.stdout.readline().strip() == 'ready'
os.chown(fake_path, service.pw_uid, config['admin_gid'])
os.chmod(fake_path, 0o660)
result = command('boundary-admin', 'admin', 'unlock', '--vault-id', vault_id, '--did', fixture['did'], '--kid', fixture['kid'])
check('SERVER_IDENTITY_MISMATCH' in result.stderr, 'kernel peer credentials reject fake daemon before TTY/password')
check(fake.stdout.readline().strip() == '0', 'fake daemon receives zero credential bytes')
fake.wait(timeout=5)
Path(fake_path).unlink()
# Refuse a regular file occupying a socket location; never unlink it.
Path(config['sign_socket']).write_text('keep me')
os.chown(config['sign_socket'], service.pw_uid, config['agent_gid'])
os.chmod(config['sign_socket'], 0o660)
result = command('anpio-key', 'serve-protected')
check(result.returncode != 0 and Path(config['sign_socket']).read_text() == 'keep me', 'stale cleanup preserves regular files')
Path(config['sign_socket']).unlink()
# Symlinks are never treated as stale sockets.
marker = Path('/tmp/keyd-boundary-marker')
marker.write_text('preserve symlink target')
Path(config['sign_socket']).symlink_to(marker)
result = command('anpio-key', 'serve-protected')
check(result.returncode != 0 and Path(config['sign_socket']).is_symlink() and marker.read_text() == 'preserve symlink target', 'stale cleanup preserves symlinks and targets')
Path(config['sign_socket']).unlink()
# A real abandoned service-owned socket is safely removed under the state lock.
with socket.socket(socket.AF_UNIX) as abandoned:
    abandoned.bind(config['sign_socket'])
os.chown(config['sign_socket'], service.pw_uid, config['agent_gid'])
os.chmod(config['sign_socket'], 0o660)
process = start()
check(command('boundary-admin', 'admin', 'status').returncode == 0, 'verified stale socket is recovered')
check(data_as('boundary-agent-a',{'operation':'GET_REQUEST_STATUS','request_id':failed_request['request_id']})['data']['state']=='outcome_unknown','restart recovers real signature with uncommitted result as unknown')
stop(process)
# Two-phase persistent management: no config edit can re-enable old principals.
process = start()
try:
    prepared = command('boundary-admin', 'admin', 'prepare-disable-principal', '--principal-id', b['principal_id'])
    assert prepared.returncode == 0, prepared.stderr
    operation = json.loads(prepared.stdout)['prepared']
    wrong = command('boundary-admin', 'admin', 'commit', '--operation-id', operation['operation_id'], '--digest', 'wrong')
    check(wrong.returncode != 0 and as_agent('boundary-agent-b')['code'] == 'OK', 'digest substitution does not disable principal')
    committed = command('boundary-admin', 'admin', 'commit', '--operation-id', operation['operation_id'], '--digest', operation['digest'])
    check(committed.returncode == 0 and as_agent('boundary-agent-b')['code'] == 'PRINCIPAL_DISABLED', 'principal disable is durable and immediate')
    check(command('boundary-admin', 'admin', 'commit', '--operation-id', operation['operation_id'], '--digest', operation['digest']).returncode != 0, 'admin commit cannot replay')
    check(as_agent('boundary-agent-a')['code'] == 'OK', 'other principal continues after disable')
finally:
    stop(process)
process = start()
try:
    check(config['principals'][1]['enabled'] and as_agent('boundary-agent-b')['code'] == 'PRINCIPAL_DISABLED', 'restart never resurrects principal from bootstrap config')
    prepared = command('boundary-admin', 'admin', 'prepare-register-principal', '--uid', str(pwd.getpwnam('boundary-agent-b').pw_uid))
    operation = json.loads(prepared.stdout)['prepared']
    committed = command('boundary-admin', 'admin', 'commit', '--operation-id', operation['operation_id'], '--digest', operation['digest'])
    check(committed.returncode == 0 and as_agent('boundary-agent-b')['principal_id'] != b['principal_id'], 'reused UID receives a new principal identity')
    listed = command('boundary-admin', 'admin', 'list-principals')
    principals = json.loads(listed.stdout)['principals']
    check(len([p for p in principals if p['uid'] == pwd.getpwnam('boundary-agent-b').pw_uid]) == 2, 'administrator sees retired and replacement principal generations')
    with sqlite3.connect(Path(config['state_dir']) / 'state.sqlite') as database:
        database.execute("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'injected failure'); END")
    check(command('boundary-admin', 'admin', 'lock-all').returncode != 0 and as_agent('boundary-agent-a')['code'] == 'AUDIT_UNAVAILABLE', 'audit persistence failure latches emergency stop')
    with sqlite3.connect(Path(config['state_dir']) / 'state.sqlite') as database:
        database.execute('DROP TRIGGER fail_audit')
    check(as_agent('boundary-agent-a')['code'] == 'AUDIT_UNAVAILABLE', 'repair alone cannot clear emergency stop without restart')
finally:
    stop(process)

# Configure finite rate/connection budgets in the root-owned schema.
resource_config=dict(config,limits={'frame_seconds':1,'response_seconds':1,'principal_connections':2,'principal_burst':2,'principal_per_second':1})
config_path.write_text(json.dumps(resource_config))
process=start()
try:
    slow_frames=r"""import socket,sys
ss=[]
for _ in range(2):
 s=socket.socket(socket.AF_UNIX);s.settimeout(3);s.connect(sys.argv[1]);s.sendall(b'\x00');ss.append(s)
print('ready',flush=True)
def closed(s):
 while True:
  try:data=s.recv(4096)
  except ConnectionResetError:return True
  if not data:return True
print(sum(closed(s) for s in ss),flush=True)
"""
    slow=subprocess.Popen([sys.executable,'-c',slow_frames,config['sign_socket']],preexec_fn=identity('boundary-agent-a'),stdout=subprocess.PIPE,text=True)
    assert slow.stdout.readline().strip()=='ready'
    time.sleep(.1)  # Allow accepted slow readers to claim their bounded slots.
    check(as_agent('boundary-agent-a')['code']=='RESOURCE_BUSY','one principal cannot exceed its active connection budget')
    check(as_agent('boundary-agent-b')['code']=='OK','other principal retains data capacity during slow frames')
    started=time.monotonic()
    check(command('boundary-admin','admin','lock-all').returncode==0 and time.monotonic()-started<1,'reserved management capacity survives principal saturation')
    check(slow.stdout.readline().strip()=='2','whole-frame deadline closes stalled authenticated connections')
    slow.wait(timeout=4)
    check(as_agent('boundary-agent-a')['code']=='OK' and as_agent('boundary-agent-a')['code']=='OK','rate budget admits configured initial burst')
    check(as_agent('boundary-agent-a')['code']=='RESOURCE_BUSY','rate excess yields bounded refusal without emergency stop')
    check(command('boundary-admin','admin','lock-all').returncode==0,'rate refusal preserves management operation')
    time.sleep(1.05)
    check(as_agent('boundary-agent-a')['code']=='OK','principal rate budget recovers monotonically')
finally:
    stop(process)
    config_path.write_text(json.dumps(config))

# Recovery and update operations are offline, preserve source history, and
# cannot make two writers active. Re-running a completed journal is idempotent.
import fcntl
with (migration_source / '.maintenance.lock').open('r+b') as maintenance:
    fcntl.flock(maintenance, fcntl.LOCK_SH | fcntl.LOCK_NB)
    conflict = subprocess.run([sys.executable, 'deploy/linux/migrate-vault.py', '--source', str(migration_source), '--apply', '--recovery-dir', str(recovery)], capture_output=True, text=True)
    check(conflict.returncode != 0, 'maintenance lease prevents concurrent legacy writer cutover')
resumed = apply_migration(migration_source, recovery)
check(resumed['vault_id'] == vault_id and json.loads(config_path.read_text())['vault_ids'] == [vault_id], 'completed migration resume is idempotent')
backup_key = next((recovery / 'vault/keys').glob('*.json'))
original_backup = backup_key.read_bytes()
backup_key.write_bytes(original_backup + b' ')
refused = subprocess.run([sys.executable, 'deploy/linux/migrate-vault.py', '--source', str(migration_source), '--apply', '--recovery-dir', str(recovery)], capture_output=True, text=True)
check(refused.returncode != 0 and ('backup changed' in refused.stderr or 'unknown bytes' in refused.stderr), 'changed recovery bytes prevent cutover before credential prompt')
backup_key.write_bytes(original_backup)
original_binary = Path(binary).read_bytes()
wrong_update = subprocess.run([sys.executable, 'deploy/linux/install.py', '--update', '--binary', args.binary, '--sha256', '0'*64, '--allow-development-build'], capture_output=True, text=True)
check(wrong_update.returncode != 0 and Path(binary).read_bytes() == original_binary, 'update rejects wrong binary digest without mutation')
updated = subprocess.run([sys.executable, 'deploy/linux/install.py', '--update', '--binary', args.binary, '--sha256', hashlib.sha256(original_binary).hexdigest(), '--allow-development-build'], capture_output=True, text=True)
check(updated.returncode == 0 and Path(binary).stat().st_mode & 0o777 == 0o755, 'offline verified update preserves executable permissions under strict umask')

if os.environ.get('ANPIO_KEY_ANP_TARGET'):
    import importlib.util
    spec = importlib.util.spec_from_file_location('keyd_real_service', Path(__file__).with_name('anp-service-acceptance.py'))
    real = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(real)
    process = start()
    try:
        print(json.dumps(real.run(globals())), flush=True)
    finally:
        stop(process)

state_path = Path(config['state_dir']) / 'state.sqlite'
# Keep an exact offline test recovery point before deliberately corrupting DB.
# This is only for the explicitly disposable systemd boot test that follows.
if args.systemd:
    systemd_backup = Path('/root/keyd-systemd-validated-state.sqlite')
    shutil.copyfile(state_path, systemd_backup)
    systemd_backup.chmod(0o600)
check(b'temporary-boundary-test-secret' not in state_path.read_bytes(), 'SQLite contains no unlock password')
check(command('anpio-key', 'init-protected-state').returncode != 0, 'explicit initialization refuses an existing database')
saved = state_path.with_suffix('.saved')
state_path.rename(saved)
try:
    result = command('anpio-key', 'serve-protected')
    check(result.returncode != 0 and not state_path.exists(), 'missing database stops startup without implicit recreation')
finally:
    saved.rename(state_path)
state_path.rename(saved)
try:
    state_path.symlink_to(saved)
    check(command('anpio-key', 'serve-protected').returncode != 0, 'symlink database rejected')
    state_path.unlink()
    os.link(saved, state_path)
    check(command('anpio-key', 'serve-protected').returncode != 0, 'multiply linked database rejected')
    state_path.unlink()
finally:
    saved.rename(state_path)
with sqlite3.connect(state_path) as database:
    schema = database.execute('PRAGMA user_version').fetchone()[0]
    database.execute(f'PRAGMA user_version={schema+1}')
check(command('anpio-key', 'serve-protected').returncode != 0, 'newer schema stops startup')
with sqlite3.connect(state_path) as database:
    database.execute(f'PRAGMA user_version={schema}')
    database.execute("UPDATE audit_events SET event_data=x'00' WHERE seq=1")
check(command('anpio-key', 'serve-protected').returncode != 0, 'corrupt audit stops startup')
if args.systemd:
    # Validate the failure through the actual unit too; do not leave restart
    # loops running while the test intentionally holds corrupt state.
    no_restart = Path('/run/systemd/system/anpio-key.service.d/fault-test.conf')
    no_restart.write_text('[Service]\nRestart=no\n')
    subprocess.run(['systemctl','daemon-reload'], check=True)
    subprocess.run(['systemctl','reset-failed','anpio-key.service'], check=True)
    subprocess.run(['systemctl','start','anpio-key.service'], capture_output=True)
    time.sleep(.5)
    check(not Path(config['admin_socket']).exists() and subprocess.check_output(['systemctl','show','anpio-key.service','-p','MainPID','--value'],text=True).strip() == '0', 'systemd unit fails closed on corrupt audit state')
    subprocess.run(['systemctl','stop','anpio-key.service'], check=True)
    shutil.copyfile(systemd_backup, state_path)
    with state_path.open('rb') as restored:
        os.fsync(restored.fileno())
    no_restart.unlink()
    Path('/run/systemd/system/anpio-key.service.d/sandbox-probe.conf').unlink()
    subprocess.run(['systemctl','daemon-reload'], check=True)
    subprocess.run(['systemctl','reset-failed','anpio-key.service'], check=True)
    check(hashlib.sha256(state_path.read_bytes()).digest() == hashlib.sha256(systemd_backup.read_bytes()).digest(), 'test restores only exact pre-fault backup before boot validation')
print(json.dumps({'passed': len(passed), 'protected_supported': expected_supported, 'systemd': args.systemd}), flush=True)
