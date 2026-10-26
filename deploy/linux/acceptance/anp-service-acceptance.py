"""Real awiki-open-server acceptance, called only by disposable test-boundary.py.

ANPIO_KEY_ANP_TARGET is a local throwaway service's physical HTTP origin. The
service must use https://example.com as public_base_url and strict signed docs.
Physical HTTP override is confined to this test; production adapter uses TLS.
"""
import json
from email.utils import parsedate_to_datetime
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid


def run(ctx):
    target = os.environ['ANPIO_KEY_ANP_TARGET'].rstrip('/')
    check, commit, prepare, data = (ctx[k] for k in ('check', 'commit_change', 'prepare_change', 'data_as'))
    command, identity = ctx['command'], ctx['identity']
    config, vault_id, fixture = ctx['config'], ctx['vault_id'], ctx['fixture']
    root, hot = ctx['root_key'], ctx['hot_key']
    path = '/user-service/v1/did-auth/rpc'
    url = 'https://example.com' + path
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def send(body, headers=None):
        request = urllib.request.Request(target + path, data=body, headers=headers or {'Content-Type': 'application/json'}, method='POST')
        try:
            with opener.open(request, timeout=10) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            return json.load(error)

    def rpc(method, params=None, headers=None):
        return send(json.dumps({'jsonrpc': '2.0', 'id': str(uuid.uuid4()), 'method': method, 'params': params or {}}, separators=(',', ':')).encode(), headers)

    def admin_secret(operation):
        result = subprocess.run([sys.executable, '-c', ctx['admin_call'], config['admin_socket'], json.dumps({'version': 2, 'request': operation})],
            preexec_fn=identity('boundary-admin'), capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    def unlock(key):
        result = admin_secret({'operation': 'UNLOCK_KEY', 'vault_id': vault_id, 'did': fixture['did'], 'kid': key['kid']})
        check(result['code'] == 'OK', 'real-service exact hot key unlock')

    def doc():
        return next(json.loads(p.read_text()) for p in (ctx['vault'] / 'dids').glob('*.json'))

    # Registration challenge is fetched by trusted code, then approved as one
    # exact operation. No Agent API can ask the root to sign challenge bytes.
    challenge = rpc('challenge')['result']['challenge']
    prepared = prepare({'kind': 'RegistrationChallenge', 'key_id': root['key_id'], 'origin': 'https://example.com', 'challenge': challenge})
    proof = admin_secret({'operation': 'COMPLETE_SECRET_OPERATION', 'operation_id': prepared['operation_id'], 'digest': prepared['digest']})
    check(proof['code'] == 'OK', 'trusted management registration proof commits before delivery')
    check(admin_secret({'operation': 'COMPLETE_SECRET_OPERATION', 'operation_id': prepared['operation_id'], 'digest': prepared['digest']})['code'] != 'OK', 'registration approval is single-use')
    registered = rpc('register', {'handle': 'keyd-m5-' + uuid.uuid4().hex[:10], 'did_document': doc(),
        'challenge': challenge, 'challenge_signature': proof['data']['challenge_signature']})
    assert 'result' in registered, registered
    token = registered['result']['token']
    check(registered['result']['did'] == fixture['did'], 'strict real ANP server accepts managed root proof and DID document')
    replay = rpc('register', {'handle': 'keyd-m5-replay', 'did_document': doc(), 'challenge': challenge,
        'challenge_signature': proof['data']['challenge_signature']})
    check('error' in replay, 'real server consumes registration challenge once')

    policy = str(uuid.uuid4())
    commit({'kind': 'Catalog', 'change': {'action': 'PublishPolicy', 'policy_id': policy, 'version': 1, 'content': {
        'schema_version': 1, 'name': 'real-anp', 'purpose': 'http-authentication', 'origin': 'https://example.com',
        'methods': ['POST'], 'paths': [path], 'query': {'mode': 'none'}, 'body': {'mode': 'bounded', 'max_bytes': 16384},
        'signature_profile': 'anp-http-v2', 'grant_limits': {'max_duration_seconds': 300, 'max_uses': 20}}}})
    principal = data('boundary-agent-a', {'operation': 'GET_CAPABILITIES'})['principal_id']

    def grant(key, seconds=240):
        return commit({'kind': 'Grant', 'change': {'action': 'Create', 'principal_id': principal, 'key_id': key['key_id'],
            'policy_id': policy, 'policy_version': 1, 'expiry': int(time.time()) + seconds, 'max_uses': 20}})['effect']['effect']['grant']['grant_id']

    def sign(g, payload=None):
        body = json.dumps(payload or {'jsonrpc': '2.0', 'id': str(uuid.uuid4()), 'method': 'get_me', 'params': {}}, separators=(',', ':')).encode()
        request = {'operation': 'SIGN_HTTP', 'grant_id': g, 'request_id': str(uuid.uuid4()), 'http': {
            'method': 'POST', 'url': url, 'headers': {'Content-Type': 'application/json'},
            'body': {'state': 'present', 'bytes': list(body)}, 'nonce': uuid.uuid4().hex}}
        result = data('boundary-agent-a', request)
        assert result['code'] == 'OK', result
        signed = result['data']['result']
        check(signed['url'] == url, 'actual send uses daemon canonical URL')
        return body, signed, request

    old_grant = grant(hot)
    unlock(hot)
    if os.environ.get('ANPIO_KEY_TEST_SDK'):
        sdk_grant = grant(hot)
        signed_sdk = subprocess.run(['node', 'adapters/test-sdk.mjs', os.environ['ANPIO_KEY_TEST_SDK'], sdk_grant, hot['key_id'], str(uuid.uuid4()), str(uuid.uuid4())],
            preexec_fn=identity('boundary-agent-a'), capture_output=True, text=True, timeout=30)
        assert signed_sdk.returncode == 0, signed_sdk.stderr
        sdk_result = json.loads(signed_sdk.stdout)
        sdk_response = send(sdk_result['body'].encode(), sdk_result['headers'])
        assert 'result' in sdk_response, sdk_response
        check(sdk_result['sdkProtocolVerified'], 'existing anp-sdk verifies v2 connector and rejects replay; Node RPC authenticates actual service')
        print(json.dumps({'external_sdk_hot_resolver_supported': sdk_result['sdkHotResolverSupported']}), flush=True)
    body, signed, _ = sign(old_grant)
    accepted = send(body, signed['headers'])
    assert 'result' in accepted, accepted
    token = accepted['result'].get('access_token', token)
    check(accepted['result']['did'] == fixture['did'], 'real ANP server authenticates v2 hot-key HTTP body and target')
    check('error' in send(body, signed['headers']), 'real ANP verifier rejects repeated nonce')
    body, signed, _ = sign(old_grant)
    check('error' in send(body + b' ', signed['headers']), 'real ANP verifier rejects substituted body')
    # Capture a still-unconsumed signature before key retirement.
    old_body, old_signed, _ = sign(old_grant)
    next_key = next(k for k in json.loads(command('boundary-admin', 'admin', 'catalog').stdout)['catalog']['keys'] if k['kid'].endswith('#http-next'))
    commit({'kind': 'Catalog', 'change': {'action': 'ConfirmRole', 'key_id': next_key['key_id'], 'role': 'hot'}})
    prepared = prepare({'kind': 'RotateHotKey', 'root_key_id': root['key_id'], 'old_key_id': hot['key_id'], 'next_key_id': next_key['key_id']})
    rotated = admin_secret({'operation': 'COMPLETE_SECRET_OPERATION', 'operation_id': prepared['operation_id'], 'digest': prepared['digest']})
    assert rotated['code'] == 'OK', rotated
    updated = rpc('update_document', {'document': rotated['data']['document']}, {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token})
    assert 'result' in updated, updated
    check('error' in send(old_body, old_signed['headers']), 'published rotation makes real server reject old hot-key signatures')
    check(data('boundary-agent-a', {'operation': 'GET_GRANT_STATUS', 'grant_id': old_grant})['data']['state'] != 'active', 'rotation revokes old local grant')
    fresh = grant(next_key)
    unlock(next_key)
    body, signed, _ = sign(fresh)
    check('result' in send(body, signed['headers']), 'new hot key authenticates after real publication')
    commit({'kind': 'Grant', 'change': {'action': 'Revoke', 'grant_id': fresh}})
    denied = data('boundary-agent-a', {'operation': 'SIGN_HTTP', 'grant_id': fresh, 'request_id': str(uuid.uuid4()), 'http': {
        'method': 'POST', 'url': url, 'headers': {}, 'body': {'state': 'present', 'bytes': []}, 'nonce': uuid.uuid4().hex}})
    check(denied['code'] != 'OK', 'revoked local grant cannot produce a real-service signature')
    short = grant(next_key, seconds=3)
    body, signed, _ = sign(short)
    # Service and signer run on different hosts. Use the verifier's HTTP Date,
    # not the Docker VM's wall clock, to cross its actual replay/time boundary.
    waited = time.monotonic()
    while True:
        with opener.open(target + '/health', timeout=10) as health:
            verifier_now = parsedate_to_datetime(health.headers['Date']).timestamp()
        remaining = signed['expires_at'] + 32 - verifier_now
        if remaining <= 0:
            break
        assert time.monotonic() - waited < 60, 'verifier clock did not advance'
        time.sleep(min(remaining, 5))
    check('error' in send(body, signed['headers']), 'real verifier rejects expiry beyond its documented 30-second tolerance')
    if 'apply_migration' in ctx:
        restart_grant = grant(next_key)
        ctx['stop'](ctx['process'])
        restored = ctx['apply_migration'](ctx['recovery'] / 'vault', Path('/root/keyd-restored-recovery'))
        vault_id = restored['vault_id']
        restored_process = ctx['start']()
        try:
            check(data('boundary-agent-a', {'operation': 'GET_GRANT_STATUS', 'grant_id': restart_grant})['data']['state'] != 'active', 'restore restart does not revive pre-restore grant')
            commit({'kind': 'Catalog', 'change': {'action': 'EnrollVault', 'vault_id': vault_id}})
            keys = json.loads(command('boundary-admin', 'admin', 'catalog').stdout)['catalog']['keys']
            restored_next = next(k for k in keys if k['vault_id'] == vault_id and k['kid'].endswith('#http-next'))
            check(restored_next['role'] == 'unclassified', 'restored recovery copy has fresh handles and unclassified roles')
            commit({'kind': 'Catalog', 'change': {'action': 'ConfirmRole', 'key_id': restored_next['key_id'], 'role': 'hot'}})
            restored_grant = grant(restored_next)
            unlock(restored_next)
            body, signed, _ = sign(restored_grant)
            check('result' in send(body, signed['headers']), 'verified encrypted backup restores real hot authentication with a fresh grant')
        finally:
            ctx['stop'](restored_process)
    return {'target': target, 'service': 'awiki-open-server', 'public_origin': 'https://example.com', 'strict_documents': True}
