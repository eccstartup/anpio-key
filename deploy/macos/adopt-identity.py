#!/usr/bin/env python3
"""Adopt an existing named-key identity into the installed protected service.

Run as root through `./install.sh --adopt ...` from the human terminal on a
macOS local-preview installation that has no vault yet.

The identity's DID and published document are never changed: `key bind-did`
reseals the same seeds under the DID-bound key ids the document already names.
Passphrases are read only by the anpio-key binary from the human's tty; this
script never receives, stores or passes them on the command line.

The source store and the identity file are preserved. This script freezes
copies under /private/var/root and never deletes the originals.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone

CONFIG = Path('/Library/ANPIOKey/service.json')
BINARY = Path('/Library/ANPIOKey/bin/anpio-key')
PLIST = Path('/Library/LaunchDaemons/org.anpio-key.local.plist')
JOB = 'system/org.anpio-key.local'
AGENT_ROOT = Path('/Library/ANPIOKey/agent')
CLI_INSTALL = Path('/Library/ANPIOKey/bin/anpio-cli')
ROOT_HOME = Path('/private/var/root')
ENV = {'PATH': '/Library/ANPIOKey/bin:/usr/bin:/bin:/usr/sbin:/sbin'}
EMPTY_BODY_METHODS = {'GET', 'HEAD', 'OPTIONS', 'DELETE'}
BODY_METHODS = {'POST', 'PUT', 'PATCH'}
ACCEPTED_METHODS = EMPTY_BODY_METHODS | BODY_METHODS
MAX_SOURCE_FILE = 1_048_576
MAX_CLI_BYTES = 256 * 1024 * 1024


class AdoptError(Exception):
    pass


def fail(message):
    raise AdoptError(message)


def step(message):
    print('==> ' + message, flush=True)


def load_bootstrap():
    spec = importlib.util.spec_from_file_location(
        'adopt_bootstrap', Path(__file__).with_name('bootstrap.py')
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def reject_acl(path):
    # A 0700 directory with an ACL can still grant access; macOS `ls` marks that
    # with a trailing `+` in the mode column.
    result = subprocess.run(
        ['/bin/ls', '-ld', str(path)], capture_output=True, text=True,
        timeout=10, env={'PATH': '/bin:/usr/bin'},
    )
    if result.returncode != 0:
        fail(f'无法检查 ACL: {path}')
    if result.stdout.split(None, 1)[0].endswith('+'):
        fail(f'路径带 ACL，拒绝接管: {path}')


def lstat_regular(path, description):
    meta = os.lstat(path)
    if not stat.S_ISREG(meta.st_mode) or stat.S_ISLNK(meta.st_mode):
        fail(f'{description} 不是常规文件: {path}')
    if meta.st_nlink != 1:
        fail(f'{description} 有额外硬链接: {path}')
    return meta


def write_atomic(path, data, mode, uid=0, gid=0):
    path = Path(path)
    temporary = path.with_name('.' + path.name + '.adopt')
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
        handle.flush()
        os.fchmod(handle.fileno(), mode)
        os.fchown(handle.fileno(), uid, gid)
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def ensure_dir(path, mode=0o700, uid=0, gid=0, strict_uid=True):
    path = Path(path)
    try:
        meta = os.lstat(path)
    except FileNotFoundError:
        os.mkdir(path, mode)
        os.chmod(path, mode)
        os.chown(path, uid, gid)
        return
    if not stat.S_ISDIR(meta.st_mode) or stat.S_ISLNK(meta.st_mode):
        fail(f'不是目录: {path}')
    if strict_uid and meta.st_uid not in (0, uid):
        fail(f'目录属于其他用户，拒绝改动: {path}')
    if meta.st_mode & 0o022:
        fail(f'目录可被组或其他人改写: {path}')
    reject_acl(path)
    os.chmod(path, mode)
    if meta.st_uid != uid:
        os.chown(path, uid, gid)


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path, description):
    meta = lstat_regular(path, description)
    if meta.st_size > MAX_SOURCE_FILE:
        fail(f'{description} 超过 1 MiB: {path}')
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as error:
        fail(f'{description} 不是 JSON: {path}: {error}')


def load_config():
    config = read_json(CONFIG, '服务配置')
    if config.get('mode') != 'macos-boundary-preview':
        fail('需要显式的 macOS 本机预览配置')
    return config


def state_path(work):
    return work / 'state.json'


def load_state(work):
    path = state_path(work)
    if not path.exists():
        return None
    return read_json(path, '接管记录')


def save_state(work, state):
    record = dict(state)
    record['updated_at'] = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    write_atomic(state_path(work), (json.dumps(record, indent=1, ensure_ascii=False) + '\n').encode(), 0o600)


def validate_identity(path, admin_uid):
    meta = lstat_regular(path, '身份文件')
    if meta.st_uid not in (0, admin_uid):
        fail(f'身份文件属于其他用户: {path}')
    if meta.st_mode & 0o022:
        fail(f'身份文件可被组或其他人改写: {path}')
    reject_acl(path)
    identity = read_json(path, '身份文件')
    did = identity.get('did')
    if not isinstance(did, str) or not did.startswith('did:wba:'):
        fail('身份文件没有 did:wba DID')
    custody = identity.get('custody')
    if not isinstance(custody, dict) or custody.get('kind') != 'anpio-key':
        fail('身份文件的 custody 不是 anpio-key，无法换绑')
    name = custody.get('name')
    device_keys = custody.get('device_keys')
    if not isinstance(name, str) or not name:
        fail('身份文件的 custody.name 缺失')
    if not isinstance(device_keys, dict):
        fail('身份文件的 custody.device_keys 缺失')
    sign_name = device_keys.get('sign')
    agreement_name = device_keys.get('agreement')
    if not isinstance(sign_name, str) or not isinstance(agreement_name, str):
        fail('身份文件的 device_keys 缺少 sign / agreement')
    if len({name, sign_name, agreement_name}) != 3:
        fail('身份文件把同一把钥匙用于了两个角色')
    document = identity.get('did_document')
    if not isinstance(document, dict) or document.get('id') != did:
        fail('身份文件里的 DID 文档与 did 不一致')
    return identity, did


def validate_source(root, admin_uid):
    meta = os.lstat(root)
    if not stat.S_ISDIR(meta.st_mode) or stat.S_ISLNK(meta.st_mode):
        fail(f'源钥匙库不是目录: {root}')
    if meta.st_uid not in (0, admin_uid):
        fail(f'源钥匙库属于其他用户: {root}')
    if meta.st_mode & 0o022:
        fail(f'源钥匙库可被组或其他人改写: {root}')
    reject_acl(root)
    for name, optional in (('keys', False), ('dids', False), ('audit', True)):
        directory = root / name
        if not os.path.lexists(directory):
            if optional:
                continue
            fail(f'源钥匙库缺少 {name}/: {root}')
        entry = os.lstat(directory)
        if not stat.S_ISDIR(entry.st_mode) or stat.S_ISLNK(entry.st_mode):
            fail(f'源钥匙库里的 {name} 不是目录: {directory}')
        if entry.st_uid not in (0, admin_uid) or entry.st_mode & 0o022:
            fail(f'源钥匙库里的 {name} 权限不安全: {directory}')
        reject_acl(directory)
        for child in directory.iterdir():
            child_meta = lstat_regular(child, '源钥匙库文件')
            if child_meta.st_uid not in (0, admin_uid) or child_meta.st_mode & 0o022:
                fail(f'源钥匙库文件权限不安全: {child}')
            reject_acl(child)
    secret = root / 'device.secret'
    if not os.path.lexists(secret):
        fail(f'源钥匙库缺少 device.secret: {root}')
    secret_meta = lstat_regular(secret, 'device.secret')
    if secret_meta.st_uid not in (0, admin_uid) or secret_meta.st_mode & 0o077:
        fail(f'device.secret 不是仅属主可读: {secret}')
    reject_acl(secret)
    names = [entry.name for entry in (root / 'keys').iterdir()]
    if len(names) < 3:
        fail(f'源钥匙库只有 {len(names)} 把钥匙，接管需要根、设备签名和设备协商三把')


def freeze_file(source, target):
    meta = lstat_regular(source, '源文件')
    with source.open('rb') as handle:
        data = handle.read(MAX_SOURCE_FILE + 1)
    if len(data) != meta.st_size:
        fail(f'读取时文件大小发生变化: {source}')
    if os.path.lexists(target):
        if lstat_regular(target, '冻结副本').st_uid != 0:
            fail(f'冻结副本不属于 root: {target}')
        if target.read_bytes() != data:
            fail(f'冻结副本与源不一致，请人工核对: {target}')
        return
    write_atomic(target, data, 0o600)


def freeze(identity_path, source_root, work):
    ensure_dir(work, 0o700)
    frozen_identity = work / 'identity.json'
    freeze_file(identity_path, frozen_identity)
    frozen_source = work / 'source'
    ensure_dir(frozen_source, 0o700)
    for name in ('keys', 'dids', 'audit'):
        source_dir = source_root / name
        if not source_dir.exists():
            if name == 'audit':
                continue
            fail(f'源钥匙库缺少 {name}/')
        target_dir = frozen_source / name
        ensure_dir(target_dir, 0o700)
        for entry in sorted(source_dir.iterdir()):
            freeze_file(entry, target_dir / entry.name)
    freeze_file(source_root / 'device.secret', frozen_source / 'device.secret')
    return frozen_identity, frozen_source


def ensure_service_stopped(boot, config):
    live = any(os.path.lexists(config[key]) for key in ('sign_socket', 'admin_socket'))
    if not live:
        return False
    result = subprocess.run(
        ['/bin/launchctl', 'bootout', JOB], capture_output=True, text=True, env=ENV, timeout=30
    )
    deadline = time.monotonic() + 15
    while any(os.path.lexists(config[key]) for key in ('sign_socket', 'admin_socket')):
        if time.monotonic() >= deadline:
            detail = (result.stderr or result.stdout).strip()
            fail(f'服务停止后 socket 仍然存在{("：" + detail) if detail else ""}')
        time.sleep(0.1)
    return True


def ensure_service_started(boot, config, plist):
    if os.path.lexists(config['admin_socket']) and boot.admin_raw('status').returncode == 0:
        return
    result = subprocess.run(
        ['/bin/launchctl', 'bootstrap', 'system', str(plist)],
        capture_output=True, text=True, env=ENV, timeout=30,
    )
    if result.returncode != 0:
        # A loaded-but-stopped job rejects bootstrap; kickstart starts it.
        subprocess.run(
            ['/bin/launchctl', 'kickstart', JOB], capture_output=True, text=True,
            env=ENV, timeout=30,
        )
    deadline = time.monotonic() + 20
    while not os.path.lexists(config['admin_socket']):
        if time.monotonic() >= deadline:
            fail('服务重启后没有开放管理 socket；请检查 launchctl 与日志')
        time.sleep(0.1)
    for _ in range(30):
        if boot.admin_raw('status').returncode == 0:
            return
        time.sleep(1)
    fail('服务重启后管理通道仍不可用')


def bind_staging(boot, binary, identity, source_root, staging):
    if not os.path.lexists(staging):
        os.mkdir(staging, 0o700)
        os.chmod(staging, 0o700)
    result = subprocess.run(
        [str(binary), 'key', 'bind-did', '--identity', str(identity),
         '--out', str(staging), '--source-root', str(source_root), '--json'],
        capture_output=True, text=True, env=ENV,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        fail('key bind-did 失败：\n' + detail)
    try:
        reply = json.loads(result.stdout)
    except json.JSONDecodeError:
        fail('key bind-did 没有返回可读的 JSON：\n' + result.stdout.strip())
    if reply.get('format') != 'anpio-key-bind-did-v1':
        fail('key bind-did 返回了未知格式')
    return reply


def call_apply(boot, change, description):
    try:
        return boot.apply_change(change, description)
    except AdoptError:
        raise
    except subprocess.CalledProcessError as error:
        fail(f'{description} 失败：{error}')


def catalog_keys(catalog, vault_id, did):
    return [
        key for key in catalog.get('keys', [])
        if key.get('vault_id') == vault_id and key.get('did') == did
    ]


def pick_key(keys, kid, role):
    matches = [key for key in keys if key.get('kid') == kid and key.get('state') == 'active']
    if len(matches) != 1:
        fail(f'登记后找不到唯一的 {role} 钥匙 ({kid})；catalog 里有 {len(matches)} 把')
    return matches[0]


def confirm_role(boot, key, role):
    detail = call_apply(
        boot,
        {'kind': 'Catalog', 'change': {
            'action': 'ConfirmRole', 'key_id': key['key_id'], 'role': role,
        }},
        f'ConfirmRole({role})',
    )
    step(f'确认角色 {role}: {key["kid"]}')
    return detail


def find_policy(rows, desired):
    best = None
    for row in rows:
        try:
            content = json.loads(row['content'])
        except (KeyError, TypeError, json.JSONDecodeError):
            continue
        if content == desired:
            if best is None or row['version'] > best['version']:
                best = row
    return best


def publish_or_reuse(boot, catalog, desired, label):
    row = find_policy(catalog.get('policies', []), desired)
    if row is not None:
        step(f'{label}: 复用已有策略 {row["policy_id"]} v{row["version"]}')
        return row['policy_id'], row['version']
    policy_id = str(uuid.uuid4())
    call_apply(
        boot,
        {'kind': 'Catalog', 'change': {
            'action': 'PublishPolicy', 'policy_id': policy_id, 'version': 1,
            'content': desired,
        }},
        label,
    )
    step(f'{label}: 发布策略 {policy_id} v1')
    return policy_id, 1


def http_policies(boot, targets, methods, body_bytes, days, uses):
    if set(methods) & EMPTY_BODY_METHODS and set(methods) & BODY_METHODS:
        fail('不能把无请求体的方法和有请求体的方法放进同一条策略；请分两次接管')
    origins = {}
    for target in targets:
        origin, path, query = boot.parse_target(target)
        if query:
            fail(f'暂不支持带查询串的目标（{target}）；请只用 scheme://host/path 形式')
        origins.setdefault(origin, set()).add(path)
    if len(origins) != 1:
        fail('所有 --target 必须属于同一个 origin；不同站点的授权需要分别接管')
    body = (
        {'mode': 'empty', 'max_bytes': 0}
        if set(methods) <= EMPTY_BODY_METHODS
        else {'mode': 'bounded', 'max_bytes': body_bytes}
    )
    limits = {
        'max_duration_seconds': days * 86400,
        'max_uses': uses,
        'max_lifetime_seconds': days * 86400,
        'max_renewals': 0,
    }
    policies = []
    for origin, paths in sorted(origins.items()):
        policies.append({
            'schema_version': 2,
            'name': ('adopt-http-' + origin.removeprefix('https://'))[:128],
            'purpose': 'http-authentication',
            'limits': dict(limits),
            'content': {
                'origin': origin,
                'methods': sorted(set(methods)),
                'paths': sorted(paths),
                'query': {'mode': 'none'},
                'body': body,
                'signature_profile': 'anp-http-v2',
            },
        })
    return policies


def document_proof_policy(did, days, uses):
    return {
        'schema_version': 2,
        'name': ('adopt-document-proof-' + did.rsplit(':', 1)[-1][-24:])[:128],
        'purpose': 'document-proof',
        'limits': {
            'max_duration_seconds': days * 86400,
            'max_uses': uses,
            'max_lifetime_seconds': days * 86400,
            'max_renewals': 0,
        },
        'content': {'proof_purposes': ['assertionMethod']},
    }


def create_grant(boot, principal_id, key, policy_id, policy_version, days, uses):
    effect = call_apply(
        boot,
        {'kind': 'Grant', 'change': {
            'action': 'Create',
            'principal_id': principal_id,
            'key_id': key['key_id'],
            'policy_id': policy_id,
            'policy_version': policy_version,
            'expiry': int(time.time()) + days * 86400,
            'max_uses': uses,
        }},
        f'Grant({key["kid"]})',
    )
    try:
        return effect['effect']['grant']['grant_id']
    except (KeyError, TypeError):
        fail('创建 grant 后没有拿到 grant_id')


def unlock(boot, vault_id, did, kid, label):
    step(f'解锁 {label} 钥匙（请在终端输入口令）')
    try:
        boot.admin('unlock', '--vault-id', vault_id, '--did', did, '--kid', kid)
    except AdoptError as error:
        fail(f'解锁 {label} 钥匙失败：{error}')


def ensure_agent_tree(agent_uid, agent_gid):
    ensure_dir(AGENT_ROOT, 0o755)
    for name in ('home', 'workspace', 'home/tmp'):
        ensure_dir(AGENT_ROOT / name, 0o700, agent_uid, agent_gid)


def install_cli(source, digest):
    meta = lstat_regular(source, 'anpio-cli')
    if meta.st_size > MAX_CLI_BYTES:
        fail('anpio-cli 超过 256 MiB')
    if sha256_file(source) != digest:
        fail('--cli-sha256 与 anpio-cli 的摘要不一致')
    if CLI_INSTALL.exists():
        target_meta = lstat_regular(CLI_INSTALL, '已安装 anpio-cli')
        if target_meta.st_uid == 0 and sha256_file(CLI_INSTALL) == digest:
            step('anpio-cli 已是该构建，跳过安装')
            return
    with source.open('rb') as handle:
        data = handle.read(MAX_CLI_BYTES + 1)
    if len(data) != meta.st_size:
        fail('anpio-cli 在读取时发生变化')
    write_atomic(CLI_INSTALL, data, 0o755)
    step(f'安装 anpio-cli: {CLI_INSTALL}')


def write_agent_identity(identity, sign_kid, http_grant, document_grant, agent_uid, agent_gid):
    home = AGENT_ROOT / 'home'
    agent = identity.get('agent')
    profile = identity.get('profile')
    if not isinstance(agent, str) or not isinstance(profile, str):
        device_id = identity.get('device_id')
        if not isinstance(device_id, str) or '/' not in device_id:
            fail('身份文件缺少 agent/profile')
        agent, profile = device_id.split('/', 1)
    directory = home / '.anpio-cli' / agent / profile
    ensure_dir(home / '.anpio-cli', 0o700, agent_uid, agent_gid)
    ensure_dir(home / '.anpio-cli' / agent, 0o700, agent_uid, agent_gid)
    ensure_dir(directory, 0o700, agent_uid, agent_gid)
    record = json.loads(json.dumps(identity))
    custody = record['custody']
    custody['config'] = str(CONFIG)
    custody['kid'] = sign_kid.split('#', 1)[1]
    custody['grant'] = http_grant
    custody['grants'] = {'http': http_grant, 'document_proof': document_grant}
    write_atomic(
        directory / 'identity.json',
        (json.dumps(record, indent=2, ensure_ascii=False) + '\n').encode(),
        0o600, agent_uid, agent_gid,
    )
    step(f'写入 Agent 身份: {directory / "identity.json"}')
    return agent


def main():
    global CONFIG, BINARY, PLIST
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=CONFIG)
    parser.add_argument('--binary', type=Path, default=BINARY)
    parser.add_argument('--plist', type=Path, default=PLIST)
    parser.add_argument('--admin-user', required=True)
    parser.add_argument('--agent-user', default='_anpagent')
    parser.add_argument('--identity', type=Path, required=True)
    parser.add_argument('--source-root', type=Path)
    parser.add_argument('--cli-binary', type=Path, required=True)
    parser.add_argument('--cli-sha256', required=True)
    parser.add_argument('--target', action='append', default=[])
    parser.add_argument('--method', action='append', default=[])
    parser.add_argument('--body-bytes', type=int, default=1024 * 1024)
    parser.add_argument('--grant-days', type=int, default=30)
    parser.add_argument('--max-uses', type=int, default=100)
    parser.add_argument('--enable-ecdh', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()

    CONFIG, BINARY, PLIST = args.config, args.binary, args.plist

    if sys.platform != 'darwin':
        fail('只支持 macOS')
    if not args.apply and not args.dry_run:
        fail('必须显式传 --apply（由 ./install.sh --adopt 调用）')
    if args.apply and os.geteuid() != 0:
        fail('必须以 root 运行（由 ./install.sh --adopt 调用）')
    if not CONFIG.is_file():
        fail(f'找不到服务配置: {CONFIG}')
    if not BINARY.is_file():
        fail(f'找不到服务程序: {BINARY}')
    if not PLIST.is_file():
        fail(f'找不到 launchd 任务: {PLIST}')

    boot = load_bootstrap()
    boot.fail = fail
    boot.step = step
    boot.ADMIN, boot.BINARY, boot.CONFIG, boot.PLIST = (
        args.admin_user, BINARY, CONFIG, PLIST
    )

    admin_record = pwd.getpwnam(args.admin_user)
    agent_record = pwd.getpwnam(args.agent_user)
    config = load_config()
    if admin_record.pw_uid not in config.get('admin_uids', []):
        fail(f'{args.admin_user} 不在服务配置的管理员 UID 中')
    principals = [
        item for item in config.get('principals', [])
        if item.get('uid') == agent_record.pw_uid and item.get('enabled')
    ]
    if len(principals) != 1:
        fail(f'服务配置里找不到唯一的 Agent principal: {args.agent_user}')

    identity, did = validate_identity(args.identity, admin_record.pw_uid)
    source_root = args.source_root or Path(admin_record.pw_dir) / '.anpio-key'
    if not source_root.is_absolute():
        fail('--source-root 必须是绝对路径')
    state_dir = Path(config.get('state_dir', '/Library/ANPIOKey/state'))
    if source_root == state_dir or state_dir in source_root.parents:
        fail('源钥匙库不能位于受保护状态目录内')
    if not source_root.is_dir():
        fail(f'找不到源命名钥匙库: {source_root}')
    validate_source(source_root, admin_record.pw_uid)

    digest = args.cli_sha256.lower()
    if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
        fail('--cli-sha256 必须是 64 位十六进制')
    cli_meta = lstat_regular(args.cli_binary, 'anpio-cli')
    if not cli_meta.st_mode & stat.S_IXUSR:
        fail(f'anpio-cli 不可执行: {args.cli_binary}')
    if sha256_file(args.cli_binary) != digest:
        fail('--cli-sha256 与 anpio-cli 的摘要不一致')
    if os.geteuid() != 0 and cli_meta.st_uid not in (0, admin_record.pw_uid):
        fail('anpio-cli 属于其他用户')

    probe = subprocess.run(
        [str(BINARY), 'key', 'bind-did', '--help'], capture_output=True, text=True,
        env=ENV, timeout=30,
    )
    if probe.returncode != 0:
        fail('已安装的 anpio-key 不支持 key bind-did；先运行 ./install.sh --upgrade')

    methods = [method.upper() for method in args.method] or ['POST']
    unknown = set(methods) - ACCEPTED_METHODS
    if unknown:
        fail('不支持的方法: ' + ', '.join(sorted(unknown)))
    if not args.target:
        fail('至少需要一个 --target')
    if not 1 <= args.grant_days <= 365:
        fail('--grant-days 必须在 1 到 365 之间')
    if not 1 <= args.max_uses <= 1_000_000:
        fail('--max-uses 必须在 1 到 1000000 之间')
    if not 1 <= args.body_bytes <= 16 * 1024 * 1024:
        fail('--body-bytes 必须在 1 到 16777216 之间')

    tail = ''.join(c for c in did.rsplit(':', 1)[-1] if c.isalnum())[-10:]
    work = ROOT_HOME / f'anpio-key-adopt-{tail}'
    state = None
    if work.exists():
        work_meta = os.lstat(work)
        if not stat.S_ISDIR(work_meta.st_mode) or work_meta.st_uid != 0:
            fail(f'接管目录不安全: {work}')
        state = load_state(work)
        if state is not None and state.get('did') != did:
            fail(f'{work} 里记录的是另一个 DID；换一个身份请先人工核对这个目录')
    journal = work / 'recovery' / 'migration.json'
    if (
        state is not None
        and state.get('phase') not in ('migrated', 'enrolled', 'ready')
        and not args.dry_run
        and journal.exists()
    ):
        # The run stopped between migration and recording its vault id.
        recorded = read_json(journal, '迁移记录').get('vault_id')
        if recorded and recorded in (config.get('vault_ids') or []):
            state['vault_id'] = str(uuid.UUID(recorded))
            state['phase'] = 'migrated'
            save_state(work, state)
            step('迁移已经完成，从记录继续')
    existing_vaults = config.get('vault_ids') or []
    if existing_vaults:
        if state is None or state.get('vault_id') not in existing_vaults:
            fail('这台机器已经有 vault；--adopt 只用于空的受保护安装')
    if state is None and not args.dry_run:
        try:
            boot.admin('status')
            catalog = boot.admin('catalog').get('catalog') or {}
        except AdoptError as error:
            fail(f'管理通道不可用（服务可能未启动）：{error}')
        if catalog.get('keys') or catalog.get('policies'):
            fail('受保护服务的目录里已经有钥匙或策略；--adopt 只用于空的安装')

    plan = {
        'did': did,
        'source_root': str(source_root),
        'identity': str(args.identity),
        'work': str(work),
        'vaults': existing_vaults,
        'targets': args.target,
        'methods': sorted(set(methods)),
        'grant_days': args.grant_days,
        'max_uses': args.max_uses,
        'enable_ecdh': args.enable_ecdh,
        'cli': str(CLI_INSTALL),
        'agent': args.agent_user,
    }
    if args.dry_run:
        print(json.dumps({'dry_run': True, 'plan': plan}, ensure_ascii=False, indent=2))
        return

    if not ROOT_HOME.is_dir():
        fail(f'找不到 root 主目录: {ROOT_HOME}')
    ensure_dir(work, 0o700)
    state = state or {
        'format': 'anpio-key-adopt-v1',
        'did': did,
        'source_root': str(source_root),
        'identity': str(args.identity),
        'work': str(work),
        'phase': 'started',
    }
    state['format'] = 'anpio-key-adopt-v1'
    save_state(work, state)

    frozen_identity, frozen_source = freeze(args.identity, source_root, work)
    staging = work / 'staging'
    recovery = work / 'recovery'
    service_stopped = False

    def staging_is_valid():
        if not state.get('kids') or not (staging / 'keys').is_dir():
            return False
        result = subprocess.run(
            [str(BINARY), 'inspect-vault', '--path', str(staging)],
            capture_output=True, text=True, env=ENV,
        )
        return result.returncode == 0

    try:
        if not staging_is_valid():
            if os.path.lexists(staging):
                # Nothing in an incomplete staging is unique: the frozen envelopes
                # and identity still exist, so a partial bind is rebuilt.
                shutil.rmtree(staging)
            step('把命名钥匙换绑成 DID 绑定信封（每把钥匙输入一次口令）')
            reply = bind_staging(boot, BINARY, frozen_identity, frozen_source, staging)
            if reply.get('did') != did:
                fail('key bind-did 返回了另一个 DID')
            roles = {}
            for key in reply.get('keys', []):
                roles.setdefault(key.get('role'), []).append(key)
            for required in ('root', 'device_signing', 'device_agreement'):
                if len(roles.get(required, [])) != 1:
                    fail(f'换绑结果缺少唯一的 {required} 钥匙')
            kids = {
                'root': roles['root'][0]['kid'],
                'sign': roles['device_signing'][0]['kid'],
                'agreement': roles['device_agreement'][0]['kid'],
            }
            for role, kid in kids.items():
                if not kid.startswith(did + '#') or kid == did + '#':
                    fail(f'换绑结果的 {role} kid 不完整: {kid}')
            step('离线检查换绑后的钥匙库')
            result = subprocess.run(
                [str(BINARY), 'inspect-vault', '--path', str(staging)],
                capture_output=True, text=True, env=ENV,
            )
            if result.returncode != 0:
                fail('inspect-vault 拒绝了换绑后的钥匙库：\n' + (result.stderr or result.stdout).strip())
            state['phase'] = 'bound'
            state['kids'] = kids
            save_state(work, state)

        kids = state.get('kids')
        if not isinstance(kids, dict) or set(kids) != {'root', 'sign', 'agreement'}:
            fail('接管记录里没有完整的 kid 列表；请人工核对接管目录')

        if state.get('phase') not in ('migrated', 'enrolled', 'ready'):
            step('停止 launchd 服务，准备离线迁移')
            service_stopped = ensure_service_stopped(boot, config) or service_stopped
            migrate = Path(__file__).with_name('migrate-vault.py')
            result = subprocess.run(
                ['/usr/bin/python3', str(migrate),
                 '--config', str(CONFIG), '--binary', str(BINARY),
                 '--source', str(staging), '--apply', '--recovery-dir', str(recovery)],
                env=ENV,
            )
            if result.returncode != 0:
                fail('离线迁移失败；修复后重跑同一条命令可以继续（recovery 会保留）')
            journal = read_json(recovery / 'migration.json', '迁移记录')
            vault_id = str(uuid.UUID(journal['vault_id']))
            config = load_config()
            if vault_id not in (config.get('vault_ids') or []):
                fail('迁移完成后服务配置里没有这个 vault_id')
            state['vault_id'] = vault_id
            state['phase'] = 'migrated'
            save_state(work, state)
        vault_id = state.get('vault_id')
        if not vault_id:
            fail('接管记录里没有 vault_id')

        # Every grant and unlock below happens after this last restart.
        step('停止服务以应用功能开关')
        service_stopped = ensure_service_stopped(boot, config) or service_stopped
        config = load_config()
        features = dict(config.get('features') or {})
        wanted = dict(features)
        wanted['sign_document_proof'] = True
        if args.enable_ecdh:
            wanted['ecdh'] = True
        if wanted != features:
            config['features'] = wanted
            write_atomic(CONFIG, (json.dumps(config, indent=2, ensure_ascii=False) + '\n').encode(), 0o644)
            step('已启用 sign_document_proof' + (' 与 ecdh' if args.enable_ecdh else ''))
        else:
            step('功能开关已经是需要的状态')
        ensure_service_started(boot, config, PLIST)
        service_stopped = False
        config = load_config()

        step('登记 vault 并确认角色')
        call_apply(
            boot,
            {'kind': 'Catalog', 'change': {'action': 'EnrollVault', 'vault_id': vault_id}},
            'EnrollVault',
        )
        catalog = boot.admin('catalog').get('catalog') or {}
        keys = catalog_keys(catalog, vault_id, did)
        enrollment = {
            'root': pick_key(keys, kids['root'], 'root'),
            'hot': pick_key(keys, kids['sign'], 'hot'),
            'key_agreement': pick_key(keys, kids['agreement'], 'key_agreement'),
        }
        for role in ('root', 'hot', 'key_agreement'):
            if enrollment[role].get('role') != role:
                confirm_role(boot, enrollment[role], role)
        catalog = boot.admin('catalog').get('catalog') or {}
        keys = catalog_keys(catalog, vault_id, did)
        enrollment = {
            'root': pick_key(keys, kids['root'], 'root'),
            'hot': pick_key(keys, kids['sign'], 'hot'),
            'key_agreement': pick_key(keys, kids['agreement'], 'key_agreement'),
        }

        step('发布或复用授权策略')
        policies = http_policies(
            boot, args.target, methods, args.body_bytes, args.grant_days, args.max_uses
        )
        http_policy_id, http_version = publish_or_reuse(
            boot, catalog, policies[0], 'PublishPolicy(HTTP)'
        )
        document_policy_id, document_version = publish_or_reuse(
            boot, catalog,
            document_proof_policy(did, args.grant_days, args.max_uses),
            'PublishPolicy(document-proof)',
        )

        step('为 Agent principal 创建两张 grant（HTTP / document-proof）')
        principal_id = principals[0]['principal_id']
        http_grant = create_grant(
            boot, principal_id, enrollment['hot'], http_policy_id, http_version,
            args.grant_days, args.max_uses,
        )
        document_grant = create_grant(
            boot, principal_id, enrollment['root'], document_policy_id, document_version,
            args.grant_days, args.max_uses,
        )
        step(f'HTTP grant:          {http_grant}')
        step(f'document-proof grant: {document_grant}')

        unlock(boot, vault_id, did, kids['sign'], 'Hot')
        unlock(boot, vault_id, did, kids['root'], 'Root')
        status = boot.admin('status')
        if not status.get('signing_available'):
            fail('解锁后服务仍报告 signing_available=false')

        install_cli(args.cli_binary, digest)
        ensure_agent_tree(agent_record.pw_uid, agent_record.pw_gid)
        agent = write_agent_identity(
            identity, kids['sign'], http_grant, document_grant,
            agent_record.pw_uid, agent_record.pw_gid,
        )

        state['phase'] = 'ready'
        state['grants'] = {'http': http_grant, 'document_proof': document_grant}
        save_state(work, state)

        print()
        print('接管完成。DID 与已发布文档没有改动。')
        print(f'DID:            {did}')
        print(f'vault:          {vault_id}')
        print(f'root kid:       {kids["root"]}')
        print(f'hot kid:        {kids["sign"]}')
        print(f'agreement kid:  {kids["agreement"]}')
        print(f'HTTP grant:     {http_grant}（{args.grant_days} 天，最多 {args.max_uses} 次）')
        print(f'proof grant:    {document_grant}')
        print(f'冻结副本:       {frozen_identity.parent}（root 持有，未删除原始数据）')
        if args.enable_ecdh:
            print('已启用 ECDH 功能开关，但没有创建 ECDH 策略或 grant；需要管理员另行授权。')
        print()
        print('以 Agent 身份验证:')
        print('  sudo -u ' + args.agent_user + ' /usr/bin/env \\')
        print(f'    HOME={AGENT_ROOT}/home TMPDIR={AGENT_ROOT}/home/tmp \\')
        print(f'    PATH=/Library/ANPIOKey/bin:/usr/bin:/bin:/usr/sbin:/sbin \\')
        print(f'    {CLI_INSTALL} did show --agent {agent}')
        print()
        print('管理员复核:')
        print(f'  {BINARY} admin --config {CONFIG} catalog')
        print()
        print('源钥匙库没有被删除。确认签名与文档都正常后，再由管理员决定是否隔离原始副本。')
    except BaseException:
        if service_stopped and not boot.restore_service():
            print('服务没有恢复；请检查 launchd 后再继续。', file=sys.stderr)
        print()
        print(f'接管没有完成。现场保留在 {work}（含冻结副本和迁移记录）。', file=sys.stderr)
        print('检查上面的错误后可以重跑同一条命令；不要手工改动受保护状态。', file=sys.stderr)
        raise


if __name__ == '__main__':
    try:
        main()
    except AdoptError as error:
        sys.exit('adopt: ' + str(error))
    except KeyboardInterrupt:
        sys.exit(130)
    except subprocess.CalledProcessError as error:
        sys.exit('adopt: 命令失败: ' + str(error))
