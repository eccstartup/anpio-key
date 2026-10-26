#!/usr/bin/env python3
"""Create a fresh identity, migrate it into protected state, and issue one grant.

Run as root through install.sh --bootstrap. Passphrases are read only by the
anpio-key binary from the human's terminal; this script never receives, stores or
passes them on the command line.
"""
import argparse
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

CONFIG = Path("/etc/anpio-key/service.json")
BINARY = Path("/usr/local/libexec/anpio-key")
ACCEPTED_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
EMPTY_BODY_METHODS = {"GET", "HEAD", "OPTIONS", "DELETE"}
BODY_METHODS = {"POST", "PUT", "PATCH"}


def fail(message):
    sys.exit("bootstrap: " + message)


def step(message):
    print("==> " + message, flush=True)


def run(command, **kwargs):
    subprocess.run(command, check=True, **kwargs)


def admin(*arguments):
    command = [
        "runuser", "-u", ADMIN, "--", str(BINARY), "admin", "--config", str(CONFIG),
        *arguments,
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        fail(f"管理命令失败: {' '.join(arguments)}\n{detail}")
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        fail(f"管理命令没有返回结果: {' '.join(arguments)}")
    try:
        reply = json.loads(lines[-1])
    except json.JSONDecodeError:
        fail(f"管理命令返回了非 JSON 输出: {lines[-1]}")
    if reply.get("code") != "OK":
        fail(f"管理命令被拒绝: {' '.join(arguments)}: {reply.get('code')}")
    return reply


def apply_change(change, description):
    # The change contains only public identifiers; it is readable by the admin
    # account because the management command runs under that UID.
    handle = tempfile.NamedTemporaryFile(
        prefix="anpio-key-admin-", suffix=".json", dir="/tmp", mode="w", delete=False
    )
    try:
        json.dump(change, handle)
        handle.close()
        os.chmod(handle.name, 0o644)
        prepared = admin("prepare", "--file", handle.name)
        detail = prepared.get("prepared")
        if not detail:
            fail(f"{description}: 没有拿到 prepared 操作")
        admin(
            "commit",
            "--operation-id", detail["operation_id"],
            "--digest", detail["digest"],
        )
        return detail.get("effect")
    finally:
        try:
            os.unlink(handle.name)
        except FileNotFoundError:
            pass


def parse_target(value):
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as error:
        fail(f"目标 URL 不合法: {error}")
    if parts.scheme != "https":
        fail("目标 URL 必须以 https:// 开头")
    if not parts.hostname:
        fail("目标 URL 缺少域名")
    if parts.username or parts.password:
        fail("目标 URL 不能包含用户名或口令")
    if parts.fragment:
        fail("目标 URL 不能包含 # 片段")
    host = parts.hostname.lower()
    origin = "https://" + host
    if port not in (None, 443):
        origin += f":{port}"
    return origin, parts.path or "/", parts.query


def build_policy(target, methods, body_bytes, days, uses):
    origin, path, query = parse_target(target)
    selected = sorted(set(methods))
    if set(selected) & EMPTY_BODY_METHODS and set(selected) & BODY_METHODS:
        fail("不能把无请求体的方法和有请求体的方法放进同一条策略；分两条策略创建")
    body = (
        {"mode": "empty", "max_bytes": 0}
        if set(selected) <= EMPTY_BODY_METHODS
        else {"mode": "bounded", "max_bytes": body_bytes}
    )
    content = {
        "schema_version": 1,
        "name": "bootstrap-" + origin.removeprefix("https://")[:100],
        "purpose": "http-authentication",
        "origin": origin,
        "methods": selected,
        "paths": [path],
        "query": {"mode": "exact", "value": query} if query else {"mode": "none"},
        "body": body,
        "signature_profile": "anp-http-v2",
        "grant_limits": {"max_duration_seconds": days * 86400, "max_uses": uses},
    }
    return content


def main():
    global ADMIN, BINARY, CONFIG
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--binary", type=Path, default=BINARY)
    parser.add_argument("--admin-user", required=True)
    parser.add_argument("--agent-user", required=True)
    parser.add_argument("--did-host", required=True)
    parser.add_argument("--did-path", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--method", action="append", default=[])
    parser.add_argument("--body-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--grant-days", type=int, default=1)
    parser.add_argument("--max-uses", type=int, default=100)
    parser.add_argument("--hardware", choices=["none", "tpm"], default="none")
    args = parser.parse_args()

    ADMIN, BINARY, CONFIG = args.admin_user, args.binary, args.config

    if os.geteuid() != 0:
        fail("必须以 root 运行（由 ./install.sh --bootstrap 调用）")
    if not CONFIG.is_file():
        fail(f"找不到服务配置: {CONFIG}")
    config = json.loads(CONFIG.read_text())
    if config.get("vault_ids"):
        fail("这台机器已经有 vault；--bootstrap 只用于全新的空安装，已有身份请按 deploy/LOCAL-USE.md 手动迁入")

    admin_record = pwd.getpwnam(ADMIN)
    agent_record = pwd.getpwnam(args.agent_user)
    if admin_record.pw_uid not in config["admin_uids"]:
        fail(f"{ADMIN} 不在服务配置的管理员 UID 中")
    principals = [
        item for item in config.get("principals", [])
        if item["uid"] == agent_record.pw_uid and item["enabled"]
    ]
    if len(principals) != 1:
        fail(f"服务配置里找不到唯一的 Agent principal: {args.agent_user}")

    methods = [method.upper() for method in args.method]
    if not methods:
        methods = ["GET"]
    unknown = set(methods) - ACCEPTED_METHODS
    if unknown:
        fail("不支持的方法: " + ", ".join(sorted(unknown)))
    if not 1 <= args.grant_days <= 365:
        fail("--grant-days 必须在 1 到 365 之间")
    if not 1 <= args.max_uses <= 1_000_000:
        fail("--max-uses 必须在 1 到 1000000 之间")
    if not 1 <= args.body_bytes <= 16 * 1024 * 1024:
        fail("--body-bytes 必须在 1 到 16777216 之间")
    policy = build_policy(args.target, methods, args.body_bytes, args.grant_days, args.max_uses)

    staging = Path(tempfile.mkdtemp(prefix="anpio-key-bootstrap-", dir="/root"))
    recovery = Path("/root/anpio-key-recovery-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))
    service_started = False
    try:
        spec = staging / "identity.spec.json"
        step("生成 did:wba 身份（接下来会要求你设置一次口令）")
        run([
            str(BINARY), "--root", str(staging), "spec",
            "--host", args.did_host, "--path", args.did_path, "--out", str(spec),
        ])
        keygen = subprocess.run(
            [str(BINARY), "--root", str(staging), "keygen", "--spec", str(spec),
             "--hardware", args.hardware],
            capture_output=True, text=True,
        )
        if keygen.returncode != 0:
            fail("生成身份失败:\n" + (keygen.stderr or keygen.stdout).strip())
        dids = [line.strip() for line in keygen.stdout.splitlines() if line.startswith("did:wba:")]
        if len(dids) != 1:
            fail("没有从 keygen 输出里读到唯一的 DID")
        did = dids[0]
        step("发布本地 DID 文档（会再要求一次同一口令）")
        published = subprocess.run(
            [str(BINARY), "--root", str(staging), "publish", "--did", did, "--spec", str(spec)],
            capture_output=True, text=True,
        )
        if published.returncode != 0:
            fail("发布 DID 文档失败:\n" + (published.stderr or published.stdout).strip())
        match = re.search(r"https://\S+/did\.json", published.stdout)
        document_url = match.group(0) if match else "（见 publish 输出）"

        step("创建日常热钥匙并更新本地 DID 文档")
        print("    依次输入: 绑定钥匙口令; 新热钥匙口令（直接回车 = 沿用同一个）;", flush=True)
        print("    看到 Write it? 时输入 y 确认写入。", flush=True)
        rotated = subprocess.run(
            [str(BINARY), "--root", str(staging), "rotate-hot-key", "--did", did,
             "--label", "daily", "--hardware", args.hardware],
            capture_output=True, text=True,
        )
        if rotated.returncode != 0:
            fail("创建热钥匙失败:\n" + (rotated.stderr or rotated.stdout).strip())
        match = re.search(r"new hot key (\S+)", rotated.stdout)
        if not match:
            fail("没有从 rotate-hot-key 输出里读到新的热钥匙 kid")
        hot_kid = match.group(1)

        step("停止服务，把身份离线迁入受保护状态（会再次要求口令）")
        subprocess.run(["systemctl", "stop", "anpio-key.service"], check=True)
        run([
            sys.executable or "python3", str(Path(__file__).with_name("migrate-vault.py")),
            "--config", str(CONFIG), "--binary", str(BINARY),
            "--source", str(staging), "--apply", "--recovery-dir", str(recovery),
        ])
        journal = json.loads((recovery / "migration.json").read_text())
        vault_id = journal["vault_id"]

        step("启动服务")
        subprocess.run(["systemctl", "start", "anpio-key.service"], check=True)
        service_started = True
        for _ in range(30):
            status = subprocess.run(
                ["runuser", "-u", ADMIN, "--", str(BINARY), "admin",
                 "--config", str(CONFIG), "status"],
                capture_output=True, text=True,
            )
            if status.returncode == 0:
                break
            time.sleep(1)
        else:
            fail("服务启动后管理通道仍不可用")

        step("登记 vault、确认热钥匙")
        apply_change(
            {"kind": "Catalog", "change": {"action": "EnrollVault", "vault_id": vault_id}},
            "EnrollVault",
        )
        catalog = admin("catalog")
        keys = [
            key for key in catalog.get("catalog", {}).get("keys", [])
            if key["vault_id"] == vault_id and key["did"] == did
        ]
        hot_keys = [key for key in keys if key["kid"] == hot_kid]
        root_keys = [key for key in keys if key["kid"] != hot_kid]
        if len(hot_keys) != 1 or len(root_keys) != 1:
            fail("登记后没有找到唯一的热钥匙和绑定钥匙")
        hot = hot_keys[0]
        apply_change(
            {"kind": "Catalog", "change": {
                "action": "ConfirmRole", "key_id": root_keys[0]["key_id"], "role": "root",
            }},
            "ConfirmRole(root)",
        )
        apply_change(
            {"kind": "Catalog", "change": {
                "action": "ConfirmRole", "key_id": hot["key_id"], "role": "hot",
            }},
            "ConfirmRole(hot)",
        )

        step("发布策略并创建 grant")
        policy_id = str(uuid.uuid4())
        apply_change(
            {"kind": "Catalog", "change": {
                "action": "PublishPolicy", "policy_id": policy_id, "version": 1,
                "content": policy,
            }},
            "PublishPolicy",
        )
        expiry = int(time.time()) + args.grant_days * 86400
        effect = apply_change(
            {"kind": "Grant", "change": {
                "action": "Create",
                "principal_id": principals[0]["principal_id"],
                "key_id": hot["key_id"],
                "policy_id": policy_id,
                "policy_version": 1,
                "expiry": expiry,
                "max_uses": args.max_uses,
            }},
            "Grant",
        )
        grant_id = effect["effect"]["grant"]["grant_id"]

        step("解锁热钥匙（最后一次口令）")
        admin(
            "unlock", "--vault-id", vault_id, "--did", did, "--kid", hot["kid"],
        )
        status = admin("status")
        if not status.get("signing_available"):
            fail("解锁后服务仍报告 signing_available=false")

        shutil.rmtree(staging)

        sample = {
            "operation": "SIGN_HTTP",
            "grant_id": grant_id,
            "request_id": "每次新操作生成并保存一个新的 UUID",
            "http": {
                "method": methods[0],
                "url": args.target,
                "headers": {},
                "body": (
                    {"state": "present", "bytes": []}
                    if methods[0] in BODY_METHODS
                    else {"state": "absent"}
                ),
                "nonce": None,
            },
        }
        print()
        print("初始化完成。")
        print(f"DID:            {did}")
        print(f"DID 文档:       {document_url}")
        print(f"vault:          {vault_id}")
        print(f"grant:          {grant_id}")
        print(f"有效期:         {args.grant_days} 天；最多 {args.max_uses} 次")
        print(f"恢复材料:       {recovery}（root 持有，含加密私钥副本，单独保护）")
        if len(methods) > 1:
            print(f"允许的方法:     {', '.join(sorted(set(methods)))}")
        print()
        print("把 DID 文档放到上面的地址；这个工具不托管任何内容。")
        print("Agent 示例请求（request_id 必须每次新操作自己生成并保存）:")
        print(json.dumps(sample, ensure_ascii=False, indent=2))
    except BaseException as error:
        if not service_started:
            subprocess.run(["systemctl", "start", "anpio-key.service"], check=False)
        print()
        print(f"初始化没有完成。临时身份留在 {staging}，迁移记录在 {recovery}。", file=sys.stderr)
        print("先检查上面的错误；不要在不明状态下重复执行 --bootstrap。", file=sys.stderr)
        if isinstance(error, SystemExit):
            raise
        if isinstance(error, KeyboardInterrupt):
            sys.exit(130)
        if isinstance(error, subprocess.CalledProcessError):
            sys.exit(1)
        sys.exit("bootstrap: " + str(error))


if __name__ == "__main__":
    main()
