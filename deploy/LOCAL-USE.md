# 本机使用：先建立边界，再交给 Agent

正式使用时，服务、管理员和 Agent 用三个系统账号：

| 账号 | 运行什么 | 能做什么 |
|---|---|---|
| 管理员（你本人） | 管理命令 | 批准变更、解锁、撤销、轮换 |
| 服务账号 | Anpio Key daemon | 保存私钥、状态和审计，执行签名 |
| Agent 账号 | 整个 AI 框架 | 只能请求签名和查询自己的授权 |

**整个 Agent 框架及其工具进程**都要在 Agent 账号下运行。只把签名子进程换账号，而模型的 shell 仍有管理员权限，边界不成立。

不要给 Agent sudo、Docker 管理权限、管理员凭据、真实身份口令，也不要让它能改服务程序或配置。

## 1. 一条命令完成安装和初始化

Linux 上在仓库根目录执行：

```bash
./install.sh --bootstrap --did-host agents.example.com \
  --target https://api.example.com/v1/status
```

这条命令依次完成：

1. 构建 release、校验摘要、创建服务账号、安装并启动 systemd 服务；
2. 生成一个 did:wba 身份，并发布本地 DID 文档；
3. 创建一个日常签名的热钥匙，更新 DID 文档；
4. 停止服务，把两把钥匙离线迁入受保护状态，再启动服务；
5. 登记 vault，确认绑定钥匙为 root、热钥匙为 hot；
6. 按 `--target` 发布策略，创建 grant；
7. 解锁热钥匙，确认 `signing_available=true`。

`--did-host` 是 DID 文档将来发布的域名，`--target` 是 Agent 要访问的完整 HTTPS 地址；省略时脚本会在终端里询问。

全程会要求你在终端输入口令：绑定钥匙、热钥匙、迁入受保护状态和解锁。口令只由 Anpio Key 从 `/dev/tty` 读取，不经过 Agent、命令行参数或环境变量。

成功后打印 DID 文档地址、vault、grant、有效期、恢复材料目录和一段 Agent 请求示例。把 DID 文档上传到打印出的地址，把 grant 交给 Agent。

常用选项：

```bash
./install.sh --admin-user operator --agent-user agent-a
./install.sh --tpm-device
./install.sh --dry-run
```

`--method` 可以重复，默认 `GET`；`--body-bytes`、`--grant-days`、`--max-uses` 分别限制请求体大小、有效天数和签名次数。指定多个 Agent 账号时，`--bootstrap` 只为第一个账号创建 grant。

只安装空服务，之后手动初始化：

```bash
./install.sh
```

手动校验发行包、更新和离线迁移见 [Linux 部署](linux/README.md)。

macOS 用同一条命令安装本机预览，始终 `protected_supported=false`；`--bootstrap` 同样可用，只使用 `_anpagent` 和 `--hardware none`，流程与 Linux 一致（生成身份、创建热钥匙、离线迁入、登记 vault、确认角色、发布策略、创建 grant 并解锁）。本机预览请用一次性身份和公开口令试跑，不要用真实密钥试错。已有身份或需要迁入真实密钥时仍按 `deploy/macos/AGENT.md` 手动完成。

## 2. 手动完成身份和授权

需要已有身份、多个 Agent 或自定义策略时，按本节手动完成。下面的程序路径是正式安装的位置；管理命令必须在管理员账号下运行（root 不在 `admin_uids` 里）。

### 2.1 准备一个身份

新身份先在一个 root 控制的暂存目录里生成。`keygen` 生成的是绑定钥匙（root）；日常签名还需要一把单独的热钥匙：

```bash
sudo install -d -m 700 /root/keyd-staging
sudo /usr/local/libexec/anpio-key --root /root/keyd-staging spec \
  --host agents.example.com --path agents/anpio-key \
  --out /root/keyd-staging/identity.spec.json
sudo /usr/local/libexec/anpio-key --root /root/keyd-staging keygen \
  --spec /root/keyd-staging/identity.spec.json
sudo /usr/local/libexec/anpio-key --root /root/keyd-staging publish \
  --did DID --spec /root/keyd-staging/identity.spec.json
sudo /usr/local/libexec/anpio-key --root /root/keyd-staging rotate-hot-key \
  --did DID --label daily
```

`publish` 打印 DID 文档地址；把文档上传到该地址。`rotate-hot-key` 打印新的热钥匙 kid，记下来。

旧身份（已经停止写入的 vault 或恢复副本）跳过这一步，直接迁移：

```bash
sudo python3 deploy/linux/migrate-vault.py --source /root/frozen-vault
sudo python3 deploy/linux/migrate-vault.py --source /root/frozen-vault \
  --apply --recovery-dir /root/keyd-recovery
```

迁移会核对摘要、逐钥验证恢复副本，并把新 vault 里的钥匙标成未分类、锁定状态。

新身份也走同一条迁移：

```bash
sudo systemctl stop anpio-key
sudo python3 deploy/linux/migrate-vault.py --source /root/keyd-staging --binary /usr/local/libexec/anpio-key
sudo python3 deploy/linux/migrate-vault.py --source /root/keyd-staging \
  --binary /usr/local/libexec/anpio-key --apply --recovery-dir /root/keyd-recovery
sudo systemctl start anpio-key
```

`migration.json` 里的 `vault_id` 后面要用到。

### 2.2 登记 vault、确认角色

所有管理变更都分两步：`prepare` 生成计划和摘要，你核对后 `commit`。示例里的 UUID、网址和 kid 都要换成真实值。

```bash
ADMIN="sudo -u operator /usr/local/libexec/anpio-key admin --config /etc/anpio-key/service.json"
```

登记 vault：

```json
{"kind":"Catalog","change":{"action":"EnrollVault","vault_id":"VAULT_UUID"}}
```

```bash
$ADMIN prepare --file enroll.json
$ADMIN commit --operation-id PREPARED_OPERATION_UUID --digest PREPARED_DIGEST
```

从 `$ADMIN catalog` 找到两把钥匙的 `key_id`：绑定钥匙确认成 root，热钥匙确认成 hot：

```json
{"kind":"Catalog","change":{"action":"ConfirmRole","key_id":"ROOT_KEY_UUID","role":"root"}}
{"kind":"Catalog","change":{"action":"ConfirmRole","key_id":"HOT_KEY_UUID","role":"hot"}}
```

分别 `prepare` 后 `commit`。root 要求钥匙指纹等于 DID 的绑定指纹；hot 要求不是 root 且在 DID 文档的 `authentication` 里。只有确认成 hot 的钥匙才能进入普通 Agent 的 grant。

### 2.3 发布策略

策略规定 Agent 能访问哪里。下面的例子只允许 `GET https://service.example.com/v1/status`：

```json
{
  "kind": "Catalog",
  "change": {
    "action": "PublishPolicy",
    "policy_id": "POLICY_UUID",
    "version": 1,
    "content": {
      "schema_version": 1,
      "name": "read-agent-status",
      "purpose": "http-authentication",
      "origin": "https://service.example.com",
      "methods": ["GET"],
      "paths": ["/v1/status"],
      "query": {"mode": "none"},
      "body": {"mode": "empty", "max_bytes": 0},
      "signature_profile": "anp-http-v2",
      "grant_limits": {"max_duration_seconds": 900, "max_uses": 100}
    }
  }
}
```

同样 `prepare` 后 `commit`。有请求体的方法（`POST`、`PUT`、`PATCH`）用 `{"mode":"bounded","max_bytes":N}`，上限 16 MiB；无请求体的方法和有请求体的方法要分成两条策略。

### 2.4 创建 grant

```json
{
  "kind": "Grant",
  "change": {
    "action": "Create",
    "principal_id": "AGENT_PRINCIPAL_UUID",
    "key_id": "HOT_KEY_UUID",
    "policy_id": "POLICY_UUID",
    "policy_version": 1,
    "expiry": 1792125000,
    "max_uses": 10
  }
}
```

`principal_id` 从 `$ADMIN list-principals` 取。`expiry` 是 Unix 秒，必须是未来时间，且不能超过策略的 `max_duration_seconds`。`max_uses` 是这张 grant 最多能签几次。提交后从返回的 effect 里取 `grant_id`，把它交给 Agent。

### 2.5 解锁

```bash
$ADMIN unlock --vault-id VAULT_UUID --did DID --kid FULL_KID
$ADMIN status
```

口令由管理 CLI 从终端读取，不经过 Agent、MCP 或聊天。解锁只让钥匙可用，不会自己产生授权；授权来自上面的 grant。`status` 应报告 `signing_available=true`。

## 3. 启动 Agent

确认 Agent 账号：

```bash
sudo -u agent-a -- id
```

输出应该是 Agent 的 UID，不是你自己的 UID。然后让整个 AI 框架在 `agent-a` 账号和专用工作目录下启动。不要把人类 HOME、令牌和管理员环境整体传给它。

Agent 可以用 CLI：

```bash
anpio-key data --config /etc/anpio-key/service.json --file request.json
```

也可以用 MCP：

```bash
anpio-key mcp --config /etc/anpio-key/service.json
```

MCP 需要构建时启用 `mcp` feature。工具参数不能覆盖配置文件、socket、DID 或 kid。

## 4. 日常：失败、重试、撤销

- 每个新操作自己生成并保存 `request_id`。重试时复用原 ID；不要因为超时换一个新 ID 重签。
- `outcome_unknown` 不表示没签名。停止自动重试，先查询状态并核对远端结果。
- 发送时用 daemon 返回的规范化 URL、原始 body 和签名头，关闭自动重定向。
- 撤销 grant 后不再产生新签名，但已经发出去的签名收不回来。

撤销：

```json
{"kind":"Grant","change":{"action":"Revoke","grant_id":"GRANT_ID"}}
```

同样 `prepare` 后 `commit`。

服务重启后所有 grant 失效、钥匙锁定、未完成批准作废。需要你重新解锁和建权，不会自动恢复。

## 5. macOS 预览和 SE

macOS 提供独立账号的本机预览，始终 `protected_supported=false`。Secure Enclave 登录助手、真实注销/休眠/整机重启、正式签名和持久 SE 仍需要单独验收，见[SE 说明](macos/SE-SESSION.md)。

预览测试通过不等于 macOS 正式发行完成，也不能把结果套到 Linux 受保护部署上。
