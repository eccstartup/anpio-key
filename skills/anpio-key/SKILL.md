---
name: anpio-key
description: 在本机安装 Anpio Key，或使用已安装的 v2 有限授权签署 did:wba HTTP 请求、查询授权密钥与请求结果、排查拒绝原因。安装是管理员动作；身份注册、解锁、轮换与迁移属于独立可信管理流程。
---

# Anpio Key

Linux v2 通过独立 OS UID 认证主体，daemon 执行 exact-key grant、目标策略、期限、次数、撤销和持久请求去重。仅正式 Linux 构建且 root 配置为 `linux-protected-v1` 时 `protected_supported=true`；旧 preview、调试、macOS 及敏感测试特性均为 false。同 UID 开发模式不提供抵御任意代码的私钥隔离。

## 首次安装

安装需要 root，属于管理员动作。只有在人类明确批准、并临时提供 sudo 时，Agent 才能执行；否则把下面这一条命令交给人类，在自己的终端里运行。身份口令、解锁口令和 sudo 口令都不进入聊天、MCP、argv 或环境变量。

在人类审阅过的仓库根目录运行一条命令，安装服务并完成身份、策略、grant 和第一次解锁：

```bash
./install.sh --bootstrap --did-host agents.example.com \
  --target https://api.example.com/v1/status
```

`--did-host` 是 DID 文档将来发布的域名，`--target` 是 Agent 要访问的完整 HTTPS 地址；省略时脚本会在终端里询问。执行中会多次要求人类输入口令：绑定钥匙、热钥匙、迁入受保护状态和解锁。口令由 Anpio Key 直接从 `/dev/tty` 读取；Agent 不要代输、捕获、转发或保存口令。

成功后打印 DID 文档地址、vault、grant、有效期、恢复材料目录和 Agent 请求示例。把 DID 文档上传到打印的地址，把 grant 交给 Agent。

只安装空服务、之后按 `deploy/LOCAL-USE.md` 手动初始化：

```bash
./install.sh
```

先看计划、不改系统：

```bash
./install.sh --dry-run
```

指定管理员、Agent 或 TPM：

```bash
./install.sh --admin-user operator --agent-user agent-a
./install.sh --tpm-device --bootstrap --did-host agents.example.com \
  --target https://api.example.com/v1/status
```

`--method` 可以重复，默认 `GET`；`--body-bytes`、`--grant-days`、`--max-uses` 限制请求体大小、有效天数和签名次数。指定多个 Agent 账号时，`--bootstrap` 只为第一个账号创建 grant。

安装后确认：

```bash
sudo systemctl status anpio-key
sudo -u ADMIN_USER /usr/local/libexec/anpio-key admin \
  --config /etc/anpio-key/service.json status
```

macOS 使用同一条命令安装本机预览，始终 `protected_supported=false`。macOS 的 `--bootstrap` 只用于全新的本机预览：使用 `_anpagent`、`--hardware none` 和一次性身份完成身份、授权与首次解锁；真实身份或已有密钥按 `deploy/macos/AGENT.md` 手动迁入。安装完成后必须收回 Agent 账号的 sudo，否则受保护边界不成立。

## 普通 Agent 工作流

使用管理员提供的 `/etc/anpio-key/service.json` 和 grant。不要自行改 socket、服务 UID、DID、kid 或策略。用 `anpio-key data --config CONFIG --file REQUEST.json` 发送一个请求对象，或通过 MCP `anpio-key mcp --config CONFIG` 使用同样的 v2 工具。

先用 `{"operation":"LIST_AUTHORIZED_KEYS"}` 查看当前主体可用的 key handle；使用 `GET_DOCUMENT` 时提供 `key_id`。没有授权时请管理端建权，解锁本身不会产生权限。

签名请求示例：

```json
{"operation":"SIGN_HTTP","grant_id":"ADMIN_PROVIDED_GRANT","request_id":"PERSISTED_UUID","http":{"method":"GET","url":"https://service.example.com/orders","headers":{},"body":{"state":"absent"},"nonce":"SERVER_EXPECTED_FRESH_NONCE"}}
```

有 body 时明确使用 `{"state":"present","bytes":[...]}`；空 body 与无 body 不同。保存 request_id 和原始请求后再发送。响应丢失时以原 ID 查询 `GET_REQUEST_STATUS`；相同请求可用原 ID 重试，不生成新 ID 偷偷重签。`outcome_unknown` 不表示未签名，停止自动重试并交给管理端核对。

只在 `data.state=completed` 且存在 `data.result` 时交付签名。实际 HTTP 发送必须使用返回的规范化 URL、原 body 和返回的签名头，不自动跟随重定向。对端仍须检查用途、期限、nonce 和业务权限。Node 适配器见仓库 `adapters/anpio-key-v2.mjs`；不提供私钥导出、密码、raw 或 challenge 工具。

## 拒绝与管理边界

- `KEY_LOCKED`：由可信管理员解锁 exact hot key；不在聊天、MCP、argv 或环境变量里索要密码。
- grant 无效、过期、耗尽或策略拒绝：管理员明确重新建权；不更换主体、密钥或目标绕过限制。
- `AUDIT_UNAVAILABLE`：停止使用，管理端检查持久化和恢复。
- 注册 proof 使用管理端两阶段 `RegistrationChallenge`，只兼容已支持的服务格式。轮换使用 `RotateHotKey`，返回公开文档必须独立发布并验证；本地写入不等于网络生效。
- 离线迁移使用 `deploy/linux/migrate-vault.py` 的 dry-run 和恢复验证，要求 root 控制的冻结源与恢复目录。Agent 不执行维护操作。

旧 `serve`、`sign` 和未带 `--config` 的 MCP 仅用于明确选择的开发模式；不自动回退 v1。软件整套目录加口令可以解封；硬件保护的是解封材料，签名仍在普通进程内存中执行。
