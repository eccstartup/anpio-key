---
name: anpio-key
description: 在本机安装或使用 Anpio Key。三条互斥路径：Linux 受保护服务、macOS 本机预览、两平台通用的无边界开发试跑。用于签署 did:wba HTTP 请求、查询授权密钥与请求结果、排查拒绝原因。安装与解锁是管理员动作，口令只在人类终端输入。
---

# Anpio Key

私钥不出本机的 daemon，调用方只拿签名结果和公钥。每次签名要一张 grant：哪把钥匙、签什么目标、多久、几次。

## 先选路径

先回答三个问题，再往下读：

1. **哪台机器？** Linux 走 A 节，macOS 走 B 节。
2. **要边界，还是只想试功能？** 试功能走 C 节，两平台都行，但不建立安全边界。
3. **你是谁？** 管理员（人类终端，能 sudo）还是 Agent（只能发请求）。

A、B、C 三节互斥，不要混用命令。每节按“谁执行 / 前置 / 命令 / 成功判据”排列。

## DID 文档放哪（默认 awiki.me）

`--did-host` 和 `--did-path` 一起决定 DID 和文档 URL：

```
did:wba:<host>:<path 各段>:<绑定公钥指纹>
文档：https://<host>/<path 各段>/did.json
```

默认用 awiki.me，路径取 `user/<handle>`（`<handle>` 换成你在 awiki 注册的名字）：

```bash
./install.sh --bootstrap --did-host awiki.me --did-path user/mybot \
  --target https://api.example.com/v1/status
```

在 awiki 注册 handle 时登记的就是 `keygen` 生成的绑定公钥；注册完成后文档由 awiki 托管，本地 `publish` 用来生成和核对文档。

换别的 DID server 只改这两个参数：

```bash
./install.sh --bootstrap --did-host agents.example.com --did-path agents/mybot \
  --target https://api.example.com/v1/status
```

- 任何能按 `https://<host>/<path 各段>/did.json` 提供文档的域名都可以；自建就是自己托管这份 JSON。
- 文档必须带自签 proof：`publish` 生成，`verify-doc` 核对归属。
- `--did-path` 的默认值是 `agents/anpio-key`，用自建域名时通常保留。
- 换域名等于换 DID，不存在“换服务器、DID 不变”。

## A. Linux：受保护服务

**谁执行** 人类管理员，在自己的终端，仓库根目录。

**前置** Rust 1.88+；审阅过的 checkout；一个非管理员 Agent 账号（不带 `--agent-user` 时安装器创建 `anp-agent`）。

**安装并初始化**（身份、热钥匙、迁入受保护状态、策略、grant、首次解锁）

```bash
./install.sh --bootstrap --did-host awiki.me --did-path user/mybot \
  --target https://api.example.com/v1/status
```

- `--did-host` / `--did-path`：默认 awiki.me 的 `user/<handle>`；换 DID server 见上节。
- `--target`：Agent 实际要访问的完整 HTTPS 地址，策略由此得出。
- 省略时脚本在终端里询问。
- 口令（绑定钥匙、热钥匙、迁入、解锁）由二进制从 `/dev/tty` 读取；不要代输、捕获或转交。

只装空服务：`./install.sh`。先看计划不改系统：`./install.sh --dry-run`。物理 TPM：加 `--tpm-device`。

**手动安装**（管理员要先独立核对摘要）

```bash
cargo build --locked --release --features mcp
sha256sum target/release/anpio-key
sudo python3 deploy/linux/install.py --binary target/release/anpio-key \
  --sha256 VERIFIED_SHA256 --admin-user operator --agent-user agent-a
sudo systemctl daemon-reload
```

**成功判据**

```bash
sudo systemctl status anpio-key
sudo -u operator /usr/local/libexec/anpio-key admin \
  --config /etc/anpio-key/service.json status
```

要 `signing_available=true` 才能签；`anpio-key build-info` 应报 `protected_supported=true`（正式 release 构建 + `linux-protected-v1` 配置）。

**位置** 程序 `/usr/local/libexec/anpio-key`，配置 `/etc/anpio-key/service.json`。安装器拒绝已有或半成品安装，它不是更新或修复命令。

## B. macOS：本机预览

**谁执行** 人类管理员，在自己的终端，仓库根目录。

**前置** Rust + 命令行工具；本地 APFS。不需要完整 Xcode、付费开发者账号、Secure Enclave 或 TPM。

**安装**

```bash
./install.sh
```

脚本先以你的账号构建，之后才要 sudo：创建 `_anpio`（服务）与 `_anpagent`（Agent）、四个组、root 所有的 `/Library/ANPIOKey` 和 launchd job，启动服务并做只读检查。

**预览身份 + 首次授权**（只用于一次性身份，不要放真实密钥）

```bash
./install.sh --bootstrap --did-host awiki.me --did-path user/mybot \
  --target https://api.example.com/v1/status
```

macOS 的 `--bootstrap` 固定使用 `_anpagent` 和 `--hardware none`，流程与 Linux 一致：生成身份、创建热钥匙、离线迁入、登记 vault、确认角色、发布策略、创建 grant、解锁。

**手动安装**

```bash
cargo build --locked --release --features mcp
shasum -a 256 target/release/anpio-key
python3 deploy/macos/provision-accounts.py --admin-user YOUR_HUMAN_ACCOUNT
sudo bash deploy/macos/setup-local.sh YOUR_HUMAN_ACCOUNT VERIFIED_SHA256
```

**成功判据**

```bash
/Library/ANPIOKey/bin/anpio-key admin --config /Library/ANPIOKey/service.json status
sudo /usr/bin/python3 deploy/macos/acceptance/test-install.py
```

macOS 始终 `protected_supported=false`：这是 UID 边界预览，不是正式受保护的 macOS 发行。装完注销并重新登录，组成员关系才生效。已有身份或真实密钥要按 `deploy/macos/AGENT.md` 手动迁入。

**位置** 程序 `/Library/ANPIOKey/bin/anpio-key`，配置 `/Library/ANPIOKey/service.json`。

## C. 两平台通用：开发试跑（不建边界）

**谁执行** 你自己的账号，不需要 sudo。

```bash
cargo build --locked --release --features mcp
mkdir -p /tmp/keyd-lab
./target/release/anpio-key --root /tmp/keyd-lab spec \
  --host awiki.me --path user/mybot --out /tmp/keyd-lab/mybot.spec.json
./target/release/anpio-key --root /tmp/keyd-lab keygen --spec /tmp/keyd-lab/mybot.spec.json
```

开发模式不会向 awiki 注册，`publish` 只在本地生成 `did.json`；这个 DID 在本机之外解析不到。

`keygen` 在终端显示一次 24 词，确认抄好，输入两遍口令，然后打印 DID。

```bash
./target/release/anpio-key --root /tmp/keyd-lab publish --did DID
./target/release/anpio-key --root /tmp/keyd-lab serve
```

另一个终端解锁并签名：

```bash
./target/release/anpio-key --root /tmp/keyd-lab unlock --did DID
./target/release/anpio-key --root /tmp/keyd-lab sign --did DID \
  --method GET --url https://service.example.net/orders/42
```

输出两行签名头，原样放进 HTTP 请求，不改任何字符。结束用 `... stop`。

开发模式所有文件都在你自己的账号下，**同一账号的任意代码都能拿到密钥**，不构成隔离。

## 装完之后：管理员怎么用

Linux：

```bash
ADMIN="sudo -u operator /usr/local/libexec/anpio-key admin --config /etc/anpio-key/service.json"
$ADMIN status
$ADMIN catalog
$ADMIN unlock --vault-id VAULT_ID --did DID --kid FULL_KID
```

macOS：

```bash
ADMIN="/Library/ANPIOKey/bin/anpio-key admin --config /Library/ANPIOKey/service.json"
$ADMIN status
$ADMIN unlock --vault-id VAULT_ID --did DID --kid FULL_KID --native-ui
```

所有变更走两步：`prepare --file change.json` 生成 effect 与摘要，人工核对后 `commit --operation-id ... --digest ...`。解锁只让钥匙可用，不产生授权；授权来自 grant。

## 装完之后：Agent 怎么用

整个 Agent（包括模型和所有工具进程）必须在 Agent 账号下运行，只给签名子进程换账号不算边界。

```bash
anpio-key data --config CONFIG --file request.json
```

`CONFIG`：Linux `/etc/anpio-key/service.json`，macOS `/Library/ANPIOKey/service.json`。

MCP 方式（构建时带 `mcp` feature）：`anpio-key mcp --config CONFIG`。工具参数不能覆盖配置、socket、DID 或 kid。

最小签名请求：

```json
{"operation":"SIGN_HTTP","grant_id":"ADMIN_GRANT","request_id":"落盘的UUID",
 "http":{"method":"GET","url":"https://service.example.com/orders",
 "headers":{},"body":{"state":"absent"},"nonce":null}}
```

规则：

- 每个新操作自己生成并**先落盘** `request_id`；重试复用原 ID，换了输入还在用旧 ID 会 `REQUEST_ID_CONFLICT`。
- 只在 `data.state=completed` 且存在 `data.result` 时交付签名。
- 发送时用返回的规范化 URL、原 body 和签名头，关闭自动重定向。
- 响应丢失先用原 ID 查 `GET_REQUEST_STATUS`；`outcome_unknown` 不代表没签，停止自动重试并交管理员核对。
- 基线六个操作永远可用；其余签名路各自一个开关，客户端只看 `GET_CAPABILITIES` 的 `operations`，不在列表里就是不支持。

## 拒绝怎么处理

| 情况 | 动作 |
|---|---|
| `KEY_LOCKED` | 管理员解锁 exact hot key；不要向任何人索要口令 |
| grant 过期、耗尽、撤销或策略拒绝 | 管理员重建 grant；不换主体、钥匙或目标绕过 |
| `OPERATION_DISABLED` | 该签名路默认关，按不支持处理，不重试 |
| `AUDIT_UNAVAILABLE` | 停止使用，管理员检查持久化与恢复 |
| `OUTCOME_UNKNOWN` | 不重签；按原 `request_id` 查询并核对远端结果 |
| `PROTOCOL_INVALID` / `REQUEST_ID_CONFLICT` | 修请求；新输入必须新 ID |

## 边界

- 注册、轮换、设备入组、撤销、迁移、策略与 grant 变更都是管理员动作，Agent 不执行。
- 口令只进人类终端，不进聊天、MCP、argv 或环境变量。
- 服务重启后所有 grant 失效、钥匙锁定，需要重新解锁和建权。
- `--root` 开发模式与 `cargo install` 都不建立安全边界。
- 要把一个自己拿私钥签名的工具改造成通过本服务签名，用 `anpio-key-integration` 技能。
