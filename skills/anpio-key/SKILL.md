---
name: anpio-key
description: 在本机安装或使用 Anpio Key。三条互斥路径：Linux 受保护服务、macOS 本机预览、两平台通用的无边界开发试跑。用于生成与保管命名钥匙、签署 did:wba HTTP 请求、查询授权密钥与请求结果、排查拒绝原因。安装与解锁是管理员动作，口令只在人类终端输入。
---

# Anpio Key

私钥不出本机的 daemon，调用方只拿签名结果和公钥。钥匙可以只有名字，不必先有 DID；身份（DID、handle、文档、注册）是 `anpio-cli did create` 的事。每次签名要一张 grant：哪把钥匙、签什么目标、多久、几次。

## 先选路径

先回答三个问题，再往下读：

1. **哪台机器？** Linux 走 A 节，macOS 走 B 节。
2. **要边界，还是只想试功能？** 试功能走 C 节，两平台都行，但不建立安全边界。
3. **你是谁？** 管理员（人类终端，能 sudo）还是 Agent（只能发请求）。

A、B、C 三节互斥，不要混用命令。每节按“谁执行 / 前置 / 命令 / 成功判据”排列。

A、B 都从同一份 checkout 开始，并且不要把它放在 Agent 可写的目录里：

```bash
git clone --depth 1 https://github.com/eccstartup/anpio-key.git ~/code/anpio-key
cd ~/code/anpio-key
```

这是安装前的第 1 步，不是安装本身。安装器运行时要 sudo 和口令，必须在你的真实终端里跑。

## 钥匙与身份是两件事

`anpio-key` 管钥匙。一把钥匙现在可以只有名字：

```bash
anpio-key key create                 # 名字由 key 生成，例如 k-7f3a2c91
anpio-key key create --name team/bot # 也可自取：字母数字和 . _ -，/ 是子目录，但不能像 e1_…
anpio-key key list                   # 名字、指纹、是否解锁
anpio-key key unlock --name NAME     # 人类终端读口令
anpio-key key rotate --name NAME     # 同名换一把，旧的作废
```

`key create` 当场显示一次 24 词，确认抄好后读两遍口令，然后返回名字。它没有 `--host`、`--path`，也不打印 DID——DID 属于身份，不属于钥匙。

身份由 `anpio-cli did create` 一条命令建完（读服务信息、预检 handle、生成钥匙、签文档、注册）：

```bash
anpio-cli did create --host awiki.me --handle mybot --email you@example.com
```

默认钥匙由 CLI 本机保管。要让本机的 `anpio-key` 保管钥匙，由**管理员在自己的终端**加 `--key anpio-key`：

```bash
anpio-cli did create --host awiki.me --handle mybot --email you@example.com --key anpio-key
```

这时 CLI 调用 `anpio-key key create --json` 拿到名字和公钥，再用 `anpio-key key sign-document` 给 DID 文档签 proof；身份文件里只记钥匙名，没有任何私钥、seed 或口令字节。非交互终端直接拒绝，不会偷偷改用本机钥匙。

授权是独立的一步，因为“谁能在什么目标上签几次”是安全决定：

```bash
anpio-key grant create --key NAME --did DID --target https://awiki.me/user-service/v1/did-auth/rpc
# 默认 --method POST --ttl 24h --uses 100；先打印摘要，确认一次才创建
anpio-cli key grant <grant-id> --agent <handle>
```

`grant create` 只给**已经登记在受保护 catalog 里**的钥匙签 grant：它核对 `--did` 的 `e1_` 段与本地钥匙指纹一致，kid 必须是 `<did>#key-1` 且处于 active。命名钥匙的登记还没做（见 TODO.md），所以这条命令现在会明确报 catalog 缺这把钥匙——它和受保护命名签名一起启用。`anpio-cli key grant` 只需运行一次，之后签名不用再给编号。

> [!NOTE]
> 命名钥匙目前的签名路是本机开发守护进程（`serve --development --allow-named-key-signing`，默认关，每次签名一条独立审计）。把它接进受保护平面（独立 capability、按 grant 核对 target/TTL/次数）还没做；在它落地之前，受保护安装不开启这条路，见仓库 TODO.md。

`spec` / `keygen` / `publish` 已从主路径移出，只留兼容别名（`--help` 不再列出，执行时会提示改用 `key create` 或 `anpio-cli did create`）。已有用坐标脚本生成的身份继续可用，迁移说明见最后一节。

## A. Linux：受保护服务

**谁执行** 人类管理员，在自己的终端，仓库根目录。

**前置** Rust 1.88+；审阅过的 checkout；一个非管理员 Agent 账号（不带 `--agent-user` 时安装器创建 `anp-agent`）。

**安装**（只装服务，不生成身份）

```bash
./install.sh
```

先看计划不改系统：`./install.sh --dry-run`。物理 TPM：加 `--tpm-device`。

**建身份**（`--key local` 默认，或由本机的 `anpio-key` 保管钥匙）

```bash
anpio-cli did create --host awiki.me --handle mybot --email you@example.com --key anpio-key
```

要在**受保护服务**上签名，钥匙必须已经迁入 vault 并登记成 `{did}#key-1`。命名钥匙还没有登记路径（见 TODO.md），所以受保护签名目前只能迁移一把 DID 绑定的钥匙；命名钥匙的 grant 等 capability 落地后用 `anpio-key grant create` 建，再用 `anpio-cli key grant <id> --agent mybot` 记进 store。

已有身份或钥匙的迁移（旧流程）仍按 `deploy/LOCAL-USE.md`：`keygen` 生成四把、`migrate-vault` 离线迁入、`EnrollVault`/`ConfirmRole` 登记、发布策略。`keygen` 铸任何东西之前把 24 词当场显示一次，这是唯一备份；它现在还会提示改用 `key create`，但为了保住 DID 绑定，受保护迁移仍用这条老路。

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

`signing_available` 只表示执行器没停，空安装也会是 `true`，不代表有钥匙或 grant。能否签看 `LIST_AUTHORIZED_KEYS`、grant 和实际签名结果。`anpio-key build-info` 应报 `protected_supported=true`（正式 release 构建 + `linux-protected-v1` 配置）。

**位置** 程序 `/usr/local/libexec/anpio-key`，配置 `/etc/anpio-key/service.json`。

**日常入口**（同一脚本，按状态决定动作）

```bash
./install.sh --status      # 只读：状态、是否运行、已装摘要
./install.sh --verify      # 只读验收；失败退出 3
./install.sh --upgrade     # 换二进制，保留配置和状态；摘要相同不重启
./install.sh --uninstall   # 停服务、删二进制和单元，保留配置、状态和账号
```

已安装时直接跑 `./install.sh` 不会重建，只打印状态并退出 0。状态不符（半成品安装、卸载后只剩配置）退出 2，缺前置退出 4。**不要**为了"重新安装"而手工删 `/etc/anpio-key`、`/var/lib/anpio-key` 或账号。

## B. macOS：本机预览

**谁执行** 人类管理员，在自己的终端，仓库根目录。

**前置** Rust 1.88+ 和命令行工具（缺则先跑 `xcode-select --install`）；本地 APFS；上面那份 checkout。不需要完整 Xcode、付费开发者账号、Secure Enclave 或 TPM。

**安装**

```bash
./install.sh
```

脚本先以你的账号构建，之后才要 sudo：创建 `_anpio`（服务）与 `_anpagent`（Agent）、四个组、root 所有的 `/Library/ANPIOKey` 和 launchd job，启动服务并做只读检查。

已安装时直接跑 `./install.sh` 只打印状态并退出 0。日常用 `--status` / `--verify` / `--upgrade` / `--uninstall`，语义与 Linux 一节相同：升级保留配置和状态，卸载保留 `service.json`、`state/` 和 `_anpio*` 账号。不要手工删这些路径或账号。

**建身份** 和 Linux 一样用 `anpio-cli did create`（要本服务保管钥匙就由管理员加 `--key anpio-key`）。但 macOS 预览同样是受保护平面，只接受已迁入 vault、登记成 `{did}#key-1` 的 DID 绑定钥匙；命名钥匙的登记还没做，所以要让预览服务真正签一把钥匙，仍用 `--bootstrap` 这条老路（一次性预览身份、迁入、登记、策略、grant、解锁）。配置在 `/Library/ANPIOKey/service.json`。

`grant create` 要带 `--config /Library/ANPIOKey/service.json`（默认值指向 Linux 的路径），并且和受保护命名签名一起启用。

**手动安装**

```bash
cargo build --locked --release --features mcp
shasum -a 256 target/release/anpio-key
python3 deploy/macos/provision-accounts.py --admin-user YOUR_HUMAN_ACCOUNT
sudo bash deploy/macos/setup-local.sh YOUR_HUMAN_ACCOUNT VERIFIED_SHA256
```

**成功判据**（先注销并重新登录，组成员关系才生效）

```bash
/Library/ANPIOKey/bin/anpio-key admin --config /Library/ANPIOKey/service.json status
sudo /usr/bin/python3 deploy/macos/acceptance/test-install.py
```

macOS 始终 `protected_supported=false`：这是 UID 边界预览，不是正式受保护的 macOS 发行。已有身份或真实密钥要按 `deploy/macos/AGENT.md` 手动迁入。

**位置** 程序 `/Library/ANPIOKey/bin/anpio-key`，配置 `/Library/ANPIOKey/service.json`。

## C. 两平台通用：开发试跑（不建边界）

**谁执行** 你自己的账号，不需要 sudo。

```bash
cargo build --locked --release --features mcp
./target/release/anpio-key --root /tmp/keyd-lab key create --name bot
```

开发模式不注册任何东西，也没有 DID 坐标。`key create` 在终端显示一次 24 词，确认抄好，输入两遍口令，然后打印名字、指纹和公钥。

要让这把钥匙签名，守护进程必须显式打开命名签名路：

```bash
./target/release/anpio-key --root /tmp/keyd-lab serve \
  --development --allow-named-key-signing
```

另一个终端解锁并签名。签名必须带上 keyid，daemon 核对它的 `e1_` 段与信封指纹一致（`<thumbprint>` 换成 `key list --json` 里那串）：

```bash
./target/release/anpio-key --root /tmp/keyd-lab key unlock --name bot
./target/release/anpio-key --root /tmp/keyd-lab sign --key bot \
  --keyid did:wba:example.com:user:mybot:<thumbprint>#key-1 \
  --method POST --url https://awiki.me/anp-im/rpc
```

输出两行签名头，原样放进 HTTP 请求，不改任何字符。结束用 `... stop`。

文档 proof 由管理员命令直接签，不经过守护进程、不需要 grant：

```bash
anpio-key key sign-document --name bot --keyid DID#key-1 \
  --document unsigned.json --out signed.json
```

它写一行自己的审计。`anpio-cli did create --key anpio-key` 调用的就是这条。

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
| `NAMED_SIGNING_DISABLED` | 命名签名路没开；要它就用 `--development --allow-named-key-signing` 重启本地 daemon，受保护服务不提供这条路 |
| `AUDIT_UNAVAILABLE` | 停止使用，管理员检查持久化与恢复 |
| `OUTCOME_UNKNOWN` | 不重签；按原 `request_id` 查询并核对远端结果 |
| `PROTOCOL_INVALID` / `REQUEST_ID_CONFLICT` | 修请求；新输入必须新 ID |

## 边界

- 注册、轮换、设备入组、撤销、迁移、策略与 grant 变更都是管理员动作，Agent 不执行。
- 口令只进人类终端，不进聊天、MCP、argv 或环境变量。
- 服务重启后所有 grant 失效、钥匙锁定，需要重新解锁和建权。
- `--root` 开发模式与 `cargo install` 都不建立安全边界。
- 要把一个自己拿私钥签名的工具改造成通过本服务签名，用 `anpio-key-integration` 技能。

## 迁移：从坐标脚本到 key create

`spec --host --path` → `keygen --spec` → `publish --did` 这条老路仍能解析，但已隐藏：

- 它先铸一把 DID 绑定的根钥匙，再用坐标算出 DID；换 handle 就得重来，用户名被占用时很别扭。
- 新流程把这层交给 `anpio-cli did create`：handle 只是候选，注册被接受之后才算数；钥匙先由 `key create` 铸好，重名只换名字不重铸。
- 已有用老路生成的钥匙和文档不用动：`key list` 会把命名钥匙和 DID 绑定信封一起列出来，老信封照常由 `list`/`sign --did` 使用；受保护迁移仍按 `deploy/LOCAL-USE.md`。
