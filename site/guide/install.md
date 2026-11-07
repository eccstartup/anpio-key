# 安装

需要 Rust 1.88 或更新。受保护部署目前只支持 Linux；macOS 提供独立账号的本机预览。

## Linux 受保护部署

服务、管理员和 Agent 会用三个系统账号。在人类审阅过的仓库根目录运行一条命令，安装、创建身份、发布策略、创建 grant 并解锁一次完成：

```bash
./install.sh --bootstrap --did-host agents.example.com \
  --target https://api.example.com/v1/status
```

- `--did-host` 是 DID 文档将来发布的域名；
- `--target` 是 Agent 实际要访问的完整 HTTPS 地址，策略里的网站、路径和方法都从它得出。

省略这两项时脚本会在终端里询问。执行中会要求输入几次口令（绑定钥匙、热钥匙、迁入受保护状态、解锁）。口令只由 Anpio Key 从终端读取，不经过 Agent、命令行参数或环境变量。

成功后打印 DID 文档地址、vault、grant、有效期、恢复材料目录和一段 Agent 请求示例。把 DID 文档上传到打印出的地址，把 grant 交给 Agent。

只安装空服务、之后手动初始化：

```bash
./install.sh
```

指定管理员和 Agent，或先用 TPM：

```bash
./install.sh --admin-user operator --agent-user agent-a --agent-user agent-b
./install.sh --tpm-device --bootstrap --did-host agents.example.com \
  --target https://api.example.com/v1/status
```

先看计划、不改系统：

```bash
./install.sh --dry-run
```

`--agent-user` 可以写多个，每个 Agent 一个账号；`--bootstrap` 只为第一个账号创建 grant。`--method` 可以重复，默认 `GET`；`--body-bytes`、`--grant-days`、`--max-uses` 分别限制请求体大小、有效天数和签名次数。

安装完成后，日常只用这一个入口：

| 命令 | 做什么 |
|---|---|
| `./install.sh` | 已安装时只打印状态并退出 0；不构建、不提权 |
| `./install.sh --status` | 只读查看状态、是否运行、已装二进制摘要 |
| `./install.sh --verify` | 对已安装服务跑只读验收，失败退出 3 |
| `./install.sh --upgrade` | 用当前构建替换二进制，保留配置和状态；摘要相同时不重启 |
| `./install.sh --uninstall` | 停止服务并删除二进制和服务单元，保留配置、状态和账号 |

退出码：0 成功或本来就是这个状态，2 状态不符（例如半成品安装、卸载后只剩配置），3 验收失败，4 缺前置（cargo、python3、systemd）。加 `--dry-run` 只打印计划。

手动完成身份和授权时，按[本机使用](/guide/local-use)执行登记 vault、确认 root/hot 角色、发布策略、创建 grant 和解锁。

装完检查（用管理员账号执行）：

```bash
sudo systemctl status anpio-key
sudo -u operator /usr/local/libexec/anpio-key admin \
  --config /etc/anpio-key/service.json status
sudo -u operator /usr/local/libexec/anpio-key probe \
  --security --config /etc/anpio-key/service.json
```

`status` 里的 `signing_available=true` 表示钥匙已经解锁，可以签名。`protected_supported=true` 只说明部署支持范围，见下文。

<details>
<summary>手动安装：自己核对发行包摘要</summary>

```bash
cargo build --locked --release --features mcp
sha256sum target/release/anpio-key
sudo python3 deploy/linux/install.py --binary target/release/anpio-key \
  --sha256 你核对过的SHA256 \
  --admin-user operator --agent-user agent-a --agent-user agent-b
sudo systemctl daemon-reload
sudo systemctl enable --now anpio-key
```

</details>

更新用 `--upgrade`。它先停服务、换二进制、再起服务，配置和状态不动：

```bash
cargo build --locked --release
./install.sh --upgrade
```

先看计划加 `--dry-run`；也可以显式给 `--binary` 和核对过的 `--sha256`。重启会锁钥匙并作废已有 grant，这是重启语义，不是升级的副作用。手动分步（`systemctl stop` → `deploy/linux/install.py --update` → `systemctl start`）见仓库 `deploy/linux/README.md`。

### 什么时候报告 `protected_supported=true`

同时满足三个条件：

- 正式 Linux release；
- 没启用 `hardware-software` 或 `seed-export`；
- 配置显式为 `linux-protected-v1`。

preview、调试构建和 macOS 都是 false。这个标志是支持范围声明，不是对任意宿主配置的持续证明。新安装默认选择保护模式；旧 preview 配置升级时保留原模式，需要管理员停机后明确切换。

### TPM

需要 TPM 后端时，一条命令完成构建和安装：

```bash
./install.sh --tpm-device
```

安装器只授予 `/dev/tpmrm0` 并把传输固定到该设备。验收步骤见[TPM 说明](/advanced/hardware-root)和仓库 `deploy/linux/TPM.md`。

## macOS 本机预览

macOS 预览不要求完整 Xcode、付费开发者会员或 Secure Enclave。从源码编译需要 Rust 和 Command Line Tools。同一条命令：

```bash
./install.sh
```

加上 `--bootstrap --did-host HOST --target https://...` 可以在同一次运行里用一次性身份创建身份、迁入受保护状态并创建首张 grant；这条路径固定使用 `_anpagent` 和 `--hardware none`。

安装器建立独立账号和 launchd 服务，始终报告 `protected_supported=false`。已有身份或真实密钥不在 `--bootstrap` 范围内，需按 `deploy/macos/AGENT.md` 手动迁入。

整个 Agent 必须在独立的非管理员账号下运行。只切换签名子进程的账号不构成隔离。

重复运行 `./install.sh` 不会改动已安装的实例（退出 0）。换二进制用 `./install.sh --upgrade`，验收用 `--verify`，卸载用 `--uninstall`——它停止 launchd job、删除 `/Library/ANPIOKey/bin/anpio-key` 和 plist，保留 `service.json`、`state/` 和 `_anpio*` 账号，避免身份丢失和 UID 复用。

## 本地开发

```bash
cargo install --path .
anpio-key probe
```

这不会建立服务/管理员/Agent 隔离，只适合临时身份和可信进程。用法见[五分钟跑通](/guide/quickstart)。

## 可选 feature

| feature | 作用 |
|---|---|
| `mcp` | 启用 MCP；v2 用 `mcp --config` |
| `seed-export` | 离线维护用的明文导出；默认不编入，启用后不声明保护支持 |
| `hardware-se` | macOS Secure Enclave 后端；开发签名身份下持久化与主机生命周期已验收，正式分发未完成 |
| `hardware-tpm` | Linux TPM 后端；部署范围已验收，实体芯片保护声明未做 |
| `hardware-software` | 测试替身，不是硬件；release 构建拒绝 |

指定硬件不可用时会报错，不会退回纯软件封装。

## 本地检查

```bash
RUST_LOG=info cargo test --locked --offline
RUST_LOG=info cargo test --locked --offline --features mcp,hardware-software
cargo clippy --locked --offline --all-targets --features mcp,hardware-software -- -D warnings
```

这些是软件回归测试，不能代替多账号、systemd 或实体硬件验收。离线运行要求依赖已经缓存。
