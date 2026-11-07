# Anpio Key

Anpio Key 是一个跑在本机的服务，替 AI Agent 保管 did:wba 私钥，只按管理员签发的许可（grant）签名。私钥不出服务进程，Agent 拿不到，也不能让服务签它没被批准的东西。

- 数据面没有任何读取或导出私钥的操作；默认构建里连 `export-seed` 子命令都不存在。
- 每次签名都要一张 grant：哪把钥匙、哪个操作、什么目标、多久、几次。
- 超出范围、过期、次数用光、被撤销、机器重启，都会拒绝。
- 新增的签名路各自一个开关，默认关；开过哪一路，启动审计里有记录。

## 它解决什么问题

Agent 要代表你访问网站、发消息、建会话，对方用 did:wba 验证签名。把私钥交给 Agent，一次提示注入、一个坏依赖或一条误发的日志就可能把私钥带走。

Anpio Key 把私钥留在本机服务里，Agent 只拿到签名结果。管理员和 Agent 使用不同的系统账号和不同的本地 socket；能签什么由服务端逐次判断，不由 Agent 自己声明。

## 现在能做什么

### Agent 能请求的（数据面）

| 操作 | 用途 | 钥匙角色 | 默认 |
|---|---|---|---|
| `GET_CAPABILITIES` | 能力协商：`operations`、用途、grant 类型 | 无 | 开 |
| `LIST_AUTHORIZED_KEYS` | 当前主体获准使用的钥匙 | 无 | 开 |
| `GET_GRANT_STATUS` | 查 grant 的期限和剩余次数 | 无 | 开 |
| `GET_DOCUMENT` | 取公开 DID 文档 | 无 | 开 |
| `SIGN_HTTP` | RFC 9421 HTTP 请求签名 | `hot` | 开 |
| `GET_REQUEST_STATUS` | 用原 `request_id` 查结果 | 无 | 开 |
| `SIGN_ORIGIN_PROOF` | ANP origin proof（消息、登录等事实） | `hot` | 关 |
| `RENEW_GRANT` | 续 session grant；只延期，不增加次数 | — | 开 |
| `SIGN_PURPOSE` | 设备/应用用途断言 | `device_signing` | 关（逐用途） |
| `ECDH` | X25519 协商，返回共享密钥 | `key_agreement` | 关 |
| `SIGN_OBJECT_PROOF` | W3C `DataIntegrityProof` 对象 proof | `device_signing` | 关 |
| `SIGN_DOCUMENT_PROOF` | DID 文档 proof | `root` | 关 |

基线六个操作永远在 `operations` 里；带“关”的操作只有对应 `features` 开关打开时才出现，关着时发过去是 `OPERATION_DISABLED`。客户端只看 `operations` 里有没有名字，不按版本号猜。

各操作的字段、编码、默认关清单和错误码见 [接入说明 §11](docs/ADAPTER.md)。`ECDH` 是唯一会把秘密交给调用方的操作：共享密钥不落库，同一个 `request_id` 重放拿不到第二次。

### 管理员能做的（管理面）

- **钥匙**：`key create` 生成一把命名钥匙（名字可自取），当场显示一次 24 词，确认抄好后读两遍口令；`key list` 看名字、指纹与解锁状态；`key rotate` 同名换钥；`key unlock` 在人类终端读口令。钥匙不必先有 DID，也没有任何导出路径。
- **身份**：DID、handle、文档与注册由 `anpio-cli did create` 一条命令完成；要让本服务保管钥匙就由管理员在终端加 `--key anpio-key`。坐标脚本 `spec` / `keygen` / `publish` 已隐藏为兼容别名，只用于迁移，`verify-doc` 继续核对文档归属。
- **恢复**：`import-mnemonic` 用一个 24 词助记词恢复 `key-1`（根绑定键）、hot、`{device}-sign`、`{device}-agreement` 四类键；`import-archive` 恢复归档里的单把钥匙。
- **授权**：所有变更走 `prepare` / `commit` 两步，先看 effect、摘要和期限，再提交批准。策略有 v1 和 v2 两种，v2 按 purpose 分字段。
- **解锁**：`admin unlock` 只让指定热钥匙可用；解锁不等于授权，签名仍要 grant。
- **设备入组**：`IssueDeviceKeys` 铸 `{device}-sign` 与 `{device}-agreement`，`ReissueDocument` 把两个公钥写进文档，`EnrollVault` 登记，`ConfirmRole` 确认 `device_signing` 和 `key_agreement`。撤销用 `ReissueDocument` 的 `remove`，两把一起退休。四步顺序不能换，见 [接入说明 §7.4](docs/ADAPTER.md)。
- **轮换与注册**：`RotateHotKey` 轮换热钥匙，`RegistrationChallenge` 完成注册 proof，`add-recovery-key` 预置恢复键，`add-agreement-key` 新增 X25519 协商键。
- **换根**：`e1_` 身份的 DID 就是根公钥的指纹，所以没有“原地换根、DID 不变”的操作。换根就是换身份，步骤见 [接入说明 §7.5](docs/ADAPTER.md)。

`IssueDeviceKeys` 铸的是随机种子，不在助记词里；后铸的设备键只能靠归档带走。助记词恢复出来的是当初 `keygen` 铸的那四把。

### 密钥类别

| 角色 | 是什么 | 能做什么 |
|---|---|---|
| `root` | DID 的绑定键，路径段由它的指纹决定 | 文档重签、设备入组/撤销、注册 proof、`SIGN_DOCUMENT_PROOF` |
| `hot` | 日常签名钥匙 | `SIGN_HTTP`、`SIGN_ORIGIN_PROOF` |
| `device_signing` | 绑定唯一用途的设备键 | `SIGN_PURPOSE`、`SIGN_OBJECT_PROOF` |
| `key_agreement` | X25519 协商键 | `ECDH` |
| `recovery` / `challenge` | 生命周期用的辅助角色 | 管理面操作 |

角色在管理面确认，绑定信封、公钥和文档摘要，改一次就定死。私钥只在解封后驻留服务内存；硬件根（TPM / Secure Enclave）保护的是解封材料，签名仍在服务进程内完成。

## 五分钟试用

这一步走开发模式，所有东西都在你的账号下运行，**不建立安全边界**。需要 Rust 1.88+。

```bash
cargo install --path .
mkdir -p /tmp/keyd-lab
anpio-key --root /tmp/keyd-lab key create --name bot
anpio-key --root /tmp/keyd-lab key list --json   # 记下 thumbprint
```

`key create` 会先在终端显示 24 个词，确认抄好后输入两遍口令，然后打印名字、指纹和公钥。它不建 DID——身份是 `anpio-cli did create` 的事，见下一节。

要让这把钥匙签名，开发模式的守护进程必须显式打开命名签名路：

```bash
anpio-key --root /tmp/keyd-lab serve --development --allow-named-key-signing
```

换一个终端解锁并签名。keyid 里的 DID 段必须带着这把钥匙的指纹：

```bash
anpio-key --root /tmp/keyd-lab key unlock --name bot
anpio-key --root /tmp/keyd-lab sign --key bot \
  --keyid did:wba:example.com:user:mybot:<thumbprint>#key-1 \
  --method GET --url https://service.example.net/orders/42
```

输出是两行签名头：

```http
Signature-Input: sig1=("@method" "@target-uri" "@authority");created=...;expires=...;keyid="did:wba:..."
Signature: sig1=:...:
```

把这两行原样放进 HTTP 请求头，不能改任何一个字符。上面这个 DID 只是让签名头长得对；对方要能查验身份，得先由 `anpio-cli did create` 建出真身份并注册文档。试完关掉：

```bash
anpio-key --root /tmp/keyd-lab stop
```

## 正式安装

Linux 上一条命令装好受保护服务：

```bash
git clone https://github.com/eccstartup/anpio-key.git && cd anpio-key
./install.sh
```

先看计划不改系统：`./install.sh --dry-run`；物理 TPM 加 `--tpm-device`。安装器创建服务、管理员与 Agent 三个系统账号、受保护配置和 systemd 单元，**不生成身份**。

装完之后建身份。DID、handle、文档与注册由 `anpio-cli did create` 一条命令完成，默认钥匙由 CLI 本机保管：

```bash
anpio-cli did create --host awiki.me --handle mybot --email you@example.com
```

要让本机的 `anpio-key` 保管钥匙，由管理员在自己的终端加 `--key anpio-key`：

```bash
anpio-cli did create --host awiki.me --handle mybot --email you@example.com --key anpio-key
```

授权是独立的一步，和受保护命名签名一起启用：`anpio-key grant create --key NAME --did DID --target URL` 打印摘要、确认一次，然后走 `prepare` / `commit`；`anpio-cli key grant <id> --agent <handle>` 把编号记进 store。它只给**已经登记在受保护 catalog 里**的钥匙签 grant（kid 是 `{did}#key-1`），而命名钥匙的登记还没做（见 [TODO](TODO.md)），所以现在跑它会明确报 catalog 里没有这把钥匙。在那之前，受保护部署里的授权签名仍走下面这条老路。

已有身份或钥匙的迁移按[本机使用指南](deploy/LOCAL-USE.md)：`keygen` 生成四把、`migrate-vault` 离线迁入、`EnrollVault` / `ConfirmRole` 登记、发布策略，再建 grant。这条老路仍然是一步式的：

```bash
./install.sh --bootstrap --did-host agents.example.com \
  --target https://api.example.com/v1/status
```

- `--did-host` 是 DID 文档将来发布的域名。
- `--target` 是 Agent 实际要访问的完整 HTTPS 地址，策略里的网站、路径和方法都从它得出。

省略这两项时，脚本会在终端里询问。执行过程中会要求你输入几次口令：绑定钥匙、日常热钥匙、迁入受保护状态和解锁。口令只由 Anpio Key 从你的终端读取，不进入 Agent、命令行参数或环境变量。完成后打印 DID 文档地址、vault、grant 编号、有效期限、root 持有的恢复材料目录，以及一段可以直接交给 Agent 的请求示例。

其他常用选项：

```bash
./install.sh --admin-user operator --agent-user agent-a --agent-user agent-b
./install.sh --tpm-device --bootstrap --did-host agents.example.com \
  --target https://api.example.com/v1/status
./install.sh --dry-run
```

`--method` 可以重复，默认只允许 `GET`；`--body-bytes` 限制请求体大小，`--grant-days` 和 `--max-uses` 限制这张 grant 的有效期和签名次数。指定多个 Agent 账号时，`--bootstrap` 只为第一个账号创建 grant。

macOS 用 `./install.sh` 安装本机预览，始终 `protected_supported=false`；装完同样用 `anpio-cli did create` 建身份。`--bootstrap` 在 macOS 上仍会铸一份一次性预览身份并完成首次解锁；真实身份或已有密钥按[本机使用指南](deploy/LOCAL-USE.md)手动迁入。

手动校验发行包、更新和离线迁移见 [Linux 部署](deploy/linux/README.md)，TPM 见 [TPM 说明](deploy/linux/TPM.md)。

## 接入 Agent

Agent 在自己的系统账号下提交一个请求文件：

```json
{
  "operation": "SIGN_HTTP",
  "grant_id": "管理员给的GRANT_ID",
  "request_id": "每次新操作自己生成的UUID",
  "http": {
    "method": "GET",
    "url": "https://service.example.com/v1/status",
    "headers": {},
    "body": {"state": "absent"},
    "nonce": null
  }
}
```

```bash
anpio-key data --config /etc/anpio-key/service.json --file request.json
```

`grant_id` 决定这次签名能用哪把钥匙、访问哪里、最多几次；`request_id` 是这次操作的唯一编号，发送前先落盘。

返回签名结果后，用返回的 URL、原始 body 和签名头发送请求，并关闭自动重定向。超时或结果不确定时，用同一个 `request_id` 查 `GET_REQUEST_STATUS`，不要换一个新 ID 重签。`completed` 只表示签名结果已持久化，不表示对端业务已经执行。

其他接入方式：

- Rust：`anpio_key::client`；Node 18+：`adapters/anpio-key-v2.mjs`；现有 ANP SDK：`anpioKeyV2Connector`，见[适配器说明](adapters/README.md)。
- MCP：构建时启用 `mcp` feature，Agent 用 `anpio-key mcp --config ...` 启动，只有五个数据面工具。
- 要把一个自己拿私钥签名的工具改成走本服务，用 [anpio-key-integration skill](skills/anpio-key-integration/SKILL.md)；安装和日常操作见 [anpio-key skill](skills/anpio-key/SKILL.md)。

## 安全边界

受保护部署的标志是 `protected_supported=true`，它同时受构建和运行配置约束：

| 环境 | 当前状态 |
|---|---|
| Linux 正式 release + 配置显式 `linux-protected-v1` | `protected_supported=true`，服务、管理员、Agent 三个系统账号 |
| Linux preview、调试构建 | `protected_supported=false`，同 UID 不隔离 |
| macOS 本机预览 | 有独立账号，但不是正式发行，`protected_supported=false` |
| Linux TPM | 部署范围已验收（含进程、权限和内核 vTPM）；实体芯片保护声明未做 |
| macOS Secure Enclave | 开发签名身份下持久 SE 与注销/重启/休眠等主机生命周期已验收；Developer ID 正式分发未完成 |

在受保护部署里，以下前提必须成立：管理员账号可信，root 和内核未被攻破，daemon 程序和配置未被替换，Agent 没有 sudo、宿主 Docker socket 或管理员凭据，整个 Agent 框架都在 Agent 账号下运行。任何一条不成立，都不能套用受保护部署的结论。

不防御的东西：root、内核、daemon 或可信管理端被控制；已经发出去的签名；同账号里的其他程序；历史备份或助记词泄露；对端是否真的执行了业务。

macOS 的 Secure Enclave 依赖图形登录会话。Agent 和任何不应持有 SE 能力的进程必须以非登录 system LaunchDaemon 运行；管理员图形登录会话内（包括 `sudo` 启动）的代码属于受信管理输入。细节见 [SE 会话说明](deploy/macos/SE-SESSION.md)。

## 仓库结构

正式安装只需要 `./install.sh`，其余目录按需查阅：

| 路径 | 是什么 |
|---|---|
| `install.sh` | 唯一的安装入口，按平台分发 |
| `src/`、`tests/` | 服务本体和 Rust 回归测试 |
| `deploy/linux/`、`deploy/macos/` | 安装、更新、迁移和身份接入入口 |
| `deploy/*/acceptance/` | 真机验收工具，要 root，只操作临时实例 |
| `deploy/*/tests/` | 安装器和验收工具的单元测试，不碰主机 |
| `deploy/checkpoints/` | 独立审计采集器 |
| `adapters/` | Node v2 客户端和现有 ANP SDK connector |
| `skills/` | 给 Agent 的安装技能和语言无关的接入规约 |
| `site/` | VitePress 文档站 |
| `docs/` | 接入说明、设计、计划与验收记录 |
| `benches/`、`examples/` | 签名吞吐基线和硬件持久化验收示例 |

`tests/` 与 `acceptance/` 的区别是运行时机，不是重要性：`deploy/*/tests/test_*.py`（下划线）在 CI 里跑，不需要 root，不修改本机状态；`deploy/*/acceptance/` 下的脚本需要 root、真实硬件或一次性容器，按文档人工执行，结果只对当次运行有效。

## 开发与测试

```bash
RUST_LOG=info cargo test --locked --offline
RUST_LOG=info cargo test --locked --offline --features mcp,hardware-software
cargo clippy --locked --offline --all-targets --features mcp,hardware-software -- -D warnings
```

CI 分三块：Linux 多 UID 容器验收、macOS 本机边界预览、独立审计采集器。都只跑临时身份和一次性环境，不触碰真实密钥。更多边界说明见 [设计](docs/DESIGN.md) 和 [测试与验证边界](site/advanced/testing.md)。

## 文档

- [本机使用：先建立边界，再交给 Agent](deploy/LOCAL-USE.md)
- [接入说明：协议、字段、错误码与强对接契约](docs/ADAPTER.md)
- [Linux 部署](deploy/linux/README.md)、[TPM](deploy/linux/TPM.md)
- [macOS 预览](deploy/macos/README.md)、[Secure Enclave](deploy/macos/SE-SESSION.md)
- [安全设计与威胁模型](docs/DESIGN.md)
- [独立审计采集器](deploy/checkpoints/README.md)
- [Node 客户端与 SDK connector](adapters/README.md)
- [给 Agent 的 skill](skills/anpio-key/SKILL.md)、[接入规约 skill](skills/anpio-key-integration/SKILL.md)
- [未完成的发行工作](TODO.md)、[当前计划](docs/plan-security-v6.md)
- 文档站：[anpio-key.vercel.app](https://anpio-key.vercel.app)

## 许可

Apache-2.0。见 [LICENSE](LICENSE)。
