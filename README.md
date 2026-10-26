# Anpio Key

Anpio Key 是一个跑在本机的服务，替你的 AI Agent 保管 did:wba 的 Ed25519 私钥，并只在允许的范围内替它签名 HTTP 请求。

Agent 通过本地 socket 提交请求，拿回签名头。私钥不出服务进程，Agent 也拿不到。

## 它解决什么问题

Agent 要代表你访问网站，网站用 did:wba 验证签名。如果直接把私钥给 Agent，一次提示注入或一个坏依赖就可能把私钥带走。

用 Anpio Key 后：

- 私钥存在本机服务里，Agent 读不到，也不能通过接口取出。
- 你给 Agent 一张许可条（grant）：哪把钥匙、哪个网站和路径、有效期、最多几次。
- 超出范围、过期、次数用光、被你撤销、机器重启，都会拒绝签名。

## 五分钟试用

这一步只让你看效果，所有东西都在你的账号下运行，**不建立安全边界**。需要 Rust 1.88+。

```bash
cargo install --path .
mkdir -p /tmp/keyd-lab
anpio-key --root /tmp/keyd-lab spec \
  --host example.com --path agents/mybot --out /tmp/keyd-lab/mybot.spec.json
anpio-key --root /tmp/keyd-lab keygen --spec /tmp/keyd-lab/mybot.spec.json
```

`keygen` 会让你输入两遍口令，然后打印一个 DID，记下来。

```bash
anpio-key --root /tmp/keyd-lab serve
```

换一个终端，解锁钥匙：

```bash
anpio-key --root /tmp/keyd-lab unlock --did 你的DID
```

签名：

```bash
anpio-key --root /tmp/keyd-lab sign --did 你的DID \
  --method GET --url https://service.example.net/orders/42
```

输出是两行签名头：

```http
Signature-Input: sig1=("@method" "@target-uri" "@authority");created=...;expires=...;keyid="did:wba:..."
Signature: sig1=:...:
```

把这两行原样放进 HTTP 请求头，不能改任何一个字符。试完关掉：

```bash
anpio-key --root /tmp/keyd-lab stop
```

## 正式安装

Linux 上一条命令完成安装、创建身份、发布策略、创建 grant 并解锁：

```bash
git clone https://github.com/eccstartup/anpio-key.git && cd anpio-key
./install.sh --bootstrap --did-host agents.example.com \
  --target https://api.example.com/v1/status
```

- `--did-host` 是 DID 文档将来发布的域名。
- `--target` 是 Agent 实际要访问的完整 HTTPS 地址，策略里的网站、路径和方法都从它得出。

省略这两项时，脚本会在终端里询问。

执行过程中会要求你输入几次口令：绑定钥匙、日常热钥匙、迁入受保护状态和解锁。口令只由 Anpio Key 从你的终端读取，不进入 Agent、命令行参数或环境变量。

完成后打印 DID 文档地址、vault、grant 编号、有效期限、root 持有的恢复材料目录，以及一段可以直接交给 Agent 的请求示例。把 DID 文档上传到打印出的地址，把 grant 编号交给 Agent，它就可以开始签名。

只安装空服务，之后手动初始化：

```bash
./install.sh
```

其他常用选项：

```bash
./install.sh --admin-user operator --agent-user agent-a
./install.sh --tpm-device --bootstrap --did-host agents.example.com \
  --target https://api.example.com/v1/status
./install.sh --dry-run
```

`--method` 可以重复，默认只允许 `GET`；`--body-bytes` 限制请求体大小，`--grant-days` 和 `--max-uses` 限制这张 grant 的有效期和签名次数。指定多个 Agent 账号时，`--bootstrap` 只为第一个账号创建 grant。

macOS 用 `./install.sh` 安装本机预览，始终 `protected_supported=false`；加上 `--bootstrap` 可以在同一条命令里用一次性身份完成身份、授权和首次解锁。真实身份或已有密钥仍按[本机使用指南](deploy/LOCAL-USE.md)手动迁入。

手动校验发行包和更新见 [Linux 部署](deploy/linux/README.md)。

## 仓库结构

正式安装只需要 `./install.sh`，其余目录按需查阅：

| 路径 | 是什么 | 用户需要吗 |
|---|---|---|
| `install.sh` | 唯一的安装入口，按平台分发 | 需要，正式安装只跑它 |
| `src/`、`tests/` | 服务本体和 Rust 回归测试 | 开发时需要 |
| `deploy/linux/`、`deploy/macos/` | 安装、更新、迁移和身份接入入口 | 按对应文档单独执行 |
| `deploy/*/acceptance/` | 真机验收工具，要 root，只操作临时实例 | 只在复核安全边界时用 |
| `deploy/*/tests/` | 安装器和验收工具的单元测试，不碰主机 | CI 自动跑，用户不用管 |

`tests/` 与 `acceptance/` 的区别是运行时机，不是重要性：

- `deploy/*/tests/test_*.py`（下划线）在 CI 里跑，不需要 root，不修改本机状态；
- `deploy/*/acceptance/` 下的脚本需要 root、真实硬件或一次性容器，按文档人工执行，结果只对当次运行有效。

## Agent 怎么用

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

`grant_id` 决定这次签名能用哪把钥匙、访问哪里、最多几次；`request_id` 是这次操作的唯一编号。

返回签名结果后，用返回的 URL、原始 body 和签名头发送请求，并关闭自动重定向。

超时或结果不确定时，用同一个 `request_id` 查询 `GET_REQUEST_STATUS`，不要换一个新 ID 重签。

## 注意事项

- 重启后所有 grant 作废、钥匙重新锁定，需要管理员重新解锁和建权。
- 撤销只阻止新签名，已经发出去的签名收不回来。
- 同一个系统账号里的程序属于同一个主体；只隔离签名子进程不够，整个 Agent 都要在 Agent 账号下运行。
- macOS 的 Secure Enclave 只在图形登录会话内可用：Agent 必须以非登录 system LaunchDaemon 运行；在管理员登录会话里（包括 `sudo` 启动）的代码属于受信管理输入，不按 UID 隔离。
- 管理员、root、内核和 daemon 本身是信任前提。
- macOS 目前只有本机预览，`protected_supported=false`；受保护部署在 Linux。

## 文档

- [本机使用：先建立边界，再交给 Agent](deploy/LOCAL-USE.md)
- [Linux 部署](deploy/linux/README.md)、[TPM](deploy/linux/TPM.md)
- [Agent 接入与 SDK](docs/ADAPTER.md)
- [安全设计与威胁模型](docs/DESIGN.md)
- [macOS 预览](deploy/macos/README.md)、[Secure Enclave](deploy/macos/SE-SESSION.md)
- [独立审计采集器](deploy/checkpoints/README.md)
- [Node 客户端与 SDK connector](adapters/README.md)
- [给 Agent 的 skill](skills/anpio-key/SKILL.md)
- 文档站：[anpio-key.vercel.app](https://anpio-key.vercel.app)

## 许可

Apache-2.0。见 [LICENSE](LICENSE)。
