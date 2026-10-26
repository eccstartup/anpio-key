# 五分钟跑通

这一页是开发模式：所有东西都在你的账号下运行，适合临时身份和联调，**不建立 Agent 隔离**。正式部署见[安装](/guide/install)和[本机使用](/guide/local-use)。

需要 Rust 1.88 或更新。为了不碰你已有的钥匙，全程放到 `/tmp/keyd-lab`：

```bash
cargo install --path .
mkdir -p /tmp/keyd-lab
export KEYD="anpio-key --root /tmp/keyd-lab"
```

## 1. 写下身份放在哪里

DID 由域名、路径和公钥算出来。先写一份规格文件：

```bash
$KEYD spec --host example.com --path agents/mybot --out /tmp/keyd-lab/mybot.spec.json
```

内容就是：

```json
{
  "host": "example.com",
  "path": "agents/mybot"
}
```

可以在这份文件里加 `services`、`agentDescriptionUrl` 等条目。拼错的字段会被拒绝，不会被忽略。域名必须是域名，不能是 IP。

## 2. 生成钥匙

```bash
$KEYD keygen --spec /tmp/keyd-lab/mybot.spec.json
```

它会让你输入两遍口令，然后打印 DID。记下这个 DID，后面每一步都要用。

口令从终端读取，不进命令行参数，也不进环境变量。生成的私钥用口令和 `device.secret` 加密后存在 `/tmp/keyd-lab` 下。

## 3. 生成公开文档

```bash
$KEYD publish --did 你的DID
```

再输入一次口令。工具会生成 `did.json` 并签上 proof，同时告诉你这个文件应该发布到哪个网址：

```text
https://example.com/agents/mybot/.../did.json
```

工具不负责托管文件。这个网址必须能返回这份 `did.json`，验证方才能查到你的公钥。

## 4. 启动服务

```bash
$KEYD serve
```

命令会马上返回，服务在后台运行，默认 socket 是 `~/.anpio-key/run/keyd.sock`（用了 `--root` 时在对应目录下）。它会打印 pid 和停止方法。

想让它占住当前终端，加 `--foreground`；systemd、launchd 这类服务管理器要用这个参数。

## 5. 解锁

换一个终端：

```bash
$KEYD unlock --did 你的DID
```

输入口令。钥匙只在内存里，默认 15 分钟不用就自动锁上（`serve --idle SECS` 可调）。上锁是正常状态，不是故障。

## 6. 签名

```bash
$KEYD sign --did 你的DID \
  --method GET \
  --url https://service.example.net/orders/42
```

标准输出是签名头：

```http
Signature-Input: sig1=("@method" "@target-uri" "@authority");created=...;expires=...;keyid="did:wba:..."
Signature: sig1=:...:
```

原样放进 HTTP 请求头，不要解析、重排或补引号。

带 body 时：

```bash
$KEYD sign --did 你的DID --method POST --url https://service.example.net/orders \
  --header 'content-type: application/json' \
  --body request.json
```

body 的 `content-digest` 由服务自己计算，请求里自带的同名头会被忽略。

如果服务要求签名里的 nonce 和 body 里的值一致，由调用方传入：

```bash
$KEYD sign --did 你的DID --method POST --url https://service.example.net/orders \
  --header 'content-type: application/json' \
  --body request.json \
  --nonce "$(jq -r .nonce request.json)"
```

不传 `--nonce` 时，上游会随机生成一个；签名里的 nonce 和请求体无关，不能用于“两处同值”的防重放流程。

## 7. 取回公开文档

Agent 需要把 `did.json` 交给对端时，可以不解锁直接取：

```bash
$KEYD document --did 你的DID
```

输出是磁盘上那份文档的原文，逐字节返回。它只能取本机发布过的 DID。

## 8. 收工

```bash
$KEYD lock --did 你的DID
$KEYD stop
```

## 下一步

- [安装](/guide/install)：部署到 Linux，建立真正的账号边界。
- [接到 Agent 上](/advanced/agent)：CLI、Node、SDK、MCP。
- [命令行](/reference/commands)：完整命令列表。
