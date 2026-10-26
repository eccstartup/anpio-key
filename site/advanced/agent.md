# 接到 Agent 上

前提：管理员已经装好服务、登记身份、发布策略、创建 grant 并解锁了热钥匙。Agent 需要知道三样东西：

- 受保护配置的路径，通常是 `/etc/anpio-key/service.json`；
- `grant_id`；
- 自己的系统账号（Agent 账号）。

完整协议和管理变更见仓库 [ADAPTER.md](https://github.com/eccstartup/anpio-key/blob/master/docs/ADAPTER.md)。

## 用 CLI 发请求

Agent 在自己的账号下，把一个请求保存成文件：

```json
{
  "operation": "SIGN_HTTP",
  "grant_id": "管理员给的GRANT_ID",
  "request_id": "6b79d06e-33cf-44e2-8209-81938b6a8ed3",
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

每个新操作要自己生成一个 UUID，并在调用前把它和原始输入保存下来。重试时复用同一个 `request_id`；不要重复使用示例里的 UUID。

其他数据操作：

| 操作 | 用途 |
|---|---|
| `LIST_AUTHORIZED_KEYS` | 看自己当前能用哪些钥匙 |
| `GET_DOCUMENT` | 取某把钥匙的公开文档，需要 `key_id` |
| `GET_GRANT_STATUS` | 查 grant 的期限和剩余次数 |
| `GET_REQUEST_STATUS` | 用原 `request_id` 查签名结果 |

数据接口没有解锁、密码、根签名、任意字节签名或生命周期操作。

## 拿到签名之后

用 daemon 返回的规范化 URL、原始 body 和签名头发送请求，关闭自动重定向。不要重新序列化 body，也不要改签名头里的任何字符。

超时或连接中断时：

1. 用原 `request_id` 查询状态；
2. 不要生成新 ID 重签；
3. `outcome_unknown` 表示结果不确定，可能需要管理员核对；
4. `completed` 只表示签名结果已保存，不表示对方业务已经执行。

## 用 Node

仓库的 [adapters/keyd-v2.mjs](https://github.com/eccstartup/anpio-key/blob/master/adapters/keyd-v2.mjs) 提供 `AnpioKeyV2Client`：

```js
import { randomUUID } from 'node:crypto'
import { AnpioKeyV2Client } from './adapters/anpio-key-v2.mjs'

const client = new AnpioKeyV2Client({
  config: '/etc/anpio-key/service.json',
  binary: '/usr/local/libexec/anpio-key',
})
const request = {
  grant_id: 管理员给的GrantId,
  request_id: randomUUID(),
  method: 'GET',
  url: 'https://service.example.com/v1/status',
}
await saveOperation(request)          // 由你的应用实现
const signed = await client.sign(request)
const response = await fetch(signed.url, {
  method: signed.method,
  headers: signed.headers,
  body: signed.body,
  redirect: 'manual',
})
```

`client.fetch(request)` 把签名和发送合在一起，同样禁用重定向，也不自动重试。

## 用现有 SDK

`anpioKeyV2Connector` 接到 `@connectx-sdk/core` 的 `createConfig` / `signRequest` 上，需要你提供一个稳定的 `requestId` 函数。高层热密钥解析要求 SDK 0.4.2 或更新；更早版本可能错误地要求热钥匙匹配根指纹。

SDK 的 ANP-02 登录体和 awiki 的 JSON-RPC envelope 不是同一种 body。先构造正确的 body 再签名，不能签完再包装。

## 用 MCP

构建时启用 `mcp`，然后由 Agent 账号启动：

```json
{
  "mcpServers": {
    "anpio-key": {
      "command": "/usr/local/libexec/anpio-key",
      "args": ["mcp", "--config", "/etc/anpio-key/service.json"]
    }
  }
}
```

| 工具 | 输入 |
|---|---|
| `list_my_keys` | 空对象 |
| `grant_status` | `grant_id` |
| `get_did_document` | `key_id` |
| `sign_request` | `grant_id`、`request_id`、`http` |
| `request_status` | `request_id` |

配置在启动时固定；工具参数不能改 socket、配置路径、DID 或 kid。口令不经过 MCP。

## 管理员做什么

管理员通过独立的 `admin` 通道：

- `prepare` / `commit`：确认钥匙角色、发布策略、创建或撤销 grant；
- `unlock`：输入口令解锁指定热钥匙；
- `complete-secret-operation`：完成注册 proof 或热钥匙轮换。

注册、轮换和恢复都必须由管理员或可信管理适配器执行，Agent 不能代办。

服务重启后旧 grant 失效、钥匙锁定，需要管理员重新解锁和建权。文档在本地生成，不代表已经发布到网上。

给 Agent 的操作约束见仓库 [skill](https://github.com/eccstartup/anpio-key/tree/master/skills/anpio-key)。
