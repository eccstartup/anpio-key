# Anpio Key v2 接入说明

本文面向 CLI、MCP、Node 和 ANP SDK 的接入者，描述当前接口、调用顺序及失败恢复。架构与威胁模型见 [DESIGN](DESIGN.md)。旧开发协议不作为受保护接入路径。

## 1. 接入结果与兼容范围

接入后，Agent 保存公开身份信息、授权引用和请求状态，通过本地 daemon 请求签名，不加载长期私钥。管理员负责身份迁入、密钥角色、解锁、策略、grant 和轮换；Agent 获得的权限由服务端逐次执行。

| 接入方式 | 当前能力 | 边界 |
|---|---|---|
| Rust CLI `data` | 全部 v2 数据操作，认证 daemon，不自动重试 | Linux，读取受保护配置 |
| Node `AnpioKeyV2Client` | 列钥、文档、授权/请求查询、结构化签名及 fetch | 调用 Rust CLI；Node 18+；body/URL 形态有限制 |
| `anpioKeyV2Signer` | `signHttpRequest` 接缝 | 调用方负责稳定 request_id、发送与业务恢复 |
| `anpioKeyV2Connector` | 现有 SDK createConfig/signRequest 接缝 | 生成 ANP-02 登录体；不接生命周期和注册挑战 |
| 受保护 MCP | 五个 v2 授权工具 | 启动时固定 config，工具参数无密码或端点覆盖 |
| 外部 SDK 高层热密钥解析 | `@connectx-sdk/core` 0.4.2 起兼容 | 更早版本仍不兼容；最低兼容版本 0.4.2 |
| awiki JSON-RPC | Node v2 client 可按实际 RPC body 签名 | SDK 原生 ANP-02 body 不能直接当作 RPC envelope |

awiki-cli-rs2 的 Rust 侧（`IdentitySigner`）**没有适配器**，今天能对上的只有结构化那两条：`http_signature_headers` ↔ `SIGN` 的 `Structured` 变体，`did_document`/`optional_did_document` ↔ `GET_DOCUMENT`。`sign_device_assertion` 从 P2 起有对应操作 `SIGN_PURPOSE`（每用途一个开关，默认关，见 §11.3/§11.7）；其余接缝仍没有对应能力：`sign`/`sign_root` 只能落到默认关闭的 `Raw` 或 `Challenge`；`sign_object_proof`/`sign_document_proof` 在 socket 上没有请求类型（`REQUEST_TYPES` 不含）；`ecdh` 要 `keyAgreement` 的 X25519 私钥，本工具只造 Ed25519，进程里也没有这条协议路径。登录/RPC 签名可以走 CLI 接缝，端到端加密那半接不了。补齐这些缺口的接口形状已冻结在 §11：P1 的两条（`SIGN_ORIGIN_PROOF`、`RENEW_GRANT`）与 P2 的 `SIGN_PURPOSE` 已经实现，其余仍在规划。

正式 Linux release 且配置显式为 `linux-protected-v1` 时支持保护声明。调试、preview、macOS、软件硬件替身及 seed-export 不在声明内。同 UID 不受限 Agent 之间没有隔离。

## 2. 管理端与 Agent 分工

```text
可信管理员：准备身份/热密钥 → 迁入并登记 → 确认角色 → 发布策略
          → 解锁 hot key → 创建 grant → 交付公开引用

隔离 Agent：列出可用 key → 按需读取公开文档 → 保存请求及 UUID
          → 请求签名 → 发送原始字节 → 保存服务响应

可信管理员：撤销 / 轮换 / 恢复 / 发布并验证 DID 文档
```

管理员通过 `/etc/anpio-key/service.json` 中的独立管理端点操作；Agent 在独立 UID 下通过签名端点操作。配置、程序、socket 父目录和存储不可被 Agent 修改。不要以 root 或管理员 UID 启动不可信 Agent。

安装器与迁移器位于 `deploy/linux/`。安装 release 需要管理员核对并提供 `--sha256`。本文的运行期示例假定服务已经安装并启动。

### 2.1 管理准备示例

以下文件均为公开管理变更，UUID 占位符须替换为真实 catalog/主体记录；策略中的 URL 也须与业务目标一致。密码不写入 JSON。

管理员先查看登记结果：

```sh
anpio-key admin --config /etc/anpio-key/service.json list-principals
anpio-key admin --config /etc/anpio-key/service.json catalog
```

迁入 vault 的密钥初始为 unclassified。准备角色确认 `role.json`：

```json
{"kind":"Catalog","change":{"action":"ConfirmRole","key_id":"HOT_KEY_UUID","role":"hot"}}
```

设备签名键在确认角色时**同时**绑定唯一用途，之后改不了：

```json
{"kind":"Catalog","change":{"action":"ConfirmRole","key_id":"DEVICE_KEY_UUID","role":"device_signing","purpose":"device_assertion"}}
```

对每个管理变更使用两步；检查返回的 `prepared.effect`、摘要及期限，再提交该次批准：

```sh
anpio-key admin --config /etc/anpio-key/service.json prepare --file role.json
anpio-key admin --config /etc/anpio-key/service.json commit \
  --operation-id PREPARED_OPERATION_UUID --digest PREPARED_DIGEST
```

根绑定钥匙不能被确认成 hot。并发管理变更、过期或重启可能使批准失效，此时重新 prepare；不能复用旧摘要提交另一份内容。

策略变更 `policy.json` 的实际结构如下：

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

同样 prepare/commit 发布。policy 版本不可变，后续修改须使用连续新版本。`origin` 使用小写 DNS host，不写默认 `:443`；路径精确匹配。query 可为 `{"mode":"none"}` 或 `{"mode":"exact","value":"page=1"}`。body 可为 empty 或 bounded，bounded 要求显式 present，即使字节为空。

创建 grant 的 `grant.json`：

```json
{
  "kind": "Grant",
  "change": {
    "action": "Create",
    "principal_id": "AGENT_PRINCIPAL_UUID",
    "key_id": "HOT_KEY_UUID",
    "policy_id": "POLICY_UUID",
    "policy_version": 1,
    "expiry": 0,
    "max_uses": 10
  }
}
```

**`expiry: 0` 必须在执行前替换为未来 Unix 秒数**，且剩余期限不超过策略的 `max_duration_seconds` 上限；0 不表示永久有效。提交后使用返回 effect 中的 grant_id，不能把 key_id 当作 grant_id。grant 绑定 exact key 和 principal，不能转交给另一个 UID 使用。

管理员通过受认证通道解锁指定 hot key：

```sh
anpio-key admin --config /etc/anpio-key/service.json unlock \
  --vault-id VAULT_UUID --did DID --kid FULL_KID
```

口令由管理 CLI 在终端读取，并在验证 daemon 后通过独立秘密帧发送；不经过 MCP。TTY 限制不构成身份认证。密钥未解锁也可以存在 grant，但签名会失败；预留后才发现锁定会消费次数，因此应先确认可用状态再交给 Agent。

## 3. CLI 与线协议

### 3.1 CLI 请求

`data --file` 接收一个 **DataRequest 对象**，无需手工添加 version/request 包装。以获准 Agent UID 执行：

```sh
anpio-key data --config /etc/anpio-key/service.json --file request.json
```

请求文件示例：

```json
{
  "operation": "SIGN_HTTP",
  "grant_id": "ADMIN_SUPPLIED_GRANT_ID",
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

示例 UUID 只用于展示格式。应用为每个新操作生成 UUID 并持久保存；重试复用原 ID。若业务需要服务端 nonce，先从对端取得，并按应用协议同时放入 body 和签名参数。

| 操作 | 字段 | 结果 `reply.data` |
|---|---|---|
| GET_CAPABILITIES | 无 | profile、body 上限、事务执行器与审计投影健康信息 |
| LIST_AUTHORIZED_KEYS | 无 | `{keys:[{key_id,did,kid}]}`，仅本主体当前获准的钥匙 |
| GET_GRANT_STATUS | grant_id | 授权状态、期限与次数 |
| GET_DOCUMENT | key_id | `{key_id,document}`，仅当前获准 key 的公开文档 |
| SIGN_HTTP | grant_id、request_id、http | 请求状态；有效 completed 结果含签名头等 |
| GET_REQUEST_STATUS | request_id | 本主体已有请求状态；满足条件时附原结果 |

成功 CLI 回复是 version=2、code=OK 的 Reply，业务数据在 data 中；读取 instance_id、principal_id 等信息时不要把它们当作客户端自选参数。`signing_available=true` 表示执行器未停止，不保证某把钥匙已解锁或 grant 可用。

### 3.2 原生 socket 实现

直接实现客户端时，每帧为 4 字节大端长度加 UTF-8 JSON，长度为 1–65536 字节。请求包装为：

```json
{"version":2,"request":{"operation":"GET_CAPABILITIES"}}
```

客户端必须先加载并验证受保护配置、校验 socket 及内核服务 UID，再发请求；只实现 JSON 编解码不足以实现可信客户端。每连接一请求，无自动重连或 v1 降级。未知字段、重复 JSON 成员、越界及未知版本拒绝。

接口定义见 `src/security/protocol.rs`，服务端认证见 `src/security/client.rs`。普通数据面不存在 UNLOCK、LOCK_ALL、SIGN_RAW、SIGN_CHALLENGE 或生命周期操作。

## 4. HTTP 字节和发送规则

签名对“最终发送的请求”负责。应用先确定 URL、方法、body 的准确字节和必需头，再请求签名；不要签完后交由另一层重新序列化 JSON、添加换行或包装 RPC。

- URL 只接受当前支持的 HTTPS DNS 子集；host 小写、默认端口规范化。拒绝 IP、百分号编码、fragment、点路径、重复斜线及重复 query 键。发送使用返回的规范化 URL。
- headers 使用名称到字符串的映射；大小写重复名称拒绝。Host、Authorization、Signature、Signature-Input、Content-Length、Transfer-Encoding、Connection 不可由调用方在签名请求中指定。
- body 必须显式 absent，或 present 加字节数组。present 空数组是明确的空请求体，并覆盖 Content-Digest。body 最多 16384 字节；JSON 字节数组会膨胀，仍受 65536 字节整帧上限约束。
- profile 固定覆盖方法、目标 URI、authority，以及存在的 body 摘要和 content-type。不能传入 covered、did、kid 或任意 profile 覆盖参数。
- 最终请求使用 daemon 返回的生成头及被覆盖的 content-type，保留原始 body 字节；其余应用头由调用方管理，不应假设都被签名或持久化。
- 禁用自动重定向。新目标需要独立检查策略和签名，不能复用旧签名头跨目标发送。

签名最长 300 秒，且不能超过 grant 的双时钟有效窗口。对端仍须检查签名、公钥用途、body 摘要、预期 nonce 与重放状态。业务成功须依据对端响应判断，本地 completed 只表示签名结果持久化。

## 5. Node 客户端

实现文件为 [adapters/keyd-v2.mjs](../adapters/keyd-v2.mjs)。它通过 execFile 调用 Rust CLI，让配置/路径/服务身份检查集中在一个实现里；临时请求文件权限为 0600，finally 删除。请求可能包含业务秘密，Agent 的本地请求存储和日志仍需自身保护。

```js
// 将导入路径改为部署后的实际位置。
import { randomUUID } from 'node:crypto'
import { AnpioKeyV2Client } from './adapters/anpio-key-v2.mjs'

const client = new AnpioKeyV2Client({
  config: '/etc/anpio-key/service.json',
  binary: '/usr/local/libexec/anpio-key',
})
const request = {
  grant_id: administratorSuppliedGrantId,
  request_id: randomUUID(),
  method: 'GET',
  url: 'https://service.example.com/v1/status',
}
// 持久化此对象和操作状态后再调用；该函数由应用实现。
await saveOperation(request)
const signed = await client.sign(request)
const response = await fetch(signed.url, {
  method: signed.method,
  headers: signed.headers,
  body: signed.body,
  redirect: 'manual',
})
```

`client.fetch(request)` 合并上述签名和发送步骤，也禁用重定向；它不持久化业务状态、不自动重试。`keys()`、`document(key_id)`、`grant(grant_id)`、`status(request_id)` 返回解包后的 data。`sign` 成功时返回签名结果并合并调用方头、method 和原 body；durable result 不保存原 body，恢复发送必须从应用自己的记录取得相同字节。

构造参数允许选择 config/binary，部署方须固定到管理员批准的文件，不从模型工具参数或远端服务输入获得。Node 的超时或子进程错误可能发生在服务已经签名之后，不能理解为未消费额度。

## 6. 现有 ANP SDK connector

```js
import { createConfig, signRequest, subjectOf } from '@connectx-sdk/core'
import { AnpioKeyV2Client, anpioKeyV2Connector } from './adapters/anpio-key-v2.mjs'

const client = new AnpioKeyV2Client()
const connector = anpioKeyV2Connector({
  client,
  grant_id: administratorSuppliedGrantId,
  key_id: administratorSuppliedExactKeyId,
  subjectOf,
  requestId: req => durableRequestIdForThisExactPayload(req),
})
const config = createConfig([connector])
const signed = await signRequest(config, connector.id, {
  method: 'POST',
  url: canonicalLoginUrl,
  nonce: serverNonce,
})
```

`durableRequestIdForThisExactPayload` 由应用实现，必须在调用前持久化操作关联，不能每调用一次就生成新 ID。它需要区分最终 body、nonce、目标及身份文档版本；同一高层调用若读到了更新文档，旧 ID 应冲突而非静默重新签名。SDK 传输层也要保持相同 URL/body 并禁用自动重定向。

connector 从已授权列表选定 exact key，读取公开文档，构造 ANP-02 JSON 登录体并签名。successorDid 等生命周期请求拒绝。若 daemon 返回 URL 与 SDK 请求 URL 不同，connector 在签名后拒绝交付；此时必须查询原 ID，不能直接改 URL 换 ID 再试。

### 6.1 SDK 版本与热密钥解析

高层热密钥解析要求 `@connectx-sdk/core` 0.4.2 或更新。DID 指纹绑定根 proof，活动根签署文档通过 exact authentication 方法授权热密钥。缺少可信 proof 的路径保持直接指纹检查，退役文档不获得新增委托能力。更早的 SDK 版本仍会拒绝合法 hot key，没有 root-key 回退。

awiki did-auth RPC 要求 JSON-RPC envelope，SDK signRequest 生成的 ANP-02 `{nonce,did,didDocument,...}` 是另一种 body。已签 body 不能再包装成 RPC；awiki 链路使用同一 v2 client 对正确 RPC 字节请求签名。

### 6.2 其他 SDK 接缝

`anpioKeyV2Signer(client, grant_id)` 只包装 `signHttpRequest(input)`，不会增加注册、文档 proof 或密钥导出能力。接入其他 IdentitySigner 接口时应逐个核对方法；需要“签调用方提供的任意文档”的接口不能直接映射数据面。awiki-cli-rs2 的全部命令或其他外部工具没有全部完成 v2 接入。

## 7. 注册、轮换、撤销与恢复

### 7.1 注册挑战走可信管理端

可信适配器负责从正确 TLS 服务获取挑战并确认 origin。准备的公开变更为：

```json
{
  "kind": "RegistrationChallenge",
  "key_id": "ROOT_KEY_UUID",
  "origin": "https://service.example.com",
  "challenge": "0123456789abcdef0123456789abcdef"
}
```

challenge 必须替换为服务实际给出的 32 位小写 hex 字符串。管理员 prepare 后查看 effect，再使用：

```sh
anpio-key admin --config /etc/anpio-key/service.json complete-secret-operation \
  --operation-id PREPARED_OPERATION_UUID --digest PREPARED_DIGEST
```

CLI 读取管理口令，daemon 单次、短期、精确绑定地完成根签名，用后销毁根密钥。管理适配器把结果提交给原服务；数据面和 MCP 无 challenge 工具。若服务运行期不接受 hot key，报告兼容失败，不自动以 root 或 raw 签名兜底。

### 7.2 热密钥轮换

管理员提前配置下一把合法 hot key，准备 `RotateHotKey`，字段为 root_key_id、old_key_id、next_key_id；使用 complete-secret-operation 完成根签署文档。操作撤销旧授权并退休旧公开方法，但不自动向网络发布。

可信发布者发布返回文档并确认远端可解析、旧方法被拒、新方法认证通过，再创建并交付新 grant。本地文件生成、服务端文档刷新和运行期授权切换是三件事。

### 7.3 撤销与重启

撤销变更为 `{"kind":"Grant","change":{"action":"Revoke","grant_id":"GRANT_ID"}}`，通过 prepare/commit 执行。确认后不开始新的获准签名；此前结果不能追回，远端业务撤销取决于验证方。

重启后所有旧 grant 失效、密钥锁定、未决批准失效。Agent 应暂停工作，等待管理员重新解锁及建权；不能从本地文件恢复旧 active 标记。备份恢复还需验证真实认证、旧权限失效和公开文档状态，文件解密成功只是其中一步。

## 8. 失败和重试处理

服务端错误、CLI 失败和网络错误是不同层。Rust client 将非 OK code 返回为错误；当前 Node 包装器的 CLI 失败可能表现为子进程异常，不能保证错误对象含独立稳定 code。生产集成应保留原 request_id，并用状态查询判断已发生的事，避免仅凭错误文案分类。

| 观察结果 | 处理 |
|---|---|
| REQUEST_ID_CONFLICT | 停止；核对原始 grant、规范化输入和持久操作记录，不能覆盖旧 ID |
| completed 且含 result | 在仍有效时可复用原签名；是否重发网络请求还取决于业务幂等和 nonce |
| completed 但无 result | 结果已不可交付；状态不授权重新签名 |
| reserved / outcome_unknown | 不自动换 ID 重签；查询、检查审计和业务服务状态，必要时交管理端处置 |
| failed_reserved / KEY_LOCKED | 预留可能已消费次数；先查状态，解锁不会使旧 ID 重新签名 |
| GRANT_INVALID / EXPIRED / EXHAUSTED、角色或策略拒绝 | 停止该操作，查询授权或请求管理员按新范围建权 |
| RESOURCE_BUSY / 连接失败 / 超时 | 查询原 ID；只有核清预留状态才考虑再次提交同一操作，绝不自动生成新 ID |
| AUDIT_UNAVAILABLE / PERSISTENCE_UNAVAILABLE | 服务可能已停止签名；管理员检查状态，不能自动建空库或重写审计 |
| REQUEST_NOT_FOUND | 该主体没有可查询记录；仍须考虑原连接是否在途和远端业务状态，重试也保留原 ID |

同一个 request_id 的摘要包含方法、规范化 URL、headers、body 和 nonce；改变未覆盖的普通请求头也可能造成冲突。保存最终待签输入，不仅保存业务参数。

`GET_REQUEST_STATUS` 只查询本主体。查询返回 completed 也不能证明服务请求已发送；网络响应丢失时，还需业务服务的幂等键或查询接口。签名去重不提供业务 exactly-once。

## 9. MCP 接入

编译启用 mcp feature 后，在 Agent 所属执行域启动：

```sh
anpio-key mcp --config /etc/anpio-key/service.json
```

受保护工具只有以下五个，均调用同一个 v2 数据客户端：

| 工具 | 输入 |
|---|---|
| list_my_keys | 空对象 |
| grant_status | grant_id |
| get_did_document | key_id |
| sign_request | grant_id、request_id、http |
| request_status | request_id |

工具返回文本 JSON，其内容是完整 Reply，业务结果仍在 data 中。工具不解锁、不批准 grant、不生成根签名，参数不能覆盖 config/socket/root/did/kid/covered。stdout 用于 MCP 协议，诊断走 stderr。

不带 `--config` 的旧 MCP 是开发路径，不能当作自动降级；两种模式必须明确选择。

## 10. 接入验收

验收使用临时身份、独立 Agent/管理员 UID 和隔离服务，不操作真实用户密钥。

1. 正常链路能完成列钥、读文档、hot 签名和实际服务验签；Agent 进程不加载 seed。
2. 停掉或锁定 daemon 后调用失败，不回退本地私钥、root、raw 或 v1。
3. A/B 使用同一程序仍不能互用 grant；PTY 启动管理 CLI 仍被拒，假 socket 不取得秘密。
4. 方法、URL、body、必签头改变时策略与签名一致；对端拒绝重放、过期及换 body。
5. 并发最后一次配额仅成功预留一次；同 ID 同输入不重复签，不同输入冲突。
6. 响应丢失后查询原 ID；撤销和重启后不交付失效结果、不复活授权。
7. 注册、轮换、远端发布、新方法认证和恢复分别有证据。

现有脚本包括 `deploy/linux/test-boundary.py`、`anp-service-acceptance.py`、`systemd-checks.py`、`systemd-boot-check.py` 及 `adapters/test-sdk.mjs`。后者是实际环境验收驱动，需要 SDK dist、有效 grant/key 和稳定请求 ID，不是无需部署的单元测试。

新增对端、SDK 版本、平台或策略形态时重新验证相应路径，不能沿用历史记录扩大支持范围。

## 11. 强对接契约（P1、P2 已实现，P3–P5 规划中）

本节冻结与 awiki-cli-rs2、anpio-cli 强对接的接口形状。**P1 已实现**：`SIGN_ORIGIN_PROOF`、`RENEW_GRANT`、session grant、策略 v2、能力协商；**P2 已实现**：`device_signing` 角色与 `SIGN_PURPOSE`（每用途一个开关）。P3–P5 的部分仍只有形状。每阶段结束更新本节的状态列和 §1 的兼容表。已冻结的名字、字节和版本号不再改；新增能力只能追加新名字。

### 11.1 三层接口

| 层 | 形态 | 用途 |
|---|---|---|
| Rust 库 `anpio_key::client` | 同步方法 + 错误按形态分类 | 进程内调用，不经过子进程 |
| JSON socket v2 | §3.2 的帧格式，新增操作进 `DataRequest` | 跨语言真源；`VERSION` 保持 2 |
| CLI `--json` | 同名子命令 | 子进程形态的调用方（`anpio-cli` 今天走这条） |

三层共享同一份字段名和错误码。现有 `document`/`sign` 的参数与输出逐字节不变。连接模型仍是**每连接一个请求**，客户端不得缓存复用；若将来加会话复用，以 `GET_CAPABILITIES` 的新字段宣告，不靠协议版本推断。

### 11.2 能力协商

`GET_CAPABILITIES` 的 `data` 追加四个字段，现有五个字段不动。下面是一个打开了 `features.sign_origin_proof` 的服务端的实际应答：

```json
{"capability_schema":1,
 "operations":["GET_CAPABILITIES","LIST_AUTHORIZED_KEYS","GET_GRANT_STATUS","GET_DOCUMENT","SIGN_HTTP","GET_REQUEST_STATUS","SIGN_ORIGIN_PROOF","RENEW_GRANT","SIGN_PURPOSE"],
 "purposes":["http-authentication","origin-proof","purpose-signing"],
 "signing_purposes":["device_assertion"],
 "grant_kinds":["request","session"]}
```

`capability_schema` 是这组字段自己的版本。`operations` 里必有基线六个和 `RENEW_GRANT`；`SIGN_ORIGIN_PROOF` 只在开关打开时出现（关着时发这个操作会收到 `OPERATION_DISABLED`）。P3–P5 的操作按阶段追加。客户端按 `operations` 里有没有某个名字决定能不能用，不按 `protocol_version` 或构建版本猜；名字不在列表里就是该项不支持，不能降级到别的操作。列表只增不减。

`signing_purposes` 是 `SIGN_PURPOSE` 的细分开关（P2 起）：只有列出来的用途能签，没列的用途发过去就是 `OPERATION_DISABLED`（用途名本身不认识则是 `PURPOSE_INVALID`）。它和 `purposes` 不是一回事：后者是策略的 purpose，前者是一次 `SIGN_PURPOSE` 的用途标签。

`RENEW_GRANT` 与 session grant 不是签名路，不受开关控制，所以总在列表里；能不能真用还取决于手上那条 grant 是不是 session 类型（§11.4）。

### 11.3 新增数据面操作

二进制字段（payload、peer 公钥、signature、共享密钥）在新操作里一律**小写 hex**；`http.body` 保持现有字节数组形状不变。

| 操作 | 输入 | 输出 `reply.data` | 状态 |
|---|---|---|---|
| `SIGN_ORIGIN_PROOF` | `grant_id`、`request_id`、`origin` = `{method, meta, body, expires?, nonce?}` | `{request_id, content_digest, signature_input, signature, created, expires}` | P1 已实现 |
| `RENEW_GRANT` | `grant_id`、`expiry` | 续期后的完整 grant（含新的 `expiry`、`renewals`） | P1 已实现 |
| `SIGN_PURPOSE` | `grant_id`、`request_id`、`purpose`、`domain`（只有 `application_assertion` 给）、`payload`（hex，≤4096 字节） | `{request_id, signature, public_multibase, purpose}` | P2 已实现 |
| `SIGN_OBJECT_PROOF` | `value`（对象）、`proof_purpose` | `{proof}`（整份带 proof 的对象） | P5 |
| `SIGN_DOCUMENT_PROOF` | 完整文档、`proof_purpose` | `{document}` | P5 |
| `ECDH` | `peer`（32 字节 hex X25519 公钥） | `{shared_secret, peer_fingerprint}` | P3 |

`SIGN_ORIGIN_PROOF` 的待签事实是 `{method, meta, body}` 这个对象，**不是**一条 HTTP 请求：没有 URL、没有 header，逻辑目标 URI 由 `meta.target.{kind,did}` 决定（`kind` ∈ `agent`/`group`/`service`）。`created` 一律用 daemon 的钟；`expires` 可省，给了就必须落在 300 秒内。签名基、`signature_input`、`signature` 全由 daemon 拼，调用方只给事实，不能覆盖 `did`/`kid`/`key_id`/`signature_profile`。`expires` 在没给时就是 `null`。

`SIGN_ORIGIN_PROOF` 与 `SIGN_HTTP` 共用一套 request_id 去重：同一个 ID 换了操作或换了输入一律 `REQUEST_ID_CONFLICT`，不是缓存命中。origin proof 的结果墓碑和 HTTP 一样永久保留，不随结果裁剪而清掉。

`SIGN_PURPOSE` 是设备断言：签的是调用方给的字节，没有任何 daemon 自己拼的签名基。唯一的例外是 `application_assertion`——上游 `anp_identity` 在这一步给载荷加了一段域前缀（`anp.identity.application-assertion.v1\0` + u16 BE 域长 + 域 + payload），daemon 必须逐字节照做，客户端按同样的规则验签。`device_assertion` 不加任何前缀，`domain` 也不许给。`purpose` 取值只有 `device_assertion`、`application_assertion`；请求签名不在这里，走 `SIGN_HTTP` / `SIGN_ORIGIN_PROOF`。

`SIGN_OBJECT_PROOF`/`SIGN_DOCUMENT_PROOF` 只接受 `id == did`、`verificationMethod == kid` 的输入，cryptosuite 固定，不接受调用方指定。

`ECDH` 是**唯一一个把秘密输出给调用方的操作**：单次、短到期、grant 内绑定 peer 白名单；审计记 `peer_fingerprint` 和 grant，**不记共享密钥**。没有 grant 的 `ECDH` 直接拒绝，不存在"只查公钥不协商"的路径。

### 11.4 授权模型

- **request grant**：一个 grant 一条请求，`max_uses` 通常很小；`max_renewals` 恒为 0，续期一律拒绝（`GRANT_INVALID`）。管理层用 `Catalog`/`Grant` 的 `Create` 变体创建。
- **session grant**（P1 已实现）：管理平面用同一个 `Grant` 变更的 `CreateSession` 动作创建，绑定 principal + 一把 `key_id` + 一个 `(policy, operation)` + `max_uses` + 绝对寿命上限。IM 每条消息一次 origin proof，靠它而不是靠管理员反复建权。`max_renewals` 取自策略，**不能由调用方指定**。
  - `RENEW_GRANT` 只能把到期日往上顶：实际写入的是 `min(请求的 expiry, now + max_duration_seconds, created_at + max_lifetime_seconds)` 三者的最小值。请求的 expiry 不大于当前到期日就是拒绝（`GRANT_INVALID`），不会"续短"。
  - 续期次数用尽返回 `GRANT_RENEWALS_EXHAUSTED`；已过期、已撤销的 grant 不能续。
  - 不能抬高 `max_uses`、不能换 key、不能跨 `boot_epoch`。
  - 每次续期落一条 `GRANT_RENEWED` 审计；session grant 的创建另有一条 `GRANT_CREATED`（request grant 不重复记，创建已在管理操作的审计里）。

grant 的构造、撤销和查看仍在管理平面（§2.1 的 prepare/commit），数据面只新增续期。

### 11.5 密钥、角色与算法字节

`KeyAlgorithm` 的线字节一次定死：`0x01` Ed25519、`0x02` P256、`0x03` **X25519**（冻结，P3 之前没有生产者）。X25519 公钥的 multikey 头是 `0xec01`，thumbprint 仍走 RFC 7638。

catalog 角色追加 `device_signing`、`key_agreement`（现有五个不变）。操作到角色的放行表：

| 操作 | 允许的角色 |
|---|---|
| `SIGN_HTTP`、`SIGN_ORIGIN_PROOF` | `hot` |
| `SIGN_PURPOSE`、`SIGN_OBJECT_PROOF` | `device_signing` |
| `SIGN_DOCUMENT_PROOF` | `root`，grant 只能由管理平面创建 |
| `ECDH` | `key_agreement` |

`SIGN_PURPOSE` 本质是签名 oracle，所以**一个 purpose 一把专用键**，注册时绑定，事后改不了；开关不塞进 `SigningGates`，也不占 legacy `REQUEST_TYPES`。

绑定发生在管理平面的 `Catalog` → `ConfirmRole`：`device_signing` 必须同时给 `purpose`（`device_assertion` 或 `application_assertion`），其余角色必须留空；DID 文档里这把键要同时挂在 `authentication` 和 `assertionMethod` 下，否则拒绝。绑一次就定死：同一把键再确认成另一个 purpose 会失败，`hot`↔`device_signing` 互相改也失败（要换就换键）。`SIGN_PURPOSE` 只认 grant 上那把键，而且要求请求里的 `purpose` 和绑定的那个逐字相等——策略里的 `purposes` 只在绑定之后再做一次收窄，不能让一把键顶两个用途。存储层从 schema 4 升到 5 时重建 `keys` 表加 `purpose` 列（默认空串），既有的 grant 和 FK 原样保留。

策略 v2（P1 起）：

```json
{"schema_version":2,"name":"im-origin-proof-review","purpose":"origin-proof",
 "limits":{"max_duration_seconds":900,"max_uses":1000,
           "max_lifetime_seconds":86400,"max_renewals":16},
 "content":{"origin":"anp://agent",
            "methods":["direct.send"],
            "paths":["/did%3Awba%3Aexample.com%3Ausers%3Aalice"],
            "body":{"mode":"bounded","max_bytes":8192}}}
```

`limits` 有硬边界：`max_duration_seconds > 0`、`max_uses > 0`、`max_lifetime_seconds ≥ max_duration_seconds` 且不超过 365 天、`max_renewals ≤ 1024`。v1 文档换算过来时 `max_lifetime_seconds = max_duration_seconds`、`max_renewals = 0`，所以 v1 建出来的 grant 续不了。

`content` 按 `purpose` 各自一套字段，彼此不通用，`deny_unknown_fields`：

| `purpose` | `content` |
|---|---|
| `http-authentication` | `origin`、`methods`、`paths`、`query`、`body`、`signature_profile`（v1 那六个） |
| `origin-proof` | `origin`、`methods`、`paths`、`body` |
| `purpose-signing` | `purposes` |
| `ecdh` | `peers`（32 字节小写 hex 公钥列表） |
| `object-proof`、`document-proof` | `proof_purposes` |
| `root` | 空对象 `{}` |

`origin-proof` 的 `origin` 是 `anp://agent` / `anp://group` / `anp://service` 之一，`paths` 里每一项是 logical target URI `anp://{kind}/{percent-encoded did}` 中 `anp://{kind}` 之后的那一段：以 `/` 开头、后面是 percent-encoded 的 DID，与待签 `@target-uri` 的后缀**逐字节**相等。发布时按上游同一个编码函数反算校验，非规范编码（该编码的没编码、小写 `%3a`）直接拒，不会留下一条永远匹配不上的策略。整项写 `"*"` 表示该 origin 下的任意 DID，只能单独出现；和具体 DID 并列就还是没收窄，按非法处理。`bounded` 的 `max_bytes` 必须大于 0（否则那条策略拒绝一切）。已发布的 purpose 字段集不可改；加新 purpose 要连 `schema_version` 一起抬。`schema_version: 1` 的文档继续可读、判定不变。

### 11.6 助记词：只进不出

- **导入**：`import-mnemonic --did` 收 BIP-39 24 词（32 字节熵）。P4 起一个助记词恢复**四类密钥**：`key-1`、hot、`{device}-sign`、`{device}-agreement`。
- **导出：永远没有。** 不加 CLI、不加 socket 操作、不加 MCP 工具；`seed-export` 特性保持默认关，发布构建断言二进制里没有导出路径。
- **自建**：`keygen` 建完身份后把 24 词**当场显示一次**——只写 tty，stdout 不是终端就拒绝，不落文件，审计只记"展示过"。之后没有任何命令能把词再取出来，所以这是唯一一次备份机会。

多密钥派生方案版本串冻结为 `bip39-entropy-v2`（`bip39-entropy-v1` 的归档继续可开）。v2 推导出的 `key-1` 必须与 v1 **逐字节相同**，否则老身份换台机器就换了 DID。新增的子路径各占一条 HKDF 域串：`anp-keyd/v2/hot`、`anp-keyd/v2/device-sign`、`anp-keyd/v2/device-agreement`；`anp-keyd/v1/kek`、`anp-keyd/v2/kek`、`anp-keyd/v2/se-hs` 一个字不动。

### 11.7 默认关清单

每个新签名路单独一个开关，默认关，开的时候单独一条审计。已实现两路：`SIGN_ORIGIN_PROOF`（`features.sign_origin_proof`）和 `SIGN_PURPOSE`（`features.sign_purpose`，每个用途一个布尔量）。`SIGN_OBJECT_PROOF`、`SIGN_DOCUMENT_PROOF`、`ECDH` 仍是待实现的开关。

`SIGN_PURPOSE` 的开关是逐用途的，列出来的才有，没列出来或整段缺省都是关：

```json
{"features":{"sign_origin_proof":true,"sign_purpose":{"device_assertion":true}}}
```

两路开关各自在启动时往审计链追加一条：`{"event":"FEATURES","sign_origin_proof":…}` 和每个开着的用途一条 `{"event":"SIGN_PURPOSE_ENABLED","purpose":…}`。关着时该操作不出现在 `operations` 里（`signing_purposes` 相应为空），发了就是 `OPERATION_DISABLED`，事后从审计能回答"这版服务开过哪些签名路"。开关只决定数据面收不收这个操作，不改变 `SIGN_HTTP` 的行为。开一路不带开另一路：两个开关互不牵连，配的是哪路就只多哪路。

`signing_available=true` 不表示这些路开着，客户端仍以 `operations` 为准。**根的管理操作**（换设备、轮换根、注册）只在管理平面，要求在场（SE 租约或等价物）。数据面唯一能用 root 键的是 `SIGN_DOCUMENT_PROOF`，且它的 grant 只能由管理平面签发——数据面自己没有任何途径造出 root 授权。

### 11.8 客户端对接要求

awiki-cli-rs2 的适配器不在本仓库，但要满足：用 async `IdentityCustody` 那条接缝，不走 `ProviderIdentitySigner`（它对 `sign`/`sign_root`/`ecdh` 一律 `PermissionDenied`）；每条消息的 origin proof、每个 KeyPackage 的设备断言、每个 secure-direct 会话的 ECDH 各对应 §11.3 一个操作。`anpio-cli` 的 `custody.rs` 从子进程 `document`/`sign` 扩到同一批操作，参数保持管理员固定、不接受调用方覆盖 config/socket/did/kid。
