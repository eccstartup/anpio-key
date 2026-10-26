# 线上协议速查（v2 受保护数据面）

帧：`u32` 大端长度（1..=65536）+ UTF-8 JSON。一条连接一个请求，请求完即关。
信封固定 `{"version":2,"request":{...}}`。所有对象 `deny_unknown_fields`——
多一个字段、少一个必需字段都是 `PROTOCOL_INVALID`。

**请求里永远没有 `did` / `kid` / `key_id` / 任何口令字段。** 用哪把钥匙由
`grant_id` 决定。调用方只能选择"用哪张 grant"。

---

## 基线六个

| 操作 | 请求额外字段 | 成功时 `data` |
| --- | --- | --- |
| `GET_CAPABILITIES` | 无 | 见下 |
| `LIST_AUTHORIZED_KEYS` | 无 | `{"keys":[{"key_id","did","kid"}]}` |
| `GET_GRANT_STATUS` | `grant_id` | 一条 grant 记录 |
| `GET_DOCUMENT` | `key_id` | `{"key_id","document"}` |
| `SIGN_HTTP` | `grant_id`,`request_id`,`http` | `{"request_id","url","headers","covered","expires_at"}` |
| `GET_REQUEST_STATUS` | `request_id` | 状态与结果（可能为空） |

`GET_CAPABILITIES` 的 `data`：

```json
{"protocol_version":2,"profile":"...","max_body_bytes":16384,
 "transaction_executor_available":true,"audit_projection_healthy":true,
 "capability_schema":1,
 "operations":["GET_CAPABILITIES","LIST_AUTHORIZED_KEYS","GET_GRANT_STATUS",
               "GET_DOCUMENT","SIGN_HTTP","GET_REQUEST_STATUS"],
 "purposes":[],"signing_purposes":[],"grant_kinds":["request","session"]}
```

`operations` 不含某个名字（或整个字段缺失）= 不支持。缺失时按基线六个理解，
**不是**"全支持"。

`GET_GRANT_STATUS` 的记录含 `grant_id / principal_id / key_id / policy_id /
policy_version / boot_epoch / expiry / kind("request"|"session") / created_at /
max_uses / used_uses / state`。

`GET_REQUEST_STATUS` 的语义：`completed` 带结果；`pending` 表示可能还在执行；
查不到 = 已被清理，**不等于没执行**。

---

## 五个签名/协商操作

### SIGN_HTTP

```json
{"operation":"SIGN_HTTP","grant_id":"G","request_id":"R","http":{
  "method":"GET",
  "url":"https://service.example.com/orders?page=1",
  "headers":{"content-type":"application/json"},
  "body":{"state":"absent"},
  "nonce":"SERVER_EXPECTED_NONCE"}}
```

- `body` 必须显式：`{"state":"absent"}` 或 `{"state":"present","bytes":[...]}`。
  空 body 与无 body 不同。
- URL 只收 `https://`，主机必须是 DNS 名（拒绝 IP、数字 IPv4 各种变体、末尾点、
  userinfo、`..`/`.` 段、重复查询键、`+`、编码过的敏感字节）；`path<=2048`，
  `url<=4096`。
- headers ≤64，不接受 `host / authorization / signature / signature-input /
  content-length / transfer-encoding / connection`。
- body ≤16384 字节。
- daemon 自己算覆盖集：下限 `@method`、`@target-uri`、`@authority`；有 body 时加
  `content-digest`，有 `content-type` 头时加 `content-type`。**没有字段能让调用方
  追加覆盖组件**，验签方要求额外组件时这里会不够。
- 返回的 `headers` 原样加到请求上（`Signature-Input`、`Signature`，必要时
  `Content-Digest`）。

### SIGN_ORIGIN_PROOF

```json
{"operation":"SIGN_ORIGIN_PROOF","grant_id":"G","request_id":"R","origin":{
  "method":"direct.send",
  "meta":{"profile":"anp.direct.base.v1",
          "target":{"kind":"agent","did":"did:wba:example.com:bob"}},
  "body":{"text":"hi"},
  "expires":1761440400,
  "nonce":"abc123"}}
```

- `method`：小写字母/数字/`._-`，≤64。
- `meta`、`body` 必须是 JSON 对象；`meta.target.kind` ∈
  `agent | group | service`；`meta.target.did` 非空、≤512。
- `expires` 只能落在 daemon 当前时刻之后 300 秒内；`nonce` ≤128、可打印 ASCII。
- 规范化字节 ≤32 KiB。
- 签名基由 daemon 拼（`@method` / `@target-uri` / `content-digest` /
  `@signature-params`）。返回 `content_digest`、`signature_input`、`signature`、
  `created`、可选 `expires`，**原样**交给协议层。
- **每次调用消耗一次 grant use。** 一次登录一条，别把 proof 当长期票据。

### SIGN_PURPOSE

```json
{"operation":"SIGN_PURPOSE","grant_id":"G","request_id":"R",
 "purpose":"device_assertion","payload":"1f8b..."}
```

- `purpose` 必须和 grant 上那把键绑定的用途一致：`device_assertion` 或
  `application_assertion`。
- `payload` 是**小写 hex**，解码后 1..=4096 字节；空、奇数长度、大写、非 hex 都拒。
- `domain` 只有 `application_assertion` 能给；`device_assertion` 给了就非法。
- `device_assertion` 签的就是 payload 本身，**不加任何前缀**；`application_assertion`
  的前缀是 `域串 + u16 BE 长度 + 域`，与上游一致。
- 返回 `signature`（hex）、`public_multibase`（键的公钥）、`purpose`（回显）。
  **调用方必须自己核对 `public_multibase` 是不是它以为的那把设备键。**

典型 payload 是上游 prepare 出来的 64 字节十六进制摘要（`signing_input()` 返回的
就是这串），远小于上限；但**不要把大对象整个塞进来**，先按上游算法算摘要。

### SIGN_OBJECT_PROOF

```json
{"operation":"SIGN_OBJECT_PROOF","grant_id":"G","request_id":"R",
 "object":{"type":"AnpDeviceBinding","agentDid":"did:wba:...","deviceId":"phone-1"}}
```

- `object` 必须是 JSON 对象；顶层 `proof` 会被摘掉、不参与签名。
- daemon 盖 `DataIntegrityProof` + `eddsa-jcs-2022`，`proofPurpose` 固定
  `assertionMethod`，`verificationMethod` 是 grant 那把键的完整 kid。
- 返回整份带 `proof` 的对象（`value`）和单独那条 `proof`。
- 产物是 `z` + base58btc 的 `proofValue`（与 anp 1.0.x 的对象 proof 一致）。

### SIGN_DOCUMENT_PROOF

```json
{"operation":"SIGN_DOCUMENT_PROOF","grant_id":"G","request_id":"R",
 "document":{...整份 DID 文档...},
 "proof_purpose":"assertionMethod","domain":"example.com","challenge":"..."}
```

- `document.id` 必须等于这把键的 DID，键必须还挂在文档里；不合规在扣配额**之前**
  就返回 `PROOF_INVALID`。
- 规范化字节 ≤32 KiB。
- `proof_purpose` ∈ `assertionMethod | authentication`；`domain`、`challenge` 会原样
  进签名基，给了就得让验签方也知道。
- **这把键是根控制键**，grant 只能由管理面铸（数据面没有根签名操作）。
- 产物是**规范形状**：`proofValue` 是 `z` + base58btc，签名基是
  `SHA256(JCS(proofConfig)) ‖ SHA256(JCS(document minus proof))`，其中
  `proofConfig` 在文档带 `@context` 时**包含** `@context`。`type` 固定
  `DataIntegrityProof`、`cryptosuite` 固定 `eddsa-jcs-2022`。
  见 `mapping.md` 的"编码一致性"。

### ECDH

```json
{"operation":"ECDH","grant_id":"G","request_id":"R","peer":"<64 位小写 hex>"}
```

- `peer` 是对方 32 字节 X25519 公钥的小写 hex。
- 用哪把协商键由 grant 决定；policy 的 `peers` 是**逐字节**白名单，非空、≤64 条、
  无通配。
- 返回 `shared_secret`（hex）与 `peer_fingerprint`。共享密钥**只回一次、不落库**：
  同一个 `request_id` 重放只会得到 `completed` + 空结果，客户端应翻成
  `OUTCOME_UNKNOWN`。调用方必须先落地 `request_id` 与结果再往下走。
- 这是唯一会吐出秘密的操作，默认关，开的时候有一条独立审计 `ECDH_ENABLED`。

### RENEW_GRANT

```json
{"operation":"RENEW_GRANT","grant_id":"G","expiry":1762000000}
```

只对 `kind=session` 的 grant 有效；到期时间被夹到
`min(请求值, now+max_duration, created_at+max_lifetime)`。**不增加 `max_uses`**。
`max_renewals=0` 的 grant 续不了（`GRANT_RENEWALS_EXHAUSTED`）。

---

## 默认关的开关与审计

| 操作 | 配置键 | 启动审计 |
| --- | --- | --- |
| `SIGN_ORIGIN_PROOF` | `features.sign_origin_proof` | `FEATURES` |
| `SIGN_PURPOSE(device_assertion)` | `features.sign_purpose.device_assertion` | `SIGN_PURPOSE_ENABLED` |
| `SIGN_PURPOSE(application_assertion)` | `features.sign_purpose.application_assertion` | `SIGN_PURPOSE_ENABLED` |
| `SIGN_OBJECT_PROOF` | `features.sign_object_proof` | `SIGN_OBJECT_PROOF_ENABLED` |
| `SIGN_DOCUMENT_PROOF` | `features.sign_document_proof` | `SIGN_DOCUMENT_PROOF_ENABLED` |
| `ECDH` | `features.ecdh` | `ECDH_ENABLED` |

接入方的代码要能在"开关关着"的情况下正常工作（降级或明确报错），
因为默认状态就是关。
