# 拒绝的形态与处置

判断只读回复里的 `code`，**不读文案、不看 HTTP 之类的外层**。code 原样留日志。
分类的目的只有一个：决定"等、找管理员、还是停"。

| 形态 | code | 处置 |
| --- | --- | --- |
| Unsupported | `PROTOCOL_VERSION_UNSUPPORTED`、`UNSUPPORTED_OPERATION`、`OPERATION_DISABLED` | 这条签名路不可用。降级到本地旧路径，或明确告诉用户"功能未开启"。**不要重试。** |
| NotGranted | `GRANT_INVALID` | 这张 grant 对这个主体/键/策略不成立。找管理面铸权。 |
| Expired | `GRANT_EXPIRED` | session grant 用 `RENEW_GRANT`；request grant 换新的。 |
| Exhausted | `GRANT_EXHAUSTED`、`GRANT_RENEWALS_EXHAUSTED` | 次数或续期用完。续期**不会**加次数，只能换 grant。 |
| Locked | `KEY_LOCKED` | 需要解锁。**预留可能已经消耗了次数**，不能当"没发生"；先 `GET_REQUEST_STATUS`。 |
| Conflict | `REQUEST_ID_CONFLICT` | 同一个 `request_id` 装了不同输入——调用方的 bug。确认这是新请求再换 id。 |
| Missing | `REQUEST_NOT_FOUND`、`KEY_NOT_FOUND` | 记录不存在：前者多半已被清理，按 `OUTCOME_UNKNOWN` 处理，**别重签**；后者是配置错了键。 |
| Busy | `RESOURCE_BUSY` | 退避后用**同一个** `request_id` 重试。 |
| Stopped | `AUDIT_UNAVAILABLE`、`PERSISTENCE_UNAVAILABLE` | 服务可能已经停止签名。停止自动重试，交给运维。 |
| Policy | `POLICY_DENIED`、`KEY_ROLE_FORBIDDEN`、`PRINCIPAL_DISABLED` | 策略/角色/主体状态不允许。找管理员，不要绕。 |

## 参数层面的拒绝（说明调用方本身写错了）

| code | 含义 |
| --- | --- |
| `PROTOCOL_INVALID` | 帧或 JSON 形状不合法（含多余字段、缺字段） |
| `REQUEST_ID_INVALID` | `request_id` 格式不合规 |
| `ORIGIN_INVALID` | origin proof 的事实不合规（method、target、时限、大小） |
| `PURPOSE_INVALID` | 用途名、domain 或缺省规则不对 |
| `PROOF_INVALID` / `PROOF_DOMAIN_INVALID` / `PROOF_CHALLENGE_INVALID` / `PROOF_TIME_INVALID` | 文档/对象 proof 的输入不合规 |
| `ECDH_INVALID` / `ECDH_PEER_INVALID` / `ECDH_PEER_FORBIDDEN` | 协商键或对端不合法（含不在白名单） |

这些**不该重试**：重试只会得到同一个拒绝。

## 不保证结果的形态

| code | 含义 |
| --- | --- |
| `OUTCOME_UNKNOWN` | 可能签了，也可能没签。停自动重试，用 `GET_REQUEST_STATUS` 或人工核对。 |
| 连接断开 / 超时 | 同上。用原 `request_id` 重发是安全的（服务端去重），但**不要换 id 重签**。 |

## 一句话原则

- 能重试的只有 `RESOURCE_BUSY` 和连接中断，而且都用**原 `request_id`**。
- 其它一切拒绝要么改配置、要么找管理员、要么停下。
- 任何"不确定签没签"的情况，统一按 `OUTCOME_UNKNOWN` 处理，不要按"没签"处理。
