---
name: anpio-key-integration
description: 把任何"在当前进程里拿着私钥签名"的工具改造成通过 Anpio Key v2 受保护数据面签名（HTTP 请求、origin proof、用途断言、W3C 对象/文档 proof、X25519 协商）。语言与 CLI 无关：这里写的是线上协议和迁移判据，不是某个仓库的改法。
---

# 接入 Anpio Key：把签名搬出进程

目标只有一个：**私钥不再出现在调用方进程里**，调用方只拿到签名结果和公钥。
本文件是语言无关的接入规约；`anpio-key` 技能的安装/管理流程另见。

## 先做判断，再写代码

按顺序回答，任何一问是"否"就先停：

1. 这个操作是**签名**、**协商**，还是**读私钥**？只有前两类能搬。
   读私钥（导出 PEM、拿根密钥）没有对应操作，见 `references/mapping.md` 的"搬不走的三类"。
2. 调用方能不能只靠**公钥**和 **DID 文档**完成本地准备（prepare）？
   签名前需要算的规范化输入、摘要、proof 选项，必须能在没有私钥的情况下算出来。
   做不到，说明这条路径把密钥当成了输入的一部分，先拆开再谈。
3. 服务端**验签方**是谁？它认哪种编码、哪套签名基？
   这一条最容易被忽略：同一份签名换一种字母表就验不过，而两种字母表在
   ANP 生态里同时存在（见 `references/mapping.md` 的"编码一致性"）。
4. 验签方是同一台机器上的对端，还是远端服务？远端要 HTTPS + DNS 主机名，
   本机 `http://localhost` 走不了 `SIGN_HTTP`。

## 接入顺序

### 1. 能力协商，不要假设

发 `GET_CAPABILITIES`（不需要 grant）。判断依据**只有一个**：
操作名在不在 `operations` 数组里。旧服务端没有这个字段，此时它的能力
**恰好**是基线六个：

```
GET_CAPABILITIES, LIST_AUTHORIZED_KEYS, GET_GRANT_STATUS,
GET_DOCUMENT, SIGN_HTTP, GET_REQUEST_STATUS
```

`SIGN_PURPOSE` 还要看 `signing_purposes`（`device_assertion` /
`application_assertion` 各自独立开关，空数组表示这一路整体没开）。
`operation` 存在但开关关着，返回 `OPERATION_DISABLED`——按"不支持"处理，
不要重试。

### 2. 线上形状

一条连接一个请求，4 字节大端长度 + JSON，长度 1..=65536：

```json
{"version":2,"request":{"operation":"GET_CAPABILITIES"}}
```

`deny_unknown_fields`：多一个字段就是 `PROTOCOL_INVALID`。请求里**没有**
`did`、`kid`、`key_id`、`password` 之类字段——用哪把钥匙由 grant 决定，
调用方给不了。完整的每操作字段见 `references/protocol.md`。

### 3. 授权模型决定调用方怎么组织

- **request grant**：`max_uses` 次，通常 `max_renewals=0`，适合"一次登录签一次"。
- **session grant**：`CreateSession` 建，可以 `RENEW_GRANT`，但续期只能把到期时间
  往上顶到策略天花板，**不会**增加 `max_uses`。
- 每次签名消耗一次 use；use 用尽 = `GRANT_EXHAUSTED`，只能找管理面换 grant。
- `request_id` 是去重键：**发送前落盘**。网络断了用同一个 `request_id` 重发；
  换了输入还复用同一个 id = `REQUEST_ID_CONFLICT`。
- 响应丢了先查 `GET_REQUEST_STATUS`。查不到（被清理）不等于没签过，
  按 `OUTCOME_UNKNOWN` 处理，不要自动重签。

调用方负责把"本地 kid"映射成"用哪张 grant"。这个映射放在客户端配置里，
不要让调用方在请求里指定钥匙。

### 4. 迁移调用点

几乎每条本地签名路径都是同一个三段式：

```
prepare(public_key, facts)  →  signing_input
sign(signing_input)         →  signature        ← 换成 daemon 操作
complete(prepared, signature) → 产物
```

把中间那一步换成 daemon 调用，前后两步留在本地、只用公钥。
逐操作对照、每条的硬约束、以及"搬不走"的清单都在
`references/mapping.md`。

### 5. 错误按形态分类，不按文案

服务端拒绝都带一个稳定 code。按"该做什么"分类：等、找管理员、停。
映射表在 `references/errors.md`；code 原样记日志，别拿 code 的文案做判断。

### 6. 验收

`references/verification.md` 是一份可以逐条打勾的清单，包括
"客户端目录里搜不到私钥"和"用**对方**的验签器验一遍"。

## 反模式

- 为了省事把私钥读出来"只是这一次"——没有这个操作，也不该有。
- 看到 `OUTCOME_UNKNOWN` 就当没签，换个 `request_id` 重签：可能已经签过两次。
- 把 daemon 当成"签名服务器"：它同时管策略、期限、次数、撤销和审计，
  拒绝是常态，重试前先看形态。
- 自己拼 proof 的规范化字节：签名基必须由**签的那一方**拼，或者由双方共同引用的
  同一个上游库算。两边各写一遍，总有一天会不一致。
- 只在开着的模式下测一遍。每个新签名路默认关，关着时的拒绝路径同样是验收项。
