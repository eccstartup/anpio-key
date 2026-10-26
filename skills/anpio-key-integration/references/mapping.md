# 从本地私钥到 daemon：逐操作对照

适用于任何用 ed25519 / X25519 私钥在进程内签名的工具。下面的"本地形状"来自
ANP 系的 Rust 库（`anp` / `anp-identity`），但判据与语言无关：**看它签的是什么，
不看它用什么 API。**

---

## 三段式：prepare → sign → complete

几乎所有本地签名路径都是：

```
prepare(public_key, facts)     →  prepared（含 signing_input）
sign(private_key, signing_input) → signature      ← 唯一要搬走的一步
complete(prepared, signature)  →  产物           ← 仍在本地
```

搬走的判据：**换成 daemon 之后，`signing_input` 必须逐字节相同。**
如果换不出来，说明本地那一步偷用了私钥之外的东西（比如用私钥派生某项），
得先拆。

实测（anp 1.0.3 / 1.0.6，同一份代码）：
- proof / binding 类的 `signing_input()` 是 **64 字节十六进制摘要**，不是整份 JSON。
- 一条 `direct.send` origin proof 的签名基约 **309 字节**。
- 因此 `SIGN_PURPOSE` 的 4096 字节上限对这些路径**不是**约束；只有把整个对象
  当 payload 塞进去才会撞上。

---

## 对照表

| 本地操作 | daemon 操作 | 谁拼签名基 | 键的角色 |
| --- | --- | --- | --- |
| HTTP 请求签名（RFC 9421） | `SIGN_HTTP` | daemon | 热键 |
| ANP origin proof（消息/登录请求的 proof） | `SIGN_ORIGIN_PROOF` | daemon | 热键 |
| 设备/应用用途断言（对一段字节签名） | `SIGN_PURPOSE` | **调用方**（daemon 签 payload 本身） | 设备签名键 |
| W3C 对象 proof（`DataIntegrityProof`） | `SIGN_OBJECT_PROOF` | daemon | 设备签名键 |
| DID 文档 proof | `SIGN_DOCUMENT_PROOF` | daemon | **根控制键**（管理面铸 grant） |
| X25519 协商 | `ECDH` | — | 协商键 |

三件调用方必须自己做的事：

1. **拿公钥。** 用 `LIST_AUTHORIZED_KEYS` + `GET_DOCUMENT` 从文档里取，不要再从
   本地 PEM 读。本地只留 DID 文档和 kid。
2. **算 prepare。** 需要规范化输入的路径（断言、proof 选项）用**和验签方相同的
   上游库**算，不要自己实现 JCS。
3. **核对产物。** `SIGN_PURPOSE` 回的 `public_multibase` 要等于本地文档里那把键；
   不等就是配错了 grant。

---

## 编码一致性（最容易踩的一条）

W3C `vc-di-eddsa`（`eddsa-jcs-2022`）对文档 proof 有两条规定：

1. `proofValue` **必须**是 base58btc 的 multibase（`z` 前缀）；base64url 不合规。
2. Create Proof §3.3.1：`If unsecuredDocument.@context is present, set proof.@context
   to unsecuredDocument.@context.` 签名输入是
   `SHA256(JCS(proofConfig)) || SHA256(JCS(document))`，proofConfig **带** `@context`。

`anp` 1.0.x 的 `complete_w3c_proof` 生成的是**旧方言**：裸 base64url，且 proof
configuration 不带 `@context`。所以"把 base64url 换成 z、字节不变"这个做法是错的：
编码符合规范、签名基不符合规范，任何按规范验的都会拒，而且现象和"签名错了"一模一样。

anpio-key 自己签文档（发布文档、`SIGN_DOCUMENT_PROOF`）走的是**规范那一条**
（`src/did/proof.rs`）：拼 proofConfig，文档带 `@context` 就并进去，输出 `z`。
所以：

- 走 daemon 的接入方，产物在 anp 1.0.6 的验签和 awiki-open-server 那边直接过；
- **自己实现签名侧**（没走 daemon）的接入方必须照规范拼，不能拿上游的
  `complete_w3c_proof` 再换字母表。

实测（同一把键、同一份**带 `@context`** 的文档）：

```
anp 1.0.6 生成(base64url)              .verify(1.0.6) = true    # 自洽但非规范
只换字母表(z, 旧签名基)                .verify(1.0.6) = false
规范形状(z, @context 进 proofConfig)   .verify(1.0.6) = true    # daemon 的产物
```

实测（同一把键、同一份文档）：

| 产物 | anp 1.0.3 验 | anp 1.0.6 验 |
| --- | --- | --- |
| 文档 proof，base64url（上游生成） | 通过 | 通过 |
| 文档 proof，`z` 换字母表、旧签名基 | **失败** | **失败**（文档带 `@context`） |
| 文档 proof，规范形状（daemon 产物） | **失败** | 通过 |
| 对象 proof（1.0.x 原生就是 `z`） | 用对象 proof 的验签器 | 通过 |

结论：**文档 proof 的字母表和签名基必须一起按验签方定**，而且要拿对方的验签器
真的跑一遍。另外，规范形状在 anp **1.0.3** 上验不过 —— 验签方钉着 1.0.3 时，
要么升级，要么明确走旧方言。

对象 proof 不存在这个问题——两边原生都是 `z`。

比字母表更早的一个坑：`anp` 的 `prepare_w3c_proof` 在没给 `proof_type` 时会按键类型
推断（Ed25519 → `Ed25519Signature2020`，而不是 `DataIntegrityProof`）。这时 `z`
根本不是这条 proof 的合法编码，验签会以"签名不对"失败——和"签名基不同"是两种原因，
看错误现象分不出来。要么显式给 `proof_type` + `cryptosuite`，要么先确认对方生成的
proof 里 `type` 到底是什么。

---

## 搬不走的四类

1. **根控制键的任意签名。** 数据面没有根签名、没有"用根键签一段字节"的操作。
   `SIGN_DOCUMENT_PROOF` 是根键**唯一**的数据面出口，而且它的 grant 只能由
   管理面铸。凡是"用根键签别的结构"的路径，得在管理面重新设计。
2. **导出私钥。** 没有这个操作，也不要新增。迁移走管理面的迁入/轮换流程。
3. **任意字节的通用签名。** 只有上表六个具名操作。一个新的签名用途要么映射到
   `SIGN_PURPOSE` 的既有 purpose（用途必须和键绑定的一致），要么先在 daemon
   侧成为一个新操作——后者是**另一个仓库的契约变更**，不是接入方自己能做的。
4. **动态对端的 X25519。** `ECDH` 的 `peers` 是逐字节白名单（≤64，无通配）。
   对端若是运行时从服务端拉来的、事先不知道的公钥，就走不了。
   前置条件是对端集合有限且可枚举；否则协商必须留在本地。

---

## 设备入组与撤销

新设备键出现在 daemon 之外时，不能"本地生成后塞进去"。标准四步全在管理面：

1. `IssueDeviceKeys`——在 vault 里铸出 `{device}-sign` 与 `{device}-agreement`；
2. `ReissueDocument`（add）——把两个公钥写进 DID 文档，重新签文档；
3. `EnrollVault`——让这把键归属到目标 vault/主体；
4. `ConfirmRole`——`device_signing` + `purpose=device_assertion`，以及
   `key_agreement`。

撤销是一条 `ReissueDocument`（remove）。**入组和撤销都不需要新私钥经过调用方
进程**，这正是"客户端目录里没有私钥文件"能成立的原因。

---

## 授权怎么落到代码里

- 一张 grant 绑定 `(principal, key, policy)`。调用方只决定"用哪张 grant"，
  决定不了"用哪把钥匙"。
- 每次签名消耗一次 use。消息量大的路径要算清楚：
  `max_uses = 次数 × 单条消耗`，而 `RENEW_GRANT` **不能**加次数。
- `request_id` 发送前落盘。断网用同一个 id 重发；`GET_REQUEST_STATUS` 查结果。
- `OUTCOME_UNKNOWN` / 查不到记录，都不等于"没签过"。

---

## 一个最小接入骨架（伪代码，语言无关）

```
caps = GET_CAPABILITIES()
grant = config.grant_for(kid)          # 客户端配置，不是请求字段
if not caps.supports("SIGN_ORIGIN_PROOF"): 走本地旧路径或明确报错

request_id = uuid(); persist(request_id, facts)
data = SIGN_ORIGIN_PROOF(grant, request_id, facts)
proof = { content_digest, signature_input, signature }   # 原样用
```

Rust 侧已有现成客户端（`anpio_key::client::Client`），它的 `Refusal` 就是下面
`errors.md` 那张表的一种实现；其他语言照协议自己写同样的几十行即可。
