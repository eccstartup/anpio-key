# 接入验收清单

按顺序做。每一步都要留下可复查的输出，不要用"看起来没问题"代替。

## 1. 静态对照（不需要部署）

- [ ] 列出调用方**所有**使用私钥的位置（`grep -rniE "private[_ ]?key|pem|seed|secret_key"`）。
      每一个都要么映射到下面六个操作之一，要么属于"搬不走"的四类。
- [ ] 对每个映射，写出它原本的 `signing_input` 是怎么算的，并证明换成 daemon 后
      逐字节相同（同一条上游库、同一份事实）。
- [ ] 确认请求里没有 `did`/`kid`/`key_id`/口令字段——有的话，它在冒充授权。
- [ ] 确认服务开关默认关时，调用方的行为是明确的（降级或报错），不是静默签本地。

## 2. 产物级互操作（不需要 root）

用**对方的**验签器验，不要用自己这边写的那一套。

做法：一个小探针 crate/脚本，只依赖上游库，不依赖 daemon：

1. 用上游库在本地生成一份产物（baseline）；
2. 在本地再造一份**规范形状**的产物（`z` + base58btc，文档的 `@context` 进
   proof configuration 再签）；
3. 分别用**上游 A 版本**和**上游 B 版本**的验签器去验。

已经量过的结果（anp 1.0.3 / 1.0.6，同一把键、同一份 DID 文档）：

| 产物 | 1.0.3 | 1.0.6 |
| --- | --- | --- |
| 文档 proof（base64url，上游生成） | 通过 | 通过 |
| 文档 proof（`z`，换字母表、旧签名基，文档带 `@context`） | 失败 | **失败** |
| 文档 proof（`z`，规范签名基：`@context` 进 proofConfig） | 失败 | 通过 |
| 对象 proof（`z`） | 通过（对象 proof 验签器） | 通过 |

结论：daemon 发的是第三行那一种（`src/did/proof.rs`）；**验签方钉着 anp 1.0.3
时会验不过**，接它之前先确认版本。文档 proof 的编码是接入时必须单独验的一条；
对象 proof 不存在差异。

同一类检查也适用于：
- HTTP 签名：把 daemon 的覆盖集和验签方要求的覆盖集逐项比对；
- origin proof：两边是否调用同一个签名基构造函数（最省事的方式是**同一个库**）；
- 断言：payload 是否是原始字节、有没有被加前缀。

## 3. 协商与降级

- [ ] 服务端 `operations` 里没有某操作时，调用方不发送它。
- [ ] 服务端没有 `capability_schema` 时，只按基线六个判断。
- [ ] `SIGN_PURPOSE` 的 `signing_purposes` 为空时，按"这一路没开"处理。
- [ ] 每个默认关的开关都跑一遍"关着"的路径。

## 4. 真部署（需要 root + 独立 UID）

受保护面要求：

- root 拥有 `/etc/anpio-key/service.json`；
- `service_uid` 与 `admin_uids`、所有 principal 的 uid **两两不同**，且都不为 0；
  `agent_gid != admin_gid`；
- `mode=linux-protected-v1` 且是正式 Linux 构建时 `protected_supported=true`；
  preview / 调试 / macOS 一律 false。

**单用户机器上做不到这一步**：同一个 uid 既当服务又当调用方会被配置校验直接拒绝
（principal 的 uid 不能等于 `service_uid`）。这不是配置技巧能绕过的，它就是边界本身。
要在容器或真正的多账号机上做。

真部署要跑的：

- [ ] `GET_CAPABILITIES`：`protected_supported=true`，`operations` 与预期一致。
- [ ] `LIST_AUTHORIZED_KEYS` / `GET_DOCUMENT`：只拿到公钥与文档。
- [ ] 六个操作各签一次，**用对方验签器**验。
- [ ] 关闭的开关各试一次，得到 `OPERATION_DISABLED`。
- [ ] 同一 `request_id` 重发一次：结果一致，没有第二次签名（审计只有一条）。
- [ ] 改一个字节再用同一 `request_id`：`REQUEST_ID_CONFLICT`。
- [ ] 耗尽 `max_uses`：`GRANT_EXHAUSTED`，且 `RENEW_GRANT` 不能救。
- [ ] `ECDH` 重放：`OUTCOME_UNKNOWN`，不是新密钥。
- [ ] 审计里每个开着的路各有一条 `*_ENABLED`。

## 5. "客户端没有私钥"

- [ ] 完整跑一遍登录、发消息、建会话；
- [ ] 然后 `grep -rniE "PRIVATE KEY|privateKey|BEGIN .* KEY" <客户端目录>` 为空；
- [ ] 客户端进程的配置里只有 DID、kid、grant、socket/config 路径；
- [ ] 换一台机器用同一份客户端配置，签名仍然成功（私钥不在客户端里）。

## 6. 回退

- [ ] 每个改过的路径都保留"服务端不支持时"的行为，并在文档里写清楚默认它是关的。
- [ ] 回退**不**靠把私钥写回客户端目录；回退是关闭开关、继续用旧的本地路径（如果
      旧路径还在），或者明确不可用。
