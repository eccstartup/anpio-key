# Anpio Key 架构与安全设计

本文描述当前实现的职责边界、持久化语义和兼容约束。接入方法见 [ADAPTER](ADAPTER.md)，命令概览见 [README](../README.md)。

## 一、产品目标与威胁模型

Anpio Key 在本机受保护服务中保管 did:wba Ed25519 密钥，让 Agent 使用有限签名授权。产品同时做到两件事：长期私钥不通过普通接口分发；调用者只能在批准的身份、请求范围、期限和次数内使用密钥。密钥已解锁本身不构成签名许可。

### 1.1 两种部署边界

| 模式 | 运行前提 | 可依赖的性质 |
|---|---|---|
| Linux v2 受保护模式 | 专用服务 UID、独立 Agent UID、独立管理员 UID，程序和信任配置受保护 | 在 OS、管理员及 daemon 可信时，限制 Agent 读密钥、改策略和跨主体用钥 |
| 开发模式 | 旧 `serve`、同 UID 客户端，macOS 或本地联调 | 常规接口不返回私钥；不提供同 UID 任意代码执行下的隔离保证 |

同 UID 的不受限进程属于同一安全主体。文件 `0600`、目录 `0700`、二进制白名单或控制终端都不能把它们隔开。PTY 可以由程序创建；终端输入限制只减少口令误入 argv、环境变量和管道，不是人类身份认证。

Agent 不能拥有 sudo、宿主 Docker socket、服务配置写权限或控制管理员进程的能力。若这些前提不成立，受保护部署的结论不成立。当前不防御 root、内核、daemon 或可信管理端被控制，也不保证已交付签名可撤回。

### 1.2 支持声明

`protected_supported` 同时受构建和部署模式约束：正式 Linux release、未启用 `hardware-software` 或 `seed-export`，且配置显式为 `linux-protected-v1` 时才为 true。preview、调试和 macOS 为 false。旧 preview 配置不会因升级自动获得该声明。

`build-info` 表示构建能力；daemon 和 `probe --security` 还检查运行配置；probe 验证调用者可访问的对应 socket。它们不是对任意宿主配置的持续远程证明。

## 二、组件与权限边界

```text
隔离 Agent UID                      专用服务 UID
 CLI / Node / MCP ── sign.sock ──▶ 主体认证 → 请求规范化/策略
                                      ↓
                                 有界签名协调器
                                      ↓
                                 SQLite 事务 + 软件签名
                                      ↓
                                 受保护 vault / 审计投影

可信管理员 UID ──── admin.sock ──▶ 管理批准 / 解锁 / 撤销 / 生命周期

外部网络：由客户端或可信管理适配器发送请求、注册和发布文档。
签名核心不联网。
```

### 2.1 主体与客户端互认

内核对端 UID 映射到持久 principal UUID；PID、cwd、调用方自报名称不用于授予权限。数字 UID 再分配时，应先禁用旧主体，再注册新的 UUID/generation，避免继承旧授权。bootstrap 配置只负责初始化，后续主体状态以数据库为准。

连接组仅授予到达 socket 的能力。管理 UID 与 Agent UID 不得重叠，服务 UID 不得注册为 Agent；管理请求还需服务端检查管理员身份。

客户端读取 root 保护的配置，校验目录、socket 类型、权限和拥有者；连接后验证内核对端服务 UID，并比较连接前后的 socket inode。只有完成服务身份验证，管理端才发送秘密。受保护连接不接受调用方自行指定 socket 作为信任根，也不自动退回旧协议。每连接处理一个请求；运行器仍需防止跨主体转交 FD 或控制对方进程。

### 2.2 默认部署布局

```text
/etc/anpio-key/service.json        root 控制的信任配置
/usr/local/libexec/anpio-key       root 控制的程序
/var/lib/anpio-key/                服务 UID 拥有，0700
  state.sqlite                   状态与审计真源，0600
  vaults/<vault_uuid>/
    device.secret
    keys/<thumbprint>.json       加密信封
    dids/<safe_did>.json          公开 DID 文档
  audit-export/events.jsonl       数据库审计投影
/run/anpio-key/                    分离的管理/签名 socket 子目录
```

默认签名端点为 `/run/anpio-key/sign/sign.sock`，管理端点为 `/run/anpio-key/admin/admin.sock`；具体路径以安装器生成的配置为准。Agent 不能写程序、配置、socket 父目录或服务状态；daemon 也不能修改部署信任配置。vault 路径由受信配置及 UUID 决定，不从 Agent 提交的 DID、UID 或任意文件路径拼接。

旧开发模式使用 `~/.anpio-key`，其 `--system` 布局不等于 v2 受保护服务。普通本地生命周期命令拒绝直接操作托管目录，避免形成管理旁路。

### 2.3 代码职责

| 入口 | 职责 |
|---|---|
| `src/security/config.rs`、`paths.rs`、`client.rs` | 配置信任根、文件边界和服务端认证 |
| `src/principal.rs`、`security/server.rs` | 内核主体映射、双 listener 和请求分派 |
| `src/security/http.rs`、`src/persistence/policy.rs` | 同一规范化请求上的摘要、策略与签名 profile |
| `src/security/coordinator.rs`、`executor.rs` | 有界排队、撤销顺序、签名事务执行 |
| `src/persistence/` | schema、授权、管理意图、恢复与事务审计 |
| `src/keystore/`、`src/sign/`、`src/crypto/` | 信封、驻留密钥、签名及密码学实现 |
| `src/mcp/protected.rs`、`adapters/anpio-key-v2.mjs` | 数据面适配，不自行授予权限 |

## 三、密钥格式与恢复兼容性

这些格式决定已有身份和备份能否恢复。不能为了接口重构修改既有推导、AAD 序列化或版本语义；需要扩展时使用明确新版本并保留旧格式读取测试。

### 3.1 助记词：`bip39-entropy-v1`

24 个 BIP-39 词直接编码 32 字节 Ed25519 seed：256 位熵加 8 位校验，共 264 位。这里使用 BIP-39 熵的编码/解码，**不使用** PBKDF2-HMAC-SHA512 的 BIP-39 seed 派生，也不接受其可选 passphrase。

标准工具的 `to_seed()` 会得到另一把钥匙，通常不会报错。恢复实现必须验证词数、推导版本、公钥、指纹和 DID 文档关系，不能只检查词语有效。实现见 `src/crypto/mnemonic.rs`。

### 3.2 信封：`WrappedKey` v1/v2

```text
pass_key = Argon2id(passphrase, salt, parameters)
v1 KEK   = HKDF-SHA256(salt, pass_key || device.secret, "anp-keyd/v1/kek")
v2 KEK   = HKDF-SHA256(salt, pass_key || device.secret || HS, "anp-keyd/v2/kek")
DEK      = AEAD-open(KEK, dek_ciphertext, nonce, AAD)
seed     = AEAD-open(DEK, sk_ciphertext, nonce, AAD)
```

KEK、DEK 和 seed 均为 32 字节。DEK 随机生成；两次 XChaCha20-Poly1305 使用不同密钥。AAD 绑定版本、DID/kid、公钥、算法、KDF 参数和标签；v2 额外绑定硬件定位符及封装材料，v1 不序列化这两个新增字段。校验 AAD 摘要不替代 AEAD 认证。

默认 Argon2id 成本为 65536 KiB、3 次、并行度 1。解封在分配前限制成本：内存最多 262144 KiB、迭代最多 10、并行度最多 4；超出范围拒绝，不静默降低成本。算法与字段验证以 `record.rs`、`wrap.rs`、`unwrap.rs` 和 `crypto/kdf.rs` 为准。

只复制信封而没有 `device.secret` 不能解封；复制完整软件目录并知道口令则可以在其他机器解封。`device.secret` 不是不可复制的机器身份，目录复制不能称为硬件绑定。丢失它时不能靠生成新的文件恢复旧信封。

### 3.3 可迁移归档：`anp-keyd-archive` v1

归档与信封是两种格式。归档由导出时的独立口令保护，不依赖 `device.secret` 或原设备硬件，因此可离线猜测口令；保护强度依赖口令及 Argon2id 成本。

固定标识为 `format=anp-keyd-archive`、`version=1`、`derivation=bip39-entropy-v1`，使用 Argon2id 和 XChaCha20-Poly1305。公开元数据包含 DID、完整 kid、该钥匙的 thumbprint、created_at、wns_handle 及含 proof 的 DID 文档；密文载荷为 seed。AAD 绑定身份和规范化文档摘要。字段定义及验证见 `src/keystore/archive.rs`。

默认构建不包含 `export-seed`；启用该 feature 的构建不能声明受保护支持。受保护 socket 不导出明文 seed；受保护模式的常规备份恢复使用加密信封、device.secret 和经验证的配套材料。可迁移归档或助记词属于另行控制的离线维护流程，不能从数据面开放。

恢复同一 seed 就是恢复同一签名能力。历史副本无法靠删除当前文件收回，泄露处置仍依赖密钥轮换、身份迁移和验证方刷新文档。

## 四、授权模型与请求策略

### 4.1 主体、密钥角色与 grant

principal 表示经过 OS 认证的执行域；key handle 是数据库内部 UUID，kid 是公开 DID 方法标识，两者不能混用。密钥角色为 root、hot、recovery、challenge 或 unclassified；只有已验证、active 的 hot key 可进入数据面 grant。

角色由管理端确认，并绑定信封、公钥及文档摘要。重新登记保留 handle，但撤销旧授权并重新确认角色；根绑定密钥不能通过改标签变成热密钥。文件摘要、文档或身份状态改变后必须重新验证。

grant 绑定 principal、exact key、不可变 policy 版本、boot epoch、绝对到期和最大次数。引用使用 32 随机字节的 hex 编码；知道引用不代表另一个主体获得授权。policy 更新创建新版本，既有 grant 不自动扩权。

密钥加载与授权分开管理：解锁不创建 grant，grant 不解锁密钥。禁用主体、撤销授权和轮换分别处理相应状态；撤销 A 的 grant 不应清掉 B 仍获准使用的共享热密钥。

### 4.2 固定请求 profile

当前 `anp-http-v2` 支持精确 HTTPS DNS origin、HTTP 方法、精确路径、禁止或精确 query、空或有界 body。没有通配域名、路径正则、业务 JSON 表达式或可执行策略。

`CanonicalHttpRequest` 是策略匹配、请求摘要、签名基和响应 URL 的共同来源。host 小写、移除默认 443 端口；拒绝 userinfo、fragment、IP 地址、百分号编码、点路径、重复斜线、重复 query 键及含混头。非默认端口使用规范十进制表示。当前 body 上限 16384 字节，整帧上限 65536 字节；策略允许的 body 更大也不会提高传输上限。

body 显式区分 absent 和 present；present 的空数组也签 Content-Digest。签名固定覆盖 `@method`、`@target-uri`、`@authority`，有 body 时覆盖 `content-digest`，有 content-type 时覆盖该头。调用者不能覆盖 profile、减少覆盖面或指定任意签名基。

签名期限不超过 grant 墙钟截止、单调剩余期限和 300 秒中的最小值。调用者可提交对端 nonce，但其来源和一次性语义仍由网络适配器及验证方管理。签名核心不会通过联网判断业务是否已经授权。

## 五、签名事务、撤销与不确定结果

### 5.1 提交顺序

有界协调器串行处理签名提交和管理撤销，避免最终授权检查与实际签名间失去顺序。数据排队有上限，管理请求有保留容量并优先处理；Argon2 与硬件解封使用独立单槽，不在签名协调器内等待。

一次新签名的顺序如下：

1. 认证主体，校验 request UUID，规范化 HTTP 请求并计算摘要。
2. 查找 `(principal_id, request_id)`；已有 ID 必须匹配同一 grant 和摘要。
3. 重新检查主体、hot 角色、文档/信封、grant、策略、boot epoch、双时钟期限和配额。
4. 事务 A：写入 reserved 请求、消费一次额度、写审计并提交；失败不调用签名后端。
5. 再检查时间边界，调用签名后端。
6. 事务 B：持久化 completed、结果、期限和审计；确认提交后才向 socket 交付结果。

事务 B 不确定时先查询持久状态，不释放内存中的签名。后端错误可能发生在签名之后，不能把所有失败都标成“未签”；已确定 KEY_LOCKED 可记 failed_reserved，不能确定的保留 outcome_unknown。

### 5.2 请求与重试语义

```text
新请求 → reserved → completed
                 ├→ failed_reserved
                 └→ outcome_unknown
```

预留后的失败仍消费次数。相同 ID、同一输入的重试只查询或复用已有结果，不重新签名、不再次扣次；改变 grant 或摘要返回冲突。达到配额阻止新预留，但最后一次有效结果在其交付条件仍成立时可复用。

`completed` 只表示签名结果已持久化；不表示 socket 已送达，更不表示远端业务已执行。缓存过期、授权撤销或重启后可保留状态，但不再交付签名。清扫删除缓存结果，永久保留请求 ID tombstone，防止旧 ID 重新成为新请求。

### 5.3 撤销、锁定和时钟

撤销在协调器内持久化并确认，之后不开始新签名；先前完成的签名可能仍在网络上传输，不能追回。客户端不得因超时自行换 ID 重签。

锁定移除驻留密钥并递增 generation；在途解封返回时重新核对 generation、管理 epoch 和文件状态，旧结果丢弃。运行期间同时检查墙钟和包含休眠时间的单调期限，时钟回拨不延长授权。

每次启动先完成恢复事务：递增 boot epoch、撤销旧 active grant、将未完成 reserved 请求置为 outcome_unknown、废止未完成批准，并保持所有密钥锁定，之后才监听。当前不支持透明无人值守恢复。

## 六、持久化、生命周期与审计

### 6.1 数据库是真源

当前 SQLite schema 为 3，通过固定的 rusqlite 访问层使用 bundled SQLite。单实例锁、rollback journal DELETE、synchronous EXTRA 和外键设置均需校验；不支持网络文件系统或多 daemon 并行写入。

数据库保存主体、vault、角色与摘要、不可变策略、grant、请求、批准意图、跨文件操作及审计。它不保存 seed、KEK、密码或原始敏感 HTTP body。结果缓存只保存生成头及 profile 覆盖的 content-type，不持久化任意调用方凭据头。

初始化是显式操作。启动拒绝缺失、损坏、链接、外来实例或更新 schema 的状态，不能静默新建空库。支持的旧 schema 在校验后事务升级；失败回滚。数据库持久化或审计失败停止新签名，不能把撤销失败谎报为成功。

### 6.2 精确管理操作

管理员通过 prepare 获取 operation_id、digest、effect 和 expires_at，检查后 commit。批准绑定同一管理员、boot/mutation epoch、墙钟及单调期限，单次使用；状态变化后旧批准可能失效。

普通管理包含主体启停、vault 登记、角色确认、策略发布、grant 创建/撤销和已签文档安装。`RegistrationChallenge` 与 `RotateHotKey` 经专用 complete-secret-operation 完成：秘密走认证后的独立有界二进制帧，根密钥瞬时解封、用后销毁，不驻留供 Agent 使用。

注册挑战限定 exact root key、HTTPS origin 和 32 位小写 hex challenge。来源真实性由可信管理适配器校验，daemon 不接受 Agent 的“已经验证”标签。256 字节长度上限不能隔离文档 proof；普通数据面没有 raw/challenge 接口。

轮换使用预先配置的新热密钥，重建并签署公开文档、撤销旧 grant、退休旧方法。返回本地文档不表示网络发布成功；管理员或可信适配器须独立发布、验证新方法，再建立运行期授权。

### 6.3 跨文件恢复与迁移

SQLite 不能原子提交信封或文档文件。文档安装/轮换先保存经过批准和审计的意图，使相关身份进入维护状态，再原子替换文件并同步文件及父目录，最后完成数据库审计。重启只按已存旧/新摘要恢复；遇到未知内容拒绝服务，不能猜选一份或自动重写。

离线迁移先停止旧写者、取得维护锁、复制到受保护 staging 并核对摘要，在可信终端逐钥验证恢复副本。源路径被禁用，恢复副本由管理员保护；新 vault 登记后角色未分类、密钥锁定，需确认角色并重新建权。恢复演练必须完成真实认证，不能只证明文件可解密。

更新和回滚只允许兼容的受保护版本；不因失败开启 v1。恢复成套备份后旧 grant 作废，网络已发布的文档仍须单独处置。迁移与恢复工具见 `deploy/linux/migrate-vault.py` 和 `src/security/migration.rs`。

### 6.4 审计证据的范围

SQLite 的状态变更和审计事件同事务提交。JSONL 按序导出到 audit-export/events.jsonl，原子替换；导出失败保留上一份完整投影，并暴露 audit_projection_healthy。数据库审计失败与投影失败的处置不同，不能把 JSONL 当第二套授权真源。

旧开发日志及锚只作为校验后的历史关联，不继续作为受保护签名真源。哈希链检测一致性，OS 权限防止 Agent 修改。独立采集器通过固定 SSH 端点保存不可变检查点，可发现源侧整体回滚或重写；它不替代本地审计，也不防御源端与采集器主机一起失陷。

审计保存请求摘要、授权依据和签名结果状态，不能保证所有解析前拒绝或网络发送都有业务回执。

## 七、资源限制与秘密内存

资源默认值来自 `src/security/limits.rs`，配置拒绝未知字段、0 及越界值。

| 项目 | 默认值 |
|---|---|
| 数据/管理活动连接 | 16 / 4 |
| 每主体活动数据连接 | 4 |
| 数据/保留管理队列 | 8 / 2 |
| 排队期限 | 2000 ms |
| 整帧/响应期限 | 各 5 秒 |
| 每主体速率 | burst 64，每秒 32 |
| SQLite 页数上限 | 262144 页 |
| KDF 并发 | 单槽，不排队 |

整帧期限不会因慢客户端逐字节发送而刷新。磁盘满、审计失败及持久化不确定进入停止签名路径，清理驻留密钥；修复后重启仍执行撤权规则。上限是资源预算，不构成生产吞吐承诺。

长期驻留材料使用锁页和清零容器，口令帧、KEK 等临时材料显式清零；不能据此承诺运行时没有任何临时副本。受保护 systemd 配置结合服务 UID、dump/debug 限制、只读路径、零有效 capabilities、网络地址族及资源约束保护服务。mlock 不能代替 OS 进程隔离。

## 八、验证边界

| 层级 | 重点 | 不能替代的验证 |
|---|---|---|
| 单元与固定向量 | 推导、AAD、签名基、规范化、策略及事务失败路径 | 安装权限和真实对端行为 |
| 进程与多 UID | socket 互认、管理拒绝、跨主体、配额竞态、MCP | systemd 沙箱与整机重启 |
| systemd 主机 | 安装、隔离、自动恢复、真实开关机、损坏状态拒绝 | 其他平台或实体硬件能力 |
| 真实服务与 SDK | 注册、热密钥认证、nonce/body/过期拒绝、轮换和恢复 | 未走过的高层 SDK API |
| 实体硬件专项 | 权限、持久化、复制和故障 | 软件替身或模拟器 |

Linux systemd 主机验收已完成，覆盖完整关机和启动；它不证明所有宿主、平台及硬件都通过。容器和模拟器结果不能被写成实体硬件或整机验收。

变更按范围运行默认/MCP 测试及 Clippy、格式与部署负例；日志测试设置 `RUST_LOG=info`。Unix socket EPERM 先排除环境限制。解析及规范化扩展需要歧义负例，适配扩展需要跨语言实际发送验证。所有攻击和故障注入使用临时身份与一次性环境，不操作真实用户密钥。

## 九、硬件根与发行边界

硬件绑定给 KEK 增加 HS 材料，当前 Ed25519 seed 解封后仍由软件签名。硬件封装、硬件内签名和备份可迁移性是三个独立属性，不能互相替代。

| 后端 | 实现方式 | 当前声明 |
|---|---|---|
| Secure Enclave | P-256 ECDH，信封携带恢复共享材料所需的信息，钥匙串 tag 定位 | 芯片 ECDH 路径可用；正式签名身份、钥匙串持久化与跨进程重启恢复未验收 |
| TPM 2.0 | TPM 创建/解封，持久句柄定位 | 部署范围已验收：设备访问、systemd 沙箱、跨进程封存/打开、跨 UID 拒绝、删除后拒绝；实体芯片保护未声明 |
| hardware-software | 文件形式测试替身 | 不是硬件；release 构建拒绝该 feature |

不可用的指定硬件后端必须报错，不能静默降级软件。v2 信封的 hardware 与 hs_ciphertext 成对存在；空封装字符串不代表未绑定硬件。当前 TPM 路径不能被描述为已具有启动状态/PCR 证明。SE 分发需要匹配的签名与 entitlement；单次临时密钥实验不证明持久化可发行。

## 十、当前不支持的能力

- macOS 受保护执行域与正式发行；当前只有 `macos-boundary-preview`，`protected_supported=false`。
- Secure Enclave 的正式签名、持久密钥、分发和主机生命周期验收。
- 实体 TPM 硬件保护声明；需要真芯片上的故障、升级、换机和恢复验收。
- 单个 workload 的受限无人值守恢复；重启仍然撤销授权并锁定密钥。
- 通配域名、路径正则、字段级 body/query、多 origin、header 约束等扩展请求策略。
- 跨主体委托链；grant 只绑定单个 principal。
- 远程多租户 KMS、通用密码管理器、完整企业 IAM，以及不可信宿主管理员下的密钥保密。

每项能力单独定义威胁模型和验收，不因 Linux 首版完成而自动获得安全声明。
