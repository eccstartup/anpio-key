# TODO

当前受保护改造的进度以本地 `docs/plan-security-v6.md` 为准；此处列未完成的发行工作。

- [x] Linux systemd 真实主机验收已完成；仅正式 Linux release 且显式受保护模式声明支持。
- [x] macOS 持久 SE 与主机生命周期验收：真实 SE＋开发签名助手＋独立 UID 服务通过；用户切换、注销/重新登录、短/长休眠、整机重启、升级、密钥丢失、签名身份与钥匙串权限变化均已验收，临时密钥均按精确标签删除并复查。保护声明仍为 `macos-boundary-preview`、`protected_supported=false`。
- [x] macOS 非登录 launchd 上下文与边界重述：2026-10-19 用一次性 system job（`UserName=_anpagent`，raw 与 `SessionCreate` 两种）运行同一签名探针，数据保护钥匙串均以 `errSecNotAvailable (-25291)` 拒绝；登录会话正对照与删除后拒绝通过。边界据此重述为“Agent 必须运行于非登录 system LaunchDaemon；管理员图形登录会话内（包括 `sudo` 启动）的代码属于受信管理输入”。同签名、同访问组探针在登录/继承会话内跨 UID 重算 HS 的反例仍保留，不宣称 UID 隔离；证据见 `docs/validation/macos-se-system-context-2026-10-19.md`。
- [ ] macOS 物理 Secure Enclave/设备故障路径：本机无法诱发，仅验证了软件可见拒绝（探测报告 NOT USABLE、删除密钥后报“no key with that label”）。
- [ ] macOS SE 正式分发：当前只有本机 Apple Development 身份与短期 profile；需 Developer ID 证书、公证、长期安装身份、正式发行产物与分发审核。
- [x] macOS 本机预览的交互初始化流程（`install.sh --bootstrap`）：2026-10-19 在本机空状态安装上跑通。先整体归档旧预览安装，再用修好的 `c57ff641…` 重装，依次完成 keygen、publish、rotate-hot-key、离线迁移（两次恢复校验）、登记 vault、确认 root/hot 角色、发布策略、创建 grant 和解锁；五个口令命令全程无提示超时，`signing_available=true`、`protected_supported=false`，catalog 与 `service.json` 一致。验收同时修掉三个缺陷：新装缺 `state/vaults`、迁移拒绝 `/var/root` 的 `/var` 符号链接、PTY 下 termios `EINTR` 被误报为终端不可用。详见 `deploy/macos/HISTORY.md`。
- [ ] 真·全新 macOS 主机上的 `install.sh --bootstrap` 复跑（含首次创建 `_anpio`、`_anpagent`、`_anpio_sign`、`_anpio_admin`）：本机专用账号已存在，`provision-accounts.py` 明确拒绝接管；删除并重建账号不可逆，未在本机执行，需在无这些账号的主机上验收。
- [ ] 改用 Anpio Key 名称后，现存的旧名安装需要各跑一次迁移并真机验收：macOS 用 `deploy/macos/migrate-name.py`（改 `_anpkeyd*` 记录名、`/Library/ANPKeyd`、launchd label），Linux 按 `deploy/linux/README.md` 的 `usermod`/`groupmod` 步骤。两者都保留原 UID/GID，但没有自动回滚；本机尚未执行。
- [x] TPM 部署范围验收（Docker + 内核 `tpm_vtpm_proxy`）：安装、设备权限、systemd 沙箱、服务 UID、跨进程封存/打开、跨 UID 拒绝、删除后拒绝全部通过；`acceptance_scope_complete=true`，报告仍记录 `virtualization=docker`、`physical_tpm_acceptance_complete=false`。
- [ ] 实体 TPM 硬件保护声明（可选）：用真芯片复跑并覆盖句柄/设备丢失、权限变化、设备故障、升级与恢复、换机复制；不作该声明前保持 physical=false，`swtpm` 结果不得当作物理验收。
- [x] U4 独立审计采集器、SSH 固定端点、原子保管、回滚/分叉/崩溃/断网验收；交付部署模板与两容器验收。保持本地审计签名继续策略，不承诺在线强制锚定或非审计状态保护。
- [ ] 受限无人值守恢复（须先指定 workload 与可信解封机制）。
- [ ] 按实际需求扩展注册 challenge 格式；当前仅支持管理端精确批准的 awiki 32 位小写 hex 格式。
- [x] 外部 awiki-cli-rs2：依赖改造已完成并推送——只删掉 `../anp/...` path 依赖，保留 `anp =1.0.3`、`anp-identity =0.2.3` 原版本钉（二者 crates.io 上均有），`Cargo.lock` 只补 `source`/`checksum`；`cargo check --locked --workspace` 通过、`cargo test -p awiki-im-core --lib` 1522 项全过。提交 `a8c5663c` 已推到 fork `eccstartup/awiki-cli-rs2` 的 `eccstartup` 分支，未推上游、未开 PR。升级 `anp-identity` 0.2.5 需先做 awiki 自己的 DID 文档迁移（0.2.5 拒绝 P6 legacy bundle，185/1522 测试失败），单列。本仓库侧交付已完成：Node v2 客户端及 anp-sdk connector，SDK 侧最低兼容版本 `@connectx-sdk/core@0.4.2`。

强对接（awiki-cli-rs2 + anpio-cli，四类密钥全部托管）的接口形状已冻结在 `docs/ADAPTER.md` §11，`0x03 = X25519` 已钉住；下面按交付物各一条，未实现前能力协商里不出现对应操作名。

- [x] 强对接 P0：契约冻结（`docs/ADAPTER.md` §11、`0x03 = X25519`、能力字段名）已完成；`anpio_key::client::v2` 覆盖全部六个数据操作并按“不支持/未授权/过期/耗尽/锁定/冲突/缺失/忙/停服/策略”分类拒绝；`benches/sign_throughput.rs` 基线在本机（release，Apple Silicon）：规范化 1.07 µs、结构化签名 99.1 µs、文档 proof 106.0 µs，即签名核心约 1 万次/秒/核 —— 瓶颈不在 Ed25519，而在这条上游拼基路径与 socket/DB。socket 往返与 SQLite 预留/提交的代价要在跑着守护进程的 Linux 上量，bench 文件头写明了这一点。
- [x] 强对接 P1：`SIGN_ORIGIN_PROOF`（事实 `{method,meta,body,expires?,nonce?}`，签名基由 daemon 用上游 `anp::proof` 拼）、`RENEW_GRANT`（夹到 `min(now+max_duration, created_at+max_lifetime)`，次数耗尽 `GRANT_RENEWALS_EXHAUSTED`）、schema-4 session grant（`kind`/`created_at`/`max_renewals`/`renewals` 与 `grant_operations` 表）、`GET_CAPABILITIES` 的 `capability_schema`/`operations`/`purposes`/`grant_kinds`、策略 `schema_version: 2` 的七个 purpose 与各自 content、`features.sign_origin_proof`（默认关，启动落一条 `FEATURES` 审计）。`SIGN_HTTP` 的输出与审计形状不变。
- [ ] 强对接 P1 收尾：在 Docker/Linux 上用真守护进程跑 awiki did-auth 全链路（socket 往返、`SIGN_ORIGIN_PROOF` 与上游 `anp` 验签逐字节一致）；今天只有单元与协议层覆盖。
- [x] 强对接 P2（daemon 侧）：`device_signing` 角色与专用键（`ConfirmRole` 同时绑 purpose，绑一次定死）、`SIGN_PURPOSE`（每 purpose 一把键、一个开关，默认关）、schema 5 重建 `keys` 保住既有 grant 与 FK、审计只记 purpose/域/长度/摘要。Docker/Linux 验收：真 socket 上出设备断言、未知用途与未开用途分开拒绝、策略只能收窄、重试与拒绝不重复扣配额、断言字节不进审计链。
- [ ] 强对接 P2 收尾：awiki-cli-rs2 的 `sign_device_assertion` 改走 `SIGN_PURPOSE`，MLS KeyPackage 的设备断言由 daemon 出，客户端不再持 `{device}-sign`。
- [x] 强对接 P3（daemon 侧）：X25519 密钥（`0x03`，multikey 头 `0xec01`，thumbprint `x1_`）、`keyAgreement` 文档支持与 `key_agreement` 角色（曲线在注册和授权两处各判一次，错曲线/错关系在角色判断前就被拒）、`ECDH` 操作（`features.ecdh` 默认关，启动落一条 `ECDH_ENABLED`）、策略 `ecdh` purpose 的 peer 白名单（逐字节、无通配）、`add-agreement-key` 管理命令。共享密钥**不落库**：`requests.result` 恒为 NULL，重放得到 `completed`+空结果（客户端翻成 `OUTCOME_UNKNOWN`）；审计只记 `peer_fingerprint`/`peer_multibase`/grant。低阶 peer → `ECDH_PEER_INVALID`。RFC 7748 §6.1 向量逐字节过。
- [ ] 强对接 P3 收尾：在 Docker/Linux 上用真守护进程跑 secure-direct 建会话全链路（socket 往返、共享密钥与 RFC 7748 向量一致、重放拿不到第二次、peer 不在白名单被拒），并让 awiki-cli-rs2 的 secure-direct 改走 `ECDH`，客户端不再持 `{device}-agreement`。
- [x] 强对接 P4（助记词与自建）：`import-mnemonic` 用一个 24 词助记词恢复四类键（`bip39-entropy-v2`，`key-1` 字节与 v1 相同）；本机没有该 DID 的文档时按四把重建并自签；本机已有文档时以文档为准，热密钥的名字按公钥找回、轮换过的不恢复并明说。`keygen` 铸任何东西**之前**把 24 词当场显示一次（只写 tty），答"没抄"则一个字节不写。发布构建断言无导出路径：`tests/cli.rs` 跑真二进制，`export-seed` 是不认识的子命令、`--help` 上也没有。验收里可自测的那半已过：集成测试在两套独立布局上跑通"换台机器只用助记词完整恢复"，四把公钥逐个相同、文档四把。
- [x] 强对接 P4（管理平面）：`ReissueDocument` 收 `add`/`remove` 两个公开输入，daemon 自己拼无签名文档、根在**带凭据的完成步**才签；完成时重算并要求与批准时逐字节相同，批准之后文档被别人动过（哪怕语义等价）就拒签；根由 DID 路径段绑定，既不能 add 也不能 remove；`keyAgreement` 现在也能撤，撤销一台设备时签名键与协商键一起退休（此前会话协商能在撤销后继续）。`IssueDeviceKeys` 铸 `device-sign` + `device-agreement` 一对信封但不公布：名字在 prepare 时定下、完成时逐字核对，先解根再铸、两把都算完才落盘，口令错或硬件根不可用不留半套。**不接受调用方交进来的私钥** —— 已有身份走本机 `import-mnemonic`/`import-archive`，socket 上没有、也不打算有导入路径。入组四步与撤销见 `docs/ADAPTER.md` §7.4。
- [ ] 强对接 P4 收尾（客户端侧）：awiki-cli-rs2 与 anpio-cli 把本地私钥交出去（按 `docs/ADAPTER.md` §7.4 入组，或在本机 `import-mnemonic`），验收是客户端目录里不再有任何私钥文件，而登录、发消息、建会话三条路都正常。这一步在各自仓库跑，`anpio-key` 这边只提供数据面操作与管理变更。
- [x] 强对接 P5：`SIGN_OBJECT_PROOF`（对象 proof，只认绑了 `device_assertion` 的设备键，`proofValue` 走 multibase base58btc）与 `SIGN_DOCUMENT_PROOF`（完整文档、root 键、purposes 只允许 `assertionMethod`/`authentication`，可选 domain/challenge；上游给的裸 base64url 转成发布文档用的 `z` 字母表再返回）。文档绑定三条在**扣配额之前**判（`id` == 键的 DID、文档锚在这个 DID 的 `e1_`/`k1_` 指纹上、这次要签的 `{did}#{fragment}` 还挂在文档里），所以不合规文档是明确的 `PROOF_INVALID` 而不是 `OUTCOME_UNKNOWN`。两路各自一个开关、各一条启动审计（`SIGN_OBJECT_PROOF_ENABLED`/`SIGN_DOCUMENT_PROOF_ENABLED`），进了 `operations` 与策略 v2 的 `proof_purposes`，完成事件只记证明形状与摘要、不记正文。`anpio_key::client` 与 socket 分发同步。管理平面的根操作（`ReissueDocument`/`IssueDeviceKeys`/`RotateHotKey`）原本就在带凭据的完成步里、要求 SE 租约，本轮不新增数据面口子——换设备与改文档时 root 私钥一个字节都不出 daemon。
- [ ] 强对接 P5 收尾（客户端侧）：awiki-cli-rs2 与 anpio-cli 的 `sign_object_proof`/`sign_document_proof` 改走上面两条操作，不再自己拼 proof、不再为改文档去碰 root 私钥；换设备与撤销按 `docs/ADAPTER.md` §7.4 的四步走。
- [ ] 根密钥轮换：`e1_` 的 DID 就是根公钥的指纹，原地换根等于换身份，所以今天没有、也不该有"根不变只换私钥"的命令。要在仓库里写清楚"换根 = 新身份 + 撤销旧设备"的完整流程（含旧设备撤销后旧 grant、旧会话、旧协商键的处置），并给出一条可执行的 runbook。

已实现：独立管理通道与服务 UID 认证、主体/角色/策略、exact-key grant、期限与撤销、事务签名、去重、结果恢复、资源限制、旧审计关联、离线迁移与恢复校验、管理注册 proof、预配置热密钥轮换、发行特性检查。

签名核心不联网；发布 DID 文档由独立适配器执行并核验。历史明文导出无法撤回，不提供远程多租户 KMS 或普通 Agent raw 签名。
