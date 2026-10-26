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

已实现：独立管理通道与服务 UID 认证、主体/角色/策略、exact-key grant、期限与撤销、事务签名、去重、结果恢复、资源限制、旧审计关联、离线迁移与恢复校验、管理注册 proof、预配置热密钥轮换、发行特性检查。

签名核心不联网；发布 DID 文档由独立适配器执行并核验。历史明文导出无法撤回，不提供远程多租户 KMS 或普通 Agent raw 签名。
