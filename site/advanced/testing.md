# 测试与验证边界

这一页写给要改代码或判断“这个结论能不能信”的人。

不同层级的测试回答不同问题：单元测试证明函数逻辑，容器测试证明进程协作，真机测试才证明安装权限和硬件。任何一层通过，都不能代替另一层。

## 先跑本地回归

```bash
RUST_LOG=info cargo test --locked --offline
RUST_LOG=info cargo test --locked --offline --features mcp,hardware-software
cargo clippy --locked --offline --all-targets --features mcp,hardware-software -- -D warnings
```

离线命令要求依赖已经缓存。

## 各层能证明什么

| 层级 | 能证明 | 不能代替 |
|---|---|---|
| 单元测试与固定向量 | 推导、加密、签名基、请求规范化、策略、事务失败路径 | 安装权限和真实对端 |
| 多进程、多账号 | socket 互认、管理拒绝、跨主体隔离、配额竞态、MCP | systemd 沙箱和整机重启 |
| systemd 真机 | 安装、隔离、自动恢复、真实开关机、损坏状态拒绝 | 其他平台或实体硬件 |
| 真实服务与 SDK | 注册、热钥匙认证、nonce/body/过期拒绝、轮换、恢复 | 没走过的高层 SDK API |
| 实体硬件 | 权限、持久化、复制、故障 | 软件替身或模拟器 |

容器通过不等于你的宿主通过；模拟器通过不等于实体芯片通过。

## 测试文件分别管什么

| 文件 | 回答的问题 |
|---|---|
| `src/**` 单元测试 | 这个函数在它的假设下对不对 |
| `tests/cli.rs` | 真启动二进制、在终端里敲命令，这一层还正常吗 |
| `tests/signature_end_to_end.rs` | 整条签名链路还通吗 |
| `tests/negative.rs` | 产品承诺的边界今天还成立吗 |
| `tests/tpm.rs` | TPM 封装、解封和根丢失拒绝 |
| `tests/vectors/` + `tests/vectors.rs` | 外部标准还认不认我们的实现 |
| `tests/probe.rs` | 体检报告说的是不是真的 |
| `tests/mcp.rs` | MCP 工具和参数边界 |
| `tests/hardware.rs` | 硬件绑定路径的形状 |
| `tests/no_key_material_on_disk.rs` | 跑完一遍后，磁盘上有没有密钥材料 |

## 目录约定

部署与验收脚本按运行时机分成两层：

| 路径 | 运行方式 | 修改本机状态吗 |
|---|---|---|
| `deploy/<platform>/tests/` | CI 每次跑；`python3 -m unittest discover` | 不修改 |
| `deploy/<platform>/acceptance/` | 人工在目标机或一次性容器里跑，需要 root | 只操作显式隔离的临时实例 |
| `deploy/<platform>/` 根目录 | 安装、更新、迁移和日常运维入口 | 会，需按文档确认 |

命名规则：下划线 `test_*.py` 属于 CI 单元测试，连字符 `test-*.py` 或 `acceptance_*.py` 属于真机验收。看到两种名字不是笔误，是刻意区分。

## 向量测试失败了该怀疑谁

`tests/vectors/` 里每条 JSON 都带 `_source`，写明出处。分两类：

- **标准文本的抄本**：RFC 8032、7638、8037、9421、8785 等。失败先怀疑实现。改向量让测试变绿，等于删掉这个测试存在的理由。
- **兄弟实现算出来的值**：例如 `anp_sdk_*`。失败说明两个实现分家了，两边仓库都要看，对方可能才是对的。

## `hardware-software` 是什么

它把“封起来的熵”存在文件里，而不是芯片里。作用只是让没有硬件的机器也能测 v2 信封格式：版本分派、AAD、拒绝降级。

`probe` 不会把它当成“这台机器有硬件根”。`tests/hardware.rs` 验的是路径形状，不是“HS 真的出不了这台机器”。

## 硬件按平台单独验收

- **Secure Enclave**：开发签名身份下持久化、跨进程重启和主机生命周期已在本机验收；Developer ID 正式分发未完成。
- **TPM**：部署范围已验收；三条硬件测试标记为 `#[ignore]`，需要显式运行。实体芯片保护声明仍需真机验收。

平台说明和未验项见[硬件根](/advanced/hardware-root)。

## 部署与故障验收

`deploy/linux/acceptance` 下的 `test-boundary.py`、`systemd-checks.py`、`systemd-boot-check.py`、`anp-service-acceptance.py` 只对显式隔离环境操作；故障注入不在日常主机执行。

macOS 使用 `deploy/macos/acceptance` 下的 `check-local-use.sh`、`check-agent.sh` 和 `se-persistence.py`，同样只对临时实例操作。

所有验收都使用临时身份，并记录代码基线、feature、部署模式、实际范围和未验项。历史结果不能当作当前运行结果，也不能扩大支持声明。
