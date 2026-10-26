# 硬件根

默认情况下，钥匙用“口令 + `device.secret`”加密后存在磁盘上。把整个目录拷走、又知道口令，就能在另一台机器上解开。

硬件根再加一份材料：它由芯片保管，不在磁盘上。三样凑齐才能解封：

```text
口令 + device.secret + 芯片里的 HS
```

注意：硬件只参与**解封**。解封之后，Ed25519 签名仍然在普通内存里执行。所以不能说“私钥从不离开硬件”。

## 可用的后端

| 后端 | 怎么用 | 当前状态 |
|---|---|---|
| Linux TPM 2.0 | 构建 `hardware-tpm`，通过 `/dev/tpmrm0` 解封 | 部署范围已验证；实体芯片保护声明未做 |
| macOS Secure Enclave | 构建 `hardware-se`，通过登录钥匙串解封 | 芯片 ECDH 路径可用；正式签名、持久化和重启恢复未验收 |
| `hardware-software` | 文件形式的测试替身 | 不是硬件；release 构建拒绝 |

本地生成钥匙时需要对应的构建：

```bash
cargo build --locked --release --features hardware-tpm   # Linux
cargo build --locked --release --features hardware-se    # macOS
```

生成钥匙时指定后端：

```bash
anpio-key keygen --spec mybot.spec.json --hardware tpm
anpio-key keygen --spec mybot.spec.json --hardware secure-enclave
```

指定的硬件不可用时会报错，不会悄悄退回纯软件封装。

## Linux TPM

安装时一条命令构建 TPM 后端并把设备交给服务：

```bash
./install.sh --tpm-device
```

同一次运行里完成身份、策略、grant 和解锁：

```bash
./install.sh --tpm-device --bootstrap --did-host agents.example.com \
  --target https://api.example.com/v1/status
```

绑定钥匙和热钥匙都会用 TPM 后端生成。安装器只开放 `/dev/tpmrm0`，并把 TPM 工具固定到该设备。

已经验证的范围：设备授权、systemd 沙箱、跨进程封存/打开、跨 UID 拒绝、删除密钥后无法再打开。

没有验证的范围：实体芯片上的故障、升级、换机和恢复。`swtpm` 模拟器通过不等于实体 TPM 通过。完整的部署和验收步骤见仓库 `deploy/linux/TPM.md`。

## macOS Secure Enclave

SE 依赖用户的登录钥匙串，所以必须有一个在图形登录会话里运行的助手。`admin se-session` 就是做这件事的：

- 只接受一把指定的热钥匙；
- 最长 900 秒；
- 每秒心跳，5 秒收不到就结束；
- 注销、切换用户、休眠或助手退出后，锁钥、撤销 grant、作废旧批准；
- 不会自动恢复 grant。

正式签名身份、持久 SE、分发、注销/重启等整机生命周期还没有验收。合成 HS 的桥接测试不等于持久 SE 证据。协议细节见仓库 `deploy/macos/SE-SESSION.md`。

## 硬件丢了怎么办

绑定硬件后，光复制信封文件解不开，必须换回原芯片或事先准备好的恢复材料。

- 助记词和便携归档不依赖硬件，可以换机器，但它们是完整的身份材料，要单独保护；
- 硬件失效后不能凭空恢复 HS；
- 应该在设备还能用时，准备并实际演练一份恢复材料。

## 相关页面

- [迁移与恢复](/advanced/recovery)
- [测试与向量](/advanced/testing)
- [设计说明](/design/)第九节
