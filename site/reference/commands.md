# 命令行

先选运行模式：

- **Linux 受保护部署**：管理命令和 Agent 数据命令走不同的 socket，使用不同的系统账号。
- **开发模式**：同一个账号下的 `serve` / `sign`，只适合联调和临时身份。

完整参数以当前二进制的 `--help` 为准。

## Linux 受保护部署

安装和初始化用仓库根目录的一条命令：

```bash
./install.sh --bootstrap --did-host agents.example.com \
  --target https://api.example.com/v1/status
```

它按平台调用 `deploy/linux/bootstrap.py` 或 `deploy/macos/bootstrap.py`，按顺序生成身份、创建热钥匙、离线迁入、登记 vault、确认角色、发布策略、创建 grant 并解锁。macOS 只用于本机预览，固定使用 `_anpagent` 和 `--hardware none`。只安装服务时去掉 `--bootstrap`。下面的管理命令用于之后的日常操作。

安装入口本身按状态工作，重复执行是空操作：

| 命令 | 做什么 |
|---|---|
| `./install.sh` | 未安装则安装；已安装则打印状态并退出 0，不构建、不提权 |
| `./install.sh --status` | 只读显示状态、是否运行、已装二进制摘要和账号 |
| `./install.sh --verify` | 对已安装服务跑只读验收，失败退出 3 |
| `./install.sh --upgrade` | 用当前构建替换二进制，保留配置和状态；摘要相同不重启 |
| `./install.sh --uninstall` | 停服务并删除二进制和服务单元，保留配置、状态和账号 |

退出码：0 成功或本来就是这个状态，2 状态不符，3 验收失败，4 缺前置。任何动作加 `--dry-run` 都只打印计划。

| 命令 | 谁用 | 做什么 |
|---|---|---|
| `build-info` | 任何人 | 查看构建支持哪些能力；不代表这台机器已经配置安全 |
| `serve-protected --config FILE` | 服务账号 | 启动 daemon；由安装器生成的 systemd 服务调用 |
| `data --config FILE --file REQUEST.json` | Agent | 发一条数据请求，例如签名、查授权、查结果 |
| `admin --config FILE status` | 管理员 | 查看服务状态 |
| `admin --config FILE catalog` | 管理员 | 查看钥匙、策略和主体 |
| `admin --config FILE list-principals` | 管理员 | 查看已登记的主体 |
| `admin --config FILE prepare --file CHANGE.json` | 管理员 | 准备一次精确变更，返回摘要和影响 |
| `admin --config FILE commit --operation-id UUID --digest HASH` | 管理员 | 提交刚才核对过的变更 |
| `admin --config FILE unlock --vault-id UUID --did DID --kid KID` | 管理员 | 读取口令并解锁指定热钥匙 |
| `admin --config FILE lock-all` | 管理员 | 移除驻留内存的钥匙 |
| `admin --config FILE complete-secret-operation --operation-id UUID --digest HASH` | 管理员 | 完成注册 proof 或热钥匙轮换 |
| `probe --security --config FILE` | 任何人 | 检查当前账号能访问哪个端点、配置是否有效、支持声明是什么 |

Agent 可用的数据操作：

| 操作 | 用途 | 默认 |
|---|---|---|
| `GET_CAPABILITIES` | 查看协议版本、可用操作、用途、grant 类型 | 开 |
| `LIST_AUTHORIZED_KEYS` | 查看当前主体能用的钥匙 | 开 |
| `GET_GRANT_STATUS` | 查看 grant 的期限和剩余次数 | 开 |
| `GET_DOCUMENT` | 取某把钥匙的公开文档 | 开 |
| `SIGN_HTTP` | RFC 9421 HTTP 请求签名 | 开 |
| `GET_REQUEST_STATUS` | 用原 `request_id` 查结果 | 开 |
| `SIGN_ORIGIN_PROOF` | ANP origin proof | 关 |
| `RENEW_GRANT` | 续 session grant，只延期不加次数 | 开 |
| `SIGN_PURPOSE` | 设备/应用用途断言 | 关（逐用途） |
| `ECDH` | X25519 协商，返回共享密钥 | 关 |
| `SIGN_OBJECT_PROOF` | W3C 对象 proof | 关 |
| `SIGN_DOCUMENT_PROOF` | DID 文档 proof（根键） | 关 |

关着的操作不会出现在 `operations` 里，发过去是 `OPERATION_DISABLED`。各操作的字段、编码和错误码见仓库 [ADAPTER.md §11](https://github.com/eccstartup/anpio-key/blob/master/docs/ADAPTER.md)。

Agent 不能解锁、不能索取私钥、不能请求任意字节签名。唯一能用根键的数据面操作是 `SIGN_DOCUMENT_PROOF`，它的 grant 只能由管理面签发；换设备、改文档、注册这些根操作全部留在管理面。

管理 JSON 的格式和完整流程见[本机使用](/guide/local-use)，接入代码见[接到 Agent 上](/advanced/agent)。

## 开发与离线维护

| 命令组 | 范围 |
|---|---|
| `serve` / `stop` | 旧开发 daemon；不是 v2 的 systemd 服务管理 |
| `sign` / `list` / `status` / `document` / `unlock` / `lock` | 旧 socket 客户端；同账号不承诺隔离 |
| `spec` / `keygen` / `publish` / `verify-doc` | 本地生成和处理身份、公开文档 |
| `add-recovery-key` / `add-agreement-key` / `rotate-hot-key` / `remove-key` / `migrate` / `deactivate` | 本地生命周期操作；托管目录拒绝这类直接写入 |
| `import-mnemonic` / `import-archive` | 从助记词或归档恢复身份并重新封装 |
| `probe` | 开发环境体检；与 `probe --security` 不同 |

控制终端不能证明“对面是人”，程序也可以创建 PTY。生命周期权限靠操作系统账号和受信管理边界，不要因为命令写着“给人用”就认为 Agent 调不到。

## 构建 feature

| feature | 增加什么 | 限制 |
|---|---|---|
| `mcp` | MCP 前端 | 保护模式必须显式传 `--config` |
| `seed-export` | `export-seed` | 默认没有；启用后不声明受保护支持 |
| `hardware-se` | macOS Secure Enclave 解封 | 开发签名身份下持久化与主机生命周期已验收；正式分发未完成 |
| `hardware-tpm` | Linux TPM 解封 | 部署范围已验收，实体芯片保护声明未做 |
| `hardware-software` | 测试替身 | 不是硬件；release 构建拒绝 |

数据面的新签名路不是构建 feature，而是运行配置里的独立开关，默认关。开关名、审计事件和逐用途清单见[默认行为](/reference/defaults)和仓库 [ADAPTER.md §11.7](https://github.com/eccstartup/anpio-key/blob/master/docs/ADAPTER.md)。
