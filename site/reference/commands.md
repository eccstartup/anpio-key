# 命令行

先选运行模式：

- **Linux 受保护部署**：管理命令和 Agent 数据命令走不同的 socket，使用不同的系统账号。
- **开发模式**：同一个账号下的 `serve` / `sign`，只适合联调和临时身份。

完整参数以当前二进制的 `--help` 为准。

## Linux 受保护部署

先装服务，再建身份。安装入口在仓库根目录：

```bash
./install.sh
```

它按平台调用 `deploy/linux/install.py` 或 macOS 的安装器，**只装服务**：构建、校验摘要、建账号、安装并启动 systemd 服务，不建身份、不收口令、不发 grant。装完用 `anpio-cli did create --host HOST --handle NAME --key anpio-key` 把新身份 provision 进服务——一条命令、一次口令确认，服务建钥匙、发布策略、发 grant，CLI 签首份文档并注册 handle（详见[安装](/guide/install)）。

已有身份（钥匙还在本地 store）用接管：macOS 是 `sudo ./install.sh --adopt --identity FILE --cli-binary PATH --cli-sha256 HASH --target URL`；Linux 的接管命令尚未提供。

`--bootstrap` 是原来的老路：按平台调 `deploy/*/bootstrap.py`，生成一次性身份、建热钥匙、离线迁入、登记 vault、确认角色、发布策略、创建 grant 并解锁。它还在，但**只用于一次性预览身份**；macOS 上固定 `_anpagent` 和 `--hardware none`。

下面的管理命令用于之后的日常操作。

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
| `admin --config FILE complete-secret-operation --operation-id UUID --digest HASH` | 管理员 | 完成注册 proof 或热钥匙轮换；`--new-secret` 时读两遍新口令，`ProvisionIdentity` 走它 |
| `admin --config FILE sign-first-document --vault-id UUID --did DID --document FILE [--domain HOST] [--challenge HEX]` | 管理员 | 签一份 DID 的**首份**文档；只在 `ProvisionIdentity` 之后紧接着有效，之后走 `SIGN_DOCUMENT_PROOF` |
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

### 命名钥匙

`key` 这一组按名字管钥匙，不需要 DID。名字只是本机的地址；host、path、DID 和注册属于 `anpio-cli`。

| 命令 | 做什么 |
|---|---|
| `key create [--name NAME] [--algorithm ed25519\|x25519] [--label LABEL]` | 铸一把命名钥匙；24 词只显示一次，口令读两遍后才写封装。不给名字时生成 `k-xxxxxxxx` |
| `key list` | 名字、指纹、是否解锁 |
| `key unlock --name NAME` | 按名字解锁（口令从终端读） |
| `key rotate --name NAME` | 同名换一把新钥匙 |
| `key sign-document --name NAME --keyid KEYID --document FILE [--domain HOST] [--challenge HEX] [--out FILE]` | 管理员动作：给一份 JSON 文档签 proof，不经过 grant |
| `key bind-did --identity FILE --out DIR [--source-root DIR]` | 接管前把命名钥匙重封成 DID 绑定封装；种子、公钥、指纹不变，源 store 只读 |

`x25519` 只能用于 ECDH，不能签名。命名钥匙进不了受保护 catalog；要把它们交给受保护服务，先用 `key bind-did` 重封，再按 macOS 的 `--adopt` 接管。

### grant

`grant create` 在受保护管理面上发 grant，只支持两种用途：`--purpose http-authentication`（要 Hot 钥匙和 `--target`）与 `--purpose document-proof`（要 Root 钥匙）。`--kid` 直接点名已登记的钥匙，`--key` 用本地名字反查 DID 并与指纹核对，两者只给一个。`--ttl` 默认 `24h`，`--uses` 默认 `100`；提交前会把完整摘要打出来问一次。

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
