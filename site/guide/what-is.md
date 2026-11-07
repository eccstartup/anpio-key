# 它是什么

Anpio Key 是一个跑在本机的服务，替 AI Agent 保管 did:wba 私钥（Ed25519 签名键和 X25519 协商键）。

Agent 要代表你访问网站时，把请求交给 Anpio Key；Anpio Key 检查许可后生成签名头，Agent 拿签名头去发请求。私钥始终在服务里，不会交给 Agent。

## 为什么需要它

网站靠数字签名确认“这是你”。签名需要私钥。

- 把私钥直接交给 Agent：它能长期保存、复制、外传；一次提示注入或一个坏依赖就可能带走。
- 用 Anpio Key：Agent 只有一个 grant。它只能在你批准的网站、路径、期限和次数内签名。

## 它怎么工作

```text
管理员
  │ 创建身份、发布策略、创建 grant、解锁
  ▼
anpio-key 守护进程 ── 私钥、状态、审计
  ▲
  │ 提交请求，拿回签名头
Agent
  │
  ▼
目标网站
```

管理员和 Agent 的操作是分开的：

- 管理员：登记身份、确认钥匙角色、发布策略、创建/撤销 grant、解锁。
- Agent：列出可用钥匙、读公开文档、请求签名、查询请求状态。

解锁不等于授权。钥匙解锁后，Agent 仍然需要一张有效的 grant 才能签名。

## 现在能做什么

数据面除了 HTTP 签名，还能做 ANP origin proof、设备/应用用途断言、W3C 对象 proof、DID 文档 proof 和 X25519 协商。基线六个操作（能力协商、列钥、查 grant、读文档、HTTP 签名、查请求结果）始终可用；其余各路各自一个开关，默认关，关着时发过去会被明确拒绝。

管理面负责身份、角色、策略、grant、解锁、轮换，以及设备入组与撤销。四类钥匙（根绑定键、热键、设备签名键、协商键）可以由一个 24 词助记词恢复；后铸的设备键不在词里，只能靠归档带走。完整清单见[命令行](/reference/commands)和仓库接入说明 §11。

## Linux 上的账号边界

正式部署用三个系统账号：

| 账号 | 做什么 |
|---|---|
| 管理员 | 人类操作管理命令，批准变更、解锁、撤销 |
| 服务账号 | 运行 daemon，保存私钥、状态和审计 |
| Agent 账号 | 运行整个 Agent 框架，只能请求签名 |

Agent 账号没有 sudo，也不能访问管理员进程或服务状态。只把签名子进程切到 Agent 账号不够，整个 Agent 框架都要在 Agent 账号下运行。

## 当前支持范围

| 环境 | 情况 |
|---|---|
| Linux 正式 release + 显式 `linux-protected-v1` | `protected_supported=true`，有上述账号边界 |
| Linux preview、调试构建 | `protected_supported=false`，同 UID 不隔离 |
| macOS 本机预览 | 有独立账号，但不是正式发行，`protected_supported=false` |
| macOS Secure Enclave | 开发签名身份下持久 SE 与主机生命周期已验收；Developer ID 正式分发未完成 |
| Linux TPM | 部署范围已验证；实体芯片保护声明未做 |

## 从哪里开始

- [五分钟跑通](/guide/quickstart)：先看效果。
- [安装](/guide/install)：安装到自己的机器。
- [本机使用](/guide/local-use)：建立边界后交给 Agent。
- [接到 Agent 上](/advanced/agent)：CLI、Node、SDK、MCP。
