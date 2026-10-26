---
layout: home

hero:
  name: Anpio Key
  text: 替 Agent 保管私钥，只按许可签名
  tagline: 跑在本机的服务。AI Agent 把请求交给它，它检查许可后生成 HTTP 签名；私钥始终留在服务里。
  actions:
    - theme: brand
      text: 五分钟跑通
      link: /guide/quickstart
    - theme: alt
      text: 它能保护什么
      link: /concepts/trust-model
    - theme: alt
      text: GitHub
      link: https://github.com/eccstartup/anpio-key

features:
  - title: 私钥不给 Agent
    details: Agent 通过本地 socket 提交要签名的请求，拿回签名头。接口里没有任何字段能取走私钥。
  - title: 每次签名都检查许可
    details: 许可写明哪把钥匙、哪个网站和路径、什么方法、有效期和次数。超出范围直接拒绝。
  - title: 撤销和重启立即生效
    details: 撤销后不再产生新签名；重启后所有旧许可作废、钥匙重新锁定。
  - title: 管理员和 Agent 分开
    details: Linux 上服务、管理员、Agent 用三个系统账号。Agent 改不了配置、策略和许可。
  - title: 默认不导出私钥
    details: 默认构建里没有导出明文的命令或开关。需要迁移时用单独的助记词或加密归档流程。
  - title: 签名核心不联网
    details: daemon 只在本机工作。发请求、注册和发布公开文档由客户端或管理员完成。
---

## 先看它做什么

Agent 要代表你访问网站，网站用 did:wba 验证签名。直接把私钥交给 Agent，一次提示注入、一个坏依赖或一条误发的日志就可能泄露。

Anpio Key 把私钥放在本机服务里，只给 Agent 一条签名通道：

```text
你（管理员）：创建身份 → 写许可 → 解锁
anpio-key：保管私钥，逐次检查许可
Agent：提交请求 → 拿到签名头 → 自己发送
```

## 先试一下

开发模式，五分钟，不建立安全边界：

```bash
cargo install --path .
mkdir -p /tmp/keyd-lab
anpio-key --root /tmp/keyd-lab spec \
  --host example.com --path agents/mybot --out /tmp/keyd-lab/mybot.spec.json
anpio-key --root /tmp/keyd-lab keygen --spec /tmp/keyd-lab/mybot.spec.json
anpio-key --root /tmp/keyd-lab serve
anpio-key --root /tmp/keyd-lab unlock --did 你的DID
anpio-key --root /tmp/keyd-lab sign --did 你的DID \
  --method GET --url https://service.example.net/orders/42
```

完整步骤见[五分钟跑通](/guide/quickstart)。

## 正式使用

Linux 上把服务、管理员和 Agent 分成三个系统账号，Agent 读不到私钥和状态。一条命令完成安装、身份、策略、grant 和解锁：

```bash
./install.sh --bootstrap --did-host agents.example.com \
  --target https://api.example.com/v1/status
```

命令会打印 DID 文档地址和 grant 编号。上传 DID 文档、把 grant 交给 Agent，就可以开始签名。详细说明见[安装](/guide/install)，手动分步完成见[本机使用](/guide/local-use)。

## 从哪儿开始

- 第一次接触：[它是什么](/guide/what-is)
- 想直接试：[五分钟跑通](/guide/quickstart)
- 要部署：[安装](/guide/install)、[本机使用](/guide/local-use)
- 想知道边界：[它能保护什么](/concepts/trust-model)
- 接入代码：[接到 Agent 上](/advanced/agent)
