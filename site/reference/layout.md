# 磁盘布局

## Linux 受保护部署

```text
/etc/anpio-key/service.json          root 持有的信任配置
/usr/local/libexec/anpio-key         root 持有的程序
/var/lib/anpio-key/                  服务账号持有，0700
  state.sqlite                      状态和事务审计，0600
  vaults/<vault_uuid>/
    device.secret                   解封材料之一
    keys/<thumbprint>.json          加密信封
    dids/<safe_did>.json            公开 DID 文档
  audit-export/events.jsonl         审计投影
/run/anpio-key/                      签名和管理 socket
```

几个要点：

- socket 的实际路径从受保护配置读取。
- 连接组只负责让请求到达端点；真正的授权来自内核 UID 和数据库里的主体记录。
- Agent 不能写程序、配置、状态或 socket 父目录。
- daemon 也不能修改部署信任配置。

## 状态和恢复

SQLite 是主体、角色、策略、grant、请求和审计的真源。

启动时只打开已有实例。数据库缺失、损坏、是符号链接、来自别的实例或 schema 更新，都会拒绝启动。不能靠“自动建一个空库”恢复服务。

重启时：

1. 递增 boot epoch；
2. 撤销旧的 active grant 和未完成批准；
3. 把未决请求标成 `outcome_unknown`；
4. 所有钥匙保持锁定。

数据库和公开文档不能靠一次普通文件重命名同时提交。文档替换依赖已批准的操作意图和旧/新摘要恢复；遇到未知内容就拒绝服务。

## 审计

授权、配额、撤销和签名事件和状态在同一个 SQLite 事务里写入。

`events.jsonl` 是按顺序导出的投影：

- 重复导出不会重复事件；
- 导出失败会保留上一份完整文件，并报告健康状态；
- 它不是第二套授权真源。

审计不记录口令、seed、原始敏感 body 或调用方自己的凭据头。请求状态区分“签名已保存”和“结果已交付”，`completed` 不代表对方业务成功。

本地哈希链和文件权限可以检查一致性、阻止 Agent 修改。独立采集器通过固定 SSH 端点保存不可变检查点，能发现源侧整体回滚或重写；它不防御源端和采集器主机一起失陷。见[独立采集器部署](https://github.com/eccstartup/anpio-key/blob/master/deploy/checkpoints/README.md)。

## 开发目录

旧开发模式默认使用 `~/.anpio-key`，里面有 `device.secret`、`keys/`、`dids/`、按月切分的 `audit/`、`log/` 和 `run/`。

`--root` 可以换目录。旧 `--system` 的按账号布局不等于 v2 受保护服务。

旧日志按月跨分片成链，并带本地锚。迁入 v2 时会校验并关联旧审计历史，新事件不会写回旧链。

## 复制和迁移

- 只复制信封、没有 `device.secret`，解不开。
- 完整目录加正确口令，可以在另一台机器解封。
- `device.secret` 不是不可复制的机器身份。
- 绑定硬件的信封必须真正拿到硬件或事先准备的恢复材料。

迁移时冻结旧写者、核对摘要、逐钥验证恢复副本。恢复副本放在管理员保护的位置。`device.secret` 丢了不能靠新生成的文件补回。恢复和迁移也不能撤回过去泄露的 seed。
