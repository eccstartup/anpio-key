# 默认行为

这一页列出容易忽略、但会直接影响结果的默认行为。每条只说它做什么、会导致什么。

## 身份和文档

- **`keygen --spec` 没有默认值。** DID 由坐标和公钥算出，坐标必须写在规格文件里。工具不会替你挑身份位置。
- **规格文件拒收未知字段。** 拼错的键会报错，不会被静默忽略。
- **`spec --host` 拒收 IP 字面量。** did:wba 要求域名。
- **根密钥的 fragment 不写进规格文件。** 它是工具内部识别根密钥的名字，不是文档声明。
- **`publish` 不带 `--spec` 时沿用本地文档的声明。** 重发不会清掉已有 service 条目。
- **`publish --spec` 的坐标必须和 `--did` 一致。** 不一致直接拒绝。
- **`keygen` 的 24 个词只显示一次。** 词在铸任何东西之前显示，只写 tty；之后没有导出路径。
- **`import-mnemonic` 恢复四类钥匙。** `key-1`、hot、`{device}-sign`、`{device}-agreement`；后铸的设备键不在词里，只能靠归档带走。

## Linux v2 的默认边界

- 重启后旧 grant 全部作废、钥匙锁定。
- 签名必须绑定到指定的热钥匙。
- grant 的绝对期限不会因为持续调用而延长。
- 配额在签名前预留，失败也可能已经扣次。
- 超时先查原 `request_id`，不自动重签。
- 策略检查和签名使用同一份规范化请求。

详见[设计说明](/design/)。

## 数据面新签名路默认关

`SIGN_ORIGIN_PROOF`、`SIGN_PURPOSE`、`ECDH`、`SIGN_OBJECT_PROOF`、`SIGN_DOCUMENT_PROOF` 各自一个开关，默认关：

- 开关在服务配置的 `features` 里，逐路独立；`SIGN_PURPOSE` 还按用途再分，只有列出来的用途能签。
- 关着时操作不出现在 `operations`，发过去是 `OPERATION_DISABLED`；客户端不能降级到别的操作。
- 每开一路，启动时往审计链追加一条事件（`FEATURES`、`SIGN_PURPOSE_ENABLED`、`ECDH_ENABLED`、`SIGN_OBJECT_PROOF_ENABLED`、`SIGN_DOCUMENT_PROOF_ENABLED`）。
- `ECDH` 是唯一输出秘密的操作：共享密钥不落库，同一个 `request_id` 重放拿不到第二次。

开关只决定数据面收不收这个操作，不改变 `SIGN_HTTP` 的行为。完整字段和默认关清单见仓库 [ADAPTER.md §11.7](https://github.com/eccstartup/anpio-key/blob/master/docs/ADAPTER.md)。

## 开发守护进程

- **`serve --idle 0` 表示立刻上锁，不是永不。** 想要永不，不要写 0。
- **`serve` 默认在后台运行，`stop` 靠 pid 文件找到它。** pid 文件会被核对：里面的进程不是这个二进制，就拒绝操作。
- **`serve --system` 不给 `--allow-binary` 会拒绝启动。** 二进制白名单不区分同账号的两个 Agent，也不能替代 v2 的主体和 grant。

## 任意字节签名默认关闭

两条路径默认都关，而且都属于旧开发协议：

- `sign --raw` 需要 `serve --development --allow-raw-signing`。
- `sign --challenge` 需要 `serve --development --allow-challenge-signing`。
- `--allow-raw-signing` 是更宽的门：开了它，challenge 也一起打开；反过来不成立。
- 两条路径都不能和 `--system` 同用。
- 启用后日志会明确警告，而且不构成受保护模式。

## nonce

- **不传 `--nonce` 时，上游会随机生成一个。** 签名里仍有一行 `nonce=`，但那个值和请求体无关。
- 只防重放时，随机 nonce 可以用；验证方仍要检查有效期和重放记录。
- 服务要求 nonce 与请求体一致时，必须由调用方传入。
- nonce 最多 256 字节，只接受可打印 ASCII，拒绝双引号、反斜线和控制字符。

## URL

开发模式的 `sign --url` 会规范化：host 转小写，默认端口去掉。`https://example.com:443/x` 按 `https://example.com/x` 签。

v2 使用更严格的 HTTPS 域名子集，拒绝 fragment、百分号编码、点路径等含混目标，并按策略精确检查 path 和 query。

## 迁移和硬件

- **`migrate --allow-different-subject` 默认关。** 默认放行会让一次打错字的 `--to` 变成无人察觉的冒名。
- **`--hardware` 默认 `none`。** 指定了硬件但不可用时是错误，不会降级。
- **导入默认有，导出默认没有。** 恢复自己的身份不需要特殊构建；把身份交出去需要。

## 归档

归档口令必须和日常口令不同，导出只执行一次，没有重试循环。归档文件可以被离线暴力破解，强度取决于口令和 Argon2id 成本。详见[信封与归档](/concepts/envelope)。
