# TODO(已归档,截至 2026-10-14)

**这不是当前待办。** 现役的在仓库根目录的 [../TODO.md](../TODO.md)。

这份收的是**已经不在 TODO.md 里的东西**:已经做完的那几件的记录(**为什么**当时
那么做、以及实测出来的坑),"和计划写得不一样的地方"那张对照表,和**三版** TODO 的
原样快照。没做完的那几件在仓库根的 [../TODO.md](../TODO.md),不在这个文件里。

**这一版正文(下面「原文」那一段)不再改。** 此后做完的几件追加在它后面(到写这行
为止有「追加一」到「追加六」),所以这份文件的末尾会一直长出新的记录来,而那段正文
始终是当时的样子。**2026-10-14 收了两次工,加过两次整份快照**:「整份归档二」和
「整份归档三」—— 各自是那一版 TODO 的原样,连同"旧号怎么对上新号"那张表。

下面是原文。

---

# TODO

还没做完的事。**为什么**这么做(威胁模型、取舍)在 [DESIGN.md](DESIGN.md)
里,尤其是 §九 —— 这里只列**要动手的东西**。

M0–M5 的代码已经写完并提交,不在这个文件里。剩下来的是三件**不能在这里做完**
的事(只有一台机器、没有签名身份)、一件**做不了**的事、和一份对照表。

原来排在第一条的"TPM 后端从来没有被编译过"**已经做完了**(2026-10-14)——
记录留在下面,因为它是"核对源码"和"验过"之间那道差距的实证。

---

## 一、TPM 后端:✅ 已在 Linux 上编译并端到端验过(2026-10-14)

`cargo test --features hardware-tpm` 全绿(含新增的 `tests/tpm.rs` 三条),
`swtpm` 的端到端也走通了:`keygen --hardware tpm` → `probe` USABLE →
`publish` → `serve` → `unlock` → `sign` 出真的 RFC 9421 头;`swtpm` 重启
之后信封照旧打得开;`tpm2_evictcontrol` 删掉密封对象之后解锁**响亮地失败**
(`HardwareMissing`),信封一个字节没动 —— **没有静默降级**。

**"逐个对着源码核对"漏掉了三样,而三样都只在真信封上才露头**(都不是类型错,
编译器一条也拦不住):

1. `tpm2-tss 3.2.1` 的 `Esys_TR_FromTPMPublic_Finish` 有一处没查空指针的
   解引用,而密码会话恰好就是 `NULL` —— 带会话调 `tr_from_tpm_public` **段
   错误**,守护进程直接 SIGSEGV(139)。修法是那次调用刻意不带会话。
2. `seal_probe` 只做到 `EvictControl` 就返回,报告里却写着 "read back" ——
   `TPM2_Unseal`(也就是 `open` 唯一真正依赖的命令)从来没被任何一次体检
   碰过。
3. 芯片上**同时**装载的对象很少(swtpm 尤其少),`create_primary` 每调一次
   占一格。峰值超了报 `0x902 out of memory for object contexts`,而那句话
   指向"这颗 TPM 不能持久化"。

细节在 `src/keystore/hardware/tpm.rs` 的模块头(逐条带注释);重跑验证的命令
在 `tests/tpm.rs` 的文件头。

**还剩一处平台陷阱**(写代码时就避开了,记在这儿免得后人踩):持久化句柄
`0x81000000`–`0x81FFFFFF` 里,`>= 0x81800000` 那一段属于
`TPM2_PLATFORM_PERSISTENT`,要的是 **platformAuth** 而不是 owner auth。所以
`handle_for` 把句柄掩进 `0x81000000..=0x817FFFFF`。

---

## 二、SE 后端:ECDH 验过了,**持久化没验**

- ✅ ECDH 那条路在**真芯片**上跑过(`cargo test --all-features --lib hardware::se`,
  4 条,没有"skipped"字样)。
- ❌ **"SE key 留在钥匙串里、进程重启之后还开得了"没验过。** 它需要签名身份,
  而这台机器上 `security find-identity -v -p codesigning` 是 **0 个**。

没有身份就只能停在这里,**不谎报做完**。有身份之后的验收:

1. `keygen --hardware secure-enclave`,记下钥匙串标签。
2. 确认 `security find-key` 能找到它、并且重启进程之后还在。
3. 删掉它 → 信封打不开,而且报的错说得清是"少了这台机器"。

`src/keystore/hardware/se.rs` 的模块头写着同一条缺口。

---

## 三、硬件绑定的端到端验收用的是**软件替身**

`tests/hardware.rs` 跑的是 `--features hardware-software` 那个假后端,所以它验
的是那条路的**形状**:

- ✅ 版本分派(v1 照旧开、v2 要硬件)
- ✅ `hardware` / `hs_ciphertext` 进 AAD:换 tag、换种类、整个拆掉都被拦
- ✅ 硬件不在 → 打不开,报的错说得出少了什么
- ✅ 硬件在但口令错 → 打不开(两路熵是**都**要,不是任一)
- ✅ 没有后端时**拒绝生成**,不静默降级
- ✅ 同一把 seed,绑与不绑导出的 24 个词逐字相同
- ❌ **"HS 真的出不了这台机器"** —— 替身的 HS 就是一个文件。这条只有真后端
  能验,而且不可能在这里被验。

最后一条是有意的缺口,文件头写明了,没拿绿勾去盖。

---

## 四、硬件根的发行前置:macOS 必须签名分发

不是代码问题,是发行决策。SE 私钥唯一的持久化机制是钥匙串,写钥匙串要
`application-identifier`,而这个 entitlement **只有 Apple 签发的证书能给**。

实测(26.7.1 / arm64):

| 情形 | 结果 |
|---|---|
| 未签名二进制建**永久** SE key | `-34018 errSecMissingEntitlement`(芯片在,是钥匙串拒绝) |
| ad-hoc 签名 + 手写 `keychain-access-groups` | 进程**被内核 SIGKILL** |
| ad-hoc 签名**不带**该 entitlement | 正常运行(所以那个 kill 确实是 entitlement 引起的) |
| 未签名二进制建**非永久** SE key | 成功、ECDH 可用,进程一退就没了 |

**不要**去试"ad-hoc 签名 + 手写 entitlement"那条路 —— 它是表里第二行,已经
量过了。

`probe` 会把这件事说出来(那一节会报 NOT USABLE 并给出 remedy),而不是报一个
假的"通过"。

---

## 五、第三层:`--allow-binary` 能不能只给一个路径(做不了)

今天是 `--allow-binary cdhash:<hex>` / `sha256:<hex>`,那个十六进制串得人自己
先算出来(macOS 上要会用 `codesign -d`,Linux 上 `shasum` 一个正在跑的
`/proc/<pid>/exe`)。想要的是"给个路径就行",摘要由工具自己算。

**没做的理由不是麻烦,是它在 macOS 上不成立。** 对端身份那一侧
([src/daemon/peer.rs:167](../src/daemon/peer.rs:167))只能给出两样:

- macOS:内核在 `connect(2)` 时冻结的 cdhash —— **它要求对端有代码签名**。
  未签名的二进制拿回来的是 `Ok(None)`("问到了,但没有身份"),
  而最该被 pin 住的那类目标(脚本、自己编译的 agent 二进制)恰好都在这一栏。
- Linux:`/proc/<pid>/exe` 的 realpath + 文件内容的 SHA-256。对端**给得出**。

所以"给个路径就行"会是一个**只在 Linux 上、且只对未被替换过的文件**成立、
在 macOS 上对最常见目标压根不成立的开关。那比现在这个更糟:它看起来像通用
做法。真要做,先得回答"未签名的对端怎么被指认"——那是另一件事(路径会被
替换、会被重编,Linux 上得配 Landlock/AppArmor 才收得住,同一条限制
`BinaryIdentity::ExecutableDigest` 的注释里已经写了)。

眼下的替代就是现在这条:**被拒的连接会把对端的 pin 写进 `log/serve.log`,
照抄进命令行即可**([src/daemon/server.rs](../src/daemon/server.rs) 的
`refuse()`)。

---

## 六、跨月那一环的覆盖面窄于相邻几环

上一版 TODO 里那条"审计日志的多写者"已经做完了(语义在
[DESIGN.md](DESIGN.md) §五,测试在 `src/audit/log.rs`),**连同顺带
发现的一个更糟的** —— 换月之后 `AuditLog::open` 会把一次正常的换月报成
"第 1 行断链":链是跨月延续的,而它从 `GENESIS` 开始验。两个都修了,也都有
测试。

留下来的这条更窄:链跨月延续、`open()` 现在从上个月末行起验,**但只验当前
这个月那个文件**。历史上的月份文件在它们自己的那个月里被验过,之后不再验 ——
也就是说改掉一个**已经过去的**月份文件(连同它的末行)不会被发现;`.anchor`
只钉住最新那条尾巴。真要收住,得让锚记的是整条链而不是最后一环,那是一次
格式变更,得单开一件事。

---

## 七、和计划写得不一样的地方(已做,列在这儿免得对不上)

拿计划 §九 的验收单逐条核对时,这三条**做法换了**,不是漏了:

| 计划写的 | 实际做法 | 为什么 |
|---|---|---|
| M2 验收 #1:跨 uid → `ERR_PERMISSION` | 返回 `KeyNotFound`(`tests/negative.rs` 第 1 条) | `Permission` 等于承认"有这么一把钥匙,只是不给你" —— 那本身就是泄露 |
| M2 验收 #3:解锁后 dump 锁定区看密钥,`lock` 后应全为 0x00 | 换成 `probe`:**一个字节的密钥材料都不打印** | 计划里的做法要么跨进程做不到,要么会把私钥打到 stdout,而 probe 是 agent 同 uid 就能跑的命令 —— 那等于把 `seed-export` 那道门拆了。理由写在 `src/ops/probe.rs` 的模块头 |
| M4 验收 #3 的另一半:`strings /proc/<pid>/mem` 翻不到私钥 | **手工做**,没进自动化测试 | 读别的进程内存要 root(macOS)或 ptrace 许可(Linux);写一条只有特定平台特定权限下才跑得起来的测试,等于留一段没人跑过的代码,还会让"这条覆盖了"显得成立。守的是它的**前提**(能力、限制、失败即拒绝),那一步留给人拿真机做一次 |
| M5 验收 #6:`probe` 在**没有**硬件根的机器上不通过 | 照做了,判据是 `src/ops/probe.rs` 的 `hardware_hygiene()` | 这不是"多报一条警告"而是**改了这一节的通过条件**:从今往后一台普通机器跑 `probe` 会是失败的。理由是那四个字("体检过了")会被读成"M5 那个缺口补上了",而它没补。想翻回"没有硬件根只算提示",改的就是 `hardware_hygiene()` 那个返回值 —— 那是**一处**,不是散开的 |

**这一条是有代价的,先说清楚:** `probe` 现在是**开箱即失败**的(任何没有硬件
根的机器)。绑不绑硬件仍然完全合法,`keygen` 不带 `--hardware` 照样生成 v1
信封照样能用 —— 这一节说的是"这台机器还不够好",不是"你不能这么用"。如果这个
默认被证明是用起来太烦(比如装机脚本被它卡住),翻回"提示"是一处改动。

---

## 明确不做

原始计划 §十一 划的 v1 范围线,不在这儿重列也不打算做:凭据中介、远程多租户
解锁仪式、委托链 / biscuit 能力令牌。边界为什么划在这儿,见
[DESIGN.md](DESIGN.md) §一 和 §六。

---

# 追加一:适配层第一件 —— ✅ 已做完(2026-10-14)

原文在那一版 [TODO.md](../TODO.md) §一:"把两个新原语做到 socket 上"(`nonce` 透传
加只读的 `GET_DOCUMENT`),方案在 [ADAPTER.md](ADAPTER.md) §三。做完的样子就是那条
验收:**两条路都签得出带调用方指定 nonce 的签名,`GET_DOCUMENT` 答得出本机发布过的
DID 和它的文档,答不出别人的。**

## 落地的形状

共用层加两处,**两个门面各接一处** —— 这正是那一节自己点出来的风险:"漏掉第二处的
症状不是编译错误,是走 MCP 的 agent 登不了录,而同一个 agent 在命令行上怎么试都是
好的"。

| | CLI | MCP |
|---|---|---|
| `nonce` | `sign --nonce VALUE` | `sign_request` 的 `nonce` 参数 |
| 文档 | `document --did …` | `get_did_document` |

守这条约束的是三条测试,分在三个层次上:`tests/cli.rs` 和 `tests/mcp.rs` 各一条
端到端(都拿上游 `anp` 的实现验签),外加一条 wire 往返和一条 handler 单测。
MCP 那条单独立着,理由就在它头的注释里。

## 和 ADAPTER 写得不一样的一处

**ADAPTER §9.3 原来写的是"四个工具,没有第五个",落地时加了第五个。** 记在这儿
是因为那是一条**明确的**排除决定,不是随手加的。

判据取自 §9.1 自己那句话:登录要走得完。§9.3 排掉的四条 —— raw 签名、keygen /
publish、export、联网 —— 共同点是**它们要么签任意字节,要么打开信封,要么把
守护进程伸到本机之外**。读一份本机已经发布过的文档不占其中任何一条:它不签字节、
不碰私钥、不产生签名,而那份文档本来就是用户 `publish` 到一个公开地址上的东西。
拿"没解锁"去挡它,挡掉的只是调用方本来就够得着的东西,换来的是**走 MCP 的 agent
登不了录**。

所以加了,并且在 ADAPTER §9.3 正文里把这次改动和理由写了下来 —— 计数改了就得说清楚
它为什么改,否则下一个人读到"五个"再看到别处写着"四个",会以为是自己数错了。

## 实测出来的三样

**一、`nonce` 的字符集是一条真的边界,不是洁癖。** 上游 `anp` 1.0.6 拼那一行是
`format!("nonce=\"{}\"", value)` —— **一个字符都不转义**。所以值里一个 `"` 能改写
它后面的 `keyid=`,一个换行能凭空造出一整行签名基。约束因此是两条:长度
(≤ `MAX_NONCE_LEN` = 256)和字符集(可打印 ASCII,去掉 `"` 和 `\`)。管长度不管
含义这条没变,**含义仍然透明,挡的是语法**。

**二、文档必须是**原文**过线,不能拆成 JSON 再拼回去。** 落盘那份是签好名的成品,
而 `serde_json` 默认的 `Map` 会按键排序 —— 一次"顺手解析一下"就足以让 proof 验不过。
所以从守护进程到 CLI stdout 是原样字节,到 MCP 是 JSON 字符串里的**一整段文本**
(不是解析过的对象)。测试断言的是逐字节相等。

**三、取件也进审计,而且摘要和字节出自同一次读。** 新事件 `DOCUMENT_READ` 带一个
`document_digest`。**它和递回去的那串字节在同一次读里算出来** —— 分两次读的话,审计
里记的可能是调用方从没拿到过的那个版本。这条事件的语义是"取件",不是"授权":文件
本来就有 `0644`,这里记的是**谁什么时候来拿过**,不是放行。

## 顺带修掉的一个竞态(不在这一节的范围内)

新加的两条 CLI 测试会多起几个守护进程,于是把一条**早就存在**的竞态撞成了必现:
`serve` 有时候在 `run/keyd.pid` 还没落盘时就把终端还回去了,紧接着敲 `stop` 的一方
读到的是一个不存在的文件 —— 症状是"守护进程明明起来了,`stop` 却说没在跑"。

根因是 `service::detach` 的就绪判据少了一问。它原来是"**socket 文件的 inode 变了
+ 孩子还活着**",而 `bind()` 和写 pid 文件之间那一小段里这两条都已经成立。补上
"**pid 文件里记的就是这个孩子**"即可,次序不动(仍然是先绑定、后落 pid 文件)。
单独跑那条测试是绿的,只有满负载时红 —— 所以它不是新引入的,是被新测试照出来的。
理由写在 `src/daemon/service.rs` 那段注释和 [DESIGN.md](DESIGN.md) §七 里。

## 这次没有留下尾巴

那一节的验收是闭合的:两条路都验到了(CLI / MCP 各一条端到端,验签用上游实现),
"答不出别人的"也在两条路上各有一条负例。ADAPTER §十一 那个端到端脚本需要的东西
到此都在 socket 上了。**下一件是原文 §二那个岔口**(注册的挑战签名),它仍然是个
要人拍的决定。

---

# 追加二:§四 那两条尾巴 —— ✅ 已做完(2026-10-14)

原文在那一版 [TODO.md](../TODO.md) §四:"动手前要核实的"四条都核完之后,还剩两条
尾巴 —— 一条是把已核过的 DID 推导钉成向量测试,一条是 `@authority` 那个 `:443`
的写法分歧。两条都收了。

## 尾巴一:把跨实现的指纹钉住

新文件 `tests/vectors/anp_sdk_ed25519_fingerprint.json`,种子是那一份测试用的
**32 个 `0x01`**,期望值是它自己断言的
`e1_UDDReOZl1ipXAfp9wYsm13sDBMK5og--QWdBjzuf6o4`。整条链逐项比:公钥 → JWK 的
`x` → 规范化 JSON → SHA-256 → `e1_` 段。只比最后那 46 个字符是不够的 —— 两边各错
一处、恰好抵消,看上去照样是绿的。

**它带出一个文件头要改的地方。** `tests/vectors.rs` 原来写着"每一个字节都是从 RFC
正文里机械抽出来的",这一条不是:它的出处是一个**兄弟实现**
(`anp-sdk/src/core/crypto/fingerprint.test.ts:11-12`,connectx 走的就是它)。出处不
同,失败时该怀疑谁也不同:

- RFC 抄本红了 → **先怀疑实现**,别改向量;
- 兄弟实现的值红了 → **两个实现分家了**,得先问是谁动了。期望值那一串在别人家也是
  断言,它有可能才是对的一方。

这条规则现在写在文件头,而不是新开一个文件、让两份测试各自守着一半的理由。`_note`
里另外写明:公钥、JWK 的 `x`、规范化 JSON、摘要这四个中间值是用**第二个实现**
(Python)从种子重算的,不是从谁的文档里抄的 —— 免得读者以为它们也是"权威文本"。

## 尾巴二:`@authority` 里的 `:443`

先说结论:**送进上游之前把 URL 规范化**,改成"一个小写 host、不带默认端口"的那一份
—— 也就是**每一个验签方自己算出来的那一份**。

原先记的是"connectx 用 WHATWG `URL.host`,会把 `:443` 吃掉;守护进程会保留"。核到
源码这一层,这件事比原来记的**更糟,也更好办**:

| 谁 | 怎么算 `@authority` | `https://example.com:443/x` |
|---|---|---|
| 上游 `anp`(开 `network`,走 `url` crate) | `host_str()` + `port()` | `example.com` |
| 上游 `anp`(**无** `network` —— keyd 用的这支) | 从文本里切 | `example.com:443` |
| anp-sdk 的签名侧(`signer.ts:67`) | `new URL(url).host` | `example.com` |
| anp-sdk 的验签侧(`verify.ts:352`) | `new URL(targetUri).host` 对上 `authority` | 要求 `example.com` |
| awiki-open-server(`shared/runtime.py`) | 拿自己配的 `public_base_url` **重拼** URL,再切 netloc | `example.com` |
| Python wheel 的 `_component_value` | `urlparse(url).netloc` | 跟着传进去的那串 |

两件事因此清楚了:

1. **分歧不只在两个仓库之间,还在上游 `anp` 自己内部** —— 开不开 `network` 是两种
   切法。keyd 走的是无网络那支,所以它和**自己的依赖**在另一种构建下不一致。
2. **被留下的是 keyd 一个。** 更硬的一条证据在 `resolveDid.ts:591`:`Host` **头**本身
   就被设成了 `url.host` —— 也就是说线上跑的那一串就是不带端口的那一份,不只是签名
   里那一份。

所以照字面签 `:443` 得到的签名**一定验不过**,而报错是"签名无效":它把人指向钥匙,
而不是指向 URL。这就是为什么这条要收,不能只写一句"平时没人那么写"。

落点是 `src/sign/rfc9421.rs` 的 `normalized_target_uri()`:host 归一成小写,空端口和
`:443` 去掉,其余一个字节不动(path、query、fragment 原样,非默认端口照旧,IPv6 字面
量里的冒号不被当成端口分隔符)。它**只在一个地方生效** —— `sign_request` 把 URL 交给
上游之前那一次 —— 因为 `@authority` 和 `@target-uri` 都出自那个字符串,换一次两个分
量一起正。`validate_url` 仍然看调用方**原样**给的 URL。

守它的是两条测试:`the_target_uri_is_normalised_the_way_a_url_parser_writes_it`
(那张对照表,含"没有被顺手多改"的那几行)和
`a_url_written_with_the_default_port_only_verifies_after_normalisation` —— 后者拿
**上游的验签器**当对端跑了一遍:照字面给的 URL 验不过,规范化过的验得过。

**和 JS 侧故意不一样的一处。** anp-sdk 那边只规范化 authority(`authority = url.host`),
`@target-uri` 用的还是**原样**的 `input.url`。我们没有那么做:awiki 的服务端是拿
`public_base_url` 重拼 URL 的,那个拼出来的 `@target-uri` 也是不带端口的,所以只管
authority 的写法在它那儿照样过不去。两个分量一起正,才能同时过两边。

---

# 追加三:`keygen` 和 `publish` 没进审计日志 —— ✅ 已做完(2026-10-14)

这条**不是**上面 §六 那个跨月的洞,虽然挨着它。§六 说的是链的历史覆盖面;这一条是
**当下这个月里就少了记录** —— 一份完整的日志记不下本机最常发生的两件事。

原来的情况:日志里一条身份"出现"只有 `IMPORT`(别人那份被搬到这台机器上),而
**本机自己 `keygen` 出来一把**一个字都没有;文档取件(`DOCUMENT_READ`)记了,而
**`publish` 把它写进本地那一份**也没记。于是拿一个 DID 去问"它是什么时候在这台机器
上出现的、本地那份文档是什么时候变成这样的",最常走的那两条路反而答不上来 —— 而
这个文件存在的理由就是事后能答上话。

## 两条记录各是怎么定的

**`KEYGEN` 的 `hardware` 取自刚写下去的那个信封**(`created.wrapped.hardware`),
**不是命令行上要的那个**(`args.hardware.choice`)。这是 `SIGNED` 那条的 `covered`
已经定下的规矩:**记结果,不记意图**。`--hardware` 要了而没有会直接报错
不生成,所以两者在成功那一条路上**今天**总是相等 —— 但那不是重点,重点是**记录本
身不该依赖一个"另一处保证了两者相等"的推理**:哪天多出一条"要不到就降级"的路,
前一种写法会自动跟着对,后一种会静静地开始撒谎。值是 `none` /
`secure-enclave` / `tpm` / `software`,和 `--hardware` 的取值、以及
`hardware::known_names()` 那套**逐字相同** —— 为此在 `HardwareRoot` 上加了
`kind()`,而不是在审计里另写一张对照表。同一个东西在两个地方有两个名字,事后拿
日志去对命令行的人会对不上。

**`PUBLISHED` 记的是写进本机 `dids/` 那一份,`publish --out DIR` 不记。** 后者只
产出一个文件交给别人去部署,**本机一个字节都没变** —— 本地 `dids/` 里那份是旧的就
还是旧的。给它记一条"发布",等于让人以为本地那份文档就是它,而本地那一份正是别人
验签时被拿来比对的对象。这是**故意漏**的第二种情况(第一种是 `--raw` 不记签名基),
两处都得在日志的语义里说清,不然"没记"和"忘了记"长得一样。

`document_digest` 用的是 `lifecycle::document_digest` —— **和 `DOCUMENT_READ` /
`ROTATE_HOT` 同一个函数**(规范化 JSON 的 SHA-256,base64url)。这是这个字段全部的
用处:把一个摘要在整份日志里搜一遍,得到的就是这份文档的一生。两处各自算各自的摘要
(一个从内存里那份签好的文档,一个从磁盘读回来的字节),对不上就等于这条线从一开始
是断的,而症状要等**事后比对时**才出现 —— 那时候已经没人能回头查了。

## 两个不显然的顺序问题

1. **`KEYGEN` 落在打印 DID 之前。** 先落账,再告诉人它成了。反过来的话,一台写不下
   审计的机器上的人照样会拿到一个 DID 去发布 —— 而那个 DID 在日志里不存在,正是这
   个文件要防的那种"说不清"。这和签名那条路一样是 **fail-closed**(`state.record(...)?`
   失败则 `SIGN` 失败),不是"尽力而为"。
2. **`PUBLISHED` 落在写文件之后。** 记的是"本机那份已经是这些字节了",所以只有它真
   落下去才成立;先记后写的话,一次写失败的 publish 会在日志里留下一条假的成功。

## 一处必须动的地方:封闭字段集那条测试

`tests/cli.rs` 的 `the_audit_log_records_the_signature_and_holds_no_secrets` 把所有
事件字段名当**封闭集合**来断言 —— 这正是"日志里没有秘密"的测法:一个能装种子的
字段一旦被加进来就立刻红,不用等谁想到它。新加的两个字段(`hardware` 是硬件根的名字,
`document_digest` 是 43 个字符合成出来的摘要,都装不下密钥材料)因此**要显式加进
白名单**。这是刻意的摩擦:谁往日志里加字段,谁就得在这一行上说明它为什么不是秘密。

同一条测试的流程(keygen → publish → daemon → unlock → sign)现在跑出四件事,断言
从"有 `SIGNED`"改成四件一件都不能少 —— 生成和发布这两条**以前恰好是少的**,把四件
列出来就是让"以后又少一件"变红。

## 新加的两条测试

- `the_same_digest_links_the_publish_to_the_read` —— 拿 `publish` 自己说的路径读回
  磁盘上那份文档,在测试里算一遍摘要,断言 `PUBLISHED` 和 `DOCUMENT_READ` 两条记录
  里是**同一个值**。守的是上面那条"两处各自算、必须对得上"。
- `publishing_to_a_file_leaves_no_record_on_this_machine` —— `publish --out DIR`
  之后整个 `audit/` 逐字节和之前一样。守的是"故意漏的那种"。

两条都用一个新的小助手 `audit_text(&TempDir)`:按月文件名排序拼起来,而且**只收
`.jsonl`** —— 同一目录里还躺着 `.anchor`,把它当日志读会得到一行解不出来的 JSON
(原来那条测试是"挑第一个 `.jsonl`",跨月时会漏掉一个文件)。

## 落地清单

| 文件 | 改了什么 |
|---|---|
| `src/audit/log.rs` | `Event` 末尾加 `Keygen { did, kid, hardware }` 和 `Published { did, document_digest }`,理由写在各自的文档注释里 |
| `src/keystore/record.rs` | `HardwareRoot::kind()` —— 审计里那个名字和 `--hardware` 的取值同源 |
| `src/cli.rs` | `keygen` 在打印 DID **之前**落一条;`publish` 只在写本地那份的分支里落一条 |
| `tests/cli.rs` | 白名单加两个字段、四件事都要有、新助手 + 两条新测试 |
| `docs/DESIGN.md` §五 | 把"会改变状态的事"展开:`KEYGEN` / `PUBLISHED` 在,`--out` 不在 |
| `TODO.md` §六 旁 | 划掉的那一条 |

---

# 追加四:跨月那一环的覆盖面 —— ✅ 已做完(2026-10-14)

原文是上一版 [TODO.md](../TODO.md) §六的**标题**那一条(不是底下 `keygen` /
`publish` 那条,那条在「追加三」里收掉了)。缺口是:链跨月延续,而 `open()` 只
从**上个月末行**起验**本月那一个文件** —— 一个已经过去的月份,连同它的末行,
在自己那个月验过之后就再没人看了。改掉它不会被发现,而本月的记录会照样接着
那条被改过的尾巴往下写。

## 做法:不是改锚的格式,是把历史走一遍

**记下来的计划说"得让锚记的是整条链而不是最后一环",落地时证明那是多余的。**
链本身就在 `.jsonl` 文件里 —— 走一遍就躲不过去,再往锚里存一份整链摘要,只是
把同一件事说两遍,还多出一个要同步的字段。所以 `.anchor` 的格式**一个字节都没
改**(它仍然只管"末条记录数 + 尾巴哈希",也就是被截断、被回滚到旧版本这两种),
改的是 `AuditLog::open`。

这一条值得记下来,因为它和「追加三」是同一类:**计划里写的是当时看得到的那条路**,
而动手时会发现更小的一条。留着"按原计划做了格式变更"的说法,下一个人去读
`.anchor` 会找不到那个字段。

新的做法:

- `history_files(dir, upto)` 收**到 `upto` 为止**的全部 `YYYY-MM.jsonl`,按文件
  名排序 —— 月份戳是零填充的,字典序就是时间序。不是这个名字的不收(同一个目录
  里躺着 `.anchor` 和 `.lock`),`upto` **之后**的也不收。
- `verify_history(dir, upto)` 从最早那份走到 `upto`,把每一份依次交给
  `verify_chain_from`,状态(末条 `seq`、末行哈希)在文件之间传下去。
- **起点是 `GENESIS` 的只有最早那一份。** 它接不回 `GENESIS` 的话,要么更早的
  月份文件被删了,要么整条链是重写出来的 —— 两种都要报,而不是当成"这份日志就
  是从这个月开始的"。
- `previous_month_file` 因此**删掉了**:它回答的是"上一份是谁",而新代码问的是
  "全部历史是哪几份"。留着一个再没人调的函数,下一个人会以为它还有用。

## 代价,以及它为什么躲不掉

`open()` 现在是 O(整份历史)的读盘。这是**不可避免**的:要发现旧月份被改过,
就得把旧月份读一遍 —— 没有任何一种只读尾巴的办法能回答"前面那份还是不是原来
那一份"。实践上它可忽略:守护进程一份 `AuditLog` 攥到进程结束,而每一条 CLI
命令本来就要付 Argon2 或者开一次 pty 的钱。

## 报错要说清是哪一份文件的第几行

链现在跨好几份文件,而原来那些消息只有"第 3 行"。所以 `verify_chain_from` 每条
消息都加上了文件名,`file_name(path)` 这个助手就是干这个的。第一行断开时那句话
也换了:它**不是**"中间哪一行被改了",而是"它该接的那一整段不在"——两种原因
(更早的月份文件没了 / 它该接的那条记录被重写了)在这份文件里长得一模一样,所以
那句话把两种都说出来,不替人猜。

原来那条测试断言的 `"breaks at line 1"` 字样**保留着**(只是后面多了文件名),
所以它不用改。

## 三份新测试

- `editing_a_record_in_an_old_month_is_caught` —— 三份月份文件(2001-01/02/03,
  各两条),先断言这份历史本身干净(6 条),再改**最早那份的第一行**,报错必须是
  `breaks at line 2 of 2001-01.jsonl`:同一份文件里的第二行立刻对不上。
- `deleting_a_whole_old_month_is_caught` —— 两条路各管一种:删**中间**那份
  (2001-02)→ 断在 `2001-03.jsonl` 第 1 行;删**最早**那份(2001-01)→ 断在
  `2001-02.jsonl` 第 1 行,而且那句话要给出**对得上的那个理由**("an earlier
  month's file is missing"),不能只报一句"链断了"。
- `opening_a_multi_month_history_continues_from_its_end` —— 守的是
  `verify_history` 的**返回值**:打开一段两个旧月份、共 5 条的历史,追加一条的
  `seq` 必须是 6、`prev` 不能是 `GENESIS`(否则就是从头重起链了),重开能看到 6 条。

测试夹具跟着改了:原来那个 `roll_over(d, before, this_month)` 只会造"一个旧月份
+ 本月"这种形状,表达不了三份文件。换成 `write_history(&d, &[(月份, 条数), …])`
——它按顺序造文件、把链和锚一起写对、并返回每一份末端的 `(seq, 哈希)`。原来的
`roll_over` 保留成一层薄包装(它那三条测试问的是"换月",不需要知道夹具换了)。

`previous_month_file` 那条测试也换成了 `the_history_files_are_every_month_up_to_now`:
那个助手收的是到 `upto` 为止的全部月份文件,按名字排,不收非月份文件。

## 没顺手做、也没变糟的一处

**时钟往回跳**会造出一份"未来"月份的文件,而 `history_files` 用 `upto` 把
`upto` 之后的排掉,所以它**不会**被接进链里 —— 这是有意的,不是遗漏:把它接进来
会让"哪一头是新的"变得可疑。跳回去那一下本身今天已经有症状了(打开时可能报
"第 1 行断链"),这一次的改动**没让它更糟**,也没试图修它 —— 那是另一件事。

## 落地清单

| 文件 | 改了什么 |
|---|---|
| `src/audit/log.rs` | `open()` 改成走整份历史;`verify_history` + `history_files` 取代 `previous_month_file`;`verify_chain_from` 每条消息带文件名;新助手 `file_name`;`last_record` 的文档指向新的验法 |
| `src/audit/log.rs` 的模块头 | "能检出 / 不能检出"那张表按新的覆盖面重写(整份历史走一遍,不是只有本月) |
| `src/audit/log.rs` 测试 | 夹具换成 `write_history`;新增三条(改旧月份 / 删整份旧月份 / 打开后接着写) |
| `docs/DESIGN.md` §五 | 加了"打开日志要走的是一整条链,不是最后一个文件"那段,含代价 |
| `docs/DESIGN.md` §十 | 那条从"还没做"里划掉(照 TPM 那一条的样子) |
| `TODO.md` §六 | 标题连同正文划掉,原地留下"收法"一行 |

## 现在的 TODO 是什么样

§四 的标题从"剩下两条尾巴"改成"两条尾巴也收了",两条尾巴各自划掉并在原地留下
"收法"一行。§六 **整节**都划掉了:标题(跨月的历史覆盖面)和底下的 `keygen` /
`publish` 那条。两件事都在原地留了指向归档的一行。README 的"几个不显然的默认值"
里加了一条 —— 改了被签的字节,就得写在明处。

**没收到的只剩 §二(注册的挑战签名)那个要人拍的岔口**,以及 §五 那三件堵在
签名身份上的(两件要 Apple 的证书,一件要真后端才能验)。

---

# 整份归档二:2026-10-14 收工时的 TODO

**下面是那一版 TODO.md 的原样快照。** 那一版是"一件是一件事"那一版(上一版的
归档是这份文件开头那一段)。它做完的几件就是上面「追加一」到「追加四」,没收的
那几件搬进了新的 [TODO.md](../TODO.md)。

**这一版重新编号了,快照里是旧号。** 上一版的 §一 / §四 / §六 都已做完,剩下的
按顺序变成了新 TODO 的一到四。旧号留在这份快照里,是因为提交信息、上面各「追加」、
以及 ADAPTER 里都用"§六 那条"、"§四 那两条尾巴"这样的说法 —— 快照在,那些话就查
得到。

**正文一字未改,只把链接前缀的 `docs/` 去掉了** —— 它从仓库根目录挪进了 `docs/`
里,不去的那些会指向 `docs/docs/`。

---

# TODO

还没做完的事。**为什么**这么做在 [DESIGN.md](DESIGN.md)(威胁模型、取舍)
和 [ADAPTER.md](ADAPTER.md)(适配层的方案)里 —— 这里只列**要动手的东西**。

**一件就是一件事。** 上一版把每件事拆成字段、拆成步骤,读起来像进度条,做起来还要
自己把它们重新拼回一件事 —— 这一版不那样写。一件做到什么算完,写在条目里;怎么
做到,在对应的文档里。

上一版整份归档在 [TODO-archive.md](TODO-archive.md):M0–M5 已完成的记录、
TPM 的三处实测结论、"和计划写得不一样的地方"那张对照表,都在那儿。

**做完的就在原地划掉,不搬走、不重编号** —— 这样跟旧的说法对得上。划掉的是"这件事
不用再做了",不是"它不重要":长的记录(**为什么**那么做、实测出来的坑)追加在归档
末尾,这里只留一行指向它。所以这个文件里,**没被划掉的才是还没做的**。

眼下的主线是**适配层** —— 在不让守护进程认识任何一个具体协议的前提下,让它满足
connectx / awiki-cli-rs2 这类工具的签名需求([ADAPTER.md](ADAPTER.md))。
硬件根和审计链是上一阶段的收尾,两件都堵着,理由在条目里。

---

## ~~一、适配层:把两个新原语做到 socket 上~~ ✅ 已做完(2026-10-14)

~~`nonce` 透传,和只读的 `GET_DOCUMENT`。方案、理由、以及"为什么它不动授权模型"在
[ADAPTER.md](ADAPTER.md) §三。~~

~~**落点是共用层,不是某个前端的参数表。** `wire` 的类型加一处,`cli` 和 `mcp` 各接
一处 —— 漏掉第二处的症状**不是编译错误**,是走 MCP 的 agent 登不了录,而同一个
agent 在命令行上怎么试都是好的(§9.1)。`nonce` 只要一条约束:进签名基所以有长度
上限,**内容是透明的**,守护进程管长度、不管含义。~~

~~**算完的样子:** 两条路都签得出带调用方指定 nonce 的签名;`GET_DOCUMENT` 答得出
本机发布过的 DID 和它的文档,答不出别人的。~~

**记录在 [TODO-archive.md](TODO-archive.md) 末尾「追加一」** —— 里面还有
和 ADAPTER 写得不一样的一处(§9.3 从"四个工具"变成五个),以及顺带修掉的一个
pid 文件竞态。

## 二、适配层:注册那个挑战签名 —— 先写下来,不必现在拍

awiki-open-server 的注册,除了 DID 文档自签,还要一次一次性挑战的证明:对服务端
下发的随机串做一次 Ed25519 签名(`challenge_signature`)。**那不是 RFC 9421**,而
[ADAPTER.md](ADAPTER.md) §十 那条线("不为适配打开 `Raw`")正挡在它前面。
三条路(不签 / 开一条比 `Raw` 窄的路 / 承认注册不在范围内)写在
[ADAPTER §3.3](ADAPTER.md) —— 那是这份方案里**唯一一处要人拍的岔口**。

**但两个客户端都不发它** —— connectx 走文档自签 + 401 重签,awiki-cli-rs2 的注册 RPC
里没这个字段(**两个都核过了**)。所以"不签"这条路**今天零成本**:它挡不住任何人,
只是一条**将来**对端把"可选"翻成"必需"时才会咬人的线。先记在这儿,不急着拍;真要拍,
要么进第七节「明确不做」,要么变成第一节那条共用层上的一件东西。

**算完的样子:** 三条路里选定的那一条写进 ADAPTER 正文,§十二 里那条"未决"落定。

## 三、适配层:客户端侧,和验收

- **connectx:接的是 connector,不是 provider。** `AnpConnector.signRequest` 收
  method / url / nonce / handle,形状正好对上 keyd 的结构化路径;EIP-1193 那层只到
  `signMessage`,用它就得开 `Raw`。实现纪律照抄 `providers/README.md`:适配器里
  只做转发和错误翻译,出现 "ANP" 这个词就是边界划错了地方(§八)。`Locked` 原样
  交回给人,**不重试、不翻译成"签名失败"**(§六)。
- **awiki-cli-rs2:接缝已经在了,而且形状就是 keyd 的。** 它那层 `IdentitySigner` 的
  `http_signature_headers(kid, url, method, headers, body, options)` 正是结构化
  `SIGN`,而且 `options` **本来就带 `nonce`**;`did_document()` 正是 `GET_DOCUMENT`。
  `AnpIdentitySigner` 已经把同一批方法转手给 `anp-identity` 这个"custody 在别处"的
  实现 —— keyd 照它再写一份即可(§八)。**一处错位**:`sign_document_proof` 收的是
  调用方构造的文档,和 keyd 的不变量 3 对不上,注册那一段的改法要单独想。
- **验收是 §十一 那五条反证。** 核心是第一条:**停掉守护进程,connectx 必须失败**
  —— 不然只是多了一条可选路径,不叫抽出来了。

## ~~四、适配层:动手前要核实的~~ ✅ 四条核完,两条尾巴也收了(2026-10-14)

1. ~~**DID 推导 —— 已核对,两边一致。** connectx 的 `ed25519Fingerprint`(RFC 7638
   JWK 指纹 → SHA-256 → base64url 无填充 → `e1_`)和守护进程走的 `anp` 上游
   `compute_multikey_fingerprint`(同一个 JWK,过 RFC 8785 JCS,`URL_SAFE_NO_PAD`)
   是同一串字节。**实测过**:拿 connectx 自己的测试向量独立算了一遍,得到
   `e1_UDDReOZl1ipXAfp9wYsm13sDBMK5og--QWdBjzuf6o4`,和它断言的一致。~~
   ~~**还没做:** 在仓库里加一条向量测试把它钉住(就拿上面那串
   `e1_UDDReOZl1ipXAfp9wYsm13sDBMK5og--QWdBjzuf6o4`),免得哪一边以后悄悄改了
   编码。~~ **做了** —— `tests/vectors/anp_sdk_ed25519_fingerprint.json`,种子是那
   一份测试用的 32 个 `0x01`,整条链(公钥 → JWK → 规范化 → SHA-256 → `e1_` 段)
   逐项比。
2. ~~**签名基的跨语言一致性 —— 已核到序列化这一层。** 覆盖面
   (`@method @target-uri @authority content-digest`)、参数顺序
   (`created;expires;nonce;keyid`,两边都不带 `alg`)、`@signature-params` 那一行的
   拼法、行分隔用 `\n` 而不是 `\r\n`,`expires` 两边都固定 300 秒 —— **逐字节相同**。~~
   ~~**还没做:** `@authority`。connectx 用 WHATWG `URL.host`,显式写出默认
   端口时会把 `:443` 吃掉;守护进程无网络构建下是从 URL 文本里切出来的,会**保留**
   `:443`。平时没人那么写,但"差一个字符就是另一条签名"正是这类地方的代价 —— 它
   只能拿真对端跑一次来收,所以在第三节那条验收里。~~
   **收法:** 送进上游之前把 URL 规范化 —— 一个小写 host、不带默认端口的那一份,
   也就是**每一个验签方自己算出来的那一份**。理由、三方实现的对照、以及新发现的
   一条(JS 侧连 `@target-uri` 都留着原样,和我们最后选的不一样)在归档「追加二」。
3. ~~**上游版本错位 —— 已核掉,签名基逐字节一致。** 整条 awiki 都在 `anp 1.0.3`
   (Rust CLI 的 path 依赖 `=1.0.3` + Python 服务端的 wheel `anp-1.0.3`),只有 Anpio Key
   钉 `=1.0.6`。拿 1.0.3 那个 pin 的 commit(`096ca3e`)和 crates.io 上的 1.0.6 对拉了
   keyd **真正产字节**的三个入口:`http_signatures.rs`(签名基 + `content-digest`)
   **两份文件逐字节相同**;`compute_multikey_fingerprint` 所在的 `did_wba.rs` 不在差异
   清单里;唯一有差异且参与拼基的 `proof/mod.rs`,改动落在**验证那一支**,上游自己
   写着 *"Keep legacy base64url signing/generation bytes unchanged"*。**所以那一个补丁
   版的差不动签名基** —— 结论和比对过程记在 ADAPTER §十二 第 3 条。~~
4. ~~**`LIST_KEYS` 要不要报出密钥角色。** 判断仍是"不加",而且新证据是往这个方向弱的:
   `IdentitySigner` 里确实有一套角色词表(`DeviceAssertion` / `Authentication` /
   `KeyAgreement` / `RootControl`),但它**从文档里推**(读 `proof.verificationMethod`
   和 `keyAgreement`),不从密钥列表里要。客户端要的是那份文档,不是 `LIST_KEYS` 多几
   个字段(§3.4)。而 `GET_DOCUMENT` 落地之后这条更是空的了 —— 客户端要文档就是取
   文档,`LIST_KEYS` 不必再长出角色字段。~~

**记录在 [TODO-archive.md](TODO-archive.md) 末尾「追加二」**(那两条尾巴),
四条各自的结论在 [ADAPTER.md](ADAPTER.md) §十二。这一节留下一句要说清楚的
话:`@authority` 那几条是**对着源码**核出来的,**拿真对端跑一次仍在第三节那条验收里**。

## 五、硬件根(M5):剩下三件,两件堵在签名身份上

代码都写完、能验的也验过了(结论在归档里),剩下的**都不是代码问题**:

- **SE 的持久化没验过。** "SE key 留在钥匙串里、进程重启之后还开得了"需要签名身份,
  而本机 `security find-identity -v -p codesigning` 是 0 个。有身份之后的三步验收
  在归档里。
- **macOS 的 SE 版本必须签名分发。** 写钥匙串要 Apple 签发的
  `application-identifier`,这是发行决策。**不要去试"ad-hoc 签名 + 手写
  entitlement"** —— 已经量过,进程会被内核 SIGKILL。
- **硬件绑定的端到端验收仍然跑在软件替身上。** `tests/hardware.rs` 验的是那条路的
  **形状**;"HS 真的出不了这台机器"只有真后端能验。TPM 那半在 Linux 上真跑过了,
  SE 那半等身份。

## ~~六、审计链:跨月那一环的覆盖面窄于相邻几环~~ ✅ 已做完(2026-10-14)

~~链跨月延续,`open()` 从上个月末行起验,**但只验当前这个月那个文件** —— 历史上的
月份文件在它们自己的那个月里被验过,之后不再验;`.anchor` 只钉住最新那条尾巴。
也就是说改掉一个**已经过去的**月份文件(连同它的末行)不会被发现。真要收住,得让
锚记的是整条链而不是最后一环 —— **那是一次格式变更**,单开一件事。~~

**收法:让 `open()` 走整份历史,从最早那份月份文件一路验到本月** —— 不是改锚的
格式。写下来打算做的那件事(锚里再加一个整链摘要)落地时证明是多余的:链本身
就在文件里,走一遍就躲不过去,再往锚里存一份只是同一件事说两遍。代价是常数级
I/O,而它不可避免 —— 要发现旧月份被改过,就得把旧月份读一遍。理由、三份新测试、
以及"那份计划里没写对的地方"在 [TODO-archive.md](TODO-archive.md)
末尾「追加四」,语义补进了 [DESIGN.md](DESIGN.md) §五。

- ~~**同一个月里也有个洞,但那个不是链的事:`keygen` 和 `publish` 本来没进日志。**
  一条身份在这台机器上出现有两条路,只记了 `IMPORT`(别人那份搬进来),没记
  `KEYGEN`(这里自己生一把);取件记了 `DOCUMENT_READ`,写下去那次没记。于是拿一个
  DID 问"它什么时候出现的、本地那份文档什么时候变成这样的",最常走的那条路反而答
  不上来。已收(2026-10-14):两个 `Event` 变体 —— `KEYGEN` 的 `hardware` 取**信封里
  实际落地的那一份**(不是命令行上要的那个,和 `SIGNED.covered` 同一个道理:记结果不
  记意图),`PUBLISHED` 的 `document_digest` 和 `DOCUMENT_READ` / `ROTATE_HOT` **用同一
  个函数**算,所以一个摘要能在整份日志里搜出这份文档的一生;`publish --out DIR` **不
  记**(本机一个字节没变)。记录在 [TODO-archive.md](TODO-archive.md)
  「追加三」,语义补进了 [DESIGN.md](DESIGN.md) §五。~~

## 七、明确不做

适配这条路上不碰的(理由都在 [ADAPTER.md](ADAPTER.md) §十):打开 `Raw`、
让守护进程认识 ANP-02 的语义、让守护进程联网、`export` 上 socket、多用户细粒度
授权。加上原始计划 §十一 划掉的 v1 范围线(凭据中介、远程多租户解锁仪式、委托链 /
biscuit 能力令牌),边界见 [DESIGN.md](DESIGN.md) §一 和 §六。

**第二节那三条路不是"明确不做"** —— 它是一个还没定的岔口,定了之后要么进这一节,
要么变成上面某一条。



---

# 追加五:那条窄路做到 socket 上 —— ✅ 已做完(2026-10-14)

上面「整份归档二」那一版 TODO 的 §二(注册那个挑战签名)是一个**要人拍的岔口**,
拍的是第二条:**开一条比 `Raw` 窄的路**。这一条记录的是把它做到 socket 上之后,
那条路到底长什么样 —— 因为它和计划里那句"比 `Raw` 窄"之间有一段距离,而那段
距离如果只留在代码里,下一个人会以为这条路**有形状**。

## 它落在哪儿

**是 `SIGN` 的第三个变体,不是新消息类型。** `SignRequest::Challenge`(tag `0x03`)
和 `Structured`(`0x01`)/ `Raw`(`0x02`)并列 —— 线上还是六种请求,§三 那句"不加
消息类型"照旧成立。所以这一件从协议层到 CLI 是四层各加一处:

| 层 | 加了什么 |
|---|---|
| `daemon/wire.rs` | `SignRequest::Challenge { did, kid, challenge }`;`MAX_CHALLENGE_LEN = 256`;`ErrorCode::ChallengeDisabled = 0x000C` |
| `daemon/state.rs` | `SigningGates`(`raw` + `challenge` 两个开关);`sign_challenge` |
| `daemon/handlers.rs` | 一条 `SIGN` 的分支;`Event::ChallengeSigned` |
| `cli.rs` | `serve --allow-challenge-signing`;`sign --challenge PATH` |
| `client/mod.rs` | `sign_challenge` |

`mcp` **一处都没接**,而且不是漏了 —— 门面的模块头写清了理由:`SIGN(Challenge)`
签的是调用方给的、没有任何消息语义的字节,本质上是小一号的 `Raw`;需要它的是
**协议客户端**(注册流程里那一步),它直接走 socket 问,agent 没有理由问这个。

## 边界:能钉住的只有那道 256 字节的墙

**"比 `Raw` 窄"在密码学上是句空话。** 256 字节以内的挑战签名和 `Raw` 产出的
是**同一个东西**:同一把钥匙、同样签调用方给的原字节、同样验证方拿公钥直接验。
分开它们的只有四样,而且全部是程序上的:

- **那道上限是唯一有实质重量的东西。** 256 字节卡在任何一份 DID 文档之下(一份
  文档是它的十几倍),所以这条路**结构上长不成**"帮我把文档签了"。这一条写进了
  `MAX_CHALLENGE_LEN` 的文档注释,也写进了 §3.3 —— 它就是这条路和 `Raw` 之间
  全部的、以及仅有的距离。
- **不解释字节,也不做字符集过滤。** 和 §3.1 的 `nonce` 正相反:那里过滤,是因为
  `nonce` 要**进签名基**,一个带换行的值会把签名基划开;这里原样签,正是对端的
  要求(`challenge.encode("utf-8")` 之后直接验)。
- **单独一条审计**(`CHALLENGE_SIGNED`,和 `RAW_SIGNED` 分开)、**单独一个开关**
  (`--allow-challenge-signing`,默认关)。

**开关的粒度有个不对称,是有意的:** `--allow-raw-signing` 打开时挑战签名**自动
也开**(`SigningGates::new` 里 `raw || challenge`),反过来不成立。理由是包含关系 ——
`Raw` 严格更宽,宽的那条开着时再拦窄的那条,拦不住任何东西,只会让人以为这里有
一层实际不存在的保护。反过来,窄的那条开着**就是**"不开宽的那条",这是一条真的
约束,不是形式主义。

## 两处是写完之后回头改的

- **`SigningGates` 的字段原来是 `pub` 的。** 那样 `SigningGates { raw: true,
  challenge: false }` 这个字面量能写出一个绕开 `raw || challenge` 的两开关组合,
  而不变式(宽的开着 ⇒ 窄的开着)只写在 `new()` 里。改成字段私有 + 两个 getter,
  让"用别的写法绕过去"这件事在类型上就做不到。
- **`SignRequest::Challenge` 的文档注释原来写着这条路"能签的东西有形状"。**
  那句话是错的,而且错得正好是这个条目最容易被误读的那一点:它签的字节**没有
  形状**,和 `Raw` 一样。注释和 ADAPTER §3.3 最后两段现在说的是同一句话:差别
  在**有上界**,不在**有形状**。

先写出一个"听起来更安全"的说法,再回头改成实话 —— 这种事在这份仓库里是按缺陷
处理的。那一行如果说反了,后面每个人都会拿它当理由去顺手放宽别的东西。

## 新测试

- `wire.rs::a_challenge_at_the_cap_is_accepted_and_one_byte_over_is_refused` ——
  边界那一格:**正好** 256 签得出来,257 在**解码**层就被拒(报 `Protocol`),
  连钥匙都不碰。
- `state.rs` 五条:`challenge_signing_is_off_unless_its_switch_is_on`、
  `the_challenge_switch_is_checked_before_the_lock_state`(关着的时候拒的理由是
  "这个开关没开",不是"锁着"——不然人会去解锁,然后撞上同一面墙)、
  `an_unlocked_key_is_usable_for_challenge_signing_when_the_switch_is_on`,
  以及那条不对称关系的两面:`opening_the_wider_raw_door_also_opens_the_narrow_challenge_one`
  / `opening_the_challenge_door_does_not_open_raw`。
- `handlers.rs` 两条:拒绝的话里要有 `--allow-challenge-signing`;签得成的那条
  顺带断言日志里是 `challenge_digest`,**挑战本身不在日志里**。
- `tests/signature_end_to_end.rs::a_challenge_signature_verifies_with_an_outside_verifier`
  —— 真的 socket、真的守护进程,签的是**顶到上限**的 256 字节,交给 `ed25519_dalek`
  拿**磁盘上那份已发布文档**里的公钥验;紧跟着量 257 字节在 socket 那头被拒。
  验签的人是外面的实现,不是这个 crate 里的代码 —— 这条证的是"对端真能验过",
  不是"我们自己觉得对"。
- `tests/cli.rs::the_challenge_flag_is_its_own_door` —— 走两条真的命令行:开关
  关着时拒、而且话里说出那个开关的名字(而且是在**解了锁之后**拒的,否则拒的
  理由可以是"没解锁");开着时签得出、外面验得过,`--raw` 同时仍被拒,日志里那条
  叫 `CHALLENGE_SIGNED`、记长度和摘要而不是挑战本身。

`tests/cli.rs` 的夹具加了 `Daemon::start_with(dir, extra)`(原来的 `Daemon::start`
成了它的一层薄包装),因为这个开关是**命令行上**的东西。测试用了两个根,不在同一个
根上起两遍守护进程:`Daemon::start` 等的是 socket **文件**出现,而上一个守护进程
留下的那个文件还在,于是它会立刻返回,下一条命令撞在一个还没绑好的 socket 上。

## 落地清单

| 文件 | 改了什么 |
|---|---|
| `src/daemon/wire.rs` | 第三个变体 + `MAX_CHALLENGE_LEN` + `ChallengeDisabled`;解码处的上限检查;一条边界测试 |
| `src/daemon/state.rs` | `SigningGates`(字段私有 + getter);`sign_challenge`;五条测试 |
| `src/daemon/handlers.rs` | `SIGN` 的分支 + `CHALLENGE_SIGNED`;两条测试 |
| `src/audit/log.rs` | `Event::ChallengeSigned`(刻意和 `RawSigned` 分开);封闭 tag 集合那条测试补上第八个 |
| `src/cli.rs` | `serve --allow-challenge-signing`;`sign --challenge`,和结构化那套、以及和 `--raw` 互相排除 |
| `src/client/mod.rs` | `sign_challenge` |
| `src/mcp/mod.rs` | **不加工具**,只在模块头写明为什么 |
| `src/error.rs` | `ChallengeDisabled` 的消息带上该开哪个开关 |
| `docs/ADAPTER.md` §3.3 / §3.1 / §三 / §八 / §九 / §十 / §十一 / §十二 | 岔口落定:四样边界、为什么不是另外两条、以及"密码学上同一个东西"那段实话 |
| `TODO.md` §一 / §五 | §一 拍定、§五 这一件做完,都在原地留下指向本条的一行 |

---

# 追加六:客户端侧和验收 —— ✅ 已做完(2026-10-14)

**下面「整份归档三」那一版(以及它前面那一版)的 §二。** 那一节的验收有两半,而两半
问的是**不同的问题**:连接器那一半问"客户端和守护进程对得上吗",服务端那一半问
"**另一个实现**认这个身份吗"。第二半是这一条补上的,也是整个适配层里唯一一次
**跨语言、跨进程的对端**。

做完的样子就是那两条验收:

| | 脚本 | 是什么 |
|---|---|---|
| 守护进程那一半 | `anp-sdk/scripts/keyd-acceptance.mjs` | 五条反证对真守护进程,九条里八过一 SKIP |
| 服务端那一半 | `anp-sdk/scripts/keyd-server-acceptance.mjs` | 注册 + 登录对真的 `awiki-open-server`,十条全过 |

两个脚本一个约定:自己的临时 root、自己的守护进程、`keyd-tty.py` 供 TTY、逐条
PASS/SKIP/FAIL、跑完把自己的根删掉,不碰 `~/.anpio-key`。第二个脚本要一台**已经在跑**
的服务端(`--target`),所以它不进 CI,是手动跑的验收 —— 这一点写在它自己的头一段里。

## 落地的形状

跨两个仓库,而且**两边各有一处只有那边才该做的改动**:

| | 在哪儿 | 是什么 |
|---|---|---|
| 连接器 | `anp-sdk/src/core/connectors/keyd.ts` | `AnpConnector` 的一支:只转发、只翻译错误 |
| 线 | `anp-sdk/src/core/connectors/keydWire.ts` | 帧 + 结构化变体 + `signChallenge`(SIGN 0x03) |
| 请求体 | `anp-sdk/src/core/protocol/anp.ts` | `buildAnpLoginBody` 提成一个函数,连接器和钱包那条路共用 |
| 挑战签名 | 同上 + `types.ts` | `AnpConnector` 上的**可选**方法 `signChallenge?` |
| `proofValue` | `anpio-key/src/did/proof_value.rs` | 出站换 multibase,交回上游验签前换回去 |

**"适配器里只做转发和错误翻译,出现协议词就是边界划错了地方"这条守住了。** 请求体
不是连接器拼的,是 SDK 自己的 `buildAnpLoginBody`;连接器里出现的唯一协议词就是那个
函数名。`Locked` 走的是 `KeydLockedError` 而不是 `ConnectxError` —— 调用方**不可能**
把它报成"签名失败",因为类型上就不是那一个。

## 实测出来的五样

**一、`proofValue` 的字母表:上游 `anp` 1.0.6 是那个离群的。** 它 `complete_w3c_proof`
交出来的是**裸 base64url**;ANP-03 §2.5.5(W3C Data Integrity)要的是 multibase
base58btc,也就是一个 `z` 前缀,而 awiki-open-server 只认这一种
(`service_identity._decode_proof_value` 见到别的前缀直接报
`did_document_proof_value_invalid`),anp-sdk 也只发这一种。**量过**:拿上游那份
base64url 去注册,服务端原样拒;同一个签名换成 `z`+base58btc,注册当场成功。

**换字母表不动签名。** 签名输入是 `jcs(proof options) ‖ jcs(document minus proof)`,
而 `proofValue` 本来就被剔在输入外面 —— 重编的是同一批字节,不是重签一次,所以既
不需要私钥,也不可能因为换而签坏。反方向的那个函数是给**上游的验签**用的:它只认得
base64url,把文档交给它之前先换回去,它算出来的输入和我们签的那一份逐字节相同,于是
它验的就是我们真正签过的东西。

**和上面那条"1.0.6 不动签名基"不矛盾** —— 那说的是 `proof/mod.rs` 改的是**验证**那一支
的输入拼法,而这里分歧的是**编码**,不在签名输入里。

**二、带签名的登录是 did-auth RPC 本身,不是 `GET /me` —— 上一版 TODO 在这一点上写错了。**
错处已划在快照里,这里记结论:`GET /user-service/v1/me` **走不到**签名那一支,它的
`legacy_me_profile` 先叫 `current_did(request, required=True)`,而 `/me` 不在
`did_auth_signature_path` 里,于是在看签名之前就抛 `missing_authentication`。这一版的
`did_verify_login` 也照旧:收 `did` + 一个配置里的 dev code,**根本不验签**。真正带签名的
登录是往 `/user-service/v1/did-auth/rpc` 发一个不带 bearer、带 `signature-input` +
`signature` 的 JSON-RPC 调用,服务端验完签名回**资料 + 一套新 token**。在这台服务端上,
"登录"和"一次带签名的调用"是同一件事,没有第二个口。

**三、连接器的 `signRequest` 接不了这条路,和注册是同一类错位。** 它签名盖住的体永远是
`buildAnpLoginBody` 产出的 `{nonce, did, didDocument}`,而这个口要的是**纯 JSON-RPC
信封**(`JsonRpcRequest` 是 `extra="forbid"` 的),形状对不上,在验签之前就被拒;
`RequestEnvelope` 又跑在签名**之后**,改不了已经算进摘要的字节。注册那边是同一个故事:
服务端要的字段和 ANP-02 的登录体不是一回事(`ADR-0003`)。

所以验收**不为此新开 SDK API** —— 开的那个口子("签调用方自己拼的体")正是 §十 挡着的
东西。走的是 CLI 那条**公开接缝**:`anpio-key sign --url --header --body <FILE>`,
调用方自己拼体,守护进程签**那串字节**。这条路本来就存在(结构化 `sign` 收的是文件),
验收只是第一个这么用它的调用方。

**四、有 proof 的文档里那条 `ANPMessageService` 是要考的,而且只对有 proof 的文档生效。**
`_ensure_anp_message_service`(`user_compat/core.py:310`)分两支:没有 proof 的文档,
服务端把模板直接塞进去;有 proof 的走验证那一支 —— 要求**恰好一条**
`ANPMessageService`,且 `serviceEndpoint` 和 `serviceDid` **等于服务端自己的配置**,
否则是 `signed_did_document_service_endpoint_mismatch` / `..._service_did_mismatch`。
其余字段(profiles / securityProfiles / authSchemes)服务端**改写**成自己的值,只保留
调用方给的 `id`。这不是挑剔:它不肯在一份自己签发的身份文档里,把一个对端指向**别人的**
消息口。keyd 的文档带 proof,走的就是这一支 —— 验收脚本因此去读服务端自己发布的那份
文档,把那条 entry 原样拿过来,而不是自己拼一个 URL。

**五、keyd 拒签非 HTTPS 的 URL,而服务端按自己的配置重算签名基 —— 两边要的是同一个串。**
`sign/rfc9421.rs::validate_url` 拒签 `http://`(理由是 did:wba 是绑在域名上的身份),
所以对一台没有 TLS 的开发服务器,签名里的来源和字节实际发到的地址是**两个值**
(脚本的 `--signed-origin`)。这能成立,是因为服务端重算签名基用的是它自己配置的
`AWIKI_PUBLIC_BASE_URL` + 路径,**不看这次连接上走的是什么协议**。同一处还有
`--did-domain`:服务端 `_validate_local_user_did` 要求 DID 的域等于它自己的
`AWIKI_DID_DOMAIN`,而它自己发布的那条 DID 会把端口写进 authority,所以默认值是从
那里推、再把端口剥掉。

## 剩下的一条尾巴

**awiki-cli-rs2 那半没动,而且不是"没写"** —— 它在这台机器上开不了工:`Cargo.toml:43-44`
两条 path 钉的是 `../anp/anp/rust`(`=1.0.3`)和
`../anp/anp-identity/crates/anp-identity`(`=0.2.3`),两个目录本机都不存在,registry 上
只有 `1.0.5`/`1.0.6` 和 `0.2.5`,`=` 钉死了换不上去。**要么把上游那两个版本弄回来,要么
松那两条钉 —— 两件都是要人拍的**,所以搬进了新的 [TODO.md](../TODO.md) 第一节。

## 落地清单

| 文件 | 改了什么 |
|---|---|
| `anp-sdk/src/core/connectors/keyd.ts` | 新增:连接器本体(转发 + 错误翻译表 + `KeydLockedError`) |
| `anp-sdk/src/core/connectors/keydWire.ts` | 新增:线协议客户端,含 `signChallenge` 与 `MAX_CHALLENGE_LEN` |
| `anp-sdk/src/core/protocol/anp.ts` | `buildAnpLoginBody` 从 `cryptoWalletProver` 里提出来,两处共用 |
| `anp-sdk/src/core/types.ts` | `'keyd'` 钱包类型;`ChallengeSignRequest` / `ChallengeSignature`;`AnpConnector.signChallenge?` |
| `anp-sdk/src/core/{index.ts,connectors/index.ts}` | 导出 `keydConnector` / `KeydLockedError` 和两个挑战类型 |
| `anp-sdk/src/core/index.test.ts` | 公开导出清单里加上那两个新名字 |
| `anp-sdk/scripts/keyd-acceptance.mjs` | 新增:对真守护进程的五条反证(九条检查) |
| `anp-sdk/scripts/keyd-server-acceptance.mjs` | 新增:对真 awiki-open-server 的注册 + 登录(十条检查) |
| `anpio-key/src/did/proof_value.rs` | 新增:两种字母表互转 + 五个测试 |
| `anpio-key/src/did/document.rs` | 签名后换成 multibase;交给上游验签前换回去;一条新测试 |
| `anpio-key/tests/signature_end_to_end.rs` | 上游验签那一处也先换字母表 |

---

# 整份归档三:2026-10-14 收工时的 TODO

**下面是那一版 TODO.md 的原样快照。** 它是"一件就是一件事"的那一版(上一版的归档是
「整份归档二」)。它在自己这一段里的那几件,记录就是上面「追加五」和「追加六」;
**没收的那一件搬进了新的 [TODO.md](../TODO.md)**。

**这一版重新编号了,快照里是旧号。** 上一版的 §一 拍定、§二 做完、§五 做完,剩下的
按顺序变成了新 TODO 的一到三。旧号留在这份快照里,是因为提交信息、上面各「追加」、以及
ADAPTER 里都用"§二 那条"、"§五 那个开关"这样的说法 —— 快照在,那些话就查得到。

**正文一字未改,只把链接前缀去掉了** —— 它从仓库根目录挪进了 `docs/` 里,`docs/` 那一段
不去的会指向 `docs/docs/`,`anp-sdk/…` 那些原本就是仓库外的相对路径,照旧。

**一处错话原样留着**:§二 里那段划掉的 `login` 说明当时是**写错的**(`GET /me` 走不到
签名那一支),更正就在它下面,没有抹掉。留着的理由和别处一样 —— 快照的意义是当时
什么样,不是后来改成了什么样。

---

# TODO

还没做完的事。**为什么**这么做在 [DESIGN.md](DESIGN.md)(威胁模型、取舍)
和 [ADAPTER.md](ADAPTER.md)(适配层的方案)里 —— 这里只列**要动手的东西**。

**一件就是一件事。** 一件做到什么算完,写在条目里;怎么做到,在对应的文档里。

**这一份重新编号了,所以旧的说法要去归档里对。** 上一版整份快照是归档里的
[TODO-archive.md](TODO-archive.md) 「整份归档二」—— 它做完的那几件
(§一 / §四 / §六)分别记在归档的「追加一」到「追加四」里,没收的四件搬过来时按顺序
成了下面的一到四:

| 上一版 | 现在 | 是什么 |
|---|---|---|
| §二 | 一 | 注册那个挑战签名(要人拍的岔口) |
| §三 | 二 | 客户端侧和验收 |
| §五 | 三 | 硬件根剩下三件 |
| §七 | 四 | 明确不做 |

**这一版内部的规矩和上一版一样:做完的就在原地划掉,不搬走、不重编号** —— 等到这一版
也收工,再整份快照进归档。所以这个文件里,**没被划掉的才是还没做的**。

眼下的主线是**适配层** —— 在不让守护进程认识任何一个具体协议的前提下,让它满足
connectx / awiki-cli-rs2 这类工具的签名需求([ADAPTER.md](ADAPTER.md))。
硬件根是上一阶段的收尾,剩下的三件不是代码问题,理由在条目里。

---

## ~~一、适配层:注册那个挑战签名 —— 先写下来,不必现在拍~~ ✅ 已拍(2026-10-14)

~~awiki-open-server 的注册,除了 DID 文档自签,还要一次一次性挑战的证明:对服务端
下发的随机串做一次 Ed25519 签名(`challenge_signature`)。**那不是 RFC 9421**,而
[ADAPTER.md](ADAPTER.md) §十 那条线("不为适配打开 `Raw`")正挡在它前面。
三条路(不签 / 开一条比 `Raw` 窄的路 / 承认注册不在范围内)写在
[ADAPTER §3.3](ADAPTER.md) —— 那是这份方案里**唯一一处要人拍的岔口**。~~

~~**但两个客户端都不发它** —— connectx 走文档自签 + 401 重签,awiki-cli-rs2 的注册 RPC
里没这个字段(**两个都核过了**)。所以"不签"这条路**今天零成本**:它挡不住任何人,
只是一条**将来**对端把"可选"翻成"必需"时才会咬人的线。先记在这儿,不急着拍;真要拍,
要么进第四节「明确不做」,要么变成共用层上的一件东西 —— 那会是一条**新**的条目,不是
把上一版那条(nonce + `GET_DOCUMENT`)捡回来,那条已经做完并归档了。~~

~~**算完的样子:** 三条路里选定的那一条写进 ADAPTER 正文,§十二 里那条"未决"落定。~~

**拍的是第二条:开一条比 `Raw` 窄的路**,四条边界写进 [ADAPTER §3.3](ADAPTER.md)
正文(256 字节上限、不做字符集过滤、不解释字节、单独审计 + 单独开关),§十二 里那条
"未决"落定。**有一条要连着读**:这条路在密码学上和 `Raw` 是同一个东西,分开它们的只有
那条上限和程序上的三样东西 —— 理由写在 §3.3 最后两段,别只看这一行。

## ~~五、适配层:把那条窄路做到 socket 上~~ ✅ 已做完(2026-10-14)

~~上一节拍下来的那条路,落点是共用层:**`SIGN` 的第三个变体**(`SignRequest::Challenge`,
和 `Structured` / `Raw` 并列),不是新消息类型。加一处类型、一处 handler、一条审计
(`CHALLENGE_SIGNED`,和 `RAW_SIGNED` 分开)、一个开关(`--allow-challenge-signing`,
默认关;`--allow-raw-signing` 打开时它自动也开,因为 `Raw` 严格更宽),`cli` 接一处。
**`mcp` 不接** —— 给 agent 一个"签这串字节"的工具,正是 §9.3 那条要挡的东西。~~

~~**这一件不是"顺手开的口子",所以边界跟着代码一起落:** 上限在协议层就拦掉(超了报
`Protocol`,不是签完再说),字节原样签名、不做字符集过滤(和 `nonce` 正相反,理由在 §3.3),
审计记 `did` / 长度 / 摘要。~~

~~**算完的样子:** `SIGN` 的第三个变体在 `wire` 上跑得通;256 字节签得出、257 字节在协议层
被拒;守护进程没开那个开关时拒绝的码和消息都对得上;开了之后签名能用上游实现验过。~~

**四样边界都落了,四条都当场量过**(256 签得出 / 257 在解码层被拒 / 关着时拒的话里
有那个开关的名字 / 开了之后交付的是 `ed25519_dalek` 拿**已发布文档**里的公钥验过的
签名),`mcp` 一处没接。**唯一要连着读的一句**:这条路在密码学上和 `Raw` 是同一个
东西,钉住它的只有那道 256 字节的墙 —— 记录在 [TODO-archive.md](TODO-archive.md)
末尾「追加五」,别把"窄"读成"有形状"。

## 二、适配层:客户端侧,和验收

- ~~**connectx:接的是 connector,不是 provider。** `AnpConnector.signRequest` 收
  method / url / nonce / handle,形状正好对上 keyd 的结构化路径;EIP-1193 那层只到
  `signMessage`,用它就得开 `Raw`。实现纪律照抄 `providers/README.md`:适配器里
  只做转发和错误翻译,出现 "ANP" 这个词就是边界划错了地方(§八)。`Locked` 原样
  交回给人,**不重试、不翻译成"签名失败"**(§六)。~~ ✅ 已做完(2026-10-14):
  连接器在 `anp-sdk/src/core/connectors/keyd.ts`,线在 `keydWire.ts`,都是公开导出。
  转发那半做到了"没有 ANP 知识" —— 请求体是 SDK 自己的 `buildAnpLoginBody` 拼的,
  连接器里出现的唯一协议词就是它;错误那半是一张只变粗的翻译表,`Locked` 走的是
  `KeydLockedError`(不是 `ConnectxError`,所以调用方不可能把它报成签名失败)。
- **awiki-cli-rs2:接缝已经在了,而且形状就是 keyd 的。** 它那层 `IdentitySigner` 的
  `http_signature_headers(kid, url, method, headers, body, options)` 正是结构化
  `SIGN`,而且 `options` **本来就带 `nonce`**;`did_document()` 正是 `GET_DOCUMENT`。
  `AnpIdentitySigner` 已经把同一批方法转手给 `anp-identity` 这个"custody 在别处"的
  实现 —— keyd 照它再写一份即可(§八)。**一处错位**:`sign_document_proof` 收的是
  调用方构造的文档,和 keyd 的不变量 3 对不上,注册那一段的改法要单独想。
  **在这台机器上开不了工,而且不是环境没配好:** `Cargo.toml:43-44` 那两条 path 钉的是
  `../anp/anp/rust`(`=1.0.3`)和 `../anp/anp-identity/crates/anp-identity`(`=0.2.3`),
  两个目录本机都不存在,registry 上只有 `1.0.5`/`1.0.6` 和 `0.2.5`,`=` 钉死了换不上去。
  要么把上游那两个版本弄回来,要么松那两条钉 —— **两件都是要人拍的**,所以这半没动。
- ~~**验收是 §十一 那五条反证。** 核心是第一条:**停掉守护进程,connectx 必须失败**
  —— 不然只是多了一条可选路径,不叫抽出来了。~~ ✅ 五条都对真守护进程跑过
  (2026-10-14):`anp-sdk/scripts/keyd-acceptance.mjs`,自己一个临时 root 和 socket,
  跑完删掉,不碰 `~/.anpio-key`。第 1 条连错误码、消息里点名 `anpio-key serve`、
  以及"守护进程回来就恢复"一起验;第 2 条验的不只是"交出个 `Locked`",而是**同一个
  请求**在人工解锁之后签得出来(不验这半,"可重试"就只是个词);第 3 条不是数行数,
  是在 JS 里把整条哈希链重算了一遍;第 4 条把 connectx 的 DID 和 `document` 子命令的
  字节逐字节比了;第 5 条交给 Python(`anp` 1.0.3)。第 5 条要另一个语言,没给
  `ANP_PYTHON` 就报 **SKIP 并说明为什么**,不假装过。后来又加了一条挑战签名
  (守护进程默认关 → 开了之后签得出 → 用文档里那把公钥验得过 → 审计里记的是摘要
  不是原文),**九条里八过一跳**。
- **验收那条已经跑通了(2026-10-14):对真的 `awiki-open-server` 走完 `register` +
  `login`。** 上一条证的是守护进程那一侧 —— 客户端和守护进程对得上;这一条把同一把
  keyd 持有的身份送到**另一个实现**面前:服务端拿 Python `anp` 重算签名基、拿 pip 的
  `cryptography` 验 Ed25519,中间隔着进程边界、一条 socket、两种语言。脚本在
  `anp-sdk/scripts/keyd-server-acceptance.mjs`,沿用上一条 `keyd-acceptance.mjs` 的
  约定(自己的临时 root、自己的守护进程、`keyd-tty.py` 供 TTY、逐条 PASS/FAIL):

  ```bash
  npm run build
  ANPIO_KEY_BIN=/path/to/anpio-key node scripts/keyd-server-acceptance.mjs \
    --target http://127.0.0.1:8792
  ```

  **十条,全过。** 前四条是注册:`challenge` → 挑战裸签 → `register` → 服务端存下来的
  文档里 `proofValue` **仍是 `z` 打头的 multibase**(这条才把 `did::proof_value` 那个
  改动钉在真对端上)→ 同一个 challenge 再花一次被拒。后六条是登录:不带签名被拒
  (`missing_authentication`)→ 带签名回来一整套 token → 重放同一份签名被拒
  (`signature_replayed`)→ 为**另一个 URL** 签的那份头拿来打这个口被拒
  (`invalid_http_signature`)。

  **服务端这一侧的规矩(对着源码核出来的):**
  - 注册走的是 JSON-RPC(`/user-service/v1/did-auth/rpc`,方法 `register`),没有
    ANP-02 那个 `/api/login/anp/verify` 口子。它要 `did` + `did_document`(带 proof,
    也就是 `publish` 出来的那一份,`GET_DOCUMENT` 取得回来),另外**可以**带一对
    `challenge` / `challenge_signature` —— `challenge` 有专门的 RPC 发(300 秒、一次
    性),签名是**对这串 challenge 本身的 Ed25519 裸签**,拿文档里的验证方法验。
    这正是 §一 拍的那条、§五 落到 socket 上的 `SIGN` 第三个变体。
  - ~~**可连接器还没接那条路。** `keydWire.ts` 里只有结构化那一支(`SIGN_STRUCTURED`),
    挑战那一支没发过,`challenge_disabled` 只是当错误码翻了个名。所以要把注册跑通,
    先得把挑战签名这条路从 `keyd.ts` 露出来 —— **这是 §二 里剩下最实的一件**。~~
    ✅ 已接上(2026-10-14):`keydWire.ts` 多了 `signChallenge`(SIGN 0x03,带
    `bytes32` 那一列)和 `MAX_CHALLENGE_LEN = 256`;`keyd.ts` 把它接成
    `AnpConnector` 上的**可选**方法 `signChallenge?`(别的连接器不实现就该不实现,
    调用方按 `events` 那种方式探),返回 base64url 的签名 + 用的是哪份文档。
    出口只有这一条窄路:上限 256 字节,超了在**连接器这一层**就拒(报
    `invalid_argument`)—— 不能留给守护进程拒,它按 `Protocol` 拒,而那张翻译表
    把 `Protocol` 读成"版本对不上",对"这不是个挑战"是句错话。开不开由守护进程的
    `--allow-challenge-signing` 定(默认关),所以 SDK 自己不另加开关:
    `challenge_disabled` 就是那个开关的读法。
  - 还有一条硬约束:服务端 `_validate_local_user_did` 要求 DID 的域等于它自己的
    `did_domain`(默认 `localhost`),所以 keyd 那把钥匙得用同一个域 `keygen` 出来,
    不是随便造一把就行。
  - **文档里那条 `ANPMessageService` 也有约束,而且只对有 proof 的文档生效。**
    `_ensure_anp_message_service`(`user_compat/core.py:310`)分两支:没有 proof 的
    文档,服务端直接把模板塞进去;有 proof 的走验证那一支 —— 它要求**恰好一条**
    `ANPMessageService`,并且 `serviceEndpoint` 和 `serviceDid` 必须**等于服务端
    自己的配置**,否则就是 `signed_did_document_service_endpoint_mismatch` /
    `..._service_did_mismatch`。其余字段(profiles / securityProfiles /
    authSchemes)服务端**改写**成自己的值,只保留调用方给的 `id`。这不是挑剔:
    它不肯在一份自己签发的身份文档里把一个对端指向**别人的**消息口。keyd 的文档
    带 proof,所以走的是这一支 —— 验收脚本因此去读服务端自己发布的那份文档,把那条
    entry 原样拿过来,而不是自己拼一个 URL。
  - ~~**`login` 另外说:** 这一版的 `did_verify_login` 收的是 `did` + 一个配置里的
    `did_verify_dev_code`(默认 `666666`),**根本不验签**。带签名的那条路是
    `GET /user-service/v1/me`:不带 bearer、带 `signature-input` 时它回一套 token ——
    那个形状正是 connectx 的 `signRequest` 产出的。所以"登录"这一步要对的是 `/me`,
    不是 `login`。~~ ❌ **上一版这一段写错了,2026-10-14 对着源码核过并已跑通:**
    `GET /user-service/v1/me` **走不到**签名那一支 —— `legacy_me_profile` 先叫
    `current_did(request, required=True)`,而 `/me` 不在 `did_auth_signature_path`
    里,于是**在看签名之前**就抛 `missing_authentication`
    (`user_compat/core.py:1273`)。`did_verify_login` 那边照旧:收 `did` + 配置里的
    `did_verify_dev_code`(默认 `666666`),**根本不验签**,登录也不是它。
    **真正带签名的登录就是 did-auth RPC 本身:** 不带 bearer、带 `signature-input` +
    `signature`,方法挑一个要身份的(`get_me`),服务端验完签名回**资料 + 一套新
    token**。在这台服务端上,"登录"和"一次带签名的调用"是同一件事,没有第二个口。
  - **连接器的 `signRequest` 接不了这条路,和注册是同一类错位。** 它签名盖住的体
    永远是 `buildAnpLoginBody` 产出的 `{nonce, did, didDocument}`;这个口子要的是
    **纯 JSON-RPC 信封**,而 `JsonRpcRequest` 是 `extra="forbid"` 的 —— 形状对不上,
    在验签之前就被拒;`RequestEnvelope` 又跑在签名**之后**,改不了已经算进摘要的
    字节。所以验收脚本不为此新开 SDK API,而是走 CLI 那条**公开接缝**:
    `anpio-key sign --url --header --body <FILE>` —— 调用方自己拼体,守护进程签
    **那串字节**。开发服务器没有 TLS 时再补一个 `--signed-origin`:keyd 拒签非
    HTTPS 的 URL(`sign/rfc9421.rs::validate_url`),而服务端重算签名基用的是它自己
    的 `AWIKI_PUBLIC_BASE_URL`,两边要的是同一个串。脚本的 `--did-domain` 同理,
    默认从服务端自己发布的那条 DID 推(把端口剥掉,因为 `AWIKI_DID_DOMAIN` 是裸域)。
- **`@authority` 那条也在这儿收了:** 规范化当初是对着源码核出来的(归档「追加二」),
  后来签名侧是真守护进程算的、验签侧是 Python `anp` 1.0.3 —— 也就是服务端自己用的
  那一份 —— 重算后对上了。~~**但对面还没有一个真的服务端**。~~ **现在有了:**
  上面那条带签名的 `get_me` 就是真对端 —— 客户端签的 URL 里 `@authority` 来自
  `--url`,服务端从它自己的 `AWIKI_PUBLIC_BASE_URL` 重算,两边拼出同一个串才验得过;
  反证是同一份体、为另一个 URL 签的头打过来被拒(`invalid_http_signature`)。
  跨实现这一环到此为止是**双向都量过**的,不再只是"源码上对得上"。

## 三、硬件根(M5):剩下三件,两件堵在签名身份上

代码都写完、能验的也验过了(结论在归档里),剩下的**都不是代码问题**:

- **SE 的持久化没验过。** "SE key 留在钥匙串里、进程重启之后还开得了"需要签名身份,
  而本机 `security find-identity -v -p codesigning` 是 0 个。有身份之后的三步验收
  在归档里。
- **macOS 的 SE 版本必须签名分发。** 写钥匙串要 Apple 签发的
  `application-identifier`,这是发行决策。**不要去试"ad-hoc 签名 + 手写
  entitlement"** —— 已经量过,进程会被内核 SIGKILL。
- **硬件绑定的端到端验收仍然跑在软件替身上。** `tests/hardware.rs` 验的是那条路的
  **形状**;"HS 真的出不了这台机器"只有真后端能验。TPM 那半在 Linux 上真跑过了,
  SE 那半等身份。

## 四、明确不做

适配这条路上不碰的(理由都在 [ADAPTER.md](ADAPTER.md) §十):打开 `Raw`、
让守护进程认识 ANP-02 的语义、让守护进程联网、`export` 上 socket、多用户细粒度
授权。加上原始计划 §十一 划掉的 v1 范围线(凭据中介、远程多租户解锁仪式、委托链 /
biscuit 能力令牌),边界见 [DESIGN.md](DESIGN.md) §一 和 §六。

**第一节那个岔口已经拍定、也做完了**(2026-10-14,记录在归档「追加五」):拍的是
"开一条比 `Raw` 窄的路",所以它**没有**落进这一节。这一节里留给它的只有两条照着
那条路划出来的线:那条窄路**不进 `mcp`**(agent 手里不该有"签这串字节"的工具,
§9.3),以及"窄"不等于"有形状"—— 它只有一个 256 字节的上界。
