//! 审计：append-only 的 JSONL，每行带一条哈希链。
//!
//! ## 记什么，不记什么
//!
//! **记 `signature_base_digest`（签名基的 SHA-256），不记签名基本身。**
//! 签名基里逐行躺着请求头的原文 —— 包括 `authorization`、`cookie`、
//! `x-api-key` 这些东西。审计文件是给人看、给机器留、还会被备份走的，
//! 把请求原文抄进去等于把一份凭据副本从签名路径漏到了另一个文件里。
//! 摘要够用了：事后要核对"某次签名签的到底是不是那条请求"，把那条请求
//! 重新拼出签名基、算一次摘要、对上就行 —— 而这本来就需要请求原文在手，
//! 也就意味着能对上的那个人本来就有权看到它。
//!
//! ## 哈希链能保证什么，不能保证什么
//!
//! 每条记录写进去之前先算好它自己的 SHA-256，放进**下一条**记录的 `prev`
//! 字段。于是：
//!
//! - **改一行、删中间一行、把两行调个位置** → 链断，可检出。
//! - **砍掉尾巴** → 链本身仍然自洽，**光看这个文件检不出来**。
//!
//! 第二条是这类结构的固有边界，不是实现没做到：一份"自己证明自己完整"
//! 的文件在数学上不存在，总得有一个链外的锚。所以旁边多放了一个
//! `.anchor`，记着行数和末行哈希，每次追加后一起落盘。
//!
//! 链是**跨月**的（一份日志就是一条链，不是每个月各一条），所以上面第一条
//! 对**已经过去的月份**同样成立 —— 前提是有人真去走那一段。[`AuditLog::open`]
//! 每次打开都从最早那份月份文件一路走到现在，走的就是整条链；早先它只验当
//! 前这个月，"改掉一个旧月份"因此在没人看的那一段上溜过去。
//!
//! 于是**能检出**：某一行被改、被删、被挪位（链断）；文件被截断或被回滚到
//! 某个旧版本（锚对不上）；某个更早的月份被整份删掉（链接不回它该接的那
//! 一行）。**不能检出**：有人同时改了 `.jsonl` 和 `.anchor` —— 那需要把锚
//! 放到这台机器之外（另一台主机、或者一个只可追加的远端），v1 不做。
//! 所以这里给的是**篡改留痕**，不是**篡改免疫**。把话说清楚比给一个
//! 听起来更强、实际做不到的承诺要好。

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nix::fcntl::{Flock, FlockArg};
use serde::Serialize;

use crate::crypto::sha256;
use crate::error::{KeydError, Result};

/// 链的起点。第一条记录的 `prev` 是这个全零。
const GENESIS: [u8; 32] = [0u8; 32];

/// 串行化"读 tail → 写记录 → 写锚"的那把锁。见 [`AuditLog`]。
///
/// **不是锁某一份 `NNNN-NN.jsonl`**:那个文件是 append 打开的,而且换月的
/// 时候会换成另一个 —— 锁住它等于在换月那一瞬间让两个进程各自拿着**不同
/// 文件**的锁,而那正是要防的窗口。这一把谁都不动。
const LOCK_FILE: &str = ".lock";

/// 一条审计记录。
///
/// 字段是**刻意具体**的：一个只写 `{"event":"sign"}` 的日志在事后什么也
/// 回答不了。记的是"谁、用哪把钥匙、覆盖了哪些分量、签名基的摘要"。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Event {
    /// 连接**被拒**。
    ///
    /// 这一条尤其重要：拒绝是安静发生的，没有它，一次跨 uid 的探测在
    /// 日志里和"什么都没发生"完全一样。
    Denied {
        /// 拿不到对端凭证时是 `None` —— 而"拿不到凭证"本身正是要记下来的
        /// 那件事,所以它不能用一个假的 uid 顶替。
        uid: Option<u32>,
        pid: Option<i32>,
        reason: String,
    },
    Unlocked {
        uid: u32,
        did: String,
    },
    /// `did` 为空 = 全锁。
    Locked {
        uid: u32,
        did: Option<String>,
        /// 实际放掉了几把。
        dropped: usize,
    },
    Signed {
        uid: u32,
        did: String,
        kid: String,
        /// **实际**被覆盖的分量，从签名基里解析回来的那一份。
        covered: Vec<String>,
        /// 签名基的 SHA-256，hex。不是签名基本身 —— 见模块头。
        signature_base_digest: String,
    },
    /// 原始签名。这条路径默认关着，开了之后每次都要留痕。
    RawSigned {
        uid: u32,
        did: String,
        payload_len: usize,
        payload_digest: String,
    },
    /// 挑战签名。这条路径默认关着，开了之后每次都要留痕。
    ///
    /// **和 [`Event::RawSigned`] 分开记，不是它的一个字段。** 两条路都签调用方
    /// 给的字节，但事后要问的问题不一样：“我们签了一次**挑战**”和“我们签了
    /// **别的什么东西**”必须是分得开的两件事。压成一条带 `kind` 字段的记录，
    /// 读日志的人就得先知道那个字段的取值表才读得懂 —— 而这条日志要回答的
    /// 恰恰是“那天到底发生了什么”。
    ChallengeSigned {
        uid: u32,
        did: String,
        challenge_len: usize,
        challenge_digest: String,
    },
    /// 有人取走了一份 DID 文档。
    ///
    /// 这条**不是**"授权"的记录，是"取件"的记录：文档本来就躺在一个 0644
    /// 的文件里，可公开。记它是因为"谁在什么时候把哪一版的文档取走了"事后
    /// 要查得出来 —— 摘要记的是**那一刻磁盘上那一份**，不是这个 DID 恒定的
    /// 某个值。
    DocumentRead {
        uid: u32,
        did: String,
        document_digest: String,
    },
    /// 空闲超时收走了钥匙。
    Swept {
        dropped: usize,
    },
    /// 换了一把热密钥。**新旧的 fragment 都要记** —— 只说"轮换过"回答不了
    /// "哪把钥匙从什么时候起不再被信任",而那正是事后要看的东西。
    RotateHot {
        did: String,
        retired_kid: Option<String>,
        new_kid: String,
        /// 轮换之后那份文档的指纹。文档改了,记下来才能和线上那一份对上。
        document_digest: String,
    },
    /// 加了一把恢复密钥(预授权,存在 `assertionMethod` 里)。
    AddRecoveryKey {
        did: String,
        kid: String,
        document_digest: String,
    },
    /// 加了一把协商密钥(X25519,只进 `keyAgreement`)。
    ///
    /// 单独一条,不并进 [`Event::AddRecoveryKey`]:事后要看得出"这个 DID 从
    /// 什么时候起有一把能做 ECDH 的钥匙",而 `ECDH` 是唯一一条会把秘密交出去
    /// 的路。
    AddAgreementKey {
        did: String,
        kid: String,
        document_digest: String,
    },
    /// 摘掉一把非绑定密钥。
    RemoveKey {
        did: String,
        kid: String,
        document_digest: String,
    },
    /// 迁移:旧文档被标成已注销并指向后继。
    Migrate {
        did: String,
        successor: String,
        document_digest: String,
        /// 两个 DID 的 stable subject path 是否相同 —— 不同就是一次换域名,
        /// 那条边的可信度低一档,事后要看得出区别。
        same_subject: bool,
    },
    /// 永久注销(或注销并指向后继 —— 那其实是迁移,这里记的是没有后继的那种)。
    Deactivate {
        did: String,
        successor: Option<String>,
        document_digest: String,
    },
    /// 导出种子。**编译期不在默认构建里**(`seed-export` 特性),但审计格式
    /// 留着:一个开着导出的构建写出来的日志,默认构建也得读得懂。
    ExportSeed {
        did: String,
        /// 导出物是"24 个词"还是"归档"。
        form: String,
    },
    /// 把一把身份导入这台机器 —— 可能是克隆,所以 `source` 要记清楚。
    ///
    /// **导入的后果是"这台机器从此也持着这把身份"**,而密钥不可撤销:
    /// 旧设备那份拷贝还活着。事后查"这台机器上什么时候多出来一把身份"
    /// 靠的就是这一条。
    Import {
        did: String,
        kid: String,
        /// `mnemonic` 或 `archive`。
        source: String,
        document_digest: String,
    },
    /// 这台机器自己生出来一把绑定密钥。
    ///
    /// 和 [`Event::Import`] 是同一个问题的两面:那条记的是"**别人那份**身份
    /// 被搬到了这台机器上",这条记的是"**这台机器自己**凭空多出来一把"。
    /// 只记导入等于留一个洞 —— 事后问"这个 DID 是什么时候在这儿出现的",
    /// 最常走的那条路(本地 `keygen`)反而答不上来。
    ///
    /// `hardware` 是**信封里实际落地的那一份**(没绑就是 `"none"`),不是
    /// 命令行上要的那个 —— 和 [`Event::Signed`] 的 `covered` 同一个道理:
    /// 记的是结果,不是意图。它用的词和 `--hardware` 的取值逐字相同
    /// ([`crate::keystore::record::HardwareRoot::kind`])。
    Keygen {
        did: String,
        kid: String,
        /// `none` / `secure-enclave` / `tpm` / `software`。
        hardware: String,
    },
    /// 24 个词在终端上显示过一次。
    ///
    /// **词本身不进审计,也不进任何文件。** 这里记的是"什么时候、给哪个
    /// DID 显示过、用的哪套推导":人以为备份已经抄下来了、而屏幕上其实
    /// 什么也没出来时,得有地方能对质。反过来说,审计链里出现 24 个词就
    /// 等于把备份抄了一份进日志 —— 那条链从此有一个擦不掉的地方。
    ///
    /// 这条和 [`Event::Keygen`] 一起落、落在后面:没铸成的那次显示没有
    /// DID 可写,而显示又必须发生在任何字节落地**之前**(人说了"没抄"
    /// 就什么都不该铸)。
    MnemonicShown {
        did: String,
        /// 推导方案的名字,现在是 `bip39-entropy-v2`
        /// ([`crate::crypto::derive::DERIVATION_V2`])—— 一个固定的版本标签,
        /// 不是任何算出来的值。
        scheme: String,
    },
    /// 一份文档被写成了本机发布的那一份(`dids/<did>.json`)。
    ///
    /// **记摘要,而且和 [`Event::DocumentRead`] / [`Event::RotateHot`] 那几条
    /// 用的是同一个函数**(规范化 JSON 的 SHA-256)—— 于是把一个摘要在整份
    /// 日志里搜一遍,得到的就是这份文档的一生:谁什么时候写下去的、谁什么
    /// 时候取走的、什么时候被改的。
    ///
    /// **`publish --out DIR` 不记。** 那条路只产出一个文件、本机一个字节都
    /// 没变(本地 `dids/` 里那份还是旧的就还是旧的),记下来会让人以为本地
    /// 那份文档是它。
    Published {
        did: String,
        document_digest: String,
    },
}

/// `.anchor` 的内容。
#[derive(Debug, Serialize, serde::Deserialize)]
struct Anchor {
    records: u64,
    tail: String,
}

/// 一个 append-only 的审计日志。
///
/// # 写它的**不止一个进程**
///
/// 这里早先写着"守护进程只有一条写路径"，那是错的：守护进程确实只有一条
/// （[`crate::daemon::state::DaemonState`] 每个目录攥一个，自己的
/// `Mutex` 串得住），但**生命周期命令也写**——每条 CLI 命令开一个
/// [`crate::ops::Session`]，里头是一份自己的 `AuditLog`，而它完全跑得起来
/// 的时间正是守护进程正忙的时候。
///
/// 两个进程各记各的 `records`/`tail`，各写各的行，后写的那一行的 `prev`
/// 指向一条不是它前驱的记录，链就断了。而这个文件存在的理由**就是**
/// 篡改留痕——链断是我们用来发现事故的信号。让一个合法操作造出这个信号，
/// 比日志乱一点糟得多：真的出了事和"有两个进程在写"会变成同一句话，而人
/// 看见几次之后只会学会忽略它。
///
/// 所以 [`AuditLog::append`] 的**读 tail → 写记录 → 写锚**整段走一把跨
/// 进程的 `flock`，和 [`crate::did::migrate::cas_publish`] 用的是同一套
/// 办法。锁是 [`LOCK_FILE`]，不是那份 `.jsonl`：后者是 append 打开的，
/// 换月还会换成另一个文件，锁它挡不住换月那一瞬间。
///
/// # 不能把锁攥一辈子
///
/// 锁只包住一次 `append`，不包住 `AuditLog` 的整个生命。守护进程会缓存
/// 一份到进程结束——攥着不放就等于"守护进程在跑的时候命令全部卡死"，而
/// 守护进程正跑着的时候 `create` 一把新钥匙是完全正常的并发操作。
#[derive(Debug)]
pub struct AuditLog {
    dir: PathBuf,
    file: File,
    month: String,
    records: u64,
    tail: [u8; 32],
    /// 我们相信当前那份 `.jsonl` 有多少字节。
    ///
    /// 和我们记得的不一样，就说明**别的进程**写过，那时才需要把状态重读
    /// 一遍。只有一个写者的时候它永远相等，于是热路径只多一次 `stat()`。
    written: u64,
}

impl AuditLog {
    /// 打开（或新建）审计目录，并**先把整条链走一遍**。
    ///
    /// 校验放在打开时而不是某个定时任务里：一份被改过的审计日志必须在
    /// 守护进程开始往上追加之前就被发现，否则新的记录会接在一个断掉的
    /// 链后面，把断点掩盖成"看起来一直是这样"。
    ///
    /// # 走的是**整份历史**，不只是这个月
    ///
    /// 链跨月延续（[`AuditLog::rotate_if_needed`] 换月不重置），所以起点是
    /// **最早那份月份文件的第一行** —— 那里必须是链的头（`prev = GENESIS`），
    /// 之后每一份都接上前一份的末行，一直走到这个月。见 [`verify_history`]。
    ///
    /// 早先这里只验当前这个月那个文件、起点取上个月末行，于是"改掉一个**已经
    /// 过去的**月份"是看不见的：那一刀落在没人看的那一段上。走完整条链是有
    /// 代价的（每次打开读一遍全部历史），但**这个代价躲不掉**：要发现旧月份
    /// 被改过，就得把旧月份读一遍，没有更便宜的办法。
    pub fn open(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;

        let month = current_month();
        let path = dir.join(format!("{month}.jsonl"));

        // 校验也在锁里。不然一个正在追加的进程会把一次干净的读变成
        // "锚和文件对不上"——又是一次假警报，和这一段要防的是同一件事。
        // 校验完就放手：攥着不放会把守护进程自己的写路径卡死。
        let (records, tail, written) = {
            let _guard = exclusive_lock(dir)?;

            let (records, tail) = verify_history(dir, &month)?;
            // 锚文件对不上 = 上次之后这个文件被截断或被回滚过（或者最后那几个
            // 月份文件没了）。
            check_anchor(dir, records, &tail)?;
            let written = fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0);
            (records, tail, written)
        };

        let file = open_append(&path)?;
        Ok(Self { dir: dir.to_path_buf(), file, month, records, tail, written })
    }

    /// 追加一条记录，落盘，并把锚一起更新。
    ///
    /// **先写记录、后写锚**，顺序不能反：反过来的话，记录写失败而锚推进了，
    /// 下次启动就会报一个并不存在的篡改。
    ///
    /// 整段在 [`LOCK_FILE`] 的排他锁里，并且**锁里第一件事是跟磁盘对账**
    /// （[`AuditLog::resync`]）——内存里那份 `records`/`tail` 只对自己这个
    /// 进程成立，而文件是共用的。
    pub fn append(&mut self, event: &Event) -> Result<()> {
        let _guard = exclusive_lock(&self.dir)?;
        self.rotate_if_needed()?;
        self.resync()?;

        let record = Record {
            seq: self.records + 1,
            at: now_rfc3339(),
            prev: hex(&self.tail),
            event,
        };
        let mut line = serde_json::to_vec(&record)
            .map_err(|e| KeydError::Protocol(format!("audit record is not serializable: {e}")))?;
        // 这条记录的哈希算的是**写出去的那串字节**，所以校验时直接把
        // 文件里的原始行拿来做 SHA-256 就行，不需要重新序列化 —— 也不必
        // 担心哪天 serde 改了字段顺序就验不过。
        self.tail = sha256(&line);
        self.records += 1;

        line.push(b'\n');
        self.file.write_all(&line)?;
        self.file.sync_all()?;
        self.written += line.len() as u64;

        self.write_anchor()?;
        Ok(())
    }

    pub fn records(&self) -> u64 {
        self.records
    }

    /// 把内存里那份状态对齐到磁盘上的真相。
    ///
    /// 判据是**文件的字节数**：每追加一行就把它加上去，所以它和我们记得的
    /// 不一样就意味着中间有别人写过。只有自己一个写者时是 O(1) 的一次
    /// `stat()`；真有人写过时才付一次整读。
    ///
    /// **变短是拒绝的理由，不是重读的理由。** 文件在别的进程手里缩短，
    /// 正是 `.anchor` 存在的意义所在；这里悄悄接受了、再往一个被截断的链
    /// 后面接一行，就把那次截断掩盖成了"看起来一直是这样"。
    fn resync(&mut self) -> Result<()> {
        let path = self.dir.join(format!("{}.jsonl", self.month));
        let on_disk = fs::metadata(&path)?.len();

        if on_disk == self.written {
            return Ok(());
        }
        if on_disk < self.written {
            return Err(KeydError::Protocol(format!(
                "{} shrank from {} to {} bytes while it was open here; that is the truncation the \
                 anchor exists to catch, and appending on top of it would hide it",
                path.display(),
                self.written,
                on_disk
            )));
        }

        let (records, tail) = last_record(&path)?;
        self.records = records;
        self.tail = tail;
        self.written = on_disk;
        Ok(())
    }

    fn rotate_if_needed(&mut self) -> Result<()> {
        let month = current_month();
        if month == self.month {
            return Ok(());
        }

        // 换月不重置链 —— 链跨文件延续，否则每个月的第一行都是一个
        // 谁都能伪造的新起点。
        self.month = month;
        self.file = open_append(&self.dir.join(format!("{}.jsonl", self.month)))?;

        // **这里是 0，不是新文件的长度。** 换月那一刻手上这份状态属于上个月，
        // 而链是延续的 —— 新文件是空的时候，上个月那份状态**正好**是这一条第
        // 一行的 `prev`，于是 `written` 和实际长度都是 0、`resync` 什么都不做，
        // 这是对的。反过来，新文件不是空的（这个月里已经有别的进程写过），
        // `0 < 长度` 就会让 `resync` 去把它重读一遍 —— 也正是需要的。
        // 要是这里写成"新文件的实际长度"，两种情况都会静悄悄地错。
        self.written = 0;
        Ok(())
    }

    fn write_anchor(&self) -> Result<()> {
        let anchor = Anchor { records: self.records, tail: hex(&self.tail) };
        let bytes = serde_json::to_vec(&anchor)
            .map_err(|e| KeydError::Protocol(format!("anchor is not serializable: {e}")))?;
        crate::keystore::layout::write_atomic(
            &self.dir.join(".anchor"),
            &bytes,
            crate::keystore::layout::SECRET_FILE_MODE,
        )
    }
}

#[derive(Serialize)]
struct Record<'a> {
    seq: u64,
    at: String,
    prev: String,
    #[serde(flatten)]
    event: &'a Event,
}

fn open_append(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(crate::keystore::layout::SECRET_FILE_MODE)
        .open(path)?;
    // 新文件先把权限盖死 —— `mode` 会被 umask 削，而审计文件不该受
    // 进程环境里的 umask 影响。
    fs::set_permissions(path, std::fs::Permissions::from_mode(crate::keystore::layout::SECRET_FILE_MODE))?;
    Ok(file)
}

/// 拿 [`LOCK_FILE`] 的排他锁，靠 `Flock` 的 `Drop` 放。
///
/// 每次拿都新开一个 fd，而不是在 `AuditLog` 里存一个 `Flock`：存着就等于
/// 攥一辈子（见 [`AuditLog`] 上那一段）。多一次 `open` 换来的是"锁只在
/// append 那一小段里存在"，而这个函数旁边本来就有一次 `sync_all()`。
///
/// 锁文件也盖成 [`crate::keystore::layout::SECRET_FILE_MODE`]：它自己不含什么
/// 秘密，但审计目录里凭空多一个 0644 的文件，正是那种会被当成"谁放进来的"
/// 而被翻来覆去看一眼的东西。
fn exclusive_lock(dir: &Path) -> Result<Flock<File>> {
    let path = dir.join(LOCK_FILE);
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(crate::keystore::layout::SECRET_FILE_MODE)
        .open(&path)?;
    fs::set_permissions(&path, std::fs::Permissions::from_mode(crate::keystore::layout::SECRET_FILE_MODE))?;
    Flock::lock(file, FlockArg::LockExclusive).map_err(|(_, error)| {
        KeydError::Protocol(format!("cannot take the audit lock {}: {error}", path.display()))
    })
}

/// 文件里最后一条记录：给出它的 `seq` 和**它那串字节**的哈希。
///
/// **不从头验链，两件事都刻意不做。**
///
/// 一是不验链：那是 [`AuditLog::open`] 的活儿（一次 [`verify_history`]），只在
/// 打开时付一次；这里是热路径上每写一行都要过的对账。
///
/// 二是**不从 GENESIS 验**：链跨月延续（见 [`AuditLog::rotate_if_needed`]），
/// 所以一个非首月的文件第一行的 `prev` 指的不是 GENESIS。拿 GENESIS 当起点
/// 去验**单独一份**换过月的文件，第一行就会"断链"——那是把一次正常的换月读成
/// 篡改。（整条链是可以从 GENESIS 验的，因为那时候手上还有它前面那些文件；
/// 这里没有。）
///
/// 末行哈希就是下一条的 `prev`，`seq` 就是下一条的前一号，两个都在这一行里，
/// 所以这里不需要别处再记一份状态。
fn last_record(path: &Path) -> Result<(u64, [u8; 32])> {
    let text = fs::read_to_string(path)?;
    let line = text
        .lines()
        .rfind(|line| !line.trim().is_empty())
        .ok_or_else(|| {
            KeydError::Protocol(format!("{} is not empty but holds no record", path.display()))
        })?;

    let parsed: serde_json::Value = serde_json::from_str(line).map_err(|error| {
        KeydError::Protocol(format!(
            "the last line of {} is not readable JSON: {error}",
            path.display()
        ))
    })?;
    let seq = parsed.get("seq").and_then(serde_json::Value::as_u64).ok_or_else(|| {
        KeydError::Protocol(format!("the last line of {} has no seq", path.display()))
    })?;

    Ok((seq, sha256(line.as_bytes())))
}

/// 走一遍链。`start` 是**前驱**的（末条 `seq`，末行哈希）；一条记录都没有时
/// 是 `(0, GENESIS)`。
///
/// 返回（末条 `seq`，末行哈希）。
///
/// # 返回的是 `seq` 而不是行数
///
/// 链跨文件延续，所以"总共有多少条"要用记录自己带的序号，不能用这个文件里
/// 数出来的行数 —— 后者在换月之后会从 1 重新开始，而 `.anchor` 里记的是累计
/// 数，两边一对不上就会报一次假的"被截断或回滚过"。
///
/// `seq` 因此是**被验过的一环**：每一行必须正好比前一行大 1。今天不改这个
/// 字段的编辑检不出来（行数不变），加上它之后检得出来。
///
/// 任何一行对不上就报**是哪一份文件的第几行** —— "审计日志坏了"这种消息没法
/// 查，而链现在跨好几份文件，"第 3 行"不说清是哪一份也一样没法查。
fn verify_chain_from(path: &Path, start: (u64, [u8; 32])) -> Result<(u64, [u8; 32])> {
    let file = file_name(path);
    let text = fs::read_to_string(path)?;
    let mut prev = start.1;
    let mut records = start.0;

    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        if line.trim().is_empty() {
            return Err(KeydError::Protocol(format!(
                "{file} line {number} is blank; a gap in an append-only log means it was rewritten"
            )));
        }

        let parsed: serde_json::Value = serde_json::from_str(line).map_err(|e| {
            KeydError::Protocol(format!("{file} line {number} is not readable JSON: {e}"))
        })?;
        let claimed = parsed
            .get("prev")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KeydError::Protocol(format!("{file} line {number} has no prev")))?;

        if claimed != hex(&prev) {
            // 断在第一行是**另一类事故**：不是"中间哪一行被改了"，而是它该接的
            // 那一整段不在（更早的月份文件没了，或者它该接的那条记录被重写了）。
            // 两种原因说在一起 —— 它们在这份文件里长得一模一样，而这里不该替
            // 人猜。
            return Err(KeydError::Protocol(if number == 1 {
                format!(
                    "the audit chain breaks at line 1 of {file}: either an earlier month's file \
                     is missing, or the record it should link to was rewritten"
                )
            } else {
                format!(
                    "the audit chain breaks at line {number} of {file}: it links to a record that \
                     is not the one before it, so a line was changed, removed, or moved"
                )
            }));
        }

        let seq = parsed
            .get("seq")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| KeydError::Protocol(format!("{file} line {number} has no seq")))?;
        if seq != records + 1 {
            return Err(KeydError::Protocol(format!(
                "{file} line {number} is record {seq} but {records} records come before it; \
                 a line was removed or a record was given the wrong number"
            )));
        }

        prev = sha256(line.as_bytes());
        records = seq;
    }

    Ok((records, prev))
}

/// 报错时用的文件名。链跨好几份文件,"第几行"必须说清是哪一份里的。
fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// **从最早那份月份文件一路走到 `upto`**,把整条链验一遍。
///
/// 返回（末条 `seq`，末行哈希）—— 也就是下一条记录该接的那个状态。
///
/// # 起点是链的头,不是"上个月末行"
///
/// 链跨月延续（见 [`AuditLog::rotate_if_needed`]）,所以中间每一份文件的起点
/// 都是前一份的末行;而**最早那份的起点只能是 `GENESIS`**。它不是的话,要么
/// 更早的月份文件被人删了,要么整条链是重写出来的 —— 两种都要报,而不是当成
/// "这份日志就是从这个月开始的"。
///
/// 这正是"改掉一个已经过去的月份"能被看见的地方:那些文件不属于"这个月",
/// 但它们在链上,走一遍就躲不过去。
///
/// `upto` **之后**的月份文件不参与:那是时钟跳到未来留下的东西,把它接进链里
/// 会让"哪一头是新的"变得可疑。这个函数回答的是"到现在为止这段历史对不对"。
fn verify_history(dir: &Path, upto: &str) -> Result<(u64, [u8; 32])> {
    let mut state = (0u64, GENESIS);
    for path in history_files(dir, upto)? {
        state = verify_chain_from(&path, state)?;
    }
    Ok(state)
}

/// `upto` 这个月（含）之前的全部月份文件,按时间排。
///
/// 文件名是 `YYYY-MM.jsonl`,所以按字节序排就是按时间排。**只收 `.jsonl`** ——
/// 同一个目录里还躺着 `.anchor` 和 `.lock`,把它们当月份文件读进来会得到一行
/// 解不出来的东西,而那会被报成"日志被改写",是一次假警报。
fn history_files(dir: &Path, upto: &str) -> Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
            name.strip_suffix(".jsonl").is_some_and(|stamp| stamp <= upto)
        })
        .collect();
    files.sort();
    Ok(files)
}

/// 锚和文件对不对得上。
///
/// 文件不存在而锚在 = 被删了；行数对不上 = 被截断或被追加过；
/// 末行哈希对不上 = 尾巴被换过。
fn check_anchor(dir: &Path, records: u64, tail: &[u8; 32]) -> Result<()> {
    let path = dir.join(".anchor");
    if !path.exists() {
        // 没有锚：要么是全新的目录，要么锚被人删了。空目录是正常起点；
        // 有记录却没有锚，就只能说不知道 —— 但不能当作没事。
        if records == 0 {
            return Ok(());
        }
        return Err(KeydError::Protocol(format!(
            "{} has {records} records but no .anchor; the anchor was removed, so \
             truncation can no longer be ruled out",
            dir.display()
        )));
    }

    let anchor: Anchor = serde_json::from_slice(&fs::read(&path)?)
        .map_err(|e| KeydError::Protocol(format!("{} is unreadable: {e}", path.display())))?;

    if anchor.records != records {
        return Err(KeydError::Protocol(format!(
            "the audit log holds {records} records but the anchor says {}; it was \
             truncated or rolled back",
            anchor.records
        )));
    }
    if anchor.tail != hex(tail) {
        return Err(KeydError::Protocol(
            "the last audit record does not match the anchor: the tail of the log was rewritten".into(),
        ));
    }
    Ok(())
}

/// 上一次导出是什么时候。
///
/// 这是"上次登录"那一类的东西,而且比它重要:导出是把整把身份抽出来,抽出来
/// 之后**没有任何办法撤销**。所以它必须能被事后看见 —— 一个被注入的 agent
/// 骗着人跑了一次 `export-seed` 之后,唯一会留下的痕迹就是这一条。
///
/// 扫的是**整个审计目录**,不只当月那份:导出可能发生在几个月前,而按月的
/// 分片意味着只看当月等于只回答"这个月有没有",那正好是最没用的那个答案。
/// 文件名是 `YYYY-MM.jsonl`,字典序就是时间序,所以最后一条命中的就是最新的。
///
/// 读不动的行一律跳过,不报错 —— 这个函数的调用点在每一条需要终端的命令的
/// 开头,而它绝不该成为那条命令失败的原因。链的完整性是 `AuditLog::open`
/// 的活儿,那是它该报错的地方。
pub fn last_export(dir: &Path) -> Option<ExportRecord> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .ok()?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .collect();
    files.sort();

    let mut latest = None;
    for path in files {
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        for line in text.lines() {
            let Ok(record) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if record.get("event").and_then(serde_json::Value::as_str) != Some("EXPORT_SEED") {
                continue;
            }
            latest = Some(ExportRecord {
                at: field(&record, "at"),
                did: field(&record, "did"),
                form: field(&record, "form"),
            });
        }
    }
    latest
}

/// 把上一次导出说成一句人话。从来没有导出过就是 `None`。
///
/// 措辞是刻意"不好看"的:这一行是最后一道提醒,它不该长得像一句状态报告。
pub fn export_tripwire(dir: &Path) -> Option<String> {
    let last = last_export(dir)?;
    Some(format!(
        "last export from this machine: {} — {} ({}).\n\
         If that was not you, treat every key here as compromised and migrate away from it.",
        last.at, last.did, last.form
    ))
}

/// 一条 `EXPORT_SEED` 记录里我们要的三样东西。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportRecord {
    pub at: String,
    pub did: String,
    pub form: String,
}

fn field(record: &serde_json::Value, name: &str) -> String {
    // 缺字段时给一句"不知道",不给一个空串 —— 空串在打印出来的时候什么都
    // 不说明,而"我不知道"至少是说清楚了的。
    record
        .get(name)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("(unreadable)")
        .to_string()
}

fn current_month() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!("{:04}-{:02}", now.year(), u8::from(now.month()))
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// 摘要的 hex 形式，给事件字段用。
pub fn digest_hex(bytes: &[u8]) -> String {
    hex(&sha256(bytes))
}

/// Read-only evidence for importing a stopped legacy writer into SQLite audit.
/// Does not create lock files, rotate history, update anchors or append events.
pub(crate) fn legacy_summary(dir: &Path) -> Result<serde_json::Value> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let metadata = fs::symlink_metadata(dir)?;
    if !metadata.is_dir() || metadata.mode() & 0o022 != 0 {
        return Err(KeydError::Protocol("unsafe legacy audit directory".into()));
    }
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"anp-keyd/legacy-files/v1\0");
    let mut total = 0u64;
    let mut paths = history_files(dir, "9999-99")?;
    let anchor = dir.join(".anchor");
    if fs::symlink_metadata(&anchor).is_ok() {
        paths.push(anchor);
    }
    for path in paths {
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&path)?;
        let m = file.metadata()?;
        total = total.saturating_add(m.len());
        if !m.is_file()
            || m.nlink() != 1
            || m.uid() != metadata.uid()
            || m.mode() & 0o022 != 0
            || total > 64 * 1024 * 1024
        {
            return Err(KeydError::Protocol(
                "unsafe or oversized legacy audit".into(),
            ));
        }
        let name = path.file_name().unwrap().as_encoded_bytes();
        hash.update((name.len() as u64).to_be_bytes());
        hash.update(name);
        hash.update(m.len().to_be_bytes());
        let mut reader = file;
        let mut buffer = [0; 8192];
        loop {
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
        }
    }
    let (records, tail) = verify_history(dir, "9999-99")?;
    check_anchor(dir, records, &tail)?;
    Ok(
        serde_json::json!({"records":records,"tail":hex(&tail),"files_digest":hex(&hash.finalize()),"scope":"local_history_not_rollback_proof"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(uid: u32) -> Event {
        Event::Unlocked { uid, did: "did:wba:example.com:user:alice:e1_abc".into() }
    }

    fn dir() -> super::tests::TempDir {
        TempDir::new()
    }

    #[test]
    fn a_signed_record_carries_the_base_digest_and_not_the_base() {
        let d = dir();
        let mut log = AuditLog::open(d.path()).unwrap();
        log.append(&Event::Signed {
            uid: 501,
            did: "did:wba:example.com:u:a:e1_x".into(),
            kid: "did:wba:example.com:u:a:e1_x#key-1".into(),
            covered: vec!["@method".into(), "@target-uri".into()],
            signature_base_digest: digest_hex(b"@method: POST\n"),
        })
        .unwrap();
        drop(log);

        let text = fs::read_to_string(d.path().join(format!("{}.jsonl", current_month()))).unwrap();
        assert!(text.contains("SIGNED"));
        assert!(text.contains("signature_base_digest"));

        // 这条是模块头的那个承诺：签名基里可能有 authorization/cookie，
        // **不能**出现在审计文件里。
        assert!(!text.contains("@method: POST"), "the base itself leaked into the log: {text}");
        assert!(!text.contains("authorization"));
    }

    #[test]
    fn records_link_to_the_record_before_them() {
        let d = dir();
        let mut log = AuditLog::open(d.path()).unwrap();
        log.append(&sample(501)).unwrap();
        log.append(&sample(502)).unwrap();
        log.append(&sample(503)).unwrap();
        assert_eq!(log.records(), 3);
        drop(log);

        // 干净的文件，重开时校验通过。
        let reopened = AuditLog::open(d.path()).unwrap();
        assert_eq!(reopened.records(), 3);
    }

    /// 改一行 —— 中间那条被改过，链在第 3 行断掉（因为第 3 行记的是
    /// 改之前那条第 2 行的哈希）。
    #[test]
    fn editing_a_record_breaks_the_chain() {
        let d = dir();
        let mut log = AuditLog::open(d.path()).unwrap();
        log.append(&sample(501)).unwrap();
        log.append(&sample(502)).unwrap();
        log.append(&sample(503)).unwrap();
        drop(log);

        let path = d.path().join(format!("{}.jsonl", current_month()));
        let text = fs::read_to_string(&path).unwrap();
        let edited = text.replacen("\"uid\":502", "\"uid\":999", 1);
        assert_ne!(text, edited, "the fixture did not actually change anything");
        fs::write(&path, edited).unwrap();

        let err = AuditLog::open(d.path()).unwrap_err();
        assert!(err.to_string().contains("breaks at line"), "{err}");
    }

    /// 删掉中间一行 —— 和改一行是同一类事故。
    #[test]
    fn removing_a_record_breaks_the_chain() {
        let d = dir();
        let mut log = AuditLog::open(d.path()).unwrap();
        for uid in [501, 502, 503] {
            log.append(&sample(uid)).unwrap();
        }
        drop(log);

        let path = d.path().join(format!("{}.jsonl", current_month()));
        let text = fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = text.lines().enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, l)| l)
            .collect();
        fs::write(&path, format!("{}\n", kept.join("\n"))).unwrap();

        let err = AuditLog::open(d.path()).unwrap_err();
        assert!(err.to_string().contains("breaks at line"), "{err}");
    }

    /// **砍掉尾巴**：链自己仍然自洽 —— 光看 jsonl 是检不出来的。
    /// 能检出来是因为旁边那个锚。
    #[test]
    fn truncating_the_tail_is_caught_by_the_anchor_not_by_the_chain() {
        let d = dir();
        let mut log = AuditLog::open(d.path()).unwrap();
        for uid in [501, 502, 503] {
            log.append(&sample(uid)).unwrap();
        }
        drop(log);

        let path = d.path().join(format!("{}.jsonl", current_month()));
        let text = fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = text.lines().take(2).collect();
        let truncated = format!("{}\n", kept.join("\n"));
        fs::write(&path, &truncated).unwrap();

        // 先确认这个前提：被砍过的文件，链本身是自洽的。
        fs::remove_file(d.path().join(".anchor")).unwrap();
        let (records, _) = verify_chain_from(&path, (0, GENESIS)).unwrap();
        assert_eq!(records, 2, "the truncated chain still validates on its own");

        // 锚一放回去，事故就露出来了。
        fs::write(
            d.path().join(".anchor"),
            serde_json::to_vec(&Anchor { records: 3, tail: hex(&GENESIS) }).unwrap(),
        )
        .unwrap();
        let err = AuditLog::open(d.path()).unwrap_err();
        assert!(err.to_string().contains("truncated or rolled back"), "{err}");
    }

    #[test]
    fn deleting_the_anchor_of_a_non_empty_log_is_refused() {
        let d = dir();
        let mut log = AuditLog::open(d.path()).unwrap();
        log.append(&sample(501)).unwrap();
        drop(log);

        fs::remove_file(d.path().join(".anchor")).unwrap();
        let err = AuditLog::open(d.path()).unwrap_err();
        assert!(err.to_string().contains("no .anchor"), "{err}");
    }

    /// 全新的空目录是正常起点，不是"锚不见了"。
    #[test]
    fn a_fresh_directory_opens_cleanly() {
        let d = dir();
        let log = AuditLog::open(d.path()).unwrap();
        assert_eq!(log.records(), 0);
    }

    #[test]
    fn rewriting_the_tail_in_place_is_caught_by_the_tail_hash() {
        let d = dir();
        let mut log = AuditLog::open(d.path()).unwrap();
        log.append(&sample(501)).unwrap();
        drop(log);

        let path = d.path().join(format!("{}.jsonl", current_month()));
        let text = fs::read_to_string(&path).unwrap();
        // 改最后一条，并把 prev 也改成自洽的 —— 链本身能过，锚过不了。
        let edited = text.replace("\"uid\":501", "\"uid\":777");
        fs::write(&path, edited).unwrap();

        let err = AuditLog::open(d.path()).unwrap_err();
        assert!(
            err.to_string().contains("does not match the anchor")
                || err.to_string().contains("breaks at line"),
            "{err}"
        );
    }

    #[test]
    fn digest_hex_is_sha256_in_hex() {
        // 空串的 SHA-256 是个到处都能对上的常数。
        assert_eq!(
            digest_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn the_audit_file_is_not_world_readable() {
        let d = dir();
        let mut log = AuditLog::open(d.path()).unwrap();
        log.append(&sample(501)).unwrap();

        let path = d.path().join(format!("{}.jsonl", current_month()));
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "audit file is mode {mode:o}");
        let mode = fs::metadata(d.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "audit dir is mode {mode:o}");
    }

    /// 事件是给人看的，字段名别飘。
    #[test]
    fn every_event_has_a_stable_tag_and_its_own_fields() {
        let events = [
            Event::Denied { uid: Some(1), pid: Some(2), reason: "cross-uid".into() },
            Event::Unlocked { uid: 1, did: "d".into() },
            Event::Locked { uid: 1, did: None, dropped: 2 },
            Event::Signed {
                uid: 1,
                did: "d".into(),
                kid: "k".into(),
                covered: vec!["@method".into()],
                signature_base_digest: "ab".into(),
            },
            Event::RawSigned { uid: 1, did: "d".into(), payload_len: 3, payload_digest: "cd".into() },
            Event::ChallengeSigned {
                uid: 1,
                did: "d".into(),
                challenge_len: 3,
                challenge_digest: "cd".into(),
            },
            Event::DocumentRead { uid: 1, did: "d".into(), document_digest: "ef".into() },
            Event::Swept { dropped: 1 },
        ];

        let tags: Vec<String> = events
            .iter()
            .map(|e| {
                serde_json::to_value(e).unwrap()["event"].as_str().unwrap().to_string()
            })
            .collect();
        assert_eq!(
            tags,
            [
                "DENIED",
                "UNLOCKED",
                "LOCKED",
                "SIGNED",
                "RAW_SIGNED",
                "CHALLENGE_SIGNED",
                "DOCUMENT_READ",
                "SWEPT"
            ]
        );
    }

    // —— say-every-export tripwire(家用路由器那句"上次登录")————

    /// 从来没有导出过,就一个字都不说。
    ///
    /// **"没有"和"不知道"在这里必须是同一个答案。** 一个刚装好的机器每次
    /// 敲命令都先被告知"上次导出:无",那句提醒在三天之内就会变成人看不见的
    /// 背景噪音 —— 而它存在的全部意义是"出现的时候人要停下来看一眼"。
    #[test]
    fn a_machine_that_never_exported_says_nothing() {
        let d = TempDir::new();
        assert_eq!(last_export(d.path()), None);
        assert_eq!(export_tripwire(d.path()), None);
    }

    #[test]
    fn other_events_are_not_mistaken_for_an_export() {
        let d = TempDir::new();
        let mut log = AuditLog::open(d.path()).unwrap();
        log.append(&Event::Import {
            did: "did:wba:example.com:u:a:e1_x".into(),
            kid: "did:wba:example.com:u:a:e1_x#key-1".into(),
            source: "archive".into(),
            document_digest: digest_hex(b"doc"),
        })
        .unwrap();

        assert_eq!(export_tripwire(d.path()), None);
    }

    /// 导出了就一直说,而且说的是**最近那一次**。
    ///
    /// 扫的是整个目录而不是当月分片,所以几个月前的一次导出也留得下来 ——
    /// "这个月有没有导出过"正好是最没用的那个答案。
    #[test]
    fn the_tripwire_reports_the_most_recent_export() {
        let d = TempDir::new();
        let mut log = AuditLog::open(d.path()).unwrap();
        log.append(&Event::ExportSeed {
            did: "did:wba:example.com:u:a:e1_first".into(),
            form: "words".into(),
        })
        .unwrap();
        log.append(&Event::ExportSeed {
            did: "did:wba:example.com:u:a:e1_second".into(),
            form: "words+archive".into(),
        })
        .unwrap();

        let last = last_export(d.path()).expect("an export happened");
        assert_eq!(last.did, "did:wba:example.com:u:a:e1_second");
        assert_eq!(last.form, "words+archive");
        assert!(!last.at.is_empty(), "the record must carry a timestamp");

        let line = export_tripwire(d.path()).unwrap();
        assert!(line.contains(&last.did), "{line}");
        assert!(line.contains(&last.at), "{line}");
    }

    /// 这一行不是状态报告,是**最后一道提醒** —— 它得说清楚"不是你,就去
    /// 迁移",而不是只说"上次导出在某时"。
    #[test]
    fn the_tripwire_says_what_to_do_about_it() {
        let d = TempDir::new();
        let mut log = AuditLog::open(d.path()).unwrap();
        log.append(&Event::ExportSeed {
            did: "did:wba:example.com:u:a:e1_x".into(),
            form: "archive".into(),
        })
        .unwrap();

        let line = export_tripwire(d.path()).unwrap();
        assert!(line.contains("If that was not you"), "{line}");
        assert!(line.contains("compromised"), "{line}");
        assert!(line.contains("migrate"), "{line}");
    }

    /// 坏行不能让这一句消失。
    ///
    /// 它的调用点在**每一条需要终端的命令的开头**,所以它绝不能成为那条命令
    /// 失败的原因 —— 而"审计文件里有一行被写坏了"正是导出之后最可能的状态。
    #[test]
    fn a_corrupt_line_does_not_hide_a_real_export() {
        let d = TempDir::new();
        let mut log = AuditLog::open(d.path()).unwrap();
        log.append(&Event::ExportSeed {
            did: "did:wba:example.com:u:a:e1_real".into(),
            form: "words".into(),
        })
        .unwrap();

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(d.path().join(format!("{}.jsonl", current_month())))
            .unwrap();
        use std::io::Write;
        file.write_all(b"{ this is not json\n").unwrap();
        file.write_all(b"\n").unwrap();
        drop(file);

        let last = last_export(d.path()).expect("the real export is still readable");
        assert_eq!(last.did, "did:wba:example.com:u:a:e1_real");
    }

    // ————————————————————————————————————————————————————————————
    // 多个写者
    // ————————————————————————————————————————————————————————————
    //
    // 上面每一条测试都只有一个 `AuditLog`。真实部署里同时有两个：守护进程
    // 攥着一个到进程结束，而每一条 CLI 命令（`create`、`sign`、`unlock`……）
    // 自己再开一个。下面这两条把那个形状**做出来**——两个 `AuditLog` 对象、
    // 同一个目录、交替追加——而不是只在注释里说一句"外部已经串好了"。

    /// **两个写者交替追加，链不断，重开也不报篡改。**
    ///
    /// 这是这个模块最要紧的一条：`prev` 接错的后果不是一个乱掉的日志，
    /// 而是**下一次打开时报一次并不存在的篡改**——而链断正是我们用来发现
    /// 真事故的信号。一个合法的并发操作必须不能把它弄响。
    ///
    /// 断言分三层，少一层这条测试就不成立：
    /// ① 两边的 `seq` 拼起来正好是 1..=6，没有重号；
    /// ② 重开时链验得过（`AuditLog::open` 不报错）；
    /// ③ 而且锚也对得上——只验链不验锚的话，"两边的计数各算各的"这种错
    ///    照样能溜过去。
    #[test]
    fn two_writers_interleaved_do_not_break_the_chain() {
        let d = dir();

        let mut keyd = AuditLog::open(d.path()).unwrap();
        let mut cli = AuditLog::open(d.path()).unwrap();

        // 交替，而不是"一边写完另一边再写"——那样两个写者永远看不见对方
        // 写过的东西，测不到 resync 那条路。
        keyd.append(&sample(501)).unwrap();
        cli.append(&sample(502)).unwrap();
        keyd.append(&sample(503)).unwrap();
        cli.append(&sample(504)).unwrap();
        keyd.append(&sample(505)).unwrap();
        cli.append(&sample(506)).unwrap();

        drop(keyd);
        drop(cli);

        let path = d.path().join(format!("{}.jsonl", current_month()));
        let text = fs::read_to_string(&path).unwrap();

        let seqs: Vec<u64> = text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
                parsed["seq"].as_u64().expect("every record carries a seq")
            })
            .collect();
        assert_eq!(
            seqs,
            [1, 2, 3, 4, 5, 6],
            "the two writers must hand the sequence number back and forth, with no repeats: \
             {text}"
        );

        // ② 链自洽，③ 锚也对得上 —— 两个都在 `open` 里。
        let reopened = AuditLog::open(d.path()).unwrap();
        assert_eq!(reopened.records(), 6);
    }

    /// **一个写者手上的状态过期了，它会自己发现。**
    ///
    /// 这条盯的是 `resync`：`stale` 是在文件里已经有 2 条的时候开的，所以它
    /// 内存里那份 `records`/`tail` 停在 2；随后 `early` 又写了第 3 条。它必须
    /// **在写之前**发现文件长长了，而不是拿那份过期的 `tail` 去写第 3 条。
    ///
    /// 把 `resync` 拿掉，这条会以"第 4 行链断"的形式红掉——也就是那个假篡改
    /// 警报本身。
    #[test]
    fn a_stale_writer_reloads_before_it_appends() {
        let d = dir();
        let mut early = AuditLog::open(d.path()).unwrap();
        early.append(&sample(501)).unwrap();
        early.append(&sample(502)).unwrap();

        // 它开的时候看到的是 2 条；这个数一会儿就不对了。
        let mut stale = AuditLog::open(d.path()).unwrap();
        assert_eq!(stale.records(), 2, "opening after two writes sees two records");

        early.append(&sample(503)).unwrap();

        // `stale` 手里还是 2。它现在写的必须是第 4 条。
        stale.append(&sample(504)).unwrap();
        drop(early);
        drop(stale);

        let path = d.path().join(format!("{}.jsonl", current_month()));
        let text = fs::read_to_string(&path).unwrap();
        let seqs: Vec<u64> = text
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["seq"].as_u64().unwrap())
            .collect();
        assert_eq!(seqs, [1, 2, 3, 4], "{text}");
        AuditLog::open(d.path()).unwrap();
    }

    /// **文件在别的进程手里被截短，追加拒绝，而不是接着往上写。**
    ///
    /// 悄悄接受截断等于把一次真事故盖成"看起来一直是这样"——那正是 `.anchor`
    /// 存在的理由。这条守的是 `resync` 里那个 `on_disk < self.written` 分支。
    #[test]
    fn a_shrunk_file_is_refused_instead_of_written_over() {
        let d = dir();
        let mut log = AuditLog::open(d.path()).unwrap();
        for uid in [501, 502, 503] {
            log.append(&sample(uid)).unwrap();
        }

        let path = d.path().join(format!("{}.jsonl", current_month()));
        let text = fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = text.lines().take(2).collect();
        fs::write(&path, format!("{}\n", kept.join("\n"))).unwrap();

        let err = log.append(&sample(504)).unwrap_err();
        assert!(err.to_string().contains("shrank"), "{err}");
        assert!(
            err.to_string().contains("truncation"),
            "the refusal must say what it is: {err}"
        );
    }

    /// 锁文件存在、权限是私有的，而且**不在** `.jsonl` 上。
    ///
    /// 锁错文件的症状是"平时都对，换月那一瞬间不是"——那种 bug 靠代码审查
    /// 抓不住，靠这条断言和 [`LOCK_FILE`] 那个常量抓得住。
    #[test]
    fn the_lock_lives_beside_the_month_files_not_on_one_of_them() {
        let d = dir();
        let log = AuditLog::open(d.path()).unwrap();
        drop(log);

        let lock = d.path().join(LOCK_FILE);
        assert!(lock.exists(), "opening the log must create the lock file");
        assert!(
            !LOCK_FILE.ends_with(".jsonl"),
            "the lock must not be one of the files that rotate"
        );
        let mode = fs::metadata(&lock).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, crate::keystore::layout::SECRET_FILE_MODE, "{mode:o}");
    }

    // ————————————————————————————————————————————————————————————
    // 换月
    // ————————————————————————————————————————————————————————————

    /// 造出一段**跨好几份月份文件**的历史，链是连续的，锚也一起落好。
    ///
    /// 参数是（月份，条数），按时间排。返回每个月**写完之后**的状态 ——
    /// （末条 `seq`，末行哈希）。0 条的月份不落文件：链只在写的时候延续，
    /// 那个月本来就没有文件。
    ///
    /// 这**就是**真跑几个月之后的磁盘样子，不用等几个月：链跨文件延续，所以
    /// 非首月文件的第一行 `prev` 指的不是 `GENESIS`。
    fn write_history(d: &TempDir, months: &[(&str, u64)]) -> Vec<(u64, [u8; 32])> {
        let mut state = (0u64, GENESIS);
        let mut states = Vec::new();

        for (month, count) in months {
            let mut text = String::new();
            for _ in 0..*count {
                let line = format!(
                    r#"{{"seq":{},"at":"{month}-01T00:00:00Z","prev":"{}","event":"UNLOCKED","uid":{},"did":"d"}}"#,
                    state.0 + 1,
                    hex(&state.1),
                    500 + state.0
                );
                state = (state.0 + 1, sha256(line.as_bytes()));
                text.push_str(&line);
                text.push('\n');
            }
            if !text.is_empty() {
                fs::write(d.path().join(format!("{month}.jsonl")), text).unwrap();
            }
            states.push(state);
        }

        fs::write(
            d.path().join(".anchor"),
            serde_json::to_vec(&Anchor { records: state.0, tail: hex(&state.1) }).unwrap(),
        )
        .unwrap();

        states
    }

    /// 造出"上个月写了 `before` 条，这个月又写了 `this_month` 条"之后的磁盘状态。
    ///
    /// 返回（上个月文件的末条 `seq`，它的哈希）。
    fn roll_over(d: &TempDir, before: u64, this_month: u64) -> (u64, [u8; 32]) {
        let month = current_month();
        write_history(d, &[("2001-01", before), (month.as_str(), this_month)])[0]
    }

    /// **`history_files` 收的是到 `upto` 为止的全部月份文件，按时间排。**
    #[test]
    fn the_history_files_are_every_month_up_to_now() {
        let d = dir();
        for name in ["2001-06.jsonl", "1999-01.jsonl", "2001-09.jsonl", "2001-01.jsonl"] {
            fs::write(d.path().join(name), b"").unwrap();
        }
        // 不是月份文件的不算 —— 同一个目录里躺着 `.anchor` 和 `.lock`。
        fs::write(d.path().join("notes.txt"), b"x").unwrap();
        fs::write(d.path().join(".anchor"), b"x").unwrap();

        let files = history_files(d.path(), "2001-10").unwrap();
        let names: Vec<&str> = files
            .iter()
            .map(|path| path.file_name().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(names, ["1999-01.jsonl", "2001-01.jsonl", "2001-06.jsonl", "2001-09.jsonl"]);

        // 比它大的一个都不算：那是时钟跳到未来留下的东西，接进链里只会让
        // "哪一头是新的"变得可疑。
        assert!(history_files(d.path(), "1998-12").unwrap().is_empty());
    }

    /// **跨过一次月边界，`open()` 照样通过，链接着走。**
    ///
    /// 这一条守的是 `verify_chain_from` 的起点和"返回 `seq` 而不是行数"两件事。
    /// 把它换回"从 `GENESIS` 验 + 数行数"，`open()` 就会把一次正常的换月报成
    /// **第 1 行断链** —— 一次假篡改警报，而这个文件存在的理由正是让这个信号
    /// 只意味着真事故。
    #[test]
    fn a_month_rollover_does_not_look_like_tampering() {
        let d = dir();
        roll_over(&d, 2, 0);

        // 本月一条都还没有：状态该接着上个月，而不是回到 GENESIS。
        let mut log = AuditLog::open(d.path()).unwrap();
        assert_eq!(log.records(), 2, "the count must carry across the month boundary");

        // 写下去的这一条必须是第 3 条，而且 `prev` 指向上个月的末行。
        log.append(&sample(701)).unwrap();
        drop(log);

        let text = fs::read_to_string(d.path().join(format!("{}.jsonl", current_month()))).unwrap();
        let record: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(record["seq"], 3, "{text}");
        assert_ne!(
            record["prev"], hex(&GENESIS),
            "the first record of a new month must link to the previous month, not to GENESIS"
        );

        // 再开一次：链跨文件接得上，锚也对得上。
        assert_eq!(AuditLog::open(d.path()).unwrap().records(), 3);
    }

    /// 本月已经有记录了，`open()` 接着上个月往下验。
    #[test]
    fn a_month_that_already_has_records_verifies_against_the_one_before() {
        let d = dir();
        let (last_seq, _) = roll_over(&d, 2, 2);

        let log = AuditLog::open(d.path()).unwrap();
        assert_eq!(log.records(), last_seq + 2, "the two months add up");
    }

    /// **上个月的文件被改过，本月 `open()` 不认。**
    ///
    /// 承接上一个月的那个哈希就是证据：上个月末行一改，本月第一行那个
    /// `prev` 立刻对不上。要是起点写死成 `GENESIS`，这一条根本无从谈起——
    /// 那时它会以"第 1 行断链"的形式永远成立，也就什么都说明不了。
    #[test]
    fn a_rewritten_previous_month_breaks_the_link_into_this_one() {
        let d = dir();
        roll_over(&d, 2, 2);

        let previous = d.path().join("2001-01.jsonl");
        let text = fs::read_to_string(&previous).unwrap();
        let edited = text.replacen("\"uid\":501", "\"uid\":999", 1);
        assert_ne!(text, edited, "the fixture did not actually change anything");
        fs::write(&previous, edited).unwrap();

        let err = AuditLog::open(d.path()).unwrap_err();
        assert!(err.to_string().contains("breaks at line 1"), "{err}");
    }

    /// **改掉一个**更早**的月份 —— 这一刀以前是看不见的。**
    ///
    /// 三个月份文件，改的是**最早**那份里的**第一行**：同一份文件里的第二行
    /// 立刻会对不上。以前 `open()` 只从上个月末行起验本月那份文件，那个文件
    /// 从头到尾没人看。
    ///
    /// 报错要说清是**哪一份文件**的第几行 —— "第 2 行"在一份跨月的日志里
    /// 什么都不说明。
    #[test]
    fn editing_a_record_in_an_old_month_is_caught() {
        let d = dir();
        write_history(&d, &[("2001-01", 2), ("2001-02", 2), ("2001-03", 2)]);
        // 前提：这份历史本身是干净的（不然下面红的原因可能是别的）。
        assert_eq!(AuditLog::open(d.path()).unwrap().records(), 6);

        let old = d.path().join("2001-01.jsonl");
        let text = fs::read_to_string(&old).unwrap();
        let edited = text.replacen("\"uid\":500", "\"uid\":999", 1);
        assert_ne!(text, edited, "the fixture did not actually change anything");
        fs::write(&old, edited).unwrap();

        let err = AuditLog::open(d.path()).unwrap_err().to_string();
        assert!(err.contains("breaks at line 2 of 2001-01.jsonl"), "{err}");
    }

    /// **整份旧月份文件被删掉，也检得出来。**
    ///
    /// 两条路各管一种：删的是**中间**那份，后面那份的第一行接不上它；删的是
    /// **最早**那份，剩下的第一行接不回链的头。
    #[test]
    fn deleting_a_whole_old_month_is_caught() {
        let history: [(&str, u64); 3] = [("2001-01", 2), ("2001-02", 2), ("2001-03", 2)];
        let d = dir();
        write_history(&d, &history);
        assert_eq!(AuditLog::open(d.path()).unwrap().records(), 6);

        // 中间那份：断在它后面那份的第一行。
        fs::remove_file(d.path().join("2001-02.jsonl")).unwrap();
        let err = AuditLog::open(d.path()).unwrap_err().to_string();
        assert!(err.contains("breaks at line 1 of 2001-03.jsonl"), "{err}");

        // 最早那份：链的头整个没了 —— 剩下的第一行接的是一条谁都看不见的记录。
        write_history(&d, &history);
        fs::remove_file(d.path().join("2001-01.jsonl")).unwrap();
        let err = AuditLog::open(d.path()).unwrap_err().to_string();
        assert!(err.contains("breaks at line 1 of 2001-02.jsonl"), "{err}");
        assert!(
            err.contains("an earlier month's file is missing"),
            "the message must offer the reason that fits, not just 'the chain broke': {err}"
        );
    }

    /// **打开之后接着写，写下去的那条接的是整段历史的末尾。**
    ///
    /// 守的是 [`verify_history`] 的返回值：它给的是**走得最远的那个状态**，
    /// 不是第一份文件的、也不是"本月还算空所以就从头开始"。
    #[test]
    fn opening_a_multi_month_history_continues_from_its_end() {
        let d = dir();
        write_history(&d, &[("2001-01", 2), ("2001-02", 3)]);

        let mut log = AuditLog::open(d.path()).unwrap();
        assert_eq!(log.records(), 5, "the two months add up");
        log.append(&sample(701)).unwrap();
        drop(log);

        let text = fs::read_to_string(d.path().join(format!("{}.jsonl", current_month()))).unwrap();
        let record: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(record["seq"], 6, "{text}");
        assert_ne!(record["prev"], hex(&GENESIS), "it must continue the chain, not restart it");
        assert_eq!(AuditLog::open(d.path()).unwrap().records(), 6);
    }

    /// 记录里的 `seq` 也是被验的一环：凭空插一条编号不对的会被拦下。
    #[test]
    fn a_record_with_the_wrong_number_is_refused() {
        let d = dir();
        let mut log = AuditLog::open(d.path()).unwrap();
        log.append(&sample(501)).unwrap();
        log.append(&sample(502)).unwrap();
        drop(log);

        let path = d.path().join(format!("{}.jsonl", current_month()));
        let text = fs::read_to_string(&path).unwrap();
        let edited = text.replacen("\"seq\":2", "\"seq\":7", 1);
        assert_ne!(text, edited, "the fixture did not actually change anything");
        fs::write(&path, edited).unwrap();

        let err = AuditLog::open(d.path()).unwrap_err();
        assert!(err.to_string().contains("is record 7"), "{err}");
    }

    mod tempdir {
        use std::os::unix::fs::PermissionsExt;
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);

        pub struct TempDir {
            path: PathBuf,
        }

        impl TempDir {
            pub fn new() -> Self {
                let n = COUNTER.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "anpio-key-audit-{}-{n}-{:?}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ));
                std::fs::create_dir_all(&path).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
                Self { path }
            }

            pub fn path(&self) -> &Path {
                &self.path
            }
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
    }

    use tempdir::TempDir;
}
