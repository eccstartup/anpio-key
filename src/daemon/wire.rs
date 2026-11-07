//! socket 帧协议。
//!
//! 形状抄 ssh-agent:**长度前缀 + 类型字节**。
//!
//! ```text
//! frame   := u32_be(len) || payload
//! payload := u8(msg_type) || body
//! ```
//!
//! 类型编号自己定,**刻意不复用 SSH 的类型码** —— 复用了的话,一个走错门
//! 的 ssh 客户端会连上来然后收到莫名其妙的应答。
//!
//! 这个模块只做编解码,不碰密码学,也不碰 socket 生命周期。所以它可以
//! 在一对内存缓冲上完整地测 —— 协议这种东西出错的代价是"两个实现各说各话",
//! 而那种 bug 只有在联调时才发现,太晚了。

use std::collections::BTreeMap;
use std::io::{self, Read, Write};

use zeroize::Zeroizing;

use crate::error::{KeydError, Result};
use crate::keystore::record::KeyAlgorithm;

/// 一帧最多这么大。
///
/// 长度前缀是**对端给的**,而我们会照着它去分配内存 —— 不设上限的话,
/// 一句 `len = 0xFFFF_FFFF` 就能让守护进程当场去要 4GB。8 MiB 够放下
/// 请求体、消息头和一份 DID 文档,离"能拿来打人"还很远。
pub const MAX_FRAME: usize = 8 * 1024 * 1024;

/// 请求体上限。比整帧小,好让头字段一定有地方放。
pub const MAX_BODY: usize = 4 * 1024 * 1024;

/// Challenge resource limit only. A DID proof signing input is 64 bytes,
/// so this cap provides no purpose isolation. Development mode only.
pub const MAX_CHALLENGE_LEN: usize = 256;

// —— 消息类型 ——

pub const LIST_KEYS: u8 = 0x01;
pub const SIGN: u8 = 0x02;
pub const UNLOCK: u8 = 0x03;
pub const LOCK: u8 = 0x04;
pub const STATUS: u8 = 0x05;
pub const GET_DOCUMENT: u8 = 0x06;
pub const OK: u8 = 0x80;
pub const ERR: u8 = 0x81;

/// **这个守护进程接受的请求类型,到此为止。**
///
/// 值得单独列出来,是因为这张表里**没有**导出,而且不该有。导出不是"被拒绝
/// 的请求",是**根本不存在的一个类型** —— 它只在一个进程自己的 `/dev/tty` 上
/// 发生,由坐在终端前的人操作(见 `ops::export` 开头那一节)。
///
/// 没有 socket 导出消息，但这不阻止同 UID 进程调用本地维护命令。
/// `/dev/tty` 不是人类身份凭证，受保护管理域仍需单独实现。
///
/// 所以:加一个类型到这张表里,等于改变整个授权模型。它必须是一次看得见的
/// 决定,而不是顺手写下的下一个编号。
///
/// **这个决定真做过一次,[`GET_DOCUMENT`] 是那一次,而它一次授权都没有改。**
/// 加它是因为适配层要让客户端内联一份 DID 文档(`docs/ADAPTER.md` §3.2):
/// 它只读、不进覆盖面、不碰私钥、不产生签名。开放的是**一次读**,不是一次
/// **授权** —— 读得到的东西本来就躺在 `dids/` 里的 0644 文件里,而那是这台
/// 机器**自己发布过**的那些 DID,别人的一个都够不到。
///
/// 上面那句话("加一个类型等于改变整个授权模型")因此并没有被推翻:它说的是
/// **会签名的**类型,而这一条不签。真正要守住的那条线还是"不许出现一个能把
/// 密钥材料交出去的类型" —— 下一个往这里加类型的人,读的还是这一段。
pub const REQUEST_TYPES: [u8; 6] = [LIST_KEYS, SIGN, UNLOCK, LOCK, STATUS, GET_DOCUMENT];

/// 错误码。
///
/// **这个表比 [`KeydError`] 粗,是故意的。** 对端能看见的只有"哪一类错",
/// 看不见"哪个细节对不上" —— 尤其是口令:错口令和错 device.secret 在密码学上
/// 本来就分不出来,协议层也就不该假装能分。分得越细,越是给爆破的人送信息。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorCode {
    /// 口令错,或者 device.secret 内容不对 —— **两者合并成一个码**。
    BadCredential = 0x0001,
    /// 信封的身份和它自称的不符(头部被改过)。
    AadMismatch = 0x0002,
    KeyNotFound = 0x0003,
    KeyExists = 0x0004,
    Locked = 0x0005,
    Permission = 0x0006,
    RawDisabled = 0x0007,
    /// 覆盖面被拒 —— 调用方要求的东西守护进程不签。
    CoveredSetRejected = 0x0008,
    /// 帧本身不合法(长度、类型、字段编码)。
    Protocol = 0x0009,
    Did = 0x000A,
    /// 这把钥匙绑了一根**这台机器上没有的**硬件根(SE 密钥被删了、信封是从
    /// 别的机器拷来的、或者这个构建里没有那个后端)。
    ///
    /// 为什么不为它复用一个已有的码:`BadCredential` 是**谎话**(口令没错),
    /// `Internal` 按它自己的约定要求消息对调用方无信息量(而这一条的全部价值
    /// 就在那句话里)。加一个码是**加**,不是改:老客户端收到认不出来的码会
    /// 报 "0x… is not an error code this client knows",而它同时拿得到
    /// `message` —— 那是安全的降级,不是静默的错误答案。
    HardwareUnavailable = 0x000B,
    /// `SIGN(Challenge)` 这条路开着没有。
    ///
    /// 为什么不复用 `RawDisabled`:两者是**不同的门**。`raw` 严格比 `challenge`
    /// 宽(打开 raw 也就打开了 challenge,反过来不成立),所以"raw 关着、challenge
    /// 开着"是一个合法状态;共用一个码,一个只开了窄门却被要求签文档的调用方会
    /// 收到"raw signing disabled",而那句话对它此刻的处境是错的。
    ///
    /// 加一个码是**加**,不是改:老客户端收到认不出来的码会报 "0x… is not an
    /// error code this client knows",同时拿得到 `message` —— 那是安全的降级。
    ChallengeDisabled = 0x000C,
    /// 按**名字**寻址的那条签名路开着没有。
    ///
    /// 又是一道单独的门:它和 `raw`、`challenge` 都不一样 —— 那两条签的是
    /// 调用方自己给的字节,这一条签的是守护进程按名字找出来的钥匙。默认关,
    /// 打开要一个专属开关,因为它让一条新路径第一次能把"钥匙"和"身份"分开。
    ///
    /// 加一个码是**加**,不是改:老客户端收到认不出来的码会报 "0x… is not an
    /// error code this client knows",同时拿得到 `message` —— 安全的降级。
    NamedSigningDisabled = 0x000D,
    /// 守护进程自己出了问题。**消息文本要对调用方无信息量。**
    Internal = 0x00FF,
}

impl std::fmt::Display for ErrorCode {
    /// 给坐在终端前面的人看的短名。
    ///
    /// 这些码**本来就是线上的字节**,客户端一定拿得到 —— 把它们印出来
    /// 不泄露任何协议没说过的信息,而不印出来就只剩一句"被拒绝了",
    /// 人分不清是没解锁、口令错、还是没权限。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ErrorCode::BadCredential => "bad credential",
            ErrorCode::AadMismatch => "aad mismatch",
            ErrorCode::KeyNotFound => "key not found",
            ErrorCode::KeyExists => "key exists",
            ErrorCode::Locked => "locked",
            ErrorCode::Permission => "permission",
            ErrorCode::RawDisabled => "raw signing disabled",
            ErrorCode::CoveredSetRejected => "covered set rejected",
            ErrorCode::Protocol => "protocol",
            ErrorCode::Did => "did",
            ErrorCode::HardwareUnavailable => "hardware root unavailable",
            ErrorCode::ChallengeDisabled => "challenge signing disabled",
            ErrorCode::NamedSigningDisabled => "named key signing disabled",
            ErrorCode::Internal => "internal",
        })
    }
}

impl ErrorCode {
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    pub fn from_u16(raw: u16) -> Option<Self> {
        use ErrorCode::*;
        Some(match raw {
            0x0001 => BadCredential,
            0x0002 => AadMismatch,
            0x0003 => KeyNotFound,
            0x0004 => KeyExists,
            0x0005 => Locked,
            0x0006 => Permission,
            0x0007 => RawDisabled,
            0x0008 => CoveredSetRejected,
            0x0009 => Protocol,
            0x000A => Did,
            0x000B => HardwareUnavailable,
            0x000C => ChallengeDisabled,
            0x000D => NamedSigningDisabled,
            0x00FF => Internal,
            _ => return None,
        })
    }
}

impl KeydError {
    /// 内部错误 → 对端能看见的错误码。
    pub fn wire_code(&self) -> ErrorCode {
        use KeydError::*;
        match self {
            BadPassphrase | BadDeviceSecret => ErrorCode::BadCredential,
            AadMismatch => ErrorCode::AadMismatch,
            KeyNotFound(_) => ErrorCode::KeyNotFound,
            KeyExists(_) => ErrorCode::KeyExists,
            Locked => ErrorCode::Locked,
            PeerCredentialUnavailable(_) | Permission(_) => ErrorCode::Permission,
            RawDisabled => ErrorCode::RawDisabled,
            ChallengeDisabled => ErrorCode::ChallengeDisabled,
            NamedSigningDisabled => ErrorCode::NamedSigningDisabled,
            CoveredSetRejected(_) => ErrorCode::CoveredSetRejected,
            Protocol(_) => ErrorCode::Protocol,
            Did(_) => ErrorCode::Did,
            // 硬件根的消息**要**原样过去 —— 那一句话就是这条错误码存在的理由。
            HardwareMissing(_) | HardwareUnavailable(_) => ErrorCode::HardwareUnavailable,
            // `Misuse` 到不了线上:它只由 `serve` / `stop` 这些本地命令产生。
            // 真要到了,那就是我们自己的 bug,所以是 `Internal`。
            Crypto(_) | Upstream(_) | Io(_) | Json(_) | Misuse(_) => ErrorCode::Internal,
            // 客户端把收到的粗码原样带回来。环是这样闭合的:服务端
            // `BadPassphrase → BadCredential`,客户端 `BadCredential →
            // Refused{code}`,再发出去还是 `BadCredential`。
            Refused { code, .. } => *code,
        }
    }

    /// 内部错误 → 对端能看见的错误消息。
    ///
    /// **这个方法存在的唯一理由是 [`KeydError::BadPassphrase`] 和
    /// [`KeydError::BadDeviceSecret`] 的 `Display` 不一样。** 直接
    /// `err.to_string()` 发出去,就等于在线上告诉对面"口令错了"还是
    /// "device.secret 错了" —— 而这两件事在密码学上本来就分不出来,
    /// 区分它们只是白白给爆破的人省一半力。所以这一对压成同一句话。
    pub fn wire_message(&self) -> String {
        match self {
            KeydError::BadPassphrase | KeydError::BadDeviceSecret => {
                "the credential was refused".to_string()
            }
            // `Refused` 已经是协议层的话,不再套一层 —— 否则消息会随着
            // 每一次转发越长,而最里面那一句才是真正有用的那一句。
            KeydError::Refused { message, .. } => message.clone(),
            other => other.to_string(),
        }
    }
}

// —— 请求 / 应答 ——

/// `SIGN` 的请求体。
///
/// 主路径提供结构化字段，由 daemon 重建签名基。
/// Raw 与 Challenge 均签调用方原字节，仅供显式开发兼容。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignRequest {
    /// 主路径。守护进程从这里重建签名基,并自己决定覆盖面下限。
    Structured {
        did: String,
        /// 要用的那个 fragment(`key-2`、`recovery-1`……)。不给 = `did` 名下
        /// 的默认那把(绑定密钥)。见 [`crate::keystore::store::resolve`]。
        kid: Option<String>,
        method: String,
        target_uri: String,
        headers: BTreeMap<String, String>,
        /// **请求体本身**,不是它的摘要。
        ///
        /// 计划草案这里写的是 `body_digest`,但那样守护进程就会去签一个
        /// **调用方给的**摘要值 —— 而"签名绑定到守护进程自己算出来的
        /// content-digest"正是防盲目签名的关键一环。摘要由我们算,
        /// 所以要拿到 body。
        ///
        /// 拿不动整份 body 的场景(大文件上传),那正是 `Raw` 存在的意义:
        /// 显式打开、逐条审计,而不是把结构化路径悄悄降级。
        body: Option<Vec<u8>>,
        /// 调用方**额外**要求覆盖的分量。只能加,不能减 —— 见
        /// [`crate::sign::rfc9421::SignRequest::covered`]。
        covered: Vec<String>,
        /// 调用方指定的 nonce。不给/给空 = 由守护进程随机生成一个(`anp`
        /// 上游在 `None` 时的行为)。
        ///
        /// **它是不透明的。** 守护进程只查长度和"能不能写进签名基",不判断
        /// 它是不是一个"合法"的 nonce —— 那是服务端的事。为什么它必须由
        /// 调用方传、而不是守护进程自己挑,见 `docs/ADAPTER.md` §3.1。
        ///
        /// 空串按"没给"处理,和这个协议里其它可选字符串(`LOCK` 的 `did`、
        /// 这里的 `kid`)是同一个约定。
        nonce: Option<String>,
        /// 按**名字**寻址的那把钥匙(`k-7f3a2c91`、`team/bot`)。给了它,
        /// `did` 就不再用来找信封 —— 名字是这台机器上唯一的地址。
        ///
        /// 和不命名的钥匙同一条规矩:名下的那份信封必须**已经解锁**。
        /// 名字这种寻址是新加的一条路,所以它默认关(`--allow-named-key-signing`),
        /// 且每签一次都要留一条独立审计。
        key: String,
        /// 这把钥匙名义上的完整 keyid(`did:wba:…#key-1`)。DID 是调用方的,
        /// 守护进程只核对其中 `e1_` 那一段与信封的指纹一致。
        ///
        /// **尾随字段。** 老客户端不发这两个字段,解码端见到 nonce 之后
        /// 就结束 —— 所以新守护进程照旧认识老请求;新客户端多发的那两段
        /// 老守护进程读不懂(它会在 nonce 之后 `expect_end` 时拒掉),
        /// 那是"发不出去",不是"发出去一个被悄悄改了意思的请求"。
        keyid: String,
    },
    /// 受限路径:原始字节。默认关,`--allow-raw-signing` 才开,且必留审计。
    Raw { did: String, kid: Option<String>, payload: Vec<u8> },
    /// 受限路径:调用方给的、有长度上限的挑战字节。默认关,
    /// `--allow-challenge-signing` 才开,且必留审计。
    ///
    /// 和 [`SignRequest::Raw`] 的差别不在"签不签调用方给的字节" —— 两条都签
    /// —— 也不在"这串字节有没有形状"(它没有,和 `Raw` 一样)。差别在**这条路
    /// 签得了的东西有上界**:[`MAX_CHALLENGE_LEN`] 卡在任何一份 DID 文档之下,
    /// 所以它答得了"证明你此刻握着这把钥匙",答不了"把我这份文档签了"。这是
    /// `docs/ADAPTER.md` §3.3 那个岔口挑定的那条窄路 —— 也是它和 `Raw` 之间
    /// 全部的、以及仅有的距离。
    ///
    /// **这里没有字符集过滤,是有意的。** `nonce` 会被拼进文本签名基,所以
    /// `validate_nonce` 要剥掉 `"` 和 `\`(它在那里能改结构);而这些字节
    /// **就是要被签的内容本身,中间没有任何拼接**,没有可以注入的地方 ——
    /// 加一条字符集限制只会让人以为边界画在字符集上,而它其实画在长度上。
    Challenge { did: String, kid: Option<String>, challenge: Vec<u8> },
}

/// 一把钥匙在磁盘上的样子 —— `LIST_KEYS` 的应答项。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySummary {
    pub did: String,
    pub kid: String,
    pub algorithm: KeyAlgorithm,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unlock { did, kid, .. } => f.debug_struct("Unlock")
                .field("did", did).field("kid", kid).field("passphrase", &"[REDACTED]").finish(),
            Self::Sign(sign) => f.debug_tuple("Sign").field(sign).finish(),
            Self::ListKeys => f.write_str("ListKeys"),
            Self::Status => f.write_str("Status"),
            Self::Lock { did, kid, .. } => f.debug_struct("Lock").field("did", did).field("kid", kid).finish(),
            Self::GetDocument { did } => f.debug_struct("GetDocument").field("did", did).finish(),
        }
    }
}

/// 一条连接上收到的请求。
#[derive(Clone, PartialEq, Eq)]
pub enum Request {
    ListKeys,
    Sign(SignRequest),
    /// 解锁一把钥匙。`passphrase` 是**明文**,只在内存里活到用完为止。
    ///
    /// `key` 非空 = 按名字解锁(`k-7f3a2c91`、`team/bot`)。这是尾随字段:
    /// 普通解锁不写它,老守护进程照旧认得。
    Unlock { did: String, kid: Option<String>, key: String, passphrase: Zeroizing<String> },
    /// 锁上。**两级**:`did` 为空表示全锁;只给 `did` 表示把这个 DID 底下
    /// 解锁着的全放掉;再给 `kid` 就是精确到一把。
    ///
    /// `key` 非空 = 只锁这一把按名字寻址的钥匙。
    Lock { did: Option<String>, kid: Option<String>, key: String },
    Status,
    /// 读一份**本机发布过的** DID 文档。只读,不签任何东西。
    ///
    /// `did` 是那台机器上 `publish` 过的某个 DID —— 这台机器没有发布过的
    /// DID 一律答 `KeyNotFound`(它不能联网去取,见 `docs/ADAPTER.md` §3.2)。
    GetDocument { did: String },
}

/// 一条应答。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Ok,
    ListKeys(Vec<KeySummary>),
    /// `u16 sig_len ‖ sig`。Ed25519 的签名是 64 字节。
    Signature(Vec<u8>),
    Status(Vec<UnlockedKey>),
    /// 一份 DID 文档的**原始字节** —— 就是 `publish` 写下去的那一份。
    ///
    /// 不是解析出来再序列化回去:那份文档是一件**签好名的成品**,它的字节
    /// 排布本身就是被签的那一份(proof 走 JCS,规范化之后的字节就是它)。
    /// 交到调用方手里必须是原文,否则"内联一份和已发布的一模一样的文档"
    /// 这句话就不成立了(`docs/ADAPTER.md` §3.2)。
    Document(Vec<u8>),
    Error { code: ErrorCode, message: String },
}

/// `STATUS` 里的一把已解锁钥匙。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockedKey {
    pub did: String,
    pub kid: String,
    /// 从解锁到现在过了多少秒。
    pub unlocked_secs: u64,
}

impl Response {
    /// **把内部错误翻译成对端能看见的东西的唯一入口。**
    ///
    /// 请求处理里不要手写 `Response::Error { code, message }`,走这里 ——
    /// 免得某一条分支顺手 `err.to_string()` 出去,把口令类错误的细节漏了。
    pub fn from_error(error: &KeydError) -> Self {
        Response::Error { code: error.wire_code(), message: error.wire_message() }
    }
}

// ————————————————————————————————————————————————————————————————————————
// 编解码
// ————————————————————————————————————————————————————————————————————————

/// 读一帧。返回 `Ok(None)` 表示对端在帧边界上干净地关了连接。
pub fn read_request<R: Read>(reader: &mut R) -> Result<Option<Request>> {
    let Some(payload) = read_frame(reader)? else {
        return Ok(None);
    };
    decode_request(&payload).map(Some)
}

/// 读一帧。返回 `Ok(None)` 表示对端在帧边界上干净地关了连接。
pub fn read_response<R: Read>(reader: &mut R) -> Result<Option<Response>> {
    let Some(payload) = read_frame(reader)? else {
        return Ok(None);
    };
    decode_response(&payload).map(Some)
}

/// 写一条应答。**写完 `flush`**,否则调用方会一直等一个躺在缓冲区里的字节。
pub fn write_response<W: Write>(writer: &mut W, response: &Response) -> Result<()> {
    let payload = encode_response(response)?;
    write_frame(writer, &payload)?;
    writer.flush()?;
    Ok(())
}

pub fn write_request<W: Write>(writer: &mut W, request: &Request) -> Result<()> {
    let payload = Zeroizing::new(encode_request(request)?);
    write_frame(writer, &payload)?;
    writer.flush()?;
    Ok(())
}

fn read_frame<R: Read>(reader: &mut R) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let mut header = [0u8; 4];
    match reader.read_exact(&mut header) {
        Ok(()) => {}
        // 干净地关在帧边界上。
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(KeydError::Io(e)),
    }

    let len = u32::from_be_bytes(header) as usize;
    if len == 0 {
        return Err(KeydError::Protocol(
            "a zero-length frame carries no message type".into(),
        ));
    }
    if len > MAX_FRAME {
        return Err(KeydError::Protocol(format!(
            "frame of {len} bytes exceeds the {MAX_FRAME}-byte limit"
        )));
    }

    let mut payload = Zeroizing::new(vec![0u8; len]);
    reader.read_exact(&mut payload).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            // 说了 len 字节却只给了一半就断 —— 这不是干净关闭。
            KeydError::Protocol(format!("connection ended inside a {len}-byte frame"))
        } else {
            KeydError::Io(e)
        }
    })?;
    Ok(Some(payload))
}

fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> Result<()> {
    if payload.is_empty() {
        return Err(KeydError::Protocol("refusing to write an empty frame".into()));
    }
    if payload.len() > MAX_FRAME {
        return Err(KeydError::Protocol(format!(
            "frame of {} bytes exceeds the {MAX_FRAME}-byte limit",
            payload.len()
        )));
    }
    writer.write_all(&(payload.len() as u32).to_be_bytes())?;
    writer.write_all(payload)?;
    Ok(())
}

// —— 请求 ——

fn decode_request(payload: &[u8]) -> Result<Request> {
    let (msg_type, body) = payload
        .split_first()
        .ok_or_else(|| KeydError::Protocol("empty frame".into()))?;

    match *msg_type {
        LIST_KEYS => {
            expect_empty(body, "LIST_KEYS")?;
            Ok(Request::ListKeys)
        }
        SIGN => decode_sign(body).map(Request::Sign),
        UNLOCK => {
            let mut c = Cursor::new(body);
            let did = c.string16()?;
            let kid = c.opt_string16()?;
            let passphrase = Zeroizing::new(c.string16()?);
            let key = if c.is_at_end() { String::new() } else { c.string16()? };
            c.expect_end("UNLOCK")?;
            Ok(Request::Unlock { did, kid, key, passphrase })
        }
        LOCK => {
            let mut c = Cursor::new(body);
            let did = c.string16()?;
            let kid = c.opt_string16()?;
            let key = if c.is_at_end() { String::new() } else { c.string16()? };
            c.expect_end("LOCK")?;
            // 空字符串 = 全部锁上。
            Ok(Request::Lock {
                did: if did.is_empty() { None } else { Some(did) },
                kid,
                key,
            })
        }
        STATUS => {
            expect_empty(body, "STATUS")?;
            Ok(Request::Status)
        }
        GET_DOCUMENT => {
            let mut c = Cursor::new(body);
            let did = c.string16()?;
            c.expect_end("GET_DOCUMENT")?;
            Ok(Request::GetDocument { did })
        }
        other => Err(KeydError::Protocol(format!(
            "0x{other:02x} is not a request type this daemon accepts"
        ))),
    }
}

fn decode_sign(body: &[u8]) -> Result<SignRequest> {
    let mut c = Cursor::new(body);
    let tag = c.u8()?;
    match tag {
        0x01 => {
            let did = c.string16()?;
            let kid = c.opt_string16()?;
            let method = c.string16()?;
            let target_uri = c.string16()?;

            let count = c.u16()? as usize;
            let mut headers = BTreeMap::new();
            for _ in 0..count {
                let name = c.string16()?;
                let value = c.string16()?;
                // 同名头出现两次意味着其中一条会被悄悄丢弃 —— 而"哪个值
                // 进了签名基"会直接改变签名结果。不在协议层替调用方做选择。
                if headers.insert(name.clone(), value).is_some() {
                    return Err(KeydError::Protocol(format!(
                        "header {name:?} is given twice"
                    )));
                }
            }

            let body = c.opt_body()?;

            let covered_count = c.u16()? as usize;
            let mut covered = Vec::with_capacity(covered_count.min(64));
            for _ in 0..covered_count {
                covered.push(c.string16()?);
            }

            // 空串 = "没给"。见 [`SignRequest::Structured::nonce`]。
            let nonce = c.opt_string16()?;

            // 尾随的按名字寻址字段。老客户端在 nonce 之后就结束了 ——
            // 见到这里还有字节才去读,于是新旧两种请求都认得。
            let (key, keyid) = if c.is_at_end() {
                (String::new(), String::new())
            } else {
                (c.string16()?, c.string16()?)
            };
            c.expect_end("SIGN(Structured)")?;

            Ok(SignRequest::Structured {
                did,
                kid,
                method,
                target_uri,
                headers,
                body,
                covered,
                nonce,
                key,
                keyid,
            })
        }
        0x02 => {
            let did = c.string16()?;
            let kid = c.opt_string16()?;
            let payload = c.bytes32()?;
            c.expect_end("SIGN(Raw)")?;
            Ok(SignRequest::Raw { did, kid, payload })
        }
        0x03 => {
            let did = c.string16()?;
            let kid = c.opt_string16()?;
            let challenge = c.bytes32()?;
            // 上限在这里,不在 handler:`bytes32` 只保证不吃掉进程的内存
            // (MAX_BODY),而"这条路能签的东西有形状"靠的是这个小得多的界。
            // 破了它,收下的就是一份"任意字节"—— 也就是 `Raw` 那条路。
            if challenge.len() > MAX_CHALLENGE_LEN {
                return Err(KeydError::Protocol(format!(
                    "a {}-byte challenge exceeds the {MAX_CHALLENGE_LEN}-byte limit",
                    challenge.len()
                )));
            }
            c.expect_end("SIGN(Challenge)")?;
            Ok(SignRequest::Challenge { did, kid, challenge })
        }
        other => Err(KeydError::Protocol(format!(
            "0x{other:02x} is not a SIGN variant"
        ))),
    }
}

// —— 应答 ——

fn decode_response(payload: &[u8]) -> Result<Response> {
    let (msg_type, body) = payload
        .split_first()
        .ok_or_else(|| KeydError::Protocol("empty frame".into()))?;

    match *msg_type {
        OK => {
            expect_empty(body, "OK")?;
            Ok(Response::Ok)
        }
        ERR => {
            let mut c = Cursor::new(body);
            let raw = c.u16()?;
            let code = ErrorCode::from_u16(raw).ok_or_else(|| {
                KeydError::Protocol(format!("0x{raw:04x} is not an error code this client knows"))
            })?;
            let message = c.string16()?;
            c.expect_end("ERR")?;
            Ok(Response::Error { code, message })
        }
        LIST_KEYS => {
            let mut c = Cursor::new(body);
            let count = c.u16()? as usize;
            let mut keys = Vec::with_capacity(count.min(1024));
            for _ in 0..count {
                let did = c.string16()?;
                let kid = c.string16()?;
                let algorithm = KeyAlgorithm::from_wire(c.u8()?).ok_or_else(|| {
                    KeydError::Protocol("unknown key algorithm byte".into())
                })?;
                keys.push(KeySummary { did, kid, algorithm });
            }
            c.expect_end("LIST_KEYS")?;
            Ok(Response::ListKeys(keys))
        }
        SIGN => {
            let mut c = Cursor::new(body);
            let signature = c.bytes16()?;
            c.expect_end("SIGN")?;
            Ok(Response::Signature(signature))
        }
        STATUS => {
            let mut c = Cursor::new(body);
            let count = c.u16()? as usize;
            let mut keys = Vec::with_capacity(count.min(1024));
            for _ in 0..count {
                let did = c.string16()?;
                let kid = c.string16()?;
                let unlocked_secs = c.u64()?;
                keys.push(UnlockedKey { did, kid, unlocked_secs });
            }
            c.expect_end("STATUS")?;
            Ok(Response::Status(keys))
        }
        GET_DOCUMENT => {
            let mut c = Cursor::new(body);
            let document = c.bytes32()?;
            c.expect_end("GET_DOCUMENT")?;
            Ok(Response::Document(document))
        }
        other => Err(KeydError::Protocol(format!(
            "0x{other:02x} is not a response type this client knows"
        ))),
    }
}

fn encode_request(request: &Request) -> Result<Vec<u8>> {
    let mut body = Encoder::default();
    let msg_type = match request {
        Request::ListKeys => LIST_KEYS,
        Request::Status => STATUS,
        Request::Sign(sign) => {
            match sign {
                SignRequest::Structured {
                    did,
                    kid,
                    method,
                    target_uri,
                    headers,
                    body: request_body,
                    covered,
                    nonce,
                    key,
                    keyid,
                } => {
                    body.push(0x01);
                    body.string16(did)?;
                    body.string16(kid.as_deref().unwrap_or(""))?;
                    body.string16(method)?;
                    body.string16(target_uri)?;
                    body.u16(u16::try_from(headers.len())
                        .map_err(|_| KeydError::Protocol("too many headers".into()))?);
                    for (name, value) in headers {
                        body.string16(name)?;
                        body.string16(value)?;
                    }
                    body.opt_body(request_body.as_deref())?;
                    body.u16(u16::try_from(covered.len())
                        .map_err(|_| KeydError::Protocol("too many covered components".into()))?);
                    for component in covered {
                        body.string16(component)?;
                    }
                    body.string16(nonce.as_deref().unwrap_or(""))?;
                    // 只在真按名字签时才写这两段。老守护进程在 nonce 之后
                    // 就 `expect_end`,多发一个空串也会被它当成尾随字节拒掉 ——
                    // 而一次普通签名的请求没有理由因为升级客户端就发不出去。
                    if !key.is_empty() || !keyid.is_empty() {
                        body.string16(key)?;
                        body.string16(keyid)?;
                    }
                }
                SignRequest::Raw { did, kid, payload } => {
                    body.push(0x02);
                    body.string16(did)?;
                    body.string16(kid.as_deref().unwrap_or(""))?;
                    body.bytes32(payload)?;
                }
                SignRequest::Challenge { did, kid, challenge } => {
                    body.push(0x03);
                    body.string16(did)?;
                    body.string16(kid.as_deref().unwrap_or(""))?;
                    body.bytes32(challenge)?;
                }
            }
            SIGN
        }
        Request::Unlock { did, kid, key, passphrase } => {
            body.string16(did)?;
            body.string16(kid.as_deref().unwrap_or(""))?;
            body.string16(passphrase)?;
            if !key.is_empty() {
                body.string16(key)?;
            }
            UNLOCK
        }
        Request::Lock { did, kid, key } => {
            body.string16(did.as_deref().unwrap_or(""))?;
            body.string16(kid.as_deref().unwrap_or(""))?;
            if !key.is_empty() {
                body.string16(key)?;
            }
            LOCK
        }
        Request::GetDocument { did } => {
            body.string16(did)?;
            GET_DOCUMENT
        }
    };

    // 类型字节在最前面。
    let mut payload = Encoder::with_capacity(body.len() + 1);
    payload.push(msg_type);
    payload.extend(body.as_slice());
    Ok(payload.into_vec())
}

fn encode_response(response: &Response) -> Result<Vec<u8>> {
    let mut body = Encoder::default();
    let msg_type = match response {
        Response::Ok => OK,
        Response::Error { code, message } => {
            body.u16(code.as_u16());
            // 错误消息的长度也是 u16,太长的消息会被截断成半句话 ——
            // 与其截断,不如在编码这一层就拒掉,这样是"发不出去",
            // 而不是"发出去一条读着像别的东西的消息"。
            body.string16(message).map_err(|_| {
                KeydError::Protocol("the error message is too long for the wire".into())
            })?;
            ERR
        }
        Response::ListKeys(keys) => {
            body.u16(u16::try_from(keys.len()).map_err(|_| {
                KeydError::Protocol("too many keys for one LIST_KEYS response".into())
            })?);
            for key in keys {
                body.string16(&key.did)?;
                body.string16(&key.kid)?;
                body.push(key.algorithm.to_wire());
            }
            LIST_KEYS
        }
        Response::Signature(signature) => {
            body.bytes16(signature)?;
            SIGN
        }
        Response::Status(keys) => {
            body.u16(u16::try_from(keys.len()).map_err(|_| {
                KeydError::Protocol("too many keys for one STATUS response".into())
            })?);
            for key in keys {
                body.string16(&key.did)?;
                body.string16(&key.kid)?;
                body.u64(key.unlocked_secs);
            }
            STATUS
        }
        Response::Document(document) => {
            body.bytes32(document)?;
            GET_DOCUMENT
        }
    };

    let mut payload = Encoder::with_capacity(body.len() + 1);
    payload.push(msg_type);
    payload.extend(body.as_slice());
    Ok(payload.into_vec())
}

// —— 字节层的小工具 ——

/// 顺序读一个 body。每一步都检查边界 —— 这一段处理的完全是**不可信输入**,
/// 越界读在这里等于把守护进程的地址空间交给对端。
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .ok_or_else(|| KeydError::Protocol("length overflow".into()))?;
        let slice = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| KeydError::Protocol("truncated frame body".into()))?;
        self.at = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let raw = self.take(2)?;
        Ok(u16::from_be_bytes([raw[0], raw[1]]))
    }

    fn u64(&mut self) -> Result<u64> {
        let raw = self.take(8)?;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(raw);
        Ok(u64::from_be_bytes(buf))
    }

    fn string16(&mut self) -> Result<String> {
        let len = self.u16()? as usize;
        let raw = self.take(len)?;
        std::str::from_utf8(raw)
            .map(str::to_owned)
            .map_err(|_| KeydError::Protocol("a string field is not valid UTF-8".into()))
    }

    /// 空串 = "没给"。和 `Lock { did }` 一直以来的约定一致。
    ///
    /// 用空串而不是另加一个标志字节:fragment 永远不可能是空的(`key-1`
    /// 至少也有一个字符),所以空串不会和任何合法值撞上,而多一个标志字节
    /// 只是给每一种请求多一处可以编错的地方。
    fn opt_string16(&mut self) -> Result<Option<String>> {
        Ok(match self.string16()? {
            value if value.is_empty() => None,
            value => Some(value),
        })
    }

    fn bytes16(&mut self) -> Result<Vec<u8>> {
        let len = self.u16()? as usize;
        Ok(self.take(len)?.to_vec())
    }

    fn bytes32(&mut self) -> Result<Vec<u8>> {
        let len = u32::from_be_bytes({
            let raw = self.take(4)?;
            [raw[0], raw[1], raw[2], raw[3]]
        }) as usize;
        if len > MAX_BODY {
            return Err(KeydError::Protocol(format!(
                "a {len}-byte payload exceeds the {MAX_BODY}-byte limit"
            )));
        }
        Ok(self.take(len)?.to_vec())
    }

    /// `u32` 长度;`0xFFFF_FFFF` 表示"没有 body"。
    fn opt_body(&mut self) -> Result<Option<Vec<u8>>> {
        let raw = self.take(4)?;
        let len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        if len == u32::MAX {
            return Ok(None);
        }
        let len = len as usize;
        if len > MAX_BODY {
            return Err(KeydError::Protocol(format!(
                "a {len}-byte body exceeds the {MAX_BODY}-byte limit"
            )));
        }
        Ok(Some(self.take(len)?.to_vec()))
    }

    /// 尾部多出来的字节是协议不一致的信号,不是可以忽略的填充。
    fn expect_end(&self, what: &str) -> Result<()> {
        if self.at != self.bytes.len() {
            return Err(KeydError::Protocol(format!(
                "{what} has {} trailing bytes",
                self.bytes.len() - self.at
            )));
        }
        Ok(())
    }

    /// 尾部还有没有字节。只用来分辨"老请求到这里就结束了"和"新请求后面
    /// 还带着可选字段" —— 单独一个字段读不到一半就断,仍然由 `take` 报错。
    fn is_at_end(&self) -> bool {
        self.at == self.bytes.len()
    }
}

/// 顺序写一个 body。每一个带长度的字段都在写入时检查**值域**:编码不出去
/// 的音高(field 长过 u16)在写入这一刻就报错,而不是在线上被悄悄截断。
#[derive(Default)]
struct Encoder {
    out: Zeroizing<Vec<u8>>,
}

impl Encoder {
    fn with_capacity(capacity: usize) -> Self {
        Self { out: Zeroizing::new(Vec::with_capacity(capacity)) }
    }

    fn push(&mut self, byte: u8) {
        self.out.push(byte);
    }

    fn len(&self) -> usize {
        self.out.len()
    }

    fn as_slice(&self) -> &[u8] {
        &self.out
    }

    fn extend(&mut self, bytes: &[u8]) {
        self.out.extend_from_slice(bytes);
    }

    fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut *self.out)
    }

    fn u16(&mut self, value: u16) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    fn string16(&mut self, value: &str) -> Result<()> {
        let len = u16::try_from(value.len()).map_err(|_| {
            KeydError::Protocol(format!("a {} byte string field does not fit in u16", value.len()))
        })?;
        self.u16(len);
        self.out.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn bytes16(&mut self, value: &[u8]) -> Result<()> {
        let len = u16::try_from(value.len()).map_err(|_| {
            KeydError::Protocol(format!("a {} byte field does not fit in u16", value.len()))
        })?;
        self.u16(len);
        self.out.extend_from_slice(value);
        Ok(())
    }

    fn bytes32(&mut self, value: &[u8]) -> Result<()> {
        if value.len() > MAX_BODY {
            return Err(KeydError::Protocol(format!(
                "a {} byte payload exceeds the {MAX_BODY}-byte limit",
                value.len()
            )));
        }
        self.out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        self.out.extend_from_slice(value);
        Ok(())
    }

    /// `0xFFFF_FFFF` 表示"没有 body",和"body 是空串"分开编码。
    fn opt_body(&mut self, value: Option<&[u8]>) -> Result<()> {
        match value {
            Some(body) => self.bytes32(body),
            None => {
                self.out.extend_from_slice(&u32::MAX.to_be_bytes());
                Ok(())
            }
        }
    }
}

fn expect_empty(body: &[u8], what: &str) -> Result<()> {
    if body.is_empty() {
        Ok(())
    } else {
        Err(KeydError::Protocol(format!(
            "{what} takes no body, but {} bytes follow the type byte",
            body.len()
        )))
    }
}

/// 守护进程和客户端之间的一次一问一答,跑在一个已经建立的双向流上。
pub fn round_trip<S: Read + Write>(stream: &mut S, request: &Request) -> Result<Response> {
    write_request(stream, request)?;
    match read_response(stream)? {
        Some(response) => Ok(response),
        // 应答之前就断,不是"对端没有应答",而是对端坏了。
        None => Err(KeydError::Protocol(
            "the connection closed before a response arrived".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip_request(request: &Request) -> Request {
        let mut wire = Vec::new();
        write_request(&mut wire, request).unwrap();

        // 真的走一遍字节,而不是直接调 decode —— 那样才测得到长度前缀。
        let mut reader = std::io::Cursor::new(wire);
        read_request(&mut reader).unwrap().unwrap()
    }

    fn round_trip_response(response: &Response) -> Response {
        let mut wire = Vec::new();
        write_response(&mut wire, response).unwrap();

        let mut reader = std::io::Cursor::new(wire);
        read_response(&mut reader).unwrap().unwrap()
    }

    fn structured() -> SignRequest {
        let mut headers = BTreeMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("x-request-id".to_string(), "abc".to_string());
        SignRequest::Structured {
            kid: None,
            did: "did:wba:example.com:user:alice:e1_abc".into(),
            method: "POST".into(),
            target_uri: "https://example.com/api".into(),
            headers,
            body: Some(b"{\"hello\":1}".to_vec()),
            covered: vec!["content-type".into()],
            nonce: None,
            key: String::new(),
            keyid: String::new(),
        }
    }

    #[test]
    fn unlock_debug_redacts_secret_and_malformed_tail_is_rejected() {
        let request = Request::Unlock {
            did: "did:wba:example.com:test".into(), kid: None,
            key: String::new(),
            passphrase: Zeroizing::new("temporary-secret-never-log".into()),
        };
        assert!(!format!("{request:?}").contains("temporary-secret-never-log"));
        let mut encoded = Zeroizing::new(encode_request(&request).unwrap());
        encoded.push(0xff);
        let error = decode_request(&encoded).unwrap_err();
        assert!(!error.to_string().contains("temporary-secret-never-log"));
    }

    /// **导出不是一个 socket 消息类型。这一条是导出策略的地基。**
    ///
    /// `ops::export` 那一整套("关掉回显、只走终端、强制先锁、密码不进
    /// argv")挡的都是**同一条通道上的**攻击。真正让被注入的 agent 无能为力
    /// 的是这里:它可以让人类把密码敲进任何一个它画的框里,但那个值**没有
    /// 一条路能到这里来**,因为这里没有这个类型。
    ///
    /// 所以这个测试同时干两件事:
    ///
    /// 1. 把 256 个字节**逐个**喂进解码器,只允许 [`REQUEST_TYPES`] 里那几个
    ///    不报"没有这个类型"。将来谁顺手加了一个新的,这里立刻红。
    /// 2. 把表本身也数一遍 —— 加成员是一次**看得见的决定**,不是顺手写的
    ///    一个分支。
    ///
    /// **`GET_DOCUMENT` 是那张表上唯一一次"加过"。** 它把 0x06 用掉了,而
    /// 0x06 本来正是下面那段点名的"下一个编号"。改这一条的时候要带着
    /// [`REQUEST_TYPES`] 的注释一起读:那次加的是一个**不签名**的类型,所以
    /// "加类型 = 改授权模型"那句话没被推翻。**下一个加的人要面对的是同一句
    /// 话,不是同一条先例。**
    #[test]
    fn the_message_types_are_the_ones_that_do_not_export_anything() {
        assert_eq!(
            REQUEST_TYPES.len(),
            6,
            "the request table changed. Read the comment on REQUEST_TYPES before \
             accepting a new one — a type that can hand out key material is a different \
             product, not a new feature"
        );

        for byte in 0u8..=0xFF {
            let refused = matches!(
                decode_request(&[byte]),
                Err(KeydError::Protocol(message)) if message.contains("is not a request type")
            );
            let listed = REQUEST_TYPES.contains(&byte);
            assert_eq!(
                refused, !listed,
                "0x{byte:02x}: listed={listed}, refused-as-unknown-type={refused}"
            );
        }

        // 顺手把几个"最像导出"的编号钉死,好在有人真去加的时候一眼看见自己
        // 加的是什么。0x07 是这张表顺下来的下一个。
        for byte in [0x00, 0x07, 0x40, 0x7F, 0x90] {
            assert!(
                decode_request(&[byte]).is_err(),
                "0x{byte:02x} must stay unused: an unused code point is what a future \
                 `EXPORT_SEED` message would need, and there is deliberately no room for it"
            );
        }
    }

    /// **`GET_DOCUMENT` 读得到文档,但读不出这台机器没有发布过的东西。**
    ///
    /// 线上那一层能保证的只是"这个 DID 名被原样送到了守护进程";答不答得出
    /// 东西由磁盘决定(见 `daemon::state::DaemonState::get_document`)。这条
    /// 测试钉的是**字节原样**:文档是 sigil 里带引号、括号、换行的 JSON,
    /// 中间任何一个字符被规范化过,内联出去的那一份就和发布的那一份对不上。
    #[test]
    fn a_document_survives_the_wire_byte_for_byte() {
        let document = b"{\n  \"id\": \"did:wba:example.com:user:alice:e1_abc\",\n  \"@context\": []\n}\n".to_vec();

        assert_eq!(
            round_trip_request(&Request::GetDocument {
                did: "did:wba:example.com:user:alice:e1_abc".into()
            }),
            Request::GetDocument { did: "did:wba:example.com:user:alice:e1_abc".into() }
        );
        assert_eq!(
            round_trip_response(&Response::Document(document.clone())),
            Response::Document(document)
        );
    }

    /// nonce 是**不透明**的,但"能不能原样穿过"是真要验的:它会被拼进
    /// `@signature-params` 那一行,路上少一个字符就是另一条签名。
    #[test]
    fn a_caller_supplied_nonce_survives_the_wire_unchanged() {
        let with_nonce = |nonce: Option<&str>| {
            SignRequest::Structured {
                did: "did:wba:x".into(),
                kid: None,
                method: "POST".into(),
                target_uri: "https://e.com/".into(),
                headers: BTreeMap::new(),
                body: None,
                covered: Vec::new(),
                nonce: nonce.map(str::to_string),
                key: String::new(),
                keyid: String::new(),
            }
        };

        for nonce in [Some("abc-123_XYZ"), Some("QUJDREVGRw"), None] {
            let request = with_nonce(nonce);
            assert_eq!(
                round_trip_request(&Request::Sign(request.clone())),
                Request::Sign(request),
                "{nonce:?}"
            );
        }

        // 空串在线上和"没给"是同一个值 —— 这是这个协议一贯的约定(见
        // `Cursor::opt_string16`),不是这里新开的口子。
        assert_eq!(
            round_trip_request(&Request::Sign(with_nonce(Some("")))),
            Request::Sign(with_nonce(None))
        );
    }

    /// 命名签名的两个字段是**尾随的**,只在真的用到时才写。
    ///
    /// 这条不只是"能穿过去":一次普通签名请求一个字节都不许多 —— 老守护
    /// 进程在 nonce 之后 `expect_end`,多发一个空串它就会当成尾随字节拒掉。
    #[test]
    fn named_signing_fields_are_trailing_and_survive_the_wire() {
        let mut named = structured();
        let SignRequest::Structured { key, keyid, .. } = &mut named else {
            unreachable!()
        };
        *key = "team/bot".into();
        *keyid = "did:wba:example.com:agents:bot:e1_abc#key-1".into();

        assert_eq!(
            round_trip_request(&Request::Sign(named.clone())),
            Request::Sign(named.clone())
        );

        let plain = encode_request(&Request::Sign(structured())).unwrap();
        let with_name = encode_request(&Request::Sign(named)).unwrap();
        assert!(
            with_name.len() > plain.len(),
            "a named signature has to carry the two fields it needs"
        );
    }

    #[test]
    fn every_request_survives_a_round_trip() {        let requests = [
            Request::ListKeys,
            Request::Status,
            Request::Sign(structured()),
            Request::Sign(SignRequest::Raw {
                did: "did:wba:x".into(),
                kid: None,
                payload: vec![0, 1, 2],
            }),
            Request::Sign(SignRequest::Challenge {
                did: "did:wba:x".into(),
                kid: None,
                challenge: vec![0, 1, 2],
            }),
            Request::Unlock {
                did: "did:wba:x".into(),
                kid: None,
                key: String::new(),
                passphrase: Zeroizing::new("hunter2".into()),
            },
            Request::Lock { did: Some("did:wba:x".into()), kid: None, key: String::new() },
            Request::Lock { did: None, kid: None, key: String::new() },
            // 命名路的地址就是名字,`did` 和 `kid` 都空着。
            Request::Unlock {
                did: String::new(),
                kid: None,
                key: "team/bot".into(),
                passphrase: Zeroizing::new("hunter2".into()),
            },
            Request::Lock { did: None, kid: None, key: "team/bot".into() },
            Request::GetDocument { did: "did:wba:x".into() },
        ];

        for request in requests {
            assert_eq!(round_trip_request(&request), request, "{request:?}");
        }
    }

    /// Challenge 长度仅限制资源消耗，不提供用途隔离。
    #[test]
    fn a_challenge_at_the_cap_is_accepted_and_one_byte_over_is_refused() {
        let with_len = |len: usize| SignRequest::Challenge {
            did: "did:wba:x".into(),
            kid: None,
            challenge: vec![0u8; len],
        };

        // 正好卡在上限:原样穿过。
        let at_cap = with_len(MAX_CHALLENGE_LEN);
        assert_eq!(
            round_trip_request(&Request::Sign(at_cap.clone())),
            Request::Sign(at_cap)
        );

        // 多一个字节:守护进程**在读的时候**就拒掉,并说清破的是哪条界、给了多少。
        let mut wire = Vec::new();
        write_request(&mut wire, &Request::Sign(with_len(MAX_CHALLENGE_LEN + 1))).unwrap();
        let mut reader = std::io::Cursor::new(wire);
        let err = read_request(&mut reader).unwrap_err();
        assert!(matches!(err, KeydError::Protocol(_)), "{err}");
        assert!(err.to_string().contains("challenge"), "{err}");
        assert!(
            err.to_string().contains(&(MAX_CHALLENGE_LEN + 1).to_string()),
            "the refusal must name the actual length: {err}"
        );
    }

    #[test]
    fn every_response_survives_a_round_trip() {
        let responses = [
            Response::Ok,
            Response::ListKeys(vec![KeySummary {
                did: "did:wba:x".into(),
                kid: "did:wba:x#key-1".into(),
                algorithm: KeyAlgorithm::Ed25519,
            }]),
            Response::Signature(vec![7u8; 64]),
            Response::Status(vec![UnlockedKey {
                did: "did:wba:x".into(),
                kid: "did:wba:x#key-1".into(),
                unlocked_secs: 42,
            }]),
            Response::Error { code: ErrorCode::BadCredential, message: "bad".into() },
            Response::Document(b"{\"id\":\"did:wba:x\"}\n".to_vec()),
        ];

        for response in responses {
            assert_eq!(round_trip_response(&response), response, "{response:?}");
        }
    }

    /// 没有 body 和"body 是空串"是两回事,不能压成同一个值 ——
    /// 前者不覆盖 `content-digest`,后者要覆盖。
    #[test]
    fn an_absent_body_is_not_an_empty_body() {
        let absent = SignRequest::Structured {
            did: "d".into(),
            kid: None,
            method: "GET".into(),
            target_uri: "https://e.com/".into(),
            headers: BTreeMap::new(),
            body: None,
            covered: Vec::new(),
            nonce: None,
            key: String::new(),
            keyid: String::new(),
        };
        let empty = match absent.clone() {
            SignRequest::Structured { did, kid, method, target_uri, headers, covered, .. } => {
                SignRequest::Structured {
                    did,
                    kid,
                    method,
                    target_uri,
                    headers,
                    body: Some(Vec::new()),
                    covered,
                    nonce: None,
                    key: String::new(),
                    keyid: String::new(),
                }
            }
            _ => unreachable!(),
        };

        assert_eq!(round_trip_request(&Request::Sign(absent.clone())), Request::Sign(absent));
        assert_eq!(round_trip_request(&Request::Sign(empty.clone())), Request::Sign(empty));
    }

    /// 长度前缀是**对端给的**,我们会照着它分配内存。不设上限就是一条
    /// 让守护进程去要 4GB 的单行指令。
    #[test]
    fn a_frame_that_claims_to_be_enormous_is_refused_before_allocating() {
        let mut reader = std::io::Cursor::new(u32::MAX.to_be_bytes().to_vec());
        let err = read_request(&mut reader).unwrap_err();
        assert!(matches!(err, KeydError::Protocol(_)), "{err}");
        assert!(err.to_string().contains("limit"), "{err}");
    }

    #[test]
    fn a_zero_length_frame_is_refused() {
        let mut reader = std::io::Cursor::new(0u32.to_be_bytes().to_vec());
        assert!(read_request(&mut reader).is_err());
    }

    /// 说到一半断掉 ≠ 说完了。前者是坏消息,后者是"对端下班了"。
    #[test]
    fn a_truncated_body_is_not_a_clean_close() {
        let mut wire = Vec::new();
        write_request(&mut wire, &Request::ListKeys).unwrap();
        wire.truncate(wire.len() - 1);

        let mut reader = std::io::Cursor::new(wire);
        let err = read_request(&mut reader).unwrap_err();
        assert!(err.to_string().contains("inside"), "{err}");
    }

    #[test]
    fn a_clean_close_at_a_frame_boundary_is_not_an_error() {
        let mut reader = std::io::Cursor::new(Vec::new());
        assert_eq!(read_request(&mut reader).unwrap(), None);
        assert_eq!(read_response(&mut reader).unwrap(), None);
    }

    /// 对端说"这里有 10 字节",可帧里只剩 3 字节 —— 不能读出去,也不能
    /// 把那 3 字节当成一个短字段。
    #[test]
    fn a_field_that_runs_past_the_end_of_the_frame_is_refused() {
        let cases: Vec<Vec<u8>> = vec![
            // UNLOCK 里 did 声称有 100 字节
            vec![UNLOCK, 0x00, 100, b'd'],
            // SIGN 的类型字节后面什么都没有
            vec![SIGN],
            // SIGN(Structured) 声称有 5000 个头
            {
                let mut v = vec![SIGN, 0x01];
                v.extend_from_slice(&0u16.to_be_bytes()); // did
                v.extend_from_slice(&0u16.to_be_bytes()); // method
                v.extend_from_slice(&0u16.to_be_bytes()); // uri
                v.extend_from_slice(&5000u16.to_be_bytes()); // header count
                v
            },
        ];

        for payload in cases {
            let err = decode_request(&payload).unwrap_err();
            assert!(matches!(err, KeydError::Protocol(_)), "{payload:?} → {err}");
        }
    }

    /// 尾部多出字节说明两边对协议的理解已经不一致了 —— 不要猜,报错。
    #[test]
    fn trailing_bytes_are_refused() {
        let mut payload = vec![LIST_KEYS];
        payload.push(0xAA);
        assert!(decode_request(&payload).is_err());

        let mut payload = vec![OK];
        payload.push(0xAA);
        assert!(decode_response(&payload).is_err());
    }

    /// 同名头出现两次,意味着有一条会被丢掉 —— 而哪条进了签名基会
    /// 直接改变签名。不在协议层替调用方挑。
    #[test]
    fn a_duplicated_header_is_refused() {
        let mut body = Encoder::default();
        body.push(0x01);
        body.string16("d").unwrap();
        body.string16("").unwrap();
        body.string16("GET").unwrap();
        body.string16("https://e.com/").unwrap();
        body.u16(2);
        body.string16("x-a").unwrap();
        body.string16("1").unwrap();
        body.string16("x-a").unwrap();
        body.string16("2").unwrap();
        body.opt_body(None).unwrap();
        body.u16(0);

        let mut payload = vec![SIGN];
        payload.extend_from_slice(body.as_slice());

        let err = decode_request(&payload).unwrap_err();
        assert!(err.to_string().contains("twice"), "{err}");
    }

    #[test]
    fn an_unknown_message_type_is_refused() {
        assert!(decode_request(&[0x7F]).is_err());
        assert!(decode_response(&[0x7F]).is_err());
        // 应答的类型码不能当请求收,反之亦然。
        assert!(decode_request(&[OK]).is_err());
        assert!(decode_response(&[LIST_KEYS]).is_err());
    }

    /// 错误码表是**故意**比内部错误粗的:错口令和错 device.secret 在密码学上
    /// 就分不出来,协议层假装能分只会给爆破的人送信息。
    #[test]
    fn the_wire_never_tells_a_caller_which_credential_was_wrong() {
        let passphrase = Response::from_error(&KeydError::BadPassphrase);
        let device_secret = Response::from_error(&KeydError::BadDeviceSecret);

        // 码一样。
        assert_eq!(passphrase, device_secret);
        assert_eq!(
            passphrase,
            Response::Error {
                code: ErrorCode::BadCredential,
                message: "the credential was refused".into(),
            }
        );

        // 而且这句话里不带任何指向性的词 —— 就算以后有人改了
        // `KeydError` 的 `Display`,这里也拦得住。
        let Response::Error { message, .. } = &passphrase else { unreachable!() };
        assert!(!message.contains("passphrase"), "{message}");
        assert!(!message.contains("device"), "{message}");
        assert!(!message.contains("secret"), "{message}");
    }

    /// 内部故障不许把内部细节漏给对端。
    #[test]
    fn internal_failures_collapse_to_one_opaque_code() {
        for error in [
            KeydError::Crypto("the real reason".into()),
            KeydError::Upstream("the real reason".into()),
            KeydError::Json(serde_json::from_str::<u8>("x").unwrap_err()),
        ] {
            assert_eq!(error.wire_code(), ErrorCode::Internal);
        }
    }

    #[test]
    fn error_codes_round_trip_and_unknown_ones_are_refused() {
        for code in [
            ErrorCode::BadCredential,
            ErrorCode::AadMismatch,
            ErrorCode::KeyNotFound,
            ErrorCode::KeyExists,
            ErrorCode::Locked,
            ErrorCode::Permission,
            ErrorCode::RawDisabled,
            ErrorCode::CoveredSetRejected,
            ErrorCode::Protocol,
            ErrorCode::Did,
            ErrorCode::ChallengeDisabled,
            ErrorCode::Internal,
        ] {
            assert_eq!(ErrorCode::from_u16(code.as_u16()), Some(code));
        }

        assert_eq!(ErrorCode::from_u16(0), None);
        assert_eq!(ErrorCode::from_u16(0x1234), None);
    }

    /// 超长字段发不出去,而不是被截断成半句话 —— 半句话读起来像别的东西。
    #[test]
    fn an_over_long_string_field_is_refused_rather_than_truncated() {
        let mut wire = Vec::new();
        let huge = "x".repeat(70_000);
        let err = write_response(
            &mut wire,
            &Response::Error { code: ErrorCode::Internal, message: huge },
        )
        .unwrap_err();

        assert!(err.to_string().contains("too long"), "{err}");
        assert!(wire.is_empty(), "nothing may be written when the message does not fit");
    }

    /// `round_trip` 在一对真 socket 上也得通 —— 这是客户端和守护进程
    /// 实际用的那条路径。
    #[test]
    fn round_trip_works_over_a_real_socket() {
        use std::os::unix::net::UnixStream;

        let (mut client, mut server) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let request = read_request(&mut server).unwrap().unwrap();
            assert_eq!(request, Request::Status);
            write_response(
                &mut server,
                &Response::Status(vec![UnlockedKey {
                    did: "did:wba:x".into(),
                    kid: "did:wba:x#key-1".into(),
                    unlocked_secs: 3,
                }]),
            )
            .unwrap();
        });

        let response = round_trip(&mut client, &Request::Status).unwrap();
        assert_eq!(
            response,
            Response::Status(vec![UnlockedKey {
                did: "did:wba:x".into(),
                kid: "did:wba:x#key-1".into(),
                unlocked_secs: 3,
            }])
        );
        handle.join().unwrap();
    }
}
