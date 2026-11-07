use thiserror::Error;

use crate::daemon::wire::ErrorCode;

/// Every failure mode the daemon can produce.
///
/// Several variants are deliberately coarse: the wire protocol must not leak
/// *why* a credential failed, only *that* it failed.
#[derive(Debug, Error)]
pub enum KeydError {
    // —— 密钥库 ——
    #[error("bad passphrase")]
    BadPassphrase,
    #[error("device secret missing or wrong")]
    BadDeviceSecret,
    #[error("envelope aad mismatch: record does not belong to this identity")]
    AadMismatch,
    /// 信封绑了一根硬件根,而这台机器上没有它(或者这个构建里没有那个后端)。
    ///
    /// **和 `BadPassphrase` 分开是有意的。** 把两者合并,一个合法用户在换了
    /// 机器之后会看到"口令错",然后一遍遍重敲自己那个明明没错的口令。分辨得出来
    /// 不泄露任何东西:`hardware` 字段本来就明文躺在信封文件里,这颗磁盘的读者
    /// 一定能看见,而口令的**内容**一个字都没说。
    ///
    /// 载荷是一整句话(照 [`KeydError::Misuse`] 的先例),因为它要在终端上直接
    /// 被人读,并且要说清该做什么。
    #[error("{0}")]
    HardwareMissing(String),
    /// 要求硬件绑定,但这台机器上没有一根**能用的**根。
    ///
    /// 这条只出现在**生成**那一侧:没有硬件根就拒绝生成,不做静默降级。
    #[error("{0}")]
    HardwareUnavailable(String),
    #[error("key not found: {0}")]
    KeyNotFound(String),
    #[error("key already exists: {0}")]
    KeyExists(String),
    #[error("key is locked")]
    Locked,

    // —— 身份 / peer ——
    ///
    /// 这一条**带**细节,和上面的口令类错误不一样:拿不到对端凭证是本地
    /// syscall 失败,errno 里没有秘密,丢掉它只会让"平台不支持"看起来
    /// 像"权限被拒"。
    #[error("peer credential could not be read: {0}")]
    PeerCredentialUnavailable(String),
    #[error("peer is not permitted to use key {0}")]
    Permission(String),

    // —— 签名 ——
    #[error("raw signing is disabled (start the daemon with --development --allow-raw-signing)")]
    RawDisabled,
    #[error(
        "challenge signing is disabled (start the daemon with --development --allow-challenge-signing)"
    )]
    ChallengeDisabled,
    #[error("caller asked for a covered component the daemon will not sign: {0}")]
    CoveredSetRejected(String),
    /// 按名字寻址的那条签名路开着没有。
    ///
    /// 单开一道门而不是并进 `RawDisabled`:那条路的调用方签的是**自己给的
    /// 字节**,这一条签的是守护进程**按名字找出来的钥匙**。把两者并在一起,
    /// 一个只想用命名路的调用方会收到"raw signing disabled",而那句话对它
    /// 此刻的处境是错的。
    #[error(
        "named key signing is disabled (start the daemon with --development --allow-named-key-signing)"
    )]
    NamedSigningDisabled,

    // —— 调用方式 ——
    /// 工具拒绝照做,而理由和 wire 无关:参数这么配起来不行、磁盘上的状态
    /// 不是它以为的那样、或者那个 pid 已经不是我们的进程了。
    ///
    /// 单开一个变体只为了终端上那一行 —— `Protocol` 的前缀是
    /// "protocol error:",这些消息挂在它后面会把人往"协议坏了"的方向带,
    /// 而真实原因就在那句话说的事情本身。
    #[error("{0}")]
    Misuse(String),

    // —— 其他 ——
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("invalid did: {0}")]
    Did(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("upstream: {0}")]
    Upstream(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    // —— 客户端 ——
    /// 守护进程拒绝了这条请求,这是**协议层告诉我们的那一件事**。
    ///
    /// 为什么客户端不把它还原成 `BadPassphrase` 之类:因为它还原不出来,
    /// 而假装还原得出来就是在撒谎。协议刻意把"口令错"和"device.secret
    /// 不对"合并成了一个码 —— 分得细就是给爆破的人送信息。客户端手上
    /// 只有那个粗码,所以它只报粗码,并且保留服务端给的那一句话。
    ///
    /// 想要细粒度的错误,办法是**别跨这条边界**:同一台机器上直接调
    /// `keystore`,那里分得清。
    ///
    /// `Display` 把粗码和那一句话都打出来。这不是泄露:两者本来就躺在
    /// 协议消息里,客户端手上就有 —— 藏起来只会让坐在终端前面的人看到
    /// 一句"被拒绝了",然后分不清是没解锁、口令错、还是根本没权限。
    #[error("the daemon refused the request ({code}): {message}")]
    Refused { code: ErrorCode, message: String },
}

pub type Result<T> = std::result::Result<T, KeydError>;
