//! 对端进程的身份 —— **只信内核告诉我们的**。
//!
//! 一个 agent 通过 unix socket 连上来时,它会说自己是谁。它说的话一个字都不能信。
//! 这个模块只用内核在 `connect(2)` 那一刻记录下来的东西:
//!
//! | | Linux | macOS |
//! |---|---|---|
//! | uid / gid | `SO_PEERCRED` | `getpeereid(3)` |
//! | pid | `SO_PEERCRED` | `LOCAL_PEERPID` |
//!
//! 这些在内核里都是**连接建立时冻结**的,不随对端的后续行为改变,也没法伪造。
//!
//! 同 UID 不提供 Agent 级隔离。可执行文件身份只是辅助条件，不能区分
//! 使用同一合法客户端的不同 Agent。Linux 边界预览使用独立 UID 主体注册表。
//!
//! **一律 fail-closed**:取不到身份就是拒绝,绝没有一个"取不到就放行"的分支。

use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use crate::error::{KeydError, Result};

/// 内核认定的对端身份。对端自己说什么都不影响这三个字段。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    /// 对端的有效 uid。
    pub uid: u32,
    /// 对端的有效 gid。
    pub gid: u32,
    /// 对端 pid。内核给的,不是对端自称的。
    ///
    /// `Option` 是因为 pid 只用来记审计日志和给用户看"是哪个进程",
    /// 拿不到不构成拒绝的理由;uid 拿不到才是致命的。
    pub pid: Option<i32>,
}

impl PeerIdentity {
    /// 记审计日志用的一行。
    pub fn audit_label(&self) -> String {
        match self.pid {
            Some(pid) => format!("uid={} gid={} pid={pid}", self.uid, self.gid),
            None => format!("uid={} gid={}", self.uid, self.gid),
        }
    }
}

/// 取对端身份。**取不到 uid 就报错,不返回任何默认值。**
pub fn peer_identity(stream: &UnixStream) -> Result<PeerIdentity> {
    let (uid, gid) = peer_uid_gid(stream)?;
    Ok(PeerIdentity { uid, gid, pid: peer_pid(stream) })
}

#[cfg(target_os = "linux")]
fn peer_uid_gid(stream: &UnixStream) -> Result<(u32, u32)> {
    let creds = linux_creds(stream)?;
    Ok((creds.uid(), creds.gid()))
}

#[cfg(target_os = "linux")]
fn peer_pid(stream: &UnixStream) -> Option<i32> {
    linux_creds(stream).ok().map(|creds| creds.pid())
}

#[cfg(target_os = "linux")]
fn linux_creds(stream: &UnixStream) -> Result<nix::sys::socket::UnixCredentials> {
    use nix::sys::socket::sockopt::PeerCredentials;
    let creds = nix::sys::socket::getsockopt(stream, PeerCredentials)
        .map_err(|e| KeydError::PeerCredentialUnavailable(format!("SO_PEERCRED failed: {e}")))?;

    // **Linux 用哨兵值表示"没有对端",不是用错误。** 在一个从没连上过的
    // AF_UNIX socket 上,`SO_PEERCRED` **成功返回**,内容是
    // `{pid: 0, uid: -1, gid: -1}` —— 实测如此(内核 6.x / aarch64),而
    // macOS 的 `getpeereid` 在同样的构造上报 ENOTCONN。不认这个哨兵的话,
    // 我们就把"拿不到身份"当成了"拿到了一个 uid = 4294967295 的对端"。
    //
    // 授权那一层碰巧会拒掉它(真进程不可能有这个 uid),但那是**碰巧**:
    // [`peer_identity`] 的契约是"取不到 uid 就报错,不返回任何默认值"。
    // 靠上一层碰巧拦住,和真的报错,是两件事 —— 而且失败时的审计行会变成
    // `uid=4294967295 gid=4294967295 pid=0` 这种没人看得懂的乱码。
    //
    // `(uid_t)-1` 是 POSIX 的无效 uid:内核不允许把进程设成它,所以拿它当
    // "没有"的哨兵是可靠的,不会和任何一个真 uid 撞。
    if creds.uid() == u32::MAX {
        return Err(KeydError::PeerCredentialUnavailable(
            "SO_PEERCRED reported no peer (uid -1, pid 0): the socket was never connected".into(),
        ));
    }
    Ok(creds)
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn peer_uid_gid(stream: &UnixStream) -> Result<(u32, u32)> {
    let (uid, gid) = nix::unistd::getpeereid(stream)
        .map_err(|e| KeydError::PeerCredentialUnavailable(format!("getpeereid failed: {e}")))?;
    Ok((uid.as_raw(), gid.as_raw()))
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn peer_pid(stream: &UnixStream) -> Option<i32> {
    use nix::sys::socket::sockopt::LocalPeerPid;
    nix::sys::socket::getsockopt(stream, LocalPeerPid).ok()
}

/// 只认这三个平台。别的平台不是"大概能跑",是**我们没验过它的对端凭证 API**;
/// 而这一层一旦猜错,后果是"任何人都能连上来签"。宁可编译不过。
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "ios")))]
compile_error!(
    "anpio-key needs a kernel peer-credential API (SO_PEERCRED or getpeereid) to identify its \
     callers, and this platform's has not been audited. Shipping without it would mean trusting \
     the caller's own claim about who it is."
);

/// 这个对端有没有资格跟我们要签名。
///
/// 模式 S(单机多 OS 用户)下守护进程由用户自己启动,所以"uid 相同"这一条
/// 既是权限收紧也是身份确认。它挡的是:socket 文件权限被人改宽了、
/// 或者守护进程以 root 跑着而 socket 却是另一个人的。
///
/// **这是第二层。** 同一个 uid 下的两个 agent 在这一层是分不出来的,
/// 那是第三层(下面的 [`BinaryIdentity`])的活儿。
pub fn authorize(self_uid: u32, allowed_uids: &[u32], peer: &PeerIdentity) -> Result<()> {
    if peer.uid == self_uid || allowed_uids.contains(&peer.uid) {
        return Ok(());
    }
    Err(KeydError::Permission(format!(
        "refusing a connection from {}: this daemon only serves uid {self_uid}{}",
        peer.audit_label(),
        if allowed_uids.is_empty() {
            String::new()
        } else {
            format!(" and {allowed_uids:?}")
        }
    )))
}

/// 守护进程自己的 uid。
pub fn self_uid() -> u32 {
    nix::unistd::Uid::effective().as_raw()
}

// ————————————————————————————————————————————————————————————————————————
// 第三层:这个对端到底是**哪个程序**。
// ————————————————————————————————————————————————————————————————————————

/// 对端的可执行文件身份。
///
/// **两个变体的强度不一样,绝不能当成一回事。**
///
/// 需要它的原因很具体:一台机器上多个 agent 通常跑在**同一个 uid** 下
/// (都是你自己),于是第一层(口令)和第二层(uid)对它们一视同仁。
/// 没有第三层,"同一个用户下的另一个 agent"就能拿你的钥匙签名 ——
/// 而 agent 恰恰是最容易被 prompt injection 牵着走的那种程序。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinaryIdentity {
    /// macOS:内核给的 audit token → `SecCode` → cdhash。
    ///
    /// token 是内核在 `connect(2)` 时冻结的 Mach task 身份,cdhash 是内核
    /// 从**正在运行的映像**算出来的摘要 —— 换掉磁盘上的文件不影响它。
    /// 所以这一条对端伪造不了,也是三者里唯一一个可以拿来授权的。
    CodeSignature {
        /// 代码目录的 SHA-256(Apple 的行话叫 cdhash)。
        cdhash: Vec<u8>,
        /// 签名标识(bundle id)。**仅供人看,不参与授权判断** ——
        /// 同一个标识可以对应不同版本的二进制。
        identifier: Option<String>,
    },

    /// Linux:`/proc/<pid>/exe` 的 realpath + 该文件内容的 SHA-256。
    ///
    /// **比 cdhash 弱一档。** 它证明的是"磁盘上那个文件长这样",
    /// 不是"进程正在跑的代码长这样" —— 进程可以在被读取之后改掉自己的
    /// 可执行文件,也可以 `exec` 成别的而 pid 不变的时间窗口里被观察。
    /// 计划里说得很清楚:Linux 侧要配合 Landlock/AppArmor 才收得住。
    ExecutableDigest {
        /// realpath 之后的路径。同样是给人看的。
        path: PathBuf,
        sha256: [u8; 32],
    },
}

impl BinaryIdentity {
    /// 授权判断**只看**这一对。
    ///
    /// `identifier` 和 `path` 被刻意排除在外:它们是"标签",标签不变而内容
    /// 已变是最常见的替换手法。
    pub fn pin(&self) -> (&'static str, &[u8]) {
        match self {
            Self::CodeSignature { cdhash, .. } => ("cdhash", cdhash),
            Self::ExecutableDigest { sha256, .. } => ("sha256", sha256),
        }
    }

    /// 记审计日志用的一行。
    pub fn audit_label(&self) -> String {
        let (kind, digest) = self.pin();
        let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
        match self {
            Self::CodeSignature { identifier, .. } => match identifier {
                Some(id) => format!("{kind}={hex}… ({id})"),
                None => format!("{kind}={hex}…"),
            },
            Self::ExecutableDigest { path, .. } => format!("{kind}={hex}… ({})", path.display()),
        }
    }

    /// 从命令行给的 `cdhash:<hex>` / `sha256:<hex>` 解析一条白名单项。
    pub fn parse(s: &str) -> Result<Self> {
        let (kind, hex) = s.split_once(':').ok_or_else(|| {
            KeydError::Protocol(format!("{s:?} is not <cdhash|sha256>:<hex>"))
        })?;
        let digest = hex_decode(hex)
            .ok_or_else(|| KeydError::Protocol(format!("{s:?} has a non-hex digest")))?;
        match kind {
            "cdhash" => Ok(Self::CodeSignature { cdhash: digest, identifier: None }),
            "sha256" if digest.len() == 32 => {
                let mut sha256 = [0u8; 32];
                sha256.copy_from_slice(&digest);
                Ok(Self::ExecutableDigest { path: PathBuf::new(), sha256 })
            }
            "sha256" => Err(KeydError::Protocol("a sha256 pin must be 32 bytes".into())),
            other => Err(KeydError::Protocol(format!(
                "unknown pin kind {other:?} (expected cdhash or sha256)"
            ))),
        }
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// 问内核:连上来的这个进程,它的可执行文件是什么。
///
/// 返回 `Ok(None)` 的意思是"**问到了,但没有身份**"(对端没有代码签名),
/// 不是"没问到"。这两个要分开:前者是一个确定的答案,后者是
/// [`KeydError::PeerCredentialUnavailable`]。
pub fn binary_identity(stream: &UnixStream, peer: &PeerIdentity) -> Result<Option<BinaryIdentity>> {
    platform_binary_identity(stream, peer)
}

// —— macOS:audit token → SecCode → cdhash ——

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn platform_binary_identity(
    stream: &UnixStream,
    _peer: &PeerIdentity,
) -> Result<Option<BinaryIdentity>> {
    use nix::sys::socket::sockopt::LocalPeerToken;

    let token = nix::sys::socket::getsockopt(stream, LocalPeerToken).map_err(|e| {
        KeydError::PeerCredentialUnavailable(format!("LOCAL_PEERTOKEN failed: {e}"))
    })?;

    sec::code_identity(&token)
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod sec {
    //! Security.framework 的最小 FFI:audit token → 签名信息。
    //!
    //! 只用两件事:`SecCodeCopyGuestWithAttributes`(拿 token 换一个 SecCode)
    //! 和 `SecCodeCopySigningInformation`(把 SecCode 摊成字典)。
    //! 全是 `unsafe`,但边界很窄 —— 每一步都检查 OSStatus,任何一步失败
    //! 都返回 `Err`,不会退化成"没有身份就当它没问题"。

    use core_foundation_sys::base::{kCFAllocatorDefault, Boolean, CFGetTypeID, CFRelease, CFTypeRef};
    use core_foundation_sys::data::{
        CFDataCreate, CFDataGetBytePtr, CFDataGetLength, CFDataGetTypeID, CFDataRef,
    };
    use core_foundation_sys::dictionary::{
        kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks, CFDictionaryCreate,
        CFDictionaryGetValue, CFDictionaryRef,
    };
    use core_foundation_sys::string::{kCFStringEncodingUTF8, CFStringGetCString, CFStringRef};
    use std::ffi::{c_char, c_void, CStr};

    use super::{BinaryIdentity, KeydError, Result};

    type OSStatus = i32;

    /// `SecCSFlags` 的"不特别要求什么"值。
    const SEC_CS_DEFAULT_FLAGS: u32 = 0;
    /// `errSecSuccess`
    const ERR_SEC_SUCCESS: OSStatus = 0;

    #[repr(C)]
    struct __SecCode {
        _opaque: [u8; 0],
    }
    type SecCodeRef = *const __SecCode;

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        static kSecGuestAttributeAudit: CFStringRef;
        static kSecCodeInfoUnique: CFStringRef;
        static kSecCodeInfoIdentifier: CFStringRef;

        fn SecCodeCopyGuestWithAttributes(
            host: SecCodeRef,
            attributes: CFDictionaryRef,
            flags: u32,
            guest: *mut SecCodeRef,
        ) -> OSStatus;

        fn SecCodeCopySigningInformation(
            code: SecCodeRef,
            flags: u32,
            information: *mut CFDictionaryRef,
        ) -> OSStatus;
    }

    /// 把 audit token 换成它的 cdhash。
    pub fn code_identity(token: &nix::sys::socket::audit_token_t) -> Result<Option<BinaryIdentity>> {
        // token 本身就是一个不透明的 32 字节值;SecCode 要的是它的字节。
        let raw = unsafe {
            std::slice::from_raw_parts(token.val.as_ptr().cast::<u8>(), std::mem::size_of_val(&token.val))
        };

        unsafe {
            let token_data = CFDataCreate(kCFAllocatorDefault, raw.as_ptr(), raw.len() as isize);
            if token_data.is_null() {
                return Err(KeydError::PeerCredentialUnavailable(
                    "CFDataCreate for the audit token returned null".into(),
                ));
            }

            let keys = [kSecGuestAttributeAudit as *const c_void];
            let values = [token_data as *const c_void];
            let attributes = CFDictionaryCreate(
                kCFAllocatorDefault,
                keys.as_ptr(),
                values.as_ptr(),
                1,
                &raw const kCFTypeDictionaryKeyCallBacks,
                &raw const kCFTypeDictionaryValueCallBacks,
            );
            // 字典已经把字节复制进去了,token_data 可以放了。
            CFRelease(token_data as CFTypeRef);
            if attributes.is_null() {
                return Err(KeydError::PeerCredentialUnavailable(
                    "building the SecGuestAttribute dictionary returned null".into(),
                ));
            }

            let outcome = copy_identity(attributes);
            CFRelease(attributes as CFTypeRef);
            outcome
        }
    }

    /// # Safety
    /// `attributes` 必须是一个活着的 CFDictionary。
    unsafe fn copy_identity(attributes: CFDictionaryRef) -> Result<Option<BinaryIdentity>> {
        let mut guest: SecCodeRef = std::ptr::null();
        let status = SecCodeCopyGuestWithAttributes(
            std::ptr::null(),
            attributes,
            SEC_CS_DEFAULT_FLAGS,
            &mut guest,
        );
        if status != ERR_SEC_SUCCESS || guest.is_null() {
            return Err(KeydError::PeerCredentialUnavailable(format!(
                "SecCodeCopyGuestWithAttributes failed with OSStatus {status}"
            )));
        }

        let mut information: CFDictionaryRef = std::ptr::null();
        let status = SecCodeCopySigningInformation(guest, SEC_CS_DEFAULT_FLAGS, &mut information);
        CFRelease(guest as CFTypeRef);

        if status != ERR_SEC_SUCCESS || information.is_null() {
            // 对端没签名(或者我们看不到它的签名信息)。
            // 这是**一个确定的答案**:它没有代码身份。
            return Ok(None);
        }

        let cdhash = cdhash_of(information);
        let identifier = string_value(information, kSecCodeInfoIdentifier);
        CFRelease(information as CFTypeRef);

        match cdhash {
            Some(cdhash) if !cdhash.is_empty() => {
                Ok(Some(BinaryIdentity::CodeSignature { cdhash, identifier }))
            }
            _ => Ok(None),
        }
    }

    /// # Safety
    /// `information` 必须是一个活着的 signing-information 字典。
    unsafe fn cdhash_of(information: CFDictionaryRef) -> Option<Vec<u8>> {
        let value = CFDictionaryGetValue(information, kSecCodeInfoUnique as *const c_void);
        if value.is_null() || CFGetTypeID(value) != CFDataGetTypeID() {
            return None;
        }
        let data = value as CFDataRef;
        let len = CFDataGetLength(data);
        if len <= 0 {
            return None;
        }
        let bytes = CFDataGetBytePtr(data);
        if bytes.is_null() {
            return None;
        }
        Some(std::slice::from_raw_parts(bytes, len as usize).to_vec())
    }

    /// # Safety
    /// `information` 必须是一个活着的 signing-information 字典,`key` 必须是一个
    /// 活着的 CFStringRef。
    unsafe fn string_value(information: CFDictionaryRef, key: CFStringRef) -> Option<String> {
        let value = CFDictionaryGetValue(information, key as *const c_void);
        if value.is_null() {
            return None;
        }
        let mut buffer = [0 as c_char; 256];
        let ok: Boolean = CFStringGetCString(
            value as CFStringRef,
            buffer.as_mut_ptr(),
            buffer.len() as isize,
            kCFStringEncodingUTF8,
        );
        if ok == 0 {
            return None;
        }
        CStr::from_ptr(buffer.as_ptr()).to_str().ok().map(str::to_owned)
    }
}

// —— Linux:/proc/<pid>/exe → 文件摘要 ——

#[cfg(target_os = "linux")]
fn platform_binary_identity(
    _stream: &UnixStream,
    peer: &PeerIdentity,
) -> Result<Option<BinaryIdentity>> {
    use sha2::{Digest, Sha256};

    // pid 是内核给的,所以这个路径不是对端能挑的 —— 但它会因为 pid 复用
    // 而指向**另一个**进程,这一点在下面的文档里说清楚了。
    let pid = peer.pid.ok_or_else(|| {
        KeydError::PeerCredentialUnavailable(
            "SO_PEERCRED gave no pid, so the peer's executable cannot be identified".into(),
        )
    })?;

    let link = PathBuf::from(format!("/proc/{pid}/exe"));
    let path = std::fs::read_link(&link).map_err(|e| {
        KeydError::PeerCredentialUnavailable(format!("reading {} failed: {e}", link.display()))
    })?;

    // 打开一次,然后**从那个 fd 读**,不按路径重开 —— 路径可以在两次读取
    // 之间被换掉。即便这样,这个 fd 指向的也未必是"进程正在跑的代码"
    // (见 `BinaryIdentity` 的文档),所以它单独不足以授权。
    let mut file = std::fs::File::open(&link).map_err(|e| {
        KeydError::PeerCredentialUnavailable(format!("opening {} failed: {e}", link.display()))
    })?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).map_err(|e| {
        KeydError::PeerCredentialUnavailable(format!("hashing {} failed: {e}", link.display()))
    })?;
    let sha256: [u8; 32] = hasher.finalize().into();

    Ok(Some(BinaryIdentity::ExecutableDigest { path, sha256 }))
}

/// 谁可以跟我们要签名。
#[derive(Debug, Clone, Default)]
pub struct PeerPolicy {
    /// 除守护进程自己之外,还允许哪些 uid。
    pub allowed_uids: Vec<u32>,
    /// 允许的可执行文件身份。**空了就是不启用第三层**,启动时会告警 ——
    /// 这一条不能悄悄放过,否则"多用户"是个假的多用户。
    pub allowed_binaries: Vec<BinaryIdentity>,
}

impl PeerPolicy {
    /// 按顺序过两层。任何一层说不,就是在动任何密码学之前说不。
    pub fn admit(&self, self_uid: u32, stream: &UnixStream) -> Result<PeerIdentity> {
        let peer = peer_identity(stream)?;
        authorize(self_uid, &self.allowed_uids, &peer)?;

        if self.allowed_binaries.is_empty() {
            return Ok(peer);
        }

        let identity = binary_identity(stream, &peer)?;
        match identity {
            Some(identity) => {
                if self.allowed_binaries.iter().any(|allowed| allowed.pin() == identity.pin()) {
                    Ok(peer)
                } else {
                    Err(KeydError::Permission(format!(
                        "refusing {}: its executable ({}) is not in the allow-list",
                        peer.audit_label(),
                        identity.audit_label()
                    )))
                }
            }
            // 问到了,但它没有身份。白名单非空时,这就是拒绝。
            None => Err(KeydError::Permission(format!(
                "refusing {}: it has no code identity, and this daemon only serves allow-listed \
                 binaries",
                peer.audit_label()
            ))),
        }
    }

    /// 第三层是不是真的开着。
    pub fn enforces_binaries(&self) -> bool {
        !self.allowed_binaries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socketpair() -> (UnixStream, UnixStream) {
        UnixStream::pair().unwrap()
    }

    /// 真开一对 socket,真从内核问对端是谁。
    #[test]
    fn kernel_reports_our_own_identity_for_our_own_process() {
        let (a, _b) = socketpair();
        let id = peer_identity(&a).unwrap();

        assert_eq!(id.uid, self_uid(), "a socketpair peer is us");
        assert_eq!(id.gid, nix::unistd::Gid::effective().as_raw());
        assert_eq!(
            id.pid,
            Some(std::process::id() as i32),
            "the kernel should hand us our own pid"
        );
    }

    #[test]
    fn both_ends_see_the_same_peer() {
        let (a, b) = socketpair();
        assert_eq!(peer_identity(&a).unwrap(), peer_identity(&b).unwrap());
    }

    /// 我们自己开的 socket,自己当然有权用。
    #[test]
    fn our_own_uid_is_authorized() {
        let (a, _b) = socketpair();
        let id = peer_identity(&a).unwrap();
        assert!(authorize(id.uid, &[], &id).is_ok());
    }

    #[test]
    fn a_foreign_uid_is_refused() {
        let me = self_uid();
        let other = PeerIdentity { uid: me.wrapping_add(1), gid: 0, pid: Some(1) };

        let err = authorize(me, &[], &other).unwrap_err();
        assert!(matches!(err, KeydError::Permission(_)));
        assert!(err.to_string().contains("uid="), "the error must name the peer");
    }

    #[test]
    fn an_explicitly_allowed_uid_is_authorized() {
        let other = PeerIdentity { uid: 4242, gid: 20, pid: Some(7) };
        assert!(authorize(1000, &[4242], &other).is_ok());
        assert!(authorize(1000, &[1, 2, 3], &other).is_err());
    }

    #[test]
    fn audit_label_survives_a_missing_pid() {
        let id = PeerIdentity { uid: 501, gid: 20, pid: Some(99) };
        assert_eq!(id.audit_label(), "uid=501 gid=20 pid=99");
        assert_eq!(PeerIdentity { pid: None, ..id }.audit_label(), "uid=501 gid=20");
    }

    // —— 第三层 ——

    /// 白名单为空 = 只过前两层。这一条是"我们确实没开第三层",
    /// 而不是"第三层开了但放行了"。
    #[test]
    fn an_empty_policy_does_not_claim_to_enforce_binaries() {
        let (a, _b) = socketpair();
        let policy = PeerPolicy::default();

        assert!(!policy.enforces_binaries());
        assert!(policy.admit(self_uid(), &a).is_ok());
    }

    /// 真拿内核给的 audit token 去问一次代码身份。
    ///
    /// 两个答案都算过:
    /// - `Some(身份)`:摘要必须非空 —— 空摘要要是被当成"有身份",白名单就
    ///   形同虚设。**是哪一种身份看平台**:macOS 上 cargo 默认 ad-hoc 签,
    ///   内核答得出 `cdhash`;Linux 上没有代码签名,答的是可执行文件自己的
    ///   `sha256`。断言的是"这个平台上该答的那一种",不是 macOS 那一种。
    /// - `None`:没有身份。是一个确定答案,policy 会拒。
    ///
    /// 但**不能是 `Err`**:那意味着我们连问都没问成,而那会让整个第三层
    /// 在真机上永远不可用。
    #[test]
    fn the_kernel_can_always_answer_who_our_executable_is() {
        let (a, _b) = socketpair();
        let peer = peer_identity(&a).unwrap();

        let identity = binary_identity(&a, &peer).expect("asking must not fail");

        if let Some(identity) = identity {
            // 第三层在 macOS 上经 `SecCode` 拿 cdhash,在 Linux 上经
            // `/proc/<pid>/exe` 拿文件摘要 —— `pin()` 的两条分支。
            let expected =
                if cfg!(any(target_os = "macos", target_os = "ios")) { "cdhash" } else { "sha256" };
            let (kind, digest) = identity.pin();
            assert_eq!(kind, expected);
            assert!(!digest.is_empty(), "an empty digest is not an identity");
            let text = identity.audit_label();
            assert!(text.starts_with(&format!("{expected}=")), "{text}");
        }
    }

    /// 白名单非空时,**认不出来的必须拒** —— 这是第三层唯一真正要紧的行为。
    #[test]
    fn a_policy_with_a_binary_allowlist_refuses_anything_it_cannot_place() {
        let (a, _b) = socketpair();
        let policy = PeerPolicy {
            allowed_uids: Vec::new(),
            allowed_binaries: vec![BinaryIdentity::CodeSignature {
                cdhash: vec![0xaa; 20],
                identifier: None,
            }],
        };

        assert!(policy.enforces_binaries());
        let err = policy.admit(self_uid(), &a).unwrap_err();
        assert!(matches!(err, KeydError::Permission(_)), "{err}");
    }

    /// 把我们**自己**的身份填进白名单,就该放行。
    /// 这一条同时验证了"问出来的身份"和"命令行给的 pin"是同一套比较。
    #[test]
    fn a_policy_that_lists_our_own_binary_admits_us() {
        let (a, _b) = socketpair();
        let peer = peer_identity(&a).unwrap();
        let Some(identity) = binary_identity(&a, &peer).unwrap() else {
            // 测试二进制没有签名时这条无从验证;上一条已经覆盖了拒绝路径。
            return;
        };

        let policy = PeerPolicy {
            allowed_uids: Vec::new(),
            allowed_binaries: vec![identity.clone()],
        };
        assert!(policy.admit(self_uid(), &a).is_ok());

        // 而摘要只差一位就不行。
        let mut wrong = identity;
        match &mut wrong {
            BinaryIdentity::CodeSignature { cdhash, .. } => cdhash[0] ^= 1,
            BinaryIdentity::ExecutableDigest { sha256, .. } => sha256[0] ^= 1,
        }
        let policy = PeerPolicy {
            allowed_uids: Vec::new(),
            allowed_binaries: vec![wrong],
        };
        assert!(policy.admit(self_uid(), &a).is_err());
    }

    /// 授权判断只看摘要。标识和路径都是标签,标签可以不换而内容换掉。
    #[test]
    fn authorization_ignores_the_human_readable_labels() {
        let a = BinaryIdentity::CodeSignature {
            cdhash: vec![1, 2, 3],
            identifier: Some("com.example.agent".into()),
        };
        let b = BinaryIdentity::CodeSignature {
            cdhash: vec![1, 2, 3],
            identifier: Some("com.example.agent".into()),
        };
        assert_eq!(a.pin(), b.pin());

        // 摘要一样、标识不同 → 仍然是同一个 pin。
        let c = BinaryIdentity::CodeSignature { cdhash: vec![1, 2, 3], identifier: None };
        assert_eq!(a.pin(), c.pin());

        // 但 cdhash 和文件摘要**永远**不相等,哪怕字节碰巧一样。
        let d = BinaryIdentity::ExecutableDigest {
            path: PathBuf::from("/usr/bin/agent"),
            sha256: [1; 32],
        };
        let e = BinaryIdentity::ExecutableDigest { path: PathBuf::new(), sha256: [1; 32] };
        assert_eq!(d.pin(), e.pin());
        assert_ne!(d.pin().0, a.pin().0);
    }

    #[test]
    fn pins_round_trip_through_their_command_line_form() {
        let pin = BinaryIdentity::parse("cdhash:aabbccdd").unwrap();
        assert_eq!(pin.pin(), ("cdhash", &[0xaa, 0xbb, 0xcc, 0xdd][..]));

        let sha = BinaryIdentity::parse(&format!("sha256:{}", "0d".repeat(32))).unwrap();
        assert_eq!(sha.pin(), ("sha256", &[0x0d; 32][..]));

        // 长度不对、有非十六进制、种类不认识 —— 都要拒,不能悄悄放过。
        assert!(BinaryIdentity::parse("sha256:00").is_err());
        assert!(BinaryIdentity::parse("cdhash:zz").is_err());
        assert!(BinaryIdentity::parse("cdhash:abc").is_err());
        assert!(BinaryIdentity::parse("md5:aabb").is_err());
        assert!(BinaryIdentity::parse("aabbcc").is_err());
    }
}
