//! 最小客户端:一条连接、一次请求、一次应答。
//!
//! 这个模块的读者有两类:本仓库的 CLI,以及**想自己接 keyd 的人**。所以
//! 它刻意小、刻意同步、刻意没有连接池和重试 —— 三行说明白协议怎么走,
//! 比一个功能齐全但看不出协议长什么样的库有用。
//!
//! ## 为什么不自动重连
//!
//! 一次 CLI 调用 = 一次连接。守护进程重启过之后旧连接就是死的,而"悄悄
//! 重连"会把一个已经失去意义的签名请求重放上去 —— 签名不是幂等的。
//! 调用方要重试,自己重连,并且**自己知道重试的是哪一次签名**。
//!
//! 解锁请求和编码缓冲使用可清零封装。v1 尚未提供受保护服务端认证。

use std::collections::BTreeMap;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use crate::daemon::wire::{self, KeySummary, Request, Response, SignRequest, UnlockedKey};
use crate::error::{KeydError, Result};

/// 连上守护进程,发请求,拿应答。
///
/// `Debug` 是安全的:这个结构里只有一个 fd 和一条路径,没有口令,也没有
/// 密钥 —— 那是**守护进程**那边的性质,客户端从头到尾没见过。
#[derive(Debug)]
pub struct Client {
    stream: UnixStream,
    path: PathBuf,
}

impl Client {
    /// 连一条 socket。
    ///
    /// "没有守护进程在听"被翻译成一条**看得懂**的错误。默认的 `io::Error`
    /// 会说 "No such file or directory",而那会让第一次用的人去查文件权限,
    /// 而真正该做的事是 `anpio-key serve`。
    pub fn connect(path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(path).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                KeydError::Protocol(format!(
                    "no anpio-key is listening on {} — start one with `anpio-key serve`",
                    path.display()
                ))
            }
            _ => KeydError::Io(error),
        })?;
        Ok(Self { stream, path: path.to_path_buf() })
    }

    /// 这个客户端连着哪个 socket。给错误消息用。
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn list_keys(&mut self) -> Result<Vec<KeySummary>> {
        match self.call(Request::ListKeys)? {
            Response::ListKeys(keys) => Ok(keys),
            other => Err(unexpected("list_keys", &other)),
        }
    }

    pub fn status(&mut self) -> Result<Vec<UnlockedKey>> {
        match self.call(Request::Status)? {
            Response::Status(keys) => Ok(keys),
            other => Err(unexpected("status", &other)),
        }
    }

    /// 解锁。`kid` 是 `did#fragment`,不给就是 `did` 名下默认那把(绑定密钥)。
    pub fn unlock(&mut self, did: &str, kid: Option<&str>, passphrase: &str) -> Result<()> {
        match self.call(Request::Unlock {
            did: did.to_string(),
            kid: kid.map(str::to_string),
            passphrase: zeroize::Zeroizing::new(passphrase.to_string()),
        })? {
            Response::Ok => Ok(()),
            other => Err(unexpected("unlock", &other)),
        }
    }

    /// 锁上。`did == None` = 全锁;给了 `did` 不给 `kid` = 那个 DID 底下全放。
    pub fn lock(&mut self, did: Option<&str>, kid: Option<&str>) -> Result<()> {
        match self.call(Request::Lock {
            did: did.map(str::to_string),
            kid: kid.map(str::to_string),
        })? {
            Response::Ok => Ok(()),
            other => Err(unexpected("lock", &other)),
        }
    }

    /// 签一条 RFC 9421 请求,拿回**要加在请求上的头**。
    ///
    /// 返回的字节就是线上的原文(一行一个 `名字: 值`)。要把它挂到真实
    /// HTTP 请求上,用 [`parse_signed_headers`]。
    pub fn sign(&mut self, request: SignRequest) -> Result<Vec<u8>> {
        match self.call(Request::Sign(request))? {
            Response::Signature(bytes) => Ok(bytes),
            other => Err(unexpected("sign", &other)),
        }
    }

    /// 原始字节签名。守护进程没开 `--allow-raw-signing` 时会被拒。
    pub fn sign_raw(&mut self, did: &str, kid: Option<&str>, payload: Vec<u8>) -> Result<Vec<u8>> {
        match self.call(Request::Sign(SignRequest::Raw {
            did: did.to_string(),
            kid: kid.map(str::to_string),
            payload,
        }))? {
            Response::Signature(bytes) => Ok(bytes),
            other => Err(unexpected("sign_raw", &other)),
        }
    }

    /// 签一段调用方给的挑战字节(注册流程里"证明此刻握着这把钥匙"那一步)。
    /// 守护进程没开 `--allow-challenge-signing` 时会被拒;超过
    /// [`crate::daemon::wire::MAX_CHALLENGE_LEN`] 字节的输入在协议层就被挡下。
    pub fn sign_challenge(
        &mut self,
        did: &str,
        kid: Option<&str>,
        challenge: Vec<u8>,
    ) -> Result<Vec<u8>> {
        match self.call(Request::Sign(SignRequest::Challenge {
            did: did.to_string(),
            kid: kid.map(str::to_string),
            challenge,
        }))? {
            Response::Signature(bytes) => Ok(bytes),
            other => Err(unexpected("sign_challenge", &other)),
        }
    }

    /// 取一份**本机发布过的** DID 文档,原样字节。
    ///
    /// 只读,而且**不需要先 unlock**:文档是可公开的成品。别人的 DID 这里
    /// 答不出来 —— 守护进程不联网,resolve 只能在客户端做。
    pub fn document(&mut self, did: &str) -> Result<Vec<u8>> {
        match self.call(Request::GetDocument { did: did.to_string() })? {
            Response::Document(bytes) => Ok(bytes),
            other => Err(unexpected("document", &other)),
        }
    }

    fn call(&mut self, request: Request) -> Result<Response> {
        wire::write_request(&mut self.stream, &request)?;

        let response = wire::read_response(&mut self.stream)?.ok_or_else(|| {
            KeydError::Protocol(
                "the daemon closed the connection without answering — it may have restarted".into(),
            )
        })?;

        match response {
            // **粗码原样带回。** 见 `KeydError::Refused`:客户端还原不出
            // 服务端到底哪个内部错误,协议层也不打算让它还原得出。
            Response::Error { code, message } => Err(KeydError::Refused { code, message }),
            other => Ok(other),
        }
    }
}

/// 把守护进程返回的头拆成 `名字 → 值`。
///
/// 格式是 daemon 定的:一行一个 `名字: 值`,以 `\n` 结尾。值里不可能有
/// `\n`([`crate::sign::rfc9421`] 在边界上就把带换行的头值拒了),所以这个
/// 拆分是无歧义的 —— 不是"一般没歧义",是**构造上不会有**。
///
/// 保留头名的原始大小写:HTTP 头名不区分大小写,但 `Signature-Input` 和
/// `Signature` 两个参数名(`keyid`、`created`、`alg`)是区分大小写的,而
/// 它们在值里,不在名字里。名字照抄最省事也最不容易错。
pub fn parse_signed_headers(bytes: &[u8]) -> Result<BTreeMap<String, String>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| KeydError::Protocol(format!("the daemon returned non-UTF-8 headers: {e}")))?;

    let mut out = BTreeMap::new();
    for line in text.lines() {
        let (name, value) = line.split_once(": ").ok_or_else(|| {
            KeydError::Protocol(format!("malformed header line from the daemon: {line:?}"))
        })?;
        if out.insert(name.to_string(), value.to_string()).is_some() {
            // 同一个头出现两次 = 上游或我们对格式的理解错了。静默取一个
            // 会让签名在被挂上去之后才失败,那时候已经查不到这里了。
            return Err(KeydError::Protocol(format!(
                "the daemon returned {name} twice"
            )));
        }
    }
    Ok(out)
}

/// 应答的类型对不上 —— 只可能是协议版本不匹配,所以要说清是哪一边。
fn unexpected(what: &str, got: &Response) -> KeydError {
    KeydError::Protocol(format!(
        "asked for {what} but the daemon answered with {}; \
         the client and the daemon are probably different versions",
        describe(got)
    ))
}

fn describe(response: &Response) -> &'static str {
    match response {
        Response::Ok => "OK",
        Response::ListKeys(_) => "LIST_KEYS",
        Response::Signature(_) => "SIGN",
        Response::Status(_) => "STATUS",
        Response::Document(_) => "GET_DOCUMENT",
        Response::Error { .. } => "ERR",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **这条测试守的是"环闭合"**:服务端的内部错误 → 粗码 → 客户端 →
    /// 再发出去还是同一个粗码。中间任何一环把粗细搞错,这里就红。
    #[test]
    fn a_wire_code_survives_the_round_trip_through_a_client() {
        let original = KeydError::BadPassphrase;
        let leaked = crate::daemon::wire::Response::from_error(&original);
        let Response::Error { code, message } = leaked else {
            panic!("expected an error response");
        };

        // 协议层给的是粗码。
        assert_eq!(code, wire::ErrorCode::BadCredential);
        // 也是含糊的话 —— 不能有"passphrase"字样。
        assert!(!message.contains("passphrase"), "{message}");

        // 客户端收下,再发出,还是同一个码。
        let received = KeydError::Refused { code, message };
        assert_eq!(received.wire_code(), wire::ErrorCode::BadCredential);
        // 而且消息不会随转发变长。
        assert_eq!(received.wire_message(), "the credential was refused");
    }

    #[test]
    fn signed_headers_split_on_the_first_colon_only() {
        let bytes = b"Signature-Input: sig1=(\"@method\");keyid=\"did:wba:x#key-1\"\nSignature: abc==\n";
        let parsed = parse_signed_headers(bytes).unwrap();

        assert_eq!(parsed.len(), 2);
        // 值里的冒号不能被当成分隔符 —— 值里全是冒号(http://、did:、
        // 时间戳)。
        assert_eq!(
            parsed["Signature-Input"],
            r#"sig1=("@method");keyid="did:wba:x#key-1""#
        );
    }

    #[test]
    fn a_repeated_header_is_refused_rather_than_silently_collapsed() {
        let bytes = b"Signature: a\nSignature: b\n";
        let error = parse_signed_headers(bytes).unwrap_err();
        assert!(error.to_string().contains("twice"), "{error}");
    }

    #[test]
    fn a_line_without_a_colon_is_refused() {
        assert!(parse_signed_headers(b"garbage\n").is_err());
    }

    #[test]
    fn an_empty_header_set_is_an_empty_map_not_an_error() {
        assert!(parse_signed_headers(b"").unwrap().is_empty());
    }

    /// 连不上时说的是"去启动守护进程",不是 errno。
    #[test]
    fn connecting_to_nothing_says_what_to_do_about_it() {
        let error = Client::connect(Path::new("/nonexistent/anpio-key/nope.sock")).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("anpio-key serve"), "{text}");
        assert!(!text.contains("os error"), "{text}");
    }

    #[test]
    fn the_type_mismatch_message_names_both_sides() {
        let error = unexpected("status", &Response::Ok);
        let text = error.to_string();
        assert!(text.contains("status"), "{text}");
        assert!(text.contains("OK"), "{text}");
    }
}
