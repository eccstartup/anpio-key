//! v2 受保护数据面的客户端。
//!
//! 和 [`super::Client`](crate::client::Client)(v1 开发协议)不是一回事:这里
//! 只连 sign 端点、只发 v2 JSON 帧、**先验证服务端内核 UID** 再发请求。每次
//! 调用开一条连接、发一个请求、关掉 —— 协议就是每连接一请求(见
//! `docs/ADAPTER.md` §11.1),所以这里没有连接池、没有重试、没有 v1 降级。
//!
//! 错误分两半:`Err(KeydError)` 是"没拿到可用应答"(连接、身份、帧),而
//! [`Refusal`] 是"拿到了应答、被明确拒绝"。后者是业务可以判的,前者不是。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::error::{KeydError, Result};
use crate::persistence::grants::Grant;
use crate::security::http::HttpRequest;
use crate::security::origin::OriginProofRequest;
use crate::security::protocol::DataRequest;

/// 没有 `operations` 字段的服务端只认这六个 —— v2 数据面的基线。
const BASELINE_OPERATIONS: [&str; 6] = [
    "GET_CAPABILITIES",
    "LIST_AUTHORIZED_KEYS",
    "GET_GRANT_STATUS",
    "GET_DOCUMENT",
    "SIGN_HTTP",
    "GET_REQUEST_STATUS",
];

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Capabilities {
    pub protocol_version: u32,
    pub profile: String,
    pub max_body_bytes: u32,
    pub transaction_executor_available: bool,
    pub audit_projection_healthy: bool,
    /// 能力协商字段(P1 起)。缺失时按基线六个操作理解,不是"全都支持"。
    #[serde(default)]
    pub capability_schema: Option<u32>,
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default)]
    pub purposes: Vec<String>,
    /// `SIGN_PURPOSE` 这一路开了哪几个 purpose。空 = 这一路整体没开。
    #[serde(default)]
    pub signing_purposes: Vec<String>,
    #[serde(default)]
    pub grant_kinds: Vec<String>,
}

impl Capabilities {
    /// 这个服务端能不能做某个操作。
    ///
    /// 判断依据只有一个:名字在不在 `operations` 里。旧服务端不带这个字段,
    /// 那时它的能力**恰好**是基线六个 —— 所以空列表按基线解释,而不是按
    /// "什么都不支持"或"什么都支持"解释。
    pub fn supports(&self, operation: &str) -> bool {
        if self.operations.is_empty() {
            BASELINE_OPERATIONS.contains(&operation)
        } else {
            self.operations.iter().any(|name| name == operation)
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct AuthorizedKey {
    pub key_id: String,
    pub did: String,
    pub kid: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct KeyList {
    pub keys: Vec<AuthorizedKey>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Document {
    pub key_id: String,
    pub document: Value,
}

/// 一次成功的结构化签名。`headers` 是 daemon 生成的那些,要原样加到请求上。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignedHttp {
    pub request_id: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub covered: Vec<String>,
    pub expires_at: i64,
}

/// 一次 ANP origin proof。三段头(或等价字段)原样交给协议层。
///
/// `expires` 可以缺省 —— 缺省时 daemon 按 profile 上限算缓存窗口。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignedOriginProof {
    pub request_id: String,
    pub content_digest: String,
    pub signature_input: String,
    pub signature: String,
    pub created: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<i64>,
}

/// 一次绑定用途的断言签名。签名是 hex,公钥是 multibase —— 都不含私钥。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignedPurpose {
    pub request_id: String,
    pub signature: String,
    pub public_multibase: String,
    /// 服务端回显的用途标签:`{"purpose":...}` 或再加 `domain`。
    pub purpose: Value,
}

/// 一次对象/文档 proof 的产物:整份带 `proof` 的对象或文档。
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct SignedProof {
    pub request_id: String,
    /// 带上 `proof` 之后的完整内容 —— 对端验的就是这一份。
    pub value: Value,
    /// 同一条 `proof` 单独拿出来,方便直接嵌进别处。
    pub proof: Value,
}

/// 一次 X25519 协商的结果:**只有这一次**,服务端不存第二份。
///
/// 没有 `Debug`、没有 `Serialize`、没有把字节拷出去的访问器 —— 共享密钥在
/// `Zeroizing` 里活到被 drop,要用只能在 [`SharedSecret::expose`] 的闭包里。
/// 这个类型存在的意义就是让"不小心打了一行日志"编译不过。
pub struct SharedSecret {
    secret: Zeroizing<[u8; 32]>,
    peer_fingerprint: String,
}

impl SharedSecret {
    pub fn expose<T>(&self, f: impl FnOnce(&[u8; 32]) -> T) -> T {
        f(&self.secret)
    }

    /// 对端公钥的 `x1_…` 指纹。可以记进日志,用来确认协商的是谁。
    pub fn peer_fingerprint(&self) -> &str {
        &self.peer_fingerprint
    }

    fn from_reply(reply: Value) -> Result<Self> {
        let reply: EcdhReply = serde_json::from_value(reply)
            .map_err(|_| KeydError::Protocol("unexpected ecdh reply".into()))?;
        let secret = decode_hex_32(&reply.shared_secret)
            .ok_or_else(|| KeydError::Protocol("ecdh reply carried no usable secret".into()))?;
        Ok(Self {
            secret,
            peer_fingerprint: reply.peer_fingerprint,
        })
    }
}

#[derive(Deserialize)]
struct EcdhReply {
    shared_secret: String,
    peer_fingerprint: String,
}

fn decode_hex_32(text: &str) -> Option<Zeroizing<[u8; 32]>> {
    if text.len() != 64 {
        return None;
    }
    let mut out = Zeroizing::new([0u8; 32]);
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        out[index] = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Some(out)
}

/// 被服务端明确拒绝的类别。
///
/// 只分到"该做什么"这一层:该等(忙)、该找管理员(没授权)、该停(过期、
/// 耗尽、冲突)。原始 code 保留在 [`Refusal::code`] 里,便于日志和排查。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// 服务端不认识这个操作,或者协议版本对不上。
    Unsupported,
    /// 这个主体没有可用于它的授权。
    NotGranted,
    Expired,
    Exhausted,
    /// 钥匙没解锁。预留可能已经消费了次数,不能当作"没发生"。
    Locked,
    /// 同一个 request_id 配了不同的输入。
    Conflict,
    /// 本主体没有这条记录。
    Missing,
    Busy,
    /// 审计或状态存储不可用;服务可能已经停止签名。
    Stopped,
    /// 策略、角色或主体状态不允许。
    Policy,
    Other(String),
}

impl Refusal {
    /// 从一次失败的调用里认出类别。不是拒绝(比如连接断了)返回 `None`。
    pub fn of(error: &KeydError) -> Option<Self> {
        Self::from_code(code_of(error)?)
    }

    pub fn from_code(code: &str) -> Option<Self> {
        Some(match code {
            "PROTOCOL_VERSION_UNSUPPORTED" | "UNSUPPORTED_OPERATION" | "OPERATION_DISABLED" => {
                Self::Unsupported
            }
            "GRANT_INVALID" => Self::NotGranted,
            "GRANT_EXPIRED" => Self::Expired,
            "GRANT_EXHAUSTED" | "GRANT_RENEWALS_EXHAUSTED" => Self::Exhausted,
            "KEY_LOCKED" => Self::Locked,
            "REQUEST_ID_CONFLICT" => Self::Conflict,
            "REQUEST_NOT_FOUND" | "KEY_NOT_FOUND" => Self::Missing,
            "RESOURCE_BUSY" => Self::Busy,
            "AUDIT_UNAVAILABLE" | "PERSISTENCE_UNAVAILABLE" => Self::Stopped,
            "POLICY_DENIED" | "KEY_ROLE_FORBIDDEN" | "PRINCIPAL_DISABLED" => Self::Policy,
            "OUTCOME_UNKNOWN" | "ORIGIN_INVALID" | "PURPOSE_INVALID" | "REQUEST_ID_INVALID" => {
                Self::Other(code.into())
            }
            "ECDH_INVALID" | "ECDH_KEY_INVALID" | "ECDH_PEER_INVALID" | "ECDH_PEER_FORBIDDEN" => {
                Self::Other(code.into())
            }
            "PROOF_INVALID" | "PROOF_DOMAIN_INVALID" | "PROOF_CHALLENGE_INVALID" => {
                Self::Other(code.into())
            }
            _ => return None,
        })
    }
}

fn code_of(error: &KeydError) -> Option<&str> {
    match error {
        KeydError::Permission(code) | KeydError::Misuse(code) | KeydError::Protocol(code) => {
            Some(code.as_str())
        }
        _ => None,
    }
}

/// 连受保护数据面的客户端。`config` 是受保护配置的路径,不是 socket。
#[derive(Debug, Clone)]
pub struct Client {
    config: PathBuf,
}

impl Client {
    pub fn new(config: impl Into<PathBuf>) -> Self {
        Self {
            config: config.into(),
        }
    }

    /// 只做一次能力协商,不发别的请求。调用方拿它决定后续用哪些操作。
    pub fn capabilities(&self) -> Result<Capabilities> {
        let data = self.call(DataRequest::Capabilities {})?;
        from_data(data, "capabilities")
    }

    pub fn keys(&self) -> Result<Vec<AuthorizedKey>> {
        let data = self.call(DataRequest::ListAuthorizedKeys {})?;
        let list: KeyList = from_data(data, "authorized keys")?;
        Ok(list.keys)
    }

    pub fn grant(&self, grant_id: &str) -> Result<Grant> {
        let data = self.call(DataRequest::GrantStatus {
            grant_id: grant_id.to_owned(),
        })?;
        from_data(data, "grant status")
    }

    pub fn document(&self, key_id: &str) -> Result<Document> {
        let data = self.call(DataRequest::Document {
            key_id: key_id.to_owned(),
        })?;
        from_data(data, "document")
    }

    /// 结构化签名。`request_id` 由调用方生成并**先持久化**:重试要复用同一个。
    pub fn sign_http(
        &self,
        grant_id: &str,
        request_id: &str,
        http: HttpRequest,
    ) -> Result<SignedHttp> {
        let data = self.call(DataRequest::SignHttp {
            grant_id: grant_id.to_owned(),
            request_id: request_id.to_owned(),
            http,
        })?;
        from_signed(data, "signed request")
    }

    /// ANP origin proof。`origin` 只是事实,签名基由 daemon 拼。
    ///
    /// 服务端没开 `sign_origin_proof` 时会拒绝;先 [`Client::capabilities`]
    /// 看 `supports("SIGN_ORIGIN_PROOF")`,别让用户看到一条莫名其妙的拒绝。
    pub fn origin_proof(
        &self,
        grant_id: &str,
        request_id: &str,
        origin: OriginProofRequest,
    ) -> Result<SignedOriginProof> {
        let data = self.call(DataRequest::SignOriginProof {
            grant_id: grant_id.to_owned(),
            request_id: request_id.to_owned(),
            origin,
        })?;
        from_signed(data, "origin proof")
    }

    /// 绑定用途的断言。`payload` 是原始字节,hex 编码由这里做。
    ///
    /// 用途必须和 grant 上那把键注册时绑定的那一个一致;服务端没开这一路时拒绝。
    /// 先看 `capabilities().signing_purposes`,别让用户看到莫名其妙的拒绝。
    pub fn sign_purpose(
        &self,
        grant_id: &str,
        request_id: &str,
        purpose: &str,
        domain: Option<&str>,
        payload: &[u8],
    ) -> Result<SignedPurpose> {
        let data = self.call(DataRequest::SignPurpose {
            grant_id: grant_id.to_owned(),
            request_id: request_id.to_owned(),
            purpose: purpose.to_owned(),
            domain: domain.map(str::to_owned),
            payload: payload.iter().map(|b| format!("{b:02x}")).collect(),
        })?;
        from_signed(data, "purpose signature")
    }

    /// 对象 proof。`object` 是任意 JSON 对象;`proof` 的 purpose 固定是
    /// `assertionMethod`,用的是 grant 上那把 `device_assertion` 键。
    ///
    /// 服务端没开 `sign_object_proof` 时拒绝;先看
    /// `capabilities().supports("SIGN_OBJECT_PROOF")`。
    pub fn sign_object_proof(
        &self,
        grant_id: &str,
        request_id: &str,
        object: Value,
    ) -> Result<SignedProof> {
        let data = self.call(DataRequest::SignObjectProof {
            grant_id: grant_id.to_owned(),
            request_id: request_id.to_owned(),
            object,
        })?;
        from_signed(data, "object proof")
    }

    /// 文档 proof。`document` 必须**就是**这把键的文档(`id` 等于键的 DID,
    /// 而键还挂在文档里),服务端在扣配额之前就判这一条。
    ///
    /// `proof_purpose` 缺省 `assertionMethod`;`domain`/`challenge` 会原样进
    /// 签名基,给了就得在验签方那边同样给。
    pub fn sign_document_proof(
        &self,
        grant_id: &str,
        request_id: &str,
        document: Value,
        proof_purpose: Option<&str>,
        domain: Option<&str>,
        challenge: Option<&str>,
    ) -> Result<SignedProof> {
        let data = self.call(DataRequest::SignDocumentProof {
            grant_id: grant_id.to_owned(),
            request_id: request_id.to_owned(),
            document,
            proof_purpose: proof_purpose.map(str::to_owned),
            domain: domain.map(str::to_owned),
            challenge: challenge.map(str::to_owned),
        })?;
        from_signed(data, "document proof")
    }

    /// 一次 X25519 协商。`peer` 是对方的 32 字节公钥,结果只回这一次。
    ///
    /// 用同一个 `request_id` 重放**拿不回来**共享密钥 —— 服务端库里根本没存,
    /// 第二次会得到 `completed` + 空结果,这里把它翻成 `OUTCOME_UNKNOWN`。
    /// 所以调用方要先把 `request_id` 和结果一起落地,再往下走。
    pub fn ecdh(
        &self,
        grant_id: &str,
        request_id: &str,
        peer: &[u8; 32],
    ) -> Result<SharedSecret> {
        let data = self.call(DataRequest::Ecdh {
            grant_id: grant_id.to_owned(),
            request_id: request_id.to_owned(),
            peer: peer.iter().map(|b| format!("{b:02x}")).collect(),
        })?;
        from_ecdh(data)
    }

    /// 续期一条 session grant。服务端会把到期日夹到策略天花板以内。
    pub fn renew_grant(&self, grant_id: &str, expiry: i64) -> Result<Grant> {
        let data = self.call(DataRequest::RenewGrant {
            grant_id: grant_id.to_owned(),
            expiry,
        })?;
        from_data(data, "renewed grant")
    }

    /// 查一次签名的状态。响应丢了之后用它,而不是换一个新 id 重签。
    pub fn request_status(&self, request_id: &str) -> Result<Value> {
        self.call(DataRequest::RequestStatus {
            request_id: request_id.to_owned(),
        })
    }

    /// 协议里认识的请求原样发出。给还没被本库包装的新操作用,也给自己写
    /// 测试的人用;返回值就是 `reply.data`。
    pub fn data(&self, request: DataRequest) -> Result<Value> {
        self.call(request)
    }

    fn call(&self, request: DataRequest) -> Result<Value> {
        let reply = crate::security::client::Client::connect(&self.config, false)?.data(request)?;
        Ok(reply.data.unwrap_or(Value::Null))
    }

    /// 这是哪份配置。给错误消息用。
    pub fn config(&self) -> &Path {
        &self.config
    }
}

/// 协商应答和签名应答同形:`RequestStatus` 套结果。区别在"完成了但没结果"
/// —— 那是一次重放,秘密已经交出去了,不能再造一份。
fn from_ecdh(data: Value) -> Result<SharedSecret> {
    if data.get("state").and_then(Value::as_str) != Some("completed") {
        return Err(KeydError::Protocol(format!(
            "unexpected ecdh state: {data}"
        )));
    }
    match data.get("result").filter(|value| !value.is_null()) {
        Some(result) => SharedSecret::from_reply(result.clone()),
        None => Err(KeydError::Misuse("OUTCOME_UNKNOWN".into())),
    }
}

fn from_data<T: serde::de::DeserializeOwned>(data: Value, what: &str) -> Result<T> {
    serde_json::from_value(data)
        .map_err(|error| KeydError::Protocol(format!("unexpected {what} reply: {error}")))
}

/// 签名类操作的应答是 `RequestStatus`:真正的结果在 `result` 里,外层是状态机。
/// 数据面一条连接一个请求,能回来就只可能是 `completed`;别的状态当协议错误。
fn from_signed<T: serde::de::DeserializeOwned>(data: Value, what: &str) -> Result<T> {
    if data.get("state").and_then(Value::as_str) != Some("completed") {
        return Err(KeydError::Protocol(format!(
            "unexpected {what} state: {data}"
        )));
    }
    from_data(data.get("result").cloned().unwrap_or(Value::Null), what)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capabilities(operations: Vec<String>) -> Capabilities {
        Capabilities {
            protocol_version: 2,
            profile: "anp-http-v2".into(),
            max_body_bytes: 16384,
            transaction_executor_available: true,
            audit_projection_healthy: true,
            capability_schema: None,
            operations,
            purposes: vec![],
            signing_purposes: vec![],
            grant_kinds: vec![],
        }
    }

    /// 旧服务端不带 `operations`,能力就是基线六个 —— 不多也不少。
    #[test]
    fn an_absent_operation_list_means_the_baseline_and_nothing_else() {
        let caps = capabilities(vec![]);
        assert!(caps.supports("SIGN_HTTP"));
        assert!(caps.supports("GET_CAPABILITIES"));
        assert!(!caps.supports("SIGN_ORIGIN_PROOF"));
        assert!(!caps.supports("ECDH"));
    }

    /// 有了列表就只信列表,即使列表比基线短。
    #[test]
    fn a_present_operation_list_is_authoritative() {
        let caps = capabilities(vec!["SIGN_ORIGIN_PROOF".into()]);
        assert!(caps.supports("SIGN_ORIGIN_PROOF"));
        assert!(!caps.supports("SIGN_HTTP"));
    }

    /// 旧服务端的应答要能被解析:新字段有默认值,不是必填。
    #[test]
    fn old_capability_json_still_parses() {
        let old = serde_json::json!({
            "protocol_version": 2, "profile": "anp-http-v2", "max_body_bytes": 16384,
            "transaction_executor_available": true, "audit_projection_healthy": true
        });
        let caps: Capabilities = serde_json::from_value(old).unwrap();
        assert!(caps.operations.is_empty());
        assert!(caps.supports("SIGN_HTTP"));
    }

    #[test]
    fn refusals_are_classified_by_what_the_caller_should_do() {
        for (code, expected) in [
            ("GRANT_INVALID", Refusal::NotGranted),
            ("GRANT_EXPIRED", Refusal::Expired),
            ("GRANT_EXHAUSTED", Refusal::Exhausted),
            ("KEY_LOCKED", Refusal::Locked),
            ("REQUEST_ID_CONFLICT", Refusal::Conflict),
            ("REQUEST_NOT_FOUND", Refusal::Missing),
            ("RESOURCE_BUSY", Refusal::Busy),
            ("AUDIT_UNAVAILABLE", Refusal::Stopped),
            ("PERSISTENCE_UNAVAILABLE", Refusal::Stopped),
            ("POLICY_DENIED", Refusal::Policy),
            ("KEY_ROLE_FORBIDDEN", Refusal::Policy),
            ("PRINCIPAL_DISABLED", Refusal::Policy),
            ("PROTOCOL_VERSION_UNSUPPORTED", Refusal::Unsupported),
            ("OPERATION_DISABLED", Refusal::Unsupported),
            ("GRANT_RENEWALS_EXHAUSTED", Refusal::Exhausted),
            ("ORIGIN_INVALID", Refusal::Other("ORIGIN_INVALID".into())),
            ("PROOF_INVALID", Refusal::Other("PROOF_INVALID".into())),
        ] {
            let error = KeydError::Permission(code.into());
            assert_eq!(Refusal::of(&error), Some(expected), "code {code}");
        }
        // 不是拒绝的错误(比如本地 IO)不硬塞进某一类。
        assert_eq!(Refusal::of(&KeydError::Locked), None);
        assert_eq!(
            Refusal::of(&KeydError::Permission("SOMETHING_NEW".into())),
            None
        );
    }

    #[test]
    fn a_connected_client_remembers_which_config_it_uses() {
        let client = Client::new("/etc/anpio-key/service.json");
        assert_eq!(
            client.config(),
            std::path::Path::new("/etc/anpio-key/service.json")
        );
    }

    /// 签名类应答的外层是 `RequestStatus`,结果在 `result` 里 —— 不是顶层的。
    #[test]
    fn signed_replies_are_unwrapped_from_the_request_status() {
        let data = serde_json::json!({
            "request_id": "5d0a0c1e-0000-4000-8000-000000000001",
            "state": "completed",
            "result": {
                "request_id": "5d0a0c1e-0000-4000-8000-000000000001",
                "url": "https://service.example.com/v1/orders",
                "headers": {"signature": "sig1=:AA==:"},
                "covered": ["@method", "@target-uri"],
                "expires_at": 42
            }
        });
        let signed: SignedHttp = from_signed(data, "signed request").unwrap();
        assert_eq!(signed.url, "https://service.example.com/v1/orders");
        assert_eq!(signed.headers["signature"], "sig1=:AA==:");
        assert_eq!(signed.covered, ["@method", "@target-uri"]);
        assert_eq!(signed.expires_at, 42);
    }

    #[test]
    fn a_purpose_reply_keeps_its_tag_after_unwrapping() {
        let data = serde_json::json!({
            "request_id": "5d0a0c1e-0000-4000-8000-000000000002",
            "state": "completed",
            "result": {
                "request_id": "5d0a0c1e-0000-4000-8000-000000000002",
                "signature": "ab".repeat(64),
                "public_multibase": "z6Mkexample",
                "purpose": {"purpose": "device_assertion"}
            }
        });
        let signed: SignedPurpose = from_signed(data, "purpose signature").unwrap();
        assert_eq!(signed.public_multibase, "z6Mkexample");
        assert_eq!(signed.purpose["purpose"], "device_assertion");
    }

    #[test]
    fn a_proof_reply_carries_the_signed_value_and_the_proof() {
        let data = serde_json::json!({
            "request_id": "5d0a0c1e-0000-4000-8000-000000000004",
            "state": "completed",
            "result": {
                "request_id": "5d0a0c1e-0000-4000-8000-000000000004",
                "value": {"id": "did:example:alice", "proof": {"proofValue": "zabc"}},
                "proof": {"proofValue": "zabc"}
            }
        });
        let signed: SignedProof = from_signed(data, "document proof").unwrap();
        assert_eq!(signed.value["id"], "did:example:alice");
        assert_eq!(signed.proof["proofValue"], "zabc");
        assert_eq!(signed.value["proof"], signed.proof);
    }

    #[test]
    fn a_status_that_did_not_complete_is_not_a_signature() {
        let data = serde_json::json!({
            "request_id": "5d0a0c1e-0000-4000-8000-000000000003",
            "state": "reserved"
        });
        let error = from_signed::<SignedHttp>(data, "signed request").unwrap_err();
        assert!(matches!(error, KeydError::Protocol(_)));
    }

    /// 共享密钥只在闭包里能用;长度和字符两个都不对就是坏应答,不是"差不多"。
    #[test]
    fn a_shared_secret_is_borrowed_not_copied() {
        let reply = serde_json::json!({
            "shared_secret": "4a".repeat(32),
            "peer_fingerprint": "x1_abc"
        });
        let secret = SharedSecret::from_reply(reply).unwrap();
        assert_eq!(secret.peer_fingerprint(), "x1_abc");
        assert_eq!(secret.expose(|bytes| bytes[0]), 0x4a);
        assert_eq!(secret.expose(|bytes| bytes[31]), 0x4a);

        for bad in [
            serde_json::json!({"shared_secret": "4a".repeat(31), "peer_fingerprint": "x1_a"}),
            serde_json::json!({"shared_secret": "4A".repeat(32), "peer_fingerprint": "x1_a"}),
            serde_json::json!({"shared_secret": "zz".repeat(32), "peer_fingerprint": "x1_a"}),
        ] {
            assert!(SharedSecret::from_reply(bad).is_err());
        }
    }

    /// 重放拿到的是 `completed` + 空结果 —— 那不是"再来一份密钥"。
    #[test]
    fn a_replayed_ecdh_reply_carries_no_secret() {
        let error = match from_ecdh(serde_json::json!({"request_id": "r", "state": "completed"})) {
            Err(error) => error,
            Ok(_) => panic!("a completed status with no result must not yield a secret"),
        };
        assert!(matches!(error, KeydError::Misuse(code) if code == "OUTCOME_UNKNOWN"));
        assert!(from_ecdh(serde_json::json!({"request_id": "r", "state": "reserved"})).is_err());
        let live = serde_json::json!({"request_id": "r", "state": "completed",
            "result": {"shared_secret": "4a".repeat(32), "peer_fingerprint": "x1_abc"}});
        assert_eq!(from_ecdh(live).unwrap().expose(|b| b[0]), 0x4a);
    }
}
