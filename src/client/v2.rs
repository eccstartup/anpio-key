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

use crate::error::{KeydError, Result};
use crate::persistence::grants::Grant;
use crate::security::http::HttpRequest;
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
            "PROTOCOL_VERSION_UNSUPPORTED" | "UNSUPPORTED_OPERATION" => Self::Unsupported,
            "GRANT_INVALID" => Self::NotGranted,
            "GRANT_EXPIRED" => Self::Expired,
            "GRANT_EXHAUSTED" => Self::Exhausted,
            "KEY_LOCKED" => Self::Locked,
            "REQUEST_ID_CONFLICT" => Self::Conflict,
            "REQUEST_NOT_FOUND" | "KEY_NOT_FOUND" => Self::Missing,
            "RESOURCE_BUSY" => Self::Busy,
            "AUDIT_UNAVAILABLE" | "PERSISTENCE_UNAVAILABLE" => Self::Stopped,
            "POLICY_DENIED" | "KEY_ROLE_FORBIDDEN" | "PRINCIPAL_DISABLED" => Self::Policy,
            "OUTCOME_UNKNOWN" => Self::Other("OUTCOME_UNKNOWN".into()),
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
        from_data(data, "signed request")
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

fn from_data<T: serde::de::DeserializeOwned>(data: Value, what: &str) -> Result<T> {
    serde_json::from_value(data)
        .map_err(|error| KeydError::Protocol(format!("unexpected {what} reply: {error}")))
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
        ] {
            let error = KeydError::Permission(code.into());
            assert_eq!(Refusal::of(&error), Some(expected), "code {code}");
        }
        // 不是拒绝的错误(比如本地 IO)不硬塞进某一类。
        assert_eq!(Refusal::of(&KeydError::Locked), None);
        assert_eq!(Refusal::of(&KeydError::Permission("SOMETHING_NEW".into())), None);
    }

    #[test]
    fn a_connected_client_remembers_which_config_it_uses() {
        let client = Client::new("/etc/anpio-key/service.json");
        assert_eq!(client.config(), std::path::Path::new("/etc/anpio-key/service.json"));
    }
}
