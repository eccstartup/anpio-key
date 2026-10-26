//! Fixed policy schemas and evaluation against one canonical input.
//!
//! v1 只有 `http-authentication` 一个 purpose,字段平铺在顶层。v2 把
//! purpose 抬成枚举、把该 purpose 自己的字段收进 `content`、把授权上限收进
//! `limits`。两份都留着:v1 文档的 `parse` 结果和判定规则一个字不变,新发布的
//! v1 文档写回去也还是原来那几个字段的顺序无关形状。
use super::*;
use std::collections::BTreeSet;

use crate::security::http::CanonicalHttpRequest;
use crate::security::origin::{OriginProof, MAX_CANONICAL_BYTES, TARGET_KINDS};

const HTTP_METHODS: [&str; 7] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
const MAX_HTTP_BODY_BYTES: u32 = 16 * 1024 * 1024;

fn denied() -> KeydError {
    KeydError::Misuse("POLICY_DENIED".into())
}

/// 策略的用途。名字即线上字符串,kebab-case。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Purpose {
    HttpAuthentication,
    OriginProof,
    PurposeSigning,
    Ecdh,
    ObjectProof,
    DocumentProof,
    Root,
}

impl Purpose {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::HttpAuthentication => "http-authentication",
            Self::OriginProof => "origin-proof",
            Self::PurposeSigning => "purpose-signing",
            Self::Ecdh => "ecdh",
            Self::ObjectProof => "object-proof",
            Self::DocumentProof => "document-proof",
            Self::Root => "root",
        }
    }
}

/// 授权上限。v1 只有前两个;v1 文档换算时 `max_lifetime_seconds` 取
/// `max_duration_seconds`、`max_renewals` 取 0 —— 即 v1 的 grant 续不了。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Limits {
    pub(super) max_duration_seconds: u32,
    pub(super) max_uses: u32,
    pub(super) max_lifetime_seconds: u32,
    pub(super) max_renewals: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
enum Query {
    None {},
    Exact { value: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    mode: String,
    max_bytes: u32,
}

/// `http-authentication` 的 content:v1 那六个字段,一个不多一个不少。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpContent {
    origin: String,
    methods: Vec<String>,
    paths: Vec<String>,
    query: Query,
    body: Body,
    signature_profile: String,
}

/// `origin-proof` 的 content。
///
/// 这里**没有** `origin`/`paths`:ANP 的 origin proof 待签的是一个
/// `{method, meta, body}` 对象,目标由 `meta.target.{kind,did}` 给出,
/// 既没有 URL 也没有路径。能收窄的只有方法名、目标类别和 body 大小。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginContent {
    methods: Vec<String>,
    target_kinds: Vec<String>,
    body: Body,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PurposeContent {
    purposes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EcdhContent {
    peers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofContent {
    proof_purposes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootContent {}

/// 校验过的 content。`purpose` 由它是哪个变体决定,不再单独存一份可以写错的副本。
#[derive(Debug, Clone)]
enum Content {
    Http(HttpContent),
    Origin(OriginContent),
    PurposeSigning(PurposeContent),
    Ecdh(EcdhContent),
    Proof((Purpose, ProofContent)),
    Root(RootContent),
}

impl Content {
    fn purpose(&self) -> Purpose {
        match self {
            Self::Http(_) => Purpose::HttpAuthentication,
            Self::Origin(_) => Purpose::OriginProof,
            Self::PurposeSigning(_) => Purpose::PurposeSigning,
            Self::Ecdh(_) => Purpose::Ecdh,
            Self::Proof((purpose, _)) => *purpose,
            Self::Root(_) => Purpose::Root,
        }
    }
}

/// 一份解析好的策略。`purpose()` 是 `content` 的投影,不是另一个字段。
#[derive(Debug, Clone)]
pub(super) struct Policy {
    content: Content,
    pub(super) limits: Limits,
}

impl Policy {
    pub(super) fn purpose(&self) -> Purpose {
        self.content.purpose()
    }
}

/// v1 的形状。留着它,是因为已经落库的 v1 文档要按原来的字段集读回来。
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct V1Policy {
    schema_version: u32,
    name: String,
    purpose: String,
    origin: String,
    methods: Vec<String>,
    paths: Vec<String>,
    query: Query,
    body: Body,
    signature_profile: String,
    grant_limits: V1Limits,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct V1Limits {
    max_duration_seconds: u32,
    max_uses: u32,
}

/// v2 的外壳。`content` 先按 `Value` 收下,再由 `purpose` 决定用哪个结构体
/// 去解 —— 这样每个 purpose 都能有自己的 `deny_unknown_fields`。
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct V2Policy {
    schema_version: u32,
    name: String,
    purpose: Purpose,
    limits: Limits,
    content: Value,
}

pub(super) fn normalize(content: Value) -> Result<Value> {
    match content.get("schema_version").and_then(Value::as_u64) {
        Some(1) => normalize_v1(content),
        Some(2) => normalize_v2(content),
        _ => Err(invalid()),
    }
}

fn normalize_v1(content: Value) -> Result<Value> {
    let p: V1Policy = serde_json::from_value(content).map_err(|_| invalid())?;
    if p.schema_version != 1
        || p.purpose != "http-authentication"
        || p.name.is_empty()
        || p.name.len() > 128
        || p.name.chars().any(char::is_control)
        || p.grant_limits.max_duration_seconds == 0
        || p.grant_limits.max_uses == 0
    {
        return Err(invalid());
    }
    validate_http(&HttpContent {
        origin: p.origin.clone(),
        methods: p.methods.clone(),
        paths: p.paths.clone(),
        query: p.query.clone(),
        body: p.body.clone(),
        signature_profile: p.signature_profile.clone(),
    })?;
    serde_json::to_value(p).map_err(|_| invalid())
}

fn normalize_v2(content: Value) -> Result<Value> {
    let p: V2Policy = serde_json::from_value(content).map_err(|_| invalid())?;
    if p.schema_version != 2
        || p.name.is_empty()
        || p.name.len() > 128
        || p.name.chars().any(char::is_control)
    {
        return Err(invalid());
    }
    validate_limits(&p.limits)?;
    parse_content(p.purpose, p.content.clone())?;
    serde_json::to_value(p).map_err(|_| invalid())
}

fn validate_limits(l: &Limits) -> Result<()> {
    if l.max_duration_seconds == 0
        || l.max_uses == 0
        || l.max_lifetime_seconds < l.max_duration_seconds
        || l.max_lifetime_seconds > 365 * 24 * 60 * 60
        || l.max_renewals > 1024
    {
        return Err(invalid());
    }
    Ok(())
}

fn parse_content(purpose: Purpose, content: Value) -> Result<Content> {
    Ok(match purpose {
        Purpose::HttpAuthentication => {
            let c: HttpContent = serde_json::from_value(content).map_err(|_| invalid())?;
            validate_http(&c)?;
            Content::Http(c)
        }
        Purpose::OriginProof => {
            let c: OriginContent = serde_json::from_value(content).map_err(|_| invalid())?;
            validate_origin(&c)?;
            Content::Origin(c)
        }
        Purpose::PurposeSigning => {
            let c: PurposeContent = serde_json::from_value(content).map_err(|_| invalid())?;
            validate_names(&c.purposes, 16)?;
            Content::PurposeSigning(c)
        }
        Purpose::Ecdh => {
            let c: EcdhContent = serde_json::from_value(content).map_err(|_| invalid())?;
            if c.peers.is_empty()
                || c.peers.len() > 64
                || c.peers.iter().collect::<BTreeSet<_>>().len() != c.peers.len()
                || c.peers.iter().any(|peer| {
                    peer.len() != 64
                        || !peer
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
            {
                return Err(invalid());
            }
            Content::Ecdh(c)
        }
        Purpose::ObjectProof | Purpose::DocumentProof => {
            let c: ProofContent = serde_json::from_value(content).map_err(|_| invalid())?;
            validate_names(&c.proof_purposes, 8)?;
            Content::Proof((purpose, c))
        }
        Purpose::Root => {
            serde_json::from_value::<RootContent>(content).map_err(|_| invalid())?;
            Content::Root(RootContent {})
        }
    })
}

fn validate_names(names: &[String], max: usize) -> Result<()> {
    if names.is_empty()
        || names.len() > max
        || names.iter().collect::<BTreeSet<_>>().len() != names.len()
        || names.iter().any(|name| {
            name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        })
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_body(body: &Body) -> Result<()> {
    if !["empty", "bounded"].contains(&body.mode.as_str())
        || (body.mode == "empty" && body.max_bytes != 0)
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_http(p: &HttpContent) -> Result<()> {
    let authority = p.origin.strip_prefix("https://").ok_or_else(invalid)?;
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(h, p)| (h, Some(p)));
    if p.signature_profile != "anp-http-v2"
        || host.is_empty()
        || host.len() > 253
        || host.ends_with('.')
        || !host
            .rsplit('.')
            .next()
            .is_some_and(|s| s.bytes().all(|b| b.is_ascii_alphabetic()))
        || host.split('.').any(|s| {
            s.is_empty()
                || s.len() > 63
                || s.starts_with('-')
                || s.ends_with('-')
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        || port.is_some_and(|v| {
            v.parse::<u16>()
                .ok()
                .filter(|p| *p != 0 && *p != 443)
                .map(|p| p.to_string())
                != Some(v.to_owned())
        })
        || p.methods.is_empty()
        || p.methods.len() > 16
        || p.methods
            .iter()
            .any(|s| !HTTP_METHODS.contains(&s.as_str()))
        || p.methods.iter().collect::<BTreeSet<_>>().len() != p.methods.len()
        || p.paths.is_empty()
        || p.paths.len() > 64
        || p.paths.iter().collect::<BTreeSet<_>>().len() != p.paths.len()
        || p.paths.iter().any(|s| {
            !s.starts_with('/')
                || s.len() > 2048
                || s.contains("//")
                || s.split('/').any(|p| p == "." || p == "..")
                || s.bytes()
                    .any(|b| !crate::security::http::safe_target_byte(b))
        })
    {
        return Err(invalid());
    }
    validate_body(&p.body)?;
    if p.body.max_bytes > MAX_HTTP_BODY_BYTES {
        return Err(invalid());
    }
    if let Query::Exact { value } = &p.query {
        let mut keys = BTreeSet::new();
        if value.is_empty()
            || value.len() > 2048
            || value
                .bytes()
                .any(|b| !crate::security::http::safe_target_byte(b) || b == b'+' || b == b'\'')
            || value.split('&').any(|pair| {
                let (k, _) = pair.split_once('=').unwrap_or((pair, ""));
                k.is_empty() || !keys.insert(k)
            })
        {
            return Err(invalid());
        }
    }
    Ok(())
}

fn validate_origin(p: &OriginContent) -> Result<()> {
    let method_ok = |name: &String| {
        let b = name.as_bytes();
        !b.is_empty()
            && b.len() <= 64
            && b.iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(b))
    };
    if p.methods.is_empty()
        || p.methods.len() > 16
        || p.methods.iter().collect::<BTreeSet<_>>().len() != p.methods.len()
        || !p.methods.iter().all(method_ok)
        || p.target_kinds.is_empty()
        || p.target_kinds
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != p.target_kinds.len()
        || p.target_kinds
            .iter()
            .any(|kind| !TARGET_KINDS.contains(&kind.as_str()))
    {
        return Err(invalid());
    }
    validate_body(&p.body)?;
    // origin-proof 是新路:`bounded` 配 0 字节只会拒绝一切,直接不收。
    if p.body.mode == "bounded" && p.body.max_bytes == 0 {
        return Err(invalid());
    }
    if p.body.max_bytes as usize > MAX_CANONICAL_BYTES {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn parse(content: Value) -> Result<Policy> {
    match content.get("schema_version").and_then(Value::as_u64) {
        Some(1) => {
            let p: V1Policy = serde_json::from_value(content).map_err(|_| invalid())?;
            if p.purpose != "http-authentication" {
                return Err(invalid());
            }
            let content = HttpContent {
                origin: p.origin,
                methods: p.methods,
                paths: p.paths,
                query: p.query,
                body: p.body,
                signature_profile: p.signature_profile,
            };
            validate_http(&content)?;
            Ok(Policy {
                content: Content::Http(content),
                limits: Limits {
                    max_duration_seconds: p.grant_limits.max_duration_seconds,
                    max_uses: p.grant_limits.max_uses,
                    max_lifetime_seconds: p.grant_limits.max_duration_seconds,
                    max_renewals: 0,
                },
            })
        }
        Some(2) => {
            let p: V2Policy = serde_json::from_value(content).map_err(|_| invalid())?;
            validate_limits(&p.limits)?;
            let content = parse_content(p.purpose, p.content)?;
            Ok(Policy {
                content,
                limits: p.limits,
            })
        }
        _ => Err(invalid()),
    }
}

/// 一个规范化请求能不能落在这条策略里。
pub(super) fn evaluate_http(content: Value, request: &CanonicalHttpRequest) -> Result<()> {
    let p = parse(content)?;
    let Content::Http(h) = &p.content else {
        return Err(denied());
    };
    let query = match &h.query {
        Query::None {} => None,
        Query::Exact { value } => Some(value.as_str()),
    };
    if h.origin != request.origin()
        || !h.methods.contains(&request.method().to_owned())
        || !h.paths.contains(&request.path().to_owned())
        || query != request.query()
        || request.body_len() > h.body.max_bytes as usize
        || (h.body.mode == "empty" && request.body_len() != 0)
        || (h.body.mode == "bounded" && !request.has_body())
    {
        return Err(denied());
    }
    Ok(())
}

/// 一条 origin proof 能不能落在这条策略里。
pub(super) fn evaluate_origin(content: Value, proof: &OriginProof) -> Result<()> {
    let p = parse(content)?;
    let Content::Origin(o) = &p.content else {
        return Err(denied());
    };
    if !o.methods.iter().any(|m| m == proof.method())
        || !o.target_kinds.iter().any(|k| k == proof.target_kind())
        || proof.body_len() > o.body.max_bytes as usize
        || (o.body.mode == "empty" && !proof.is_empty_body())
        || (o.body.mode == "bounded" && proof.is_empty_body())
    {
        return Err(denied());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v1() -> Value {
        json!({"schema_version":1,"name":"read-orders","purpose":"http-authentication","origin":"https://service.example.com","methods":["GET"],"paths":["/v1/orders"],"query":{"mode":"none"},"body":{"mode":"empty","max_bytes":0},"signature_profile":"anp-http-v2","grant_limits":{"max_duration_seconds":900,"max_uses":100}})
    }

    fn v2(purpose: &str, content: Value) -> Value {
        json!({"schema_version":2,"name":"im-origin-proof","purpose":purpose,
               "limits":{"max_duration_seconds":900,"max_uses":1000,
                         "max_lifetime_seconds":86400,"max_renewals":16},
               "content":content})
    }

    fn origin_content() -> Value {
        json!({"methods":["direct.send"],"target_kinds":["agent"],
               "body":{"mode":"bounded","max_bytes":8192}})
    }

    /// v1 文档的规范化结果和以前逐字节一致。
    #[test]
    fn v1_normalization_is_unchanged() {
        let normalized = normalize(v1()).unwrap();
        assert_eq!(
            normalized,
            serde_json::to_value(serde_json::from_value::<V1Policy>(v1()).unwrap()).unwrap()
        );
        let policy = parse(normalized).unwrap();
        assert_eq!(policy.purpose(), Purpose::HttpAuthentication);
        // v1 的 grant 续不了:寿命上限就是时长上限,续期次数为 0。
        assert_eq!(policy.limits.max_lifetime_seconds, 900);
        assert_eq!(policy.limits.max_renewals, 0);
    }

    #[test]
    fn v2_round_trips_and_keeps_its_purpose() {
        let normalized = normalize(v2("origin-proof", origin_content())).unwrap();
        let policy = parse(normalized.clone()).unwrap();
        assert_eq!(policy.purpose(), Purpose::OriginProof);
        assert_eq!(policy.limits.max_renewals, 16);
        assert_eq!(normalize(normalized.clone()).unwrap(), normalized);
    }

    /// 每个 purpose 只认自己那套字段:夹带别人的字段就是非法。
    #[test]
    fn content_shapes_do_not_leak_across_purposes() {
        let wrong = origin_content();
        assert!(normalize(v2("http-authentication", wrong)).is_err());

        let mut with_origin = origin_content();
        with_origin["origin"] = json!("https://service.example.com");
        assert!(normalize(v2("origin-proof", with_origin)).is_err());

        assert!(normalize(v2("root", json!({}))).is_ok());
        assert!(normalize(v2("root", json!({"peers":[]}))).is_err());
    }

    #[test]
    fn origin_content_only_accepts_real_targets_and_methods() {
        for broken in [
            json!({"methods":[],"target_kinds":["agent"],"body":{"mode":"empty","max_bytes":0}}),
            json!({"methods":["Direct.Send"],"target_kinds":["agent"],"body":{"mode":"empty","max_bytes":0}}),
            json!({"methods":["direct.send"],"target_kinds":["robot"],"body":{"mode":"empty","max_bytes":0}}),
            json!({"methods":["direct.send"],"target_kinds":["agent"],"body":{"mode":"bounded","max_bytes":0}}),
            json!({"methods":["direct.send"],"target_kinds":["agent"],"body":{"mode":"bounded","max_bytes":65536}}),
        ] {
            assert!(normalize(v2("origin-proof", broken)).is_err());
        }
    }

    #[test]
    fn limits_cannot_promise_more_life_than_they_cost() {
        for limits in [
            json!({"max_duration_seconds":0,"max_uses":1,"max_lifetime_seconds":1,"max_renewals":0}),
            json!({"max_duration_seconds":900,"max_uses":0,"max_lifetime_seconds":900,"max_renewals":0}),
            json!({"max_duration_seconds":900,"max_uses":1,"max_lifetime_seconds":600,"max_renewals":0}),
            json!({"max_duration_seconds":900,"max_uses":1,"max_lifetime_seconds":900,"max_renewals":4096}),
        ] {
            let mut policy = v2("origin-proof", origin_content());
            policy["limits"] = limits;
            assert!(normalize(policy).is_err());
        }
    }

    #[test]
    fn ecdh_policy_carries_a_hex_peer_allowlist() {
        let peer = "aa".repeat(32);
        assert!(normalize(v2("ecdh", json!({"peers":[peer.clone()]}))).is_ok());
        assert!(normalize(v2("ecdh", json!({"peers":[]}))).is_err());
        assert!(normalize(v2("ecdh", json!({"peers":["AA".repeat(32)]}))).is_err());
        assert!(normalize(v2("ecdh", json!({"peers":["aa".repeat(31)]}))).is_err());
    }

    #[test]
    fn an_unknown_schema_version_is_not_silently_read_as_v1() {
        let mut policy = v1();
        policy["schema_version"] = json!(3);
        assert!(normalize(policy).is_err());
    }
}
