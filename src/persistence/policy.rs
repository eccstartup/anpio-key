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
// `PurposeSigning` 的前缀就是枚举名,但线上词是 `purpose-signing`,不为 lint 改。
#[allow(clippy::enum_variant_names)]
pub(super) enum Purpose {
    HttpAuthentication,
    OriginProof,
    PurposeSigning,
    Ecdh,
    ObjectProof,
    DocumentProof,
    Root,
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
/// 待签的对象是 `{method, meta, body}`,daemon 从 `meta.target.{kind,did}`
/// 拼出 logical target URI `anp://{kind}/{percent-encoded did}`,签名基里
/// `@target-uri` 就是它。所以这里按 URL 的样子收窄:`origin` 是
/// `anp://{kind}`, `paths` 里每一项是 URI 剩下的那一段(以 `/` 开头、
/// 后面是编码过的 DID);整项写 `*` 表示该类别的任意 DID。
/// `paths` 里的字节和待签 `@target-uri` 的后缀**逐字节**相等,不做模糊匹配。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginContent {
    origin: String,
    methods: Vec<String>,
    paths: Vec<String>,
    body: Body,
}

/// `*` 是 `paths` 里唯一的通配写法。
const WILDCARD_PATH: &str = "*";

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
///
/// 每个变体只由对应的 `evaluate_*` 求值:拿到别的变体就是拒绝,不是"差不多的
/// 策略也能用"。
#[allow(dead_code)]
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
            validate_proof_purposes(&c.proof_purposes, 8, purpose)?;
            Content::Proof((purpose, c))
        }
        Purpose::Root => {
            serde_json::from_value::<RootContent>(content).map_err(|_| invalid())?;
            Content::Root(RootContent {})
        }
    })
}

/// 文档 proof 能声明的 purpose。对象 proof 只用得上第一个 —— 上游把它写死成
/// `assertionMethod`,这条路上发不出别的。
const PROOF_PURPOSE_NAMES: [&str; 2] = ["assertionMethod", "authentication"];

fn proof_purposes_for(purpose: Purpose) -> &'static [&'static str] {
    match purpose {
        Purpose::ObjectProof => &PROOF_PURPOSE_NAMES[..1],
        _ => &PROOF_PURPOSE_NAMES,
    }
}

/// `proof_purposes` 用**自己的**词表,不是 [`validate_names`] 那套小写标识符:
/// 这些名字是 W3C 的 camelCase 术语,原样进签名基,大小写不能动。
///
/// 词表按 purpose 分开。对象策略里写 `authentication` 不是"更宽",而是写了
/// 一个这条路根本发不出来的东西 —— 拒掉,免得策略说一件做不到的事。
fn validate_proof_purposes(names: &[String], max: usize, purpose: Purpose) -> Result<()> {
    let allowed = proof_purposes_for(purpose);
    if names.is_empty()
        || names.len() > max
        || names.iter().collect::<BTreeSet<_>>().len() != names.len()
        || names.iter().any(|name| !allowed.contains(&name.as_str()))
    {
        return Err(invalid());
    }
    Ok(())
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
    let kind = p
        .origin
        .strip_prefix("anp://")
        .filter(|kind| TARGET_KINDS.contains(kind))
        .ok_or_else(invalid)?;
    if p.methods.is_empty()
        || p.methods.len() > 16
        || p.methods.iter().collect::<BTreeSet<_>>().len() != p.methods.len()
        || !p.methods.iter().all(method_ok)
        || p.paths.is_empty()
        || p.paths.len() > 64
        || p.paths.iter().collect::<BTreeSet<_>>().len() != p.paths.len()
        || (p.paths.len() > 1 && p.paths.iter().any(|path| path == WILDCARD_PATH))
        || !p
            .paths
            .iter()
            .all(|path| path == WILDCARD_PATH || valid_origin_path(kind, path))
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

/// 一条 path 是不是能将来的 `@target-uri` 后缀。
///
/// 校验办法是反着算:解出 DID,再用上游拼 logical target URI 的同一个函数
/// 重新编码,要求和策略里写下的 `origin + path` 逐字节相等。非规范编码
/// (比如小写 `%3a` 或不该编码的字符)在这里就被拒,不会变成一条发布时
/// 看起来正常、运行时永远匹配不上的策略。
fn valid_origin_path(kind: &str, path: &str) -> bool {
    let Some(encoded) = path.strip_prefix('/') else {
        return false;
    };
    let Some(did) = percent_encoding::percent_decode_str(encoded)
        .decode_utf8()
        .ok()
        .filter(|did| !did.is_empty() && did.len() <= 512 && !did.chars().any(char::is_control))
    else {
        return false;
    };
    let Ok(target_kind) = anp::proof::TargetKind::try_from(kind) else {
        return false;
    };
    let Ok(uri) = anp::proof::build_logical_target_uri(target_kind, &did) else {
        return false;
    };
    uri.strip_prefix("anp://")
        .and_then(|rest| rest.strip_prefix(kind))
        == Some(path)
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
    // 待签 `@target-uri` 用 daemon 拼签名基的同一个函数算,再把策略的
    // `origin` 剥掉得到 suffix:匹配的就是签名基里那几个字节,不是另算一套。
    let kind = anp::proof::TargetKind::try_from(proof.target_kind()).map_err(|_| denied())?;
    let target =
        anp::proof::build_logical_target_uri(kind, proof.target_did()).map_err(|_| denied())?;
    let path = target
        .strip_prefix(&o.origin)
        .filter(|path| path.starts_with('/'))
        .ok_or_else(denied)?;
    if !o.methods.iter().any(|m| m == proof.method())
        || !o
            .paths
            .iter()
            .any(|allowed| allowed == WILDCARD_PATH || allowed == path)
        || proof.body_len() > o.body.max_bytes as usize
        || (o.body.mode == "empty" && !proof.is_empty_body())
        || (o.body.mode == "bounded" && proof.is_empty_body())
    {
        return Err(denied());
    }
    Ok(())
}

/// 一个 `SIGN_PURPOSE` 的 purpose 标签能不能落在这条策略里。标签是签名基的
/// 一部分,不在白名单里就等于换了一个请求形状,直接拒。
pub(super) fn evaluate_signing(content: Value, purpose: &str) -> Result<()> {
    let p = parse(content)?;
    let Content::PurposeSigning(s) = &p.content else {
        return Err(denied());
    };
    if !s.purposes.iter().any(|name| name == purpose) {
        return Err(denied());
    }
    Ok(())
}

/// 一次 ECDH 的 peer 能不能落在这条策略里。白名单是 32 字节公钥的**逐字节**
/// 比对:没有通配、没有前缀、没有曲线之外的等价写法。
pub(super) fn evaluate_ecdh(content: Value, peer: &[u8; 32]) -> Result<()> {
    let p = parse(content)?;
    let Content::Ecdh(e) = &p.content else {
        return Err(denied());
    };
    let hex: String = peer.iter().map(|b| format!("{b:02x}")).collect();
    if !e.peers.iter().any(|allowed| allowed == &hex) {
        return Err(denied());
    }
    Ok(())
}

/// 一次对象/文档 proof 的 purpose 能不能落在这条策略里。
///
/// 两道都要过:策略的 purpose 得就是这一种(对象策略不能被文档请求借用),
/// 请求的 purpose 得在策略声明的名单里。
pub(super) fn evaluate_proof(content: Value, purpose: Purpose, requested: &str) -> Result<()> {
    let p = parse(content)?;
    let Content::Proof((declared, c)) = &p.content else {
        return Err(denied());
    };
    if *declared != purpose || !c.proof_purposes.iter().any(|name| name == requested) {
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
        json!({"origin":"anp://agent","methods":["direct.send"],"paths":["*"],
               "body":{"mode":"bounded","max_bytes":8192}})
    }

    /// 一条 path 在策略里长什么样:和 daemon 拼的 `@target-uri` 同一个后缀。
    fn origin_path(kind: &str, did: &str) -> String {
        let uri = anp::proof::build_logical_target_uri(
            anp::proof::TargetKind::try_from(kind).unwrap(),
            did,
        )
        .unwrap();
        uri.strip_prefix(&format!("anp://{kind}"))
            .unwrap()
            .to_owned()
    }

    fn origin_proof(kind: &str, did: &str) -> OriginProof {
        crate::security::origin::OriginProofRequest {
            method: "direct.send".into(),
            meta: json!({"target":{"kind":kind,"did":did}}),
            body: json!({"text":"hi"}),
            expires: None,
            nonce: None,
        }
        .validate(1_000)
        .unwrap()
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

        let mut with_old_shape = origin_content();
        with_old_shape["target_kinds"] = json!(["agent"]);
        assert!(normalize(v2("origin-proof", with_old_shape)).is_err());

        assert!(normalize(v2("root", json!({}))).is_ok());
        assert!(normalize(v2("root", json!({"peers":[]}))).is_err());
    }

    #[test]
    fn origin_content_only_accepts_real_targets_and_methods() {
        let body = || json!({"mode":"bounded","max_bytes":8192});
        let path = origin_path("agent", "did:wba:example.com:agent:alice");
        for broken in [
            json!({"origin":"anp://agent","methods":[],"paths":["*"],"body":body()}),
            json!({"origin":"anp://agent","methods":["Direct.Send"],"paths":["*"],"body":body()}),
            // origin 只认 origin proof 的那三种 kind,且拼法必须完全一样。
            json!({"origin":"anp://robot","methods":["direct.send"],"paths":["*"],"body":body()}),
            json!({"origin":"https://service.example.com","methods":["direct.send"],"paths":["*"],"body":body()}),
            json!({"origin":"anp://agent/","methods":["direct.send"],"paths":["*"],"body":body()}),
            // 旧的 target_kinds 形状不能再回来。
            json!({"methods":["direct.send"],"target_kinds":["agent"],"body":body()}),
            // path 必须是以 `/` 开头的规范编码 DID。
            json!({"origin":"anp://agent","methods":["direct.send"],"paths":[],"body":body()}),
            json!({"origin":"anp://agent","methods":["direct.send"],
                   "paths":[path.trim_start_matches('/')],"body":body()}),
            json!({"origin":"anp://agent","methods":["direct.send"],
                   "paths":["/did:wba:example.com:agent:alice"],"body":body()}),
            json!({"origin":"anp://agent","methods":["direct.send"],
                   "paths":["/did%3awba%3Aexample.com%3Aagent%3Aalice"],"body":body()}),
            // 通配符和具体 DID 摆在一起就还是没收窄;重复项也是笔误。
            json!({"origin":"anp://agent","methods":["direct.send"],"paths":["*",path],"body":body()}),
            json!({"origin":"anp://agent","methods":["direct.send"],"paths":[path,path],"body":body()}),
            json!({"origin":"anp://agent","methods":["direct.send"],"paths":["*"],
                   "body":{"mode":"bounded","max_bytes":0}}),
            json!({"origin":"anp://agent","methods":["direct.send"],"paths":["*"],
                   "body":{"mode":"bounded","max_bytes":65536}}),
        ] {
            assert!(
                normalize(v2("origin-proof", broken.clone())).is_err(),
                "{broken} should be refused"
            );
        }
    }

    /// origin 收窄到 kind 还是收窄到一个 DID,判定都对着签名基里的
    /// `@target-uri` 那段字节,不是另算一套比较。
    #[test]
    fn origin_policy_narrows_to_a_kind_or_one_did() {
        let alice = "did:wba:example.com:agent:alice";
        let bob = "did:wba:example.com:agent:bob";
        let any_agent = v2("origin-proof", origin_content());
        assert!(evaluate_origin(any_agent.clone(), &origin_proof("agent", alice)).is_ok());
        assert!(evaluate_origin(any_agent.clone(), &origin_proof("agent", bob)).is_ok());
        // 通配符只在一条 path 里:`*` 说的是"这个 origin 的任意 DID",
        // 不会把别的 kind 也放进来。
        assert!(evaluate_origin(any_agent.clone(), &origin_proof("group", alice)).is_err());
        assert!(evaluate_origin(any_agent, &origin_proof("service", alice)).is_err());

        let mut narrowed = origin_content();
        narrowed["paths"] = json!([origin_path("agent", bob)]);
        let only_bob = v2("origin-proof", narrowed);
        assert!(evaluate_origin(only_bob.clone(), &origin_proof("agent", bob)).is_ok());
        assert!(evaluate_origin(only_bob.clone(), &origin_proof("agent", alice)).is_err());
        // 只收窄到 DID 并不放宽 kind:同一个 DID 字符串换个 kind 就是另一个目标。
        assert!(evaluate_origin(only_bob, &origin_proof("group", bob)).is_err());
        // 方法名和 body 上限照旧各自把关。
        let mut other_method = origin_content();
        other_method["methods"] = json!(["direct.ack"]);
        assert!(evaluate_origin(
            v2("origin-proof", other_method),
            &origin_proof("agent", bob)
        )
        .is_err());
        let mut tiny = origin_content();
        tiny["body"] = json!({"mode":"bounded","max_bytes":4});
        assert!(evaluate_origin(v2("origin-proof", tiny), &origin_proof("agent", bob)).is_err());
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
    fn purpose_signing_only_admits_the_listed_tags() {
        let content = json!({"purposes":["device_assertion"]});
        let policy = v2("purpose-signing", content.clone());
        assert!(normalize(policy.clone()).is_ok());
        assert!(evaluate_signing(policy.clone(), "device_assertion").is_ok());
        assert!(evaluate_signing(policy.clone(), "application_assertion").is_err());
        // 换一个 purpose 的策略不认 signing 标签,哪怕 content 形状碰巧一样。
        assert!(
            evaluate_signing(v2("origin-proof", origin_content()), "device_assertion").is_err()
        );
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
    fn proof_policies_name_w3c_purposes_and_nothing_else() {
        // camelCase 是规范里的写法,策略原样收;小写会被拒 —— 那是另一个字符串。
        assert!(normalize(v2("document-proof", json!({"proof_purposes":["assertionMethod"]}))).is_ok());
        assert!(normalize(v2(
            "document-proof",
            json!({"proof_purposes":["authentication","assertionMethod"]})
        ))
        .is_ok());
        assert!(normalize(v2("document-proof", json!({"proof_purposes":[]}))).is_err());
        assert!(normalize(v2("document-proof", json!({"proof_purposes":["assertionmethod"]}))).is_err());
        assert!(normalize(v2(
            "document-proof",
            json!({"proof_purposes":["assertionMethod","assertionMethod"]})
        ))
        .is_err());

        // 对象 proof 只有 assertionMethod 这一种,写别的等于承诺一件做不到的事。
        assert!(
            normalize(v2("object-proof", json!({"proof_purposes":["assertionMethod"]}))).is_ok()
        );
        assert!(normalize(v2("object-proof", json!({"proof_purposes":["authentication"]}))).is_err());
        assert!(normalize(v2(
            "object-proof",
            json!({"proof_purposes":["assertionMethod","authentication"]})
        ))
        .is_err());
    }

    #[test]
    fn a_proof_request_must_match_both_the_purpose_and_the_list() {
        let object = v2("object-proof", json!({"proof_purposes":["assertionMethod"]}));
        assert!(evaluate_proof(object.clone(), Purpose::ObjectProof, "assertionMethod").is_ok());
        assert!(evaluate_proof(object.clone(), Purpose::ObjectProof, "authentication").is_err());
        // 对象策略不能被文档请求借用。
        assert!(evaluate_proof(object, Purpose::DocumentProof, "assertionMethod").is_err());

        let document = v2("document-proof", json!({"proof_purposes":["assertionMethod"]}));
        assert!(
            evaluate_proof(document.clone(), Purpose::DocumentProof, "assertionMethod").is_ok()
        );
        assert!(evaluate_proof(document, Purpose::DocumentProof, "authentication").is_err());
        // 换了 purpose 但 content 形状一样的策略也不认。
        assert!(evaluate_proof(
            v2("origin-proof", origin_content()),
            Purpose::DocumentProof,
            "assertionMethod"
        )
        .is_err());
    }

    #[test]
    fn an_unknown_schema_version_is_not_silently_read_as_v1() {
        let mut policy = v1();
        policy["schema_version"] = json!(3);
        assert!(normalize(policy).is_err());
    }
}
