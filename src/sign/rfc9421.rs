//! RFC 9421 HTTP 消息签名 —— **由守护进程决定签什么**。
//!
//! 这个模块是"agent 手里从来没有私钥字节"这句话最容易被架空的地方。
//! 光是不给私钥不够:如果 agent 能挑「这条签名覆盖哪些分量」,它就能让守护
//! 进程签一条只覆盖 `@method` 的签名,拿去配一个完全不同的 body 和 URL ——
//! 私钥没泄露,但签名被用在了别处。这就是盲目签名。
//!
//! 所以这里的规矩是:
//!
//! 1. **覆盖面有一个下限,由 [`required_components`] 决定,不接受调用方输入。**
//!    调用方可以要求**多**覆盖几个分量(有些 API 就要求签名里带上
//!    `content-type`),但**不可能少覆盖任何一个** —— 见 [`SignRequest::covered`]。
//! 2. 请求里凡是会进入签名基的东西(方法、URL、头值)先过一遍边界校验 ——
//!    签名基是**按行**拼的,一个带 `\n` 的头值能凭空插进一行
//!    `"@authority": evil.com`,那就等于把覆盖面让给了调用方。
//! 3. 拼完之后**再从签名基里把覆盖面解析回来**,确认它真的是我们要的那一组。
//!    这一步不信任上游,也不信任我们自己的调用参数。

use std::collections::BTreeMap;

use serde_json::Value;

use crate::crypto::sha256;
use crate::error::{KeydError, Result};
use crate::sign::{LockedSigningKey, Signer};

/// 一条待签的 HTTP 请求。
#[derive(Debug, Clone, Default)]
pub struct SignRequest {
    /// HTTP 方法,如 `POST`、`GET`。
    pub method: String,
    /// 完整的请求 URL(`@target-uri` 就是它)。
    pub url: String,
    pub headers: BTreeMap<String, String>,
    /// 请求体。给了就一定会覆盖 `content-digest`。
    pub body: Option<Vec<u8>>,
    /// 调用方**额外**要求覆盖的分量,小写。
    ///
    /// 这个字段只会让覆盖面**变大**。有些服务端要求签名里必须带上
    /// `content-type`,或者要求覆盖某个自定义头,那时调用方需要能说
    /// "请把这个也签上"。
    ///
    /// 但它**减不掉** [`required_components`] 里的任何一个 —— 那里的四个是
    /// 下限,谁说话都不好使。所以这里不是一个"调用方决定覆盖面"的口子,
    /// 只是"调用方可以请求得更严"。
    pub covered: Vec<String>,
    /// 调用方指定的 nonce。`None` = 由上游随机生成一个。
    ///
    /// **它和 `covered` 是反着来的**:`covered` 只能让签名保护得更多,
    /// 而这个只能让这次签名**是调用方要的那一次**。
    ///
    /// 为什么它得由调用方给、不能由守护进程自己挑,见 `docs/ADAPTER.md` §3.1:
    /// 它同时出现在请求体和签名基里,而**两处必须是同一个值**,所以挑的人
    /// 只能是那个能看到请求体的人。它在 401 之后还会换一次,换的值来自服务端
    /// —— 那是网络状态机的一部分,守护进程看不到。
    ///
    /// **守护进程管长度和"能不能写进去",不管含义。** 见 [`validate_nonce`]。
    pub nonce: Option<String>,
}

/// 调用方指定的 nonce 的上限,按字节算。
///
/// nonce 进签名基,**它的长度就是签名基的长度** —— 所以有一条上限。256 比
/// 任何会真实出现的挑战都宽得多(base64url 编 32 字节才 43 个字符),又不至于
/// 让一条签名请求变成一次任意长度的写入。
pub const MAX_NONCE_LEN: usize = 256;

/// 签完之后的产物。
#[derive(Debug, Clone)]
pub struct Signed {
    pub created_at: Option<i64>,
    /// Explicit service-selected expiry; absent for the legacy profile.
    pub expires_at: Option<i64>,
    /// 要加到请求上的头:`Signature-Input`、`Signature`,有 body 时还有 `Content-Digest`。
    pub headers: BTreeMap<String, String>,
    /// **实际**被覆盖的分量,从签名基里解析回来的。
    pub covered: Vec<String>,
    /// 签名基的 SHA-256 —— 审计日志记这个,不记签名基本身。
    pub signature_base_digest: [u8; 32],
}

/// 守护进程要求覆盖的最小集合。
///
/// 少了 `@method`,签名可以被换成另一个方法;少了 `@target-uri`,可以被换成
/// 另一个资源;少了 `@authority`,可以被换成另一个服务。有 body 时少了
/// `content-digest`,签名就和 body 脱钩了,body 可以随便换。
///
/// 这是一个**下限**,不随调用方的意愿变。
pub fn required_components(req: &SignRequest) -> Vec<String> {
    let mut components = vec![
        "@method".to_string(),
        "@target-uri".to_string(),
        "@authority".to_string(),
    ];
    if req.body.is_some() {
        components.push("content-digest".to_string());
    }
    components
}

impl SignRequest {
    /// 进入签名基之前必须过的那一关。
    pub fn validate(&self) -> Result<()> {
        validate_method(&self.method)?;
        validate_url(&self.url)?;
        if let Some(nonce) = &self.nonce {
            validate_nonce(nonce)?;
        }
        for (name, value) in &self.headers {
            validate_header_name(name)?;
            validate_header_value(name, value)?;
        }
        for component in &self.covered {
            validate_covered_component(component)?;
            // 要求覆盖一个请求里根本没有的头,是调用方的错,不该等到上游
            // 报一句 "Invalid signature input" 才知道。
            if !self.headers.keys().any(|name| name.eq_ignore_ascii_case(component)) {
                return Err(KeydError::CoveredSetRejected(format!(
                    "{component:?} was asked for but the request carries no such header"
                )));
            }
        }
        self.validate_content_digest()
    }

    /// 请求体的摘要必须是**守护进程自己算的**。
    ///
    /// 上游的 `prepare_http_signature_headers` 往头表里填 `Content-Digest`
    /// 用的是 `or_insert_with` —— 调用方要是预先塞了一个,上游就会照着那个
    /// 值去签,而那个值和真实请求体可以毫无关系。上游的 verifier 会重算摘要
    /// 从而发现不一致,但不是每个验签方都会这么做;只信签名、不核对 body 的
    /// 验签方就会中招。
    fn validate_content_digest(&self) -> Result<()> {
        let Some((name, supplied)) = self
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-digest"))
        else {
            return Ok(());
        };

        let Some(body) = &self.body else {
            return Err(KeydError::Protocol(format!(
                "header {name:?} is present but there is no body; a digest the daemon did not \
                 compute itself must never reach the signature base"
            )));
        };

        let actual = anp::authentication::build_content_digest(body);
        if supplied.trim() != actual {
            return Err(KeydError::Protocol(format!(
                "the supplied Content-Digest does not match the request body, which hashes to {actual}"
            )));
        }
        Ok(())
    }
}

/// 签一条请求。
///
/// 顺序是刻意的:先校验输入 → 定覆盖面 → 让上游拼基 → **把覆盖面解析回来核对**
/// → 才把字节递给私钥。私钥一签,就再也没有回头路了。
pub fn sign_request(
    document: &Value,
    key: &LockedSigningKey,
    req: &SignRequest,
) -> Result<Signed> {
    sign_request_with_window(document, key, req, None)
}

/// Internal profile entry point: only the trusted executor supplies timestamps.
/// A grant deadline must be converted to a non-extending wall deadline by it.
pub(crate) fn sign_request_with_window(
    document: &Value,
    key: &LockedSigningKey,
    req: &SignRequest,
    window: Option<(i64, i64)>,
) -> Result<Signed> {
    if window.is_some_and(|(created, expires)| created < 0 || expires <= created) {
        return Err(KeydError::Protocol("invalid signature validity window".into()));
    }
    req.validate()?;
    let required = required_components(req);

    // 下限 ∪ 调用方要求的。顺序是先下限,调用方只能往后加。
    let mut wanted = required.clone();
    for component in &req.covered {
        if !wanted.iter().any(|w| w.eq_ignore_ascii_case(component)) {
            wanted.push(component.clone());
        }
    }

    // 把调用方的 `Content-Digest` 摘掉,让上游按**我们自己**看到的 body 重新算。
    // 上面已经校验过它和 body 一致,所以摘掉不会改变结果 —— 但它从此不再可能
    // 是一条由调用方选定的值。
    let mut headers = req.headers.clone();
    headers.retain(|name, _| !name.eq_ignore_ascii_case("content-digest"));

    // 送进上游的是**规范化之后**的 URL。签名基里 `@authority` 和 `@target-uri`
    // 都出自这一个字符串,所以在这里换一次,两个分量一起正 —— 见
    // [`normalized_target_uri`]。
    let target_uri = normalized_target_uri(&req.url);

    let prepared = anp::authentication::prepare_http_signature_headers(
        document,
        &target_uri,
        &req.method,
        Some(&headers),
        req.body.as_deref(),
        anp::authentication::HttpSignatureOptions {
            keyid: Some(key.id().kid.clone()),
            // 调用方给的 nonce 原样交上去;没给就是 `None`,上游自己随机一个
            // (今天的行为不变)。它不是"签什么内容"的一部分,是"这是哪一次
            // 签名"的一部分 —— 所以它是**被签的**,调用方改它最多让自己那条
            // 签名对不上服务端的挑战。见 `docs/ADAPTER.md` §3.1。
            nonce: req.nonce.clone(),
            created: window.map(|v| v.0),
            expires: window.map(|v| v.1),
            // 这里就是"守护进程决定"落到实处的地方 —— 这个值不是调用方给的,
            // 调用方最多只能让它变大。
            covered_components: Some(wanted.clone()),
        },
    )
    .map_err(|e| KeydError::Upstream(format!("preparing the HTTP signature failed: {e}")))?;

    let signature_base = prepared.signing_input();
    let signature_base_text = std::str::from_utf8(signature_base)
        .map_err(|_| KeydError::Protocol("the signature base is not valid UTF-8".into()))?;

    // 在签名**之前**核对:签名基里真正被覆盖的,必须包含我们要的那一组
    // (含调用方额外要求的那几个 —— 要求了却没覆盖上,宁可现在失败)。
    let covered = verify_covered_set(signature_base_text, &wanted)?;
    let signature_base_digest = sha256(signature_base);

    let signature = key.sign(signature_base)?;

    // `complete_http_signature_headers` 会拿文档里的公钥先验一遍我们刚签出来的
    // 签名。签错钥匙这种事在这一步当场炸掉,不会流出去。
    let headers = anp::authentication::complete_http_signature_headers(prepared, &signature)
        .map_err(|e| KeydError::Upstream(format!("completing the HTTP signature failed: {e}")))?;

    Ok(Signed {
        created_at: window.map(|v|v.0),
        expires_at: window.map(|v|v.1),
        headers,
        covered,
        signature_base_digest,
    })
}

/// 从签名基里把**实际**被覆盖的分量解析回来,并确认 `required` 全在里面。
///
/// 解析的是 `@signature-params` 那一行括号里的列表 —— RFC 9421 规定它就是
/// 覆盖面的权威声明。另外核对每个列出来的分量在基里都真有对应的一行,免得
/// 出现「声称覆盖了、其实没写进去」。
pub fn verify_covered_set(signature_base: &str, required: &[String]) -> Result<Vec<String>> {
    let covered = covered_components(signature_base)?;

    for want in required {
        if !covered.iter().any(|c| c.eq_ignore_ascii_case(want)) {
            return Err(KeydError::CoveredSetRejected(format!(
                "{want} is missing from the covered set; \
                 a signature that does not cover it can be replayed against another request"
            )));
        }
    }

    // 已被覆盖的分量必须在基里有自己那一行 —— 否则基是残缺的。
    let present = base_line_components(signature_base);
    for component in &covered {
        if !present.iter().any(|p| p.eq_ignore_ascii_case(component)) {
            return Err(KeydError::CoveredSetRejected(format!(
                "{component} is listed as covered but has no line in the signature base"
            )));
        }
    }

    Ok(covered)
}

/// 解析签名基里 `@signature-params` 的括号列表。
fn covered_components(signature_base: &str) -> Result<Vec<String>> {
    let params_line = signature_base
        .lines()
        .find(|line| line.starts_with("\"@signature-params\":"))
        .ok_or_else(|| {
            KeydError::CoveredSetRejected("the signature base has no @signature-params line".into())
        })?;

    let list = params_line
        .split_once('(')
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(inner, _)| inner)
        .ok_or_else(|| {
            KeydError::CoveredSetRejected("the @signature-params line has no component list".into())
        })?;

    let parsed = parse_component_list(list)?;
    if parsed.is_empty() {
        return Err(KeydError::CoveredSetRejected(
            "the signature covers nothing at all".into(),
        ));
    }
    Ok(parsed)
}

/// `"@method" "@authority" "content-digest";sf` → `["@method", "@authority", "content-digest"]`
///
/// 分量后面可以跟参数(如 `;sf`、`;key="x"`),但这里只关心分量本身。
fn parse_component_list(list: &str) -> Result<Vec<String>> {
    let bytes = list.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if bytes[i] != b'"' {
            return Err(KeydError::CoveredSetRejected(format!(
                "malformed component list at byte {i}: expected a quoted component id"
            )));
        }
        i += 1;
        let start = i;
        while i < bytes.len() && bytes[i] != b'"' {
            i += 1;
        }
        if i >= bytes.len() {
            return Err(KeydError::CoveredSetRejected(
                "unterminated component id in the signature params".into(),
            ));
        }
        // 引号都是 ASCII,所以这里一定切在字符边界上。
        out.push(list[start..i].to_string());
        i += 1;
        // 跳过分量后面的参数,吃到下一个**不在引号里**的空白为止。
        // 参数值可以是带空格的引号串(`;key="a b"`),所以不能只找空白。
        while i < bytes.len() {
            match bytes[i] {
                b if b.is_ascii_whitespace() => break,
                b'"' => {
                    i += 1;
                    while i < bytes.len() && bytes[i] != b'"' {
                        i += 1;
                    }
                    if i < bytes.len() {
                        i += 1;
                    }
                }
                _ => i += 1,
            }
        }
    }

    Ok(out)
}

/// 基里每一行的分量名(不含 `@signature-params` 那行)。
fn base_line_components(signature_base: &str) -> Vec<String> {
    signature_base
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix('"')?;
            let (name, _) = rest.split_once("\":")?;
            Some(name.to_string())
        })
        .collect()
}

/// RFC 7230 的 token 字符集。
fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^'
                        | b'_' | b'`' | b'|' | b'~'
                )
        })
}

/// 有控制字符就会破坏"一行一个分量"的签名基结构。
fn has_control_characters(s: &str) -> bool {
    s.chars().any(|c| c.is_control() || c == '\u{7f}')
}

fn validate_method(method: &str) -> Result<()> {
    if !method.bytes().all(|b| b.is_ascii_uppercase()) || !is_token(method) {
        return Err(KeydError::Protocol(format!(
            "{method:?} is not an uppercase HTTP method token"
        )));
    }
    Ok(())
}

fn validate_url(url: &str) -> Result<()> {
    if has_control_characters(url) {
        return Err(KeydError::Protocol(
            "the request URL contains control characters".into(),
        ));
    }
    if url.contains(' ') {
        return Err(KeydError::Protocol(
            "the request URL contains a space; it must be percent-encoded".into(),
        ));
    }
    if !url.starts_with("https://") {
        // did:wba 是绑在域名上的身份,明文 HTTP 上没有任何意义。
        return Err(KeydError::Protocol(format!(
            "refusing to sign a non-HTTPS request URL: {url:?}"
        )));
    }
    let authority = split_authority(url).map_or("", |(authority, _)| authority);
    if authority.is_empty() {
        return Err(KeydError::Protocol(format!(
            "the request URL has no authority: {url:?}"
        )));
    }
    // 带 userinfo 的 URL 会让 `@authority` 的抽取结果和用户的直觉不一致。
    if authority.contains('@') {
        return Err(KeydError::Protocol(format!(
            "the request URL carries userinfo, which is not signed as part of @authority: {url:?}"
        )));
    }
    Ok(())
}

/// 把 URL 切成「authority」和「其余」两段。`https://` 之外没 authority。
fn split_authority(url: &str) -> Option<(&str, &str)> {
    let rest = url.strip_prefix("https://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Some((&rest[..end], &rest[end..]))
}

/// 把 URL 规范成**一个 URL 解析器会写出来的那个样子**,其余字节原样。
///
/// 只有两处改动,而且都在 authority 里:**host 归一成小写**,**默认端口去掉**
/// (`:443`,空端口也算)。这两处之外一个字节都不碰 —— path、query、fragment
/// 原样。
///
/// **为什么非改不可。** 被签的是 `@authority` 和 `@target-uri`,而验签方那边是
/// **自己解析 URL 重新算一遍**的:awiki 的服务端拿它配的 `public_base_url` 拼出
/// URL 再切 netloc;connectx / anp-sdk 那侧是 `new URL(url).host` 和 `url.href`。
/// 两边算出来的都是小写 host、不带默认端口的那一份。所以调用方写
/// `https://Example.com:443/x` 时,照字面签出来的签名**一定验不过** —— 而报错
/// 会是"签名无效",把人指向钥匙,而不是指向 URL。
///
/// 上游 `anp` 自己就分岔在这个点上:`network` 那支走 `url` crate(就是下面这个
/// 规则),无网络那支按文本切、把 `:443` 留着。守护进程走的是后者,这一层补的
/// 就是那个差。它是 RFC 3986 §6.2.2.1 / §6.2.3 的规范化,不是改意思。
pub fn normalized_target_uri(url: &str) -> String {
    let Some((authority, rest)) = split_authority(url) else {
        return url.to_string();
    };
    format!("https://{}{rest}", normalize_authority(authority))
}

/// authority 的规范形式,见 [`normalized_target_uri`]。
fn normalize_authority(authority: &str) -> String {
    let lower = authority.to_ascii_lowercase();
    // `[::1]` 里也有冒号,所以只有"冒号后面全是数字"的那一截才算端口。
    let Some((host, port)) = lower.rsplit_once(':') else {
        return lower;
    };
    if !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return lower;
    }
    if port.is_empty() || port == "443" {
        return host.to_string();
    }
    lower
}

fn validate_header_name(name: &str) -> Result<()> {
    if !is_token(name) {
        return Err(KeydError::Protocol(format!(
            "{name:?} is not a valid HTTP header name"
        )));
    }
    Ok(())
}

/// 头值里的换行会**伪造出一整行签名基**。
///
/// 签名基是按行拼的,一行形如 `"名字": 值`。一个值为
/// `x\r\n"@authority": evil.com` 的头能插进一行假的 `@authority`,
/// 于是"覆盖了 @authority"这句话就变成假的 —— 覆盖面被调用方拿到了。
fn validate_header_value(name: &str, value: &str) -> Result<()> {
    if value.contains('\r') || value.contains('\n') {
        return Err(KeydError::Protocol(format!(
            "header {name:?} contains a line break; it would forge signature base lines"
        )));
    }
    if has_control_characters(value) {
        return Err(KeydError::Protocol(format!(
            "header {name:?} contains control characters"
        )));
    }
    Ok(())
}

/// 调用方给的 nonce 必须能**原样**活到签名基里。
///
/// 上游把它拼成 `nonce="<值>"` 塞进 `@signature-params` 那一行,而且
/// **一个字符都不转义**(`anp` 的 `serialize_signature_params` 就是一句
/// `format!("nonce=\"{}\"", value)`)。所以这个值里出现一个 `"`,就能提前
/// 合上引号、往那条结构化字段列表里再塞一段 —— 例如重写 `keyid`;出现一个
/// 换行,就能凭空补出一整行签名基。和 [`validate_header_value`] 挡的是同一类
/// 事,只是入口换了一个。
///
/// **这里管的是"能不能写进签名基",不是"含义对不对"。** 这个 nonce 是不是
/// 服务端发的、有没有过期、是不是重放,守护进程一概不问 —— 那是服务端的事,
/// 一个替人保管私钥的进程去"理解"挑战正是 `docs/ADAPTER.md` §一 要防的越界。
/// 所以下面只排除**结构上有破坏性**的字节,不缩小它作为一串不透明字节的取值
/// 空间:可见 ASCII(空格也算),去掉引号和反斜杠,就是全部规则。
fn validate_nonce(nonce: &str) -> Result<()> {
    if nonce.len() > MAX_NONCE_LEN {
        return Err(KeydError::Protocol(format!(
            "the nonce is {} bytes, over the {MAX_NONCE_LEN}-byte limit; it goes into the \
             signature base, so its length becomes the signature base's length",
            nonce.len()
        )));
    }

    if let Some(bad) = nonce
        .bytes()
        .find(|byte| !(0x20..=0x7e).contains(byte) || *byte == b'"' || *byte == b'\\')
    {
        return Err(KeydError::Protocol(format!(
            "the nonce contains {bad:#04x}, which cannot be written into the \
             @signature-params line as it stands — a quote or a backslash escapes it, and a \
             control character forges a whole line of the signature base"
        )));
    }

    Ok(())
}

/// 调用方额外要求覆盖的分量,只能是这个形状。
///
/// 收得这么紧是因为这个字符串会**原样进入 `@signature-params` 那一行的括号里**。
/// 那里是个结构化字段列表:引号、逗号、分号、括号、空白都是它的结构字符。
/// 放一个这样的字符进来,就等于让调用方去改写那条列表 —— 而那条列表正是
/// 覆盖面的权威声明。参数(`;sf` 之类)也因此一并拒绝:支持它得先有一个
/// 真正解析结构化字段的解析器,而不是把字符串拼进去。
///
/// **只能加字段分量(头名),不能加派生分量。** 需要参数的派生分量
/// (`@query-param";name="x"`)在我们这里没有参数可给,而不需要参数的那三个
/// (`@method`/`@target-uri`/`@authority`)本来就在下限里,加了也是重复。
fn validate_covered_component(component: &str) -> Result<()> {
    if component.starts_with('@') {
        return Err(KeydError::CoveredSetRejected(format!(
            "{component:?}: derived components cannot be requested by the caller; the ones that \
             matter are already mandatory, and the rest need parameters this protocol does not carry"
        )));
    }

    if component.is_empty()
        || !component
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(KeydError::CoveredSetRejected(format!(
            "{component:?} is not a plain lowercase component name; parameters and quoting are \
             not accepted here"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hygiene::LockedBytes;
    use crate::did::document::{build_unsigned, sign_document, DidDocumentSpec};
    use crate::keystore::record::KeyId;

    fn key(seed_byte: u8) -> LockedSigningKey {
        let seed = LockedBytes::fill(|d| *d = [seed_byte; 32]).unwrap();
        LockedSigningKey::from_seed(
            KeyId { did: String::new(), kid: String::new(), thumbprint: String::new() },
            seed,
        )
        .unwrap()
    }

    /// 造一把钥匙 + 它自己的(已签名)文档 —— 上游要文档来查 keyid 的授权。
    fn fixture(seed_byte: u8) -> (LockedSigningKey, Value) {
        let k = key(seed_byte);
        let spec = DidDocumentSpec::new("example.com", vec!["user".into(), "alice".into()]);
        let (did, unsigned) = build_unsigned(&spec, &k.verifying_key().unwrap()).unwrap();
        let signed = sign_document(&unsigned, &k, &format!("{did}#key-1")).unwrap();

        // 文档必须是自洽的,否则后面测的就不是签名逻辑了。
        crate::did::document::verify_path_binding(&did, &signed).unwrap();

        // 把 kid 补成文档里的那个 —— fixture 里先造了空 id。
        let seed = LockedBytes::fill(|d| *d = [seed_byte; 32]).unwrap();
        let with_id = LockedSigningKey::from_seed(
            KeyId {
                did: did.clone(),
                kid: format!("{did}#key-1"),
                thumbprint: did.rsplit(':').next().unwrap().to_string(),
            },
            seed,
        )
        .unwrap();
        assert_eq!(with_id.public_multibase(), signed["verificationMethod"][0]["publicKeyMultibase"]
            .as_str()
            .unwrap());
        (with_id, signed)
    }

    #[test]
    fn canonical_profile_caps_validity_by_both_grant_clocks_and_covers_empty_body() {
        use crate::persistence::clock::Time;
        use crate::security::http::{Body, CanonicalHttpRequest, HttpRequest};
        let (key, doc) = fixture(46);
        let canonical = CanonicalHttpRequest::new(HttpRequest {
            method: "POST".into(),
            url: "https://EXAMPLE.com:443/x".into(),
            headers: BTreeMap::from([("Content-Type".into(), "application/json".into())]),
            body: Body::Present { bytes: vec![] },
            nonce: Some("test-nonce".into()),
        })
        .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        for (wall_expiry, mono_deadline, expected) in [
            (now + 600, 101_000, now + 100),
            (now + 20, 101_000, now + 20),
            (now + 1000, 1_001_000, now + 300),
        ] {
            let signed = canonical
                .sign_profile(
                    &doc,
                    &key,
                    Time {
                        wall: now,
                        monotonic_ms: 1000,
                    },
                    wall_expiry,
                    mono_deadline,
                )
                .unwrap();
            let req = canonical.signing_request();
            let mut headers = req.headers.clone();
            headers.extend(signed.headers);
            let metadata = anp::authentication::verify_http_message_signature(
                &doc,
                &req.method,
                &req.url,
                &headers,
                req.body.as_deref(),
            )
            .unwrap();
            assert_eq!(metadata.created, now);
            assert_eq!(metadata.expires, Some(expected));
            assert_eq!(metadata.keyid, key.id().kid);
            for name in [
                "@method",
                "@target-uri",
                "@authority",
                "content-digest",
                "content-type",
            ] {
                assert!(metadata.components.contains(&name.to_owned()));
            }
        }
        for (expiry, deadline) in [(now, 101_000), (now + 10, 1000), (now + 10, 1999)] {
            assert!(canonical
                .sign_profile(
                    &doc,
                    &key,
                    Time {
                        wall: now,
                        monotonic_ms: 1000
                    },
                    expiry,
                    deadline
                )
                .is_err());
        }
    }

    fn request(body: Option<&[u8]>) -> SignRequest {
        let mut headers = BTreeMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        SignRequest {
            method: "POST".into(),
            url: "https://example.com/api/agents/alice".into(),
            headers,
            body: body.map(|b| b.to_vec()),
            covered: Vec::new(),
            nonce: None,
        }
    }

    #[test]
    fn a_body_less_request_covers_the_three_derived_components() {
        let (key, doc) = fixture(21);
        let mut req = request(None);
        req.method = "GET".into();

        let signed = sign_request(&doc, &key, &req).unwrap();
        assert_eq!(signed.covered, ["@method", "@target-uri", "@authority"]);
        assert!(signed.headers.contains_key("Signature"));
        assert!(signed.headers.contains_key("Signature-Input"));
        assert!(!signed.headers.contains_key("Content-Digest"));
    }

    #[test]
    fn a_request_with_a_body_always_covers_content_digest() {
        let (key, doc) = fixture(22);
        let signed = sign_request(&doc, &key, &request(Some(b"{\"hello\":1}"))).unwrap();

        assert!(signed.covered.iter().any(|c| c == "content-digest"));
        assert!(signed.headers.contains_key("Content-Digest"));
        // 摘要必须是**这个** body 的。
        assert_eq!(
            signed.headers["Content-Digest"],
            anp::authentication::build_content_digest(b"{\"hello\":1}")
        );
    }

    /// 上游的 verify 会重新拼一遍签名基并验签。我们自己签的东西必须过得去 ——
    /// 否则等于我们在自娱自乐。
    #[test]
    fn the_signature_verifies_against_the_upstream_verifier() {
        let (key, doc) = fixture(23);
        let req = request(Some(b"payload"));

        let signed = sign_request(&doc, &key, &req).unwrap();

        let mut headers = req.headers.clone();
        for (name, value) in &signed.headers {
            headers.insert(name.clone(), value.clone());
        }

        let metadata = anp::authentication::verify_http_message_signature(
            &doc,
            &req.method,
            &req.url,
            &headers,
            req.body.as_deref(),
        )
        .expect("our own signature must verify under the upstream verifier");

        assert_eq!(metadata.keyid, key.id().kid);
        assert_eq!(metadata.components, signed.covered);
    }

    // ---- `@authority` / `@target-uri` 的写法 ----

    /// **一个 URL 解析器怎么写,签名基里就该怎么写。**
    ///
    /// 表里每一行是"调用方写的"对"解析器写的"。后面几行要证明的是**没有顺手
    /// 多改**:非默认端口、path、query、fragment、host 之外的大小写,都得原样
    /// 过去 —— 一个"顺手把整个 URL 小写"的实现会把 path 弄坏,而它看起来
    /// 只是"清理了一下"。
    #[test]
    fn the_target_uri_is_normalised_the_way_a_url_parser_writes_it() {
        for (written, canonical) in [
            ("https://example.com/x", "https://example.com/x"),
            ("https://Example.COM/x", "https://example.com/x"),
            ("https://example.com:443/x", "https://example.com/x"),
            ("https://example.com:/x", "https://example.com/x"),
            ("https://example.com:8443/x", "https://example.com:8443/x"),
            ("https://example.com:443", "https://example.com"),
            ("https://example.com:443/x?a=1#f", "https://example.com/x?a=1#f"),
            // IPv6 字面量里的冒号不是端口分隔符。
            ("https://[::1]/x", "https://[::1]/x"),
            ("https://[::1]:443/x", "https://[::1]/x"),
            ("https://[::1]:8443/x", "https://[::1]:8443/x"),
            // 大小写只归一 host。
            ("https://example.com/Case?Q=U&x=1", "https://example.com/Case?Q=U&x=1"),
            // 不是 https 就原样返回,交给 `validate_url` 去拒。
            ("not a url", "not a url"),
        ] {
            assert_eq!(normalized_target_uri(written), canonical, "{written}");
        }
    }

    /// **同一个请求,两种写法,验签方只认解析器写出来的那一种。**
    ///
    /// 这条不是"我们改了一个字符串",是**不这么改签名就没人认**:拿调用方原样
    /// 的 URL 去验会失败,拿规范化过的去验才过。用的是上游那个验签器 —— 它按
    /// 文本切 authority,和每个真对端一样是**自己重算一遍**的。
    #[test]
    fn a_url_written_with_the_default_port_only_verifies_after_normalisation() {
        let (key, doc) = fixture(25);
        let mut req = request(None);
        req.method = "GET".into();
        req.url = "https://Example.com:443/api/agents/alice".into();

        let signed = sign_request(&doc, &key, &req).unwrap();
        let mut headers = req.headers.clone();
        headers.extend(signed.headers.clone());

        anp::authentication::verify_http_message_signature(
            &doc, &req.method, &req.url, &headers, None,
        )
        .expect_err("the literal URL must not verify: its authority is not the one in the base");

        let metadata = anp::authentication::verify_http_message_signature(
            &doc,
            &req.method,
            &normalized_target_uri(&req.url),
            &headers,
            None,
        )
        .expect("the normalised URL is the one every verifier derives");
        assert_eq!(metadata.components, signed.covered);
    }

    // ---- 反盲目签名 ----

    /// 覆盖面是由我们决定的:**没有**任何输入能让它变成一组更弱的分量。
    #[test]
    fn the_covered_set_is_fixed_regardless_of_headers_url_and_query() {
        let (key, doc) = fixture(24);

        let mut req = request(None);
        req.method = "GET".into();
        req.url = "https://example.com/anything?a=1&b=2".into();
        req.headers.insert("x-custom".into(), "v".into());
        req.headers.insert("content-type".into(), "text/plain".into());

        let signed = sign_request(&doc, &key, &req).unwrap();
        assert_eq!(signed.covered, ["@method", "@target-uri", "@authority"]);

        // 基里的 @authority 出自 URL,所以上游照真实 URL 重拼一定能验过。
        let mut headers = req.headers.clone();
        headers.extend(signed.headers.clone());
        anp::authentication::verify_http_message_signature(
            &doc, &req.method, &req.url, &headers, None,
        )
        .expect("the authority in the base must come from the URL, not from a header");
    }

    /// 派生分量的名字(`@method` 之类)根本不是合法的头名,所以调用方
    /// 连"用一个头去冒充它"这一步都走不到。
    #[test]
    fn a_header_cannot_impersonate_a_derived_component() {
        for name in ["@method", "@authority", "@target-uri", "@signature-params"] {
            let mut req = request(None);
            req.headers.insert(name.into(), "evil".into());
            assert!(
                matches!(req.validate(), Err(KeydError::Protocol(_))),
                "{name:?} must not be usable as a header name"
            );
        }
    }

    /// 调用方给的 `Content-Digest` 和 body 对不上 → 拒。对得上 → 用它,
    /// 但值仍然是我们自己算出来的那个。
    #[test]
    fn a_content_digest_the_daemon_did_not_compute_is_refused() {
        let (key, doc) = fixture(28);

        let mut req = request(Some(b"the real body"));
        req.headers
            .insert("content-digest".into(), "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:".into());
        assert!(matches!(req.validate(), Err(KeydError::Protocol(_))));
        assert!(sign_request(&doc, &key, &req).is_err());

        // 没有 body 却带着摘要 —— 同样拒。
        let mut req = request(None);
        req.headers
            .insert("content-digest".into(), anp::authentication::build_content_digest(b"x"));
        assert!(req.validate().is_err());

        // 对得上的那个值没问题,而且签出来的摘要一定等于 body 的摘要。
        let body = b"the real body";
        let mut req = request(Some(body));
        req.headers
            .insert("content-digest".into(), anp::authentication::build_content_digest(body));
        let signed = sign_request(&doc, &key, &req).unwrap();
        assert_eq!(
            signed.headers["Content-Digest"],
            anp::authentication::build_content_digest(body)
        );
    }

    #[test]
    fn signing_the_same_request_twice_differs_because_of_the_nonce() {
        let (key, doc) = fixture(25);
        let a = sign_request(&doc, &key, &request(None)).unwrap();
        let b = sign_request(&doc, &key, &request(None)).unwrap();
        assert_ne!(a.headers["Signature"], b.headers["Signature"]);
        assert_ne!(a.signature_base_digest, b.signature_base_digest);
    }

    // ---- 调用方指定的 nonce ----

    /// **调用方给的 nonce 必须原样出现在签名基里,而且签出来的东西要验得过。**
    ///
    /// 这条是适配层的落脚点:connectx 要把同一个 nonce 写进请求体(于是它进
    /// `content-digest`)**和**签名基,而"同一个值"这件事只有调用方能保证。
    #[test]
    fn a_caller_supplied_nonce_reaches_the_signature_base_and_verifies() {
        let (key, doc) = fixture(31);
        let nonce = "QUJDREVGRw";
        let mut req = request(Some(b"{\"nonce\":\"QUJDREVGRw\"}"));
        req.nonce = Some(nonce.to_string());

        let signed = sign_request(&doc, &key, &req).unwrap();

        // 它在签名基里 —— 也就是 `Signature-Input` 那一行里,原样。
        let input = &signed.headers["Signature-Input"];
        assert!(input.contains(&format!("nonce=\"{nonce}\"")), "{input}");

        // 而且上游的验签方(它会从那一行里把 nonce 读回去重拼基)认这条签名。
        let mut headers = req.headers.clone();
        for (name, value) in &signed.headers {
            headers.insert(name.clone(), value.clone());
        }
        let metadata = anp::authentication::verify_http_message_signature(
            &doc,
            &req.method,
            &req.url,
            &headers,
            req.body.as_deref(),
        )
        .expect("a signature over a caller-chosen nonce must verify");
        assert_eq!(metadata.keyid, key.id().kid);
    }

    /// 不给 nonce 时行为不变:上游自己随机一个,两条同样的请求签出来不一样。
    #[test]
    fn without_a_caller_nonce_the_upstream_still_picks_one() {
        let (key, doc) = fixture(32);
        let signed = sign_request(&doc, &key, &request(None)).unwrap();
        assert!(signed.headers["Signature-Input"].contains("nonce=\""), "{:?}", signed.headers);
    }

    /// **nonce 会被原样拼进 `@signature-params` 那一行的引号里,上游不转义。**
    /// 所以能在这里改写结构的字节,一个都不能进 —— 和头值里的换行是同一类
    /// 攻击,只是入口换了一个。
    #[test]
    fn a_nonce_that_could_rewrite_the_signature_base_is_refused() {
        let (key, doc) = fixture(33);

        for bad in [
            // 提前合上引号,再塞一段参数 —— 例如把 keyid 重写掉。
            "x\";keyid=\"did:wba:evil#key-1",
            // 凭空补一整行签名基。
            "x\n\"@authority\": evil.com",
            "x\r\n\"@method\": GET",
            "x\\\"",
            // 上界之外:它不是"含义不对",是签不出去。
            "aé",
            "\u{7f}",
        ] {
            let mut req = request(None);
            req.nonce = Some(bad.to_string());
            assert!(
                matches!(req.validate(), Err(KeydError::Protocol(_))),
                "{bad:?} must not reach the signature base"
            );
            assert!(sign_request(&doc, &key, &req).is_err(), "{bad:?}");
        }

        // 长度上限也一样:超了就拒,而不是截断 —— 截断会悄悄换掉那个值。
        let mut req = request(None);
        req.nonce = Some("a".repeat(MAX_NONCE_LEN));
        assert!(sign_request(&doc, &key, &req).is_ok(), "正好到上限应当放行");

        let mut req = request(None);
        req.nonce = Some("a".repeat(MAX_NONCE_LEN + 1));
        let err = sign_request(&doc, &key, &req).unwrap_err();
        assert!(matches!(err, KeydError::Protocol(_)), "{err}");
        assert!(err.to_string().contains("256"), "{err}");
    }

    /// 但**不能**因为防御就顺手去"理解"这个值:base64url、hex、UUID、带空格的
    /// 都被放行 —— 守护进程管的是能不能写进去,不是它是不是一个"合法"的挑战。
    #[test]
    fn the_nonce_is_opaque_and_only_its_shape_is_checked() {
        let (key, doc) = fixture(34);

        for good in [
            "QUJDREVGRw",
            "9f8b2c1d4e5a6b7c",
            "550e8400-e29b-41d4-a716-446655440000",
            "a b c",
            "with.dots_and-dashes~",
        ] {
            let mut req = request(None);
            req.nonce = Some(good.to_string());
            let signed = sign_request(&doc, &key, &req).unwrap();
            assert!(
                signed.headers["Signature-Input"].contains(&format!("nonce=\"{good}\"")),
                "{good:?}"
            );
        }
    }

    // ---- 签名基注入 ----

    /// 头值里的换行能凭空伪造一行签名基。必须在边界上挡掉。
    #[test]
    fn a_header_value_with_a_line_break_is_refused() {
        let (key, doc) = fixture(26);

        for evil in [
            "x\r\n\"@authority\": evil.com",
            "x\n\"@authority\": evil.com",
            "x\r\"@method\": GET",
        ] {
            let mut req = request(None);
            req.headers.insert("x-forwarded-host".into(), evil.to_string());
            assert!(
                matches!(req.validate(), Err(KeydError::Protocol(_))),
                "{evil:?} must not reach the signature base"
            );
            assert!(sign_request(&doc, &key, &req).is_err());
        }
    }

    /// URL 里的换行同理 —— `@target-uri` 是原样写进基里的。
    #[test]
    fn a_url_with_a_line_break_is_refused() {
        for evil in [
            "https://example.com/x\n\"@authority\": evil.com",
            "https://example.com/x\r\n\r\nGET /admin HTTP/1.1",
            "https://example.com/x y",
        ] {
            let mut req = request(None);
            req.url = evil.into();
            assert!(req.validate().is_err(), "{evil:?} must not be signed");
        }
    }

    #[test]
    fn only_https_urls_and_real_methods_are_signed() {
        let mut req = request(None);
        req.url = "http://example.com/x".into();
        assert!(req.validate().is_err(), "plaintext HTTP must be refused");

        for evil in ["get", "POST /x HTTP/1.1", "GE T", ""] {
            let mut req = request(None);
            req.method = evil.into();
            assert!(req.validate().is_err(), "{evil:?} is not a method token");
        }
    }

    #[test]
    fn a_url_with_userinfo_is_refused() {
        let mut req = request(None);
        req.url = "https://evil.com@example.com/x".into();
        assert!(req.validate().is_err(), "userinfo would not be covered by @authority");
    }

    #[test]
    fn bad_header_names_are_refused() {
        for evil in ["bad name", "bad:name", "", "bad\nname", "bad\"name"] {
            let mut req = request(None);
            req.headers.clear();
            req.headers.insert(evil.into(), "v".into());
            assert!(req.validate().is_err(), "{evil:?} is not a header name");
        }
    }

    // ---- 覆盖面核对本身 ----

    #[test]
    fn a_base_that_drops_a_required_component_is_rejected() {
        let base = "\"@method\": POST\n\
                    \"@signature-params\": (\"@method\");created=1;keyid=\"k\"";
        assert!(matches!(
            verify_covered_set(base, &["@method".into(), "@authority".into()]),
            Err(KeydError::CoveredSetRejected(_))
        ));
    }

    /// 声称覆盖了、基里却没有那一行 —— 也是残缺的基。
    #[test]
    fn a_base_that_claims_a_component_it_does_not_include_is_rejected() {
        let base = "\"@method\": POST\n\
                    \"@signature-params\": (\"@method\" \"@authority\");created=1;keyid=\"k\"";
        assert!(matches!(
            verify_covered_set(base, &["@method".into()]),
            Err(KeydError::CoveredSetRejected(_))
        ));
    }

    #[test]
    fn a_base_with_no_signature_params_line_is_rejected() {
        assert!(verify_covered_set("\"@method\": POST", &["@method".into()]).is_err());
    }

    #[test]
    fn a_base_covering_nothing_is_rejected() {
        let base = "\"@signature-params\": ();created=1;keyid=\"k\"";
        assert!(verify_covered_set(base, &[]).is_err());
    }

    #[test]
    fn component_ids_with_parameters_are_parsed() {
        let list = "\"@method\" \"content-digest\";sf \"x\";key=\"a b\"";
        assert_eq!(
            parse_component_list(list).unwrap(),
            ["@method", "content-digest", "x"]
        );
    }

    #[test]
    fn malformed_component_lists_are_rejected() {
        for bad in ["@method", "\"unterminated", "1", ""] {
            let r = parse_component_list(bad);
            assert!(
                r.is_err() || r.unwrap().is_empty(),
                "{bad:?} is not a valid component list"
            );
        }
    }

    #[test]
    fn the_real_signature_base_parses_back_to_what_we_asked_for() {
        let (key, doc) = fixture(27);
        let req = request(Some(b"body"));

        let signed = sign_request(&doc, &key, &req).unwrap();
        assert_eq!(
            signed.covered,
            ["@method", "@target-uri", "@authority", "content-digest"]
        );
    }

    /// 调用方**可以**要求多覆盖几个分量 —— 有的服务端就要求签名里带上
    /// `content-type`。这一条确认那个请求真的落到了签名基里。
    #[test]
    fn a_caller_may_ask_for_extra_components() {
        let (key, doc) = fixture(28);
        let mut req = request(Some(b"body"));
        req.covered = vec!["content-type".into()];

        let signed = sign_request(&doc, &key, &req).unwrap();
        assert!(
            signed.covered.iter().any(|c| c == "content-type"),
            "{:?}",
            signed.covered
        );
        // 而且四个下限一个不少。
        for required in ["@method", "@target-uri", "@authority", "content-digest"] {
            assert!(signed.covered.iter().any(|c| c == required), "{required}");
        }

        // 加进去之后仍然是有效签名 —— 不是只在字符串上像。
        let mut headers = req.headers.clone();
        for (name, value) in &signed.headers {
            headers.insert(name.clone(), value.clone());
        }
        let metadata = anp::authentication::verify_http_message_signature(
            &doc,
            &req.method,
            &req.url,
            &headers,
            req.body.as_deref(),
        )
        .expect("a signature with an extra component must still verify");
        assert!(metadata.components.iter().any(|c| c == "content-type"));
    }

    /// 但**减不掉**下限。
    ///
    /// 这是整个模块存在的理由:被 prompt injection 的 agent 最想干的事,
    /// 就是让签名只覆盖一个无关紧要的分量,然后拿去配别的 body 和 URL。
    /// 这里把所有能写进 `covered` 的花样都试一遍 —— 要么被直接拒,
    /// 要么签出来的东西四个下限一个不少。**没有第三种结果。**
    #[test]
    fn nothing_a_caller_writes_can_lower_the_covered_set() {
        let (key, doc) = fixture(29);

        for attempt in [
            vec!["@method".to_string()],
            vec!["@method".to_string(), "@authority".to_string()],
            vec!["x-absent".to_string()],
            vec!["content-digest".to_string()],
            vec!["\"@method\"".to_string()],
            vec!["x-custom".to_string()],
            Vec::new(),
        ] {
            let mut req = request(Some(b"body"));
            req.headers.insert("x-custom".into(), "v".into());
            req.covered = attempt.clone();

            let Ok(signed) = sign_request(&doc, &key, &req) else {
                continue;
            };
            for required in ["@method", "@target-uri", "@authority", "content-digest"] {
                assert!(
                    signed.covered.iter().any(|c| c == required),
                    "asking for {attempt:?} dropped {required}; got {:?}",
                    signed.covered
                );
            }
        }
    }

    /// 分量名会原样进入 `@signature-params` 的括号里,那里是结构化字段列表。
    /// 引号、逗号、分号、括号、空格都是它的结构字符 —— 一个都不能放进来。
    #[test]
    fn a_component_name_that_could_rewrite_the_covered_set_is_refused() {
        let (key, doc) = fixture(30);

        for bad in [
            "\"@method\"",
            "@method, \"@authority\"",
            "@method\"",
            "content-digest;sf",
            "@query-param",
            "Content-Type",
            "x y",
            "",
            "@",
        ] {
            let mut req = request(None);
            req.covered = vec![bad.into()];
            let err = sign_request(&doc, &key, &req).unwrap_err();
            assert!(
                matches!(err, KeydError::CoveredSetRejected(_)),
                "{bad:?} must be refused, got {err:?}"
            );
        }

        // 要求覆盖一个请求里没带的头,也是调用方的错 —— 但要给一句能看懂的话。
        let mut req = request(None);
        req.covered = vec!["x-absent".into()];
        let err = sign_request(&doc, &key, &req).unwrap_err();
        assert!(matches!(err, KeydError::CoveredSetRejected(_)), "{err}");

        // 而正规的形状照过。
        for good in ["content-type", "x-custom-header", "x.y_z-1"] {
            let mut req = request(None);
            req.headers.insert(good.to_string(), "v".into());
            req.covered = vec![good.into()];
            assert!(sign_request(&doc, &key, &req).is_ok(), "{good:?}");
        }
    }
}
