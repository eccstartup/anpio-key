//! 同 DID 内改文档 —— 也就是"**换密钥但不换身份**"。
//!
//! 路径型 DID 的形状决定了这里只有一条路可走:
//!
//! ```text
//! did:wba:example.com:agents:mybot:e1_<binding key 的指纹>
//!        └── 你控制的域名 ──┘└─ 路径 ─┘└──── 身份就是这个 ────┘
//! ```
//!
//! **最后一段是绑定密钥的指纹。** 它一动,DID 就变 —— 那不是轮换,是迁移
//! (见 [`crate::did::migrate`])。所以"能换密钥而不换身份"的全部余地,都在
//! 绑定密钥**之外**的那些验证方法上:规范原文说得很清楚,只要路径里那把
//! 指纹不变,文档里加新验证密钥、废掉旧的、改 service 端点都是允许的。
//!
//! 于是这个模块只做三件事:读出文档里非绑定的那些密钥、算出下一个可用的
//! fragment、以及把注销标记写进去。密码学一步都没有 —— 改完还是要拿绑定
//! 密钥去重签,那一步在 [`crate::did::document::sign_document`]。

use std::collections::BTreeSet;

use serde_json::Value;

use crate::did::document::{DidDocumentSpec, ExtraKey, ExtraKeyMaterial, ROOT_FRAGMENT};
use crate::did::parse::parse_did_wba;
use crate::error::{KeydError, Result};

/// 热密钥的 fragment 前缀。`key-1` 被根密钥占了,所以从 `key-2` 开始。
pub const HOT_KEY_PREFIX: &str = "key-";
/// 恢复密钥的 fragment 前缀。
pub const RECOVERY_FRAGMENT_PREFIX: &str = "recovery-";
/// 恢复密钥的 fragment。第一把就是这个。
pub const RECOVERY_FRAGMENT: &str = "recovery-1";

/// 文档里被 `deactivated` 标记为已注销。
pub fn is_deactivated(document: &Value) -> bool {
    document.get("deactivated").and_then(Value::as_bool) == Some(true)
}

/// 文档指向的后继 DID。
pub fn successor_of(document: &Value) -> Option<&str> {
    document.get("successorDid").and_then(Value::as_str)
}

/// `did:wba:example.com:a:b:e1_xxx` → `example.com:a:b`。
///
/// 这就是规范说的 **stable subject path**:绑定指纹**之前**的那一段。
/// 是不是"同一个主体换了把钥匙",看的就是它 —— 域名、端口、路径段全都
/// 必须一样,唯独最后那把密钥可以不同。
pub fn subject_path(did: &str) -> Result<String> {
    let parts = parse_did_wba(did)?;
    if parts.path_segments.is_empty() {
        return Err(KeydError::Did(format!("{did} has no path segments")));
    }
    let mut segments = parts.path_segments.clone();
    // 最后一段必须是 e1_ 绑定段;不是的话这个 DID 根本不是路径型。
    let last = segments.pop().unwrap_or_default();
    if !last.starts_with("e1_") {
        return Err(KeydError::Did(format!("{did} has no e1_ binding segment")));
    }
    let mut out = parts.host.clone();
    if let Some(port) = parts.port {
        out.push_str(&format!(":{port}"));
    }
    for segment in segments {
        out.push(':');
        out.push_str(&segment);
    }
    Ok(out)
}

/// 文档里**除根密钥之外**的验证方法,按它们在 `verificationMethod` 里的顺序。
///
/// 读不出来的一律报错,不跳过:一份文档里有一条读不懂的验证方法,意味着
/// 我们接下来重签的时候会把它**弄丢** —— 而丢掉的可能是别人正靠着的热密钥
/// 或者恢复密钥。宁可现在失败。
pub fn extra_keys(document: &Value, did: &str) -> Result<Vec<ExtraKey>> {
    let root_id = format!("{did}#{ROOT_FRAGMENT}");
    let methods = document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .ok_or_else(|| KeydError::Did("the document has no verificationMethod array".into()))?;

    let mut out = Vec::with_capacity(methods.len().saturating_sub(1));
    for method in methods {
        let id = method
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| KeydError::Did("a verification method has no id".into()))?;
        if id == root_id {
            continue;
        }

        let fragment = id
            .strip_prefix(&format!("{did}#"))
            .ok_or_else(|| {
                KeydError::Did(format!(
                    "the verification method {id} does not belong to {did} — \
                     a document may not vouch for a key in someone else's namespace"
                ))
            })?
            .to_string();

        let material = anp::authentication::extract_public_key(method)
            .map_err(|e| KeydError::Did(format!("{id}: unreadable public key: {e}")))?;
        let material = match material {
            anp::PublicKeyMaterial::Ed25519(key) => ExtraKeyMaterial::Ed25519(key),
            anp::PublicKeyMaterial::X25519(key) => ExtraKeyMaterial::X25519(key),
            _ => {
                return Err(KeydError::Did(format!(
                    "{id} is an Ed25519 or X25519 key only in this build, and re-signing a \
                     document that carries anything else at this position would silently \
                     drop it"
                )))
            }
        };

        let mut relationships = Vec::new();
        for (name, relationship) in [
            ("authentication", anp::authentication::DidVerificationRelationship::Authentication),
            ("assertionMethod", anp::authentication::DidVerificationRelationship::AssertionMethod),
            ("keyAgreement", anp::authentication::DidVerificationRelationship::KeyAgreement),
        ] {
            let listed = document
                .get(name)
                .and_then(Value::as_array)
                .is_some_and(|list| list.iter().any(|entry| entry.as_str() == Some(id)));
            if listed {
                relationships.push(relationship);
            }
        }

        out.push(ExtraKey { fragment, material, relationships });
    }
    Ok(out)
}

/// 当前那把热密钥 —— `authentication` 里那个**不是**绑定密钥的。
///
/// 冷热分离的意义就在这一条:绑定密钥是冷的(它的指纹就是 DID,动不了),
/// 日常签名用的那把挂在 `authentication` 下,可以随时换。
pub fn hot_key(document: &Value, did: &str) -> Result<Option<ExtraKey>> {
    Ok(extra_keys(document, did)?
        .into_iter()
        .find(|key| {
            key.relationships
                .contains(&anp::authentication::DidVerificationRelationship::Authentication)
        }))
}

/// 文档里挂着**这把公钥**的热密钥叫什么名字。
///
/// 助记词恢复用得上:纸推出来的热密钥是确定的,只有**编号**不由纸决定 ——
/// 它由当初那次 `keygen`(以及之后轮换过几次)决定。这里按公钥找回那个
/// 名字,而不是让恢复去算"下一个空位":算了会得到 `key-3`,而纸上那把在
/// 文档里叫 `key-2`,于是恢复会凭空添一把谁也没引用的钥匙,又漏掉真正
/// 该接回来的那一把。
///
/// `None` 有两个含义,而且都对恢复是同一个结论:文档里的热密钥不是这张纸
/// 的(比如轮换过 —— 轮换铸的是新的随机种子,不在纸上),或者文档里根本
/// 没有热密钥。
pub fn hot_fragment_of(
    document: &Value,
    did: &str,
    public_key: &ed25519_dalek::VerifyingKey,
) -> Result<Option<String>> {
    for key in extra_keys(document, did)? {
        if !key
            .relationships
            .contains(&anp::authentication::DidVerificationRelationship::Authentication)
        {
            continue;
        }
        if let ExtraKeyMaterial::Ed25519(listed) = key.material {
            if listed.to_bytes() == public_key.to_bytes() {
                return Ok(Some(key.fragment));
            }
        }
    }
    Ok(None)
}

/// 下一个可用的热密钥 fragment:`key-2`、`key-3`……
///
/// 用"**曾经**用掉的最大编号 + 1",不是"数量 + 1",也不是"文档里还剩的
/// 最大编号 + 1":轮换过几轮之后编号会留下空洞,而重用一个已经退休过的编号
/// 会让两份**内容不同**的文档顶着同一个 `id` —— 任何缓存过旧文档的验证方
/// 都会把新签名判成坏签名。单调递增,永不复用。
///
/// "曾经"这个字是关键,所以签名里要一个 [`also_used`]:文档只记得**现在
/// 还挂着**的钥匙,而摘掉一把之后,那个编号就从文档里消失了。本机铸过的
/// 全部编号在 [`crate::keystore::store::envelope_fragments`] 里 —— 摘钥匙
/// 不删信封,这正是那个决定在这里兑现的地方。
///
/// [`also_used`]: next_fragment
pub fn next_hot_fragment(
    document: &Value,
    did: &str,
    also_used: &BTreeSet<String>,
) -> Result<String> {
    next_fragment(document, did, HOT_KEY_PREFIX, also_used)
}

/// 同 [`next_hot_fragment`],按前缀算。恢复密钥用 `recovery-`。
///
/// 恢复密钥也不复用编号,理由和热密钥一样:一份缓存过的文档里写的是
/// "`recovery-1` 这把钥匙",而钥匙换了、名字没换,那个缓存就变成了一把
/// 已经作废的钥匙的通行证。
///
/// 编号取"文档里的"和 `also_used`(本机信封里的)的**并集** —— 两个集合
/// 会不一致,而漏掉任何一个都会让编号倒着走。
pub fn next_fragment(
    document: &Value,
    did: &str,
    prefix: &str,
    also_used: &BTreeSet<String>,
) -> Result<String> {
    let mut highest = 0u32;
    let listed = extra_keys(document, did)?.into_iter().map(|key| key.fragment);
    for fragment in listed.chain(also_used.iter().cloned()) {
        if let Some(number) = fragment.strip_prefix(prefix) {
            if let Ok(number) = number.parse::<u32>() {
                highest = highest.max(number);
            }
        }
    }
    // 热密钥从 2 起(`key-1` 是根密钥),恢复密钥从 1 起。
    let floor = if prefix == HOT_KEY_PREFIX { 1 } else { 0 };
    Ok(format!("{prefix}{}", highest.max(floor) + 1))
}

/// 同一条"不复用编号"的规则,但名字是"基名 + 后缀":`device-sign`、
/// `device-sign-2`、`device-sign-3`……
///
/// 设备钥匙的名字里带连字符,拼不出 [`next_fragment`] 那种"前缀 + 数字"的
/// 形状。规则本身一样:取"文档里的"和 `also_used`(本机信封里的)的并集,
/// 第一把用基名,之后接 `-2`、`-3`。
pub fn next_suffix_fragment(
    document: &Value,
    did: &str,
    base: &str,
    also_used: &BTreeSet<String>,
) -> Result<String> {
    let listed: Vec<String> = extra_keys(document, did)?
        .into_iter()
        .map(|key| key.fragment)
        .collect();
    let taken = |name: &str| listed.iter().any(|fragment| fragment == name) || also_used.contains(name);
    if !taken(base) {
        return Ok(base.to_string());
    }
    (2u32..)
        .map(|number| format!("{base}-{number}"))
        .find(|name| !taken(name))
        .ok_or_else(|| KeydError::Did(format!("no free fragment for {base}")))
}

/// 把文档标记成已注销,可选指向后继。
///
/// 规范的两条硬要求落在这里:
/// - **`successorDid` 只能写一次,而且写下去之后不许动。** 已经注销过、
///   而这次给的又不是**同一个**后继时,这里报错而不是改写。"不许动"包括
///   `None` —— 那个值会把边抹掉,而抹掉一次迁移的边和改掉它是同一件事:
///   走这条路的人从此找不到新家。
/// - 注销**不是删除**。老文档必须继续可解析,否则别人从旧 DID 出发就
///   找不到新家了;`deactivated` 只是告诉它"别再往这儿发了,往那边走"。
///
/// 返回的文档**没有 proof**,因为它已经不是你签过的那一份了,调用方必须
/// 用**旧 DID 的绑定密钥**重新签一次 —— 那一下正是"同一个主体宣布这次
/// 迁移"的证据,少了它,这条边在验证方眼里只能算 `provider_asserted`。
pub fn deactivate(document: &Value, successor: Option<&str>) -> Result<Value> {
    if let Some(existing) = successor_of(document) {
        if successor != Some(existing) {
            return Err(KeydError::Did(format!(
                "this document already points at {existing} as its successor, and a \
                 successor edge may only be written once — {} would erase the path the \
                 previous migration was recorded on",
                match successor {
                    Some(successor) => format!("changing it to {successor}"),
                    None => "clearing it".to_string(),
                }
            )));
        }
    }

    // 旧 proof 摘掉,理由和 [`rekey`] 里那处一样:它盖的是改动之前的字节。
    // 这里比那里更要紧 —— 一份"自称已注销、但签名盖的是另一份文档"的文件
    // 不是没用的签名,是**一句假话**:验证方按 proof 一验就拒,而人只会
    // 看到"这个 DID 的文档验不过",不会想到是本地改文档时忘了重签。
    let mut out = strip_proof(document)?;
    let object = out
        .as_object_mut()
        .ok_or_else(|| KeydError::Did("the document is not a JSON object".into()))?;
    object.insert("deactivated".into(), Value::Bool(true));
    match successor {
        Some(successor) => {
            object.insert("successorDid".into(), Value::String(successor.to_string()));
        }
        // 永久注销:不留一条指向空气的边。(已经有一条边的文档走不到这里 ——
        // 上面那个分支会先把它拦下来。)
        None => {
            object.remove("successorDid");
        }
    }
    Ok(out)
}

/// 重签之前把旧的 `proof` 摘掉。
///
/// proof 覆盖的是**整份文档**,包括它自己那一块吗?不 —— 摘掉是为了让
/// 签名输入里的文档和它将来的样子一致。留着一份旧 proof 去签一份新文档,
/// 签出来的东西覆盖的是旧 proof 的字节,而那正是要被替换掉的东西。
pub fn strip_proof(document: &Value) -> Result<Value> {
    let mut out = document.clone();
    let object = out
        .as_object_mut()
        .ok_or_else(|| KeydError::Did("the document is not a JSON object".into()))?;
    object.remove("proof");
    Ok(out)
}

/// 文档的一个能进审计日志的指纹 —— JCS 之后的 SHA-256。
///
/// 审计里记这个而不是记整份文档:整份文档太大,而指纹足够回答"当时发布的
/// 是这一份吗"。
pub fn document_digest(document: &Value) -> Result<String> {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    let canonical = serde_json_canonicalizer::to_vec(document)
        .map_err(|e| KeydError::Protocol(format!("the document is not canonically encodable: {e}")))?;
    let digest = Sha256::digest(&canonical);
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest))
}

/// 把一条 `verificationMethod` 从文档里彻底摘掉。
///
/// "彻底"是重点:只从 `verificationMethod` 里删、把 `id` 留在
/// `authentication` 里,得到的是一份**指向不存在的方法**的文档 —— 上游的
/// 规范性检查会拒,而拒绝的理由会指向一个跟真因毫无关系的地方。
pub fn remove_method(document: &Value, method_id: &str) -> Result<Value> {
    let fragment = method_id.rsplit_once('#').map(|(_, fragment)| fragment);
    if fragment == Some(ROOT_FRAGMENT) {
        return Err(KeydError::Did(format!(
            "{method_id} is the binding key, and removing it would leave a document that \
             no longer binds to its own DID — the DID's last segment IS that key's \
             fingerprint. Rotating the binding key is a migration, not an edit"
        )));
    }

    let mut out = document.clone();
    let object = out
        .as_object_mut()
        .ok_or_else(|| KeydError::Did("the document is not a JSON object".into()))?;

    let mut removed = false;
    if let Some(methods) = object.get_mut("verificationMethod").and_then(Value::as_array_mut) {
        let before = methods.len();
        methods.retain(|method| method.get("id").and_then(Value::as_str) != Some(method_id));
        removed = methods.len() != before;
    }

    for name in ["authentication", "assertionMethod", "keyAgreement"] {
        if let Some(list) = object.get_mut(name).and_then(Value::as_array_mut) {
            list.retain(|entry| entry.as_str() != Some(method_id));
            // 空的关系数组留在文档里是噪音,而且它和"这个关系没被用过"
            // 在 JSON 上长得一样 —— 摘掉。
            if list.is_empty() {
                object.remove(name);
            }
        }
    }

    if !removed {
        return Err(KeydError::Did(format!(
            "{method_id} is not a verification method in this document"
        )));
    }
    Ok(out)
}

/// 两份文档说的是不是同一个主体。
///
/// 判断依据是 stable subject path,不是 DID 本身 —— 换绑密钥会改 DID,
/// 但主体没变。迁移要挡的是相反的情况:两个 path 根本不同的 DID 之间的
/// "迁移",那不是换密钥,那是**冒名**。
pub fn same_subject(old: &str, new: &str) -> Result<bool> {
    Ok(subject_path(old)? == subject_path(new)?)
}

// ————————————————————————————————————————————————————————————————————————
// 改动文档:加一把、摘一把
// ————————————————————————————————————————————————————————————————————————

/// 上游的构建器自己生成的那几个顶层属性。
///
/// 重建文档时只有这些由上游说了算。**其余的一律原样搬过来** ——
/// `deactivated`、`successorDid`,以及将来任何我们还不认识的属性。
/// 白名单而不是黑名单:黑名单漏掉一个,那个属性就会被一次轮换悄悄删掉,
/// 而覆盖写是不报错的。
const UPSTREAM_FIELDS: [&str; 7] = [
    "@context",
    "id",
    "verificationMethod",
    "authentication",
    "assertionMethod",
    "keyAgreement",
    "service",
];

/// 加一把非绑定密钥,其余一切不动。
pub fn with_extra_key(
    document: &Value,
    did: &str,
    root: &ed25519_dalek::VerifyingKey,
    new: ExtraKey,
) -> Result<Value> {
    let mut extras = extra_keys(document, did)?;
    if extras.iter().any(|key| key.fragment == new.fragment) {
        return Err(KeydError::Did(format!(
            "{did} already has a verification method named {}, and reusing a fragment \
             for a different key makes every document anyone cached say the wrong thing \
             about it",
            new.fragment
        )));
    }
    extras.push(new);
    rekey(document, &DidDocumentSpec::from_document(document)?, did, root, extras)
}

/// 摘掉一把非绑定密钥,其余一切不动。
pub fn without_method(
    document: &Value,
    did: &str,
    root: &ed25519_dalek::VerifyingKey,
    method_id: &str,
) -> Result<Value> {
    let fragment = method_id
        .rsplit_once('#')
        .map(|(_, fragment)| fragment)
        .ok_or_else(|| KeydError::Did(format!("{method_id} is not a verification method id")))?;
    if fragment == ROOT_FRAGMENT {
        return Err(KeydError::Did(format!(
            "{method_id} is the binding key — see remove_method for why that cannot go"
        )));
    }

    let all = extra_keys(document, did)?;
    let mut extras = Vec::with_capacity(all.len());
    let mut found = false;
    for key in all {
        if key.fragment == fragment {
            found = true;
            continue;
        }
        extras.push(key);
    }
    if !found {
        return Err(KeydError::Did(format!(
            "{method_id} is not a verification method in this document"
        )));
    }
    rekey(document, &DidDocumentSpec::from_document(document)?, did, root, extras)
}

/// 用"根密钥 + 这几把附加密钥"重建文档,并把上游不认识的顶层属性搬回去。
///
/// 走的是重建而不是就地改 JSON,理由只有一个:**规范形式**。就地改出来的
/// 文档能不能过上游的 `validate_did_document_binding`,取决于我们拼的那几
/// 个对象和上游拼的逐字节一致 —— 那把"能不能用"押在了我们抄得对不对上。
/// 重建则相反:形状是上游自己产的,不可能抄错。
///
/// 代价是重建会**丢掉**上游不认识的属性,所以搬回来这一步不是可选的;
/// 而 `service` 那一档虽然上游认识、却由规格说了算,所以**规格也得给对**
/// —— 从 `document` 里反推出来的那份([`DidDocumentSpec::from_document`])
/// 就是"这份文档现在声明的东西"。
pub(crate) fn rekey(
    document: &Value,
    spec: &DidDocumentSpec,
    did: &str,
    root: &ed25519_dalek::VerifyingKey,
    extras: Vec<ExtraKey>,
) -> Result<Value> {
    let stripped = strip_proof(document)?;
    let mut canonical = crate::did::document::rebuild_with(spec, did, root, extras)
        .map_err(|error| match error {
            // 重建对不上 DID,说明**别人给的文档**里的根密钥不是这个 DID 的
            // 那把。往上抛一句"这不是规范形式"会把人引到格式上去,而真因是
            // 身份对不上。
            KeydError::Did(_) => KeydError::Did(format!(
                "cannot rebuild {did} from its own document: the root key in the document \
                 is not the one the DID's fingerprint names ({error})"
            )),
            other => other,
        })?;

    let source = stripped
        .as_object()
        .ok_or_else(|| KeydError::Did("the document is not a JSON object".into()))?;
    let target = canonical
        .as_object_mut()
        .ok_or_else(|| KeydError::Protocol("the rebuilt document is not an object".into()))?;
    for (name, value) in source {
        if !UPSTREAM_FIELDS.contains(&name.as_str()) {
            target.insert(name.clone(), value.clone());
        }
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hygiene::LockedBytes;
    use crate::did::document::{build_unsigned_with, sign_document, ExtraKey, ROOT_FRAGMENT};
    use crate::keystore::record::KeyId;
    use crate::keystore::wrap::seed_to_public;
    use crate::sign::LockedSigningKey;
    use anp::authentication::DidVerificationRelationship as R;

    fn root_key(byte: u8) -> LockedSigningKey {
        let seed = LockedBytes::fill(|d| *d = [byte; 32]).unwrap();
        LockedSigningKey::from_seed(
            KeyId { did: String::new(), kid: String::new(), thumbprint: String::new() },
            seed,
        )
        .unwrap()
    }

    fn extra(fragment: &str, byte: u8, relationships: Vec<R>) -> ExtraKey {
        let seed = LockedBytes::fill(|d| *d = [byte; 32]).unwrap();
        let (public_key, _) = seed_to_public(&seed);
        ExtraKey::new(fragment, public_key, relationships)
    }

    /// 一个已发布的样子:根密钥 + 一把热密钥,签好。
    fn published(extra_byte: u8) -> (LockedSigningKey, String, Value) {
        let key = root_key(0x51);
        let spec = crate::did::document::DidDocumentSpec::new(
            "example.com",
            vec!["user".into(), "alice".into()],
        );
        let (did, unsigned) = build_unsigned_with(
            &spec,
            &key.verifying_key().unwrap(),
            vec![extra("key-2", extra_byte, vec![R::Authentication])],
        )
        .unwrap();
        let signed = sign_document(&unsigned, &key, &format!("{did}#{ROOT_FRAGMENT}")).unwrap();
        (key, did, signed)
    }

    #[test]
    fn the_subject_path_is_everything_before_the_binding_segment() {
        assert_eq!(
            subject_path("did:wba:example.com:user:alice:e1_abc").unwrap(),
            "example.com:user:alice"
        );
        // 端口是身份的一部分 —— 同一个域名上的另一个端口是另一个主体。
        assert_eq!(
            subject_path("did:wba:example.com%3A8443:user:alice:e1_abc").unwrap(),
            "example.com:8443:user:alice"
        );
        assert!(same_subject(
            "did:wba:example.com:user:alice:e1_aaa",
            "did:wba:example.com:user:alice:e1_bbb"
        )
        .unwrap());
        assert!(!same_subject(
            "did:wba:example.com:user:alice:e1_aaa",
            "did:wba:example.com:user:alice2:e1_aaa"
        )
        .unwrap());
    }

    /// 换的是同一路径下的最后一段 —— 那才是"同一个主体换了把钥匙"。
    #[test]
    fn a_did_without_a_binding_segment_has_no_subject_path() {
        assert!(subject_path("did:wba:example.com:user:alice").is_err());
    }

    #[test]
    fn hot_fragments_are_monotonic_and_never_reused() {
        let (_, did, mut document) = published(0x61);
        let nothing = BTreeSet::new();
        assert_eq!(next_hot_fragment(&document, &did, &nothing).unwrap(), "key-3");

        // 换一把,再换一把:编号只增不减。
        let key = root_key(0x51);
        for expected in ["key-3", "key-4"] {
            document = with_extra_key(
                &document,
                &did,
                &key.verifying_key().unwrap(),
                extra(expected, 0x70, vec![R::Authentication]),
            )
            .unwrap();
            assert_eq!(next_hot_fragment(&document, &did, &nothing).unwrap(), {
                let n: u32 = expected.trim_start_matches("key-").parse().unwrap();
                format!("key-{}", n + 1)
            });
        }

        // 编号留了洞也不回头补:`key-3` 退休之后下一个还是 `key-5`。
        // 复用编号 = 两份内容不同的文档顶着同一个 id。
        let without = without_method(&document, &did, &key.verifying_key().unwrap(), &format!("{did}#key-3"))
            .unwrap();
        assert_eq!(next_hot_fragment(&without, &did, &nothing).unwrap(), "key-5");
    }

    /// **摘掉一把钥匙不会把它的编号放回池子里。**
    ///
    /// `remove-key` 之后文档里再也找不到那把钥匙,所以单看文档,"下一个可用
    /// 编号"会倒着走回 `key-2`。而 `remove-key` 存在的主要理由就是"这把热密钥
    /// 泄露了" —— 让它的编号被一把新钥匙顶替,等于给泄露出去的那把发了一张
    /// 新的通行证:缓存过旧文档的验证方会把 `key-2` 认成它。
    ///
    /// 本机信封是那个"曾经用过"的记录(摘钥匙不删信封),编号分配必须看它。
    #[test]
    fn a_removed_key_does_not_release_its_fragment() {
        let (key, did, document) = published(0x64);
        let removed = without_method(&document, &did, &key.verifying_key().unwrap(), &format!("{did}#key-2"))
            .unwrap();

        // 只看文档:编号回到了池子里 —— 这正是要防的那个状态。
        assert_eq!(next_hot_fragment(&removed, &did, &BTreeSet::new()).unwrap(), "key-2");

        // 带上本机信封的记录:`key-2` 已经被用掉了,下一个是 `key-3`。
        let used: BTreeSet<String> = ["key-2".to_string()].into_iter().collect();
        assert_eq!(next_hot_fragment(&removed, &did, &used).unwrap(), "key-3");
    }

    #[test]
    fn recovery_fragments_start_at_one() {
        let (_, did, document) = published(0x62);
        let nothing = BTreeSet::new();
        assert_eq!(
            next_fragment(&document, &did, RECOVERY_FRAGMENT_PREFIX, &nothing).unwrap(),
            "recovery-1"
        );

        let key = root_key(0x51);
        let with = with_extra_key(
            &document,
            &did,
            &key.verifying_key().unwrap(),
            extra("recovery-1", 0x63, vec![R::AssertionMethod]),
        )
        .unwrap();
        assert_eq!(
            next_fragment(&with, &did, RECOVERY_FRAGMENT_PREFIX, &nothing).unwrap(),
            "recovery-2"
        );
    }

    /// 加一把钥匙**不能**顺手把别的东西弄丢。
    #[test]
    fn adding_a_key_preserves_foreign_top_level_fields() {
        let (key, did, document) = published(0x64);
        let mut annotated = document.clone();
        annotated["deactivated"] = Value::Bool(true);
        annotated["successorDid"] = Value::String("did:wba:example.com:user:alice:e1_next".into());
        annotated["agentDescription"] = Value::String("https://example.com/alice.md".into());

        let with = with_extra_key(
            &annotated,
            &did,
            &key.verifying_key().unwrap(),
            extra("recovery-1", 0x65, vec![R::AssertionMethod]),
        )
        .unwrap();

        assert_eq!(with["deactivated"], Value::Bool(true));
        assert_eq!(with["successorDid"], "did:wba:example.com:user:alice:e1_next");
        assert_eq!(with["agentDescription"], "https://example.com/alice.md");
        // 热密钥也在,新钥匙也在。
        let names: Vec<_> = extra_keys(&with, &did)
            .unwrap()
            .into_iter()
            .map(|key| key.fragment)
            .collect();
        assert_eq!(names, ["key-2", "recovery-1"]);
    }

    /// 重建之后文档仍然自洽:proof 摘掉了,而且上游认可它的形状。
    #[test]
    fn a_rekeyed_document_is_still_a_valid_document() {
        let (key, did, document) = published(0x66);
        let with = with_extra_key(
            &document,
            &did,
            &key.verifying_key().unwrap(),
            extra("recovery-1", 0x67, vec![R::AssertionMethod]),
        )
        .unwrap();

        assert!(with.get("proof").is_none(), "a rekeyed document must be unsigned");
        let signed = sign_document(&with, &key, &format!("{did}#{ROOT_FRAGMENT}")).unwrap();
        assert!(crate::did::document::verify_path_binding(&did, &signed).is_ok());
    }

    /// **加一把钥匙不能把 service 声明弄丢。**
    ///
    /// `service` 在上游的构建器里,所以它既不在"上游不认识的属性原样搬回去"
    /// 那一档里,也不会自己从 DID 里长出来 —— 重建时它完全由规格决定。规格
    /// 是从被改的**那份文档**反推的,这一条就是在验这条线没断:断了的话,
    /// 一个绑了 WNS handle 的 DID 会在加一把热密钥之后**静静地**不再绑着它。
    #[test]
    fn rekeying_keeps_the_service_entries() {
        let key = root_key(0x7a);
        let spec = crate::did::document::DidDocumentSpec::new(
            "example.com",
            vec!["user".into(), "alice".into()],
        )
        .with_service(serde_json::json!({
            "id": "#handle",
            "type": "ANPHandleService",
            "serviceEndpoint": "https://wns.example.com/alice",
        }));
        let (did, unsigned) = build_unsigned_with(&spec, &key.verifying_key().unwrap(), Vec::new()).unwrap();
        let document = sign_document(&unsigned, &key, &format!("{did}#{ROOT_FRAGMENT}")).unwrap();
        let before = document["service"].clone();
        assert!(before.as_array().is_some_and(|entries| entries.len() == 1));

        let with = with_extra_key(
            &document,
            &did,
            &key.verifying_key().unwrap(),
            extra("key-2", 0x7b, vec![R::Authentication]),
        )
        .unwrap();

        assert_eq!(with["service"], before, "a rekey must not drop a service binding");
    }

    /// 恢复密钥挂在 `assertionMethod` 里 —— 而不是 `authentication`。
    ///
    /// 挂错关系不是"少了个字段":恢复密钥一旦能认证,它就等于一把常驻的
    /// 热密钥,而"预授权、平时不用"这个性质是恢复机制的全部意义。
    #[test]
    fn a_recovery_key_lands_in_assertion_method_only() {
        let (key, did, document) = published(0x68);
        let with = with_extra_key(
            &document,
            &did,
            &key.verifying_key().unwrap(),
            extra("recovery-1", 0x69, vec![R::AssertionMethod]),
        )
        .unwrap();

        let id = format!("{did}#recovery-1");
        let listed = |name: &str| {
            with[name]
                .as_array()
                .is_some_and(|list| list.iter().any(|entry| entry.as_str() == Some(id.as_str())))
        };
        assert!(listed("assertionMethod"));
        assert!(!listed("authentication"));
        assert_eq!(hot_key(&with, &did).unwrap().unwrap().fragment, "key-2");
    }

    #[test]
    fn a_relationship_set_upstream_cannot_express_is_refused() {
        // 空关系 = 一份没人能用的验证方法。
        let error = build_unsigned_with(
            &crate::did::document::DidDocumentSpec::new("example.com", vec!["a".into()]),
            &root_key(0x6a).verifying_key().unwrap(),
            vec![extra("key-2", 0x6b, vec![])],
        )
        .unwrap_err();
        assert!(error.to_string().contains("no relationships"), "{error}");
    }

    /// 重签时必须把**已有的**那些密钥一把不落地带回去。
    #[test]
    fn retiring_one_key_keeps_the_others() {
        let (key, did, document) = published(0x6c);
        let with_recovery = with_extra_key(
            &document,
            &did,
            &key.verifying_key().unwrap(),
            extra("recovery-1", 0x6d, vec![R::AssertionMethod]),
        )
        .unwrap();

        let without =
            without_method(&with_recovery, &did, &key.verifying_key().unwrap(), &format!("{did}#key-2"))
                .unwrap();
        let names: Vec<_> = extra_keys(&without, &did)
            .unwrap()
            .into_iter()
            .map(|key| key.fragment)
            .collect();
        assert_eq!(names, ["recovery-1"]);
        // 关系数组里也不许留下指向已删方法的 id。
        assert!(!serde_json::to_string(&without).unwrap().contains("#key-2"));
    }

    /// 绑定密钥摘不掉 —— 它的指纹就是 DID 的最后一段。
    #[test]
    fn the_binding_key_cannot_be_retired() {
        let (key, did, document) = published(0x6e);
        let error = without_method(&document, &did, &key.verifying_key().unwrap(), &format!("{did}#key-1"))
            .unwrap_err();
        assert!(error.to_string().contains("binding key"), "{error}");
        assert!(remove_method(&document, &format!("{did}#key-1")).is_err());
    }

    #[test]
    fn deactivating_twice_with_a_different_successor_is_refused() {
        let (_, _, document) = published(0x6f);
        let old = "did:wba:example.com:user:alice:e1_old";
        let one = "did:wba:example.com:user:alice:e1_one";
        let two = "did:wba:example.com:user:alice:e1_two";

        let done = deactivate(&document, Some(one)).unwrap();
        assert!(is_deactivated(&done));
        assert_eq!(successor_of(&done), Some(one));

        // 同一个后继:幂等,不报错。
        assert!(deactivate(&done, Some(one)).is_ok());

        // 换一个后继:拒绝。回头改会让历史出现两条指向不同下一代的边。
        let error = deactivate(&done, Some(two)).unwrap_err();
        assert!(error.to_string().contains("only be written once"), "{error}");

        // **抹掉**也不行。抹掉一次迁移的边和改掉它是同一件事:走这条路的人
        // 从此找不到新家。
        let error = deactivate(&done, None).unwrap_err();
        assert!(error.to_string().contains("clearing it"), "{error}");

        // 而一份**从来没**注销过的文档,可以永久注销 —— 不留一条指向空气的边。
        let permanent = deactivate(&document, None).unwrap();
        assert!(is_deactivated(&permanent));
        assert_eq!(successor_of(&permanent), None);
        let _ = old;
    }

    /// 一份读不懂的验证方法必须让整件事失败,而不是被静默丢掉。
    #[test]
    fn an_unreadable_verification_method_stops_the_rekey() {
        let (_, did, mut document) = published(0x70);
        document["verificationMethod"].as_array_mut().unwrap().push(serde_json::json!({
            "id": format!("{did}#key-9"),
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": "not-a-multibase-key",
        }));

        let error = extra_keys(&document, &did).unwrap_err();
        assert!(error.to_string().contains("unreadable"), "{error}");
    }

    /// 文档不能替**别人**的密钥背书。
    #[test]
    fn a_method_from_another_did_is_refused() {
        let (_, did, mut document) = published(0x71);
        document["verificationMethod"].as_array_mut().unwrap().push(serde_json::json!({
            "id": "did:wba:example.com:user:mallory:e1_x#key-2",
            "type": "Multikey",
            "controller": "did:wba:example.com:user:mallory:e1_x",
            "publicKeyMultibase": "z6MkwVDfCg9LbbY6xjH3EZk8YSFQZujV5Y4y1ZWeER9tDiN3",
        }));

        let error = extra_keys(&document, &did).unwrap_err();
        assert!(error.to_string().contains("someone else's namespace"), "{error}");
    }

    #[test]
    fn the_digest_changes_when_the_document_does() {
        let (_, _, document) = published(0x72);
        let before = document_digest(&document).unwrap();
        let mut changed = document.clone();
        changed["deactivated"] = Value::Bool(true);
        assert_ne!(before, document_digest(&changed).unwrap());
        // 摘要稳定:同一份文档永远是同一个。
        assert_eq!(before, document_digest(&document).unwrap());
    }

    /// 读回来的曲线必须和文档里写的一致;签名密钥就是 Ed25519。
    #[test]
    fn an_extra_key_carries_the_curve_its_method_declares() {
        let (_, did, document) = published(0x73);
        let key = extra_keys(&document, &did).unwrap().remove(0);
        assert!(matches!(
            key.relationships.as_slice(),
            [R::Authentication]
        ));
        // 上游看到的必须是 Ed25519,而不是别的曲线 —— 换一条曲线就得换
        // 一整套指纹算法,而 DID 的最后一段是按 Ed25519 的多基指纹算的。
        assert!(matches!(
            key.material,
            ExtraKeyMaterial::Ed25519(_)
        ));
    }
}
