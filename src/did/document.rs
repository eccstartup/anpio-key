//! DID 文档的构造、签名、以及**路径绑定校验**。
//!
//! 绑定校验是这里最要紧的一件事。一个 `did:wba` 的最后一段是
//! `e1_<公钥指纹>` —— 也就是说,DID 这个字符串本身就把公钥写进去了。
//! 于是"文档里的公钥"和"DID 里的指纹"必须互相对得上,否则就是
//! 「拿一个 DID 去兑现一把不属于它的钥匙」。这条检查必须在**发布前**
//! 和**使用前**都做。

use serde_json::Value;

use crate::crypto::thumbprint::e1_segment;
use crate::did::parse::parse_did_wba;
use crate::did::proof_value;
use crate::error::{KeydError, Result};
use crate::sign::{LockedSigningKey, Signer};

// 规格(文档该有什么)住在 [`crate::did::spec`],这里只负责把规格变成一份
// 规范形式的文档并签名。这两个东西分开是为了让"文档里放什么"能独立于
// 钥匙保管往前走 —— 见那个模块的头。
pub use crate::did::spec::{DidDocumentSpec, SpecFile, ROOT_FRAGMENT};

/// 设备签名密钥的名字。第一把用这个名字,不编号 —— 上游按 kid 找它。
pub const DEVICE_SIGN_FRAGMENT: &str = "device-sign";
/// 协商密钥的名字(第一把;再多是 `device-agreement-2`、`-3`,见
/// [`crate::ops::keys`])。
pub const DEVICE_AGREEMENT_FRAGMENT: &str = "device-agreement";

/// 文档里**除根密钥之外**的一把验证方法。
///
/// 上游的 `SuppliedDidKey` 里有一个 `role` 字段,但**它不会写进文档** ——
/// 落到 JSON 里的只有 `id`/`type`/`controller`/`publicKeyMultibase`,加上
/// 它在哪几个关系数组里被列过。所以从文档读回来的时候,role 只能重新猜一个
/// 非根的;好在除此之外它是无损的,而 role 唯一被用到的地方就是"附加密钥
/// 不得是 RootControl"那一条检查。
#[derive(Debug, Clone)]
pub struct ExtraKey {
    pub fragment: String,
    pub material: ExtraKeyMaterial,
    pub relationships: Vec<anp::authentication::DidVerificationRelationship>,
}

/// 附加密钥可以是两种曲线之一,而且**哪种只由文档里的验证方法类型决定**。
///
/// 上游把这事定成了硬配对:Ed25519 只能当签名角色,X25519 只能当
/// `keyAgreement`。所以这里保留曲线信息,给 [`role_for`] 拿去配对 ——
/// 一个"签名角色配 X25519"的组合在本地就拒,不必等上游回一句
/// `UnsupportedProfile`。
#[derive(Debug, Clone, Copy)]
pub enum ExtraKeyMaterial {
    Ed25519(ed25519_dalek::VerifyingKey),
    X25519([u8; 32]),
}

impl ExtraKey {
    pub fn new(
        fragment: impl Into<String>,
        public_key: ed25519_dalek::VerifyingKey,
        relationships: Vec<anp::authentication::DidVerificationRelationship>,
    ) -> Self {
        Self {
            fragment: fragment.into(),
            material: ExtraKeyMaterial::Ed25519(public_key),
            relationships,
        }
    }

    /// 协商密钥:文档里是 `X25519KeyAgreementKey2019`,关系只有 `keyAgreement`。
    pub fn agreement(
        fragment: impl Into<String>,
        public: [u8; 32],
        relationships: Vec<anp::authentication::DidVerificationRelationship>,
    ) -> Self {
        Self {
            fragment: fragment.into(),
            material: ExtraKeyMaterial::X25519(public),
            relationships,
        }
    }
}

/// [`ExtraKey::relationships`] → 上游要的那个 `role`。
///
/// 上游把这两者定成了**一对一**:每个角色在 `validate_supplied_key` 里对应
/// 恰好一组关系,多一个少一个都直接 `InvalidDidDocument`。而 role 本身
/// **不写进文档** —— 落盘的只有关系数组。所以关系是权威,role 是从它推出来
/// 的。曲线也参与配对:X25519 只认 `keyAgreement`,Ed25519 不认它。
///
/// | 关系 | 曲线 | role | 用途 |
/// |---|---|---|---|
/// | `authentication` | Ed25519 | `RequestSigning` | 热密钥:日常签名 |
/// | `assertionMethod` | Ed25519 | `E2eeSigning` | 恢复密钥:预授权签一次迁移 |
/// | 两者都有 | Ed25519 | `DeviceSigning` | 既是热密钥又预授权 |
/// | `keyAgreement` | X25519 | `E2eeAgreement` | 会话密钥协商 |
fn role_for(
    relationships: &[anp::authentication::DidVerificationRelationship],
    material: ExtraKeyMaterial,
) -> Result<anp::authentication::DidKeyRole> {
    use anp::authentication::{DidKeyRole, DidVerificationRelationship as R};

    let mut set = relationships.to_vec();
    set.sort_by_key(|r| *r as u8);
    let before = set.len();
    set.dedup();
    if set.len() != before {
        return Err(KeydError::Did(
            "an extra key lists the same relationship twice".into(),
        ));
    }

    match (set.as_slice(), material) {
        ([R::Authentication], ExtraKeyMaterial::Ed25519(_)) => Ok(DidKeyRole::RequestSigning),
        ([R::AssertionMethod], ExtraKeyMaterial::Ed25519(_)) => Ok(DidKeyRole::E2eeSigning),
        ([R::Authentication, R::AssertionMethod], ExtraKeyMaterial::Ed25519(_)) => {
            Ok(DidKeyRole::DeviceSigning)
        }
        ([R::KeyAgreement], ExtraKeyMaterial::X25519(_)) => Ok(DidKeyRole::E2eeAgreement),
        ([R::KeyAgreement], ExtraKeyMaterial::Ed25519(_)) => Err(KeydError::Did(
            "a `keyAgreement` key has to be X25519, and this one is Ed25519".into(),
        )),
        (_, ExtraKeyMaterial::X25519(_)) => Err(KeydError::Did(
            "an X25519 key may only sit under `keyAgreement` — it cannot sign, and a document \
             that lists it anywhere else would claim otherwise"
                .into(),
        )),
        _ => Err(KeydError::Did(
            "an extra key has no relationships at all, so no document would list it — \
             a verification method nobody refers to is not a key anyone can use"
                .into(),
        )),
    }
}

/// 构造一份**未签名**的 did:wba 文档,同时把它的 DID 返回。
///
/// 把 DID 和文档一起返回是刻意的:DID 的最后一段是当前这把公钥算出来的,
/// 调用方没有机会自己拼一个和公钥对不上的 DID 出来。
pub fn build_unsigned(
    spec: &DidDocumentSpec,
    root: &ed25519_dalek::VerifyingKey,
) -> Result<(String, Value)> {
    build_unsigned_with(spec, root, Vec::new())
}

/// 同上,但允许在根密钥之外再挂几把。热密钥和恢复密钥走这里。
pub fn build_unsigned_with(
    spec: &DidDocumentSpec,
    root: &ed25519_dalek::VerifyingKey,
    extra: Vec<ExtraKey>,
) -> Result<(String, Value)> {
    let additional_keys = extra
        .into_iter()
        .map(|key| {
            // 上游拒收 role 为 `RootControl` 的附加密钥(index > 0 时直接
            // `InvalidDidDocument`)。这不是我们可以绕的:一个 DID 只能有
            // 一个根,其余的都得是别的角色 —— 而具体是哪个角色,由它
            // 挂在哪些关系下、以及它是哪种曲线决定(见 [`role_for`])。
            let role = role_for(&key.relationships, key.material)?;
            let public_key = match key.material {
                ExtraKeyMaterial::Ed25519(key) => anp::PublicKeyMaterial::Ed25519(key),
                ExtraKeyMaterial::X25519(key) => anp::PublicKeyMaterial::X25519(key),
            };
            Ok(anp::authentication::SuppliedDidKey {
                fragment: key.fragment,
                role,
                public_key,
                relationships: key.relationships,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let options = anp::authentication::SuppliedE1DidDocumentOptions {
        port: spec.port,
        path_segments: spec.path_segments.clone(),
        agent_description_url: spec.agent_description_url.clone(),
        services: spec.services.clone(),
        root_key: anp::authentication::SuppliedDidKey {
            fragment: spec.fragment.clone(),
            role: anp::authentication::DidKeyRole::RootControl,
            public_key: anp::PublicKeyMaterial::Ed25519(*root),
            relationships: vec![
                anp::authentication::DidVerificationRelationship::Authentication,
                anp::authentication::DidVerificationRelationship::AssertionMethod,
            ],
        },
        additional_keys,
    };

    let document = anp::authentication::build_unsigned_e1_did_document(&spec.host, options)
        .map_err(|e| KeydError::Upstream(format!("building the DID document failed: {e}")))?;

    let did = document
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| KeydError::Upstream("the built document has no id".into()))?
        .to_string();

    Ok((did, document))
}

/// 用守护进程里的私钥给文档盖上 `DataIntegrityProof`。
///
/// 私钥只在 `Signer::sign` 里露一次面,而且是借出去的;
/// [`crate::did::proof::complete`] 会**自己拿公钥验一遍**我们刚签出来的签名,
/// 所以"签错钥匙"这种事在这里就会当场炸掉,不会流到磁盘上。
///
/// 形状由 [`crate::did::proof`] 定:规范的 `z` + base58btc,文档的 `@context`
/// 进 proof configuration 再签。对端(awiki-open-server、anp-sdk)和 `anp`
/// 1.0.6 的验签读的都是这一条,见那个模块的头。
pub fn sign_document(
    document: &Value,
    key: &LockedSigningKey,
    verification_method: &str,
) -> Result<Value> {
    let created = crate::did::proof::timestamp(time::OffsetDateTime::now_utc());
    let prepared = crate::did::proof::prepare(
        document,
        &key.anp_public_key()?,
        crate::did::proof::Facts {
            verification_method,
            purpose: "assertionMethod",
            created: &created,
            domain: None,
            challenge: None,
        },
    )?;

    let signature = key.sign(prepared.signing_input())?;
    Ok(crate::did::proof::complete(prepared, &signature)?.document)
}

/// 从 DID 字符串 + 公钥**重建**出那份文档。
///
/// 签名路径需要文档,但签名路径手里只有磁盘上的信封(它存了 DID 和公钥),
/// 没有当初构造文档时的那些参数。好在 DID 本身就是**坐标**的编码 ——
/// 域名、端口、路径段全在里面。所以这里从 DID 反推规格,可选项留空。
///
/// 想带上 agent description 或 service 条目(WNS handle 就在那一档)的,
/// 走 [`rebuild_with`] 并给一份补齐了的规格。
///
/// 重建之后**必须**和原来的 DID 逐字节相等,否则拒。这一条保证了
/// 「我们手上的 DID」和「我们重建出的文档」说的是同一件事;不相等就说明
/// 这个 DID 不是规范形式(比如被额外百分号编码过),那就别猜,直接失败。
pub fn rebuild(did: &str, root: &ed25519_dalek::VerifyingKey) -> Result<Value> {
    rebuild_with(&DidDocumentSpec::coordinates_from_did(did)?, did, root, Vec::new())
}

/// 同上,但用**给定的规格**重建,并把附加密钥一起挂回去。
///
/// **给已经挂了热密钥/恢复密钥的 DID 重发文档时必须走这一条。** 走
/// [`rebuild`] 等于拿着一份只有根密钥的文档去盖掉线上那份 —— 而
/// `deactivated`/`successorDid` 也好、热密钥也好、恢复密钥也好,全在
/// 那次重发里消失。这正是"文档是以 DIDs 为键的、覆盖写"这件事最危险的地方:
/// 覆盖不会报错,只会静静地少掉东西。
///
/// `spec` 必须是 `did` 的规格:坐标对不上就直接拒,而不是拿它去签一份
/// 挂在别的地方的文档。
pub fn rebuild_with(
    spec: &DidDocumentSpec,
    did: &str,
    root: &ed25519_dalek::VerifyingKey,
    extra: Vec<ExtraKey>,
) -> Result<Value> {
    spec.check_canonical(did, root)?;
    let (_, document) = build_unsigned_with(spec, root, extra)?;
    Ok(document)
}

/// 一份**可以发布出去**的文档:重建 → 签名 → 自检,三步缺一不可。
///
/// `publish` 走的也是这三步(它另外还要问口令、决定写到哪去、把本地那份里
/// 已有的附加密钥带上 —— 那些是"人"的部分)。测试要一份"真的会被发布出去"
/// 的文档时走这里,而不是手拼一份没签名的:手拼的那种,要到验签那一刻才
/// 发现不是一回事。
pub fn publishable(
    spec: &DidDocumentSpec,
    did: &str,
    key: &LockedSigningKey,
) -> Result<Value> {
    let unsigned = rebuild_with(spec, did, &key.verifying_key()?, Vec::new())?;
    let signed = sign_document(&unsigned, key, &key.id().kid)?;
    verify_path_binding(did, &signed)?;
    Ok(signed)
}

/// 校验一份文档确实是它自称的那个 DID 的文档。
///
/// 三道,缺一不可:
/// 1. `document.id` 就是我们要找的 DID —— 上游的绑定检查是从文档里读 id
///    再自己和自己比,所以它查不出"这是别人的文档";
/// 2. **自己重算** `e1_` 指纹,和对得上才算过 —— 给的是能查原因的错误;
/// 3. 上游的规范性检查(含 proof 验签)。
pub fn verify_path_binding(did: &str, document: &Value) -> Result<()> {
    let parts = parse_did_wba(did)?;
    let expected = parts
        .e1_segment()
        .ok_or_else(|| KeydError::Did(format!("{did} has no e1_ binding segment")))?;

    let document_id = document.get("id").and_then(Value::as_str).unwrap_or_default();
    if document_id != did {
        return Err(KeydError::Did(format!(
            "this document is {document_id:?}, not {did:?}"
        )));
    }

    let method = authentication_method(document).ok_or_else(|| {
        KeydError::Did("no authentication-authorized verification method in the document".into())
    })?;
    let material = anp::authentication::extract_public_key(&method)
        .map_err(|e| KeydError::Did(format!("unreadable verification method: {e}")))?;
    let actual = match &material {
        anp::PublicKeyMaterial::Ed25519(pk) => e1_segment(pk)?,
        _ => {
            return Err(KeydError::Did(
                "the e1_ path binding requires an Ed25519 root key".into(),
            ))
        }
    };
    if actual != expected {
        return Err(KeydError::Did(format!(
            "{did} claims fingerprint {expected}, but its key hashes to {actual}"
        )));
    }

    if !upstream_accepts_the_proof(document)? {
        return Err(KeydError::Did(format!(
            "the document for {did} failed the normative did:wba binding check"
        )));
    }
    Ok(())
}

/// 上游的规范性检查,两种 `proofValue` 方言都认。
///
/// 原样的文档先过一遍:这覆盖规范那条(`z` + `@context` 进签名基)和裸
/// base64url。不成立再把 `z` 换成 base64url 字母表过一遍 —— 有的文档的 `z`
/// 是换字母表得来的,签名基里没有 `@context`,上游对这条旧写法另有一条分支。
/// 换字母表不动签名,`proofValue` 本来就不进签名输入。
fn upstream_accepts_the_proof(document: &Value) -> Result<bool> {
    if anp::authentication::validate_did_document_binding(document, true) {
        return Ok(true);
    }
    if !document
        .get("proof")
        .and_then(|proof| proof.get("proofValue"))
        .and_then(Value::as_str)
        .is_some_and(proof_value::is_multibase)
    {
        return Ok(false);
    }
    let mut legacy = document.clone();
    proof_value::into_base64url(&mut legacy)?;
    Ok(anp::authentication::validate_did_document_binding(&legacy, true))
}

/// 找回一份文档里被 `authentication` 授权的那把验证方法。
fn authentication_method(document: &Value) -> Option<Value> {
    let authorized = document.get("authentication")?.as_array()?;
    authorized.iter().find_map(|entry| {
        // `authentication` 里可能是内联对象,也可能是一个引用字符串。
        let id = entry
            .as_str()
            .or_else(|| entry.get("id").and_then(Value::as_str))?;
        if !anp::authentication::is_authentication_authorized(document, id) {
            return None;
        }
        anp::authentication::find_verification_method(document, id)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hygiene::LockedBytes;
    use crate::keystore::record::KeyId;

    fn key(seed_byte: u8) -> LockedSigningKey {
        let seed = LockedBytes::fill(|d| *d = [seed_byte; 32]).unwrap();
        LockedSigningKey::from_seed(
            KeyId {
                did: String::new(),
                kid: String::new(),
                thumbprint: String::new(),
            },
            seed,
        )
        .unwrap()
    }

    fn spec() -> DidDocumentSpec {
        DidDocumentSpec::new("example.com", vec!["user".into(), "alice".into()])
    }

    fn signed_document(seed_byte: u8) -> (String, Value) {
        let k = key(seed_byte);
        let (did, unsigned) = build_unsigned(&spec(), &k.verifying_key().unwrap()).unwrap();
        let method = format!("{did}#{ROOT_FRAGMENT}");
        let signed = sign_document(&unsigned, &k, &method).unwrap();
        (did, signed)
    }

    #[test]
    fn the_did_ends_with_the_keys_own_fingerprint() {
        let k = key(3);
        let (did, doc) = build_unsigned(&spec(), &k.verifying_key().unwrap()).unwrap();

        let expected = e1_segment(&k.verifying_key().unwrap()).unwrap();
        assert!(did.starts_with("did:wba:example.com:user:alice:"), "{did}");
        assert!(did.ends_with(&expected), "{did} should end with {expected}");
        assert_eq!(doc["id"], did.as_str());
    }

    #[test]
    fn the_root_key_lands_in_authentication_and_assertion() {
        let k = key(4);
        let (did, doc) = build_unsigned(&spec(), &k.verifying_key().unwrap()).unwrap();
        let method = format!("{did}#{ROOT_FRAGMENT}");

        for relationship in ["authentication", "assertionMethod"] {
            let list = doc[relationship].as_array().unwrap();
            assert!(
                list.iter().any(|v| v.as_str() == Some(method.as_str())),
                "{relationship} must list the root key"
            );
        }
    }

    #[test]
    fn signing_produces_a_verifiable_data_integrity_proof() {
        let (did, doc) = signed_document(5);
        let proof = &doc["proof"];

        assert_eq!(proof["type"], anp::proof::PROOF_TYPE_DATA_INTEGRITY);
        assert_eq!(proof["cryptosuite"], anp::proof::CRYPTOSUITE_EDDSA_JCS_2022);
        assert_eq!(proof["proofPurpose"], "assertionMethod");
        assert_eq!(proof["verificationMethod"], format!("{did}#{ROOT_FRAGMENT}"));

        // 上游的规范性检查会连 proof 一起验,而且读的就是规范那条:文档的
        // `@context` 并进 proof configuration 之后再算签名基。
        assert!(anp::authentication::validate_did_document_binding(&doc, true));
        assert!(verify_path_binding(&did, &doc).is_ok());
    }

    /// 发出去的那一份必须是 ANP-03 §2.5.5 要的 multibase base58btc。
    /// 对端只认这一种:换成别的,注册那一步会原样被拒。
    #[test]
    fn a_published_proof_value_is_multibase_base58btc() {
        let (_, doc) = signed_document(9);
        let proof_value = doc["proof"]["proofValue"].as_str().unwrap();
        assert!(proof_value.starts_with('z'), "got {proof_value:?}");
        let decoded = bs58::decode(&proof_value[1..]).into_vec().unwrap();
        assert_eq!(decoded.len(), 64);
    }

    /// 核心攻击面:拿一份**别的钥匙**签出来的文档,冒充成这个 DID 的文档。
    /// 第一步就得被 DID 里的指纹拦住。
    #[test]
    fn a_document_signed_by_another_key_cannot_claim_this_did() {
        let (did, _) = signed_document(6);
        let (_, other_doc) = signed_document(7);

        // 把别的文档的 id 改成我们问的这个 DID,假装它是。
        let mut imposter = other_doc.clone();
        imposter["id"] = Value::String(did.clone());

        assert!(
            verify_path_binding(&did, &imposter).is_err(),
            "a document whose key does not hash to the DID's fingerprint must be refused"
        );
    }

    /// 把文档里的公钥换成另一把 —— 指纹对不上,必须拒。
    #[test]
    fn swapping_the_public_key_breaks_the_binding() {
        let (did, doc) = signed_document(8);
        let other = key(9);

        let mut tampered = doc.clone();
        let method_id = format!("{did}#{ROOT_FRAGMENT}");
        let multibase = other.public_multibase().to_string();
        for m in tampered["verificationMethod"].as_array_mut().unwrap() {
            if m["id"].as_str() == Some(method_id.as_str()) {
                m["publicKeyMultibase"] = Value::String(multibase.clone());
            }
        }

        assert!(verify_path_binding(&did, &tampered).is_err());
    }

    #[test]
    fn an_unsigned_document_does_not_pass_the_binding_check() {
        let k = key(10);
        let (did, unsigned) = build_unsigned(&spec(), &k.verifying_key().unwrap()).unwrap();

        // 指纹那一条过得去(公钥确实是对的),但没有 proof,规范性检查必须拒。
        assert!(verify_path_binding(&did, &unsigned).is_err());
    }

    #[test]
    fn a_did_without_an_e1_segment_is_refused() {
        let (_, doc) = signed_document(11);
        assert!(verify_path_binding("did:wba:example.com:user:alice", &doc).is_err());
    }

    #[test]
    fn port_and_extra_path_segments_survive_the_round_trip() {
        let k = key(12);
        let spec = DidDocumentSpec::new("example.com", vec!["user".into(), "bob".into()])
            .with_port(8443);
        let (did, unsigned) = build_unsigned(&spec, &k.verifying_key().unwrap()).unwrap();

        assert!(did.starts_with("did:wba:example.com%3A8443:user:bob:"), "{did}");
        // 端口必须能从 DID 解回 URL —— 否则发布出去没人找得到。
        assert_eq!(
            crate::did::parse::did_url_path(&did).unwrap(),
            format!(
                "https://example.com:8443/user/bob/{}/did.json",
                e1_segment(&k.verifying_key().unwrap()).unwrap()
            )
        );

        let method = format!("{did}#{ROOT_FRAGMENT}");
        let signed = sign_document(&unsigned, &k, &method).unwrap();
        assert!(verify_path_binding(&did, &signed).is_ok());
    }
}
