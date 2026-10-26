//! 对象/文档 proof(P5):调用方给对象或完整文档,daemon 用托管键把 proof 拼出来。
//!
//! - 对象 proof 走 [`anp::proof::prepare_object_proof`] /
//!   [`anp::proof::complete_object_proof`]:purpose 固定 `assertionMethod`
//!   (上游常量),`proofValue` 是 base58btc(`z` 前缀)。
//! - 文档 proof 走 [`crate::did::proof`]:`proofValue` 是 `z` + base58btc,
//!   文档的 `@context`(有的话)并进 proof configuration 再签 —— W3C
//!   `vc-di-eddsa` 那一版签名基,和上游 1.0.6 的验签、和对端都一致。purpose
//!   由调用方在 [`ProofPurpose`] 里选;`type` 与 `cryptosuite` 由 daemon 定死
//!   (DataIntegrityProof / eddsa-jcs-2022)—— 这两个值一改,验签方看到的就是
//!   另一种 proof,不能让调用方按请求换。
//!
//! 边界:
//!
//! - **键不在请求里**。键由 grant 决定;`verificationMethod` 由 daemon 用
//!   `{did}#{kid}` 拼,调用方写不进来。
//! - **`created` 用 daemon 的钟**。它是签名基的一部分,让调用方定时刻等于让
//!   它重放一条老 proof;调用方要的时刻就是返回的 proof 里那一个。
//! - 文档 proof 只对**属于这把键的完整文档**签:`id` 必须等于键的 DID、DID
//!   路径段绑定必须过、而这把键必须还挂在文档上。否则一条 proof 等于把整个
//!   身份交出去。
//! - 对象 proof 只认绑了 `device_assertion` 的键:它是设备断言,不是"任意
//!   对象上盖个章"。

use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::{KeydError, Result};
use crate::sign::{LockedSigningKey, Signer};

/// 文档/对象的规范化上限。帧本身 64 KiB,信封和其他字段要留出余量。
pub const MAX_BYTES: usize = 32 * 1024;
/// proof 的结果能取多久。proof 本身不过期,这个数只限制缓存窗口。
pub const CACHE_SECONDS: i64 = 300;

const OBJECT_DIGEST_DOMAIN: &[u8] = b"anp.sign-object-proof.v1\0";
const DOCUMENT_DIGEST_DOMAIN: &[u8] = b"anp.sign-document-proof.v1\0";

fn invalid() -> KeydError {
    KeydError::Misuse("PROOF_INVALID".into())
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// W3C 的 proof purpose。只收这两个:其余名字在这条路上没有对应的签名形状,
/// 收了也只是给策略白名单添一个永远不会被用到的词。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofPurpose {
    AssertionMethod,
    Authentication,
}

impl ProofPurpose {
    /// 固定顺序。启动审计和错误消息都按这个顺序列。
    pub const ALL: [Self; 2] = [Self::AssertionMethod, Self::Authentication];

    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "assertionMethod" => Ok(Self::AssertionMethod),
            "authentication" => Ok(Self::Authentication),
            _ => Err(invalid()),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::AssertionMethod => "assertionMethod",
            Self::Authentication => "authentication",
        }
    }
}

/// 一次 proof 的产物。`value` 是带上 `proof` 之后的完整对象/文档。
///
/// `options` 是审计里那一段(proof options 与摘要),`signature_base_digest`
/// 是真正被签名的那串字节的摘要 —— 两者都不含文档正文。
#[derive(Debug, Clone, Serialize)]
pub struct SignedProof {
    pub value: Value,
    pub proof: Value,
    pub created_at: i64,
    pub signature_base_digest: String,
    pub options: Value,
}

/// 校验过的一次对象 proof 请求:对象是 JSON 对象,摘下顶层 `proof` 之后的
/// 规范化字节在上限内。
#[derive(Debug, Clone)]
pub struct ObjectProofRequest {
    document: Value,
    canonical: Vec<u8>,
}

/// 校验过的一次文档 proof 请求:除了对象那一套,还带上 purpose 与
/// domain/challenge。
#[derive(Debug, Clone)]
pub struct DocumentProofRequest {
    document: Value,
    canonical: Vec<u8>,
    purpose: ProofPurpose,
    domain: Option<String>,
    challenge: Option<String>,
}

impl ObjectProofRequest {
    pub fn new(document: Value) -> Result<Self> {
        let canonical = canonical_without_proof(&document)?;
        Ok(Self { document, canonical })
    }

    /// 去重用的输入摘要。对象按自己的域算,和文档 proof 同形不同域。
    pub fn digest(&self) -> String {
        digest_of(OBJECT_DIGEST_DOMAIN, &self.canonical)
    }

    /// `verification_method` 是键的完整 `{did}#{fragment}`(即 `KeyRecord.kid`
    /// 本身),上游会核它确实落在 `did` 的命名空间里。
    pub fn sign(
        &self,
        key: &LockedSigningKey,
        did: &str,
        verification_method: &str,
        created_at: i64,
    ) -> Result<SignedProof> {
        let created = stamp(created_at)?;
        let verification_method = verification_method.to_owned();
        let public = key.anp_public_key()?;
        let prepared = anp::proof::prepare_object_proof(
            &self.document,
            &public,
            &verification_method,
            did,
            Some(created.clone()),
        )
        .map_err(|_| invalid())?;
        let signature_base_digest = hex_of(&Sha256::digest(prepared.signing_input()));
        let signature = key.sign(prepared.signing_input())?;
        let value =
            anp::proof::complete_object_proof(prepared, &signature).map_err(|_| invalid())?;
        let proof = value.get("proof").cloned().ok_or_else(invalid)?;
        Ok(SignedProof {
            options: json!({
                "purpose": ProofPurpose::AssertionMethod.name(),
                "proof_type": anp::proof::PROOF_TYPE_DATA_INTEGRITY,
                "cryptosuite": anp::proof::CRYPTOSUITE_EDDSA_JCS_2022,
                "verification_method": verification_method,
                "created": created,
                "document_bytes": self.canonical.len(),
                "document_digest": hex_of(&Sha256::digest(&self.canonical)),
            }),
            value,
            proof,
            created_at,
            signature_base_digest,
        })
    }
}

impl DocumentProofRequest {
    /// 线上形状。`proof_purpose` 缺省是 `assertionMethod`(上游 `prepare_w3c_proof`
    /// 的默认值,和对象 proof 的固定值一致);`domain`/`challenge` 只在文档
    /// proof 上有,原样进签名基。
    pub fn from_wire(document: Value, proof_purpose: Option<&str>) -> Result<Self> {
        Self::new(document, proof_purpose, None, None)
    }

    pub fn new(
        document: Value,
        proof_purpose: Option<&str>,
        domain: Option<String>,
        challenge: Option<String>,
    ) -> Result<Self> {
        let purpose = match proof_purpose {
            Some(name) => ProofPurpose::parse(name)?,
            None => ProofPurpose::AssertionMethod,
        };
        for (code, value) in [
            ("PROOF_DOMAIN_INVALID", &domain),
            ("PROOF_CHALLENGE_INVALID", &challenge),
        ] {
            if let Some(value) = value {
                if value.is_empty()
                    || value.len() > 256
                    || !value.bytes().all(|byte| byte.is_ascii_graphic())
                {
                    return Err(KeydError::Misuse(code.into()));
                }
            }
        }
        let canonical = canonical_without_proof(&document)?;
        Ok(Self {
            document,
            canonical,
            purpose,
            domain,
            challenge,
        })
    }

    pub fn purpose(&self) -> ProofPurpose {
        self.purpose
    }

    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    pub fn challenge(&self) -> Option<&str> {
        self.challenge.as_deref()
    }

    /// 摘要里带上 purpose 与 domain/challenge:同一个 `request_id` 换了其中
    /// 任何一项都是另一个请求,重放会撞 `REQUEST_ID_CONFLICT` 而不是命中缓存。
    pub fn digest(&self) -> String {
        let mut material = self.canonical.clone();
        material.extend_from_slice(b"\0");
        material.extend_from_slice(self.purpose.name().as_bytes());
        if let Some(domain) = &self.domain {
            material.extend_from_slice(b"\0domain\0");
            material.extend_from_slice(domain.as_bytes());
        }
        if let Some(challenge) = &self.challenge {
            material.extend_from_slice(b"\0challenge\0");
            material.extend_from_slice(challenge.as_bytes());
        }
        digest_of(DOCUMENT_DIGEST_DOMAIN, &material)
    }

    /// 这份文档是不是这把键的文档。
    ///
    /// 三条都要过,少一条就是"拿根钥匙给别人的文档盖章":
    /// ① `id` 等于键的 DID;② 文档锚在这个 DID 上(`e1_`/`k1_` 段编的是绑定
    /// 键的指纹,文档里得真有那把键);③ 这把键的 `{did}#{fragment}` 还挂在
    /// 文档里。
    ///
    /// ② 不看文档自带的 `proof`:调用方交上来的常是刚改过、要去重新签的文档,
    /// 它要么没 proof,要么还挂着上一条。上游
    /// [`anp::authentication::validate_did_document_binding`] 对 `e1_` 的 DID
    /// 一律连 proof 一起验(参数只对 `k1_` 有效),用它就等于要求先有签名 ——
    /// 那正是这条路要产出的东西。
    ///
    /// 授权在**扣配额之前**调它,所以一份不合规的文档是明确的
    /// `PROOF_INVALID`,不是"可能签了、可能没签"的 `OUTCOME_UNKNOWN`。
    pub fn verify_binding(&self, did: &str, verification_method: &str) -> Result<()> {
        if self.document.get("id").and_then(Value::as_str) != Some(did) {
            return Err(invalid());
        }
        if !anchored_to(&self.document, did) {
            return Err(invalid());
        }
        if verification_method
            .strip_prefix(did)
            .and_then(|rest| rest.strip_prefix('#'))
            .is_none()
            || anp::authentication::find_verification_method(&self.document, verification_method)
                .is_none()
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// 同对象 proof:`verification_method` 是完整的 `{did}#{fragment}`。
    /// 这里不收 `did` —— 文档自己的 `id` 就是它,而绑定已经由
    /// [`DocumentProofRequest::verify_binding`] 在授权那一步判过了。
    pub fn sign(
        &self,
        key: &LockedSigningKey,
        verification_method: &str,
        created_at: i64,
    ) -> Result<SignedProof> {
        let created = stamp(created_at)?;
        let verification_method = verification_method.to_owned();
        let public = key.anp_public_key()?;
        let prepared = crate::did::proof::prepare(
            &self.document,
            &public,
            crate::did::proof::Facts {
                verification_method: &verification_method,
                purpose: self.purpose.name(),
                created: &created,
                domain: self.domain.as_deref(),
                challenge: self.challenge.as_deref(),
            },
        )
        .map_err(|_| invalid())?;
        let signature_base_digest = hex_of(&Sha256::digest(prepared.signing_input()));
        let signature = key.sign(prepared.signing_input())?;
        let signed = crate::did::proof::complete(prepared, &signature).map_err(|_| invalid())?;
        let value = signed.document;
        let proof = signed.proof;
        Ok(SignedProof {
            options: json!({
                "purpose": self.purpose.name(),
                "proof_type": anp::proof::PROOF_TYPE_DATA_INTEGRITY,
                "cryptosuite": anp::proof::CRYPTOSUITE_EDDSA_JCS_2022,
                "verification_method": verification_method,
                "created": created,
                "domain": self.domain,
                "challenge": self.challenge,
                "document_bytes": self.canonical.len(),
                "document_digest": hex_of(&Sha256::digest(&self.canonical)),
            }),
            value,
            proof,
            created_at,
            signature_base_digest,
        })
    }
}

/// 文档里有一把键就是 DID 路径段编出来的那一把。
///
/// 不带 `e1_`/`k1_` 段的 DID 没有可核的锚,和上游一样放行。
fn anchored_to(document: &Value, did: &str) -> bool {
    let segment = did.rsplit(':').next().unwrap_or_default();
    if !segment.starts_with("e1_") && !segment.starts_with("k1_") {
        return true;
    }
    document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .is_some_and(|methods| {
            methods
                .iter()
                .any(|method| anp::authentication::verify_did_key_binding(did, method))
        })
}

/// 下上游 `prepare_*` 之前的那一份:必须是 JSON 对象,摘掉顶层 `proof` 之后
/// 的规范化字节要非空且在上限内。顶层 `proof` 不参与签名(上游同样先摘),
/// 所以摘要也只算摘过的那份 —— 带不带旧 proof 是同一个请求。
fn canonical_without_proof(document: &Value) -> Result<Vec<u8>> {
    if !document.is_object() {
        return Err(invalid());
    }
    let mut signing = document.clone();
    if let Some(object) = signing.as_object_mut() {
        object.remove("proof");
    }
    let canonical = serde_json_canonicalizer::to_vec(&signing).map_err(|_| invalid())?;
    if canonical.is_empty() || canonical.len() > MAX_BYTES {
        return Err(invalid());
    }
    Ok(canonical)
}

fn digest_of(domain: &[u8], material: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(material);
    hex_of(&hasher.finalize())
}

/// 上游要的是 RFC 3339;两边用同一个形状(`%Y-%m-%dT%H:%M:%SZ`),免得
/// proof 里的 `created` 一会儿是 `Z`、一会儿是 `+00:00`。
fn stamp(unix_seconds: i64) -> Result<String> {
    let at = time::OffsetDateTime::from_unix_timestamp(unix_seconds)
        .map_err(|_| KeydError::Protocol("PROOF_TIME_INVALID".into()))?;
    Ok(crate::did::proof::timestamp(at))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hygiene::LockedBytes;
    use crate::keystore::record::KeyId;

    const DID: &str = "did:example:alice";

    fn key() -> LockedSigningKey {
        LockedSigningKey::from_seed(
            KeyId {
                did: DID.into(),
                kid: format!("{DID}#key-1"),
                thumbprint: "e1_test".into(),
            },
            LockedBytes::generate().unwrap(),
        )
        .unwrap()
    }

    fn issuer_document(key: &LockedSigningKey) -> Value {
        let verification_method = format!("{DID}#key-1");
        json!({
            "id": DID,
            "verificationMethod": [{
                "id": verification_method,
                "type": "Multikey",
                "controller": DID,
                "publicKeyMultibase": key.public_multibase(),
            }],
            "assertionMethod": [verification_method],
            "authentication": [verification_method],
        })
    }

    #[test]
    fn an_object_proof_verifies_against_the_upstream_verifier() {
        let key = key();
        let document = json!({"kind": "device-join", "nonce": "0011", "threshold": 2});
        let request = ObjectProofRequest::new(document).unwrap();
        let signed = request
            .sign(&key, DID, &format!("{DID}#key-1"), 1_700_000_000)
            .unwrap();
        // 上游的验签器是消费方要用的那一个:proof 的形状、编码、签名基都按它的
        // 定义算,这里逐项过一遍。
        anp::proof::verify_object_proof(&signed.value, DID, &issuer_document(&key)).unwrap();
        assert_eq!(signed.proof["proofPurpose"], json!("assertionMethod"));
        assert_eq!(signed.proof["type"], json!("DataIntegrityProof"));
        assert_eq!(signed.proof["cryptosuite"], json!("eddsa-jcs-2022"));
        assert_eq!(signed.proof["verificationMethod"], json!(format!("{DID}#key-1")));
        assert_eq!(signed.proof["created"], json!("2023-11-14T22:13:20Z"));
        assert!(signed.proof["proofValue"]
            .as_str()
            .unwrap()
            .starts_with('z'));
        assert_eq!(signed.value["kind"], json!("device-join"));
        assert_eq!(signed.options["purpose"], json!("assertionMethod"));
        // 同一个请求同一个 id 重放:摘要不变,缓存才有意义。
        assert_eq!(request.digest(), ObjectProofRequest::new(signed.value.clone()).unwrap().digest());
    }

    #[test]
    fn a_document_proof_verifies_against_the_upstream_verifier() {
        let key = key();
        let request = DocumentProofRequest::new(
            issuer_document(&key),
            Some("authentication"),
            Some("chat.alpha".into()),
            Some("challenge-1".into()),
        )
        .unwrap();
        request.verify_binding(DID, &format!("{DID}#key-1")).unwrap();
        let signed = request.sign(&key, &format!("{DID}#key-1"), 1_700_000_000).unwrap();

        assert!(anp::proof::verify_w3c_proof(
            &signed.value,
            &key.anp_public_key().unwrap(),
            anp::proof::ProofVerificationOptions {
                expected_purpose: Some("authentication".into()),
                expected_domain: Some("chat.alpha".into()),
                expected_challenge: Some("challenge-1".into()),
            },
        ));
        // 换了其中任何一项都验不过 —— 这三项都在签名基里。
        assert!(!anp::proof::verify_w3c_proof(
            &signed.value,
            &key.anp_public_key().unwrap(),
            anp::proof::ProofVerificationOptions {
                expected_purpose: Some("assertionMethod".into()),
                expected_domain: None,
                expected_challenge: None,
            },
        ));
        assert_eq!(signed.proof["proofPurpose"], json!("authentication"));
        assert_eq!(signed.proof["created"], json!("2023-11-14T22:13:20Z"));
        assert_eq!(signed.value["id"], json!(DID));
        // 规范要的字母表:`z` + base58btc,不是上游那个裸 base64url。
        assert!(signed.proof["proofValue"].as_str().unwrap().starts_with('z'));

        // 缺省 purpose 是 assertionMethod,和不给 domain/challenge 一样验得过。
        let plain = DocumentProofRequest::from_wire(issuer_document(&key), None).unwrap();
        assert_eq!(plain.purpose(), ProofPurpose::AssertionMethod);
        let signed = plain.sign(&key, &format!("{DID}#key-1"), 1_700_000_000).unwrap();
        assert!(anp::proof::verify_w3c_proof(
            &signed.value,
            &key.anp_public_key().unwrap(),
            anp::proof::ProofVerificationOptions {
                expected_purpose: Some("assertionMethod".into()),
                expected_domain: None,
                expected_challenge: None,
            },
        ));
    }

    /// 文档带 `@context` 时,它必须进 proof configuration。
    ///
    /// 上游读到 `z` 会把文档的 `@context` 补进 proof options 再算签名基;
    /// 这一步验得过,就说明我们签的正是带 `@context` 的那一条 —— 反过来,
    /// "签完再换字母表"那种产物在这里一定失败。
    #[test]
    fn a_document_with_context_is_signed_over_that_context() {
        let key = key();
        let mut document = issuer_document(&key);
        document["@context"] = json!([
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
        ]);
        let context = document["@context"].clone();
        let request = DocumentProofRequest::from_wire(document, None).unwrap();
        let signed = request.sign(&key, &format!("{DID}#key-1"), 1_700_000_000).unwrap();

        assert!(anp::proof::verify_w3c_proof(
            &signed.value,
            &key.anp_public_key().unwrap(),
            anp::proof::ProofVerificationOptions {
                expected_purpose: Some("assertionMethod".into()),
                expected_domain: None,
                expected_challenge: None,
            },
        ));
        // `@context` 进的是签名基,不是产出的 proof 对象。
        assert!(signed.proof.get("@context").is_none());
        assert_eq!(signed.value["@context"], context);
    }

    #[test]
    fn a_document_proof_only_covers_the_key_that_signed_it() {
        let key = key();
        let document = issuer_document(&key);
        let request = DocumentProofRequest::from_wire(document, None).unwrap();
        request.verify_binding(DID, &format!("{DID}#key-1")).unwrap();
        // 不是这把键的 DID。
        assert!(request
            .verify_binding("did:example:bob", &format!("{DID}#key-1"))
            .is_err());
        // 是这把键的 DID,但这把键不在文档里。
        assert!(request
            .verify_binding(DID, &format!("{DID}#key-2"))
            .is_err());
        // 方法名不在这个 DID 的命名空间里,哪怕文档里真有这么一条。
        assert!(request.verify_binding(DID, "key-1").is_err());

        // 路径段绑定不成立(把别人的 id 抄过来)。
        let mut forged = issuer_document(&key);
        forged["id"] = json!("did:wba:example.com:user:alice:e1_other");
        let forged_request =
            DocumentProofRequest::new(forged, None, None, None).unwrap();
        assert!(forged_request
            .verify_binding(
                "did:wba:example.com:user:alice:e1_other",
                "did:wba:example.com:user:alice:e1_other#key-1"
            )
            .is_err());
    }

    /// `e1_` 段就是从绑定键算出来的。文档还没签(没有 `proof`)也得核得上 ——
    /// 这条路要签的正是那份要去签的文档。
    #[test]
    fn an_unsigned_document_is_bound_by_the_identity_path_segment_alone() {
        let key = key();
        let method = json!({
            "id": "placeholder#key-1",
            "type": "Multikey",
            "controller": "placeholder",
            "publicKeyMultibase": key.public_multibase(),
        });
        let public = anp::authentication::extract_public_key(&method).unwrap();
        let fingerprint = anp::authentication::compute_multikey_fingerprint(&public).unwrap();
        let did = format!("did:wba:example.com:user:alice:e1_{fingerprint}");
        let verification_method = format!("{did}#key-1");
        let document = json!({
            "id": did,
            "verificationMethod": [{
                "id": verification_method,
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": key.public_multibase(),
            }],
            "assertionMethod": [verification_method],
            "authentication": [verification_method],
        });
        let request = DocumentProofRequest::from_wire(document, None).unwrap();
        request.verify_binding(&did, &verification_method).unwrap();
        let signed = request.sign(&key, &verification_method, 1_700_000_000).unwrap();
        assert!(anp::proof::verify_w3c_proof(
            &signed.value,
            &key.anp_public_key().unwrap(),
            anp::proof::ProofVerificationOptions {
                expected_purpose: Some("assertionMethod".into()),
                expected_domain: None,
                expected_challenge: None,
            },
        ));

        // 同一个文档配一个指纹对不上的 DID:不是这份身份的文档。
        let wrong = format!("did:wba:example.com:user:bob:e1_{fingerprint}x");
        let mut forged = signed.value.clone();
        forged["id"] = json!(wrong);
        let forged = DocumentProofRequest::from_wire(forged, None).unwrap();
        assert!(forged
            .verify_binding(&wrong, &format!("{wrong}#key-1"))
            .is_err());
    }

    #[test]
    fn malformed_proof_inputs_are_refused_before_anything_is_signed() {
        assert!(ObjectProofRequest::new(json!([1, 2, 3])).is_err());
        assert!(ObjectProofRequest::new(json!("not an object")).is_err());
        assert!(DocumentProofRequest::from_wire(json!({"id": DID}), Some("bogus")).is_err());
        assert!(DocumentProofRequest::new(
            json!({"id": DID}),
            None,
            Some(String::new()),
            None
        )
        .is_err());
        assert!(DocumentProofRequest::new(
            json!({"id": DID}),
            None,
            None,
            Some("with space".into())
        )
        .is_err());
        // 太大的对象不接:帧装不下,签名基也不是给人传大文件的。
        let huge = json!({"blob": "a".repeat(MAX_BYTES)});
        assert!(ObjectProofRequest::new(huge).is_err());
    }
}
