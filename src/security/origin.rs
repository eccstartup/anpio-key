//! ANP RFC 9421 origin proof:请求形状、边界检查与签名。
//!
//! 待签的事实是一个 JSON 对象 `{method, meta, body}`,**不是**一条 HTTP 请求:
//! 目标由 `meta.target.{kind,did}` 决定,逻辑目标 URI 和签名基都由 `anp` 拼。
//! 所以这里没有 URL、没有 header、没有 HTTP 方法表 —— 那些是 `super::http`
//! 的事,两者只在"签名基由 daemon 拼、调用方只给事实"这一点上同形。
//!
//! `created` 一律用 daemon 的钟:调用方给的 `created` 不参与签名。`expires`
//! 可以给,但只能落在 300 秒之内,否则一条 proof 可以被无限期重放。

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::{KeydError, Result};
use crate::sign::{LockedSigningKey, Signer};

/// 规范化后的待签对象上限。帧本身 64 KiB,信封和其他字段要留出余量。
pub const MAX_CANONICAL_BYTES: usize = 32 * 1024;
/// proof 的有效期上限,和 HTTP profile 的窗口一致。
pub const MAX_LIFETIME_SECONDS: i64 = 300;
pub const TARGET_KINDS: [&str; 3] = ["agent", "group", "service"];

fn invalid() -> KeydError {
    KeydError::Misuse("ORIGIN_INVALID".into())
}

/// 线上形状。字段与 `anp_identity::OriginProofRequest` 一一对应,只是没有
/// `created` 和 `key`:前者由 daemon 定,后者来自 grant。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginProofRequest {
    pub method: String,
    pub meta: Value,
    pub body: Value,
    #[serde(default)]
    pub expires: Option<i64>,
    #[serde(default)]
    pub nonce: Option<String>,
}

/// 校验过的 origin proof。构造成功即代表:方法名合法、`meta.target` 在那儿、
/// 大小在上限内。
#[derive(Debug, Clone)]
pub struct OriginProof {
    method: String,
    meta: Value,
    body: Value,
    target_kind: String,
    target_did: String,
    expires: Option<i64>,
    nonce: Option<String>,
    canonical: Vec<u8>,
    body_len: usize,
}

/// 一次 origin proof 签名的结果。
#[derive(Debug, Clone, Serialize)]
pub struct SignedOrigin {
    pub content_digest: String,
    pub signature_input: String,
    pub signature: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub signature_base_digest: String,
}

impl OriginProofRequest {
    /// `now` 是 daemon 的钟。`expires` 只能落在它之后 [`MAX_LIFETIME_SECONDS`] 内。
    pub fn validate(self, now: i64) -> Result<OriginProof> {
        if self.method.is_empty()
            || self.method.len() > 64
            || !self
                .method
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        {
            return Err(invalid());
        }
        if !self.meta.is_object() || !self.body.is_object() {
            return Err(invalid());
        }
        let target = self.meta.get("target").and_then(Value::as_object).ok_or_else(invalid)?;
        let target_kind = target
            .get("kind")
            .and_then(Value::as_str)
            .filter(|k| TARGET_KINDS.contains(k))
            .ok_or_else(invalid)?
            .to_owned();
        let target_did = target
            .get("did")
            .and_then(Value::as_str)
            .filter(|d| !d.is_empty() && d.len() <= 512 && !d.chars().any(char::is_control))
            .ok_or_else(invalid)?
            .to_owned();
        if let Some(expires) = self.expires {
            if expires <= now || expires - now > MAX_LIFETIME_SECONDS {
                return Err(invalid());
            }
        }
        if let Some(nonce) = &self.nonce {
            if nonce.is_empty()
                || nonce.len() > 128
                || !nonce.bytes().all(|b| b.is_ascii_graphic())
            {
                return Err(invalid());
            }
        }
        // 用上游同一个拼基路径算规范化字节:签名基和这里的大小检查不会各算各的。
        let object = anp::proof::build_signed_request_object(&self.method, &self.meta, &self.body)
            .map_err(|_| invalid())?;
        let canonical =
            anp::proof::canonicalize_signed_request_object(&object).map_err(|_| invalid())?;
        if canonical.is_empty() || canonical.len() > MAX_CANONICAL_BYTES {
            return Err(invalid());
        }
        let body_len = serde_json_canonicalizer::to_vec(&self.body)
            .map_err(|_| invalid())?
            .len();
        Ok(OriginProof {
            method: self.method,
            meta: self.meta,
            body: self.body,
            target_kind,
            target_did,
            expires: self.expires,
            nonce: self.nonce,
            canonical,
            body_len,
        })
    }
}

impl OriginProof {
    pub fn method(&self) -> &str {
        &self.method
    }

    pub fn target_kind(&self) -> &str {
        &self.target_kind
    }

    pub fn target_did(&self) -> &str {
        &self.target_did
    }

    pub fn body_len(&self) -> usize {
        self.body_len
    }

    /// 规范化之后的规范化 body 是不是空对象 `{}`。
    pub fn is_empty_body(&self) -> bool {
        self.body.as_object().is_some_and(|b| b.is_empty())
    }

    fn canonical(&self) -> &[u8] {
        &self.canonical
    }

    /// 去重用的输入摘要。按用途分域:同一个 id 在别的用途下重放会撞
    /// `REQUEST_ID_CONFLICT`,而不是命中这里的缓存。
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"anp.origin-proof.v1\0");
        hasher.update(self.canonical());
        hasher.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// 签名。`created` 由调用方(executor)从 daemon 的钟给出。
    pub fn sign(&self, key: &LockedSigningKey, created: i64) -> Result<SignedOrigin> {
        let options = anp::proof::Rfc9421OriginProofGenerationOptions {
            created: Some(created),
            expires: self.expires,
            nonce: self.nonce.clone(),
            label: None,
        };
        let prepared = anp::proof::prepare_rfc9421_origin_proof(
            &self.method,
            &self.meta,
            &self.body,
            &key.anp_public_key(),
            &key.id().kid,
            options,
        )
        .map_err(|e| KeydError::Upstream(format!("preparing the origin proof failed: {e}")))?;
        let signature_base_digest = Sha256::digest(prepared.signing_input())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let signature = key.sign(prepared.signing_input())?;
        let proof = anp::proof::complete_rfc9421_origin_proof(prepared, &signature)
            .map_err(|e| KeydError::Upstream(format!("completing the origin proof failed: {e}")))?;
        Ok(SignedOrigin {
            content_digest: proof.content_digest,
            signature_input: proof.signature_input,
            signature: proof.signature,
            created_at: created,
            expires_at: self.expires,
            signature_base_digest,
        })
    }
}

/// 审计里记的那几个 proof option。不含共享秘密,也不含任何密钥材料。
pub fn audit_options(proof: &OriginProof, created: i64) -> Value {
    json!({
        "method": proof.method(),
        "target_kind": proof.target_kind(),
        "target_did": proof.target_did(),
        "created": created,
        "expires": proof.expires,
        "nonce": proof.nonce,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hygiene::LockedBytes;
    use crate::keystore::record::KeyId;

    fn key() -> LockedSigningKey {
        let seed = LockedBytes::fill(|d| *d = [5; 32]).unwrap();
        LockedSigningKey::from_seed(
            KeyId {
                did: "did:wba:example.com:user:alice".into(),
                kid: "did:wba:example.com:user:alice#key-2".into(),
                thumbprint: "alice".into(),
            },
            seed,
        )
        .unwrap()
    }

    fn request() -> OriginProofRequest {
        OriginProofRequest {
            method: "direct.send".into(),
            meta: json!({
                "profile": "anp.direct.base.v1",
                "sender_did": "did:wba:example.com:user:alice",
                "target": {"kind": "agent", "did": "did:wba:example.com:user:bob"},
                "message_id": "msg-1",
            }),
            body: json!({"text": "hi"}),
            expires: None,
            nonce: None,
        }
    }

    #[test]
    fn a_well_formed_proof_is_signed_and_verifiable_by_the_upstream() {
        let proof = request().validate(1_000).unwrap();
        let signed = proof.sign(&key(), 1_000).unwrap();
        assert!(signed.signature_input.starts_with("sig1=("));
        assert_eq!(signed.created_at, 1_000);
        assert_eq!(signed.expires_at, None);
        assert_eq!(signed.signature_base_digest.len(), 64);
        assert!(signed.signature.starts_with("sig1=:"));

        // 用上游的验证器验一遍 —— 自己签的自己验不够。
        let verified = anp::proof::verify_rfc9421_origin_proof(
            &anp::proof::Rfc9421OriginProof {
                content_digest: signed.content_digest,
                signature_input: signed.signature_input,
                signature: signed.signature,
            },
            "direct.send",
            &request().meta,
            &request().body,
            anp::proof::Rfc9421OriginProofVerificationOptions {
                verification_method: Some(json!({
                    "id": "did:wba:example.com:user:alice#key-2",
                    "type": "Multikey",
                    "controller": "did:wba:example.com:user:alice",
                    "publicKeyMultibase": key().public_multibase(),
                })),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(matches!(
            verified,
            anp::proof::ImProofVerificationResult { .. }
        ));
    }

    #[test]
    fn the_digest_separates_purposes_and_moves_with_the_facts() {
        let a = request().validate(1_000).unwrap();
        let b = request().validate(1_000).unwrap();
        assert_eq!(a.digest(), b.digest());
        let mut other = request();
        other.body = json!({"text": "bye"});
        assert_ne!(a.digest(), other.validate(1_000).unwrap().digest());
    }

    #[test]
    fn malformed_requests_are_refused_without_echoing_input() {
        for broken in [
            OriginProofRequest {
                method: "Direct.Send".into(),
                ..request()
            },
            OriginProofRequest {
                method: String::new(),
                ..request()
            },
            OriginProofRequest {
                meta: json!({"no_target": true}),
                ..request()
            },
            OriginProofRequest {
                meta: json!({"target": {"kind": "robot", "did": "did:x"}}),
                ..request()
            },
            OriginProofRequest {
                meta: json!({"target": {"kind": "agent", "did": ""}}),
                ..request()
            },
            OriginProofRequest {
                body: json!([1, 2]),
                ..request()
            },
            OriginProofRequest {
                expires: Some(900),
                ..request()
            },
            OriginProofRequest {
                expires: Some(1_000 + MAX_LIFETIME_SECONDS + 1),
                ..request()
            },
            OriginProofRequest {
                nonce: Some("contains space".into()),
                ..request()
            },
        ] {
            let error = broken.validate(1_000).unwrap_err();
            assert!(matches!(error, KeydError::Misuse(ref code) if code == "ORIGIN_INVALID"));
        }
    }

    #[test]
    fn an_oversized_body_is_refused_before_anything_is_signed() {
        let big = "x".repeat(MAX_CANONICAL_BYTES);
        let error = OriginProofRequest {
            body: json!({"text": big}),
            ..request()
        }
        .validate(1_000)
        .unwrap_err();
        assert!(matches!(error, KeydError::Misuse(ref code) if code == "ORIGIN_INVALID"));
    }
}
