//! 文档的 `DataIntegrityProof`:proof configuration、签名基、编码,一处定死。
//!
//! 同一件事上游 `anp::proof` 也能做(`prepare_w3c_proof` / `complete_w3c_proof`),
//! 但它生成的那一路是**老方言**:`proofValue` 是裸 base64url,proof options 里
//! 没有文档的 `@context`。W3C `vc-di-eddsa`(`eddsa-jcs-2022`)要的是另一样:
//!
//! 1. `proofValue` 必须是 base58btc 的 multibase —— `z` 前缀;
//! 2. Create Proof 一步:`If unsecuredDocument.@context is present, set
//!    proof.@context to unsecuredDocument.@context.`;签名输入是
//!    `SHA256(JCS(proofConfig)) ‖ SHA256(JCS(document minus proof))`。
//!
//! 上游 1.0.6 的验签读到 `z` 时按第 2 条算(`verify_w3c_proof` 里的
//! `standard_signature` 分支),所以"把老方言的字节换个字母表交出去"必然验不过。
//! 这里自己拼,拼的就是规范那一条。
//!
//! 产物里**不带** proof 级的 `@context`:规范要它进签名基;验签方会从文档里
//! 把它补回来(上游就是这么做的)。带上也能验过,但同一份文档会有两种写法。

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::did::proof_value;
use crate::error::{KeydError, Result};

/// 一次文档 proof 的公开事实。`type` 与 `cryptosuite` 不在这里 —— 它们是
/// daemon 定死的,调用方换不了。
pub(crate) struct Facts<'a> {
    pub verification_method: &'a str,
    pub purpose: &'a str,
    pub created: &'a str,
    pub domain: Option<&'a str>,
    pub challenge: Option<&'a str>,
}

/// 签之前的全部输入:要签的字节已经算好,proof 的字段也已经定好。
pub(crate) struct Prepared {
    document: Value,
    proof_object: Map<String, Value>,
    signing_input: Vec<u8>,
    public: anp::PublicKeyMaterial,
}

impl Prepared {
    /// 真正交给签名器的字节:两个 SHA-256,proof configuration 在前。
    pub(crate) fn signing_input(&self) -> &[u8] {
        &self.signing_input
    }
}

pub(crate) struct Signed {
    pub document: Value,
    pub proof: Value,
}

pub(crate) fn prepare(
    document: &Value,
    public: &anp::PublicKeyMaterial,
    facts: Facts<'_>,
) -> Result<Prepared> {
    let mut config = Map::new();
    config.insert("type".into(), json!(anp::proof::PROOF_TYPE_DATA_INTEGRITY));
    config.insert("created".into(), json!(facts.created));
    config.insert("verificationMethod".into(), json!(facts.verification_method));
    config.insert("proofPurpose".into(), json!(facts.purpose));
    config.insert("cryptosuite".into(), json!(anp::proof::CRYPTOSUITE_EDDSA_JCS_2022));
    for (name, value) in [("domain", facts.domain), ("challenge", facts.challenge)] {
        if let Some(value) = value {
            config.insert(name.into(), json!(value));
        }
    }

    let mut signing_document = document.clone();
    let object = signing_document
        .as_object_mut()
        .ok_or_else(|| unusable("the document to prove is not a JSON object"))?;
    object.remove("proof");
    if let Some(context) = object.get("@context").cloned() {
        config.insert("@context".into(), context);
    }

    let mut signing_input = Vec::with_capacity(64);
    signing_input.extend_from_slice(&digest(&Value::Object(config.clone()))?);
    signing_input.extend_from_slice(&digest(&signing_document)?);

    Ok(Prepared {
        document: document.clone(),
        proof_object: config,
        signing_input,
        public: public.clone(),
    })
}

pub(crate) fn complete(prepared: Prepared, signature: &[u8; 64]) -> Result<Signed> {
    prepared
        .public
        .verify_message(&prepared.signing_input, signature)
        .map_err(|_| unusable("the signature does not match the key that was asked to make it"))?;

    let mut proof_object = prepared.proof_object;
    proof_object.remove("@context");
    proof_object.insert(
        "proofValue".into(),
        json!(proof_value::encode(signature)),
    );

    let mut document = prepared.document;
    let object = document
        .as_object_mut()
        .ok_or_else(|| unusable("the proven document stopped being a JSON object"))?;
    object.insert("proof".into(), Value::Object(proof_object.clone()));
    Ok(Signed {
        document,
        proof: Value::Object(proof_object),
    })
}

/// `created` 的形状:`%Y-%m-%dT%H:%M:%SZ`,和上游同一个。
pub(crate) fn timestamp(at: time::OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    )
}

fn digest(value: &Value) -> Result<Vec<u8>> {
    let canonical = serde_json_canonicalizer::to_vec(value)
        .map_err(|error| unusable(&format!("canonicalizing the proof input failed: {error}")))?;
    Ok(Sha256::digest(&canonical).to_vec())
}

fn unusable(why: &str) -> KeydError {
    KeydError::Upstream(why.to_owned())
}
