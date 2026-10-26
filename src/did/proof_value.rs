//! `proofValue` 的编码:规范要的那一种,以及老方言的读法。
//!
//! W3C `vc-di-eddsa` / ANP-03 §2.5.5 要的是 base58btc multibase(`z` 前缀)。
//! daemon 签出来的文档与对象 proof 都是这一种,拼法见 [`crate::did::proof`]。
//!
//! 但两种旧东西还在,验证侧得读得懂:
//!
//! - 裸 base64url:上游 `anp` 1.0.6 的 `complete_w3c_proof` 生成的还是它,
//!   有对端的文档是这么签的;
//! - **`z` 的旧签名基**:`z` 比规范那条签名基出现得早。有一批文档的 `z` 是从
//!   base64url 换字母表得来的,签名基里没有 `@context`。上游验签对这两种写法
//!   各有一条分支(`verify_w3c_proof` 的 `standard_signature`),所以验证侧
//!   两种都得试:先按原样验(规范那条 + 裸 base64url),不成立再换成
//!   base64url 字母表验一次(旧 `z` 那条)。
//!
//! 这里只做编码与换字母表。签名基怎么拼由 [`crate::did::proof`] 负责 ——
//! 换字母表不是重签,`proofValue` 本来就不进签名输入。

use base64::Engine as _;
use serde_json::Value;

use crate::error::{KeydError, Result};

/// ANP-03 §2.5.5 / W3C Data Integrity 的 multibase 前缀:base58btc。
const MULTIBASE: char = 'z';

/// 一条 Ed25519 签名固定 64 字节。两边都按它判"这一串到底是不是签名"。
const SIGNATURE_LEN: usize = 64;

/// 一条 Ed25519 签名 → 规范要的 `z` + base58btc。
pub fn encode(signature: &[u8; SIGNATURE_LEN]) -> String {
    format!("{MULTIBASE}{}", bs58::encode(signature).into_string())
}

/// 一份文档里 `proofValue`(multibase base58btc)→ 裸 base64url。
pub fn to_base64url(value: &str) -> Result<String> {
    let body = value.strip_prefix(MULTIBASE).ok_or_else(|| {
        KeydError::Did(format!(
            "the document's proofValue is not multibase base58btc (no `{MULTIBASE}` prefix): {value:?}"
        ))
    })?;
    let bytes = bs58::decode(body).into_vec().map_err(|error| {
        KeydError::Did(format!(
            "the document's proofValue has no valid base58btc in it: {error}"
        ))
    })?;
    if bytes.len() != SIGNATURE_LEN {
        return Err(KeydError::Did(format!(
            "the document's proofValue decodes to {} byte(s), not {SIGNATURE_LEN} — it is not an Ed25519 signature",
            bytes.len()
        )));
    }
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes))
}

/// 就地把一份文档的 `proof.proofValue` 换成裸 base64url:给上游那版验签读旧
/// `z` 文档用。
///
/// 没有 `proof`、或者 `proofValue` 不是字符串,都拒 —— 调用方站在"这一份一定
/// 有 proof"的位置上,悄悄返回等于把"签名没发生"咽下去。
pub fn into_base64url(document: &mut Value) -> Result<()> {
    let proof = document
        .get_mut("proof")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| KeydError::Upstream("this document has no proof object".into()))?;
    let current = proof
        .get("proofValue")
        .and_then(Value::as_str)
        .ok_or_else(|| KeydError::Upstream("this document's proof has no proofValue".into()))?
        .to_string();
    proof.insert("proofValue".into(), Value::String(to_base64url(&current)?));
    Ok(())
}

/// 这一串是不是已经在 multibase base58btc 里了。
pub fn is_multibase(value: &str) -> bool {
    value.starts_with(MULTIBASE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// 一条固定的签名(64 字节),用来把编码钉死。
    fn signature() -> [u8; SIGNATURE_LEN] {
        let mut bytes = [0u8; SIGNATURE_LEN];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        bytes
    }

    #[test]
    fn a_signature_is_encoded_as_base58btc_behind_a_z_header() {
        let bytes = signature();
        let encoded = encode(&bytes);
        assert_eq!(encoded, format!("z{}", bs58::encode(bytes).into_string()));
        let decoded = bs58::decode(&encoded[1..]).into_vec().unwrap();
        assert_eq!(decoded, bytes);
        // 再换回 base64url 是同一批字节 —— 换字母表,不是重签。
        assert_eq!(
            to_base64url(&encoded).unwrap(),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
        );
    }

    #[test]
    fn a_multibase_that_is_not_a_signature_is_refused() {
        // 长度不对。
        assert!(to_base64url(&format!("z{}", bs58::encode([1u8, 2, 3]).into_string())).is_err());
        // base58btc 里没有 `l`。
        assert!(to_base64url(&format!("z{}", "l".repeat(64))).is_err());
        // 前缀不是 `z`。
        assert!(to_base64url(&encode(&signature())[1..]).is_err());
    }

    #[test]
    fn rewriting_a_document_touches_only_the_proof_value() {
        let mut document = json!({
            "id": "did:wba:example.com:user:e1_x",
            "proof": {
                "type": "DataIntegrityProof",
                "created": "2026-10-14T00:00:00Z",
                "verificationMethod": "did:wba:example.com:user:e1_x#key-1",
                "proofPurpose": "assertionMethod",
                "cryptosuite": "eddsa-jcs-2022",
                "proofValue": encode(&signature()),
            },
        });
        let before = document.clone();
        into_base64url(&mut document).unwrap();

        let mut expected = before.clone();
        expected["proof"]["proofValue"] = json!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature())
        );
        assert_eq!(document, expected);
    }

    #[test]
    fn a_document_without_a_usable_proof_is_refused() {
        assert!(into_base64url(&mut json!({"id": "did:wba:x:y:e1_z"})).is_err());
        assert!(into_base64url(&mut json!({"proof": {}})).is_err());
        assert!(into_base64url(&mut json!({"proof": {"proofValue": 7}})).is_err());
    }
}
