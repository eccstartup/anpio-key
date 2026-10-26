//! RFC 7638 JWK 指纹 → did:wba 的 `e1_` 路径段。
//!
//! 指纹本身由上游 `anp` 算:它是**验签方**会用的同一份实现,自己重算一遍
//! 只会带来"两边算法微妙的差别"这种最难查的 bug。这一层只做拼装和校验。
//!
//! 上游有个容易踩的坑:`compute_multikey_fingerprint` 返回的是**裸的 43 字符
//! base64url 指纹**,`e1_` 前缀是 `anp` 内部自己拼的,不会给你。
//!
//! X25519 是唯一的例外:上游的 `compute_multikey_fingerprint` 只认 Ed25519,
//! 给它一把协商公钥会直接报错。所以 `x1_` 那一段按 RFC 7638 自己做,并用
//! 一个独立的复算测试盯住它(见 `upstream_fingerprint_is_really_rfc7638`)。

use anp::PublicKeyMaterial;
use ed25519_dalek::VerifyingKey;

use crate::error::{KeydError, Result};

/// E1 路径段的字符数:`e1_` + 43。
const E1_FINGERPRINT_LEN: usize = 43;

/// 从 Ed25519 公钥算出 DID 路径最后一段,形如 `e1_<43 字符>`。
pub fn e1_segment(public: &VerifyingKey) -> Result<String> {
    let material = PublicKeyMaterial::Ed25519(*public);
    let fingerprint = anp::authentication::compute_multikey_fingerprint(&material)
        .map_err(|e| KeydError::Upstream(format!("multikey fingerprint failed: {e}")))?;
    debug_assert_eq!(fingerprint.len(), E1_FINGERPRINT_LEN);
    Ok(format!("e1_{fingerprint}"))
}

/// 从完整 DID 里取出最后那一段 `e1_...`。
pub fn e1_from_did(did: &str) -> Result<&str> {
    let last = did
        .rsplit(':')
        .next()
        .ok_or_else(|| KeydError::Did(format!("did has no segments: {did}")))?;
    let rest = last
        .strip_prefix("e1_")
        .ok_or_else(|| KeydError::Did(format!("did path does not end in an e1_ binding: {did}")))?;
    if rest.len() != E1_FINGERPRINT_LEN || !rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(KeydError::Did(format!(
            "malformed e1_ binding segment in did: {last}"
        )));
    }
    Ok(last)
}

/// Ed25519 公钥的 multikey 编码:`z` + base58btc(`0xed 0x01` ‖ 32 字节公钥)。
///
/// 上游有一个等价实现但它是私有的,所以这里重写一份。`0xed 0x01` 是 multicodec
/// 给 ed25519-pub 分配的 varint。
pub fn ed25519_multibase(public: &VerifyingKey) -> String {
    let mut buf = [0u8; 34];
    buf[0] = 0xed;
    buf[1] = 0x01;
    buf[2..].copy_from_slice(&public.to_bytes());
    format!("z{}", bs58::encode(buf).into_string())
}

/// [`ed25519_multibase`] 的逆向:信封里存着的那串公钥读回成一把钥匙。
///
/// 解析**不宽容**:前缀、长度、multicodec 头、曲线点合法性,四样全对才算数。
/// 信封是从磁盘读回来的**不可信输入**,而这里出来的东西下一步就要拿去和
/// DID 的指纹比对 —— 一个"能解析但解析成了别的东西"的公钥,症状是绑定
/// 校验莫名其妙地失败。
pub fn ed25519_from_multibase(multibase: &str) -> Result<VerifyingKey> {
    let body = multibase.strip_prefix('z').ok_or_else(|| {
        KeydError::Protocol(format!(
            "a multibase public key must start with `z` (base58btc), got {multibase:?}"
        ))
    })?;
    let raw = bs58::decode(body)
        .into_vec()
        .map_err(|e| KeydError::Protocol(format!("bad base58 in a multibase public key: {e}")))?;
    if raw.len() != 34 || raw[0] != 0xed || raw[1] != 0x01 {
        return Err(KeydError::Protocol(
            "this multibase is not an ed25519-pub multicodec key".into(),
        ));
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&raw[2..]);
    VerifyingKey::from_bytes(&bytes).map_err(|e| {
        KeydError::Protocol(format!("a multibase public key is not a valid ed25519 point: {e}"))
    })
}

/// X25519 公钥的 JWK 指纹(RFC 7638),裸的 43 字符。
///
/// 上游只肯给 Ed25519 算这个,所以协商键这一路按 RFC 7638 自己做:
/// `{"crv":"X25519","kty":"OKP","x":<base64url 无填充>}` → JCS → SHA-256 →
/// base64url 无填充。与 Ed25519 那份**同一个定义**,只是 `crv` 不同。
pub fn x25519_fingerprint(public: &x25519_dalek::PublicKey) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public.as_bytes());
    // JCS 会按键名排序,这里的字面顺序不影响结果;写成 crv/kty/x 只为好读。
    let jwk = serde_json::json!({ "crv": "X25519", "kty": "OKP", "x": x });
    let canonical = serde_json_canonicalizer::to_vec(&jwk)
        .expect("the thumbprint JWK is a plain object with string members");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(&canonical))
}

/// 协商键的指纹段,形如 `x1_<43 字符>`。
///
/// 和 `e1_` 一样长、同一个字母表,但**前缀不同是有意的**:它永远不会出现在
/// DID 的最后一段(DID 绑的是根 Ed25519 键),只用作信封文件名与索引键。
/// 前缀不同也让"拿 e1_ 段的 DID 去认一把协商键"这种错永远写不出来。
pub fn x1_segment(public: &x25519_dalek::PublicKey) -> String {
    format!("x1_{}", x25519_fingerprint(public))
}

/// X25519 公钥的 multikey 编码:`z` + base58btc(`0xec 0x01` ‖ 32 字节公钥)。
pub fn x25519_multibase(public: &x25519_dalek::PublicKey) -> String {
    let mut buf = [0u8; 34];
    buf[0] = 0xec;
    buf[1] = 0x01;
    buf[2..].copy_from_slice(public.as_bytes());
    format!("z{}", bs58::encode(buf).into_string())
}

/// [`x25519_multibase`] 的逆向。和 Ed25519 那份一样,**解析不宽容**。
///
/// X25519 的 32 字节公开值不要求是合法曲线点(它只是一个 u 坐标),所以这里
/// 能查的只有长度与 multicodec 头;全零那种低阶值留到真正做 DH 时由
/// `was_contributory` 拒掉 —— 那才是唯一有意义的时刻。
pub fn x25519_from_multibase(multibase: &str) -> Result<[u8; 32]> {
    let body = multibase.strip_prefix('z').ok_or_else(|| {
        KeydError::Protocol(format!(
            "a multibase public key must start with `z` (base58btc), got {multibase:?}"
        ))
    })?;
    let raw = bs58::decode(body)
        .into_vec()
        .map_err(|e| KeydError::Protocol(format!("bad base58 in a multibase public key: {e}")))?;
    if raw.len() != 34 || raw[0] != 0xec || raw[1] != 0x01 {
        return Err(KeydError::Protocol(
            "this multibase is not an x25519-pub multicodec key".into(),
        ));
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&raw[2..]);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8032 §7.1 TEST 1 的私钥与公钥。
    const RFC8032_TEST1_SK: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const RFC8032_TEST1_PK: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    fn test_key() -> VerifyingKey {
        VerifyingKey::from_bytes(&RFC8032_TEST1_PK).unwrap()
    }

    #[test]
    fn ed25519_derivation_matches_rfc8032_vector() {
        // 先把"RFC 8032 的公钥确实来自那个 seed"钉住,后面的指纹才立得住。
        let sk = ed25519_dalek::SigningKey::from_bytes(&RFC8032_TEST1_SK);
        assert_eq!(sk.verifying_key(), test_key());
    }

    #[test]
    fn multibase_has_the_z6mk_prefix() {
        let mb = ed25519_multibase(&test_key());
        assert!(mb.starts_with("z6Mk"), "ed25519 multikey must start z6Mk, got {mb}");
    }

    /// 编码再解码要回到原来那把钥匙 —— 信封里存的公钥就是这么读回来的。
    #[test]
    fn multibase_roundtrips_back_into_the_same_key() {
        let mb = ed25519_multibase(&test_key());
        assert_eq!(ed25519_from_multibase(&mb).unwrap(), test_key());
    }

    #[test]
    fn a_multibase_that_is_not_an_ed25519_key_is_refused() {
        let other_codec = format!("z{}", bs58::encode([0xec, 0x01, 9, 9]).into_string());
        for bad in [
            "6Mkabcd".to_string(),  // 少了 `z` 前缀
            "z".to_string(),        // 空
            "zzzz".to_string(),     // 不是 base58
            "z6Mkattacker".to_string(), // 长度不对
            other_codec,            // 别的 multicodec
        ] {
            assert!(
                ed25519_from_multibase(&bad).is_err(),
                "{bad:?} must not be read as an ed25519 public key"
            );
        }
    }

    #[test]
    fn e1_segment_is_e1_plus_43_chars() {
        let seg = e1_segment(&test_key()).unwrap();
        assert!(seg.starts_with("e1_"));
        assert_eq!(seg.len(), 3 + 43);
        // 与 did_transition.rs 里那条正则同一个字母表。
        assert!(seg[3..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    /// 独立复算一遍指纹,确认上游给的确实是 RFC 7638 的定义。
    ///
    /// 这不是重复上游的实现,而是**验证**上游:JWK 的三个成员按字典序拼装、
    /// JCS 规范化、SHA-256、base64url 无填充 —— 只要上游哪一步走偏就会红。
    #[test]
    fn upstream_fingerprint_is_really_rfc7638() {
        use base64::Engine;
        use sha2::{Digest, Sha256};

        let key = test_key();
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.to_bytes());

        // 字典序:crv < kty < x
        let jwk = serde_json::json!({ "crv": "Ed25519", "kty": "OKP", "x": x });
        let canonical = serde_json_canonicalizer::to_vec(&jwk).unwrap();
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(&canonical));

        assert_eq!(expected.len(), E1_FINGERPRINT_LEN);
        assert_eq!(e1_segment(&key).unwrap(), format!("e1_{expected}"));
    }

    #[test]
    fn e1_from_did_roundtrips() {
        let seg = e1_segment(&test_key()).unwrap();
        let did = format!("did:wba:example.com:user:alice:{seg}");
        assert_eq!(e1_from_did(&did).unwrap(), seg);
    }

    #[test]
    fn e1_from_did_rejects_non_binding_dids() {
        assert!(e1_from_did("did:wba:example.com:user:alice").is_err());
        assert!(e1_from_did("did:wba:example.com:user:alice:e1_short").is_err());
        assert!(e1_from_did("did:wba:example.com:user:alice:k1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").is_err());
    }

    /// RFC 7748 §6.1 的 Alice 公钥 —— 协商键那一路所有测试的共用向量。
    const RFC7748_ALICE_PK: [u8; 32] = [
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7,
        0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b,
        0x4e, 0x6a,
    ];

    fn alice() -> x25519_dalek::PublicKey {
        x25519_dalek::PublicKey::from(RFC7748_ALICE_PK)
    }

    /// `x1_` 段和 `e1_` 一样是 43 字符,而且**独立复算**一遍确认它是 RFC 7638。
    #[test]
    fn x1_segment_is_an_rfc7638_thumbprint_of_the_x25519_jwk() {
        use base64::Engine;
        use sha2::{Digest, Sha256};

        let key = alice();
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.as_bytes());
        let jwk = serde_json::json!({ "crv": "X25519", "kty": "OKP", "x": x });
        let canonical = serde_json_canonicalizer::to_vec(&jwk).unwrap();
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(&canonical));

        let seg = x1_segment(&key);
        assert_eq!(seg, format!("x1_{expected}"));
        assert_eq!(seg.len(), 3 + E1_FINGERPRINT_LEN);
        assert!(seg[3..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    /// 曲线名参与了指纹:同一串 32 字节,按 X25519 与按 Ed25519 算出来必须不同。
    #[test]
    fn the_curve_name_is_part_of_the_fingerprint() {
        use base64::Engine;
        use sha2::{Digest, Sha256};

        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(RFC7748_ALICE_PK);
        let as_ed25519 = serde_json::json!({ "crv": "Ed25519", "kty": "OKP", "x": x });
        let canonical = serde_json_canonicalizer::to_vec(&as_ed25519).unwrap();
        let other = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(&canonical));

        assert_ne!(x25519_fingerprint(&alice()), other);
    }

    #[test]
    fn x25519_multibase_roundtrips_and_uses_the_0xec01_codec() {
        let mb = x25519_multibase(&alice());
        assert!(mb.starts_with('z'));
        assert_eq!(x25519_from_multibase(&mb).unwrap(), RFC7748_ALICE_PK);

        // 前缀里那两字节就是 multicodec 头,别被 base58 藏起来。
        let raw = bs58::decode(&mb[1..]).into_vec().unwrap();
        assert_eq!(&raw[..2], &[0xec, 0x01]);
    }

    #[test]
    fn an_ed25519_multibase_is_not_an_x25519_key_and_vice_versa() {
        let ed = ed25519_multibase(&test_key());
        assert!(x25519_from_multibase(&ed).is_err());
        assert!(ed25519_from_multibase(&x25519_multibase(&alice())).is_err());
    }
}
