//! X25519 密钥协商(P3):daemon 用自己的 `{device}-agreement` 键和调用方给的
//! peer 公钥做一次 Diffie-Hellman。
//!
//! 这是数据面**唯一**一条把秘密交给调用方的路 —— 签名回出去的公钥人人可见,
//! 共享密钥不是。所以三处比签名更严:
//!
//! 1. **共享密钥不落库。** 完成事件只写状态,`result` 永远是 NULL:同一个
//!    `request_id` 再来一次拿到的是 `completed` + 空结果,不是同一把密钥。
//! 2. **审计只记 peer 指纹**,不记共享密钥,也不记 peer 的原始字节以外的东西。
//! 3. **peer 必须在 grant 的策略白名单里**,逐字节相等;没有通配,没有前缀。
//!
//! 低阶 peer 在 [`crate::sign::key::LockedSigningKey::diffie_hellman`] 里被拒:
//! 那会让共享密钥退化成一个人人可算的值。

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use x25519_dalek::PublicKey;

use crate::crypto::hygiene::LockedBytes;
use crate::crypto::thumbprint::{x25519_multibase, x1_segment};
use crate::error::{KeydError, Result};
use crate::sign::LockedSigningKey;

pub const PEER_BYTES: usize = 32;
/// 去重摘要的域串。和签名那几条一样按用途分开:同一个 request_id 换个操作
/// 重放会撞 `REQUEST_ID_CONFLICT`,不会命中这里的缓存。
const DIGEST_DOMAIN: &[u8] = b"anp.ecdh.v1\0";

fn invalid() -> KeydError {
    KeydError::Misuse("ECDH_INVALID".into())
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 校验过的一次协商请求。`peer` 是对方那把 X25519 公钥,只有 32 字节。
#[derive(Clone)]
pub struct EcdhRequest {
    peer: [u8; PEER_BYTES],
    fingerprint: String,
    multibase: String,
}

impl EcdhRequest {
    /// 线上形状:32 字节公钥的小写 hex。大写、奇数长度、非 hex 一律不收 ——
    /// 同一把公钥有第二种写法,审计里的两个指纹就会看起来像两把不同的钥匙。
    pub fn from_wire(peer: &str) -> Result<Self> {
        if peer.len() != PEER_BYTES * 2
            || !peer
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid());
        }
        let mut bytes = [0u8; PEER_BYTES];
        for (i, slot) in bytes.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&peer[i * 2..i * 2 + 2], 16).expect("validated hex");
        }
        Ok(Self::new(bytes))
    }

    pub fn new(peer: [u8; PEER_BYTES]) -> Self {
        let public = PublicKey::from(peer);
        Self {
            peer,
            fingerprint: x1_segment(&public),
            multibase: x25519_multibase(&public),
        }
    }

    pub fn peer(&self) -> &[u8; PEER_BYTES] {
        &self.peer
    }

    /// peer 公钥的 RFC 7638 指纹(`x1_…`)。审计里记这个,不记共享密钥。
    pub fn peer_fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn peer_multibase(&self) -> &str {
        &self.multibase
    }

    /// 去重用的输入摘要。只对 peer 公钥算,和用哪把钥匙协商无关 ——
    /// 同一份输入换一把钥匙是被授权模型挡住的,不是靠摘要区分。
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(DIGEST_DOMAIN);
        hasher.update(self.peer);
        hex_of(&hasher.finalize())
    }

    /// 审计里记的那几个字段:`peer_fingerprint` 和 `peer_multibase`,两者都是
    /// 公开信息。共享密钥不在这里,也不在任何别的审计段里。
    pub fn audit_options(&self) -> Value {
        json!({
            "peer_fingerprint": self.fingerprint,
            "peer_multibase": self.multibase,
        })
    }

    /// 算一次共享密钥。结果落进锁定区,没有 `Serialize`,只能借闭包读。
    ///
    /// 钥匙必须是 X25519 —— 角色表已经保证走到这里的是 `key_agreement`
    /// 键,`diffie_hellman` 自己还会再判一次曲线,两道都不省。
    pub fn derive(&self, key: &LockedSigningKey) -> Result<LockedBytes> {
        key.diffie_hellman(&self.peer)
    }
}

/// 回给调用方的那一次协商结果。
///
/// `shared_secret` 是 hex,和所有二进制字段同一个形状(§11.3)。这个类型
/// **只有服务端构造**:客户端那边有一个同形状的只读类型,不经由这里。
#[derive(Serialize, Deserialize)]
pub struct SharedSecretReply {
    pub shared_secret: String,
    pub peer_fingerprint: String,
}

impl SharedSecretReply {
    pub fn new(shared_secret: &LockedBytes, request: &EcdhRequest) -> Result<Self> {
        Ok(Self {
            shared_secret: shared_secret.expose(|bytes| hex_of(bytes)),
            peer_fingerprint: request.peer_fingerprint().to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7748 §6.1。
    const ALICE_SK: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];
    const BOB_PK_HEX: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    const SHARED_HEX: &str = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

    fn alice() -> LockedSigningKey {
        let mut seed = ALICE_SK;
        LockedSigningKey::from_seed_with_algorithm(
            crate::keystore::record::KeyId {
                did: "did:wba:example.com:user:alice:e1_x".into(),
                kid: "did:wba:example.com:user:alice:e1_x#alice-agreement".into(),
                thumbprint: "x1_x".into(),
            },
            crate::keystore::record::KeyAlgorithm::X25519,
            LockedBytes::new(&mut seed).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn the_request_derives_the_rfc7748_vector() {
        let request = EcdhRequest::from_wire(BOB_PK_HEX).unwrap();
        let shared = request.derive(&alice()).unwrap();
        shared.expose(|bytes| assert_eq!(hex_of(bytes), SHARED_HEX));

        // 指纹是 peer 公钥的,不是共享密钥的 —— 审计只记前者。
        assert!(request.peer_fingerprint().starts_with("x1_"));
        let options = request.audit_options().to_string();
        assert!(options.contains(request.peer_fingerprint()));
        assert!(!options.contains(SHARED_HEX));
    }

    #[test]
    fn the_wire_form_is_exactly_32_lowercase_hex_bytes() {
        for bad in ["", "00", &"0".repeat(63), &"0".repeat(65), "DE9EDB7D"] {
            assert!(EcdhRequest::from_wire(bad).is_err(), "{bad:?}");
        }
        assert!(EcdhRequest::from_wire(&BOB_PK_HEX.to_ascii_uppercase()).is_err());
        assert!(EcdhRequest::from_wire(&"zz".repeat(32)).is_err());
    }

    /// 低阶 peer 必须拒:那样的共享密钥是公开值。
    #[test]
    fn a_low_order_peer_never_produces_a_secret() {
        let request = EcdhRequest::new([0u8; 32]);
        assert!(matches!(
            request.derive(&alice()),
            Err(KeydError::Protocol(ref code)) if code.starts_with("ECDH_PEER_INVALID")
        ));
    }

    /// 两把不同的 peer 公钥去重摘要不同;同一个则相同。
    #[test]
    fn the_digest_is_about_the_peer_only() {
        let a = EcdhRequest::from_wire(BOB_PK_HEX).unwrap();
        let b = EcdhRequest::from_wire(&"11".repeat(32)).unwrap();
        assert_ne!(a.digest(), b.digest());
        assert_eq!(a.digest(), a.digest());
        assert_eq!(a.digest().len(), 64);
    }

    #[test]
    fn the_reply_carries_the_secret_once() {
        let request = EcdhRequest::from_wire(BOB_PK_HEX).unwrap();
        let shared = request.derive(&alice()).unwrap();
        let reply = SharedSecretReply::new(&shared, &request).unwrap();
        assert_eq!(reply.shared_secret, SHARED_HEX);
        assert_eq!(reply.peer_fingerprint, request.peer_fingerprint());
    }
}
