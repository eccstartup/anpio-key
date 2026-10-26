//! 解锁后的密钥在内存里唯一的存在形式。
//!
//! seed 躺在 `mlock` 住、不许换页、不许进 core dump 的页里,只用闭包借出。
//! 同一个类型装两种算法:**Ed25519**(签名)与 **X25519**(协商)。私钥永远
//! 只有那 32 字节 seed,公开面按算法各存一份 —— 信封上写的是哪种算法,
//! 解出来就是哪种,不存在"同一把 seed 当两种曲线用"的路。

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::hygiene::LockedBytes;
use crate::crypto::thumbprint::{ed25519_multibase, x25519_multibase};
use crate::error::{KeydError, Result};
use crate::keystore::record::{KeyAlgorithm, KeyId};
use crate::sign::backend::Signer;

/// 公开面。**没有私钥,也没有 `Debug`。**
enum Material {
    Ed25519 { verifying: VerifyingKey },
    X25519 { public: PublicKey },
}

/// 从 seed 推出 X25519 公钥。
///
/// **信封生成与解锁两条路共用这一个推导** —— 分头各写一遍是这类代码最容易
/// 出错的地方:生成时夹紧、解锁时不夹紧,症状是"信封上写的公钥不是这把
/// seed 的公钥",而那要等到第一次解封才发作。
pub fn x25519_public_from_seed(seed: &LockedBytes) -> PublicKey {
    seed.expose(|bytes| PublicKey::from(&StaticSecret::from(*bytes)))
}

pub struct LockedSigningKey {
    id: KeyId,
    seed: LockedBytes,
    material: Material,
    public_multibase: String,
}

impl LockedSigningKey {
    /// 从信封里解出来的 32 字节 seed 构造一把 Ed25519 钥匙。
    pub fn from_seed(id: KeyId, seed: LockedBytes) -> Result<Self> {
        Self::from_seed_with_algorithm(id, KeyAlgorithm::Ed25519, seed)
    }

    /// 按信封上写的算法构造。[`crate::keystore::unwrap`] 走这条 —— 信封的
    /// `algorithm` 在 AAD 里,所以这里读到的那个值已经被认证过。
    pub fn from_seed_with_algorithm(
        id: KeyId,
        algorithm: KeyAlgorithm,
        seed: LockedBytes,
    ) -> Result<Self> {
        let (material, public_multibase) = match algorithm {
            KeyAlgorithm::Ed25519 => {
                let verifying =
                    seed.expose(|bytes| SigningKey::from_bytes(bytes).verifying_key());
                (Material::Ed25519 { verifying }, ed25519_multibase(&verifying))
            }
            KeyAlgorithm::X25519 => {
                // `StaticSecret::from` 不夹紧,夹紧发生在 `PublicKey::from(&secret)`
                // 与 `diffie_hellman` 里 —— 所以这里算出的公钥和真正做 DH 时
                // 用的标量一定是同一个。
                let public = x25519_public_from_seed(&seed);
                (Material::X25519 { public }, x25519_multibase(&public))
            }
            KeyAlgorithm::P256 => {
                return Err(KeydError::Protocol(
                    "this build has no P-256 backend; that envelope cannot be opened".into(),
                ))
            }
        };
        Ok(Self {
            id,
            seed,
            material,
            public_multibase,
        })
    }

    pub fn id(&self) -> &KeyId {
        &self.id
    }

    pub fn did(&self) -> &str {
        &self.id.did
    }

    /// 公钥。`VerifyingKey` 是 Copy 的,给出去的是值,不是通往 seed 的路。
    ///
    /// 协商键没有 Ed25519 公钥,所以这里是可失败的 —— 调用方要么已经知道
    /// 算法(签名的每一路都知道),要么就该先看 [`LockedSigningKey::algorithm`]。
    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        match &self.material {
            Material::Ed25519 { verifying } => Ok(*verifying),
            Material::X25519 { .. } => Err(KeydError::Protocol(format!(
                "{:?} is an X25519 agreement key and has no Ed25519 verifying key",
                self.algorithm()
            ))),
        }
    }

    /// anp 的 `PublicKeyMaterial` 需要一把公钥;它**永远拿不到私钥**。
    pub fn anp_public_key(&self) -> Result<anp::PublicKeyMaterial> {
        Ok(match &self.material {
            Material::Ed25519 { verifying } => anp::PublicKeyMaterial::Ed25519(*verifying),
            Material::X25519 { public } => {
                anp::PublicKeyMaterial::X25519(*public.as_bytes())
            }
        })
    }

    /// 协商公钥的原始 32 字节。公开信息,给文档与测试用。
    pub fn x25519_public(&self) -> Result<[u8; 32]> {
        match &self.material {
            Material::X25519 { public } => Ok(*public.as_bytes()),
            Material::Ed25519 { .. } => Err(KeydError::Protocol(
                "this is an Ed25519 key and has no X25519 public value".into(),
            )),
        }
    }

    /// 做一次 X25519,结果是共享密钥。
    ///
    /// 输出直接落进锁定区:调用方拿到的是一个 `LockedBytes`,要读必须借闭包,
    /// 而且它没有 `Serialize`。**这是本仓库唯一一条把"秘密的新副本"交给
    /// 调用方的路**,所以限制比签名严:只有协商键能做,而且拒绝低阶 peer
    /// (那会让共享密钥退化成一个人人皆知的值)。
    pub fn diffie_hellman(&self, peer: &[u8; 32]) -> Result<LockedBytes> {
        if !matches!(self.material, Material::X25519 { .. }) {
            return Err(KeydError::Protocol(
                "ECDH_KEY_INVALID: key agreement needs an X25519 key".into(),
            ));
        }
        let mut rejected = false;
        let shared = self.seed.expose(|bytes| {
            LockedBytes::fill(|dst| {
                let point = StaticSecret::from(*bytes).diffie_hellman(&PublicKey::from(*peer));
                if point.was_contributory() {
                    dst.copy_from_slice(point.as_bytes());
                } else {
                    rejected = true;
                }
            })
        })?;
        if rejected {
            return Err(KeydError::Protocol(
                "ECDH_PEER_INVALID: the peer public value is of low order".into(),
            ));
        }
        Ok(shared)
    }

    /// 自检用:验一个自己刚签出来的签名。
    pub fn verify(&self, msg: &[u8], signature: &[u8; 64]) -> bool {
        match &self.material {
            Material::Ed25519 { verifying } => verifying
                .verify_strict(msg, &ed25519_dalek::Signature::from_bytes(signature))
                .is_ok(),
            Material::X25519 { .. } => false,
        }
    }
}

impl Signer for LockedSigningKey {
    fn algorithm(&self) -> KeyAlgorithm {
        match self.material {
            Material::Ed25519 { .. } => KeyAlgorithm::Ed25519,
            Material::X25519 { .. } => KeyAlgorithm::X25519,
        }
    }

    fn public_multibase(&self) -> &str {
        &self.public_multibase
    }

    fn sign(&self, msg: &[u8]) -> Result<[u8; 64]> {
        match &self.material {
            Material::Ed25519 { .. } => {
                // `SigningKey` 在闭包里就地展开、就地丢弃;开了 `zeroize` 特性之后
                // 它带 `ZeroizeOnDrop`,展开出来的那份标量也不会留在栈上。
                Ok(self
                    .seed
                    .expose(|bytes| SigningKey::from_bytes(bytes).sign(msg).to_bytes()))
            }
            Material::X25519 { .. } => Err(KeydError::Protocol(
                "ECDH_KEY_INVALID: an X25519 agreement key cannot sign".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_from(seed_byte: u8) -> LockedSigningKey {
        let id = KeyId {
            did: "did:wba:example.com:user:alice:e1_x".into(),
            kid: "did:wba:example.com:user:alice:e1_x#key-1".into(),
            thumbprint: "e1_x".into(),
        };
        let seed = LockedBytes::fill(|d| *d = [seed_byte; 32]).unwrap();
        LockedSigningKey::from_seed(id, seed).unwrap()
    }

    /// RFC 8032 §7.1 TEST 1:签名输出必须逐字节相等。
    #[test]
    fn signs_the_rfc8032_test1_vector() {
        let seed_bytes: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        let expected: [u8; 64] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
            0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
            0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
            0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];

        let id = KeyId {
            did: "did:wba:example.com:user:alice:e1_x".into(),
            kid: "did:wba:example.com:user:alice:e1_x#key-1".into(),
            thumbprint: "e1_x".into(),
        };
        let mut seed_bytes = seed_bytes;
        let key = LockedSigningKey::from_seed(id, LockedBytes::new(&mut seed_bytes).unwrap()).unwrap();

        assert_eq!(key.sign(b"").unwrap(), expected);
    }

    #[test]
    fn signature_verifies_and_is_key_bound() {
        let key = key_from(1);
        let sig = key.sign(b"hello").unwrap();
        assert!(key.verify(b"hello", &sig));

        // 换一把钥匙验,必须失败。
        let other = key_from(2);
        assert!(!other.verify(b"hello", &sig));
        assert!(!key.verify(b"other message", &sig));
    }

    /// RFC 8032 §7.1 TEST 1 的公钥 → multikey 必须以 `z6Mk` 开头。
    #[test]
    fn public_multibase_comes_from_the_seed() {
        let key = key_from(42);
        assert!(key.public_multibase().starts_with("z6Mk"));
        assert_eq!(key.algorithm(), KeyAlgorithm::Ed25519);
    }

    /// RFC 7748 §6.1 的两把私钥与那把共享密钥。
    const ALICE_SK: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];
    const ALICE_PK: [u8; 32] = [
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7,
        0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b,
        0x4e, 0x6a,
    ];
    const BOB_SK: [u8; 32] = [
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e,
        0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88,
        0xe0, 0xeb,
    ];
    const BOB_PK: [u8; 32] = [
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35,
        0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88,
        0x2b, 0x4f,
    ];
    const SHARED: [u8; 32] = [
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f,
        0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16,
        0x17, 0x42,
    ];

    fn x_key(secret: [u8; 32]) -> LockedSigningKey {
        let id = KeyId {
            did: "did:wba:example.com:user:alice:e1_x".into(),
            kid: "did:wba:example.com:user:alice:e1_x#alice-agreement".into(),
            thumbprint: "x1_x".into(),
        };
        let mut bytes = secret;
        let seed = LockedBytes::new(&mut bytes).unwrap();
        LockedSigningKey::from_seed_with_algorithm(id, KeyAlgorithm::X25519, seed).unwrap()
    }

    /// RFC 7748 §6.1:两边各自算出来的共享密钥必须逐字节相同,且等于向量值。
    #[test]
    fn diffie_hellman_matches_the_rfc7748_vector() {
        let alice = x_key(ALICE_SK);
        let bob = x_key(BOB_SK);
        assert_eq!(alice.x25519_public().unwrap(), ALICE_PK);
        assert_eq!(bob.x25519_public().unwrap(), BOB_PK);

        alice
            .diffie_hellman(&BOB_PK)
            .unwrap()
            .expose(|s| assert_eq!(s, &SHARED));
        bob.diffie_hellman(&ALICE_PK)
            .unwrap()
            .expose(|s| assert_eq!(s, &SHARED));
    }

    #[test]
    fn an_agreement_key_cannot_sign_and_a_signing_key_cannot_agree() {
        let x = x_key(ALICE_SK);
        assert!(matches!(
            x.sign(b"msg"),
            Err(KeydError::Protocol(ref code)) if code.starts_with("ECDH_KEY_INVALID")
        ));
        assert!(x.verifying_key().is_err());
        assert!(!x.verify(b"msg", &[0u8; 64]));

        let ed = key_from(1);
        assert!(matches!(
            ed.diffie_hellman(&ALICE_PK),
            Err(KeydError::Protocol(ref code)) if code.starts_with("ECDH_KEY_INVALID")
        ));
        assert!(ed.x25519_public().is_err());
        assert!(matches!(
            ed.anp_public_key().unwrap(),
            anp::PublicKeyMaterial::Ed25519(_)
        ));
    }

    /// 全零(低阶)peer 会让共享密钥变成公开值,必须拒。
    #[test]
    fn a_low_order_peer_is_refused() {
        let alice = x_key(ALICE_SK);
        assert!(alice.diffie_hellman(&[0u8; 32]).is_err());
    }

    #[test]
    fn an_agreement_multibase_comes_from_the_seed() {
        let x = x_key(ALICE_SK);
        assert_eq!(x.algorithm(), KeyAlgorithm::X25519);
        assert_eq!(
            crate::crypto::thumbprint::x25519_from_multibase(x.public_multibase()).unwrap(),
            ALICE_PK
        );
    }
}
