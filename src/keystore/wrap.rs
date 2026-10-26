//! 信封封装:把一把 seed 变成磁盘上的 `WrappedKey`。
//!
//! ```text
//! KEK ──XChaCha20-Poly1305(nonce, aad)──> DEK  (存密文)
//! DEK ──XChaCha20-Poly1305(nonce, aad)──> seed (存密文)
//! ```
//!
//! 两层不是装饰。DEK 那一层就是**硬件根插进来的地方**:绑了硬件之后,KEK 的
//! 熵从两路变成三路(`crypto::kdf::derive_kek_bound`),而 seed 那一层的结构
//! 一个字都不用动。信封的分层正是为了这个。

use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::aead::{self, NONCE_LEN};
use crate::crypto::hygiene::LockedBytes;
use crate::crypto::kdf::{self, Argon2Config};
use crate::error::{KeydError, Result};
use crate::keystore::hardware::SealedHardware;
use crate::keystore::record::{
    self, AeadParams, KeyAlgorithm, KeyId, KdfParams, WrappedKey, RECORD_VERSION,
    RECORD_VERSION_HARDWARE,
};

/// 封装一个信封所需的全部输入。
///
/// 用结构体而不是八个位置参数:这里面有三个 `&[u8; 32]` 形状的秘密,
/// 位置传参意味着一个手滑就能把 seed 当口令使,而编译器不会有意见。
#[derive(Debug)]
pub struct SealRequest<'a> {
    pub id: KeyId,
    pub algorithm: KeyAlgorithm,
    /// `z6Mk...` multibase
    pub public_multibase: String,
    pub label: String,
    pub passphrase: &'a [u8],
    pub device_secret: &'a LockedBytes,
    pub seed: &'a LockedBytes,
    pub argon: Argon2Config,
    /// 硬件那一趟的结果。`None` = 不绑硬件,写 v1。
    ///
    /// **由调用方先跑**([`crate::keystore::hardware::seal_new`]),而不是在这里
    /// 收一个 `HardwareChoice`:封装需要的是那 32 字节 HS 本身,而拿到它的过程
    /// 会碰钥匙串或 TPM。把它挡在这个纯函数外面,`seal` 就仍然是一个不碰任何
    /// 外部状态、随便测的东西。
    pub hardware: Option<SealedHardware>,
}

/// 把一个 seed 封成信封。
pub fn seal(req: SealRequest<'_>) -> Result<WrappedKey> {
    let SealRequest {
        id,
        algorithm,
        public_multibase,
        label,
        passphrase,
        device_secret,
        seed,
        argon,
        hardware,
    } = req;

    let mut salt = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    // 版本由"有没有硬件那一趟"决定,**没有第三个来源**。这样就不可能出现
    // 一个 v2 的信封配一条没跑的硬件路径。
    let (version, root, hs_ciphertext) = match &hardware {
        Some(sealed) => (
            RECORD_VERSION_HARDWARE,
            Some(sealed.root.clone()),
            Some(record::encode_b64(&sealed.ciphertext)),
        ),
        None => (RECORD_VERSION, None, None),
    };

    // 先搭出信封骨架 —— 它的头字段就是 AAD 的全部输入。
    // 走和 `unlock` **同一个** `aad_digest()`,所以两边不可能算岔。
    let mut wrapped = WrappedKey {
        version,
        id,
        algorithm,
        public_multibase,
        label,
        kdf: KdfParams {
            alg: "argon2id".into(),
            salt: record::encode_b64(&salt),
            m_cost: argon.m_cost,
            t_cost: argon.t_cost,
            p_cost: argon.p_cost,
        },
        aead: AeadParams {
            alg: "xchacha20poly1305".into(),
            nonce: record::encode_b64(&nonce),
            aad_digest: String::new(),
        },
        dek_ciphertext: String::new(),
        sk_ciphertext: String::new(),
        created_at: now_rfc3339(),
        hardware: root,
        hs_ciphertext,
    };

    let aad = wrapped.aad_digest()?;
    wrapped.aead.aad_digest = record::encode_b64(&aad);

    // 口令派生物用完立刻擦掉,绝不带出这个函数。
    let mut pass_key = kdf::argon2id(passphrase, &salt, argon.m_cost, argon.t_cost, argon.p_cost)?;

    // ②/③ KEK —— 分版。绑了硬件就是三路熵,没绑就是两路。
    let kek = Zeroizing::new(match &hardware {
        Some(sealed) => kdf::derive_kek_bound(&pass_key, device_secret, &salt, &sealed.hs),
        None => kdf::derive_kek(&pass_key, device_secret, &salt),
    });
    pass_key.zeroize();

    // 每把 key 一把自己的 DEK,随机生成、不落盘。
    let dek = LockedBytes::generate()?;

    let dek_ciphertext = dek.expose(|dek_bytes| aead::seal(&kek, &nonce, &aad, dek_bytes))?;
    wrapped.dek_ciphertext = record::encode_b64(&dek_ciphertext);

    let sk_ciphertext = dek.expose(|dek_bytes| {
        seed.expose(|seed_bytes| aead::seal(dek_bytes, &nonce, &aad, seed_bytes))
    })?;
    wrapped.sk_ciphertext = record::encode_b64(&sk_ciphertext);

    // dek 随 `LockedBytes` 的 Drop 擦除并 munlock;`hardware.hs` 同样。
    wrapped.validate()?;
    Ok(wrapped)
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

/// 从 32 字节 seed 构造指纹所需的一切 —— 生成与导入共用的那一步。
pub fn seed_to_public(seed: &LockedBytes) -> (ed25519_dalek::VerifyingKey, String) {
    let verifying = seed.expose(|bytes| {
        ed25519_dalek::SigningKey::from_bytes(bytes).verifying_key()
    });
    let multibase = crate::crypto::thumbprint::ed25519_multibase(&verifying);
    (verifying, multibase)
}

/// 协商键的同一趟:seed → 公钥 → multibase。推导本身在
/// [`crate::sign::key::x25519_public_from_seed`],和解锁那条路是同一个。
pub fn seed_to_x25519_public(seed: &LockedBytes) -> ([u8; 32], String) {
    let public = crate::sign::key::x25519_public_from_seed(seed);
    let multibase = crate::crypto::thumbprint::x25519_multibase(&public);
    (*public.as_bytes(), multibase)
}

/// 信封里解出来的负载必须是正好 32 字节。
///
/// 这一步在 AEAD 认证**之后** —— 所以走到这里长度还不对,意味着信封本身
/// 是被人构造出来的,不是口令错。
pub(crate) fn exact32(mut raw: Vec<u8>) -> Result<LockedBytes> {
    if raw.len() != 32 {
        raw.zeroize();
        return Err(KeydError::Protocol(format!(
            "envelope payload is {} bytes, expected 32",
            raw.len()
        )));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&raw);
    raw.zeroize();
    LockedBytes::new(&mut buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::Argon2Config;

    fn fast() -> Argon2Config {
        Argon2Config {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn id() -> KeyId {
        KeyId {
            did: "did:wba:example.com:user:alice:e1_x".into(),
            kid: "did:wba:example.com:user:alice:e1_x#key-1".into(),
            thumbprint: "e1_x".into(),
        }
    }

    fn device() -> LockedBytes {
        LockedBytes::fill(|d| *d = [5u8; 32]).unwrap()
    }

    #[test]
    fn sealed_envelope_carries_no_plaintext_seed() {
        let seed = LockedBytes::fill(|d| *d = [0xAB; 32]).unwrap();
        let (_, multibase) = seed_to_public(&seed);

        let w = seal(SealRequest {
            id: id(),
            algorithm: KeyAlgorithm::Ed25519,
            public_multibase: multibase,
            label: "alice".into(),
            passphrase: b"correct horse battery staple",
            device_secret: &device(),
            seed: &seed,
            argon: fast(),
            hardware: None,
        })
        .unwrap();

        let json = serde_json::to_string(&w).unwrap();
        // 磁盘上的 JSON 里不能出现 seed 的十六进制、base64 或十进制形式。
        assert!(!json.contains("abababab"), "hex seed leaked: {json}");
        assert!(!json.contains(&record::encode_b64(&[0xAB; 32])));
        let decimal_seed = serde_json::to_string(&[0xABu8; 32].as_slice()).unwrap();
        assert!(!json.contains(&decimal_seed), "decimal seed leaked");
    }

    #[test]
    fn aad_digest_is_populated_and_self_consistent() {
        let seed = LockedBytes::fill(|d| *d = [1u8; 32]).unwrap();
        let (_, multibase) = seed_to_public(&seed);
        let w = seal(SealRequest {
            id: id(),
            algorithm: KeyAlgorithm::Ed25519,
            public_multibase: multibase,
            label: "alice".into(),
            passphrase: b"pw",
            device_secret: &device(),
            seed: &seed,
            argon: fast(),
            hardware: None,
        })
        .unwrap();

        assert!(w.verify_aad().is_ok());
        assert!(!w.aead.aad_digest.is_empty());
    }
}
