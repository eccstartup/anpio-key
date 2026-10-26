//! 信封解开:口令 + `device.secret`(+ 硬件根) → 内存里的一把签名密钥。
//!
//! 顺序是刻意的:**AAD 自检 → (v2)取出硬件那一趟的熵 → 派生 KEK → 解 DEK →
//! 解 seed**。任何一步不过就停在原地,不往下走。
//!
//! 硬件那一步放在 Argon2 **之前**,有两个理由:
//! 1. 硬件根不在的时候要立刻说。先花掉 64 MiB 和三轮 Argon2 再报错,人拿到的
//!    是一句"口令错",而真相是"这台机器上没有那把根"—— 那是最坏的一种错。
//! 2. 它**碰得到外部状态**(钥匙串、`/dev/tpmrm0`),所以要放在一个"头已经被
//!    认证过"的位置上:顺序反了,就成了让一个没被认证的字符串去指路。

use zeroize::{Zeroize, Zeroizing};

use crate::crypto::aead;
use crate::crypto::hygiene::LockedBytes;
use crate::crypto::kdf;
use crate::error::{KeydError, Result};
use crate::keystore::hardware;
use crate::keystore::record::{self, WrappedKey, RECORD_VERSION, RECORD_VERSION_HARDWARE};
use crate::keystore::wrap::exact32;
use crate::sign::{LockedSigningKey, Signer};

/// 解开一个信封。
///
/// 失败时给什么错**是有讲究的**:
/// - `AadMismatch` —— 信封的头被人动过(改名/改标/换硬件根)。这不是口令问题。
/// - `HardwareMissing` —— 信封绑的硬件根**这台机器上没有**。这是"少了这台
///   机器",不是"口令错" —— 混起来的话,一个换了机器的人会一遍遍重敲自己
///   那个明明没错的口令。
/// - `BadPassphrase` —— 口令错,**或者** `device.secret` 存在但内容不对。
/// - `BadDeviceSecret` —— `device.secret` 根本不在了(由调用方判定)。
///
/// "`device.secret` 存在但内容错"和"口令错"在密码学上不可区分 —— 两者都让
/// KEK 变错,AEAD 只会说"认证失败"。所以这里报 `BadPassphrase`,而调用方
/// 负责在文件缺失时给出更准确的那个错。
pub fn unlock(
    wrapped: &WrappedKey,
    passphrase: &[u8],
    device_secret: &LockedBytes,
) -> Result<LockedSigningKey> {
    let seed = seed_of(wrapped, passphrase, device_secret)?;
    key_from_seed(wrapped, seed)
}

fn key_from_seed(wrapped: &WrappedKey, seed: LockedBytes) -> Result<LockedSigningKey> {
    // 算法取自信封头,而它已经在 AAD 里 —— 所以"这把 seed 该当哪种曲线用"
    // 不是调用方的选择,是被认证过的事实。
    let key = LockedSigningKey::from_seed_with_algorithm(
        wrapped.id.clone(),
        wrapped.algorithm,
        seed,
    )?;

    // ⑤ 信封上写的公钥必须就是这把 seed 的公钥。
    //
    // AAD 已经绑住了 `public_multibase`,所以正常路径上这一条不可能不过。
    // 留着是因为它**从私钥侧重新导出**了公钥:万一哪天信封格式变了、或者
    // 有人拿到口令重封了一个自相矛盾的信封,这里会在它走出去之前拦住。
    if key.public_multibase() != wrapped.public_multibase {
        return Err(KeydError::Protocol(
            "envelope advertises a public key that is not the one its sealed private key derives"
                .into(),
        ));
    }
    Ok(key)
}

/// 解出 seed —— **内部的**那一条。
///
/// [`unlock`] 要它来造签名密钥;导出要的是那 32 个字节本身。两件事在
/// 密码学上是同一段代码,在**能拿到什么**上完全不同:前者拿到的是一把只会
/// 签名的东西,后者拿到的是种子。所以这个函数不对外 —— 对外的那个口子
/// (`open_seed`)只在带 `seed-export` 的构建里存在。
fn seed_of(wrapped: &WrappedKey, passphrase: &[u8], device_secret: &LockedBytes) -> Result<LockedBytes> {
    wrapped.validate()?;

    // ① 重算 AAD 摘要并比对。先于任何密码学 —— 也先于**任何外部调用**,
    //    所以钥匙串或者 TPM 只会被一个已经被认证过的定位符指到。
    let aad = wrapped.verify_aad()?;

    // ② 绑了硬件就先把它那一趟的 32 字节取回来。这一步碰外部状态,所以它
    //    要求 ① 已经过了。v1 的信封在这里什么都不做。
    //
    //    **不写 `_ => None` 兜底**:那样一来一个认不出来的版本号会静默地走
    //    纯软件的推导,也就是悄悄降级。`validate()` 已经拦过一道,这里再
    //    拦一道,因为这一处正是降级会发生的地方。
    let hs = match wrapped.version {
        RECORD_VERSION => None,
        RECORD_VERSION_HARDWARE => Some(hardware::open_hs(wrapped)?),
        other => {
            return Err(KeydError::Protocol(format!(
                "unsupported envelope version {other} (this build speaks {RECORD_VERSION} and \
                 {RECORD_VERSION_HARDWARE})"
            )))
        }
    };

    decrypt_seed(wrapped, passphrase, device_secret, hs.as_ref(), &aad)
}

#[cfg(all(test, target_os = "macos", feature = "hardware-se"))]
pub(crate) fn rewrap_test_se(wrapped: &WrappedKey, passphrase: &[u8], device_secret: &LockedBytes) -> WrappedKey {
    let seed = seed_of(wrapped, passphrase, device_secret).unwrap();
    crate::keystore::wrap::seal(crate::keystore::wrap::SealRequest {
        id: wrapped.id.clone(), algorithm: wrapped.algorithm,
        public_multibase: wrapped.public_multibase.clone(), label: wrapped.label.clone(),
        passphrase, device_secret, seed: &seed,
        argon: crate::crypto::kdf::Argon2Config { m_cost: 1024, t_cost: 1, p_cost: 1 },
        hardware: Some(crate::keystore::hardware::SealedHardware {
            root: record::HardwareRoot::SecureEnclave { tag: "anp-keyd/synthetic-bridge-fixture".into() },
            ciphertext: vec![4; 65], hs: LockedBytes::fill(|bytes| *bytes = [29; 32]).unwrap(),
        }),
    }).unwrap()
}

/// Trusted management bridge only: the caller pins the exact envelope snapshot
/// and keeps the loaded key under a live login-session lease. No public export API.
pub(crate) fn unlock_with_se_hs(
    wrapped: &WrappedKey,
    passphrase: &[u8],
    device_secret: &LockedBytes,
    hs: &LockedBytes,
) -> Result<LockedSigningKey> {
    wrapped.validate()?;
    let aad = wrapped.verify_aad()?;
    if !matches!(wrapped.hardware, Some(record::HardwareRoot::SecureEnclave { .. }))
        || wrapped.version != RECORD_VERSION_HARDWARE
    {
        return Err(KeydError::Locked);
    }
    key_from_seed(wrapped, decrypt_seed(wrapped, passphrase, device_secret, Some(hs), &aad)?)
}

fn decrypt_seed(
    wrapped: &WrappedKey,
    passphrase: &[u8],
    device_secret: &LockedBytes,
    hs: Option<&LockedBytes>,
    aad: &[u8],
) -> Result<LockedBytes> {

    // ③ 口令 + device.secret (+ HS)→ KEK。
    let salt = wrapped.kdf.salt_bytes()?;
    let mut pass_key = kdf::argon2id(
        passphrase,
        &salt,
        wrapped.kdf.m_cost,
        wrapped.kdf.t_cost,
        wrapped.kdf.p_cost,
    )?;
    let kek = Zeroizing::new(match hs {
        Some(hs) => kdf::derive_kek_bound(&pass_key, device_secret, &salt, hs),
        None => kdf::derive_kek(&pass_key, device_secret, &salt),
    });
    pass_key.zeroize();

    let nonce = wrapped.aead.nonce_bytes()?;

    // ④ KEK 解出 DEK。
    let dek_ciphertext = record::decode_b64(&wrapped.dek_ciphertext)?;
    let dek = exact32(aead::open(&kek, &nonce, aad, &dek_ciphertext)?)?;

    // ⑤ DEK 解出 seed。
    let sk_ciphertext = record::decode_b64(&wrapped.sk_ciphertext)?;
    exact32(dek.expose(|d| aead::open(d, &nonce, aad, &sk_ciphertext))?)
}

/// 把 seed 解出来给导出用 —— **默认构建里没有这个函数。**
///
/// 导出路径要的是**那 32 个字节本身**:它要能原样再封回一个信封、能写成
/// 24 个词、能被搬去另一台机器。这些东西一把 `LockedSigningKey` 都给不了,
/// 而为了它们去给 `LockedSigningKey` 开一个"吐 seed"的口子,等于让签名层
/// 也变成一条导出通道 —— 那正是这一整块要避免的事。
///
/// # 这个 `#[cfg]` 不是装饰
///
/// 计划要的是"导出在默认构建里根本不存在"。`export-seed` 子命令和
/// `ops::export` 都在特性后面,但那只挡住了**命令**:一个 `pub` 的解种子
/// 函数不开特性也一样编进库里,谁链接这个库都能调它换出一把 seed。
/// 够不到的导出路径才是"不存在"的导出路径。
#[cfg(feature = "seed-export")]
pub fn open_seed(
    wrapped: &WrappedKey,
    passphrase: &[u8],
    device_secret: &LockedBytes,
) -> Result<LockedBytes> {
    seed_of(wrapped, passphrase, device_secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::Argon2Config;
    use crate::keystore::record::{KeyAlgorithm, KeyId};
    use crate::keystore::wrap::{seal, seed_to_public, SealRequest};
    use crate::sign::Signer;

    const PASS: &[u8] = b"correct horse battery staple";

    #[test]
    fn se_management_bridge_requires_exact_hardware_secret_and_passphrase() {
        // Synthetic wrapping material tests the bridge, not physical hardware.
        let (old, _, seed) = fixture("se-bridge");
        let hs = device(42);
        let wrapped = seal(SealRequest {
            id: old.id.clone(), algorithm: KeyAlgorithm::Ed25519,
            public_multibase: old.public_multibase.clone(), label: old.label.clone(),
            passphrase: PASS, device_secret: &device(7), seed: &seed, argon: fast(),
            hardware: Some(crate::keystore::hardware::SealedHardware {
                root: record::HardwareRoot::SecureEnclave { tag: "anp-keyd/se-bridge".into() },
                ciphertext: vec![4; 65], hs: device(42),
            }),
        }).unwrap();
        let key = unlock_with_se_hs(&wrapped, PASS, &device(7), &hs).unwrap();
        assert_eq!(key.public_multibase(), old.public_multibase);
        assert!(unlock_with_se_hs(&wrapped, PASS, &device(7), &device(43)).is_err());
        assert!(unlock_with_se_hs(&wrapped, b"wrong", &device(7), &hs).is_err());
        assert!(unlock_with_se_hs(&wrapped, PASS, &device(8), &hs).is_err());
        assert!(unlock_with_se_hs(&old, PASS, &device(7), &hs).is_err());
        let mut tampered = wrapped.clone();
        tampered.hs_ciphertext = Some(record::encode_b64(&[5; 65]));
        assert!(unlock_with_se_hs(&tampered, PASS, &device(7), &hs).is_err());
        tampered.aead.aad_digest = record::encode_b64(&tampered.aad_digest().unwrap());
        assert!(unlock_with_se_hs(&tampered, PASS, &device(7), &hs).is_err());
    }

    fn fast() -> Argon2Config {
        Argon2Config {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn device(byte: u8) -> LockedBytes {
        LockedBytes::fill(|d| *d = [byte; 32]).unwrap()
    }

    /// 造一个信封,同时把它的 seed 和公钥带出来供比对。
    fn fixture(did_suffix: &str) -> (WrappedKey, [u8; 32], LockedBytes) {
        let seed_bytes = [0x5Au8; 32];
        let seed = LockedBytes::fill(|d| *d = seed_bytes).unwrap();
        let (_, multibase) = seed_to_public(&seed);
        let did = format!("did:wba:example.com:user:alice:{did_suffix}");
        let wrapped = seal(SealRequest {
            id: KeyId {
                kid: format!("{did}#key-1"),
                did,
                thumbprint: did_suffix.to_string(),
            },
            algorithm: KeyAlgorithm::Ed25519,
            public_multibase: multibase,
            label: "alice".into(),
            passphrase: PASS,
            device_secret: &device(7),
            seed: &seed,
            argon: fast(),
            hardware: None,
        })
        .unwrap();
        (wrapped, seed_bytes, seed)
    }

    /// 计划 M1 验收第 1 条:正确口令 + 正确 device.secret → 解出的私钥与
    /// 生成时**逐字节相同**。
    #[test]
    fn unlock_recovers_the_exact_seed() {
        let (wrapped, seed_bytes, _) = fixture("e1_x");
        let key = unlock(&wrapped, PASS, &device(7)).unwrap();

        let (expected_pub, expected_multibase) = seed_to_public(
            &LockedBytes::fill(|d| *d = seed_bytes).unwrap(),
        );

        // 最硬的一条:拿**生成时那把 seed** 的公钥去验解出来这把钥匙的签名。
        // 逐字节相同的话,这一条必然过;差一个 bit 就必然不过。
        assert_eq!(key.public_multibase(), expected_multibase);
        let sig = key.sign(b"probe").unwrap();
        expected_pub
            .verify_strict(b"probe", &ed25519_dalek::Signature::from_bytes(&sig))
            .expect("the unlocked key must be byte-identical to the sealed one");

        assert!(key.verify(b"probe", &sig));
        assert!(!key.verify(b"probe!", &sig));
    }

    /// 负例 A:只给磁盘上的 `keys/*.json`、不给口令 → `BadPassphrase`。
    #[test]
    fn wrong_passphrase_yields_bad_passphrase() {
        let (wrapped, _, _) = fixture("e1_x");
        assert!(matches!(
            unlock(&wrapped, b"not the passphrase", &device(7)),
            Err(crate::error::KeydError::BadPassphrase)
        ));
        // 空口令(等价于"没给口令")同样如此。
        assert!(matches!(
            unlock(&wrapped, b"", &device(7)),
            Err(crate::error::KeydError::BadPassphrase)
        ));
    }

    /// 负例 B 的密码学一侧:口令对、但 `device.secret` 的内容不对 → 解不开。
    /// (文件整个缺失由 `keystore::device::load` 报 `BadDeviceSecret`。)
    #[test]
    fn wrong_device_secret_yields_bad_passphrase() {
        let (wrapped, _, _) = fixture("e1_x");
        assert!(matches!(
            unlock(&wrapped, PASS, &device(8)),
            Err(crate::error::KeydError::BadPassphrase)
        ));
    }

    /// 负例 C:把 A 的信封改标成 B 的 id → `AadMismatch`,且**先于解密**发生。
    #[test]
    fn relabelled_envelope_yields_aad_mismatch() {
        let (mut wrapped, _, _) = fixture("e1_x");
        wrapped.id.did = "did:wba:example.com:user:bob:e1_y".into();
        wrapped.id.kid = "did:wba:example.com:user:bob:e1_y#key-1".into();

        assert!(matches!(
            unlock(&wrapped, PASS, &device(7)),
            Err(crate::error::KeydError::AadMismatch)
        ));
    }

    #[test]
    fn swapping_in_another_keys_ciphertext_fails() {
        let (a, _, _) = fixture("e1_x");
        let (b, _, _) = fixture("e1_y");

        // 只换密文、不换头 —— AAD 会对上,但 AEAD 认证会失败。
        let mut patched = a.clone();
        patched.dek_ciphertext = b.dek_ciphertext.clone();
        patched.aead.nonce = b.aead.nonce.clone();
        assert!(unlock(&patched, PASS, &device(7)).is_err());

        let mut patched = a.clone();
        patched.sk_ciphertext = b.sk_ciphertext.clone();
        patched.aead.nonce = b.aead.nonce.clone();
        assert!(unlock(&patched, PASS, &device(7)).is_err());
    }

    #[test]
    fn tampering_with_kdf_params_is_caught_before_derivation() {
        let (mut wrapped, _, _) = fixture("e1_x");
        // 成本参数参与 AAD,所以在派生 KEK 之前就被拦下 —— 不会去申请
        // 那个被人改过的内存量。
        wrapped.kdf.m_cost = 8;
        assert!(matches!(
            unlock(&wrapped, PASS, &device(7)),
            Err(crate::error::KeydError::AadMismatch)
        ));

        let (mut wrapped, _, _) = fixture("e1_x");
        wrapped.kdf.salt = record::encode_b64(&[0x11; 32]);
        assert!(matches!(
            unlock(&wrapped, PASS, &device(7)),
            Err(crate::error::KeydError::AadMismatch)
        ));
    }

    /// 信封上写的公钥被换成别人的 → 在 AAD 那一步就被拦下。
    #[test]
    fn swapping_the_advertised_public_key_is_refused() {
        let (mut wrapped, _, _) = fixture("e1_x");
        wrapped.public_multibase = "z6Mkattackerattackerattackerattackerattacker".into();
        assert!(matches!(
            unlock(&wrapped, PASS, &device(7)),
            Err(crate::error::KeydError::AadMismatch)
        ));
    }
}
