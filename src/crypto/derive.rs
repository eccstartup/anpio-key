//! 一个助记词,四把钥匙。
//!
//! # 方案:`bip39-entropy-v2`
//!
//! ```text
//! 24 个词 ──BIP-39──> 32 字节熵 ─┬──────────────────────────────> key-1 的 seed
//!                                ├─HKDF("anp-keyd/v2/hot")────────> 热密钥的 seed
//!                                ├─HKDF("anp-keyd/v2/device-sign")> 设备签名密钥的 seed
//!                                └─HKDF("anp-keyd/v2/device-agreement")> 协商密钥的 seed
//! ```
//!
//! `key-1` 那一条**没有** HKDF:熵本身就是它的 seed,和 v1 逐字节相同。这是
//! 整个方案里必须最先钉住的一点 —— 同一张纸在 v1 和 v2 下必须推出同一个
//! DID,否则老身份换台机器就换了身份,而纸上的词还在。
//!
//! 另外三条是**新增**的推导,不是对 v1 的修改:`anp-keyd/v1/kek`、
//! `anp-keyd/v2/kek`、`anp-keyd/v2/se-hs` 这些已发布的域串一个字都不动
//! (`kek` 那两条在 [`crate::crypto::kdf`])。
//!
//! # 为什么三条子密钥用 HKDF 而不是"熵的后 32 字节"
//!
//! 分开的域串换来的是可证明的互不相关:知道热密钥的 seed 推不出根,知道
//! 根也推不出别的曲线上的那把。拿同一段字节切片当三把钥匙,信息上其实是
//! 一把。HKDF-SHA256 在这里不需要 salt —— IKM 本身就是 256 位均匀随机,
//! salt 再加一层不会变强,只会多一个要一起守住的字段。
//!
//! # 这份推导是**备份能力的全部**
//!
//! 一把没有被推导出来的钥匙(比如轮换过的热密钥)就不在助记词里。这一点
//! 必须让人知道:纸能恢复的是**这个方案原先铸出来的那四把**,轮换之后的新
//! 钥匙只能靠归档带走。所以 `keygen` 显示词的那一屏会把这件事说出来,而不是
//! 让人以为"有纸就够了"。

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::crypto::hygiene::LockedBytes;
use crate::error::Result;

/// 多密钥派生方案版本号。
///
/// 归档里那条 `derivation` 字段仍然写 `bip39-entropy-v1`
/// (见 [`crate::keystore::archive::DERIVATION_BIP39_ENTROPY_V1`]):一份归档
/// 装的是**一把** seed,它的读法没有变。v2 是"一个助记词推出四把"这件事的
/// 名字,写进审计,让人事后说得清这台机器上的四把是哪来的。
pub const DERIVATION_V2: &str = "bip39-entropy-v2";

/// 热密钥的域串。
const HOT_INFO: &[u8] = b"anp-keyd/v2/hot";
/// 设备签名密钥的域串。
const DEVICE_SIGN_INFO: &[u8] = b"anp-keyd/v2/device-sign";
/// 协商密钥的域串。
const DEVICE_AGREEMENT_INFO: &[u8] = b"anp-keyd/v2/device-agreement";

/// HKDF-SHA256(无 salt,IKM = 根 seed) → 32 字节子 seed。
///
/// 输出先落在栈上的数组里,再交给 `LockedBytes::fill` 复制并 `zeroize` ——
/// 中间不会出现一个 `Vec<u8>` 之类的、Drop 时什么都不擦的容器。
fn subkey(root: &LockedBytes, info: &[u8]) -> Result<LockedBytes> {
    root.expose(|ikm| {
        let hk = Hkdf::<Sha256>::new(None, ikm);
        let mut out = [0u8; 32];
        // 32 字节对 HKDF-SHA256 永远是合法长度,这个 expect 不可能触发。
        hk.expand(info, &mut out)
            .expect("32 is a valid HKDF-SHA256 output length");
        let seed = LockedBytes::fill(|bytes| *bytes = out);
        out.zeroize();
        seed
    })
}

/// 热密钥(`key-N`,日常请求签名)。
pub fn hot(root: &LockedBytes) -> Result<LockedBytes> {
    subkey(root, HOT_INFO)
}

/// 设备签名密钥(`device-sign`,设备断言)。
pub fn device_sign(root: &LockedBytes) -> Result<LockedBytes> {
    subkey(root, DEVICE_SIGN_INFO)
}

/// 协商密钥(`device-agreement`,ECDH)。
pub fn device_agreement(root: &LockedBytes) -> Result<LockedBytes> {
    subkey(root, DEVICE_AGREEMENT_INFO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::mnemonic;
    use crate::keystore::wrap::seed_to_public;

    fn root(byte: u8) -> LockedBytes {
        LockedBytes::fill(|bytes| *bytes = [byte; 32]).unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// **冻结测试:方案一改它就会响。**
    ///
    /// 这三个值是用 [`super::subkey`] 现在的实现算出来之后抄进来的。它们
    /// 钉住的不只是算法,还有**域串的拼写** —— 少一个连字符、把 `v2` 写成
    /// `v1`,推出来的就是另一把钥匙,而且没有任何东西会报错。
    #[test]
    fn the_v2_subkeys_are_what_they_were_when_the_scheme_was_frozen() {
        let root = root(0x00);
        assert_eq!(
            hot(&root).unwrap().expose(|bytes| hex(bytes)),
            "9b6aa9d2947c52c929c36377dc3c8f6477e7218f16d8ddee2b508fae442afb00"
        );
    }

    /// 根 seed 就是熵本身 —— 这一条是 v1 兼容的全部内容。
    ///
    /// 从 24 个词解出来的 32 字节,直接当 Ed25519 的 seed 用,和 v1 的
    /// `import-mnemonic` 走的是同一个函数([`mnemonic::from_words`])。这里
    /// 拿一个固定的词串把两条路的公钥都算一遍,逐字节比。
    #[test]
    fn the_root_key_is_still_the_mnemonic_entropy() {
        let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon art";
        let entropy = mnemonic::from_words(words).unwrap();
        let (verifying, multibase) = seed_to_public(&entropy);
        assert_eq!(
            crate::crypto::thumbprint::e1_segment(&verifying).unwrap(),
            "e1_9ZP03Nu8GrXPAUkbKNxHOKBzxPX83SShgFkRNK-f2lw",
            "the root seed must be the entropy itself; a PBKDF2 reading would produce \
             a different DID from the same paper"
        );
        assert_eq!(
            multibase,
            "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
        );
    }

    /// 三条子路径彼此不同,也都不是根 —— 否则"四把钥匙"其实是同一把。
    #[test]
    fn the_three_subkeys_differ_from_the_root_and_from_each_other() {
        let root = root(0x5a);
        let hot = hot(&root).unwrap();
        let sign = device_sign(&root).unwrap();
        let agree = device_agreement(&root).unwrap();

        let bytes = |key: &LockedBytes| key.expose(|b| *b);
        assert_ne!(bytes(&root), bytes(&hot));
        assert_ne!(bytes(&root), bytes(&sign));
        assert_ne!(bytes(&root), bytes(&agree));
        assert_ne!(bytes(&hot), bytes(&sign));
        assert_ne!(bytes(&hot), bytes(&agree));
        assert_ne!(bytes(&sign), bytes(&agree));
    }

    /// 同样的词永远推出同样的四把 —— 换台机器恢复时这是唯一的依据。
    #[test]
    fn derivation_is_deterministic() {
        let a = root(0x11);
        let b = root(0x11);
        assert_eq!(hot(&a).unwrap().expose(|x| *x), hot(&b).unwrap().expose(|x| *x));
        assert_eq!(
            device_sign(&a).unwrap().expose(|x| *x),
            device_sign(&b).unwrap().expose(|x| *x)
        );
        assert_eq!(
            device_agreement(&a).unwrap().expose(|x| *x),
            device_agreement(&b).unwrap().expose(|x| *x)
        );
    }

    /// 换一个字(哪怕只改一个 bit)四把全变 —— 一张纸对应一组身份。
    #[test]
    fn a_single_bit_change_moves_every_key() {
        let a = root(0x22);
        let mut changed = [0x22u8; 32];
        changed[31] ^= 1;
        let b = LockedBytes::fill(|bytes| *bytes = changed).unwrap();

        assert_ne!(a.expose(|x| *x), b.expose(|x| *x));
        assert_ne!(hot(&a).unwrap().expose(|x| *x), hot(&b).unwrap().expose(|x| *x));
        assert_ne!(
            device_sign(&a).unwrap().expose(|x| *x),
            device_sign(&b).unwrap().expose(|x| *x)
        );
        assert_ne!(
            device_agreement(&a).unwrap().expose(|x| *x),
            device_agreement(&b).unwrap().expose(|x| *x)
        );
    }
}

