//! 密码学原语。这一层不做策略判断,只做正确的运算。

pub mod aead;
pub mod derive;
pub mod hygiene;
pub mod kdf;
pub mod mnemonic;
pub mod thumbprint;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// SHA-256。AAD 摘要、指纹、密钥哈希都走这里。
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// 常量时间相等比较。
///
/// 比较的东西未必都是秘密(比如 AAD 摘要),但**调用点的写法不该取决于
/// "这次比的是不是秘密"** —— 那种判断迟早会写错一次。
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // 长度不是秘密,提前返回不泄露信息。
        return false;
    }
    a.ct_eq(b).into()
}
