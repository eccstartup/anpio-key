//! BIP-39 助记词 —— 把 32 字节种子编码成 24 个能抄在纸上的词。
//!
//! # 这一版是**冻结**的推导方案
//!
//! ```text
//! 24 个词  <──BIP-39──>  32 字节熵  ==  Ed25519 的 seed
//! ```
//!
//! **走的是熵的编码/解码,不是 BIP-39 的种子派生。** 这一点必须说透,因为
//! 它是整份方案里最容易搞错、而且错了不会报错的地方:
//!
//! 标准的 BIP-39 用法是
//! `熵 → 词 → PBKDF2-HMAC-SHA512(词, 可选口令) → 64 字节种子`。
//! **这里没有那一层。** 24 个词直接编码那把 32 字节的 Ed25519 seed:没有
//! PBKDF2,也没有 BIP-39 的可选 passphrase(计划明确不做 —— 那是第二个会
//! 丢的秘密,连"默认关闭"都不给)。
//!
//! 两种读法会推出**两把完全不同的钥匙**。所以换实现、换语言、换工具时,
//! 必须按这一份来;按标准那一份来,得到的不会是一个错误,而是**另一个
//! DID** —— 纸上的词还在,打不开的东西却不报错。
//!
//! README 里有同一份说明,这是"反锁定承诺"的实质部分:格式一变,以后就再
//! 也打不开自己的身份了。
//!
//! # 为什么是 24 个词
//!
//! 32 字节 = 256 位熵 + 8 位校验和 = 264 位 = 24 × 11。别的字数对应别的
//! 熵长度,而我们的 seed 永远是 32 字节,所以这里只认 24 个词 —— 收到别的
//! 字数不是"能不能凑合",是"这根本不是我写出去的词"。

use bip39::{Language, Mnemonic};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::hygiene::LockedBytes;
use crate::error::{KeydError, Result};

/// 词数。32 字节熵的标准长度。
pub const WORDS: usize = 24;

/// 熵的字节数 —— 也就是 Ed25519 seed 的长度。
pub const ENTROPY_BYTES: usize = 32;

/// 种子 → 24 个词。
///
/// 返回 `Zeroizing<String>`:这串字单独拿出来就是私钥,所以它得跟着
/// `Zeroizing` 走,而不是变成一个随手指传递的 `String`。
pub fn to_words(seed: &LockedBytes) -> Result<Zeroizing<String>> {
    let mnemonic = seed
        .expose(|bytes| Mnemonic::from_entropy(bytes))
        .map_err(|error| {
            KeydError::Crypto(format!("this seed cannot be written as BIP-39 words: {error}"))
        })?;
    Ok(Zeroizing::new(mnemonic.to_string()))
}

/// 24 个词 → 种子。校验和不对直接拒。
///
/// 归一化自己做(见下),因为**输入是人从纸上敲回来的**:大小写、换行、
/// 多敲的空格都不该让一次恢复失败 —— 而它们也不该让一次**错误的**恢复
/// 成功,所以除了空白和大小写,一个字符都不放过。
pub fn from_words(phrase: &str) -> Result<LockedBytes> {
    let normalized = phrase
        .split_whitespace()
        .map(str::to_lowercase)
        .collect::<Vec<_>>()
        .join(" ");

    let mnemonic = Mnemonic::parse_in_normalized(Language::English, &normalized).map_err(|error| {
        // 这个错误直接给人看,所以它要说"下一步该干什么",而不只是"错在哪"。
        KeydError::Crypto(format!(
            "these words are not a valid BIP-39 mnemonic ({error}). Check them against what \
             was written down — every word, in order; the last one carries the checksum that \
             catches most slips"
        ))
    })?;

    if mnemonic.word_count() != WORDS {
        return Err(KeydError::Crypto(format!(
            "this mnemonic has {} words, and anpio-key only ever writes {WORDS} (a {ENTROPY_BYTES}-byte \
             seed). A different word count encodes a different amount of entropy, so this is \
             not a mistyped one of ours — it is a mnemonic from somewhere else",
            mnemonic.word_count()
        )));
    }

    let (mut entropy, len) = mnemonic.to_entropy_array();
    debug_assert_eq!(len, ENTROPY_BYTES, "24 words must decode to 32 bytes");

    let seed = LockedBytes::fill(|out| out.copy_from_slice(&entropy[..ENTROPY_BYTES]));
    // 无论上面成没成,明文都要抹掉。`fill` 只在 mlock 失败时失败,而那条
    // 路径上更是留不得明文。
    entropy.zeroize();
    seed
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **冻结测试:方案换了它就会响。**
    ///
    /// 这两条是 BIP-39 规范 §Test vectors 里那两个 32 字节熵的向量,
    /// 原样抄下来。它们钉住的正是"熵编码"这个读法 —— 如果哪天有人把它
    /// 改成 `to_seed()`(PBKDF2 那一层),这两个向量立刻对不上。
    #[test]
    fn the_bip39_spec_vectors_encode_the_entropy_itself() {
        let zeros = LockedBytes::fill(|d| *d = [0x00; 32]).unwrap();
        assert_eq!(
            to_words(&zeros).unwrap().as_str(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon art"
        );

        let sevens = LockedBytes::fill(|d| *d = [0x7f; 32]).unwrap();
        assert_eq!(
            to_words(&sevens).unwrap().as_str(),
            "legal winner thank year wave sausage worth useful legal winner thank year wave \
             sausage worth useful legal winner thank year wave sausage worth title"
        );
    }

    /// 一个随机种子来回一趟,必须**逐字节**回到原处 —— 差一个 bit 就是
    /// 另一个 DID,而那种错误不会有任何别的提示。
    #[test]
    fn any_seed_survives_the_round_trip() {
        for byte in [0x00u8, 0x01, 0x5a, 0x7f, 0xff] {
            let seed = LockedBytes::fill(|d| *d = [byte; 32]).unwrap();
            let words = to_words(&seed).unwrap();
            let back = from_words(&words).unwrap();
            assert_eq!(
                seed.expose(|a| *a),
                back.expose(|b| *b),
                "seed {byte:#04x} did not survive"
            );
        }
    }

    /// 24 个词里挑一个换成另一个**合法**的词 → 校验和必须拒。
    ///
    /// 挑最后一个换:`art` → `abandon` 只改一个词,而校验和就藏在最后那个
    /// 词的 3 个 bit 里。这正是"抄错一个词"最常见的形状。
    #[test]
    fn one_wrong_word_is_caught_by_the_checksum() {
        let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon about";
        // 12 个词本身是合法 BIP-39,但不是我们写的长度。
        assert!(from_words(twelve).is_err());

        let seed = LockedBytes::fill(|d| *d = [0x11; 32]).unwrap();
        let written = to_words(&seed).unwrap();
        let mut words: Vec<&str> = written.split(' ').collect();
        assert_eq!(words.len(), WORDS);
        let original = words.clone();
        words[WORDS - 1] = "abandon";
        assert_ne!(words, original, "the fixture must actually differ");
        let error = from_words(&words.join(" ")).unwrap_err();
        assert!(
            error.to_string().contains("not a valid BIP-39 mnemonic"),
            "{error}"
        );
    }

    /// 表外的词直接拒,而不是当成某个近似的词。
    #[test]
    fn an_unknown_word_is_refused() {
        let mut words: Vec<String> = to_words(&LockedBytes::fill(|d| *d = [0x22; 32]).unwrap())
            .unwrap()
            .split(' ')
            .map(str::to_string)
            .collect();
        words[3] = "notaword".into();
        assert!(from_words(&words.join(" ")).is_err());
    }

    /// 人从纸上敲回来的样子:大写、换行、多个空格、首尾空白 —— 都要吃得下。
    #[test]
    fn whitespace_and_case_do_not_break_a_restore() {
        let seed = LockedBytes::fill(|d| *d = [0x33; 32]).unwrap();
        let words = to_words(&seed).unwrap();
        let scribbled = format!("  {}\n", words.to_uppercase().replace(' ', "   "));

        let back = from_words(&scribbled).unwrap();
        assert_eq!(seed.expose(|a| *a), back.expose(|b| *b));
    }
}
