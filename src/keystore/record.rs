//! 磁盘记录 —— 信封的线格式。
//!
//! 磁盘上唯一存的是 `WrappedKey`。**没有任何字段携带明文密钥。**

use serde::{Deserialize, Serialize};

use crate::crypto::aead::NONCE_LEN;
use crate::error::{KeydError, Result};

/// 一个密钥在 did:wba 世界里的完整坐标。
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct KeyId {
    /// 形如 `did:wba:example.com:user:alice:e1_<指纹>`
    pub did: String,
    /// 形如 `did:wba:example.com:user:alice:e1_<指纹>#key-1`
    pub kid: String,
    /// `e1_` + 公钥 JWK 的 RFC 7638 指纹
    pub thumbprint: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyAlgorithm {
    Ed25519,
    P256,
    /// 只为把线上编号定死而存在:`0x03` 一旦被别的算法占了,协商键
    /// 就再也进不来。造它的是 `add-agreement-key` 与 `IssueDeviceKeys`
    /// (见 `docs/ADAPTER.md` §11.5)。
    X25519,
}

impl KeyAlgorithm {
    /// 磁盘上用 `serde` 的字符串,线上用单字节 —— 线上的编号一旦定下
    /// **就不能再改**,所以显式写出来,不跟着枚举顺序走。
    pub fn to_wire(self) -> u8 {
        match self {
            Self::Ed25519 => 0x01,
            Self::P256 => 0x02,
            Self::X25519 => 0x03,
        }
    }

    /// 认不出来就是 `None`。**不许蒙一个默认值** —— 把 P-256 的密钥
    /// 当成 Ed25519 用,后果是签出来的东西验不过,或者更糟。
    pub fn from_wire(raw: u8) -> Option<Self> {
        match raw {
            0x01 => Some(Self::Ed25519),
            0x02 => Some(Self::P256),
            0x03 => Some(Self::X25519),
            _ => None,
        }
    }
}

/// 口令派生的参数。**随信封一起存**,因为解开它必须重现这些参数。
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct KdfParams {
    /// `"argon2id"`
    pub alg: String,
    /// base64, 32B
    pub salt: String,
    /// KiB
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    pub fn salt_bytes(&self) -> Result<Vec<u8>> {
        decode_b64(&self.salt)
    }
}

/// AEAD 的参数。
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct AeadParams {
    /// `"xchacha20poly1305"`
    pub alg: String,
    /// base64, 24B
    pub nonce: String,
    /// base64, SHA-256(信封头 JCS) —— 防移植/重放
    pub aad_digest: String,
}

impl AeadParams {
    pub fn nonce_bytes(&self) -> Result<[u8; NONCE_LEN]> {
        let raw = decode_b64(&self.nonce)?;
        raw.try_into()
            .map_err(|_| KeydError::Protocol(format!("nonce must be {NONCE_LEN} bytes")))
    }
}

/// 信封头里参与 AAD 的那部分字段。
///
/// 这一组字段就是"信封的身份"。改其中任何一个,解密都会失败 ——
/// 所以 A 的信封无法被改标成 B 的。
///
/// 比计划 §四列的字段多三个:`kdf_m_cost` / `kdf_t_cost` / `kdf_p_cost`。
/// 信封文件是**不可信输入**,而成本参数决定了解开它时守护进程要申请多少
/// 内存 —— 不绑进 AAD,能写这个文件的人就能替守护进程挑 Argon2 的内存开销
/// (抬到几 GB 就是一次 OOM),而且症状和"口令错"长得一模一样。
/// 绑进来之后,这类改动在**分配任何内存之前**就以 `AadMismatch` 暴露。
///
/// # v2 多出来的那两个字段
///
/// `hardware` 和 `hs_ciphertext` 是硬件绑定信封(v2)才有的,绑进 AAD 是为了
/// 让"绑了**哪种**硬件、哪个 tag"本身被认证:`hardware` 决定去钥匙串或 TPM
/// 里按什么名字找东西,一个没被认证的字符串指路等于让能写这个文件的人把
/// 我们往**别处**引。
///
/// 两个字段都带 `skip_serializing_if`,`None` 时整个键都不出现 —— 所以 v1 的
/// 规范化 JSON 逐字节不变(见 [`WrappedKey::aad_digest`] 的用例)。
#[derive(Debug, Serialize)]
struct AadHeader<'a> {
    version: u8,
    did: &'a str,
    kid: &'a str,
    algorithm: KeyAlgorithm,
    public_multibase: &'a str,
    kdf_alg: &'a str,
    kdf_salt: &'a str,
    kdf_m_cost: u32,
    kdf_t_cost: u32,
    kdf_p_cost: u32,
    label: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    hardware: Option<&'a HardwareRoot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hs_ciphertext: Option<&'a str>,
}

/// 磁盘上唯一存的东西。
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WrappedKey {
    pub version: u8,
    pub id: KeyId,
    pub algorithm: KeyAlgorithm,
    /// 公钥,可公开。`z6Mk...` multibase
    pub public_multibase: String,
    /// 人读的标签,仅供 `LIST_KEYS` 展示
    #[serde(default)]
    pub label: String,
    pub kdf: KdfParams,
    pub aead: AeadParams,
    /// base64(被 KEK 包住的 DEK)
    pub dek_ciphertext: String,
    /// base64(被 DEK 包住的 Ed25519 seed)
    pub sk_ciphertext: String,
    /// RFC3339
    pub created_at: String,
    /// v1 恒为 None;v2 恒为 Some —— 两者同时成立由 [`WrappedKey::validate`] 管。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardware: Option<HardwareRoot>,
    /// base64(硬件那一趟的产物)。和 `hardware` 同生共死。
    ///
    /// **可以是一个空串**,而且那不是 bug:TPM 和软件假后端把秘密整个留在
    /// 设备里,信封上不需要带任何东西;只有 macOS SE 那一侧必须带(它要带上
    /// 临时公钥,好让 ECDH 能再算一次)。字段在,值可以空 —— 一个"有没有
    /// 硬件"的判据应该是 `hardware` 在不在,不是这里长不长。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hs_ciphertext: Option<String>,
}

/// 信封绑的是哪一根根,以及**去哪儿找它**。
///
/// 这个枚举就是定位符本身,所以 [`crate::keystore::unwrap::unlock`] 的签名
/// 不需要多一个参数 —— 它拿到记录就知道该找谁。
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HardwareRoot {
    /// 钥匙串里的一把 SE 私钥,`tag` 是它的标签。
    ///
    /// **这一根搬不走**:SE 私钥不可导出,它唯一的持久化机制是钥匙串。
    SecureEnclave { tag: String },
    /// TPM 里一个持久化的密封对象,`handle` 是它的持久句柄。
    ///
    /// 用持久句柄而不是 transient 的:后者重启就没了,而"重启之后信封还在"
    /// 是普通人对一台机器的预期。
    Tpm { handle: u32 },
    /// 纯软件的替身,`tag` 是它那个目录的路径。**只在 `hardware-software`
    /// 构建里存在**,而且它自己承认自己不是硬件。
    Software { tag: String },
}

impl HardwareRoot {
    /// 这一根的名字 —— **和 `--hardware` 的取值、以及
    /// [`crate::keystore::hardware::known_names`] 那套逐字相同**。
    ///
    /// 审计里记的是这个词。同一个东西在两个地方有两个名字,事后拿日志去
    /// 对照命令行的人会对不上;所以这里的字面量和 `FromStr` 那一侧同源。
    pub fn kind(&self) -> &'static str {
        match self {
            Self::SecureEnclave { .. } => "secure-enclave",
            Self::Tpm { .. } => "tpm",
            Self::Software { .. } => "software",
        }
    }
}

/// v1:口令 + `device.secret`,两路熵。
pub const RECORD_VERSION: u8 = 1;

/// v2:再多一路来自硬件根的熵(`hs_ciphertext` 里那 32 字节)。
///
/// **v1 的字节一个都没改** —— 旧信封照旧能开,这条是硬要求,因为别人手里
/// 那些信封是他仅有的一份。
pub const RECORD_VERSION_HARDWARE: u8 = 2;

impl WrappedKey {
    /// 安全等级:从磁盘读回来的记录先过这一关,再谈密码学。
    pub fn validate(&self) -> Result<()> {
        match self.version {
            RECORD_VERSION => {
                // v1 不许偷偷带上硬件字段:那会是一个**没被认证过**的
                // `hardware`(v1 的 AAD 里没有它),也就等于一个能指路的
                // 自由字符串。要么升版,要么什么都没有。
                if self.hardware.is_some() || self.hs_ciphertext.is_some() {
                    return Err(KeydError::Protocol(
                        "a version-1 envelope carries hardware fields; version 1 has nowhere to \
                         authenticate them"
                            .into(),
                    ));
                }
            }
            RECORD_VERSION_HARDWARE => {
                // 反过来也一样:v2 必须两样都在。少了任何一样就不是"绑了硬件
                // 的信封",而是一个自称绑了、实际没有的东西 —— 正是这一整块
                // 要消灭的中间态。`hs_ciphertext` 可以是空串(见它的注释),
                // 但**必须是一个 `Some`**。
                if self.hardware.is_none() || self.hs_ciphertext.is_none() {
                    return Err(KeydError::Protocol(
                        "a version-2 envelope must carry both `hardware` and `hs_ciphertext`"
                            .into(),
                    ));
                }
            }
            other => {
                return Err(KeydError::Protocol(format!(
                    "unsupported envelope version {other} (this build speaks {RECORD_VERSION} and \
                     {RECORD_VERSION_HARDWARE})"
                )));
            }
        }
        if self.id.thumbprint.is_empty() || self.id.did.is_empty() || self.id.kid.is_empty() {
            return Err(KeydError::Protocol("envelope has an incomplete KeyId".into()));
        }
        Ok(())
    }

    /// 重算 AAD 摘要。
    ///
    /// **每一次解开之前都要重算**,再和存下来的 `aead.aad_digest` 比。
    /// 这个比对先于任何解密,所以"被改过标签的信封"在这里就露馅了。
    pub fn aad_digest(&self) -> Result<[u8; 32]> {
        let header = AadHeader {
            version: self.version,
            did: &self.id.did,
            kid: &self.id.kid,
            algorithm: self.algorithm,
            public_multibase: &self.public_multibase,
            kdf_alg: &self.kdf.alg,
            kdf_salt: &self.kdf.salt,
            kdf_m_cost: self.kdf.m_cost,
            kdf_t_cost: self.kdf.t_cost,
            kdf_p_cost: self.kdf.p_cost,
            label: &self.label,
            hardware: self.hardware.as_ref(),
            hs_ciphertext: self.hs_ciphertext.as_deref(),
        };
        let canonical = serde_json_canonicalizer::to_vec(&header)
            .map_err(|e| KeydError::Protocol(format!("jcs failed on envelope header: {e}")))?;
        Ok(crate::crypto::sha256(&canonical))
    }

    /// 信封上那把公钥,读回成一把可用的钥匙。
    ///
    /// 文档的**重建**用它:DID 文档里写什么,取决于这把钥匙;而重建发生在
    /// 签名之前、在解密之后 —— 手上当时只有信封和刚解出来的 seed。从 seed
    /// 再推一次公钥也行,但那是"再算一遍",而这里要的是"信封上声明的是哪
    /// 一把" —— 两者一旦不同,信封就已经坏了,那就该在这里炸掉。
    pub fn verifying_key(&self) -> Result<ed25519_dalek::VerifyingKey> {
        if self.algorithm != KeyAlgorithm::Ed25519 {
            return Err(KeydError::Protocol(
                "this build only holds Ed25519 keys".into(),
            ));
        }
        crate::crypto::thumbprint::ed25519_from_multibase(&self.public_multibase)
    }

    /// AAD 自检:摘要是重新算出来的,不是信存下来的那个数。
    pub fn verify_aad(&self) -> Result<[u8; 32]> {
        let recomputed = self.aad_digest()?;
        let stored = decode_b64(&self.aead.aad_digest)?;
        // 定长比较,不因为"摘要不是秘密"就偷懒用 `==`。
        if !crate::crypto::ct_eq(&recomputed, &stored) {
            return Err(KeydError::AadMismatch);
        }
        Ok(recomputed)
    }
}

pub(crate) fn encode_b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub(crate) fn decode_b64(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| KeydError::Protocol(format!("bad base64 in envelope: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> WrappedKey {
        WrappedKey {
            version: RECORD_VERSION,
            id: KeyId {
                did: "did:wba:example.com:user:alice:e1_abc".into(),
                kid: "did:wba:example.com:user:alice:e1_abc#key-1".into(),
                thumbprint: "e1_abc".into(),
            },
            algorithm: KeyAlgorithm::Ed25519,
            public_multibase: "z6Mkexample".into(),
            label: "alice".into(),
            kdf: KdfParams {
                alg: "argon2id".into(),
                salt: encode_b64(&[1u8; 32]),
                m_cost: 65536,
                t_cost: 3,
                p_cost: 1,
            },
            aead: AeadParams {
                alg: "xchacha20poly1305".into(),
                nonce: encode_b64(&[2u8; NONCE_LEN]),
                aad_digest: String::new(),
            },
            dek_ciphertext: encode_b64(&[3u8; 48]),
            sk_ciphertext: encode_b64(&[4u8; 48]),
            created_at: "2026-10-13T00:00:00Z".into(),
            hardware: None,
            hs_ciphertext: None,
        }
    }

    /// 同一个 fixture,升成 v2 —— 除了多出来的那两个字段,别的一个字都不动。
    fn sample_bound() -> WrappedKey {
        let mut k = sample();
        k.version = RECORD_VERSION_HARDWARE;
        k.hardware = Some(HardwareRoot::SecureEnclave { tag: "anpio-key:e1_abc".into() });
        k.hs_ciphertext = Some(encode_b64(&[0x77u8; 80]));
        k
    }

    #[test]
    fn aad_is_stable_across_serialization() {
        let k = sample();
        assert_eq!(k.aad_digest().unwrap(), k.aad_digest().unwrap());
    }

    /// **v1 的 AAD 摘要被钉死在这个常量上。**
    ///
    /// 加硬件根那一版时,AAD 头多了两个字段。`serde_json_canonicalizer` 按
    /// 字典序排键,两个新字段在 `None` 时被 `skip_serializing_if` 整个跳过,
    /// 所以 v1 的规范化 JSON **一个字节都没变**。这一条测试就是那个"没变"的
    /// 证据 —— 它红了说明有人改动了 v1 的 AAD 输入,而那会让**每一个已经发出去
    /// 的信封**打不开。
    #[test]
    fn the_version_1_aad_digest_is_frozen() {
        let hex: String = sample()
            .aad_digest()
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hex, "0b904bc6c88224cfabc19b013e44fbd78120b101c577c3580e2342ab896f8e4e",
            "the v1 AAD input must not change: every envelope already on disk is rebuilt from it"
        );
    }

    #[test]
    fn relabelling_the_did_breaks_the_aad() {
        let mut k = sample();
        let sealed = k.aad_digest().unwrap();
        k.aead.aad_digest = encode_b64(&sealed);

        // 现在把信封改标成"别人的"。
        k.id.did = "did:wba:example.com:user:bob:e1_abc".into();
        assert!(matches!(k.verify_aad(), Err(KeydError::AadMismatch)));
    }

    #[test]
    fn changing_the_label_breaks_the_aad() {
        let mut k = sample();
        let sealed = k.aad_digest().unwrap();
        k.aead.aad_digest = encode_b64(&sealed);

        k.label = "production".into();
        assert!(
            matches!(k.verify_aad(), Err(KeydError::AadMismatch)),
            "a label the user reads must not be silently editable"
        );
    }

    /// 成本参数必须绑进 AAD —— 否则能写这个文件的人就能替守护进程挑
    /// Argon2 的内存开销。
    #[test]
    fn downgrading_the_cost_params_breaks_the_aad() {
        for tamper in [
            (|k: &mut WrappedKey| k.kdf.m_cost = 8) as fn(&mut WrappedKey),
            |k: &mut WrappedKey| k.kdf.t_cost = 1,
            |k: &mut WrappedKey| k.kdf.p_cost = 4,
        ] {
            let mut k = sample();
            k.aead.aad_digest = encode_b64(&k.aad_digest().unwrap());
            tamper(&mut k);
            assert!(
                matches!(k.verify_aad(), Err(KeydError::AadMismatch)),
                "cost parameters are part of the envelope's identity"
            );
        }
    }

    /// 公钥也是信封身份的一部分:换掉它等于让守护进程对外宣称一把
    /// 自己签不出来的钥匙。
    #[test]
    fn swapping_the_public_key_breaks_the_aad() {
        let mut k = sample();
        k.aead.aad_digest = encode_b64(&k.aad_digest().unwrap());

        k.public_multibase = "z6Mkattacker".into();
        assert!(matches!(k.verify_aad(), Err(KeydError::AadMismatch)));
    }

    #[test]
    fn changing_the_salt_breaks_the_aad() {
        let mut k = sample();
        k.aead.aad_digest = encode_b64(&k.aad_digest().unwrap());

        k.kdf.salt = encode_b64(&[9u8; 32]);
        assert!(matches!(k.verify_aad(), Err(KeydError::AadMismatch)));
    }

    #[test]
    fn verifying_a_matching_aad_succeeds() {
        let mut k = sample();
        k.aead.aad_digest = encode_b64(&k.aad_digest().unwrap());
        assert!(k.verify_aad().is_ok());
    }

    /// 信封上写的公钥要能读回成一把真钥匙 —— 重建文档时用的就是它。
    #[test]
    fn the_envelope_public_key_reads_back() {
        let seed = crate::crypto::hygiene::LockedBytes::fill(|d| *d = [5u8; 32]).unwrap();
        let (expected, multibase) = crate::keystore::wrap::seed_to_public(&seed);

        let mut k = sample();
        k.public_multibase = multibase;
        assert_eq!(k.verifying_key().unwrap(), expected);

        // 不是 Ed25519 的算法不在这里"试着解一下"。
        k.algorithm = KeyAlgorithm::P256;
        assert!(k.verifying_key().is_err());
    }

    /// 算法编号是**对外承诺**,不是实现细节:客户端按它解释公钥。
    /// 前两个已经发出去,第三个现在留死给协商键 —— 加算法只能往后接。
    #[test]
    fn algorithm_bytes_are_frozen() {
        assert_eq!(KeyAlgorithm::Ed25519.to_wire(), 0x01);
        assert_eq!(KeyAlgorithm::P256.to_wire(), 0x02);
        assert_eq!(KeyAlgorithm::X25519.to_wire(), 0x03);

        for raw in 0x01..=0x03u8 {
            let alg = KeyAlgorithm::from_wire(raw).unwrap();
            assert_eq!(alg.to_wire(), raw);
        }
        assert_eq!(KeyAlgorithm::from_wire(0x00), None);
        assert_eq!(KeyAlgorithm::from_wire(0x04), None);
        assert_eq!(KeyAlgorithm::from_wire(0xff), None);

        // 一个编号只能对一把算法,反之亦然。
        let all = [KeyAlgorithm::Ed25519, KeyAlgorithm::P256, KeyAlgorithm::X25519];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a.to_wire(), b.to_wire());
            }
        }

        // 磁盘上的名字同样冻结。
        for (alg, name) in [
            (KeyAlgorithm::Ed25519, "\"ed25519\""),
            (KeyAlgorithm::P256, "\"p256\""),
            (KeyAlgorithm::X25519, "\"x25519\""),
        ] {
            assert_eq!(serde_json::to_string(&alg).unwrap(), name);
        }
    }

    /// X25519 进了枚举,但**这个构建不拿它签名** —— 编号是给协议留的,
    /// 不是给 `verifying_key` 留的。
    #[test]
    fn an_x25519_envelope_does_not_read_back_as_a_signing_key() {
        let mut k = sample();
        k.algorithm = KeyAlgorithm::X25519;
        assert!(k.verifying_key().is_err());
    }

    // —— v2:硬件那一趟必须是被认证的 ——

    /// 把信封换个硬件根(或者换个 tag)—— 那就是让守护进程去**别处**找
    /// HS。AAD 绑住它,所以这类改动解不开。
    #[test]
    fn swapping_the_hardware_tag_breaks_the_aad() {
        let mut k = sample_bound();
        k.aead.aad_digest = encode_b64(&k.aad_digest().unwrap());
        assert!(k.verify_aad().is_ok());

        k.hardware = Some(HardwareRoot::SecureEnclave { tag: "anpio-key:someone-else".into() });
        assert!(matches!(k.verify_aad(), Err(KeydError::AadMismatch)));
    }

    /// 连**换一种硬件**都要被抓住:SE 信封不能被改标成 TPM 信封。
    #[test]
    fn changing_which_kind_of_hardware_breaks_the_aad() {
        let mut k = sample_bound();
        k.aead.aad_digest = encode_b64(&k.aad_digest().unwrap());

        k.hardware = Some(HardwareRoot::Tpm { handle: 0x8100_0000 });
        assert!(matches!(k.verify_aad(), Err(KeydError::AadMismatch)));
    }

    /// `hs_ciphertext` 也进 AAD:换掉它等于换掉第三路熵的来源。
    #[test]
    fn swapping_the_hs_ciphertext_breaks_the_aad() {
        let mut k = sample_bound();
        k.aead.aad_digest = encode_b64(&k.aad_digest().unwrap());

        k.hs_ciphertext = Some(encode_b64(&[0x88u8; 80]));
        assert!(matches!(k.verify_aad(), Err(KeydError::AadMismatch)));
    }

    /// **把硬件整个拆掉的那一次降级。**
    ///
    /// 有两种拆法,挡它们的地方不一样 —— 这条测试的价值就在于把这件事说清楚,
    /// 而不是假设某一道防线包打天下。
    #[test]
    fn stripping_the_hardware_off_a_v2_envelope_is_refused() {
        // ① 只拆字段、不改版本号 → AAD 对不上。那两个键在 AAD 头里消失了,
        //    而 `aad_digest` 还是老的。
        let mut k = sample_bound();
        k.aead.aad_digest = encode_b64(&k.aad_digest().unwrap());
        k.hardware = None;
        assert!(matches!(k.verify_aad(), Err(KeydError::AadMismatch)));

        // ② 连版本号一起改回 1、摘要重算 → **AAD 会重新自洽**。这是真的,
        //    不是漏洞:攻击者手里有整份文件,他当然能重算一个摘要。
        //
        //    这一刀不在 AAD 上,也不在 `validate()` 上 —— 落完就成了一份
        //    字节合法、自洽的 v1 信封,格式本身分辨不出来。挡住它的是**派生**:
        //    密文是在 v2 的 KEK 下封的,而 v1 的头根本算不出那个 KEK(少一路
        //    HS),所以 `unwrap::seed_of` 会拿到一个错的 KEK、AEAD 认证不过。
        //    也就是说攻击者拿不到任何东西:他改得了标签,改不了密文。
        let mut k = sample_bound();
        k.version = RECORD_VERSION;
        k.hardware = None;
        k.hs_ciphertext = None;
        k.aead.aad_digest = encode_b64(&k.aad_digest().unwrap());
        assert!(k.verify_aad().is_ok(), "an attacker who has the file can always recompute the aad");
        assert!(
            k.validate().is_ok(),
            "after the rewrite this IS a well-formed v1 envelope — the record alone cannot tell"
        );
    }

    /// 反过来:v1 不许带硬件字段。带了也没有地方认证它。
    #[test]
    fn a_v1_envelope_may_not_carry_hardware_fields() {
        let mut k = sample();
        k.hardware = Some(HardwareRoot::Tpm { handle: 1 });
        assert!(matches!(k.validate(), Err(KeydError::Protocol(_))));

        let mut k = sample();
        k.hs_ciphertext = Some(String::new());
        assert!(matches!(k.validate(), Err(KeydError::Protocol(_))));
    }

    /// v2 必须**两样都在**。留一个空壳("自称绑了硬件")是这一整块要消灭的
    /// 中间态。
    #[test]
    fn a_v2_envelope_must_carry_both_hardware_fields() {
        let mut k = sample_bound();
        assert!(k.validate().is_ok());

        k.hs_ciphertext = None;
        assert!(matches!(k.validate(), Err(KeydError::Protocol(_))));

        let mut k = sample_bound();
        k.hardware = None;
        assert!(matches!(k.validate(), Err(KeydError::Protocol(_))));
    }

    /// 空串是**合法**的 `hs_ciphertext`(TPM 和软件假后端把秘密整个留在设备
    /// 里),所以"有没有硬件"的判据是 `hardware` 在不在,不是这里长不长。
    #[test]
    fn an_empty_hs_ciphertext_is_still_a_bound_envelope() {
        let mut k = sample_bound();
        k.hs_ciphertext = Some(String::new());
        k.aead.aad_digest = encode_b64(&k.aad_digest().unwrap());
        assert!(k.validate().is_ok());
        assert!(k.verify_aad().is_ok());
    }

    /// 认不出来的版本号要报出**两个**它能说的版本,而不是只说 v1。
    #[test]
    fn an_unknown_version_names_both_versions_this_build_speaks() {
        let mut k = sample();
        k.version = 9;
        let message = k.validate().unwrap_err().to_string();
        assert!(message.contains("9"), "{message}");
        assert!(message.contains("1") && message.contains("2"), "{message}");
    }

    /// v1 序列化出来的 JSON 里**不该出现** `hardware` / `hs_ciphertext`
    /// 这两个键 —— 这是"v1 一个字节都没改"在**磁盘上**那一半的证据。
    #[test]
    fn a_v1_envelope_writes_no_hardware_keys_at_all() {
        let json = serde_json::to_string(&sample()).unwrap();
        assert!(!json.contains("hardware"), "{json}");
        assert!(!json.contains("hs_ciphertext"), "{json}");
    }
}
