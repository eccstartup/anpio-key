//! 归档 —— 把一把钥匙搬去另一台机器。
//!
//! # 和信封**不是**同一个东西
//!
//! 信封([`crate::keystore::record::WrappedKey`])有一半的熵来自
//! `device.secret`。那是好事:偷走磁盘上那个文件的人打不开它。但那也意味着
//! 信封**搬不走** —— 换一台机器,`device.secret` 就没了,信封跟着作废。
//!
//! 归档是另一个极端,而它只能是这样:它的全部保护就是**导出时现设的那个
//! 一次性口令**。没有 `device.secret`,没有别的。任何一个在别的机器上打开
//! 得开的备份,都必然如此 —— 这正是"备份"这个词的意思,也要说清楚:
//!
//! **归档文件本身就是一个可以离线暴力破解的口令保护文件。** 它的强度等于
//! 那个口令的强度乘以 Argon2id 的成本参数。所以导出时会强制要求一个不弱的
//! 口令,而且一遍就够,不留重试。
//!
//! # 格式是冻结的、公开的
//!
//! ```text
//! ┌─ 明文 ─────────────────────────────────────────────┐
//! │ format / version      这个文件是什么、哪一版         │
//! │ derivation            推导方案版本号(见 mnemonic)   │
//! │ did / kid / thumbprint  这把钥匙是谁的               │
//! │ created_at / wns_handle 什么时候造的、挂在哪个名字下 │
//! │ document              整份 DID 文档(**含 proof**)   │
//! ├─ 密文 ─────────────────────────────────────────────┤
//! │ kdf / aead / seed_ciphertext   32 字节 seed,就这样  │
//! └────────────────────────────────────────────────────┘
//! ```
//!
//! 明文那一半是**故意**明文的:那些信息本来就挂在域名上给所有人看,加密它
//! 只是让人以为"这里也有秘密"。而且明文有个实际好处 —— 一张打不开的备份,
//! 至少还能告诉人"这是谁的备份"。
//!
//! 这份格式一旦发布就不能改。改了的后果不是报错,是**旧的备份打不开**:用户
//! 手里那张纸、那个文件,是他仅有的一份。所以每个字段都要么现在就在,要么
//! 就再也进不来。README 里有同一份说明。
//!
//! # AAD 里为什么要塞文档摘要
//!
//! `did`/`kid`/`thumbprint` 绑住了"这是谁的钥匙"。但文档是整个搬过来的 ——
//! 有人换掉文档里的公钥,再把 seed 挪过去,单看头是看不出来的。所以 AAD 里
//! 放的是 **JCS 规范化后**的整份文档的 SHA-256:文档里任何一个字节变了
//! (包括与钥匙无关的字段),摘要就对不上,而这一条**先于解密**发生。

use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::crypto::aead::{self, NONCE_LEN};
use crate::crypto::hygiene::LockedBytes;
use crate::crypto::kdf::{self, Argon2Config};
use crate::error::{KeydError, Result};
use crate::keystore::record::{self, AeadParams, KdfParams};
use crate::keystore::wrap::exact32;

/// 归档文件的标识。认不出来就不是我们的文件,直接拒。
pub const ARCHIVE_FORMAT: &str = "anp-keyd-archive";

/// 归档格式版本。改格式就改它,并且**只在新版本能读懂旧版本时**才改。
pub const ARCHIVE_VERSION: u8 = 1;

/// 推导方案版本号 —— 和 [`crate::crypto::mnemonic`] 里那一套是同一个东西。
///
/// 它写进归档,是为了让文件自己说得出"我是怎么从词推出这个 seed 的"。少了
/// 这一句,一份归档就只能靠猜 —— 而猜错的代价不是报错,是**另一把钥匙**。
pub const DERIVATION_BIP39_ENTROPY_V1: &str = "bip39-entropy-v1";

const KDF_ALG: &str = "argon2id";
const AEAD_ALG: &str = "xchacha20poly1305";

/// 一份归档。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Archive {
    pub format: String,
    pub version: u8,
    /// 推导方案版本号。见 [`DERIVATION_BIP39_ENTROPY_V1`]。
    pub derivation: String,

    pub did: String,
    /// 完整的 `did#fragment`。
    pub kid: String,
    /// 这把钥匙自己的 multibase 指纹(不是 DID 里那一段 —— 只有 `key-1`
    /// 两者才相同)。导入后信封的**文件名**用它,所以它必须跟着走。
    pub thumbprint: String,
    pub created_at: String,
    /// WNS 名字(如果有)。
    ///
    /// 现在还没有 WNS 支持,所以写出来永远是 `null`。留着是因为格式冻结:
    /// 等有了 WNS 再往回塞这个字段,新旧两代归档就分叉了 —— 那时候旧版本
    /// 的 anpio-key 读新文件会拒,而这恰好是最不该拒的一类文件。
    #[serde(default)]
    pub wns_handle: Option<String>,

    /// 整份 DID 文档,**含 proof**。导入时要靠它验路径绑定。
    pub document: Value,

    pub kdf: KdfParams,
    pub aead: AeadParams,
    /// 32 字节 seed 的密文。
    pub seed_ciphertext: String,
}

/// 封一份归档所需的全部输入。
///
/// 和 [`crate::keystore::wrap::SealRequest`] 一样用结构体:这里同时有一个
/// 口令和一个 seed,位置传参意味着一次手滑就能把两者对调。
#[derive(Debug)]
pub struct SealRequest<'a> {
    pub did: String,
    pub kid: String,
    pub thumbprint: String,
    /// 钥匙的**创建时间**,不是现在。导出会换机器、换时间,而"这把钥匙是什么
    /// 时候造的"是它自己的属性,不该被导出那一刻覆盖掉。
    pub created_at: String,
    pub wns_handle: Option<String>,
    pub document: Value,
    /// 导出时现设的一次性口令。**不是**日常那个。
    pub password: &'a [u8],
    pub seed: &'a LockedBytes,
    pub argon: Argon2Config,
}

impl Archive {
    /// 结构自检。**在碰任何密码学之前**跑。
    ///
    /// 这里拒绝的每一条都是"我读不懂这个文件",而不是"这个文件是假的"。
    /// 区分这两者是有用的:前者要人去找正确的工具版本,后者要人去找正确的
    /// 口令或怀疑文件被人动过。
    pub fn validate(&self) -> Result<()> {
        if self.format != ARCHIVE_FORMAT {
            return Err(KeydError::Protocol(format!(
                "this file says it is a `{}`, and anpio-key archives are `{ARCHIVE_FORMAT}`",
                self.format
            )));
        }
        if self.version != ARCHIVE_VERSION {
            return Err(KeydError::Protocol(format!(
                "this archive is version {}, and this build reads version {ARCHIVE_VERSION}. \
                 Do not retry with a guess — use a build of anpio-key that knows this version, \
                 because a wrong reading of the format produces garbage rather than an error",
                self.version
            )));
        }
        if self.derivation != DERIVATION_BIP39_ENTROPY_V1 {
            return Err(KeydError::Protocol(format!(
                "this archive was made with derivation scheme `{}`, and this build only knows \
                 `{DERIVATION_BIP39_ENTROPY_V1}`. The seed inside is not derivable any other \
                 way, and guessing would yield a different key that opens nothing",
                self.derivation
            )));
        }
        if self.kdf.alg != KDF_ALG {
            return Err(KeydError::Protocol(format!(
                "unsupported archive KDF `{}`",
                self.kdf.alg
            )));
        }
        if self.aead.alg != AEAD_ALG {
            return Err(KeydError::Protocol(format!(
                "unsupported archive cipher `{}`",
                self.aead.alg
            )));
        }
        if self.did.is_empty() || self.kid.is_empty() || self.thumbprint.is_empty() {
            return Err(KeydError::Protocol(
                "this archive does not say whose key it holds".into(),
            ));
        }
        Ok(())
    }

    /// 重算 AAD 摘要并返回 AAD 原文。
    ///
    /// 和信封那边**同一个套路**:摘要只覆盖头,不覆盖密文;算完拿
    /// `ct_eq` 比,比不过就停,绝不用一份可疑的头去解密。
    fn verify_aad(&self) -> Result<Vec<u8>> {
        let expected = self.aad_digest()?;
        let stored = record::decode_b64(&self.aead.aad_digest)?;
        if !crate::crypto::ct_eq(&expected, &stored) {
            return Err(KeydError::AadMismatch);
        }
        Ok(expected.to_vec())
    }

    fn aad_digest(&self) -> Result<[u8; 32]> {
        // `format` 和 `version` 用常量而不是字段:它们已经由 `validate()`
        // 卡死了,而在这里用字段的话,一个被改过的 `format` 会以
        // `AadMismatch` 的形状出现 —— 那个错误在说"文件被动过",而事实是
        // "这不是我们的文件"。
        let header = AadHeader {
            format: ARCHIVE_FORMAT,
            version: ARCHIVE_VERSION,
            derivation: &self.derivation,
            did: &self.did,
            kid: &self.kid,
            thumbprint: &self.thumbprint,
            created_at: &self.created_at,
            wns_handle: self.wns_handle.as_deref(),
            document_digest: document_digest(&self.document)?,
            kdf_alg: &self.kdf.alg,
            kdf_salt: &self.kdf.salt,
            kdf_m_cost: self.kdf.m_cost,
            kdf_t_cost: self.kdf.t_cost,
            kdf_p_cost: self.kdf.p_cost,
            aead_alg: &self.aead.alg,
        };
        let bytes = serde_json_canonicalizer::to_vec(&header)
            .map_err(|e| KeydError::Protocol(format!("archive header is not canonicalizable: {e}")))?;
        Ok(crate::crypto::sha256(&bytes))
    }

    /// 写成人能存、机器能读的字节。缩进过,因为这份文件有可能被人打开看。
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| KeydError::Protocol(format!("could not serialize archive: {e}")))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let archive: Archive = serde_json::from_slice(bytes)
            .map_err(|e| KeydError::Protocol(format!("this is not an anpio-key archive: {e}")))?;
        archive.validate()?;
        Ok(archive)
    }
}

/// AAD 的**全部**输入。字段顺序无所谓 —— JCS 会按键名排序 —— 但字段集合
/// 就是"什么被认证了"的定义。
#[derive(Serialize)]
struct AadHeader<'a> {
    format: &'a str,
    version: u8,
    derivation: &'a str,
    did: &'a str,
    kid: &'a str,
    thumbprint: &'a str,
    created_at: &'a str,
    wns_handle: Option<&'a str>,
    document_digest: String,
    kdf_alg: &'a str,
    kdf_salt: &'a str,
    kdf_m_cost: u32,
    kdf_t_cost: u32,
    kdf_p_cost: u32,
    aead_alg: &'a str,
}

/// 文档摘要。
///
/// 走 JCS 再哈希,而不是对磁盘上那份字节哈希:文档会经过写盘、再读回、
/// 被 `serde_json::Value` 重排键序。JCS 把所有"表示上的差别"抹平,留下的
/// 才是**内容**。少了这一步,一份完全没被改过的文档也会在解归档时被拒。
fn document_digest(document: &Value) -> Result<String> {
    let canonical = serde_json_canonicalizer::to_vec(document)
        .map_err(|e| KeydError::Protocol(format!("DID document is not canonicalizable: {e}")))?;
    Ok(record::encode_b64(&crate::crypto::sha256(&canonical)))
}

/// 封一份归档。
pub fn seal(req: SealRequest<'_>) -> Result<Archive> {
    let mut salt = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    // 先搭骨架 —— 头字段就是 AAD 的全部输入,走和 `open` **同一个**
    // `aad_digest()`,所以两边不可能算岔。
    let mut archive = Archive {
        format: ARCHIVE_FORMAT.into(),
        version: ARCHIVE_VERSION,
        derivation: DERIVATION_BIP39_ENTROPY_V1.into(),
        did: req.did,
        kid: req.kid,
        thumbprint: req.thumbprint,
        created_at: req.created_at,
        wns_handle: req.wns_handle,
        document: req.document,
        kdf: KdfParams {
            alg: KDF_ALG.into(),
            salt: record::encode_b64(&salt),
            m_cost: req.argon.m_cost,
            t_cost: req.argon.t_cost,
            p_cost: req.argon.p_cost,
        },
        aead: AeadParams {
            alg: AEAD_ALG.into(),
            nonce: record::encode_b64(&nonce),
            aad_digest: String::new(),
        },
        seed_ciphertext: String::new(),
    };

    let aad = archive.aad_digest()?;
    archive.aead.aad_digest = record::encode_b64(&aad);

    // **这里没有 `derive_kek`** —— 归档的钥匙就是 argon2id 的输出。
    //
    // 信封那边把口令派生物再过一层 HKDF 混进 `device.secret`;归档不能那么
    // 做,因为要打开它的机器上根本没有那个 `device.secret`,而那正是整件事
    // 的目的。代价是明确的:归档的全部保护就是这个口令。
    let key = Zeroizing::new(kdf::argon2id(
        req.password,
        &salt,
        req.argon.m_cost,
        req.argon.t_cost,
        req.argon.p_cost,
    )?);

    let ciphertext = req
        .seed
        .expose(|seed_bytes| aead::seal(&key, &nonce, &aad, seed_bytes))?;
    archive.seed_ciphertext = record::encode_b64(&ciphertext);

    archive.validate()?;
    Ok(archive)
}

/// 打开一份归档,拿到那把 seed。
///
/// 顺序和信封完全一致:**自检 → AAD 比对 → 派生 → 解密**。
pub fn open(archive: &Archive, password: &[u8]) -> Result<LockedBytes> {
    archive.validate()?;
    let aad = archive.verify_aad()?;

    let salt = archive.kdf.salt_bytes()?;
    let key = Zeroizing::new(kdf::argon2id(
        password,
        &salt,
        archive.kdf.m_cost,
        archive.kdf.t_cost,
        archive.kdf.p_cost,
    )?);

    let nonce = archive.aead.nonce_bytes()?;
    let ciphertext = record::decode_b64(&archive.seed_ciphertext)?;
    exact32(aead::open(&key, &nonce, &aad, &ciphertext)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PASS: &[u8] = b"one-time export password";
    const SEED: [u8; 32] = [0x4Du8; 32];

    fn fast() -> Argon2Config {
        // 测试里把成本压到最低:真实默认值(m=64MiB, t=3)每跑一次要几百毫秒,
        // 而这里要跑几十次。**只在测试里**这样。
        Argon2Config {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn doc(did: &str) -> Value {
        json!({
            "id": did,
            "verificationMethod": [{
                "id": format!("{did}#key-1"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": "z6Mkexample",
            }],
            "authentication": [format!("{did}#key-1")],
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "proofValue": "z3ExampleProof",
            },
        })
    }

    fn fixture(tag: &str) -> Archive {
        let seed = LockedBytes::fill(|d| *d = SEED).unwrap();
        let did = format!("did:wba:example.com:user:{tag}:e1_QhYvvM2FXwFfLcVgNqXjQhYvvM2FXwFfLcVgNqXjQ");
        seal(SealRequest {
            kid: format!("{did}#key-1"),
            thumbprint: "z6MkexampleThumbprint".into(),
            did: did.clone(),
            created_at: "2026-01-02T03:04:05Z".into(),
            wns_handle: None,
            document: doc(&did),
            password: PASS,
            seed: &seed,
            argon: fast(),
        })
        .unwrap()
    }

    /// 核心那一条:归档在**一台从来没有过 `device.secret` 的机器**上也打得开。
    ///
    /// 这是它的全部意义。所以测试里刻意把归档写成字节再读回来 —— 中途不碰
    /// 任何本机状态,连 `device` 模块都不出现。
    #[test]
    fn an_archive_opens_with_nothing_but_its_password() {
        let sealed = fixture("alice");
        let bytes = sealed.to_bytes().unwrap();
        let read_back = Archive::from_bytes(&bytes).unwrap();

        let seed = open(&read_back, PASS).unwrap();
        assert_eq!(seed.expose(|s| *s), SEED);
    }

    #[test]
    fn the_wrong_password_yields_bad_passphrase() {
        let sealed = fixture("alice");
        assert!(matches!(
            open(&sealed, b"not the export password"),
            Err(KeydError::BadPassphrase)
        ));
        assert!(matches!(open(&sealed, b""), Err(KeydError::BadPassphrase)));
    }

    /// 有人换掉归档里的文档(比如把公钥换成自己的)→ AAD 先响。
    ///
    /// 换文档而不换 `did`/`kid`/`thumbprint`,所以头字段看着还是原来那个人;
    /// 挡住它的只有文档摘要。
    #[test]
    fn swapping_the_document_is_caught_before_decryption() {
        let mut tampered = fixture("alice");
        tampered.document = doc("did:wba:evil.example:user:mallory:e1_QhYvvM2FXwFfLcVgNqXjQ");

        // 用一个**错**的口令来证明顺序:如果是解密先跑,这里会是
        // `BadPassphrase`(密文确实解不开);AAD 先跑,所以是 `AadMismatch`。
        assert!(matches!(
            open(&tampered, b"definitely wrong"),
            Err(KeydError::AadMismatch)
        ));
    }

    /// 光是键序不同、或者文档被重新序列化过,不该被当成篡改。
    ///
    /// 这一条守着 JCS 那一步:把它换成"对字节直接哈希",这个测试立刻红。
    #[test]
    fn re_serializing_the_document_is_not_tampering() {
        let sealed = fixture("alice");

        // 差别在**文本**这一层:内存里的 `Value` 用的是有序映射,一读进来
        // 键序就被抹平了,所以只有比原文才看得出这份文档确实被重排过。
        let reordered_text = format!(
            "{{\"proof\":{},\"id\":{},\"authentication\":{},\"verificationMethod\":{}}}",
            sealed.document["proof"],
            sealed.document["id"],
            sealed.document["authentication"],
            sealed.document["verificationMethod"],
        );
        assert_ne!(
            reordered_text,
            serde_json::to_string(&sealed.document).unwrap(),
            "the fixture must actually be reordered"
        );

        let mut patched = sealed;
        patched.document = serde_json::from_str(&reordered_text).unwrap();
        assert_eq!(open(&patched, PASS).unwrap().expose(|s| *s), SEED);
    }

    /// 把 A 的归档改标成 B 的 → `AadMismatch`。
    #[test]
    fn relabelling_the_archive_yields_aad_mismatch() {
        let mut tampered = fixture("alice");
        tampered.did = "did:wba:example.com:user:bob:e1_QhYvvM2FXwFfLcVgNqXjQ".into();
        tampered.kid = format!("{}#key-1", tampered.did);
        assert!(matches!(
            open(&tampered, PASS),
            Err(KeydError::AadMismatch)
        ));
    }

    /// 改 KDF 成本参数 → 在派生之前就被拦下(不会去申请那个被人改过的内存量)。
    #[test]
    fn tampering_with_kdf_params_is_caught_before_derivation() {
        let mut tampered = fixture("alice");
        tampered.kdf.m_cost = 8;
        assert!(matches!(
            open(&tampered, PASS),
            Err(KeydError::AadMismatch)
        ));

        let mut tampered = fixture("alice");
        tampered.kdf.salt = record::encode_b64(&[0x11; 32]);
        assert!(matches!(
            open(&tampered, PASS),
            Err(KeydError::AadMismatch)
        ));
    }

    /// **冻结测试:推导方案版本号换了它就会响。**
    ///
    /// 这一条是明文里的,不在 AAD 里 —— 它必须在**解密之前**被读懂,因为
    /// "这份归档用的是哪一套推导"决定了后面怎么处理那个 seed。所以它由
    /// `validate()` 拒,而不是被当成篡改。
    #[test]
    fn a_derivation_scheme_this_build_does_not_know_is_refused() {
        let mut tampered = fixture("alice");
        tampered.derivation = "bip39-pbkdf2-v1".into();
        let error = open(&tampered, PASS).unwrap_err();
        assert!(
            error.to_string().contains("derivation scheme"),
            "the refusal must name the thing that is wrong: {error}"
        );
    }

    /// 更高版本号的归档要说"去找新版本",而不是"文件是假的"。
    #[test]
    fn a_newer_archive_version_is_refused_with_a_readable_reason() {
        let mut tampered = fixture("alice");
        tampered.version = ARCHIVE_VERSION + 1;
        let error = open(&tampered, PASS).unwrap_err();
        assert!(error.to_string().contains("version 2"), "{error}");
    }

    /// 不是我们的文件要说"不是我们的文件"。
    #[test]
    fn a_foreign_json_file_is_refused() {
        let error = Archive::from_bytes(b"{\"hello\":\"world\"}").unwrap_err();
        assert!(error.to_string().contains("not an anpio-key archive"), "{error}");

        let mut tampered = fixture("alice");
        tampered.format = "someone-elses-backup".into();
        let error = tampered.validate().unwrap_err();
        assert!(error.to_string().contains("anp-keyd-archive"), "{error}");
    }

    /// 密文被改动一个字节 → AEAD 认证失败。
    #[test]
    fn a_corrupted_ciphertext_does_not_open() {
        let mut tampered = fixture("alice");
        let mut raw = record::decode_b64(&tampered.seed_ciphertext).unwrap();
        raw[0] ^= 0x01;
        tampered.seed_ciphertext = record::encode_b64(&raw);
        assert!(open(&tampered, PASS).is_err());
    }

    /// 两份归档的密文不能互换(它们的 AAD 不同,所以换过去也解不开)。
    #[test]
    fn one_archives_ciphertext_does_not_open_another() {
        let a = fixture("alice");
        let b = fixture("bob");
        let mut patched = a.clone();
        patched.seed_ciphertext = b.seed_ciphertext.clone();
        assert!(open(&patched, PASS).is_err());
    }

    /// 每次封出来都不一样 —— 盐和 nonce 都是随机的,所以同样的输入不产生
    /// 同样的文件。少了这个,两份归档长得一样就等于告诉人"这两把钥匙相同"。
    #[test]
    fn sealing_twice_does_not_produce_the_same_file() {
        let a = fixture("alice").to_bytes().unwrap();
        let b = fixture("alice").to_bytes().unwrap();
        assert_ne!(a, b);
    }
}
