//! macOS Secure Enclave —— 真后端之一:**ECDH 封装 + 钥匙串持久化**。
//!
//! # 为什么是 ECDH,不是"拿 SE 公钥把 HS 加密"
//!
//! Secure Enclave 只做 ECDH(P-256)—— 它不做公钥加密,也没有"用公钥包一段
//! 数据"这个动作。所以这一根的工作方式是:
//!
//! ```text
//! 封装(不需要 SE 参与,只需要它的公钥 —— 所以封可以在任何机器上做):
//!     临时 P-256 私钥 e ──ECDH──> SE 公钥    → shared
//!     HS = HKDF-SHA256(shared, "anp-keyd/v2/se-hs")
//!     信封带 e 的公钥(X9.63,65 字节);e 的私钥用完就扔
//!
//! 打开(必须站在这台机器上,因为 SE 私钥出不来):
//!     SE 私钥 ──ECDH──> 从信封里重建的 e 公钥 → shared
//!     HS = HKDF-SHA256(shared, ...)          ← 逐字节相同
//! ```
//!
//! 临时私钥用完就扔**不是疏忽**:它唯一的作用是让 `shared` 只有握着 SE 私钥的
//! 一方算得出来。一台已经被攻破、能替我们调 SE 的机器本来就能拿到 HS —— 那不在
//! 这一层的威胁模型里。这一层管的是**那把私钥拷不走**:把 `~/.anpio-key/` 整个搬
//! 到另一台机器,信封上那个临时公钥是公开的,少了 SE 私钥就什么都算不出来。
//!
//! # 持久化需要 Apple 签发的证书(实测,不是照抄文档)
//!
//! 在 macOS 26.7.1 / arm64 上直接量过([`probe`] 量的是同一件事):
//!
//! | 动作 | 结果 |
//! |---|---|
//! | 不签名的二进制建**不持久**的 SE 私钥(`kSecAttrIsPermanent=false`) | 成功,ECDH 可用,进程退出即消失 |
//! | 不签名的二进制建**持久**的 SE 私钥(登录钥匙串) | `-34018 errSecMissingEntitlement` |
//! | 不签名的二进制建**持久**的 SE 私钥(数据保护钥匙串) | `-34018 errSecMissingEntitlement` |
//! | 加了手写的 `keychain-access-groups` 版权限 + ad-hoc 签名 | 进程被内核 SIGKILL |
//!
//! 原因是链式的:SE 私钥**只能**靠钥匙串活过一次进程 → 写钥匙串要
//! `application-identifier` → 那个 entitlement **只有 Apple 签发的证书**给得了。
//! 所以"`--features hardware-se` 编得进去"和"这台机器上它可用"是两件事,而
//! [`probe`] 量的是后者。**不要**去试那第四行(手写 entitlement 再 ad-hoc 签),
//! 那不是失败,是进程当场被杀。
//!
//! # 这个文件里哪些**真的**被验过
//!
//! ECDH 那一整条路(临时密钥、65 字节公钥、从字节重建公钥、两侧算出同一个
//! shared、HKDF)在本机对着**真芯片**跑通过 —— 见文件末尾的
//! `the_ecdh_wrap_round_trips_on_the_real_chip`,它用的是一把不持久的 SE 私钥,
//! 而那把钥匙不需要签名身份。跑的是 [`seal`](HardwareBackend::seal) 和
//! [`open`](HardwareBackend::open) 里除了持久化之外的**每一行**。
//!
//! 持久化由独立签名验收示例覆盖，普通单元测试不能代替该验收。
//! 同签名/访问组的原始探针已在另一个 UID 和新审计会话中重开密钥，
//! 因此不能把这些 OS 属性当成钥匙串拒绝保证。生产 `seal/open` 还会执行
//! 当前本机图形登录用户检查；原始验收路径保持独立，避免把软件拒绝误记成
//! 钥匙串拒绝。详细证据和未验项见部署验收记录。
//!
//! # 执行上下文也是前置条件
//!
//! Apple TN3137 明确规定数据保护钥匙串只在用户登录上下文可用，系统
//! LaunchDaemon 不可访问。签名和 provisioning profile 不能消除这个限制。
//! 本后端不能凭登录会话内的成功探测宣称支持独立服务 UID 的后台部署。
//! https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains

use core_foundation::base::{TCFType, ToVoid};
use core_foundation::data::CFData;
use core_foundation::dictionary::CFMutableDictionary;
use core_foundation::error::{CFError, CFErrorRef};
use hkdf::Hkdf;
use security_framework::item::{ItemClass, ItemSearchOptions, KeyClass, Location, Reference, SearchResult};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework_sys::item::{
    kSecAttrKeyClass, kSecAttrKeyClassPublic, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom,
};
use security_framework_sys::key::SecKeyCreateWithData;
use sha2::Sha256;

use crate::crypto::hygiene::LockedBytes;
use crate::error::{KeydError, Result};
use crate::keystore::record::HardwareRoot;

use super::{HardwareBackend, RootProbe, SealedHardware};

/// `probe` 报告里那一行的名字。
const KIND: &str = "macOS Secure Enclave";

/// 信封里带的那个临时公钥:X9.63 非压缩 P-256 点(`0x04 ‖ X ‖ Y`)。
///
/// 长度写死在这里,是因为它同时是**信封的校验条件** —— 一个长度不对的
/// `hs_ciphertext` 要在碰 Security.framework 之前就被拒掉。
const EPHEMERAL_PUBLIC_LEN: usize = 65;

/// 我们从 ECDH 里取多少字节。P-256 的 shared secret 就是 32 字节。
const SHARED_SECRET_LEN: usize = 32;

/// HS 的推导域。和 KEK 的域分开:同一个 shared 不能既当 KEK 又当 HS。
const HS_INFO: &[u8] = b"anp-keyd/v2/se-hs";

/// 钥匙串标签的前缀。
const LABEL_PREFIX: &str = "anp-keyd/";

/// `probe` 用一次就删的那个标签。
///
/// 固定名字(不带 pid)是有意的:一次崩溃留下一个残留项之后,下一次 `probe` 会
/// 先把它清掉,而不是每次崩溃都往钥匙串里多堆一个。
const PROBE_LABEL: &str = "anp-keyd/probe";

/// `errSecMissingEntitlement`。这个数字要单独认出来,因为它说的不是"这里没有
/// SE",而是"这个二进制没资格" —— 两句话对应两种完全不同的做法。
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;

/// `errSecItemNotFound`。
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

pub static SECURE_ENCLAVE: SecureEnclave = SecureEnclave;

pub struct SecureEnclave;

// ————————————————————————————————————————————————————————————————————————
// 钥匙的造法
// ————————————————————————————————————————————————————————————————————————

/// `GenerateKeyOptions` 的装配。
///
/// `location` 是**持久化开关**,而且只有这一个开关:`security-framework` 里
/// `is_permanent = location.is_some()`,而 `SecKeyCreateRandomKey` 在没有
/// `kSecAttrIsPermanent` 时**默认持久**。所以"不持久"必须写成
/// `location: None`(它会显式落下 `kSecAttrIsPermanent=false`),而不是"不写
/// 这个键" —— 实测里少写这个键的那一次拿到的是 `-34018`,看起来像"没有权限",
/// 其实只是被默认值带进了钥匙串。
fn generate_options(token: Token, location: Option<Location>) -> GenerateKeyOptions {
    let mut options = GenerateKeyOptions::default();
    options.set_key_type(KeyType::ec_sec_prime_random());
    options.set_size_in_bits(256);
    options.set_token(token);
    if let Some(location) = location {
        options.set_location(location);
    }
    options
}

/// 一把**纯软件**的 P-256 私钥 —— 封装那一侧的临时钥匙。
///
/// 它不落钥匙串(`location: None`),所以在一个没有签名身份的二进制里也建得
/// 出来。这不削弱这一层:它是一次性的,真正的秘密在 SE 那边。
fn ephemeral_key() -> Result<SecKey> {
    SecKey::new(&generate_options(Token::Software, None)).map_err(|error| {
        KeydError::Crypto(format!(
            "could not create the ephemeral P-256 key: {error} (code {})",
            error.code()
        ))
    })
}

/// 一把**不落钥匙串**的 SE 私钥 —— 进程退出就没了。
///
/// 它证明的是"这台机器有 SE,而且 ECDH 在这块芯片上真的能用"。它**不是**一封
/// SEP 信封能用的东西:那样一把钥匙活不过这次进程。所以它只出现在两处:
/// [`probe`] 的第一刀,和本文件末尾那个对着真芯片验 ECDH 的单元测试。
fn unpersisted_se_key() -> Result<SecKey> {
    SecKey::new(&generate_options(Token::SecureEnclave, None)).map_err(|error| {
        KeydError::HardwareUnavailable(format!(
            "this machine could not create a Secure Enclave key: {error} (code {})",
            error.code()
        ))
    })
}

/// 一把**持久**的 SE 私钥 —— 存在钥匙串里,活过这次进程。
///
/// **这一行就是需要 Apple 签发证书的那一行。** 它失败时给出的
/// [`KeydError::HardwareUnavailable`] 里带着完整的原因链和该做什么,因为这是
/// 整个 M5 里最容易被误诊的一步:芯片在、代码编进去了,失败的却是权限。
fn create_persistent_se_key(label: &str) -> Result<SecKey> {
    let mut options = generate_options(Token::SecureEnclave, Some(Location::DataProtectionKeychain));
    options.set_label(label);

    SecKey::new(&options).map_err(|error| {
        let code = error.code() as i32;
        if code == ERR_SEC_MISSING_ENTITLEMENT {
            KeydError::HardwareUnavailable(format!(
                "this binary is not allowed to save a Secure Enclave key ({label}): {error} \
                 (errSecMissingEntitlement, {code}).\n\
                 A Secure Enclave private key's only way to outlive the process is the keychain, \
                 and on macOS writing a keychain item needs the `application-identifier` / \
                 `keychain-access-groups` entitlement — which only a binary signed with an \
                 Apple-issued certificate can carry.\n\
                 First check execution context: the data protection keychain requires a user \
                 login context and is unavailable to a system LaunchDaemon (Apple TN3137). \
                 A certificate cannot fix that deployment mismatch. In a supported login \
                 context, use an app-like signed bundle with an authorized provisioning profile \
                 and the required entitlement. No build flag can replace these prerequisites."
            ))
        } else {
            KeydError::HardwareUnavailable(format!(
                "this machine could not create the persistent Secure Enclave key {label:?}: \
                 {error} (code {code})"
            ))
        }
    })
}

/// 按标签把一把已存下来的 SE 私钥找回来。
///
/// 找不到就是 [`KeydError::HardwareMissing`] —— "这台机器上没有",而不是"坏
/// 了"。这两句话对一个人的下一步动作完全不同:前者要他去那台老机器上导出,
/// 后者要他报 bug。
fn find_key(label: &str) -> Result<SecKey> {
    let mut search = ItemSearchOptions::new();
    search
        .class(ItemClass::key())
        // Key generation can persist both halves under the same label. ECDH
        // and deletion must select the private half, never the first match.
        .key_class(KeyClass::private())
        .label(label)
        // 数据保护钥匙串。SE 私钥必须存在这里(Apple 的规矩),而搜的时候
        // 不指明的话搜的是登录钥匙串 —— 那就永远找不到,症状却又像"钥匙丢
        // 了"。两边用同一个标签、同一个钥匙串,才不会自己骗自己。
        .ignore_legacy_keychains()
        .load_refs(true);

    let missing = |why: String| {
        KeydError::HardwareMissing(format!(
            "this envelope is bound to a macOS Secure Enclave key labelled {label:?}, and this \
             machine cannot use it: {why}\n\
             A Secure Enclave private key cannot be copied between machines, so this envelope was \
             most likely made on a different one. The only supported way to move a key is \
             `export-seed` on the machine that still has it — do that while that machine is alive."
        ))
    };

    let results = match search.search() {
        Ok(results) => results,
        // 钥匙串里没有这一把 —— 正常,换机器了。`SecItemCopyMatching` 在什么都没
        // 匹配到时**报这个错**,而不是给一个空数组,所以这一支和下面"搜出来是
        // 空的"是同一件事。
        Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Vec::new(),
        // 这个二进制根本够不着钥匙串 —— 另一种问题(发行方式),另说。
        Err(error) if error.code() == ERR_SEC_MISSING_ENTITLEMENT => {
            return Err(KeydError::HardwareMissing(format!(
                "this envelope is bound to a macOS Secure Enclave key labelled {label:?}, and this \
                 binary is not allowed to read the keychain at all ({error}, \
                 errSecMissingEntitlement {ERR_SEC_MISSING_ENTITLEMENT}). It was built without \
                 the entitlement a Secure Enclave key needs — see the note at the top of \
                 `keystore::hardware::se`."
            )));
        }
        Err(error) => {
            return Err(missing(format!(
                "the keychain search failed ({error}, code {})",
                error.code()
            )));
        }
    };

    for result in results {
        if let SearchResult::Ref(Reference::Key(key)) = result {
            return Ok(key);
        }
    }

    Err(missing(
        "the keychain has no key with that label".to_string(),
    ))
}

/// 从信封里那 65 字节重建一个**公钥对象**,好让 SE 拿它做 ECDH。
///
/// `security-framework` 的安全封装里没有 `SecKeyCreateWithData`(只有
/// `security-framework-sys` 里有),所以这一段是 FFI。它是整个文件里唯一一处
/// 我们自己的 `unsafe`,而且输入是**不可信**的:那 65 字节虽然由 AAD 保护,
/// AAD 本身又只保证"和封的时候一样",不保证"封的时候就是对的点"。所以长度
/// 先自己查(见 [`EPHEMERAL_PUBLIC_LEN`]),再交给系统去验曲线点。
fn public_key_from_bytes(bytes: &[u8]) -> Result<SecKey> {
    if bytes.len() != EPHEMERAL_PUBLIC_LEN {
        return Err(KeydError::Protocol(format!(
            "a Secure Enclave envelope must carry a {EPHEMERAL_PUBLIC_LEN}-byte X9.63 public key; \
             this one carries {} bytes",
            bytes.len()
        )));
    }

    let attributes = CFMutableDictionary::from_CFType_pairs(&[
        (
            unsafe { kSecAttrKeyType }.to_void(),
            unsafe { kSecAttrKeyTypeECSECPrimeRandom }.to_void(),
        ),
        (
            unsafe { kSecAttrKeyClass }.to_void(),
            unsafe { kSecAttrKeyClassPublic }.to_void(),
        ),
    ])
    .to_immutable();

    let data = CFData::from_buffer(bytes);
    let mut error: CFErrorRef = std::ptr::null_mut();
    let key = unsafe {
        SecKeyCreateWithData(
            data.as_concrete_TypeRef(),
            attributes.as_concrete_TypeRef(),
            &mut error,
        )
    };

    if !error.is_null() {
        let error = unsafe { CFError::wrap_under_create_rule(error) };
        return Err(KeydError::Protocol(format!(
            "the envelope's ephemeral public key is not a usable P-256 point: {error} (code {})",
            error.code()
        )));
    }
    if key.is_null() {
        return Err(KeydError::Protocol(
            "the platform returned no key and no error for the envelope's ephemeral public key"
                .into(),
        ));
    }
    Ok(unsafe { SecKey::wrap_under_create_rule(key) })
}

/// 一把钥匙的公开部分,编码成 X9.63(非压缩 EC 点)。
fn public_bytes(key: &SecKey) -> Result<Vec<u8>> {
    let public = key.public_key().ok_or_else(|| {
        KeydError::Crypto("the Secure Enclave did not hand out a public key".into())
    })?;
    let data = public.external_representation().ok_or_else(|| {
        KeydError::Crypto("the Secure Enclave public key has no external representation".into())
    })?;
    Ok(data.bytes().to_vec())
}

/// ECDH。两个方向算出来的必须逐字节相同,否则整根根不成立 —— 这一点由
/// [`wrap_and_open_use_the_same_secret`] 和文件末尾那个真芯片测试守着。
fn shared_secret(private: &SecKey, peer: &SecKey) -> Result<Vec<u8>> {
    private
        .key_exchange(Algorithm::ECDHKeyExchangeStandard, peer, SHARED_SECRET_LEN, None)
        .map_err(|error| {
            KeydError::Crypto(format!(
                "Secure Enclave ECDH failed: {error} (code {})",
                error.code()
            ))
        })
}

/// 从 shared secret 推 HS。
///
/// 不过 `hs` 从哪来的问一句"它均匀吗"是不必要的:P-256 上随机临时私钥乘一个
/// 固定公钥,得到的是一个随机点的 X 坐标 —— 32 字节的计算性均匀随机。HKDF 在
/// 这里的作用是**域分隔**(同一个 shared 不能既当 KEK 又当 HS),不是拉伸。
fn derive_hs(shared: &[u8]) -> Result<LockedBytes> {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut hs = [0u8; 32];
    hk.expand(HS_INFO, &mut hs)
        .expect("32 is a valid HKDF-SHA256 output length");
    LockedBytes::new(&mut hs)
}

/// 信封里那个定位符(钥匙串标签)。指纹来自我们自己的代码,但它落在**磁盘上**,
/// 是外部输入的形状,所以先挡一道。
fn label_for(tag_hint: &str) -> Result<String> {
    let safe = !tag_hint.is_empty()
        && tag_hint.len() <= 128
        && tag_hint
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !safe {
        return Err(KeydError::Protocol(format!(
            "{tag_hint:?} is not usable as a Secure Enclave label"
        )));
    }
    Ok(format!("{LABEL_PREFIX}{tag_hint}"))
}

// ————————————————————————————————————————————————————————————————————————
// 后端
// ————————————————————————————————————————————————————————————————————————

impl HardwareBackend for SecureEnclave {
    fn describe(&self) -> &'static str {
        "macOS Secure Enclave (P-256 ECDH)"
    }

    fn is_hardware(&self) -> bool {
        true
    }

    fn seal(&self, tag_hint: &str) -> Result<SealedHardware> {
        crate::security::se_session::require_local_login()?;
        self.seal_raw(tag_hint)
    }

    fn open(&self, root: &HardwareRoot, ciphertext: &[u8]) -> Result<LockedBytes> {
        crate::security::se_session::require_local_login()?;
        self.open_raw(root, ciphertext)
    }
}

impl SecureEnclave {
    // Raw keychain access is deliberately kept separate from the production
    // login policy so acceptance probes cannot mistake our guard for OS denial.
    fn seal_raw(&self, tag_hint: &str) -> Result<SealedHardware> {
        let label = label_for(tag_hint)?;

        // 标签撞了就拒绝,不覆盖 —— 覆盖会把上一封信封的第三路熵悄悄换掉,
        // 症状是"那把钥匙突然打不开了",而不是任何一个报错。`find_key` 失败
        // 在这里是**期望**的(那个标签还没人用),所以只认"找到了"这一种。
        if find_key(&label).is_ok() {
            return Err(KeydError::KeyExists(format!(
                "the keychain already holds a Secure Enclave key labelled {label:?}; refusing to \
                 replace it, because replacing it would silently break the envelope that is \
                 already bound to it"
            )));
        }

        let se_key = create_persistent_se_key(&label)?;

        match wrap_against(&se_key) {
            Ok((ciphertext, hs)) => Ok(SealedHardware {
                root: HardwareRoot::SecureEnclave { tag: label },
                ciphertext,
                hs,
            }),
            Err(error) => {
                // 走到这里说明钥匙串里躺着一把**永远用不上**的钥匙(信封没写成)。
                // 删掉它,而不是留下一份看起来配好了的东西。删不掉也不掩盖原错误
                // —— 原来的那个才是要报出去的。
                let _ = se_key.delete();
                Err(error)
            }
        }
    }

    fn open_raw(&self, root: &HardwareRoot, ciphertext: &[u8]) -> Result<LockedBytes> {
        let HardwareRoot::SecureEnclave { tag } = root else {
            return Err(KeydError::Protocol(
                "the Secure Enclave backend was handed a record for a different kind of root".into(),
            ));
        };
        let se_key = find_key(tag)?;
        let peer = public_key_from_bytes(ciphertext)?;
        let shared = shared_secret(&se_key, &peer)?;
        derive_hs(&shared)
    }
}

/// 封装那一侧的全部动作,除了"把钥匙存下来"。
///
/// 单独一个函数是为了让单元测试能拿一把**不持久**的 SE 私钥把这一整段跑一遍
/// —— 那是这台机器上唯一验得了的部分,而它恰好是密码学的那部分。
fn wrap_against(se_key: &SecKey) -> Result<(Vec<u8>, LockedBytes)> {
    let se_public = se_key.public_key().ok_or_else(|| {
        KeydError::Crypto("the Secure Enclave did not hand out a public key".into())
    })?;

    // 临时密钥在软件里生成:封装这一步**不需要** SE 参与,而这正是"封可以在
    // 任何机器上做、开只能在这台机器上做"的来源。
    let ephemeral = ephemeral_key()?;
    let shared = shared_secret(&ephemeral, &se_public)?;
    let hs = derive_hs(&shared)?;
    let ciphertext = public_bytes(&ephemeral)?;
    Ok((ciphertext, hs))
}

// ————————————————————————————————————————————————————————————————————————
// probe
// ————————————————————————————————————————————————————————————————————————

/// 这根根现在能不能用,以及不能用时**该做什么**。
///
/// 三件事分开量,因为它们各自独立地坏,而且指向三个不同的动作者:
///
/// 1. **芯片在不在、ECDH 有没有**:建一把不持久的 SE 私钥。它不需要签名身份
///    (实测),所以这一步失败的含义是"这台机器不行"(Intel 没有 T2 的机器、
///    虚拟机),而不是"这个二进制不行"。
/// 2. **这个二进制能不能让 SE 私钥活下去**:建一把持久的 SE 私钥,然后**删掉**。
///    这一步才是 SEP 信封成不成立的真正前提,而它是发行方式决定的。
/// 3. **删干净没有**:体检不该在被体检的东西上留痕。
///
/// # 这一次体检会往钥匙串里写东西
///
/// 第 2 步没法"只看不碰":写不写得进去,只有写一次才知道。所以它写一把
/// [`PROBE_LABEL`] 的钥匙、立刻删掉,删不掉也照实说(那一句会进报告)。
/// 这是"`probe` 不改变被体检的东西"那条规矩的**一处有意的例外**,而且例外
/// 的范围写死在这里:一个固定标签、一把和任何信封都无关的钥匙、用完即删。
pub fn probe() -> RootProbe {
    // ① 芯片和 ECDH。
    if let Err(error) = unpersisted_se_key() {
        return RootProbe {
            kind: KIND,
            compiled: true,
            usable: false,
            detail: format!(
                "no Secure Enclave available: creating even a non-persistent SE key failed ({error})"
            ),
            remedy: Some(
                "This is not a signing problem: a non-persistent Secure Enclave key needs no \
                 entitlement, so a failure here means the chip is missing (Intel Macs without a \
                 T2) or the platform refuses ECDH for this process. Nothing can be built around \
                 it on this machine — use `--hardware tpm` on a Linux box, or run without a \
                 hardware root and accept that a copy of the disk plus the passphrase is enough."
                    .into(),
            ),
        };
    }

    // ② 持久化。残留的探针钥匙先清掉(上次崩溃留下的),再建。
    let _ = find_key(PROBE_LABEL).map(|leftover| leftover.delete());

    let se_key = match create_persistent_se_key(PROBE_LABEL) {
        Ok(key) => key,
        Err(error) => {
            return RootProbe {
                kind: KIND,
                compiled: true,
                usable: false,
                detail: format!(
                    "the chip is there and ECDH works, but a Secure Enclave key cannot be made to \
                     survive this process: {error}"
                ),
                remedy: Some(
                    "Check execution context first: this backend requires the user login data \
                     protection keychain, unavailable to a system LaunchDaemon (Apple TN3137). \
                     In a supported login context, check the signed app-like bundle, authorized \
                     provisioning profile and keychain entitlements. Signing alone does not \
                     establish persistent service access."
                        .into(),
                ),
            };
        }
    };

    // ③ 别留痕 —— 而且删不掉要说出来,不能让报告看起来是干净的。
    let cleaned = se_key.delete();

    let (usable, detail, remedy) = match cleaned {
        Ok(()) => (
            true,
            "a persistent Secure Enclave key was created, used and removed again — this binary \
             can hold an SE key across processes, so envelopes bound to one will open here"
                .to_string(),
            None,
        ),
        Err(error) => (
            true,
            format!(
                "a persistent Secure Enclave key was created and works, but the probe could not \
                 remove its own {PROBE_LABEL:?} test key again ({error}, code {}) — that leftover \
                 protects nothing, but you may want to delete it by hand",
                error.code()
            ),
            None,
        ),
    };

    RootProbe {
        kind: KIND,
        compiled: true,
        usable,
        detail,
        remedy,
    }
}

// ————————————————————————————————————————————————————————————————————————
// 验收专用入口(默认构建里不存在)
// ————————————————————————————————————————————————————————————————————————

/// 这三条只给 `examples/se-persistence.rs` 用:让"进程 A 建、进程 B 开、
/// 再删掉"成为一次真实的跨进程验收。
///
/// 它们不是发行接口。`se-acceptance` 特性默认关闭,关着的时候这段代码连
/// 同删除动作都不在二进制里;而就算打开,标签也必须以 `acceptance-` 开头,
/// 碰不到任何真实信封的钥匙。
#[cfg(feature = "se-acceptance")]
const ACCEPTANCE_TAG_PREFIX: &str = "acceptance-";

#[cfg(feature = "se-acceptance")]
fn acceptance_label(root: &HardwareRoot) -> Result<&str> {
    let HardwareRoot::SecureEnclave { tag } = root else {
        return Err(KeydError::Misuse(
            "SE acceptance only operates on a secure-enclave root".into(),
        ));
    };
    let prefix = format!("{LABEL_PREFIX}{ACCEPTANCE_TAG_PREFIX}");
    if !tag.starts_with(&prefix) {
        return Err(KeydError::Misuse(format!(
            "SE acceptance refuses label {tag:?}; it only touches labels beginning with {prefix:?}"
        )));
    }
    Ok(tag)
}

#[cfg(feature = "se-acceptance")]
pub fn acceptance_create(tag_hint: &str) -> Result<SealedHardware> {
    if !tag_hint.starts_with(ACCEPTANCE_TAG_PREFIX) {
        return Err(KeydError::Misuse(format!(
            "SE acceptance tag must begin with {ACCEPTANCE_TAG_PREFIX:?}"
        )));
    }
    SECURE_ENCLAVE.seal_raw(tag_hint)
}

#[cfg(feature = "se-acceptance")]
pub fn acceptance_open(root: &HardwareRoot, ciphertext: &[u8]) -> Result<LockedBytes> {
    acceptance_label(root)?;
    SECURE_ENCLAVE.open_raw(root, ciphertext)
}

/// Test the production login policy separately from the raw OS keychain path.
#[cfg(feature = "se-acceptance")]
pub fn acceptance_open_checked(root: &HardwareRoot, ciphertext: &[u8]) -> Result<LockedBytes> {
    acceptance_label(root)?;
    SECURE_ENCLAVE.open(root, ciphertext)
}

#[cfg(feature = "se-acceptance")]
pub fn acceptance_delete(root: &HardwareRoot) -> Result<()> {
    let label = acceptance_label(root)?;
    let key = find_key(label)?;
    key.delete().map_err(|error| {
        KeydError::HardwareUnavailable(format!(
            "could not delete the acceptance key {label:?}: {error} (code {})",
            error.code()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **这一段对着真芯片跑,而且它跑的是 `seal`/`open` 里除了持久化之外的
    /// 每一行。**
    ///
    /// 用的是一把**不持久**的 SE 私钥 —— 那不需要签名身份(见模块头那张表),
    /// 所以这台 0 个签名身份的机器上也跑得起来。于是"临时公钥重建得回来吗、
    /// 两侧算出的是同一个 shared 吗、HKDF 是不是真的对得上"这三个问题在这里
    /// 有答案,而不是靠读代码相信。
    ///
    /// 持久化那一段**仍然没被这条测试覆盖**,它也不在这里 —— 那一段要
    /// Apple 签发的证书,本机没有。
    #[test]
    fn the_ecdh_wrap_round_trips_on_the_real_chip() {
        let se_key = match unpersisted_se_key() {
            Ok(key) => key,
            Err(error) => {
                // 没有芯片 / 没有权限:构造不出这个场景。一条因为**机器**而红的
                // 测试只是噪音,所以跳过 —— 但把话说出来,免得看起来像跑过了。
                eprintln!("skipped: this machine has no usable Secure Enclave ({error})");
                return;
            }
        };

        // 封装那一侧:临时密钥 × SE 公钥。
        let (ciphertext, sealed) = wrap_against(&se_key).expect("wrapping against the real chip");
        assert_eq!(ciphertext.len(), EPHEMERAL_PUBLIC_LEN, "X9.63 P-256 public key");

        // 打开那一侧:SE 私钥 × 从信封字节重建的公钥 —— 走的是
        // `open` 里的同一串调用。
        let peer = public_key_from_bytes(&ciphertext).expect("the ephemeral public key rebuilds");
        let shared = shared_secret(&se_key, &peer).expect("the chip does the other half of the ECDH");
        let opened = derive_hs(&shared).expect("derive HS");

        let same = sealed.expose(|a| opened.expose(|b| crate::crypto::ct_eq(a, b)));
        assert!(
            same,
            "the two directions of the ECDH must land on the same 32 bytes — if they do not, an \
             SE-bound envelope can be sealed and never opened again"
        );
    }

    /// 两侧算法/长度只要有一处不一致,`shared` 就会不同,而症状是"信封打不开"
    /// 这种最难查的报错。这条测试把"同一个 shared"这件事本身钉住。
    #[test]
    fn wrap_and_open_use_the_same_secret() {
        let Ok(se_key) = unpersisted_se_key() else {
            eprintln!("skipped: no usable Secure Enclave on this machine");
            return;
        };
        let Ok(se_public) = se_key.public_key().ok_or(()) else {
            return;
        };

        let ephemeral = ephemeral_key().expect("software P-256");
        let forward = shared_secret(&ephemeral, &se_public).expect("ephemeral × SE");
        let rebuilt = public_key_from_bytes(&public_bytes(&ephemeral).unwrap()).expect("rebuild");
        let backward = shared_secret(&se_key, &rebuilt).expect("SE × rebuilt ephemeral");

        assert_eq!(forward, backward);
    }

    #[test]
    fn a_bad_ephemeral_public_key_is_refused_before_the_platform_sees_it() {
        for length in [0usize, 32, 64, 66] {
            let error = public_key_from_bytes(&vec![0u8; length])
                .expect_err("a key of the wrong length must not reach Security.framework");
            assert!(
                error.to_string().contains("65-byte"),
                "the error should say what a valid one looks like: {error}"
            );
        }
    }

    /// 标签是从磁盘上那个指纹来的,挡在这里。它同时是钥匙串里的名字,所以
    /// 一个能带分隔符或空格的标签等于让信封替我们挑名字。
    #[test]
    fn a_label_that_is_not_a_thumbprint_is_refused() {
        for bad in ["", "has space", "../escape", "a/b", &"x".repeat(129)] {
            assert!(
                label_for(bad).is_err(),
                "{bad:?} must not become a keychain label"
            );
        }
        assert_eq!(label_for("e1_abc-DEF").unwrap(), "anp-keyd/e1_abc-DEF");
    }
}
