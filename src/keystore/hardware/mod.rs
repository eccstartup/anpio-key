//! 硬件根 —— 信封的**第三路**熵。
//!
//! ```text
//! HS  = 32 随机字节,由硬件封装后存进信封(hs_ciphertext)
//! KEK = HKDF-SHA256( argon2id(口令) ‖ device.secret ‖ HS, salt )
//! DEK = open(KEK, dek_ciphertext)
//! seed = open(DEK, sk_ciphertext)
//! ```
//!
//! # 为什么是"HS 进 HKDF",不是"硬件包 KEK"
//!
//! 直接把 KEK 交给硬件包起来听起来更省事,但那要求 KEK **落盘** —— 它今天
//! 是派生出来的、从不落盘,包它就得先把它存下来,多一步而且更弱。改成 HS 走了
//! 一趟硬件,KEK 仍然是派生物,信封的两层结构、`exact32`、"同一个 nonce 两个
//! key"这些一个字节都不用动。
//!
//! # 这是第三层,不替代 `device.secret`
//!
//! `device.secret` 管"**备份**拷走没用"(它和信封在同一个目录里,一起被拷走,
//! 但那个目录不在这台机器上就打不开);硬件根管"**目录**拷到别的机器没用"。
//! 两件事,两道锁,谁都不替代谁。少任何一路都开不了。
//!
//! # 记录本身就是定位符
//!
//! [`HardwareRoot`] 那三个变体各自带着"去哪儿找这根根":SE 是钥匙串标签,
//! TPM 是持久化句柄,软件假后端是路径。所以 [`crate::keystore::unwrap::unlock`]
//! 的签名**没有变** —— 它拿到记录就知道该找谁,不需要调用方多传一个参数。
//!
//! # 没有可用硬件根就拒绝生成
//!
//! 不给"看起来在保护、其实没有"的中间态。要硬件绑定而这里没有,**报错**,
//! 不悄悄退回到纯软件信封。

#[cfg(feature = "hardware-software")]
use std::path::PathBuf;

use crate::crypto::hygiene::LockedBytes;
use crate::error::{KeydError, Result};
use crate::keystore::record::{self, HardwareRoot, WrappedKey};

#[cfg(all(target_os = "linux", feature = "hardware-tpm"))]
pub mod tpm;
#[cfg(all(target_os = "macos", feature = "hardware-se"))]
pub mod se;
#[cfg(feature = "hardware-software")]
pub mod software;

/// 一根硬件根提供的两个动作。
///
/// `seal` 在**生成**信封时跑:造出第三路熵,交回定位符、信封要带的字节和
/// 那 32 字节 HS 本身。`open` 在**解开**信封时跑:拿记录里的定位符和密文,
/// 把那 32 字节**再算一遍**。
///
/// 这两件事不对称是刻意的,而且是有用的性质:**SE 那一侧的封装不需要硬件**
/// (它是拿 SE 的**公钥**做一次 ECDH),**只有打开需要站在这台机器上**。
/// 于是"封在任意机器上做、开只能在本机做"这句话在类型上就成立。
pub trait HardwareBackend: Sync {
    /// 进 `probe` 报告和错误消息的一句话。
    fn describe(&self) -> &'static str;

    /// 这根是不是**真**硬件。软件假后端返回 `false` —— `probe` 靠它决定
    /// 体检过不过,所以假后端永远不会让一个"没有硬件"的机器体检通过。
    fn is_hardware(&self) -> bool;

    /// 造一把新的第三路熵,并把它封在这根根里。`tag_hint` 是每把钥匙唯一的
    /// 字符串(指纹),给需要"一把钥匙一个对象"的后端当名字用。
    ///
    /// # 这 32 字节是**这根根自己造的**,不是从外面递进来的
    ///
    /// 早先的签名是 `seal(&self, tag_hint, hs: &LockedBytes)` —— 调用方先生成
    /// 32 字节再递进来。那个签名对 SE **说不通**:SE 那一侧的 HS 是**推导**出来
    /// 的(拿 SE 公钥做一次 ECDH,再走一趟 HKDF),它没有"接受"一个外面给的
    /// 随机数的余地 —— 递进来的那个参数只能被忽略。一个被实现方忽略的参数是
    /// 一句谎话:读代码的人会以为那 32 字节的来历和它有关。
    ///
    /// "这 32 字节从哪来"本来就**是**各根根不一样的地方,所以它落在这个方法
    /// 里面,而不是在它的参数表上。
    fn seal(&self, tag_hint: &str) -> Result<SealedHardware>;

    /// 按记录里的定位符开一把 HS。**找不到就是 [`KeydError::HardwareMissing`]**,
    /// 而且那句话要说清是"少了哪根根",因为换机器之后人最需要知道的就是这个。
    fn open(&self, root: &HardwareRoot, ciphertext: &[u8]) -> Result<LockedBytes>;
}

/// 一封已经读过硬件那一趟的信封把料凑齐了的样子。
#[derive(Debug)]
pub struct SealedHardware {
    pub root: HardwareRoot,
    pub ciphertext: Vec<u8>,
    /// 明文 HS。**只活在这次封装的栈上**,由 `LockedBytes` 的 `Drop` 擦除。
    pub hs: LockedBytes,
}

/// 用户在命令行上挑的那一根。
///
/// 四个取值分三类:不绑、真硬件两根、以及 `Software` —— 一个**只在
/// `hardware-software` 构建里存在**的假后端,存在的理由是让 v2 格式在没有
/// 硬件的机器上真的能被测。它自己承认自己不是硬件([`HardwareBackend::is_hardware`]),
/// 所以拿它当"这台机器有硬件根"的证据是过不了 `probe` 的。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareChoice {
    None,
    SecureEnclave,
    Tpm,
    Software,
}

/// 命令行上认的名字。
///
/// **只列出这个构建/这台机器兑现得了的那些** —— 列一个然后说"这个构建里没有",
/// 正是"看起来在保护、其实没有"的那种中间态。
pub fn known_names() -> Vec<&'static str> {
    #[allow(unused_mut)]
    let mut names = vec!["none"];
    #[cfg(all(target_os = "macos", feature = "hardware-se"))]
    names.push("secure-enclave");
    #[cfg(all(target_os = "linux", feature = "hardware-tpm"))]
    names.push("tpm");
    #[cfg(feature = "hardware-software")]
    names.push("software");
    names
}

impl std::str::FromStr for HardwareChoice {
    type Err = KeydError;

    fn from_str(raw: &str) -> Result<Self> {
        match raw {
            "none" => Ok(Self::None),
            "secure-enclave" => {
                #[cfg(all(target_os = "macos", feature = "hardware-se"))]
                {
                    Ok(Self::SecureEnclave)
                }
                #[cfg(not(all(target_os = "macos", feature = "hardware-se")))]
                {
                    Err(unavailable("secure-enclave", "Secure Enclave", SE_MISSING))
                }
            }
            "tpm" => {
                #[cfg(all(target_os = "linux", feature = "hardware-tpm"))]
                {
                    Ok(Self::Tpm)
                }
                #[cfg(not(all(target_os = "linux", feature = "hardware-tpm")))]
                {
                    Err(unavailable("tpm", "TPM 2.0", TPM_MISSING))
                }
            }
            "software" => {
                #[cfg(feature = "hardware-software")]
                {
                    Ok(Self::Software)
                }
                #[cfg(not(feature = "hardware-software"))]
                {
                    Err(unavailable("software", "software stand-in", SOFTWARE_MISSING))
                }
            }
            other => Err(KeydError::HardwareUnavailable(format!(
                "unknown hardware root {other:?}; this build knows: {}",
                known_names().join(", ")
            ))),
        }
    }
}

const SE_MISSING: &str = "build it with `--features hardware-se` on macOS, and note that a \
     distributed binary must be signed with an Apple-issued certificate";
const TPM_MISSING: &str = "build it with `--features hardware-tpm` on Linux";
// `SE_MISSING` / `TPM_MISSING` 两个始终有人用 —— `uncompiled_roots()` 拿它们
// 报"这个构建里没编进来的那几根"。软件假后端没有那一条路(它从不假装是硬件),
// 所以它那句只在没开特性的时候才用得上。
#[cfg(not(feature = "hardware-software"))]
const SOFTWARE_MISSING: &str = "build it with `--features hardware-software` (test stand-in only)";

fn unavailable(name: &str, human: &str, remedy: &str) -> KeydError {
    KeydError::HardwareUnavailable(format!(
        "this build cannot use the {name} hardware root ({human} is not compiled in): {remedy}"
    ))
}

/// 记录里的定位符 → 能开它的那个后端。
///
/// **这个构建里没有那个后端,和这台机器上没有那根根,是两件事,分开说。**
/// 前者是发行决策(少编了一个 feature),后者是"信封从别的机器拷来的"或者
/// "钥匙串里的那把被删了"。把两者压成一句话,人就没法判断该做什么。
///
/// # 那些 `as &'static dyn HardwareBackend` 不是啰嗦,删了 `--all-features` 就不编
///
/// 下面每个分支里都写了一遍那个 cast(`seal_new` 里同样六处)。看着像可以
/// 让函数体自己去推导,其实不行:各处返回的是**具体的**后端类型
/// (`&'static se::SecureEnclave`、`&'static SoftwareRoot`……),而三个
/// `#[cfg]` 兄弟里**只有零到两个**在这个构建里存在。没有 cast 时,`match`
/// 的各个分支就得先自己统一成一个类型 —— 在开着多个特性的构建里它们各不相同,
/// 于是报 E0308 "match arms have incompatible types",指着两个八竿子打不着
/// 的后端说它们对不上。cast 把这件事挪到**每个分支内部**做完,分支统一的就
/// 是 `dyn HardwareBackend` 了。
///
/// 换句话说:它是在给"这个构建里有哪几根后端"这件事留出组合空间,而不是在
/// 给编译器添麻烦。
pub fn backend_for(root: &HardwareRoot) -> Result<&'static dyn HardwareBackend> {
    match root {
        HardwareRoot::SecureEnclave { .. } => {
            #[cfg(all(target_os = "macos", feature = "hardware-se"))]
            {
                Ok(&se::SECURE_ENCLAVE as &'static dyn HardwareBackend)
            }
            #[cfg(not(all(target_os = "macos", feature = "hardware-se")))]
            {
                Err(KeydError::HardwareMissing(format!(
                    "this envelope is bound to a macOS Secure Enclave key, but this build has no \
                     Secure Enclave backend ({SE_MISSING})"
                )))
            }
        }
        HardwareRoot::Tpm { .. } => {
            #[cfg(all(target_os = "linux", feature = "hardware-tpm"))]
            {
                Ok(&tpm::TPM as &'static dyn HardwareBackend)
            }
            #[cfg(not(all(target_os = "linux", feature = "hardware-tpm")))]
            {
                Err(KeydError::HardwareMissing(format!(
                    "this envelope is bound to a TPM sealed object, but this build has no TPM \
                     backend ({TPM_MISSING})"
                )))
            }
        }
        HardwareRoot::Software { .. } => {
            #[cfg(feature = "hardware-software")]
            {
                Ok(&software::SOFTWARE as &'static dyn HardwareBackend)
            }
            #[cfg(not(feature = "hardware-software"))]
            {
                Err(KeydError::HardwareMissing(
                    "this envelope is bound to the software stand-in root, which only exists in \
                     builds made with `--features hardware-software`".into()
                ))
            }
        }
    }
}

/// 挑一根根,封一把新的 HS。
///
/// `None` 是**合法**的:不绑硬件仍然是默认,而且必须是默认 —— v1 的信封一个
/// 字节都没改,旧信封照旧能开,归档那两个字节也不受影响。硬件是**要的人开口
/// 要**的东西,不是悄悄加上去的东西。
pub fn seal_new(choice: HardwareChoice, tag_hint: &str) -> Result<Option<SealedHardware>> {
    // 每个分支给一个 `Result`、用一个 `?` 收口,而不是在分支里直接 `return Err`。
    // 两种写法在开着特性的构建里一模一样,但在**默认构建**里,后者会让
    // `match` 的每一个分支都发散 —— 后面那段就变成不可达代码,编译器只好报
    // unreachable + 未使用的变量。这里没有"永远走不到"的代码,只有"这个构建
    // 走不到"的代码,不该用 allow 把差别抹掉。
    let backend: &'static dyn HardwareBackend = match choice {
        HardwareChoice::None => return Ok(None),
        HardwareChoice::SecureEnclave => {
            #[cfg(all(target_os = "macos", feature = "hardware-se"))]
            {
                Ok(&se::SECURE_ENCLAVE as &'static dyn HardwareBackend)
            }
            #[cfg(not(all(target_os = "macos", feature = "hardware-se")))]
            {
                Err(unavailable("secure-enclave", "Secure Enclave", SE_MISSING))
            }
        }
        HardwareChoice::Tpm => {
            #[cfg(all(target_os = "linux", feature = "hardware-tpm"))]
            {
                Ok(&tpm::TPM as &'static dyn HardwareBackend)
            }
            #[cfg(not(all(target_os = "linux", feature = "hardware-tpm")))]
            {
                Err(unavailable("tpm", "TPM 2.0", TPM_MISSING))
            }
        }
        HardwareChoice::Software => {
            #[cfg(feature = "hardware-software")]
            {
                Ok(&software::SOFTWARE as &'static dyn HardwareBackend)
            }
            #[cfg(not(feature = "hardware-software"))]
            {
                Err(unavailable("software", "software stand-in", SOFTWARE_MISSING))
            }
        }
    }?;

    Ok(Some(backend.seal(tag_hint)?))
}

/// 从**记录**里把那一路熵取回来。
///
/// 调用它的时机在 `verify_aad()` **之后** —— `hardware` 和 `hs_ciphertext`
/// 都在 AAD 头里,所以"绑了哪种硬件、哪个 tag"是**被认证过**的,再去钥匙串
/// 或 TPM 里按它找东西。顺序反过来就等于让一个没认证过的字符串去指路。
///
/// 放在 argon2id **之前**也是刻意的:硬件根不在的时候要立刻说,而不是先花掉
/// 64 MiB 和三轮 Argon2 再报一个"口令错"。
pub fn open_hs(wrapped: &WrappedKey) -> Result<LockedBytes> {
    let root = wrapped.hardware.as_ref().ok_or_else(|| {
        // `validate()` 已经保证 v2 一定带 hardware,走到这里就是真出问题了。
        KeydError::Protocol("envelope asks for a hardware root but carries none".into())
    })?;
    let ciphertext = record::decode_b64(
        wrapped
            .hs_ciphertext
            .as_deref()
            .ok_or_else(|| KeydError::Protocol("envelope has no hs_ciphertext".into()))?,
    )?;
    backend_for(root)?.open(root, &ciphertext)
}

// ————————————————————————————————————————————————————————————————————————
// probe
// ————————————————————————————————————————————————————————————————————————

/// `probe` 报告里的一行。
pub struct RootProbe {
    /// 给人看的名字。
    pub kind: &'static str,
    /// 这个构建里编没编进这根的后端。没编进来时 `usable` 一定是 `false`,
    /// 而 `remedy` 说的是"怎么把它编进来"。
    pub compiled: bool,
    /// 现在**真的**试了一下,成不成。不是"文件在不在"。
    pub usable: bool,
    pub detail: String,
    /// 不成立时该做什么。`None` 表示除了看 detail 没别的办法。
    pub remedy: Option<String>,
}

/// 这个构建里编进了哪几根真后端,以及它们现在能不能用。
///
/// **软件假后端不在这个列表里。** 它存在的理由是测 v2 格式,不是给"这台机器
/// 有硬件根"提供证据;把它放进来,`probe` 就会在一个没有硬件的机器上说体检
/// 通过 —— 那正是"看起来在保护、其实没有"。
///
/// 空表意味着"这个构建里一根真后端都没有",而**这本身不是失败** ——
/// 不绑硬件的部署完全合法,那是今天所有部署的样子。真正会失败的是"用户在
/// 信封里绑了硬件,而这里没有那根根",那由 [`backend_for`] 在打开时说出来。
pub fn probe_real_roots() -> Vec<RootProbe> {
    // 用 `vec![]` 而不是"先 `Vec::new()` 再逐个 `push`":元素上的 `#[cfg]`
    // 会被展开成"这个元素不存在",一个都没剩下来时就是一个空 `vec![]`。
    // 一路 `push` 的写法在**默认构建**里会变成"建了个空的、什么都没推进去",
    // clippy 的 `vec_init_then_push` 会为它报警 —— 而那不是"永远走不到"的
    // 代码,只是"这个构建没编进来",不该用 allow 把差别抹掉。
    vec![
        #[cfg(all(target_os = "macos", feature = "hardware-se"))]
        se::probe(),
        #[cfg(all(target_os = "linux", feature = "hardware-tpm"))]
        tpm::probe(),
    ]
}

/// 这个构建里**没**编进来的真后端 —— `probe` 要把它们也印出来。
///
/// 否则一份空报告看起来像"检查过了,没事",而事实是"根本没检查":一个人
/// 以为自己在 SE 上跑,拿到的却是默认构建,那正是这一整块要防的中间态。
/// 每项是 `(名字, 怎么办)`。
pub fn uncompiled_roots() -> Vec<(&'static str, &'static str)> {
    let mut missing = Vec::new();
    if !cfg!(all(target_os = "macos", feature = "hardware-se")) {
        missing.push(("macOS Secure Enclave", SE_MISSING));
    }
    if !cfg!(all(target_os = "linux", feature = "hardware-tpm")) {
        missing.push(("Linux TPM 2.0", TPM_MISSING));
    }
    missing
}

/// 软件假后端把它的根目录放在哪儿。
///
/// 默认 `$HOME/.anpio-key-software-hsm`;`ANPIO_KEY_SOFTWARE_HSM` 可以改,
/// 测"把信封拷到另一台机器"用的就是它。生产部署不该用它 —— 它**不是硬件**,
/// 一个能读这个目录的人就能开信封。
#[cfg(feature = "hardware-software")]
pub fn software_root_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("ANPIO_KEY_SOFTWARE_HSM") {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var_os("HOME").ok_or_else(|| {
        KeydError::HardwareUnavailable(
            "the software stand-in root needs $HOME or $ANPIO_KEY_SOFTWARE_HSM to know where to live"
                .into(),
        )
    })?;
    Ok(PathBuf::from(home).join(".anpio-key-software-hsm"))
}
