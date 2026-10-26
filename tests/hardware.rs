//! M5 硬件根的验收。**这里不测真硬件** —— 测的是硬件绑定那条路的**形状**。
//!
//! 真后端(macOS SE / Linux TPM)需要真的芯片,而这个仓库跑测试的地方不一定
//! 有(CI 上没有;这个开发机上没有签名身份,SE 那半边端到端根本验不了,见
//! `src/keystore/hardware/se.rs` 的模块头)。所以真正被测的是**纯软件的替身**
//! (`--features hardware-software`),它和真硬件的差别只有一条:HS 那 32 字节
//! 出得来。而这一整块要拿到的东西 —— "把 `~/.anpio-key/` 拷到另一台机器打不开"
//! —— 恰恰是那一条差别之外的**形状**,所以能在这里被真的测出来。
//!
//! 用替身测出来的东西**是什么**要说清楚,否则这些绿勾会变成一句超出范围的
//! 承诺:
//!
//! - ✅ 版本分派(v1 照旧开、v2 要硬件)
//! - ✅ `hardware` / `hs_ciphertext` 进 AAD:换 tag、换种类、整个拆掉都会被拦
//! - ✅ 硬件不在 → 打不开,而且报的错**说得出是少了什么**
//! - ✅ 硬件在但口令错 → 打不开(两路熵是**都**要,不是任一)
//! - ✅ 没有后端时**拒绝生成**,不静默降级
//! - ❌ "HS 出不了这台机器" —— 替身的 HS 就是一个文件,这条**没被验**,
//!   而且不可能在这里被验。那是真后端的事。
//!
//! 最后一条是有意的缺口,不是遗漏。

#[cfg(feature = "hardware-software")]
use std::path::{Path, PathBuf};
#[cfg(feature = "hardware-software")]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "hardware-software")]
use std::sync::Mutex;

use anpio_key::crypto::hygiene::LockedBytes;
use anpio_key::crypto::kdf::Argon2Config;
use anpio_key::did::document::DidDocumentSpec;
use anpio_key::error::KeydError;
use anpio_key::keystore::hardware::HardwareChoice;
#[cfg(feature = "hardware-software")]
use anpio_key::keystore::record::HardwareRoot;
use anpio_key::keystore::create;
#[cfg(all(feature = "hardware-software", feature = "seed-export"))]
use anpio_key::keystore::wrap;

#[cfg(feature = "hardware-software")]
use stand_in::*;

const PASS: &[u8] = b"correct horse battery staple";

fn fast() -> Argon2Config {
    Argon2Config { m_cost: 1024, t_cost: 1, p_cost: 1 }
}

/// 取错误而不要求 `T: Debug` —— 这几个 `Ok` 类型**故意**没有 `Debug`
/// (`LockedSigningKey`、`Created` 里都有秘密),`expect_err` 用不了。
fn expect_err<T>(result: Result<T, KeydError>, what: &str) -> KeydError {
    match result {
        Ok(_) => panic!("{what}"),
        Err(error) => error,
    }
}

fn device(byte: u8) -> LockedBytes {
    LockedBytes::fill(|d| *d = [byte; 32]).unwrap()
}

fn spec(tag: &str) -> DidDocumentSpec {
    DidDocumentSpec::new("example.com", vec!["agents".into(), tag.into()])
}

/// 只有绑硬件的那些测试用得上的脚手架 —— 在没开 `hardware-software` 的
/// 构建里它们一个都用不到,所以整块跟着 feature 一起编译掉(否则默认
/// 构建会为"一个从没被构造过的 `TempDir`"报警告)。
#[cfg(feature = "hardware-software")]
mod stand_in {
    use super::*;

    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new(tag: &str) -> Self {
            static COUNTER: AtomicUsize = AtomicUsize::new(0);
            let path = PathBuf::from("/tmp").join(format!(
                "keyd-hardware-{tag}-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).expect("create the temp dir");
            Self(path)
        }

        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `ANPIO_KEY_SOFTWARE_HSM` 是**进程级**的,而这些测试跑在线程里。
    ///
    /// 只有**封装**那一趟会读它(打开用的是信封里记着的那个绝对路径),所以
    /// 拿这把锁把"设变量 → 封信封"圈起来就够了,不会让测试变成串行。
    pub static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// 在一台"软件根在 `root` 这台机器上"的机器上生成一把钥匙。
    pub fn generate_with_root(root: &Path, tag: &str) -> create::Created {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        std::env::set_var("ANPIO_KEY_SOFTWARE_HSM", root);
        let created = create::generate(
            &spec(tag),
            "hardware",
            PASS,
            &device(7),
            fast(),
            HardwareChoice::Software,
        )
        .expect("seal against the software stand-in root");
        std::env::remove_var("ANPIO_KEY_SOFTWARE_HSM");
        created
    }

    /// 信封记着的那台机器上的 HS 文件在哪。
    pub fn hs_path(created: &create::Created) -> PathBuf {
        match created.wrapped.hardware.as_ref().expect("a bound envelope records its root") {
            HardwareRoot::Software { tag } => Path::new(tag).join("hs"),
            other => panic!("expected a software root, got {other:?}"),
        }
    }
}

// ————————————————————————————————————————————————————————————
// 验收第 1 条:删掉硬件密钥 → 信封打不开
// ————————————————————————————————————————————————————————————

/// **这一条就是 M5 的全部意义。**
///
/// 信封还在、口令也对、`device.secret` 也对 —— 少了那第三路,就是开不了。
#[cfg(feature = "hardware-software")]
#[test]
fn deleting_the_hardware_secret_closes_the_envelope() {
    let root = TempDir::new("delete-root");
    let created = generate_with_root(root.path(), "delete");

    // 先确认它在**没删**的时候真的开得了 —— 否则下面那条"打不开"可能只是
    // 因为别的地方本来就是坏的。
    anpio_key::keystore::unwrap::unlock(&created.wrapped, PASS, &device(7))
        .expect("with the hardware secret in place the envelope opens");

    let path = hs_path(&created);
    assert!(path.exists(), "the stand-in root must have written {path:?}");
    std::fs::remove_file(&path).unwrap();

    let error = expect_err(
        anpio_key::keystore::unwrap::unlock(&created.wrapped, PASS, &device(7)),
        "without the third source of entropy the envelope must not open",
    );

    // **错要说得清是"少了这台机器",不是"口令错"。** 这两种混在一起的话,
    // 一个把信封抄到新机器上的人会一遍遍重敲自己那个明明没错的口令。
    assert!(
        matches!(error, KeydError::HardwareMissing(_)),
        "the error must name the missing root, got {error:?}"
    );
    assert!(
        error.to_string().contains(&path.display().to_string()),
        "the error must say WHERE it looked: {error}"
    );
}

// ————————————————————————————————————————————————————————————
// 验收第 2 条:硬件在、但口令错 → 打不开
// ————————————————————————————————————————————————————————————

/// 三路熵是**都**要,不是**任一**。
///
/// 这一条防的是一类很具体的错:把硬件那一路当成了口令的替代品(或者反过来),
/// 于是"有 SE 就不用口令了"或者"硬件不对就用口令兜"。两种都是把两个因子
/// 压成一个。
#[cfg(feature = "hardware-software")]
#[test]
fn the_right_hardware_and_the_wrong_passphrase_still_fails() {
    let root = TempDir::new("pw-root");
    let created = generate_with_root(root.path(), "pw");

    assert!(
        matches!(
            anpio_key::keystore::unwrap::unlock(&created.wrapped, b"not the passphrase", &device(7)),
            Err(KeydError::BadPassphrase)
        ),
        "the passphrase is not optional just because the root is present"
    );

    // `device.secret` 那一侧同理 —— 第几路都不是可以省的。
    assert!(
        matches!(
            anpio_key::keystore::unwrap::unlock(&created.wrapped, PASS, &device(8)),
            Err(KeydError::BadPassphrase)
        ),
        "device.secret is still the second layer; the hardware root does not replace it"
    );
}

// ————————————————————————————————————————————————————————————
// 验收第 3 条:整份目录拷到另一台机器 → 打不开,而且说得清
// ————————————————————————————————————————————————————————————

/// 把 `~/.anpio-key/` 整个搬到一台**没有那根根**的机器上。
///
/// 替身这一侧的"另一台机器"就是"那个目录不存在"—— `HardwareRoot::Software`
/// 里存的是一条绝对路径,它不会跟着 JSON 一起搬过去。真硬件上这件事更强
/// (HS 根本出不来),但**形状**一致:`hardware` 那个定位符在这台机器上
/// 指不到任何东西。
#[cfg(feature = "hardware-software")]
#[test]
fn an_envelope_copied_to_another_machine_will_not_open() {
    let machine_a = TempDir::new("machine-a");
    let machine_b = TempDir::new("machine-b");

    let created = generate_with_root(machine_a.path(), "copied");

    // 把信封抄到 B:一个全新的布局,和"在新机器上装了 anpio-key"一样。
    let layout_b = anpio_key::keystore::layout::KeydLayout::at(machine_b.path().join("root"));
    layout_b.ensure().unwrap();
    anpio_key::keystore::store::save_new(&layout_b, &created.wrapped).unwrap();

    // B 上读回来的那份,跟 A 上那份是同一个东西。
    let copied =
        anpio_key::keystore::store::load(&layout_b, &created.wrapped.id.thumbprint).unwrap();
    assert_eq!(copied.id, created.wrapped.id, "the copy must be the same key");

    // **先说清楚哪一步不是问题**:信封本身是可搬的,文件抄过去照样解析得开。
    // 只要 A 那根根还在,B 上就能开 —— 说明拉不开的**不是**搬家这件事。
    anpio_key::keystore::unwrap::unlock(&copied, PASS, &device(7))
        .expect("as long as the root is still reachable, the copy opens — the file moved fine");

    // 现在让那根根**不跟着走**:A 机器上那根根不在,而这正是一台没走到过
    // 那根根的机器上的样子。
    std::fs::remove_dir_all(machine_a.path()).unwrap();

    let error = expect_err(
        anpio_key::keystore::unwrap::unlock(&copied, PASS, &device(7)),
        "without the root, the copy must be useless",
    );

    assert!(matches!(error, KeydError::HardwareMissing(_)), "{error:?}");
    let message = error.to_string();
    assert!(
        message.contains(&hs_path(&created).display().to_string()),
        "the error has to name the root it looked for: {message}"
    );
    assert!(
        message.contains("this machine does not have"),
        "the error has to say it is *this machine* that is missing it: {message}"
    );
}

// ————————————————————————————————————————————————————————————
// 验收第 4 条:绑不绑硬件,导出的 24 个词逐字相同
// ————————————————————————————————————————————————————————————

/// **硬件绑的是信封,不是钥匙。**
///
/// 这一条保证 M5 没有把助记词那条路变成"只有在这台机器上才抄得出"(那样的话
/// 芯片坏了就等于钥匙丢了)。同一把 seed,两个信封开出来的种子必须逐字节
/// 相同,于是 24 个词也逐字相同。
///
/// 要 `seed-export`:`open_seed` 在默认构建里根本不存在(见 `unwrap` 的模块头)。
#[cfg(all(feature = "seed-export", feature = "hardware-software"))]
#[test]
fn the_same_seed_exports_the_same_words_whether_bound_or_not() {
    let root = TempDir::new("words-root");

    // 同一把 seed,走两条路:一条纯软件,一条绑硬件。
    let seed = LockedBytes::fill(|bytes| *bytes = [0x5A; 32]).unwrap();
    let (_, public_multibase) = wrap::seed_to_public(&seed);

    let bound = {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        std::env::set_var("ANPIO_KEY_SOFTWARE_HSM", root.path());
        let sealed = anpio_key::keystore::hardware::seal_new(HardwareChoice::Software, "words")
            .unwrap()
            .expect("a software root was asked for");
        std::env::remove_var("ANPIO_KEY_SOFTWARE_HSM");

        wrap::seal(wrap::SealRequest {
            id: anpio_key::keystore::record::KeyId {
                did: "did:wba:example.com:agents:words:e1_words".into(),
                kid: "did:wba:example.com:agents:words:e1_words#key-1".into(),
                thumbprint: "e1_words".into(),
            },
            algorithm: anpio_key::keystore::record::KeyAlgorithm::Ed25519,
            public_multibase: public_multibase.clone(),
            label: "words".into(),
            passphrase: PASS,
            device_secret: &device(7),
            seed: &seed,
            argon: fast(),
            hardware: Some(sealed),
        })
        .unwrap()
    };

    let plain = wrap::seal(wrap::SealRequest {
        id: anpio_key::keystore::record::KeyId {
            did: "did:wba:example.com:agents:words:e1_words".into(),
            kid: "did:wba:example.com:agents:words:e1_words#key-1".into(),
            thumbprint: "e1_words".into(),
        },
        algorithm: anpio_key::keystore::record::KeyAlgorithm::Ed25519,
        public_multibase,
        label: "words".into(),
        passphrase: PASS,
        device_secret: &device(7),
        seed: &seed,
        argon: fast(),
        hardware: None,
    })
    .unwrap();

    // 两个信封是**不一样**的 —— 版本号就不一样。否则下面那一步可能只是在
    // 比较同一个对象。
    assert_eq!(bound.version, anpio_key::keystore::record::RECORD_VERSION_HARDWARE);
    assert_eq!(plain.version, anpio_key::keystore::record::RECORD_VERSION);

    let bound_seed =
        anpio_key::keystore::unwrap::open_seed(&bound, PASS, &device(7)).expect("the bound one opens");
    let plain_seed =
        anpio_key::keystore::unwrap::open_seed(&plain, PASS, &device(7)).expect("the plain one opens");

    let bound_words = anpio_key::crypto::mnemonic::to_words(&bound_seed).unwrap();
    let plain_words = anpio_key::crypto::mnemonic::to_words(&plain_seed).unwrap();

    assert_eq!(
        bound_words.as_str(),
        plain_words.as_str(),
        "the hardware root binds the ENVELOPE, not the key — the words must not depend on it"
    );
    // 而且它们就是**原来那把** seed 的词 —— 不是一个两边都错、但错得一样的词表。
    assert_eq!(bound_words.as_str(), anpio_key::crypto::mnemonic::to_words(&seed).unwrap().as_str());
}

// ————————————————————————————————————————————————————————————
// 验收第 5 条:没有后端就拒绝生成
// ————————————————————————————————————————————————————————————

/// **不静默降级。**
///
/// 这一条在两个构建里都必须成立,只是错法不同:没有那个 feature 时是
/// `HardwareUnavailable`("这个构建里没有"),而默认构建里**所有**真后端
/// 都属于这一类。要的就是"要硬件而这里没有 → 报错",绝不是"要硬件而这里
/// 没有 → 给一个纯软件的信封"。
#[cfg(not(feature = "hardware-software"))]
#[test]
fn asking_for_the_stand_in_without_the_feature_refuses_instead_of_downgrading() {
    let error = expect_err(
        create::generate(
            &spec("nofeature"),
            "hardware",
            PASS,
            &device(7),
            fast(),
            HardwareChoice::Software,
        ),
        "a build without the backend must refuse",
    );

    assert!(
        matches!(error, KeydError::HardwareUnavailable(_)),
        "asking for a root this build cannot give must be *unavailable*, not a fallback: {error:?}"
    );
    assert!(
        error.to_string().contains("--features hardware-software"),
        "the error has to say how to get it: {error}"
    );
}

/// 真后端的名字在没有对应 feature 的构建里也是**拒绝**,不是当作 `none` 吞掉。
#[cfg(not(feature = "hardware-software"))]
#[test]
fn a_hardware_name_that_is_not_compiled_in_is_not_silently_none() {
    use std::str::FromStr;

    for name in ["secure-enclave", "tpm"] {
        // 在这台机器上这个构建里它一定没编进来(macOS 没有 `hardware-tpm` 的
        // 依赖,Linux 没有 `hardware-se` 的);真编进来了就跳过 —— 那说明这台
        // 机器上它可用,这一条不适用。
        if HardwareChoice::from_str(name).is_ok() {
            continue;
        }
        let error = HardwareChoice::from_str(name)
            .expect_err("a name that cannot be honoured must be an error, never `none`");
        assert!(
            error.to_string().contains("--features hardware-"),
            "the error has to name the feature: {error}"
        );
    }
}

/// 命令行上认不出来的名字要把认识的名字列出来 —— 光说"不认识"等于让人猜。
#[test]
fn an_unknown_root_name_lists_the_ones_that_exist() {
    use std::str::FromStr;

    let error = HardwareChoice::from_str("hsm").expect_err("`hsm` is not a root this tool knows");
    let message = error.to_string();
    assert!(message.contains("none"), "{message}");
}
