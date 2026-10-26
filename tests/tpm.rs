//! TPM 后端的验收 —— 三条,一条守一个曾经真的破过的地方。
//!
//! # 为什么要单开一个文件,而不是并进 `negative.rs`
//!
//! 因为这份文件里的东西**在一台没有 TPM 的机器上跑不了**,而上面那份清单
//! 必须处处能跑。混在一起的代价是每一条都得带上"没 TPM 就跳过",于是那份
//! 清单读起来就分不清哪条在真的验、哪条只是在打照面。
//!
//! # 三条都带 `#[ignore]` —— 因为"没跑"必须是**看得见**的
//!
//! 一台没有 TPM 的机器上,这三条跑不了。而"跑不了就自己跳过"是一条**很有害**
//! 的写法:TPM 后端自己坏掉的时候,症状恰恰就是"没有 TPM"(`Context::new`
//! 连不上、TCTI 指错、owner 层级被设了口令)—— 于是一条本该红的测试会安静地
//! 变绿,而且永远绿下去。
//!
//! 所以这里不写"探测到没有 TPM 就 return"。`#[ignore]` 让它们在默认跑法里
//! 显示成 **`3 ignored`** —— 一个看得见的"没跑";而一个自己 `return` 的测试
//! 会显示成 `3 passed`,和"真的验过了"长得一模一样。这正是这份文件要防的
//! 那种假绿。
//!
//! 要跑就得明说:
//!
//! ```text
//! TPM2TOOLS_TCTI=swtpm:host=localhost,port=2321 \
//!   cargo test --features hardware-tpm --test tpm -- --ignored
//! ```
//!
//! 打开之后,里面任何一条失败都是失败 —— 包括"连不上 TPM"。
//!
//! # 三条测试在进程内互斥
//!
//! 芯片上能**同时**装载几个对象是个很紧的数(`swtpm` 那种实现尤其紧),
//! 而这里每一条都会在芯片上短暂地占着主键和密封对象。并行跑的时候三份叠
//! 在一起就越过上限,报出来的是 `out of memory for object contexts`,指向
//! "这颗 TPM 不能持久化" —— 一句和真正发生的事毫无关系的话。实测:并行跑
//! 三条挂两条,串行跑三条全过,而且芯片上什么都不剩。
//!
//! 这**不是**把测试调松:一台机器同一时刻在芯片上放几个对象,是这颗芯片的
//! 属性,不是这批测试的属性。所以这件事写在代码里([`chip`] 那把锁),而不是
//! 写在命令行上 —— 让 `cargo test` 的默认跑法能过。
//!
//! 第 3 条要用 `tpm2_evictcontrol`(包名 `tpm2-tools`)把一个对象从芯片上
//! **真的**删掉 —— 这是唯一能构造出"信封还在、根没了"的办法,而那是 M5 最
//! 该守住的那个场景。

#![cfg(all(target_os = "linux", feature = "hardware-tpm"))]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use anpio_key::crypto::kdf::Argon2Config;
use anpio_key::did::document::DidDocumentSpec;
use anpio_key::error::KeydError;
use anpio_key::keystore::hardware::{probe_real_roots, HardwareChoice};
use anpio_key::keystore::layout::KeydLayout;
use anpio_key::keystore::{create, device, store, unwrap};
use serde_json::Value;

const PASSPHRASE: &[u8] = b"tpm passphrase";

/// 持久句柄里属于 owner 层级的那一段(`TPM2_PERSISTENT_FIRST` 起,32 位
/// 地址空间里归 owner 的那一半)。和 `hardware/tpm.rs` 里那段是同一个区间;
/// 那边是私有常量,所以这里照抄一遍并把它当成**验收条件**来断言 ——
/// 落在别处的句柄在真芯片上要么建不出来,要么根本不属于我们。
const OWNER_RANGE: std::ops::RangeInclusive<u32> = 0x8100_0000..=0x817F_FFFF;

fn fast() -> Argon2Config {
    Argon2Config { m_cost: 1024, t_cost: 1, p_cost: 1 }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let path = PathBuf::from("/tmp").join(format!(
            "keyd-tpm-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("create the temp dir");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 一把钥匙,记录在 `record` 里,外加一份**还没落下**的信封。
struct Sealed {
    _dir: TempDir,
    layout: KeydLayout,
    did: String,
    thumbprint: String,
    /// 信封文件,以及它创建时那份**字节**。第 3 条要拿它比对"没被改过"。
    path: PathBuf,
    bytes: Vec<u8>,
    handle: u32,
}

impl Sealed {
    fn new(tag: &str) -> Self {
        let dir = TempDir::new(tag);
        let layout = KeydLayout::at(dir.path().to_path_buf());
        layout.ensure().unwrap();
        let spec = DidDocumentSpec::new("example.com", vec!["agents".into(), tag.into()]);
        let created =
            create::create(&layout, &spec, "tpm", PASSPHRASE, fast(), HardwareChoice::Tpm).expect("seal a key to the TPM");

        let thumbprint = created.wrapped.id.thumbprint.clone();
        let path = layout.key_path(&thumbprint).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let handle = handle_of(&bytes);

        Self { _dir: dir, layout, did: created.did, thumbprint, path, bytes, handle }
    }

    /// 从磁盘上读回那份信封 —— 走调用方真正走的那条路,而不是复用内存里
    /// 那个结构体。段错误那条崩溃路径只在这条路上出现过。
    fn wrapped(&self) -> anpio_key::keystore::record::WrappedKey {
        store::load(&self.layout, &self.thumbprint).expect("the envelope is on disk")
    }
}

/// 信封里那个持久句柄。
fn handle_of(bytes: &[u8]) -> u32 {
    let envelope: Value = serde_json::from_slice(bytes).expect("the envelope is JSON");
    envelope["hardware"]["handle"]
        .as_u64()
        .unwrap_or_else(|| panic!("a version-2 envelope carries a TPM handle: {envelope}")) as u32
}

/// 一个"这把钥匙在芯片上的对象已经没了"的收尾动作,**幂等**。
///
/// 用 `Drop` 而不是每个测试结尾写一行,因为真正需要它的时候往往是测试
/// **失败**的时候 —— 而一条测试失败的时候还往芯片上留一个持久对象,等于
/// 让下一次运行带着上一次的垃圾开始(持久句柄的槽位是芯片上很紧的一份资源)。
struct Evict(u32);

impl Drop for Evict {
    fn drop(&mut self) {
        // 失败就失败:一个不存在的对象本来就该删不动,那正是"已经清干净了"。
        let _ = Command::new("tpm2_evictcontrol")
            .arg("-C")
            .arg("o")
            .arg("-c")
            .arg(format!("{:#010x}", self.0))
            .status();
    }
}

/// 一次只让一条测试碰那颗芯片。理由见文件头那段"三条测试在进程内互斥"。
static THE_CHIP: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn chip() -> std::sync::MutexGuard<'static, ()> {
    // 中毒的锁照样用:一条测试 panic 之后,下一条要守的东西和"上一条炸了"
    // 毫无关系 —— 丢掉它的后果是那一条以一条完全无关的报错变红,
    // 而这正是这份文件最想避免的那种误导。
    THE_CHIP.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ————————————————————————————————————————————————————————————
// 1. 信封长得对,而且**打得开**
// ————————————————————————————————————————————————————————————

/// 绑到 TPM 上的信封:版本 2、指着一个 owner 层级的持久句柄、`hs_ciphertext`
/// 是空的,而且 —— 最要紧的 —— `unlock` **真的回得来**。
///
/// # 最后那一条不是陪衬
///
/// 曾经这里会**段错误**。`tpm2-tss 3.2.1` 的 `Esys_TR_FromTPMPublic_Finish`
/// 在"带了会话"的那条路上会解引用 `session_tab[0]`,而同一份代码给**密码
/// 会话**填的正是 `NULL`(见 `hardware/tpm.rs` 里 `attach` 的注释)。触发条件
/// 是"那个句柄上真的有一个对象" —— 于是 `probe` 那套自我测试碰不到它,
/// 只有**真信封**才炸。
///
/// 所以这条测试的价值全在"建一把真信封,再开一次"这个组合上:它是唯一
/// 从外面能看见那个崩溃的形状。
#[test]
#[ignore = "needs a TPM 2.0 (or swtpm) and a matching TPM2TOOLS_TCTI; run with `-- --ignored`"]
fn a_tpm_envelope_is_version_two_and_opens() {
    let _chip = chip();

    let sealed = Sealed::new("opens");
    let _cleanup = Evict(sealed.handle);

    let envelope: Value = serde_json::from_slice(&sealed.bytes).unwrap();
    assert_eq!(envelope["version"], 2, "binding to hardware is what version 2 means: {envelope}");
    assert_eq!(
        envelope["id"]["did"], sealed.did,
        "the envelope has to be the one that was just created, for that identity: {envelope}"
    );
    assert_eq!(
        envelope["hardware"]["kind"], "tpm",
        "the locator has to name which root: {envelope}"
    );
    // TPM 把秘密整个留在设备里,信封上不带任何东西 —— 和 SE 那一侧必须带
    // 临时公钥是两种设计。这个字段**必须在而且为空**:"在"是 v2 的硬要求,
    // "为空"是这一根根的性质。
    assert_eq!(
        envelope["hs_ciphertext"], "",
        "a TPM envelope carries no ciphertext; the secret never leaves the chip: {envelope}"
    );

    let handle = handle_of(&sealed.bytes);
    assert!(
        OWNER_RANGE.contains(&handle),
        "handle {handle:#010x} is outside the owner's persistent range — a handle there could \
         not have been created by this build, so the envelope is pointing at something else"
    );

    let device_secret = device::load(&sealed.layout).unwrap();

    // 口令错 -> 打不开。**而且这一步得先做**:它证明下面那次成功不是因为
    // 硬件那一趟把口令那一趟绕过去了。
    let wrong = match unwrap::unlock(&sealed.wrapped(), b"not the passphrase", &device_secret) {
        Ok(_) => panic!("the wrong passphrase must not open a TPM envelope"),
        Err(error) => error,
    };
    assert!(
        matches!(wrong, KeydError::BadPassphrase),
        "a wrong passphrase is a wrong passphrase, hardware root or not: {wrong}"
    );

    // **真的开一次。** 段错误就在这里发生。
    unwrap::unlock(&sealed.wrapped(), PASSPHRASE, &device_secret)
        .expect("a TPM envelope must open on the machine that sealed it");
}

// ————————————————————————————————————————————————————————————
// 2. 探针:报的是真话,而且**不留痕**
// ————————————————————————————————————————————————————————————

/// 体检报 TPM 可用,而且**连跑两次都可用**。
///
/// # "连跑两次"这一条是冲着一次真的对象表耗尽来的
///
/// `probe` 要建两把主键(一把在 Null 层级问"这玩意是不是 TPM"、一把用来封
/// 探针对象),再加上装载回来的那个密封对象 —— 而芯片上**同时**能装载几个
/// 对象是个很小的数。三格一起占着就越过上限,报出来的是 `out of memory for
/// object contexts`(0x902),而那句话指向的是"这颗 TPM 不能持久化",和真正
/// 发生的事毫无关系。修法是把用过的主键立刻还回去,把峰值压到两格。
///
/// 单跑一次未必看得见 —— 它取决于这一轮同时占了几格。所以这里跑两次。
#[test]
#[ignore = "needs a TPM 2.0 (or swtpm) and a matching TPM2TOOLS_TCTI; run with `-- --ignored`"]
fn the_probe_reports_the_tpm_usable_and_leaves_no_transient_objects_behind() {
    let _chip = chip();

    for round in 1..=2 {
        let probes = probe_real_roots();
        let tpm = probes
            .iter()
            .find(|probe| probe.kind == "Linux TPM 2.0")
            .unwrap_or_else(|| panic!("the TPM backend is compiled in, so it must be reported"));

        assert!(tpm.compiled, "round {round}: this is a `hardware-tpm` build: {}", tpm.detail);
        assert!(tpm.usable, "round {round}: the TPM must be usable: {}", tpm.detail);

        // 报告里必须说清"封进去又读了回来,然后删掉了"。少了后半句,一份
        // 留着自己对象的报告看起来和干净的一模一样。
        assert!(
            tpm.detail.contains("read back") && tpm.detail.contains("removed again"),
            "round {round}: the report has to say the probe object was read back AND removed: {}",
            tpm.detail
        );
    }
}

// ————————————————————————————————————————————————————————————
// 3. 根没了:拒绝,而且**不许有第二条路**
// ————————————————————————————————————————————————————————————

/// **把芯片上那个对象删掉,信封就必须开不了 —— 而不是换条路打开。**
///
/// M5 的全部价值压在这一条上:硬件根是第三路熵,少了它就是开不了。这里
/// 用一个**真的**删除(`tpm2_evictcontrol`)来构造,而不是改一改信封里的
/// 句柄 —— 后者会被 AAD 挡住(`hardware` 和 `hs_ciphertext` 都在认证头里),
/// 报出来的是 `AadMismatch`,那是另一条防线、另一个故事。
///
/// 两件事一起断言:错误是 `HardwareMissing`(不是"口令错"、不是"文件坏了"),
/// 以及**信封文件一个字节都没动**。后者是"没有静默降级"的可观测形式 ——
/// 一个会在失败时悄悄改写信封的实现,症状就是这里的字节变了。
#[test]
#[ignore = "needs a TPM 2.0 (or swtpm) and a matching TPM2TOOLS_TCTI; run with `-- --ignored`"]
fn an_envelope_whose_tpm_object_is_gone_is_refused_without_falling_back() {
    let _chip = chip();

    let sealed = Sealed::new("gone");
    let _cleanup = Evict(sealed.handle);

    // 先把"它本来是好的"钉住 —— 否则下面那条失败可能只是因为钥匙根本没建对。
    let device_secret = device::load(&sealed.layout).unwrap();
    unwrap::unlock(&sealed.wrapped(), PASSPHRASE, &device_secret)
        .expect("the envelope must open before the object is removed");

    // 从芯片上删掉它。
    let status = Command::new("tpm2_evictcontrol")
        .arg("-C")
        .arg("o")
        .arg("-c")
        .arg(format!("{:#010x}", sealed.handle))
        .status()
        .expect(
            "this test needs `tpm2_evictcontrol` (Debian: `tpm2-tools`) to remove the sealed \
             object; without it there is no way to construct \"the envelope is here, the root is \
             not\" and skipping would hide exactly what this test guards",
        );
    assert!(status.success(), "evicting {:#010x} failed: {status}", sealed.handle);

    let refusal = match unwrap::unlock(&sealed.wrapped(), PASSPHRASE, &device_secret) {
        Ok(_) => panic!(
            "the TPM object is gone, so this envelope must not open — anything that opens it now \
             is a silent downgrade"
        ),
        Err(error) => error,
    };

    assert!(
        matches!(refusal, KeydError::HardwareMissing(_)),
        "a missing root is its own failure; the user has to be able to tell it apart from a bad \
         passphrase: {refusal}"
    );
    let message = refusal.to_string();
    assert!(
        message.contains(&format!("{:#010x}", sealed.handle)) || message.contains(&format!("{:x}", sealed.handle)),
        "the refusal has to name the handle it looked for — that is the one fact a person needs \
         to go find their root: {message}"
    );

    // 信封本身没被动过。
    assert_eq!(
        std::fs::read(&sealed.path).unwrap(),
        sealed.bytes,
        "the envelope changed while it was being refused; opening a key is a read"
    );
}
