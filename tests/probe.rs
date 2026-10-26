//! `probe` 的验收:它**报告**得对,而且**什么都不漏**。
//!
//! 第二条比第一条要紧得多。`probe` 是计划 §九 M2 验收 #3 换了个做法之后的
//! 产物(理由见 `ops::probe` 的模块头),而它之所以敢留在**默认构建**里,
//! 全靠"一个字节的密钥材料都不打印"这一条成立。所以这里不测"它跑得起来",
//! 测的是"**它跑起来之后,屏幕上没有秘密**"。
//!
//! 测法是跑真的子进程收真的 stdout —— 不是调函数。因为要防的正是"某条
//! `println!` 顺手把它打出来了",而那件事只在**进程边界上**才看得见。

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use anpio_key::crypto::kdf::Argon2Config;
use anpio_key::did::document::DidDocumentSpec;
use anpio_key::keystore::layout::KeydLayout;
use anpio_key::keystore::hardware::HardwareChoice;
use anpio_key::keystore::{create, device};

const PASSPHRASE: &[u8] = b"probe passphrase";

fn fast() -> Argon2Config {
    Argon2Config { m_cost: 1024, t_cost: 1, p_cost: 1 }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let path = PathBuf::from("/tmp").join(format!(
            "keyd-probe-{tag}-{}-{}",
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

/// **一次只让一个 `probe` 跑。**
///
/// 平时看不出区别 —— 直到这个构建里编进了 `hardware-tpm`,而这台机器上又有
/// 一颗 TPM(或 `swtpm`)。那时 `probe` 的硬件那一节会**真的往芯片上写**
/// (建主键、封一个探针对象、再删掉),而芯片上**同时**能装载的对象是个很小
/// 的数。这里有好几条测试各自起一个 `probe` 子进程,并行起来就互相顶:
/// 实测过,`cargo test --features hardware-tpm` 连跑三次,中间那一次在芯片上
/// 留下了一个删不掉的持久对象(报告里照实说了,但那是**并发**造成的,
/// 不是那块芯片的毛病)。
///
/// 所以这把锁不是为了保护测试自己,是为了**让被测的东西不受测试的干扰** ——
/// 一份体检报告的结论不该取决于同时有几个人在体检。
static ONE_PROBE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn probe(root: &Path, did: Option<&str>) -> std::process::Output {
    let _one_at_a_time = ONE_PROBE_AT_A_TIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut command = Command::new(env!("CARGO_BIN_EXE_anpio-key"));
    command.arg("probe").arg("--root").arg(root);
    if let Some(did) = did {
        command.arg("--did").arg(did);
    }
    command.output().expect("run `anpio-key probe`")
}

/// 一台装好了一把钥匙的机器。
fn machine(tag: &str) -> (TempDir, KeydLayout, String) {
    let dir = TempDir::new(tag);
    let layout = KeydLayout::at(dir.path().join("root"));
    layout.ensure().unwrap();
    let spec = DidDocumentSpec::new("example.com", vec!["agents".into(), tag.into()]);
    let created = create::create(&layout, &spec, "probe", PASSPHRASE, fast(), HardwareChoice::None).unwrap();
    (dir, layout, created.did)
}

// ————————————————————————————————————————————————————————————
// 1. 装了钥匙的机器:每一节都报出来,而硬件那一节决定成不成
// ————————————————————————————————————————————————————————————

/// 装了钥匙的机器:内存、目录、信封三节都得报出真话来,而**结论**由硬件那一
/// 节决定。
///
/// # 这条原来是"退出码必须是 0"
///
/// M5 改了它。`probe` 回答的是"这台机器**能不能兑现**这个工具给出的承诺",
/// 而 M5 把那句承诺改了:在那之前,"拷走目录 + 知道口令 = 拿到私钥"是已知缺口;
/// 硬件根就是补它的那一层。一台没有可用硬件根的机器只能兑现**旧的**承诺 ——
/// 报成通过的话,"体检过了"这四个字会让人觉得缺口已经补上了。
///
/// # 但"这台机器没有硬件根"不是这条测试能假定的事
///
/// 一台装着真 TPM 2.0、或者起来了 `swtpm` 的机器上,`probe` 会报 USABLE,
/// 而且**应该**退出 0 —— 那是同一份报告在说真话。把"没有根"写进断言,等于让
/// 一份正确的报告变红(实测过:Linux + `--features hardware-tpm` + swtpm 上
/// 红的正是这一条)。
///
/// 所以要断言的是那条规矩本身:**结论跟着硬件那一节走** —— 没有可用的根就
/// 不许报通过,有的话就不许报失败。环境是环境,规矩是规矩。
#[test]
fn a_machine_with_a_key_reports_every_section_and_fails_on_the_hardware_root() {
    let (_dir, layout, did) = machine("clean");
    let output = probe(layout.root(), Some(&did));
    let stdout = String::from_utf8_lossy(&output.stdout);

    // 这段原文出现 = 硬件那一节没过;没出现 = 过了。
    let no_usable_root = stdout.contains("This machine has no usable hardware root");
    if no_usable_root {
        assert_ne!(
            output.status.code(),
            Some(0),
            "a machine with no usable hardware root must not report success: {stdout}"
        );
    } else {
        assert_eq!(
            output.status.code(),
            Some(0),
            "the report says a hardware root is usable, so the probe must not fail: {stdout}"
        );
    }

    // 内存那一节照常报,而且这篇报告里没有假话。
    assert!(stdout.contains("locked memory"), "{stdout}");

    // `--did` 那一段要真的说出信封是谁的。
    assert!(stdout.contains(&did), "the envelope report must name the DID: {stdout}");

    // 硬件那一节必须**指名道姓地说出该装什么、该改什么** —— "不通过"而
    // 不说怎么做,等于把人丢在原地。
    assert!(stdout.contains("hardware root (M5)"), "{stdout}");
    if no_usable_root {
        assert!(
            stdout.contains("This machine has no usable hardware root"),
            "the report must say, in words, what the conclusion is: {stdout}"
        );
    }
    assert!(
        stdout.contains("--features hardware-se") || stdout.contains("--features hardware-tpm"),
        "the report must name the feature to build with: {stdout}"
    );
    assert!(
        stdout.contains("signed with an Apple-issued certificate"),
        "on macOS the SE side has a distribution prerequisite, and the report must say it: \
         {stdout}"
    );
}

// ————————————————————————————————————————————————————————————
// 2. 什么都不漏
// ————————————————————————————————————————————————————————————

/// **屏幕上不能出现那半个秘密。**
///
/// `device.secret` 就在磁盘上,所以这条断言是**真的**在比对一个秘密的字节
/// —— 不是"看起来像秘密的东西"。十六进制和 base64 两种写法都查,因为漏的
/// 时候通常是某处顺手 `hex::encode` 了一下。
#[test]
fn the_probe_never_echoes_the_device_secret() {
    let (_dir, layout, did) = machine("nosecrets");
    let output = probe(layout.root(), Some(&did));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let screen = format!("{stdout}{stderr}");

    let secret = device::load(&layout).unwrap();
    let (hex, lower_hex) = secret.expose(|bytes| {
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        (hex.to_uppercase(), hex)
    });

    assert!(
        !screen.contains(&lower_hex) && !screen.contains(&hex),
        "the device secret reached the screen — that is half of every envelope's \
         entropy; stdout={stdout:?}"
    );

    // 顺带:信封里那两段密文也不许原样打出来。
    //
    // 按 JSON 取值而不是按字符串切,因为信封的排版(紧凑/缩进)不是我们要
    // 断言的东西 —— 断言的是那张屏幕上没有这些字节,与它长什么样无关。
    let envelope: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(layout.key_path(&thumbprint(&layout)).unwrap()).unwrap())
            .expect("the envelope is JSON");
    for field in ["sk_ciphertext", "dek_ciphertext"] {
        let ciphertext = envelope[field]
            .as_str()
            .unwrap_or_else(|| panic!("the envelope carries `{field}`: {envelope}"));
        assert!(ciphertext.len() >= 32, "`{field}` should be a real ciphertext");
        assert!(
            !screen.contains(ciphertext),
            "the envelope's `{field}` reached the screen: {screen:?}"
        );
    }
}

/// 目录里那把信封的 thumbprint(也就一个文件)。
fn thumbprint(layout: &KeydLayout) -> String {
    let paths = layout.list_key_paths().unwrap();
    assert_eq!(paths.len(), 1, "expected exactly one envelope");
    paths[0]
        .file_stem()
        .and_then(|stem| stem.to_str())
        .expect("the envelope is named after its thumbprint")
        .to_string()
}

// ————————————————————————————————————————————————————————————
// 3. 坏掉的机器:报告失败,而且非零退出
// ————————————————————————————————————————————————————————————

/// **丢了 `device.secret` = 体检不通过,而且退出码非零。**
///
/// 非零这件事不是形式:这份报告最该被用起来的地方是装机脚本、CI、容器启动
/// 前的自检 —— 在那里,退出码就是唯一被读的东西。
#[test]
fn a_machine_that_lost_its_device_secret_fails_the_probe() {
    let (dir, layout, did) = machine("missing");
    std::fs::remove_file(dir.path().join("root").join("device.secret")).unwrap();

    let output = probe(layout.root(), Some(&did));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_ne!(
        output.status.code(),
        Some(0),
        "a machine whose envelopes can never open must not report success: {stdout}"
    );
    assert!(
        stdout.contains("device.secret") && stdout.contains("MISSING"),
        "the report has to name what is missing: {stdout}"
    );
}

/// 还没生成过钥匙的机器:根目录都不在,报告要照实说,而且**不创建**它。
///
/// 一次体检不该改变被体检的东西 —— 这一条和 M5 无关,是 `probe` 一开始就
/// 定下的。所以就算整篇报告的结论因为"没有硬件根"而不通过,这一段的行为
/// 也不能跟着变。
#[test]
fn a_fresh_machine_reports_an_absent_root_without_creating_it() {
    let dir = TempDir::new("fresh");
    let output = probe(&dir.path().join("never-created"), None);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("absent"), "{stdout}");
    // 体检**不创建**它。
    assert!(
        !dir.path().join("never-created").exists(),
        "the probe must not create the root directory"
    );
}

// ————————————————————————————————————————————————————————————
// 4. core dump 那一层:报告的是真话,而且真的会拦
// ————————————————————————————————————————————————————————————

/// 体检报告里必须交代 core dump 这一层。
///
/// 它容易被漏掉,因为"memlock 成功了"看起来已经把内存保护说完了 —— 而
/// `MADV_DONTDUMP` 不在,种子就可能跟着一次崩溃落到磁盘上,恰恰是 M4 #3
/// 要防的那件事。
#[test]
fn the_report_accounts_for_core_dumps() {
    let dir = TempDir::new("coredump-line");
    let output = probe(&dir.path().join("never-created"), None);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("core dumps"),
        "the memory section has to account for core dumps, not just mlock: {stdout}"
    );
}

/// `MADV_DONTDUMP` 只在 Linux 上有。别的系统上照抄"DONTDUMP accepted"是句
/// 假话,而一份体检报告里最不该有的就是假话。
#[test]
fn the_report_does_not_claim_dontdump_where_it_does_not_exist() {
    let dir = TempDir::new("dontdump");
    let output = probe(&dir.path().join("never-created"), None);
    let stdout = String::from_utf8_lossy(&output.stdout);

    if cfg!(target_os = "linux") {
        assert!(stdout.contains("DONTDUMP"), "on Linux the region really is excluded: {stdout}");
    } else {
        assert!(
            stdout.contains("Linux-only"),
            "outside Linux the report must say DONTDUMP is not available: {stdout}"
        );
    }
}

/// **把 core dump 打开,体检必须不通过。**
///
/// 这一条挡的是"报告写得像回事、实际什么也没查"。限制只在 Linux 之外才
/// 致命 —— 那边没有 `MADV_DONTDUMP` 可以把锁定区摘出去,rlimit 是唯一挡在
/// 中间的东西 —— 所以这一条只在 Linux 之外有意义。
///
/// 硬上限不允许抬高的环境里,这个场景**根本构造不出来**,直接跳过:一条因为
/// 环境而红的测试只是噪音。
#[cfg(all(unix, not(target_os = "linux")))]
#[test]
fn core_dumps_enabled_make_the_probe_fail() {
    use std::os::unix::process::CommandExt;

    let dir = TempDir::new("coredump-on");
    let mut command = Command::new(env!("CARGO_BIN_EXE_anpio-key"));
    command.arg("probe").arg("--root").arg(dir.path().join("never-created"));
    unsafe {
        command.pre_exec(|| {
            let limit = nix::libc::rlimit {
                rlim_cur: nix::libc::RLIM_INFINITY,
                rlim_max: nix::libc::RLIM_INFINITY,
            };
            if nix::libc::setrlimit(nix::libc::RLIMIT_CORE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let Ok(output) = command.output() else {
        // 抬不动 RLIMIT_CORE —— 这台机器上构造不出这个场景。
        return;
    };
    let stdout = String::from_utf8_lossy(&output.stdout);

    // 先说它**确实跑到了那一行**。少了这一句,"非零退出"也可能是因为别的
    // 原因失败,而那和这条测试想守的东西毫无关系。
    assert!(
        stdout.contains("core dumps ............... ALLOWED"),
        "the child should have seen a raised limit and said so: {stdout}"
    );
    assert_ne!(
        output.status.code(),
        Some(0),
        "with core dumps enabled and no MADV_DONTDUMP to exclude the region, a \
         crash would write the seed to disk — the probe must not call that ok: {stdout}"
    );
}

