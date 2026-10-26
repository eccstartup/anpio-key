//! `probe` —— 这台机器**能不能兑现**这个工具给出的承诺。
//!
//! # 计划里它是"dump 锁定区",这里它是"报告能不能锁"
//!
//! 计划 §九 M2 验收 #3 写的是:解锁后 dump 锁定区应该看到密钥,`lock` 之后
//! 应该全是 `0x00`。那个验收**换了个做法**,理由有两条,一条技术一条安全:
//!
//! **技术上的那一条是硬伤:跨进程做不到。** `probe` 是另一个进程,而锁定区
//! 被 `mlock` 锁页、前后加了 guard page(Linux 上还请求了 `MADV_DONTDUMP`)
//! —— 它读不到守护进程的内存,那不是"没实现",那正是这套保护在起作用。做成
//! 进程内自测倒是能读,但那就引出第二条。
//!
//! **安全上的那一条:进程内自测会把私钥打到 stdout**,而这个二进制
//! **agent 也能跑**(同一个 uid)。一条能把私钥打出来的命令,和 `export-seed`
//! 是同一类东西 —— 而导出在默认构建里是**根本不存在的**。让 `probe` 成为
//! 那条口子的默认版本,等于把 `seed-export` 那道门拆了。
//!
//! 所以这里**一个字节的密钥材料都不打印**。它报告的是**前提**:
//!
//! - 这台机器的内存保护**能不能建起来**(`Policy::Strict`:拿不到就失败,
//!   不静默降级)。这一条最值得在真机上跑一次 —— 容器里 `ulimit -l` 太小、
//!   systemd 的 `LimitMEMLOCK` 没调,症状是**启动就失败**,而这里能当场
//!   说清是哪一条不满足。
//! - 锁定区建起来之后**读得回来**(不是"分配成功",是"能按字节读回原值")。
//! - **一次崩溃会不会把种子写到磁盘上。** `memlock` 成功容易被当成"内存这
//!   一块说完了",但 core dump 是另一条路:`MADV_DONTDUMP` 只管 Linux,别的
//!   平台上只剩 `RLIMIT_CORE` 挡着 —— 所以这里分开报,而在没有
//!   `MADV_DONTDUMP` 又不限制 core dump 的机器上**体检不通过**。
//! - `device.secret` 在不在、模式对不对、长度是不是 32。
//! - 给了 `--did` 的话,那把**信封**是不是完好的、绑的是不是这个身份 ——
//!   这些全是公开信息(thumbprint 本来就挂在域名上),不需要口令。
//! - **这台机器有没有一根能用的硬件根**(M5)。这一节是**会失败的**,理由见
//!   下面。
//!
//! # 为什么"没有硬件根"是一次体检不通过
//!
//! 这个模块的头一句话定义了这个命令:`probe` 回答的是"这台机器**能不能兑现**
//! 这个工具给出的承诺"。M5 把那句承诺改了:在今天之前,"磁盘拷走 + 知道口令"
//! 就能拿到私钥是**已知的缺口**,而硬件根就是补它的那一层。补完之后,
//! "磁盘上的东西不够"才成立。
//!
//! 所以一台没有可用硬件根的机器,能兑现的是**旧的**承诺 —— 它不该被报成
//! 通过,否则"体检过了"这四个字会让人觉得缺口已经补上了。这一节失败时说的
//! 是**该装什么、该改什么**(编哪个 feature、签什么证书),不是一句"不对"。
//!
//! 这和"不绑硬件的部署完全合法"并不矛盾:`keygen` 不带 `--hardware` 照样
//! 生成 v1 信封,照样能用。**这一节说的是"这台机器还不够好",不是"你不能
//! 这么用"** —— 体检报告本来就说的是前者。
//!
//! "`lock` 之后密钥从内存里消失"这条**行为**上不变量,测在
//! `tests/negative.rs`(第 8 条)里;而"区域归零"是 `shrouded` 和 `Zeroize`
//! 的 Drop 保证 —— 验它等于验那两个库,不值得我们用一段自己写的不安全代码
//! 去读一块已经 free 的内存来假装验过。
//!
//! # M4 验收 #3 的另一半,以及为什么它留着手工做
//!
//! 那条写的是"`strings /proc/<pid>/mem` 翻不到私钥字节"。**读另一个进程的
//! 内存**这件事不在任何一段自动化测试里:macOS 上要 root,Linux 上要 ptrace
//! 许可(`yama/ptrace_scope`)。写一条只有某个平台、某种权限下才跑得起来的
//! 测试,等于留一段**没人跑过的代码**在仓库里 —— 而它的存在还会让"这一条
//! 被覆盖了"显得成立。所以这里守的是它的**前提**(能力、限制、失败即拒绝),
//! 真正那一步留给人拿上面这条命令在真机上做一次。

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::crypto::hygiene::LockedBytes;
use crate::error::{KeydError, Result};
use crate::keystore::layout::{KeydLayout, SECRET_FILE_MODE, DIR_MODE};
use crate::keystore::store;

/// 跑一次体检,把结果打到 stdout。
///
/// 走 stdout 而不是 tty:它不打印任何秘密,所以没有"提问必须落在人看着的
/// 那个屏幕上"这条约束;而它会经常出现在"把输出贴到 issue 里"的场合。
pub fn probe(root: Option<&Path>, did: Option<&str>) -> Result<()> {
    let layout = match root {
        Some(root) => KeydLayout::at(root.to_path_buf()),
        None => KeydLayout::user_default()?,
    };

    crate::security::paths::deny_managed_directory(layout.root())?;
    println!("anpio-key memory & layout probe");
    println!("root: {}", layout.root().display());
    println!("(this command never prints key material)");
    println!();

    let memory_ok = memory_hygiene();
    let layout_ok = layout_hygiene(&layout)?;
    let hardware_ok = hardware_hygiene();

    let envelope_ok = match did {
        Some(did) => envelope_report(&layout, did)?,
        None => true,
    };

    println!();
    if memory_ok && layout_ok && envelope_ok && hardware_ok {
        println!("memory: ok — this machine can keep the promises the daemon makes");
        Ok(())
    } else {
        // **非零退出。** 一份"体检报告"如果失败还退 0,脚本里就用不起来,
        // 而那正是它最该被用起来的地方(装机脚本、CI、容器启动前的自检)。
        Err(KeydError::Protocol(
            "one or more checks failed; see the report above".into(),
        ))
    }
}

/// 这台机器的硬件根:有没有、是哪种、现在能不能用。
///
/// 三件事分开说,因为它们能各自独立地坏:
/// - **这个构建里有没有那个后端**(发行决策:少编了一个 feature);
/// - **这台机器有没有那根根**(硬件在不在、设备节点在不在);
/// - **那根根现在真的能用吗**(SE 私钥能不能持久化 —— 那要签名身份)。
///
/// 最后一条是最容易被漏掉的一条:`security-framework` 编得进去、SE 芯片也
/// 真的在,但一个**没有 Apple 签发证书**的二进制造不出持久的 SE 私钥,
/// 于是"绑了硬件"这件事根本兑现不了。只报前两条的话,那台机器会被报成通过。
fn hardware_hygiene() -> bool {
    use crate::keystore::hardware::{probe_real_roots, uncompiled_roots};

    println!();
    println!("hardware root (M5)");

    let roots = probe_real_roots();
    if roots.is_empty() {
        println!("  compiled ................. none (this build has no real hardware backend)");
    } else {
        println!(
            "  compiled ................. {}",
            roots.iter().map(|r| r.kind).collect::<Vec<_>>().join(", ")
        );
    }

    for root in &roots {
        if root.compiled && root.usable {
            println!("  {} ... USABLE", root.kind);
            println!("      {}", root.detail);
        } else {
            println!("  {} ... NOT USABLE", root.kind);
            println!("      {}", root.detail);
            if let Some(remedy) = &root.remedy {
                for line in remedy.lines() {
                    println!("      {line}");
                }
            }
        }
    }

    // **没编进来的那几根也要印出来**,否则"compiled: none"看起来像"检查过了,
    // 没事",而事实是"根本没检查"。
    let missing = uncompiled_roots();
    if !missing.is_empty() {
        println!("  not compiled in this build:");
        for (kind, remedy) in &missing {
            println!("    {kind} — {remedy}");
        }
    }

    let usable = roots.iter().any(|root| root.compiled && root.usable);
    if !usable {
        println!();
        println!(
            "      This machine has no usable hardware root, so an envelope bound to one\n\
             \x20     cannot be opened here — and an envelope that is NOT bound to one can\n\
             \x20     still be opened by anyone who copies the disk and knows the passphrase.\n\
             \x20     That is the gap M5 exists to close. Until this line reads USABLE, the\n\
             \x20     tool cannot keep that promise on this machine."
        );
    }
    usable
}

/// 内存保护能不能建起来、读不读得回来。
///
/// 返回这一节是否通过。
fn memory_hygiene() -> bool {
    println!("memory hygiene");

    // ① 能不能建起一个锁定区。
    //
    // `LockedBytes::generate` 走的是 `Policy::Strict`,`mlock` 拿不到就返回
    // Err —— **不降级**。所以这一步成功,等于锁页和 guard page 在这台机器上
    // 都被接受了(`MADV_DONTDUMP` 只有 Linux 上才有,它那一层单独报,见
    // `core_dump_hygiene`)。
    let locked = match LockedBytes::generate() {
        Ok(locked) => {
            // **这句话要按平台说。** `MADV_DONTDUMP` 是 Linux 才有的,`shrouded`
            // 里那一段就是 `#[cfg(target_os = "linux")]` —— 在 macOS 上照抄
            // "DONTDUMP accepted" 是一句假话,而体检报告里最不该有的就是假话。
            // 别的平台上那一层由下面 `core_dump_hygiene` 单独交代。
            if cfg!(target_os = "linux") {
                println!("  locked memory ............ ok (mlock + guard page + DONTDUMP accepted)");
            } else {
                println!("  locked memory ............ ok (mlock + guard page accepted)");
                println!("      (MADV_DONTDUMP is Linux-only; see the core-dump line below)");
            }
            locked
        }
        Err(error) => {
            println!("  locked memory ............ FAILED");
            println!("      {error}");
            println!(
                "      This machine cannot hold keys safely. On Linux check `ulimit -l`\n\
                 \x20     (MB, so 64 is 64 MiB) and systemd's `LimitMEMLOCK=`; in a\n\
                 \x20     container check that the runtime did not cap it."
            );
            // 后面那一节没有意义了,但**仍然把报告打完** —— 一次体检应该
            // 把知道的全说出来,而不是在第一个问题上停住。
            return false;
        }
    };

    // ② 建起来了之后,读得回来吗。
    //
    // 写一个已知模式、读回来比 —— 而且**不打印那个模式**,也不打印读回来的
    // 东西:这是一块真实存放密钥的内存,今天放的是模式,明天放的是 seed。
    // 这个函数里没有任何一条路径会输出它的内容。
    let written = LockedBytes::fill(|bytes| {
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(7).wrapping_add(11);
        }
    });
    let round_trips = match written {
        Ok(buffer) => buffer.expose(|bytes| {
            (0..32).all(|index| bytes[index] == (index as u8).wrapping_mul(7).wrapping_add(11))
        }),
        Err(_) => false,
    };
    if round_trips {
        println!("  read-back ................ ok (32 bytes written and read back intact)");
    } else {
        println!("  read-back ................ FAILED (a locked buffer did not round-trip)");
    }

    // ③ 撤掉一个锁定区不会失败 —— 失败的那种(比如 `munlock` 报错)在这里
    // 会变成 panic 或错误,而不会静默留下一个可换出的页面。
    drop(locked);
    println!("  release .................. ok (no error while tearing down)");

    let core_dumps_safe = core_dump_hygiene();

    round_trips && core_dumps_safe
}

/// 计划 §九 M4 验收 #3 里"进程内存里翻不到私钥"这一条,在这台机器上靠什么成立。
///
/// 两件事**互相独立**,而且特别容易被当成同一件:
///
/// - `MADV_DONTDUMP` 把**这一块区域**排除出 core dump —— 但它**只在 Linux
///   上有**(`shrouded` 里那一段是 `#[cfg(target_os = "linux")]`,在 macOS 上
///   整个编译掉)。
/// - `RLIMIT_CORE = 0` 让**整个进程**根本产生不了 core dump。
///
/// 所以这里分开报。rlimit 是 0:dump 根本不会发生,后面那句就不用再说了。
/// 不是 0:Linux 上锁定区自己仍然被排除,别的系统上**没有这一层** —— 那时
/// 一次崩溃就会把 seed 连同内存一起写到磁盘上,而这正是那条验收要防的事,
/// 所以那种情况下**体检不通过**,并且说清该改什么。
fn core_dump_hygiene() -> bool {
    let mut limit = nix::libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    if unsafe { nix::libc::getrlimit(nix::libc::RLIMIT_CORE, &mut limit) } != 0 {
        // 问不出来就照实说问不出来,不猜。这不是"通过了",也不是"没通过"。
        println!("  core dumps ............... UNKNOWN (could not read RLIMIT_CORE)");
        return true;
    }

    if limit.rlim_cur == 0 {
        println!("  core dumps ............... disabled (RLIMIT_CORE is 0)");
        return true;
    }

    if cfg!(target_os = "linux") {
        println!(
            "  core dumps ............... allowed ({}) but this region is excluded (MADV_DONTDUMP)",
            describe_limit(limit.rlim_cur)
        );
        return true;
    }

    println!(
        "  core dumps ............... ALLOWED ({}) AND THIS PLATFORM HAS NO MADV_DONTDUMP",
        describe_limit(limit.rlim_cur)
    );
    println!(
        "      A crash would write the seed to a core file. This platform cannot\n\
         \x20     exclude the locked region the way Linux does, so the limit is the\n\
         \x20     only thing standing there. Set it to 0 for whatever starts the\n\
         \x20     daemon (`ulimit -c 0`, launchd's `SoftResourceLimits`, systemd's\n\
         \x20     `LimitCORE=0`)."
    );
    false
}

fn describe_limit(value: u64) -> String {
    if value == nix::libc::RLIM_INFINITY {
        "unlimited".to_string()
    } else {
        format!("{value} bytes")
    }
}

/// 目录和 `device.secret` 的卫生。
fn layout_hygiene(layout: &KeydLayout) -> Result<bool> {
    println!();
    println!("on-disk layout");

    let mut ok = true;

    // 根目录还没有 —— 一台刚装好、还没生成过钥匙的机器就是这样。这不是
    // 失败,所以**不要**在这里 `ensure()` 把它建出来:一次体检不该改变被
    // 体检的东西。
    if !layout.root().exists() {
        println!("  root directory ........... absent (no keys on this machine yet)");
        return Ok(true);
    }

    let root_mode = mode_of(layout.root())?;
    let root_private = root_mode == DIR_MODE;
    ok &= report(
        "root directory mode",
        format!("{root_mode:04o}"),
        root_private,
        format!("expected {DIR_MODE:04o} (only you can enter it)"),
    );

    // `device.secret` —— 缺失和"刚生成"是两件事(见 `device` 模块),
    // 所以这里分三态报,而不是一句"没有"。
    let secret_path = layout.device_secret_path();
    if !secret_path.exists() {
        ok = false;
        println!("  device.secret ............ MISSING");
        println!(
            "      Without it every envelope on this machine is unopenable, and a\n\
             \x20     freshly generated one will not open the old ones."
        );
    } else {
        let secret_mode = mode_of(&secret_path)?;
        ok &= report(
            "device.secret mode",
            format!("{secret_mode:04o}"),
            secret_mode == SECRET_FILE_MODE,
            format!("expected {SECRET_FILE_MODE:04o}"),
        );
        match crate::keystore::device::load(layout) {
            Ok(secret) => {
                let length = secret.expose(|bytes| bytes.len());
                ok &= report(
                    "device.secret length",
                    format!("{length} bytes"),
                    // 故意不打印那几个字节。
                    length == 32,
                    "expected 32 bytes".into(),
                );
            }
            Err(error) => {
                ok = false;
                println!("  device.secret ............ UNREADABLE");
                println!("      {error}");
            }
        }
    }

    let keys = layout.list_key_paths()?;
    println!("  envelopes ................ {} (listed by count only)", keys.len());

    Ok(ok)
}

/// 一把信封是完好的、而且绑的是它自称的那个身份吗。
///
/// 全程不碰口令、不碰 seed —— 说的全是本来就挂在域名上的公开信息。
fn envelope_report(layout: &KeydLayout, did: &str) -> Result<bool> {
    println!();
    println!("envelope for {did}");

    // `resolve` 不看口令,只按 DID 找到信封并核对它自称的身份。
    let wrapped = match store::resolve(layout, did, None) {
        Ok(wrapped) => wrapped,
        Err(error) => {
            println!("  resolve .................. FAILED");
            println!("      {error}");
            return Ok(false);
        }
    };

    println!("  kid ...................... {}", wrapped.id.kid);
    println!("  thumbprint ............... {}", wrapped.id.thumbprint);
    println!("  bound did ................ {}", wrapped.id.did);

    // 从磁盘上重新读一遍,确认能解析回来 —— 信封是磁盘上唯一存着的东西,
    // "内存里那个对象是对的"说明不了文件是不是好的。
    let reloaded = store::load(layout, &wrapped.id.thumbprint)?;
    let intact = reloaded.id == wrapped.id;
    println!(
        "  reload from disk ......... {}",
        if intact { "ok" } else { "FAILED (the file does not round-trip)" }
    );

    Ok(intact)
}

fn mode_of(path: &Path) -> Result<u32> {
    Ok(std::fs::metadata(path)
        .map_err(KeydError::Io)?
        .permissions()
        .mode()
        & 0o777)
}

/// 打一行 `名字 ... 值`,返回这一条是否通过。不过的话把期望值补在后面 ——
/// 一份只说"不对"的体检报告等于没说。
fn report(name: &str, got: String, ok: bool, expected: String) -> bool {
    if ok {
        println!("  {name} {got}");
    } else {
        println!("  {name} {got}  <-- {expected}");
    }
    ok
}
