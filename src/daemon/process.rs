//! 认一个 **pid 是不是我们自己** —— `stop` 需要的那一层。
//!
//! pid 会被内核回收。一个守护进程死了、pid 被分配给别的进程之后,光看
//! `run/keyd.pid` 里那个数字,`stop` 就会去打一个无辜的进程。所以文件里
//! 存的数字本身**不足以**授权一次 `kill` —— 必须再问一句"现在占用这个
//! pid 的,是不是这个二进制"。
//!
//! 比的是 `(dev, ino)` 而不是路径字符串。路径会因为符号链接、`~/bin/`
//! 那种转发、以及"二进制被重新编译过"而字面不同,但 inode 不会。
//!
//! 注意这一层**不是**给 socket 那边用的:那边认的是内核在 `connect(2)`
//! 时冻结的身份([`crate::daemon::peer`])。这里认的是"磁盘上那个文件的
//! 身份",弱一档,但用来避免误杀足够了。

use std::path::PathBuf;

#[cfg(any(target_os = "macos", target_os = "ios"))]
use std::ffi::OsString;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use std::os::unix::ffi::OsStringExt;

/// 一个活着的进程正在跑的可执行文件是哪个。进程不在、或者问不到,就是
/// `None`(Linux 上 `/proc` 没挂、macOS 上进程刚死都会走到这里)。
///
/// **`None` 不等于"安全"。** 调用方拿到 `None` 必须当成"验不了"处理,
/// 而不是"那就是它"。
pub fn executable_of(pid: i32) -> Option<PathBuf> {
    if pid <= 0 {
        return None;
    }
    platform_executable_of(pid)
}

/// `pid` 现在跑的是不是 `ours` 这个文件 —— 按 `(dev, ino)` 比。
///
/// `ours` 是我们自己:`current_exe()` 在 macOS 上给的是**被调用时那个
/// 路径**(可能还带着符号链接),所以不能比字符串。
pub fn is_same_executable(ours: &std::path::Path, pid: i32) -> bool {
    use std::os::unix::fs::MetadataExt;

    let Some(theirs) = executable_of(pid).and_then(|path| std::fs::metadata(path).ok()) else {
        return false;
    };
    let Ok(ours) = std::fs::metadata(ours) else {
        return false;
    };
    theirs.dev() == ours.dev() && theirs.ino() == ours.ino()
}

/// `pid` 是不是一个**还在跑**的进程。
///
/// 用的是 `kill(pid, 0)`:它只做权限和存在性检查,**不发任何信号**。
/// `EPERM` 也算活着 —— 那个进程在,只是不是我们的。
///
/// **但"存在"不等于"还在跑":僵尸也算存在。** 一个已经退出、父进程还没
/// `wait` 掉的进程,`kill(pid, 0)` 照样成功 —— 它已经死了,只是还占着一个
/// pid 槽位等着收尸。这里回答的是"它还在跑吗",所以僵尸算**不在**。
///
/// 这个区别在 Linux 上是看得见的,而且不是只在测试里:守护进程是 `serve`
/// **重新执行自己**放出去的,退出之后归 PID 1 收尸。systemd 和 launchd 都会
/// 收,但容器里那个 PID 1(`sleep`、`bash`、`sh` 这类)不会 —— 而容器恰恰是
/// 跑一个守护进程的常见地方。症状是 `stop` 发完 SIGTERM 老老实实等满 5 秒,
/// 然后报"pid N still there",而它其实早就没了。
pub fn is_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    if unsafe { nix::libc::kill(pid, 0) } != 0 {
        return std::io::Error::last_os_error().raw_os_error() == Some(nix::libc::EPERM);
    }
    !is_a_zombie(pid)
}

/// 这个 pid 是不是一具还没被收走的尸体。
///
/// Linux 上读 `/proc/<pid>/stat` 的第三个字段。**不能按空白切**:那个文件的
/// 第二个字段是 `(comm)`,而 comm 里可以有空格和括号 —— 得从**最后一个**
/// `)` 之后再切,才有保证。
///
/// macOS 上没做这一步:那边的 PID 1 是 launchd,重挂上来的孤儿它都会收,
/// 所以这个情形在那儿不出现。
#[cfg(target_os = "linux")]
fn is_a_zombie(pid: i32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        // 读不到 = 它的 `/proc` 项正在消失,也就是它正在被收走。上面那句
        // `kill` 刚说过它还在,这里保守地信那一句。
        return false;
    };
    stat.rfind(')')
        .and_then(|end| stat[end + 1..].split_whitespace().next())
        .is_some_and(|state| state == "Z")
}

#[cfg(not(target_os = "linux"))]
fn is_a_zombie(_pid: i32) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn platform_executable_of(pid: i32) -> Option<PathBuf> {
    // `/proc/<pid>/exe` 是个符号链接,指向**真正的** inode,即使文件被
    // 替换或删掉也还指得着。
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn platform_executable_of(pid: i32) -> Option<PathBuf> {
    // `proc_pidpath` 走 libproc:不需要调试权限,也不需要调用方是同一个
    // uid 就能问到路径。要不到(进程不在了)返回 0。
    let mut buffer = vec![0u8; nix::libc::PATH_MAX as usize];
    let written = unsafe {
        nix::libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32)
    };
    if written <= 0 {
        return None;
    }
    buffer.truncate(written as usize);
    Some(PathBuf::from(OsString::from_vec(buffer)))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "ios")))]
compile_error!(
    "anpio-key has no process-identity check for this platform, so `stop` could kill a recycled \
     pid. Refusing to compile beats shipping a kill that guesses."
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn our_own_pid_is_our_own_executable() {
        let me = std::env::current_exe().unwrap();
        assert!(
            is_same_executable(&me, std::process::id() as i32),
            "the test binary should recognize itself"
        );
    }

    #[test]
    fn a_pid_that_cannot_be_running_is_not_us() {
        let me = std::env::current_exe().unwrap();
        // 一个几乎所有机器上都空着的 pid。就算是活的,也不可能是这个
        // 测试二进制 —— 而这一条正是 `stop` 要挡住的那种误杀。
        assert!(!is_same_executable(&me, 4_000_000));
    }

    #[test]
    fn no_pid_means_no_answer() {
        assert!(executable_of(0).is_none());
        assert!(executable_of(-1).is_none());
    }
}
