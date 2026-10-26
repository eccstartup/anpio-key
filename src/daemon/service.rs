//! 守护进程的进程管理:进后台、写 pid 文件、装日志。
//!
//! 这一层管的是"这个进程怎么活着",不是"它怎么应答"
//! ([`crate::daemon::server`] 管后者)。分开是因为两边的失败方式完全不同:
//! 那边失败是协议问题,这边失败是"终端上什么都没看见"。

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use tracing_subscriber::EnvFilter;

use crate::error::{KeydError, Result};
use crate::keystore::layout::SECRET_FILE_MODE;

/// 起来之后最多等这么久去确认 socket。够一次 Argon2id 之外的所有启动活儿,
/// 又短到不至于让人以为命令卡住了。
const READINESS_TIMEOUT: Duration = Duration::from_secs(5);

/// 轮询间隔。10ms 是"人感觉不到延迟"和"不把 CPU 烧掉"之间的老位置。
const READINESS_POLL: Duration = Duration::from_millis(10);

/// 日志往哪去。
///
/// **只有一个去处:stderr。** 后台模式下父进程已经把子进程的 stderr 接到
/// 日志文件上了,所以不需要在这里再开一次 —— 两个写者各自 append 同一个
/// 文件,顺序反而没法说清。
///
/// 颜色按 `stderr` **是不是终端**决定,不按"是不是 `--foreground`"决定:
/// 后台那个子进程内部就是 `--foreground`(它和 launchd 拉起来的那个是同一个
/// 进程),它的 stderr 却是文件。按标志判断会给日志里塞满 ANSI 转义。
pub fn install_logging() -> Result<()> {
    use std::io::IsTerminal;

    // 装不上不算失败:测试进程里可能已经装过一个,而"日志没有输出"不该
    // 让守护进程起不来。
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .with_target(false)
        .try_init();
    Ok(())
}

/// 0600 追加。从创建那一刻就是 0600,不存在"先建后 chmod"的窗口。
fn open_log_file(path: &Path) -> Result<std::fs::File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(OpenOptions::new()
        .create(true)
        .append(true)
        .mode(SECRET_FILE_MODE)
        .open(path)?)
}

/// pid 文件:写下来,活着的期间一直在,退出时自己删掉。
///
/// 用 RAII 而不是"在几个 return 前面各加一句":绑定失败、收到 SIGTERM、
/// panic 展开,三条路都得删 —— 漏掉任何一条,下一次 `stop` 就会对着一个
/// 已经不存在的 pid 说话。
pub struct PidFile {
    path: PathBuf,
}

impl PidFile {
    pub fn write(path: PathBuf) -> Result<Self> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(SECRET_FILE_MODE)
            .open(&path)?;
        writeln!(file, "{}", std::process::id())?;
        file.sync_all()?;
        Ok(Self { path })
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// socket 文件的身份:`(dev, ino)`。拿不到(文件不在、没权限)就是 `None`。
///
/// 用它而不是路径来回答"现在躺在那个路径上的是不是刚建出来的那个" ——
/// 路径上的东西会被换掉,而 inode 不会。
fn socket_identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;

    let meta = std::fs::metadata(path).ok()?;
    Some((meta.dev(), meta.ino()))
}

/// pid 文件里记的是哪个 pid。文件还没落盘、正写到一半、或者里面不是数字,
/// 都算"还不知道" —— 这一层只用来等它,不用来判断对错。
fn recorded_pid(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// 把守护进程放到后台,然后**把这个终端还回去**。
///
/// 做法是**重新执行自己**,不是 fork:后台那个进程就是
/// `anpio-key serve --foreground`,和服务管理器拉起来的一模一样。守护进程
/// 本体于是只有一条代码路径 —— "后台跑的"和"launchd 跑的"不会各自长出
/// 一种毛病。
///
/// `setsid` 必须在 `pre_exec` 里做。它让子进程离开当前会话:**没有它,
/// 终端一关,那个 SIGHUP 会顺着会话找上来**,而症状是"关掉窗口之后守护
/// 进程就没了",看起来像随机故障。
///
/// 返回 `Ok` 表示"已经在后台跑起来了",不是"它一定健康" —— 后者没法保证,
/// 这里只保证"没有立刻死掉,而且**我们起的那个** socket 在那儿,pid 文件也
/// 已经写好"。
pub fn detach(log_path: &Path, sock_path: &Path, pid_path: &Path) -> Result<()> {
    // **起子进程之前先记住这个 socket 现在长什么样。**
    //
    // 少了这一步,"那儿有一个 socket 文件"这个条件在有别的守护进程占着同一个
    // 路径时**一开始就成立** —— 父进程会把"它早就在那儿了"报成"我们起来了",
    // 然后退出码 0。真正的原因(子进程绑定失败、日志里那句 already served)
    // 就此被吞掉,而人拿到的是一句好消息加一个不是自己起的守护进程。
    let before = socket_identity(sock_path);

    let log = open_log_file(log_path)?;
    let errors = log.try_clone()?;

    let mut command = std::process::Command::new(std::env::current_exe()?);
    command
        // 参数原样带上,只加一个 `--foreground`。
        .args(std::env::args_os().skip(1))
        .arg("--foreground")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(errors));

    // SAFETY: `pre_exec` 里只调 `setsid`,它是 async-signal-safe 的,
    // 不分配、不加锁、不碰 Rust 运行时的任何状态。
    unsafe {
        command.pre_exec(|| {
            if nix::libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = command.spawn()?;
    let pid = child.id();

    let exited = |status: std::process::ExitStatus| {
        KeydError::Misuse(format!(
            "the daemon exited immediately ({status}); last lines of {}:\n{}",
            log_path.display(),
            tail(log_path, 10)
        ))
    };

    let deadline = Instant::now() + READINESS_TIMEOUT;
    loop {
        // **先看它死没死,再看 socket。** 反过来会把"别处已经有一个守护
        // 进程占着这个 socket"读成"我们起来了"。
        if let Some(status) = child.try_wait()? {
            return Err(exited(status));
        }

        // 就绪 = **那个 socket 文件不是原来那个了、孩子还活着,而且 pid 文件
        // 已经写下他。**
        //
        // 比 `(dev, ino)`:子进程要么在一个死文件上重建一个(inode 变了),
        // 要么从无到有建一个(`before` 是 `None`),两种都算数。而"文件是新的
        // + 孩子没死"就够了吗?不够 —— `bind()` 之后孩子那边**还有一步**:
        // 写 pid 文件。漏掉它,`serve` 就会在 socket 出现、pid 文件还没落盘的
        // 那一小段里把终端还回去,而这一段**不是**零:紧接着 `serve` 敲一句
        // `stop` 的脚本,或者一条读完就去看 `run/keyd.pid` 的测试,都会读到
        // 一个不存在的文件 —— 症状是"守护进程明明起来了,`stop` 却说没在跑"。
        // 这是实测撞到的:`serve` 之后立刻读 pid 文件,负载一上来就开始红。
        //
        // **这里不连 socket。** 起先连过,后来发现它有个不那么显然的代价:
        // 开了第三层(`--allow-binary`)之后,那条探测连接会被拒 —— 对端是
        // 一条连上就走的空连接,内核给的凭证读不出来,于是守护进程每一次
        // 启动都给自己记一条 `DENIED` 审计事件,外加一条 WARN。审计是防篡改
        // 的证据,不该混进工具自己的噪声。
        let now = socket_identity(sock_path);
        if now.is_some() && now != before && recorded_pid(pid_path) == Some(pid) {
            // 再看一眼:孩子可能正好在"重建了 socket 文件、bind 又失败"的
            // 那条路上,而那条路也以退出收场。
            if let Some(status) = child.try_wait()? {
                return Err(exited(status));
            }
            println!("listening on {} (pid {pid})", sock_path.display());
            println!("to stop it: anpio-key stop");
            return Ok(());
        }

        if Instant::now() >= deadline {
            // 说清楚是"没确认",不是"起来了"。含糊其辞会让人以为 socket
            // 一定在,然后在下一句命令上撞墙。
            println!(
                "started (pid {pid}) but {} is still not listening after {}s; check {}",
                sock_path.display(),
                READINESS_TIMEOUT.as_secs(),
                log_path.display()
            );
            return Ok(());
        }

        std::thread::sleep(READINESS_POLL);
    }
}

/// 日志尾部若干行,给它留出"失败了,但看得见为什么"。
///
/// 只读文件末尾一小段:日志按天攒下去可以是几十兆,而这里只为了报一句话。
fn tail(path: &Path, lines: usize) -> String {
    const KEEP: usize = 8 * 1024;

    let Ok(bytes) = std::fs::read(path) else {
        return "(the log could not be read)".into();
    };
    let start = bytes.len().saturating_sub(KEEP);
    let text = String::from_utf8_lossy(&bytes[start..]);
    let recent: Vec<&str> = text.lines().rev().take(lines).collect();
    recent.into_iter().rev().collect::<Vec<_>>().join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tail_keeps_the_last_lines_and_drops_the_rest() {
        let dir = std::env::temp_dir().join(format!("keyd-service-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("serve.log");

        let mut file = open_log_file(&path).unwrap();
        for n in 1..=50 {
            writeln!(file, "line {n}").unwrap();
        }
        drop(file);

        let tail = tail(&path, 3);
        assert_eq!(tail, "line 48\nline 49\nline 50");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_log_file_lands_at_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("keyd-logmode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("log").join("serve.log");

        open_log_file(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, SECRET_FILE_MODE, "the serve log must not be world readable");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_pid_file_disappears_with_its_guard() {
        let dir = std::env::temp_dir().join(format!("keyd-pidfile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keyd.pid");

        {
            let _guard = PidFile::write(path.clone()).unwrap();
            assert!(path.exists());
            let recorded = std::fs::read_to_string(&path).unwrap();
            assert_eq!(recorded.trim(), std::process::id().to_string());
        }
        assert!(!path.exists(), "the pid file must go away with its guard");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
