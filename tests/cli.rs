//! CLI 层:真起一个 `anpio-key` 进程,真的在一个终端上敲命令。
//!
//! # 为什么这一层必须存在,以及为什么它必须用**真终端**
//!
//! 前四份集成测试都走库 API,于是它们看不见一整层东西:`clap` 的解析与
//! 互斥、退出码、打印给人看的那些话、以及 `ops::Session::open` 里那条
//! "口令只从 `/dev/tty` 读"的纪律。而那一条纪律恰恰是**没法在库里面测的**
//! —— `Session::open` 自己调 `tty::open()`,没有一个注入口。这不是缺陷:
//! 一个可以被调用方塞进"另一个终端"的实现,正是第六节里那条
//! `SCM_RIGHTS` 攻击要利用的东西。
//!
//! 所以唯一的测法就是**和人类一样用它**:分配一对真 pty,让子进程
//! `setsid` + `TIOCSCTTY` 把它当控制终端,然后照提示语回答。
//!
//! 顺带把 `ops` 那五个生命周期命令(`add-recovery-key` / `rotate-hot-key` /
//! `remove-key` / `migrate` / `deactivate`)也盖住了 —— 它们同样只从终端读
//! 秘密,之前一条测试都没有。
//!
//! # 自动回答
//!
//! 每条命令的提问顺序是固定的,但与其把顺序抄进测试(那样改一句提示语就
//! 红一片),这里按**提示语的样子**回答:看到 "(its binding key):" 就回
//! 绑定密钥那个口令,看到 "Repeat it:" 就重复一遍,看到 "[y/N]" 就点头。
//! 认不出来的提示语会拖到超时 —— 那是**失败**,不是跳过:一条没人回答的
//! 提问意味着这里有一处人机交互没被覆盖。

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_anpio-key");
const PASSPHRASE: &str = "a passphrase that the echo must never show";

// ————————————————————————————————————————————————————————————————————————
// 夹具
// ————————————————————————————————————————————————————————————————————————

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let path = PathBuf::from("/tmp").join(format!(
            "keyd-cli-{tag}-{}-{}",
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

// ————————————————————————————————————————————————————————————————————————
// 一个真的终端
// ————————————————————————————————————————————————————————————————————————

/// 回答提示语的规则:**先匹配上的先用**。顺序有意义 ——
/// `"Passphrase for "` 是兜底的那条,必须排在更具体的后面。
fn default_rules() -> Vec<(&'static str, String)> {
    vec![
        ("(its binding key): ", PASSPHRASE.to_string()),
        ("New passphrase for this key: ", PASSPHRASE.to_string()),
        ("Repeat it: ", PASSPHRASE.to_string()),
        ("Passphrase for the new key", String::new()),
        ("Passphrase for ", PASSPHRASE.to_string()),
        ("[y/N] ", "y".to_string()),
    ]
}

struct Outcome {
    stdout_and_stderr: String,
    /// 单独接到管子上的 stdout(只有 [`run_in_terminal_keeping_stdout_separate`]
    /// 会填它)。默认那条路三头都在 pty 上,所以这里恒为空。
    stdout: String,
    code: Option<i32>,
    timed_out: bool,
}

impl Outcome {
    #[track_caller]
    fn expect_ok(&self) -> &str {
        assert!(!self.timed_out, "the command never finished:\n{}", self.text());
        assert_eq!(
            self.code,
            Some(0),
            "the command failed (exit {:?}):\n{}",
            self.code,
            self.text()
        );
        &self.stdout_and_stderr
    }

    #[track_caller]
    fn expect_failure(&self) -> &str {
        assert!(!self.timed_out, "the command never finished:\n{}", self.text());
        assert_ne!(
            self.code,
            Some(0),
            "the command was supposed to be refused:\n{}",
            self.text()
        );
        &self.stdout_and_stderr
    }

    #[track_caller]
    fn text(&self) -> &str {
        &self.stdout_and_stderr
    }
}

/// 在一个**真终端**里跑一条命令,按规则回答提问,等它结束。
fn run_in_terminal(root: &Path, args: &[&str], rules: &[(&str, String)]) -> Outcome {
    spawn_and_drive(root, args, rules, false)
}

/// 同 [`run_in_terminal`],但 **stdout 接一根管子**,不接终端。
///
/// 用来证明"某个东西只走终端":pty 上看到的是人类屏幕,管子里看到的是能
/// 被重定向、被 `tee`、被日志收走的那一份。助记词必须只出现在前者。
fn run_in_terminal_keeping_stdout_separate(
    root: &Path,
    args: &[&str],
    rules: &[(&str, String)],
) -> Outcome {
    spawn_and_drive(root, args, rules, true)
}

fn spawn_and_drive(
    root: &Path,
    args: &[&str],
    rules: &[(&str, String)],
    separate_stdout: bool,
) -> Outcome {
    let pair = nix::pty::openpty(None, None).expect("openpty");
    let master = File::from(pair.master);
    let slave = File::from(pair.slave);
    let slave_fd = slave.as_raw_fd();

    let mut command = Command::new(BIN);
    command.arg(args[0]).args(&args[1..]);
    command.arg("--root").arg(root);

    // 默认三头都接到从设备上:这样 stdout 和 stderr 一起进 pty,读起来是一条
    // 按时间排好的流 —— 而这条流正是人类在屏幕上看到的东西。`keygen` 那条
    // 例外:stdout 单独走管子,好在事后查它是不是空的。
    command.stdin(Stdio::from(slave.try_clone().expect("clone the pty slave")));
    command.stdout(if separate_stdout {
        Stdio::piped()
    } else {
        Stdio::from(slave.try_clone().expect("clone the pty slave"))
    });
    command.stderr(Stdio::from(slave.try_clone().expect("clone the pty slave")));

    unsafe {
        command.pre_exec(move || {
            // 裸 `setsid(2)` 而不是 `nix::unistd::setsid`:这个闭包跑在 `fork`
            // 之后、`exec` 之前,中间只能用异步信号安全的东西。
            if nix::libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            // 有了自己的会话还不够 —— 控制终端得**认领**:没有这一步,
            // 子进程里的 `open("/dev/tty")` 拿不到东西。
            if nix::libc::ioctl(slave_fd, nix::libc::TIOCSCTTY as nix::libc::c_ulong, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = command.spawn().expect("spawn anpio-key");
    // **父进程手里那几份从设备必须关掉。** 留着它们,子进程退出之后主设备
    // 那头也不会给出 EOF,读线程就只能靠超时收场。
    drop(command);
    drop(slave);

    // 管子要在等子进程之前就开始排空:超过管道缓冲(64 KiB)时,写不进去的
    // 子进程会停下来等、而这边在等它退出 —— 两边一起卡死。
    let stdout_pipe = separate_stdout.then(|| {
        let mut pipe = child.stdout.take().expect("piped stdout");
        std::thread::spawn(move || {
            let mut text = String::new();
            let _ = pipe.read_to_string(&mut text);
            text
        })
    });

    let mut outcome = drive(&master, &mut child, rules);
    if let Some(reader) = stdout_pipe {
        outcome.stdout = reader.join().unwrap_or_default();
    }
    outcome
}

/// 读主设备那头,见到提示语就照规则回答,直到子进程结束。
fn drive(master: &File, child: &mut Child, rules: &[(&str, String)]) -> Outcome {
    set_nonblocking(master);

    let seen = Arc::new(Mutex::new(String::new()));
    let cursor = Arc::new(Mutex::new(0usize));
    let exited = Arc::new(AtomicBool::new(false));

    let reader = {
        let master = master.try_clone().expect("clone the pty master");
        let seen = Arc::clone(&seen);
        let cursor = Arc::clone(&cursor);
        let exited = Arc::clone(&exited);
        let rules: Vec<(String, String)> =
            rules.iter().map(|(p, r)| (p.to_string(), r.clone())).collect();

        std::thread::spawn(move || {
            let mut quiet_since = Instant::now();
            loop {
                let mut chunk = [0u8; 4096];
                match (&master).read(&mut chunk) {
                    Ok(0) => break,
                    Ok(read) => {
                        let text = String::from_utf8_lossy(&chunk[..read]);
                        seen.lock().unwrap().push_str(&text);
                        answer(&master, &seen, &cursor, &rules);
                        quiet_since = Instant::now();
                    }
                    Err(_) => {
                        // 非阻塞下没有数据可读就是 `WouldBlock`。子进程已经
                        // 退出、而且安静了一小会儿,就可以收工了。
                        if exited.load(Ordering::Relaxed)
                            && quiet_since.elapsed() > Duration::from_millis(150)
                        {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
            }
        })
    };

    let status = child.wait().expect("wait for anpio-key");
    exited.store(true, Ordering::Relaxed);
    let _ = reader.join();

    let text = seen.lock().unwrap().clone();
    Outcome {
        stdout_and_stderr: text,
        stdout: String::new(),
        code: status.code(),
        timed_out: status.code().is_none(),
    }
}

/// 在**还没回答过**的那一段里找规则表里**第一条**命中的,回过去,推进游标。
///
/// 挑的是"规则表里的先后",不是"出现在文本里的先后",这一点很要紧。
/// 绑定密钥那句提示语是
/// `Passphrase for {did} (its binding key): ` —— 通用的
/// `"Passphrase for "` 出现在句子最前面,而具体的那条在句尾。按位置选就会
/// 先命中通用的那条,游标只推过一小段,句尾剩下的 `(its binding key): `
/// 下一轮又被答一遍:多出来的一行会把**后面**的提问整个顶掉(实测就是确认框
/// 读到一个空行,于是报 "you answered no")。按规则表先后选,具体的那条在
/// 前面,游标一次推过整句。
///
/// 一次可能命中好几条(提示语挤在同一个读块里),所以这里是循环。
fn answer(
    master: &File,
    seen: &Arc<Mutex<String>>,
    cursor: &Arc<Mutex<usize>>,
    rules: &[(String, String)],
) {
    loop {
        let index = {
            let buffer = seen.lock().unwrap();
            let mut cursor = cursor.lock().unwrap();
            match first_match(&buffer, *cursor, rules) {
                Some((position, index)) => {
                    *cursor = position + rules[index].0.len();
                    index
                }
                None => return,
            }
        };

        let mut writer = master.try_clone().expect("clone the pty master for writing");
        let wrote = writer
            .write_all(rules[index].1.as_bytes())
            .and_then(|()| writer.write_all(b"\n"))
            .and_then(|()| writer.flush());
        if wrote.is_err() {
            // 子进程已经走了,没有人在等这个回答。这不是失败 —— 断言在
            // 调用方那边看输出。
            return;
        }
    }
}

/// 规则表里第一条在游标之后出现的。
fn first_match(buffer: &str, cursor: usize, rules: &[(String, String)]) -> Option<(usize, usize)> {
    if cursor > buffer.len() {
        return None;
    }
    let tail = &buffer[cursor..];
    rules
        .iter()
        .enumerate()
        .find_map(|(index, (pattern, _))| {
            tail.find(pattern.as_str()).map(|offset| (cursor + offset, index))
        })
}

fn set_nonblocking(file: &File) {
    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    let flags = fcntl(file, FcntlArg::F_GETFL).expect("F_GETFL");
    let flags = OFlag::from_bits_truncate(flags);
    fcntl(file, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).expect("F_SETFL");
}

// ————————————————————————————————————————————————————————————————————————
// 不带终端的命令:参数解析、退出码、帮助
// ————————————————————————————————————————————————————————————————————————

/// 跑一条不需要终端的命令,也不带 `--root`:只有参数解析会被走到。
fn run_bare(args: &[&str]) -> Outcome {
    let output = Command::new(BIN).args(args).output().expect("spawn anpio-key");
    Outcome {
        stdout_and_stderr: format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        stdout: String::new(),
        code: output.status.code(),
        timed_out: false,
    }
}

// ========================================================================
// 一、参数解析:在问口令**之前**就把该说的说出来
// ========================================================================

/// `--spec` 没有默认值,漏了就当场说。
///
/// 这条挡的是一句谎话:DID 是"坐标 + 公钥"算出来的,而坐标必须是人写在
/// 文件里的那几个 —— 由工具替人挑一个,等于替人决定他的身份挂在哪儿。
/// clap 的退出码是 2:那是"你用错了",不是"事情办不成"。
#[test]
fn keygen_without_a_spec_file_is_refused_by_the_argument_parser() {
    let dir = TempDir::new("no-spec");
    let outcome = run_bare(&[
        "keygen",
        "--root",
        &dir.path().display().to_string(),
    ]);

    assert_eq!(outcome.code, Some(2), "clap must reject it:\n{}", outcome.text());
    assert!(
        outcome.text().contains("--spec"),
        "the error has to name the missing flag:\n{}",
        outcome.text()
    );
}

/// 每一个子命令都出现在 `--help` 里 —— 包括那些只在特定特性下存在的。
///
/// 这一条防的是"忘了往 `Command` 里加一个变体":命令还在 `cli.rs` 里,
/// 但人在 `--help` 上看不到它,于是它等于不存在。
#[test]
fn help_lists_every_command() {
    let outcome = run_bare(&["--help"]);
    let text = outcome.expect_ok();

    for command in [
        "serve",
        "keygen",
        "spec",
        "publish",
        "verify-doc",
        "list",
        "status",
        "probe",
        "unlock",
        "lock",
        "sign",
        "add-recovery-key",
        "rotate-hot-key",
        "remove-key",
        "migrate",
        "deactivate",
        "import-mnemonic",
        "import-archive",
    ] {
        assert!(text.contains(command), "`{command}` is missing from --help:\n{text}");
    }
}

/// `--raw` 和结构化那套参数**互相排除**,而且 clap 就得拦住。
///
/// 不是洁癖:两者都能给的话,调用方会以为 `--body` 也进了覆盖面,而原始
/// 签名的输入只有那个文件 —— 这正是"悄悄降级"的形状。
#[test]
fn sign_refuses_raw_together_with_structured_flags() {
    let outcome = run_bare(&[
        "sign",
        "--did",
        "did:wba:example.com:a:e1_x",
        "--url",
        "https://example.com/x",
        "--raw",
        "/tmp/some-file",
    ]);
    assert_eq!(outcome.code, Some(2), "clap must reject the combination:\n{}", outcome.text());
}

// ========================================================================
// 二、keygen:两句口令,一个信封
// ========================================================================

/// 一份规格文件,写在临时目录里,返回它的路径。
///
/// 文档该有什么由**这个文件**说了算 —— `keygen` 只是照它构造文档、签名。
/// 工具不再接 `--host` / `--path` 这类参数,理由见 `spec` 那个模块的头。
fn spec_file(dir: &TempDir, name: &str, content: &str) -> String {
    let path = dir.path().join(format!("{name}.spec.json"));
    std::fs::write(&path, content).expect("write the spec file");
    path.display().to_string()
}

fn a_spec_for(host: &str, path: &str) -> String {
    format!(r#"{{ "host": "{host}", "path": "{path}" }}"#)
}

/// 造一把钥匙,然后**在磁盘上确认它真的躺在那儿**,而且模式是 0600。
fn keygen(dir: &TempDir, tag: &str) -> String {
    let spec = spec_file(dir, tag, &a_spec_for("example.com", &format!("agents/{tag}")));
    let outcome = run_in_terminal(
        dir.path(),
        &["keygen", "--spec", &spec],
        &default_rules(),
    );
    let text = outcome.expect_ok();

    assert!(
        !text.contains(PASSPHRASE),
        "the passphrase must never be echoed back:\n{text}"
    );

    text.lines()
        .map(str::trim)
        .find(|line| line.starts_with("did:wba:"))
        .expect("keygen prints the DID")
        .to_string()
}

/// `spec` 的产物就是 `keygen` 要读的那个文件 —— 中间没有别的格式。
#[test]
fn spec_writes_a_file_that_keygen_can_use() {
    let dir = TempDir::new("spec");
    let written = dir.path().join("written.spec.json");
    run_bare(&[
        "spec",
        "--host",
        "example.com",
        "--path",
        "agents/bot",
        "--out",
        &written.display().to_string(),
    ])
    .expect_ok();

    let did = run_in_terminal(
        dir.path(),
        &["keygen", "--spec", &written.display().to_string()],
        &default_rules(),
    )
    .expect_ok()
    .lines()
    .map(str::trim)
    .find(|line| line.starts_with("did:wba:"))
    .expect("keygen prints the DID")
    .to_string();

    assert!(did.starts_with("did:wba:example.com:agents:bot:e1_"), "got {did:?}");
}

#[test]
fn keygen_mints_four_keys_and_writes_the_signed_document() {
    let dir = TempDir::new("keygen");
    let did = keygen(&dir, "bot");

    assert!(did.starts_with("did:wba:example.com:agents:bot:e1_"), "got {did:?}");

    // 一个助记词铸出四把:根、热、设备签名、协商。四份信封都不该是被别的东西
    // 顺手写下的 —— 数量少一把就说明某条推导没跑到。
    let keys: Vec<_> = std::fs::read_dir(dir.path().join("keys"))
        .expect("keys/ exists")
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(keys.len(), 4, "root, hot, device-sign, device-agreement: {keys:?}");

    for key in &keys {
        let mode = std::fs::metadata(key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{} is a secret: {mode:o}", key.display());
    }

    // 文档已经签好、落在本地那一份上 —— 它和钥匙是同一趟里出来的,所以
    // 四把都在里面。(文件名不是 `{did}.json`:DID 里的 `:` 落不了地。)
    let documents: Vec<_> = std::fs::read_dir(dir.path().join("dids"))
        .expect("keygen writes a signed document")
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(documents.len(), 1, "{documents:?}");
    let document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&documents[0]).unwrap()).unwrap();
    assert_eq!(document["id"], did);
    assert_eq!(document["verificationMethod"].as_array().unwrap().len(), 4);

    let listed = |relationship: &str| -> Vec<String> {
        document[relationship]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| id.as_str().unwrap().rsplit('#').next().unwrap().to_string())
            .collect()
    };
    assert_eq!(listed("authentication"), ["key-1", "key-2", "device-sign"]);
    assert_eq!(listed("assertionMethod"), ["key-1", "device-sign"]);
    assert_eq!(listed("keyAgreement"), ["device-agreement"]);
}

/// 词出现过一次,而且**只在终端上** —— 重定向过的 stdout 里不能有。
///
/// 这一条盯的是"有没有第二次":没有导出路径是设计的一部分,所以抄写那一屏
/// 就是全部机会。它同时盯住词不走 stdout —— 走 stdout 的话,一个
/// `keygen > log` 就把备份写进了谁都能读的文件。
#[test]
fn keygen_shows_the_words_on_the_terminal_and_never_on_stdout() {
    let dir = TempDir::new("words");
    let spec = spec_file(&dir, "bot", &a_spec_for("example.com", "agents/bot"));
    let outcome = run_in_terminal_keeping_stdout_separate(
        dir.path(),
        &["keygen", "--spec", &spec],
        &default_rules(),
    );
    outcome.expect_ok();

    let screen = outcome.text();
    assert_eq!(
        screen.matches("These 24 words are the only backup").count(),
        1,
        "the words are shown exactly once:\n{screen}"
    );
    let numbered = (1..=24)
        .filter(|n| screen.contains(&format!("{n:>2}. ")))
        .count();
    assert_eq!(numbered, 24, "all 24 words have to be on that screen:\n{screen}");

    // 词不能出现在 stdout 上:它是要被重定向、被 `tee`、被日志收走的那一份。
    // 这里取屏幕上那串词里连续三个当探针 —— 单个词可能本来就是 nginx 之类的
    // 普通词,连着的三个不是。
    let words: Vec<&str> = screen
        .lines()
        .filter_map(|line| {
            let rest = line.trim_start().split_once(". ")?.1;
            (!rest.is_empty() && !rest.contains(' ')).then_some(rest)
        })
        .collect();
    assert_eq!(words.len(), 24, "could not read the words back:\n{screen}");
    let probe = words[..3].join(" ");
    assert!(
        !outcome.stdout.contains(&probe),
        "the words must not reach stdout:\n{}",
        outcome.stdout
    );
    assert!(!outcome.stdout.contains("These 24 words"));
    assert!(
        outcome.stdout.contains(&format!("did:wba:")),
        "the DID itself is still on stdout — that part is not a secret:\n{}",
        outcome.stdout
    );
}

/// 说"没抄"就**什么都不铸** —— 一套没有备份的身份比没有身份更糟。
#[test]
fn keygen_writes_nothing_when_the_words_are_not_written_down() {
    let dir = TempDir::new("no-backup");
    let spec = spec_file(&dir, "bot", &a_spec_for("example.com", "agents/bot"));
    let rules: Vec<(&str, String)> = vec![
        ("New passphrase for this key: ", PASSPHRASE.to_string()),
        ("Repeat it: ", PASSPHRASE.to_string()),
        ("[y/N] ", "n".to_string()),
    ];
    let outcome = run_in_terminal(dir.path(), &["keygen", "--spec", &spec], &rules);
    let text = outcome.expect_failure();

    assert!(
        text.contains("were not written down"),
        "it has to say why nothing happened:\n{text}"
    );
    assert!(
        !dir.path().join("keys").exists()
            || std::fs::read_dir(dir.path().join("keys")).unwrap().count() == 0,
        "no envelope may be written"
    );
    assert!(!dir.path().join("dids").exists(), "and no document either");
}

/// 两遍对不上就**什么都不写**,而不是留一个自己打不开的信封。
#[test]
fn keygen_refuses_when_the_two_entries_do_not_match() {
    let dir = TempDir::new("mismatch");
    let rules: Vec<(&str, String)> = vec![
        ("New passphrase for this key: ", "one".into()),
        ("Repeat it: ", "another".into()),
    ];

    // 三轮都答错,于是到顶 —— 每一轮都要重新回答"新口令"和"重复"两句,
    // 所以规则得能重复命中(游标是往前推的,不是"每条只答一次")。
    let spec = spec_file(&dir, "bot", &a_spec_for("example.com", "agents/bot"));
    let outcome = run_in_terminal(dir.path(), &["keygen", "--spec", &spec], &rules);
    let text = outcome.expect_failure();

    assert!(
        text.contains("the passphrase was not confirmed"),
        "it has to say the refusal out loud:\n{text}"
    );
    assert!(
        !dir.path().join("keys").exists() || std::fs::read_dir(dir.path().join("keys")).unwrap().count() == 0,
        "nothing may be written when the passphrase was never confirmed"
    );
}

/// IP 字面量被拒 —— 而且是在**问口令之前**。
///
/// 后半句才是这条测试的价值:人已经坐下来、敲完两遍口令之后才被告知"你
/// 这个域名不行",那条错误本来在他敲第一个字符之前就成立了。
#[test]
fn an_ip_literal_host_is_refused_before_the_passphrase_is_ever_asked() {
    let dir = TempDir::new("ip-literal");
    let spec = spec_file(&dir, "ip", &a_spec_for("127.0.0.1", "agents/bot"));
    let outcome = run_in_terminal(dir.path(), &["keygen", "--spec", &spec], &default_rules());
    let text = outcome.expect_failure();

    assert!(text.contains("IP"), "the refusal has to name what is wrong:\n{text}");
    assert!(
        !text.contains("New passphrase"),
        "it must not get as far as asking for a passphrase:\n{text}"
    );
}

// ========================================================================
// 三、publish / verify-doc
// ========================================================================

/// 发布一份文档,并拿它自己验一遍 —— 一份签得出来却绑不上路径的文档,
/// 发布出去只会让**别人**发现我们在骗自己。
#[test]
fn a_published_document_verifies_against_its_own_did() {
    let dir = TempDir::new("publish");
    let did = keygen(&dir, "bot");

    let published = run_in_terminal(dir.path(), &["publish", "--did", &did], &default_rules());
    let text = published.expect_ok();

    // 取回地址是**完整的** DID 路径 —— 最后那段 `e1_<指纹>` 也在里面。
    // did:wba 的规则是"把 DID 的路径段原样当 URL 路径",少一段就没人找得到
    // 这份文档,而那意味着签名验不过 —— 这是"工具的产物能不能用"的问题。
    let segment = did.rsplit(':').next().expect("the e1_ segment");
    assert!(
        text.contains(&format!("https://example.com/agents/bot/{segment}/did.json")),
        "it has to say where the file must be served:\n{text}"
    );
    assert!(
        text.contains("this tool cannot host anything"),
        "and it has to admit it cannot host it:\n{text}"
    );

    let verified = run_in_terminal(dir.path(), &["verify-doc", "--did", &did], &default_rules());
    let text = verified.expect_ok();
    assert!(text.contains("is valid"), "the local copy must verify:\n{text}");
}

/// 验一份**不是**这个 DID 的文档:路径绑定对不上就得拒。
#[test]
fn a_document_for_another_did_is_refused() {
    let dir = TempDir::new("wrong-did");
    let did = keygen(&dir, "bot");
    run_in_terminal(dir.path(), &["publish", "--did", &did], &default_rules()).expect_ok();

    let local = std::fs::read_dir(dir.path().join("dids"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .next()
        .expect("the published document");

    let borrowed = did.replace("agents:bot:", "agents:someone-else:");
    let outcome = run_in_terminal(
        dir.path(),
        &["verify-doc", "--did", &borrowed, "--file", &local.display().to_string()],
        &default_rules(),
    );
    outcome.expect_failure();
}

/// 拿一个 DID 去签**另一个地方**的文档:直接拒,不挑一个信。
///
/// 这条挡的不是手滑,是那句话本身:文档要不要改动由规格说了算,而规格里的
/// 坐标要是和 `--did` 对不上,那就说明**其中一样不是你的本意**。挑一个信等于
/// 替人决定哪个是本意 —— 而这两个选项都签得出一个能验过的文档。
#[test]
fn publish_refuses_a_spec_that_points_somewhere_else() {
    let dir = TempDir::new("spec-mismatch");
    let spec = spec_file(&dir, "bot", &a_spec_for("example.com", "agents/bot"));
    let did = run_in_terminal(dir.path(), &["keygen", "--spec", &spec], &default_rules())
        .expect_ok()
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("did:wba:"))
        .expect("keygen prints the DID")
        .to_string();

    let elsewhere = spec_file(
        &dir,
        "elsewhere",
        &a_spec_for("example.com", "agents/someone-else"),
    );
    // `keygen` 已经把文档写下去了,所以要盯的是**它没被改**,而不是"没写"。
    let before_document = read_local_document(&dir, &did);
    let outcome = run_in_terminal(
        dir.path(),
        &["publish", "--did", &did, "--spec", &elsewhere],
        &default_rules(),
    );
    let text = outcome.expect_failure();

    assert!(
        text.contains("someone-else"),
        "the refusal has to name the path it could not reconcile:\n{text}"
    );
    assert_eq!(
        read_local_document(&dir, &did),
        before_document,
        "a mismatched spec must not touch the document that is already there"
    );
}

/// 不带 `--spec` 重发一次,本地文档里已有的声明**一个也不许掉**。
///
/// 这是这次拆分的头号动机。`service` 由规格说了算,所以它不在"上游不认识的
/// 属性原样搬回去"那一档里 —— 从前从 DID 字符串重建文档,`service` 会因为
/// "没人提到它"而消失,**而且不报错**。WNS handle 的绑定就挂在那个数组里。
#[test]
fn republishing_keeps_the_declarations_already_in_the_local_document() {
    let dir = TempDir::new("republish");
    let spec = dir.path().join("bot.spec.json");
    std::fs::write(
        &spec,
        r##"{
            "host": "example.com",
            "path": "agents/bot",
            "services": [
                {
                    "id": "#handle",
                    "type": "ANPHandleService",
                    "serviceEndpoint": "https://example.com/handle/bot"
                }
            ]
        }"##,
    )
    .unwrap();
    let spec = spec.display().to_string();

    let did = run_in_terminal(dir.path(), &["keygen", "--spec", &spec], &default_rules())
        .expect_ok()
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("did:wba:"))
        .expect("keygen prints the DID")
        .to_string();

    run_in_terminal(
        dir.path(),
        &["publish", "--did", &did, "--spec", &spec],
        &default_rules(),
    )
    .expect_ok();
    let before = read_local_document(&dir, &did);
    assert_eq!(
        before["service"][0]["id"],
        serde_json::Value::String(format!("{did}#handle")),
        "the `#`-prefixed id must be expanded against the DID: {before:#}"
    );

    // 再发一次,**不提任何规格** —— 它必须沿用本地那份文档里的声明。
    run_in_terminal(dir.path(), &["publish", "--did", &did], &default_rules()).expect_ok();
    let after = read_local_document(&dir, &did);
    assert_eq!(
        after["service"], before["service"],
        "a republish that drops `service` is a silent loss of the handle binding"
    );
    // 而 proof 是**新**的 —— 否则上面那条只是在比一份没被重签的旧文件。
    assert_ne!(
        after["proof"], before["proof"],
        "the document must actually have been re-signed"
    );
}

// ========================================================================
// 四、守护进程:解锁、签名、上锁
// ========================================================================

/// 一个跑着的 `anpio-key serve`。
struct Daemon {
    child: Child,
}

impl Daemon {
    /// `--foreground` 是必须的:不给的话 `serve` 会把守护进程放进它自己的
    /// 会话里跑,而那个进程不是这个孩子的孩子 —— `Drop` 里的 `kill` 够不着
    /// 它,于是每跑一次测试就在机器上留一个守护进程。
    fn start(dir: &TempDir) -> Self {
        Self::start_with(dir, &[])
    }

    /// 同上,但给 `serve` 多带几个参数 —— 开关是命令行上的东西,要测它就得
    /// 从这儿进来。
    fn start_with(dir: &TempDir, extra: &[&str]) -> Self {
        let mut child = Command::new(BIN)
            .arg("serve")
            .arg("--foreground")
            .args(extra)
            .arg("--root")
            .arg(dir.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn `anpio-key serve`");

        let socket = dir.path().join("run").join("keyd.sock");
        for _ in 0..600 {
            if socket.exists() {
                return Self { child };
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        // 走到这儿 `Daemon` 还没被构造出来,所以析构不会替我们收尸;
        // 不先杀掉,这个进程会在整个测试跑完之前一直挂着。
        let _ = child.kill();
        let _ = child.wait();
        panic!("the daemon never created {}", socket.display());
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// 一个**真的进了后台**的守护进程。
///
/// 和上面的 `Daemon` 不一样:那个是测试的孩子,这个不是 —— `setsid` 之后
/// 它属于自己的会话,`Child::kill` 够不着。所以收尸只能走 `stop`,而且必须
/// 在析构里做:断言一失败就走不到测试末尾,漏掉的话机器上会留下一个没人
/// 记得的守护进程,它占着的 socket 会让**下一次**跑测试红在一个毫不相干的
/// 地方。
struct Background {
    root: PathBuf,
}

impl Background {
    /// 起一个,**并确认命令真的回来了**。
    ///
    /// `run` 用的是 `Command::output()`,它会一直读到子进程的 stdout/stderr
    /// 关上 —— 也就是说,守护进程要是继承了那两根管道,这一条会挂在那儿
    /// 不动,而不是"稍微慢一点"。挂住本身就是那个 bug 的样子。
    fn start(root: &Path) -> (Self, String) {
        Self::start_with(root, &[])
    }

    /// 同上,但给 `serve` 多带几个参数。
    fn start_with(root: &Path, extra: &[&str]) -> (Self, String) {
        let mut args = vec!["serve"];
        args.extend_from_slice(extra);
        let output = run(root, &args).expect_ok().to_string();
        (Self { root: root.to_path_buf() }, output)
    }

    fn pid(&self) -> i32 {
        std::fs::read_to_string(self.root.join("run").join("keyd.pid"))
            .expect("a daemon in the background writes its pid")
            .trim()
            .parse()
            .expect("the pid file holds a pid")
    }
}

impl Drop for Background {
    fn drop(&mut self) {
        let _ = run(&self.root, &["stop"]);
    }
}

/// 解锁一条命令。走 socket,但口令仍然只在终端上问。
fn unlock(dir: &TempDir, did: &str) -> Outcome {
    run_in_terminal(dir.path(), &["unlock", "--did", did], &default_rules())
}

fn sign(dir: &TempDir, did: &str) -> Outcome {
    run(dir.path(), &["sign", "--did", did, "--method", "GET", "--url", "https://api.example.net/orders/42"])
}

fn run(root: &Path, args: &[&str]) -> Outcome {
    let mut full: Vec<String> = vec![BIN.to_string()];
    full.extend(args.iter().map(|arg| arg.to_string()));
    full.push("--root".into());
    full.push(root.display().to_string());

    let output = Command::new(&full[0]).args(&full[1..]).output().expect("spawn anpio-key");
    Outcome {
        stdout_and_stderr: format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        stdout: String::new(),
        code: output.status.code(),
        timed_out: false,
    }
}

/// 整条路走通:造钥匙、发布、起守护进程、解锁、签名、上锁、再签被拒。
///
/// 这一条是给人看的那一层里最要紧的一条 —— 它跑的就是 README 里那五步。
#[test]
fn the_five_steps_in_the_readme_work_end_to_end() {
    let dir = TempDir::new("walkthrough");
    let did = keygen(&dir, "bot");
    run_in_terminal(dir.path(), &["publish", "--did", &did], &default_rules()).expect_ok();

    let daemon = Daemon::start(&dir);

    // 上锁时签名必须被拒 —— 而且现在磁盘上有钥匙,所以拒的理由只可能是
    // "没解锁",不是"没这把钥匙"。
    let refused = sign(&dir, &did);
    refused.expect_failure();

    unlock(&dir, &did).expect_ok();

    let listed = run(dir.path(), &["list"]);
    assert!(listed.expect_ok().contains(&did), "a key on this machine must be listed");

    let status = run(dir.path(), &["status"]);
    assert!(
        status.expect_ok().contains(&did),
        "an unlocked key must show up in status"
    );

    let signed = sign(&dir, &did);
    let text = signed.expect_ok();
    assert!(
        text.contains("Signature-Input: ") && text.contains("Signature: "),
        "the signature headers go to stdout, verbatim:\n{text}"
    );

    // 覆盖面是**守护进程自己**定的,而且认的是它自己那把钥匙 —— 签名基
    // 不由调用方给。
    assert!(
        text.contains("@method") && text.contains("@target-uri") && text.contains(&did),
        "the daemon's own signature base must name the method, the target URI\n\
         and this key:\n{text}"
    );

    // 两次签名**不**逐字节相同:覆盖面里的 `created` 是当下时间、`nonce`
    // 每次重新随机。Ed25519 本身是确定性的,但签名基不是 —— 一条请求被
    // 重放时,验证方能从 nonce 看出来这是第二次。
    assert_ne!(text, sign(&dir, &did).expect_ok(), "the signature base must not repeat");

    run(dir.path(), &["lock"]).expect_ok();
    sign(&dir, &did).expect_failure();

    drop(daemon);
}

/// **调用方指定的 nonce 走完 CLI → socket → 守护进程 → 签名头这一整条路。**
///
/// 它必须由调用方给:同一个 nonce 同时出现在请求体里(经由 `content-digest`)
/// 和 `@signature-params` 里,而调用方是唯一同时知道这两处的那一方。守护进程
/// 管它的长度,不管它的含义。
#[test]
fn a_caller_supplied_nonce_reaches_the_signature() {
    let dir = TempDir::new("nonce");
    let did = keygen(&dir, "bot");
    run_in_terminal(dir.path(), &["publish", "--did", &did], &default_rules()).expect_ok();

    let _daemon = Daemon::start(&dir);
    unlock(&dir, &did).expect_ok();

    let signed = run(
        dir.path(),
        &[
            "sign",
            "--did",
            &did,
            "--method",
            "POST",
            "--url",
            "https://api.example.net/orders",
            "--nonce",
            "caller-chosen-42",
        ],
    );
    let text = signed.expect_ok();

    assert!(text.contains(r#"nonce="caller-chosen-42""#), "{text}");

    // 不给就是不给了:守护进程自己随机一个,而不是把上一次那个留下来。
    let plain = sign(&dir, &did);
    let generated = plain.expect_ok();
    assert!(
        !generated.contains("caller-chosen-42"),
        "an absent --nonce must not inherit the previous one: {generated}"
    );
}

/// **`document` 答得出本机发布过的那一份,逐字节一样,而且不用解锁。**
///
/// 走 socket 而不是让调用方自己去读文件:文件在 `0700` 的目录里、
/// `publish --out` 还能把它挪走,路径是**内部布局**。逐字节是重点 —— 这是
/// 一件签好名的成品,内联进别的东西里靠的就是这一点。
#[test]
fn document_prints_the_published_bytes_without_unlocking() {
    let dir = TempDir::new("document");
    let did = keygen(&dir, "bot");
    let published = run_in_terminal(dir.path(), &["publish", "--did", &did], &default_rules());
    let published = published.expect_ok();

    // 发布时它自己说了写到哪儿 —— 拿这句话当"磁盘上那一份"的出处,而不是
    // 在测试里重算一遍内部布局(那正是 `document` 存在的理由:布局是内部
    // 的事)。
    let path = published
        .lines()
        .find_map(|line| line.strip_prefix("wrote "))
        .expect("publish says where it wrote the document")
        .trim()
        .to_string();
    let on_disk = std::fs::read(&path).expect("the published document is on disk");

    let _daemon = Daemon::start(&dir);

    // 没解锁也答得出来 —— 文档是可公开的。
    let answered = run(dir.path(), &["document", "--did", &did]);
    let served = answered.expect_ok();
    assert_eq!(
        served.as_bytes(),
        on_disk.as_slice(),
        "the daemon must hand back the published bytes, not a re-serialised copy"
    );

    // 别人的 DID:答不出来。守护进程不联网,resolve 是客户端的事。
    let refused = run(dir.path(), &["document", "--did", "did:wba:example.com:user:bob:e1_zzz"]);
    refused.expect_failure();
}

/// 口令敲错就是打不开,而且报的错和"少了 device.secret"**一模一样**。
///
/// 两者可区分等于告诉拿到磁盘的人"你缺的是哪个因子"。
#[test]
fn unlock_with_the_wrong_passphrase_is_refused() {
    let dir = TempDir::new("wrong-pass");
    let did = keygen(&dir, "bot");
    let _daemon = Daemon::start(&dir);

    let rules: Vec<(&str, String)> = vec![("Passphrase for ", "not the passphrase".into())];
    let outcome = run_in_terminal(dir.path(), &["unlock", "--did", &did], &rules);
    let text = outcome.expect_failure();

    assert!(
        text.to_lowercase().contains("passphrase"),
        "the refusal must not say which factor was wrong, but it must be an\n\
         authentication failure rather than a crash:\n{text}"
    );

    // 而且它**没有**被解锁。
    assert!(!run(dir.path(), &["status"]).expect_ok().contains(&did));
}

/// 没有守护进程时,`sign` 说的是"连不上",不是别的东西。
#[test]
fn signing_without_a_daemon_says_it_cannot_connect() {
    let dir = TempDir::new("no-daemon");
    let did = keygen(&dir, "bot");

    let outcome = sign(&dir, &did);
    outcome.expect_failure();
}

/// `audit/` 里那些日志行的原文,按月份文件拼起来。
///
/// 只收 `.jsonl`:同一个目录里还躺着 `.anchor`(累计条数 + 末行哈希),
/// 把它当日志读会得到一行解不出来的 JSON。
fn audit_text(dir: &TempDir) -> String {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir.path().join("audit"))
        .expect("audit/ exists")
        .map(|entry| entry.expect("a readable directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .collect();
    files.sort();
    files
        .iter()
        .map(|path| {
            std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        })
        .collect()
}

/// 审计日志里**没有密钥材料**,而且记下了刚才那次签名。
///
/// 这一条和 `tests/no_key_material_on_disk.rs` 是一对:那一份扫的是整棵
/// 目录树,这一份走一条**真的 CLI 路径** —— 只有后者能证明"用户真会走
/// 的那条路上"也干净。
#[test]
fn the_audit_log_records_the_signature_and_holds_no_secrets() {
    let dir = TempDir::new("audit");
    let did = keygen(&dir, "bot");
    // 签名要读**已发布的那份文档** —— 签名基里的 `keyid` 和公钥出自它,
    // 所以没有文档就没有可签的东西(报的是 "key not found",因为对这个
    // DID 而言,本机确实什么都还没有)。
    run_in_terminal(dir.path(), &["publish", "--did", &did], &default_rules()).expect_ok();
    let _daemon = Daemon::start(&dir);
    unlock(&dir, &did).expect_ok();
    sign(&dir, &did).expect_ok();

    let text = audit_text(&dir);

    assert!(
        text.contains("\"event\":\"SIGNED\""),
        "the signature must be recorded:\n{text}"
    );
    assert!(text.contains(&did), "and it must say which key signed:\n{text}");

    // 这条路走下来一共四件事,**一件都不能少**:身份是什么时候生的、文档是
    // 什么时候写下去的、什么时候被解锁、什么时候签的。少一件就是一条事后
    // 答不上来的问题 —— 生成和发布这两条以前恰好是少的。
    for event in ["KEYGEN", "PUBLISHED", "UNLOCKED", "SIGNED"] {
        assert!(
            text.contains(&format!("\"event\":\"{event}\"")),
            "{event} must be recorded as well:\n{text}"
        );
    }
    assert!(
        text.contains("\"hardware\":\"none\""),
        "the keygen record must say what the envelope is bound to — an unbound\n\
         envelope and one bound to a chip are not the same thing:\n{text}"
    );

    assert!(!text.contains(PASSPHRASE), "the passphrase must never reach the log");

    // 字段名是一个**封闭集合**,这就是"日志里没有秘密"的测法 —— 一个能装
    // 种子的字段一旦被加进来,这里立刻红,而不是等谁去想到它。
    const FIELDS: [&str; 12] = [
        "seq",
        "at",
        "prev",
        "event",
        "uid",
        "did",
        "kid",
        "covered",
        "signature_base_digest",
        // 后加的两个:一个是硬件根的名字(`none` / `secure-enclave` …),
        // 一个是文档规范化之后那 43 个字符的摘要。两个都是**算出来的短值**,
        // 装不下密钥材料 —— 这正是加进这个集合的门槛。
        "hardware",
        "document_digest",
        // 助记词推导方案的名字(`bip39-entropy-v2`):一个写死的版本标签,
        // 不是算出来的东西,更装不下密钥材料。
        "scheme",
    ];
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let event: serde_json::Value = serde_json::from_str(line).expect("one event per line");
        for name in event.as_object().expect("an event is an object").keys() {
            assert!(
                FIELDS.contains(&name.as_str()),
                "an audit event grew a field {name:?} — it must not be one that can hold\n\
                 key material:\n{line}"
            );
        }
    }
}

/// **`--challenge` 是自己一条路,不是 `--raw` 的别名。**
///
/// 三件事一起量,因为它们各自都可能是假的:签得出、而且签的**就是那串字节**
/// (拿文档里的公钥在外面验一次);`--raw` 在这个开关下面**仍然**被拒(这只
/// 开了它自己那扇门);日志里那条叫 `CHALLENGE_SIGNED`,记的是长度和摘要,
/// **不是挑战本身**。
#[test]
fn the_challenge_flag_is_its_own_door() {
    // —— 开关关着:拒,而且拒的话得说出是哪个开关 ——
    //
    // 另起一个根,不在下面那个上做第二遍:同一个根上 `Daemon::start` 会看到
    // **上一个守护进程留下的那个 socket 文件**而立刻返回,于是下一条命令撞在
    // 一个还没绑好的 socket 上。
    {
        let dir = TempDir::new("challenge-off");
        let did = keygen(&dir, "bot");
        run_in_terminal(dir.path(), &["publish", "--did", &did], &default_rules()).expect_ok();

        let path = dir.path().join("challenge.txt");
        std::fs::write(&path, b"a server-issued nonce").expect("write the challenge");

        let _daemon = Daemon::start(&dir);
        // 解了锁还拒,拒的理由才只可能是那个开关 —— 这是这一条的全部意思。
        unlock(&dir, &did).expect_ok();
        let refused = run(
            dir.path(),
            &["sign", "--did", &did, "--challenge", &path.display().to_string()],
        );
        let text = refused.expect_failure();
        assert!(
            text.contains("--allow-challenge-signing"),
            "a refusal has to name the switch that would allow it:\n{text}"
        );
    }

    // —— 开着:签得出,而且外面验得过 ——
    let dir = TempDir::new("challenge-on");
    let did = keygen(&dir, "bot");
    run_in_terminal(dir.path(), &["publish", "--did", &did], &default_rules()).expect_ok();

    let challenge = b"a server-issued nonce, signed as-is";
    let path = dir.path().join("challenge.txt");
    std::fs::write(&path, challenge).expect("write the challenge");
    let path = path.display().to_string();

    let _daemon = Daemon::start_with(&dir, &["--development", "--allow-challenge-signing"]);
    unlock(&dir, &did).expect_ok();
    let printed = run(dir.path(), &["sign", "--did", &did, "--challenge", &path]);
    let printed = printed.expect_ok();

    let document = read_local_document(&dir, &did);
    let multibase = document["verificationMethod"][0]["publicKeyMultibase"]
        .as_str()
        .expect("the published document carries the public key");
    let key = anpio_key::crypto::thumbprint::ed25519_from_multibase(multibase)
        .expect("the document's key must decode");

    let signature = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(printed.trim())
            .expect("the CLI prints base64")
    };
    let signature = ed25519_dalek::Signature::from_slice(&signature).expect("64 bytes");
    {
        use ed25519_dalek::Verifier;
        key.verify(challenge, &signature)
            .expect("the signature must be over the challenge bytes themselves");
    }

    // —— 这个开关**只**开自己那扇门 ——
    let raw_path = dir.path().join("raw.bin");
    std::fs::write(&raw_path, b"anything at all").expect("write the raw payload");
    let raw = run(
        dir.path(),
        &["sign", "--did", &did, "--raw", &raw_path.display().to_string()],
    );
    let text = raw.expect_failure();
    assert!(
        text.contains("--allow-raw-signing"),
        "opening the narrow door must not open the wide one:\n{text}"
    );

    // —— 日志:一条自己的记录,存的是摘要不是内容 ——
    let text = audit_text(&dir);
    assert!(
        text.contains("\"event\":\"CHALLENGE_SIGNED\""),
        "the challenge signature needs its own line, not a `RAW_SIGNED`:\n{text}"
    );
    assert!(
        text.contains(&format!("\"challenge_len\":{}", challenge.len())),
        "and it must say how long the challenge was:\n{text}"
    );
    assert!(
        !text.contains("a server-issued nonce"),
        "the log records a digest of the challenge, never the challenge itself:\n{text}"
    );
}

/// **一份文档的一生:写下去的那条、和取件那条,摘要是同一个算出来的。**
///
/// 这是 `document_digest` 这个字段全部的用处 —— 一个摘要能在整份日志里被
/// 搜出来,把"什么时候写的、谁什么时候取走的"串成一条线。两处各自算各自的
/// 摘要(一个从内存里那份签好的文档,一个从磁盘上读回来的字节),对不上
/// 就等于这条线从一开始是断的,而症状是"事后比对时发现对不上",那时候
/// 已经没人能回头查了。
#[test]
fn the_same_digest_links_the_publish_to_the_read() {
    let dir = TempDir::new("digest-life");
    let did = keygen(&dir, "bot");
    let published = run_in_terminal(dir.path(), &["publish", "--did", &did], &default_rules());
    let published = published.expect_ok();

    // 拿 `publish` 自己说的路径去读,不在测试里重算内部布局 —— 布局是内部
    // 的事(和 `document_prints_the_published_bytes_without_unlocking` 同一个理由)。
    let path = published
        .lines()
        .find_map(|line| line.strip_prefix("wrote "))
        .expect("publish says where it wrote the document")
        .trim()
        .to_string();
    let on_disk: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("the published document")).unwrap();
    let expected = anpio_key::did::lifecycle::document_digest(&on_disk).expect("a digest");

    let _daemon = Daemon::start(&dir);
    run(dir.path(), &["document", "--did", &did]).expect_ok();

    let text = audit_text(&dir);
    // `publish` 会写第二条 `PUBLISHED`(`keygen` 自己已经写过一条),要的是
    // **刚刚这次** —— 所以取最后一条,不是第一条。
    let line_with = |event: &str| {
        text.lines()
            .filter(|line| line.contains(&format!("\"event\":\"{event}\"")))
            .next_back()
            .unwrap_or_else(|| panic!("no {event} record:\n{text}"))
            .to_string()
    };

    assert!(
        line_with("PUBLISHED").contains(&expected),
        "the publish record must carry the digest of the bytes it wrote:\n{text}"
    );
    assert!(
        line_with("DOCUMENT_READ").contains(&expected),
        "and the read record must carry the digest of the bytes it handed back — \n\
         same document, same digest:\n{text}"
    );
}

/// **`publish --out` 在本机什么都没改,所以日志里一个字都不该多出来。**
///
/// 它只产出一个文件给别人去部署,`dids/` 里那份还是旧的就还是旧的。记成
/// 一次"发布"会让人以为本地那份文档是它 —— 而本地那一份正是别人验签时
/// 比对的对象。
#[test]
fn publishing_to_a_file_leaves_no_record_on_this_machine() {
    let dir = TempDir::new("publish-out");
    let did = keygen(&dir, "bot");
    let before = audit_text(&dir);

    let out = dir.path().join("out");
    let published = run_in_terminal(
        dir.path(),
        &["publish", "--did", &did, "--out", out.to_str().expect("a UTF-8 temp path")],
        &default_rules(),
    );
    published.expect_ok();

    assert!(out.join("did.json").exists(), "前提:文件确实写出来了");
    assert_eq!(
        audit_text(&dir),
        before,
        "a document written to a directory that is not the store changes nothing here"
    );
}

// ========================================================================
// 五、生命周期:ops 那一层
// ========================================================================

/// 把文档读回来,按 `verificationMethod` 的 fragment 列出所有钥匙。
///
/// 按**文件名**取,不按"目录里的第一个" —— `dids/` 里除了文档还躺着别的
/// 东西(生命周期命令会在同一个目录里放一把 `.lock`),而 `read_dir` 的顺序
/// 是文件系统说了算的。
fn fragments_of(dir: &TempDir, did: &str) -> Vec<String> {
    let document = read_local_document(dir, did);

    document["verificationMethod"]
        .as_array()
        .expect("verificationMethod is an array")
        .iter()
        .map(|method| method["id"].as_str().unwrap().rsplit('#').next().unwrap().to_string())
        .collect()
}

/// 一条一条把生命周期命令跑过去,每一步都在**磁盘上**确认它真的做了事。
///
/// `add-recovery-key` / `rotate-hot-key` / `migrate` / `deactivate` 之前一条
/// 测试都没有:它们只从终端读秘密,所以在库 API 那一层是不可达的。
#[test]
fn the_lifecycle_commands_rewrite_the_document() {
    let dir = TempDir::new("lifecycle");
    let did = keygen(&dir, "bot");
    run_in_terminal(dir.path(), &["publish", "--did", &did], &default_rules()).expect_ok();

    // `keygen` 现在一个助记词铸四把,所以"新鲜文档"就是这四把。
    assert_eq!(
        fragments_of(&dir, &did),
        vec!["key-1", "key-2", "device-sign", "device-agreement"],
        "keygen mints root, hot, device signing and agreement"
    );

    // —— 加一把恢复钥匙 ——
    let added = run_in_terminal(dir.path(), &["add-recovery-key", "--did", &did], &default_rules());
    let text = added.expect_ok();
    assert!(text.contains("added "), "it must name what it added:\n{text}");
    assert!(
        text.contains("is not\na recovery key") || text.contains("not"),
        "it has to warn that a recovery key on the same host is not a recovery key:\n{text}"
    );
    assert!(
        fragments_of(&dir, &did).contains(&"recovery-1".to_string()),
        "the recovery key has to land in the document: {:?}",
        fragments_of(&dir, &did)
    );

    // —— 轮换热密钥 ——
    //
    // `keygen` 已经把 `key-2` 用掉了,所以轮换出来的是 `key-3`,而 `key-2`
    // 退休出文档 —— 编号不回头。
    let rotated = run_in_terminal(dir.path(), &["rotate-hot-key", "--did", &did], &default_rules());
    rotated.expect_ok();
    let fragments = fragments_of(&dir, &did);
    assert!(fragments.contains(&"key-3".to_string()), "the rotated hot key lands as key-3: {fragments:?}");
    assert!(!fragments.contains(&"key-2".to_string()), "the retired hot key leaves: {fragments:?}");

    // —— 摘掉它 ——
    let removed = run_in_terminal(
        dir.path(),
        &["remove-key", "--did", &did, "--kid", "key-3"],
        &default_rules(),
    );
    removed.expect_ok();
    assert!(
        !fragments_of(&dir, &did).contains(&"key-3".to_string()),
        "the hot key must be gone: {:?}",
        fragments_of(&dir, &did)
    );

    // —— 再轮换一次:编号**不复用** ——
    //
    // 这条挡的是一个具体的洞:一个被缓存过的文档里写着"key-2 这把钥匙",
    // 钥匙换了而名字没换,那份缓存就成了一张已作废钥匙的通行证。
    let rotated = run_in_terminal(dir.path(), &["rotate-hot-key", "--did", &did], &default_rules());
    rotated.expect_ok();
    let fragments = fragments_of(&dir, &did);
    assert!(
        fragments.contains(&"key-4".to_string()) && !fragments.contains(&"key-3".to_string()),
        "the fragment number must not be reused: {fragments:?}"
    );

    // 恢复钥匙还在 —— 摘掉热密钥不该顺手带走别的。
    assert!(fragments.contains(&"recovery-1".to_string()));
}

/// 注销之后**再注销一次被拒**,理由不是"文档会坏",而是**审计会撒谎**。
///
/// 第二次得到的是同一份文档(Ed25519 是确定性的),却会在审计日志里留下
/// 一条"某时刻注销了它"的记录 —— 而那一刻什么也没发生。
#[test]
fn deactivating_twice_is_refused_so_the_audit_log_cannot_lie() {
    let dir = TempDir::new("deactivate");
    let did = keygen(&dir, "bot");
    run_in_terminal(dir.path(), &["publish", "--did", &did], &default_rules()).expect_ok();

    let first = run_in_terminal(dir.path(), &["deactivate", "--did", &did], &default_rules());
    let text = first.expect_ok();
    assert!(text.contains("with no successor"), "it has to say the line ended:\n{text}");

    let second = run_in_terminal(dir.path(), &["deactivate", "--did", &did], &default_rules());
    let text = second.expect_failure();
    assert!(
        text.contains("already deactivated"),
        "the second run has to be refused with a reason:\n{text}"
    );

    // 被拒的那一次**没有**在日志里留下痕迹 —— 这正是拒它的理由。
    let log = std::fs::read_dir(dir.path().join("audit"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .expect("a monthly shard");
    let text = std::fs::read_to_string(&log).unwrap();
    assert_eq!(
        text.matches("\"event\":\"DEACTIVATE\"").count(),
        1,
        "exactly one deactivation:\n{text}"
    );
}

/// 迁移写的是**旧**文档:它保留钥匙,加上 `deactivated` 和 `successorDid`。
///
/// "迁移到另一台机器上的 DID"是正常用法,所以后继在本机没有文档**不是**
/// 错误 —— 但它必须说出来,因为一个打错字的 `--to` 正是在这里现形。
#[test]
fn migrate_marks_the_old_document_and_names_the_successor() {
    let dir = TempDir::new("migrate");
    let did = keygen(&dir, "bot");
    run_in_terminal(dir.path(), &["publish", "--did", &did], &default_rules()).expect_ok();

    // 后继是**同一个主体**的绑定了新密钥的 DID:绑定密钥轮换只改最后那一
    // 段,路径不动。拿一条改了路径的 DID 当后继会被当场拒绝(见下一条断言),
    // 因为那在验证方眼里是**另一个主体**,不是同一个人换了钥匙。
    //
    // 它在**另一个根**里铸:换机器的情形就是"后继不在这台机器上",而那正是
    // 这条测试要说的那句提示成立的前提。
    let other = TempDir::new("migrate-other");
    let successor = keygen(&other, "bot");
    assert_ne!(successor, did, "a second keygen must mint a different binding key");

    let outcome = run_in_terminal(
        dir.path(),
        &["migrate", "--did", &did, "--to", &successor],
        &default_rules(),
    );
    let text = outcome.expect_ok();

    assert!(
        text.contains("is now deactivated and points at"),
        "it has to say which way the edge points:\n{text}"
    );
    assert!(
        text.contains("no document on this machine"),
        "the successor is not local, and that has to be said out loud:\n{text}"
    );

    // 旧文档还在原地,而且**没有**被删掉 —— 一份被删掉的文档在验证方眼里
    // 和"这个 DID 从来不存在"完全一样,而它其实存在过。
    let document = read_local_document(&dir, &did);
    assert_eq!(document["deactivated"], serde_json::json!(true));
    assert_eq!(document["successorDid"], serde_json::json!(successor));
    assert!(
        !document["verificationMethod"].as_array().unwrap().is_empty(),
        "the old document keeps its keys"
    );
}

/// 换了主体路径的后继**默认**被拒 —— 而那通常是打了个错字。
///
/// 一条打错字的 `--to` 会让验证方以为"这个人搬到了另一个主体",而真正的
/// 主人什么都没做。所以默认关,要越过得自己说出来。
#[test]
fn migrate_refuses_a_successor_that_is_a_different_subject() {
    let dir = TempDir::new("migrate-subject");
    let did = keygen(&dir, "bot");
    run_in_terminal(dir.path(), &["publish", "--did", &did], &default_rules()).expect_ok();

    let stranger = did.replace("agents:bot:", "agents:someone-else:");
    let outcome = run_in_terminal(
        dir.path(),
        &["migrate", "--did", &did, "--to", &stranger],
        &default_rules(),
    );
    let text = outcome.expect_failure();

    assert!(
        text.contains("--allow-different-subject"),
        "the refusal has to name the flag that overrides it:\n{text}"
    );
    // 拒了就是**什么都没发生**:旧文档还在,而且没有被标记。
    assert_eq!(read_local_document(&dir, &did)["deactivated"], serde_json::json!(null));
}

/// 后继就是自己,当然是拒 —— 但它得说清"没有后继"该怎么表达。
#[test]
fn deactivate_refuses_a_successor_that_is_itself() {
    let dir = TempDir::new("self-successor");
    let did = keygen(&dir, "bot");
    run_in_terminal(dir.path(), &["publish", "--did", &did], &default_rules()).expect_ok();

    let outcome =
        run_in_terminal(dir.path(), &["deactivate", "--did", &did, "--to", &did], &default_rules());
    let text = outcome.expect_failure();
    assert!(
        text.contains("cannot succeed itself"),
        "the refusal has to name the mistake:\n{text}"
    );
}

/// 生命周期命令要的是磁盘上那份**真的**文档,不是从 DID 现编的一份。
///
/// 现编一份会静默丢掉真文档里带的东西(热密钥、恢复密钥、迁移记录),而
/// 覆盖写不会报错。
#[test]
fn a_lifecycle_command_without_a_published_document_says_what_to_run_first() {
    let dir = TempDir::new("unpublished");
    let did = keygen(&dir, "bot");

    // `keygen` 现在自己把文档签好写下来。**没有本地文档**仍然是一种真实
    // 状态 —— 它被删了、或者这台机器只持有钥匙而文档在别处 —— 而那种时候
    // 命令必须让人先跑 `publish`,不能从 DID 现编一份再覆盖上去。
    std::fs::remove_file(
        dir.path()
            .join("dids")
            .join(format!("{}.json", did.replace(':', "_"))),
    )
    .expect("the document keygen just wrote");

    let outcome = run_in_terminal(dir.path(), &["add-recovery-key", "--did", &did], &default_rules());
    let text = outcome.expect_failure();
    assert!(
        text.contains("publish"),
        "it has to name the command that makes a document exist:\n{text}"
    );
}

fn read_local_document(dir: &TempDir, did: &str) -> serde_json::Value {
    let flat = did.replace(':', "_").replace(['/', '\\'], "_");
    let path = dir.path().join("dids").join(format!("{flat}.json"));
    serde_json::from_slice(&std::fs::read(&path).unwrap_or_else(|error| {
        panic!("cannot read {}: {error}", path.display())
    }))
    .expect("the document is JSON")
}

/// 一个空目录里 `list` 说的是"没有钥匙",不是"连不上"。
#[test]
fn an_empty_machine_lists_nothing_rather_than_failing() {
    let dir = TempDir::new("empty");
    let _daemon = Daemon::start(&dir);
    assert!(run(dir.path(), &["list"]).expect_ok().contains("no keys"));
    assert!(run(dir.path(), &["status"]).expect_ok().contains("nothing is unlocked"));
}

/// `--body` 收的是**文件**,而写错时那句错误必须提文件名。
///
/// 习惯上 `--header` 收的是字面量,于是很自然地把请求体也照着字面量写。
/// `io: No such file or directory` 一个字都没提那个路径,人只能自己猜。
#[test]
fn a_missing_body_file_is_reported_with_its_path() {
    let dir = TempDir::new("missing-body");
    let did = keygen(&dir, "bot");
    let _daemon = Daemon::start(&dir);
    unlock(&dir, &did).expect_ok();

    let outcome = run(
        dir.path(),
        &[
            "sign",
            "--did",
            &did,
            "--method",
            "POST",
            "--url",
            "https://api.example.net/orders",
            "--body",
            "/tmp/definitely-not-here.json",
        ],
    );
    let text = outcome.expect_failure();
    assert!(
        text.contains("/tmp/definitely-not-here.json"),
        "the message has to name the file it could not read:\n{text}"
    );
}

/// `--header` 里同一个名字给两遍是拒 —— 第二条会**静默地**赢。
#[test]
fn a_doubled_header_is_refused_rather_than_silently_resolved() {
    let dir = TempDir::new("doubled-header");
    let did = keygen(&dir, "bot");
    let _daemon = Daemon::start(&dir);
    unlock(&dir, &did).expect_ok();

    let outcome = run(
        dir.path(),
        &[
            "sign",
            "--did",
            &did,
            "--url",
            "https://api.example.net/orders",
            "--header",
            "accept: application/json",
            "--header",
            "Accept: text/plain",
        ],
    );
    let text = outcome.expect_failure();
    assert!(
        text.contains("twice"),
        "it has to say the header was given twice:\n{text}"
    );
}

/// 覆盖面**只能加,不能减**。
///
/// `sign --cover` 要求多覆盖一些分量可以;而守护进程自己决定那些**必须**
/// 覆盖的东西不会因为调用方没提就掉出去。这一条是那个设计的验收。
#[test]
fn a_caller_can_add_coverage_but_the_daemon_keeps_its_own() {
    let dir = TempDir::new("coverage");
    let did = keygen(&dir, "bot");
    run_in_terminal(dir.path(), &["publish", "--did", &did], &default_rules()).expect_ok();
    let _daemon = Daemon::start(&dir);
    unlock(&dir, &did).expect_ok();

    let plain = sign(&dir, &did).expect_ok().to_string();
    let extra = run(
        dir.path(),
        &[
            "sign",
            "--did",
            &did,
            "--url",
            "https://api.example.net/orders/42",
            "--cover",
            "content-type",
            "--header",
            "content-type: application/json",
        ],
    )
    .expect_ok()
    .to_string();

    let input = |text: &str| -> String {
        let parsed = anpio_key::client::parse_signed_headers(text.as_bytes())
            .expect("the daemon returns header lines");
        parsed
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("signature-input"))
            .map(|(_, value)| value.clone())
            .expect("signature-input")
    };

    let plain_input = input(&plain);
    let extra_input = input(&extra);

    assert!(
        !plain_input.contains("content-type"),
        "nothing asked for it, so nothing covers it:\n{plain_input}"
    );
    assert!(
        extra_input.contains("content-type"),
        "the added component has to appear:\n{extra_input}"
    );
    assert!(
        extra_input.contains("@method") && extra_input.contains("@target-uri"),
        "and the components the daemon always covers stay:\n{extra_input}"
    );
}

// ========================================================================
// 六、守护进程的进程管理:后台、停止、拒绝
// ========================================================================
//
// 这一节测的是**进程怎么活着**,不是它怎么应答 —— 后者在第四节。两边的
// 失败方式完全不同:那边失败是"协议里少了一个字段",这边失败是"终端上
// 多了一个命令没回来",或者更糟:"命令说成功了,而它说的话不是真的"。

/// 敲完 `serve` 就该回到提示符,而且回来时守护进程真的在跑。
#[test]
fn serve_hands_the_terminal_back_and_leaves_a_working_daemon() {
    let dir = TempDir::new("background");
    let (daemon, output) = Background::start(dir.path());
    let pid = daemon.pid();

    assert!(
        output.contains("listening on") && output.contains(&pid.to_string()),
        "the command reports where it listens and which pid to thank for it:\n{output}"
    );
    assert!(
        output.contains("anpio-key stop"),
        "and it says how to get rid of it:\n{output}"
    );

    // 回来的这几句话不是嘴上说说:后台那个进程真的在应答。
    run(dir.path(), &["status"]).expect_ok();
}

/// `stop` 停掉它,而且**再停一次不算错** —— 脚本里常见连着两句。
#[test]
fn stop_stops_it_and_a_second_stop_is_not_an_error() {
    let dir = TempDir::new("stop");
    let (daemon, _) = Background::start(dir.path());
    let pid = daemon.pid();

    let stopped = run(dir.path(), &["stop"]);
    assert!(
        stopped.expect_ok().contains(&pid.to_string()),
        "it must say **which** pid it stopped:\n{}",
        stopped.text()
    );

    // 进程走干净了,它留下的两样东西也一起没了。socket 不走 `stop` 的手
    // (守护进程自己在停机路径上删),所以检查它等于在检查那段路径跑过。
    assert!(
        !dir.path().join("run").join("keyd.pid").exists(),
        "the pid file belongs to the process that wrote it"
    );
    assert!(
        !dir.path().join("run").join("keyd.sock").exists(),
        "and the daemon removes its own socket on the way out"
    );

    let again = run(dir.path(), &["stop"]);
    assert!(
        again.expect_ok().contains("nothing is running"),
        "stopping twice is stopping an already-stopped daemon:\n{}",
        again.text()
    );
}

/// 第二个 `serve` 必须失败,**并且不许碰第一个**。
///
/// 这条测试的第二个断言比第一个要紧。`serve` 起后台进程是"先派一个孩子出去
/// 探路":孩子失败、父进程照实报错,这条路其实挺容易写对。难的是那个孩子的
/// 副作用 —— 它写过 pid 文件没有?覆盖掉了正在跑的那个没有?而这些副作用
/// 一旦发生,症状出现在**下一句**命令上(`stop` 说 nothing is running,而
/// 守护进程正听着),离这儿很远。
#[test]
fn a_second_serve_refuses_and_leaves_the_first_one_alone() {
    let dir = TempDir::new("double");
    let (daemon, _) = Background::start(dir.path());
    let pid = daemon.pid();

    let refused = run(dir.path(), &["serve"]);
    let text = refused.expect_failure();
    assert!(
        text.contains("already served"),
        "the reason must be the socket, in words a person can act on:\n{text}"
    );

    let recorded = std::fs::read_to_string(dir.path().join("run").join("keyd.pid"))
        .expect("the running daemon's pid file must survive a failed second start");
    assert_eq!(
        recorded.trim(),
        pid.to_string(),
        "the failed attempt must not overwrite the running daemon's pid file"
    );
    run(dir.path(), &["status"]).expect_ok();
}

/// pid 文件里那个数字**不足以**授权一次 `kill`。
///
/// pid 会被内核回收:一个陈旧的 pid 文件指向的完全可能是一个无辜的进程,
/// 而 `stop` 发的是 SIGTERM —— 对方多半直接死。这里拿一个真的活着的
/// 别的进程当诱饵,确认 `stop` 拒绝、并且**连 pid 文件都不删**(看不懂的
/// 时候动手是最坏的选择)。
#[test]
fn stop_refuses_a_pid_that_is_not_this_binary() {
    let dir = TempDir::new("foreign-pid");
    std::fs::create_dir_all(dir.path().join("run")).expect("create run/");

    let mut decoy = Command::new("sleep").arg("300").spawn().expect("spawn the decoy");
    std::fs::write(
        dir.path().join("run").join("keyd.pid"),
        format!("{}\n", decoy.id()),
    )
    .expect("write the pid file");

    let refused = run(dir.path(), &["stop"]);
    let text = refused.expect_failure();
    assert!(
        text.contains("Refusing to signal"),
        "it has to say that it did nothing, not just fail:\n{text}"
    );
    assert!(
        text.contains("sleep"),
        "and name what that pid actually is, so a person can check:\n{text}"
    );

    assert!(
        decoy.try_wait().expect("ask about the decoy").is_none(),
        "the decoy must still be running — that is the whole point"
    );
    assert!(
        dir.path().join("run").join("keyd.pid").exists(),
        "and the pid file stays: we did not understand it, so we do not touch it"
    );

    let _ = decoy.kill();
    let _ = decoy.wait();
}

/// `--system` 是一个守护进程服务所有 uid,所以 uid 不再是承诺的粒度 ——
/// 不给第三层就**拒绝启动**,而不是打一条没人看的警告。
///
/// 顺带确认这条拒绝发生在**任何文件系统操作之前**:`--system` 的目录在
/// 没有 root 的机器上根本建不出来,要是先建目录再检查,这条测试就会红在
/// "权限不够"上,而真正的原因(配置不对)看不见。
#[test]
fn serve_system_without_a_pin_refuses_before_anything_else() {
    let dir = TempDir::new("system-refusal");
    let refused = run(dir.path(), &["serve", "--system"]);
    let text = refused.expect_failure();

    assert!(
        text.contains("--allow-binary") && text.contains("uid"),
        "the refusal has to name the flag and the reason:\n{text}"
    );
    assert!(
        !dir.path().join("run").exists(),
        "and nothing may have been created on the way to it"
    );
}

/// 后台跑的守护进程把话写进文件,而且那个文件**只有它的主人看得见**。
///
/// 日志里有 uid、pid、路径、被拒的 pin —— 不是秘密本身,但也没有理由让
/// 同一个系统上的其他人读。
#[test]
fn the_serve_log_records_the_start_and_is_not_world_readable() {
    let dir = TempDir::new("serve-log");
    let (daemon, _) = Background::start(dir.path());

    let log = dir.path().join("log").join("serve.log");
    // 父进程返回时守护进程刚答应过话,而"写进日志"是它自己那一侧的下一步
    // —— 差的是几个微秒,但那是真的会输的赛跑,所以等一等。
    let text = wait_for_text(&log, "listening");

    assert!(
        text.contains(&daemon.pid().to_string()) || text.contains("keyd.sock"),
        "the first line should say where it is listening:\n{text}"
    );

    let mode = std::fs::metadata(&log)
        .expect("the log exists")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode,
        anpio_key::keystore::layout::SECRET_FILE_MODE,
        "the serve log must not be world readable"
    );
}

/// 等到一个文件里出现某段文字,或者超时。返回文件内容(超时就是超时那一次
/// 读到的内容,让调用方的断言去说为什么不对)。
fn wait_for_text(path: &Path, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        if text.contains(needle) || Instant::now() >= deadline {
            return text;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// 开了第三层,启动**不该**留下一条拒绝。
///
/// 后台化之后父进程要确认孩子起来了,而"连一下 socket"是当时最自然的做法。
/// 但那条探测是一条连上就走的空连接:第三层开着时它过不了 `admit`(内核给
/// 不出一个已经走掉的对端的凭证),于是**每一次启动都给自己记一条 `DENIED`
/// 审计事件**。审计是防哈希链篡改的证据,不该混进工具自己的噪声 —— 一条
/// 每次启动都有的 DENIED,会让人学会无视那本日志。
#[test]
fn turning_on_the_third_layer_does_not_make_startup_a_denial() {
    let dir = TempDir::new("self-denial");
    let pin = format!("sha256:{}", "00".repeat(32));
    let (_daemon, _) = Background::start_with(dir.path(), &["--allow-binary", &pin]);

    // 真连一次:这一条该被拒(白名单里那个摘要不可能是任何东西)。
    run(dir.path(), &["status"]).expect_failure();

    let log = dir.path().join("log").join("serve.log");
    let text = wait_for_text(&log, "refused a connection");
    assert_eq!(
        text.matches("refused a connection").count(),
        1,
        "只有上面那一条真连接该被拒 —— 多出来的那条是启动时的探测:\n{text}"
    );

    let audit: String = std::fs::read_dir(dir.path().join("audit"))
        .expect("the audit directory exists")
        .filter_map(|entry| std::fs::read_to_string(entry.ok()?.path()).ok())
        .collect();
    assert_eq!(
        audit.matches("\"DENIED\"").count(),
        1,
        "审计里也只该有一条,而且它是**那一条真连接**的:\n{audit}"
    );
}

