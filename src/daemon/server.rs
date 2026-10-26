//! Unix socket 主循环：接受连接、认人、一条一条地应答。
//!
//! ## 一条连接一个线程,因为这里的每一件事都是阻塞的
//!
//! 处理一条请求要跑一次 Argon2id(故意慢)、读几次文件、签一次名 —— 全是
//! 阻塞活儿。把它们塞进异步任务里,等于用一个假的 yield 点骗自己,实际
//! 还是把 runtime 的 worker 焊在那里。所以 accept 用 tokio(为了和信号、
//! 定时器待在一起),连接一到手就 `into_std()` 交给 `spawn_blocking`,
//! 在那条连接里从头到尾用同步 I/O。
//!
//! **接线只有一次。** 对端身份在连接建立时取一次,之后整条连接都用它。
//! 每次请求都去重取一遍不会更安全(内核给的东西不会变),但会让"我到底
//! 按哪一次的结果授权的"这个问题重新变得有得可争。

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::UnixListener;
use tokio::sync::watch;

use crate::audit::Event;
use crate::daemon::peer::{binary_identity, peer_identity, self_uid, PeerPolicy};
use crate::daemon::state::DaemonState;
use crate::daemon::{handlers, wire};
use crate::error::{KeydError, Result};

/// socket 路径的长度上限,**含结尾的 NUL**。
///
/// `sockaddr_un.sun_path` 是定长数组:Linux 上 108,BSD(含 macOS)上
/// 104。取小的那个,这样这条检查在两种系统上都成立,而不会在 macOS 上
/// 放过去、到内核那儿才炸。
const SUN_PATH_MAX: usize = 104;

/// 监听什么、认谁。
pub struct ServerConfig {
    pub sock_path: PathBuf,
    pub policy: PeerPolicy,
}

/// 跑起来,直到收到停机信号。
///
/// 返回时 socket 文件已经删掉、内存里的钥匙已经全部放掉。
pub async fn serve(state: Arc<DaemonState>, config: ServerConfig, stop: watch::Receiver<bool>) -> Result<()> {
    let listener = bind(&config.sock_path)?;
    serve_on(state, config, stop, listener).await
}

/// 用**已经绑好的** listener 跑起来。
///
/// 和 [`serve`] 分开,是为了让 `serve` 那条路能把"绑定"插在"写 pid 文件"
/// 前面:绑定成功才是这个 socket 的守护进程,所以"我在这个 pid 上"这句话
/// 只有绑上了才配写下来。顺序反过来的话,一个注定失败的第二个 `serve`
/// 会先覆盖**正在跑的那个**的 pid 文件,再在退出时把它删掉 —— 于是 `stop`
/// 会对着一个活得好好的守护进程说"nothing is running"。
pub async fn serve_on(
    state: Arc<DaemonState>,
    config: ServerConfig,
    mut stop: watch::Receiver<bool>,
    listener: std::os::unix::net::UnixListener,
) -> Result<()> {
    let listener = as_tokio(listener)?;
    tracing::info!(sock = %config.sock_path.display(), "listening");

    let sweeper = {
        let state = Arc::clone(&state);
        let sweep_stop = stop.clone();
        tokio::spawn(async move { sweep_until_stopped(state, sweep_stop).await })
    };

    let outcome = accept_loop(&state, &config, &listener, &mut stop).await;

    // 停机:先停清扫,再收钥匙,最后删 socket。
    sweeper.abort();
    state.lock_everything();

    // 删 socket 文件。**不忽略失败** —— 留一个没人听的 socket 在那儿,
    // 下一次启动要靠"连一下试试"才能判断它是死的,而那个判断本身
    // 就是把决定权交给了一个可能刚好在重启的竞争对手。
    if let Err(error) = std::fs::remove_file(&config.sock_path) {
        if error.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(sock = %config.sock_path.display(), "could not remove the socket: {error}");
        }
    }

    outcome
}

async fn accept_loop(
    state: &Arc<DaemonState>,
    config: &ServerConfig,
    listener: &UnixListener,
    stop: &mut watch::Receiver<bool>,
) -> Result<()> {
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            outcome = stop.changed() => {
                // 通道关掉和"收到停机"是同一件事:发信号的那位不在了,
                // 这台机器上再没有别人会告诉我们什么时候停。
                if outcome.is_err() || *stop.borrow() {
                    tracing::info!("stopping");
                    return Ok(());
                }
                continue;
            }
        };

        match accepted {
            Ok((stream, _addr)) => {
                let state = Arc::clone(state);
                let policy = config.policy.clone();
                tokio::spawn(async move {
                    // 连接一到手就离开 async 世界:后面的活儿全是阻塞的。
                    //
                    // **必须显式关掉非阻塞。** accept 出来的 fd 继承 listener
                    // 的 O_NONBLOCK(macOS 上如此,Linux 上也一样),而
                    // connection_loop 从头到尾是同步阻塞 I/O —— 不关掉的话
                    // 第一帧就会读到 EAGAIN,表现为"每个客户端连上就断",
                    // 而且报错信息是 WouldBlock,和权限、协议都不沾边。
                    let stream = match stream.into_std() {
                        Ok(stream) => stream,
                        Err(error) => {
                            tracing::warn!("could not take the connection: {error}");
                            return;
                        }
                    };
                    if let Err(error) = stream.set_nonblocking(false) {
                        tracing::warn!("could not put the connection back into blocking mode: {error}");
                        return;
                    }

                    let outcome = tokio::task::spawn_blocking(move || {
                        connection_loop(&state, &policy, stream)
                    })
                    .await;

                    // 一条连接出了错只影响这条连接。守护进程继续听。
                    match outcome {
                        Ok(Err(error)) => tracing::debug!("connection ended: {error}"),
                        Err(error) => tracing::warn!("a connection task panicked: {error}"),
                        Ok(Ok(())) => {}
                    }
                });
            }
            Err(error) => {
                // accept 失败通常是"对端在 connect 之后立刻走了"。这不该
                // 让守护进程倒下 —— 它必须一直听着。
                tracing::warn!("accept failed: {error}");
            }
        }
    }
}

/// 一条连接的整个生命周期。
fn connection_loop(
    state: &DaemonState,
    policy: &PeerPolicy,
    mut stream: std::os::unix::net::UnixStream,
) -> Result<()> {
    // **认人在动任何别的东西之前。** 认不过就写完拒绝的应答然后关门。
    let peer = match policy.admit(self_uid(), &stream) {
        Ok(peer) => peer,
        Err(error) => {
            refuse(state, &mut stream, &error)?;
            return Err(error);
        }
    };

    loop {
        let request = match wire::read_request(&mut stream) {
            Ok(Some(request)) => request,
            // 对端干净地关了连接。正常。
            Ok(None) => return Ok(()),
            Err(error) => {
                // 帧本身不合法 —— 回一条 ERR 再关。能说话就说一句,
                // 免得对端只能看到"连接断了"而不知道为什么。
                let _ = wire::write_response(&mut stream, &wire::Response::from_error(&error));
                return Err(error);
            }
        };

        let response = handlers::handle(state, &peer, request);
        wire::write_response(&mut stream, &response)?;
    }
}

/// 拒绝一条连接:先记审计,再尽量告诉对端为什么。
fn refuse(
    state: &DaemonState,
    stream: &mut std::os::unix::net::UnixStream,
    error: &KeydError,
) -> Result<()> {
    // uid 可能压根没取到 —— 那正是要记下来的事,所以它是 `Option`。
    let (uid, pid) = match peer_identity(stream) {
        Ok(peer) => (Some(peer.uid), peer.pid),
        Err(_) => (None, None),
    };

    let event = Event::Denied {
        uid,
        pid,
        reason: error.wire_message(),
    };
    if let Err(audit_error) = state.record_service(&event) {
        tracing::error!("a refused connection could not be recorded: {audit_error}");
    }

    // 被拒的这一刻,是对端 pin **唯一的出处**。
    //
    // `--system` 下没给 `--allow-binary` 就直接拒绝启动,所以人要配第三层
    // 就得先拿到那个值;而那个值只能从"跑一次、被拒一次"里来。日志里这
    // 一行是可以直接抄进命令行的。
    //
    // 不写进上面的审计事件:那个结构的形状和哈希链绑在一起,而 pin 是
    // 给人看的东西 —— 两件事没必要用同一条通道。
    log_the_pin_we_would_need(stream, error);

    // 应答能不能写出去不影响拒绝本身 —— 对端可能在拒绝的这一刻已经走了。
    let _ = wire::write_response(stream, &wire::Response::from_error(error));
    Ok(())
}

/// 把"要给这个对端放行,该往 `--allow-binary` 里写什么"打进日志。
///
/// 三件事分开说,因为它们**要人做的事不一样**:能 pin 的给出那一行;
/// 没有代码签名的明确说 pin 不了(免得人对着日志找不存在的值);
/// 问不到说问不到。
fn log_the_pin_we_would_need(stream: &std::os::unix::net::UnixStream, error: &KeydError) {
    let Ok(peer) = peer_identity(stream) else {
        tracing::warn!(denied = %error.wire_message(), "refused a connection, and its uid could not be read");
        return;
    };

    match binary_identity(stream, &peer) {
        Ok(Some(identity)) => {
            let (kind, digest) = identity.pin();
            let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
            tracing::warn!(
                denied = %error.wire_message(),
                peer = %identity.audit_label(),
                "refused a connection; to admit this binary, give the daemon: --allow-binary {kind}:{hex}"
            );
        }
        Ok(None) => tracing::warn!(
            denied = %error.wire_message(),
            peer = %peer.audit_label(),
            "refused a connection; this binary carries no code signature, so it cannot be pinned \
             with --allow-binary at all"
        ),
        Err(identity_error) => tracing::warn!(
            denied = %error.wire_message(),
            peer = %peer.audit_label(),
            "refused a connection, and its binary identity could not be read: {identity_error}"
        ),
    }
}

/// 定期把空闲太久的钥匙放掉。
///
/// 这只是**及时性**:真正的保证在 [`crate::daemon::state::Vault`] 每次访问
/// 之前的那一刻自检里 —— 就算这个任务被饿死,过期的钥匙也签不出东西来。
async fn sweep_until_stopped(state: Arc<DaemonState>, mut stop: watch::Receiver<bool>) {
    let period = sweep_period(state.autolock().idle_duration());
    let mut ticker = tokio::time::interval(period);
    // 第一次 tick 立刻就到;跳过它,启动不该顺手收一遍什么。
    ticker.tick().await;

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let dropped = state.sweep_all(std::time::Instant::now());
                if dropped > 0 {
                    tracing::info!(dropped, "idle keys were locked");
                }
            }
            _ = stop.changed() => return,
        }
    }
}

/// 清扫周期:超时的四分之一,夹在 1 秒到 1 分钟之间。
///
/// 上限 60 秒是为了"钥匙最多多活一分钟",下限 1 秒是为了别把一个
/// `--idle 0` 变成忙等。
fn sweep_period(idle: std::time::Duration) -> std::time::Duration {
    (idle / 4).clamp(
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(60),
    )
}

/// 建监听 socket。
///
/// 目录 0700、socket 0600 —— 但这两条都只是**方便**,不是安全边界:
/// 真正决定谁能用的是连接建立时内核给的对端凭证。权限位挡不住同 uid 的
/// 另一个进程,而那个进程正是这个设计要防的对象。
///
/// 返回标准库的 listener 而不是 tokio 的:这一段全是文件系统的事,不需要
/// 也不应该要求一个 runtime 在场。转换是下一步的事。
pub fn bind(sock_path: &Path) -> Result<std::os::unix::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;

    // `sockaddr_un.sun_path` 是一个定长数组(BSD 上 104 字节,含结尾的
    // NUL),所以 socket 路径有硬上限。超了的话,内核回的是
    // "path must be shorter than SUN_LEN" —— 既不说是哪条路径,也不说是
    // 多少,而人手上能做的调整只有"把 --root 挪浅一点"。这里把那句话补全。
    let length = sock_path.as_os_str().as_encoded_bytes().len();
    if length >= SUN_PATH_MAX {
        return Err(KeydError::Misuse(format!(
            "the socket path {} is {length} bytes, and the kernel's limit for one is \
             {SUN_PATH_MAX} (including the terminator) — move --root somewhere shallower",
            sock_path.display()
        )));
    }

    if let Some(parent) = sock_path.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }

    if sock_path.exists() {
        // 已经有东西在那儿。**连一下试试**才能分辨"另一个守护进程活着"
        // 和"上次崩溃留下的死文件" —— 只看文件在不在是分不出来的。
        match std::os::unix::net::UnixStream::connect(sock_path) {
            Ok(_) => {
                return Err(KeydError::Misuse(format!(
                    "{} is already served by another anpio-key; refusing to start a second one",
                    sock_path.display()
                )))
            }
            Err(_) => {
                tracing::info!(sock = %sock_path.display(), "removing a stale socket");
                std::fs::remove_file(sock_path)?;
            }
        }
    }

    let listener = std::os::unix::net::UnixListener::bind(sock_path)?;
    std::fs::set_permissions(sock_path, std::fs::Permissions::from_mode(0o600))?;
    // tokio 只接受非阻塞的 fd。标准库的 listener 默认是阻塞的,交出去之前
    // 得先把这个属性改掉 —— 否则不是"稍微低效",是直接 panic。
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// 把监听 socket 交给 tokio。**必须在 runtime 里调。**
fn as_tokio(listener: std::os::unix::net::UnixListener) -> Result<UnixListener> {
    Ok(UnixListener::from_std(listener)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 死 socket 会被清掉,活着的会被认出来。
    ///
    /// 这一条值得测:分不清这两种情况的话,要么每次崩溃重启都得让用户
    /// 手动删文件,要么两个守护进程同时握着同一批钥匙。
    #[test]
    fn a_live_listener_is_not_replaced_but_a_dead_socket_is() {
        let dir = TempDir::new();
        let sock = dir.path().join("keyd.sock");

        // 死 socket:一个没人听的路径。
        std::fs::write(&sock, b"").unwrap();
        let listener = bind(&sock).expect("a leftover file is not a live daemon");
        drop(listener);
        std::fs::remove_file(&sock).unwrap();

        // 活着的:同一个路径上真的有一个 listener。
        let _live = bind(&sock).unwrap();
        let err = bind(&sock).unwrap_err();
        assert!(err.to_string().contains("already served"), "{err}");
    }

    #[test]
    fn the_socket_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new();
        let sock = dir.path().join("keyd.sock");
        let _listener = bind(&sock).unwrap();

        assert_eq!(std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(
            std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn the_sweeper_runs_often_enough_but_never_spins() {
        assert_eq!(sweep_period(std::time::Duration::from_secs(900)), std::time::Duration::from_secs(60));
        assert_eq!(sweep_period(std::time::Duration::from_secs(4)), std::time::Duration::from_secs(1));
        assert_eq!(sweep_period(std::time::Duration::ZERO), std::time::Duration::from_secs(1));
    }

    mod tempdir {
        use std::os::unix::fs::PermissionsExt;
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);

        pub struct TempDir {
            path: PathBuf,
        }

        impl TempDir {
            pub fn new() -> Self {
                let n = COUNTER.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "anpio-key-server-{}-{n}-{:?}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ));
                std::fs::create_dir_all(&path).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
                Self { path }
            }

            pub fn path(&self) -> &Path {
                &self.path
            }
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
    }

    // —— 端到端:真的起一个监听、真的连上去 ——

    use crate::client::Client;
    use crate::crypto::kdf::Argon2Config;
    use crate::daemon::peer::BinaryIdentity;
    use crate::daemon::state::{Roots, SigningGates};
    use crate::did::DidDocumentSpec;
    use crate::error::KeydError;
    use crate::keystore::hardware::HardwareChoice;
    use crate::keystore::layout::{KeydLayout, SECRET_FILE_MODE};
    use crate::keystore::{create, store};

    const PASSPHRASE: &str = "correct horse battery staple";

    struct Running {
        _dir: TempDir,
        sock: PathBuf,
        did: String,
        stop: watch::Sender<bool>,
    }

    impl Running {
        async fn start(policy: PeerPolicy) -> Self {
            let dir = TempDir::new();
            let layout = KeydLayout::at(dir.path().to_path_buf());
            layout.ensure().unwrap();

            let spec = DidDocumentSpec::new("example.com", vec!["user".into(), "alice".into()])
                .with_fragment("key-1");
            let created = create::create(
                &layout,
                &spec,
                "default",
                PASSPHRASE.as_bytes(),
                Argon2Config { m_cost: 1024, t_cost: 1, p_cost: 1 },
                HardwareChoice::None,
            )
            .unwrap();
            let wrapped = store::load(&layout, &created.wrapped.id.thumbprint).unwrap();
            let device_secret = crate::keystore::device::load(&layout).unwrap();
            let key =
                crate::keystore::unwrap::unlock(&wrapped, PASSPHRASE.as_bytes(), &device_secret)
                    .unwrap();
            let document = crate::did::document::publishable(&spec, &created.did, &key).unwrap();
            store::write_did_document(&layout, &created.did, &document).unwrap();
            drop(key);

            let state = Arc::new(DaemonState::new(
                Roots::Single(KeydLayout::at(dir.path().to_path_buf())),
                policy.clone(),
                crate::daemon::autolock::Autolock::idle(std::time::Duration::from_secs(900)),
                SigningGates::new(false, false),
            ));

            let sock = dir.path().join("keyd.sock");
            let (stop, stop_rx) = watch::channel(false);
            let config = ServerConfig { sock_path: sock.clone(), policy };

            tokio::spawn(async move {
                let _ = serve(state, config, stop_rx).await;
            });

            let running = Self { _dir: dir, sock, did: created.did, stop };
            running.wait_for_socket().await;
            running
        }

        /// 等到真的能连上为止。
        ///
        /// 起一个后台任务再立刻去连是个竞态 —— 而一个偶发失败的测试比没有
        /// 测试更糟,因为它会训练人忽略红色。
        async fn wait_for_socket(&self) {
            for _ in 0..200 {
                if std::os::unix::net::UnixStream::connect(&self.sock).is_ok() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            panic!("the daemon never started listening on {}", self.sock.display());
        }

        /// 在**阻塞线程池**上跑一段客户端会话。
        ///
        /// 这层包装不是洁癖。客户端是同步阻塞 I/O,而默认的
        /// `#[tokio::test]` 是单线程 runtime —— 直接在测试的 async 体里跑它,
        /// 就是在守护进程要用来应答的那唯一一条线程上等待守护进程应答。
        /// 自己把自己锁死,而且看上去像"守护进程没反应"。
        async fn session<T, F>(&self, f: F) -> T
        where
            T: Send + 'static,
            F: FnOnce(&mut Client) -> T + Send + 'static,
        {
            let sock = self.sock.clone();
            tokio::task::spawn_blocking(move || {
                let mut client = Client::connect(&sock).unwrap();
                f(&mut client)
            })
            .await
            .unwrap()
        }

        fn audit_text(&self) -> String {
            let dir = self._dir.path().join("audit");
            let mut out = String::new();
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    if entry.path().extension().is_some_and(|e| e == "jsonl") {
                        out.push_str(&std::fs::read_to_string(entry.path()).unwrap());
                    }
                }
            }
            out
        }
    }

    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.stop.send(true);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_client_can_list_unlock_and_sign_over_the_socket() {
        let running = Running::start(PeerPolicy::default()).await;
        let did = running.did.clone();

        // 整场会话在**同一个客户端**上跑完 —— 这也顺带证明了帧协议是
        // 有状态的:认人只在连接建立时做一次,后面几条请求都沿用。
        //
        // 走的是 `Client`,也就是 CLI 会走的那条路。用裸 `round_trip` 测
        // 会漏掉客户端把应答翻译回 `Result` 的那一段,而客户端同时也是
        // "别人照着接 keyd"的参考实现 —— 它错了,错的是两份。
        let outcome = running
            .session(move |client| {
                let listed = client.list_keys();

                // 锁着的时候签不出来。
                let locked = client.sign(wire::SignRequest::Structured {
                    kid: None,
                    did: did.clone(),
                    method: "POST".into(),
                    target_uri: "https://example.com/api".into(),
                    headers: Default::default(),
                    body: Some(b"{}".to_vec()),
                    covered: Vec::new(),
                    nonce: None,
                });

                // 解锁。口令就是从这个 socket 上传过去的 —— 这是 v1 的
                // 解锁仪式,它成立的前提是这条 socket 的另一头一定是我们自己。
                let unlocked = client.unlock(&did, None, PASSPHRASE);

                let signed = client.sign(wire::SignRequest::Structured {
                    kid: None,
                    did: did.clone(),
                    method: "POST".into(),
                    target_uri: "https://example.com/api".into(),
                    headers: Default::default(),
                    body: Some(b"{}".to_vec()),
                    covered: Vec::new(),
                    nonce: None,
                });

                (listed, locked, unlocked, signed)
            })
            .await;

        let (listed, locked, unlocked, signed) = outcome;

        let keys = listed.expect("listing keys needs no unlock");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].did, running.did);

        // 锁着的时候,客户端拿到的是**粗码**,而且它不做任何还原。
        let error = locked.expect_err("a locked key must not sign");
        assert!(
            matches!(
                error,
                KeydError::Refused { code: wire::ErrorCode::Locked, .. }
            ),
            "{error:?}"
        );

        unlocked.expect("the right passphrase unlocks");

        let bytes = signed.expect("an unlocked key signs");
        let headers = crate::client::parse_signed_headers(&bytes).unwrap();
        assert!(headers.contains_key("Signature-Input"), "{headers:?}");
        assert!(headers.contains_key("Signature"), "{headers:?}");
        // 有 body,就有 content-digest —— 而且是守护进程自己算的。
        assert!(headers.contains_key("Content-Digest"), "{headers:?}");

        // 整条路走完了,而且全程留了痕。
        let audit = running.audit_text();
        assert!(audit.contains("UNLOCKED"), "{audit}");
        assert!(audit.contains("SIGNED"), "{audit}");
    }

    /// 对端身份不认时:回一条 ERR_PERMISSION,并且**留一行审计**。
    ///
    /// 用"白名单里列了一个我们不可能是的文件摘要"来制造这个局面 ——
    /// 测试跑不起来第二个 uid,但拒绝这条路本身是同一段代码。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_peer_gets_a_permission_error_and_an_audit_line() {
        let running = Running::start(PeerPolicy {
            allowed_uids: Vec::new(),
            allowed_binaries: vec![BinaryIdentity::ExecutableDigest {
                path: PathBuf::from("/nonexistent/not-this-binary"),
                sha256: [0u8; 32],
            }],
        })
        .await;

        // 拒绝发生在读帧**之前** —— 所以这条连接上我们连一条请求都发不
        // 进去,发出去的东西没有任何人在读。客户端要么读到那条 ERR,
        // 要么因为对端已经关门而断在写/读上,两种都算拒绝。
        let response = running
            .session(|client| client.status())
            .await;

        match response {
            Err(KeydError::Refused { code, .. }) => {
                assert_eq!(code, wire::ErrorCode::Permission);
            }
            // 拒绝之后立刻关门也是对的:对端可能连应答都没读到就断了。
            Err(_) => {}
            Ok(status) => panic!("a refused peer must not get a status: {status:?}"),
        }

        // 这一条是关键:拒绝是安静发生的,没有这行审计,一次探测在事后
        // 和"什么都没发生"完全一样。
        let audit = running.audit_text();
        assert!(audit.contains("DENIED"), "{audit}");
    }

    /// 停机时 socket 被删掉。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stopping_removes_the_socket() {
        let running = Running::start(PeerPolicy::default()).await;
        assert!(running.sock.exists());

        running.stop.send(true).unwrap();

        for _ in 0..200 {
            if !running.sock.exists() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("the socket was still there after the daemon stopped");
    }

    /// 建 socket 时盖的权限位。
    #[test]
    fn the_socket_mode_constant_is_the_one_we_set() {
        assert_eq!(SECRET_FILE_MODE, 0o600);
    }

    use tempdir::TempDir;
}
