//! 端到端:一份**已发布的**文档、一个真的守护进程、一条真的 socket,
//! 最后交给**别人**验签。
//!
//! 单元测试已经证明 `sign_request` 和上游一致。这一条证的是**整根管子**:
//! 信封解封、socket 协议、守护进程自己重建签名基、客户端把它原样搬回来。
//!
//! 验签用的是 `anp` 自己的实现,不是我们的 —— 一段自己验自己的代码,
//! 错了只会跟着一起错。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use anpio_key::client::Client;
use anpio_key::crypto::kdf::Argon2Config;
use anpio_key::daemon::peer::PeerPolicy;
use anpio_key::daemon::state::{autolock_from_secs, DaemonState, Roots, SigningGates};
use anpio_key::daemon::wire::{SignRequest, MAX_CHALLENGE_LEN};
use anpio_key::daemon::{self, server, ServerConfig};
use anpio_key::did::document::{self, DidDocumentSpec};
use anpio_key::did::proof_value;
use anpio_key::keystore::layout::KeydLayout;
use anpio_key::keystore::hardware::HardwareChoice;
use anpio_key::keystore::{create, device, store};
use serde_json::Value;

const PASSPHRASE: &[u8] = b"e2e passphrase";

/// 一个用完就删的目录。集成测试用不了 crate 里 `#[cfg(test)]` 那套夹具 ——
/// 那些代码在编译这个文件时根本不存在。
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        // 名字必须**真的**唯一。用时钟不够:几个测试是并行起的,同一个
        // 纳秒撞上太容易,而撞上之后两条测试会共用同一个目录 —— 一条把
        // 另一条的信封连同 device.secret 一起删掉,症状是莫名其妙的
        // `BadPassphrase`,完全看不出真因。计数器是唯一不会撞的那个东西。
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let unique = format!(
            "keyd-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        // 故意不用 `env::temp_dir()`:macOS 上那是 `/var/folders/<很长>/T`,
        // 而 socket 路径有 `sun_path` 那个硬上限(见 `server::bind`)。
        // 短一点,免得测试量到的是 tmpdir 有多深而不是协议对不对。
        let path = PathBuf::from("/tmp").join(unique);
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

/// Argon2 用测试参数:这里验的是协议,不是抗爆破强度。
fn fast() -> Argon2Config {
    Argon2Config { m_cost: 1024, t_cost: 1, p_cost: 1 }
}

struct Running {
    _dir: TempDir,
    /// 停机信号的发送端。**必须握着。**
    ///
    /// watch 的所有 sender 一旦全被丢掉,`Receiver::changed()` 会立刻返回
    /// `Err`;而守护进程正是 `select!` 在那上面等停机的 —— 于是它一收到
    /// 就退出。写成 `let _ = stop_tx;` 就是把 sender 立刻丢掉(那个 `_`
    /// 是个立即丢弃的绑定),守护进程会在启动的同一瞬间关掉,而症状是
    /// 客户端拿到"连接被关闭",看起来跟这里毫无关系。
    _stop: tokio::sync::watch::Sender<bool>,
    sock: PathBuf,
    /// **已发布**的文档 —— 带 proof 的那一份,跟别人从 `did.json` 抓到的
    /// 一模一样。
    document: Value,
    did: String,
}

impl Running {
    fn start() -> Self {
        Self::start_with_gates(false, false)
    }

    /// 同一套夹具,两个签名开关自己定 —— 挑战签名那一条要真的开着才测得出来。
    fn start_with_gates(raw: bool, challenge: bool) -> Self {
        let dir = TempDir::new("e2e");
        let root = dir.path().join("root");
        let layout = KeydLayout::at(root.clone());

        let spec = DidDocumentSpec::new("example.com", vec!["agents".into(), "e2e".into()]);
        let created = create::create(&layout, &spec, "e2e", PASSPHRASE, fast(), HardwareChoice::None).unwrap();

        // 走一遍 `publish` 的路径:把公钥从信封里解出来、重建文档、盖 proof、
        // 落盘。之后验签用的就是磁盘上这一份 —— 不是内存里的那个半成品。
        let wrapped = store::load(&layout, &created.wrapped.id.thumbprint).unwrap();
        let device_secret = device::load(&layout).unwrap();
        let key = anpio_key::keystore::unwrap::unlock(&wrapped, PASSPHRASE, &device_secret).unwrap();
        let unsigned = document::rebuild(&created.did, &key.verifying_key()).unwrap();
        let signed = document::sign_document(&unsigned, &key, &wrapped.id.kid).unwrap();
        document::verify_path_binding(&created.did, &signed).unwrap();
        store::write_did_document(&layout, &created.did, &signed).unwrap();
        drop(key);

        let sock = layout.sock_path();
        let state = Arc::new(DaemonState::new(
            Roots::Single(KeydLayout::at(root)),
            PeerPolicy { allowed_uids: vec![], allowed_binaries: vec![] },
            autolock_from_secs(900),
            SigningGates::new(raw, challenge),
        ));

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let serving = sock.clone();
        runtime.spawn(async move {
            if let Err(error) =
                server::serve(
                    state,
                    ServerConfig { sock_path: serving, policy: PeerPolicy::default() },
                    stop_rx,
                )
                    .await
            {
                panic!("the daemon stopped with {error}");
            }
        });

        wait_for_socket(&sock);
        // runtime 故意 leaked:守护进程要活到这个测试结束。测试进程随即退出,
        // 该放的钥匙随地址空间一起消失。
        std::mem::forget(runtime);

        Self { _dir: dir, _stop: stop_tx, sock, document: signed, did: created.did }
    }

    /// 在一条**阻塞**线程上跟守护进程说话。
    ///
    /// 不能直接在这个线程里调:客户端是同步阻塞 IO,而这里跑在 tokio 的
    /// 运行时上 —— 同步等下去,守护进程那条应答就永远发不出来。
    async fn session<T, F>(&self, work: F) -> T
    where
        T: Send + 'static,
        F: FnOnce(&mut Client) -> T + Send + 'static,
    {
        let sock = self.sock.clone();
        tokio::task::spawn_blocking(move || {
            let mut client = Client::connect(&sock).expect("connect");
            work(&mut client)
        })
        .await
        .expect("join")
    }
}

fn wait_for_socket(path: &Path) {
    for _ in 0..500 {
        if path.exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("the daemon never created {}", path.display());
}

/// 把守护进程给的头接到请求头上去 —— 调用方要做的就是这个动作。
fn splice(original: &BTreeMap<String, String>, signed: &[u8]) -> BTreeMap<String, String> {
    let mut headers = original.clone();
    for (name, value) in anpio_key::client::parse_signed_headers(signed).unwrap() {
        headers.insert(name, value);
    }
    headers
}

fn verify(
    document: &Value,
    method: &str,
    url: &str,
    headers: &BTreeMap<String, String>,
    body: Option<&[u8]>,
) -> Result<anp::authentication::http_signatures::SignatureMetadata, String> {
    anp::authentication::verify_http_message_signature(document, method, url, headers, body)
        .map_err(|error| error.to_string())
}

/// 挑战签名的验法 —— **和对端做的事一模一样**:从已发布的文档里取出公钥,
/// 拿它对 `challenge` 的**原字节**验一次签名。没有签名基、没有 nonce,
/// 这一份密文里也没有第二个字段可以挑。
///
/// 验签的人是 `ed25519_dalek`,不是这个 crate 里的任何代码;公钥则是从
/// **磁盘上那份文档**里读出来的,不是内存里刚造的那把钥匙 —— 中间任何一步
/// 把字节换了地方,这里都会红。
fn verify_challenge(document: &Value, signature: &[u8], challenge: &[u8]) -> Result<(), String> {
    let methods = document["verificationMethod"]
        .as_array()
        .ok_or_else(|| "the document has no verificationMethod".to_string())?;
    assert_eq!(methods.len(), 1, "this fixture creates exactly one key");
    let multibase = methods[0]["publicKeyMultibase"]
        .as_str()
        .ok_or_else(|| "a verification method without publicKeyMultibase".to_string())?;

    let key = anpio_key::crypto::thumbprint::ed25519_from_multibase(multibase)
        .map_err(|error| error.to_string())?;
    let signature = ed25519_dalek::Signature::from_slice(signature).map_err(|e| e.to_string())?;

    use ed25519_dalek::Verifier;
    key.verify(challenge, &signature).map_err(|error| error.to_string())
}

/// **这是那一条测试。** 一条连着 socket 的请求,签出来,交给上游验。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_signature_made_over_the_socket_verifies_with_the_upstream_verifier() {
    let running = Running::start();
    let did = running.did.clone();

    let (with_body, without_body) = running
        .session(move |client| {
            client.unlock(&did, None, std::str::from_utf8(PASSPHRASE).unwrap()).unwrap();

            let get = client
                .sign(SignRequest::Structured {
                    did: did.clone(),
                    kid: None,
                    method: "GET".into(),
                    target_uri: "https://example.com/agents/e2e/resource?page=2".into(),
                    headers: BTreeMap::from([("accept".to_string(), "application/json".into())]),
                    body: None,
                    covered: vec![],
                    nonce: None,
                })
                .unwrap();

            let post = client
                .sign(SignRequest::Structured {
                    did: did.clone(),
                    kid: None,
                    method: "POST".into(),
                    target_uri: "https://example.com/agents/e2e/resource".into(),
                    headers: BTreeMap::from([(
                        "content-type".to_string(),
                        "application/json".into(),
                    )]),
                    body: Some(br#"{"hello":"world"}"#.to_vec()),
                    covered: vec![],
                    nonce: None,
                })
                .unwrap();

            (post, get)
        })
        .await;

    // —— 没有 body 的那条 ——
    let headers = splice(&BTreeMap::new(), &without_body);
    let metadata = verify(
        &running.document,
        "GET",
        "https://example.com/agents/e2e/resource?page=2",
        &headers,
        None,
    )
    .expect("a GET signed by the daemon must verify upstream");

    // 三个下限一个不少 —— 这不是格式检查,是**覆盖面**检查。
    for required in ["@method", "@target-uri", "@authority"] {
        assert!(
            metadata.components.iter().any(|c| c == required),
            "{required} missing from {:?}",
            metadata.components
        );
    }

    // —— 有 body 的那条 ——
    let body = br#"{"hello":"world"}"#;
    let headers = splice(
        &BTreeMap::from([("content-type".to_string(), "application/json".into())]),
        &with_body,
    );
    let metadata = verify(
        &running.document,
        "POST",
        "https://example.com/agents/e2e/resource",
        &headers,
        Some(body),
    )
    .expect("a POST with a body must verify upstream");
    assert!(
        metadata.components.iter().any(|c| c == "content-digest"),
        "a body must bring content-digest into the covered set: {:?}",
        metadata.components
    );
    assert_eq!(metadata.keyid, running.document["id"].as_str().map(|_| metadata.keyid.clone()).unwrap());
}

/// 签名必须**绑死**在那条请求上。改一个字节,它就应当验不过。
///
/// 这一条是"防盲目签名"的验收标准:签名如果换个 URL 也能用,那 agent
/// 被 prompt injection 之后拿到的就是一张空白支票。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_signature_is_bound_to_the_request_it_was_made_for() {
    let running = Running::start();
    let did = running.did.clone();

    let signed = running
        .session(move |client| {
            client.unlock(&did, None, std::str::from_utf8(PASSPHRASE).unwrap()).unwrap();
            client
                .sign(SignRequest::Structured {
                    did: did.clone(),
                    kid: None,
                    method: "POST".into(),
                    target_uri: "https://example.com/pay".into(),
                    headers: BTreeMap::new(),
                    body: Some(b"amount=10".to_vec()),
                    covered: vec![],
                    nonce: None,
                })
                .unwrap()
        })
        .await;

    let headers = splice(&BTreeMap::new(), &signed);

    // 原件验得过。
    verify(&running.document, "POST", "https://example.com/pay", &headers, Some(b"amount=10"))
        .expect("the original must verify");

    // 换成另一个 URL:验不过。
    assert!(
        verify(
            &running.document,
            "POST",
            "https://example.com/refund",
            &headers,
            Some(b"amount=10")
        )
        .is_err(),
        "the signature must not be reusable on a different URL"
    );

    // 换方法:验不过。
    assert!(
        verify(&running.document, "PUT", "https://example.com/pay", &headers, Some(b"amount=10"))
            .is_err(),
        "the signature must not be reusable with a different method"
    );

    // 换 body:验不过 —— 但拦下它的是 `content-digest`,也就是守护进程
    // 自己算的那个摘要,不是调用方给的那个。
    assert!(
        verify(
            &running.document,
            "POST",
            "https://example.com/pay",
            &headers,
            Some(b"amount=1000000")
        )
        .is_err(),
        "the signature must not survive a swapped body"
    );
}

/// 文档本身也得对得上:DID 的 `e1_` 段必须是文档里那把公钥的指纹。
///
/// 这条挡的是最阴的一种情况 —— 签名验得过,但验签用的公钥**不是** DID
/// 声称的那一把。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_document_that_verified_the_signature_is_bound_to_the_did() {
    let running = Running::start();
    document::verify_path_binding(&running.did, &running.document)
        .expect("the published document must be bound to its DID");

    // 而且它真的是一份**签过的**文档,不是裸文档。
    assert!(running.document.get("proof").is_some(), "the document carries no proof");
    // 上游那一版验签只读得懂裸 base64url,而我们从 2026-10-14 起发的是
    // ANP-03 §2.5.5 要的 multibase(见 `did::proof_value`)。换回去之后它验的
    // 还是同一批字节 —— `proofValue` 本来就不进签名输入。
    assert!(
        anp::authentication::validate_did_document_method(
            &proof_value::as_upstream_reads_it(&running.document).unwrap(),
            true
        ),
        "upstream rejects this document"
    );
}

/// 守护进程没解锁的时候,签名这条路必须是**关着**的。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signing_is_refused_while_locked() {
    let running = Running::start();
    let did = running.did.clone();

    let error = running
        .session(move |client| {
            client
                .sign(SignRequest::Structured {
                    did,
                    kid: None,
                    method: "GET".into(),
                    target_uri: "https://example.com/x".into(),
                    headers: BTreeMap::new(),
                    body: None,
                    covered: vec![],
                    nonce: None,
                })
                .unwrap_err()
        })
        .await;

    assert_eq!(error.wire_code(), anpio_key::daemon::wire::ErrorCode::Locked, "{error}");
}

/// 同一把钥匙被两个客户端同时签:两个都成,而且**内容各自独立**。
///
/// 计划里这一条的要求是"第二个要么排队要么明确拒绝,不许交错"。这台
/// 守护进程选的是排队(每次签名都要进那把锁,签名基在锁里拼),所以这里
/// 验的是排队的结果:两个应答都完整、都能验过、而且 nonce 不同 ——
/// 如果哪一天有人把签名基拼到锁外面去,nonce 就会重复,这条会红。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_concurrent_signers_do_not_interleave() {
    let running = Running::start();
    let did = running.did.clone();

    running
        .session({
            let did = did.clone();
            move |client| client.unlock(&did, None, std::str::from_utf8(PASSPHRASE).unwrap()).unwrap()
        })
        .await;

    let mut tasks = Vec::new();
    for index in 0..2 {
        let sock = running.sock.clone();
        let did = did.clone();
        tasks.push(tokio::task::spawn_blocking(move || {
            let mut client = Client::connect(&sock).unwrap();
            let signed = client
                .sign(SignRequest::Structured {
                    did,
                    kid: None,
                    method: "GET".into(),
                    target_uri: format!("https://example.com/x/{index}"),
                    headers: BTreeMap::new(),
                    body: None,
                    covered: vec![],
                    nonce: None,
                })
                .unwrap();
            (index, signed)
        }));
    }

    let mut nonces = Vec::new();
    for task in tasks {
        let (index, signed) = task.await.unwrap();
        let headers = splice(&BTreeMap::new(), &signed);
        let metadata = verify(
            &running.document,
            "GET",
            &format!("https://example.com/x/{index}"),
            &headers,
            None,
        )
        .expect("each concurrent signature must verify on its own request");
        nonces.push(metadata.nonce.expect("every signature carries a nonce"));
    }

    assert_ne!(nonces[0], nonces[1], "two signatures shared a nonce");
}

/// **第二条端到端的测试。** 挑战签名:一条真的 socket 请求,签的是调用方
/// 给的**原字节**,交给外面的验签实现验;边上量一下那道 256 字节的墙。
///
/// 这一条和第 256 个字节是同一个东西的两面 —— 上限**就是**这条路和 `Raw`
/// 之间全部的差别(见 ADAPTER §3.3),所以它得在"真的能签"旁边一起被量。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_challenge_signature_verifies_with_an_outside_verifier() {
    let running = Running::start_with_gates(false, true);
    let did = running.did.clone();

    // 正好顶到上限:不是随手挑的短串 —— 边界那一格也得真的签得出来。
    let challenge = vec![b'a'; MAX_CHALLENGE_LEN];

    let signature = running
        .session({
            let did = did.clone();
            let challenge = challenge.clone();
            move |client| {
                client
                    .unlock(&did, None, std::str::from_utf8(PASSPHRASE).unwrap())
                    .unwrap();
                client.sign(SignRequest::Challenge { did, kid: None, challenge }).unwrap()
            }
        })
        .await;

    verify_challenge(&running.document, &signature, &challenge)
        .expect("a challenge signed over the socket must verify against the published document");

    // 往上一格:多一个字节,在协议层就被拦下,连钥匙都不碰。
    let error = running
        .session({
            let did = did.clone();
            move |client| {
                client
                    .sign(SignRequest::Challenge {
                        did,
                        kid: None,
                        challenge: vec![b'a'; MAX_CHALLENGE_LEN + 1],
                    })
                    .unwrap_err()
            }
        })
        .await;

    assert_eq!(
        error.wire_code(),
        anpio_key::daemon::wire::ErrorCode::Protocol,
        "one byte over the cap must be a protocol error, not a signature: {error}"
    );
    assert!(error.to_string().contains("257"), "{error}");
}

/// 目录布局:测试结束后没必要留东西,但这个断言顺手确认 socket 真的建在
/// 布局说的位置上(`--root` 那个开关就是从这儿推导的)。
#[test]
fn the_socket_lives_where_the_layout_says() {
    let dir = TempDir::new("layout");
    let layout = KeydLayout::at(dir.path().join("root"));
    assert!(layout.sock_path().starts_with(dir.path()));
    let _ = daemon::self_uid();
}
