#![cfg(feature = "mcp")]
//! MCP 前端接的是一根**真的管子**:一个真守护进程、一条真 socket、一个真的
//! `anpio-key mcp` 子进程,说的是一行一个 JSON-RPC 的 MCP 协议。
//!
//! # 为什么在进程边界上测,而不是在 Rust 里调
//!
//! 因为**这里被测的东西就是进程边界**。MCP 客户端的配置文件里写的是
//! `command: anpio-key mcp` —— 它对我们的了解止于"一个说 stdio MCP 的进程"。
//! 在 Rust 里直接调 `ServerHandler::call_tool` 要自己拼 `RequestContext` 这些
//! rmcp 的内部类型,测出来的是"我和 rmcp 的当前版本对得上",而不是"一个
//! MCP 客户端能用"。前者会在 rmcp 升级时红,后者才是产品承诺。
//!
//! # 还有一条是别处测不到的:stdout 必须是**干净**的
//!
//! stdout 归协议。一句 `println!` 就能把一次初始化打成 JSON 解析错误,而症状
//! 看起来像"MCP 客户端不认这个服务器",跟真正的原因隔了十万八千里。所以
//! 这里把子进程的 stdout 每一行都按 JSON 解析 —— 解析不了的**当场就是失败**。

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anpio_key::crypto::kdf::Argon2Config;
use anpio_key::daemon::peer::PeerPolicy;
use anpio_key::daemon::state::{autolock_from_secs, DaemonState, Roots, SigningGates};
use anpio_key::daemon::{server, ServerConfig};
use anpio_key::did::document::{self, DidDocumentSpec};
use anpio_key::keystore::hardware::HardwareChoice;
use anpio_key::keystore::layout::KeydLayout;
use anpio_key::keystore::{create, device, store, unwrap};
use serde_json::{json, Value};

const PASSPHRASE: &[u8] = b"mcp passphrase";

fn fast() -> Argon2Config {
    Argon2Config { m_cost: 1024, t_cost: 1, p_cost: 1 }
}

/// 用完就删的目录。名字靠计数器唯一 —— 测试是并行起的,共用目录的症状
/// 是"另一条把 device.secret 删了",看起来和真因毫无关系。
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let path = PathBuf::from("/tmp").join(format!(
            "keyd-mcp-{tag}-{}-{}",
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

/// 一个真的守护进程,握着**已发布**的那份文档。
struct Daemon {
    _dir: TempDir,
    /// 停机信号的发送端,**必须握着**(见 `signature_end_to_end.rs` 里
    /// 同一处的说明:丢掉它等于当场把守护进程关掉)。
    _stop: tokio::sync::watch::Sender<bool>,
    sock: PathBuf,
    did: String,
    document: Value,
}

impl Daemon {
    fn start() -> Self {
        let dir = TempDir::new("daemon");
        let root = dir.path().join("root");
        let layout = KeydLayout::at(root.clone());

        let spec = DidDocumentSpec::new("example.com", vec!["agents".into(), "mcp".into()]);
        let created =
            create::create(&layout, &spec, "mcp", PASSPHRASE, fast(), HardwareChoice::None)
                .unwrap();

        // 走一遍 publish 那条路,把带 proof 的文档落盘 —— 和外面从 did.json
        // 抓到的一模一样。
        let wrapped = store::load(&layout, &created.wrapped.id.thumbprint).unwrap();
        let device_secret = device::load(&layout).unwrap();
        let key = unwrap::unlock(&wrapped, PASSPHRASE, &device_secret).unwrap();
        let unsigned = document::rebuild(&created.did, &key.verifying_key().unwrap()).unwrap();
        let signed = document::sign_document(&unsigned, &key, &wrapped.id.kid).unwrap();
        document::verify_path_binding(&created.did, &signed).unwrap();
        store::write_did_document(&layout, &created.did, &signed).unwrap();
        drop(key);

        let sock = layout.sock_path();
        let state = Arc::new(DaemonState::new(
            Roots::Single(KeydLayout::at(root)),
            PeerPolicy { allowed_uids: vec![], allowed_binaries: vec![] },
            autolock_from_secs(900),
            SigningGates::new(false, false),
        ));

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let serving = sock.clone();
        runtime.spawn(async move {
            server::serve(
                state,
                ServerConfig { sock_path: serving, policy: PeerPolicy::default() },
                stop_rx,
            )
            .await
            .expect("the daemon must not stop on its own");
        });
        wait_for_socket(&sock);
        // runtime 故意留着:守护进程要活到这个测试结束,而测试进程退出时
        // 地址空间一起消失,该放的钥匙随之不见。
        std::mem::forget(runtime);

        Self { _dir: dir, _stop: stop_tx, sock, did: created.did, document: signed }
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

/// 一个真的 `anpio-key mcp` 子进程,说 stdio 上的 MCP。
struct Mcp {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Mcp {
    fn start(socket: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_anpio-key"))
            .arg("mcp")
            .arg("--socket")
            .arg(socket)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // stderr 留给它自己:诊断走 tracing,而 stdout 归协议。
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn `anpio-key mcp`");

        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        let mut mcp = Self { child, stdin, stdout };

        // 握手。这三步是 MCP 的最小开场,少一步后面什么都不应答。
        let init = mcp.request(1, "initialize", json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "anpio-key tests", "version": "0"},
        }));
        assert_eq!(
            init["result"]["protocolVersion"], "2024-11-05",
            "the handshake must come back with a protocol version: {init}"
        );
        mcp.notify("notifications/initialized", json!({}));

        mcp
    }

    /// 发一条请求,读回它对应的那一条应答。
    ///
    /// **每一行都必须能解析成 JSON。** 这是这份测试里最要紧的一句断言:
    /// stdout 上多一个字符,一个真的 MCP 客户端就整条连接都废了。
    fn request(&mut self, id: u64, method: &str, params: Value) -> Value {
        let line = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        writeln!(self.stdin, "{line}").expect("write to the MCP server");
        self.stdin.flush().expect("flush");

        loop {
            let mut line = String::new();
            let read = self.stdout.read_line(&mut line).expect("read from the MCP server");
            assert!(read > 0, "the MCP server closed stdout while waiting for `{method}`");
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let message: Value = serde_json::from_str(trimmed).unwrap_or_else(|error| {
                panic!(
                    "stdout is not clean JSON-RPC — a stray write went to the protocol \
                     channel: {error}; the offending line was {trimmed:?}"
                )
            });
            // 跳过通知(id 缺席的那一类),等我们这一条的应答。
            if message.get("id").and_then(Value::as_u64) == Some(id) {
                return message;
            }
        }
    }

    fn notify(&mut self, method: &str, params: Value) {
        let line = json!({"jsonrpc": "2.0", "method": method, "params": params});
        writeln!(self.stdin, "{line}").expect("write to the MCP server");
        self.stdin.flush().expect("flush");
    }

    fn call_tool(&mut self, id: u64, name: &str, arguments: Value) -> Value {
        let message = self.request(id, "tools/call", json!({"name": name, "arguments": arguments}));
        assert!(
            message.get("error").is_none(),
            "tool `{name}` failed: {message}"
        );
        message["result"].clone()
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// 工具结果里的文本是 JSON —— 取回来当值用。
fn payload(result: &Value) -> Value {
    let text = result["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("the tool result has no text content: {result}"));
    serde_json::from_str(text).unwrap_or_else(|error| panic!("the tool text is not JSON: {error}; {text:?}"))
}

// ————————————————————————————————————————————————————————————
// 1. 四个工具,握手就列得出来
// ————————————————————————————————————————————————————————————

/// **工具表就是这四个,和 `mcp` 模块里那条单元测试说的是同一件事。**
///
/// 两条测试不重复:那条守的是"我们的代码里注册了几个",这条守的是"一个真的
/// MCP 客户端**看得见**几个"。中间隔着 rmcp 的 schema 生成和协议编解码,
/// 而一个工具在客户端看不见,等于不存在。
#[test]
fn a_client_sees_exactly_the_four_documented_tools() {
    let daemon = Daemon::start();
    let mut mcp = Mcp::start(&daemon.sock);

    let listed = mcp.request(2, "tools/list", json!({}));
    let mut names: Vec<String> = listed["result"]["tools"]
        .as_array()
        .expect("tools must be an array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("a tool name").to_string())
        .collect();
    names.sort();

    assert_eq!(
        names,
        ["get_did_document", "list_my_keys", "sign_request", "status"]
    );
    assert!(
        !names.iter().any(|name| name.contains("raw")),
        "raw signing must not be reachable over MCP: {names:?}"
    );
}

// ————————————————————————————————————————————————————————————
// 2. 转发真的通到守护进程
// ————————————————————————————————————————————————————————————

/// **`list_my_keys` 返回的是守护进程里那把真的钥匙。**
///
/// 这一条把四个环节串起来:子进程 → socket → 守护进程的密钥库 → 再回来。
/// 少了任何一环(路径推导错、协议版本不对、应答类型对不上),拿回来的都
/// 不会是那个 DID。
#[test]
fn list_my_keys_returns_the_daemons_real_key() {
    let daemon = Daemon::start();
    let mut mcp = Mcp::start(&daemon.sock);

    let result = mcp.call_tool(3, "list_my_keys", json!({}));
    let keys = payload(&result);

    let listed = keys["keys"].as_array().expect("a keys array");
    assert_eq!(listed.len(), 1, "exactly one key was created: {keys}");
    assert_eq!(listed[0]["did"], daemon.did);
    assert!(
        !keys.to_string().contains("seed") && !keys.to_string().contains("private"),
        "a key listing must never carry key material: {keys}"
    );
}

/// `status` 一开始是空的 —— 没解锁过。
#[test]
fn status_is_empty_before_anything_is_unlocked() {
    let daemon = Daemon::start();
    let mut mcp = Mcp::start(&daemon.sock);

    let result = mcp.call_tool(4, "status", json!({}));
    assert_eq!(
        payload(&result)["unlocked"].as_array().map(Vec::len),
        Some(0),
        "nothing has been unlocked yet"
    );
}

/// **`get_did_document` 给的是磁盘上那一份的原文,而且不用解锁。**
///
/// 这是走 MCP 的 agent 登录那一半:它要证明自己是谁,手上就得有这份文档。
/// 这里不走 `unlock` —— 文档是可公开的成品,拿"没解锁"去挡它挡掉的只是
/// 调用方本来就够得着的东西。
///
/// 断言的是**逐字节**相等:那份文档是签好名的,内联进别的东西里靠的就是
/// 这一点。中间任何一层"顺手重排一下键"都会让签名对不上。
#[test]
fn get_did_document_returns_the_published_bytes_without_unlocking() {
    let daemon = Daemon::start();
    let mut mcp = Mcp::start(&daemon.sock);

    let result = mcp.call_tool(5, "get_did_document", json!({"did": daemon.did}));
    let answer = payload(&result);

    assert_eq!(answer["did"], daemon.did);
    let served: Value =
        serde_json::from_str(answer["document"].as_str().expect("the document is text")).unwrap();
    assert_eq!(served, daemon.document, "the document came back changed");
    // 而且它确实是**那一份**文档,不是随便一段 JSON:路径绑定还挂得上。
    document::verify_path_binding(&daemon.did, &served).unwrap();

    // 别人的 DID 答不出来 —— 守护进程不联网,resolve 是客户端的事。
    let refused = mcp.request(6, "tools/call", json!({
        "name": "get_did_document",
        "arguments": {"did": "did:wba:example.com:user:bob:e1_zzz"},
    }));
    assert!(
        refused.get("error").is_some(),
        "a DID this machine never published must not be served: {refused}"
    );
}

// ————————————————————————————————————————————————————————————
// 3. 签名真的签得出来、验得过去
// ————————————————————————————————————————————————————————————

/// **解锁 → 签名 → 上游验签通过。**
///
/// 验签用的是 `anp` 自己的实现,不是我们的。最后再加一条反向的:把 URL
/// 换掉必须验不过 —— 否则这一条只是证明了"有个签名",不是"签名绑住了那个
/// 请求"。
#[test]
fn unlock_then_sign_request_produces_headers_upstream_accepts() {
    let daemon = Daemon::start();
    let mut mcp = Mcp::start(&daemon.sock);

    anpio_key::client::Client::connect(&daemon.sock).unwrap()
        .unlock(&daemon.did, None, std::str::from_utf8(PASSPHRASE).unwrap()).unwrap();

    let unlocked = payload(&mcp.call_tool(6, "status", json!({})));
    assert_eq!(
        unlocked["unlocked"].as_array().map(Vec::len),
        Some(1),
        "the unlock must be visible in status: {unlocked}"
    );

    let url = "https://example.com/api/things";
    let signed = payload(&mcp.call_tool(7, "sign_request", json!({
        "did": daemon.did,
        "method": "POST",
        "url": url,
        "headers": {"content-type": "application/json"},
        "body": "{\"hello\":1}",
    })));

    let headers: BTreeMap<String, String> = serde_json::from_value(signed["headers"].clone())
        .unwrap_or_else(|error| panic!("the signed headers must be a map: {error}; {signed}"));
    assert!(headers.contains_key("Signature"), "{headers:?}");
    assert!(headers.contains_key("Signature-Input"), "{headers:?}");

    // 挂到请求上 —— 调用方要做的就是这个动作。
    let mut request_headers: BTreeMap<String, String> =
        [("content-type".to_string(), "application/json".to_string())].into_iter().collect();
    request_headers.extend(headers);

    anp::authentication::verify_http_message_signature(
        &daemon.document,
        "POST",
        url,
        &request_headers,
        Some(b"{\"hello\":1}"),
    )
    .expect("a signature produced over MCP must verify upstream");

    // ③ 换个 URL 必须验不过,否则上面那条什么也没证明。
    assert!(
        anp::authentication::verify_http_message_signature(
            &daemon.document,
            "POST",
            "https://evil.example.com/api/things",
            &request_headers,
            Some(b"{\"hello\":1}"),
        )
        .is_err(),
        "the signature must be bound to the request it was made for"
    );
}

/// **`nonce` 走 MCP 这条路也要到得了签名里。**
///
/// 这一条单独立着,因为它挡的是一种**不会报错**的漏接:nonce 是共用层
/// (`wire`)的类型,而门面各接一处。漏掉 MCP 那一处,命令行上怎么试都好,
/// 只有走 agent 的那条路静默地拿不到它 —— 而那个调用方多半正指望着它。
///
/// 验的还是上游的实现:请求体里带着同一个 nonce,签名必须照样验得过。
#[test]
fn a_caller_supplied_nonce_reaches_the_signature_over_mcp() {
    let daemon = Daemon::start();
    let mut mcp = Mcp::start(&daemon.sock);

    anpio_key::client::Client::connect(&daemon.sock).unwrap()
        .unlock(&daemon.did, None, std::str::from_utf8(PASSPHRASE).unwrap()).unwrap();

    let url = "https://example.com/api/nonce";
    let nonce = "caller-chosen-42";
    let body = format!(r#"{{"nonce":"{nonce}"}}"#);
    let signed = payload(&mcp.call_tool(2, "sign_request", json!({
        "did": daemon.did,
        "method": "POST",
        "url": url,
        "headers": {"content-type": "application/json"},
        "body": body,
        // 同一个 nonce 也在请求体里 —— 它同时出现在两处,所以只能由调用方
        // 给,而守护进程只负责把它原样放进 `@signature-params`。
        "nonce": nonce,
    })));

    let headers: BTreeMap<String, String> = serde_json::from_value(signed["headers"].clone())
        .unwrap_or_else(|error| panic!("the signed headers must be a map: {error}; {signed}"));
    assert!(
        headers["Signature-Input"].contains(&format!("nonce=\"{nonce}\"")),
        "the caller's nonce must land in @signature-params: {:?}",
        headers["Signature-Input"]
    );

    let mut request_headers: BTreeMap<String, String> =
        [("content-type".to_string(), "application/json".to_string())].into_iter().collect();
    request_headers.extend(headers);

    anp::authentication::verify_http_message_signature(
        &daemon.document,
        "POST",
        url,
        &request_headers,
        Some(body.as_bytes()),
    )
    .expect("a signature carrying a caller-chosen nonce must verify upstream");
}

// ————————————————————————————————————————————————————————————
// 4. 失败的时候不许多嘴
// ————————————————————————————————————————————————————————————

/// An old client cannot unlock through MCP; rejection must not echo its secret.
#[test]
fn unlock_is_not_available_over_mcp() {
    let daemon = Daemon::start();
    let mut mcp = Mcp::start(&daemon.sock);

    let message = mcp.request(8, "tools/call", json!({
        "name": "unlock",
        "arguments": {"did": daemon.did, "passphrase": "not the passphrase"},
    }));

    let error = message.get("error").unwrap_or_else(|| {
        panic!("the removed unlock tool must return an MCP error: {message}")
    });
    let rendered = error.to_string();
    assert!(
        !rendered.contains("not the passphrase"),
        "the refusal must not echo the passphrase back: {rendered}"
    );
    assert!(
        !rendered.to_lowercase().contains("credential"),
        "the removed tool must not reach daemon credential verification: {rendered}"
    );
}
