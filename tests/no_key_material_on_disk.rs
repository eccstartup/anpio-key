//! 计划 §九 M4 验收 #2:`grep -r --binary -e "<私钥hex前缀>" <密钥库> <agent 目录>`
//! → **零命中**。
//!
//! # 为什么这条测试得用一把"我知道的"种子
//!
//! 别处的测试都是让 `create` 自己生成种子 —— 那是对的,但没法用来搜磁盘:
//! 不知道要找什么,`grep` 永远零命中,而**一条永远零命中的测试什么都没证明**。
//! 所以这里反着来:选 32 个字节,自己把这把种子封成信封(`wrap::seal`,和
//! 导入用同一个函数),于是这 32 个字节是这份测试里的已知量。
//!
//! # 搜的不是一种写法,是七种
//!
//! 只搜十六进制是不够的:这个代码库里秘密**存的是 base64**(见
//! `record::encode_b64`),所以真要漏,漏的多半是 base64 那一份。raw、
//! 大小写十六进制、标准/URL-safe base64 各带不带填充,七种写法一起搜。
//!
//! # 扫完之后还得证明这把尺子量得出东西
//!
//! `the_scanner_finds_a_leak_when_there_is_one` 把种子故意写进同一个目录,
//! 确认七个写法全被抓到。少了这一条,上面那些零命中断言可能只是"我的扫描器
//! 坏了"—— 而那和"没有泄露"在报告里长得一模一样。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anpio_key::client::Client;
use anpio_key::crypto::hygiene::LockedBytes;
use anpio_key::crypto::kdf::Argon2Config;
use anpio_key::crypto::thumbprint::e1_segment;
use anpio_key::daemon::peer::PeerPolicy;
use anpio_key::daemon::state::{autolock_from_secs, DaemonState, Roots, SigningGates};
use anpio_key::daemon::wire::SignRequest;
use anpio_key::daemon::{server, ServerConfig};
use anpio_key::keystore::layout::KeydLayout;
use anpio_key::keystore::record::{KeyAlgorithm, KeyId};
use anpio_key::keystore::{device, store, wrap};
use base64::Engine;

/// 这把钥匙的种子。**这份测试里唯一的已知量** —— 没有它,下面每一条
/// grep 断言都会以"零命中"的样子通过,不管实现对不对。
const SEED: [u8; 32] = [
    0x3b, 0x91, 0x7d, 0x2e, 0xc4, 0x05, 0xa8, 0x6f, 0x12, 0xde, 0x53, 0x80, 0xbb, 0x47, 0x1c, 0xf9,
    0x60, 0x2a, 0x95, 0xee, 0x38, 0x74, 0xd1, 0x0b, 0xc6, 0x1f, 0x8a, 0x3d, 0x52, 0xe7, 0x99, 0x24,
];

const PASSPHRASE: &[u8] = b"disk passphrase";

fn fast() -> Argon2Config {
    Argon2Config { m_cost: 1024, t_cost: 1, p_cost: 1 }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let path = PathBuf::from("/tmp").join(format!(
            "keyd-disk-{tag}-{}-{}",
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

// ————————————————————————————————————————————————————————————
// 尺子:七种写法
// ————————————————————————————————————————————————————————————

/// 一个秘密在这份代码库里可能长成的样子。
///
/// 返回 `(名字, 字节)` 而不是 `String` —— 磁盘上是字节,拿 `String` 比会把
/// 非 UTF-8 的文件整个跳过,而那恰好是"二进制文件里有私钥"这种情况。
fn forms(secret: &[u8; 32]) -> Vec<(&'static str, Vec<u8>)> {
    let hex = secret.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let upper = hex.to_uppercase();
    let std_engine = base64::engine::general_purpose::STANDARD;
    let url_engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    vec![
        ("raw", secret.to_vec()),
        ("hex", hex.clone().into_bytes()),
        ("HEX", upper.into_bytes()),
        ("base64", std_engine.encode(secret).into_bytes()),
        ("base64-no-pad", std_engine.encode(secret).trim_end_matches('=').as_bytes().to_vec()),
        ("base64url", std_engine.encode(secret).replace('+', "-").replace('/', "_").into_bytes()),
        ("base64url-no-pad", url_engine.encode(secret).into_bytes()),
    ]
}

/// 扫一棵目录树,把命中的 `(文件, 写法)` 全列出来。
///
/// 按字节扫,不按行、不按 UTF-8 —— 要漏的话不会体贴地漏在文本文件里。
fn scan(root: &Path, needles: &[(&'static str, Vec<u8>)]) -> Vec<(PathBuf, &'static str)> {
    let mut hits = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&path) {
                stack.extend(entries.flatten().map(|entry| entry.path()));
            }
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        for (name, needle) in needles {
            if bytes.windows(needle.len()).any(|window| window == needle.as_slice()) {
                hits.push((path.clone(), *name));
            }
        }
    }
    hits
}

// ————————————————————————————————————————————————————————————
// 一台真的机器:已知种子 → 信封 → 守护进程 → 签一条请求
// ————————————————————————————————————————————————————————————

struct Machine {
    _dir: TempDir,
    /// 得握着,松手等于当场把守护进程关掉(见 `signature_end_to_end.rs`)。
    _stop: tokio::sync::watch::Sender<bool>,
    sock: PathBuf,
    layout: KeydLayout,
    /// agent 干活的那个目录 —— 计划 #2 里的 `/tmp/agent-workdir`。
    workdir: PathBuf,
    did: String,
    document: serde_json::Value,
}

impl Machine {
    fn start() -> Self {
        let dir = TempDir::new("machine");
        let layout = KeydLayout::at(dir.path().join("root"));
        layout.ensure().unwrap();
        let workdir = dir.path().join("agent-workdir");
        std::fs::create_dir_all(&workdir).unwrap();

        // ① 已知种子 → 公钥 → 指纹 → DID。指纹那一段必须**真的**是这把
        //    公钥的,否则 DID 和信封对不上,签名那一步会以别的原因失败。
        let mut seed = SEED;
        let seed = LockedBytes::new(&mut seed).unwrap();
        let (verifying, public_multibase) = wrap::seed_to_public(&seed);
        let fingerprint = e1_segment(&verifying).unwrap();
        let did = format!("did:wba:example.com:agents:disk:{fingerprint}");
        let fragment = "key-1";

        // ② 封成信封 —— 和导入用的是**同一个** `wrap::seal`,不是另一条路。
        let device_secret = device::load_or_create(&layout).unwrap();
        let wrapped = wrap::seal(wrap::SealRequest {
            id: KeyId {
                kid: format!("{did}#{fragment}"),
                did: did.clone(),
                thumbprint: fingerprint.clone(),
            },
            algorithm: KeyAlgorithm::Ed25519,
            public_multibase,
            label: "disk".into(),
            passphrase: PASSPHRASE,
            device_secret: &device_secret,
            seed: &seed,
            argon: fast(),
            hardware: None,
        })
        .unwrap();
        store::save_new(&layout, &wrapped).unwrap();

        // ③ 一份带 proof 的文档,落盘。
        //
        // **必须落盘**:守护进程的签名路径会先把这份文档读出来
        // (`state::sign_structured` 里那一步,决定覆盖面的是它),没有文档
        // 就没有签名这条路 —— 而这条测试要的正是"签过一次之后",所以少了
        // 这一步会以一个看起来毫不相干的 `KeyNotFound` 失败。
        let key = anpio_key::keystore::unwrap::unlock(&wrapped, PASSPHRASE, &device_secret).unwrap();
        let unsigned = anpio_key::did::document::rebuild(&did, &key.verifying_key()).unwrap();
        let document =
            anpio_key::did::document::sign_document(&unsigned, &key, &wrapped.id.kid).unwrap();
        anpio_key::did::document::verify_path_binding(&did, &document).unwrap();
        store::write_did_document(&layout, &did, &document).unwrap();
        drop(key);

        // ④ 守护进程。它自己再建一个布局对象 —— `KeydLayout` 不是 `Clone`
        //    (它是一份路径推导,没有共享状态可言),这正是 `--root` 那条
        //    约定在类型上的样子。
        let sock = layout.sock_path();
        let state = Arc::new(DaemonState::new(
            Roots::Single(KeydLayout::at(dir.path().join("root"))),
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
        std::mem::forget(runtime);

        Self { _dir: dir, _stop: stop_tx, sock, layout, workdir, did, document }
    }

    /// 解锁 + 签一条请求,把守护进程给的头**照 agent 会做的那样**写进工作目录。
    ///
    /// 走 socket,不走库函数:agent 够得到的只有 socket 这一条路,而这条测试
    /// 要证明的正是"它从这条路上拿到的东西里没有种子"。
    fn sign_as_an_agent_would(&self) -> Vec<u8> {
        let sock = self.sock.clone();
        let did = self.did.clone();
        let signed = tokio::task::block_in_place(|| {
            let mut client = Client::connect(&sock).unwrap();
            client
                .unlock(&did, None, std::str::from_utf8(PASSPHRASE).unwrap())
                .unwrap();
            client
                .sign(SignRequest::Structured {
                    did,
                    kid: None,
                    method: "POST".into(),
                    target_uri: "https://example.com/agents/disk/resource".into(),
                    headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
                    body: Some(br#"{"hello":"disk"}"#.to_vec()),
                    covered: vec![],
                    nonce: None,

                })
                .unwrap()
        });

        // agent 拿到头之后会把它落到自己的目录里 —— 那正是 #2 要搜的地方。
        std::fs::write(self.workdir.join("signed-request.headers"), &signed).unwrap();
        std::fs::write(
            self.workdir.join("request.http"),
            b"POST /agents/disk/resource HTTP/1.1\nhost: example.com\n",
        )
        .unwrap();
        signed
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

// ————————————————————————————————————————————————————————————
// 1. 计划 §九 M4 #2 本文
// ————————————————————————————————————————————————————————————

/// **私钥不在密钥库里,也不在 agent 的目录里。**
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_seed_is_on_no_disk_the_agent_can_reach() {
    let machine = Machine::start();
    let signed = machine.sign_as_an_agent_would();

    // 先说这次签名是真的成了 —— 否则下面"什么都没搜到"可能只是因为**什么
    // 都没发生**。
    let headers = anpio_key::client::parse_signed_headers(&signed).unwrap();
    assert!(headers.contains_key("Signature"), "{headers:?}");
    anp::authentication::verify_http_message_signature(
        &machine.document,
        "POST",
        "https://example.com/agents/disk/resource",
        &headers,
        Some(br#"{"hello":"disk"}"#),
    )
    .expect("the signature this test is built around must verify");

    let needles = forms(&SEED);
    for where_to_look in [machine.layout.root(), machine.workdir.as_path()] {
        let hits = scan(where_to_look, &needles);
        assert!(
            hits.is_empty(),
            "the seed is on disk under {}: {hits:?}\n\
             (the whole point is that these 32 bytes exist nowhere the agent can read)",
            where_to_look.display()
        );
    }
}

/// 密钥库里那把信封在,**而且它是密的** —— 上一条不搜到东西,不能是因为
/// 什么都没生成。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_envelope_is_there_and_carries_no_plaintext() {
    let machine = Machine::start();
    machine.sign_as_an_agent_would();

    let envelopes = machine.layout.list_key_paths().unwrap();
    assert_eq!(envelopes.len(), 1, "the machine should hold exactly one envelope");

    let raw = std::fs::read_to_string(&envelopes[0]).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
    for field in ["sk_ciphertext", "dek_ciphertext"] {
        assert!(
            parsed[field].as_str().is_some_and(|value| value.len() >= 32),
            "the envelope should carry a real `{field}`: {parsed}"
        );
    }
    // 公钥是公开的,写在信封里没问题 —— 这条断言把"哪些能明文、哪些不能"
    // 划清楚,免得以后有人为了"顺手"把种子也塞进来。
    assert!(parsed["public_multibase"].as_str().is_some(), "{parsed}");
}

// ————————————————————————————————————————————————————————————
// 2. 这把尺子量得出东西
// ————————————————————————————————————————————————————————————

/// **故意漏一次,确认七个写法全被抓到。**
///
/// 没有这一条,上面那些"零命中"可能是扫描器坏了。而"扫描器坏了"和"没有
/// 泄露"在报告里长得一模一样 —— 这正是这份文件存在的理由,所以尺子本身
/// 也得量一遍。
#[test]
fn the_scanner_finds_a_leak_when_there_is_one() {
    let dir = TempDir::new("scanner");
    let needles = forms(&SEED);

    // 干净的时候:零命中。
    std::fs::write(dir.path().join("harmless.txt"), b"nothing to see here").unwrap();
    assert!(scan(dir.path(), &needles).is_empty(), "a clean directory must scan clean");

    // 每种写法各漏一次,每一次都必须被抓到 —— 漏一个,上面那些断言就多
    // 一个盲区。
    for (name, needle) in &needles {
        let planted = dir.path().join(format!("leak-{name}.bin"));
        std::fs::write(&planted, needle).unwrap();

        let hits = scan(dir.path(), &needles);
        assert!(
            hits.iter().any(|(path, _)| *path == planted),
            "the scanner missed a leak written as `{name}` — those bytes would \
             have gone unnoticed in the on-disk test too"
        );
        std::fs::remove_file(&planted).unwrap();
    }
}

/// 扫描器要**按字节**扫。一个"跳过非 UTF-8"的实现会在最该响的时候安静:
/// 私钥落在一个二进制文件里,恰恰是最真实的那种漏法。
#[test]
fn the_scanner_reads_binary_files_too() {
    let dir = TempDir::new("binary");
    let needles = forms(&SEED);

    // 前面塞一段非法 UTF-8,后面才是种子。
    let mut blob = vec![0xff, 0xfe, 0x00, 0x80, 0xc3, 0x28];
    blob.extend_from_slice(&SEED);
    std::fs::write(dir.path().join("binary.bin"), &blob).unwrap();

    let hits = scan(dir.path(), &needles);
    assert!(
        !hits.is_empty(),
        "a seed embedded in a binary file must still be found — otherwise the \
         strongest form of the leak is the one the test is blind to"
    );
}
