//! 反例清单 —— 计划 §十 的那十条,一条一个 `#[test]`。
//!
//! # 为什么单开一个文件,而不是并进各自的单元测试
//!
//! 单元测试回答的是"这个函数在它的假设下对不对";这一份回答的是**"这个产品
//! 承诺过的那十件事,今天还成立吗"**。两者的失败含义不一样:前者红了是代码
//! 写错了,后者红了是**有人把一道墙拆了**。所以它们值得一个自己的文件、一个
//! 自己的名字,以及一条一条列出来的样子 —— 读这份文件的人应该能一眼数出十
//! 条,并且看出每一条挡的是什么。
//!
//! 用**公开 API**,不碰 crate 内部:一份"从外面看这个系统"的检查,如果必须
//! 借道内部状态才跑得起来,那它检查的就不是这个系统了。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anpio_key::audit::{AuditLog, Event};
use anpio_key::did::document;
use anpio_key::crypto::hygiene::LockedBytes;
use anpio_key::crypto::kdf::Argon2Config;
use anpio_key::daemon::peer::{self, PeerPolicy};
use anpio_key::daemon::autolock::Autolock;
use anpio_key::daemon::state::{DaemonState, Roots, SigningGates};
use anpio_key::did::document::DidDocumentSpec;
use anpio_key::error::KeydError;
use anpio_key::keystore::layout::KeydLayout;
use anpio_key::keystore::hardware::HardwareChoice;
use anpio_key::keystore::{create, device, store, unwrap};
use anpio_key::sign::rfc9421::SignRequest;
use serde_json::Value;
use zeroize::Zeroizing;

const PASSPHRASE: &[u8] = b"a passphrase that is not in the audit log";
/// 谁在这台机器上。`DaemonState` 的每一格都按 uid 分开。
const UID: u32 = 501;

/// Argon2 用测试参数:这里验的是"哪条路被拒",不是抗爆破强度。
fn fast() -> Argon2Config {
    Argon2Config { m_cost: 1024, t_cost: 1, p_cost: 1 }
}

/// 一个用完就删的目录。
///
/// 名字必须真的唯一:测试是并行起的,而两条测试共用同一个根目录的后果
/// 是"另一条把 device.secret 删了",症状看起来完全无关。计数器是唯一
/// 不会撞的那个东西。
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let path = PathBuf::from("/tmp").join(format!(
            "keyd-neg-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("create the temp dir");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    /// 一个已经装好一把钥匙的密钥库,外加**已发布**的那份文档(带 proof)
    /// —— 和别人从 `did.json` 抓到的一模一样,验签用的就是它。
    fn with_a_key(tag: &str) -> (Self, KeydLayout, create::Created, Value) {
        let dir = TempDir::new(tag);
        let layout = KeydLayout::at(dir.path().to_path_buf());
        layout.ensure().unwrap();
        let spec = DidDocumentSpec::new("example.com", vec!["agents".into(), tag.into()]);
        let created =
            create::create(&layout, &spec, "default", PASSPHRASE, fast(), HardwareChoice::None).expect("create a key");

        let device_secret = device::load(&layout).unwrap();
        let key = unwrap::unlock(&created.wrapped, PASSPHRASE, &device_secret).unwrap();
        let signed = document::publishable(&spec, &created.did, &key).unwrap();
        store::write_did_document(&layout, &created.did, &signed).unwrap();
        drop(key);
        (dir, layout, created, signed)
    }

    /// 一个空布局。
    fn empty(tag: &str) -> (Self, KeydLayout) {
        let dir = TempDir::new(tag);
        let layout = KeydLayout::at(dir.path().to_path_buf());
        layout.ensure().unwrap();
        // 一个连 device.secret 都没有的根目录,和一台刚装好的机器一样。
        device::load_or_create(&layout).unwrap();
        (dir, layout)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 拿一个"必须失败"的结果,而不用 `unwrap_err`。
///
/// 不是风格问题:`unwrap_err` 要求 `Ok` 那半边实现 `Debug`,而
/// `LockedSigningKey` **故意没有** `Debug` —— 不给它 Debug 正是"密钥不进日志、
/// 不进 panic 消息"这条纪律的一部分。所以外面的人只能这样拆。
fn refusal<T>(result: anpio_key::error::Result<T>, what: &str) -> KeydError {
    match result {
        Ok(_) => panic!("{what}"),
        Err(error) => error,
    }
}

fn state_for(layout: KeydLayout, raw_signing: bool) -> DaemonState {
    DaemonState::new(
        Roots::Single(layout),
        PeerPolicy::default(),
        Autolock::idle(Duration::from_secs(900)),
        SigningGates::new(raw_signing, false),
    )
}

fn request() -> SignRequest {
    SignRequest {
        method: "POST".to_string(),
        url: "https://example.com/api".to_string(),
        headers: BTreeMap::new(),
        body: Some(b"{\"hello\":1}".to_vec()),
        covered: Vec::new(),
        nonce: None,
    }
}

// ————————————————————————————————————————————————————————————
// 1. 跨 uid 取 key
// ————————————————————————————————————————————————————————————

/// **同一个 uid 之外的东西,连"有没有这把钥匙"都不该知道。**
///
/// 注意这条测试断言的是 `KeyNotFound`,不是 `Permission`。这个区别是有内容
/// 的:`Permission` 等于承认"有这么一把钥匙,只是不给你" —— 那本身就是泄露。
/// 而对端确实是从**另一个根目录**来的,那里什么都没有,所以"没有"是唯一
/// 既说得通、又不多嘴的答案。
#[test]
fn one_uid_cannot_reach_another_uids_key() {
    let (_victim_dir, victim_layout, victim, _) = TempDir::with_a_key("victim");
    let victim_state = state_for(victim_layout, false);

    let (_attacker_dir, attacker_layout) = TempDir::empty("attacker");
    let attacker_state = state_for(attacker_layout, false);

    // 攻击者一字不差地报出受害者的 DID —— 结果和"报了一个不存在的 DID"一样。
    assert!(attacker_state.list_keys(UID).unwrap().is_empty());
    assert!(matches!(
        attacker_state
            .unlock(UID, &victim.did, None, Zeroizing::new(String::from_utf8_lossy(PASSPHRASE).into_owned()))
            .unwrap_err(),
        KeydError::KeyNotFound(_)
    ));
    assert!(matches!(
        attacker_state.sign_structured(UID, &victim.did, None, &request()).unwrap_err(),
        KeydError::KeyNotFound(_)
    ));

    // 而受害者那把钥匙好好的。
    victim_state
        .unlock(UID, &victim.did, None, Zeroizing::new(String::from_utf8_lossy(PASSPHRASE).into_owned()))
        .unwrap();
    assert!(victim_state.sign_structured(UID, &victim.did, None, &request()).is_ok());
}

// ————————————————————————————————————————————————————————————
// 2. 无 device.secret 解封
// ————————————————————————————————————————————————————————————

/// **半个秘密打不开信封,而且不是"降级打开"。**
///
/// 信封的熵一半来自口令、一半来自 `device.secret`。少了后者,手上剩下的东西
/// 不比一个口令保护的压缩包多 —— 而这里要断言的不是"打不开",是**没有一条
/// 代码会顺手生成一个新的 device.secret 然后把信封打开**:那会静默地把一个
/// 两因子的东西变成一个单因子的东西,而且用户看不出任何区别。
#[test]
fn an_envelope_does_not_open_without_the_device_secret() {
    let (dir, layout, created, _) = TempDir::with_a_key("no-device");
    let wrapped = store::load(&layout, &created.wrapped.id.thumbprint).unwrap();

    // 文件整个不在:报的是"device secret 缺失",不是"顺手生成一个"。
    std::fs::remove_file(dir.path().join("device.secret")).unwrap();
    assert!(matches!(device::load(&layout), Err(KeydError::BadDeviceSecret)));
    // 而"生成一个新的"这条路是**显式**的 —— 它会生成,但生成出来的那把
    // 打不开旧信封。两件事分开,人才可能看出自己丢了什么。
    let fresh = device::load_or_create(&layout).unwrap();
    assert!(matches!(
        unwrap::unlock(&wrapped, PASSPHRASE, &fresh),
        Err(KeydError::BadPassphrase)
    ));
}

// ————————————————————————————————————————————————————————————
// 3. 口令错
// ————————————————————————————————————————————————————————————

/// **口令错和 device.secret 不对,必须给出一模一样的回答。**
///
/// 这条测的其实不是"错口令打不开",是**两者不可区分**。分得开的话,攻击者
/// 就能用"这次报错和上次不一样"来判断自己猜对了一半 —— 而在这套信封里,
/// 半对等于全错。
#[test]
fn the_wrong_passphrase_and_the_wrong_device_secret_are_indistinguishable() {
    let (_dir, layout, created, _) = TempDir::with_a_key("credentials");
    let wrapped = store::load(&layout, &created.wrapped.id.thumbprint).unwrap();
    let real_device = device::load(&layout).unwrap();

    let wrong_passphrase = refusal(
        unwrap::unlock(&wrapped, b"not the passphrase", &real_device),
        "the wrong passphrase must not open the envelope",
    );

    let other_device = LockedBytes::fill(|bytes| *bytes = [0x5a; 32]).unwrap();
    let wrong_device = refusal(
        unwrap::unlock(&wrapped, PASSPHRASE, &other_device),
        "a foreign device secret must not open the envelope",
    );

    assert!(matches!(wrong_passphrase, KeydError::BadPassphrase));
    assert!(matches!(wrong_device, KeydError::BadPassphrase));
    assert_eq!(
        wrong_passphrase.to_string(),
        wrong_device.to_string(),
        "the two failures must not be distinguishable from the outside"
    );

    // 而这一条不是"永远打不开"的托词:正确的两半确实打得开。
    assert!(unwrap::unlock(&wrapped, PASSPHRASE, &real_device).is_ok());
}

// ————————————————————————————————————————————————————————————
// 4. AAD 不匹配(信封改名)
// ————————————————————————————————————————————————————————————

/// **把信封的文件名换成另一个身份的名字,必须在解密之前就停住。**
///
/// AAD 覆盖的是头(身份 + 公钥),它在解封之前被重算并比对。所以这一条挡的是
/// "有人把 A 的信封搬到 B 的位置上" —— 一个只看密文、不看头的实现会把它解
/// 出来,然后**成功**解出一把和文件名不符的钥匙。
#[test]
fn an_envelope_renamed_to_another_identity_is_refused_before_decryption() {
    let (_dir, layout, first, _) = TempDir::with_a_key("rename");
    let envelope = store::load(&layout, &first.wrapped.id.thumbprint).unwrap();

    // 换掉头里的身份,别的字节原样不动 —— 密文仍然是好的,坏的只有 AAD。
    let mut relabelled = envelope.clone();
    relabelled.id.did = "did:wba:example.com:agents:someone-else:e1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
    relabelled.id.kid = format!("{}#key-1", relabelled.id.did);

    let device_secret = device::load(&layout).unwrap();
    assert!(matches!(
        unwrap::unlock(&relabelled, PASSPHRASE, &device_secret),
        Err(KeydError::AadMismatch)
    ));
}

// ————————————————————————————————————————————————————————————
// 5. 未开开关的 raw 签名
// ————————————————————————————————————————————————————————————

/// **"用我的私钥签任意字节"这条口子默认不存在,而且拒绝的话要说清楚。**
///
/// 它是守护进程里唯一一条能给调用方**任意签名**的路,一旦默认打开,授权模型
/// 就只剩 uid + 可执行文件身份一道墙 —— 而那道墙挡不住同一个 uid 下另一个
/// agent 冒充我。
#[test]
fn raw_signing_is_refused_while_the_switch_is_off() {
    let (_dir, layout, created, _) = TempDir::with_a_key("raw-off");
    let state = state_for(layout, false);

    state
        .unlock(UID, &created.did, None, Zeroizing::new(String::from_utf8_lossy(PASSPHRASE).into_owned()))
        .unwrap();

    // 解锁了也不行 —— 开关是开关,和"钥匙在不在内存里"无关。
    assert!(matches!(
        state.sign_raw(UID, &created.did, None, |_key| Ok(())),
        Err(KeydError::RawDisabled)
    ));

    // 而操作者显式打开之后它是通的 —— 否则这条测试等于在验一个死开关。
    let (_dir2, layout2, created2, _) = TempDir::with_a_key("raw-on");
    let state2 = state_for(layout2, true);
    state2
        .unlock(UID, &created2.did, None, Zeroizing::new(String::from_utf8_lossy(PASSPHRASE).into_owned()))
        .unwrap();
    assert!(state2.sign_raw(UID, &created2.did, None, |_key| Ok(())).is_ok());
}

// ————————————————————————————————————————————————————————————
// 6. 结构化请求的字段被篡改后验签失败
// ————————————————————————————————————————————————————————————

/// **调用方声明什么不重要,签名覆盖的是守护进程重建出来的那份请求。**
///
/// 计划 §M3 的反例二:调用方说"我要覆盖 `@method` 和 `@target-uri`",同时
/// 把 URL 指向别的域 —— 而签名基是守护进程自己从**字段的真实值**重建的,
/// 于是签出来的是真实那个 URL。拿被篡改的那份去验,**必须验不过**。
///
/// 这里用上游的验签实现,不是我们自己的:一段自己验自己的代码,错了只会跟着
/// 一起错。
#[test]
fn a_signature_does_not_verify_against_a_tampered_request() {
    let (_dir, layout, created, document) = TempDir::with_a_key("tamper");
    let state = state_for(layout, false);
    state
        .unlock(UID, &created.did, None, Zeroizing::new(String::from_utf8_lossy(PASSPHRASE).into_owned()))
        .unwrap();

    let request = request();
    let signed = state
        .sign_structured(UID, &created.did, None, &request)
        .expect("sign");

    let mut headers = request.headers.clone();
    headers.extend(signed.headers.clone());

    // ① 换一个目标 URL —— 验不过。
    assert!(
        verify(&document, &request, "https://evil.example.com/api", &headers).is_err(),
        "an attacker's URL must not verify against a signature made for another one"
    );
    // ② 换一个方法 —— 验不过。
    assert!(
        verify_method(&document, "DELETE", &request.url, &headers).is_err(),
        "the method is covered, so changing it must break verification"
    );
    // ③ 而原样的那份是验得过的 —— 否则上面两条什么也没证明。
    assert!(
        verify(&document, &request, &request.url, &headers).is_ok(),
        "the untampered request must verify"
    );
}

/// 目录里唯一那份当月分片。文件名是 `YYYY-MM.jsonl`。写死月份等于让这个
/// 测试在跨月的那一秒变脆 —— 而它要测的是截断,不是日历。
fn the_only_log_file(dir: &Path) -> PathBuf {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .collect();
    assert_eq!(files.len(), 1, "expected exactly one log shard in {dir:?}");
    files.pop().unwrap()
}

fn verify(
    document: &Value,
    request: &SignRequest,
    url: &str,
    headers: &BTreeMap<String, String>,
) -> Result<(), String> {
    anp::authentication::verify_http_message_signature(
        document,
        &request.method,
        url,
        headers,
        request.body.as_deref(),
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn verify_method(
    document: &Value,
    method: &str,
    url: &str,
    headers: &BTreeMap<String, String>,
) -> Result<(), String> {
    anp::authentication::verify_http_message_signature(document, method, url, headers, Some(b"{\"hello\":1}"))
        .map(|_| ())
        .map_err(|error| error.to_string())
}

// ————————————————————————————————————————————————————————————
// 7. 连接拿不到 peer credential
// ————————————————————————————————————————————————————————————

/// **拿不到对端身份 = 拒绝,没有"取不到就放行"的分支。**
///
/// 这一层是整个授权模型的地基:uid 是它给的。它一旦有降级路径,降级的那条
/// 就是"任何人都能连上来签"。
///
/// 构造方式是最朴素的那种:**一个从没有对端的 Unix socket**,于是内核真的
/// 答不出来 —— 不是模拟失败,是真的取不到。
///
/// 注意这里不是"把 socketpair 的一头关掉":两端都答得出来(凭证在连接建立
/// 时就冻结了,人走了它还在)。得是一个从没连上过的 socket。
///
/// **两个平台"答不出来"的样子不一样,而这一条正是要它们归一:**
/// - macOS:`getpeereid` / `SO_PEERCRED` 报 ENOTCONN,直接是一条错误;
/// - Linux:`SO_PEERCRED` **成功返回** `{pid: 0, uid: -1, gid: -1}` 这个哨兵
///   (实测,内核 6.x),得由 `linux_creds` 自己认出来再转成同一个拒绝。
///
/// 所以这条测试在两边是同一个断言、同一个变体 —— 如果哪天 Linux 那边又
/// 开始"成功"返回一个 uid,红的会是这里。
#[test]
fn a_connection_whose_credentials_cannot_be_read_is_refused() {
    // 一个**没有对端**的 Unix socket。
    let raw = nix::sys::socket::socket(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::Stream,
        nix::sys::socket::SockFlag::empty(),
        None,
    )
    .expect("socket");
    let ours = unsafe {
        use std::os::fd::{FromRawFd, IntoRawFd};
        std::os::unix::net::UnixStream::from_raw_fd(raw.into_raw_fd())
    };

    let error = refusal(
        peer::peer_identity(&ours),
        "a socket with no peer must not yield an identity",
    );
    assert!(
        matches!(error, KeydError::PeerCredentialUnavailable(_)),
        "the failure must be its own variant, not a generic error: {error}"
    );

    // 而活着的连接是拿得到身份的 —— 否则上面那条只是证明了"这个函数坏了"。
    let (ours, _theirs) = std::os::unix::net::UnixStream::pair().expect("socketpair");
    let identity = peer::peer_identity(&ours).expect("our own identity");
    assert_eq!(identity.uid, peer::self_uid());
}

// ————————————————————————————————————————————————————————————
// 8. 解锁超时后请求被拒
// ————————————————————————————————————————————————————————————

/// **空闲到点之后,钥匙从内存里消失,下一个请求拿到的是 `Locked`。**
///
/// 时间是被拨过去的,不是等出来的 —— 而这一点值得说明:清扫是**由请求驱动
/// 的**(每一次进 vault 都先看时间),所以"把时钟拨过线"正是生产里那个
/// 后台清扫任务做的事,不是对它的近似。
#[test]
fn a_request_after_the_idle_deadline_is_refused() {
    let (_dir, layout, created, _) = TempDir::with_a_key("idle");
    let state = state_for(layout, false);
    state
        .unlock(UID, &created.did, None, Zeroizing::new(String::from_utf8_lossy(PASSPHRASE).into_owned()))
        .unwrap();
    assert!(state.sign_structured(UID, &created.did, None, &request()).is_ok());

    let past_the_deadline = Instant::now() + Duration::from_secs(901);
    assert_eq!(state.sweep_all(past_the_deadline), 1, "the idle key must be dropped");

    assert!(matches!(
        state.sign_structured(UID, &created.did, None, &request()).unwrap_err(),
        KeydError::Locked
    ));
}

// ————————————————————————————————————————————————————————————
// 9. 同一 key 并发两次 sign
// ————————————————————————————————————————————————————————————

/// **并发签名不许交错:要么排队,要么明确拒绝。**
///
/// 这条测试能断言的东西比"不交错"弱一点,但它是**可以从外面看见**的那部分:
/// 每个线程都拿到一个能验过的签名,而且签名基摘要两两不同 —— 后者说明每次
/// 签名都用了新的 nonce,没有两次请求共用过同一个 signature base(那正是
/// 交错会留下的痕迹)。
#[test]
fn concurrent_signatures_on_one_key_do_not_interleave() {
    let (_dir, layout, created, document) = TempDir::with_a_key("concurrent");
    let state = Arc::new(state_for(layout, false));
    state
        .unlock(UID, &created.did, None, Zeroizing::new(String::from_utf8_lossy(PASSPHRASE).into_owned()))
        .unwrap();

    const THREADS: usize = 8;
    let digests = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();

    for _ in 0..THREADS {
        let state = Arc::clone(&state);
        let digests = Arc::clone(&digests);
        let did = created.did.clone();
        let document = document.clone();
        handles.push(std::thread::spawn(move || {
            let request = request();
            let signed = state
                .sign_structured(UID, &did, None, &request)
                .expect("every caller must get a signature");

            // 每一个都必须是**能验过**的那个 —— 交错会签出一份自相矛盾的
            // signature input,而那种东西的症状正是验不过。
            let mut headers = request.headers.clone();
            headers.extend(signed.headers.clone());
            anp::authentication::verify_http_message_signature(
                &document,
                &request.method,
                &request.url,
                &headers,
                request.body.as_deref(),
            )
            .expect("every signature must verify");

            digests.lock().unwrap().push(signed.signature_base_digest);
        }));
    }
    for handle in handles {
        handle.join().expect("no thread may panic");
    }

    let digests = digests.lock().unwrap();
    assert_eq!(digests.len(), THREADS);
    let mut unique = digests.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        unique.len(),
        THREADS,
        "two requests sharing a signature base is what interleaving looks like"
    );
}

// ————————————————————————————————————————————————————————————
// 10. 审计文件被截断
// ————————————————————————————————————————————————————————————

/// **把审计日志截短,下一次打开必须发现。**
///
/// 审计的价值全在于"它记的都是真事"。一份可以被悄悄删掉几条的日志,事后
/// 说不清任何事 —— 而"删掉几条"正是攻破机器之后第一件会做的事。所以链和
/// 锚两样都在:链抓**改动**,锚抓**截断**(截掉尾巴的那一段,链自己是自洽的)。
#[test]
fn a_truncated_audit_log_is_detected_when_it_is_next_opened() {
    let dir = TempDir::new("audit");
    let mut log = AuditLog::open(dir.path()).expect("a fresh log opens");

    for _ in 0..4 {
        log.append(&Event::Unlocked {
            uid: UID,
            did: "did:wba:example.com:agents:audit:e1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        })
        .unwrap();
    }
    drop(log);

    // 干净地重开一次:不该报错,否则下面那条"报错"什么都证明不了。
    assert!(AuditLog::open(dir.path()).is_ok());

    // 砍掉最后一行 —— 链本身仍然是自洽的(每一行都还指着前一行),只有
    // 锚记得这里曾经更多。
    let path = the_only_log_file(dir.path());
    let text = std::fs::read_to_string(&path).unwrap();
    let mut lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 4);
    lines.pop();
    std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();

    let error = AuditLog::open(dir.path()).expect_err("a truncated log must be refused");
    let message = error.to_string();
    assert!(
        message.contains("audit"),
        "the refusal has to say which file is in question: {message}"
    );
}
