//! 改文档里的钥匙:加恢复密钥、轮换热密钥、摘掉一把。
//!
//! 三个命令共用同一条脊柱:
//!
//! ```text
//! 读本地文档 → 算摘要 → 解绑定密钥 → 改文档 → 生成新钥匙 → 签名 → 自检
//!            → 人点头 → CAS 写文档
//! ```
//!
//! 这条脊柱上**只有绑定密钥**需要解开。新加的那把是在本进程里生成的,它
//! 一生成就立刻被封进信封,此后只以 `LockedBytes` 的形态存在 —— 也就是说
//! 整个命令期间,明文 seed 最多只有一份活着。
//!
//! ## 顺序:钥匙先落盘,文档后落盘
//!
//! 反过来的话,一份指向"本机没有的钥匙"的文档会先落地 —— 而那份文档谁
//! 也签不出来,包括它自己的绑定密钥(`authentication` 里挂着一把打不开的
//! 钥匙)。先写钥匙,最坏的结果是多一个没人用到的信封,删掉就行。
//!
//! ## 为什么摘钥匙要单独一个命令
//!
//! 计划里的 CLI 清单只有"加"和"轮换"。但一把**泄露**的热密钥必须能被摘掉,
//! 而"轮换"做不到这件事:轮换只保证以后签名用新的那把,被泄露的那把
//! **还在文档里** —— 任何人拿它签的东西都照样验得过。摘掉是唯一能让一把
//! 已经不在我们手上的私钥停止生效的动作。

use std::path::Path;

use zeroize::Zeroizing;

use crate::audit::Event;
use crate::crypto::kdf::Argon2Config;
use crate::did::lifecycle;
use crate::error::Result;
use crate::keystore::create;
use crate::keystore::hardware::HardwareChoice;
use crate::ops::{hosting_notice, sign_confirm_and_write, Session};

/// 加一把恢复密钥。
pub struct AddRecoveryKey {
    pub did: String,
    /// 人读的标签。它进 AAD,所以改它要重封,不是改个注释。
    pub label: String,
    /// 新信封要不要绑一根硬件根。见 [`crate::cli::HardwareArgs`]。
    ///
    /// 恢复密钥尤其值得绑:它的用途是"别的都没了的时候用它搬家",所以它比
    /// 任何一把钥匙都更可能被抄到 U 盘或者备份盘上 —— 而硬件绑定的作用恰恰
    /// 就是让那份拷贝在别的机器上打不开。
    pub hardware: HardwareChoice,
}

pub fn add_recovery_key(root: Option<&Path>, args: AddRecoveryKey) -> Result<()> {
    use anp::authentication::DidVerificationRelationship as R;

    let mut session = Session::open(root)?;
    let (document, expected) = session.current_document(&args.did)?;

    // fragment 在**改动之前**的文档上算:算完之后那个编号就归新钥匙了,
    // 而 `next_fragment` 的规则是"用过的最大编号 + 1"。它还要看本机信封 ——
    // 一份文档记不住已经被摘掉的编号。
    let used = crate::keystore::store::envelope_fragments(session.layout(), &args.did)?;
    let fragment = lifecycle::next_fragment(
        &document,
        &args.did,
        lifecycle::RECOVERY_FRAGMENT_PREFIX,
        &used,
    )?;

    let binding_passphrase = session.ask_secret(&binding_prompt(&args.did))?;
    let (_, binding) = session.unlock_with(&args.did, None, binding_passphrase.as_bytes())?;

    let passphrase = new_key_passphrase(&session, &binding_passphrase)?;
    let (wrapped, key) = create::create_extra(
        session.layout(),
        &args.did,
        &fragment,
        vec![R::AssertionMethod],
        &args.label,
        passphrase.as_bytes(),
        Argon2Config::default(),
        args.hardware,
    )?;

    let updated =
        lifecycle::with_extra_key(&document, &args.did, &binding.verifying_key()?, key)?;

    let digest = sign_confirm_and_write(
        &session,
        &args.did,
        &binding,
        &updated,
        &expected,
        &format!(
            "Add a recovery key to {}.\n\n\
             It lands in `assertionMethod` and NOT in `authentication`: it can sign one\n\
             thing, a migration away from this DID, and it cannot sign requests.\n\n\
             new key: {}#{}",
            args.did, args.did, fragment
        ),
    )?;

    session.audit(&Event::AddRecoveryKey {
        did: args.did.clone(),
        kid: format!("{}#{fragment}", args.did),
        document_digest: digest,
    })?;

    println!("added {}#{}", args.did, fragment);
    println!(
        "envelope written to {}",
        session.layout().key_path(&wrapped.id.thumbprint)?.display()
    );
    println!();
    println!("a recovery key that lives on the same machine as the DID it rescues is not");
    println!("a recovery key. Move it off this host, or its whole point is lost.");
    hosting_notice(&args.did)
}

/// 加一把协商密钥(X25519)。
///
/// 这是四类钥匙里唯一一条**不做签名**的:它只进 `keyAgreement`,只能被
/// `ECDH` 用。曲线由 `create::create_agreement` 定死,命令行给不了算法 ——
/// 一把 Ed25519 挂进 `keyAgreement` 是文档层面的错,不是选项。
pub struct AddAgreementKey {
    pub did: String,
    /// 人读的标签。它进 AAD,所以改它要重封。
    pub label: String,
    /// 信封要不要绑一根硬件根。协商密钥每次建会话都要用,而建立会话的往往
    /// 是无人值守的进程 —— 绑了硬件根,那个进程就得能碰到那根根,自己权衡。
    pub hardware: HardwareChoice,
}

pub fn add_agreement_key(root: Option<&Path>, args: AddAgreementKey) -> Result<()> {
    let mut session = Session::open(root)?;
    let (document, expected) = session.current_document(&args.did)?;

    let used = crate::keystore::store::envelope_fragments(session.layout(), &args.did)?;
    let fragment = next_agreement_fragment(&document, &args.did, &used)?;

    let binding_passphrase = session.ask_secret(&binding_prompt(&args.did))?;
    let (_, binding) = session.unlock_with(&args.did, None, binding_passphrase.as_bytes())?;

    let passphrase = new_key_passphrase(&session, &binding_passphrase)?;
    let (wrapped, key) = create::create_agreement(
        session.layout(),
        &args.did,
        &fragment,
        &args.label,
        passphrase.as_bytes(),
        Argon2Config::default(),
        args.hardware,
    )?;

    let updated =
        lifecycle::with_extra_key(&document, &args.did, &binding.verifying_key()?, key)?;

    let digest = sign_confirm_and_write(
        &session,
        &args.did,
        &binding,
        &updated,
        &expected,
        &format!(
            "Add a key-agreement key to {}.\n\n\
             It lands in `keyAgreement` and nowhere else: it is X25519, so it cannot\n\
             sign anything, and the daemon will only use it for ECDH — one shared\n\
             secret per call, never stored.\n\n\
             new key: {}#{}",
            args.did, args.did, fragment
        ),
    )?;

    session.audit(&Event::AddAgreementKey {
        did: args.did.clone(),
        kid: format!("{}#{fragment}", args.did),
        document_digest: digest,
    })?;

    println!("added {}#{}", args.did, fragment);
    println!(
        "envelope written to {}",
        session.layout().key_path(&wrapped.id.thumbprint)?.display()
    );
    hosting_notice(&args.did)
}

/// 协商密钥的名字:第一把 `device-agreement`,之后 `device-agreement-2`、`-3`…
///
/// 不复用编号,理由和热密钥一样 —— 一份缓存过的文档写着这个名字,而钥匙换了
/// 名字没换,那份缓存就成了旧钥匙的通行证。这里和 `next_fragment` 不同的
/// 只是前缀没有连字符编号:设备名本身要稳定,调用方按 kid 找键。
fn next_agreement_fragment(
    document: &serde_json::Value,
    did: &str,
    used: &std::collections::BTreeSet<String>,
) -> Result<String> {
    const BASE: &str = "device-agreement";
    let listed: Vec<String> = lifecycle::extra_keys(document, did)?
        .into_iter()
        .map(|key| key.fragment)
        .collect();
    let taken =
        |name: &str| listed.iter().any(|f| f == name) || used.contains(name);
    if !taken(BASE) {
        return Ok(BASE.to_string());
    }
    (2u32..)
        .map(|n| format!("{BASE}-{n}"))
        .find(|name| !taken(name))
        .ok_or_else(|| crate::error::KeydError::Did("no free agreement fragment".into()))
}

/// 轮换热密钥:新的一把进 `authentication`,旧的那把出文档。
pub struct RotateHotKey {
    pub did: String,
    pub label: String,
    /// 把旧的那把留在文档里(默认不留)。
    pub keep_old: bool,
    /// 新信封要不要绑一根硬件根。
    ///
    /// **只影响新生成的那把。** 退休的那一把信封原样留在磁盘上,它绑没绑
    /// 硬件、绑的是哪一根,都由它自己那个文件说了算 —— 轮换不该、也不能
    /// 悄悄重封一把别人已经用过的钥匙。
    pub hardware: HardwareChoice,
}

pub fn rotate_hot_key(root: Option<&Path>, args: RotateHotKey) -> Result<()> {
    use anp::authentication::DidVerificationRelationship as R;

    let mut session = Session::open(root)?;
    let (document, expected) = session.current_document(&args.did)?;

    let retired = lifecycle::hot_key(&document, &args.did)?;
    let retired_kid = retired
        .as_ref()
        .map(|key| format!("{}#{}", args.did, key.fragment));
    if retired.is_none() {
        println!("note: {} has no hot key yet, so this is an add, not a rotation.", args.did);
    }

    // 编号在**改动之前**算:退休的那个编号还挂在文档上,所以新编号一定比它
    // 大,不会重用。这正是热密钥编号必须单调递增的地方 —— 一个被缓存过的
    // 文档里写着"key-2 这把钥匙",钥匙换了而名字没换,那份缓存就成了一张
    // 已经作废的钥匙的通行证。
    //
    // `remove-key` 之后文档会**忘掉**那个编号,所以还得看本机信封:一把因为
    // 泄露而被摘掉的钥匙,它的编号绝不能回到池子里。
    let used = crate::keystore::store::envelope_fragments(session.layout(), &args.did)?;
    let fragment = lifecycle::next_hot_fragment(&document, &args.did, &used)?;

    let binding_passphrase = session.ask_secret(&binding_prompt(&args.did))?;
    let (_, binding) = session.unlock_with(&args.did, None, binding_passphrase.as_bytes())?;

    let passphrase = new_key_passphrase(&session, &binding_passphrase)?;
    let (wrapped, key) = create::create_extra(
        session.layout(),
        &args.did,
        &fragment,
        vec![R::Authentication],
        &args.label,
        passphrase.as_bytes(),
        Argon2Config::default(),
        args.hardware,
    )?;

    let mut updated =
        lifecycle::with_extra_key(&document, &args.did, &binding.verifying_key()?, key)?;

    if let Some(retired) = &retired {
        if args.keep_old {
            println!("keeping {}#{} in the document", args.did, retired.fragment);
        } else {
            updated = lifecycle::without_method(
                &updated,
                &args.did,
                &binding.verifying_key()?,
                &format!("{}#{}", args.did, retired.fragment),
            )?;
        }
    }

    let digest = sign_confirm_and_write(
        &session,
        &args.did,
        &binding,
        &updated,
        &expected,
        &format!(
            "Rotate the hot key for {}.\n\n\
             New key in `authentication`: {}#{}\n\
             Old key {} the document.\n\n\
             What this changes: the old key can no longer sign anything *new*, once the\n\
             document is republished. What it does not change: every signature it already\n\
             made still verifies, and whoever holds a copy of it still holds it.",
            args.did,
            args.did,
            fragment,
            if args.keep_old { "stays in" } else { "comes out of" }
        ),
    )?;

    session.audit(&Event::RotateHot {
        did: args.did.clone(),
        retired_kid,
        new_kid: format!("{}#{fragment}", args.did),
        document_digest: digest,
    })?;

    println!("new hot key {}#{}", args.did, fragment);
    println!(
        "envelope written to {}",
        session.layout().key_path(&wrapped.id.thumbprint)?.display()
    );
    hosting_notice(&args.did)
}

/// 摘掉一把非绑定密钥。
pub struct RemoveKey {
    pub did: String,
    /// **fragment**,不是完整的 `did#fragment`。
    pub kid: String,
}

pub fn remove_key(root: Option<&Path>, args: RemoveKey) -> Result<()> {
    let mut session = Session::open(root)?;
    let (document, expected) = session.current_document(&args.did)?;

    let fragment = args.kid.trim_start_matches('#').to_string();
    let full = format!("{}#{fragment}", args.did);

    let binding_passphrase = session.ask_secret(&binding_prompt(&args.did))?;
    let (_, binding) = session.unlock_with(&args.did, None, binding_passphrase.as_bytes())?;

    let updated =
        lifecycle::without_method(&document, &args.did, &binding.verifying_key()?, &full)?;

    // 本地的信封**不删**。摘掉的是"文档认它",不是"我们不再有它":删文件
    // 不可逆,而摘引用是可逆的(再 publish 一次就回来了)。把不可逆的那一步
    // 绑在一个可以后悔的动作上,是这类工具最容易犯的错。
    let envelope = crate::keystore::store::resolve(&session.layout, &args.did, Some(&fragment));

    let digest = sign_confirm_and_write(
        &session,
        &args.did,
        &binding,
        &updated,
        &expected,
        &format!(
            "Remove {full} from {}.\n\n\
             The document stops listing it. Its envelope stays on this machine — this\n\
             command will not delete it, because that cannot be undone and this can.\n\n\
             Anyone still holding a copy of that private key can keep signing with it\n\
             until the document is republished. After that, verifiers will not find it.",
            args.did
        ),
    )?;

    session.audit(&Event::RemoveKey {
        did: args.did.clone(),
        kid: full.clone(),
        document_digest: digest,
    })?;

    println!("removed {full} from the document");
    match envelope {
        Ok(wrapped) => {
            let path = session.layout().key_path(&wrapped.id.thumbprint)?;
            println!("its envelope is still at {}", path.display());
            println!("delete it by hand if you meant to destroy it — that step cannot be undone.");
            println!(
                "it is also this machine's only record that `{fragment}` was ever used, so \
                 deleting it\nlets that number be handed to a different key later — and a \
                 verifier holding an\nolder copy of the document would read the new key as \
                 the old one."
            );
        }
        Err(_) => println!("(its envelope is not on this machine)"),
    }
    hosting_notice(&args.did)
}

fn binding_prompt(did: &str) -> String {
    format!("Passphrase for {did} (its binding key): ")
}

/// 给新钥匙问一个口令。回车 = 沿用绑定密钥那个。
///
/// 允许沿用的是计划里的选择,理由也清楚:人刚刚才敲过绑定密钥的口令,而要
/// 一次轮换再敲两遍新口令,绝大多数人只会想"还是那个"。但**必须他自己按**,
/// 不能悄悄替他沿用 —— 那等于让两把钥匙共用一份口令而他从没被告知。
///
/// 代价要说清楚:沿用之后,`device.secret` **加上**这一个口令就能开两把
/// 钥匙。`device.secret` 和口令本来就是各一半的两半因素,所以这不是"从
/// 两把锁变成一把锁",但它确实让一次口令泄露的影响面从一把扩大到两把。
fn new_key_passphrase(session: &Session, binding: &Zeroizing<String>) -> Result<Zeroizing<String>> {
    loop {
        let answer =
            session.ask_secret("Passphrase for the new key (Enter = same as the binding key's): ")?;
        if !answer.is_empty() {
            return Ok(answer);
        }
        if !binding.is_empty() {
            return Ok(binding.clone());
        }
        // 绑定密钥那个口令是空的(不该发生 —— `read_secret_twice` 挡过,
        // 但那个口令可能是手工改出来的)。新钥匙不接受空口令。
        session.say("an empty passphrase is not allowed for a new key\n")?;
    }
}
