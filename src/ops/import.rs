//! 导入(恢复):把一把钥匙接回这台机器。
//!
//! # 为什么这一块**必须**在默认构建里
//!
//! 导出是编译期就不存在的(`seed-export`,见 [`super::export`]),因为
//! 那是一条"把私钥弄出来"的路。导入正好相反:**一个不能把钥匙接回来的
//! 工具不是自持工具,是把钥匙交给它了。** 所以这一块默认就在,而且和导出
//! 的开关毫无关系 —— 一个把钥匙托付给某个软件的人,最起码得能把它拿回来。
//!
//! 反过来说:默认构建拿不走你的钥匙,但接得住你的钥匙。
//!
//! # 两条路,同一个终点
//!
//! - `import-mnemonic` —— 敲 24 个词。纸比文件可靠,而且纯离线。
//! - `import-archive` —— 读一个加密归档,输导出时设的密码。
//!
//! 两条路**必须等价**:24 个词是规范表示,归档只是同一个 seed 的再加密
//! 容器。所以下面的七步走的是同一段代码,两条路只在"seed 从哪来"和"手里
//! 有没有一份文档"上分岔。
//!
//! 有一处**不等价**,而且是故意的:24 个词是整张纸,**同一个根 seed 推出的
//! 另外三把(热、设备签名、协商)也能一起恢复**;归档装的是**一把**钥匙的
//! seed,所以它只恢复那一把。见 [`restore_derived`]。
//!
//! # 导入不是"原样落盘",是"重新封装"
//!
//! 这是最容易做错的一步。归档/词里带回来的是**种子**,不是信封 —— 到了新
//! 机器上要重新走一遍封装:新的 `device.secret`(或者本机已有的那份)、新的
//! salt、新的 nonce、绑在**新的** `KeyId` 上的 AAD、以及人类**新设的一个
//! 本地口令**。
//!
//! 少了这一步,等于把导出时的口令变成这台机器的日常口令 —— 而那个口令是
//! 为了"搬一次家"设的,人在设它的时候就知道它要经过邮件、U 盘、或者任何
//! 别的东西。
//!
//! # 和迁移的分工
//!
//! **默认应该是迁移,不是导入。** 换机时正解是新设备上新生成一把钥匙、
//! 旧设备签一条 `deactivated + successorDid` —— 秘密一步都不动,而且旧设备
//! 那把钥匙被明确作废。
//!
//! 导入只在两种情况下是对的:旧设备**整台丢了、再也签不出名**;或者要从
//! 冷备份恢复**同一个 DID**(比如那个 DID 字符串已经被别人验证过了)。
//! 这两种情况下,导入之后这台机器和别人手里的那份备份**同时活着** ——
//! 而钥匙不可撤销,这件事只能靠说清楚,不能靠技术解决。

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::audit::Event;
use crate::crypto::hygiene::LockedBytes;
use crate::crypto::kdf::Argon2Config;
use crate::crypto::mnemonic;
use crate::did::document;
use crate::did::document::ExtraKey;
use crate::did::lifecycle;
use crate::did::parse::parse_did_wba;
use crate::error::{KeydError, Result};
use crate::keystore::archive::Archive;
use crate::keystore::hardware::{self, HardwareChoice};
use crate::keystore::layout::KeydLayout;
use crate::keystore::record::{KeyAlgorithm, KeyId};
use crate::keystore::{device, store, wrap};
use crate::ops::{hosting_notice, Session};
use crate::sign::LockedSigningKey;

/// 从 24 个词恢复**整套身份**:绑定密钥,加上同一个根 seed 推出的另外三把。
pub struct ImportMnemonic {
    /// 这个 DID。词里推不出它 —— 路径段是人选的,公钥只决定最后那一段。
    pub did: String,
    /// 新信封的标签。
    pub label: String,
    /// 本地已经有同一把钥匙时也照做。
    pub force: bool,
    /// 新的那几个信封要不要绑一根硬件根。
    ///
    /// **导入是重封,不是接回来**:`place` 走的是和 `keygen` 同一条封装路径。
    /// 所以一台**没有**硬件根的新机器上,`--root tpm` 会在这里失败 —— 而不是
    /// 悄悄给一个纯软件的信封。要的就是这个:一台不满足条件的机器不该假装
    /// 自己满足。
    pub hardware: HardwareChoice,
}

/// 从加密归档恢复。
pub struct ImportArchive {
    pub file: PathBuf,
    pub label: String,
    pub force: bool,
    /// 同 [`ImportMnemonic::hardware`]。归档自己那套字节一个都没变 ——
    /// 硬件绑定是**落地时**才加上的,不是归档格式的一部分。
    pub hardware: HardwareChoice,
}

pub fn import_mnemonic(root: Option<&Path>, args: ImportMnemonic) -> Result<()> {
    // 先解析 DID:**在这之前一个字节的输入都还没读**,所以打错字的 `--did`
    // 会立刻失败,而不是等人敲完 24 个词才告诉他。
    let parts = parse_did_wba(&args.did)
        .map_err(|error| KeydError::Did(format!("--did {} is not a did:wba DID: {error}", args.did)))?;
    let segment = parts.e1_segment().ok_or_else(|| {
        KeydError::Did(format!(
            "{} has no `e1_` segment, so there is nothing to bind a key to. \
             `import-mnemonic` identifies the identity by its BINDING key — the one whose \
             fingerprint IS the DID — because words alone cannot tell you which DID a \
             non-binding key belongs to (that lives in the document, and there is no \
             document here). The other three keys are then derived from the same root seed",
            args.did
        ))
    })?;
    let expected_thumbprint = segment.to_string();

    let mut session = Session::open(root)?;

    session.say(&format!(
        "\nPaste the 24 words for {}.\n\
         They are shown as you type so you can check them against the paper. Every word,\n\
         in order — the last one carries the checksum.\n\n",
        args.did
    ))?;
    let phrase = session.ask_line("Words: ")?;
    let seed = mnemonic::from_words(&phrase)?;

    place(
        &mut session,
        Recovered {
            did: args.did,
            fragment: document::ROOT_FRAGMENT.to_string(),
            // 走词这条路时,能恢复的只有绑定密钥,所以指纹就是 DID 最后那段。
            // 下面的自检因此变成"这些词是不是**这个 DID** 的"。
            thumbprint: expected_thumbprint,
            created_at: None,
            wns_handle: None,
            document: None,
            seed,
            label: args.label,
            source: "mnemonic",
            derive_extras: true,
        },
        args.force,
        args.hardware,
    )
}

pub fn import_archive(root: Option<&Path>, args: ImportArchive) -> Result<()> {
    let mut session = Session::open(root)?;

    let bytes = std::fs::read(&args.file).map_err(|error| {
        KeydError::Protocol(format!("could not read {}: {error}", args.file.display()))
    })?;
    let archive = Archive::from_bytes(&bytes)?;

    // 归档的密码**只能从终端读**。不接受 `--password`:那会把一个秘密放进
    // argv(ps 看得见)或者环境变量(同 uid 的进程读得见 /proc/<pid>/environ)。
    let password = session.ask_secret(&format!(
        "Password this archive was exported with ({}): ",
        args.file.display()
    ))?;
    let seed = crate::keystore::archive::open(&archive, password.as_bytes())?;

    let fragment = archive
        .kid
        .strip_prefix(&format!("{}#", archive.did))
        .ok_or_else(|| {
            KeydError::Protocol(format!(
                "this archive's key id `{}` does not belong to its DID `{}`",
                archive.kid, archive.did
            ))
        })?
        .to_string();

    place(
        &mut session,
        Recovered {
            did: archive.did,
            fragment,
            thumbprint: archive.thumbprint,
            created_at: Some(archive.created_at),
            wns_handle: archive.wns_handle,
            document: Some(archive.document),
            seed,
            label: args.label,
            source: "archive",
            // 归档装的是**一把**钥匙的 seed,不是根 seed。从它推不出另外三把。
            derive_extras: false,
        },
        args.force,
        args.hardware,
    )
}

/// 一条导入路径带回来的全部东西。
struct Recovered {
    did: String,
    /// **fragment**(`key-1`、`key-2`),不是完整的 kid。
    fragment: String,
    /// 这把钥匙**自己**的 multibase 指纹,也是它信封的文件名。
    thumbprint: String,
    /// 归档里记着的创建时间。从词恢复时没有这个 —— 词只带得走种子。
    created_at: Option<String>,
    wns_handle: Option<String>,
    /// 归档里那份文档。从词恢复时为 `None`。
    document: Option<Value>,
    seed: LockedBytes,
    label: String,
    /// `mnemonic` 或 `archive`,进审计。
    source: &'static str,
    /// 还要不要从**根 seed** 推出另外三把。
    ///
    /// 只有词那条路是 `true`:纸带的正是根 seed,三把都能算出来。归档里装的
    /// 是一把钥匙自己的 seed,拿它当根去推只会推出三把**谁也不认识的**钥匙。
    derive_extras: bool,
}

/// 七步。两条路都走这里。
fn place(
    session: &mut Session,
    recovered: Recovered,
    force: bool,
    hardware: HardwareChoice,
) -> Result<()> {
    let Recovered {
        did,
        fragment,
        thumbprint,
        created_at,
        wns_handle,
        document: archived_document,
        seed,
        label,
        source,
        derive_extras,
    } = recovered;

    // ② 从 seed 推出公钥,再算指纹 —— 和 DID 里那一段(或归档自己写的那
    // 一段)**逐字符**比。
    let (verifying, public_multibase) = wrap::seed_to_public(&seed);
    let derived = check_fingerprint(&verifying, &thumbprint)?;

    // ③ 手里有文档的话,它得自验通过 —— 含 proof —— 而且里面那把钥匙得
    // 就是这把 seed。
    if let Some(archived) = &archived_document {
        check_document_key(archived, &did, &fragment, &verifying)?;
    }

    // ⑤ 拒绝静默覆盖。**在让人确认之前查** —— 一个注定要被拒的操作不该先
    // 把人叫过来看一遍。
    let conflict = conflict(session.layout(), &did, &fragment, &thumbprint);
    if let Some(why) = &conflict {
        if !force {
            return Err(KeydError::Protocol(format!(
                "{why}.\n\
                 Nothing was written. Importing over it would replace an identity this \
                 machine already holds — and if that key is still the one signing for some \
                 DID, the copy you are about to write becomes a second live key nobody can \
                 revoke.\n\
                 If you are sure, run it again with --force"
            )));
        }
    }

    // ④ 摆出来,要一个明确的 yes。
    //
    // 打印的是"这台机器从此持有什么",而不是文件路径 —— 导入的后果是持有
    // 一把能替这个 DID 签名的钥匙,而人要确认的正是这个。
    session.say(&format!(
        "\nAbout to import an identity onto this machine.\n\n\
         \x20 DID          {did}\n\
         \x20 key          {did}#{fragment}\n\
         \x20 fingerprint  {derived}\n\
         \x20 WNS handle   {}\n\
         \x20 created      {}\n\
         \x20 source       {source}\n\n\
         {}\n\n\
         This is not a file being copied. It is the ability to sign as `{did}` — and the\n\
         key it restores cannot be revoked, so wherever else a copy of it lives, that copy\n\
         stays live.\n\n",
        wns_handle.as_deref().unwrap_or("(none)"),
        created_at.as_deref().unwrap_or("unknown (words carry no timestamp)"),
        match &conflict {
            Some(why) => format!(
                "*** --force is on: {why}. That existing identity is being REPLACED. ***"
            ),
            None => "Nothing on this machine is being replaced.".to_string(),
        }
    ))?;
    if !session.confirm("Import it?")? {
        return Err(KeydError::Protocol(
            "nothing was written; you answered no".into(),
        ));
    }

    // ⑥ 重新套信封。
    let passphrase = session.ask_new_secret(
        "New LOCAL passphrase for this key: ",
        "Repeat it: ",
    )?;

    let fresh_device_secret = !device::exists(session.layout());
    let device_secret = device::load_or_create(session.layout())?;

    // 导入不只是"把 seed 接回来",还是一次**新的封装**(见模块头),所以硬件
    // 绑定也在这里重新做一遍:和 `keygen` 一样,要硬件而这里没有就拒绝,
    // 不悄悄退回纯软件的信封。
    //
    // 绑定的是**这一把**的指纹,所以另外三把各绑各的 —— 下面 `restore_derived`
    // 拿到的还是那个 `HardwareChoice`,不是这里已经绑好的这一份。
    let sealed_hardware = hardware::seal_new(hardware, &thumbprint)?;

    let wrapped = wrap::seal(wrap::SealRequest {
        id: KeyId {
            kid: format!("{did}#{fragment}"),
            did: did.clone(),
            thumbprint: thumbprint.clone(),
        },
        algorithm: KeyAlgorithm::Ed25519,
        public_multibase,
        label,
        passphrase: passphrase.as_bytes(),
        device_secret: &device_secret,
        seed: &seed,
        argon: Argon2Config::default(),
        hardware: sealed_hardware,
    })?;

    // ⑥b 一个根 seed 带回来的不只是绑定密钥。
    //
    // **先全部算出来,再一起落盘**:这一步里的任何失败(最可能的是硬件根
    // 绑不上第二把)都不该留下"根进去了、另外三把没有"的半套身份。而且
    // 后面要写的文档必须已经知道这三把 —— 一份只说得出"这个 DID 有一把根
    // 密钥"的文档,和手里的纸对不上。
    let local_document = store::read_did_document(session.layout(), &did).ok();
    let (restored, notes) = if derive_extras {
        restore_derived(
            session.layout(),
            &did,
            local_document.as_ref(),
            &verifying,
            passphrase.as_bytes(),
            &device_secret,
            hardware,
            &seed,
        )?
    } else {
        (Restored::default(), Vec::new())
    };
    for note in &notes {
        session.say(note)?;
    }

    if force {
        store::write(session.layout(), &wrapped)?;
    } else {
        store::save_new(session.layout(), &wrapped)?;
    }
    for envelope in &restored.envelopes {
        store::save_new(session.layout(), envelope)?;
        println!("restored {} ({})", envelope.id.kid, envelope.id.thumbprint);
    }

    let document_digest = ensure_document(
        session,
        &did,
        &fragment,
        archived_document.as_ref(),
        &verifying,
        &restored.keys,
        seed,
    )?;

    // ⑦ seed 到这里为止。`wrapped` 里那份是密文;明文那一份要么被
    // `LockedSigningKey` 接手、要么随 `LockedBytes` 的 Drop 擦除并 munlock,
    // 没有第三条路。

    session.audit(&Event::Import {
        did: did.clone(),
        kid: format!("{did}#{fragment}"),
        source: source.to_string(),
        document_digest,
    })?;

    let path = session.layout().key_path(&thumbprint)?;
    println!("imported {did}#{fragment}");
    println!("envelope written to {}", path.display());
    if fresh_device_secret {
        println!();
        println!("this machine had no device.secret, so a new one was just created. It is");
        println!("half of every key this machine will ever hold — back up ~/.anpio-key's");
        println!("device.secret separately from any exported archive, or a stolen archive");
        println!("plus later access to this machine is still not enough to open anything.");
    }

    clone_warning(&did);
    hosting_notice(&did)
}

/// 一个助记词能带回来的另外三把,已经算好、还没落盘。
#[derive(Default)]
struct Restored {
    /// 要挂进重建的那份文档里的钥匙。
    keys: Vec<ExtraKey>,
    /// 盘上还没有、需要写的信封。
    envelopes: Vec<crate::keystore::record::WrappedKey>,
}

/// 用根 seed 推出热、设备签名、协商三把,**不写盘**。
///
/// 三把的 seed 全部由根 seed 决定,所以"能不能恢复"不由这台机器的状态决定,
/// 只由**本机那份文档**决定:
///
/// 1. **本机没有这个 DID 的文档**(换机恢复的正常情形)→ 三把全接回来,
///    调用方随后按四把重建文档。
/// 2. **本机有文档** → 文档说了算。`did#fragment` 挂着的公钥**正好是这张纸
///    推出来的那把**才接;挂着别的钥匙的不接(纸证明不了它的私钥),文档里
///    根本没有的 fragment 也不接 —— 凭空多出一把没人引用的信封,只会让
///    "这台机器到底持有什么"更难说清。
/// 3. **信封已经在盘上** → 不重写。同一个 seed 推出的指纹必然相同,`save_new`
///    在那里只会报"已经存在",而内容本来就是一回事。
///
/// 推导本身走的是 [`crate::keystore::create::derived_extras`] —— 和 `keygen`
/// 同一段代码。两条路分岔一次,同一张纸就会长出两份不同的文档。
///
/// 返回 `(要落盘的,要说给人听的)`。跳过的那几把**必须**说出来:本机文档
/// 和手里的纸对不上,是那种"什么都不做也不报错"的失败,而人正以为自己做完了
/// 一次恢复。
#[allow(clippy::too_many_arguments)] // 与 `place` 手里那批东西一致
fn restore_derived(
    layout: &KeydLayout,
    did: &str,
    local_document: Option<&Value>,
    root_verifying: &ed25519_dalek::VerifyingKey,
    passphrase: &[u8],
    device_secret: &LockedBytes,
    hardware: HardwareChoice,
    root_seed: &LockedBytes,
) -> Result<(Restored, Vec<String>)> {
    // 热密钥的**名字**从本机文档里找回来 —— 纸决定的是钥匙,不是编号。
    // 文档里有热密钥、但那把不是这张纸推出来的(轮换铸的是新的随机种子,
    // 不在纸上),就干脆不恢复热密钥:给它新编号等于往文档里塞一把没人
    // 引用的钥匙,而"这台机器能当热密钥用"这句话仍然不成立。
    let mut notes = Vec::new();
    let hot_public = wrap::seed_to_public(&crate::crypto::derive::hot(root_seed)?).0;
    let hot_fragment = match local_document {
        Some(document) => {
            let found = lifecycle::hot_fragment_of(document, did, &hot_public)?;
            if found.is_none() {
                notes.push(
                    "note: no hot key was restored. The document on this machine has no\n\
                     authentication key derived from these words — it was rotated at some\n\
                     point, and a rotated key is not on the paper.\n"
                        .to_string(),
                );
            }
            found
        }
        // 本机没有文档 = 新身份的那份布局:编号从"只有根"的文档上算。
        None => Some(lifecycle::next_hot_fragment(
            &document::build_unsigned(
                &document::DidDocumentSpec::coordinates_from_did(did)?,
                root_verifying,
            )?
            .1,
            did,
            &store::envelope_fragments(layout, did)?,
        )?),
    };

    let derived = crate::keystore::create::derived_extras(
        did,
        hot_fragment.as_deref(),
        passphrase,
        device_secret,
        Argon2Config::default(),
        hardware,
        root_seed,
    )?;

    let mut restored = Restored::default();
    for (envelope, key) in derived {
        let kid = envelope.id.kid.clone();
        if let Some(document) = local_document {
            let listed = listed_multibase(document, &kid);
            if listed.as_deref() != Some(envelope.public_multibase.as_str()) {
                notes.push(format!(
                    "note: {kid} was not restored. {}\n",
                    match listed {
                        Some(other) => format!(
                            "The document on this machine names a different key there ({other}), \
                             so the words you entered are not what it signs with."
                        ),
                        None => "The document on this machine does not list that key at all."
                            .to_string(),
                    }
                ));
                continue;
            }
        }

        if !store::exists(layout, &envelope.id.thumbprint) {
            restored.envelopes.push(envelope);
        }
        restored.keys.push(key);
    }
    Ok((restored, notes))
}

/// 文档里某个验证方法挂的公钥(`publicKeyMultibase`),没有就是 `None`。
fn listed_multibase(document: &Value, kid: &str) -> Option<String> {
    document
        .get("verificationMethod")?
        .as_array()?
        .iter()
        .find(|method| method.get("id").and_then(Value::as_str) == Some(kid))?
        .get("publicKeyMultibase")?
        .as_str()
        .map(str::to_string)
}

/// ② 这把种子**是**它自称的那把钥匙吗。
///
/// 比的是 `e1_<43 字符>` 这一整段。从词恢复时,参照物是 `--did` 里那一段;
/// 从归档恢复时,是归档自己记的那一段 —— 而归档可能被改过,所以**照样得比**。
///
/// 这一条是"路径绑定"在导入侧的实现:did:wba 的全部信任都压在"DID 最后那段
/// 就是公钥的哈希"上,所以一台机器持有的钥匙必须**从自己的字节**推得出这个
/// 字符串。推不出,就没有任何别的东西能补救。
fn check_fingerprint(verifying: &ed25519_dalek::VerifyingKey, thumbprint: &str) -> Result<String> {
    let derived = crate::crypto::thumbprint::e1_segment(verifying)?;
    if derived != thumbprint {
        return Err(KeydError::Did(format!(
            "these hold a key that is not the one being restored.\n\
             they derive the fingerprint {derived}, but the DID (or the archive) says \
             {thumbprint}.\n\
             Nothing was written.\n\
             Check that you are restoring the right backup, for the right DID. Do not retry \
             variations of it: a differently-read key material does not fail here, it produces \
             a DIFFERENT working key — and a different DID to go with it — which is why this \
             check exists at all."
        )));
    }
    Ok(derived)
}

/// ③ 文档自验通过,而且里面那把钥匙**就是**这把种子。
///
/// 两件事,缺一不可:
///
/// - `verify_path_binding` 会跑规范那道 `did:wba` 绑定检查,**含 proof** ——
///   一份没签名或者签坏了的文档到这里就停住。归档里的文档是别人写的字节,
///   不验就写进本地目录,等于把一份"看起来像"的文档当成自己的身份。
/// - 然后是路径绑定**不管**的那一半:文档里 `did#fragment` 这个方法挂的
///   公钥,得和手里这把种子推出来的公钥一样。少了这一条,一份**为别的钥匙
///   签名过的、完全合法的**文档也能通过 —— 它确实自洽,只是说的不是这把钥匙。
fn check_document_key(
    document: &Value,
    did: &str,
    fragment: &str,
    verifying: &ed25519_dalek::VerifyingKey,
) -> Result<()> {
    document::verify_path_binding(did, document)?;

    let kid = format!("{did}#{fragment}");
    let listed = method_public_key(document, &kid)?;
    if listed.to_bytes() != verifying.to_bytes() {
        return Err(KeydError::Did(format!(
            "the document's {kid} is a different key than the one being restored.\n\
             Nothing was written.\n\
             The archive's document is internally consistent and correctly signed — it just \
             does not describe this seed. That combination is what a mixed-up backup looks \
             like, so it is refused here rather than written."
        )));
    }
    Ok(())
}

/// 本机已经持有这把钥匙了吗。
fn conflict(layout: &KeydLayout, did: &str, fragment: &str, thumbprint: &str) -> Option<String> {
    // 文件一级:信封按指纹命名,同指纹就是同一个文件,写下去就覆盖了。
    if store::exists(layout, thumbprint) {
        return Some(format!("this machine already has an envelope at keys/{thumbprint}.json"));
    }

    // 文档一级:编号一样而钥匙不一样,说明本地文档正靠着一个别的公钥认这个
    // `did#fragment`。这种情况下导入会把文档和钥匙拆散。
    let kid = format!("{did}#{fragment}");
    let listed = store::read_did_document(layout, did).ok().and_then(|document| {
        document
            .get("verificationMethod")
            .and_then(Value::as_array)
            .and_then(|methods| {
                methods
                    .iter()
                    .find(|method| method.get("id").and_then(Value::as_str) == Some(&kid))
                    .cloned()
            })
    });
    if let Some(method) = listed {
        return Some(format!(
            "this machine's document for {did} already lists {kid} ({}), with a different key",
            method
                .get("publicKeyMultibase")
                .and_then(Value::as_str)
                .unwrap_or("no key material")
        ));
    }
    None
}

/// 取一份文档里某个验证方法的 Ed25519 公钥。
fn method_public_key(document: &Value, kid: &str) -> Result<ed25519_dalek::VerifyingKey> {
    let method = document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .and_then(|methods| {
            methods
                .iter()
                .find(|method| method.get("id").and_then(Value::as_str) == Some(kid))
        })
        .ok_or_else(|| KeydError::Did(format!("the archive's document does not list {kid}")))?;

    match anp::authentication::extract_public_key(method)
        .map_err(|e| KeydError::Did(format!("{kid}: unreadable public key: {e}")))?
    {
        anp::PublicKeyMaterial::Ed25519(key) => Ok(key),
        _ => Err(KeydError::Did(format!("{kid} is not an Ed25519 key"))),
    }
}

/// 让这台机器对 `did` 有一份本地文档。
///
/// 三条路,严格按"会不会弄丢东西"的次序判断:
///
/// 1. **本机已经有一份** → 不动它。从词恢复时本机没有文档可带,但"没有"
///    和"有"是两回事:有的话,按规范形式重建会把热密钥和恢复密钥全丢掉,
///    而且不会报错。
/// 2. **归档带了文档** → 原样写下去。那份文档里可能有热密钥、恢复密钥、
///    甚至一条注销记录,而它们**只能**从文档里带回来。
/// 3. **都没有** → 按规范形式重建并签名。这就是 `publish` 做的事,在这里
///    顺手做掉,是因为一把没有文档的钥匙会让后面每一条改身份的命令都失败,
///    而人手上还拿着一份纸,不该再被要求多敲一条命令。
///
/// 返回写下去那份文档的摘要,给审计用。
fn ensure_document(
    session: &Session,
    did: &str,
    fragment: &str,
    archived: Option<&Value>,
    verifying: &ed25519_dalek::VerifyingKey,
    extras: &[ExtraKey],
    seed: LockedBytes,
) -> Result<String> {
    // ① 本机已经有一份 —— 不动它,理由在上面的文档注释里。
    if store::read_did_document(session.layout(), did).is_ok() {
        session.say(
            "\nnote: this machine already had a document for that DID, so it was left alone.\n\
             Rebuilding it from the key alone would have dropped any hot key, recovery key,\n\
             or deactivation record in it — silently, and without an error.\n",
        )?;
        return document_digest_of(session, did);
    }

    // ② 归档带了文档 —— 原样写下去,连 proof 一起。
    if let Some(archived) = archived {
        store::write_did_document(session.layout(), did, archived)?;
        println!(
            "wrote {} (the exported document, byte for byte)",
            session.layout().did_path(did).display()
        );
        return lifecycle::document_digest(archived);
    }

    // ③ 都没有 —— 按规范形式重建并签名。
    //
    // 这一步需要签名密钥,而 `LockedSigningKey::from_seed` 就是 seed 的
    // 终点:给它之后,seed 的那 32 个字节只活在签名密钥内部,随它的 Drop
    // 擦除。
    let key = LockedSigningKey::from_seed(
        KeyId {
            kid: format!("{did}#{fragment}"),
            did: did.to_string(),
            thumbprint: crate::crypto::thumbprint::e1_segment(verifying)?,
        },
        seed,
    )?;
    let (signed, digest) = rebuild_and_sign(did, fragment, key, extras.to_vec())?;
    store::write_did_document(session.layout(), did, &signed)?;
    println!(
        "wrote {} (rebuilt from the key: a canonical document, signed just now)",
        session.layout().did_path(did).display()
    );
    Ok(digest)
}

fn clone_warning(did: &str) {
    println!();
    println!("=====================================================================");
    println!("  THIS MACHINE IS NOW A CLONE OF AN IDENTITY THAT STILL EXISTS.");
    println!("=====================================================================");
    println!();
    println!("Export is a copy, and a key cannot be revoked. Whatever device or backup");
    println!("this came from still holds a working copy of the same private key — there is");
    println!("no way for anyone, including this tool, to make that copy stop working.");
    println!();
    println!("You cannot undo an export. You can migrate off it:");
    println!("    anpio-key rotate-hot-key --did {did}");
    println!("  ...so day-to-day signing uses a key only this machine has, and");
    println!("    anpio-key migrate --did {did} --to <new DID>");
    println!("  ...so the DID everyone has cached is explicitly retired and pointed");
    println!("     somewhere new.");
    println!();
    println!("Do that as soon as the old device is confirmed gone, not before: if it is");
    println!("still signing, migrating away from it is the correct end, and doing it early");
    println!("just leaves two half-retired DIDs behind.");
}

/// 审计里那条 `IMPORT` 要的文档摘要 —— 顺手确认一下"这台机器现在真的有一份
/// 文档",因为没有文档的钥匙在后面的命令里会以别的面貌失败。
fn document_digest_of(session: &Session, did: &str) -> Result<String> {
    let document = store::read_did_document(session.layout(), did)?;
    lifecycle::document_digest(&document)
}

/// 给 `ensure_document` 用:按规范形式重建 + 签名。
///
/// 走 [`document::rebuild_with`] 而不是 [`document::rebuild`]:后者只认识根
/// 密钥,拿它重建一份本来就挂着热/设备签名/协商键的文档,会把那三把**静静
/// 地**从文档里抹掉 —— 而钥匙还躺在 `keys/` 里,于是这台机器持有的钥匙和
/// 它自己的文档从此对不上。
fn rebuild_and_sign(
    did: &str,
    fragment: &str,
    key: LockedSigningKey,
    extras: Vec<ExtraKey>,
) -> Result<(Value, String)> {
    let spec = document::DidDocumentSpec::coordinates_from_did(did)?;
    let unsigned = document::rebuild_with(&spec, did, &key.verifying_key()?, extras)?;
    let signed = document::sign_document(&unsigned, &key, &format!("{did}#{fragment}"))?;
    document::verify_path_binding(did, &signed)?;
    let digest = lifecycle::document_digest(&signed)?;
    Ok((signed, digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hygiene::LockedBytes;
    use crate::keystore::layout::KeydLayout;
    use crate::keystore::wrap::{seal, seed_to_public, SealRequest};
    use crate::keystore::store;

    /// 一把确定的钥匙,seed 全填 `seed_byte`。
    fn key(seed_byte: u8) -> LockedSigningKey {
        let seed = LockedBytes::fill(|bytes| *bytes = [seed_byte; 32]).unwrap();
        LockedSigningKey::from_seed(
            KeyId {
                did: String::new(),
                kid: String::new(),
                thumbprint: String::new(),
            },
            seed,
        )
        .unwrap()
    }

    /// 一份真的文档:真 DID、真钥匙、真 proof。
    fn signed_document(seed_byte: u8) -> (String, Value) {
        let key = key(seed_byte);
        let spec = document::DidDocumentSpec::new("example.com", vec!["user".into(), "alice".into()]);
        let (did, unsigned) = document::build_unsigned(&spec, &key.verifying_key().unwrap()).unwrap();
        let signed =
            document::sign_document(&unsigned, &key, &format!("{did}#{}", document::ROOT_FRAGMENT))
                .unwrap();
        (did, signed)
    }

    fn layout(name: &str) -> KeydLayout {
        let dir = std::env::temp_dir().join(format!("keyd-import-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let layout = KeydLayout::at(dir);
        layout.ensure().unwrap();
        layout
    }

    /// 一个能落盘的信封。指纹由 `thumbprint` 指定 —— 冲突检查只看文件名,
    /// 所以这里不需要它和 seed 真的对得上。
    fn envelope(did: &str, fragment: &str, thumbprint: &str) -> crate::keystore::record::WrappedKey {
        let seed = LockedBytes::fill(|bytes| *bytes = [0x11; 32]).unwrap();
        let (_, multibase) = seed_to_public(&seed);
        let device = LockedBytes::fill(|bytes| *bytes = [0x22; 32]).unwrap();
        seal(SealRequest {
            id: KeyId {
                did: did.to_string(),
                kid: format!("{did}#{fragment}"),
                thumbprint: thumbprint.to_string(),
            },
            algorithm: KeyAlgorithm::Ed25519,
            public_multibase: multibase,
            label: "restored".into(),
            passphrase: b"pw",
            device_secret: &device,
            seed: &seed,
            argon: Argon2Config { m_cost: 1024, t_cost: 1, p_cost: 1 },
            hardware: None,
        })
        .unwrap()
    }

    // —— ② 路径指纹 ————————————————————————————————————————

    #[test]
    fn the_right_words_pass_the_path_binding() {
        let (did, _) = signed_document(1);
        let thumbprint = crate::crypto::thumbprint::e1_from_did(&did).unwrap().to_string();

        let derived = check_fingerprint(&key(1).verifying_key().unwrap(), &thumbprint).unwrap();

        assert_eq!(derived, thumbprint, "the derived segment is what gets displayed");
        assert!(did.ends_with(&derived));
    }

    /// 计划 §十 那一批里的第二条:**词对,但不是这个 DID 的**。
    ///
    /// 这是整条导入路里最值钱的一条检查 —— 24 个词本身完全合法,校验和也过,
    /// 唯一的错处是它们不是 `--did` 那把钥匙的。少了这一条,人会得到一台
    /// "导入成功"、却替另一个身份签名的机器,而且没有任何东西会报错。
    #[test]
    fn words_for_a_different_did_are_refused() {
        let (did, _) = signed_document(2);
        let claimed = crate::crypto::thumbprint::e1_from_did(&did).unwrap().to_string();

        let error = check_fingerprint(&key(3).verifying_key().unwrap(), &claimed).unwrap_err();

        let message = error.to_string();
        assert!(message.contains("not the one being restored"), "{message}");
        assert!(message.contains("Nothing was written"), "{message}");
        // 必须说清楚"别试别的写法":种子读错不报错,只会给出另一把能用的钥匙。
        assert!(message.contains("Do not retry"), "{message}");
    }

    // —— ③ 文档 ————————————————————————————————————————————

    #[test]
    fn a_document_that_verifies_and_matches_the_seed_is_accepted() {
        let (did, doc) = signed_document(4);

        check_document_key(&doc, &did, document::ROOT_FRAGMENT, &key(4).verifying_key().unwrap()).unwrap();
    }

    /// 计划 §十:**归档缺 proof → 必须拒**。
    ///
    /// 归档里的文档是别人写的字节。一份没有 proof 的文档不是"还没签名",是
    /// 一份谁都能改的文档 —— 而它落盘之后就会变成这台机器对外的身份。
    #[test]
    fn a_document_without_its_proof_is_refused() {
        let (did, doc) = signed_document(5);
        let mut unsigned = doc.clone();
        unsigned.as_object_mut().unwrap().remove("proof");

        let error = check_document_key(
            &unsigned,
            &did,
            document::ROOT_FRAGMENT,
            &key(5).verifying_key().unwrap(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("failed the normative"), "{error}");
    }

    /// **这一段是 `verify_path_binding` 管不到的那半。**
    ///
    /// 手里这份文档完全自洽:它自己的 DID、它自己的钥匙、它自己签的 proof。
    /// 唯一的问题是它说的不是手里这把种子。少了公钥比对,这种"混错备份"会
    /// 一路通过,然后把这台机器变成另一个身份的持有者。
    #[test]
    fn a_perfectly_valid_document_for_another_key_is_refused() {
        let (did, doc) = signed_document(6);

        let error =
            check_document_key(&doc, &did, document::ROOT_FRAGMENT, &key(7).verifying_key().unwrap())
                .unwrap_err();

        let message = error.to_string();
        assert!(message.contains("different key than the one being restored"), "{message}");
        assert!(message.contains("Nothing was written"), "{message}");
    }

    /// 被改过 `id` 的文档必须先死在**绑定**那一关,而不是死在公钥比对那一关:
    /// 两条检查的次序决定了人看到的是哪一句错误,而先说"这份文档不是这个
    /// DID 的"更有用。
    #[test]
    fn a_document_with_a_patched_id_dies_at_the_binding_check() {
        let (did, _) = signed_document(8);
        let (_, other) = signed_document(9);
        let mut imposter = other.clone();
        imposter["id"] = Value::String(did.clone());

        let error = check_document_key(
            &imposter,
            &did,
            document::ROOT_FRAGMENT,
            &key(8).verifying_key().unwrap(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("hashes to"), "{error}");
    }

    // —— ⑤ 拒绝静默覆盖 ————————————————————————————————————

    #[test]
    fn a_fresh_machine_has_no_conflict() {
        let (did, _) = signed_document(10);
        let thumbprint = crate::crypto::thumbprint::e1_from_did(&did).unwrap().to_string();

        assert!(conflict(&layout("fresh"), &did, document::ROOT_FRAGMENT, &thumbprint).is_none());
    }

    /// 计划 §十:**同 KeyId 已存在 → 必须拒(除非 `--force`)**。
    /// 这里查的是"会不会拒",`--force` 那半边在 `place` 里。
    #[test]
    fn an_existing_envelope_for_the_same_key_is_a_conflict() {
        let (did, _) = signed_document(11);
        let thumbprint = crate::crypto::thumbprint::e1_from_did(&did).unwrap().to_string();
        let layout = layout("envelope-taken");
        store::write(&layout, &envelope(&did, document::ROOT_FRAGMENT, &thumbprint)).unwrap();

        let why = conflict(&layout, &did, document::ROOT_FRAGMENT, &thumbprint).unwrap();

        assert!(why.contains("already has an envelope"), "{why}");
        assert!(why.contains(&thumbprint), "{why}");
    }

    /// 编号一样、钥匙不一样:本地文档正靠着一个**别的**公钥认这个
    /// `did#key-1`。这时候导入会把文档和钥匙拆散 —— 文档说那把,钥匙是这把,
    /// 而两样都在本机。
    #[test]
    fn a_local_document_listing_the_kid_with_another_key_is_a_conflict() {
        let (did, doc) = signed_document(12);
        let layout = layout("doc-taken");
        store::write_did_document(&layout, &did, &doc).unwrap();
        let other_thumbprint = crate::crypto::thumbprint::e1_segment(&key(13).verifying_key().unwrap())
            .unwrap();

        let why =
            conflict(&layout, &did, document::ROOT_FRAGMENT, &other_thumbprint).unwrap();

        assert!(why.contains("already lists"), "{why}");
        assert!(why.contains("different key"), "{why}");
    }

    /// 同一把钥匙的第二个 fragment(`key-2` 之类)和绑定密钥并存是正常的 ——
    /// 冲突检查看的必须是**这个 kid**,而不是"这个 DID 的文档里有没有东西"。
    #[test]
    fn a_document_listing_a_different_kid_is_not_a_conflict() {
        let (did, doc) = signed_document(14);
        let layout = layout("doc-other-kid");
        store::write_did_document(&layout, &did, &doc).unwrap();
        let thumbprint = crate::crypto::thumbprint::e1_segment(&key(15).verifying_key().unwrap()).unwrap();

        assert!(conflict(&layout, &did, "key-2", &thumbprint).is_none());
    }

    // —— ⑥b 一个根 seed 推出另外三把 ————————————————————————

    fn root_seed(byte: u8) -> LockedBytes {
        LockedBytes::fill(|bytes| *bytes = [byte; 32]).unwrap()
    }

    fn device_secret() -> LockedBytes {
        LockedBytes::fill(|bytes| *bytes = [0x22; 32]).unwrap()
    }

    fn spec() -> document::DidDocumentSpec {
        document::DidDocumentSpec::new("example.com", vec!["user".into(), "alice".into()])
    }

    fn did_for(seed: &LockedBytes) -> (String, ed25519_dalek::VerifyingKey) {
        let (verifying, _) = seed_to_public(seed);
        let (did, _) = document::build_unsigned(&spec(), &verifying).unwrap();
        (did, verifying)
    }

    fn fragments(restored: &Restored) -> Vec<&str> {
        restored
            .envelopes
            .iter()
            .map(|envelope| envelope.id.kid.rsplit('#').next().unwrap())
            .collect()
    }

    fn restore(
        layout: &KeydLayout,
        did: &str,
        local: Option<&Value>,
        verifying: &ed25519_dalek::VerifyingKey,
        seed: &LockedBytes,
    ) -> (Restored, Vec<String>) {
        restore_derived(
            layout,
            did,
            local,
            verifying,
            b"pw",
            &device_secret(),
            HardwareChoice::None,
            seed,
        )
        .unwrap()
    }

    /// 纸上那一串词足够铸出另外三把,而且三把在**全部算完之前**一个字节都
    /// 不落盘:半套身份比没有身份更难收拾。
    #[test]
    fn one_root_seed_derives_the_other_three_and_writes_nothing() {
        let layout = layout("derive-fresh");
        let seed = root_seed(0x42);
        let (did, verifying) = did_for(&seed);

        let (restored, notes) = restore(&layout, &did, None, &verifying, &seed);

        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(fragments(&restored), ["key-2", "device-sign", "device-agreement"]);
        assert_eq!(restored.keys.len(), 3, "三把都要进重建的那份文档");
        for envelope in &restored.envelopes {
            assert!(
                !store::exists(&layout, &envelope.id.thumbprint),
                "{} was written before the whole identity was computed",
                envelope.id.thumbprint
            );
        }
    }

    /// **同一个 seed,`keygen` 和助记词恢复必须铸出同一组公钥。**
    ///
    /// 这条是"纸能当备份"的全部内容:两条路分岔一次,纸上那 24 个词就只对
    /// 当初那台机器成立,而人在另一台机器上恢复出来的是一把谁也认不出的钥匙。
    #[test]
    fn the_words_restore_exactly_the_keys_keygen_minted() {
        let seed = root_seed(0x43);
        let (did, verifying) = did_for(&seed);

        let minted = crate::keystore::create::create_identity(
            &layout("derive-keygen"),
            &spec(),
            "alice",
            b"pw",
            Argon2Config { m_cost: 1024, t_cost: 1, p_cost: 1 },
            HardwareChoice::None,
            &seed,
        )
        .unwrap();
        let (restored, _) = restore(&layout("derive-words"), &did, None, &verifying, &seed);

        let minted: Vec<&str> =
            minted.extras.iter().map(|envelope| envelope.public_multibase.as_str()).collect();
        let words: Vec<&str> =
            restored.envelopes.iter().map(|envelope| envelope.public_multibase.as_str()).collect();
        assert_eq!(minted, words, "keygen and the words must mint the same four keys");
        assert_eq!(minted.len(), 3);
    }

    /// 本机已经有这份身份的文档时,**名字照着文档来**:纸上的热密钥在文档里
    /// 叫 `key-2`,恢复就得还叫 `key-2` —— 按"下一个空位"算会得出 `key-3`,
    /// 然后落下一把文档里没有的钥匙,同时漏掉真正该接回来的那一把。
    #[test]
    fn a_machine_that_already_has_the_document_keeps_the_names_in_it() {
        let layout = layout("derive-doc");
        let seed = root_seed(0x45);
        let (did, verifying) = did_for(&seed);
        let (first, _) = restore(&layout, &did, None, &verifying, &seed);
        let document =
            document::rebuild_with(&spec(), &did, &verifying, first.keys.clone()).unwrap();
        store::write_did_document(&layout, &did, &document).unwrap();

        let (second, notes) = restore(&layout, &did, Some(&document), &verifying, &seed);

        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(fragments(&second), ["key-2", "device-sign", "device-agreement"]);
    }

    /// 文档里的热密钥**不是**这张纸推出来的(轮换过)→ 不恢复热密钥,而且
    /// 要说出来。轮换铸的是新的随机种子,它从来不在纸上;硬把纸上的那把塞进
    /// 文档会多出一把没人引用的钥匙,而人以为自己已经恢复了热密钥。
    #[test]
    fn a_rotated_hot_key_is_not_replaced_by_the_one_on_the_paper() {
        let layout = layout("derive-rotated");
        let seed = root_seed(0x46);
        let (did, verifying) = did_for(&seed);
        let (first, _) = restore(&layout, &did, None, &verifying, &seed);

        let (foreign, _) = seed_to_public(&root_seed(0x47));
        let mut keys: Vec<ExtraKey> =
            first.keys.iter().filter(|key| key.fragment != "key-2").cloned().collect();
        keys.push(ExtraKey::new(
            "key-2",
            foreign,
            vec![anp::authentication::DidVerificationRelationship::Authentication],
        ));
        let document = document::rebuild_with(&spec(), &did, &verifying, keys).unwrap();

        let (second, notes) = restore(&layout, &did, Some(&document), &verifying, &seed);

        assert!(
            notes.iter().any(|note| note.contains("no hot key was restored")),
            "{notes:?}"
        );
        assert!(second.keys.iter().all(|key| key.fragment != "key-2"), "the paper's hot key is stale");
        assert_eq!(second.keys.len(), 2, "the two fixed-name keys are still the paper's");
    }

    // —— 一句话的其余部分 ——————————————————————————————————

    /// 计划 §十的最后一条里能测的那半:**托管 URL 必须打得出**。
    /// 打印本身要终端,但那条 URL 是它唯一的输入,坏了要先在这里响。
    #[test]
    fn the_hosting_url_for_a_restored_did_is_reachable() {
        let (did, _) = signed_document(16);
        let url = crate::did::did_url_path(&did).unwrap();

        // 托管路径**带着绑定段**:别人要取的正是这个 DID 自己的那份文档,
        // 而不是域名的根。
        let thumbprint = crate::crypto::thumbprint::e1_from_did(&did).unwrap();
        assert_eq!(url, format!("https://example.com/user/alice/{thumbprint}/did.json"));
        assert!(url.ends_with("/did.json"), "{url}");
    }

    /// `import_mnemonic` 只用得上绑定密钥:词里没有 fragment,所以拿它去恢复
    /// `key-2` 是不可能的。这里钉住那句错误的存在 —— 它是人唯一能拿到的
    /// 解释,而"没有解释的拒绝"会让人去试别的写法。
    #[test]
    fn a_did_without_an_e1_segment_has_nothing_to_bind_to() {
        let error = import_mnemonic(
            None,
            ImportMnemonic {
                did: "did:wba:example.com:user:alice".into(),
                label: "x".into(),
                force: false,
                hardware: HardwareChoice::None,
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("no `e1_` segment"), "{error}");
    }
}
