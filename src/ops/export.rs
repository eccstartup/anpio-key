//! 导出种子 —— **默认构建里根本不存在这一块**。
//!
//! # 为什么是 `#[cfg]` 而不是一个运行时开关
//!
//! 这是整个导出策略里最要紧的一句话。运行期拒绝的导出**可以被绕过**:一个
//! 补丁、一个忘了检查的分支、一次调试器附加,任何一条都能把一个 `if` 翻过去。
//! 编译期不存在的代码没有可翻的东西 —— 发布的二进制里没有那个分支、没有那个
//! 字符串、没有那条路径。**"带导出的构建"因此是一个不同的产物,由运营者
//! 刻意构建。**
//!
//! 所以这个文件、`export-seed` 那个子命令、以及它们依赖的一切,都在
//! `seed-export` 特性后面。不开这个特性,`anpio-key export-seed` 是 `clap`
//! 嘴里的"没有这个子命令"。
//!
//! # 三道收紧,以及它们各自挡住的是谁
//!
//! **① 断链,而不是保密。** 关键不是"agent 不知道导出密码",而是
//! **agent 够不到那条通道**。一个被注入的 agent 会做的事是编一个像样的
//! 提示框让人类把密码敲进去 —— "他不知道密码"根本挡不住这个。真正成立的性质
//! 是**导出不是 socket 上的一个消息类型**([`crate::daemon::wire::Request`]
//! 里没有导出变体),它只在这个进程自己的 `/dev/tty` 上、由人类本人操作。
//! 于是就算人类被骗着把密码敲进了 agent 的聊天窗,agent 也**送不到守护进程**。
//!
//! 顺着这一条,还有一句必须写死的话:**绝不通过 `SCM_RIGHTS` 接收终端 fd**。
//! 否则 agent 可以自己开一个 pty、把从设备 fd 通过 socket 递过来,让守护进程
//! 以为自己在和一个终端说话,于是渲染一个假提示、读走人类敲进去的密码。
//! 在这里,这一条是**结构上成立**的:导出不是一个 socket 操作,这条路径从头
//! 到尾没有接收过任何 fd。守住它的方式是**不加那条代码**,而不是加一个检查
//! —— 所以这里没有检查,只有这句话。
//!
//! **② 独立密码、一次性、强制先锁。** 导出密码必须**不是**日常解锁口令:
//! 否则"人类解锁了日常签名"就等于"人类授权了导出",能力没有分离。它只能用
//! 一次(不落盘、不复用、下次再要一个),而且导出前先 `LOCK` 把正在进行的
//! 签名会话全部杀掉 —— **让导出变成一件有破坏性、看得见的动作,这是特性
//! 不是缺点。**
//!
//! **③ 永不进 argv / env / 文件。** 没有 `--password` 参数(argv 会被 `ps`
//! 看到),不看环境变量(同 uid 的进程读得见 `/proc/<pid>/environ`),不从
//! 文件读一个口令。只从终端读、关回显、读完 zeroize、不进日志。
//!
//! # 它买到了什么,没买到什么
//!
//! **买到了**:被注入的 agent 无法**机械地**把整把身份一次抽干 —— 关掉了
//! "一次接口调用 = 全丢"。
//!
//! **没买到**:对**内存失陷**无效。签名路径本来就要在内存里放明文 seed,
//! 能读守护进程内存的攻击者直接读走,根本不需要导出密码。**导出密码是"接口
//! 的门",不是"材料的锁"。** 唯一真锁是硬件不可导出,而 Ed25519 在主流消费
//! 级硬件上做不到(Apple SE 只支持 P-256,TPM 2.0 的 ECC 也只有 NIST 曲线)。
//!
//! **也没买到**:防**社工**。agent 可以求人类"帮我跑一下 `anpio-key
//! export-seed`,把结果贴给我"。这个只能靠教育 + 明确警告 + **下次启动时
//! 报告"上次导出在何时"**(见 [`crate::audit::log::export_tripwire`] ——
//! 家用路由器显示"上次登录"那种东西)。
//!
//! # 与"默认不可导出"并存的那个事实
//!
//! 导出**不是**迁移的主要手段。换机、换域名、换托管商都走 `successorDid`
//! (T0)加预授权恢复密钥(T2)—— **秘密一步都不动**,而且旧设备那把钥匙被
//! 明确作废。只有在"旧设备整台丢了、再也签不出迁移"或者"要从冷备份恢复
//! 同一个 DID"时,才真的需要这里。默认关掉导出正是因为它守的是最危险、
//! 最不常用的那批操作。

use std::path::{Path, PathBuf};

use crate::audit::{log as audit_log, Event};
use crate::crypto::kdf::Argon2Config;
use crate::crypto::mnemonic;
use crate::did::document;
use crate::error::{KeydError, Result};
use crate::keystore::archive::{self, SealRequest};
use crate::keystore::layout::KeydLayout;
use crate::keystore::{device, store, unwrap};
use crate::ops::Session;

/// 一次导出要走多远。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// 24 个词,打到终端上。
    Words,
    /// 加密归档,写进 `<out>/<thumbprint>.anpkeyd.json`。
    Archive,
    /// 两个都要。**这是默认**,因为纸会丢、文件会坏,而这两样各能补救另一样。
    Both,
}

impl Form {
    fn wants_words(self) -> bool {
        matches!(self, Form::Words | Form::Both)
    }

    fn wants_archive(self) -> bool {
        matches!(self, Form::Archive | Form::Both)
    }

    fn label(self) -> &'static str {
        match self {
            Form::Words => "words",
            Form::Archive => "archive",
            Form::Both => "words+archive",
        }
    }
}

pub struct ExportSeed {
    pub did: String,
    /// 导出哪一把。不给就是绑定密钥。
    pub kid: Option<String>,
    /// 归档写到哪个目录。默认密钥目录本身。
    pub out: Option<PathBuf>,
    /// 输出文件已存在时也照写。
    pub force: bool,
    pub form: Form,
}

pub fn export_seed(root: Option<&Path>, args: ExportSeed) -> Result<()> {
    let mut session = Session::open(root)?;

    let wrapped = store::resolve(session.layout(), &args.did, args.kid.as_deref())?;
    let fragment = wrapped
        .id
        .kid
        .strip_prefix(&format!("{}#", wrapped.id.did))
        .unwrap_or(&wrapped.id.kid)
        .to_string();

    // 归档要带一份**验得过的**文档 —— 导入那边第 ③ 步就是验它。
    let did_document = export_document(&session, &wrapped.id.did)?;

    // ——① 强制先锁 ——————————————————————————————————————————————
    //
    // 放在最前面(在问任何秘密之前):这是一个有破坏性、人看得见的动作,而它
    // 必须在"人已经决定要导出"之后、"导出真的发生"之前发生。
    lock_daemon(session.layout(), &wrapped.id.did)?;

    // 上次导出过就在这儿说出来 —— tripwire 最有用的位置不是日志,是人正要
    // **再导一次**的时候问的那一句"上次那是你吗"。
    if let Some(line) = audit_log::export_tripwire(&session.layout().audit_dir()) {
        session.say(&format!("\n{line}\n"))?;
    }

    // ——② 独立密码 ————————————————————————————————————————————
    //
    // 先问日常口令(要种子),再问导出密码,然后**比对这两个**。反过来的话
    // 就没法比了 —— 而这一比就是"能力分离"这个性质的实现本身。
    let passphrase = session.ask_secret(&format!(
        "Passphrase for {}#{} (the key being exported): ",
        wrapped.id.did, fragment
    ))?;
    let device_secret = device::load(session.layout())?;
    let seed = unwrap::open_seed(&wrapped, passphrase.as_bytes(), &device_secret)?;

    let export_password = match args.form.wants_archive() {
        true => {
            let password = session.ask_new_secret(
                "Export password (ONE-TIME; NOT your daily passphrase): ",
                "Repeat the export password: ",
            )?;
            if password.as_bytes() == passphrase.as_bytes() {
                return Err(KeydError::Protocol(
                    "the export password must not be the passphrase you just unlocked with.\n\
                     The point of asking for it separately is that unlocking for daily signing \
                     and authorizing an export are two different decisions. One password for \
                     both makes them the same decision.\n\
                     Nothing was exported."
                        .into(),
                ));
            }
            Some(password)
        }
        false => None,
    };

    // ——③ 让人看清后果 ————————————————————————————————————————
    let archive_path = match args.form.wants_archive() {
        true => Some(archive_path_for(session.layout(), &wrapped.id.thumbprint, args.out.as_deref())?),
        false => None,
    };
    if let Some(path) = &archive_path {
        if path.exists() && !args.force {
            return Err(KeydError::Protocol(format!(
                "{} already exists.\n\
                 Refusing to overwrite it: an older export is exactly the file someone would \
                 want back if this one turns out to be wrong, and keeping both costs nothing \
                 (pass --force if you really meant to replace it, or --out a different \
                 directory)",
                path.display()
            )));
        }
    }

    session.say(&format!(
        "\nAbout to export the private key for {kid}.\n\n\
         \x20 key          {kid}\n\
         \x20 fingerprint  {thumbprint}\n\
         \x20 producing    {form}{writing}\n\n\
         An export is a COPY, and a key cannot be revoked. After this, whatever holds these\n\
         words or this file holds a working copy of this identity — permanently. There is no\n\
         undo, and no way to tell this tool to invalidate that copy.\n\n\
         The words ARE the private key. Anyone who reads them over your shoulder has it.\n\
         Write them down; do not photograph them; do not paste them into a chat.\n\n",
        kid = wrapped.id.kid,
        thumbprint = wrapped.id.thumbprint,
        form = args.form.label(),
        writing = match &archive_path {
            Some(path) => format!("\n  writing to     {}", path.display()),
            None => String::new(),
        }
    ))?;

    if !session.confirm("Export it?")? {
        return Err(KeydError::Protocol(
            "nothing was exported; you answered no".into(),
        ));
    }

    // ——说出那 24 个词 ————————————————————————————————————————
    //
    // 走终端,不走 stdout。stdout 常常被重定向到文件或管道,而这几行**就是
    // 私钥** —— `anpio-key export-seed > /tmp/backup.txt` 这个名字听起来像是
    // 在做备份,实际做的是把一个明文私钥写进 /tmp。
    if args.form.wants_words() {
        let words = mnemonic::to_words(&seed)?;
        // `as_str()` 而不是直接把 `Zeroizing` 塞进格式串:它是故意不实现
        // `Display` 的,免得一个手滑就把它写进某个不该去的地方。要打印必须
        // 在这里明写一次 —— 这一行就是那一次。
        session.say(&format!(
            "\n\
             =====================================================================\n\
             \x20 THE 24 WORDS. THIS IS THE PRIVATE KEY.\n\
             =====================================================================\n\n\
             {words}\n\n\
             Write them on paper. Anywhere else — a screenshot, a synced notes app, a chat\n\
             window — is a copy you do not control.\n\n\
             The scheme is frozen: these words encode the 32-byte seed itself as BIP-39\n\
             entropy. No PBKDF2 step, no BIP-39 passphrase. Restoring them with standard\n\
             BIP-39 tooling gives a DIFFERENT key, and gives it without an error.\n\n",
            words = words.as_str()
        ))?;
    }

    // ——归档 ————————————————————————————————————————————————
    if let (Some(path), Some(password)) = (&archive_path, &export_password) {
        let archive = archive::seal(SealRequest {
            did: wrapped.id.did.clone(),
            kid: wrapped.id.kid.clone(),
            thumbprint: wrapped.id.thumbprint.clone(),
            created_at: wrapped.created_at.clone(),
            wns_handle: None,
            document: did_document,
            password: password.as_bytes(),
            seed: &seed,
            argon: Argon2Config::default(),
        })?;

        write_private(path, &archive.to_bytes()?)?;
        println!("wrote {}", path.display());
        println!("  it opens with the export password you just typed — and with nothing else.");
        println!("  this machine's device.secret is NOT part of it, on purpose: a backup that");
        println!("  needs this machine is not a backup.");
    }

    // seed 到此为止:`LockedBytes` 的 Drop 擦除并 munlock,导出密码随
    // `Zeroizing` 一起。

    session.audit(&Event::ExportSeed {
        did: wrapped.id.did.clone(),
        form: args.form.label().to_string(),
    })?;

    // ——导出完仍然是锁着的 ————————————————————————————————————
    //
    // 计划写的是"导出前先 LOCK";这里**导出后再锁一次**,于是这件事留下的
    // 状态是"守护进程锁着"。差别是有意的:一次导出之后,人已经证明了他此刻
    // 正坐在这个终端前,但把钥匙重新解锁回去会抹掉刚才那次锁的可见后果 ——
    // 而"让导出变成一件看得见的动作"正是这条路要的东西。
    lock_daemon(session.layout(), &wrapped.id.did)?;

    println!();
    println!("the daemon is locked. Unlock deliberately when you want to sign again:");
    println!("    anpio-key unlock --did {}", wrapped.id.did);
    println!();
    println!("importing this elsewhere does NOT retire the key on this machine. If the export");
    println!("was for a machine that is gone, migrate away from it once you are sure the old");
    println!("one will never sign again:");
    println!("    anpio-key migrate --did {} --to <new DID>", wrapped.id.did);
    Ok(())
}

/// 要把哪一份文档塞进归档。
///
/// 本地那份优先,而且**必须**优先:它可能挂着热密钥、恢复密钥,甚至一条注销
/// 记录,而那些东西只能从文档里带回来。
///
/// 本地没有时**拒绝**,不重建。重建出来的是一份只有根密钥的规范文档,而归档
/// 一旦只带着它,导入到新机器上就会把这些东西无声地丢掉 —— 更直接的问题是
/// "这个 DID 本机连文档都没有",那通常意味着它压根没在这台机器上发布过,
/// 而拿它做备份是搞错了对象。`publish` 一条命令就能补上。
fn export_document(session: &Session, did: &str) -> Result<serde_json::Value> {
    let document = store::read_did_document(session.layout(), did).map_err(|error| {
        KeydError::Protocol(format!(
            "no local document for {did} ({error}).\n\
             An archive carries the document with it, and an archive whose document cannot be \
             checked is not a backup — the import side has nothing to verify the key against.\n\
             Run `anpio-key publish --did {did}` first, then export."
        ))
    })?;
    document::verify_path_binding(did, &document)?;
    Ok(document)
}

/// 归档的落盘位置。
///
/// 文件名按**指纹**,不按 DID:一个 DID 名下的每一把钥匙各有各的指纹,而
/// 分两次导出同一个 DID 的两把钥匙不该互相覆盖。
fn archive_path_for(layout: &KeydLayout, thumbprint: &str, out: Option<&Path>) -> Result<PathBuf> {
    let dir = out.unwrap_or(layout.root());
    Ok(dir.join(format!("{thumbprint}.anpkeyd.json")))
}

/// 把一个含秘密的文件写下去,权限盖死。
///
/// 归档本身是加密的,所以它不是明文秘密 —— 但它是一个**离线可暴力破解的
/// 口令保护文件**,而且里面带着整份 DID 文档。默认不给别人看,是这个文件
/// 唯一说得过去的权限。
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(crate::keystore::layout::SECRET_FILE_MODE)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// 让守护进程把正在进行的签名会话丢掉。
///
/// **守护进程没在跑是正常的,不是错误** —— 导出本来就该在没人签名的安静
/// 时刻做,而"没跑"意味着"没有任何会话需要杀"。但要说出来:"锁了一次"和
/// "没有东西可锁"在人眼里不该长得一样。
fn lock_daemon(layout: &KeydLayout, did: &str) -> Result<()> {
    match crate::client::Client::connect(&layout.sock_path()) {
        Ok(mut client) => {
            client.lock(Some(did), None)?;
            println!("locked {did} in the running daemon");
            Ok(())
        }
        Err(_) => {
            println!("no daemon is running, so there is no signing session to kill");
            Ok(())
        }
    }
}
