//! 改身份的那几个命令:加恢复密钥、轮换热密钥、摘钥匙、迁移、注销。
//!
//! ## 它们为什么不走 socket
//!
//! `sign` 和 `unlock` 走 socket,因为私钥必须留在守护进程里 —— 那是整个
//! 产品的立身之本。这一组**也**要签东西(被改过的 DID 文档),但它们
//! **故意**不走 socket,而是在当前进程里把信封解开。
//!
//! 理由是对称的:走 socket 就意味着要给守护进程加一条"用我的私钥签任意
//! 字节"的消息类型。那正是 `--allow-raw-signing` 那一整套防范要挡掉的
//! 东西 —— 一旦存在,守护进程的授权模型(uid + 可执行文件身份)就成了
//! 唯一一道墙,而这道墙挡不住"同一个 uid 下另一个 agent 想冒充我"。
//!
//! 代价是这些命令短命地在自己的地址空间里持有一把**绑定密钥**(冷的、平时
//! 根本不解锁的那把),在几毫秒内签一次文档,然后把它丢回 `LockedBytes`
//! 的锁定区里等 drop。这是拿"一次短暂的暴露"换"守护进程永远不会有万能
//! 签名口子",换得值。
//!
//! ## 文档写下去之前,三件事一件都不能少
//!
//! 1. **重签**(用旧 DID 的绑定密钥)。一份改过却还挂着旧 proof 的文档不是
//!    "没签名",是**假话** —— 验证方一验就拒,而人只会看到"这文档验不过"。
//! 2. **自检**。签得出来却绑不上路径的文档,发出去只会让**别人**替我们
//!    发现我们在骗自己。
//! 3. **让人看一眼摘要再点头**。这些操作全都是不可逆的:迁移只写一次、
//!    摘掉的钥匙的 seed 只在这个文件里。

#[cfg(feature = "seed-export")]
pub mod export;
pub mod identity;
pub mod import;
pub mod keys;
pub mod probe;

use std::path::Path;

use serde_json::Value;

use crate::audit::{AuditLog, Event};
use crate::did::document;
use crate::did::migrate;
use crate::error::{KeydError, Result};
use crate::keystore::layout::KeydLayout;
use crate::keystore::{device, store, unwrap};
use crate::sign::LockedSigningKey;
use crate::tty;

/// 一次操作的上下文:目录、终端、审计。
///
/// 把这三样绑在一起,是因为它们必须**同时**对:没有终端的迁移等于在自动化
/// 里悄悄改身份;没有审计的迁移等于事后说不清"这台机器上这把身份是什么
/// 时候变成那样的"。
pub struct Session {
    _maintenance: nix::fcntl::Flock<std::fs::File>,
    pub layout: KeydLayout,
    tty: std::fs::File,
    audit: AuditLog,
}

impl Session {
    pub fn open(root: Option<&Path>) -> Result<Self> {
        let layout = match root {
            Some(root) => KeydLayout::at(root.to_path_buf()),
            None => KeydLayout::user_default()?,
        };
        crate::security::paths::deny_managed_directory(layout.root())?;
        layout.ensure()?;
        let maintenance = crate::security::paths::legacy_lease(layout.root())?;
        let audit = AuditLog::open(&layout.audit_dir())?;
        let session = Self { layout, tty: tty::open()?, audit, _maintenance: maintenance };

        // 上次导出过就在这里说一句。
        //
        // 位置选在"每一条需要终端的命令的开头",而不是守护进程启动的时候:
        // 守护进程由服务管理器拉起来,人根本看不见它的输出。而人一定会看见
        // 自己敲的那条命令的输出 —— 家用路由器把"上次登录"印在登录页上,
        // 正是同一个道理。用得着这个提醒的场合,是那个**正在敲命令的人**
        // 被 agent 说服了要跑一次导出。
        if let Some(line) = crate::audit::log::export_tripwire(&session.layout.audit_dir()) {
            session.say(&format!("\n{line}\n"))?;
        }
        Ok(session)
    }

    pub fn layout(&self) -> &KeydLayout {
        &self.layout
    }

    /// 解开一把钥匙。`kid` 是**fragment**(`key-2`、`recovery-1`),
    /// 不给就是绑定密钥。
    ///
    /// 返回的 `LockedSigningKey` 用完就 drop —— 它是短命的,不进任何缓存。
    pub fn unlock(
        &self,
        did: &str,
        kid: Option<&str>,
        prompt: &str,
    ) -> Result<(crate::keystore::record::WrappedKey, LockedSigningKey)> {
        let passphrase = tty::read_secret(&self.tty, prompt)?;
        self.unlock_with(did, kid, passphrase.as_bytes())
    }

    /// 同上,但口令已经拿在手上。
    ///
    /// 分成两个而不是"一个带 `Option<&str>` 的",是因为**持有**口令和
    /// **问出**口令是两件事:轮换时要拿绑定密钥那个口令去当新钥匙的默认值,
    /// 于是它得在作用域里多活一会儿。把这个需求写成参数,调用点就一眼看得见
    /// "这个口令在这段代码里是活的"。
    pub fn unlock_with(
        &self,
        did: &str,
        kid: Option<&str>,
        passphrase: &[u8],
    ) -> Result<(crate::keystore::record::WrappedKey, LockedSigningKey)> {
        let wrapped = store::resolve(&self.layout, did, kid)?;
        let device_secret = device::load(&self.layout)?;
        let key = unwrap::unlock(&wrapped, passphrase, &device_secret)?;
        Ok((wrapped, key))
    }

    /// 问一次秘密。新钥匙的信封要用它。
    pub(crate) fn ask_secret(&self, prompt: &str) -> Result<zeroize::Zeroizing<String>> {
        tty::read_secret(&self.tty, prompt)
    }

    /// 问一个**新的**秘密,问两遍。
    ///
    /// 导入和导出设的都是"这台机器上的新口令":敲错一个字符的代价是以后
    /// 再也解不开,而那时候人已经在用别的东西了。所以和 `keygen` 走同一条
    /// 路 —— 不给"我就问一次"这个选项。
    pub(crate) fn ask_new_secret(
        &self,
        prompt: &str,
        confirm: &str,
    ) -> Result<zeroize::Zeroizing<String>> {
        tty::read_secret_twice(&self.tty, prompt, confirm)
    }

    /// 读一行**看得见**的输入。
    ///
    /// 给 24 个词用。它确实是秘密,但这里选看得见:人是照着纸上那份一个词
    /// 一个词对过去的,不显示等于让他闭着眼睛抄 —— 而校验和只能抓出"错得
    /// 不巧"的那些,抓不出"两个都是合法词、抄的时候看串了行"。
    pub(crate) fn ask_line(&self, prompt: &str) -> Result<zeroize::Zeroizing<String>> {
        write_tty(&self.tty, prompt)?;
        tty::read_line(&self.tty)
    }

    pub(crate) fn confirm(&self, question: &str) -> Result<bool> {
        tty::confirm(&self.tty, question)
    }

    pub(crate) fn say(&self, text: &str) -> Result<()> {
        write_tty(&self.tty, text)
    }

    pub fn audit(&mut self, event: &Event) -> Result<()> {
        self.audit.append(event)
    }

    /// 磁盘上那份文档,以及它的摘要。
    pub fn current_document(&self, did: &str) -> Result<(Value, String)> {
        let document = store::read_did_document(&self.layout, did).map_err(|error| {
            KeydError::Protocol(format!(
                "no local document for {did} ({error}). These commands change the document \
                 that is already there, so run `anpio-key publish --did {did}` first — \
                 inventing one from the DID alone would silently drop anything the real \
                 one carries (hot keys, recovery keys, a migration record)"
            ))
        })?;
        let digest = crate::did::lifecycle::document_digest(&document)?;
        Ok((document, digest))
    }
}

fn write_tty(tty: &std::fs::File, text: &str) -> Result<()> {
    use std::io::Write;
    // 提示语走 tty 而不是 stdout:stdout 可能是管道,而提问必须落在人正
    // 看着的那个屏幕上,否则他看到的是一段没有问题的等待。
    let mut out = tty.try_clone().map_err(KeydError::Io)?;
    out.write_all(text.as_bytes())?;
    out.flush()?;
    Ok(())
}

/// 签好、自检、让人点头、CAS 落盘。
///
/// 返回写完之后那份文档的摘要。**摘要算的是签名之后的字节** —— 它就是
/// 事后拿线上那份来比对时用的那个值,所以必须在签名之后算,在写之前算。
pub fn sign_confirm_and_write(
    session: &Session,
    did: &str,
    binding: &LockedSigningKey,
    document: &Value,
    expected_digest: &str,
    what: &str,
) -> Result<String> {
    let signed = document::sign_document(document, binding, &binding.id().kid)?;

    // 自检放在确认**之前**:让人点头说"是的,写这一份",而他点的必须是一份
    // 我们自己都验不过的东西吗?不。验不过就根本不该问他。
    document::verify_path_binding(did, &signed)?;

    let digest = crate::did::lifecycle::document_digest(&signed)?;
    show_and_confirm(session, did, what, &digest)?;

    migrate::cas_publish(&session.layout, did, expected_digest, &signed)?;
    Ok(digest)
}

/// 把即将发生的事摆出来,要一个明确的 yes。
///
/// 打印的是**摘要**,不是整份文档:整份文档有几十行,人会直接翻过去;
/// 而摘要短到没法不看见,并且事后能拿来和线上那份逐字比对。
fn show_and_confirm(session: &Session, did: &str, what: &str, digest: &str) -> Result<()> {
    session.say(&format!(
        "\n{what}\n\n  {did}\n  document digest: {digest}\n\n\
         This cannot be undone. The digest above is what the served document must hash to\n\
         afterwards — write it down if you want to be able to tell later whether the copy\n\
         that went live is this one.\n\n"
    ))?;

    if !session.confirm("Write it?")? {
        return Err(KeydError::Protocol(
            "nothing was written; you answered no".into(),
        ));
    }
    Ok(())
}

/// 文档写下去之后都得说一句:这个工具**不能托管任何东西**。
///
/// 不打印它,人就会以为命令跑完 = 改动生效。而实际上别人看到的还是域名底下
/// 那一份 —— 直到有人把新文件放上去。
pub fn hosting_notice(did: &str) -> Result<()> {
    let url = crate::did::did_url_path(did)?;
    let host = url
        .strip_prefix("https://")
        .and_then(|rest| rest.split('/').next())
        .unwrap_or(url.as_str())
        .to_string();
    migrate::hosting_notice(&url, &host);
    Ok(())
}
