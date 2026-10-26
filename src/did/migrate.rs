//! 迁移 —— 换掉 binding key 或换掉域名。**DID 必变**,所以这不是编辑文档,
//! 是给一份死掉的文档写遗言,再让新 DID 接着活。
//!
//! 规范把这条边写得很死(§2.5.3),这里逐条落实:
//!
//! 1. 旧文档**不得删除**,必须继续可解析,并置 `deactivated = true` +
//!    `successorDid = <新 DID>`。
//! 2. `successorDid` **只写一次**。以后再有轮换,不得回头改前一代 ——
//!    回头改会让历史出现两条指向不同下一代的边。
//! 3. 防并发轮换:对"当前完整 DID"做**原子 compare-and-swap**。
//!
//! ## 一个必须说清楚的边界
//!
//! 这个工具**只能改自己手上那份文档**。真正让别人看得见的动作是把这个文件
//! 重新放到域名底下去 —— 那需要 `example.com` 的写权限,而 keyd 没有、
//! 也不该有。所以每个出口命令都要把这句话打出来,而不是让人以为自己
//! "迁移完了"。
//!
//! 还有一条同样重要:**迁移不搬任何秘密**。旧 DID 的钥匙还在旧机器上,
//! 它只是被明确作废了;新 DID 的钥匙在新机器上。这也是为什么默认应该走
//! 迁移而不是导出 —— 秘密一步都不动。

use std::collections::BTreeMap;
use std::io::Write;

use serde_json::Value;

use crate::did::lifecycle;
use crate::did::parse::parse_did_wba;
use crate::error::{KeydError, Result};
use crate::keystore::layout::{self, KeydLayout, PUBLIC_FILE_MODE};

/// 迁移到**不同 subject path** 的 DID 时,这个开关必须显式给。
///
/// 换域名是规范允许的迁移之一(§六·七 情况二),但它的性质完全不同:验证方
/// 认"同一个 stable subject path"是同一个主体,path 一变,这条边就只能靠
/// 域名自己作证 —— 规范把这种 hop 定成 `provider_asserted` 或 `unverified`,
/// 并明说**校验方不得把它升级、也不该缓存**。默认拒,是因为默认放行等于
/// 让一次打错字的 `--to` 变成一次无人察觉的冒名。
pub const DIFFERENT_SUBJECT_IS_REFUSED: &str =
    "the successor DID has a different stable subject path, which is a different \
     subject as far as verifiers are concerned";

/// 从 `start` 出发沿 `successorDid` 一路走,走到尽头(或走不动)为止。
///
/// 撞上环就报错。**环检测必须在写之前做**:写下去之后,再想把环拆掉就得
/// 重新签一遍已经作废的文档,而那正是"不得回头改 successorDid"要挡的事。
pub fn successor_chain<F>(start: &str, lookup: F) -> Result<Vec<String>>
where
    F: Fn(&str) -> Option<String>,
{
    let mut chain = vec![start.to_string()];
    let mut seen = std::collections::BTreeSet::new();
    seen.insert(start.to_string());

    let mut cursor = start.to_string();
    // 上限不是"够了",而是**环路一定在有限步内撞上重复**:每一步都必须在
    // `seen` 里插进一个新值,插不进就是环。这个上界只是防病态输入把内存
    // 吃光的一根保险丝。
    for _ in 0..1024 {
        let Some(next) = lookup(&cursor) else {
            return Ok(chain);
        };
        if next == cursor {
            return Err(KeydError::Did(format!(
                "{cursor} names itself as its own successor"
            )));
        }
        if !seen.insert(next.clone()) {
            return Err(KeydError::Did(format!(
                "the successor chain loops: {} → {next}, and {next} is already in it \
                 (a migration path that goes in a circle is one no verifier can walk)",
                chain.join(" → ")
            )));
        }
        chain.push(next.clone());
        cursor = next;
    }
    Err(KeydError::Did(format!(
        "the successor chain from {start} is longer than any real migration path — \
         refusing rather than walking it further"
    )))
}

/// 一次迁移要满足的全部条件,查完返回**旧文档该有的新样子**(还是未签名)。
///
/// `known_successors` 是本机已知的 `DID → successorDid`。环检测只能靠它:
/// 离线是查不到全网链的,而"我看得见的那部分里有没有环"是能诚实地回答的
/// 那一半 —— 所以这里做,并把看不见的部分在文档里说清楚。
pub fn plan(
    from: &str,
    to: &str,
    document: &Value,
    known_successors: &BTreeMap<String, String>,
    allow_different_subject: bool,
) -> Result<Value> {
    if from == to {
        return Err(KeydError::Did(format!(
            "{to} cannot succeed itself — a DID that points at itself is a loop, and a \
             verifier walking it never arrives anywhere"
        )));
    }
    // 两边的 DID 都得先能解析,否则后面算 subject path 报的错会指向别处。
    parse_did_wba(to).map_err(|error| {
        KeydError::Did(format!("--to {to} is not a did:wba DID: {error}"))
    })?;

    if !lifecycle::same_subject(from, to)? && !allow_different_subject {
        return Err(KeydError::Did(format!(
            "{DIFFERENT_SUBJECT_IS_REFUSED}: {} is {from}, and {to} is {}. A \
             binding-key rotation keeps the path and changes only the last segment; \
             a domain change is a different operation, and verifiers are told not to \
             cache it. Pass --allow-different-subject if that is really what you mean",
            lifecycle::subject_path(from)?,
            lifecycle::subject_path(to)?
        )));
    }

    // 环:从**新** DID 出发能不能走回旧 DID。这才是环的形状 ——
    // 旧文档里那条边还没写下去,所以从它出发是查不出来的。
    let chain = successor_chain(to, |did| known_successors.get(did).cloned())?;
    if chain.iter().any(|did| did == from) {
        return Err(KeydError::Did(format!(
            "this migration would close a loop: {} → {from}, and {from} is already \
             being migrated away from",
            chain.join(" → ")
        )));
    }

    // `successorDid` 只写一次。`deactivate` 里再挡一遍(它是那个不变式的
    // 所有者),这里挡是因为迁移的语义是"换一个新的",硬要改写一条已经存在
    // 的边是调用方搞错了命令。
    if lifecycle::is_deactivated(document) {
        return Err(KeydError::Did(format!(
            "{from} is already deactivated; a document may only be deactivated once, and \
             its successor edge only written once"
        )));
    }

    lifecycle::deactivate(document, Some(to))
}

/// 拿本机所有 DID 文档里的 `DID → successorDid` 建表 —— 环检测的输入。
pub fn known_successors(layout: &KeydLayout) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for path in layout.list_did_paths()? {
        let Ok(bytes) = std::fs::read(&path) else { continue };
        let Ok(document) = serde_json::from_slice::<Value>(&bytes) else {
            // 读不懂的文档不参与环检测:它没有任何 successor 边可言,而
            // 把它当成错误会让一次迁移因为**别人的**坏文件而失败。
            continue;
        };
        let Some(did) = document.get("id").and_then(Value::as_str) else { continue };
        if let Some(successor) = lifecycle::successor_of(&document) {
            out.insert(did.to_string(), successor.to_string());
        }
    }
    Ok(out)
}

/// 对一个 DID 的文档做原子 compare-and-swap。
///
/// "原子"在这里是三层,缺一层都不成立:
///
/// 1. **进程间串行**:`flock` 排他锁把"读→比→写"整段包住。没有它,两个
///    并发的迁移可以各自读到同一份旧文档、各自通过检查,然后先后写下**两个
///    不同的** successor —— 规范点名要防的就是这个。
/// 2. **比对内容**:`expected_digest` 是人在终端上确认过的那一份。锁只保证
///    没有别人同时进来,不保证**从确认到执行**这中间文档没被改过。
/// 3. **原子落盘**:`write_atomic`(临时文件 → fsync → rename)。
///
/// 锁文件是 `dids/<did>.lock` 而不是文档本身:`write_atomic` 是 rename,
/// 锁住旧 inode 挡不住任何东西。
pub fn cas_publish(
    layout: &KeydLayout,
    did: &str,
    expected_digest: &str,
    document: &Value,
) -> Result<()> {
    layout.ensure()?;
    let lock_path = layout.did_lock_path(did);
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;

    // `Flock` 是 RAII 的:锁随这个绑定走,到函数结束才放。这里**没有**提前
    // 解锁的分支 —— 提前放锁等于把 CAS 拆成"读、比、别人插进来、写"。
    let _guard = nix::fcntl::Flock::lock(lock, nix::fcntl::FlockArg::LockExclusive).map_err(
        |(_, error)| {
            KeydError::Protocol(format!("cannot lock {}: {error}", lock_path.display()))
        },
    )?;

    let current = crate::keystore::store::read_did_document(layout, did).map_err(|error| {
        KeydError::Protocol(format!(
            "cannot re-read {did} under the lock, so this change cannot be made atomically: \
             {error}"
        ))
    })?;
    let now = lifecycle::document_digest(&current)?;
    if now != expected_digest {
        return Err(KeydError::Protocol(format!(
            "the document for {did} changed while this was being decided (it was \
             {expected_digest}, it is now {now}) — nothing was written. Re-run and look at \
             the new one: whoever changed it may have been a concurrent rotation, and \
             overwriting it would throw their successor edge away"
        )));
    }

    let mut bytes = serde_json::to_vec_pretty(document)?;
    let result = layout::write_atomic(&layout.did_path(did), &bytes, PUBLIC_FILE_MODE);
    zeroize::Zeroize::zeroize(&mut bytes);
    result
}

/// 磁盘上这份文档的摘要 —— 叫人确认时用的就是它。
pub fn digest_of(layout: &KeydLayout, did: &str) -> Result<String> {
    let document = crate::keystore::store::read_did_document(layout, did)?;
    lifecycle::document_digest(&document)
}

/// 把文档写到 `--out` 指定的文件(给"我自己去放"的用法)。
pub fn write_to(path: &std::path::Path, document: &Value) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut file = std::fs::File::create(path)?;
    file.write_all(&serde_json::to_vec_pretty(document)?)?;
    file.sync_all()?;
    Ok(())
}

/// 每个出口命令都要打的那句话。
///
/// 不打印它,人就会以为命令跑完 = 迁移完成。而实际上**别人看到的还是旧文档**
/// —— 直到有人把新文件放到域名底下。这是这个工具最大的一处越界,必须每次
/// 都说。
pub fn hosting_notice(document_url: &str, host: &str) {
    println!();
    println!("this tool cannot host anything. To make this real you need write access to");
    println!("    {host}");
    println!("so that {document_url}");
    println!("serves this file. Until then, nothing anyone else can see has changed.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hygiene::LockedBytes;
    use crate::did::document::{build_unsigned, sign_document, DidDocumentSpec, ROOT_FRAGMENT};
    use crate::keystore::layout::KeydLayout;
    use crate::keystore::record::KeyId;
    use crate::sign::LockedSigningKey;

    const PATH: &str = "user/alice";

    fn key(byte: u8) -> LockedSigningKey {
        let seed = LockedBytes::fill(|d| *d = [byte; 32]).unwrap();
        LockedSigningKey::from_seed(
            KeyId { did: String::new(), kid: String::new(), thumbprint: String::new() },
            seed,
        )
        .unwrap()
    }

    /// 一个签好的文档,挂在 `host` 上。
    fn signed(byte: u8, host: &str) -> (String, Value) {
        let key = key(byte);
        let spec = DidDocumentSpec::new(host, PATH.split('/').map(str::to_string).collect());
        let (did, unsigned) = build_unsigned(&spec, &key.verifying_key().unwrap()).unwrap();
        let signed = sign_document(&unsigned, &key, &format!("{did}#{ROOT_FRAGMENT}")).unwrap();
        (did, signed)
    }

    fn layout(name: &str) -> KeydLayout {
        let dir = std::env::temp_dir().join(format!("keyd-migrate-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let l = KeydLayout::at(dir);
        l.ensure().unwrap();
        l
    }

    // ————————————————————————————————————————————————————————————————————
    // 环
    // ————————————————————————————————————————————————————————————————————

    #[test]
    fn a_chain_that_ends_is_walked_to_the_end() {
        let table: BTreeMap<String, String> =
            [("a", "b"), ("b", "c")].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        assert_eq!(successor_chain("a", |d| table.get(d).cloned()).unwrap(), ["a", "b", "c"]);
    }

    /// 两跳的环。
    #[test]
    fn a_two_hop_loop_is_detected() {
        let table: BTreeMap<String, String> =
            [("a", "b"), ("b", "a")].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let error = successor_chain("a", |d| table.get(d).cloned()).unwrap_err();
        assert!(error.to_string().contains("loops"), "{error}");
    }

    /// 自己指自己:一步的环。
    #[test]
    fn a_self_loop_is_detected() {
        let table: BTreeMap<String, String> =
            [("a", "a")].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let error = successor_chain("a", |d| table.get(d).cloned()).unwrap_err();
        assert!(error.to_string().contains("its own successor"), "{error}");
    }

    /**
     * 迁移**闭合**一个环:新 DID 已经在往旧 DID 走的路上。

     * 这条是环检测真正的用武之地 —— 旧文档里那条边还没写下去,所以只从
     * 旧 DID 出发是查不出来的。要查的是"从新 DID 走得回旧 DID 吗"。
     */
    #[test]
    fn a_migration_that_would_close_a_loop_is_refused() {
        let (from, document) = signed(0x81, "example.com");
        let (to, _) = signed(0x82, "example.com");

        // 新 DID 已经在往别处走,而那个"别处"正是旧 DID。
        let table: BTreeMap<String, String> =
            [(to.clone(), from.clone())].into_iter().collect();

        let error = plan(&from, &to, &document, &table, false).unwrap_err();
        assert!(error.to_string().contains("close a loop"), "{error}");
    }

    // ————————————————————————————————————————————————————————————————————
    // subject path
    // ————————————————————————————————————————————————————————————————————

    /// 默认拒绝换域名,而且要说清楚为什么 —— 这是四次"我打错字了"里的四次。
    #[test]
    fn a_different_subject_path_is_refused_unless_asked_for() {
        let (from, document) = signed(0x83, "example.com");
        let (to, _) = signed(0x84, "elsewhere.com");
        let table = BTreeMap::new();

        let error = plan(&from, &to, &document, &table, false).unwrap_err();
        assert!(error.to_string().contains("different stable subject path"), "{error}");

        // 明确说了要为,那就为。
        let planned = plan(&from, &to, &document, &table, true).unwrap();
        assert_eq!(lifecycle::successor_of(&planned), Some(to.as_str()));
    }

    /// 同一路径、换最后一段:这就是"换 binding key",放行。
    #[test]
    fn rotating_the_binding_key_inside_one_path_is_allowed() {
        let (from, document) = signed(0x85, "example.com");
        let (to, _) = signed(0x86, "example.com");
        assert!(lifecycle::same_subject(&from, &to).unwrap());

        let planned = plan(&from, &to, &document, &BTreeMap::new(), false).unwrap();
        assert!(lifecycle::is_deactivated(&planned));
        assert_eq!(lifecycle::successor_of(&planned), Some(to.as_str()));
        // 摘掉旧 proof —— 它盖的是旧字节,留着等于签一份已经不存在的文档。
        assert!(planned.get("proof").is_none());
    }

    #[test]
    fn a_did_cannot_succeed_itself() {
        let (from, document) = signed(0x87, "example.com");
        let error = plan(&from, &from, &document, &BTreeMap::new(), false).unwrap_err();
        assert!(error.to_string().contains("cannot succeed itself"), "{error}");
    }

    #[test]
    fn an_already_deactivated_document_cannot_be_migrated_again() {
        let (from, document) = signed(0x88, "example.com");
        let (first, _) = signed(0x89, "example.com");
        let (second, _) = signed(0x8a, "example.com");

        let done = lifecycle::deactivate(&document, Some(&first)).unwrap();
        let error = plan(&from, &second, &done, &BTreeMap::new(), false).unwrap_err();
        assert!(error.to_string().contains("already deactivated"), "{error}");
    }

    #[test]
    fn a_successor_that_is_not_a_did_at_all_is_refused() {
        let (from, document) = signed(0x8b, "example.com");
        let error = plan(&from, "https://example.com", &document, &BTreeMap::new(), true)
            .unwrap_err();
        assert!(error.to_string().contains("not a did:wba DID"), "{error}");
    }

    // ————————————————————————————————————————————————————————————————————
    // CAS
    // ————————————————————————————————————————————————————————————————————

    #[test]
    fn a_stale_digest_writes_nothing() {
        let l = layout("stale");
        let (did, document) = signed(0x8c, "example.com");
        crate::keystore::store::write_did_document(&l, &did, &document).unwrap();

        let stale = "not-the-current-digest";
        let (to, _) = signed(0x8d, "example.com");
        let planned = plan(&did, &to, &document, &BTreeMap::new(), false).unwrap();

        let error = cas_publish(&l, &did, stale, &planned).unwrap_err();
        assert!(error.to_string().contains("changed while this was being decided"), "{error}");

        // 磁盘上那份必须**一动不动**。
        let after = crate::keystore::store::read_did_document(&l, &did).unwrap();
        assert!(!lifecycle::is_deactivated(&after), "a refused CAS must not have written");

        let _ = std::fs::remove_dir_all(l.root());
    }

    #[test]
    fn the_current_digest_goes_through() {
        let l = layout("through");
        let (did, document) = signed(0x8e, "example.com");
        crate::keystore::store::write_did_document(&l, &did, &document).unwrap();

        let (to, _) = signed(0x8f, "example.com");
        let planned = plan(&did, &to, &document, &BTreeMap::new(), false).unwrap();
        cas_publish(&l, &did, &digest_of(&l, &did).unwrap(), &planned).unwrap();

        let after = crate::keystore::store::read_did_document(&l, &did).unwrap();
        assert_eq!(lifecycle::successor_of(&after), Some(to.as_str()));

        let _ = std::fs::remove_dir_all(l.root());
    }

    /// **并发轮换只能有一个成功。**
    ///
    /// 规范点名要防的就是它:两个并发轮换各自读到同一份旧文档、各自通过检查,
    /// 然后先后写下**两个不同的** successor —— 历史从此分叉,而任何一个
    /// 走到这里的验证方都会随机落到其中一条上。
    #[test]
    fn concurrent_rotations_leave_exactly_one_successor() {
        let l = layout("concurrent");
        let (did, document) = signed(0x90, "example.com");
        crate::keystore::store::write_did_document(&l, &did, &document).unwrap();
        let digest = digest_of(&l, &did).unwrap();

        // 每个人都拿着**同一个**摘要 —— 也就是都通过了"内容没变"这一关。
        // 那之后就只有锁和锁内重读能救场了。
        let mut plans = Vec::new();
        for byte in 0x91..0x95u8 {
            let (to, _) = signed(byte, "example.com");
            plans.push((to.clone(), plan(&did, &to, &document, &BTreeMap::new(), false).unwrap()));
        }

        let results: Vec<_> = std::thread::scope(|scope| {
            let handles: Vec<_> = plans
                .iter()
                .map(|(_, planned)| {
                    let (l, did, digest) = (&l, did.clone(), digest.clone());
                    scope.spawn(move || cas_publish(l, &did, &digest, planned).is_ok())
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });

        assert_eq!(
            results.iter().filter(|ok| **ok).count(),
            1,
            "exactly one concurrent rotation may land: {results:?}"
        );

        let after = crate::keystore::store::read_did_document(&l, &did).unwrap();
        let winner = lifecycle::successor_of(&after).unwrap();
        assert!(plans.iter().any(|(to, _)| to == winner), "the survivor must be one of ours");

        let _ = std::fs::remove_dir_all(l.root());
    }

    /// 重签之后的注销文档**仍然**是一份合法的 did:wba 文档。
    ///
    /// 这一条不是形式主义,它是整条迁移链的前提:验证方从旧 DID 出发,拿到的
    /// 是一份带 `deactivated` 和 `successorDid` 的文档,而它必须能通过**同一套**
    /// 规范性检查、proof 照样验得过 —— 否则"顺着 successorDid 走过去"这件事
    /// 就无从谈起,规范说的 `verified` 那一档可信度也就不存在。
    #[test]
    fn a_deactivated_document_still_passes_the_binding_check() {
        let k = key(0x97);
        let spec = DidDocumentSpec::new("example.com", PATH.split('/').map(str::to_string).collect());
        let (did, unsigned) = build_unsigned(&spec, &k.verifying_key().unwrap()).unwrap();
        let method = format!("{did}#{ROOT_FRAGMENT}");

        let live = sign_document(&unsigned, &k, &method).unwrap();
        crate::did::document::verify_path_binding(&did, &live).unwrap();

        let (to, _) = signed(0x98, "example.com");
        let planned = plan(&did, &to, &live, &BTreeMap::new(), false).unwrap();
        let deactivated = sign_document(&planned, &k, &method).unwrap();

        // `deactivated` 和 `successorDid` 都在 proof 覆盖的字节里,所以这份
        // 签名同时作证了"这个 DID 的持有人说要迁移"。
        crate::did::document::verify_path_binding(&did, &deactivated)
            .expect("a deactivated document must still be a well-formed did:wba document");
        assert_eq!(lifecycle::successor_of(&deactivated), Some(to.as_str()));
    }

    #[test]
    fn known_successors_reads_the_local_documents() {
        let l = layout("known");
        let (old, old_doc) = signed(0x95, "example.com");
        let (new, new_doc) = signed(0x96, "example.com");
        crate::keystore::store::write_did_document(&l, &old, &old_doc).unwrap();
        crate::keystore::store::write_did_document(&l, &new, &new_doc).unwrap();

        // 只有一条边,另一份文档还没注销。
        let table = known_successors(&l).unwrap();
        assert!(table.is_empty());

        let planned = plan(&old, &new, &old_doc, &table, false).unwrap();
        cas_publish(&l, &old, &digest_of(&l, &old).unwrap(), &planned).unwrap();

        let table = known_successors(&l).unwrap();
        assert_eq!(table.get(&old), Some(&new));

        let _ = std::fs::remove_dir_all(l.root());
    }
}
