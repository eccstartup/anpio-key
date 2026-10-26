//! 守护进程的状态:**谁解锁了哪把钥匙,以及它现在还在不在内存里**。
//!
//! ## 命名空间就是 uid
//!
//! 这是这个模块里唯一重要的结构决定:已解锁的钥匙不是存在一个全局表里,
//! 而是**按对端 uid 分的 vault**,每个 vault 有自己的磁盘根
//! (`/var/lib/anpio-key/users/<uid>`)。
//!
//! 于是"uid A 用不了 uid B 的钥匙"不是一条需要记得去执行的检查,而是
//! **没有那个入口**:一个请求能说出任何 did,但 did 只会在调用者自己那个
//! vault 里被查。A 说出 B 的 did,结果和说一个不存在的 did 完全一样。
//! 检查会漏、会被绕过、会在重构时被挪走;"查不到"不会。
//!
//! ## 锁着的时候,内存里没有钥匙
//!
//! 没解锁的钥匙,在这个进程里**不存在**。不是"存在但被拦住",是真的
//! 没有 —— 只有解开的那些在 `mlock` 住的页里躺着,其余时候守护进程手上
//! 只有磁盘上的信封。所以"杀掉守护进程"和"锁上"在密钥这件事上是同一件事。

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::audit::{AuditLog, Event};
use crate::daemon::autolock::Autolock;
use crate::daemon::peer::PeerPolicy;
use crate::daemon::wire::{KeySummary, UnlockedKey};
use crate::did::parse::parse_did_wba;
use crate::error::{KeydError, Result};
use crate::keystore::{device, layout::KeydLayout, store};
use crate::sign::{ed25519::LockedSigningKey, rfc9421};

/// 磁盘根从哪来。
pub enum Roots {
    /// 单用户:整个守护进程只服务 `~/.anpio-key` 这一个命名空间。
    Single(KeydLayout),
    /// 系统服务:`/var/lib/anpio-key/users/<uid>`,对端 uid 决定用哪个。
    PerUid,
}

impl Roots {
    /// 对端 uid → 它的磁盘根。
    ///
    /// `Single` 分支**不看 uid** —— 它只会拿到自己的 uid(对端授权在
    /// [`PeerPolicy::admit`] 那一层已经做过),所以这里没有可以搞错的地方。
    pub fn layout_for(&self, uid: u32) -> Result<KeydLayout> {
        match self {
            Roots::Single(layout) => Ok(KeydLayout::at(layout.root().to_path_buf())),
            Roots::PerUid => KeydLayout::system(uid),
        }
    }

    /// 服务方自己的审计目录。
    ///
    /// 被拒的连接记到这里,而不是被拒那位自己的目录:多数情况下我们根本
    /// 写不进去,而且往别人家里写日志也不是这个进程该做的事。
    pub fn service_audit_dir(&self) -> std::path::PathBuf {
        match self {
            Roots::Single(layout) => layout.audit_dir(),
            Roots::PerUid => std::path::PathBuf::from("/var/lib/anpio-key/audit"),
        }
    }
}

/// 一把已经解开、正躺在 `mlock` 页里的钥匙。
struct Unlocked {
    key: LockedSigningKey,
    /// 什么时候解开的。只用来回答 `status`(给人类看"开了多久")。
    unlocked_at: Instant,
    /// 最后一次被用。空闲超时从这一刻起算。
    last_used: Instant,
}

/// 一个 uid 的命名空间。
pub struct Vault {
    layout: KeydLayout,
    /// **键是 `kid`,不是 `did`。**
    ///
    /// 一个 DID 底下可以挂不止一把钥匙:绑定密钥(它的指纹就是 DID 的最后
    /// 一段,动不了)+ 若干热密钥/恢复密钥(见 [`crate::did::lifecycle`])。
    /// 按 did 索引的话,后挂上的那几把会互相盖掉,而且"现在解锁的到底是
    /// 哪一把"会取决于解锁的先后顺序 —— 那种不确定性最后会变成"同一份
    /// 请求有时验得过有时验不过"。
    unlocked: BTreeMap<String, Unlocked>,
    generation: u64,
}

impl Vault {
    fn new(layout: KeydLayout) -> Self {
        Self {
            layout,
            unlocked: BTreeMap::new(),
            generation: 0,
        }
    }

    pub fn layout(&self) -> &KeydLayout {
        &self.layout
    }

    /// 把空闲太久的钥匙放掉。
    ///
    /// 这个动作在**每次访问之前**都跑一遍,所以超时是真的成立,不管有没有
    /// 一个后台清扫任务在跑。后台那一份只是让"没人访问"的时候也能及时锁上,
    /// 是体验,不是保证。
    fn sweep(&mut self, autolock: Autolock, now: Instant) {
        self.unlocked.retain(|_, entry| {
            !autolock.is_expired(now.saturating_duration_since(entry.last_used))
        });
    }

    /// 磁盘上所有的信封 —— 不需要解锁就能列。
    pub fn list_keys(&self) -> Result<Vec<KeySummary>> {
        Ok(store::load_all(&self.layout)?
            .into_iter()
            .map(|wrapped| KeySummary {
                did: wrapped.id.did,
                kid: wrapped.id.kid,
                algorithm: wrapped.algorithm,
            })
            .collect())
    }

    /// 当前解锁着的钥匙。调用方先 [`Vault::sweep`],这里就只管报。
    pub fn unlocked_keys(&self, now: Instant) -> Vec<UnlockedKey> {
        self.unlocked
            .values()
            .map(|entry| UnlockedKey {
                did: entry.key.id().did.clone(),
                kid: entry.key.id().kid.clone(),
                unlocked_secs: now.saturating_duration_since(entry.unlocked_at).as_secs(),
            })
            .collect()
    }

    /// 锁上。返回被放掉了几把。
    ///
    /// `did == None` 是"全锁"。**这个动作不报错**:锁一个本来就没解锁的
    /// 东西应该成功,而不是失败 —— 想要的东西已经在那儿了。
    ///
    /// 给了 `did` 而没给 `kid`:把这个 DID 底下**当时解锁着的**全放掉。
    /// 这把钥匙那个 DID 底下本来可能有热度密钥两把都开着,锁一把留一把
    /// 是另一种语义(而且没人要过),不能靠"顺手实现成哪个"来决定。
    ///
    /// `kid` 是 **fragment**(`key-2`),和 `--kid`、和线上协议一致;`unlocked`
    /// 的键是完整的 `did#fragment`,拼接在这里做一次。
    fn lock(&mut self, did: Option<&str>, kid: Option<&str>) -> usize {
        // Even locking an absent key cancels every older in-flight unlock.
        self.generation = self
            .generation
            .checked_add(1)
            .expect("vault generation exhausted");
        match did {
            None => {
                let count = self.unlocked.len();
                self.unlocked.clear();
                count
            }
            Some(did) => {
                let before = self.unlocked.len();
                match kid {
                    Some(kid) => {
                        self.unlocked.remove(&format!("{did}#{kid}"));
                    }
                    None => {
                        let prefix = format!("{did}#");
                        self.unlocked
                            .retain(|resident, _| !resident.starts_with(&prefix));
                    }
                }
                before - self.unlocked.len()
            }
        }
    }

    /// 借出钥匙用一下,并刷新它的空闲计时。
    ///
    /// 钥匙**不复制**给调用方:它没有 `Clone`,连所有权都拿不走,只能在
    /// 这个闭包里被借用。用完之后守护进程手上还是只有那一份。
    fn with_key<R>(
        &mut self,
        resident: &str,
        autolock: Autolock,
        now: Instant,
        f: impl FnOnce(&LockedSigningKey) -> Result<R>,
    ) -> Result<R> {
        self.sweep(autolock, now);

        let entry = self.unlocked.get_mut(resident).ok_or(KeydError::Locked)?;
        let out = f(&entry.key)?;
        // 刷新只在**成功之后**做。一次失败的调用不该把钥匙的寿命续上。
        entry.last_used = now;
        Ok(out)
    }
}

/// 哪几条签名路开着。
///
/// 一个具名的结构体,而不是构造函数上两个挨着的位置参数 —— 两个 `bool` 摆
/// 在一起,调换顺序编译得过去、行为却完全相反,而且没有任何地方看得出来。
///
/// `challenge` 由 [`SigningGates::new`] 按 `raw || challenge` **算出来**,不是
/// 照着传进来的值原样存:`raw` 严格比 `challenge` 宽(凡是挑战签得了的,原始
/// 签名都签得了,反过来不成立),所以一个打开了宽门的操作者不该被再要求去把
/// 窄门也打开一次。
///
/// 字段私有,只留 [`SigningGates::new`] 一个入口 —— 否则那句"算出来"就只是一
/// 句注释:字面量构造 `SigningGates { raw: true, challenge: false }` 编译得过
/// 去,而且没有任何地方看得出来它错了。
pub struct SigningGates {
    raw: bool,
    challenge: bool,
}

impl SigningGates {
    pub fn new(raw: bool, challenge: bool) -> Self {
        Self {
            raw,
            challenge: raw || challenge,
        }
    }

    /// 原始签名那条路开着没有。
    pub fn raw(&self) -> bool {
        self.raw
    }

    /// 挑战签名那条路开着没有。
    pub fn challenge(&self) -> bool {
        self.challenge
    }
}

/// 守护进程的全部可变状态。
pub struct DaemonState {
    roots: Roots,
    policy: PeerPolicy,
    autolock: Autolock,
    /// 哪几条签名路开着 —— `--allow-raw-signing` / `--allow-challenge-signing`。
    gates: SigningGates,
    vaults: Mutex<BTreeMap<u32, Vault>>,
    /// **一个目录一个 [`AuditLog`]**,按路径索引。
    ///
    /// 不能每个 vault 自己攥一个:同一个文件上放两个 `AuditLog`,它们各自
    /// 记着不同的 `seq` 和 `tail`,写出来的行接不上,链当场就断了 ——
    /// 而链断了恰恰是我们用来发现篡改的那个信号,自己造一个假阳性最糟。
    audits: Mutex<BTreeMap<std::path::PathBuf, AuditLog>>,
}

impl DaemonState {
    pub fn new(roots: Roots, policy: PeerPolicy, autolock: Autolock, gates: SigningGates) -> Self {
        Self {
            roots,
            policy,
            autolock,
            gates,
            vaults: Mutex::new(BTreeMap::new()),
            audits: Mutex::new(BTreeMap::new()),
        }
    }

    /// 往某个目录的审计日志里追加一条。
    ///
    /// 日志按需打开,而打开会把整条链验一遍 —— 所以"审计被人动过"会在
    /// **第一次要写它的时候**就炸出来,而不是等到某天有人去查。
    fn append_audit(&self, dir: &std::path::Path, event: &Event) -> Result<()> {
        let mut audits = self
            .audits
            .lock()
            .map_err(|_| KeydError::Protocol("the audit lock was poisoned".into()))?;

        if !audits.contains_key(dir) {
            audits.insert(dir.to_path_buf(), AuditLog::open(dir)?);
        }
        let log = audits
            .get_mut(dir)
            .ok_or_else(|| KeydError::Protocol("the audit log vanished mid-append".into()))?;
        log.append(event)
    }

    /// 记一件发生在某个 uid 命名空间里的事。
    pub fn record(&self, uid: u32, event: &Event) -> Result<()> {
        let dir = self.layout_for(uid)?.audit_dir();
        self.append_audit(&dir, event)
    }

    /// 记一件服务方自己的事(被拒的连接)。
    ///
    /// 拒绝发生在"这个 uid 是谁"还没确定或者确定下来是**别人**的时候,
    /// 所以它不能记到对方的目录里去。
    pub fn record_service(&self, event: &Event) -> Result<()> {
        let dir = self.roots.service_audit_dir();
        self.append_audit(&dir, event)
    }

    pub fn policy(&self) -> &PeerPolicy {
        &self.policy
    }

    pub fn autolock(&self) -> Autolock {
        self.autolock
    }

    pub fn raw_signing(&self) -> bool {
        self.gates.raw
    }

    /// 对端 uid 的磁盘根。不需要碰锁 —— 它只取决于 uid。
    pub fn layout_for(&self, uid: u32) -> Result<KeydLayout> {
        self.roots.layout_for(uid)
    }

    /// 在某个 uid 的 vault 上做一件事。
    ///
    /// 所有用到已解锁钥匙的操作都从这里进去。锁是 `std::sync::Mutex` 而
    /// 不是 tokio 的:里面的活儿(Argon2id、文件 I/O)是**阻塞**的,
    /// 调用方应该整体放进 `spawn_blocking`,而不是在这里假装它不阻塞。
    fn with_vault<R>(&self, uid: u32, f: impl FnOnce(&mut Vault) -> Result<R>) -> Result<R> {
        let layout = self.layout_for(uid)?;
        let mut vaults = self
            .vaults
            .lock()
            .map_err(|_| KeydError::Protocol("the vault lock was poisoned".into()))?;
        let vault = vaults.entry(uid).or_insert_with(|| Vault::new(layout));
        f(vault)
    }

    // —— 下面这几个是 handlers 真正调的 ——

    pub fn list_keys(&self, uid: u32) -> Result<Vec<KeySummary>> {
        self.with_vault(uid, |vault| vault.list_keys())
    }

    pub fn status(&self, uid: u32) -> Result<Vec<UnlockedKey>> {
        let autolock = self.autolock;
        let now = Instant::now();
        self.with_vault(uid, |vault| {
            vault.sweep(autolock, now);
            Ok(vault.unlocked_keys(now))
        })
    }

    /// 读一份**本机发布过的** DID 文档,原样交回字节。
    ///
    /// 只读,而且**不需要解锁** —— 文档是可公开的,它躺在 `dids/` 里就是
    /// 0644。所以这里不进 vault、不碰私钥、不产生签名,也不进覆盖面:它开放
    /// 的是一次读,不是一次授权(`docs/ADAPTER.md` §3.2)。
    ///
    /// 答不出来的只有一种情形:这台机器上没有发布过这个 DID。守护进程不联网,
    /// 所以它**替不了**调用方去 resolve 别人的 DID —— 那件事只能在客户端做。
    pub fn get_document(&self, uid: u32, did: &str) -> Result<(Vec<u8>, String)> {
        let layout = self.layout_for(uid)?;
        let bytes = store::read_did_document_bytes(&layout, did)?;
        // 交出去的字节和记进审计的摘要是**同一次读**的两面,所以在这里
        // 一次算完 —— 分成两次读,两次之间文档可能已经被替换,审计里那条
        // 就会指着一份调用方从没见过的版本。
        let document: serde_json::Value = serde_json::from_slice(&bytes)?;
        let digest = crate::did::lifecycle::document_digest(&document)?;
        Ok((bytes, digest))
    }

    pub fn unlock(
        &self,
        uid: u32,
        did: &str,
        kid: Option<&str>,
        passphrase: Zeroizing<String>,
    ) -> Result<()> {
        self.unlock_guarded(uid, did, kid, passphrase, || Ok(()))
    }

    pub(crate) fn unlock_guarded<G>(
        &self,
        uid: u32,
        did: &str,
        kid: Option<&str>,
        passphrase: Zeroizing<String>,
        before_install: impl FnOnce() -> Result<G>,
    ) -> Result<()> {
        self.unlock_using(uid, did, kid, passphrase, None, before_install)
    }

    pub(crate) fn se_envelope(
        &self,
        uid: u32,
        did: &str,
        kid: &str,
    ) -> Result<(u64, crate::keystore::record::WrappedKey)> {
        self.with_vault(uid, |vault| {
            Ok((
                vault.generation,
                store::resolve(&vault.layout, did, Some(kid))?,
            ))
        })
    }

    pub(crate) fn unlock_se_guarded<G>(
        &self,
        uid: u32,
        wrapped: &crate::keystore::record::WrappedKey,
        passphrase: Zeroizing<String>,
        hs: &crate::crypto::hygiene::LockedBytes,
        expected_generation: u64,
        before_install: impl FnOnce() -> Result<G>,
    ) -> Result<()> {
        let fragment = wrapped
            .id
            .kid
            .strip_prefix(&format!("{}#", wrapped.id.did))
            .filter(|s| !s.is_empty() && !s.contains('#'))
            .ok_or(KeydError::Locked)?;
        self.unlock_using(
            uid,
            &wrapped.id.did,
            Some(fragment),
            passphrase,
            Some((wrapped, hs, expected_generation)),
            before_install,
        )
    }

    fn unlock_using<G>(
        &self,
        uid: u32,
        did: &str,
        kid: Option<&str>,
        passphrase: Zeroizing<String>,
        se: Option<(
            &crate::keystore::record::WrappedKey,
            &crate::crypto::hygiene::LockedBytes,
            u64,
        )>,
        before_install: impl FnOnce() -> Result<G>,
    ) -> Result<()> {
        let (generation, wrapped, device_secret) = self.with_vault(uid, |vault| {
            let wrapped = store::resolve(&vault.layout, did, kid)?;
            let secret = device::load(&vault.layout)?;
            Ok((vault.generation, wrapped, secret))
        })?;
        // Expensive derivation must not hold the vault mutex: LOCK can cancel it.
        let key = if let Some((expected, hs, expected_generation)) = se {
            if generation != expected_generation
                || serde_json::to_vec(expected)? != serde_json::to_vec(&wrapped)?
            {
                return Err(KeydError::Locked);
            }
            crate::keystore::unwrap::unlock_with_se_hs(
                &wrapped,
                passphrase.as_bytes(),
                &device_secret,
                hs,
            )?
        } else {
            crate::keystore::unwrap::unlock(&wrapped, passphrase.as_bytes(), &device_secret)?
        };
        let _install_guard = before_install()?;
        self.with_vault(uid, |vault| {
            if vault.generation != generation {
                return Err(KeydError::Locked);
            }
            // A concurrent lifecycle file replacement must not install an old key.
            let current = store::resolve(&vault.layout, did, kid)?;
            if serde_json::to_vec(&current)? != serde_json::to_vec(&wrapped)? {
                return Err(KeydError::Locked);
            }
            let now = Instant::now();
            vault.unlocked.insert(
                wrapped.id.kid.clone(),
                Unlocked {
                    key,
                    unlocked_at: now,
                    last_used: now,
                },
            );
            Ok(())
        })
    }

    pub fn lock(&self, uid: u32, did: Option<&str>, kid: Option<&str>) -> Result<usize> {
        self.with_vault(uid, |vault| Ok(vault.lock(did, kid)))
    }

    /// 把所有 uid 的钥匙全放掉。退出前用。
    ///
    /// 退出的路径上**不能失败**:进程马上就要没了,这里报错除了让退出码
    /// 难看之外没有任何用。所以它把能收的都收掉,收不动的写日志,不返回错。
    pub fn lock_everything(&self) {
        let mut vaults = match self.vaults.lock() {
            Ok(vaults) => vaults,
            Err(poisoned) => poisoned.into_inner(),
        };
        for (uid, vault) in vaults.iter_mut() {
            let dropped = vault.lock(None, None);
            if dropped > 0 {
                tracing::info!(uid, dropped, "locked on shutdown");
            }
        }
    }

    /// Protected-mode sweeping records only through the SQLite audit owner.
    pub(crate) fn sweep_protected(&self, now: Instant) -> usize {
        let mut vaults = match self.vaults.lock() {
            Ok(v) => v,
            Err(p) => p.into_inner(),
        };
        vaults
            .values_mut()
            .map(|vault| {
                let before = vault.unlocked.len();
                vault.sweep(self.autolock, now);
                before - vault.unlocked.len()
            })
            .sum()
    }

    /// 后台清扫:把每个 vault 里空闲太久的钥匙放掉。
    ///
    /// 返回被放掉的总数,纯粹是为了让测试和日志看得见。
    ///
    /// 每次真的收走东西都留痕 —— "钥匙在我不知道的时候没了"和"它超时了"
    /// 必须是能分开的两件事,否则用户看到签名突然要求重新解锁会无从判断。
    pub fn sweep_all(&self, now: Instant) -> usize {
        let autolock = self.autolock;
        let mut dropped_per_uid = Vec::new();

        {
            let mut vaults = match self.vaults.lock() {
                Ok(vaults) => vaults,
                // 毒化的锁说明别的线程在改状态时 panic 了。清扫不是要紧事,
                // 跳过它 —— 但**不**去 unwrap,那会把一个已经在恢复的进程再炸一次。
                Err(poisoned) => poisoned.into_inner(),
            };

            for (uid, vault) in vaults.iter_mut() {
                let before = vault.unlocked.len();
                vault.sweep(autolock, now);
                let dropped = before - vault.unlocked.len();
                if dropped > 0 {
                    dropped_per_uid.push((*uid, dropped));
                }
            }
        }

        let mut total = 0;
        for (uid, dropped) in dropped_per_uid {
            total += dropped;
            // 记不进去不该让清扫失败 —— 钥匙已经收了,那才是要紧的事。
            if let Err(error) = self.record(uid, &Event::Swept { dropped }) {
                tracing::error!(uid, "the sweep could not be recorded: {error}");
            }
        }
        total
    }

    /// 结构化签名 —— 签名基由 [`rfc9421::sign_request`] 重建,覆盖面由它决定。
    ///
    /// 调用方给不出签名基,只能给一份请求的**描述**。
    ///
    /// `did` 单独传,不在 [`rfc9421::SignRequest`] 里:那把结构体描述的是
    /// "一个 HTTP 请求长什么样",而 did 说的是"用谁的钥匙"。两件事混在一个
    /// 结构里,迟早有人以为请求里的某个字段能影响选哪把钥匙。
    pub fn sign_structured(
        &self,
        uid: u32,
        did: &str,
        kid: Option<&str>,
        request: &rfc9421::SignRequest,
    ) -> Result<rfc9421::Signed> {
        let layout = self.layout_for(uid)?;

        // 谁要有权决定"用哪把钥匙",只能是这里 —— 不在调用方手上。
        let resident = store::resolve(&layout, did, kid)?.id.kid;
        // 文档先读出来 —— 别在读磁盘的时候攥着锁。
        let document = store::read_did_document(&layout, did)?;

        let autolock = self.autolock;
        let now = Instant::now();
        self.with_vault(uid, |vault| {
            vault.with_key(&resident, autolock, now, |key| {
                rfc9421::sign_request(&document, key, request)
            })
        })
    }

    /// Exact-key v2 profile. Called only by the protected transaction executor.
    pub(crate) fn sign_protected(
        &self,
        uid: u32,
        key_record: &crate::persistence::catalog::KeyRecord,
        request: &crate::security::http::CanonicalHttpRequest,
        expiry: i64,
        deadline: i64,
    ) -> Result<rfc9421::Signed> {
        let document = store::read_did_document(&self.layout_for(uid)?, &key_record.did)?;
        self.with_vault(uid, |vault| {
            vault.with_key(&key_record.kid, self.autolock, Instant::now(), |key| {
                use crate::persistence::clock::Clock;
                request.sign_profile(
                    &document,
                    key,
                    crate::persistence::clock::SystemClock.now()?,
                    expiry,
                    deadline,
                )
            })
        })
    }

    /// ANP origin proof。签名基由 `anp` 在上游拼,这里只负责把钥匙交进闭包。
    ///
    /// 不需要读 DID 文档:公钥来自 [`LockedSigningKey`],没有路径绑定要复核。
    pub(crate) fn sign_origin_proof(
        &self,
        uid: u32,
        key_record: &crate::persistence::catalog::KeyRecord,
        proof: &crate::security::origin::OriginProof,
        created: i64,
    ) -> Result<crate::security::origin::SignedOrigin> {
        self.with_vault(uid, |vault| {
            vault.with_key(&key_record.kid, self.autolock, Instant::now(), |key| {
                proof.sign(key, created)
            })
        })
    }

    /// 绑定用途的断言。message 已经按 purpose 定好,这里只负责把钥匙交进闭包。
    pub(crate) fn sign_purpose(
        &self,
        uid: u32,
        key_record: &crate::persistence::catalog::KeyRecord,
        request: &crate::security::purpose::PurposeRequest,
    ) -> Result<crate::security::purpose::SignedPurpose> {
        self.with_vault(uid, |vault| {
            vault.with_key(&key_record.kid, self.autolock, Instant::now(), |key| {
                request.sign(key)
            })
        })
    }

    /// 借出钥匙做一次原始签名(`--allow-raw-signing` 那条路)。
    ///
    /// 开关的检查**在这里**,不在 handlers —— 让"能不能走这条路"和
    /// "这条路怎么走"待在同一个地方,免得哪天有人绕开 handler 直接调。
    pub fn sign_raw<R>(
        &self,
        uid: u32,
        did: &str,
        kid: Option<&str>,
        f: impl FnOnce(&LockedSigningKey) -> Result<R>,
    ) -> Result<R> {
        if !self.gates.raw {
            return Err(KeydError::RawDisabled);
        }
        let layout = self.layout_for(uid)?;
        let resident = store::resolve(&layout, did, kid)?.id.kid;
        let autolock = self.autolock;
        let now = Instant::now();
        self.with_vault(uid, |vault| vault.with_key(&resident, autolock, now, f))
    }

    /// 借出钥匙做一次挑战签名(`--allow-challenge-signing` 那条路)。
    ///
    /// 形状和 [`DaemonState::sign_raw`] 逐字相同 —— 同样的
    /// `layout_for` / `store::resolve` / `with_vault` / `with_key` —— 只换了
    /// 查哪一扇开关、以及拒绝时报哪个码。
    ///
    /// 开关的检查**在这里**,不在 handlers:让"能不能走这条路"和"这条路怎么走"
    /// 待在同一个地方,免得哪天有人绕开 handler 直接调。
    pub fn sign_challenge<R>(
        &self,
        uid: u32,
        did: &str,
        kid: Option<&str>,
        f: impl FnOnce(&LockedSigningKey) -> Result<R>,
    ) -> Result<R> {
        if !self.gates.challenge {
            return Err(KeydError::ChallengeDisabled);
        }
        let layout = self.layout_for(uid)?;
        let resident = store::resolve(&layout, did, kid)?.id.kid;
        let autolock = self.autolock;
        let now = Instant::now();
        self.with_vault(uid, |vault| vault.with_key(&resident, autolock, now, f))
    }
}

/// `did:wba:...:e1_<指纹>` → `e1_<指纹>`,也就是信封的文件名。
///
/// 没有 `e1_` 段的 DID 是**目录 DID**,不是一把具体的钥匙 —— 它没有对应的
/// 信封,所以是 `KeyNotFound` 而不是别的。
pub fn thumbprint_of(did: &str) -> Result<String> {
    let parts = parse_did_wba(did)?;
    match parts.e1_segment() {
        Some(segment) => Ok(segment.to_string()),
        None => Err(KeydError::KeyNotFound(format!(
            "{did} names no key: it has no e1_ segment"
        ))),
    }
}

/// 方便调用方:把 `Duration` 变成 [`Autolock`]。
pub fn autolock_from_secs(secs: u64) -> Autolock {
    Autolock::idle(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::Argon2Config;
    use crate::daemon::wire::Request;
    use crate::did::DidDocumentSpec;
    use crate::keystore::create;
    use crate::keystore::hardware::HardwareChoice;
    use crate::keystore::record::KeyAlgorithm;
    use crate::sign::rfc9421::SignRequest;
    use crate::sign::Signer;

    const PASSPHRASE: &str = "correct horse battery staple";

    /// Argon2 是**刻意慢**的 —— 那是它对离线爆破的抵抗。测试不该为此等
    /// 三秒钟一次,所以参数压到最小;信封里存的是这批参数,解开时照用,
    /// 所以快慢只影响测试时长,不影响被验的代码路径。
    fn fast() -> Argon2Config {
        Argon2Config {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn spec() -> DidDocumentSpec {
        DidDocumentSpec::new("example.com", vec!["user".into(), "alice".into()])
            .with_fragment("key-1")
    }

    /// 一个装着一把真钥匙的 vault。DID 由公钥算出来,所以**不能硬编码** ——
    /// 拿回去用。
    struct Fixture {
        _dir: TempDir,
        state: DaemonState,
        did: String,
        /// vault 的键 —— `did#fragment`,而不是 DID 本身。见 [`Vault::unlocked`]。
        resident: String,
    }

    impl Fixture {
        fn new(gates: SigningGates) -> Self {
            let dir = TempDir::new();
            let layout = KeydLayout::at(dir.path().to_path_buf());
            layout.ensure().unwrap();

            let created = create::create(
                &layout,
                &spec(),
                "default",
                PASSPHRASE.as_bytes(),
                fast(),
                HardwareChoice::None,
            )
            .unwrap();

            // keygen 不写 DID 文档(没签名的文档落盘会让人误以为发布了)。
            // 但签名要用它,而且用的必须是**已发布出去的那一份**,所以这里
            // 补上 `publish` 的活。
            let wrapped = store::load(&layout, &created.wrapped.id.thumbprint).unwrap();
            let device_secret = crate::keystore::device::load(&layout).unwrap();
            let key =
                crate::keystore::unwrap::unlock(&wrapped, PASSPHRASE.as_bytes(), &device_secret)
                    .unwrap();
            let document = crate::did::document::publishable(&spec(), &created.did, &key).unwrap();
            store::write_did_document(&layout, &created.did, &document).unwrap();
            drop(key);

            // vault 认的是 kid,不是 DID。从落盘的信封里读回来,别在这里
            // 手拼一个 "… #key-1" —— 那种字符串一旦和实际写进去的不一样,
            // 测试就会以"钥匙没解锁"的面目失败,而真因在测试自己身上。
            let resident = store::load_all(&layout).unwrap()[0].id.kid.clone();

            Self {
                state: DaemonState::new(
                    Roots::Single(layout),
                    PeerPolicy::default(),
                    Autolock::idle(Duration::from_secs(900)),
                    gates,
                ),
                did: created.did,
                resident,
                _dir: dir,
            }
        }

        fn unlock(&self) {
            self.state
                .unlock(501, &self.did, None, Zeroizing::new(PASSPHRASE.to_string()))
                .unwrap();
        }

        fn request(&self) -> SignRequest {
            SignRequest {
                method: "POST".to_string(),
                url: "https://example.com/api".to_string(),
                headers: BTreeMap::new(),
                body: Some(b"{}".to_vec()),
                covered: Vec::new(),
                nonce: None,
            }
        }
    }

    #[test]
    fn se_unlock_pins_snapshot_and_lock_cancels_inflight_install() {
        use crate::crypto::hygiene::LockedBytes;
        use crate::keystore::{
            hardware::SealedHardware,
            record::HardwareRoot,
            wrap::{seal, seed_to_public, SealRequest},
        };
        let f = Fixture::new(SigningGates::new(false, false));
        let layout = KeydLayout::at(f._dir.path().to_path_buf());
        let old = store::resolve(&layout, &f.did, Some("key-1")).unwrap();
        let seed = LockedBytes::fill(|bytes| *bytes = [17; 32]).unwrap();
        let hs = LockedBytes::fill(|bytes| *bytes = [29; 32]).unwrap();
        let hardware_hs = LockedBytes::fill(|bytes| *bytes = [29; 32]).unwrap();
        let wrapped = seal(SealRequest {
            id: old.id.clone(),
            algorithm: old.algorithm,
            public_multibase: seed_to_public(&seed).1,
            label: old.label,
            passphrase: PASSPHRASE.as_bytes(),
            device_secret: &device::load(&layout).unwrap(),
            seed: &seed,
            argon: fast(),
            hardware: Some(SealedHardware {
                root: HardwareRoot::SecureEnclave {
                    tag: "anp-keyd/synthetic-session-test".into(),
                },
                ciphertext: vec![4; 65],
                hs: hardware_hs,
            }),
        })
        .unwrap();
        store::write(&layout, &wrapped).unwrap();
        let pass = || Zeroizing::new(PASSPHRASE.to_string());
        let (generation, _) = f.state.se_envelope(501, &f.did, "key-1").unwrap();
        f.state
            .unlock_se_guarded(501, &wrapped, pass(), &hs, generation, || Ok(()))
            .unwrap();
        f.state.lock_everything();
        assert!(
            f.state
                .unlock_se_guarded(501, &wrapped, pass(), &hs, generation, || Ok(()))
                .is_err(),
            "a pre-password lock must cancel the challenge"
        );
        let (generation, _) = f.state.se_envelope(501, &f.did, "key-1").unwrap();
        assert!(f
            .state
            .unlock_se_guarded(501, &wrapped, pass(), &hs, generation, || {
                f.state.lock_everything();
                Ok(())
            })
            .is_err());
        let mut changed = wrapped.clone();
        changed.label = "different snapshot".into();
        let (generation, _) = f.state.se_envelope(501, &f.did, "key-1").unwrap();
        assert!(f
            .state
            .unlock_se_guarded(501, &changed, pass(), &hs, generation, || Ok(()))
            .is_err());
        assert!(f
            .state
            .with_vault(501, |vault| Ok(vault.unlocked.is_empty()))
            .unwrap());
    }

    #[test]
    fn lock_cancels_derived_key_before_installation() {
        let f = Fixture::new(SigningGates::new(false, false));
        let result =
            f.state
                .unlock_guarded(501, &f.did, None, Zeroizing::new(PASSPHRASE.into()), || {
                    assert_eq!(f.state.lock(501, None, None).unwrap(), 0);
                    Ok(())
                });
        assert!(matches!(result, Err(KeydError::Locked)));
        assert!(f.state.status(501).unwrap().is_empty());
        f.unlock();
        assert_eq!(f.state.status(501).unwrap().len(), 1);
    }

    #[test]
    fn emergency_lock_cancels_derived_key_before_installation() {
        let f = Fixture::new(SigningGates::new(false, false));
        let result =
            f.state
                .unlock_guarded(501, &f.did, None, Zeroizing::new(PASSPHRASE.into()), || {
                    f.state.lock_everything();
                    Ok(())
                });
        assert!(matches!(result, Err(KeydError::Locked)));
        assert!(f.state.status(501).unwrap().is_empty());
    }

    #[test]
    fn listing_keys_does_not_require_the_vault_to_be_unlocked() {
        let f = Fixture::new(SigningGates::new(false, false));
        let keys = f.state.list_keys(501).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].did, f.did);
        assert_eq!(keys[0].algorithm, KeyAlgorithm::Ed25519);
        assert!(
            f.state.status(501).unwrap().is_empty(),
            "nothing is unlocked yet"
        );
    }

    #[test]
    fn signing_a_locked_key_is_refused_rather_than_prompted() {
        let f = Fixture::new(SigningGates::new(false, false));
        let err = f
            .state
            .sign_structured(501, &f.did, None, &f.request())
            .unwrap_err();
        assert!(matches!(err, KeydError::Locked), "{err}");
    }

    #[test]
    fn the_right_passphrase_unlocks_and_then_the_key_signs() {
        let f = Fixture::new(SigningGates::new(false, false));
        f.unlock();

        assert_eq!(f.state.status(501).unwrap().len(), 1);
        let signed = f
            .state
            .sign_structured(501, &f.did, None, &f.request())
            .unwrap();
        assert!(signed.headers.contains_key("Signature"));

        // 覆盖面下限照样在 —— 解锁不改变"谁来定覆盖面"这件事。
        for want in ["@method", "@target-uri", "@authority", "content-digest"] {
            assert!(
                signed.covered.iter().any(|c| c == want),
                "{:?}",
                signed.covered
            );
        }
    }

    #[test]
    fn the_wrong_passphrase_leaves_nothing_unlocked() {
        let f = Fixture::new(SigningGates::new(false, false));
        let err = f
            .state
            .unlock(501, &f.did, None, Zeroizing::new("wrong".to_string()))
            .unwrap_err();
        assert!(matches!(err, KeydError::BadPassphrase), "{err}");
        assert!(f.state.status(501).unwrap().is_empty());
    }

    /// 锁上之后,钥匙不只是"被拦住"—— 它从进程里消失了。
    #[test]
    fn locking_removes_the_key_from_memory() {
        let f = Fixture::new(SigningGates::new(false, false));
        f.unlock();
        assert_eq!(f.state.lock(501, Some(&f.did), None).unwrap(), 1);

        assert!(f.state.status(501).unwrap().is_empty());
        assert!(matches!(
            f.state
                .sign_structured(501, &f.did, None, &f.request())
                .unwrap_err(),
            KeydError::Locked
        ));
        // 锁第二次不是错误 —— 想要的状态已经在那儿了。
        assert_eq!(f.state.lock(501, Some(&f.did), None).unwrap(), 0);
    }

    #[test]
    fn locking_everything_is_a_different_request_from_locking_one_key() {
        assert_ne!(
            Request::Lock {
                kid: None,
                did: None
            },
            Request::Lock {
                kid: None,
                did: Some("d".to_string())
            }
        );
    }

    /// **本模块的核心断言**:B 的 did 在 A 的 vault 里查不到。
    ///
    /// 就算 A 一字不差地报出 B 的 did,结果也只和"报了一个不存在的 did"
    /// 一样 —— 没有分支会走到 B 的磁盘根上去。
    #[test]
    fn one_uid_cannot_reach_another_uids_key_even_by_naming_it_exactly() {
        // B 有一把装满的 vault。
        let b = Fixture::new(SigningGates::new(false, false));
        assert_eq!(b.state.list_keys(502).unwrap().len(), 1);

        // A 的 vault 是空的。
        let a_dir = TempDir::new();
        let a_layout = KeydLayout::at(a_dir.path().to_path_buf());
        a_layout.ensure().unwrap();
        crate::keystore::device::load_or_create(&a_layout).unwrap();

        let a = DaemonState::new(
            Roots::Single(a_layout),
            PeerPolicy::default(),
            Autolock::idle(Duration::from_secs(900)),
            SigningGates::new(false, false),
        );

        // A 报出 B 的 did:列不到、解不开、更签不出来。
        //
        // 三个都报 `KeyNotFound` —— "我这儿没有这么一把钥匙" —— 而不是
        // `Locked`。这个区别是有意思的:`Locked` 等于承认"有这么一把钥匙,
        // 只是锁着",那本身就是 A 不该知道的信息。A 的根目录下确实什么都
        // 没有,所以 `KeyNotFound` 是这里唯一说得通、也不多嘴的答案。
        assert!(a.list_keys(501).unwrap().is_empty());
        assert!(matches!(
            a.unlock(501, &b.did, None, Zeroizing::new(PASSPHRASE.to_string()))
                .unwrap_err(),
            KeydError::KeyNotFound(_)
        ));
        assert!(matches!(
            a.sign_structured(501, &b.did, None, &b.request())
                .unwrap_err(),
            KeydError::KeyNotFound(_)
        ));

        // 而 B 自己那把钥匙好好的,没被动过。
        b.unlock();
        assert!(b
            .state
            .sign_structured(501, &b.did, None, &b.request())
            .is_ok());
    }

    #[test]
    fn an_idle_key_is_dropped_before_it_can_be_used() {
        let f = Fixture::new(SigningGates::new(false, false));
        f.unlock();
        assert_eq!(f.state.status(501).unwrap().len(), 1);

        // 把"现在"往后拨过超时线 —— 不用真的等 15 分钟。
        let later = Instant::now() + Duration::from_secs(901);
        assert_eq!(f.state.sweep_all(later), 1);

        assert!(f.state.status(501).unwrap().is_empty());
        assert!(matches!(
            f.state
                .sign_structured(501, &f.did, None, &f.request())
                .unwrap_err(),
            KeydError::Locked
        ));
    }

    /// 用一次就续一次。空闲超时收走的是"没人用"的钥匙,不是"开了一会儿"的。
    #[test]
    fn using_a_key_restarts_its_idle_clock() {
        let f = Fixture::new(SigningGates::new(false, false));
        f.unlock();

        // 解锁在 T0。现在假装时钟走到 T0+800s 并"用"一次。
        let now = Instant::now() + Duration::from_secs(800);
        f.state
            .with_vault(501, |vault| {
                vault.with_key(&f.resident, f.state.autolock(), now, |_| Ok(()))
            })
            .unwrap();

        // 从 T0 算早就过期了,从 T0+800s 算还没。
        assert_eq!(f.state.sweep_all(now + Duration::from_secs(99)), 0);
        // 再往前走满 900s 就又过期了。
        assert_eq!(f.state.sweep_all(now + Duration::from_secs(901)), 1);
    }

    /// 一个失败的调用不该把钥匙的寿命续上。
    #[test]
    fn a_failed_sign_does_not_extend_the_lifetime() {
        let f = Fixture::new(SigningGates::new(false, false));
        f.unlock();

        let now = Instant::now() + Duration::from_secs(800);
        let outcome = f.state.with_vault(501, |vault| {
            vault.with_key(&f.resident, f.state.autolock(), now, |_| {
                Err::<(), _>(KeydError::Protocol("nope".into()))
            })
        });
        assert!(outcome.is_err());

        // last_used 还停在解锁那一刻,所以过了超时线就掉。
        assert_eq!(f.state.sweep_all(now + Duration::from_secs(101)), 1);
    }

    #[test]
    fn raw_signing_is_off_unless_it_was_turned_on() {
        let f = Fixture::new(SigningGates::new(false, false));
        f.unlock();

        let err = f.state.sign_raw(501, &f.did, None, |_| Ok(())).unwrap_err();
        assert!(matches!(err, KeydError::RawDisabled), "{err}");
    }

    /// 开关先于一切:关着的时候,连"没解锁"都轮不到报。
    #[test]
    fn the_raw_switch_is_checked_before_the_lock_state() {
        let f = Fixture::new(SigningGates::new(false, false));
        assert!(matches!(
            f.state.sign_raw(501, &f.did, None, |_| Ok(())).unwrap_err(),
            KeydError::RawDisabled
        ));
    }

    #[test]
    fn an_unlocked_key_is_usable_for_raw_signing_when_the_switch_is_on() {
        let f = Fixture::new(SigningGates::new(true, false));
        f.unlock();

        let signature = f
            .state
            .sign_raw(501, &f.did, None, |key| Ok(key.sign(b"hello").unwrap()))
            .unwrap();
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn challenge_signing_is_off_unless_its_switch_is_on() {
        let f = Fixture::new(SigningGates::new(false, false));
        f.unlock();

        let err = f
            .state
            .sign_challenge(501, &f.did, None, |_| Ok(()))
            .unwrap_err();
        assert!(matches!(err, KeydError::ChallengeDisabled), "{err}");
    }

    /// **开关先于一切:** 关着的时候连"没解锁"都轮不到报 —— 和
    /// [`the_raw_switch_is_checked_before_the_lock_state`] 同一个形状,因为
    /// 这两条路共用一套外壳。
    #[test]
    fn the_challenge_switch_is_checked_before_the_lock_state() {
        let f = Fixture::new(SigningGates::new(false, false));
        assert!(matches!(
            f.state
                .sign_challenge(501, &f.did, None, |_| Ok(()))
                .unwrap_err(),
            KeydError::ChallengeDisabled
        ));
    }

    #[test]
    fn an_unlocked_key_is_usable_for_challenge_signing_when_the_switch_is_on() {
        let f = Fixture::new(SigningGates::new(false, true));
        f.unlock();

        let signature = f
            .state
            .sign_challenge(501, &f.did, None, |key| Ok(key.sign(b"challenge").unwrap()))
            .unwrap();
        assert_eq!(signature.len(), 64);
    }

    /// **开宽门就等于开窄门。** `raw` 比 `challenge` 宽,所以一个启动时只给了
    /// `--allow-raw-signing` 的操作者不该再被要求去给 `--allow-challenge-signing`
    /// —— 那条路能签的东西 `raw` 全都答得了。这条测试钉的是
    /// [`SigningGates::new`] 里那个 `raw || challenge`。
    #[test]
    fn opening_the_wider_raw_door_also_opens_the_narrow_challenge_one() {
        let f = Fixture::new(SigningGates::new(true, false));
        f.unlock();

        assert!(f
            .state
            .sign_challenge(501, &f.did, None, |key| Ok(key.sign(b"challenge").unwrap()))
            .is_ok());
    }

    /// Challenge 不会打开 Raw，但仍能签 64 字节文档 proof 输入。
    #[test]
    fn opening_the_challenge_door_does_not_open_raw() {
        let f = Fixture::new(SigningGates::new(false, true));
        f.unlock();

        assert!(matches!(
            f.state.sign_raw(501, &f.did, None, |_| Ok(())).unwrap_err(),
            KeydError::RawDisabled
        ));
    }

    #[test]
    fn a_did_without_a_key_segment_names_no_key() {
        let err = thumbprint_of("did:wba:example.com:user:alice").unwrap_err();
        assert!(matches!(err, KeydError::KeyNotFound(_)), "{err}");
        // 有 e1_ 段的就取最后那一段。
        assert_eq!(
            thumbprint_of("did:wba:example.com:user:alice:e1_abc").unwrap(),
            "e1_abc"
        );
        // 连 did:wba 都不是的,报的是 DID 解析失败,不是"找不到钥匙"。
        assert!(matches!(
            thumbprint_of("https://example.com/").unwrap_err(),
            KeydError::Did(_)
        ));
    }

    /// 测试用的小临时目录。**不引入 `tempfile` 依赖** —— 这一层只需要
    /// "建一个进程退出就没了、每次名字都不同的目录"。
    mod tempdir {
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
                    "anpio-key-test-{}-{n}-{:?}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ));
                std::fs::create_dir_all(&path).unwrap();
                Self { path }
            }

            pub fn path(&self) -> &Path {
                &self.path
            }
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                // 权限是 0700,内容里没有明文秘密(全是信封),直接删。
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
    }

    use tempdir::TempDir;
}
