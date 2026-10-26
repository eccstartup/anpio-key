//! Stateful exact-key grants; reservations and results live in requests.
//!
//! 两种 grant:一次性的 `request`(今天就有,一个 grant 一条 HTTP 签名)和
//! `session`(P1 起,IM 每条消息一次 origin proof,靠续期而不是靠管理员反复建权)。
//! 两者都绑 principal + 一把精确的 key + 一个不可变 policy;`session` 多一个
//! 绝对寿命上限和续期次数上限,续期只能在这个天花板下面往上顶。
use super::*;
use crate::security::http::CanonicalHttpRequest;
use crate::security::origin::OriginProof;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", deny_unknown_fields)]
pub enum GrantChange {
    Create {
        principal_id: String,
        key_id: String,
        policy_id: String,
        policy_version: u32,
        expiry: i64,
        max_uses: u32,
    },
    /// 长生命周期授权。续期次数上限取自 policy,不由调用方给。
    CreateSession {
        principal_id: String,
        key_id: String,
        policy_id: String,
        policy_version: u32,
        expiry: i64,
        max_uses: u32,
    },
    Revoke {
        grant_id: String,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub grant_id: String,
    pub principal_id: String,
    pub key_id: String,
    pub policy_id: String,
    pub policy_version: u32,
    pub boot_epoch: i64,
    pub expiry: i64,
    /// `request` 或 `session`。只有后者能续期。
    pub kind: String,
    pub created_at: i64,
    pub max_uses: u32,
    pub used_uses: u32,
    pub max_renewals: u32,
    pub renewals: u32,
    pub state: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", deny_unknown_fields)]
pub(super) enum Effect {
    Create {
        grant: Grant,
        monotonic_deadline: i64,
        operations: Vec<String>,
    },
    Revoke {
        grant_id: String,
    },
}
fn refused(code: &str) -> KeydError {
    KeydError::Misuse(code.into())
}
fn principal(db: &Connection, id: &str) -> Result<()> {
    if !db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM principals WHERE principal_id=?1 AND state='enabled')",
            [id],
            |r| r.get::<_, bool>(0),
        )
        .map_err(db_error)?
    {
        return Err(refused("PRINCIPAL_DISABLED"));
    }
    Ok(())
}

/// 一个 purpose 允许用哪种角色的键。P1 只有前两个 purpose 有操作;
/// 其余的 purpose 形已经冻结在 policy 里,但还没有键角色和操作,建 grant 会被拒。
fn role_for(purpose: super::policy::Purpose) -> Result<catalog::KeyRole> {
    use super::policy::Purpose;
    Ok(match purpose {
        Purpose::HttpAuthentication | Purpose::OriginProof => catalog::KeyRole::Hot,
        Purpose::PurposeSigning | Purpose::ObjectProof | Purpose::DocumentProof | Purpose::Ecdh
        | Purpose::Root => return Err(refused("GRANT_INVALID")),
    })
}

/// purpose 到操作名的绑定。grant 的 `grant_operations` 行就取自这里。
pub(super) fn operation_for(purpose: super::policy::Purpose) -> Result<&'static str> {
    use super::policy::Purpose;
    Ok(match purpose {
        Purpose::HttpAuthentication => "SIGN_HTTP",
        Purpose::OriginProof => "SIGN_ORIGIN_PROOF",
        Purpose::PurposeSigning
        | Purpose::ObjectProof
        | Purpose::DocumentProof
        | Purpose::Ecdh
        | Purpose::Root => return Err(refused("GRANT_INVALID")),
    })
}

fn key_for(
    db: &Connection,
    root: &Path,
    id: &str,
    purpose: super::policy::Purpose,
) -> Result<catalog::KeyRecord> {
    let key = catalog::get_key(db, id).map_err(|_| refused("KEY_ROLE_FORBIDDEN"))?;
    if key.role != role_for(purpose)? || key.state != "active" {
        return Err(refused("KEY_ROLE_FORBIDDEN"));
    }
    catalog::check_key(db, root, &key.vault_id, &key.did, &key.kid)
        .map_err(|_| refused("KEY_ROLE_FORBIDDEN"))?;
    Ok(key)
}
pub(super) fn hot_key(db: &Connection, root: &Path, id: &str) -> Result<catalog::KeyRecord> {
    key_for(db, root, id, super::policy::Purpose::HttpAuthentication)
}
pub(super) fn policy(db: &Connection, id: &str, version: u32) -> Result<Value> {
    let content: String = db
        .query_row(
            "SELECT content FROM policies WHERE policy_id=?1 AND version=?2",
            params![id, version],
            |r| r.get(0),
        )
        .optional()
        .map_err(db_error)?
        .ok_or_else(|| refused("POLICY_DENIED"))?;
    serde_json::from_str(&content).map_err(|_| unavailable())
}
fn validate(
    db: &Connection,
    root: &Path,
    g: &Grant,
    now: Time,
) -> Result<super::policy::Policy> {
    principal(db, &g.principal_id)?;
    let p = super::policy::parse(policy(db, &g.policy_id, g.policy_version)?)?;
    key_for(db, root, &g.key_id, p.purpose())?;
    let duration = g
        .expiry
        .checked_sub(now.wall)
        .filter(|v| *v > 0)
        .ok_or_else(|| refused("GRANT_EXPIRED"))?;
    if duration > i64::from(p.limits.max_duration_seconds)
        || g.max_uses == 0
        || g.max_uses > p.limits.max_uses
    {
        return Err(refused("GRANT_INVALID"));
    }
    match g.kind.as_str() {
        "request" => {
            // 一次性的 grant 不续期,也不可能有续期预算。
            if g.max_renewals != 0 || g.renewals != 0 {
                return Err(refused("GRANT_INVALID"));
            }
        }
        "session" => {
            if g.max_renewals > p.limits.max_renewals || g.created_at > now.wall {
                return Err(refused("GRANT_INVALID"));
            }
            let lifetime = g
                .expiry
                .checked_sub(g.created_at)
                .filter(|v| *v > 0)
                .ok_or_else(|| refused("GRANT_INVALID"))?;
            if lifetime > i64::from(p.limits.max_lifetime_seconds) {
                return Err(refused("GRANT_INVALID"));
            }
        }
        _ => return Err(refused("GRANT_INVALID")),
    }
    Ok(p)
}
fn fresh(
    principal_id: String,
    key_id: String,
    policy_id: String,
    policy_version: u32,
    boot: i64,
    expiry: i64,
    max_uses: u32,
    kind: &str,
    created_at: i64,
    max_renewals: u32,
) -> Grant {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    Grant {
        grant_id: hex(&bytes),
        principal_id,
        key_id,
        policy_id,
        policy_version,
        boot_epoch: boot,
        expiry,
        kind: kind.into(),
        created_at,
        max_uses,
        used_uses: 0,
        max_renewals,
        renewals: 0,
        state: "active".into(),
    }
}
fn deadline(expiry: i64, now: Time) -> Result<i64> {
    expiry
        .checked_sub(now.wall)
        .and_then(|s| s.checked_mul(1000))
        .and_then(|ms| now.monotonic_ms.checked_add(ms))
        .ok_or_else(invalid)
}
pub(super) fn resolve(
    db: &Connection,
    root: &Path,
    change: GrantChange,
    boot: i64,
    now: Time,
) -> Result<Effect> {
    match change {
        GrantChange::Create {
            principal_id,
            key_id,
            policy_id,
            policy_version,
            expiry,
            max_uses,
        } => {
            let grant = fresh(
                principal_id,
                key_id,
                policy_id,
                policy_version,
                boot,
                expiry,
                max_uses,
                "request",
                now.wall,
                0,
            );
            let p = validate(db, root, &grant, now)?;
            Ok(Effect::Create {
                monotonic_deadline: deadline(expiry, now)?,
                operations: vec![operation_for(p.purpose())?.to_owned()],
                grant,
            })
        }
        GrantChange::CreateSession {
            principal_id,
            key_id,
            policy_id,
            policy_version,
            expiry,
            max_uses,
        } => {
            let ceiling =
                super::policy::parse(policy(db, &policy_id, policy_version)?)?.limits.max_renewals;
            let grant = fresh(
                principal_id,
                key_id,
                policy_id,
                policy_version,
                boot,
                expiry,
                max_uses,
                "session",
                now.wall,
                ceiling,
            );
            let p = validate(db, root, &grant, now)?;
            Ok(Effect::Create {
                monotonic_deadline: deadline(expiry, now)?,
                operations: vec![operation_for(p.purpose())?.to_owned()],
                grant,
            })
        }
        GrantChange::Revoke { grant_id } => {
            if get(db, &grant_id)?.is_none() {
                return Err(refused("GRANT_INVALID"));
            }
            Ok(Effect::Revoke { grant_id })
        }
    }
}
pub(super) fn apply(
    tx: &Transaction<'_>,
    root: &Path,
    effect: Effect,
    boot: i64,
    now: Time,
) -> Result<()> {
    match effect {
        Effect::Create {
            grant: g,
            monotonic_deadline,
            operations,
        } => {
            validate(tx, root, &g, now)?;
            if g.boot_epoch != boot || now.monotonic_ms >= monotonic_deadline {
                return Err(refused("GRANT_EXPIRED"));
            }
            tx.execute(
                "INSERT INTO grants(grant_id,principal_id,key_id,policy_id,policy_version,boot_epoch,expiry,kind,created_at,max_uses,used_uses,max_renewals,renewals,state) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,0,?11,0,'active')",
                params![
                    g.grant_id,
                    g.principal_id,
                    g.key_id,
                    g.policy_id,
                    g.policy_version,
                    boot,
                    g.expiry,
                    g.kind,
                    g.created_at,
                    g.max_uses,
                    g.max_renewals
                ],
            )
            .map_err(db_error)?;
            for operation in &operations {
                tx.execute(
                    "INSERT INTO grant_operations VALUES(?1,?2)",
                    params![g.grant_id, operation],
                )
                .map_err(db_error)?;
            }
            tx.execute(
                "INSERT INTO grant_deadlines VALUES(?1,?2)",
                params![g.grant_id, monotonic_deadline],
            )
            .map_err(db_error)?;
            // 一次性的 grant 今天不落这条;长寿命授权值得单独一行。
            if g.kind == "session" {
                append(
                    tx,
                    &json!({"event":"GRANT_CREATED","grant_id":g.grant_id,"principal_id":g.principal_id,"key_id":g.key_id,"policy_id":g.policy_id,"policy_version":g.policy_version,"kind":g.kind,"expiry":g.expiry,"max_uses":g.max_uses,"max_renewals":g.max_renewals,"operations":operations,"at":now.wall}),
                )?;
            }
        }
        Effect::Revoke { grant_id } => {
            tx.execute(
                "UPDATE grants SET state='revoked' WHERE grant_id=?1 AND state='active'",
                [grant_id],
            )
            .map_err(db_error)?;
        }
    }
    Ok(())
}
pub(super) fn get(db: &Connection, id: &str) -> Result<Option<Grant>> {
    db.query_row("SELECT grant_id,principal_id,key_id,policy_id,policy_version,boot_epoch,expiry,kind,created_at,max_uses,used_uses,max_renewals,renewals,state FROM grants WHERE grant_id=?1",[id],|r|Ok(Grant{grant_id:r.get(0)?,principal_id:r.get(1)?,key_id:r.get(2)?,policy_id:r.get(3)?,policy_version:r.get(4)?,boot_epoch:r.get(5)?,expiry:r.get(6)?,kind:r.get(7)?,created_at:r.get(8)?,max_uses:r.get(9)?,used_uses:r.get(10)?,max_renewals:r.get(11)?,renewals:r.get(12)?,state:r.get(13)?})).optional().map_err(db_error)
}
impl Database {
    pub(super) fn refresh_grants(&mut self, now: Time) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        if tx.query_row("SELECT EXISTS(SELECT 1 FROM grants g LEFT JOIN grant_deadlines d USING(grant_id) WHERE g.state='active' AND g.boot_epoch=?1 AND d.grant_id IS NULL)",[self.boot_epoch],|r|r.get::<_,bool>(0)).map_err(db_error)? {
            return Err(unavailable());
        }
        let exhausted = tx
            .execute(
                "UPDATE grants SET state='exhausted' WHERE state='active' AND used_uses>=max_uses",
                [],
            )
            .map_err(db_error)?;
        if exhausted > 0 {
            append(
                &tx,
                &json!({"event":"GRANTS_EXHAUSTED","count":exhausted,"at":now.wall}),
            )?;
        }
        let changed=tx.execute("UPDATE grants SET state='expired' WHERE state='active' AND (expiry<=?1 OR grant_id IN (SELECT grant_id FROM grant_deadlines WHERE monotonic_deadline<=?2))",params![now.wall,now.monotonic_ms]).map_err(db_error)?;
        if changed > 0 {
            append(
                &tx,
                &json!({"event":"GRANTS_EXPIRED","count":changed,"at":now.wall}),
            )?;
        }
        tx.commit().map_err(db_error)
    }
    pub fn grant_status(&mut self, principal_id: &str, id: &str, now: Time) -> Result<Grant> {
        self.refresh_grants(now)?;
        principal(&self.connection, principal_id)?;
        get(&self.connection, id)?
            .filter(|g| g.principal_id == principal_id)
            .ok_or_else(|| refused("GRANT_INVALID"))
    }
    pub fn authorized_keys(
        &mut self,
        principal_id: &str,
        now: Time,
    ) -> Result<Vec<catalog::KeyRecord>> {
        self.refresh_grants(now)?;
        principal(&self.connection, principal_id)?;
        let ids = {
            let mut s=self.connection.prepare("SELECT DISTINCT key_id FROM grants WHERE principal_id=?1 AND state='active' AND boot_epoch=?2 AND used_uses<max_uses").map_err(db_error)?;
            let ids = s
                .query_map(params![principal_id, self.boot_epoch], |r| {
                    r.get::<_, String>(0)
                })
                .map_err(db_error)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(db_error)?;
            ids
        };
        ids.iter()
            .map(|id| hot_key(&self.connection, &self.root, id))
            .collect()
    }

    /// 一个 grant 能不能做 `operation`,以及它对应的键和策略原文。
    ///
    /// 策略原文要给调用方拿去按 purpose 自己判 —— 判定靠的是这份不可变内容,
    /// 不是 `authorize` 期间的任何缓存。
    fn authorize(
        &mut self,
        principal_id: &str,
        id: &str,
        purpose: super::policy::Purpose,
        operation: &str,
        now: Time,
    ) -> Result<(Grant, catalog::KeyRecord, Value)> {
        let g = self.grant_status(principal_id, id, now)?;
        match g.state.as_str() {
            "expired" => return Err(refused("GRANT_EXPIRED")),
            "exhausted" => return Err(refused("GRANT_EXHAUSTED")),
            "active" => {}
            _ => return Err(refused("GRANT_INVALID")),
        }
        if g.boot_epoch != self.boot_epoch {
            return Err(refused("GRANT_INVALID"));
        }
        if g.used_uses >= g.max_uses {
            return Err(refused("GRANT_EXHAUSTED"));
        }
        let allowed = self
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM grant_operations WHERE grant_id=?1 AND operation=?2)",
                params![g.grant_id, operation],
                |r| r.get::<_, bool>(0),
            )
            .map_err(db_error)?;
        if !allowed {
            return Err(refused("GRANT_INVALID"));
        }
        let content = policy(&self.connection, &g.policy_id, g.policy_version)?;
        if super::policy::parse(content.clone())?.purpose() != purpose {
            return Err(refused("POLICY_DENIED"));
        }
        let key = key_for(&self.connection, &self.root, &g.key_id, purpose)?;
        Ok((g, key, content))
    }

    pub fn authorize_http(
        &mut self,
        principal_id: &str,
        id: &str,
        request: &CanonicalHttpRequest,
        now: Time,
    ) -> Result<(Grant, catalog::KeyRecord)> {
        let (g, key, content) = self.authorize(
            principal_id,
            id,
            super::policy::Purpose::HttpAuthentication,
            "SIGN_HTTP",
            now,
        )?;
        super::policy::evaluate_http(content, request)?;
        Ok((g, key))
    }

    pub fn authorize_origin(
        &mut self,
        principal_id: &str,
        id: &str,
        proof: &OriginProof,
        now: Time,
    ) -> Result<(Grant, catalog::KeyRecord)> {
        let (g, key, content) = self.authorize(
            principal_id,
            id,
            super::policy::Purpose::OriginProof,
            "SIGN_ORIGIN_PROOF",
            now,
        )?;
        super::policy::evaluate_origin(content, proof)?;
        Ok((g, key))
    }

    /// 续期。只能往上顶到策略给的天花板,不能抬高次数、不能换键、不能跨 boot。
    pub fn renew_grant(
        &mut self,
        principal_id: &str,
        id: &str,
        requested_expiry: i64,
        now: Time,
    ) -> Result<Grant> {
        self.refresh_grants(now)?;
        principal(&self.connection, principal_id)?;
        let g = get(&self.connection, id)?
            .filter(|g| g.principal_id == principal_id)
            .ok_or_else(|| refused("GRANT_INVALID"))?;
        if g.boot_epoch != self.boot_epoch || g.kind != "session" {
            return Err(refused("GRANT_INVALID"));
        }
        match g.state.as_str() {
            "active" => {}
            "exhausted" => return Err(refused("GRANT_EXHAUSTED")),
            "expired" => return Err(refused("GRANT_EXPIRED")),
            _ => return Err(refused("GRANT_INVALID")),
        }
        if g.used_uses >= g.max_uses {
            return Err(refused("GRANT_EXHAUSTED"));
        }
        if g.renewals >= g.max_renewals {
            return Err(refused("GRANT_RENEWALS_EXHAUSTED"));
        }
        let p = super::policy::parse(policy(&self.connection, &g.policy_id, g.policy_version)?)?;
        // 键还能用才有续期的意义:轮换、撤角色、文档变更都会让它在这里停下。
        key_for(&self.connection, &self.root, &g.key_id, p.purpose())?;
        // 两个天花板取小:从现在起的一轮,和从建 grant 起的绝对寿命。
        let from_now = now
            .wall
            .checked_add(i64::from(p.limits.max_duration_seconds))
            .ok_or_else(invalid)?;
        let absolute = g
            .created_at
            .checked_add(i64::from(p.limits.max_lifetime_seconds))
            .ok_or_else(invalid)?;
        let expiry = requested_expiry.min(from_now).min(absolute);
        if expiry <= g.expiry {
            return Err(refused("GRANT_INVALID"));
        }
        let monotonic_deadline = deadline(expiry, now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let changed = tx
            .execute(
                "UPDATE grants SET expiry=?1,renewals=renewals+1 WHERE grant_id=?2 AND state='active' AND renewals=?3",
                params![expiry, id, g.renewals],
            )
            .map_err(db_error)?;
        if changed != 1 {
            return Err(unavailable());
        }
        let extended = tx
            .execute(
                "UPDATE grant_deadlines SET monotonic_deadline=?1 WHERE grant_id=?2",
                params![monotonic_deadline, id],
            )
            .map_err(db_error)?;
        if extended != 1 {
            return Err(unavailable());
        }
        append(
            &tx,
            &json!({"event":"GRANT_RENEWED","grant_id":id,"principal_id":principal_id,"key_id":g.key_id,"policy_id":g.policy_id,"policy_version":g.policy_version,"from":g.expiry,"to":expiry,"requested":requested_expiry,"renewals":g.renewals+1,"at":now.wall}),
        )?;
        tx.commit().map_err(db_error)?;
        get(&self.connection, id)?.ok_or_else(unavailable)
    }
}
